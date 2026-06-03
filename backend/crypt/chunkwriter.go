// Streaming multipart upload support for crypt.
//
// crypt encrypts plaintext in fixed blockDataSize (64 KiB) blocks with a
// deterministic per-block nonce (initialNonce + blockIndex). That makes it
// possible to encrypt each multipart part independently - provided every
// part except the last is a whole number of blocks - and concatenate the
// results into a valid encrypted file. Only the first part carries the
// 32-byte file header.
//
// This lets callers such as serve s3 stream a multipart upload straight
// through crypt into the underlying backend, with memory bounded by the
// parts in flight rather than the whole file.

package crypt

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/rclone/rclone/fs"
	"github.com/rclone/rclone/lib/multipart"
	"github.com/rclone/rclone/lib/pool"
	"github.com/rclone/rclone/lib/ranges"
)

// Errors returned when the parts of a multipart upload don't tile the file
// the way crypt's independent-part encryption requires: a uniform part size
// (except the last part) and contiguous coverage with no overlaps or gaps.
var (
	// errPartSize is returned when a non-final part isn't a whole number of
	// crypt blocks, so it can't be encrypted independently.
	errPartSize = fmt.Errorf("crypt: multipart part size must be a multiple of %d bytes (the crypt block size)", blockDataSize)
	// errPartOverlap is returned when a part overlaps another (a shifted or
	// non-uniform part).
	errPartOverlap = errors.New("crypt: overlapping multipart parts - all parts except the last must be the same size")
	// errPartMissing is returned when the parts don't cover the whole file
	// (a missing part or a non-uniform part leaving a gap).
	errPartMissing = errors.New("crypt: multipart parts don't cover the whole file - all parts except the last must be the same size")
)

// OpenChunkWriter returns the chunk size and a ChunkWriter that encrypts
// each part and streams it into the underlying backend.
//
// It is advertised only when the underlying Fs supports OpenChunkWriter or
// OpenWriterAt (see the feature setup in NewFs).
func (f *Fs) OpenChunkWriter(ctx context.Context, remote string, src fs.ObjectInfo, options ...fs.OpenOption) (info fs.ChunkWriterInfo, writer fs.ChunkWriter, err error) {
	encName := f.cipher.EncryptFileName(remote)

	// With no data encryption there is no block structure, so just delegate
	// straight to the underlying chunk writer.
	if f.opt.NoDataEncryption {
		do := f.Fs.Features().OpenChunkWriter
		if do == nil {
			return info, nil, fs.ErrorNotImplemented
		}
		return do(ctx, encName, f.newObjectInfo(src, nonce{}), options...)
	}

	// One nonce for the whole file, shared by every part.
	var fileNonce nonce
	if err := fileNonce.fromReader(f.cipher.cryptoRand); err != nil {
		return info, nil, err
	}
	encSrc := f.newObjectInfo(src, fileNonce)

	w := &cryptChunkWriter{
		f:       f,
		remote:  remote,
		nonce:   fileNonce,
		pending: map[int]*pool.RW{},
	}

	switch {
	case f.Fs.Features().OpenChunkWriter != nil:
		uInfo, cw, err := f.Fs.Features().OpenChunkWriter(ctx, encName, encSrc, options...)
		if err != nil {
			return info, nil, err
		}
		w.underlyingCW = cw
		info = fs.ChunkWriterInfo{
			ChunkSize:   plaintextChunkSize(uInfo.ChunkSize),
			Concurrency: uInfo.Concurrency,
		}
	case f.Fs.Features().OpenWriterAt != nil:
		wa, err := f.Fs.Features().OpenWriterAt(ctx, encName, encSrc.Size())
		if err != nil {
			return info, nil, err
		}
		w.writerAt = wa
		// There is no underlying ChunkWriterInfo to take a concurrency from,
		// so default to --multi-thread-streams like the built-in OpenWriterAt
		// chunk-writer adapter does (otherwise multi-thread copy falls back to
		// a single stream).
		info = fs.ChunkWriterInfo{
			ChunkSize:   plaintextChunkSize(0),
			Concurrency: fs.GetConfig(ctx).MultiThreadStreams,
		}
	default:
		return info, nil, fs.ErrorNotImplemented
	}

	return info, w, nil
}

// partEncrypter must forward a backend's accounting delay to the source so
// double reads (checksum + upload) aren't double counted.
var _ pool.DelayAccountinger = (*partEncrypter)(nil)

// plaintextChunkSize turns a preferred underlying (ciphertext) chunk size
// into a plaintext chunk size that is a whole number of crypt blocks, so
// every part a caller produces lands on a block boundary. A zero or tiny
// hint falls back to a 64 MiB default (matching --multi-thread-chunk-size).
//
// The block count is rounded up so the encrypted part is at least as large as
// the underlying preferred chunk size - rounding down could push it below a
// backend's minimum part size (e.g. s3's 5 MiB), failing the upload.
func plaintextChunkSize(underlyingCiphertextSize int64) int64 {
	blocks := (underlyingCiphertextSize + blockSize - 1) / blockSize
	if blocks < 1 {
		blocks = (64 * 1024 * 1024) / blockDataSize
	}
	return blocks * blockDataSize
}

// cryptChunkWriter encrypts each part of a multipart upload and writes it
// into the underlying backend. Exactly one of underlyingCW / writerAt is set.
type cryptChunkWriter struct {
	f      *Fs
	remote string
	nonce  nonce // the file's block-0 nonce

	underlyingCW fs.ChunkWriter    // underlying OpenChunkWriter path
	writerAt     fs.WriterAtCloser // underlying OpenWriterAt path

	mu            sync.Mutex
	sizeKnown     bool             // partSize/blocksPerPart have been determined
	partSize      int64            // uniform plaintext part size
	blocksPerPart int64            // partSize / blockDataSize
	pending       map[int]*pool.RW // parts buffered (in pooled memory) before the size was known
	written       ranges.Ranges    // plaintext byte ranges placed so far
	maxEnd        int64            // highest plaintext offset placed (the file size)
}

// WriteChunk encrypts and writes part chunkNumber (indexed from 0).
//
// The uniform part size is learned from the first part (chunk 0) or, if
// higher-numbered parts arrive first, from the lowest-numbered of any two
// parts seen - that part is necessarily a full (non-final) part, so two
// parts are enough and we don't have to wait for chunk 0. A part that can't
// yet be placed is buffered (in a pooled memory buffer) until the size is
// known, because the caller reclaims the reader once WriteChunk returns.
// WriteChunk is safe to call concurrently.
func (w *cryptChunkWriter) WriteChunk(ctx context.Context, chunkNumber int, reader io.ReadSeeker) (int64, error) {
	if chunkNumber < 0 {
		return -1, fmt.Errorf("crypt: invalid chunk number %d", chunkNumber)
	}

	size, err := reader.Seek(0, io.SeekEnd)
	if err != nil {
		return -1, err
	}
	if _, err := reader.Seek(0, io.SeekStart); err != nil {
		return -1, err
	}

	w.mu.Lock()

	// Size already known: place this part straight away.
	if w.sizeKnown {
		w.mu.Unlock()
		if err := w.place(ctx, chunkNumber, size, reader); err != nil {
			return -1, err
		}
		return size, nil
	}

	// This part lets us determine the uniform size if it is chunk 0 or if
	// at least one other part has already been seen (their sizes are in
	// pending). Chunk 0 always writes at offset 0 with the header, so its
	// arrival fixes the size whether or not it is the only/last part.
	if chunkNumber == 0 || len(w.pending) >= 1 {
		w.learnSizeLocked(chunkNumber, size)
		pending := w.pending
		w.pending = nil
		w.mu.Unlock()

		// Place this part (its reader is still live - no copy needed).
		err := w.place(ctx, chunkNumber, size, reader)
		// Then flush the parts that were waiting for the size.
		for n, prw := range pending {
			if err == nil {
				err = w.place(ctx, n, prw.Size(), prw)
			}
			_ = prw.Close()
		}
		if err != nil {
			return -1, err
		}
		return size, nil
	}

	// First out-of-order part and not chunk 0: buffer it until a second
	// part (or chunk 0) tells us the size.
	w.mu.Unlock()
	prw := multipart.NewRW().Reserve(size)
	if _, err := io.Copy(prw, reader); err != nil {
		_ = prw.Close()
		return -1, err
	}

	w.mu.Lock()
	if !w.sizeKnown {
		w.pending[chunkNumber] = prw
		w.mu.Unlock()
		return size, nil
	}
	// The size became known while we were copying - flush ourselves.
	w.mu.Unlock()
	err = w.place(ctx, chunkNumber, prw.Size(), prw)
	_ = prw.Close()
	if err != nil {
		return -1, err
	}
	return size, nil
}

// learnSizeLocked fixes the uniform part size from the lowest-numbered part
// seen so far (this part plus any pending). Must be called with w.mu held
// and only once.
func (w *cryptChunkWriter) learnSizeLocked(chunkNumber int, size int64) {
	lowest, lowestSize := chunkNumber, size
	for n, prw := range w.pending {
		if n < lowest {
			lowest, lowestSize = n, prw.Size()
		}
	}
	w.partSize = lowestSize
	w.blocksPerPart = lowestSize / blockDataSize
	w.sizeKnown = true
}

// place encrypts and writes part chunkNumber, which must be done only after
// the size is known. A non-first part can only be placed if every earlier
// part is a whole number of blocks. The part's plaintext byte range is
// recorded so overlaps are caught here and gaps at Close - both meaning the
// parts weren't a uniform size.
func (w *cryptChunkWriter) place(ctx context.Context, chunkNumber int, size int64, reader io.ReadSeeker) error {
	if chunkNumber != 0 && w.partSize%blockDataSize != 0 {
		return errPartSize
	}
	offset := int64(chunkNumber) * w.partSize
	if size > 0 {
		r := ranges.Range{Pos: offset, Size: size}
		w.mu.Lock()
		before := w.written.Size()
		w.written.Insert(r)
		overlap := w.written.Size()-before != size
		if end := offset + size; end > w.maxEnd {
			w.maxEnd = end
		}
		w.mu.Unlock()
		if overlap {
			return errPartOverlap
		}
	}
	return w.flushChunk(ctx, chunkNumber, int64(chunkNumber)*w.blocksPerPart, size, reader)
}

// flushChunk encrypts reader as blocks starting at blockOff and writes the
// ciphertext to the underlying backend. The file header is emitted only for
// chunk 0. size is the plaintext length of the part.
func (w *cryptChunkWriter) flushChunk(ctx context.Context, chunkNumber int, blockOff, size int64, reader io.ReadSeeker) error {
	withHeader := chunkNumber == 0

	if w.underlyingCW != nil {
		// Offsets are handled by the underlying backend's concatenation, so
		// we only need a (zero-copy, deterministic) encrypted reader.
		penc, err := w.f.cipher.newPartEncrypter(reader, w.nonce, blockOff, withHeader)
		if err != nil {
			return err
		}
		_, err = w.underlyingCW.WriteChunk(ctx, chunkNumber, penc)
		return err
	}

	// writerAt path: compute the ciphertext offset ourselves. Part layout
	// (overlaps/gaps) is validated by place; here we just write the bytes.
	var offset int64
	if !withHeader {
		offset = int64(fileHeaderSize) + blockOff*int64(blockSize)
	}
	encSize := w.f.cipher.EncryptedSize(size)
	if !withHeader {
		encSize -= int64(fileHeaderSize)
	}

	if _, err := reader.Seek(0, io.SeekStart); err != nil {
		return err
	}
	enc, err := w.f.cipher.newEncrypterAt(reader, w.nonce, blockOff, withHeader)
	if err != nil {
		return err
	}
	ow := io.NewOffsetWriter(w.writerAt, offset)
	n, err := io.Copy(ow, enc)
	if err != nil {
		return err
	}
	if n != encSize {
		return fmt.Errorf("crypt: short write for chunk %d: %d of %d", chunkNumber, n, encSize)
	}
	return nil
}

// Close finalises the upload.
func (w *cryptChunkWriter) Close(ctx context.Context) error {
	w.mu.Lock()
	pending := w.pending
	w.pending = nil
	w.mu.Unlock()
	if len(pending) > 0 {
		// The first part never arrived, so the parts can't be placed.
		for _, prw := range pending {
			_ = prw.Close()
		}
		_ = w.abort(ctx)
		return errors.New("crypt: multipart upload finished without enough parts to determine the part size")
	}

	// Check the parts tiled the whole file with no gaps (a gap means a part
	// was missing or smaller than the uniform part size).
	w.mu.Lock()
	missing := w.written.FindMissing(ranges.Range{Pos: 0, Size: w.maxEnd})
	w.mu.Unlock()
	if !missing.IsEmpty() {
		_ = w.abort(ctx)
		return errPartMissing
	}

	if w.underlyingCW != nil {
		return w.underlyingCW.Close(ctx)
	}
	return w.writerAt.Close()
}

// Abort cancels the upload and cleans up.
func (w *cryptChunkWriter) Abort(ctx context.Context) error {
	return w.abort(ctx)
}

func (w *cryptChunkWriter) abort(ctx context.Context) error {
	w.mu.Lock()
	pending := w.pending
	w.pending = nil
	w.mu.Unlock()
	for _, prw := range pending {
		_ = prw.Close()
	}
	if w.underlyingCW != nil {
		return w.underlyingCW.Abort(ctx)
	}
	err := w.writerAt.Close()
	// Remove the partially written object.
	if o, e := w.f.Fs.NewObject(ctx, w.f.cipher.EncryptFileName(w.remote)); e == nil {
		_ = o.Remove(ctx)
	}
	return err
}
