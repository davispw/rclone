package crypt

import (
	"bytes"
	"context"
	"crypto/md5"
	"fmt"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/rclone/rclone/fs"
	"github.com/rclone/rclone/fs/hash"
	"github.com/rclone/rclone/fs/object"
	"github.com/rclone/rclone/lib/random"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Create a temporary local fs to upload things from

func makeTempLocalFs(t *testing.T) (localFs fs.Fs) {
	localFs, err := fs.TemporaryLocalFs(context.Background())
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, localFs.Rmdir(context.Background(), ""))
	})
	return localFs
}

// Upload a file to a remote
func uploadFile(t *testing.T, f fs.Fs, remote, contents string) (obj fs.Object) {
	inBuf := bytes.NewBufferString(contents)
	t1 := time.Date(2012, time.December, 17, 18, 32, 31, 0, time.UTC)
	upSrc := object.NewStaticObjectInfo(remote, t1, int64(len(contents)), true, nil, nil)
	obj, err := f.Put(context.Background(), inBuf, upSrc)
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, obj.Remove(context.Background()))
	})
	return obj
}

// Test the ObjectInfo
func testObjectInfo(t *testing.T, f *Fs, wrap bool) {
	var (
		contents = random.String(100)
		path     = "hash_test_object"
		ctx      = context.Background()
	)
	if wrap {
		path = "_wrap"
	}

	localFs := makeTempLocalFs(t)

	obj := uploadFile(t, localFs, path, contents)

	// encrypt the data
	inBuf := bytes.NewBufferString(contents)
	var outBuf bytes.Buffer
	enc, err := f.cipher.newEncrypter(inBuf, nil)
	require.NoError(t, err)
	nonce := enc.nonce // read the nonce at the start
	_, err = io.Copy(&outBuf, enc)
	require.NoError(t, err)

	var oi fs.ObjectInfo = obj
	if wrap {
		// wrap the object in an fs.ObjectUnwrapper if required
		oi = fs.NewOverrideRemote(oi, "new_remote")
	}

	// wrap the object in a crypt for upload using the nonce we
	// saved from the encrypter
	src := f.newObjectInfo(oi, nonce)

	// Test ObjectInfo methods
	if !f.opt.NoDataEncryption {
		assert.Equal(t, int64(outBuf.Len()), src.Size())
	}
	assert.Equal(t, f, src.Fs())
	assert.NotEqual(t, path, src.Remote())

	// Test ObjectInfo.Hash
	wantHash := md5.Sum(outBuf.Bytes())
	gotHash, err := src.Hash(ctx, hash.MD5)
	require.NoError(t, err)
	assert.Equal(t, fmt.Sprintf("%x", wantHash), gotHash)
}

func testComputeHash(t *testing.T, f *Fs) {
	var (
		contents = random.String(100)
		path     = "compute_hash_test"
		ctx      = context.Background()
		hashType = f.Fs.Hashes().GetOne()
	)

	if hashType == hash.None {
		t.Skipf("%v: does not support hashes", f.Fs)
	}

	localFs := makeTempLocalFs(t)

	// Upload a file to localFs as a test object
	localObj := uploadFile(t, localFs, path, contents)

	// Upload the same data to the remote Fs also
	remoteObj := uploadFile(t, f, path, contents)

	// Calculate the expected Hash of the remote object
	computedHash, err := f.ComputeHash(ctx, remoteObj.(*Object), localObj, hashType)
	require.NoError(t, err)

	// Test computed hash matches remote object hash
	remoteObjHash, err := remoteObj.(*Object).Object.Hash(ctx, hashType)
	require.NoError(t, err)
	assert.Equal(t, remoteObjHash, computedHash)
}

// testChunkWriter drives the streaming-multipart OpenChunkWriter directly,
// delivering parts out of order, and checks the object decrypts correctly.
// It also checks a misaligned non-final part is rejected.
func testChunkWriter(t *testing.T, f *Fs) {
	ctx := context.Background()
	if f.Features().OpenChunkWriter == nil {
		t.Skip("backing Fs can't stream multipart through crypt")
	}

	const partSize = 2 * blockDataSize // uniform part = 2 crypt blocks
	// 3 full parts plus a partial final part
	plain := []byte(random.String(3*partSize + blockDataSize + 17))
	var parts [][]byte
	for start := 0; start < len(plain); start += partSize {
		end := start + partSize
		if end > len(plain) {
			end = len(plain)
		}
		parts = append(parts, plain[start:end])
	}

	t.Run("OutOfOrder", func(t *testing.T) {
		remote := "chunkwriter_test"
		src := object.NewStaticObjectInfo(remote, time.Now(), int64(len(plain)), true, nil, nil)
		_, w, err := f.OpenChunkWriter(ctx, remote, src)
		require.NoError(t, err)

		// Deliver parts concurrently, with chunk 0 deliberately delayed so
		// the others have to be buffered until the part size is known.
		var wg sync.WaitGroup
		errs := make([]error, len(parts))
		for _, n := range []int{2, 1, 3, 0} {
			wg.Add(1)
			go func(n int) {
				defer wg.Done()
				if n == 0 {
					time.Sleep(10 * time.Millisecond)
				}
				_, errs[n] = w.WriteChunk(ctx, n, bytes.NewReader(parts[n]))
			}(n)
		}
		wg.Wait()
		for _, err := range errs {
			require.NoError(t, err)
		}
		require.NoError(t, w.Close(ctx))

		obj, err := f.NewObject(ctx, remote)
		require.NoError(t, err)
		t.Cleanup(func() { require.NoError(t, obj.Remove(ctx)) })
		assert.Equal(t, int64(len(plain)), obj.Size())
		rc, err := obj.Open(ctx)
		require.NoError(t, err)
		got, err := io.ReadAll(rc)
		require.NoError(t, err)
		require.NoError(t, rc.Close())
		assert.Equal(t, plain, got)
	})

	t.Run("MisalignedPartRejected", func(t *testing.T) {
		remote := "chunkwriter_misaligned"
		src := object.NewStaticObjectInfo(remote, time.Now(), -1, true, nil, nil)
		_, w, err := f.OpenChunkWriter(ctx, remote, src)
		require.NoError(t, err)

		// A later part is buffered, then chunk 0 arrives with a size that
		// isn't a whole number of blocks. Chunk 0 itself is at offset 0, but
		// the buffered part can't be placed, so the upload is rejected when
		// chunk 0 tries to flush it.
		_, err = w.WriteChunk(ctx, 1, bytes.NewReader(make([]byte, partSize)))
		require.NoError(t, err)
		_, err = w.WriteChunk(ctx, 0, bytes.NewReader(make([]byte, blockDataSize+5)))
		require.ErrorIs(t, err, errPartSize)
		require.NoError(t, w.Abort(ctx))
	})

	t.Run("SizeFromTwoNonZeroChunks", func(t *testing.T) {
		// Deliver higher-numbered parts before chunk 0: the size must be
		// learned from the lowest of any two parts seen, without chunk 0.
		remote := "chunkwriter_twochunks"
		src := object.NewStaticObjectInfo(remote, time.Now(), int64(len(plain)), true, nil, nil)
		_, w, err := f.OpenChunkWriter(ctx, remote, src)
		require.NoError(t, err)

		// Part 2 is buffered, then part 3 fixes the size from part 2 (the
		// lowest of the two) - all before parts 1 and 0 arrive.
		for _, n := range []int{2, 3, 1, 0} {
			_, err := w.WriteChunk(ctx, n, bytes.NewReader(parts[n]))
			require.NoError(t, err)
		}
		require.NoError(t, w.Close(ctx))

		obj, err := f.NewObject(ctx, remote)
		require.NoError(t, err)
		t.Cleanup(func() { require.NoError(t, obj.Remove(ctx)) })
		rc, err := obj.Open(ctx)
		require.NoError(t, err)
		got, err := io.ReadAll(rc)
		require.NoError(t, err)
		require.NoError(t, rc.Close())
		assert.Equal(t, plain, got)
	})

	t.Run("MissingPartRejected", func(t *testing.T) {
		// A gap (part 2 never sent) must be detected at Close.
		remote := "chunkwriter_missing"
		src := object.NewStaticObjectInfo(remote, time.Now(), -1, true, nil, nil)
		_, w, err := f.OpenChunkWriter(ctx, remote, src)
		require.NoError(t, err)

		for _, n := range []int{0, 1, 3} {
			_, err := w.WriteChunk(ctx, n, bytes.NewReader(parts[n]))
			require.NoError(t, err)
		}
		require.ErrorIs(t, w.Close(ctx), errPartMissing)
	})

	t.Run("NonUniformPartRejected", func(t *testing.T) {
		// A non-final part bigger than the (uniform) part size overlaps the
		// next part and must be rejected.
		remote := "chunkwriter_nonuniform"
		src := object.NewStaticObjectInfo(remote, time.Now(), -1, true, nil, nil)
		_, w, err := f.OpenChunkWriter(ctx, remote, src)
		require.NoError(t, err)

		// Part 0 sets the size; part 1 is twice as big (still block aligned)
		// so part 2 overlaps it.
		_, err = w.WriteChunk(ctx, 0, bytes.NewReader(parts[0]))
		require.NoError(t, err)
		_, err = w.WriteChunk(ctx, 1, bytes.NewReader(make([]byte, 2*partSize)))
		require.NoError(t, err)
		_, err = w.WriteChunk(ctx, 2, bytes.NewReader(parts[2]))
		require.ErrorIs(t, err, errPartOverlap)
		require.NoError(t, w.Abort(ctx))
	})
}

// InternalTest is called by fstests.Run to extra tests
func (f *Fs) InternalTest(t *testing.T) {
	t.Run("ObjectInfo", func(t *testing.T) { testObjectInfo(t, f, false) })
	t.Run("ObjectInfoWrap", func(t *testing.T) { testObjectInfo(t, f, true) })
	t.Run("ComputeHash", func(t *testing.T) { testComputeHash(t, f) })
	t.Run("ChunkWriter", func(t *testing.T) { testChunkWriter(t, f) })
}
