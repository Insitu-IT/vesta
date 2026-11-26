package storagerestore

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"sync"

	"vnbui/agent/internal/encryption"
	"vnbui/agent/internal/models"
)

const copyBufferBytes = 128 * 1024
const transactionChunkBytes = 5242880

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r *contextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(p)
}

type measuredReader struct {
	reader io.Reader
	hash   hash.Hash
	n      int64
}

func measure(reader io.Reader, expected int64) *measuredReader {
	return &measuredReader{reader: io.LimitReader(reader, expected+1), hash: sha256.New()}
}

func (r *measuredReader) Read(p []byte) (int, error) {
	n, err := r.reader.Read(p)
	r.n += int64(n)
	_, _ = r.hash.Write(p[:n])
	return n, err
}

func (r *measuredReader) verify(length int64, digest string) error {
	var extra [1]byte
	n, err := io.ReadFull(r, extra[:])
	if n != 0 || err != io.EOF || r.n != length || hex.EncodeToString(r.hash.Sum(nil)) != digest {
		return errors.New("object length or SHA256 does not match receipt")
	}
	return nil
}

func openObject(ctx context.Context, target models.StorageTarget, obj models.StorageObjectReceipt, open ObjectOpener) (*measuredReader, func() error, error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	body, err := open(ctx, target, obj)
	if err != nil {
		return nil, nil, err
	}
	if body == nil {
		return nil, nil, errors.New("object reader returned nil body")
	}
	var once sync.Once
	var closeErr error
	closeBody := func() { once.Do(func() { closeErr = body.Close() }) }
	stop := context.AfterFunc(ctx, closeBody)
	close := func() error {
		stop()
		closeBody()
		return closeErr
	}
	return measure(&contextReader{ctx: ctx, reader: body}, obj.CiphertextBytes), close, nil
}

func applyPayload(ctx context.Context, member validatedMember, obj models.StorageObjectReceipt, manifest volumeManifest, file *os.File, key []byte, open ObjectOpener) (err error) {
	ciphertext, close, err := openObject(ctx, member.Request.Plan.Target, obj, open)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, close()) }()
	var source io.Reader = ciphertext
	if *manifest.Encrypted {
		source, err = decryptReader(ciphertext, key)
		if err != nil {
			return err
		}
	}
	plaintext := measure(source, obj.PlaintextBytes)
	buffer := make([]byte, copyBufferBytes)
	zeroes := make([]byte, copyBufferBytes)
	for _, extent := range manifest.StoredExtents {
		if err := ctx.Err(); err != nil {
			return err
		}
		if _, err := file.Seek(int64(extent.DiskOffset), io.SeekStart); err != nil {
			return err
		}
		if extent.ZeroFill {
			// Incremental zeroes must overwrite previous nonzero data. Merely
			// seeking (or creating a sparse hole only at the end) loses deletes.
			remaining := int64(extent.Length)
			for remaining > 0 {
				if err := ctx.Err(); err != nil {
					return err
				}
				n := min(remaining, int64(len(zeroes)))
				written, err := file.Write(zeroes[:n])
				if err != nil {
					return err
				}
				if int64(written) != n {
					return io.ErrShortWrite
				}
				remaining -= n
			}
		} else {
			n, err := io.CopyBuffer(file, io.LimitReader(plaintext, int64(extent.Length)), buffer)
			if err != nil {
				return err
			}
			if n != int64(extent.Length) {
				return io.ErrUnexpectedEOF
			}
		}
	}
	if err := plaintext.verify(obj.PlaintextBytes, obj.PlaintextSHA256); err != nil {
		return fmt.Errorf("plaintext: %w", err)
	}
	if err := ciphertext.verify(obj.CiphertextBytes, obj.CiphertextSHA256); err != nil {
		return fmt.Errorf("ciphertext: %w", err)
	}
	return ctx.Err()
}

// vnBUReader uses the existing VNBU v1 wire format, with the transaction
// profile's fixed 5-MiB ceiling. Untrusted chunk lengths never size an unbounded
// allocation. Authentication succeeds before any bytes from a chunk are exposed.
type vnBUReader struct {
	reader io.Reader
	gcm    cipher.AEAD
	chunk  []byte
	plain  []byte
	ended  bool
}

func decryptReader(reader io.Reader, key []byte) (io.Reader, error) {
	if len(key) != 32 {
		return nil, errors.New("VNBU restore requires a 32-byte DEK")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	var header [encryption.HeaderSize]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return nil, fmt.Errorf("VNBU header: %w", err)
	}
	if string(header[:4]) != encryption.Magic || header[4] != encryption.Version {
		return nil, errors.New("unsupported VNBU header")
	}
	return &vnBUReader{reader: reader, gcm: gcm}, nil
}

func (r *vnBUReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if len(r.plain) == 0 {
		if r.ended {
			return 0, io.EOF
		}
		var length [4]byte
		if _, err := io.ReadFull(r.reader, length[:]); err != nil {
			if err == io.EOF {
				r.ended = true
			}
			return 0, err
		}
		n := binary.BigEndian.Uint32(length[:])
		if n <= encryption.NonceSize+encryption.TagSize || n > transactionChunkBytes+encryption.NonceSize+encryption.TagSize {
			return 0, errors.New("VNBU chunk is outside the supported transaction bounds")
		}
		if cap(r.chunk) < int(n) {
			r.chunk = make([]byte, n)
		} else {
			r.chunk = r.chunk[:n]
		}
		if _, err := io.ReadFull(r.reader, r.chunk); err != nil {
			return 0, err
		}
		plain, err := r.gcm.Open(r.chunk[encryption.NonceSize:encryption.NonceSize], r.chunk[:encryption.NonceSize], r.chunk[encryption.NonceSize:], nil)
		if err != nil {
			return 0, fmt.Errorf("VNBU chunk authentication: %w", err)
		}
		r.plain = plain
	}
	n := copy(p, r.plain)
	r.plain = r.plain[n:]
	return n, nil
}
