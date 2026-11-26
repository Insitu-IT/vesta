package encryption

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"sync/atomic"
	"time"
)

// EncryptStream reads from r, encrypts in VNBU format (AES-256-GCM chunked),
// and writes to w. The key must be exactly 32 bytes.
// Format: "VNBU" (4b) + version (1b) + chunks
// Each chunk: uint32 big-endian length + 12b nonce + ciphertext + 16b GCM tag
func EncryptStream(r io.Reader, w io.Writer, key []byte) error {
	return EncryptStreamChunked(r, w, key, ChunkSize)
}

// EncryptStreamChunked writes the same VNBU stream format with a caller-sized
// plaintext chunk. Chunk boundaries are encoded in the format, so readers do
// not need to know the writer's chosen size.
func EncryptStreamChunked(r io.Reader, w io.Writer, key []byte, chunkSize int) error {
	if chunkSize <= 0 {
		return fmt.Errorf("chunk size must be positive")
	}
	if chunkSize > ChunkSize {
		return fmt.Errorf("chunk size exceeds supported maximum: %d", chunkSize)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("create cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("create GCM: %w", err)
	}

	// Write VNBU header
	if _, err := w.Write([]byte(Magic)); err != nil {
		return fmt.Errorf("write header magic: %w", err)
	}
	if _, err := w.Write([]byte{Version}); err != nil {
		return fmt.Errorf("write header version: %w", err)
	}

	buf := make([]byte, chunkSize)
	for {
		n, readErr := io.ReadFull(r, buf)
		if n > 0 {
			nonce := make([]byte, NonceSize)
			if _, err := rand.Read(nonce); err != nil {
				return fmt.Errorf("generate nonce: %w", err)
			}

			ciphertext := gcm.Seal(nil, nonce, buf[:n], nil)

			// Chunk length includes nonce + ciphertext (matching EncryptFile format)
			lenBuf := make([]byte, 4)
			binary.BigEndian.PutUint32(lenBuf, uint32(len(nonce)+len(ciphertext)))
			if _, err := w.Write(lenBuf); err != nil {
				return fmt.Errorf("write chunk length: %w", err)
			}
			if _, err := w.Write(nonce); err != nil {
				return fmt.Errorf("write nonce: %w", err)
			}
			if _, err := w.Write(ciphertext); err != nil {
				return fmt.Errorf("write ciphertext: %w", err)
			}
		}

		if readErr == io.EOF || readErr == io.ErrUnexpectedEOF {
			return nil
		}
		if readErr != nil {
			return fmt.Errorf("read source: %w", readErr)
		}
	}
}

// CountingReader wraps an io.Reader to track bytes read with stall detection.
type CountingReader struct {
	R            io.Reader
	BytesRead    atomic.Int64
	OnProgress   func(int64)
	LastProgress atomic.Value // stores time.Time
	StallTimeout time.Duration
}

// NewCountingReader creates a CountingReader with stall detection.
func NewCountingReader(r io.Reader, stallTimeout time.Duration, onProgress func(int64)) *CountingReader {
	cr := &CountingReader{
		R:            r,
		OnProgress:   onProgress,
		StallTimeout: stallTimeout,
	}
	cr.LastProgress.Store(time.Now())
	return cr
}

func (cr *CountingReader) Read(p []byte) (int, error) {
	// Check stall before reading
	if cr.StallTimeout > 0 {
		last := cr.LastProgress.Load().(time.Time)
		if time.Since(last) > cr.StallTimeout {
			return 0, fmt.Errorf("stalled: no data for %v", cr.StallTimeout)
		}
	}

	n, err := cr.R.Read(p)
	if n > 0 {
		total := cr.BytesRead.Add(int64(n))
		cr.LastProgress.Store(time.Now())
		if cr.OnProgress != nil {
			cr.OnProgress(total)
		}
	}
	return n, err
}
