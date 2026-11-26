package encryption

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"os"
)

const (
	// VNBU file format constants
	Magic      = "VNBU"
	Version    = 0x01
	HeaderSize = 5                // 4 bytes magic + 1 byte version
	ChunkSize  = 64 * 1024 * 1024 // 64 MiB
	NonceSize  = 12
	TagSize    = 16
	// Every supported writer emits at most ChunkSize plaintext bytes. Bound
	// untrusted frame lengths before allocation, including nonce and GCM tag.
	MaxChunkBytes = ChunkSize + NonceSize + TagSize
)

// EncryptFile encrypts a file using AES-256-GCM in the VNBU format.
// Format: VNBU (4b) + version (1b) + chunks
// Each chunk: uint32 big-endian length + 12b nonce + ciphertext + 16b GCM tag
func EncryptFile(inputPath, outputPath string, key []byte) error {
	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("create GCM: %w", err)
	}

	in, err := os.Open(inputPath)
	if err != nil {
		return fmt.Errorf("open input: %w", err)
	}
	defer in.Close()

	out, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("create output: %w", err)
	}
	defer out.Close()

	// Write header
	header := []byte(Magic)
	header = append(header, Version)
	if _, err := out.Write(header); err != nil {
		return fmt.Errorf("write header: %w", err)
	}

	buf := make([]byte, ChunkSize)
	for {
		n, err := io.ReadFull(in, buf)
		if n == 0 {
			if err == io.EOF {
				break
			}
			return fmt.Errorf("read: %w", err)
		}

		plaintext := buf[:n]

		// Generate nonce
		nonce := make([]byte, NonceSize)
		if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
			return fmt.Errorf("generate nonce: %w", err)
		}

		// Encrypt
		ciphertext := gcm.Seal(nil, nonce, plaintext, nil)

		// Write chunk: length (nonce + ciphertext) as uint32 big-endian
		chunkLen := uint32(len(nonce) + len(ciphertext))
		lenBuf := make([]byte, 4)
		binary.BigEndian.PutUint32(lenBuf, chunkLen)

		if _, err := out.Write(lenBuf); err != nil {
			return fmt.Errorf("write chunk length: %w", err)
		}
		if _, err := out.Write(nonce); err != nil {
			return fmt.Errorf("write nonce: %w", err)
		}
		if _, err := out.Write(ciphertext); err != nil {
			return fmt.Errorf("write ciphertext: %w", err)
		}

		if err == io.EOF || err == io.ErrUnexpectedEOF {
			break
		}
	}

	return nil
}

// DecryptFile decrypts a VNBU-format encrypted file.
func DecryptFile(inputPath, outputPath string, key []byte) error {
	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("create GCM: %w", err)
	}

	in, err := os.Open(inputPath)
	if err != nil {
		return fmt.Errorf("open input: %w", err)
	}
	defer in.Close()

	// Read and verify header
	header := make([]byte, HeaderSize)
	if _, err := io.ReadFull(in, header); err != nil {
		return fmt.Errorf("read header: %w", err)
	}
	if string(header[:4]) != Magic {
		return fmt.Errorf("invalid magic: %q", string(header[:4]))
	}
	if header[4] != Version {
		return fmt.Errorf("unsupported version: %d", header[4])
	}

	out, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("create output: %w", err)
	}
	defer out.Close()

	lenBuf := make([]byte, 4)
	for {
		// Read chunk length
		_, err := io.ReadFull(in, lenBuf)
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("read chunk length: %w", err)
		}

		chunkLen := binary.BigEndian.Uint32(lenBuf)
		if chunkLen < uint32(NonceSize+TagSize) {
			return fmt.Errorf("chunk too small: %d", chunkLen)
		}
		if chunkLen > MaxChunkBytes {
			return fmt.Errorf("chunk exceeds supported size: %d", chunkLen)
		}

		// Read chunk data (nonce + ciphertext)
		chunkData := make([]byte, chunkLen)
		if _, err := io.ReadFull(in, chunkData); err != nil {
			return fmt.Errorf("read chunk: %w", err)
		}

		nonce := chunkData[:NonceSize]
		ciphertext := chunkData[NonceSize:]

		// Decrypt
		plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
		if err != nil {
			return fmt.Errorf("decrypt chunk: %w", err)
		}

		if _, err := out.Write(plaintext); err != nil {
			return fmt.Errorf("write plaintext: %w", err)
		}
	}

	return nil
}
