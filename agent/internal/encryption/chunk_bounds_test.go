package encryption

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDecryptFileRejectsOversizedChunkBeforePayloadRead(t *testing.T) {
	for _, size := range []uint32{MaxChunkBytes + 1, 1 << 31, ^uint32(0)} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			dir := t.TempDir()
			input, output := filepath.Join(dir, "bad.enc"), filepath.Join(dir, "output.raw")
			frame := append([]byte(Magic), Version)
			frame = binary.BigEndian.AppendUint32(frame, size)
			if err := os.WriteFile(input, frame, 0o600); err != nil {
				t.Fatal(err)
			}
			err := DecryptFile(input, output, make([]byte, 32))
			// A truncated-payload error would mean we accepted the attacker size
			// and attempted its allocation/read instead of enforcing the bound.
			if err == nil || !strings.Contains(err.Error(), "chunk exceeds supported size") {
				t.Fatalf("size %d: %v", size, err)
			}
			if data, err := os.ReadFile(output); err != nil || len(data) != 0 {
				t.Fatalf("malformed chunk exposed plaintext: %d bytes, %v", len(data), err)
			}
			if data, err := os.ReadFile(input); err != nil || !bytes.Equal(data, frame) {
				t.Fatalf("encrypted source changed: %v", err)
			}
		})
	}
}

func TestEncryptStreamRejectsUnsupportedChunkBeforeIO(t *testing.T) {
	for _, size := range []int{-1, 0, ChunkSize + 1, int(^uint(0) >> 1)} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			input := bytes.NewReader([]byte("unchanged"))
			var output bytes.Buffer
			if err := EncryptStreamChunked(input, &output, make([]byte, 32), size); err == nil {
				t.Fatalf("unsupported size %d accepted", size)
			}
			if input.Len() != len("unchanged") || output.Len() != 0 {
				t.Fatal("invalid chunk size consumed input or emitted a partial stream")
			}
		})
	}
}
