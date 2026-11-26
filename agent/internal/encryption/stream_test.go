package encryption

import (
	"bytes"
	"crypto/rand"
	"io"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func TestEncryptStreamVNBUHeader(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)

	input := bytes.NewReader([]byte("hello world"))
	var output bytes.Buffer

	if err := EncryptStream(input, &output, key); err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	data := output.Bytes()
	if len(data) < HeaderSize {
		t.Fatalf("output too short: %d bytes", len(data))
	}
	if string(data[:4]) != Magic {
		t.Fatalf("expected magic %q, got %q", Magic, string(data[:4]))
	}
	if data[4] != Version {
		t.Fatalf("expected version %d, got %d", Version, data[4])
	}
}

func TestEncryptStreamRoundTrip(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)

	// Test data: 150KB (spans multiple chunks if chunk size were small, single chunk with 64MB)
	original := make([]byte, 150*1024)
	rand.Read(original)

	// Encrypt via stream
	var encrypted bytes.Buffer
	if err := EncryptStream(bytes.NewReader(original), &encrypted, key); err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	// Write encrypted data to temp file for DecryptFile
	tmpDir := t.TempDir()
	encPath := filepath.Join(tmpDir, "test.vnbu")
	decPath := filepath.Join(tmpDir, "test.raw")

	if err := os.WriteFile(encPath, encrypted.Bytes(), 0644); err != nil {
		t.Fatalf("write encrypted: %v", err)
	}

	// Decrypt using existing DecryptFile
	if err := DecryptFile(encPath, decPath, key); err != nil {
		t.Fatalf("decrypt: %v", err)
	}

	decrypted, err := os.ReadFile(decPath)
	if err != nil {
		t.Fatalf("read decrypted: %v", err)
	}

	if !bytes.Equal(original, decrypted) {
		t.Fatalf("roundtrip mismatch: original %d bytes, decrypted %d bytes", len(original), len(decrypted))
	}
}

func TestEncryptStreamChunkedRoundTrip(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	original := make([]byte, 150*1024)
	if _, err := rand.Read(original); err != nil {
		t.Fatal(err)
	}

	var encrypted bytes.Buffer
	if err := EncryptStreamChunked(bytes.NewReader(original), &encrypted, key, 32*1024); err != nil {
		t.Fatal(err)
	}
	tmpDir := t.TempDir()
	encPath := filepath.Join(tmpDir, "chunked.vnbu")
	decPath := filepath.Join(tmpDir, "chunked.raw")
	if err := os.WriteFile(encPath, encrypted.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	if err := DecryptFile(encPath, decPath, key); err != nil {
		t.Fatal(err)
	}
	decrypted, err := os.ReadFile(decPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(original, decrypted) {
		t.Fatalf("roundtrip mismatch: original %d bytes, decrypted %d bytes", len(original), len(decrypted))
	}
}

func TestEncryptStreamEmpty(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)

	var output bytes.Buffer
	if err := EncryptStream(bytes.NewReader(nil), &output, key); err != nil {
		t.Fatalf("encrypt empty: %v", err)
	}

	// Should have header only
	if output.Len() != HeaderSize {
		t.Fatalf("expected %d bytes (header only), got %d", HeaderSize, output.Len())
	}
}

func TestCountingReader(t *testing.T) {
	data := make([]byte, 1024)
	rand.Read(data)

	var cbTotal int64
	cr := NewCountingReader(bytes.NewReader(data), 0, func(total int64) {
		cbTotal = total
	})

	buf := make([]byte, 256)
	totalRead := 0
	for {
		n, err := cr.Read(buf)
		totalRead += n
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("read error: %v", err)
		}
	}

	if totalRead != 1024 {
		t.Fatalf("expected 1024 bytes read, got %d", totalRead)
	}
	if cr.BytesRead.Load() != 1024 {
		t.Fatalf("expected BytesRead=1024, got %d", cr.BytesRead.Load())
	}
	if cbTotal != 1024 {
		t.Fatalf("expected callback total=1024, got %d", cbTotal)
	}
}

func TestCountingReaderStallDetection(t *testing.T) {
	// Create a reader that blocks after first read
	pr, pw := io.Pipe()
	go func() {
		pw.Write([]byte("initial"))
		// Then stall — don't write more
		time.Sleep(200 * time.Millisecond)
		pw.Close()
	}()

	cr := NewCountingReader(pr, 50*time.Millisecond, nil)

	buf := make([]byte, 256)
	// First read succeeds
	_, err := cr.Read(buf)
	if err != nil {
		t.Fatalf("first read should succeed: %v", err)
	}

	// Wait for stall timeout
	time.Sleep(60 * time.Millisecond)

	// Next read should detect stall
	_, err = cr.Read(buf)
	if err == nil {
		t.Fatal("expected stall error")
	}
}

func TestCountingReaderNoStallWithoutTimeout(t *testing.T) {
	cr := NewCountingReader(bytes.NewReader([]byte("data")), 0, nil)
	buf := make([]byte, 10)
	n, err := cr.Read(buf)
	if err != nil || n != 4 {
		t.Fatalf("expected 4 bytes, got %d, err: %v", n, err)
	}

	// Verify atomic operations
	var v atomic.Int64
	v.Add(1)
	if v.Load() != 1 {
		t.Fatal("atomic sanity check failed")
	}
}
