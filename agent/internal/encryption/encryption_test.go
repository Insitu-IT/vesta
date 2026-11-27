package encryption

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
)

func TestEncryptDecryptRoundTrip(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)

	plaintext := make([]byte, 1024*1024) // 1 MiB
	rand.Read(plaintext)

	dir := t.TempDir()
	inputPath := filepath.Join(dir, "test.data")
	encPath := filepath.Join(dir, "test.data.enc")
	decPath := filepath.Join(dir, "test.data.dec")

	os.WriteFile(inputPath, plaintext, 0o644)

	if err := EncryptFile(inputPath, encPath, key); err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	// Verify header
	encData, _ := os.ReadFile(encPath)
	if string(encData[:4]) != Magic {
		t.Errorf("magic: got %q, want %q", string(encData[:4]), Magic)
	}
	if encData[4] != Version {
		t.Errorf("version: got %d, want %d", encData[4], Version)
	}

	if err := DecryptFile(encPath, decPath, key); err != nil {
		t.Fatalf("decrypt: %v", err)
	}

	decData, _ := os.ReadFile(decPath)
	if !bytes.Equal(decData, plaintext) {
		t.Error("decrypted data does not match original")
	}
}

func TestEncryptDecryptLargeFile(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)

	plaintext := make([]byte, 128*1024*1024) // 128 MiB, tests multiple chunks
	rand.Read(plaintext)

	dir := t.TempDir()
	inputPath := filepath.Join(dir, "large.data")
	encPath := filepath.Join(dir, "large.data.enc")
	decPath := filepath.Join(dir, "large.data.dec")

	os.WriteFile(inputPath, plaintext, 0o644)

	if err := EncryptFile(inputPath, encPath, key); err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if err := DecryptFile(encPath, decPath, key); err != nil {
		t.Fatalf("decrypt: %v", err)
	}

	decData, _ := os.ReadFile(decPath)
	if !bytes.Equal(decData, plaintext) {
		t.Error("decrypted data does not match original (large file)")
	}
}

func TestDecryptWrongKey(t *testing.T) {
	key1 := make([]byte, 32)
	key2 := make([]byte, 32)
	rand.Read(key1)
	rand.Read(key2)

	dir := t.TempDir()
	inputPath := filepath.Join(dir, "test.data")
	encPath := filepath.Join(dir, "test.data.enc")
	decPath := filepath.Join(dir, "test.data.dec")

	os.WriteFile(inputPath, []byte("secret data"), 0o644)
	EncryptFile(inputPath, encPath, key1)

	err := DecryptFile(encPath, decPath, key2)
	if err == nil {
		t.Error("expected error decrypting with wrong key")
	}
}

func TestFernetToAESKey(t *testing.T) {
	fernetKey := "cHNldWRvLXJhbmRvbS1mZXJuZXQta2V5LWZvci10ZXN0"
	key, err := FernetToAESKey(fernetKey)
	if err != nil {
		t.Fatalf("FernetToAESKey: %v", err)
	}
	if len(key) != 32 {
		t.Errorf("key length: got %d, want 32", len(key))
	}
}

func TestDeriveKeyAES256GCM(t *testing.T) {
	rawKey := make([]byte, 32)
	rand.Read(rawKey)
	encoded := base64.StdEncoding.EncodeToString(rawKey)

	key, err := DeriveKey(encoded, "aes-256-gcm")
	if err != nil {
		t.Fatalf("DeriveKey: %v", err)
	}
	if !bytes.Equal(key, rawKey) {
		t.Error("derived key should match raw key")
	}
}

func TestDirectoryEncryptDecryptMultiplePatterns(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)

	dir := t.TempDir()

	// Create test files with all supported extensions
	testFiles := []string{"vda.data", "disk.raw", "image.qcow2", "backup.img"}
	origData := map[string][]byte{}
	for _, name := range testFiles {
		data := make([]byte, 512)
		rand.Read(data)
		origData[name] = data
		os.WriteFile(filepath.Join(dir, name), data, 0o644)
	}
	os.WriteFile(filepath.Join(dir, "vmconfig.xml"), []byte("<domain/>"), 0o644)

	if err := EncryptDirectory(context.Background(), dir, key); err != nil {
		t.Fatalf("EncryptDirectory: %v", err)
	}

	// All originals should be gone, encrypted versions should exist
	for _, name := range testFiles {
		if _, err := os.Stat(filepath.Join(dir, name)); err == nil {
			t.Errorf("%s should not exist after encryption", name)
		}
		if _, err := os.Stat(filepath.Join(dir, name+".enc")); err != nil {
			t.Errorf("%s.enc should exist", name)
		}
	}

	// vmconfig.xml untouched
	if _, err := os.Stat(filepath.Join(dir, "vmconfig.xml")); err != nil {
		t.Error("vmconfig.xml should be untouched")
	}

	if err := DecryptDirectory(dir, key); err != nil {
		t.Fatalf("DecryptDirectory: %v", err)
	}

	// All files should be restored with correct content
	for _, name := range testFiles {
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Errorf("%s should exist after decryption: %v", name, err)
			continue
		}
		if !bytes.Equal(data, origData[name]) {
			t.Errorf("%s content mismatch after decrypt", name)
		}
	}
}

func TestDirectoryEncryptDecrypt(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)

	dir := t.TempDir()

	// Create test .data files and track original content
	origData := map[string][]byte{}
	for _, name := range []string{"vda.data", "vdb.data"} {
		data := make([]byte, 1024)
		rand.Read(data)
		origData[name] = data
		os.WriteFile(filepath.Join(dir, name), data, 0o644)
	}
	os.WriteFile(filepath.Join(dir, "vmconfig.xml"), []byte("<domain/>"), 0o644)

	if err := EncryptDirectory(context.Background(), dir, key); err != nil {
		t.Fatalf("EncryptDirectory: %v", err)
	}

	// .data gone, .data.enc present
	for _, name := range []string{"vda.data", "vdb.data"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err == nil {
			t.Errorf("%s should not exist after encryption", name)
		}
		if _, err := os.Stat(filepath.Join(dir, name+".enc")); err != nil {
			t.Errorf("%s.enc should exist", name)
		}
	}

	// vmconfig.xml untouched
	if _, err := os.Stat(filepath.Join(dir, "vmconfig.xml")); err != nil {
		t.Error("vmconfig.xml should be untouched")
	}

	if err := DecryptDirectory(dir, key); err != nil {
		t.Fatalf("DecryptDirectory: %v", err)
	}

	// .data back with correct content
	for _, name := range []string{"vda.data", "vdb.data"} {
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Errorf("%s should exist after decryption", name)
			continue
		}
		if !bytes.Equal(data, origData[name]) {
			t.Errorf("%s content mismatch after decrypt", name)
		}
	}
}

func TestDirectoryEncryptionKeepsOriginalIfOutputAlreadyExists(t *testing.T) {
	root := t.TempDir()
	original := filepath.Join(root, "ordinary.raw")
	encrypted := original + ".enc"
	for file, body := range map[string]string{original: "sample local bytes", encrypted: "existing fixture"} {
		if err := os.WriteFile(file, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := EncryptDirectory(context.Background(), root, make([]byte, 32)); err == nil {
		t.Fatal("existing ciphertext allowed replacement or successful staging")
	}
	for file, expected := range map[string]string{original: "sample local bytes", encrypted: "existing fixture"} {
		got, err := os.ReadFile(file)
		if err != nil || string(got) != expected {
			t.Fatalf("fixture file changed: %v", err)
		}
	}
}
