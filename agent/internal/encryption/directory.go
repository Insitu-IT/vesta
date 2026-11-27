package encryption

import (
	"context"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
)

// encryptableExtensions are file extensions that should be encrypted.
// Matches Python agent: *.data, *.raw, *.qcow2, *.img
var encryptableExtensions = []string{".data", ".raw", ".qcow2", ".img"}

// isEncryptable returns true if the filename has an encryptable extension.
func isEncryptable(name string) bool {
	for _, ext := range encryptableExtensions {
		if strings.HasSuffix(name, ext) {
			return true
		}
	}
	return false
}

// isEncrypted returns true if the filename is an encrypted version of an encryptable file.
func isEncrypted(name string) bool {
	for _, ext := range encryptableExtensions {
		if strings.HasSuffix(name, ext+".enc") {
			return true
		}
	}
	return false
}

// EncryptDirectory encrypts all encryptable files in a directory (*.data, *.raw, *.qcow2, *.img).
// Respects context cancellation between files.
func EncryptDirectory(ctx context.Context, dir string, key []byte) error {
	var pending []string
	if err := filepath.WalkDir(dir, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		if !entry.Type().IsRegular() {
			return fmt.Errorf("non-regular staging entry: %s", entry.Name())
		}
		if isEncryptable(entry.Name()) {
			pending = append(pending, path)
		}
		return nil
	}); err != nil {
		return fmt.Errorf("scan encryption stage: %w", err)
	}
	if len(pending) == 0 {
		return fmt.Errorf("no plaintext backup files to encrypt")
	}

	for _, inputPath := range pending {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := EncryptFile(inputPath, inputPath+".enc", key); err != nil {
			return fmt.Errorf("encrypt %s: %w", filepath.Base(inputPath), err)
		}
		if err := os.Remove(inputPath); err != nil {
			return fmt.Errorf("remove plaintext %s: %w", filepath.Base(inputPath), err)
		}
	}
	return ctx.Err()
}

// DecryptFiles decrypts only the named files (if they have .enc suffix) in a directory.
// Used for chain restores where each member may have a different encryption key.
func DecryptFiles(dir string, key []byte, files []string) error {
	for _, name := range files {
		if !isEncrypted(name) {
			continue
		}

		inputPath := filepath.Join(dir, name)
		outputPath := strings.TrimSuffix(inputPath, ".enc")

		if err := DecryptFile(inputPath, outputPath, key); err != nil {
			return fmt.Errorf("decrypt %s: %w", name, err)
		}

		if err := os.Remove(inputPath); err != nil {
			slog.Warn("remove encrypted file", "file", inputPath, "error", err)
		}

		slog.Debug("decrypted", "file", name)
	}

	return nil
}

// DecryptDirectory decrypts all encrypted files in a directory.
func DecryptDirectory(dir string, key []byte) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("read dir: %w", err)
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if !isEncrypted(entry.Name()) {
			continue
		}

		inputPath := filepath.Join(dir, entry.Name())
		outputPath := strings.TrimSuffix(inputPath, ".enc")

		if err := DecryptFile(inputPath, outputPath, key); err != nil {
			return fmt.Errorf("decrypt %s: %w", entry.Name(), err)
		}

		// Remove encrypted file
		if err := os.Remove(inputPath); err != nil {
			slog.Warn("remove encrypted file", "file", inputPath, "error", err)
		}

		slog.Debug("decrypted", "file", entry.Name())
	}

	return nil
}
