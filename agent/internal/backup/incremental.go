package backup

import (
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
)

// symlinkParentMetadata symlinks files from the parent backup directory
// into the output directory so virtnbdbackup can find the previous backup's
// checkpoints, config, and data files when running an incremental backup.
//
// virtnbdbackup expects all chain data in a single directory. Since we use
// per-backup-ID directories, we symlink the parent's files. Symlinks cost
// no disk space and are cleaned up by cleanupParentSymlinks before S3 upload.
//
// Directories (e.g. checkpoints/) are created as real dirs with symlinked
// contents, so virtnbdbackup can write NEW files into them (new checkpoint
// XMLs) without modifying the parent backup.
func symlinkParentMetadata(parentPath, outputPath string) error {
	if _, err := os.Stat(parentPath); err != nil {
		return fmt.Errorf("parent backup path not found: %s", parentPath)
	}

	entries, err := os.ReadDir(parentPath)
	if err != nil {
		return fmt.Errorf("read parent dir: %w", err)
	}

	for _, entry := range entries {
		name := entry.Name()
		src := filepath.Join(parentPath, name)

		if entry.IsDir() {
			// Create real directory, symlink contents individually.
			// virtnbdbackup writes new checkpoints here — must be a real dir
			// so new files land in the output dir, not the parent's.
			if err := symlinkDirContents(src, filepath.Join(outputPath, name)); err != nil {
				return fmt.Errorf("symlink dir %s: %w", name, err)
			}
			continue
		}

		dstName := name
		// Encrypted data files (.data.enc) — symlink without .enc suffix
		// so virtnbdbackup recognizes the original backup file name.
		if strings.HasSuffix(name, ".data.enc") {
			dstName = strings.TrimSuffix(name, ".enc")
		}

		dst := filepath.Join(outputPath, dstName)
		if _, err := os.Lstat(dst); err == nil {
			continue // don't overwrite existing
		}

		if err := os.Symlink(src, dst); err != nil {
			return fmt.Errorf("symlink %s: %w", name, err)
		}
		slog.Debug("symlinked parent file", "name", dstName, "src", src)
	}

	slog.Info("prepared incremental backup", "parent", parentPath, "output", outputPath)
	return nil
}

// symlinkDirContents creates a real directory at dst and symlinks each file
// from src into it.
func symlinkDirContents(srcDir, dstDir string) error {
	if err := os.MkdirAll(dstDir, 0755); err != nil {
		return fmt.Errorf("create dir: %w", err)
	}

	entries, err := os.ReadDir(srcDir)
	if err != nil {
		return fmt.Errorf("read dir: %w", err)
	}

	for _, entry := range entries {
		src := filepath.Join(srcDir, entry.Name())
		dst := filepath.Join(dstDir, entry.Name())

		if _, err := os.Lstat(dst); err == nil {
			continue
		}

		if err := os.Symlink(src, dst); err != nil {
			return fmt.Errorf("symlink %s: %w", entry.Name(), err)
		}
		slog.Debug("symlinked parent dir entry", "dir", filepath.Base(dstDir), "name", entry.Name())
	}
	return nil
}

// cleanupParentSymlinks removes symlinks from the output directory tree.
// Called after backup completes to keep only real files for S3 upload.
// Recurses into real directories to clean symlinks inside them (e.g.
// checkpoints/ is a real dir with symlinked parent checkpoint XMLs).
func cleanupParentSymlinks(outputPath string) error {
	return filepath.WalkDir(outputPath, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.Type()&os.ModeSymlink == 0 {
			return nil
		}
		if path == outputPath {
			return fmt.Errorf("backup staging root is a symlink")
		}
		return os.Remove(path)
	})
}
