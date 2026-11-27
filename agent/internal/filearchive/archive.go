// Package filearchive writes and recovers encrypted Vesta Linux file backups.
package filearchive

import (
	"archive/tar"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"path"
	"strings"
	"time"
	"unicode/utf8"

	"filippo.io/age"
)

const (
	Format           = "vesta-file-archive-v1"
	magic            = Format + "\n"
	contentPrefix    = "files/"
	inventoryName    = "vesta-inventory.json"
	maxPath          = 4095
	maxDepth         = 128
	maxInventorySize = 4096
)

// Summary reports regular files, directories below the root, and plaintext file bytes.
type Summary struct {
	Files       int64 `json:"files"`
	Directories int64 `json:"directories"`
	Bytes       int64 `json:"bytes"`
}

type entry struct {
	Name     string `json:"path"`
	Type     string `json:"type"`
	Mode     uint32 `json:"mode"`
	Modified int64  `json:"mtime_unix"`
	Size     int64  `json:"size"`
	SHA256   string `json:"sha256,omitempty"`
}

type inventory struct {
	Summary
	SHA256 string `json:"inventory_sha256"`
}

func (m *inventory) add(digest hash.Hash, item entry) {
	if item.Type == "directory" {
		m.Directories++
	} else {
		m.Files++
		m.Bytes += item.Size
	}
	// These fields are all serializable. Newline separates canonical records.
	record, _ := json.Marshal(item)
	digest.Write(record)
	digest.Write([]byte{'\n'})
}

func (m *inventory) finish(digest hash.Hash) {
	m.SHA256 = hex.EncodeToString(digest.Sum(nil))
}

// ValidateRecipient accepts a single native age X25519 public recipient.
func ValidateRecipient(recipient string) error {
	_, err := age.ParseX25519Recipient(recipient)
	if err != nil {
		return errors.New("expected a native age X25519 public recipient (age1...)")
	}
	return nil
}

// Write streams a full archive of an approved absolute directory to dst. The
// caller owns dst and must discard its output on any error. It must not commit
// an object until Write has returned success. Only regular files and real
// directories below root are included. Symlinks, special files and nested mount
// points fail the backup.
func Write(ctx context.Context, dst io.Writer, root, recipient string) (Summary, error) {
	if err := ctx.Err(); err != nil {
		return Summary{}, err
	}
	key, err := age.ParseX25519Recipient(recipient)
	if err != nil {
		return Summary{}, errors.New("expected a native age X25519 public recipient (age1...)")
	}
	directory, err := openDirectory(root)
	if err != nil {
		return Summary{}, fmt.Errorf("open approved directory: %w", err)
	}
	defer directory.Close()
	encrypted, err := age.Encrypt(contextWriter{ctx, dst}, key)
	if err != nil {
		return Summary{}, err
	}
	if _, err := io.WriteString(encrypted, magic); err != nil {
		return Summary{}, err
	}
	w := archiveWriter{
		ctx: ctx, tar: tar.NewWriter(encrypted), digest: sha256.New(),
		buffer: make([]byte, 64<<10),
	}
	if err := w.walk(directory, "", 0); err != nil {
		return Summary{}, err
	}
	w.inventory.finish(w.digest)
	record, err := json.Marshal(w.inventory)
	if err != nil {
		return Summary{}, err
	}
	if err := w.tar.WriteHeader(&tar.Header{Name: inventoryName, Typeflag: tar.TypeReg, Mode: 0600, Size: int64(len(record)), Format: tar.FormatUSTAR}); err != nil {
		return Summary{}, err
	}
	if _, err := w.tar.Write(record); err != nil {
		return Summary{}, err
	}
	if err := w.tar.Close(); err != nil {
		return Summary{}, err
	}
	if err := encrypted.Close(); err != nil {
		return Summary{}, err
	}
	if err := ctx.Err(); err != nil {
		return Summary{}, err
	}
	return w.inventory.Summary, nil
}

type archiveWriter struct {
	ctx         context.Context
	tar         *tar.Writer
	digest      hash.Hash
	inventory   inventory
	buffer      []byte
	namesBudget int
}

func (w *archiveWriter) header(item entry) error {
	kind := byte(tar.TypeReg)
	if item.Type == "directory" {
		kind = tar.TypeDir
	}
	return w.tar.WriteHeader(&tar.Header{
		Name: contentPrefix + item.Name, Typeflag: kind, Mode: int64(item.Mode),
		Size: item.Size, ModTime: time.Unix(item.Modified, 0), Format: tar.FormatPAX,
	})
}

func validName(name string) bool {
	if len(name) == 0 || len(name) > maxPath || !utf8.ValidString(name) ||
		strings.ContainsAny(name, "\\\x00") || name == "." || name == ".." ||
		strings.HasPrefix(name, "../") || path.IsAbs(name) || path.Clean(name) != name {
		return false
	}
	levels := 0
	for part := range strings.SplitSeq(name, "/") {
		levels++
		if len(part) > 255 || levels > maxDepth {
			return false
		}
	}
	return true
}

type contextReader struct {
	context.Context
	io.Reader
}

func (r contextReader) Read(p []byte) (int, error) {
	if err := r.Err(); err != nil {
		return 0, err
	}
	return r.Reader.Read(p)
}

type contextWriter struct {
	context.Context
	io.Writer
}

func (w contextWriter) Write(p []byte) (int, error) {
	if err := w.Err(); err != nil {
		return 0, err
	}
	return w.Writer.Write(p)
}
