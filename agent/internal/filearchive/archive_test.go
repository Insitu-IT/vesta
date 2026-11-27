package filearchive

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
	"golang.org/x/sys/unix"
)

func fixture(t *testing.T) ([]byte, *Identity, string) {
	t.Helper()
	base := t.TempDir()
	tree := filepath.Join(base, "source")
	if err := os.MkdirAll(filepath.Join(tree, "a", "empty"), 0750); err != nil {
		t.Fatal(err)
	}
	longName := strings.Repeat("m", 105) + "-é"
	original := bytes.Repeat([]byte("private test content\x00"), 9000)
	file := filepath.Join(tree, "a", longName)
	if err := os.WriteFile(file, original, 0640); err != nil {
		t.Fatal(err)
	}
	stamp := time.Unix(1_700_000_022, 0)
	if err := os.Chtimes(file, stamp, stamp); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tree, "b"), []byte("second file"), 0600); err != nil {
		t.Fatal(err)
	}
	identityPath := filepath.Join(base, "identity")
	recipient, err := CreateIdentity(identityPath)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := LoadIdentity(identityPath)
	if err != nil || identity.Recipient() != recipient {
		t.Fatalf("load identity: %v", err)
	}
	var out bytes.Buffer
	summary, err := Write(context.Background(), &out, tree, recipient)
	if err != nil || summary != (Summary{Files: 2, Directories: 2, Bytes: int64(len(original) + len("second file"))}) {
		t.Fatalf("write: %+v %v", summary, err)
	}
	if bytes.Contains(out.Bytes(), []byte(longName)) {
		t.Fatal("filename visible in ciphertext")
	}
	return out.Bytes(), identity, longName
}

func TestFileArchiveRoundTrip(t *testing.T) {
	ciphertext, identity, longName := fixture(t)
	digest := sha256.Sum256(ciphertext)
	opts := ReadOptions{Identity: identity, ExpectedSHA256: hex.EncodeToString(digest[:])}
	var listed bytes.Buffer
	ctx := context.Background()
	summary, err := List(ctx, bytes.NewReader(ciphertext), opts, &listed)
	if err != nil {
		t.Fatal(err)
	}
	var listing struct {
		Format  string
		Entries []entry
		Summary Summary
	}
	if err := json.Unmarshal(listed.Bytes(), &listing); err != nil {
		t.Fatal(err)
	}
	if listing.Format != Format || summary != listing.Summary || len(listing.Entries) != 4 ||
		listing.Entries[2].Name != "a/"+longName || listing.Entries[2].SHA256 == "" {
		// Siblings are sorted by name, so "empty" precedes the long file name.
		t.Fatalf("unexpected listing: %+v", listing)
	}
	output := filepath.Join(t.TempDir(), "restore")
	result, err := Extract(ctx, bytes.NewReader(ciphertext), opts, output, []string{"a"})
	if err != nil || result != summary {
		t.Fatalf("extract: %+v %v", result, err)
	}
	restored := filepath.Join(output, "a", longName)
	got, err := os.ReadFile(restored)
	if err != nil || !bytes.Equal(got, bytes.Repeat([]byte("private test content\x00"), 9000)) {
		t.Fatalf("read restored file: %v", err)
	}
	info, err := os.Stat(restored)
	if err != nil || info.Mode().Perm() != 0640 || info.ModTime().Unix() != 1_700_000_022 {
		t.Fatalf("restored metadata: %v %v", info, err)
	}
	if _, err := os.Stat(filepath.Join(output, "a", "empty")); err != nil {
		t.Fatalf("empty directory not restored: %v", err)
	}
	if _, err := os.Stat(filepath.Join(output, "b")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unselected file exists: %v", err)
	}
	if _, err := Extract(ctx, bytes.NewReader(ciphertext), opts, output, nil); err == nil {
		t.Fatal("existing restore directory was accepted")
	}
	missing := filepath.Join(filepath.Dir(output), "missing")
	if _, err := Extract(ctx, bytes.NewReader(ciphertext), opts, missing, []string{"not-in-archive"}); err == nil {
		t.Fatal("unknown selection was accepted")
	}
	if _, err := os.Stat(missing); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed selection was published: %v", err)
	}
}

func TestBadCiphertextNeverPublishes(t *testing.T) {
	ciphertext, identity, _ := fixture(t)
	wrong, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	altered := bytes.Clone(ciphertext)
	altered[len(altered)-1] ^= 0xff
	extra := append(bytes.Clone(ciphertext), make([]byte, 29)...)
	invalidDigest := strings.Repeat("0", 64)
	for _, tt := range []struct {
		name string
		data []byte
		opts ReadOptions
	}{
		{"wrong-identity", ciphertext, ReadOptions{Identity: &Identity{key: wrong}}},
		{"wrong-digest", ciphertext, ReadOptions{Identity: identity, ExpectedSHA256: invalidDigest}},
		{"truncated", ciphertext[:len(ciphertext)-1], ReadOptions{Identity: identity}},
		{"modified-final-byte", altered, ReadOptions{Identity: identity}},
		{"appended", extra, ReadOptions{Identity: identity}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var listing bytes.Buffer
			ctx := context.Background()
			if _, err := List(ctx, bytes.NewReader(tt.data), tt.opts, &listing); err == nil || listing.Len() != 0 {
				t.Fatalf("invalid archive listed: output=%d bytes err=%v", listing.Len(), err)
			}
			parent := t.TempDir()
			output := filepath.Join(parent, "output")
			if _, err := Extract(ctx, bytes.NewReader(tt.data), tt.opts, output, nil); err == nil {
				t.Fatal("invalid archive was extracted")
			}
			entries, err := os.ReadDir(parent)
			if err != nil || len(entries) != 0 {
				t.Fatalf("invalid archive wrote files: %v %v", entries, err)
			}
		})
	}
}

func TestAuthenticatedInvalidArchiveRejected(t *testing.T) {
	key, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		name        string
		kind        byte
		destination string
		members     []string
		footer      string
	}{
		{"traversal", tar.TypeReg, "", []string{"files/../outside"}, ""},
		{"absolute-path", tar.TypeReg, "", []string{"files//outside"}, ""},
		{"symlink", tar.TypeSymlink, "/outside", []string{"files/a"}, ""},
		{"hardlink", tar.TypeLink, "/outside", []string{"files/a"}, ""},
		{"fifo", tar.TypeFifo, "", []string{"files/a"}, ""},
		{"missing-parent", tar.TypeReg, "", []string{"files/a/b"}, ""},
		{"duplicate", tar.TypeReg, "", []string{"files/a", "files/a"}, ""},
		{"reordered", tar.TypeReg, "", []string{"files/b", "files/a"}, ""},
		{"inventory-mismatch", tar.TypeReg, "", []string{"files/a"}, "{}"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var encrypted bytes.Buffer
			enc, err := age.Encrypt(&encrypted, key.Recipient())
			if err != nil {
				t.Fatal(err)
			}
			if _, err := io.WriteString(enc, magic); err != nil {
				t.Fatal(err)
			}
			w := tar.NewWriter(enc)
			for _, name := range tt.members {
				if err := w.WriteHeader(&tar.Header{Name: name, Typeflag: tt.kind, Linkname: tt.destination, Mode: 0600, Format: tar.FormatUSTAR}); err != nil {
					t.Fatal(err)
				}
			}
			if tt.footer != "" {
				if err := w.WriteHeader(&tar.Header{Name: inventoryName, Typeflag: tar.TypeReg, Mode: 0600, Size: int64(len(tt.footer)), Format: tar.FormatUSTAR}); err != nil {
					t.Fatal(err)
				}
				if _, err := io.WriteString(w, tt.footer); err != nil {
					t.Fatal(err)
				}
			}
			if err := w.Close(); err != nil {
				t.Fatal(err)
			}
			if err := enc.Close(); err != nil {
				t.Fatal(err)
			}
			if _, err := Verify(context.Background(), &encrypted, ReadOptions{Identity: &Identity{key: key}}); err == nil {
				t.Fatal("accepted invalid archive with valid age encryption")
			}
		})
	}
}

func TestSourceRejectsSymlinkAndSpecialFiles(t *testing.T) {
	key, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	target := t.TempDir()
	root := t.TempDir()
	link := filepath.Join(root, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{root, link} {
		if _, err := Write(context.Background(), io.Discard, path, key.Recipient().String()); err == nil {
			t.Fatalf("accepted symlink on source path %q", path)
		}
	}
	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mkfifo(filepath.Join(root, "named-pipe"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Write(context.Background(), io.Discard, root, key.Recipient().String()); err == nil {
		t.Fatal("accepted named pipe in source tree")
	}
}
