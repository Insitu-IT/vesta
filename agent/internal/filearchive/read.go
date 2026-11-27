package filearchive

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"strings"

	"filippo.io/age"
)

// ReadOptions identifies the recovery key. ExpectedSHA256 can pin the exact
// ciphertext recorded in a trusted backup receipt. A public encryption
// recipient can be used by anyone, so verification alone does not identify
// the producer.
type ReadOptions struct {
	Identity       *Identity
	ExpectedSHA256 string
}

// Verify reads every member, checks the inventory, and authenticates the end
// of the age stream before returning success.
func Verify(ctx context.Context, src io.Reader, options ReadOptions) (Summary, error) {
	return scan(ctx, src, options, scanVisitors{})
}

// List writes an inventory as JSON only after verifying the entire archive.
// The entry list is spooled to a private temporary file to bound memory use.
func List(ctx context.Context, src io.Reader, options ReadOptions, dst io.Writer) (Summary, error) {
	staged, err := anonymousTemp()
	if err != nil {
		return Summary{}, err
	}
	defer staged.Close()
	first := true
	result, err := scan(ctx, src, options, scanVisitors{observe: func(item entry) error {
		if !first {
			if _, err := io.WriteString(staged, ",\n"); err != nil {
				return err
			}
		}
		first = false
		record, err := json.Marshal(item)
		if err != nil {
			return err
		}
		_, err = staged.Write(record)
		return err
	}})
	if err != nil {
		return Summary{}, err
	}
	if _, err := staged.Seek(0, io.SeekStart); err != nil {
		return Summary{}, err
	}
	output := contextWriter{ctx, dst}
	if _, err := fmt.Fprintf(output, "{\"format\":%q,\"entries\":[", Format); err != nil {
		return Summary{}, err
	}
	if _, err := io.Copy(output, staged); err != nil {
		return Summary{}, err
	}
	summary, err := json.Marshal(result)
	if err != nil {
		return Summary{}, err
	}
	if _, err := fmt.Fprintf(output, "],\"summary\":%s}\n", summary); err != nil {
		return Summary{}, err
	}
	return result, nil
}

type scanVisitors struct {
	consume func(entry, io.Reader) error
	observe func(entry) error
}

type directoryFrame struct {
	name string
	last string
}

func scan(ctx context.Context, src io.Reader, options ReadOptions, visitors scanVisitors) (Summary, error) {
	if options.Identity == nil || options.Identity.key == nil {
		return Summary{}, errors.New("a native age recovery identity is required")
	}
	var expected []byte
	if options.ExpectedSHA256 != "" {
		var err error
		expected, err = hex.DecodeString(options.ExpectedSHA256)
		if err != nil || len(expected) != sha256.Size {
			return Summary{}, errors.New("expected SHA-256 must contain exactly 64 hexadecimal characters")
		}
	}
	reader := io.Reader(contextReader{ctx, src})
	cipherDigest := sha256.New()
	if expected != nil {
		reader = io.TeeReader(reader, cipherDigest)
	}
	clear, err := age.Decrypt(reader, options.Identity.key)
	if err != nil {
		if ctx.Err() != nil {
			return Summary{}, ctx.Err()
		}
		return Summary{}, errors.New("cannot decrypt age archive with the supplied identity")
	}
	prefix := make([]byte, len(magic))
	if _, err := io.ReadFull(clear, prefix); err != nil || string(prefix) != magic {
		return Summary{}, errors.New("invalid or unsupported Vesta file archive format")
	}
	tr := tar.NewReader(clear)
	tree := []directoryFrame{{name: "."}}
	content := sha256.New()
	digest := sha256.New()
	buffer := make([]byte, 64<<10)
	var calculated inventory
	for {
		hdr, err := tr.Next()
		if err != nil {
			if err == io.EOF {
				return Summary{}, errors.New("missing archive inventory")
			}
			return Summary{}, fmt.Errorf("read archive member: %w", err)
		}
		if hdr.Name == inventoryName {
			calculated.finish(digest)
			if err := checkInventory(tr, clear, hdr, calculated); err != nil {
				return Summary{}, err
			}
			break
		}
		item, err := parseEntry(hdr)
		if err != nil {
			return Summary{}, err
		}
		parent := path.Dir(item.Name)
		for len(tree) > 0 && tree[len(tree)-1].name != parent {
			tree = tree[:len(tree)-1]
		}
		if len(tree) == 0 {
			return Summary{}, errors.New("archive entry appears outside its declared directory")
		}
		current := &tree[len(tree)-1]
		base := path.Base(item.Name)
		if base <= current.last {
			return Summary{}, errors.New("archive contains duplicate or unordered entries")
		}
		current.last = base
		if item.Type == "directory" {
			tree = append(tree, directoryFrame{name: item.Name})
		}
		content.Reset()
		payload := io.TeeReader(tr, content)
		if visitors.consume != nil {
			if err := visitors.consume(item, payload); err != nil {
				return Summary{}, err
			}
		}
		if _, err := io.CopyBuffer(io.Discard, payload, buffer); err != nil {
			return Summary{}, fmt.Errorf("read archive member: %w", err)
		}
		if item.Type == "file" {
			item.SHA256 = hex.EncodeToString(content.Sum(nil))
		}
		calculated.add(digest, item)
		if visitors.observe != nil {
			if err := visitors.observe(item); err != nil {
				return Summary{}, err
			}
		}
	}
	if expected != nil && !bytes.Equal(expected, cipherDigest.Sum(nil)) {
		return Summary{}, errors.New("ciphertext SHA-256 does not match the expected archive")
	}
	if err := ctx.Err(); err != nil {
		return Summary{}, err
	}
	return calculated.Summary, nil
}

func parseEntry(hdr *tar.Header) (entry, error) {
	name, ok := strings.CutPrefix(hdr.Name, contentPrefix)
	if !ok || !validName(name) || hdr.Linkname != "" || hdr.Mode < 0 || hdr.Mode > 0777 || hdr.Size < 0 ||
		(hdr.Format != tar.FormatUSTAR && hdr.Format != tar.FormatPAX) {
		return entry{}, errors.New("archive contains an invalid path, mode or tar header")
	}
	for key := range hdr.PAXRecords {
		switch key {
		case "path", "mtime", "size":
		default:
			return entry{}, errors.New("archive contains an unsupported tar extension")
		}
	}
	item := entry{Name: name, Mode: uint32(hdr.Mode & 0777), Modified: hdr.ModTime.Unix(), Size: hdr.Size}
	switch {
	case hdr.Typeflag == tar.TypeReg:
		item.Type = "file"
	case hdr.Typeflag == tar.TypeDir && hdr.Size == 0:
		item.Type = "directory"
	default:
		return entry{}, errors.New("archive contains a link or an unsupported file type")
	}
	return item, nil
}

func checkInventory(tr *tar.Reader, clear io.Reader, hdr *tar.Header, calculated inventory) error {
	if hdr.Typeflag != tar.TypeReg || hdr.Format != tar.FormatUSTAR || hdr.Mode != 0600 ||
		hdr.Linkname != "" || hdr.Size <= 0 || hdr.Size > maxInventorySize {
		return errors.New("invalid archive inventory header")
	}
	record, err := io.ReadAll(tr)
	if err != nil {
		return fmt.Errorf("read archive inventory: %w", err)
	}
	canonical, err := json.Marshal(calculated)
	if err != nil || !bytes.Equal(record, canonical) {
		return errors.New("archive inventory mismatch")
	}
	// A generic tar parser accepts a short end marker. Require inventory
	// padding, both complete zero blocks, and then the authenticated age EOF.
	var suffix [3 * 512]byte
	padding := (512 - hdr.Size%512) % 512
	end := suffix[:padding+1024]
	if _, err := io.ReadFull(clear, end); err != nil {
		return fmt.Errorf("read authenticated archive end: %w", err)
	}
	for _, b := range end {
		if b != 0 {
			return errors.New("invalid archive end marker")
		}
	}
	if _, err := io.ReadFull(clear, suffix[:1]); err != io.EOF {
		if err != nil {
			return fmt.Errorf("authenticate archive end: %w", err)
		}
		return errors.New("unexpected data after archive inventory")
	}
	return nil
}

func anonymousTemp() (*os.File, error) {
	f, err := os.CreateTemp("", "vesta-file-restore-*")
	if err != nil {
		return nil, err
	}
	if err := os.Remove(f.Name()); err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}
