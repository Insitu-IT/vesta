package filearchive

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// Extract verifies the archive before writing any recovered files. It
// publishes a new output directory atomically without overwriting existing
// paths. An empty selection restores all entries. A selected directory also
// restores its descendants.
func Extract(ctx context.Context, src io.Reader, options ReadOptions, output string, selected []string) (Summary, error) {
	if output == "" {
		return Summary{}, errors.New("a new output directory is required")
	}
	wanted := make(map[string]bool, len(selected))
	for _, name := range selected {
		if !validName(name) {
			return Summary{}, fmt.Errorf("invalid archive selection %q", name)
		}
		wanted[name] = false
	}
	full, err := filepath.Abs(output)
	if err != nil {
		return Summary{}, err
	}
	base := filepath.Base(full)
	if full == string(filepath.Separator) {
		return Summary{}, errors.New("output directory must not exist")
	}
	parent, err := openDirectory(filepath.Dir(full))
	if err != nil {
		return Summary{}, fmt.Errorf("open restore output parent: %w", err)
	}
	defer parent.Close()
	parentFD := int(parent.Fd())
	var stat unix.Stat_t
	if err := unix.Fstatat(parentFD, base, &stat, unix.AT_SYMLINK_NOFOLLOW); !errors.Is(err, unix.ENOENT) {
		if err != nil {
			return Summary{}, err
		}
		return Summary{}, errors.New("output directory must not exist")
	}

	ciphertext, err := anonymousTemp()
	if err != nil {
		return Summary{}, err
	}
	defer ciphertext.Close()
	result, err := Verify(ctx, io.TeeReader(src, ciphertext), options)
	if err != nil {
		return Summary{}, err
	}
	if _, err := ciphertext.Seek(0, io.SeekStart); err != nil {
		return Summary{}, err
	}

	parentRoot, err := os.OpenRoot("/proc/self/fd/" + strconv.Itoa(parentFD))
	if err != nil {
		return Summary{}, err
	}
	defer parentRoot.Close()
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return Summary{}, err
	}
	temporary := ".vesta-file-restore-" + hex.EncodeToString(random[:])
	if err := parentRoot.Mkdir(temporary, 0700); err != nil {
		return Summary{}, err
	}
	published := false
	defer func() {
		if !published {
			_ = parentRoot.RemoveAll(temporary)
		}
	}()
	destination, err := parentRoot.OpenRoot(temporary)
	if err != nil {
		return Summary{}, err
	}
	defer destination.Close()

	e := extractor{root: destination, wanted: wanted}
	if _, err := scan(ctx, ciphertext, options, scanVisitors{consume: e.write}); err != nil {
		return Summary{}, err
	}
	if err := e.finishDirectories(""); err != nil {
		return Summary{}, err
	}
	for name, found := range wanted {
		if !found {
			return Summary{}, fmt.Errorf("archive has no entry %q", name)
		}
	}
	if err := syncTreeDirectory(destination, "."); err != nil {
		return Summary{}, err
	}
	if err := ctx.Err(); err != nil {
		return Summary{}, err
	}
	if err := unix.Renameat2(parentFD, temporary, parentFD, base, unix.RENAME_NOREPLACE); err != nil {
		return Summary{}, fmt.Errorf("publish new restore directory: %w", err)
	}
	published = true
	if err := unix.Fsync(parentFD); err != nil {
		return Summary{}, fmt.Errorf("restore was renamed but parent sync failed: %w", err)
	}
	return result, nil
}

type extractor struct {
	root        *os.Root
	wanted      map[string]bool
	directories []entry
}

func (e *extractor) write(item entry, payload io.Reader) (writeErr error) {
	if err := e.finishDirectories(item.Name); err != nil {
		return err
	}
	chosen := len(e.wanted) == 0
	for name := range e.wanted {
		switch {
		case item.Name == name:
			e.wanted[name] = true
			chosen = true
		case strings.HasPrefix(item.Name, name+"/"),
			item.Type == "directory" && strings.HasPrefix(name, item.Name+"/"):
			chosen = true
		}
	}
	if !chosen {
		return nil
	}
	if item.Type == "directory" {
		if err := e.root.Mkdir(item.Name, 0700); err != nil {
			return err
		}
		e.directories = append(e.directories, item)
		return nil
	}
	out, err := e.root.OpenFile(item.Name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer func() { writeErr = errors.Join(writeErr, out.Close()) }()
	if _, err := io.Copy(out, payload); err != nil {
		return err
	}
	mtime := time.Unix(item.Modified, 0)
	if err := e.root.Chtimes(item.Name, mtime, mtime); err != nil {
		return err
	}
	if err := out.Chmod(os.FileMode(item.Mode)); err != nil {
		return err
	}
	return out.Sync()
}

func syncTreeDirectory(root *os.Root, name string) error {
	dir, err := root.Open(name)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func (e *extractor) finishDirectories(next string) error {
	for len(e.directories) > 0 {
		index := len(e.directories) - 1
		item := e.directories[index]
		if strings.HasPrefix(next, item.Name+"/") {
			break
		}
		mtime := time.Unix(item.Modified, 0)
		if err := e.root.Chtimes(item.Name, mtime, mtime); err != nil {
			return err
		}
		// Keep directory traversal and cleanup possible for the restoring user.
		if err := e.root.Chmod(item.Name, os.FileMode(item.Mode)|0700); err != nil {
			return err
		}
		if err := syncTreeDirectory(e.root, item.Name); err != nil {
			return err
		}
		e.directories = e.directories[:index]
	}
	return nil
}

// OpenLocal opens an offline archive without accepting symlinks or devices.
func OpenLocal(name string) (*os.File, error) {
	fd, err := unix.Openat2(unix.AT_FDCWD, name, &unix.OpenHow{
		Flags:   unix.O_PATH | unix.O_NOFOLLOW | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_NO_SYMLINKS,
	})
	if err != nil {
		return nil, err
	}
	defer unix.Close(fd)
	var info unix.Stat_t
	if err := unix.Fstat(fd, &info); err != nil {
		return nil, err
	}
	if info.Mode&unix.S_IFMT != unix.S_IFREG {
		return nil, errors.New("offline archive must be a regular file")
	}
	return os.Open("/proc/self/fd/" + strconv.Itoa(fd))
}
