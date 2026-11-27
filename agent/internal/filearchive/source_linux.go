package filearchive

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"

	"golang.org/x/sys/unix"
)

const maxWalkNamesBytes = 16 << 20

func openDirectory(name string) (*os.File, error) {
	if !filepath.IsAbs(name) || filepath.Clean(name) != name {
		return nil, errors.New("directory must be an absolute, canonical path")
	}
	fd, err := unix.Openat2(unix.AT_FDCWD, name, &unix.OpenHow{
		Flags:   unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_NO_SYMLINKS,
	})
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), name), nil
}

func (w *archiveWriter) walk(directory *os.File, parent string, depth int) error {
	if err := w.ctx.Err(); err != nil {
		return err
	}
	var before, after unix.Stat_t
	if err := unix.Fstat(int(directory.Fd()), &before); err != nil {
		return err
	}
	var names []string
	// Bound the total memory used to sort sibling names along the active walk.
	reserved := 0
	defer func() { w.namesBudget -= reserved }()
	for {
		if err := w.ctx.Err(); err != nil {
			return err
		}
		batch, err := directory.Readdirnames(128)
		if err != nil && err != io.EOF {
			return err
		}
		for _, name := range batch {
			cost := len(name) + 64
			w.namesBudget += cost
			reserved += cost
			if w.namesBudget > maxWalkNamesBytes {
				return errors.New("directory tree exceeds the archive name sorting limit")
			}
			names = append(names, name)
		}
		if err == io.EOF {
			break
		}
	}
	if depth == maxDepth && len(names) != 0 {
		return errors.New("directory tree exceeds the archive nesting limit")
	}
	sort.Strings(names)
	for _, child := range names {
		if err := w.ctx.Err(); err != nil {
			return err
		}
		name := path.Join(parent, child)
		if !validName(name) {
			return fmt.Errorf("unsupported archive-relative path %q", name)
		}
		if err := w.writeChild(directory, child, name, depth); err != nil {
			return fmt.Errorf("archive %q: %w", name, err)
		}
	}
	if err := unix.Fstat(int(directory.Fd()), &after); err != nil {
		return err
	}
	if before.Mtim != after.Mtim || before.Ctim != after.Ctim {
		return errors.New("directory contents changed during backup")
	}
	return nil
}

func (w *archiveWriter) writeChild(parent *os.File, child, name string, depth int) error {
	fd, err := unix.Openat2(int(parent.Fd()), child, &unix.OpenHow{
		Flags:   unix.O_PATH | unix.O_NOFOLLOW | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_XDEV | unix.RESOLVE_BENEATH,
	})
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	var before, after unix.Stat_t
	if err := unix.Fstat(fd, &before); err != nil {
		return err
	}
	item := entry{Name: name, Mode: before.Mode & 0777, Modified: before.Mtim.Sec}
	flags := os.O_RDONLY
	switch before.Mode & unix.S_IFMT {
	case unix.S_IFDIR:
		item.Type = "directory"
		flags |= unix.O_DIRECTORY
	case unix.S_IFREG:
		item.Type = "file"
		item.Size = before.Size
	default:
		return errors.New("symlinks and special files are unsupported")
	}
	// Reopen the checked inode through its descriptor. Reopening the child name
	// would risk following a replacement file or device.
	f, err := os.OpenFile("/proc/self/fd/"+strconv.Itoa(fd), flags, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := w.header(item); err != nil {
		return err
	}
	if item.Type == "directory" {
		w.inventory.add(w.digest, item)
		if err := w.walk(f, name, depth+1); err != nil {
			return err
		}
	} else {
		digest := sha256.New()
		read := &io.LimitedReader{R: contextReader{w.ctx, f}, N: item.Size}
		copied, err := io.CopyBuffer(io.MultiWriter(w.tar, digest), read, w.buffer)
		if err != nil {
			return err
		}
		if copied != item.Size {
			return errors.New("file size changed during backup")
		}
		item.SHA256 = hex.EncodeToString(digest.Sum(nil))
		w.inventory.add(w.digest, item)
	}
	if err := unix.Fstat(fd, &after); err != nil {
		return err
	}
	if before.Mode != after.Mode || before.Size != after.Size || before.Mtim != after.Mtim || before.Ctim != after.Ctim {
		return errors.New("entry changed during backup")
	}
	return nil
}
