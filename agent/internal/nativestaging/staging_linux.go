//go:build linux

// Package nativestaging connects an unprivileged agent to an allocation-only
// root broker. It neither enrolls verity nor releases backup capacity.
package nativestaging

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"syscall"
	"time"
	"unsafe"
)

const maxFrame = 4 << 20

var ErrHeld = errors.New("native staging unavailable or consumed; retain original custody")
var uuid = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

type Profile struct {
	Root, Socket  string
	device, inode uint64
}

// NewProfile binds configuration before any producer starts. Enabling a new
// staging profile on a populated journal, or redirecting an enrolled profile,
// refuses instead of guessing where an old producer might have written.
func NewProfile(journal, root, socket string) (*Profile, error) {
	marker := filepath.Join(journal, "staging-profile.json")
	body, err := readFile(marker, false)
	if err != nil && !os.IsNotExist(err) {
		return nil, ErrHeld
	}
	if root == "" && socket == "" {
		if err == nil {
			return nil, ErrHeld
		}
		return nil, nil
	}
	if runtime.GOARCH != "amd64" || root == "" || socket == "" || protected(root, true) != nil || protected(filepath.Dir(socket), true) != nil || !filepath.IsAbs(socket) || filepath.Clean(socket) != socket {
		return nil, ErrHeld
	}
	info, e := os.Lstat(root)
	if e != nil {
		return nil, ErrHeld
	}
	st := info.Sys().(*syscall.Stat_t)
	expected, _ := json.Marshal(map[string]any{"schema": "libvirt-staging-profile/1", "root": root, "socket": socket, "directory": []uint64{uint64(st.Dev), st.Ino}})
	if err == nil {
		if !bytes.Equal(body, expected) {
			return nil, ErrHeld
		}
	} else {
		for _, name := range []string{"requests", "uploads", "attempts"} {
			entries, e := os.ReadDir(filepath.Join(journal, name))
			if e != nil || len(entries) != 0 {
				return nil, ErrHeld
			}
		}
		file, e := os.OpenFile(marker, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0600)
		if e != nil {
			return nil, e
		}
		_, e = file.Write(expected)
		if e == nil {
			e = file.Sync()
		}
		closeErr := file.Close()
		if e != nil || closeErr != nil {
			return nil, ErrHeld
		}
		dir, e := os.Open(journal)
		if e != nil {
			return nil, e
		}
		e = dir.Sync()
		_ = dir.Close()
		if e != nil {
			return nil, e
		}
	}
	return &Profile{Root: root, Socket: socket, device: uint64(st.Dev), inode: st.Ino}, nil
}

func protected(path string, include bool) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return ErrHeld
	}
	if !include {
		path = filepath.Dir(path)
	}
	for {
		info, err := os.Lstat(path)
		if err != nil || !info.IsDir() || info.Mode().Perm()&0022 != 0 || info.Sys().(*syscall.Stat_t).Uid != 0 {
			return ErrHeld
		}
		if path == "/" {
			return nil
		}
		path = filepath.Dir(path)
	}
}

func (p *Profile) Path(attempt string) (string, error) {
	if !uuid.MatchString(attempt) {
		return "", ErrHeld
	}
	return filepath.Join(p.Root, attempt), nil
}

func (p *Profile) request(body []byte) (string, error) {
	info, err := os.Lstat(p.Root)
	if err != nil || protected(p.Root, true) != nil {
		return "", ErrHeld
	}
	st := info.Sys().(*syscall.Stat_t)
	if uint64(st.Dev) != p.device || st.Ino != p.inode {
		return "", ErrHeld
	}
	if len(body) == 0 || len(body) > maxFrame {
		return "", ErrHeld
	}
	var request struct {
		Attempt string `json:"attempt_id"`
		Output  string `json:"output_path"`
	}
	if json.Unmarshal(body, &request) != nil {
		return "", ErrHeld
	}
	path, err := p.Path(request.Attempt)
	if err != nil || request.Output != path {
		return "", ErrHeld
	}
	return path, nil
}

type allocation struct {
	Schema     string   `json:"schema"`
	RequestSHA string   `json:"request_sha256"`
	Directory  []uint64 `json:"directory"`
	UID        uint32   `json:"uid"`
	GID        uint32   `json:"gid"`
	Reserved   int64    `json:"reserved_bytes"`
}

// Fresh confirms the immutable root-issued slot before allowing any original
// producer invocation. Missing intent alone is never this positive authority.
func (p *Profile) Fresh(body []byte) error {
	path, err := p.request(body)
	if err != nil || protected(path, false) != nil {
		return ErrHeld
	}
	dir, err := os.OpenFile(path, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return ErrHeld
	}
	defer dir.Close()
	info, err := dir.Stat()
	if err != nil || !info.IsDir() || info.Mode().Perm()&0066 != 0 {
		return ErrHeld
	}
	st := info.Sys().(*syscall.Stat_t)
	if st.Uid != uint32(os.Geteuid()) {
		return ErrHeld
	}
	names, err := dir.Readdirnames(2)
	if err != nil && err != io.EOF {
		return ErrHeld
	}
	if len(names) != 1 || names[0] != "allocation.json" {
		return ErrHeld
	}
	fd, err := syscall.Openat(int(dir.Fd()), "allocation.json", syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return ErrHeld
	}
	file := os.NewFile(uintptr(fd), "allocation.json")
	defer file.Close()
	fi, err := file.Stat()
	if err != nil || !fi.Mode().IsRegular() || fi.Mode().Perm()&0222 != 0 || fi.Size() > maxFrame {
		return ErrHeld
	}
	fs := fi.Sys().(*syscall.Stat_t)
	if fs.Uid != 0 || fs.Nlink != 1 {
		return ErrHeld
	}
	var flags uint64
	_, _, e := syscall.Syscall(syscall.SYS_IOCTL, file.Fd(), 0x80086601, uintptr(unsafe.Pointer(&flags)))
	if e != 0 || flags&0x10 == 0 {
		return ErrHeld
	}
	saved, err := io.ReadAll(io.LimitReader(file, maxFrame+1))
	if err != nil || len(saved) > maxFrame {
		return ErrHeld
	}
	var a allocation
	decoder := json.NewDecoder(bytes.NewReader(saved))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&a) != nil {
		return ErrHeld
	}
	h := sha256.Sum256(body)
	if a.Schema != "libvirt-staging-allocation/1" || a.RequestSHA != hex.EncodeToString(h[:]) || len(a.Directory) != 2 || a.Directory[0] != uint64(st.Dev) || a.Directory[1] != st.Ino || a.UID != st.Uid || a.GID != st.Gid || a.Reserved <= 0 {
		return ErrHeld
	}
	expected, _ := json.Marshal(map[string]any{"schema": a.Schema, "request_sha256": a.RequestSHA, "directory": a.Directory, "uid": a.UID, "gid": a.GID, "reserved_bytes": a.Reserved})
	if !bytes.Equal(saved, expected) {
		return ErrHeld
	}
	return nil
}

func brokerUID(conn *net.UnixConn) (uint32, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return 0, err
	}
	var uid uint32
	var inner error
	err = raw.Control(func(fd uintptr) {
		cred, e := syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
		inner = e
		if e == nil {
			uid = cred.Uid
		}
	})
	if err != nil {
		return 0, err
	}
	return uid, inner
}

func exchange(conn *net.UnixConn, body []byte, expectedUID uint32) error {
	uid, err := brokerUID(conn)
	if err != nil || uid != expectedUID {
		return ErrHeld
	}
	envelope, err := json.Marshal(map[string]any{"action": "allocate", "request": json.RawMessage(body)})
	if err != nil || len(envelope) > maxFrame {
		return ErrHeld
	}
	frame := make([]byte, 4+len(envelope))
	binary.BigEndian.PutUint32(frame, uint32(len(envelope)))
	copy(frame[4:], envelope)
	if _, err = io.Copy(conn, bytes.NewReader(frame)); err != nil {
		return ErrHeld
	}
	header := make([]byte, 4)
	if _, err = io.ReadFull(conn, header); err != nil {
		return ErrHeld
	}
	size := binary.BigEndian.Uint32(header)
	if size == 0 || size > maxFrame {
		return ErrHeld
	}
	response := make([]byte, int(size))
	if _, err = io.ReadFull(conn, response); err != nil {
		return ErrHeld
	}
	var reply struct {
		Schema string `json:"schema"`
		Status string `json:"status"`
		SHA    string `json:"request_sha256"`
	}
	decoder := json.NewDecoder(bytes.NewReader(response))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&reply) != nil {
		return ErrHeld
	}
	h := sha256.Sum256(body)
	if reply.Schema != "libvirt-staging-reply/1" || reply.Status != "allocated" || reply.SHA != hex.EncodeToString(h[:]) {
		return ErrHeld
	}
	expected, _ := json.Marshal(map[string]string{"schema": reply.Schema, "status": reply.Status, "request_sha256": reply.SHA})
	if !bytes.Equal(expected, response) {
		return ErrHeld
	}
	return nil
}

func (p *Profile) Allocate(ctx context.Context, body []byte) error {
	if _, err := p.request(body); err != nil {
		return err
	}
	if protected(filepath.Dir(p.Socket), true) != nil {
		return ErrHeld
	}
	conn, err := (&net.Dialer{}).DialContext(ctx, "unix", p.Socket)
	if err != nil {
		return ErrHeld
	}
	defer conn.Close()
	deadline := time.Now().Add(10 * time.Second)
	if limit, ok := ctx.Deadline(); ok && limit.Before(deadline) {
		deadline = limit
	}
	if conn.SetDeadline(deadline) != nil {
		return ErrHeld
	}
	if exchange(conn.(*net.UnixConn), body, 0) != nil {
		return ErrHeld
	}
	return p.Fresh(body)
}

func readFile(path string, rootOwned bool) ([]byte, error) {
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > maxFrame {
		return nil, ErrHeld
	}
	st := info.Sys().(*syscall.Stat_t)
	if st.Nlink != 1 || (rootOwned && st.Uid != 0) {
		return nil, ErrHeld
	}
	body, err := io.ReadAll(io.LimitReader(file, maxFrame+1))
	if err != nil || len(body) > maxFrame {
		return nil, ErrHeld
	}
	return body, nil
}
