//go:build linux

// Package nativefileset fences closed native files without reading payloads.
// Filesystem identity detects replacement, not content integrity or job ownership.
package nativefileset

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"syscall"

	"vnbui/agent/internal/models"
)

var ErrHeld = errors.New("native file set held; retain local evidence")
var uuid = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
var identifier = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
var component = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$`)

const MaxFiles = 4096
const MaxMetadata = 16 << 20
const MaxTotalBytes int64 = 128*(1<<50) + (2*128+4)*MaxMetadata
const MaxPathBytes = 256 << 10
const MaxComponents = 4096
const MaxDepth = 16
const MaxDirectories = 1024

// Inventory budget is global, including shared path components. Subtraction
// before addition makes hostile declared sizes unable to wrap the accumulator.
func inventoryBudget(files []models.NativeFile) error {
	var total int64
	pathBytes, components := 0, 0
	dirs := map[string]string{}
	if len(files) > MaxFiles {
		return ErrHeld
	}
	for _, f := range files {
		if !safePath(f.Path) || f.Size < 0 || f.Size > MaxTotalBytes-total {
			return ErrHeld
		}
		total += f.Size
		if len(f.Path) > MaxPathBytes-pathBytes {
			return ErrHeld
		}
		pathBytes += len(f.Path)
		components += len(strings.Split(f.Path, "/"))
		if components > MaxComponents {
			return ErrHeld
		}
		for d := path.Dir(f.Path); d != "."; d = path.Dir(d) {
			folded := strings.ToLower(d)
			if previous, exists := dirs[folded]; exists && previous != d {
				return ErrHeld
			}
			dirs[folded] = d
			if len(dirs) > MaxDirectories {
				return ErrHeld
			}
		}
	}
	return nil
}

func safePath(p string) bool {
	if len(p) == 0 || len(p) > 1024 || path.Clean(p) != p || len(strings.Split(p, "/")) > MaxDepth {
		return false
	}
	for _, part := range strings.Split(p, "/") {
		if !component.MatchString(part) {
			return false
		}
	}
	return true
}

// ArtifactID uses only immutable member identity, never display names/settings.
func ArtifactID(s models.NativeFileSet, f models.NativeFile) string {
	b, _ := json.Marshal([]any{s.Format, s.DomainUUID, s.BackupID, s.AttemptID, s.JobID, s.Checkpoint, f.MemberBackupID, f.MemberCheckpoint, f.Path, f.Role, f.DiskID})
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func Validate(s models.NativeFileSet) error {
	if inventoryBudget(s.Files) != nil {
		return ErrHeld
	}
	if s.Format != models.NativeFileSetFormat || !uuid.MatchString(s.DomainUUID) || !uuid.MatchString(s.BackupID) || !uuid.MatchString(s.AttemptID) || !identifier.MatchString(s.JobID) || !identifier.MatchString(s.Checkpoint) || len(s.Disks) == 0 || len(s.Disks) > 128 || len(s.Files) == 0 || len(s.Files) > MaxFiles {
		return ErrHeld
	}
	disks, targets, payloads := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, d := range s.Disks {
		if !identifier.MatchString(d.ID) || !identifier.MatchString(d.Target) || !identifier.MatchString(d.Bus) || len(d.Serial) > 256 || disks[d.ID] || targets[d.Target] {
			return ErrHeld
		}
		disks[d.ID], targets[d.Target] = true, true
	}
	paths, ids, inodes := map[string]bool{}, map[string]bool{}, map[[2]uint64]bool{}
	config, checkpoint := 0, 0
	roles := map[string]bool{}
	for _, f := range s.Files {
		if f.MemberBackupID != s.BackupID || f.MemberCheckpoint != s.Checkpoint {
			return ErrHeld
		}
		roleKey := f.Role
		if f.DiskID != nil {
			roleKey += ":" + *f.DiskID
		}
		if roles[roleKey] {
			return ErrHeld
		}
		roles[roleKey] = true
		p := strings.ToLower(f.Path)
		if !safePath(f.Path) || paths[p] || ids[f.ArtifactID] || f.ArtifactID != ArtifactID(s, f) || f.Size < 0 || f.Size > 1<<50 || f.Inode == 0 || inodes[[2]uint64{f.Device, f.Inode}] {
			return ErrHeld
		}
		paths[p], ids[f.ArtifactID], inodes[[2]uint64{f.Device, f.Inode}] = true, true, true
		if f.DiskID != nil && !disks[*f.DiskID] {
			return ErrHeld
		}
		switch f.Role {
		case "disk_payload":
			if f.DiskID == nil || payloads[*f.DiskID] {
				return ErrHeld
			}
			payloads[*f.DiskID] = true
		case "disk_checksum", "disk_metadata":
			if f.DiskID == nil || f.Size > MaxMetadata {
				return ErrHeld
			}
		case "domain_config", "checkpoint", "autostart", "backup_metadata":
			if f.DiskID != nil || f.Size > MaxMetadata {
				return ErrHeld
			}
			if f.Role == "domain_config" {
				config++
			}
			if f.Role == "checkpoint" {
				checkpoint++
			}
		default:
			return ErrHeld
		}
	}
	if len(payloads) != len(disks) || config != 1 || checkpoint != 1 {
		return ErrHeld
	}
	// A file cannot also be a parent directory, including case-folded aliases.
	for p := range paths {
		for d := path.Dir(p); d != "."; d = path.Dir(d) {
			if paths[d] {
				return ErrHeld
			}
		}
	}
	return nil
}

// openExact refuses symlinks at every component, including the selected root.
// The caller must separately establish that this root belongs to the local job.
func openExact(root, relative string) (*os.File, error) {
	return openMember(root, relative, false)
}
func openMember(root, relative string, directory bool) (*os.File, error) {
	if !safePath(relative) && !(directory && relative == ".") {
		return nil, ErrHeld
	}
	fd, err := syscall.Open(root, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, ErrHeld
	}
	parts := strings.Split(relative, "/")
	for i, p := range parts {
		flags := syscall.O_RDONLY | syscall.O_NOFOLLOW | syscall.O_CLOEXEC | syscall.O_NONBLOCK
		if i < len(parts)-1 || directory {
			flags |= syscall.O_DIRECTORY
		}
		next, e := syscall.Openat(fd, p, flags, 0)
		_ = syscall.Close(fd)
		if e != nil {
			return nil, ErrHeld
		}
		fd = next
	}
	f := os.NewFile(uintptr(fd), relative)
	info, err := f.Stat()
	if err != nil || (directory && !info.IsDir()) || (!directory && !info.Mode().IsRegular()) {
		_ = f.Close()
		return nil, ErrHeld
	}
	return f, nil
}

func identity(file *os.File, f models.NativeFile) (models.NativeFile, error) {
	i, err := file.Stat()
	if err != nil || !i.Mode().IsRegular() {
		return f, ErrHeld
	}
	st, ok := i.Sys().(*syscall.Stat_t)
	if !ok || st.Nlink != 1 {
		return f, ErrHeld
	}
	f.Device, f.Inode, f.Size = uint64(st.Dev), st.Ino, st.Size
	f.MtimeNS, f.CtimeNS = st.Mtim.Nano(), st.Ctim.Nano()
	return f, nil
}

// Capture receives explicit member roles from closed job evidence; it never
// classifies files by names. Exact tree equality rejects unknown output files.
// Its return must be durably committed before OpenForUpload or provider effects.
func Capture(root string, s models.NativeFileSet) (models.NativeFileSet, error) {
	if inventoryBudget(s.Files) != nil {
		return s, ErrHeld
	}
	s.Files = append([]models.NativeFile(nil), s.Files...)
	for i, f := range s.Files {
		file, err := openExact(root, f.Path)
		if err != nil {
			return s, ErrHeld
		}
		member, err := identity(file, f)
		_ = file.Close()
		if err != nil {
			return s, ErrHeld
		}
		member.ArtifactID = ArtifactID(s, member)
		s.Files[i] = member
	}
	sort.Slice(s.Files, func(i, j int) bool { return s.Files[i].Path < s.Files[j].Path })
	if Validate(s) != nil || CheckTree(root, s) != nil {
		return s, ErrHeld
	}
	return s, nil
}

// CheckTree does not hash files. All regular members must match committed
// custody; all directories must be necessary, with no symlink traversal.
func CheckTree(root string, s models.NativeFileSet) error {
	return checkTreeBudget(root, s, MaxFiles+MaxDirectories)
}

// The budget is shared by the whole walk, not reset for each directory.
func checkTreeBudget(root string, s models.NativeFileSet, remaining int) error {
	if remaining < 0 || remaining > MaxFiles+MaxDirectories {
		return ErrHeld
	}
	if Validate(s) != nil {
		return ErrHeld
	}
	want := map[string]models.NativeFile{}
	dirs := map[string]bool{".": true}
	for _, f := range s.Files {
		want[f.Path] = f
		for p := path.Dir(f.Path); p != "."; p = path.Dir(p) {
			dirs[p] = true
		}
	}
	var visit func(string) error
	visit = func(p string) error {
		f, e := openMember(root, p, true)
		if e != nil {
			return ErrHeld
		}
		entries, e := f.ReadDir(remaining + 1)
		_ = f.Close()
		if e != nil && e != io.EOF {
			return ErrHeld
		}
		if len(entries) > remaining {
			return ErrHeld
		}
		remaining -= len(entries)
		for _, entry := range entries {
			n := path.Join(p, entry.Name())
			if entry.IsDir() {
				if !dirs[n] || visit(n) != nil {
					return ErrHeld
				}
				continue
			}
			member, ok := want[n]
			if !ok || entry.Type()&os.ModeSymlink != 0 {
				return ErrHeld
			}
			file, e := OpenForUpload(root, member)
			if e != nil {
				return ErrHeld
			}
			_ = file.Close()
			delete(want, n)
		}
		return nil
	}
	if visit(".") != nil || len(want) != 0 {
		return ErrHeld
	}
	return nil
}

// PinnedFile revalidates after EOF; the uploader must propagate that error and
// must not publish its receipt on a failed Verify. No local bytes are removed.
type PinnedFile struct {
	*os.File
	expected models.NativeFile
}

func OpenForUpload(root string, member models.NativeFile) (*PinnedFile, error) {
	f, err := openExact(root, member.Path)
	if err != nil {
		return nil, ErrHeld
	}
	p := &PinnedFile{f, member}
	if p.Verify() != nil {
		_ = f.Close()
		return nil, ErrHeld
	}
	return p, nil
}
func (p *PinnedFile) Verify() error {
	f, e := identity(p.File, p.expected)
	if e != nil || !reflect.DeepEqual(f, p.expected) {
		return ErrHeld
	}
	return nil
}
func (p *PinnedFile) Read(b []byte) (int, error) {
	n, e := p.File.Read(b)
	if e == io.EOF && p.Verify() != nil {
		return n, ErrHeld
	}
	return n, e
}
