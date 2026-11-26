//go:build linux

package nativefileset

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"vnbui/agent/internal/models"
)

func specimen(t *testing.T) (string, models.NativeFileSet) {
	t.Helper()
	root := t.TempDir()
	disk1, disk2 := "disk-1", "disk-2"
	s := models.NativeFileSet{Format: models.NativeFileSetFormat, DomainUUID: "11111111-1111-4111-8111-111111111111", BackupID: "22222222-2222-4222-8222-222222222222", AttemptID: "33333333-3333-4333-8333-333333333333", JobID: "local-job-1", Checkpoint: "checkpoint-1", Disks: []models.NativeDisk{{ID: disk1, Target: "vda", Bus: "virtio"}, {ID: disk2, Target: "vdb", Bus: "virtio"}}, Files: []models.NativeFile{
		{Path: "vda.data", Role: "disk_payload", DiskID: &disk1}, {Path: "vdb.data", Role: "disk_payload", DiskID: &disk2}, {Path: "vmconfig.xml", Role: "domain_config"}, {Path: "checkpoints/member.xml", Role: "checkpoint"}, {Path: "autostart", Role: "autostart"},
	}}
	for i := range s.Files {
		s.Files[i].MemberBackupID = s.BackupID
		s.Files[i].MemberCheckpoint = s.Checkpoint
	}
	for _, f := range s.Files {
		p := filepath.Join(root, f.Path)
		if e := os.MkdirAll(filepath.Dir(p), 0700); e != nil {
			t.Fatal(e)
		}
		if e := os.WriteFile(p, []byte("native specimen"), 0600); e != nil {
			t.Fatal(e)
		}
	}
	return root, s
}

func TestCaptureReopenAndRead(t *testing.T) {
	root, s := specimen(t)
	s, e := Capture(root, s)
	if e != nil {
		t.Fatal(e)
	}
	body, e := json.Marshal(s)
	if e != nil {
		t.Fatal(e)
	}
	if strings.Contains(string(body), "sha256") {
		t.Fatal("pre-upload digest invented")
	}
	var reopened models.NativeFileSet
	if json.Unmarshal(body, &reopened) != nil || CheckTree(root, reopened) != nil {
		t.Fatal("reopen")
	}
	for _, f := range reopened.Files {
		p, e := OpenForUpload(root, f)
		if e != nil {
			t.Fatal(e)
		}
		b, e := io.ReadAll(p)
		if e != nil || string(b) != "native specimen" || p.Verify() != nil {
			t.Fatal("read")
		}
		_ = p.Close()
	}
	if CheckTree(root, s) != nil {
		t.Fatal("reads destroyed local data")
	}
}

func TestSingleMemberOwnershipAndCardinality(t *testing.T) {
	for _, fault := range []string{"missing-member", "foreign-member", "missing-checkpoint", "foreign-checkpoint", "checkpoint", "domain_config", "autostart", "backup_metadata", "disk_checksum", "disk_metadata"} {
		t.Run(fault, func(t *testing.T) {
			root, s := specimen(t)
			s, err := Capture(root, s)
			if err != nil {
				t.Fatal(err)
			}
			switch fault {
			case "missing-member":
				s.Files[0].MemberBackupID = ""
			case "foreign-member":
				s.Files[0].MemberBackupID = s.AttemptID
			case "missing-checkpoint":
				s.Files[0].MemberCheckpoint = ""
			case "foreign-checkpoint":
				s.Files[0].MemberCheckpoint = "parent-checkpoint"
			default:
				f := s.Files[0]
				f.Role = fault
				f.DiskID = nil
				if strings.HasPrefix(fault, "disk_") {
					f.DiskID = &s.Disks[0].ID
				}
				// Optional roles are accepted once, then rejected twice.
				found := false
				for _, old := range s.Files {
					if old.Role == fault {
						found = true
					}
				}
				if !found {
					f.Path = "optional"
					f.Inode = 999
					f.ArtifactID = ArtifactID(s, f)
					s.Files = append(s.Files, f)
					if Validate(s) != nil {
						t.Fatal("singular optional role refused")
					}
				}
				f.Path = "duplicate"
				f.Inode = 1000
				s.Files = append(s.Files, f)
			}
			for i := range s.Files {
				s.Files[i].ArtifactID = ArtifactID(s, s.Files[i])
			}
			if Validate(s) == nil {
				t.Fatal("invalid ownership/cardinality admitted")
			}
		})
	}
}

func TestExternalHardlinkAtEveryBoundary(t *testing.T) {
	for _, phase := range []string{"capture", "open", "eof"} {
		t.Run(phase, func(t *testing.T) {
			root, s := specimen(t)
			var p *PinnedFile
			if phase != "capture" {
				var e error
				s, e = Capture(root, s)
				if e != nil {
					t.Fatal(e)
				}
			}
			f := s.Files[0]
			if phase == "eof" {
				var e error
				p, e = OpenForUpload(root, f)
				if e != nil {
					t.Fatal(e)
				}
				defer p.Close()
			}
			if e := os.Link(filepath.Join(root, f.Path), filepath.Join(t.TempDir(), "external")); e != nil {
				t.Fatal(e)
			}
			switch phase {
			case "capture":
				if _, e := Capture(root, s); e == nil {
					t.Fatal("hardlink captured")
				}
			case "open":
				if p, e := OpenForUpload(root, f); e == nil {
					p.Close()
					t.Fatal("hardlink opened")
				}
			case "eof":
				if _, e := io.ReadAll(p); e == nil {
					t.Fatal("hardlink mutation accepted")
				}
			}
		})
	}
}

func TestAggregateAndDepthBounds(t *testing.T) {
	root, s := specimen(t)
	s, e := Capture(root, s)
	if e != nil {
		t.Fatal(e)
	}
	f := s.Files[0]
	old := ArtifactID(s, f)
	f.MemberCheckpoint = "different"
	if old == ArtifactID(s, f) {
		t.Fatal("member identity absent from digest")
	}
	for _, n := range []int{MaxDepth, MaxDepth + 1} {
		p := strings.Repeat("d/", n-1) + "f"
		if safePath(p) != (n == MaxDepth) {
			t.Fatal("depth bound")
		}
	}
	s.Files[0].Size = int64(^uint64(0) >> 1)
	s.Files[0].ArtifactID = ArtifactID(s, s.Files[0])
	if Validate(s) == nil {
		t.Fatal("overflow-sized inventory")
	}
}

func TestGlobalInventoryBudget(t *testing.T) {
	files := []models.NativeFile{{Path: "a", Size: MaxTotalBytes}}
	if inventoryBudget(files) != nil {
		t.Fatal("exact byte limit")
	}
	files = append(files, models.NativeFile{Path: "b", Size: 1})
	if inventoryBudget(files) == nil {
		t.Fatal("aggregate byte limit")
	}
	for _, kind := range []string{"paths", "components", "directories"} {
		t.Run(kind, func(t *testing.T) {
			files := []models.NativeFile{}
			limit := MaxPathBytes / 255
			if kind == "components" {
				limit = MaxComponents / MaxDepth
			}
			if kind == "directories" {
				limit = MaxDirectories
			}
			for i := 0; i <= limit; i++ {
				p := strings.Repeat("a", 255)
				if kind == "components" {
					p = strings.Repeat("d/", 15) + "f"
				}
				if kind == "directories" {
					p = fmt.Sprintf("d%d/f", i)
				}
				files = append(files, models.NativeFile{Path: p})
			}
			if inventoryBudget(files[:limit]) != nil || inventoryBudget(files) == nil {
				t.Fatal("global boundary")
			}
		})
	}
}

func TestDirectoryComponentCaseIdentity(t *testing.T) {
	for _, tc := range []struct {
		name, first, second string
		allowed             bool
	}{
		{"shared", "A/nested/x", "A/nested/y", true},
		{"root-alias", "A/x", "a/y", false},
		{"deep-alias", "A/Nested/x", "A/nested/y", false},
		{"ancestor-alias", "A/one/x", "a/two/y", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root, s := specimen(t)
			for i, relative := range []string{tc.first, tc.second} {
				if e := os.MkdirAll(filepath.Dir(filepath.Join(root, relative)), 0700); e != nil {
					t.Fatal(e)
				}
				if e := os.Rename(filepath.Join(root, s.Files[i].Path), filepath.Join(root, relative)); e != nil {
					t.Fatal(e)
				}
				s.Files[i].Path = relative
			}
			captured, e := Capture(root, s)
			if (e == nil) != tc.allowed {
				t.Fatal("directory identity verdict")
			}
			if tc.allowed && CheckTree(root, captured) != nil {
				t.Fatal("shared directory refused")
			}
		})
	}
}

func TestOnDiskRecursiveBudget(t *testing.T) {
	root, s := specimen(t)
	// Two separate subtrees plus the checkpoint directory. Each directory
	// individually fits both budgets; only global accounting distinguishes them.
	for i, relative := range []string{"one/nested/x", "two/nested/y"} {
		if e := os.MkdirAll(filepath.Dir(filepath.Join(root, relative)), 0700); e != nil {
			t.Fatal(e)
		}
		if e := os.Rename(filepath.Join(root, s.Files[i].Path), filepath.Join(root, relative)); e != nil {
			t.Fatal(e)
		}
		s.Files[i].Path = relative
	}
	s, e := Capture(root, s)
	if e != nil {
		t.Fatal(e)
	}
	// Five files and five necessary directories (root itself is not an entry).
	if CheckTree(root, s) != nil || checkTreeBudget(root, s, 10) != nil {
		t.Fatal("exact global bound refused")
	}
	if checkTreeBudget(root, s, 9) == nil {
		t.Fatal("per-directory budget reset hid exhaustion")
	}
}

func TestWireRejectsLooseOrUnknownInventory(t *testing.T) {
	root, s := specimen(t)
	s, e := Capture(root, s)
	if e != nil {
		t.Fatal(e)
	}
	b, _ := json.Marshal(s)
	if parsed, e := models.DecodeNativeFileSet(b); e != nil || Validate(*parsed) != nil {
		t.Fatal("valid wire refused")
	}
	for _, fault := range []string{"missing", "extra", "duplicate", "unknown-format", "null-files", "oversized"} {
		t.Run(fault, func(t *testing.T) {
			var v map[string]any
			_ = json.Unmarshal(b, &v)
			switch fault {
			case "missing":
				delete(v, "job_id")
			case "extra":
				v["credential"] = "not-allowed"
			case "unknown-format":
				v["format"] = "libvirt-native-fileset/2"
			case "null-files":
				v["files"] = nil
			}
			body, _ := json.Marshal(v)
			if fault == "duplicate" {
				body = append([]byte(`{"format":"libvirt-native-fileset/1",`), body[1:]...)
			}
			if fault == "oversized" {
				body = []byte(strings.Repeat(" ", 1<<20+1))
			}
			if _, e := models.DecodeNativeFileSet(body); e == nil {
				t.Fatal("loose wire accepted")
			}
		})
	}
}

func TestC01NativeFixture(t *testing.T) {
	b, err := os.ReadFile("../../../tests/fixtures/storage-contract-v1/libvirt-native-fileset.json")
	if err != nil {
		t.Fatal(err)
	}
	s, err := models.DecodeNativeFileSet(b)
	if err != nil || Validate(*s) != nil {
		t.Fatal("native fixture parity", err)
	}
	if len(s.Disks) != 2 || len(s.Files) != 5 {
		t.Fatal("fixture omitted shared metadata or a disk")
	}
	for _, f := range s.Files {
		if f.Role == "domain_config" && f.DiskID != nil {
			t.Fatal("shared metadata assigned to guessed disk")
		}
	}
}

func TestMembershipRefusal(t *testing.T) {
	for _, fault := range []string{"extra", "missing", "omit-disk", "unknown-disk", "duplicate-disk", "duplicate-payload", "duplicate-path", "case-collision", "traversal", "absolute", "unknown-role", "backup-guessed-disk", "symlink", "directory-symlink", "hardlink", "changed-attempt", "metadata-size"} {
		t.Run(fault, func(t *testing.T) {
			root, s := specimen(t)
			switch fault {
			case "extra":
				_ = os.WriteFile(filepath.Join(root, "extra"), nil, 0600)
			case "missing":
				_ = os.Remove(filepath.Join(root, "vda.data"))
			case "omit-disk":
				s.Files = s.Files[1:]
			case "unknown-disk":
				v := "foreign"
				s.Files[0].DiskID = &v
			case "duplicate-disk":
				s.Disks = append(s.Disks, s.Disks[0])
			case "duplicate-payload":
				f := s.Files[0]
				f.Path = "second.data"
				s.Files = append(s.Files, f)
				_ = os.WriteFile(filepath.Join(root, f.Path), nil, 0600)
			case "duplicate-path":
				s.Files = append(s.Files, s.Files[0])
			case "case-collision":
				f := s.Files[0]
				f.Path = "VDA.data"
				s.Files = append(s.Files, f)
				_ = os.WriteFile(filepath.Join(root, f.Path), nil, 0600)
			case "traversal":
				s.Files[0].Path = "../escape"
			case "absolute":
				s.Files[0].Path = "/escape"
			case "unknown-role":
				s.Files[0].Role = "guessed"
			case "backup-guessed-disk":
				s.Files[2].DiskID = s.Files[0].DiskID
			case "symlink":
				_ = os.Remove(filepath.Join(root, "vda.data"))
				_ = os.Symlink("vdb.data", filepath.Join(root, "vda.data"))
			case "directory-symlink":
				_ = os.Rename(filepath.Join(root, "checkpoints"), filepath.Join(root, "other"))
				_ = os.Symlink("other", filepath.Join(root, "checkpoints"))
			case "hardlink":
				_ = os.Remove(filepath.Join(root, "vda.data"))
				_ = os.Link(filepath.Join(root, "vdb.data"), filepath.Join(root, "vda.data"))
			case "changed-attempt":
				s.AttemptID = "invalid"
			case "metadata-size":
				f, e := os.OpenFile(filepath.Join(root, "vmconfig.xml"), os.O_WRONLY, 0600)
				if e != nil {
					t.Fatal(e)
				}
				_ = f.Truncate(MaxMetadata + 1)
				_ = f.Close()
			}
			if _, e := Capture(root, s); e == nil {
				t.Fatal("unsafe inventory accepted")
			}
		})
	}
}

func TestPinnedMutationAndReplacement(t *testing.T) {
	for _, fault := range []string{"replace-before", "mutate-during", "truncate-during", "path-replace-during"} {
		t.Run(fault, func(t *testing.T) {
			root, s := specimen(t)
			s, e := Capture(root, s)
			if e != nil {
				t.Fatal(e)
			}
			member := s.Files[0]
			name := filepath.Join(root, member.Path)
			if fault == "replace-before" {
				_ = os.Remove(name)
				_ = os.WriteFile(name, []byte("replacement"), 0600)
				if f, e := OpenForUpload(root, member); e == nil {
					_ = f.Close()
					t.Fatal("replacement admitted")
				}
				return
			}
			f, e := OpenForUpload(root, member)
			if e != nil {
				t.Fatal(e)
			}
			defer f.Close()
			switch fault {
			case "mutate-during":
				_ = os.WriteFile(name, []byte("changed content"), 0600)
			case "truncate-during":
				_ = os.Truncate(name, 0)
			case "path-replace-during":
				_ = os.Rename(name, name+".old")
				_ = os.WriteFile(name, []byte("replacement"), 0600)
			}
			if CheckTree(root, s) == nil {
				t.Fatal("changed closed set accepted")
			}
			if fault != "path-replace-during" {
				if _, e := io.ReadAll(f); e == nil {
					t.Fatal("mutation at EOF accepted")
				}
			}
		})
	}
}
