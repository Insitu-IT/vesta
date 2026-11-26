package nativerestore

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"vnbui/agent/internal/backup"
	"vnbui/agent/internal/encryption"
	"vnbui/agent/internal/models"
	"vnbui/agent/internal/nativefileset"
)

func sealImageMember(t *testing.T, m Member, images map[string][]byte, key []byte) (Member, map[string][]byte) {
	t.Helper()
	manifest := &m.PushResult.Manifest
	plain := map[string][]byte{"domain.xml": []byte("<domain>captured</domain>"), "checkpoint.xml": []byte("<domaincheckpoint/>")}
	for i := range manifest.Disks {
		d := &manifest.Disks[i]
		data := images[d.Target]
		d.SizeBytes = int64(len(data))
		d.VirtualSize = 262144
		d.SHA256 = hash(data)
		plain[d.File] = data
	}
	canonical, _ := models.StorageCanonical(*manifest)
	m.PushResult.ManifestSHA256 = hash(canonical)
	plain["manifest.json"] = canonical
	p := &m.Request.Plan
	inv := &p.Source.Inventory
	inv.BackupID = m.Request.BackupID
	inv.AttemptID = m.Request.ReservationID
	inv.Checkpoint = manifest.Checkpoint
	inv.JobID = "vnbui-native-" + m.Request.ReservationID
	for i := range inv.Files {
		f := &inv.Files[i]
		f.MemberBackupID = inv.BackupID
		f.MemberCheckpoint = inv.Checkpoint
		f.Size = int64(len(plain[f.Path]))
		f.ArtifactID = nativefileset.ArtifactID(*inv, *f)
	}
	body, _ := models.StorageCanonical(*inv)
	p.Source.InventorySHA256 = hash(body)
	var err error
	p.Artifacts, err = nativefileset.BuildArtifacts(p.Source, m.Request.OrgID, m.Request.BackupID, m.Request.ReservationID, p.Encryption)
	if err != nil {
		t.Fatal(err)
	}
	body, _ = models.StorageCanonical(*p)
	m.Request.PlanSHA256 = hash(body)
	m.Receipt.BackupID = m.Request.BackupID
	m.Receipt.ReservationID = m.Request.ReservationID
	m.Receipt.Objects = nil
	store := map[string][]byte{}
	for _, a := range p.Artifacts {
		var data []byte
		for _, f := range inv.Files {
			if f.ArtifactID == a.ArtifactID {
				data = plain[f.Path]
			}
		}
		var encrypted bytes.Buffer
		if err := encryption.EncryptStream(bytes.NewReader(data), &encrypted, key); err != nil {
			t.Fatal(err)
		}
		stored := encrypted.Bytes()
		store[a.Key] = stored
		m.Receipt.Objects = append(m.Receipt.Objects, models.NativeStorageObjectReceipt{ArtifactID: a.ArtifactID, DiskID: a.DiskID, Role: a.Role, Key: a.Key, ETag: `"image"`, PlaintextBytes: int64(len(data)), CiphertextBytes: int64(len(stored)), PlaintextSHA256: hash(data), CiphertextSHA256: hash(stored)})
	}
	return m, store
}

func TestActualQcow2EncryptedReceiptChainToFreshRaw(t *testing.T) {
	if _, err := exec.LookPath("qemu-img"); err != nil {
		t.Skip("qemu-img10.1.x required for offline image test")
	}
	if _, err := exec.LookPath("qemu-io"); err != nil {
		t.Skip("qemu-io required")
	}
	command := func(name string, args ...string) {
		t.Helper()
		if output, err := exec.Command(name, args...).CombinedOutput(); err != nil {
			t.Fatal(name, err, string(output))
		}
	}
	root := t.TempDir()
	fullData, incData := map[string][]byte{}, map[string][]byte{}
	for _, target := range []string{"vda", "vdb"} {
		full, incremental := filepath.Join(root, target+"-full.qcow2"), filepath.Join(root, target+"-incremental.qcow2")
		command("qemu-img", "create", "-f", "qcow2", full, "262144")
		command("qemu-io", "-f", "qcow2", "-c", "write -P 0x41 0 262144", full)
		command("qemu-img", "create", "-f", "qcow2", "-F", "qcow2", "-b", full, incremental)
		command("qemu-io", "-f", "qcow2", "-c", "write -P 0x42 65536 65536", "-c", "write -z 131072 65536", incremental)
		command("qemu-img", "rebase", "-u", "-f", "qcow2", "-b", "", incremental)
		fullData[target], _ = os.ReadFile(full)
		incData[target], _ = os.ReadFile(incremental)
	}
	bundle, _, firstKey := bundleFixture(t, true)
	first, store := sealImageMember(t, bundle.Members[0], fullData, firstKey)
	body, _ := json.Marshal(first)
	var second Member
	_ = json.Unmarshal(body, &second)
	second.Request.BackupID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	second.Request.ReservationID = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
	second.Request.Plan.AttemptID = second.Request.ReservationID
	_, receiptSHA, err := nativefileset.CanonicalReceipt(first.Receipt, first.Request.Plan.Artifacts, first.Request.BackupID, first.Request.ReservationID, first.Request.Plan.Target, first.Request.Plan.Encryption)
	if err != nil {
		t.Fatal(err)
	}
	second.Request.Plan.BackupType = "incremental"
	second.Request.Plan.Parent = &models.StorageParent{BackupID: first.Request.BackupID, RootBackupID: first.Request.BackupID, ReceiptSHA256: receiptSHA, GenerationID: "dddddddd-dddd-4ddd-8ddd-dddddddddddd", TrackerUID: first.PushResult.Manifest.DomainUUID, Checkpoint: first.PushResult.Manifest.Checkpoint}
	second.PushResult.Manifest.BackupID = second.Request.BackupID
	second.PushResult.Manifest.AttemptID = second.Request.ReservationID
	second.PushResult.Manifest.Checkpoint = "vnbui-" + second.Request.ReservationID
	second.PushResult.Manifest.ParentBackupID = &first.Request.BackupID
	second.PushResult.Manifest.ParentManifestSHA256 = &first.PushResult.ManifestSHA256
	secondKey := bytes.Repeat([]byte{9}, 32)
	second, more := sealImageMember(t, second, incData, secondKey)
	for key, value := range more {
		store[key] = value
	}
	bundle.Members = []Member{first, second}
	if err := Validate(bundle); err != nil {
		t.Fatal(err)
	}
	open := func(_ context.Context, _ models.StorageTarget, o models.StorageObjectReceipt) (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(store[o.Key])), nil
	}
	keys := func(_ context.Context, m Member) ([]byte, error) {
		if m.Request.BackupID == first.Request.BackupID {
			return firstKey, nil
		}
		return secondKey, nil
	}
	members, err := Materialize(context.Background(), bundle, filepath.Join(root, "verified-members"), open, keys)
	if err != nil {
		t.Fatal(err)
	}
	disks, err := backup.RestoreNativePush(context.Background(), members, filepath.Join(root, "raw"))
	if err != nil {
		t.Fatal(err)
	}
	want := append(bytes.Repeat([]byte("A"), 65536), bytes.Repeat([]byte("B"), 65536)...)
	want = append(want, make([]byte, 65536)...)
	want = append(want, bytes.Repeat([]byte("A"), 65536)...)
	if len(disks) != 2 {
		t.Fatal(disks)
	}
	for _, disk := range disks {
		got, err := os.ReadFile(disk.Path)
		if err != nil || !bytes.Equal(got, want) || disk.SHA256 != hash(want) {
			t.Fatal("full/incremental/zero output mismatch", disk, err)
		}
	}
	for i, m := range members {
		for _, disk := range m.Manifest.Disks {
			data, err := os.ReadFile(filepath.Join(m.Directory, disk.File))
			if err != nil || hash(data) != disk.SHA256 {
				t.Fatal("input changed", i, disk.Target, err)
			}
		}
	}
	if _, err := backup.RestoreNativePush(context.Background(), members, filepath.Join(root, "raw")); err == nil {
		t.Fatal("existing restored output overwritten")
	}
	bundle.Members = []Member{second, first}
	if Validate(bundle) == nil {
		t.Fatal("reordered ancestry admitted")
	}
}
