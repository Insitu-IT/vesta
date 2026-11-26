package storagerestore

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"vnbui/agent/internal/models"
	"vnbui/agent/internal/storageupload"
)

func hashBytes(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

func pointer[T any](value T) *T { return &value }

// memoryStore implements the actual uploader's provider boundary. Its outputs,
// including encryption and receipt measurements, feed the restore consumer.
type memoryStore struct {
	target models.StorageTarget
	data   map[string][]byte
	meta   map[string]map[string]string
	reads  int
}

func newStore() *memoryStore {
	return &memoryStore{data: map[string][]byte{}, meta: map[string]map[string]string{}}
}

func (s *memoryStore) Target() models.StorageTarget { return s.target }
func (s *memoryStore) Begin(_ context.Context, key string, metadata map[string]string) (string, error) {
	s.meta[key] = metadata
	s.data[key] = nil
	return "upload-id", nil
}
func (s *memoryStore) Part(_ context.Context, key, _ string, n int, body []byte, checksum string) (string, error) {
	digest := sha256.Sum256(body)
	if base64.StdEncoding.EncodeToString(digest[:]) != checksum {
		return "", errors.New("part checksum mismatch")
	}
	s.data[key] = append(s.data[key], body...)
	return fmt.Sprintf("part-%d", n), nil
}
func (s *memoryStore) Complete(_ context.Context, key, _ string, _ []storageupload.Part) (storageupload.ObjectInfo, error) {
	return storageupload.ObjectInfo{ETag: hashBytes(s.data[key]), VersionID: pointer("version-" + key), Metadata: map[string]string{}}, nil
}
func (s *memoryStore) Head(_ context.Context, key string, version *string, etag string) (storageupload.ObjectInfo, error) {
	return storageupload.ObjectInfo{ETag: etag, VersionID: version, Bytes: int64(len(s.data[key])), Metadata: s.meta[key]}, nil
}
func (s *memoryStore) open(_ context.Context, target models.StorageTarget, obj models.StorageObjectReceipt) (io.ReadCloser, error) {
	s.reads++
	if target != s.target || obj.VersionID == nil || *obj.VersionID != "version-"+obj.Key {
		return nil, errors.New("incorrect exact object identity")
	}
	body, ok := s.data[obj.Key]
	if !ok {
		return nil, errors.New("missing object")
	}
	return io.NopCloser(bytes.NewReader(body)), nil
}

func rehash(t *testing.T, member *Member) {
	t.Helper()
	body, err := models.StorageCanonical(member.Request.Plan)
	if err != nil {
		t.Fatal(err)
	}
	member.Request.PlanSHA256 = hashBytes(body)
}

func produce(t *testing.T, store *memoryStore, index int, parent *Member, capacity int64, extents []storedExtent, payload, key []byte) Member {
	t.Helper()
	fixture, err := os.ReadFile("../../contracts/storage_semantic_valid.json")
	if err != nil {
		t.Fatal(err)
	}
	var member Member
	if err := json.Unmarshal(fixture, &member.Request); err != nil {
		t.Fatal(err)
	}
	r := &member.Request
	r.BackupID = fmt.Sprintf("33333333-3333-4333-8333-%012d", index)
	r.ReservationID = fmt.Sprintf("55555555-5555-4555-8555-%012d", index)
	r.Plan.AttemptID = r.ReservationID
	r.Plan.Source.Volumes[0].CapacityBytes = capacity
	if parent != nil {
		_, digest, err := models.CanonicalReceipt(&parent.Request, parent.Receipt)
		if err != nil {
			t.Fatal(err)
		}
		root := parent.Request.BackupID
		if parent.Request.Plan.Parent != nil {
			root = parent.Request.Plan.Parent.RootBackupID
		}
		r.Plan.BackupType = "incremental"
		r.Plan.Parent = &models.StorageParent{BackupID: parent.Request.BackupID, RootBackupID: root, ReceiptSHA256: digest,
			GenerationID: fmt.Sprintf("77777777-7777-4777-8777-%012d", index-1), TrackerUID: "tracker-uid", Checkpoint: fmt.Sprintf("checkpoint-%d", index-1)}
	}
	if key != nil {
		r.Plan.Encryption = models.StorageEncryption{Format: "vnbu1-aes256gcm-chunk5242880", KeyRef: pointer("kek:66666666-6666-4666-8666-666666666666:aaaaaaaaaaaaaaaa")}
	}
	for i := range r.Plan.Artifacts {
		a := &r.Plan.Artifacts[i]
		a.Key = "vnbui-owned/v1/" + hashBytes([]byte(r.OrgID)) + "/" + hashBytes([]byte(r.BackupID)) + "/payload/" + r.ReservationID + "/" + hashBytes([]byte(a.VolumeID)) + "/" + a.Role
		if a.Role == "volume_payload" {
			a.PlaintextMax, a.CiphertextMax = capacity, capacity
			if key != nil {
				a.CiphertextMin = 5
				a.CiphertextMax = 5 + capacity + 32*((capacity+transactionChunkBytes-1)/transactionChunkBytes)
			}
		}
	}
	rehash(t, &member)
	requestBody, err := json.Marshal(member.Request)
	if err != nil {
		t.Fatal(err)
	}
	journal, err := storageupload.Create(t.TempDir(), requestBody)
	if err != nil {
		t.Fatal(err)
	}
	defer journal.Close()
	store.target = r.Plan.Target
	manifest := volumeManifest{
		VMNamespace: r.Plan.Source.Namespace, VMUID: r.Plan.Source.VMUID, Format: "vnbui-kubevirt-cbt-v1", BackupType: r.Plan.BackupType,
		Checkpoint: fmt.Sprintf("checkpoint-%d", index), Volume: r.Plan.Source.Volumes[0].Name, VirtualSize: uint64(capacity),
		Encrypted: pointer(key != nil), PayloadKey: r.Plan.Artifacts[1].Key, StoredExtents: extents,
	}
	manifestBytes, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	inputs := make([]storageupload.Input, 0, 2)
	for _, artifact := range r.Plan.Artifacts {
		data := payload
		if artifact.Role == "volume_manifest" {
			data = manifestBytes
		}
		inputs = append(inputs, storageupload.Input{Artifact: artifact, Open: func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(data)), nil }})
	}
	if err := journal.UploadAll(context.Background(), store, inputs, key); err != nil {
		t.Fatal(err)
	}
	snapshot, err := journal.Snapshot()
	if err != nil || snapshot.Receipt == nil {
		t.Fatal("uploader did not prepare receipt", err)
	}
	member.Receipt = *snapshot.Receipt
	return member
}

func chainFixture(t *testing.T, encrypted bool) ([]Member, *memoryStore, KeyResolver, []byte) {
	t.Helper()
	store := newStore()
	var key1, key2 []byte
	if encrypted {
		key1, key2 = bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32)
	}
	full := produce(t, store, 1, nil, 12, []storedExtent{
		{DiskOffset: 0, Length: 4, PayloadOffset: pointer(uint64(0))},
		{DiskOffset: 8, Length: 4, PayloadOffset: pointer(uint64(4))},
	}, []byte("ABCDIJKL"), key1)
	inc := produce(t, store, 2, &full, 12, []storedExtent{
		{DiskOffset: 1, Length: 2, PayloadOffset: pointer(uint64(0))},
		{DiskOffset: 8, Length: 2, ZeroFill: true},
		{DiskOffset: 11, Length: 1, PayloadOffset: pointer(uint64(2))},
	}, []byte("xy!"), key2)
	keys := func(_ context.Context, m Member) ([]byte, error) {
		if m.Request.BackupID == full.Request.BackupID {
			return bytes.Clone(key1), nil
		}
		if m.Request.BackupID == inc.Request.BackupID {
			return bytes.Clone(key2), nil
		}
		return nil, errors.New("unknown member")
	}
	return []Member{full, inc}, store, keys, []byte{'A', 'x', 'y', 'D', 0, 0, 0, 0, 0, 0, 'K', '!'}
}

func TestUploaderFullAndIncrementalRoundTrip(t *testing.T) {
	for _, encrypted := range []bool{false, true} {
		t.Run(fmt.Sprintf("encrypted=%t", encrypted), func(t *testing.T) {
			chain, store, keys, want := chainFixture(t, encrypted)
			dir := filepath.Join(t.TempDir(), "restored")
			disks, err := Assemble(context.Background(), chain, dir, store.open, keys)
			if err != nil || len(disks) != 1 {
				t.Fatal(disks, err)
			}
			got, err := os.ReadFile(disks[0].Path)
			if err != nil || !bytes.Equal(got, want) || disks[0].SHA256 != hashBytes(want) || disks[0].SizeBytes != 12 {
				t.Fatalf("restore = %q, want %q; disk=%+v err=%v", got, want, disks[0], err)
			}
			info, err := os.Stat(disks[0].Path)
			if err != nil || info.Mode().Perm() != 0600 {
				t.Fatal("restored disk is not private", err)
			}
		})
	}
}

func TestEncryptedMultiChunkAndZeroOnlySuccessor(t *testing.T) {
	store := newStore()
	key := bytes.Repeat([]byte{7}, 32)
	data := bytes.Repeat([]byte{19}, transactionChunkBytes+73)
	full := produce(t, store, 1, nil, int64(len(data)), []storedExtent{{Length: uint64(len(data)), PayloadOffset: pointer(uint64(0))}}, data, key)
	inc := produce(t, store, 2, &full, int64(len(data)), []storedExtent{{DiskOffset: transactionChunkBytes - 7, Length: 80, ZeroFill: true}}, nil, key)
	disks, err := Assemble(context.Background(), []Member{full, inc}, filepath.Join(t.TempDir(), "restored"), store.open,
		func(context.Context, Member) ([]byte, error) { return bytes.Clone(key), nil })
	if err != nil {
		t.Fatal(err)
	}
	clear(data[transactionChunkBytes-7:])
	got, err := os.ReadFile(disks[0].Path)
	if err != nil || !bytes.Equal(got, data) {
		t.Fatal("multi-chunk baseline or empty incremental payload differs", err)
	}
}

func TestEachIncrementalParentHasItsOwnPublishedGeneration(t *testing.T) {
	chain, store, keys, want := chainFixture(t, false)
	third := produce(t, store, 3, &chain[1], 12, []storedExtent{{DiskOffset: 3, Length: 1, PayloadOffset: pointer(uint64(0))}}, []byte("!"), nil)
	if third.Request.Plan.Parent.GenerationID == chain[1].Request.Plan.Parent.GenerationID {
		t.Fatal("fixture must use distinct published generations")
	}
	chain = append(chain, third)
	disks, err := Assemble(context.Background(), chain, filepath.Join(t.TempDir(), "restore"), store.open, keys)
	if err != nil {
		t.Fatal(err)
	}
	want[3] = '!'
	got, err := os.ReadFile(disks[0].Path)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("third member = %q, want %q: %v", got, want, err)
	}
}

func TestInvalidChainRefusedBeforeObjectAccess(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func([]Member) []Member
	}{
		{"reverse", func(c []Member) []Member { return []Member{c[1], c[0]} }},
		{"duplicate", func(c []Member) []Member { return []Member{c[0], c[1], c[1]} }},
		{"parent_hash", func(c []Member) []Member {
			c[1].Request.Plan.Parent.ReceiptSHA256 = strings.Repeat("0", 64)
			rehash(t, &c[1])
			return c
		}},
		{"foreign_vm", func(c []Member) []Member {
			c[1].Request.Plan.Source.VMUID = "replacement-vm"
			rehash(t, &c[1])
			return c
		}},
		{"changed_disk_mapping", func(c []Member) []Member {
			c[1].Request.Plan.Source.Volumes[0].Mapping.Bus = "scsi"
			rehash(t, &c[1])
			return c
		}},
		{"plan_digest", func(c []Member) []Member { c[1].Request.PlanSHA256 = strings.Repeat("0", 64); return c }},
	} {
		t.Run(test.name, func(t *testing.T) {
			chain, store, keys, _ := chainFixture(t, false)
			dir := filepath.Join(t.TempDir(), "restore")
			if _, err := Assemble(context.Background(), test.mutate(chain), dir, store.open, keys); err == nil || store.reads != 0 {
				t.Fatal("invalid chain opened objects", err, store.reads)
			}
			if _, err := os.Stat(dir); !os.IsNotExist(err) {
				t.Fatal("invalid chain created output")
			}
		})
	}
}

func TestCorruptionNeverReturnsDiskAndCleansOutput(t *testing.T) {
	for _, name := range []string{"manifest_bytes", "payload_bytes", "truncated", "appended", "plaintext_digest", "ciphertext_digest", "checkpoint", "wrong_dek", "oversized_chunk"} {
		t.Run(name, func(t *testing.T) {
			encrypted := name == "wrong_dek" || name == "oversized_chunk" || name == "plaintext_digest" || name == "ciphertext_digest"
			chain, store, keys, _ := chainFixture(t, encrypted)
			obj := &chain[1].Receipt.Objects[1]
			switch name {
			case "manifest_bytes":
				key := chain[1].Receipt.Objects[0].Key
				store.data[key][0] = '!'
			case "payload_bytes":
				store.data[obj.Key][0] ^= 1
			case "truncated":
				store.data[obj.Key] = store.data[obj.Key][:len(store.data[obj.Key])-1]
			case "appended":
				store.data[obj.Key] = append(store.data[obj.Key], '!')
			case "plaintext_digest":
				obj.PlaintextSHA256 = strings.Repeat("0", 64)
			case "ciphertext_digest":
				obj.CiphertextSHA256 = strings.Repeat("0", 64)
			case "checkpoint":
				chain[1].Request.Plan.Parent.Checkpoint = "foreign-checkpoint"
				rehash(t, &chain[1])
			case "wrong_dek":
				keys = func(context.Context, Member) ([]byte, error) { return bytes.Repeat([]byte{9}, 32), nil }
			case "oversized_chunk":
				binary.BigEndian.PutUint32(store.data[obj.Key][5:9], 0xffffffff)
				obj.CiphertextSHA256 = hashBytes(store.data[obj.Key])
			}
			dir := filepath.Join(t.TempDir(), "restore")
			disks, err := Assemble(context.Background(), chain, dir, store.open, keys)
			if err == nil || disks != nil {
				t.Fatal("corrupted backup returned a restored disk", err)
			}
			if _, err := os.Stat(dir); !os.IsNotExist(err) {
				t.Fatal("partial restore output survived error", err)
			}
		})
	}
}

func TestManifestExtentRefusals(t *testing.T) {
	for _, test := range []struct {
		name string
		edit func(*volumeManifest)
	}{
		{"overlap", func(m *volumeManifest) { m.StoredExtents[1].DiskOffset = 2 }},
		{"beyond_disk", func(m *volumeManifest) { m.StoredExtents[2].Length = 2 }},
		{"payload_gap", func(m *volumeManifest) { m.StoredExtents[2].PayloadOffset = pointer(uint64(3)) }},
		{"zero_with_payload", func(m *volumeManifest) { m.StoredExtents[1].PayloadOffset = pointer(uint64(2)) }},
		{"wrong_vm", func(m *volumeManifest) { m.VMUID = "other-vm" }},
		{"wrong_volume", func(m *volumeManifest) { m.Volume = "other-disk" }},
		{"wrong_payload", func(m *volumeManifest) { m.PayloadKey += "foreign" }},
		{"missing_encryption", func(m *volumeManifest) { m.Encrypted = nil }},
	} {
		t.Run(test.name, func(t *testing.T) {
			chain, store, keys, _ := chainFixture(t, false)
			obj := &chain[1].Receipt.Objects[0]
			var manifest volumeManifest
			if err := json.Unmarshal(store.data[obj.Key], &manifest); err != nil {
				t.Fatal(err)
			}
			test.edit(&manifest)
			data, err := json.Marshal(manifest)
			if err != nil {
				t.Fatal(err)
			}
			store.data[obj.Key] = data
			obj.PlaintextBytes, obj.CiphertextBytes = int64(len(data)), int64(len(data))
			obj.PlaintextSHA256, obj.CiphertextSHA256 = hashBytes(data), hashBytes(data)
			if disks, err := Assemble(context.Background(), chain, filepath.Join(t.TempDir(), "restore"), store.open, keys); err == nil || disks != nil {
				t.Fatal("accepted malformed extent manifest", err)
			}
		})
	}
}

func TestExistingOutputNeverOverwritten(t *testing.T) {
	chain, store, keys, _ := chainFixture(t, false)
	dir := t.TempDir()
	path := filepath.Join(dir, "owner-data")
	if err := os.WriteFile(path, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Assemble(context.Background(), chain, dir, store.open, keys); err == nil || store.reads != 0 {
		t.Fatal("restore accepted an existing directory")
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "keep" {
		t.Fatal("existing data was modified")
	}
}

func TestCancellationClosesBlockedObjectRead(t *testing.T) {
	chain, store, keys, _ := chainFixture(t, false)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	started := make(chan struct{})
	reader, writer := io.Pipe()
	defer writer.Close()
	opener := func(context.Context, models.StorageTarget, models.StorageObjectReceipt) (io.ReadCloser, error) {
		close(started)
		return reader, nil
	}
	done := make(chan error, 1)
	dir := filepath.Join(t.TempDir(), "restore")
	go func() {
		_, err := Assemble(ctx, chain, dir, opener, keys)
		done <- err
	}()
	<-started
	cancel()
	select {
	case err := <-done:
		if err == nil || store.reads != 0 {
			t.Fatal("canceled restore succeeded")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("cancellation did not close blocked object body")
	}
}

func TestManifestStrictJSON(t *testing.T) {
	for _, body := range []string{
		`{"format":"a","format":"b"}`,
		`{"stored_extents":[{"length":1,"length":2}]}`,
		`{"unknown":true}`,
		`{"format":"a"} {"format":"b"}`,
	} {
		var manifest volumeManifest
		if err := decodeManifest([]byte(body), &manifest); err == nil {
			t.Fatalf("accepted invalid JSON %s", body)
		}
	}
}
