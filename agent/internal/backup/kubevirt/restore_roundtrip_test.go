//go:build kubevirt

package kubevirt

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"vnbui/agent/internal/encryption"
	"vnbui/agent/internal/models"
	"vnbui/agent/internal/storagerestore"
	"vnbui/agent/internal/storageupload"
)

type restoreRoundTripStore struct {
	target models.StorageTarget
	data   map[string][]byte
	meta   map[string]map[string]string
}

func (s *restoreRoundTripStore) Target() models.StorageTarget { return s.target }
func (s *restoreRoundTripStore) Begin(_ context.Context, key string, meta map[string]string) (string, error) {
	s.meta[key] = meta
	s.data[key] = nil
	return "roundtrip-upload", nil
}
func (s *restoreRoundTripStore) Part(_ context.Context, key, _ string, n int, data []byte, _ string) (string, error) {
	s.data[key] = append(s.data[key], data...)
	return strconv.Itoa(n), nil
}
func (s *restoreRoundTripStore) Complete(_ context.Context, key, _ string, _ []storageupload.Part) (storageupload.ObjectInfo, error) {
	return storageupload.ObjectInfo{ETag: nativeHash(s.data[key]), Metadata: map[string]string{}}, nil
}
func (s *restoreRoundTripStore) Head(_ context.Context, key string, version *string, etag string) (storageupload.ObjectInfo, error) {
	return storageupload.ObjectInfo{ETag: etag, VersionID: version, Bytes: int64(len(s.data[key])), Metadata: s.meta[key]}, nil
}

// This crosses the real map parser, range reader, manifest encoder, receipt
// uploader and restore consumer. No test-side manifest encoder participates.
func TestTransactionProducerFullAndTwoIncrementalRestore(t *testing.T) {
	for _, encrypted := range []bool{false, true} {
		t.Run(fmt.Sprintf("encrypted=%t", encrypted), func(t *testing.T) {
			store := &restoreRoundTripStore{data: map[string][]byte{}, meta: map[string]map[string]string{}}
			var key []byte
			if encrypted {
				key = bytes.Repeat([]byte{71}, 32)
			}
			fullBytes := []byte{'a', 'b', 'c', 'd', 'e', 'f', 0, 0, 0, 0, 'k', 'l', 0, 0, 0, 0}
			firstIncrement := bytes.Clone(fullBytes)
			copy(firstIncrement[2:4], "XY")
			clear(firstIncrement[5:11])
			copy(firstIncrement[14:], "Z!")
			secondIncrement := bytes.Clone(firstIncrement)
			secondIncrement[1], secondIncrement[15] = '!', 0
			steps := []struct {
				data []byte
				maps []mapExtent
			}{
				{fullBytes, []mapExtent{{Offset: 0, Length: 6, Description: "data"}, {Offset: 6, Length: 4, Description: "hole"}, {Offset: 10, Length: 2, Description: "data"}, {Offset: 12, Length: 4, Description: "hole"}}},
				{firstIncrement, []mapExtent{{Offset: 0, Length: 2, Description: "clean"}, {Offset: 2, Length: 2, Description: "dirty"}, {Offset: 4, Length: 1, Description: "clean"}, {Offset: 5, Length: 6, Description: "dirty,zero"}, {Offset: 11, Length: 3, Description: "clean"}, {Offset: 14, Length: 2, Description: "dirty"}}},
				{secondIncrement, []mapExtent{{Offset: 0, Length: 1, Description: "clean"}, {Offset: 1, Length: 1, Description: "dirty"}, {Offset: 2, Length: 13, Description: "clean"}, {Offset: 15, Length: 1, Description: "dirty,zero"}}},
			}
			members := []storagerestore.Member{}
			for index, step := range steps {
				members = append(members, produceRestoreRoundTripMember(t, store, members, index+1, step.data, step.maps, key))
			}
			if members[1].Request.Plan.Parent.GenerationID == members[2].Request.Plan.Parent.GenerationID {
				t.Fatal("each parent must identify its own published generation")
			}
			open := func(_ context.Context, target models.StorageTarget, obj models.StorageObjectReceipt) (io.ReadCloser, error) {
				data, exists := store.data[obj.Key]
				if !exists || target != store.target || obj.ETag != nativeHash(data) {
					return nil, fmt.Errorf("unexpected stored object identity")
				}
				return io.NopCloser(bytes.NewReader(data)), nil
			}
			keys := func(context.Context, storagerestore.Member) ([]byte, error) { return bytes.Clone(key), nil }
			verified, err := storagerestore.Verify(context.Background(), members, open, keys)
			if err != nil || verified == nil || len(verified.Members) != 3 {
				t.Fatalf("verify actual producer artifacts: result=%+v error=%v", verified, err)
			}
			disks, err := storagerestore.Assemble(context.Background(), members, filepath.Join(t.TempDir(), "recovered"), open, keys)
			if err != nil || len(disks) != 1 {
				t.Fatalf("assemble producer artifacts: disks=%d error=%v", len(disks), err)
			}
			got, err := os.ReadFile(disks[0].Path)
			if err != nil || !bytes.Equal(got, secondIncrement) || disks[0].SHA256 != nativeHash(secondIncrement) {
				t.Fatalf("restored=%q expected=%q disk=%+v error=%v", got, secondIncrement, disks[0], err)
			}
		})
	}
}

func produceRestoreRoundTripMember(t *testing.T, store *restoreRoundTripStore, previous []storagerestore.Member, index int, data []byte, extents []mapExtent, key []byte) storagerestore.Member {
	t.Helper()
	body, err := os.ReadFile("../../../contracts/storage_semantic_valid.json")
	if err != nil {
		t.Fatal(err)
	}
	r, err := models.DecodeStorageTransaction(body)
	if err != nil {
		t.Fatal(err)
	}
	r.BackupID = fmt.Sprintf("33333333-3333-4333-8333-%012d", index)
	r.ReservationID = fmt.Sprintf("55555555-5555-4555-8555-%012d", index)
	// One chain can span an upgrade and a later legacy preference. Each
	// member keeps its own hash-bound profile during verification/restore.
	if index == 2 {
		r.Plan.TransferProfile = models.KubevirtTransfer32
	}
	r.Plan.AttemptID = r.ReservationID
	r.Plan.Source.Volumes[0].CapacityBytes = int64(len(data))
	if len(previous) > 0 {
		parent := previous[len(previous)-1]
		_, digest, err := models.CanonicalReceipt(&parent.Request, parent.Receipt)
		if err != nil {
			t.Fatal(err)
		}
		r.Plan.BackupType = "incremental"
		r.Plan.Parent = &models.StorageParent{BackupID: parent.Request.BackupID, RootBackupID: previous[0].Request.BackupID, ReceiptSHA256: digest,
			GenerationID: fmt.Sprintf("77777777-7777-4777-8777-%012d", index-1), TrackerUID: "roundtrip-tracker", Checkpoint: fmt.Sprintf("roundtrip-checkpoint-%d", index-1)}
	}
	if key != nil {
		ref := "kek:66666666-6666-4666-8666-666666666666:aaaaaaaaaaaaaaaa"
		r.Plan.Encryption = models.StorageEncryption{Format: "vnbu1-aes256gcm-chunk5242880", KeyRef: &ref}
	}
	for i := range r.Plan.Artifacts {
		a := &r.Plan.Artifacts[i]
		a.Key = "vnbui-owned/v1/" + nativeHash([]byte(r.OrgID)) + "/" + nativeHash([]byte(r.BackupID)) + "/payload/" + r.ReservationID + "/" + nativeHash([]byte(a.VolumeID)) + "/" + a.Role
		if a.Role == "volume_payload" {
			a.PlaintextMax, a.CiphertextMax = int64(len(data)), int64(len(data))
			if key != nil {
				a.CiphertextMin, a.CiphertextMax = 5, 5+int64(len(data))+32
			}
		}
	}
	canonical, err := models.StorageCanonical(r.Plan)
	if err != nil {
		t.Fatal(err)
	}
	r.PlanSHA256 = nativeHash(canonical)
	body, err = json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	journal, err := storageupload.Create(t.TempDir(), body)
	if err != nil {
		t.Fatal(err)
	}
	defer journal.Close()
	store.target = r.Plan.Target
	read := &transactionExport{ctx: context.Background(), token: "roundtrip-export-token", validate: func() error { return nil }, client: &http.Client{Transport: exportTransport(func(req *http.Request) (*http.Response, error) {
		if req.Header.Get(exportTokenHeader) != "roundtrip-export-token" {
			t.Fatal("range read did not carry export token")
		}
		if req.URL.Path == "/map" {
			return exportResponse(mapPage{Extents: extents}), nil
		}
		offset, offsetErr := strconv.Atoi(req.URL.Query().Get("offset"))
		length, lengthErr := strconv.Atoi(req.URL.Query().Get("length"))
		if req.URL.Path != "/data" || offsetErr != nil || lengthErr != nil || offset < 0 || length <= 0 || offset > len(data) || length > len(data)-offset {
			return nil, fmt.Errorf("invalid mapped data request")
		}
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader(data[offset : offset+length]))}, nil
	})}}
	volume := storageupload.ExportVolume{Name: r.Plan.Source.Volumes[0].Name, VolumeID: r.Plan.Source.Volumes[0].PVCUID, DiskTarget: "vda", DataURL: "https://export.example/data", MapURL: "https://export.example/map"}
	mapped, _, err := read.extents(volume, uint64(len(data)), r.Plan.BackupType, storageupload.MaxExportRanges)
	if err != nil {
		t.Fatal(err)
	}
	state := storageupload.State{Request: *r, Export: &storageupload.ExportState{Checkpoint: fmt.Sprintf("roundtrip-checkpoint-%d", index), Volumes: []storageupload.ExportVolume{volume}}, Maps: []storageupload.ExportMap{mapped}}
	definition, err := json.Marshal(map[string]interface{}{
		"apiVersion": "kubevirt.io/v1", "kind": "VirtualMachine",
		"metadata": map[string]interface{}{"name": r.Plan.VMName, "namespace": r.Plan.Source.Namespace, "uid": r.Plan.Source.VMUID, "resourceVersion": "10"},
		"spec":     map[string]interface{}{"running": true},
	})
	if err != nil {
		t.Fatal(err)
	}
	if key != nil {
		var encrypted bytes.Buffer
		if err := encryption.EncryptStream(bytes.NewReader(definition), &encrypted, key); err != nil {
			t.Fatal(err)
		}
		definition = encrypted.Bytes()
	}
	state.Native = &storageupload.NativeState{EncodedVMDefinition: base64.StdEncoding.EncodeToString(definition)}
	inputs, err := transactionInputs(read, &state)
	if err != nil {
		t.Fatal(err)
	}
	if err := journal.UploadAll(context.Background(), store, inputs, key); err != nil {
		t.Fatal(err)
	}
	snapshot, err := journal.Snapshot()
	if err != nil || snapshot.Receipt == nil {
		t.Fatal("producer receipt missing", err)
	}
	return storagerestore.Member{Request: *r, Receipt: *snapshot.Receipt}
}
