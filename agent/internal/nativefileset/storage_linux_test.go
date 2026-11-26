//go:build linux

package nativefileset

import (
	"bytes"
	"encoding/json"
	"os"
	"reflect"
	"slices"
	"testing"

	"vnbui/agent/internal/encryption"
	"vnbui/agent/internal/models"
)

type storageExample struct {
	Request       models.NativeTransactionRequest `json:"request"`
	Source        models.NativeStorageSource      `json:"source"`
	OrgID         string                          `json:"org_id"`
	Target        models.StorageTarget            `json:"target"`
	Encryption    models.StorageEncryption        `json:"encryption"`
	Artifacts     []models.NativeStorageArtifact  `json:"artifacts"`
	Receipt       models.NativeStorageReceipt     `json:"receipt"`
	ReceiptSHA256 string                          `json:"receipt_sha256"`
	SourceSHA256  string                          `json:"source_sha256"`
}

func storageExamples(t *testing.T) []storageExample {
	t.Helper()
	body, err := os.ReadFile("../../contracts/native_storage_examples.json")
	if err != nil {
		t.Fatal(err)
	}
	var examples []storageExample
	if err := json.Unmarshal(body, &examples); err != nil {
		t.Fatal(err)
	}
	if len(examples) != 2 {
		t.Fatal("missing encrypted/plain vectors")
	}
	return examples
}

func TestNativeStorageExamples(t *testing.T) {
	for _, e := range storageExamples(t) {
		t.Run(e.Encryption.Format, func(t *testing.T) {
			request, err := models.StorageCanonical(e.Request)
			if err != nil {
				t.Fatal(err)
			}
			decoded, err := DecodeTransaction(request)
			if err != nil || !reflect.DeepEqual(*decoded, e.Request) {
				t.Fatal("whole plan parity", err)
			}
			if _, err := models.DecodeStorageTransaction(request); err == nil {
				t.Fatal("native accepted as KubeVirt")
			}
			body, err := models.StorageCanonical(e.Source)
			if err != nil || hash(body) != e.SourceSHA256 {
				t.Fatal("source digest parity", err)
			}
			if _, err := DecodeSource(body); err != nil {
				t.Fatal(err)
			}
			artifacts, err := BuildArtifacts(e.Source, e.OrgID, e.Receipt.BackupID, e.Receipt.ReservationID, e.Encryption)
			if err != nil || !reflect.DeepEqual(artifacts, e.Artifacts) {
				t.Fatal("artifact parity", err)
			}
			body, digest, err := CanonicalReceipt(e.Receipt, artifacts, e.Receipt.BackupID, e.Receipt.ReservationID, e.Target, e.Encryption)
			if err != nil || digest != e.ReceiptSHA256 {
				t.Fatal("receipt parity", err)
			}
			var old models.StorageReceipt
			if models.DecodeStorageValue(body, &old, models.MaxStorageReceiptBytes) == nil {
				t.Fatal("native receipt accepted as KubeVirt")
			}
			slices.Reverse(e.Source.Inventory.Files)
			inventory, err := models.StorageCanonical(e.Source.Inventory)
			if err != nil {
				t.Fatal(err)
			}
			e.Source.InventorySHA256 = hash(inventory)
			again, err := BuildArtifacts(e.Source, e.OrgID, e.Receipt.BackupID, e.Receipt.ReservationID, e.Encryption)
			if err != nil || !reflect.DeepEqual(again, artifacts) {
				t.Fatal("order became artifact identity", err)
			}
			changed, _ := models.StorageCanonical(e.Source)
			if hash(changed) == e.SourceSHA256 {
				t.Fatal("reordered evidence became identical replay")
			}
		})
	}
}

func TestNativeStorageReceiptRefusals(t *testing.T) {
	for _, e := range storageExamples(t) {
		for _, fault := range []string{"representation", "schema", "extra", "missing", "duplicate", "artifact", "disk", "role", "key", "count", "hash", "endpoint", "backup", "version"} {
			t.Run(e.Encryption.Format+"/"+fault, func(t *testing.T) {
				body, _ := json.Marshal(e.Receipt)
				var value map[string]any
				if err := json.Unmarshal(body, &value); err != nil {
					t.Fatal(err)
				}
				objects := value["objects"].([]any)
				o := objects[0].(map[string]any)
				switch fault {
				case "representation", "endpoint":
					value[fault] = "foreign"
				case "backup":
					value["backup_id"] = "foreign"
				case "schema":
					value["schema"] = true
				case "extra":
					o["volume_id"] = "guessed"
				case "missing":
					value["objects"] = objects[:len(objects)-1]
				case "duplicate":
					objects[len(objects)-1] = o
				case "artifact":
					o["artifact_id"] = "wrong"
				case "disk":
					o["disk_id"] = "guessed"
				case "role":
					o["role"] = "volume_payload"
				case "key":
					o["key"] = o["key"].(string) + "/other"
				case "count":
					o["ciphertext_bytes"] = o["ciphertext_bytes"].(float64) + 1
				case "hash":
					o["plaintext_sha256"] = "not-a-hash"
				case "version":
					o["version_id"] = ""
				}
				body, _ = json.Marshal(value)
				var receipt models.NativeStorageReceipt
				if models.DecodeStorageValue(body, &receipt, models.MaxStorageReceiptBytes) != nil {
					return
				}
				if _, _, err := CanonicalReceipt(receipt, e.Artifacts, e.Receipt.BackupID, e.Receipt.ReservationID, e.Target, e.Encryption); err == nil {
					t.Fatal("invalid receipt accepted")
				}
			})
		}
	}
}

func TestNativeStorageSourceRefusals(t *testing.T) {
	for _, fault := range []string{"representation", "digest", "agent", "extra", "member", "missing", "duplicate-json"} {
		t.Run(fault, func(t *testing.T) {
			e := storageExamples(t)[0]
			s := &e.Source
			switch fault {
			case "representation":
				s.Representation = "libvirt-native-fileset/2"
			case "digest":
				s.InventorySHA256 = "wrong"
			case "agent":
				s.AgentID = "display-name"
			case "member":
				s.Inventory.Files[0].MemberCheckpoint = "foreign"
			case "missing":
				s.Inventory.Files = s.Inventory.Files[1:]
			}
			if fault == "missing" || fault == "member" {
				b, _ := models.StorageCanonical(s.Inventory)
				s.InventorySHA256 = hash(b)
			}
			body, _ := models.StorageCanonical(s)
			if fault == "extra" {
				body = append([]byte(`{"namespace":"guessed",`), body[1:]...)
			}
			if fault == "duplicate-json" {
				body = append([]byte(`{"agent_id":"duplicate",`), body[1:]...)
			}
			if _, err := DecodeSource(body); err == nil {
				t.Fatal("invalid source admitted")
			}
		})
	}
}

func TestNativeStorageUnsignedCustodyDigest(t *testing.T) {
	e := storageExamples(t)[0]
	e.Source.Inventory.Files[0].Inode = ^uint64(0)
	body, err := models.StorageCanonical(e.Source.Inventory)
	if err != nil || !bytes.Contains(body, []byte("18446744073709551615")) {
		t.Fatal("uint64 custody lost", err)
	}
	e.Source.InventorySHA256 = hash(body)
	body, _ = models.StorageCanonical(e.Source)
	if _, err := DecodeSource(body); err != nil {
		t.Fatal(err)
	}
}

func TestNativeStorageArtifactBindingRefusals(t *testing.T) {
	for _, fault := range []string{"org", "backup", "attempt", "format", "key", "raw-key"} {
		t.Run(fault, func(t *testing.T) {
			e := storageExamples(t)[1]
			switch fault {
			case "org":
				e.OrgID = "tenant-name"
			case "backup":
				e.Receipt.BackupID = "00000000-0000-4000-8000-000000000001"
			case "attempt":
				e.Receipt.ReservationID = "00000000-0000-4000-8000-000000000001"
			case "format":
				e.Encryption.Format = "unknown"
			case "key":
				e.Encryption.KeyRef = nil
			case "raw-key":
				value := "not-an-authoritative-key-reference"
				e.Encryption.KeyRef = &value
			}
			if _, err := BuildArtifacts(e.Source, e.OrgID, e.Receipt.BackupID, e.Receipt.ReservationID, e.Encryption); err == nil {
				t.Fatal("unbound native artifacts admitted")
			}
		})
	}
}

func TestNativeStorageAllFileFramingMatchesProducer(t *testing.T) {
	e := storageExamples(t)[1]
	for _, size := range []int64{0, 1, 5242880, 5242881} {
		for i := range e.Source.Inventory.Files {
			e.Source.Inventory.Files[i].Size = size
		}
		body, _ := models.StorageCanonical(e.Source.Inventory)
		e.Source.InventorySHA256 = hash(body)
		artifacts, err := BuildArtifacts(e.Source, e.OrgID, e.Receipt.BackupID, e.Receipt.ReservationID, e.Encryption)
		if err != nil {
			t.Fatal(err)
		}
		var out bytes.Buffer
		if err := encryption.EncryptStreamChunked(bytes.NewReader(make([]byte, size)), &out, make([]byte, 32), 5242880); err != nil {
			t.Fatal(err)
		}
		for _, a := range artifacts {
			if a.PlaintextMin != size || a.PlaintextMax != size || a.CiphertextMin != int64(out.Len()) || a.CiphertextMax != int64(out.Len()) {
				t.Fatal("per-file framing drift")
			}
		}
	}
}
