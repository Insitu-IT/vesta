package storageupload

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestVMDefinitionFrozenEncryptedAndCleartext(t *testing.T) {
	for _, encrypted := range []bool{false, true} {
		t.Run(map[bool]string{false: "plain", true: "encrypted"}[encrypted], func(t *testing.T) {
			root, body := t.TempDir(), request(t, encrypted)
			j, err := Create(root, body)
			if err != nil {
				t.Fatal(err)
			}
			r := j.state.Request
			doc, _ := json.Marshal(map[string]any{
				"apiVersion": "kubevirt.io/v1", "kind": "VirtualMachine",
				"metadata": map[string]any{"namespace": r.Plan.Source.Namespace, "name": r.Plan.VMName, "uid": r.Plan.Source.VMUID, "resourceVersion": "17"},
				"spec":     map[string]any{"template": map[string]any{"spec": map[string]any{"cloudInit": "private-bootstrap"}}},
			})
			n := nativePlan()
			n.VMDefinition = string(doc)
			if err = j.PrepareNative(n); err != nil {
				t.Fatal(err)
			}
			var key []byte
			if encrypted {
				key = bytes.Repeat([]byte{117}, 32)
			}
			defer clear(key)
			if err = j.SealVMDefinition(key); err != nil {
				t.Fatal(err)
			}
			s, _ := j.Snapshot()
			encoded := s.Native.EncodedVMDefinition
			data, err := base64.StdEncoding.Strict().DecodeString(encoded)
			if err != nil || encoded == "" {
				t.Fatal("missing stored definition")
			}
			if encrypted {
				if !bytes.HasPrefix(data, []byte("VNBU")) || bytes.Contains(data, []byte("private-bootstrap")) {
					t.Fatal("definition not encrypted")
				}
			} else if !bytes.Equal(data, doc) {
				t.Fatal("definition changed")
			}
			if err = j.Close(); err != nil {
				t.Fatal(err)
			}
			j, err = Open(root, body)
			if err != nil {
				t.Fatal(err)
			}
			defer j.Close()
			if err = j.SealVMDefinition(key); err != nil {
				t.Fatal(err)
			}
			s, _ = j.Snapshot()
			if s.Native.EncodedVMDefinition != encoded {
				t.Fatal("replay re-encrypted captured definition")
			}
			journal, _ := os.ReadFile(filepath.Join(root, r.ReservationID, "transaction.json"))
			if encrypted && bytes.Contains(journal, []byte(base64.StdEncoding.EncodeToString(key))) {
				t.Fatal("DEK entered journal")
			}
		})
	}
}
