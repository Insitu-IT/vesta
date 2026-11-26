package storagerestore

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"vnbui/agent/internal/encryption"
)

func TestFreshFilesystemDestinationRoundTripAndRefusal(t *testing.T) {
	for _, encrypted := range []bool{false, true} {
		t.Run(map[bool]string{false: "plain", true: "encrypted"}[encrypted], func(t *testing.T) {
			members, store, keys, want := chainFixture(t, encrypted)
			file := filepath.Join(t.TempDir(), "disk.img")
			targets := []Destination{{VolumeName: members[0].Request.Plan.Source.Volumes[0].Name, Path: file}}
			disks, err := AssembleTo(context.Background(), members, targets, store.open, keys)
			if err != nil {
				t.Fatal(err)
			}
			got, err := os.ReadFile(file)
			if err != nil || !bytes.Equal(got, want) || disks[0].SHA256 != hashBytes(want) {
				t.Fatal(got, err)
			}
			if _, err = AssembleTo(context.Background(), members, targets, store.open, keys); err == nil {
				t.Fatal("existing filesystem disk overwritten")
			}
			targets[0].Block = true
			if _, err = AssembleTo(context.Background(), members, targets, store.open, keys); err == nil {
				t.Fatal("regular file accepted as block device")
			}
			got, _ = os.ReadFile(file)
			if !bytes.Equal(got, want) {
				t.Fatal("refused target was modified")
			}
		})
	}
}

func TestBlockInitializationZerosEntireDeviceRange(t *testing.T) {
	// Exercise the bounded block initialization algorithm against a file. An
	// actual CSI block mount is an installation test, not faked as a device.
	f, err := os.CreateTemp(t.TempDir(), "block-algorithm-")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	data := bytes.Repeat([]byte{0xff}, 3*copyBufferBytes+13)
	_, _ = f.Write(data)
	_, _ = f.Seek(0, 0)
	if err = zeroDestination(context.Background(), f, int64(len(data))); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(f.Name())
	if !bytes.Equal(got, make([]byte, len(data))) {
		t.Fatal("old block bytes survived")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err = zeroDestination(ctx, f, 1); err == nil {
		t.Fatal("cancelled zero operation continued")
	}
}

func definitionFor(member Member) map[string]interface{} {
	s := member.Request.Plan.Source
	return map[string]interface{}{"apiVersion": "kubevirt.io/v1", "kind": "VirtualMachine", "metadata": map[string]interface{}{"name": member.Request.Plan.VMName, "namespace": s.Namespace, "uid": s.VMUID, "resourceVersion": "10"}, "spec": map[string]interface{}{"running": true, "template": map[string]interface{}{"spec": map[string]interface{}{"domain": map[string]interface{}{"memory": map[string]interface{}{"guest": "512Mi"}}}}}}
}

func attachDefinition(t *testing.T, member *Member, store *memoryStore, encoded string) {
	t.Helper()
	for i, obj := range member.Receipt.Objects {
		if obj.Role == "volume_manifest" {
			var manifest map[string]interface{}
			if err := json.Unmarshal(store.data[obj.Key], &manifest); err != nil {
				t.Fatal(err)
			}
			manifest["vm_definition"] = encoded
			body, _ := json.Marshal(manifest)
			store.data[obj.Key] = body
			member.Receipt.Objects[i].PlaintextBytes = int64(len(body))
			member.Receipt.Objects[i].CiphertextBytes = int64(len(body))
			member.Receipt.Objects[i].PlaintextSHA256 = hashBytes(body)
			member.Receipt.Objects[i].CiphertextSHA256 = hashBytes(body)
		}
	}
}

func TestReceiptBoundVMDefinition(t *testing.T) {
	for _, encrypted := range []bool{false, true} {
		t.Run(map[bool]string{false: "plain", true: "encrypted"}[encrypted], func(t *testing.T) {
			members, store, keys, _ := chainFixture(t, encrypted)
			last := &members[len(members)-1]
			if _, err := ReadVMDefinition(context.Background(), members, store.open, keys); err == nil {
				t.Fatal("definition inferred without a capture")
			}
			definition := definitionFor(*last)
			body, _ := json.Marshal(definition)
			if encrypted {
				key, _ := keys(context.Background(), *last)
				var output bytes.Buffer
				if err := encryption.EncryptStream(bytes.NewReader(body), &output, key); err != nil {
					t.Fatal(err)
				}
				body = output.Bytes()
			}
			attachDefinition(t, last, store, base64.StdEncoding.EncodeToString(body))
			got, err := ReadVMDefinition(context.Background(), members, store.open, keys)
			if err != nil || got["kind"] != "VirtualMachine" {
				t.Fatal(got, err)
			}
			body[len(body)-1] ^= 0x20
			attachDefinition(t, last, store, base64.StdEncoding.EncodeToString(body))
			if _, err = ReadVMDefinition(context.Background(), members, store.open, keys); err == nil {
				t.Fatal("invalid or unauthenticated definition accepted")
			}
		})
	}
}
