//go:build linux

package backup

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"vnbui/agent/internal/models"
	"vnbui/agent/internal/nativefileset"
	"vnbui/agent/internal/storageupload"
)

func nativeCaptureFixture(t *testing.T) (NativePushRequest, NativePushResult) {
	t.Helper()
	request := NativePushRequest{Schema: NativePushFormat, URI: "qemu:///system",
		BackupID: "22222222-2222-4222-8222-222222222222", AttemptID: "33333333-3333-4333-8333-333333333333",
		DomainUUID: "11111111-1111-4111-8111-111111111111", Exclusions: []string{},
		Disks:      []NativeSourceDisk{{Target: "vda", Source: "/vm/source.qcow2", Format: "qcow2", Bus: "virtio"}},
		OutputPath: t.TempDir(), TimeoutSeconds: 60}
	if err := os.Mkdir(NativePushTree(request.OutputPath), 0700); err != nil {
		t.Fatal(err)
	}
	hash := func(body []byte) string { h := sha256.Sum256(body); return hex.EncodeToString(h[:]) }
	files := map[string][]byte{"domain.xml": []byte("<domain/>"), "checkpoint.xml": []byte("<domaincheckpoint/>"), "vda.qcow2": []byte("closed producer payload")}
	m := NativePushManifest{Schema: NativePushFormat, BackupID: request.BackupID, AttemptID: request.AttemptID,
		DomainUUID: request.DomainUUID, Checkpoint: "vnbui-" + request.AttemptID,
		CheckpointSHA256: hash(files["checkpoint.xml"]), DomainXMLSHA256: hash(files["domain.xml"]),
		Source: request.Disks, Exclusions: request.Exclusions,
		Disks: []NativePushDisk{{Target: "vda", File: "vda.qcow2", VirtualSize: 4096,
			SizeBytes: int64(len(files["vda.qcow2"])), SHA256: hash(files["vda.qcow2"])}}}
	canonical, err := models.StorageCanonical(m)
	if err != nil {
		t.Fatal(err)
	}
	files["manifest.json"] = canonical
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(NativePushTree(request.OutputPath), name), body, 0600); err != nil {
			t.Fatal(err)
		}
	}
	return request, NativePushResult{Manifest: m, ManifestSHA256: hash(canonical)}
}

func TestCaptureNativePushIsExactDurableUploadAdmission(t *testing.T) {
	request, result := nativeCaptureFixture(t)
	body, err := CaptureNativePush(request, result, strings.Repeat("a", 64), strings.Repeat("b", 32))
	if err != nil {
		t.Fatal(err)
	}
	var admission storageupload.ClosedNativeAdmission
	if err := models.DecodeStorageValue(body, &admission, models.MaxStorageRequestBytes); err != nil {
		t.Fatalf("uploader cannot consume captured producer: %v", err)
	}
	if err := nativefileset.CheckTree(NativePushTree(request.OutputPath), admission.Inventory); err != nil {
		t.Fatal(err)
	}
	if len(admission.Inventory.Files) != 4 || admission.Inventory.Checkpoint != result.Manifest.Checkpoint ||
		admission.PushResult.ManifestSHA256 != result.ManifestSHA256 || admission.ClosedJob.State != "exited" {
		t.Fatal("producer/receipt membership changed")
	}
	saved, err := os.ReadFile(filepath.Join(request.OutputPath, "admission.json"))
	if err != nil || string(saved) != string(body) {
		t.Fatal("upload admitted before durable native result")
	}
	if _, err := CaptureNativePush(request, result, strings.Repeat("a", 64), strings.Repeat("b", 32)); err == nil {
		t.Fatal("rewrote original invocation custody")
	}
}

func TestCaptureNativePushRefusesForeignFileAndChangedManifest(t *testing.T) {
	for _, fault := range []string{"unknown-file", "manifest", "parent", "attempt"} {
		t.Run(fault, func(t *testing.T) {
			request, result := nativeCaptureFixture(t)
			switch fault {
			case "unknown-file":
				if err := os.WriteFile(filepath.Join(NativePushTree(request.OutputPath), "foreign"), []byte("keep me"), 0600); err != nil {
					t.Fatal(err)
				}
			case "manifest":
				if err := os.WriteFile(filepath.Join(NativePushTree(request.OutputPath), "manifest.json"), []byte("{}"), 0600); err != nil {
					t.Fatal(err)
				}
			case "parent":
				request.Parent = &result
			case "attempt":
				request.AttemptID = request.BackupID
			}
			if _, err := CaptureNativePush(request, result, strings.Repeat("a", 64), strings.Repeat("b", 32)); err == nil {
				t.Fatal("ambiguous native custody accepted")
			}
			if _, err := os.Stat(filepath.Join(request.OutputPath, "admission.json")); !os.IsNotExist(err) {
				t.Fatal("uncertain attempt gained upload admission")
			}
			if _, err := os.Stat(filepath.Join(NativePushTree(request.OutputPath), "vda.qcow2")); err != nil {
				t.Fatal("uncertain output removed")
			}
		})
	}
}
