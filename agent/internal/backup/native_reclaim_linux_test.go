//go:build linux

package backup

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"vnbui/agent/internal/models"
	"vnbui/agent/internal/storageupload"
)

func nativeReclaimFixture(t *testing.T) (string, *NativeJobRequest, []byte, models.NativeFileSet) {
	t.Helper()
	e, _, request := nativeRunnerFixture(t)
	path := filepath.Join(e.cfg.BackupStoragePath, "native-transactions", "attempts", request.Intent.AttemptID)
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	producer := NativePushRequest{Schema: NativePushFormat, URI: "qemu:///system",
		BackupID: request.Intent.BackupID, AttemptID: request.Intent.AttemptID,
		DomainUUID: request.Intent.Source.DomainUUID, Disks: request.Intent.Source.Disks,
		Exclusions: request.Intent.Source.Exclusions, OutputPath: path, TimeoutSeconds: 60}
	result := sealedNativeResult(t, producer)
	admission, err := CaptureNativePush(producer, *result, request.IntentSHA256, strings.Repeat("a", 32))
	if err != nil {
		t.Fatal(err)
	}
	var closed storageupload.ClosedNativeAdmission
	if err := models.DecodeStorageValue(admission, &closed, models.MaxStorageRequestBytes); err != nil {
		t.Fatal(err)
	}
	return path, request, admission, closed.Inventory
}

func nativeAcceptedFixture(request *NativeJobRequest) *models.StorageAcceptance {
	return &models.StorageAcceptance{Accepted: true, ReservationID: request.Intent.AttemptID,
		ReceiptSHA256: strings.Repeat("a", 64), AcceptanceID: "accepted-fixture"}
}

func TestPublishedNativeReclaimResumesAfterPartialUnlink(t *testing.T) {
	path, request, admission, inventory := nativeReclaimFixture(t)
	if published, err := readNativePublished(path, request, admission); err != nil || published {
		t.Fatal("unpublished attempt had completion authority", err)
	}
	if err := writeNativePublished(path, request, admission, nativeAcceptedFixture(request)); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(NativePushTree(path), inventory.Files[0].Path)); err != nil {
		t.Fatal(err)
	}
	if err := reclaimNativeTree(path, inventory); err != nil {
		t.Fatal(err)
	}
	if err := reclaimNativeTree(path, inventory); err != nil {
		t.Fatal("idempotent cleanup refused", err)
	}
	if _, err := os.Lstat(NativePushTree(path)); !os.IsNotExist(err) {
		t.Fatal("local producer data still exists", err)
	}
	if _, err := readNativeFile(filepath.Join(path, "admission.json")); err != nil {
		t.Fatal("original admission was discarded", err)
	}
	if published, err := readNativePublished(path, request, admission); err != nil || !published {
		t.Fatal("completion marker did not survive reclamation", err)
	}
}

func TestNativeRunnerRestartOnlyReclaimsPartiallyPublishedTree(t *testing.T) {
	path, request, admission, inventory := nativeReclaimFixture(t)
	if err := writeNativePublished(path, request, admission, nativeAcceptedFixture(request)); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(NativePushTree(path), inventory.Files[0].Path)); err != nil {
		t.Fatal(err)
	}
	e, body, _ := nativeRunnerFixture(t)
	// The fixture above has its own temp root. Point the new runner at the
	// captured attempt to exercise its post-restart cleanup path.
	e.cfg.BackupStoragePath = filepath.Dir(filepath.Dir(filepath.Dir(path)))
	r := nativeReady(t, e)
	if err := e.StartNativeJob(context.Background(), body); err != nil {
		t.Fatal(err)
	}
	var effects atomic.Int32
	r.produce = func(context.Context, NativePushRequest) (*NativePushResult, error) {
		effects.Add(1)
		return nil, ErrNativeUncertain
	}
	r.upload = func(context.Context, string, string, string, string, string, []byte, *http.Client, *http.Client, func(context.Context) (string, error)) (*models.StorageAcceptance, error) {
		effects.Add(1)
		return nil, ErrNativeUncertain
	}
	r.publish = func(context.Context, string, string, *models.StorageAcceptance, *http.Client, func(context.Context) (string, error)) error {
		effects.Add(1)
		return ErrNativeUncertain
	}
	go r.run()
	nativeWait(t, e, request.Intent.BackupID, models.TaskStatusCompleted)
	if err := e.CloseStorageTransactions(); err != nil {
		t.Fatal(err)
	}
	if effects.Load() != 0 {
		t.Fatal("restart repeated producer, upload or publication")
	}
	if _, err := os.Lstat(NativePushTree(path)); !os.IsNotExist(err) {
		t.Fatal("restart retained published producer files", err)
	}
}

func TestPublishedNativeReclaimRefusesForeignOrReplacedFiles(t *testing.T) {
	for _, kind := range []string{"foreign", "replacement", "symlink"} {
		t.Run(kind, func(t *testing.T) {
			path, request, admission, inventory := nativeReclaimFixture(t)
			if err := writeNativePublished(path, request, admission, nativeAcceptedFixture(request)); err != nil {
				t.Fatal(err)
			}
			tree := NativePushTree(path)
			switch kind {
			case "foreign":
				if err := os.WriteFile(filepath.Join(tree, "foreign"), []byte("keep"), 0600); err != nil {
					t.Fatal(err)
				}
			case "replacement", "symlink":
				member := filepath.Join(tree, inventory.Files[0].Path)
				if err := os.Remove(member); err != nil {
					t.Fatal(err)
				}
				if kind == "replacement" {
					if err := os.WriteFile(member, []byte("replacement"), 0600); err != nil {
						t.Fatal(err)
					}
				} else if err := os.Symlink(filepath.Join(tree, inventory.Files[1].Path), member); err != nil {
					t.Fatal(err)
				}
			}
			if err := reclaimNativeTree(path, inventory); err == nil {
				t.Fatal("foreign local file was reclaimed")
			}
			if _, err := os.Lstat(tree); err != nil {
				t.Fatal("held tree was removed", err)
			}
		})
	}
}

func TestNativePublishedMarkerRejectsChangedCustody(t *testing.T) {
	path, request, admission, _ := nativeReclaimFixture(t)
	if err := writeNativePublished(path, request, admission, nativeAcceptedFixture(request)); err != nil {
		t.Fatal(err)
	}
	wrong := *request
	wrong.IntentSHA256 = strings.Repeat("b", 64)
	if published, err := readNativePublished(path, &wrong, admission); err == nil || published {
		t.Fatal("changed intent reused completion marker")
	}
	if published, err := readNativePublished(path, request, []byte("changed admission")); err == nil || published {
		t.Fatal("changed admission reused completion marker")
	}
}
