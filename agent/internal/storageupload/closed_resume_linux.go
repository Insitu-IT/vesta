//go:build linux

package storageupload

import (
	"os"
	"path/filepath"
	"reflect"

	"vnbui/agent/internal/models"
	"vnbui/agent/internal/nativefileset"
)

// CanResumeClosedNative only inspects the original closed inventory and journal.
// It does not create an uploader/producer, clear held custody or touch a provider.
func CanResumeClosedNative(journalRoot, tree, org, agent string, admission []byte) error {
	var closed ClosedNativeAdmission
	if models.DecodeStorageValue(admission, &closed, models.MaxStorageRequestBytes) != nil ||
		nativefileset.Validate(closed.Inventory) != nil || !validHash(closed.IntentSHA256) ||
		closed.PushResult.Manifest.Schema != "libvirt-push-qcow2/1" ||
		closed.ClosedJob.JobID != closed.Inventory.JobID || closed.ClosedJob.AttemptID != closed.Inventory.AttemptID ||
		(closed.ClosedJob.State != "exited" && closed.ClosedJob.State != "sealed") || closed.ClosedJob.ExitCode != 0 {
		return ErrHeld
	}
	if _, err := os.Lstat(filepath.Join(journalRoot, closed.Inventory.AttemptID)); os.IsNotExist(err) {
		// The durable admission precedes first upload. A closed tree can enter
		// that original transaction; no producer invocation is necessary.
		return nativefileset.CheckTree(tree, closed.Inventory)
	} else if err != nil {
		return ErrHeld
	}
	j, err := openFileSet(journalRoot, closed.Inventory.AttemptID, func(r models.NativeTransactionRequest) bool {
		return r.OrgID == org && r.AgentID == agent && r.BackupID == closed.Inventory.BackupID &&
			r.ReservationID == closed.Inventory.AttemptID && reflect.DeepEqual(r.Plan.Source.Inventory, closed.Inventory)
	})
	if err != nil {
		return ErrHeld
	}
	defer j.Close()
	if j.state.Phase == "held" {
		return ErrHeld
	}
	if j.state.Phase == "uploading" {
		return nativefileset.CheckTree(tree, closed.Inventory)
	}
	return nil // Prepared/accepted receipts need no reread of original payloads.
}
