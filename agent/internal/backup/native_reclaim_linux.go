//go:build linux

package backup

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"

	"vnbui/agent/internal/models"
	"vnbui/agent/internal/nativefileset"
)

// A completed backend publication is the only authority for reclaiming the
// native producer's local files. The marker precedes every unlink, so a crash
// during reclamation cannot turn missing files into a producer/upload retry.
type nativePublishedMarker struct {
	Schema          int    `json:"schema"`
	BackupID        string `json:"backup_id"`
	AttemptID       string `json:"attempt_id"`
	IntentSHA256    string `json:"intent_sha256"`
	AdmissionSHA256 string `json:"admission_sha256"`
	ReceiptSHA256   string `json:"receipt_sha256"`
	AcceptanceID    string `json:"acceptance_id"`
}

func nativePublishedPath(attemptPath string) string {
	return filepath.Join(attemptPath, "published.json")
}

func readNativePublished(attemptPath string, request *NativeJobRequest, admission []byte) (bool, error) {
	body, err := readNativeFile(nativePublishedPath(attemptPath))
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, ErrNativeUncertain
	}
	var marker nativePublishedMarker
	if models.DecodeStorageValue(body, &marker, models.MaxStorageRequestBytes) != nil {
		return false, ErrNativeUncertain
	}
	admissionHash := sha256.Sum256(admission)
	if marker.Schema != 1 || marker.BackupID != request.Intent.BackupID ||
		marker.AttemptID != request.Intent.AttemptID || marker.IntentSHA256 != request.IntentSHA256 ||
		marker.AdmissionSHA256 != hex.EncodeToString(admissionHash[:]) ||
		!validNativeDigest(marker.ReceiptSHA256) || marker.AcceptanceID == "" {
		return false, ErrNativeUncertain
	}
	return true, nil
}

func validNativeDigest(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size && hex.EncodeToString(decoded) == value
}

func writeNativePublished(attemptPath string, request *NativeJobRequest, admission []byte, accepted *models.StorageAcceptance) error {
	if accepted == nil || !accepted.Accepted || accepted.ReservationID != request.Intent.AttemptID ||
		!validNativeDigest(accepted.ReceiptSHA256) || accepted.AcceptanceID == "" {
		return ErrNativeUncertain
	}
	admissionHash := sha256.Sum256(admission)
	marker := nativePublishedMarker{Schema: 1, BackupID: request.Intent.BackupID,
		AttemptID: request.Intent.AttemptID, IntentSHA256: request.IntentSHA256,
		AdmissionSHA256: hex.EncodeToString(admissionHash[:]),
		ReceiptSHA256:   accepted.ReceiptSHA256, AcceptanceID: accepted.AcceptanceID}
	body, err := json.Marshal(marker)
	if err != nil || len(body) > models.MaxStorageRequestBytes {
		return ErrNativeUncertain
	}
	if err = writeNativeFile(nativePublishedPath(attemptPath), body); err != nil {
		return ErrNativeUncertain
	}
	return nil
}

// reclaimNativeTree removes only admitted, inode-matched files. Missing files
// are expected on a retry after a crash; unexpected entries or replacements
// hold the cleanup. The original admission and upload journal are retained.
func reclaimNativeTree(attemptPath string, inventory models.NativeFileSet) error {
	if nativefileset.Validate(inventory) != nil {
		return ErrNativeUncertain
	}
	tree := NativePushTree(attemptPath)
	info, err := os.Lstat(tree)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || !info.IsDir() {
		return ErrNativeUncertain
	}
	members := make(map[string]models.NativeFile, len(inventory.Files))
	for _, member := range inventory.Files {
		if member.Path != filepath.Base(member.Path) {
			return ErrNativeUncertain // This producer creates only flat files.
		}
		members[member.Path] = member
	}
	entries, err := os.ReadDir(tree)
	if err != nil || len(entries) > len(members) {
		return ErrNativeUncertain
	}
	for _, entry := range entries {
		member, ok := members[entry.Name()]
		if !ok || !entry.Type().IsRegular() {
			return ErrNativeUncertain
		}
		file, err := nativefileset.OpenForUpload(tree, member)
		if err != nil {
			return ErrNativeUncertain
		}
		if err = file.Close(); err != nil {
			return ErrNativeUncertain
		}
	}
	for _, member := range inventory.Files {
		path := filepath.Join(tree, member.Path)
		if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
			continue
		} else if err != nil {
			return ErrNativeUncertain
		}
		file, err := nativefileset.OpenForUpload(tree, member)
		if err != nil {
			return ErrNativeUncertain
		}
		if err = file.Close(); err != nil || os.Remove(path) != nil {
			return ErrNativeUncertain
		}
	}
	if err := os.Remove(tree); err != nil {
		return ErrNativeUncertain
	}
	if err := syncNativeDirectory(attemptPath); err != nil {
		return ErrNativeUncertain
	}
	return nil
}

func (r *nativeRunner) finishPublished(work *nativeWork, path string, admission []byte, inventory models.NativeFileSet, accepted *models.StorageAcceptance) error {
	exists, err := readNativePublished(path, work.request, admission)
	if err != nil {
		return err
	}
	if !exists {
		if err = writeNativePublished(path, work.request, admission, accepted); err != nil {
			return err
		}
	}
	return reclaimNativeTree(path, inventory)
}
