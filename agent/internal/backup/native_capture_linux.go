//go:build linux

package backup

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"

	"vnbui/agent/internal/models"
	"vnbui/agent/internal/nativefileset"
	"vnbui/agent/internal/storageupload"
)

// NativePushTree is the exact upload tree. Attempt intent and uncertain-state
// journals stay outside it; they must never be classified as backup artifacts.
func NativePushTree(attemptPath string) string { return filepath.Join(attemptPath, "data") }

// CaptureNativePush bridges a successfully returned producer to the existing
// immutable file-set uploader. It is NOT a recovery/adoption function: invoke
// only with the result returned by this process's uninterrupted RunNativePush.
// After this admission is durable, upload-only retry needs no hypervisor call.
func CaptureNativePush(request NativePushRequest, result NativePushResult, intentSHA256, invocationID string) ([]byte, error) {
	return captureNativePush(request, result, intentSHA256, invocationID, "exited", nil)
}

func captureNativePush(request NativePushRequest, result NativePushResult, intentSHA256, invocationID, state string, sealed []nativeSealedArtifact) ([]byte, error) {
	if _, err := os.Lstat(filepath.Join(request.OutputPath, "producer-closed-failure.json")); !os.IsNotExist(err) {
		return nil, ErrNativeUncertain
	}
	if (state != "exited" && state != "sealed") || (state == "sealed") != (sealed != nil) {
		return nil, ErrNativeUncertain
	}
	m := result.Manifest
	canonical, err := models.StorageCanonical(m)
	h := sha256.Sum256(canonical)
	if err != nil || m.Schema != NativePushFormat || m.BackupID != request.BackupID ||
		m.AttemptID != request.AttemptID || m.DomainUUID != request.DomainUUID ||
		m.Checkpoint != "vnbui-"+request.AttemptID || result.ManifestSHA256 != hex.EncodeToString(h[:]) ||
		!reflect.DeepEqual(m.Source, request.Disks) || !reflect.DeepEqual(m.Exclusions, request.Exclusions) ||
		!regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(intentSHA256) ||
		!regexp.MustCompile(`^[0-9a-f]{32}$`).MatchString(invocationID) {
		return nil, ErrNativeUncertain
	}
	if request.Parent == nil {
		if m.ParentBackupID != nil || m.ParentManifestSHA256 != nil {
			return nil, ErrNativeUncertain
		}
	} else if m.ParentBackupID == nil || m.ParentManifestSHA256 == nil ||
		*m.ParentBackupID != request.Parent.Manifest.BackupID || *m.ParentManifestSHA256 != request.Parent.ManifestSHA256 {
		return nil, ErrNativeUncertain
	}
	set := models.NativeFileSet{
		Format: models.NativeFileSetFormat, DomainUUID: m.DomainUUID,
		BackupID: m.BackupID, AttemptID: m.AttemptID, JobID: "vnbui-native-" + m.AttemptID,
		Checkpoint: m.Checkpoint,
	}
	add := func(path, role string, disk *string) {
		file := models.NativeFile{Path: path, Role: role, DiskID: disk,
			MemberBackupID: m.BackupID, MemberCheckpoint: m.Checkpoint}
		file.ArtifactID = nativefileset.ArtifactID(set, file)
		set.Files = append(set.Files, file)
	}
	add("domain.xml", "domain_config", nil)
	add("checkpoint.xml", "checkpoint", nil)
	add("manifest.json", "backup_metadata", nil)
	byTarget := make(map[string]NativeSourceDisk, len(m.Source))
	for _, source := range m.Source {
		byTarget[source.Target] = source
	}
	for _, disk := range m.Disks {
		source, ok := byTarget[disk.Target]
		if !ok || disk.File != disk.Target+".qcow2" || disk.SizeBytes <= 0 {
			return nil, ErrNativeUncertain
		}
		target := disk.Target
		set.Disks = append(set.Disks, models.NativeDisk{ID: target, Target: target, Bus: source.Bus})
		add(disk.File, "disk_payload", &target)
	}
	set, err = nativefileset.Capture(NativePushTree(request.OutputPath), set)
	if err != nil {
		return nil, fmt.Errorf("%w: capture exact native tree", ErrNativeUncertain)
	}
	if sealed != nil {
		if len(sealed) != len(set.Files) {
			return nil, ErrNativeUncertain
		}
		for index, member := range set.Files {
			if !sealed[index].matches(member) {
				return nil, ErrNativeUncertain
			}
		}
	}
	// Verify the exact helper-written canonical manifest, through an inode-pinned
	// descriptor. Data checksums are checked by receipt admission after upload,
	// avoiding a redundant full payload read here.
	for _, file := range set.Files {
		if file.Role == "disk_payload" {
			for _, disk := range m.Disks {
				if file.DiskID != nil && *file.DiskID == disk.Target && file.Size != disk.SizeBytes {
					return nil, ErrNativeUncertain
				}
			}
		}
		if file.Role != "backup_metadata" {
			continue
		}
		if file.Size != int64(len(canonical)) {
			return nil, ErrNativeUncertain
		}
		stream, err := nativefileset.OpenForUpload(NativePushTree(request.OutputPath), file)
		if err != nil {
			return nil, ErrNativeUncertain
		}
		var actual bytes.Buffer
		_, readErr := actual.ReadFrom(stream)
		verifyErr := stream.Verify()
		_ = stream.Close()
		if readErr != nil || verifyErr != nil || !bytes.Equal(actual.Bytes(), canonical) {
			return nil, ErrNativeUncertain
		}
	}
	admission := storageupload.ClosedNativeAdmission{IntentSHA256: intentSHA256, Inventory: set, PushResult: result}
	admission.ClosedJob.JobID, admission.ClosedJob.AttemptID = set.JobID, set.AttemptID
	admission.ClosedJob.InvocationID, admission.ClosedJob.State = invocationID, state
	body, err := json.Marshal(admission)
	if err != nil {
		return nil, ErrNativeUncertain
	}
	return writeNativeAdmission(request.OutputPath, body)
}

// The final name is never a partial write and never replaces existing custody.
// A crash may retain the private temporary file outside the payload tree.
func writeNativeAdmission(path string, body []byte) ([]byte, error) {
	file, err := os.CreateTemp(path, ".admission-*.tmp")
	if err != nil {
		return nil, ErrNativeUncertain
	}
	_, err = file.Write(body)
	if err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err != nil || closeErr != nil {
		return nil, ErrNativeUncertain
	}
	// A same-directory hard link publishes the already-fsynced inode atomically
	// and refuses an existing destination, including on filesystems without
	// renameat2(RENAME_NOREPLACE). Neither name is ever opened for writing again.
	if err := os.Link(file.Name(), filepath.Join(path, "admission.json")); err != nil {
		return nil, fmt.Errorf("%w: publish admission: %v", ErrNativeUncertain, err)
	}
	if syncNativeDirectory(path) != nil {
		return nil, ErrNativeUncertain
	}
	if os.Remove(file.Name()) != nil || syncNativeDirectory(path) != nil {
		return nil, ErrNativeUncertain
	}
	return body, nil
}
