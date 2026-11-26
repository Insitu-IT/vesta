//go:build linux

package backup

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"regexp"

	"vnbui/agent/internal/models"
	"vnbui/agent/internal/nativefileset"
)

// A seal attests the successful terminal producer phase, not Python exit status.
// It is written only after the attributed QEMU cycles and local image writers
// finish. Neither current libvirt jobs nor a manifest alone can replace it.
type nativeProducerSeal struct {
	Schema        string                 `json:"schema"`
	RequestSHA256 string                 `json:"request_sha256"`
	InvocationID  string                 `json:"invocation_id"`
	Result        NativePushResult       `json:"result"`
	Artifacts     []nativeSealedArtifact `json:"artifacts"`
}

type nativeSealedArtifact struct {
	Path    string `json:"path"`
	Device  uint64 `json:"device"`
	Inode   uint64 `json:"inode"`
	Size    int64  `json:"size"`
	MtimeNS int64  `json:"mtime_ns"`
	CtimeNS int64  `json:"ctime_ns"`
	SHA256  string `json:"sha256"`
}

func (a nativeSealedArtifact) matches(f models.NativeFile) bool {
	return a.Path == f.Path && a.Device == f.Device && a.Inode == f.Inode && a.Size == f.Size && a.MtimeNS == f.MtimeNS && a.CtimeNS == f.CtimeNS
}

// readNativeSeal is read-only except confirming durability of positive evidence.
// Payload verification uses descriptors pinned to the certificate's identities.
// No helper, image command or libvirt operation may run in this path.
func readNativeSeal(path, uploadPath string, request NativePushRequest) (*nativeProducerSeal, error) {
	body, err := readNativeFile(filepath.Join(path, "producer-sealed.json"))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, ErrNativeUncertain
	}
	for _, name := range []string{"prebegin-refusal.json", "uncertain.json", "published.json", "producer-closed-failure.json"} {
		if _, err := os.Lstat(filepath.Join(path, name)); !os.IsNotExist(err) {
			return nil, ErrNativeUncertain
		}
	}
	if _, err := os.Lstat(uploadPath); !os.IsNotExist(err) {
		return nil, ErrNativeUncertain
	}
	intent, err := readNativeFile(filepath.Join(path, "intent.json"))
	canonical, canonicalErr := models.StorageCanonical(request)
	if err != nil || canonicalErr != nil || !bytes.Equal(intent, canonical) {
		return nil, ErrNativeUncertain
	}
	requestDigest := sha256.Sum256(canonical)
	digest := hex.EncodeToString(requestDigest[:])
	begin, err := readNativeFile(filepath.Join(path, "begin-intent.json"))
	expectedBegin, _ := models.StorageCanonical(map[string]any{"schema": "libvirt-begin-intent/1", "request_sha256": digest})
	if err != nil || !bytes.Equal(begin, expectedBegin) {
		return nil, ErrNativeUncertain
	}
	var seal nativeProducerSeal
	if models.DecodeStorageValue(body, &seal, models.MaxStorageRequestBytes) != nil || seal.Schema != "libvirt-producer-seal/1" || seal.RequestSHA256 != digest ||
		!regexp.MustCompile(`^[0-9a-f]{32}$`).MatchString(seal.InvocationID) {
		return nil, ErrNativeUncertain
	}
	canonical, err = models.StorageCanonical(seal)
	if err != nil || !bytes.Equal(body, canonical) {
		return nil, ErrNativeUncertain
	}
	m := seal.Result.Manifest
	manifest, err := models.StorageCanonical(m)
	manifestDigest := sha256.Sum256(manifest)
	if err != nil || seal.Result.ManifestSHA256 != hex.EncodeToString(manifestDigest[:]) || m.Schema != NativePushFormat || m.BackupID != request.BackupID ||
		m.AttemptID != request.AttemptID || m.DomainUUID != request.DomainUUID || m.Checkpoint != "vnbui-"+request.AttemptID ||
		!reflect.DeepEqual(m.Source, request.Disks) || !reflect.DeepEqual(m.Exclusions, request.Exclusions) {
		return nil, ErrNativeUncertain
	}
	if request.Parent == nil {
		if m.ParentBackupID != nil || m.ParentManifestSHA256 != nil {
			return nil, ErrNativeUncertain
		}
	} else if m.ParentBackupID == nil || m.ParentManifestSHA256 == nil || *m.ParentBackupID != request.Parent.Manifest.BackupID || *m.ParentManifestSHA256 != request.Parent.ManifestSHA256 {
		return nil, ErrNativeUncertain
	}
	want := map[string]string{"domain.xml": m.DomainXMLSHA256, "checkpoint.xml": m.CheckpointSHA256, "manifest.json": seal.Result.ManifestSHA256}
	for _, disk := range m.Disks {
		if disk.File != disk.Target+".qcow2" || disk.SizeBytes <= 0 {
			return nil, ErrNativeUncertain
		}
		if _, duplicate := want[disk.File]; duplicate {
			return nil, ErrNativeUncertain
		}
		want[disk.File] = disk.SHA256
	}
	if len(seal.Artifacts) != len(want) || len(want) > nativefileset.MaxFiles {
		return nil, ErrNativeUncertain
	}
	tree, err := os.Open(NativePushTree(path))
	if err != nil {
		return nil, ErrNativeUncertain
	}
	entries, treeErr := tree.ReadDir(len(want) + 1)
	closeErr := tree.Close()
	if treeErr != nil || closeErr != nil || len(entries) != len(want) {
		return nil, ErrNativeUncertain
	}
	for _, entry := range entries {
		if _, exists := want[entry.Name()]; !exists || !entry.Type().IsRegular() {
			return nil, ErrNativeUncertain
		}
	}
	previous := ""
	for _, a := range seal.Artifacts {
		if a.Path <= previous || filepath.Base(a.Path) != a.Path || a.Inode == 0 || a.Size <= 0 || a.MtimeNS <= 0 || a.CtimeNS <= 0 ||
			a.SHA256 != want[a.Path] || !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(a.SHA256) {
			return nil, ErrNativeUncertain
		}
		previous = a.Path
		member := models.NativeFile{Path: a.Path, Device: a.Device, Inode: a.Inode, Size: a.Size, MtimeNS: a.MtimeNS, CtimeNS: a.CtimeNS}
		stream, err := nativefileset.OpenForUpload(NativePushTree(path), member)
		if err != nil {
			return nil, ErrNativeUncertain
		}
		hash := sha256.New()
		count, readErr := io.Copy(hash, stream)
		verifyErr := stream.Verify()
		syncErr := stream.Sync()
		closeErr := stream.Close()
		if readErr != nil || verifyErr != nil || syncErr != nil || closeErr != nil || count != a.Size || hex.EncodeToString(hash.Sum(nil)) != a.SHA256 {
			return nil, ErrNativeUncertain
		}
	}
	// Reconfirm marker durability before manufacturing any new closed admission.
	for name, content := range map[string][]byte{"intent.json": intent, "begin-intent.json": begin, "producer-sealed.json": body} {
		if syncNativeNoEffectFile(filepath.Join(path, name), content) != nil {
			return nil, ErrNativeUncertain
		}
	}
	if syncNativeDirectory(NativePushTree(path)) != nil || syncNativeDirectory(filepath.Dir(path)) != nil {
		return nil, ErrNativeUncertain
	}
	return &seal, nil
}

func captureNativeSeal(request NativePushRequest, seal *nativeProducerSeal, intentSHA256 string) ([]byte, error) {
	return captureNativePush(request, seal.Result, intentSHA256, seal.InvocationID, "sealed", seal.Artifacts)
}

func nativeProducerRequest(i *NativeJobRequest, path string) NativePushRequest {
	intent := i.Intent
	return NativePushRequest{Schema: NativePushFormat, URI: "qemu:///system", BackupID: intent.BackupID, AttemptID: intent.AttemptID,
		DomainUUID: intent.Source.DomainUUID, Disks: intent.Source.Disks, Exclusions: intent.Source.Exclusions, Parent: intent.PushParent,
		OutputPath: path, TimeoutSeconds: 86400}
}
