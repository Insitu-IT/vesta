// Package storagerestore reconstructs raw KubeVirt disks from committed storage
// transaction receipts. The caller supplies the authorized chain and exact-object
// readers; object-store listing is never used to infer chain membership.
package storagerestore

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"

	"vnbui/agent/internal/models"
)

// Member is one full backup or incremental successor. Receipt must come from the
// durable, authorized catalog: valid hashes alone do not establish permission or
// prove that a producer committed its checkpoint.
type Member struct {
	Request models.StorageTransactionRequest `json:"request"`
	Receipt models.StorageReceipt            `json:"receipt"`
}

// ObjectOpener must read the specified version (or use the receipt ETag as an
// If-Match condition for an unversioned object), honoring ctx during I/O. Restore
// and Verify additionally check both complete-object digests and lengths.
type ObjectOpener func(context.Context, models.StorageTarget, models.StorageObjectReceipt) (io.ReadCloser, error)

// KeyResolver returns the DEK for this exact member, not just its wrapping KEK.
// The returned bytes are owned by the consumer and cleared after the member.
type KeyResolver func(context.Context, Member) ([]byte, error)

type Disk struct {
	Volume    models.StorageVolume `json:"volume"`
	Path      string               `json:"path"`
	SizeBytes int64                `json:"size_bytes"`
	SHA256    string               `json:"sha256"`
}

type objectPair struct {
	manifest models.StorageObjectReceipt
	payload  models.StorageObjectReceipt
}

type validatedMember struct {
	Member
	digest  string
	objects map[string]objectPair
}

// ValidateMembers checks catalog-supplied chain structure without object I/O.
// It does not verify artifact bytes or establish the bundle's provenance.
func ValidateMembers(members []Member) error {
	_, err := validateChain(members)
	return err
}

// Assemble builds a full baseline followed by the supplied ordered incrementals.
// outputDir must not exist. It is created mode 0700 and removed on failure; only
// a successful return publishes usable disk paths. Callers must not consume files
// while this function is running. Payloads and zero writes use fixed-size buffers.
func Assemble(ctx context.Context, members []Member, outputDir string, open ObjectOpener, keys KeyResolver) (_ []Disk, err error) {
	if ctx == nil || open == nil || outputDir == "" {
		return nil, errors.New("restore requires context, object reader and a new output directory")
	}
	chain, err := validateChain(members)
	if err != nil {
		return nil, err
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	outputDir, err = filepath.Abs(outputDir)
	if err != nil {
		return nil, err
	}
	if err = os.Mkdir(outputDir, 0700); err != nil {
		return nil, fmt.Errorf("create new restore directory: %w", err)
	}
	// The directory was exclusively created above; cleanup never targets a
	// caller's pre-existing directory or an object-store resource.
	defer func() {
		if err != nil {
			err = errors.Join(err, os.RemoveAll(outputDir))
		}
	}()

	volumes := chain[0].Request.Plan.Source.Volumes
	disks := make([]Disk, len(volumes))
	for i, volume := range volumes {
		path := filepath.Join(outputDir, fmt.Sprintf("disk-%03d.raw", i))
		file, createErr := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
		if createErr != nil {
			return nil, createErr
		}
		// The full member's omitted ranges are holes/zeroes in this new file.
		truncateErr := file.Truncate(volume.CapacityBytes)
		closeErr := file.Close()
		if truncateErr != nil || closeErr != nil {
			return nil, errors.Join(truncateErr, closeErr)
		}
		disks[i] = Disk{Volume: volume, Path: path, SizeBytes: volume.CapacityBytes}
	}

	previousCheckpoint := ""
	seenCheckpoints := map[string]bool{}
	for i := range chain {
		checkpoint, applyErr := applyMember(ctx, chain[i], disks, previousCheckpoint, open, keys)
		if applyErr != nil {
			return nil, fmt.Errorf("backup %s: %w", chain[i].Request.BackupID, applyErr)
		}
		if seenCheckpoints[checkpoint] {
			return nil, errors.New("chain repeats a checkpoint")
		}
		seenCheckpoints[checkpoint] = true
		previousCheckpoint = checkpoint
	}
	for i := range disks {
		file, openErr := os.Open(disks[i].Path)
		if openErr != nil {
			return nil, openErr
		}
		h := sha256.New()
		n, readErr := io.CopyBuffer(h, &contextReader{ctx: ctx, reader: file}, make([]byte, copyBufferBytes))
		closeErr := file.Close()
		if readErr != nil || closeErr != nil || n != disks[i].SizeBytes {
			return nil, errors.Join(errors.New("final disk checksum read failed"), readErr, closeErr)
		}
		disks[i].SHA256 = hex.EncodeToString(h.Sum(nil))
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	return disks, nil
}

func validateChain(members []Member) ([]validatedMember, error) {
	if len(members) == 0 || len(members) > 256 {
		return nil, errors.New("restore chain requires between one and 256 members")
	}
	chain := make([]validatedMember, 0, len(members))
	seen := map[string]bool{}
	for i, member := range members {
		body, err := json.Marshal(member.Request)
		if err != nil {
			return nil, err
		}
		request, err := models.DecodeStorageTransaction(body)
		if err != nil {
			return nil, fmt.Errorf("member %d request: %w", i, err)
		}
		body, digest, err := models.CanonicalReceipt(request, member.Receipt)
		if err != nil {
			return nil, fmt.Errorf("member %d receipt: %w", i, err)
		}
		var receipt models.StorageReceipt
		if err := models.DecodeStorageValue(body, &receipt, models.MaxStorageReceiptBytes); err != nil {
			return nil, err
		}
		if seen[request.BackupID] {
			return nil, errors.New("duplicate backup in restore chain")
		}
		seen[request.BackupID] = true
		if i == 0 {
			if request.Plan.BackupType != "full" || request.Plan.Parent != nil {
				return nil, errors.New("restore chain must begin with a full backup")
			}
		} else {
			root, previous := chain[0].Request, chain[i-1]
			parent := request.Plan.Parent
			if request.Plan.BackupType != "incremental" || parent == nil ||
				parent.BackupID != previous.Request.BackupID || parent.RootBackupID != root.BackupID || parent.ReceiptSHA256 != previous.digest {
				return nil, errors.New("incremental parent, root or receipt does not match supplied chain order")
			}
			if !sameSource(root, *request) {
				return nil, errors.New("VM, disk identity or disk mapping changed within restore chain")
			}
			if i > 1 {
				firstParent := chain[1].Request.Plan.Parent
				// Each backup publishes a distinct generation. The authorized
				// catalog resolves that ID to this exact predecessor; it is not
				// a chain-wide identity. Tracker identity remains continuous.
				if parent.TrackerUID != firstParent.TrackerUID {
					return nil, errors.New("incremental tracker changed within restore chain")
				}
			}
		}
		objects := make(map[string]objectPair, len(request.Plan.Source.Volumes))
		for _, obj := range receipt.Objects {
			pair := objects[obj.VolumeID]
			if obj.Role == "volume_manifest" {
				pair.manifest = obj
			} else {
				pair.payload = obj
			}
			objects[obj.VolumeID] = pair
		}
		chain = append(chain, validatedMember{Member: Member{Request: *request, Receipt: receipt}, digest: digest, objects: objects})
	}
	return chain, nil
}

func sameSource(a, b models.StorageTransactionRequest) bool {
	if a.Plan.Source.Schema != b.Plan.Source.Schema {
		return false
	}
	if a.Plan.Source.Schema == 2 && !sameVolumes(a.Plan.Source.NativeVolumes, b.Plan.Source.NativeVolumes) {
		return false
	}
	x, y := a.Plan.Source, b.Plan.Source
	if a.OrgID != b.OrgID || a.AgentID != b.AgentID || a.Plan.Target != b.Plan.Target || a.Plan.VMName != b.Plan.VMName || x.VMID != y.VMID || x.VMUID != y.VMUID ||
		x.Namespace != y.Namespace || len(x.Volumes) != len(y.Volumes) || !reflect.DeepEqual(a.Plan.Exclusions, b.Plan.Exclusions) {
		return false
	}
	return sameVolumes(x.Volumes, y.Volumes)
}

func applyMember(ctx context.Context, member validatedMember, disks []Disk, previousCheckpoint string, open ObjectOpener, keys KeyResolver) (string, error) {
	if parent := member.Request.Plan.Parent; parent != nil && parent.Checkpoint != previousCheckpoint {
		return "", errors.New("parent checkpoint does not match preceding manifest")
	}
	var key []byte
	if member.Request.Plan.Encryption.Format != "none" {
		if keys == nil {
			return "", errors.New("encrypted backup requires a per-member DEK resolver")
		}
		var err error
		key, err = keys(ctx, member.Member)
		defer clear(key)
		if err != nil || len(key) != 32 {
			return "", errors.Join(errors.New("could not resolve the backup's 32-byte DEK"), err)
		}
	}
	checkpoint := ""
	for _, disk := range disks {
		pair := member.objects[disk.Volume.PVCUID]
		manifest, err := readManifest(ctx, member, disk.Volume, pair, open)
		if err != nil {
			return "", fmt.Errorf("volume %s manifest: %w", disk.Volume.Name, err)
		}
		if checkpoint != "" && checkpoint != manifest.Checkpoint {
			return "", errors.New("volume manifests disagree on checkpoint")
		}
		checkpoint = manifest.Checkpoint
		file, err := os.OpenFile(disk.Path, os.O_RDWR, 0)
		if err != nil {
			return "", err
		}
		err = applyPayload(ctx, member, pair.payload, manifest, file, key, open)
		if err == nil {
			err = file.Sync()
		}
		closeErr := file.Close()
		if err != nil || closeErr != nil {
			return "", fmt.Errorf("volume %s payload: %w", disk.Volume.Name, errors.Join(err, closeErr))
		}
	}
	return checkpoint, nil
}

func sameVolumes(x, y []models.StorageVolume) bool {
	if len(x) != len(y) {
		return false
	}
	volumes := make(map[string]models.StorageVolume, len(x))
	for _, v := range x {
		volumes[v.PVCUID] = v
	}
	for _, v := range y {
		original, ok := volumes[v.PVCUID]
		// In a catalog-authorized chain, VMI UID and PVC resourceVersion may
		// change on a valid VM restart. The caller still owns catalog lineage
		// admission; volume ownership, capacity and mapping remain identical.
		if !ok || original.Name != v.Name || original.PVCName != v.PVCName || original.CapacityBytes != v.CapacityBytes || !reflect.DeepEqual(original.Mapping, v.Mapping) {
			return false
		}
		delete(volumes, v.PVCUID)
	}
	return len(volumes) == 0
}
