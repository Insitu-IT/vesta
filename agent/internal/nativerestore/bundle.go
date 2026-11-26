// Package nativerestore consumes only explicit, accepted native push bundles.
package nativerestore

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"

	"vnbui/agent/internal/backup"
	"vnbui/agent/internal/models"
	"vnbui/agent/internal/nativefileset"
	"vnbui/agent/internal/storagerestore"
)

const BundleSchema = "vnbui-native-restore/1"

type Member struct {
	Request    models.NativeTransactionRequest `json:"request"`
	Receipt    models.NativeStorageReceipt     `json:"receipt"`
	PushResult models.NativePushResult         `json:"push_result"`
}
type Bundle struct {
	Schema  string   `json:"schema"`
	Members []Member `json:"members"`
}
type KeyResolver func(context.Context, Member) ([]byte, error)

var ErrBundle = errors.New("intact accepted native push chain required")

func hash(value []byte) string { h := sha256.Sum256(value); return hex.EncodeToString(h[:]) }

// Validate checks request/receipt content membership and all parent links. It
// does not turn an arbitrary caller's bundle into catalog admission authority.
func Validate(bundle Bundle) error {
	if bundle.Schema != BundleSchema || len(bundle.Members) == 0 || len(bundle.Members) > 256 {
		return ErrBundle
	}
	first := bundle.Members[0]
	var previousHash string
	seen := map[string]bool{}
	for i, m := range bundle.Members {
		body, _ := json.Marshal(m.Request)
		if _, err := nativefileset.DecodeTransaction(body); err != nil {
			return ErrBundle
		}
		r, p, x := m.Request, m.Request.Plan, m.PushResult.Manifest
		_, receiptHash, err := nativefileset.CanonicalReceipt(m.Receipt, p.Artifacts, r.BackupID, r.ReservationID, p.Target, p.Encryption)
		if err != nil || seen[r.BackupID] || r.OrgID != first.Request.OrgID || r.AgentID != first.Request.AgentID ||
			p.Source.VMID != first.Request.Plan.Source.VMID || p.Target != first.Request.Plan.Target ||
			x.Schema != backup.NativePushFormat || x.BackupID != r.BackupID || x.AttemptID != p.AttemptID ||
			x.DomainUUID != p.Source.Inventory.DomainUUID || x.Checkpoint != p.Source.Inventory.Checkpoint ||
			!reflect.DeepEqual(x.Source, first.PushResult.Manifest.Source) || !slices.Equal(x.Exclusions, p.Exclusions) ||
			!slices.Equal(x.Exclusions, first.PushResult.Manifest.Exclusions) {
			return ErrBundle
		}
		canonical, err := models.StorageCanonical(x)
		if err != nil || hash(canonical) != m.PushResult.ManifestSHA256 {
			return ErrBundle
		}
		if i == 0 {
			if p.BackupType != "full" || p.Parent != nil || x.ParentBackupID != nil || x.ParentManifestSHA256 != nil {
				return ErrBundle
			}
		} else {
			prev := bundle.Members[i-1]
			if p.BackupType != "incremental" || p.Parent == nil || p.Parent.BackupID != prev.Request.BackupID ||
				p.Parent.RootBackupID != first.Request.BackupID || p.Parent.ReceiptSHA256 != previousHash ||
				p.Parent.TrackerUID != prev.PushResult.Manifest.DomainUUID || p.Parent.Checkpoint != prev.PushResult.Manifest.Checkpoint ||
				x.ParentBackupID == nil || *x.ParentBackupID != prev.Request.BackupID || x.ParentManifestSHA256 == nil ||
				*x.ParentManifestSHA256 != prev.PushResult.ManifestSHA256 {
				return ErrBundle
			}
		}
		if err := validateObjects(m, canonical); err != nil {
			return err
		}
		previousHash = receiptHash
		seen[r.BackupID] = true
	}
	return nil
}

func validateObjects(m Member, canonical []byte) error {
	x := m.PushResult.Manifest
	sources := map[string]models.NativeSourceDisk{}
	previous := ""
	for _, source := range x.Source {
		if !safeName.MatchString(source.Target) || source.Target <= previous || !safeName.MatchString(source.Bus) || !filepath.IsAbs(source.Source) || (source.Format != "raw" && source.Format != "qcow2") {
			return ErrBundle
		}
		sources[source.Target] = source
		previous = source.Target
	}
	for _, excluded := range x.Exclusions {
		if _, ok := sources[excluded]; !ok {
			return ErrBundle
		}
	}
	if len(x.Source) != len(x.Disks)+len(x.Exclusions) {
		return ErrBundle
	}
	disks := map[string]models.NativePushDisk{}
	for _, d := range x.Disks {
		if d.Target == "" || d.File != d.Target+".qcow2" || filepath.Base(d.File) != d.File || d.SizeBytes <= 0 || d.VirtualSize <= 0 || disks[d.Target].Target != "" {
			return ErrBundle
		}
		disks[d.Target] = d
	}
	for _, disk := range m.Request.Plan.Source.Inventory.Disks {
		if disk.ID != disk.Target || sources[disk.Target].Bus != disk.Bus || disks[disk.Target].Target != disk.Target || slices.Contains(x.Exclusions, disk.Target) {
			return ErrBundle
		}
	}
	if len(disks) != len(m.Request.Plan.Source.Inventory.Disks) || len(m.Receipt.Objects) != len(disks)+3 {
		return ErrBundle
	}
	files := map[string]models.NativeFile{}
	for _, f := range m.Request.Plan.Source.Inventory.Files {
		files[f.ArtifactID] = f
	}
	seen := map[string]bool{}
	for _, o := range m.Receipt.Objects {
		f, ok := files[o.ArtifactID]
		if !ok {
			return ErrBundle
		}
		name, digest, size := "", "", f.Size
		switch o.Role {
		case "domain_config":
			name, digest = "domain.xml", x.DomainXMLSHA256
		case "checkpoint":
			name, digest = "checkpoint.xml", x.CheckpointSHA256
		case "backup_metadata":
			name, digest, size = "manifest.json", m.PushResult.ManifestSHA256, int64(len(canonical))
		case "disk_payload":
			if o.DiskID == nil {
				return ErrBundle
			}
			d, ok := disks[*o.DiskID]
			if !ok {
				return ErrBundle
			}
			name, digest, size = d.File, d.SHA256, d.SizeBytes
		default:
			return ErrBundle
		}
		if name != f.Path || seen[name] || size != f.Size || o.PlaintextBytes != size || o.PlaintextSHA256 != digest {
			return ErrBundle
		}
		seen[name] = true
	}
	return nil
}

// Materialize writes only named receipt members, exclusively into a new private
// directory. Partial input is retained on failure, never silently overwritten.
func Materialize(ctx context.Context, bundle Bundle, directory string, open storagerestore.ObjectOpener, keys KeyResolver) ([]backup.NativeRestoreMember, error) {
	if err := Validate(bundle); err != nil {
		return nil, err
	}
	if err := os.Mkdir(directory, 0700); err != nil {
		return nil, err
	}
	members := make([]backup.NativeRestoreMember, 0, len(bundle.Members))
	for i, m := range bundle.Members {
		memberDir := filepath.Join(directory, fmt.Sprintf("member-%03d", i))
		if err := os.Mkdir(memberDir, 0700); err != nil {
			return nil, err
		}
		var key []byte
		encrypted := m.Request.Plan.Encryption.Format != "none"
		if encrypted {
			if keys == nil {
				return nil, errors.New("native member DEK resolver unavailable")
			}
			var err error
			key, err = keys(ctx, m)
			if err != nil || len(key) != 32 {
				return nil, errors.New("native member DEK unavailable")
			}
		}
		paths := map[string]string{}
		for _, f := range m.Request.Plan.Source.Inventory.Files {
			paths[f.ArtifactID] = f.Path
		}
		for _, o := range m.Receipt.Objects {
			f, err := os.OpenFile(filepath.Join(memberDir, paths[o.ArtifactID]), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
			if err != nil {
				return nil, err
			}
			obj := models.StorageObjectReceipt{Key: o.Key, VersionID: o.VersionID, ETag: o.ETag, PlaintextBytes: o.PlaintextBytes, CiphertextBytes: o.CiphertextBytes, PlaintextSHA256: o.PlaintextSHA256, CiphertextSHA256: o.CiphertextSHA256}
			err = storagerestore.WriteVerifiedObject(ctx, m.Request.Plan.Target, obj, encrypted, key, open, f)
			if err == nil {
				err = f.Sync()
			}
			err = errors.Join(err, f.Close())
			if err != nil {
				return nil, err
			}
		}
		if err := SyncDirectory(memberDir); err != nil {
			return nil, err
		}
		members = append(members, backup.NativeRestoreMember{Manifest: m.PushResult.Manifest, ManifestSHA256: m.PushResult.ManifestSHA256, Directory: memberDir})
	}
	if err := SyncDirectory(directory); err != nil {
		return nil, err
	}
	return members, nil
}

func SyncDirectory(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	return errors.Join(f.Sync(), f.Close())
}
