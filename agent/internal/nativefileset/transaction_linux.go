//go:build linux

package nativefileset

import (
	"crypto/subtle"
	"reflect"
	"regexp"
	"slices"

	"vnbui/agent/internal/models"
)

// DecodeTransaction rejects unknown representations before any local/provider
// effect. Its digest includes lossless uint64 filesystem custody, not secrets.
func DecodeTransaction(body []byte) (*models.NativeTransactionRequest, error) {
	var r models.NativeTransactionRequest
	if models.DecodeStorageValue(body, &r, models.MaxStorageRequestBytes) != nil {
		return nil, ErrHeld
	}
	p := &r.Plan
	if r.Protocol != models.StorageProtocol || p.Provider != "libvirt" ||
		!slices.Contains(models.StorageProfiles(), p.CapabilityProfile) ||
		(p.BackupType != "full" && p.BackupType != "incremental") ||
		(p.BackupType == "full") != (p.Parent == nil) ||
		p.Source.Inventory.Checkpoint != "vnbui-"+p.AttemptID || p.Source.Inventory.JobID != "vnbui-native-"+p.AttemptID ||
		p.CredentialRef != "installation/storage.s3" || p.ChecksumPolicy != "sha256-parts-receipt-v2" ||
		r.AgentID != p.Source.AgentID || r.ReservationID != p.AttemptID || !models.ValidStorageTarget(p.Target) {
		return nil, ErrHeld
	}
	if parent := p.Parent; parent != nil {
		if !uuid.MatchString(parent.BackupID) || !uuid.MatchString(parent.RootBackupID) || !uuid.MatchString(parent.GenerationID) ||
			parent.BackupID == r.BackupID || parent.RootBackupID == r.BackupID || parent.TrackerUID != p.Source.Inventory.DomainUUID ||
			!regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(parent.ReceiptSHA256) ||
			len(parent.Checkpoint) != 42 || parent.Checkpoint[:6] != "vnbui-" || !uuid.MatchString(parent.Checkpoint[6:]) {
			return nil, ErrHeld
		}
	}
	a, err := BuildArtifacts(p.Source, r.OrgID, r.BackupID, r.ReservationID, p.Encryption)
	if err != nil || !reflect.DeepEqual(a, p.Artifacts) {
		return nil, ErrHeld
	}
	if len(p.Exclusions) > 128 || !slices.IsSorted(p.Exclusions) {
		return nil, ErrHeld
	}
	name := regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	for i, x := range p.Exclusions {
		if !name.MatchString(x) || (i > 0 && x == p.Exclusions[i-1]) {
			return nil, ErrHeld
		}
		for _, d := range p.Source.Inventory.Disks {
			if d.Target == x {
				return nil, ErrHeld
			}
		}
	}
	canonical, err := models.StorageCanonical(r.Plan)
	if err != nil || subtle.ConstantTimeCompare([]byte(hash(canonical)), []byte(r.PlanSHA256)) != 1 {
		return nil, ErrHeld
	}
	return &r, nil
}
