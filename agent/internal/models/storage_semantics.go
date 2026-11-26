package models

import (
	"crypto/sha256"
	"encoding/hex"
	"net/url"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

var storageUUID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
var storageName = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$`)
var storageIdentity = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,252}$`)
var storageResourceVersion = regexp.MustCompile(`^[1-9][0-9]{0,19}$`)

func storageHash(value string) string {
	hash := sha256.Sum256([]byte(value))
	return hex.EncodeToString(hash[:])
}

// ValidStorageTarget is shared literal destination admission, not credentials.
func ValidStorageTarget(t StorageTarget) bool {
	u, err := url.Parse(t.Endpoint)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil ||
		u.Path != "" || u.RawQuery != "" || u.Fragment != "" || t.Endpoint != "https://"+u.Host || strings.Contains(u.Host, "%") {
		return false
	}
	for _, c := range u.Host {
		if c <= 32 || c >= 127 {
			return false
		}
	}
	if port := u.Port(); port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return false
		}
	}
	if !storageName.MatchString(t.Bucket) || len(t.Bucket) < 3 || len(t.Bucket) > 63 || strings.Contains(t.Bucket, "..") ||
		(t.Region != "" && !storageIdentity.MatchString(t.Region)) || len(t.ConfigurationPrefix) > 1024 ||
		strings.HasPrefix(t.ConfigurationPrefix, "/") || strings.Contains(t.ConfigurationPrefix, `\`) {
		return false
	}
	for _, c := range t.ConfigurationPrefix {
		if c < 32 || c == 127 {
			return false
		}
	}
	for _, part := range strings.Split(t.ConfigurationPrefix, "/") {
		if part == "." || part == ".." {
			return false
		}
	}
	return true
}

// Semantic admission is not persisted authority or an activation switch.
// Persisted incremental authority is admitted separately by the backend reader.
func validStorageSemantics(r *StorageTransactionRequest) bool {
	p, s := &r.Plan, &r.Plan.Source
	if p.TransferProfile != "" && p.TransferProfile != KubevirtTransfer32 {
		return false
	}
	for _, id := range []string{r.OrgID, r.AgentID, r.BackupID, r.ReservationID, s.AgentID, s.VMID, p.AttemptID} {
		if !storageUUID.MatchString(id) {
			return false
		}
	}
	if r.AgentID != s.AgentID || r.ReservationID != p.AttemptID || p.AttemptID[14] != '4' ||
		!storageIdentity.MatchString(s.VMUID) || (s.VMIUID != nil && !storageIdentity.MatchString(*s.VMIUID)) ||
		!storageName.MatchString(s.Namespace) || len(s.Namespace) > 63 || !storageName.MatchString(p.VMName) ||
		p.CredentialRef != "installation/storage.s3" || p.ChecksumPolicy != "sha256-parts-receipt-v2" {
		return false
	}
	if p.BackupType == "full" {
		if p.Parent != nil {
			return false
		}
	} else {
		if p.BackupType != "incremental" || p.Parent == nil {
			return false
		}
		for _, id := range []string{p.Parent.BackupID, p.Parent.RootBackupID, p.Parent.GenerationID} {
			if !storageUUID.MatchString(id) || id == r.BackupID {
				return false
			}
		}
		if matched, _ := regexp.MatchString(`^[0-9a-f]{64}$`, p.Parent.ReceiptSHA256); !matched {
			return false
		}
		if !storageIdentity.MatchString(p.Parent.TrackerUID) || !storageIdentity.MatchString(p.Parent.Checkpoint) {
			return false
		}
	}
	encrypted := p.Encryption.Format == "vnbu1-aes256gcm-chunk5242880"
	if encrypted {
		if p.Encryption.KeyRef == nil {
			return false
		}
		parts := strings.Split(*p.Encryption.KeyRef, ":")
		if len(parts) != 3 || parts[0] != "kek" || !storageUUID.MatchString(parts[1]) {
			return false
		}
		if matched, _ := regexp.MatchString(`^(?:[0-9a-f]{16}|[0-9a-f]{64})$`, parts[2]); !matched {
			return false
		}
	} else if p.Encryption.Format != "none" || p.Encryption.KeyRef != nil {
		return false
	}
	if !ValidStorageTarget(p.Target) {
		return false
	}
	if len(s.Volumes) < 1 || len(s.Volumes) > 256 {
		return false
	}
	if s.Schema == 1 && len(s.NativeVolumes) != 0 {
		return false
	}
	if !validStorageVolumes(s.Volumes) {
		return false
	}
	names := map[string]bool{}
	volumes := map[string]StorageVolume{}
	for _, v := range s.Volumes {
		names[v.Name] = true
		volumes[v.PVCUID] = v
	}
	if s.Schema == 2 {
		if !validStorageVolumes(s.NativeVolumes) {
			return false
		}
		native := map[string]StorageVolume{}
		for _, v := range s.NativeVolumes {
			native[v.Name] = v
		}
		for _, v := range s.Volumes {
			if !reflect.DeepEqual(native[v.Name], v) {
				return false
			}
		}
		for _, v := range s.NativeVolumes {
			if !names[v.Name] && !slices.Contains(p.Exclusions, v.Name) {
				return false
			}
		}
	}
	if len(p.Exclusions) > 256 || !slices.IsSorted(p.Exclusions) {
		return false
	}
	for i, x := range p.Exclusions {
		if !storageName.MatchString(x) || names[x] || (i > 0 && x == p.Exclusions[i-1]) {
			return false
		}
	}
	if len(p.Artifacts) != 2*len(volumes) {
		return false
	}
	root := "vnbui-owned/v1/" + storageHash(r.OrgID) + "/" + storageHash(r.BackupID) + "/payload/" + p.AttemptID + "/"
	keys := []string{}
	pairs := map[string]bool{}
	for _, a := range p.Artifacts {
		v, ok := volumes[a.VolumeID]
		pair := a.VolumeID + "/" + a.Role
		if !ok || (a.Role != "volume_payload" && a.Role != "volume_manifest") || pairs[pair] ||
			a.Key != root+storageHash(a.VolumeID)+"/"+a.Role {
			return false
		}
		pairs[pair] = true
		maximum := v.CapacityBytes
		if a.Role == "volume_manifest" {
			maximum = 16 * 1024 * 1024
		}
		ciphertextMin, ciphertextMax := int64(0), maximum
		if encrypted && a.Role == "volume_payload" {
			ciphertextMin = 5
			ciphertextMax = 5 + maximum + 32*((maximum+5242880-1)/5242880)
		}
		if a.PlaintextMin != 0 || a.CiphertextMin != ciphertextMin || a.PlaintextMax != maximum || a.CiphertextMax != ciphertextMax {
			return false
		}
		keys = append(keys, a.Key)
	}
	return slices.IsSorted(keys)
}

func validStorageVolumes(set []StorageVolume) bool {
	if len(set) < 1 || len(set) > 256 {
		return false
	}
	names, pvcs, serials := map[string]bool{}, map[string]bool{}, map[string]bool{}
	volumes := map[string]StorageVolume{}
	for _, v := range set {
		_, repeated := volumes[v.PVCUID]
		if !storageName.MatchString(v.Name) || !storageName.MatchString(v.PVCName) || !storageIdentity.MatchString(v.PVCUID) ||
			!storageResourceVersion.MatchString(v.PVCResourceVersion) || v.CapacityBytes <= 0 || v.CapacityBytes > (int64(1<<63-1)/2) ||
			names[v.Name] || pvcs[v.PVCName] || repeated {
			return false
		}
		names[v.Name], pvcs[v.PVCName], volumes[v.PVCUID] = true, true, v
		m := v.Mapping
		if m.DiskName != v.Name || m.Device != "disk" || !slices.Contains([]string{"virtio", "sata", "scsi", "usb"}, m.Bus) {
			return false
		}
		if m.Serial != nil {
			if !storageIdentity.MatchString(*m.Serial) || serials[*m.Serial] {
				return false
			}
			serials[*m.Serial] = true
		}
	}

	return true
}
