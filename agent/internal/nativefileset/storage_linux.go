//go:build linux

package nativefileset

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"reflect"
	"regexp"
	"sort"
	"strings"

	"vnbui/agent/internal/models"
)

func hash(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

// ValidateSource is wire admission only. No job, descriptor or DB authority is
// established by a matching inventory hash.
func ValidateSource(s models.NativeStorageSource) error {
	if s.Representation != models.NativeFileSetFormat || !uuid.MatchString(s.AgentID) ||
		!uuid.MatchString(s.VMID) || Validate(s.Inventory) != nil {
		return ErrHeld
	}
	body, err := models.StorageCanonical(s.Inventory)
	if err != nil || subtle.ConstantTimeCompare([]byte(hash(body)), []byte(s.InventorySHA256)) != 1 {
		return ErrHeld
	}
	return nil
}

func DecodeSource(body []byte) (*models.NativeStorageSource, error) {
	var source models.NativeStorageSource
	if models.DecodeStorageValue(body, &source, models.MaxStorageRequestBytes) != nil || ValidateSource(source) != nil {
		return nil, ErrHeld
	}
	return &source, nil
}

var keySuffix = regexp.MustCompile(`^(?:[0-9a-f]{16}|[0-9a-f]{64})$`)

func encrypted(e models.StorageEncryption) (bool, error) {
	if e.Format == "none" && e.KeyRef == nil {
		return false, nil
	}
	if e.Format != "vnbu1-aes256gcm-chunk5242880" || e.KeyRef == nil {
		return false, ErrHeld
	}
	p := strings.Split(*e.KeyRef, ":")
	if len(p) != 3 || p[0] != "kek" || !uuid.MatchString(p[1]) || !keySuffix.MatchString(p[2]) {
		return false, ErrHeld
	}
	return true, nil
}

// BuildArtifacts consumes immutable native member identity, never a guessed
// volume/role pair. Every file, including common metadata, is encrypted when
// selected. Empty encrypted members retain the five-byte VNBU framing header.
func BuildArtifacts(s models.NativeStorageSource, org, backup, reservation string, e models.StorageEncryption) ([]models.NativeStorageArtifact, error) {
	if ValidateSource(s) != nil || !uuid.MatchString(org) || !uuid.MatchString(backup) ||
		!uuid.MatchString(reservation) || reservation[14] != '4' ||
		s.Inventory.BackupID != backup || s.Inventory.AttemptID != reservation {
		return nil, ErrHeld
	}
	useEncryption, err := encrypted(e)
	if err != nil {
		return nil, err
	}
	root := "vnbui-owned/v1/" + hash([]byte(org)) + "/" + hash([]byte(backup)) + "/payload/" + reservation + "/native/"
	result := make([]models.NativeStorageArtifact, 0, len(s.Inventory.Files))
	for _, f := range s.Inventory.Files {
		stored := f.Size
		if useEncryption {
			stored = 5 + f.Size + 32*((f.Size+5242880-1)/5242880)
		}
		result = append(result, models.NativeStorageArtifact{
			ArtifactID: f.ArtifactID, DiskID: f.DiskID, Role: f.Role, Key: root + f.ArtifactID,
			PlaintextMin: f.Size, PlaintextMax: f.Size, CiphertextMin: stored, CiphertextMax: stored,
		})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Key < result[j].Key })
	return result, nil
}

var receiptHash = regexp.MustCompile(`^[0-9a-f]{64}$`)

// CanonicalReceipt validates the native schema-2 variant against already
// validated committed artifacts. It establishes no provider/backend acceptance.
func CanonicalReceipt(r models.NativeStorageReceipt, artifacts []models.NativeStorageArtifact, backup, reservation string, target models.StorageTarget, e models.StorageEncryption) ([]byte, string, error) {
	if r.Protocol != models.StorageProtocol || r.Schema != 2 || r.Representation != models.NativeFileSetFormat ||
		r.BackupID != backup || r.ReservationID != reservation || r.Endpoint != target.Endpoint || r.Bucket != target.Bucket ||
		len(r.Objects) == 0 || len(r.Objects) > MaxFiles || len(r.Objects) != len(artifacts) {
		return nil, "", ErrHeld
	}
	useEncryption, err := encrypted(e)
	if err != nil {
		return nil, "", err
	}
	planned := map[string]models.NativeStorageArtifact{}
	for _, a := range artifacts {
		if _, exists := planned[a.Key]; exists {
			return nil, "", ErrHeld
		}
		planned[a.Key] = a
	}
	for _, o := range r.Objects {
		a, ok := planned[o.Key]
		if !ok || o.ArtifactID != a.ArtifactID || !reflect.DeepEqual(o.DiskID, a.DiskID) || o.Role != a.Role ||
			strings.TrimSpace(o.ETag) == "" || len(o.ETag) > 1024 ||
			(o.VersionID != nil && (*o.VersionID == "" || len(*o.VersionID) > 1024)) ||
			o.PlaintextBytes < a.PlaintextMin || o.PlaintextBytes > a.PlaintextMax ||
			o.CiphertextBytes < a.CiphertextMin || o.CiphertextBytes > a.CiphertextMax ||
			!receiptHash.MatchString(o.PlaintextSHA256) || !receiptHash.MatchString(o.CiphertextSHA256) {
			return nil, "", ErrHeld
		}
		delete(planned, o.Key)
		stored := o.PlaintextBytes
		if useEncryption {
			stored = 5 + stored + 32*((stored+5242880-1)/5242880)
		}
		if o.CiphertextBytes != stored || (!useEncryption && o.PlaintextSHA256 != o.CiphertextSHA256) {
			return nil, "", ErrHeld
		}
	}
	body, err := models.StorageCanonical(r)
	if err != nil || len(body) > models.MaxStorageReceiptBytes {
		return nil, "", ErrHeld
	}
	return body, hash(body), nil
}
