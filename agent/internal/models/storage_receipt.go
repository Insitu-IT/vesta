package models

import (
	"bytes"
	"crypto/subtle"
	"encoding/json"
	"io"
	"reflect"
	"regexp"
	"strings"
)

const MaxStorageReceiptBytes = 4 * 1024 * 1024

type StorageReceipt struct {
	Protocol      string                 `json:"protocol"`
	Schema        int                    `json:"schema"`
	ReservationID string                 `json:"reservation_id"`
	BackupID      string                 `json:"backup_id"`
	Endpoint      string                 `json:"endpoint"`
	Bucket        string                 `json:"bucket"`
	Objects       []StorageObjectReceipt `json:"objects"`
}

type StorageObjectReceipt struct {
	Key              string  `json:"key"`
	VersionID        *string `json:"version_id"`
	ETag             string  `json:"etag"`
	PlaintextBytes   int64   `json:"plaintext_bytes"`
	CiphertextBytes  int64   `json:"ciphertext_bytes"`
	PlaintextSHA256  string  `json:"plaintext_sha256"`
	CiphertextSHA256 string  `json:"ciphertext_sha256"`
	VolumeID         string  `json:"volume_id"`
	Role             string  `json:"role"`
}

type StorageVerification struct {
	Key       string  `json:"key"`
	VersionID *string `json:"version_id"`
	Assurance string  `json:"assurance"`
	Reason    *string `json:"reason"`
}

type StorageAcceptance struct {
	Protocol      string                `json:"protocol"`
	ReservationID string                `json:"reservation_id"`
	ReceiptSHA256 string                `json:"receipt_sha256"`
	Accepted      bool                  `json:"accepted"`
	AcceptanceID  string                `json:"acceptance_id"`
	ScrubRequired bool                  `json:"scrub_required"`
	Verification  []StorageVerification `json:"verification"`
}

// StorageCanonical uses the same lossless canonical encoding as the plan hash.
func StorageCanonical(value any) ([]byte, error) {
	body, err := json.Marshal(value)
	if err != nil || !storageUnicode(body) {
		return nil, ErrStorageRequest
	}
	d := json.NewDecoder(bytes.NewReader(body))
	d.UseNumber()
	var parsed any
	if err = d.Decode(&parsed); err != nil {
		return nil, ErrStorageRequest
	}
	var out bytes.Buffer
	if err = canonicalJSON(&out, parsed, true); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

// DecodeStorageValue is exact, duplicate-rejecting wire parsing, not authority.
func DecodeStorageValue(body []byte, dst any, limit int) error {
	if len(body) > limit || !storageUnicode(body) {
		return ErrStorageRequest
	}
	d := json.NewDecoder(bytes.NewReader(body))
	d.UseNumber()
	v, err := strictValueBound(d, 0, 10000)
	if err != nil {
		return ErrStorageRequest
	}
	if _, err = d.Token(); err != io.EOF {
		return ErrStorageRequest
	}
	kind := reflect.TypeOf(dst)
	if kind.Kind() != reflect.Pointer || !exactShape(v, kind.Elem()) {
		return ErrStorageRequest
	}
	if json.Unmarshal(body, dst) != nil {
		return ErrStorageRequest
	}
	return nil
}

var receiptHash = regexp.MustCompile(`^[0-9a-f]{64}$`)

func ValidateStorageObject(a StorageArtifact, obj StorageObjectReceipt) error {
	if obj.Key != a.Key || obj.VolumeID != a.VolumeID || obj.Role != a.Role ||
		strings.TrimSpace(obj.ETag) == "" || len(obj.ETag) > 1024 ||
		(obj.VersionID != nil && (*obj.VersionID == "" || len(*obj.VersionID) > 1024)) ||
		obj.PlaintextBytes < a.PlaintextMin || obj.PlaintextBytes > a.PlaintextMax ||
		obj.CiphertextBytes < a.CiphertextMin || obj.CiphertextBytes > a.CiphertextMax ||
		!receiptHash.MatchString(obj.PlaintextSHA256) || !receiptHash.MatchString(obj.CiphertextSHA256) {
		return ErrStorageRequest
	}
	return nil
}

// CanonicalReceipt checks membership by exact identity, not array position.
// Canonical JSON preserves array order, including the accepted C01 fixtures;
// an identical replay must retain the original complete receipt bytes.
func CanonicalReceipt(request *StorageTransactionRequest, receipt StorageReceipt) ([]byte, string, error) {
	if receipt.Protocol != StorageProtocol || receipt.Schema != 2 ||
		receipt.ReservationID != request.ReservationID || receipt.BackupID != request.BackupID ||
		receipt.Endpoint != request.Plan.Target.Endpoint || receipt.Bucket != request.Plan.Target.Bucket ||
		len(receipt.Objects) != len(request.Plan.Artifacts) {
		return nil, "", ErrStorageRequest
	}
	planned := make(map[string]StorageArtifact, len(request.Plan.Artifacts))
	for _, artifact := range request.Plan.Artifacts {
		if _, exists := planned[artifact.Key]; exists {
			return nil, "", ErrStorageRequest
		}
		planned[artifact.Key] = artifact
	}
	for _, obj := range receipt.Objects {
		artifact, ok := planned[obj.Key]
		if !ok || ValidateStorageObject(artifact, obj) != nil {
			return nil, "", ErrStorageRequest
		}
		delete(planned, obj.Key)
		if request.Plan.Encryption.Format == "none" || obj.Role == "volume_manifest" {
			if obj.PlaintextBytes != obj.CiphertextBytes || obj.PlaintextSHA256 != obj.CiphertextSHA256 {
				return nil, "", ErrStorageRequest
			}
		} else if obj.CiphertextBytes != 5+obj.PlaintextBytes+32*((obj.PlaintextBytes+5242880-1)/5242880) {
			return nil, "", ErrStorageRequest
		}
	}
	body, err := StorageCanonical(receipt)
	if err != nil || len(body) > MaxStorageReceiptBytes {
		return nil, "", ErrStorageRequest
	}
	return body, storageHash(string(body)), nil
}

func DecodeStorageAcceptance(body []byte, request *StorageTransactionRequest, receipt StorageReceipt) (*StorageAcceptance, error) {
	_, digest, err := CanonicalReceipt(request, receipt)
	if err != nil {
		return nil, ErrStorageRequest
	}
	objects := map[string]*string{}
	for _, o := range receipt.Objects {
		objects[o.Key] = o.VersionID
	}
	return DecodeReceiptAcceptance(body, request.ReservationID, digest, request.Plan.CapabilityProfile, objects)
}

// DecodeReceiptAcceptance validates acknowledgement of an already canonical,
// representation-validated receipt. Callers supply exact key/version membership.
func DecodeReceiptAcceptance(body []byte, reservation, digest, profile string, objects map[string]*string) (*StorageAcceptance, error) {
	var a StorageAcceptance
	if DecodeStorageValue(body, &a, MaxStorageReceiptBytes) != nil || a.Protocol != StorageProtocol || !a.Accepted ||
		a.ReservationID != reservation || a.AcceptanceID == "" || len(a.AcceptanceID) > 256 ||
		subtle.ConstantTimeCompare([]byte(a.ReceiptSHA256), []byte(digest)) != 1 || len(a.Verification) != len(objects) {
		return nil, ErrStorageRequest
	}
	scrub := false
	for _, v := range a.Verification {
		o, ok := objects[v.Key]
		if !ok || !reflect.DeepEqual(v.VersionID, o) {
			return nil, ErrStorageRequest
		}
		delete(objects, v.Key)
		switch v.Assurance {
		case "identity_metadata_only":
			if v.Reason == nil || *v.Reason != "provider_full_object_sha256_unavailable" {
				return nil, ErrStorageRequest
			}
			scrub = true
		case "provider_checksum_verified":
			if v.Reason != nil || profile != "checksum-enforced/1" {
				return nil, ErrStorageRequest
			}
		default:
			return nil, ErrStorageRequest
		}
	}
	if len(objects) != 0 || a.ScrubRequired != scrub {
		return nil, ErrStorageRequest
	}
	return &a, nil
}
