// Package s3recovery discovers and validates offline recovery data in a
// locally configured versioned S3 bucket.
package s3recovery

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"vnbui/agent/internal/models"
)

const maxPoint = 64 << 10
const maxGeneration = 16 << 20

var uuid = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
var checksum = regexp.MustCompile(`^[0-9a-f]{64}$`)
var ErrMetadata = errors.New("invalid or unsupported recovery metadata")

func ValidID(value string) bool {
	return value != "00000000-0000-0000-0000-000000000000" && uuid.MatchString(value)
}

type Trust struct {
	Schema         string `json:"schema"`
	InstallationID string `json:"installation_id"`
	OrgID          string `json:"org_id"`
	KeyID          string `json:"key_id"`
	PublicKey      string `json:"public_key"`
}

type generationPin struct {
	Endpoint  string `json:"endpoint"`
	Bucket    string `json:"bucket"`
	Region    string `json:"region"`
	Key       string `json:"key"`
	VersionID string `json:"version_id"`
	ETag      string `json:"etag"`
	Bytes     int64  `json:"bytes"`
	SHA256    string `json:"sha256"`
}

type point struct {
	Format         string        `json:"format"`
	InstallationID string        `json:"installation_id"`
	OrgID          string        `json:"org_id"`
	BackupID       string        `json:"backup_id"`
	GenerationID   string        `json:"generation_id"`
	RootBackupID   string        `json:"root_backup_id"`
	Provider       string        `json:"provider"`
	Name           string        `json:"name"`
	CompletedAt    string        `json:"completed_at"`
	Generation     generationPin `json:"generation"`
}

func hash(data []byte) string {
	value := sha256.Sum256(data)
	return hex.EncodeToString(value[:])
}

func decode64(encoding *base64.Encoding, value string) ([]byte, error) {
	data, err := encoding.Strict().DecodeString(value)
	if err != nil || encoding.EncodeToString(data) != value {
		return nil, ErrMetadata
	}
	return data, nil
}

func DecodeTrust(raw []byte) (Trust, error) {
	var trust Trust
	if models.DecodeStorageValue(raw, &trust, maxPoint) != nil {
		return Trust{}, ErrMetadata
	}
	_, err := trust.key()
	return trust, err
}

func (t Trust) key() (ed25519.PublicKey, error) {
	key, err := decode64(base64.RawURLEncoding, t.PublicKey)
	if err != nil || t.Schema != "vesta-recovery-trust/1" || !ValidID(t.InstallationID) ||
		!ValidID(t.OrgID) || len(key) != ed25519.PublicKeySize || t.KeyID != hash(key) {
		return nil, errors.New("invalid recovery verification key or installation/organization identity")
	}
	return ed25519.PublicKey(key), nil
}

func (t Trust) prefix() string {
	return "vesta-recovery/v1/" + t.InstallationID + "/" + t.OrgID + "/"
}

func generationKey(org, root, id string) string {
	return "vnbui-owned/v1/" + hash([]byte(org)) + "/" + hash([]byte(root)) + "/generations/" + id + ".json"
}

func (t Trust) verify(raw []byte, objectKey string) (point, error) {
	var envelope struct {
		Format    string `json:"format"`
		PublicKey string `json:"public_key"`
		JWS       string `json:"jws"`
	}
	var protected struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
		Typ string `json:"typ"`
	}
	var value point
	key, err := t.key()
	if err != nil {
		return value, err
	}
	if models.DecodeStorageValue(raw, &envelope, maxPoint) != nil ||
		envelope.Format != "vesta-recovery-envelope/1" || envelope.PublicKey != t.PublicKey {
		return value, ErrMetadata
	}
	segments := strings.SplitN(envelope.JWS, ".", 4)
	if len(segments) != 3 {
		return value, ErrMetadata
	}
	header, err := decode64(base64.RawURLEncoding, segments[0])
	if err != nil || models.DecodeStorageValue(header, &protected, 1024) != nil ||
		protected.Alg != "EdDSA" || protected.Kid != t.KeyID || protected.Typ != "vesta-recovery-point+jws" {
		return value, ErrMetadata
	}
	signature, err := decode64(base64.RawURLEncoding, segments[2])
	signed := envelope.JWS[:len(segments[0])+len(segments[1])+1]
	if err != nil || !ed25519.Verify(key, []byte(signed), signature) {
		return value, errors.New("recovery point signature does not match independently trusted key")
	}
	rawPayload, err := decode64(base64.RawURLEncoding, segments[1])
	if err != nil || models.DecodeStorageValue(rawPayload, &value, maxPoint) != nil {
		return value, ErrMetadata
	}
	if value.Format != "vesta-recovery-point/1" || value.InstallationID != t.InstallationID ||
		value.OrgID != t.OrgID || !ValidID(value.BackupID) || !ValidID(value.GenerationID) ||
		!ValidID(value.RootBackupID) || objectKey != t.prefix()+value.BackupID+".json" ||
		!validName(value.Name) || (value.Provider != "libvirt" && value.Provider != "kubevirt") {
		return point{}, ErrMetadata
	}
	at, err := time.Parse(time.RFC3339Nano, value.CompletedAt)
	if err != nil || at.IsZero() || !strings.HasSuffix(value.CompletedAt, "Z") {
		return point{}, ErrMetadata
	}
	pin := value.Generation
	if pin.Key != generationKey(value.OrgID, value.RootBackupID, value.GenerationID) ||
		pin.Bytes <= 0 || pin.Bytes > maxGeneration || !checksum.MatchString(pin.SHA256) {
		return point{}, ErrMetadata
	}
	return value, nil
}

func validName(name string) bool {
	return name != "" && len(name) <= 1024 && utf8.ValidString(name) &&
		strings.IndexFunc(name, unicode.IsControl) < 0
}
