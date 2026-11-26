package encryption

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
)

// FernetToAESKey derives a 32-byte AES key from a Fernet key.
// SHA256(base64_decode(fernet_key)) → 32-byte AES key
func FernetToAESKey(fernetKey string) ([]byte, error) {
	decoded, err := base64.URLEncoding.DecodeString(fernetKey)
	if err != nil {
		// Try standard base64
		decoded, err = base64.StdEncoding.DecodeString(fernetKey)
		if err != nil {
			return nil, fmt.Errorf("decode Fernet key: %w", err)
		}
	}

	hash := sha256.Sum256(decoded)
	return hash[:], nil
}

// DeriveKey derives a 32-byte AES key from a base64-encoded key.
// For aes-256-gcm: the key is already a raw 32-byte key, base64-encoded.
// For fernet: SHA256(base64_decode(key)).
func DeriveKey(key string, encType string) ([]byte, error) {
	switch encType {
	case "aes-256-gcm":
		decoded, err := base64.StdEncoding.DecodeString(key)
		if err != nil {
			return nil, fmt.Errorf("decode AES key: %w", err)
		}
		if len(decoded) != 32 {
			return nil, fmt.Errorf("AES key must be 32 bytes, got %d", len(decoded))
		}
		return decoded, nil

	case "fernet":
		return FernetToAESKey(key)

	default:
		return nil, fmt.Errorf("unsupported encryption type: %s", encType)
	}
}
