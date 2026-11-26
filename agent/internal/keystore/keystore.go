package keystore

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// Store handles encrypted API key storage using a stable identity-derived key.
type Store struct {
	path     string
	identity string
}

// Data holds the stored key data.
type Data struct {
	AgentAPIKey        string `json:"agent_api_key"`
	OrchestratorAPIKey string `json:"orchestrator_api_key"`
	AgentID            string `json:"agent_id"`
}

// New creates a keystore at the given path. A non-empty identity is intended
// for containers without /etc/machine-id. An empty identity preserves the host
// machine-id derivation used by installed libvirt agents.
func New(path, identity string) *Store {
	return &Store{path: path, identity: identity}
}

// Save encrypts and stores key data.
func (s *Store) Save(data *Data) error {
	key, err := deriveKey(s.identity)
	if err != nil {
		return fmt.Errorf("derive key: %w", err)
	}

	plaintext, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}

	ciphertext, err := encrypt(key, plaintext)
	if err != nil {
		return fmt.Errorf("encrypt: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return fmt.Errorf("mkdir: %w", err)
	}

	if err := os.WriteFile(s.path, ciphertext, 0o600); err != nil {
		return fmt.Errorf("write: %w", err)
	}

	return nil
}

// Load decrypts and returns stored key data.
func (s *Store) Load() (*Data, error) {
	key, err := deriveKey(s.identity)
	if err != nil {
		return nil, fmt.Errorf("derive key: %w", err)
	}

	ciphertext, err := os.ReadFile(s.path)
	if err != nil {
		return nil, fmt.Errorf("read: %w", err)
	}

	plaintext, err := decrypt(key, ciphertext)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}

	var data Data
	if err := json.Unmarshal(plaintext, &data); err != nil {
		return nil, fmt.Errorf("unmarshal: %w", err)
	}

	return &data, nil
}

// Exists returns true if the key file exists.
func (s *Store) Exists() bool {
	_, err := os.Stat(s.path)
	return err == nil
}

func deriveKey(identity string) ([]byte, error) {
	if identity != "" {
		hash := sha256.Sum256([]byte("vnbui-keystore-identity-v1:" + identity))
		return hash[:], nil
	}
	machineID, err := os.ReadFile("/etc/machine-id")
	if err != nil {
		return nil, fmt.Errorf("read machine-id: %w", err)
	}
	hash := sha256.Sum256(machineID)
	return hash[:], nil
}

func encrypt(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

func decrypt(key, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	if len(ciphertext) < gcm.NonceSize() {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce := ciphertext[:gcm.NonceSize()]
	ct := ciphertext[gcm.NonceSize():]

	return gcm.Open(nil, nonce, ct, nil)
}
