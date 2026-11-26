package tls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
)

// GenerateCSR generates a CSR from the existing agent private key.
// Returns the CSR in PEM format.
func (m *Manager) GenerateCSR(hostname string) ([]byte, error) {
	keyPath := filepath.Join(m.certsPath, keyFile)
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("read key: %w", err)
	}

	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in key file")
	}

	privKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		// Try PKCS8
		key, err2 := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err2 != nil {
			return nil, fmt.Errorf("parse key: %w (pkcs8: %w)", err, err2)
		}
		var ok bool
		privKey, ok = key.(*ecdsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("key is not ECDSA")
		}
	}

	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   hostname,
			Organization: []string{"vnbui-agent"},
		},
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, privKey)
	if err != nil {
		return nil, fmt.Errorf("create CSR: %w", err)
	}

	csrPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrDER,
	})

	return csrPEM, nil
}

// GenerateKeyPair creates a new ECDSA P-256 keypair and saves the key.
// Returns the private key.
func (m *Manager) GenerateKeyPair() (*ecdsa.PrivateKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("marshal key: %w", err)
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: keyDER,
	})

	if err := os.MkdirAll(m.certsPath, 0o700); err != nil {
		return nil, fmt.Errorf("create certs dir: %w", err)
	}

	keyPath := filepath.Join(m.certsPath, keyFile)
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return nil, fmt.Errorf("write key: %w", err)
	}

	return key, nil
}
