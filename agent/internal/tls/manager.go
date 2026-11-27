package tls

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"
)

const (
	certsDir          = "/var/lib/vnbui/certs"
	certFile          = "agent.crt"
	keyFile           = "agent.key"
	caFile            = "ca.crt"
	renewalDaysBefore = 30
)

// Manager handles TLS certificate storage and SSL context creation.
type Manager struct {
	certsPath string
}

// New creates a TLS manager.
func New(certsPath string) *Manager {
	if certsPath == "" {
		certsPath = certsDir
	}
	return &Manager{certsPath: certsPath}
}

func (m *Manager) CertPath() string { return filepath.Join(m.certsPath, certFile) }
func (m *Manager) CAPath() string   { return filepath.Join(m.certsPath, caFile) }
func (m *Manager) KeyPath() string  { return filepath.Join(m.certsPath, keyFile) }

// HasCerts returns true if agent certificates exist.
func (m *Manager) HasCerts() bool {
	certPath := filepath.Join(m.certsPath, certFile)
	keyPath := filepath.Join(m.certsPath, keyFile)

	_, certErr := os.Stat(certPath)
	_, keyErr := os.Stat(keyPath)
	return certErr == nil && keyErr == nil
}

// HasCA returns true if the CA certificate exists.
func (m *Manager) HasCA() bool {
	_, err := os.Stat(filepath.Join(m.certsPath, caFile))
	return err == nil
}

// SaveCerts stores certificate, key, and CA with proper permissions.
func (m *Manager) SaveCerts(cert, key, ca []byte) error {
	if len(cert) == 0 {
		return fmt.Errorf("agent certificate is empty")
	}
	newKey := key != nil
	if !newKey {
		var err error
		key, err = os.ReadFile(filepath.Join(m.certsPath, keyFile))
		if err != nil {
			return fmt.Errorf("read existing agent key: %w", err)
		}
	}
	if _, err := tls.X509KeyPair(cert, key); err != nil {
		return fmt.Errorf("agent certificate/key mismatch: %w", err)
	}
	if ca != nil {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(ca) {
			return fmt.Errorf("agent CA contains no usable certificate")
		}
	}
	if err := os.MkdirAll(m.certsPath, 0o700); err != nil {
		return fmt.Errorf("create certs dir: %w", err)
	}
	// A renewal passes nil key: keep the existing private key rather than
	// truncating it. On first enrollment write the key before its certificate.
	if newKey {
		if err := os.WriteFile(filepath.Join(m.certsPath, keyFile), key, 0o600); err != nil {
			return fmt.Errorf("write %s: %w", keyFile, err)
		}
	}
	if ca != nil {
		if err := os.WriteFile(filepath.Join(m.certsPath, caFile), ca, 0o600); err != nil {
			return fmt.Errorf("write %s: %w", caFile, err)
		}
	}
	if err := os.WriteFile(filepath.Join(m.certsPath, certFile), cert, 0o600); err != nil {
		return fmt.Errorf("write %s: %w", certFile, err)
	}

	slog.Info("saved TLS certificates", "path", m.certsPath)
	return nil
}

// NeedsRenewal checks if the agent cert expires within the renewal window.
func (m *Manager) NeedsRenewal() (bool, error) {
	certPath := filepath.Join(m.certsPath, certFile)
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return false, fmt.Errorf("read cert: %w", err)
	}

	cert, err := parseCertPEM(certPEM)
	if err != nil {
		return false, err
	}

	daysLeft := time.Until(cert.NotAfter).Hours() / 24
	if daysLeft < float64(renewalDaysBefore) {
		slog.Info("certificate needs renewal",
			"expires", cert.NotAfter,
			"days_left", int(daysLeft),
		)
		return true, nil
	}

	return false, nil
}

// Fingerprint returns the SHA256 fingerprint of the agent certificate.
func (m *Manager) Fingerprint() (string, error) {
	certPath := filepath.Join(m.certsPath, certFile)
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return "", fmt.Errorf("read cert: %w", err)
	}

	cert, err := parseCertPEM(certPEM)
	if err != nil {
		return "", err
	}

	hash := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(hash[:]), nil
}

// ClientTLSConfig creates a TLS config for outbound mTLS connections.
//
// FAILS CLOSED on a CA that cannot be read or parsed (#49). It previously did
// the opposite, one function away from ServerTLSConfig which has always failed
// closed:
//
//	if caPEM, err := os.ReadFile(caPath); err == nil { ... config.RootCAs = pool }
//
// When ReadFile failed the `if` simply did not fire, RootCAs stayed nil, and Go
// falls back to the SYSTEM ROOT POOL. A client built to verify the orchestrator
// against our PRIVATE CA would instead have verified it against public roots —
// not a bypass, so no flag sweep finds it, but a silent change of trust anchor
// that leaves a working client behind. The absence of a CA file yielded success.
//
// The two paths diverged for a structural reason rather than a careless one:
// ServerTLSConfig CANNOT function without the CA — there is nothing to verify
// clients against — so its absence forced an error return. This path COULD
// function without it, by degrading silently, so nothing forced the question.
//
// A caller that legitimately wants public roots should say so explicitly rather
// than get it from a missing file; the agent already has cfg.OrchestratorVerifySSL
// for the deliberate-no-verification case.
//
// NOTE: this function currently has NO CALLERS anywhere in the agent — outbound
// requests are built in cmd/vnbui-agent/main.go with their own http.Client. The
// defect was therefore latent rather than live. It is fixed rather than deleted
// so that whoever wires mTLS up inherits the correct posture, and because the
// inconsistency with its sibling was itself the trap.
func (m *Manager) ClientTLSConfig() (*tls.Config, error) {
	certPath := filepath.Join(m.certsPath, certFile)
	keyPath := filepath.Join(m.certsPath, keyFile)

	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("load keypair: %w", err)
	}

	caPath := filepath.Join(m.certsPath, caFile)
	caPEM, err := os.ReadFile(caPath)
	if err != nil {
		return nil, fmt.Errorf("read CA cert for server verification: %w", err)
	}
	pool := x509.NewCertPool()
	// AppendCertsFromPEM returns false when it parsed nothing usable. Discarding
	// it made a MALFORMED CA produce an empty pool, which fails CLOSED — so the
	// two failure modes were inconsistent with each other as well as with the
	// server path: missing CA opened, malformed CA closed.
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("CA cert at %s contains no usable certificate", caPath)
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      pool,
		MinVersion:   tls.VersionTLS12,
	}, nil
}

// ServerTLSConfig creates a TLS config for the agent's HTTPS server.
func (m *Manager) ServerTLSConfig(verifyClient bool) (*tls.Config, error) {
	return ReloadingServerTLSConfigFromFiles(
		filepath.Join(m.certsPath, certFile),
		filepath.Join(m.certsPath, keyFile),
		filepath.Join(m.certsPath, caFile),
		verifyClient,
	)
}

// ReloadingServerTLSConfigFromFiles validates the pair before startup, then
// follows atomic journal or projected-file renewal on every new handshake.
func ReloadingServerTLSConfigFromFiles(certPath, keyPath, caPath string, verifyClient bool) (*tls.Config, error) {
	cfg, err := ServerTLSConfigFromFiles(certPath, keyPath, caPath, verifyClient)
	if err != nil {
		return nil, err
	}
	cfg.Certificates = nil
	cfg.GetCertificate = func(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
		pair, err := tls.LoadX509KeyPair(certPath, keyPath)
		if err != nil {
			return nil, err
		}
		return &pair, nil
	}
	return cfg, nil
}

// ServerTLSConfigFromFiles serves certificates supplied by the installation's
// mounted Secret without copying them into the writable agent journal.
func ServerTLSConfigFromFiles(certPath, keyPath, caPath string, verifyClient bool) (*tls.Config, error) {
	if certPath == "" || keyPath == "" {
		return nil, fmt.Errorf("TLS server requires both certificate and key paths")
	}

	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("load keypair: %w", err)
	}

	config := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}

	if verifyClient {
		if caPath == "" {
			return nil, fmt.Errorf("TLS client verification requires a CA path")
		}
		caPEM, err := os.ReadFile(caPath)
		if err != nil {
			return nil, fmt.Errorf("read CA cert for client verification: %w", err)
		}
		pool := x509.NewCertPool()
		// Checked for the same reason as the client path (#49): an unparseable CA
		// otherwise yields an empty pool that rejects every client, which is safe
		// but reports itself as a handshake failure rather than a config error.
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, fmt.Errorf("CA cert at %s contains no usable certificate", caPath)
		}
		config.ClientAuth = tls.RequireAndVerifyClientCert
		config.ClientCAs = pool
	}

	return config, nil
}

func parseCertPEM(pem []byte) (*x509.Certificate, error) {
	block, _ := x509.ParseCertificate(pem)
	if block != nil {
		return block, nil
	}

	// Try PEM decode
	certs, err := x509.ParseCertificates(pem)
	if err == nil && len(certs) > 0 {
		return certs[0], nil
	}

	// Try standard PEM parse
	tlsCert, err := tls.X509KeyPair(pem, nil)
	if err == nil && len(tlsCert.Certificate) > 0 {
		return x509.ParseCertificate(tlsCert.Certificate[0])
	}

	return nil, fmt.Errorf("failed to parse certificate PEM")
}
