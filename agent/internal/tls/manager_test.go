package tls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The defect (#49): ClientTLSConfig treated an unreadable CA as "no CA" and left
// RootCAs nil, which makes Go fall back to the SYSTEM ROOT POOL — verification
// against public roots instead of our private CA. Not a bypass, so no flag sweep
// finds it; a silent change of trust anchor that leaves a working client behind.
//
// ServerTLSConfig, one function away in the same file, has always failed closed.
// These tests assert both paths now reject the same inputs, because the
// inconsistency was the trap rather than either behaviour alone.

// writeCerts lays down a usable keypair, and whatever CA bytes the test wants.
// Pass caPEM == nil to leave ca.crt absent entirely.
func writeCerts(t *testing.T, caPEM []byte) string {
	t.Helper()
	dir := t.TempDir()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "vnbui-agent-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	if err := os.WriteFile(filepath.Join(dir, certFile), certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, keyFile), keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if caPEM != nil {
		if err := os.WriteFile(filepath.Join(dir, caFile), caPEM, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// validCA reuses the self-signed cert as a CA — enough for AppendCertsFromPEM.
func validCA(t *testing.T) []byte {
	t.Helper()
	dir := writeCerts(t, nil)
	b, err := os.ReadFile(filepath.Join(dir, certFile))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestSaveCertsRenewalKeepsExistingPrivateKey(t *testing.T) {
	dir := writeCerts(t, validCA(t))
	manager := New(dir)
	cert, err := os.ReadFile(filepath.Join(dir, certFile))
	if err != nil {
		t.Fatal(err)
	}
	keyBefore, err := os.ReadFile(filepath.Join(dir, keyFile))
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.SaveCerts(cert, nil, nil); err != nil {
		t.Fatalf("renew certificate using existing key: %v", err)
	}
	keyAfter, err := os.ReadFile(filepath.Join(dir, keyFile))
	if err != nil || string(keyAfter) != string(keyBefore) {
		t.Fatalf("renewal changed private key: %v", err)
	}
	if _, err := tls.LoadX509KeyPair(filepath.Join(dir, certFile), filepath.Join(dir, keyFile)); err != nil {
		t.Fatalf("renewed identity unusable: %v", err)
	}
}

func TestSaveCertsRejectsMismatchedRenewalWithoutChangingIdentity(t *testing.T) {
	dir := writeCerts(t, validCA(t))
	manager := New(dir)
	certBefore, _ := os.ReadFile(filepath.Join(dir, certFile))
	keyBefore, _ := os.ReadFile(filepath.Join(dir, keyFile))
	foreignCert, _ := os.ReadFile(filepath.Join(writeCerts(t, nil), certFile))
	if err := manager.SaveCerts(foreignCert, nil, nil); err == nil {
		t.Fatal("mismatched renewal accepted")
	}
	certAfter, _ := os.ReadFile(filepath.Join(dir, certFile))
	keyAfter, _ := os.ReadFile(filepath.Join(dir, keyFile))
	if string(certAfter) != string(certBefore) || string(keyAfter) != string(keyBefore) {
		t.Fatal("rejected renewal changed existing identity")
	}
}

func TestClientTLSConfigFailsClosedOnMissingCA(t *testing.T) {
	// THE defect. Before the fix this returned a usable config with RootCAs nil,
	// i.e. a client silently verifying against public roots.
	m := New(writeCerts(t, nil))

	cfg, err := m.ClientTLSConfig()
	if err == nil {
		t.Fatalf("expected an error for a missing CA; got a usable config "+
			"(RootCAs nil = system pool = wrong trust anchor): %+v", cfg)
	}
	if !strings.Contains(err.Error(), "read CA cert") {
		t.Errorf("error should name the CA read; got %q", err)
	}
}

func TestClientTLSConfigFailsClosedOnMalformedCA(t *testing.T) {
	// AppendCertsFromPEM's return value used to be discarded, so a malformed CA
	// produced an EMPTY pool. That failed closed at handshake time rather than at
	// config time — safe, but inconsistent with the missing-CA case, which opened.
	m := New(writeCerts(t, []byte("-----BEGIN CERTIFICATE-----\nnot base64\n-----END CERTIFICATE-----\n")))

	if _, err := m.ClientTLSConfig(); err == nil {
		t.Fatal("expected an error for a malformed CA")
	} else if !strings.Contains(err.Error(), "no usable certificate") {
		t.Errorf("error should say the CA parsed to nothing; got %q", err)
	}
}

func TestClientTLSConfigUsesThePrivateCAWhenPresent(t *testing.T) {
	// The positive control: without this the two tests above pass against a
	// function that always errors, which would be "fail closed" in the useless sense.
	m := New(writeCerts(t, validCA(t)))

	cfg, err := m.ClientTLSConfig()
	if err != nil {
		t.Fatalf("valid CA should produce a config: %v", err)
	}
	if cfg.RootCAs == nil {
		t.Error("RootCAs is nil, so Go would use the system pool — the whole defect")
	}
	if len(cfg.Certificates) != 1 {
		t.Errorf("client cert not loaded: %d certificates", len(cfg.Certificates))
	}
}

func TestServerTLSConfigStillFailsClosedOnMissingCA(t *testing.T) {
	// Unchanged behaviour, asserted so the fix cannot be "fixed" by making the
	// server path match the old client path instead of the other way round.
	m := New(writeCerts(t, nil))

	if _, err := m.ServerTLSConfig(true); err == nil {
		t.Fatal("expected an error for a missing CA with verifyClient=true")
	}
}

func TestServerTLSConfigFailsClosedOnMalformedCA(t *testing.T) {
	m := New(writeCerts(t, []byte("garbage, not a PEM block at all")))

	if _, err := m.ServerTLSConfig(true); err == nil {
		t.Fatal("expected an error for a malformed CA")
	} else if !strings.Contains(err.Error(), "no usable certificate") {
		t.Errorf("error should say the CA parsed to nothing; got %q", err)
	}
}

func TestServerTLSConfigNeedsNoCAWithoutClientVerification(t *testing.T) {
	// verifyClient=false has nothing to verify against, so a missing CA is fine.
	// Pinned so "fail closed on missing CA" is not over-applied to this path.
	m := New(writeCerts(t, nil))

	if _, err := m.ServerTLSConfig(false); err != nil {
		t.Fatalf("verifyClient=false should not require a CA: %v", err)
	}
}

func TestServerTLSConfigFromMountedFiles(t *testing.T) {
	dir := writeCerts(t, validCA(t))
	cfg, err := ServerTLSConfigFromFiles(
		filepath.Join(dir, certFile), filepath.Join(dir, keyFile), filepath.Join(dir, caFile), true,
	)
	if err != nil {
		t.Fatalf("mounted certificate pair should enable HTTPS: %v", err)
	}
	if len(cfg.Certificates) != 1 || cfg.ClientCAs == nil {
		t.Fatal("mounted TLS configuration lacks server certificate or client CA")
	}
}

func TestServerTLSConfigFromMountedFilesFailsClosed(t *testing.T) {
	dir := writeCerts(t, nil)
	cert := filepath.Join(dir, certFile)
	key := filepath.Join(dir, keyFile)
	for _, tc := range []struct {
		name, cert, key, ca string
		verify              bool
	}{
		{"missing certificate path", "", key, "", false},
		{"missing key path", cert, "", "", false},
		{"unreadable key", cert, filepath.Join(dir, "missing.key"), "", false},
		{"missing client CA", cert, key, "", true},
		{"unreadable client CA", cert, key, filepath.Join(dir, "missing.ca"), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ServerTLSConfigFromFiles(tc.cert, tc.key, tc.ca, tc.verify); err == nil {
				t.Fatal("invalid mounted TLS inputs must not enable HTTP fallback")
			}
		})
	}
}

func TestBothPathsRejectTheSameInputs(t *testing.T) {
	// The property the issue was actually about: not either behaviour on its own,
	// but that two constructors one function apart disagreed about what an
	// unreadable CA means.
	cases := []struct {
		name string
		ca   []byte
	}{
		{"missing", nil},
		{"malformed", []byte("not a certificate")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := New(writeCerts(t, tc.ca))
			_, clientErr := m.ClientTLSConfig()
			_, serverErr := m.ServerTLSConfig(true)
			if (clientErr == nil) != (serverErr == nil) {
				t.Errorf("paths disagree on a %s CA: client=%v server=%v",
					tc.name, clientErr, serverErr)
			}
		})
	}
}

func TestMinVersionIsSetOnBothPaths(t *testing.T) {
	// Go's default floor moves between releases; pinning it makes the shipped
	// binary's posture a property of this file rather than of the toolchain.
	m := New(writeCerts(t, validCA(t)))

	client, err := m.ClientTLSConfig()
	if err != nil {
		t.Fatal(err)
	}
	if client.MinVersion == 0 {
		t.Error("client MinVersion unset")
	}
	server, err := m.ServerTLSConfig(true)
	if err != nil {
		t.Fatal(err)
	}
	if server.MinVersion == 0 {
		t.Error("server MinVersion unset")
	}
}
