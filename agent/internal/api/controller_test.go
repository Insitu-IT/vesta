package api

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"vnbui/agent/internal/config"
)

const controllerFixture = "controller test fixture"

func testControllerConfig(cfg *config.Config) *config.Config {
	cfg.AgentID = "agent"
	pin := sha256.Sum256([]byte(controllerFixture))
	cfg.ObserveControllers(hex.EncodeToString(pin[:]), hex.EncodeToString(pin[:]))
	return cfg
}

func testControllerTLS() *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS12, ClientAuth: tls.RequireAndVerifyClientCert}
}

func testVerifiedControllerLeaf(raw []byte) *tls.ConnectionState {
	at := time.Now()
	return &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{{
		Raw: raw, NotBefore: at.Add(-time.Minute), NotAfter: at.Add(time.Hour),
	}}}}
}

func certifyTestController(r *http.Request) {
	r.Header.Set("X-Vesta-Agent-ID", "agent")
	r.TLS = testVerifiedControllerLeaf([]byte(controllerFixture))
}

func controllerTestCertificates(t *testing.T) (*x509.CertPool, []tls.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	at := time.Now()
	authority := &x509.Certificate{
		SerialNumber: big.NewInt(1), NotBefore: at.Add(-time.Minute), NotAfter: at.Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, authority, authority, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	certificates := make([]tls.Certificate, 3)
	for i := range certificates {
		client, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		leaf := &x509.Certificate{
			SerialNumber: big.NewInt(int64(i + 2)), NotBefore: at.Add(-time.Minute), NotAfter: at.Add(time.Hour),
			KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		}
		cert, err := x509.CreateCertificate(rand.Reader, leaf, ca, client.Public(), key)
		if err != nil {
			t.Fatal(err)
		}
		certificates[i] = tls.Certificate{Certificate: [][]byte{cert}, PrivateKey: client}
	}
	return roots, certificates
}

func TestControllerCertificatesOnVMRestoreRoutes(t *testing.T) {
	roots, certs := controllerTestCertificates(t)
	for _, variant := range []struct {
		name, body string
		executor   func() ServerOption
	}{
		{"libvirt", `{"restore_id":"fixture","native":{"schema":"vnbui-native-vm-restore/1"}}`, func() ServerOption { return WithRestoreExecutor(&freshNativeExecutor{}) }},
		{"kubevirt", `{"restore_id":"fixture","kubevirt":{"schema":"vnbui-kubevirt-vm-restore/1"}}`, func() ServerOption { return WithRestoreExecutor(&freshRestoreExecutor{}) }},
	} {
		t.Run(variant.name, func(t *testing.T) {
			cfg := &config.Config{Provider: variant.name, AgentID: "agent", EnableAPIKeyValidation: true, OrchestratorAPIKey: "fixture"}
			mounted := &tls.Config{MinVersion: tls.VersionTLS12, ClientAuth: tls.VerifyClientCertIfGiven, ClientCAs: roots}
			server := httptest.NewUnstartedServer(NewServer(cfg, "test", WithTLSConfig(mounted), variant.executor()).router)
			server.TLS = mounted
			server.StartTLS()
			defer server.Close()
			request := func(certificate int, target string, want int) {
				t.Helper()
				trans := server.Client().Transport.(*http.Transport).Clone()
				defer trans.CloseIdleConnections()
				if certificate >= 0 {
					trans.TLSClientConfig.Certificates = []tls.Certificate{certs[certificate]}
				}
				req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, server.URL+"/api/restores", strings.NewReader(variant.body))
				if err != nil {
					t.Fatal(err)
				}
				req.Header.Set("X-Orchestrator-Key", "fixture")
				if target != "" {
					req.Header.Set("X-Vesta-Agent-ID", target)
				}
				body, err := (&http.Client{Transport: trans}).Do(req)
				if err != nil {
					t.Fatal(err)
				}
				defer body.Body.Close()
				if body.StatusCode != want {
					data, _ := io.ReadAll(body.Body)
					t.Fatalf("HTTP %d, want %d: %s", body.StatusCode, want, data)
				}
			}
			request(0, "agent", http.StatusServiceUnavailable)
			pin := sha256.Sum256(certs[0].Certificate[0])
			cfg.ObserveControllers("", hex.EncodeToString(pin[:]))
			request(0, "agent", http.StatusServiceUnavailable)
			cfg.ObserveControllers(hex.EncodeToString(pin[:]), "")
			request(0, "agent", http.StatusAccepted)
			request(1, "agent", http.StatusForbidden)
			request(-1, "agent", http.StatusForbidden)
			request(0, "", http.StatusForbidden)
			request(0, "other-agent", http.StatusForbidden)
			renewed := sha256.Sum256(certs[2].Certificate[0])
			cfg.ObserveControllers(hex.EncodeToString(renewed[:]), "")
			request(0, "agent", http.StatusForbidden)
			request(2, "agent", http.StatusAccepted)
			cfg.ObserveControllers("", "")
			request(2, "agent", http.StatusServiceUnavailable)
		})
	}
}
