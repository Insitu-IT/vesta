package heartbeat

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"vnbui/agent/internal/config"
	tlspkg "vnbui/agent/internal/tls"
)

func TestEnrollClientCertificateUsesRegisteredAgentKeyAndDurableJournal(t *testing.T) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "agent identity CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/pki/renew":
			requests++
			if r.Header.Get("X-Agent-Key") != "registered-agent-key" {
				t.Error("certificate request lacked registered agent identity")
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			var body struct {
				CSR string `json:"csr"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Error(err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			block, _ := pem.Decode([]byte(body.CSR))
			if block == nil {
				t.Error("CSR missing")
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			csr, err := x509.ParseCertificateRequest(block.Bytes)
			if err != nil || csr.Subject.CommonName != "agent-test" {
				t.Errorf("unexpected agent CSR: %v", err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			leaf := &x509.Certificate{
				SerialNumber: big.NewInt(2), Subject: csr.Subject,
				NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
				ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
			}
			der, err := x509.CreateCertificate(rand.Reader, leaf, ca, csr.PublicKey, caKey)
			if err != nil {
				t.Error(err)
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]string{
				"cert_pem": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
			})
		case "/api/v1/pki/ca":
			_, _ = w.Write(caPEM)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	manager := tlspkg.New(t.TempDir())
	cfg := &config.Config{Hostname: "agent-test", AgentAPIKey: "registered-agent-key", OrchestratorURL: server.URL}
	if err := EnrollClientCertificate(cfg, server.Client(), manager); err != nil {
		t.Fatalf("enroll existing agent: %v", err)
	}
	if !manager.HasCerts() || requests != 1 {
		t.Fatalf("enrollment did not persist one identity: certs=%v requests=%d", manager.HasCerts(), requests)
	}
	if _, err := manager.ClientTLSConfig(); err != nil {
		t.Fatalf("journal certificate is unusable: %v", err)
	}
	if err := EnrollClientCertificate(cfg, server.Client(), manager); err == nil {
		t.Fatal("re-enrollment overwrote an existing callback identity")
	}
}
