package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"vnbui/agent/internal/config"
	tlspkg "vnbui/agent/internal/tls"
)

func testServerPair(t *testing.T, directory, certName, keyName string) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPath := filepath.Join(directory, certName)
	keyPath := filepath.Join(directory, keyName)
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath
}

func TestAgentServerTLSConfigUsesMountedCertificate(t *testing.T) {
	cert, key := testServerPair(t, t.TempDir(), "tls.crt", "tls.key")
	cfg := &config.Config{TLSEnabled: true, TLSCertFile: cert, TLSKeyFile: key}
	serverTLS, err := agentServerTLSConfig(cfg, tlspkg.New(t.TempDir()))
	if err != nil || serverTLS == nil || len(serverTLS.Certificates) != 1 {
		t.Fatalf("mounted certificate did not enable HTTPS: config=%v err=%v", serverTLS, err)
	}
}

func TestAgentServerTLSConfigRequiresSeparateClientCA(t *testing.T) {
	dir := t.TempDir()
	cert, key := testServerPair(t, dir, "tls.crt", "tls.key")
	clientCA, _ := testServerPair(t, dir, "client-ca.crt", "client-ca.key")
	cfg := &config.Config{
		TLSEnabled: true, TLSCertFile: cert, TLSKeyFile: key,
		TLSCAFile: cert, TLSVerifyClient: true,
	}
	if _, err := agentServerTLSConfig(cfg, tlspkg.New(t.TempDir())); err == nil {
		t.Fatal("outbound server trust was reused for inbound client verification")
	}
	cfg.TLSClientCAFile = clientCA
	serverTLS, err := agentServerTLSConfig(cfg, tlspkg.New(t.TempDir()))
	if err != nil || serverTLS.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Fatalf("explicit client CA did not enable verified client TLS: config=%v err=%v", serverTLS, err)
	}
}

func TestOutboundTLSDoesNotUseHTTPSServingCertificateAsCallbackIdentity(t *testing.T) {
	dir := t.TempDir()
	serverCert, serverKey := testServerPair(t, dir, "server.crt", "server.key")
	callbackCert, callbackKey := testServerPair(t, dir, "callback.crt", "callback.key")
	cfg := &config.Config{
		OrchestratorVerifySSL: true,
		TLSCertFile:           serverCert, TLSKeyFile: serverKey,
	}
	outbound, err := cfg.OutboundTLSConfig()
	if err != nil || outbound.GetClientCertificate != nil {
		t.Fatalf("serving identity leaked into callback TLS: config=%v err=%v", outbound, err)
	}
	cfg.CallbackClientCertFile = callbackCert
	if _, err := cfg.OutboundTLSConfig(); err == nil {
		t.Fatal("half-configured callback credential was accepted")
	}
	cfg.CallbackClientKeyFile = callbackKey
	outbound, err = cfg.OutboundTLSConfig()
	if err != nil || outbound.GetClientCertificate == nil {
		t.Fatalf("dedicated callback credential unavailable: config=%v err=%v", outbound, err)
	}
	selected, err := outbound.GetClientCertificate(&tls.CertificateRequestInfo{})
	if err != nil || selected == nil || len(selected.Certificate) != 1 {
		t.Fatalf("callback client credential could not be loaded: cert=%v err=%v", selected, err)
	}
	serving, err := tls.LoadX509KeyPair(serverCert, serverKey)
	if err != nil {
		t.Fatal(err)
	}
	if string(selected.Certificate[0]) == string(serving.Certificate[0]) {
		t.Fatal("callback client identity equals the HTTPS serving identity")
	}
}

func TestFreshRegistrationUsesVerifiedBootstrapOnlyUntilCertificateExists(t *testing.T) {
	dir := t.TempDir()
	journal := tlspkg.New(dir)
	cfg := &config.Config{
		OrchestratorURL:        "https://backend.example",
		OrchestratorVerifySSL:  true,
		RegistrationKey:        "one-use-registration-key",
		CallbackClientCertFile: journal.CertPath(),
		CallbackClientKeyFile:  journal.KeyPath(),
	}
	if _, err := cfg.OutboundTLSConfig(); err == nil {
		t.Fatal("normal callback transport accepted a missing client certificate")
	}
	// Exercise runtime synchronization before bootstrap to catch copying a used
	// Config mutex while deriving certificate-free registration transport.
	cfg.ApplyRemoteConfig(map[string]interface{}{"heartbeat_interval": 15})
	bootstrap, err := registrationTLSConfig(cfg, journal)
	if err != nil || bootstrap.GetClientCertificate != nil {
		t.Fatalf("fresh registration did not use certificate-free verified TLS: config=%v err=%v", bootstrap, err)
	}
	if cfg.CallbackClientCertFile != journal.CertPath() || cfg.CallbackClientKeyFile != journal.KeyPath() || cfg.HeartbeatIntervalSeconds() != 15 {
		t.Fatal("bootstrap changed live callback identity or runtime configuration")
	}
	if bootstrap.InsecureSkipVerify {
		t.Fatal("registration disabled server certificate verification")
	}

	testServerPair(t, dir, "agent.crt", "agent.key")
	if _, err := registrationTLSConfig(cfg, journal); err == nil {
		t.Fatal("fresh registration would overwrite an existing journal certificate")
	}
	normal, err := cfg.OutboundTLSConfig()
	if err != nil || normal.GetClientCertificate == nil {
		t.Fatalf("issued callback certificate unavailable after registration: config=%v err=%v", normal, err)
	}
	if _, err := normal.GetClientCertificate(&tls.CertificateRequestInfo{}); err != nil {
		t.Fatalf("issued callback certificate could not be reloaded: %v", err)
	}
}

func TestFreshRegistrationNeverBootstrapsOverUnverifiedOrIncompleteTLS(t *testing.T) {
	dir := t.TempDir()
	journal := tlspkg.New(dir)
	cert := journal.CertPath()
	key := journal.KeyPath()
	for _, cfg := range []*config.Config{
		{OrchestratorURL: "http://backend.example", OrchestratorVerifySSL: true, RegistrationKey: "key", CallbackClientCertFile: cert, CallbackClientKeyFile: key},
		{OrchestratorURL: "https://backend.example", OrchestratorVerifySSL: false, RegistrationKey: "key", CallbackClientCertFile: cert, CallbackClientKeyFile: key},
		{OrchestratorURL: "https://backend.example", OrchestratorVerifySSL: true, CallbackClientCertFile: cert, CallbackClientKeyFile: key},
		{OrchestratorURL: "https://backend.example", OrchestratorVerifySSL: true, RegistrationKey: "key", CallbackClientCertFile: cert},
		{OrchestratorURL: "https://backend.example", OrchestratorVerifySSL: true, RegistrationKey: "key", CallbackClientCertFile: filepath.Join(dir, "other.crt"), CallbackClientKeyFile: key},
	} {
		if _, err := registrationTLSConfig(cfg, journal); err == nil {
			t.Fatalf("unsafe registration bootstrap accepted: %+v", cfg)
		}
	}
	if err := os.WriteFile(cert, []byte("incomplete"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := registrationTLSConfig(&config.Config{
		OrchestratorURL: "https://backend.example", OrchestratorVerifySSL: true,
		RegistrationKey: "key", CallbackClientCertFile: cert, CallbackClientKeyFile: key,
	}, journal); err == nil {
		t.Fatal("fresh registration would overwrite a partial certificate journal")
	}
}

func TestFreshRegistrationTransportSwitchesToIssuedPeerCertificate(t *testing.T) {
	dir := t.TempDir()
	journal := tlspkg.New(filepath.Join(dir, "journal"))
	clientCert, clientKey := testServerPair(t, dir, "client.crt", "client.key")
	clientPEM, err := os.ReadFile(clientCert)
	if err != nil {
		t.Fatal(err)
	}
	clientKeyPEM, err := os.ReadFile(clientKey)
	if err != nil {
		t.Fatal(err)
	}
	clientCAs := x509.NewCertPool()
	if !clientCAs.AppendCertsFromPEM(clientPEM) {
		t.Fatal("client fixture certificate unreadable")
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if len(r.TLS.PeerCertificates) == 0 {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	server.TLS = &tls.Config{ClientAuth: tls.VerifyClientCertIfGiven, ClientCAs: clientCAs}
	server.StartTLS()
	defer server.Close()
	serverCA := filepath.Join(dir, "server-ca.crt")
	if err := os.WriteFile(serverCA, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{
		OrchestratorURL:        server.URL,
		OrchestratorVerifySSL:  true,
		TLSCAFile:              serverCA,
		RegistrationKey:        "one-use-registration-key",
		CallbackClientCertFile: journal.CertPath(),
		CallbackClientKeyFile:  journal.KeyPath(),
	}
	bootstrap, err := registrationTLSConfig(cfg, journal)
	if err != nil {
		t.Fatal(err)
	}
	response, err := orchestratorHTTPClient(bootstrap).Get(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("registration unexpectedly presented a client certificate: HTTP %d", response.StatusCode)
	}
	if err := journal.SaveCerts(clientPEM, clientKeyPEM, nil); err != nil {
		t.Fatal(err)
	}
	callback, err := cfg.OutboundTLSConfig()
	if err != nil {
		t.Fatal(err)
	}
	response, err = orchestratorHTTPClient(callback).Get(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("post-registration callback lacked the issued certificate: HTTP %d", response.StatusCode)
	}
}

func TestReadinessProbeRequiresDedicatedVerifiedClientIdentity(t *testing.T) {
	serverCert, serverKey := testServerPair(t, t.TempDir(), "server.crt", "server.key")
	for _, cfg := range []*config.Config{
		{TLSEnabled: false, OrchestratorVerifySSL: true},
		{TLSEnabled: true, OrchestratorVerifySSL: true, TLSCertFile: serverCert, TLSKeyFile: serverKey},
		{TLSEnabled: true, OrchestratorVerifySSL: true, CallbackClientCertFile: serverCert},
	} {
		if err := probeReady(cfg); err == nil {
			t.Fatal("readiness probe accepted an absent or incomplete client identity")
		}
	}
}

func TestClientCertificateEnrollmentRequiresHTTPSAPIKeyBootstrap(t *testing.T) {
	for _, cfg := range []*config.Config{
		{OrchestratorURL: "http://backend", Hostname: "agent", AgentAPIKey: "key"},
		{OrchestratorURL: "https://backend", Hostname: "agent", AgentAPIKey: "key", CallbackClientCertFile: "/already/active"},
	} {
		if err := enrollClientCert(cfg); err == nil {
			t.Fatal("enrollment accepted an unverified or already-active transport")
		}
	}
}

func TestReadinessProbeUsesVerifiedSiteAndClientCertificates(t *testing.T) {
	dir := t.TempDir()
	clientCert, clientKey := testServerPair(t, dir, "client.crt", "client.key")
	clientPEM, err := os.ReadFile(clientCert)
	if err != nil {
		t.Fatal(err)
	}
	clientCAs := x509.NewCertPool()
	if !clientCAs.AppendCertsFromPEM(clientPEM) {
		t.Fatal("client fixture certificate unreadable")
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/health/ready" || r.TLS == nil || len(r.TLS.PeerCertificates) != 1 {
			t.Error("readiness request lacks verified client identity")
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	server.TLS = &tls.Config{ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: clientCAs}
	server.StartTLS()
	defer server.Close()
	caPath := filepath.Join(dir, "server-ca.crt")
	if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	endpoint, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	host, portText, err := net.SplitHostPort(endpoint.Host)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{
		TLSEnabled: true, AgentIP: host, AgentPort: port,
		OrchestratorVerifySSL: true, TLSCAFile: caPath,
		CallbackClientCertFile: clientCert, CallbackClientKeyFile: clientKey,
	}
	if err := probeReady(cfg); err != nil {
		t.Fatalf("verified readiness probe failed: %v", err)
	}
}

func TestAgentServerTLSConfigRequiresCertificateWhenEnabled(t *testing.T) {
	manager := tlspkg.New(t.TempDir())
	for _, cfg := range []*config.Config{
		{TLSEnabled: true},
		{TLSEnabled: true, TLSCertFile: "/missing/tls.crt"},
	} {
		if serverTLS, err := agentServerTLSConfig(cfg, manager); err == nil || serverTLS != nil {
			t.Fatalf("enabled HTTPS degraded to HTTP: config=%v err=%v", serverTLS, err)
		}
	}
}

func TestAgentServerTLSConfigPreservesManagedCertificate(t *testing.T) {
	dir := t.TempDir()
	testServerPair(t, dir, "agent.crt", "agent.key")
	serverTLS, err := agentServerTLSConfig(&config.Config{TLSEnabled: true}, tlspkg.New(dir))
	if err != nil || serverTLS == nil {
		t.Fatalf("managed certificate did not enable HTTPS: config=%v err=%v", serverTLS, err)
	}
}

func TestAgentServerTLSConfigAllowsExplicitHTTPMode(t *testing.T) {
	serverTLS, err := agentServerTLSConfig(&config.Config{TLSEnabled: false}, tlspkg.New(t.TempDir()))
	if err != nil || serverTLS != nil {
		t.Fatalf("explicit HTTP mode changed: config=%v err=%v", serverTLS, err)
	}
}
