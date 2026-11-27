package api

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"vnbui/agent/internal/config"
	"vnbui/agent/internal/models"
	"vnbui/agent/internal/verification"
)

type testVerifier struct {
	calls int
	err   error
	org   string
}

func (e *testVerifier) Submit(req verification.Request) (*verification.Progress, error) {
	e.calls++
	return &verification.Progress{Schema: verification.ProgressSchema, VerificationID: req.Plan.VerificationID, Status: "pending"}, e.err
}
func (e *testVerifier) Get(id, org string) *verification.Progress {
	if org != e.org {
		return nil
	}
	e.calls++
	return &verification.Progress{VerificationID: id, OrgID: org, Status: "held"}
}
func (e *testVerifier) Cancel(id, org, planSHA string) *verification.Progress { return e.Get(id, org) }

func verificationBody(t *testing.T) []byte {
	t.Helper()
	body, err := json.Marshal(verification.Request{Plan: verification.Plan{Schema: verification.Schema, VerificationID: "operation", OrgID: "org", AgentID: "agent", Provider: "kubevirt", AuthoritySHA256: strings.Repeat("a", 64), Bundle: json.RawMessage(`{}`)}, S3: models.KubeVirtRestoreS3{SecretKey: "secret-must-not-echo"}, Keys: map[string]string{}})
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func verificationServer(e *testVerifier) *Server {
	return NewServer(testControllerConfig(&config.Config{EnableAPIKeyValidation: true, OrchestratorAPIKey: "expected"}), "test", WithVerificationExecutor(e), WithTLSConfig(&tls.Config{MinVersion: tls.VersionTLS12, ClientAuth: tls.RequireAndVerifyClientCert}))
}

func TestVerificationRequiresAuthenticatedHTTPSForAllOperations(t *testing.T) {
	for _, operation := range []string{"submit", "get", "cancel", "capability"} {
		for _, fault := range []string{"valid", "http", "server-http", "no-key", "wrong-key", "auth-disabled", "empty-key"} {
			t.Run(operation+"/"+fault, func(t *testing.T) {
				cfg := testControllerConfig(&config.Config{EnableAPIKeyValidation: true, OrchestratorAPIKey: "expected"})
				if fault == "auth-disabled" {
					cfg.EnableAPIKeyValidation = false
				}
				if fault == "empty-key" {
					cfg.OrchestratorAPIKey = ""
				}
				e := &testVerifier{org: "org"}
				opts := []ServerOption{WithVerificationExecutor(e)}
				if fault != "server-http" {
					opts = append(opts, WithTLSConfig(&tls.Config{MinVersion: tls.VersionTLS12, ClientAuth: tls.RequireAndVerifyClientCert}))
				}
				s := NewServer(cfg, "test", opts...)
				method, path := http.MethodPost, "/api/verifications"
				if operation == "get" {
					method, path = http.MethodGet, "/api/verifications/operation?org_id=org"
				}
				if operation == "capability" {
					method, path = http.MethodGet, "/api/verifications/capability"
				}
				if operation == "cancel" {
					path = "/api/verifications/operation/cancel?org_id=org"
				}
				r := httptest.NewRequest(method, "https://agent"+path, bytes.NewReader(verificationBody(t)))
				certifyTestController(r)
				r.Header.Set("X-Orchestrator-Key", "expected")
				if fault == "http" {
					r.TLS = nil
				}
				if fault == "no-key" {
					r.Header.Del("X-Orchestrator-Key")
				}
				if fault == "wrong-key" {
					r.Header.Set("X-Orchestrator-Key", "wrong")
				}
				w := httptest.NewRecorder()
				s.router.ServeHTTP(w, r)
				if (w.Code < 300) != (fault == "valid") || (e.calls == 1) != (fault == "valid" && operation != "capability") {
					t.Fatal(w.Code, w.Body.String(), e.calls)
				}
			})
		}
	}
}

func TestVerificationStrictWireErrorsNeverEchoSecrets(t *testing.T) {
	valid := string(verificationBody(t))
	for _, body := range []string{valid + `{}`, `null`, strings.TrimSuffix(valid, "}") + `,"secret-must-not-echo":"unknown"}`, strings.Replace(valid, `"keys":{}`, `"keys":{},"keys":{}`, 1), `{"plan":"secret-must-not-echo"}`} {
		t.Run(body[:min(len(body), 20)], func(t *testing.T) {
			e := &testVerifier{}
			s := verificationServer(e)
			r := httptest.NewRequest(http.MethodPost, "https://agent/api/verifications", strings.NewReader(body))
			certifyTestController(r)
			r.Header.Set("X-Orchestrator-Key", "expected")
			w := httptest.NewRecorder()
			s.router.ServeHTTP(w, r)
			if w.Code != http.StatusBadRequest || e.calls != 0 || strings.Contains(w.Body.String(), "secret-must-not-echo") {
				t.Fatal(w.Code, w.Body.String(), e.calls)
			}
		})
	}
}

func TestVerificationErrorMappingAndOrgScopedReadCancel(t *testing.T) {
	for _, test := range []struct {
		err  error
		code int
	}{{verification.ErrPlan, 422}, {verification.ErrConflict, 409}, {verification.ErrBusy, 429}, {verification.ErrJournal, 503}, {errors.New("secret-must-not-echo"), 503}} {
		t.Run(test.err.Error(), func(t *testing.T) {
			e := &testVerifier{err: test.err}
			s := verificationServer(e)
			r := httptest.NewRequest(http.MethodPost, "https://agent/api/verifications", bytes.NewReader(verificationBody(t)))
			certifyTestController(r)
			r.Header.Set("X-Orchestrator-Key", "expected")
			w := httptest.NewRecorder()
			s.router.ServeHTTP(w, r)
			if w.Code != test.code || w.Header().Get("Cache-Control") != "no-store" || strings.Contains(w.Body.String(), "secret-must-not-echo") {
				t.Fatal(w.Code, w.Body.String())
			}
			if test.code == 429 {
				var req verification.Request
				var body map[string]string
				if json.Unmarshal(verificationBody(t), &req) != nil || json.Unmarshal(w.Body.Bytes(), &body) != nil {
					t.Fatal("busy JSON")
				}
				canonical, _ := models.StorageCanonical(req.Plan)
				sum := sha256.Sum256(canonical)
				if len(body) != 7 || body["schema"] != "vnbui-backup-verification-admission/1" || body["verification_id"] != req.Plan.VerificationID || body["org_id"] != req.Plan.OrgID || body["agent_id"] != req.Plan.AgentID || body["plan_sha256"] != hex.EncodeToString(sum[:]) || body["status"] != "not_admitted" || body["reason"] != "agent_busy" {
					t.Fatal(body)
				}
			}
		})
	}
	for _, path := range []string{"/api/verifications/operation", "/api/verifications/operation/cancel"} {
		e := &testVerifier{org: "org"}
		s := verificationServer(e)
		method := http.MethodGet
		if strings.HasSuffix(path, "cancel") {
			method = http.MethodPost
		}
		r := httptest.NewRequest(method, "https://agent"+path+"?org_id=foreign", nil)
		certifyTestController(r)
		r.Header.Set("X-Orchestrator-Key", "expected")
		w := httptest.NewRecorder()
		s.router.ServeHTTP(w, r)
		if w.Code != 404 || e.calls != 0 {
			t.Fatal("foreign organization reached operation", w.Code, e.calls)
		}
	}
}
