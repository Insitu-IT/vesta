package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"vnbui/agent/internal/filearchive"
)

func TestFileCommandsAndReleaseReports(t *testing.T) {
	dir := t.TempDir()
	identity := filepath.Join(dir, "recovery-key")
	invoke := func(args ...string) (string, error) {
		t.Helper()
		stdout, stderr := &bytes.Buffer{}, &bytes.Buffer{}
		err := run(context.Background(), args, stdout, stderr)
		return stdout.String(), err
	}
	for _, tt := range []struct{ flag, want string }{
		{"--version", "vesta-restore " + version},
		{"--file-archive-format", filearchive.Format},
	} {
		got, err := invoke(tt.flag)
		if err != nil || strings.TrimSpace(got) != tt.want {
			t.Fatalf("%s = %q, %v", tt.flag, got, err)
		}
	}
	public, err := invoke("files", "keygen", "--identity", identity)
	if err != nil {
		t.Fatal(err)
	}
	recipient := strings.TrimSpace(public)
	if err := filearchive.ValidateRecipient(recipient); err != nil {
		t.Fatal(err)
	}
	keyBytes, err := os.ReadFile(identity)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(identity)
	if err != nil || info.Mode().Perm() != 0600 || bytes.Contains([]byte(public), bytes.TrimSpace(keyBytes)) {
		t.Fatalf("identity file permissions or public output are invalid: %v", err)
	}
	if _, err := invoke("files", "keygen", "--identity", identity); err == nil {
		t.Fatal("existing identity was replaced")
	}
	got, err := invoke("files", "recipient", "--identity", identity)
	if err != nil || got != public {
		t.Fatalf("recipient = %q, %v", got, err)
	}
	archive := filepath.Join(dir, "backup.age")
	ciphertext := makeFileArchive(t, recipient)
	if err := os.WriteFile(archive, ciphertext, 0600); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(ciphertext)
	verifyArgs := []string{"--archive", archive, "--identity", identity, "--sha256", hex.EncodeToString(digest[:])}
	for _, mode := range []string{"verify", "list"} {
		got, err := invoke(append([]string{"files", mode}, verifyArgs...)...)
		if err != nil || !strings.Contains(got, filearchive.Format) || !json.Valid([]byte(got)) {
			t.Fatalf("offline %s: %q, %v", mode, got, err)
		}
	}
	output := filepath.Join(dir, "recovered")
	extract := append([]string{"files", "extract"}, verifyArgs...)
	if _, err := invoke(append(extract, "--output", output, "--select", "example.txt")...); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(output, "example.txt"))
	if err != nil || string(data) != "file archive fixture" {
		t.Fatalf("recovered file = %q, %v", data, err)
	}
}

func TestFileCommandsUseTrustedS3Configuration(t *testing.T) {
	dir := t.TempDir()
	identity := filepath.Join(dir, "identity")
	recipient, err := filearchive.CreateIdentity(identity)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext := makeFileArchive(t, recipient)
	var requests atomic.Int32
	s3 := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Method != http.MethodGet || r.URL.Path != "/archive-bucket/backups/a.age" || r.URL.Query().Get("versionId") != "test-version" ||
			!strings.Contains(r.Header.Get("Authorization"), "Credential=example-access/") {
			t.Errorf("unexpected S3 request %s %s", r.Method, r.URL)
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.Header().Set("Last-Modified", time.Now().UTC().Format(http.TimeFormat))
		w.Header().Set("ETag", "\"fixture\"")
		w.Header().Set("Content-Length", fmt.Sprint(len(ciphertext)))
		w.Header().Set("x-amz-version-id", "test-version")
		if _, err := w.Write(ciphertext); err != nil {
			t.Error(err)
		}
	}))
	defer s3.Close()
	cfg, err := json.Marshal(s3Configuration{
		Endpoint: s3.URL, Bucket: "archive-bucket", Region: "us-east-1",
		AccessKey: "example-access", SecretKey: "test-only-secret",
		CAPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s3.Certificate().Raw})),
	})
	if err != nil {
		t.Fatal(err)
	}
	config := filepath.Join(dir, "s3-config.json")
	if err := os.WriteFile(config, cfg, 0600); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(ciphertext)
	args := []string{"files", "verify", "--identity", identity, "--s3-config", config, "--s3-version-id", "test-version", "--sha256", hex.EncodeToString(digest[:])}
	var stdout, stderr bytes.Buffer
	ctx := context.Background()
	if err := run(ctx, append(args, "--archive", "s3://different-bucket/backups/a.age"), &stdout, &stderr); err == nil || requests.Load() != 0 {
		t.Fatalf("request escaped configured bucket: %v, requests=%d", err, requests.Load())
	}
	if err := run(ctx, append(args, "--archive", "s3://archive-bucket/backups/a.age"), &stdout, &stderr); err != nil {
		t.Fatalf("verify S3 archive: %v", err)
	}
	if requests.Load() != 1 || !strings.Contains(stdout.String(), filearchive.Format) {
		t.Fatalf("S3 verification output = %q, requests=%d", stdout.String(), requests.Load())
	}
}

func makeFileArchive(t *testing.T, recipient string) []byte {
	t.Helper()
	source := t.TempDir()
	if err := os.WriteFile(filepath.Join(source, "example.txt"), []byte("file archive fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	var ciphertext bytes.Buffer
	if _, err := filearchive.Write(context.Background(), &ciphertext, source, recipient); err != nil {
		t.Fatal(err)
	}
	return ciphertext.Bytes()
}
