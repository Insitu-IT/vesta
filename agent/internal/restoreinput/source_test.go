package restoreinput

import (
	"context"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"vnbui/agent/internal/models"
)

func TestHistoricalRestoreKeepsExactObjectAndRepositoryScope(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Method != http.MethodGet || r.URL.Path != "/bucket/object" || r.URL.Query().Get("versionId") != "receipt-version" ||
			r.Header.Get("If-Match") != `"receipt-etag"` ||
			!strings.Contains(r.Header.Get("Authorization"), "/us-east-1/s3/aws4_request,") {
			http.Error(w, "scope", http.StatusPreconditionFailed)
			return
		}
		w.Header().Set("ETag", `"receipt-etag"`)
		w.Header().Set("X-Amz-Version-Id", "receipt-version")
		w.Header().Set("Last-Modified", "Thu, 01 Oct 2026 00:00:00 GMT")
		_, _ = w.Write([]byte("fixture"))
	}))
	defer server.Close()
	cfg := S3Configuration{Endpoint: server.URL, Bucket: "bucket", Region: "us-east-1", AccessKey: "example-read", SecretKey: "example-secret",
		CAPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}))}
	target := models.StorageTarget{Endpoint: server.URL, Bucket: "bucket", Region: ""}
	version := "receipt-version"
	object := models.StorageObjectReceipt{Key: "object", ETag: `"receipt-etag"`, VersionID: &version, CiphertextBytes: 7}
	strict, closeStrict, err := S3SourceConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer closeStrict()
	if _, err := strict(context.Background(), target, object); err == nil {
		t.Fatal("explicit catalog credential accepted an unbound blank region")
	}
	open, closeRecovery, err := S3RestoreSourceConfig(cfg, &models.RestoreOrigin{OrgID: "source-org", AgentID: "source-agent"})
	if err != nil {
		t.Fatal(err)
	}
	defer closeRecovery()
	for _, foreign := range []models.StorageTarget{
		{Endpoint: "https://other.example", Bucket: "bucket"},
		{Endpoint: server.URL, Bucket: "foreign-bucket"},
		{Endpoint: server.URL, Bucket: "bucket", Region: "eu-central-1"},
	} {
		if _, err := open(context.Background(), foreign, object); err == nil {
			t.Fatal("foreign recovery target was accepted")
		}
	}
	if requests.Load() != 0 {
		t.Fatal("scope mismatch reached S3")
	}
	body, err := open(context.Background(), target, object)
	if err != nil {
		t.Fatal(err)
	}
	defer body.Close()
	got, err := io.ReadAll(body)
	if err != nil || string(got) != "fixture" || requests.Load() != 1 {
		t.Fatal("wrong historical object read", err)
	}
}
