package restoreinput

import (
	"context"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"vnbui/agent/internal/models"
)

func TestRecoveryAvailabilityChecksOneExactVersion(t *testing.T) {
	var status atomic.Int32
	status.Store(http.StatusOK)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodHead || r.URL.Path != "/bucket/generation.json" ||
			r.URL.Query().Get("versionId") != "generation-version" ||
			r.Header.Get("If-Match") != `"pinned"` ||
			!strings.Contains(r.Header.Get("Authorization"), "/us-east-1/s3/aws4_request,") {
			t.Error("unexpected recovery availability request")
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if current := int(status.Load()); current != http.StatusOK {
			w.WriteHeader(current)
			return
		}
		w.Header().Set("ETag", `"pinned"`)
		w.Header().Set("X-Amz-Version-Id", "generation-version")
		w.Header().Set("Last-Modified", "Thu, 01 Oct 2026 00:00:00 GMT")
		w.Header().Set("Content-Length", "12")
	}))
	defer server.Close()
	cfg := S3Configuration{Endpoint: server.URL, Bucket: "bucket", Region: "us-east-1", AccessKey: "fixture", SecretKey: "fixture",
		CAPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}))}
	client, _, closeClient, err := newS3Client(cfg, false)
	if err != nil {
		t.Fatal(err)
	}
	defer closeClient()
	bucket := Bucket{target: models.StorageTarget{Bucket: "bucket"}, client: client}
	version := "generation-version"
	pin := models.StorageObjectReceipt{Key: "generation.json", ETag: `"pinned"`, VersionID: &version, CiphertextBytes: 12}
	for _, tc := range []struct {
		status int
		ok     bool
		err    bool
	}{
		{http.StatusOK, true, false},
		{http.StatusNotFound, false, false},
		{http.StatusPreconditionFailed, false, false},
		{http.StatusForbidden, false, true},
	} {
		status.Store(int32(tc.status))
		ok, err := bucket.VersionAvailable(context.Background(), pin)
		if ok != tc.ok || (err != nil) != tc.err {
			t.Fatalf("status %d: availability %t, error %v", tc.status, ok, err)
		}
	}
}
