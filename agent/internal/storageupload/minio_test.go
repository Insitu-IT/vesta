package storageupload

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"vnbui/agent/internal/models"
)

// This is the real pinned SDK over a private trusted TLS fixture, not a live
// target capability probe. Only multipart control responses and HEAD are read.
func TestMinioExactWire(t *testing.T) {
	for _, versioned := range []bool{false, true} {
		t.Run(fmt.Sprint(versioned), func(t *testing.T) {
			var calls []string
			var target, bucket, key string
			var meta map[string]string
			data := []byte("bounded artifact")
			raw, _ := hex.DecodeString(digest(data))
			checksum := base64.StdEncoding.EncodeToString(raw)
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls = append(calls, r.Method)
				if r.URL.Path != "/"+bucket+"/"+key || !strings.HasPrefix(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256 ") {
					t.Error("wrong exact destination or missing authenticated signature")
				}
				q := r.URL.Query()
				switch {
				case r.Method == "POST" && q.Has("uploads"):
					if r.Header.Get("X-Amz-Checksum-Algorithm") != "SHA256" {
						t.Error("missing checksum algorithm")
					}
					for k, v := range meta {
						if r.Header.Get("X-Amz-Meta-"+k) != v {
							t.Error("missing exact reservation metadata")
						}
					}
					fmt.Fprint(w, `<InitiateMultipartUploadResult><UploadId>exact-upload</UploadId></InitiateMultipartUploadResult>`)
				case r.Method == "PUT" && q.Get("uploadId") == "exact-upload":
					body, _ := io.ReadAll(io.LimitReader(r.Body, 1024))
					if string(body) != string(data) || q.Get("partNumber") != "1" || r.Header.Get("X-Amz-Checksum-Sha256") != checksum {
						t.Error("part body/number/checksum differs")
					}
					w.Header().Set("ETag", `"part-opaque"`)
					w.Header().Set("X-Amz-Checksum-Sha256", checksum)
				case r.Method == "POST" && q.Get("uploadId") == "exact-upload":
					body, _ := io.ReadAll(io.LimitReader(r.Body, 4096))
					if r.Header.Get("If-None-Match") != "*" || !strings.Contains(string(body), "<ChecksumSHA256>"+checksum+"</ChecksumSHA256>") {
						t.Error("completion condition/checksum missing")
					}
					if versioned {
						w.Header().Set("X-Amz-Version-Id", "version-opaque")
					}
					fmt.Fprintf(w, `<CompleteMultipartUploadResult><Bucket>%s</Bucket><Key>%s</Key><ETag>"object-opaque"</ETag></CompleteMultipartUploadResult>`, bucket, key)
				case r.Method == "HEAD":
					if r.Header.Get("If-Match") != `"object-opaque"` || r.Header.Get("X-Amz-Checksum-Mode") != "ENABLED" || (versioned && q.Get("versionId") != "version-opaque") || (!versioned && q.Has("versionId")) {
						t.Error("HEAD exact identity/checksum mode missing")
					}
					w.Header().Set("ETag", `"object-opaque"`)
					w.Header().Set("Content-Length", fmt.Sprint(len(data)))
					w.Header().Set("Last-Modified", "Mon, 14 Sep 2026 00:00:00 GMT")
					w.Header().Set("X-Amz-Checksum-Sha256", checksum)
					w.Header().Set("X-Amz-Checksum-Type", "FULL_OBJECT")
					if versioned {
						w.Header().Set("X-Amz-Version-Id", "version-opaque")
					}
					for k, v := range meta {
						w.Header().Set("X-Amz-Meta-"+k, v)
					}
				default:
					t.Error("unexpected provider operation")
					w.WriteHeader(400)
				}
			}))
			defer server.Close()
			r, _ := models.DecodeStorageTransaction(request(t, false))
			target = server.URL
			r.Plan.Target.Endpoint = target
			r.Plan.CapabilityProfile = "checksum-enforced/1"
			p, _ := models.StorageCanonical(r.Plan)
			r.PlanSHA256 = digest(p)
			body, _ := json.Marshal(r)
			bucket, key = r.Plan.Target.Bucket, r.Plan.Artifacts[0].Key
			meta = metadata(r, r.Plan.Artifacts[0])
			roots := x509.NewCertPool()
			roots.AddCert(server.Certificate())
			transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}}
			defer transport.CloseIdleConnections()
			s, e := NewS3(body, "fixture-access", "fixture-secret", "", transport)
			if e != nil {
				t.Fatal(e)
			}
			ctx := context.Background()
			id, e := s.Begin(ctx, key, meta)
			if e != nil || id != "exact-upload" {
				t.Fatal("begin", e)
			}
			etag, e := s.Part(ctx, key, id, 1, data, checksum)
			if e != nil || etag != "part-opaque" {
				t.Fatal("part", e)
			}
			info, e := s.Complete(ctx, key, id, []Part{{Number: 1, Bytes: int64(len(data)), SHA256: digest(data), ETag: etag}})
			if e != nil || info.ETag != `"object-opaque"` {
				t.Fatal("complete", e)
			}
			head, e := s.Head(ctx, key, info.VersionID, info.ETag)
			if e != nil || head.Bytes != int64(len(data)) || head.SHA256 != digest(data) || !equalMetadata(head.Metadata, meta) || !reflect.DeepEqual(head.VersionID, info.VersionID) {
				t.Fatal("HEAD contract mismatch", e)
			}
			if !reflect.DeepEqual(calls, []string{"POST", "PUT", "POST", "HEAD"}) {
				t.Fatal("unexpected call sequence", calls)
			}
		})
	}
}
