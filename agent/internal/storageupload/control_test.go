package storageupload

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

func fakeAuthority(s *fakeStore, key, id string, n, size int, hash, checksum string) *signedPart {
	now := time.Now().UTC().Truncate(time.Second)
	q := url.Values{"uploadId": {id}, "partNumber": {strconv.Itoa(n)}, "X-Amz-Algorithm": {"AWS4-HMAC-SHA256"}, "X-Amz-Credential": {"EXAMPLE/" + now.Format("20060102") + "/" + s.r.Plan.Target.Region + "/s3/aws4_request"}, "X-Amz-Date": {now.Format("20060102T150405Z")}, "X-Amz-Expires": {"60"}, "X-Amz-SignedHeaders": {"content-length;host;x-amz-checksum-sha256;x-amz-content-sha256"}, "X-Amz-Signature": {strings.Repeat("a", 64)}}
	return &signedPart{Method: "PUT", URL: s.r.Plan.Target.Endpoint + "/" + s.r.Plan.Target.Bucket + "/" + key + "?" + q.Encode(), Headers: map[string]string{"content-length": strconv.Itoa(size), "x-amz-checksum-sha256": checksum, "x-amz-content-sha256": hash}, Expires: now.Unix() + 60}
}

func controlledFixture(t *testing.T, b []byte, s *fakeStore, fail string, mutate func(*signedPart)) *ControlledS3 {
	t.Helper()
	var selectedKey, selectedUpload string
	backend := &http.Client{Transport: roundTrip(func(r *http.Request) (*http.Response, error) {
		if r.Header.Get("X-Agent-Key") != "registered-fixture" {
			t.Fatal("agent authentication absent")
		}
		data, _ := io.ReadAll(r.Body)
		var body struct {
			Schema    int             `json:"schema"`
			Binding   map[string]any  `json:"binding"`
			Key       string          `json:"artifact_key"`
			Operation string          `json:"operation"`
			Args      json.RawMessage `json:"args"`
		}
		if json.Unmarshal(data, &body) != nil || body.Schema != 1 || body.Binding["plan_sha256"] != s.r.PlanSHA256 {
			t.Fatal("wrong binding")
		}
		if strings.Contains(string(data), "X-Amz-Signature") {
			t.Fatal("signed authority in control request")
		}
		if body.Operation == fail {
			return nil, errors.New("PRIVATE_CONTROL_BODY")
		}
		result := controlResponse{Schema: 1}
		switch body.Operation {
		case "create":
			var a = s.r.Plan.Artifacts[0]
			for _, v := range s.r.Plan.Artifacts {
				if v.Key == body.Key {
					a = v
				}
			}
			id, e := s.Begin(r.Context(), body.Key, metadata(&s.r, a))
			if e != nil {
				return nil, e
			}
			result.UploadID = id
		case "part":
			var p struct {
				UploadID string `json:"upload_id"`
				Number   int    `json:"number"`
				Bytes    int    `json:"bytes"`
				SHA256   string `json:"sha256"`
			}
			_ = json.Unmarshal(body.Args, &p)
			raw, _ := hex.DecodeString(p.SHA256)
			selectedKey, selectedUpload = body.Key, p.UploadID
			result.Authority = fakeAuthority(s, body.Key, p.UploadID, p.Number, p.Bytes, p.SHA256, base64.StdEncoding.EncodeToString(raw))
			if mutate != nil {
				mutate(result.Authority)
			}
		case "part_ack":
			result.Acknowledged = true
		case "complete":
			var p struct {
				UploadID string `json:"upload_id"`
				Parts    []Part `json:"parts"`
			}
			_ = json.Unmarshal(body.Args, &p)
			info, e := s.Complete(r.Context(), body.Key, p.UploadID, p.Parts)
			if e != nil {
				return nil, e
			}
			info.ETag = strconv.Quote(info.ETag)
			result.Object = &info
		case "head":
			var p struct {
				Version *string `json:"version_id"`
				ETag    string  `json:"etag"`
			}
			_ = json.Unmarshal(body.Args, &p)
			info, e := s.Head(r.Context(), body.Key, p.Version, p.ETag)
			if e != nil {
				return nil, e
			}
			result.Object = &info
		default:
			t.Fatal("unplanned control")
		}
		response, _ := json.Marshal(result)
		return &http.Response{StatusCode: 200, Header: http.Header{"Cache-Control": {"no-store"}}, Body: io.NopCloser(bytes.NewReader(response))}, nil
	})}
	provider := &http.Client{Transport: roundTrip(func(r *http.Request) (*http.Response, error) {
		if fail == "provider" {
			return nil, errors.New("PRIVATE_SIGNED_URL")
		}
		if r.Method != "PUT" || r.URL.Query().Get("uploadId") != selectedUpload || r.Header.Get("X-Agent-Key") != "" {
			t.Fatal("provider authority mismatch")
		}
		data, _ := io.ReadAll(r.Body)
		n, _ := strconv.Atoi(r.URL.Query().Get("partNumber"))
		etag, e := s.Part(r.Context(), selectedKey, selectedUpload, n, data, r.Header.Get("X-Amz-Checksum-Sha256"))
		if e != nil {
			return nil, e
		}
		return &http.Response{StatusCode: 200, Header: http.Header{"Etag": {strconv.Quote(etag)}}, Body: io.NopCloser(strings.NewReader(""))}, nil
	})}
	result, e := NewControlledS3(b, "https://backend.example", backend, provider, func(context.Context) (string, error) { return "registered-fixture", nil })
	if e != nil {
		t.Fatal(e)
	}
	return result
}

func TestControlledProfileCannotUseStaticCredentialAdapter(t *testing.T) {
	if _, err := NewS3(request(t, false), "example-access", "example-secret", "", nil); err == nil {
		t.Fatal("selected profile accepted unrestricted credentials")
	}
}

func TestControlledResponseShapeRefuses(t *testing.T) {
	for _, body := range []string{`{"schema":1,"schema":1,"upload_id":"a"}`, `{"schema":1}`, `{"schema":true,"upload_id":"a"}`, `{"schema":1,"upload_id":"a","extra":1}`, strings.Repeat("x", (1<<20)+1)} {
		t.Run(fmt.Sprint(len(body)), func(t *testing.T) {
			b := request(t, false)
			s := store(t, b)
			p := controlledFixture(t, b, s, "", nil)
			defer p.Close()
			p.client.Transport = roundTrip(func(*http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: 200, Header: http.Header{"Cache-Control": {"no-store"}}, Body: io.NopCloser(strings.NewReader(body))}, nil
			})
			a := s.r.Plan.Artifacts[0]
			if _, err := p.Begin(context.Background(), a.Key, metadata(&s.r, a)); err == nil {
				t.Fatal("invalid control response admitted")
			}
		})
	}
}

func TestControlledStreamingTwoArtifactsReopenNoAuthorityCustody(t *testing.T) {
	for _, encrypted := range []bool{false, true} {
		for _, versioned := range []bool{false, true} {
			for _, size := range []int{0, 1, 9 * 1024 * 1024} {
				t.Run(fmt.Sprintf("encrypted=%v/version=%v/size=%d", encrypted, versioned, size), func(t *testing.T) {
					b := request(t, encrypted)
					s := store(t, b)
					s.version = versioned
					p := controlledFixture(t, b, s, "", nil)
					defer p.Close()
					root := t.TempDir()
					j, e := Create(root, b)
					if e != nil {
						t.Fatal(e)
					}
					opens := 0
					in := inputs(s.r, size, &opens)
					if e = j.UploadAll(context.Background(), p, in, make([]byte, 32)); e != nil {
						t.Fatal(e)
					}
					if j.state.Phase != "prepared" || opens != 2 {
						t.Fatal("partial success")
					}
					disk, e := os.ReadFile(j.path)
					if e != nil {
						t.Fatal(e)
					}
					for _, forbidden := range []string{"registered-fixture", "X-Amz-", "aws4_request"} {
						if bytes.Contains(disk, []byte(forbidden)) {
							t.Fatal("authority persisted")
						}
					}
					calls := len(s.calls)
					_ = j.Close()
					j, e = Open(root, b)
					if e != nil {
						t.Fatal(e)
					}
					defer j.Close()
					p2 := controlledFixture(t, b, s, "", nil)
					defer p2.Close()
					if e = j.UploadAll(context.Background(), p2, in, make([]byte, 32)); e != nil || len(s.calls) != calls || opens != 2 {
						t.Fatal("restart caused new upload/read")
					}
				})
			}
		}
	}
}

func TestControlledLostRepliesStayHeldOnReopen(t *testing.T) {
	for _, phase := range []string{"create", "part", "part_ack", "complete", "head", "provider"} {
		t.Run(phase, func(t *testing.T) {
			b := request(t, false)
			s := store(t, b)
			p := controlledFixture(t, b, s, phase, nil)
			root := t.TempDir()
			j, e := Create(root, b)
			if e != nil {
				t.Fatal(e)
			}
			opens := 0
			in := inputs(s.r, 8, &opens)
			if e = j.UploadAll(context.Background(), p, in, nil); e == nil || strings.Contains(e.Error(), "PRIVATE") {
				t.Fatal("uncertainty leaked/succeeded")
			}
			count := len(s.calls)
			_ = j.Close()
			j, e = Open(root, b)
			if e != nil {
				t.Fatal(e)
			}
			defer j.Close()
			if e = j.UploadAll(context.Background(), p, in, nil); e == nil || len(s.calls) != count {
				t.Fatal("blind resend")
			}
		})
	}
}

func TestControlledPartAuthorityTamperingRefusesBeforeProvider(t *testing.T) {
	for _, mode := range []string{"http", "host", "path", "method", "expired", "long-ttl", "header", "checksum", "part", "upload", "duplicate", "extra-query", "signature"} {
		t.Run(mode, func(t *testing.T) {
			b := request(t, false)
			s := store(t, b)
			p := controlledFixture(t, b, s, "", func(a *signedPart) {
				u, _ := url.Parse(a.URL)
				q := u.Query()
				switch mode {
				case "http":
					u.Scheme = "http"
				case "host":
					u.Host = "foreign.example"
				case "path":
					u.Path += "/other"
				case "method":
					a.Method = "DELETE"
				case "expired":
					a.Expires = time.Now().Unix() - 1
				case "long-ttl":
					a.Expires = time.Now().Unix() + 120
				case "header":
					a.Headers["x-amz-acl"] = "public-read"
				case "checksum":
					a.Headers["x-amz-checksum-sha256"] = "foreign"
				case "part":
					q.Set("partNumber", "2")
				case "upload":
					q.Set("uploadId", "foreign")
				case "duplicate":
					q.Add("uploadId", "foreign")
				case "extra-query":
					q.Set("acl", "")
				case "signature":
					q.Set("X-Amz-Signature", "bad")
				}
				u.RawQuery = q.Encode()
				a.URL = u.String()
			})
			j, e := Create(t.TempDir(), b)
			if e != nil {
				t.Fatal(e)
			}
			defer j.Close()
			n := 0
			if e = j.UploadAll(context.Background(), p, inputs(s.r, 8, &n), nil); e == nil {
				t.Fatal("tampering admitted")
			}
			if len(s.calls) != 1 {
				t.Fatal("tampering reached provider")
			}
		})
	}
}
