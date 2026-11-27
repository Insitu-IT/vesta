package files3

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

type captureTransport func(*http.Request) (*http.Response, error)

func (f captureTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func TestSDKUsesApprovedArchiveScope(t *testing.T) {
	const bucket = "archive-vault"
	const key = "site/managed-files/documents/job/ archive.age"
	for _, test := range []struct {
		name, configured, region, authority, signingRegion string
	}{
		{"default global", "", "", "s3.us-east-1.amazonaws.com", "us-east-1"},
		{"global with known region", "https://s3.amazonaws.com", "eu-west-2", "s3.eu-west-2.amazonaws.com", "eu-west-2"},
		{"regional", "https://s3.us-west-2.amazonaws.com", "us-west-2", "s3.us-west-2.amazonaws.com", "us-west-2"},
		{"legacy regional", "https://s3-us-west-2.amazonaws.com", "", "s3.us-west-2.amazonaws.com", "us-west-2"},
		{"explicit dualstack", "https://s3.dualstack.eu-west-2.amazonaws.com", "eu-west-2", "s3.dualstack.eu-west-2.amazonaws.com", "eu-west-2"},
		{"FIPS", "https://s3-fips.us-west-2.amazonaws.com", "us-west-2", "s3-fips.us-west-2.amazonaws.com", "us-west-2"},
		{"PrivateLink", "https://bucket.vpce-0123456789abcdef0-abcdefg.s3.us-west-2.vpce.amazonaws.com", "us-west-2", "bucket.vpce-0123456789abcdef0-abcdefg.s3.us-west-2.vpce.amazonaws.com", "us-west-2"},
		{"custom TLS port", "https://Archive.Example:19443/", "site-west", "archive.example:19443", "site-west"},
	} {
		t.Run(test.name, func(t *testing.T) {
			endpoint, region, err := Normalize(test.configured, test.region)
			if err != nil || endpoint != "https://"+test.authority || region != test.signingRegion {
				t.Fatalf("normalized = %s %s (%v)", endpoint, region, err)
			}
			seen := make([]string, 0, 2)
			client, err := NewClient(endpoint, region, bucket, credentials.NewStaticV4("test-access", "test-secret", ""),
				captureTransport(func(request *http.Request) (*http.Response, error) {
					seen = append(seen, request.Method)
					if request.URL.Scheme != "https" || request.URL.Host != test.authority || request.URL.Path != "/"+bucket+"/"+key ||
						!strings.Contains(request.Header.Get("Authorization"), "/"+test.signingRegion+"/s3/aws4_request") {
						t.Errorf("unexpected signed request target: %s %s", request.Method, request.URL)
					}
					if request.Method == http.MethodGet && request.URL.Query().Get("versionId") != "v1" {
						t.Error("version identity did not reach the GET")
					}
					if request.Body != nil {
						io.Copy(io.Discard, request.Body)
						request.Body.Close()
					}
					return &http.Response{
						StatusCode: http.StatusOK,
						Header: http.Header{
							"Etag": {"\"test-etag\""}, "X-Amz-Version-Id": {"v1"},
							"Last-Modified": {"Mon, 02 Jan 2006 15:04:05 GMT"}, "Content-Length": {"0"},
						},
						Body: http.NoBody, Request: request,
					}, nil
				}))
			if err != nil {
				t.Fatal(err)
			}
			core := &minio.Core{Client: client}
			body, _, _, err := core.GetObject(context.Background(), bucket, key, minio.GetObjectOptions{VersionID: "v1"})
			if err != nil {
				t.Fatal(err)
			}
			body.Close()
			if _, err := client.PutObject(context.Background(), bucket, key, strings.NewReader("archive"), 7, minio.PutObjectOptions{DisableMultipart: true}); err != nil {
				t.Fatal(err)
			}
			if got := strings.Join(seen, ","); got != "GET,PUT" {
				t.Fatalf("requests = %s", got)
			}
		})
	}
}

func TestArchiveScopeRefusesOtherBucketAndRedirect(t *testing.T) {
	endpoint, region, err := Normalize("", "")
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	client, err := NewClient(endpoint, region, "archive-vault", credentials.NewStaticV4("test-access", "test-secret", ""),
		captureTransport(func(request *http.Request) (*http.Response, error) {
			calls++
			return &http.Response{
				StatusCode: http.StatusTemporaryRedirect,
				Header:     http.Header{"Location": {"https://different.example/archive-vault/key"}},
				Body:       http.NoBody, Request: request,
			}, nil
		}))
	if err != nil {
		t.Fatal(err)
	}
	core := &minio.Core{Client: client}
	if body, _, _, err := core.GetObject(t.Context(), "archive-vault-other", "key", minio.GetObjectOptions{}); err == nil || body != nil || calls != 0 {
		t.Fatalf("request escaped its approved bucket: calls=%d error=%v", calls, err)
	}
	if body, _, _, err := core.GetObject(t.Context(), "archive-vault", "key", minio.GetObjectOptions{}); err == nil || body != nil || calls != 1 {
		t.Fatalf("redirect escaped its approved endpoint: calls=%d error=%v", calls, err)
	}
	for _, target := range []struct{ endpoint, region string }{
		{"https://s3.us-west-2.amazonaws.com", "us-east-1"},
		{"https://s3.us-west-2.amazonaws.com:19443", "us-west-2"},
		{"https://s3.amazonaws.com", "cn-north-1"},
	} {
		if _, _, err := Normalize(target.endpoint, target.region); err == nil {
			t.Errorf("accepted a conflicting AWS authority: %s %s", target.endpoint, target.region)
		}
	}
}
