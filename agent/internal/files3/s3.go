// Package files3 binds managed-file storage to a single approved S3 origin.
package files3

import (
	"errors"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"github.com/minio/minio-go/v7/pkg/s3utils"
)

var (
	regionName   = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
	endpointHost = regexp.MustCompile(`^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$`)
	awsRegion    = regexp.MustCompile(`^[a-z]{2}(-[a-z0-9]+)+-[0-9]+$`)
	ordinaryAWS  = regexp.MustCompile(`^s3[.-](dualstack\.)?([a-z]{2}(?:-[a-z0-9]+)+-[0-9]+)\.amazonaws\.com(\.cn)?$`)
)

// Normalize resolves the global AWS alias before storage authority is recorded.
// The S3 SDK selects an ordinary AWS endpoint from its region; special/private
// endpoints keep their literal authority.
func Normalize(endpoint, region string) (string, string, error) {
	if endpoint == "" {
		endpoint = "https://s3.amazonaws.com"
	}
	endpoint, err := CanonicalOrigin(endpoint)
	if err != nil {
		return "", "", err
	}
	u, _ := url.Parse(endpoint)
	regional := ordinaryAWS.FindStringSubmatch(u.Hostname())
	if region == "" {
		region = s3utils.GetRegionFromURL(*u)
		if len(regional) != 0 {
			region = regional[2]
		}
		if region == "" {
			region = "us-east-1"
		}
	}
	if !regionName.MatchString(region) {
		return "", "", errors.New("invalid file archive S3 region")
	}
	switch {
	case u.Hostname() == "s3.amazonaws.com":
		if u.Port() != "" || !awsRegion.MatchString(region) || strings.HasPrefix(region, "cn-") || strings.HasPrefix(region, "us-iso") {
			return "", "", errors.New("global AWS S3 requires a standard AWS region and HTTPS port")
		}
		endpoint = "https://s3." + region + ".amazonaws.com"
	case len(regional) != 0:
		if u.Port() != "" || regional[2] != region || (regional[3] != "") != strings.HasPrefix(region, "cn-") {
			return "", "", errors.New("AWS S3 endpoint differs from its configured region or HTTPS port")
		}
		endpoint = "https://s3." + regional[1] + region + ".amazonaws.com" + regional[3]
	}
	return endpoint, region, nil
}

func CanonicalOrigin(endpoint string) (string, error) {
	invalid := errors.New("file archive S3 endpoint must be a plain HTTPS origin")
	if strings.ContainsAny(endpoint, "?#") || strings.TrimSpace(endpoint) != endpoint {
		return "", invalid
	}
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Scheme != "https" || parsed.User != nil ||
		parsed.Host == "" || strings.HasSuffix(parsed.Host, ":") ||
		(parsed.Path != "" && parsed.Path != "/") || parsed.RawPath != "" {
		return "", invalid
	}
	host := strings.TrimSuffix(strings.ToLower(parsed.Hostname()), ".")
	if ip := net.ParseIP(host); ip != nil {
		host = ip.String()
	} else if !endpointHost.MatchString(host) {
		return "", invalid
	}
	if port := parsed.Port(); port != "" {
		number, err := strconv.ParseUint(port, 10, 16)
		if err != nil || number == 0 {
			return "", invalid
		}
		if number != 443 {
			return "https://" + net.JoinHostPort(host, strconv.FormatUint(number, 10)), nil
		}
	}
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	return "https://" + host, nil
}

// NewClient scopes every signed path-style request to the approved authority
// and bucket. The SDK disables redirects; this guard also refuses any request
// whose destination changes during SDK endpoint resolution or retries.
func NewClient(endpoint, region, bucket string, creds *credentials.Credentials, transport http.RoundTripper) (*minio.Client, error) {
	u, err := url.Parse(endpoint)
	if err != nil {
		return nil, err
	}
	client, err := minio.New(u.Host, &minio.Options{
		Creds: creds, Secure: true, Region: region, BucketLookup: minio.BucketLookupPath,
		MaxRetries: 1, Transport: scopedTransport{transport: transport, authority: u.Host, bucketPath: "/" + bucket, region: region},
	})
	if err != nil {
		return nil, err
	}
	client.SetS3EnableDualstack(strings.HasPrefix(u.Hostname(), "s3.dualstack.") && ordinaryAWS.MatchString(u.Hostname()))
	return client, nil
}

type scopedTransport struct {
	transport  http.RoundTripper
	authority  string
	bucketPath string
	region     string
}

func (s scopedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Scheme != "https" || req.URL.Host != s.authority || req.Host != "" && req.Host != s.authority ||
		(req.URL.Path != s.bucketPath && !strings.HasPrefix(req.URL.Path, s.bucketPath+"/")) ||
		!strings.Contains(req.Header.Get("Authorization"), "/"+s.region+"/s3/aws4_request,") {
		return nil, errors.New("S3 request left the configured file archive destination")
	}
	return s.transport.RoundTrip(req)
}
