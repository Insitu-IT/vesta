// Package restoreinput opens exact immutable restore objects and private key files.
package restoreinput

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"github.com/minio/minio-go/v7/pkg/s3utils"
	"golang.org/x/sys/unix"
	"vnbui/agent/internal/files3"
	"vnbui/agent/internal/models"
	"vnbui/agent/internal/storagerestore"
)

func LocalSource(directory string) (storagerestore.ObjectOpener, func(), error) {
	root, err := os.OpenRoot(directory)
	if err != nil {
		return nil, nil, fmt.Errorf("open object snapshot: %w", err)
	}
	open := func(ctx context.Context, target models.StorageTarget, object models.StorageObjectReceipt) (io.ReadCloser, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if !models.ValidStorageTarget(target) || object.Key == "" || path.IsAbs(object.Key) ||
			path.Clean(object.Key) != object.Key || strings.Contains(object.Key, `\`) || object.Key == "." || strings.HasPrefix(object.Key, "../") {
			return nil, errors.New("invalid snapshot object path")
		}
		// Root.Open prevents symlinks in a snapshot from escaping its directory.
		f, err := root.Open(target.Bucket + "/" + object.Key)
		if err != nil {
			return nil, err
		}
		info, err := f.Stat()
		if err != nil || !info.Mode().IsRegular() || info.Size() != object.CiphertextBytes {
			f.Close()
			return nil, errors.New("snapshot object is not a regular file with the expected stored size")
		}
		return f, nil
	}
	return open, func() { _ = root.Close() }, nil
}

// A trusted local configuration scopes credentials to one literal destination.
// The chain file cannot redirect these credentials to another endpoint/bucket.
type S3Configuration struct {
	Endpoint     string `json:"endpoint"`
	Bucket       string `json:"bucket"`
	Region       string `json:"region"`
	AccessKey    string `json:"access_key"`
	SecretKey    string `json:"secret_key"`
	SessionToken string `json:"session_token,omitempty"`
	CAFile       string `json:"ca_file,omitempty"`
	CAPEM        string `json:"ca_pem,omitempty"`
}

type scopedTransport struct {
	transport http.RoundTripper
	host      string
	bucket    string
	region    string
}

type boundedBody struct {
	io.Reader
	io.Closer
}

func (s scopedTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	bucketPath := "/" + s.bucket
	if request.URL.Scheme != "https" || request.URL.Host != s.host ||
		(request.Host != "" && request.Host != s.host) || (request.Method != http.MethodGet && request.Method != http.MethodHead) ||
		(request.URL.Path != bucketPath && !strings.HasPrefix(request.URL.Path, bucketPath+"/")) ||
		!strings.Contains(request.Header.Get("Authorization"), "/"+s.region+"/s3/aws4_request,") {
		return nil, errors.New("S3 request left the configured restore scope")
	}
	list := request.URL.Query().Has("versions")
	response, err := s.transport.RoundTrip(request)
	if err == nil && (list || response.StatusCode >= 300) {
		// Limit the S3 SDK's XML parser even if the server disregards
		// MaxKeys or returns an unbounded S3 error response.
		response.Body = boundedBody{Reader: io.LimitReader(response.Body, 2<<20), Closer: response.Body}
	}
	return response, err
}

func readS3Configuration(configPath string) (S3Configuration, error) {
	var cfg S3Configuration
	if err := ReadJSONFile(configPath, &cfg, 64<<10, true); err != nil {
		// A JSON syntax/type error can quote input, so do not repeat it for a
		// credentials-bearing file.
		return cfg, errors.New("cannot read private S3 configuration; check its JSON fields and mode 0600")
	}
	if cfg.CAFile != "" && !filepath.IsAbs(cfg.CAFile) {
		cfg.CAFile = filepath.Join(filepath.Dir(configPath), cfg.CAFile)
	}
	return cfg, nil
}

func S3Source(configPath string) (storagerestore.ObjectOpener, func(), error) {
	cfg, err := readS3Configuration(configPath)
	if err != nil {
		return nil, nil, err
	}
	return S3SourceConfig(cfg)
}

func newS3Client(cfg S3Configuration, fileArchive bool) (*minio.Core, scopedTransport, func(), error) {
	target := models.StorageTarget{Endpoint: cfg.Endpoint, Bucket: cfg.Bucket, Region: cfg.Region}
	if !models.ValidStorageTarget(target) || cfg.AccessKey == "" || cfg.SecretKey == "" {
		return nil, scopedTransport{}, nil, errors.New("S3 configuration requires a canonical HTTPS endpoint, bucket, and read credentials")
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	transport.DisableCompression = true
	transport.MaxResponseHeaderBytes = 16 << 10
	transport.ResponseHeaderTimeout = 30 * time.Second
	if cfg.CAFile != "" || cfg.CAPEM != "" {
		caPath := cfg.CAFile
		pem := []byte(cfg.CAPEM)
		if caPath != "" {
			var err error
			pem, err = os.ReadFile(caPath)
			if err != nil {
				return nil, scopedTransport{}, nil, errors.New("cannot read configured S3 CA file")
			}
		}
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM(pem) {
			return nil, scopedTransport{}, nil, errors.New("S3 CA file contains no certificates")
		}
		transport.TLSClientConfig.RootCAs = roots
	}
	endpoint, _ := url.Parse(cfg.Endpoint)
	signingRegion := cfg.Region
	networkOrigin := cfg.Endpoint
	amazon := s3utils.IsAmazonEndpoint(*endpoint)
	if amazon {
		// The SDK resolves ordinary AWS origins from region. Reuse the
		// reviewed routing policy while retaining the configured literal
		// destination independently for the receipt/point comparison.
		var err error
		networkOrigin, signingRegion, err = files3.Normalize(cfg.Endpoint, cfg.Region)
		if err != nil {
			return nil, scopedTransport{}, nil, err
		}
		endpoint, _ = url.Parse(networkOrigin)
	}
	if signingRegion == "" {
		signingRegion = "us-east-1"
	}
	scoped := scopedTransport{transport: transport, host: endpoint.Host, bucket: cfg.Bucket, region: signingRegion}
	if fileArchive || amazon {
		client, err := files3.NewClient(networkOrigin, signingRegion, cfg.Bucket,
			credentials.NewStaticV4(cfg.AccessKey, cfg.SecretKey, cfg.SessionToken), scoped)
		if err != nil {
			return nil, scopedTransport{}, nil, errors.New("cannot construct scoped S3 client")
		}
		return &minio.Core{Client: client}, scoped, transport.CloseIdleConnections, nil
	}
	client, err := minio.NewCore(endpoint.Host, &minio.Options{
		Creds:  credentials.NewStaticV4(cfg.AccessKey, cfg.SecretKey, cfg.SessionToken),
		Secure: true, Region: signingRegion, MaxRetries: 1, BucketLookup: minio.BucketLookupPath,
		Transport: scoped,
	})
	if err != nil {
		return nil, scopedTransport{}, nil, errors.New("cannot construct S3 restore client")
	}
	return client, scoped, transport.CloseIdleConnections, nil
}

// S3SourceConfig accepts an installation-authorized credential target, never object-selected authority.
func S3SourceConfig(cfg S3Configuration) (storagerestore.ObjectOpener, func(), error) {
	return S3RestoreSourceConfig(cfg, nil)
}

// S3RestoreSourceConfig uses the recovery origin from an already validated restore plan.
// Historical blank regions select the effective signer without changing the retained manifest.
func S3RestoreSourceConfig(cfg S3Configuration, origin *models.RestoreOrigin) (storagerestore.ObjectOpener, func(), error) {
	client, _, closeClient, err := newS3Client(cfg, false)
	if err != nil {
		return nil, nil, err
	}
	open := func(ctx context.Context, wanted models.StorageTarget, object models.StorageObjectReceipt) (io.ReadCloser, error) {
		if wanted.Endpoint != cfg.Endpoint || wanted.Bucket != cfg.Bucket || origin.SigningRegion(wanted.Region) != cfg.Region {
			return nil, errors.New("chain S3 destination does not match the trusted configuration")
		}
		etag, err := strconv.Unquote(object.ETag)
		if err != nil || etag == "" || strconv.Quote(etag) != object.ETag {
			return nil, errors.New("receipt has an invalid quoted ETag")
		}
		opts := minio.GetObjectOptions{}
		if err := opts.SetMatchETag(etag); err != nil {
			return nil, errors.New("receipt has an invalid ETag")
		}
		if object.VersionID != nil {
			if *object.VersionID == "" {
				return nil, errors.New("receipt has an empty object version")
			}
			opts.VersionID = *object.VersionID
		}
		body, info, _, err := client.GetObject(ctx, cfg.Bucket, object.Key, opts)
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			return nil, errors.New("S3 GET failed for the receipt's object identity")
		}
		if info.ETag != etag || info.Size != object.CiphertextBytes ||
			(object.VersionID != nil && info.VersionID != *object.VersionID) {
			body.Close()
			return nil, errors.New("S3 returned a different object identity or stored size")
		}
		return body, nil
	}
	return open, closeClient, nil
}

// OpenS3Archive opens one file archive at a locally supplied object key.
// The private local configuration determines the endpoint and allowed bucket.
// File archive integrity is verified separately by the archive reader.
func OpenS3Archive(ctx context.Context, configPath, bucket, key, versionID string) (io.ReadCloser, func(), error) {
	cfg, err := readS3Configuration(configPath)
	if err != nil {
		return nil, nil, err
	}
	if bucket != cfg.Bucket {
		return nil, nil, errors.New("archive S3 bucket does not match the trusted configuration")
	}
	if key == "" || len(key) > 1024 || !utf8.ValidString(key) || key == "." || key == ".." ||
		path.IsAbs(key) || path.Clean(key) != key || strings.HasPrefix(key, "../") || strings.ContainsAny(key, "\\\x00") {
		return nil, nil, errors.New("invalid S3 archive object key")
	}
	cfg.Endpoint, cfg.Region, err = files3.Normalize(cfg.Endpoint, cfg.Region)
	if err != nil {
		return nil, nil, err
	}
	client, _, closeClient, err := newS3Client(cfg, true)
	if err != nil {
		return nil, nil, err
	}
	body, info, _, err := client.GetObject(ctx, cfg.Bucket, key, minio.GetObjectOptions{VersionID: versionID})
	if err != nil {
		closeClient()
		if ctx.Err() != nil {
			return nil, nil, ctx.Err()
		}
		return nil, nil, errors.New("S3 GET failed for the file archive")
	}
	if versionID != "" && info.VersionID != versionID {
		body.Close()
		closeClient()
		return nil, nil, errors.New("S3 returned a different archive object version")
	}
	return body, closeClient, nil
}

func FileKeys(directory string) (storagerestore.KeyResolver, func(), error) {
	if directory == "" {
		return func(context.Context, storagerestore.Member) ([]byte, error) {
			return nil, errors.New("encrypted members require -keys-dir with a private DEK for each backup")
		}, func() {}, nil
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		return nil, nil, fmt.Errorf("open key directory: %w", err)
	}
	resolve := func(ctx context.Context, member storagerestore.Member) ([]byte, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		id := member.Request.BackupID
		if id == "" || filepath.Base(id) != id || strings.ContainsAny(id, `/\`) || id == "." || id == ".." {
			return nil, errors.New("invalid backup identity for key lookup")
		}
		file, err := root.Open(id + ".key")
		if err != nil {
			return nil, errors.New("no readable DEK file for backup " + id)
		}
		defer file.Close()
		info, err := file.Stat()
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || info.Size() > 4096 {
			return nil, errors.New("DEK must be a private regular file (mode 0600)")
		}
		encoded, err := io.ReadAll(io.LimitReader(file, 4097))
		if err != nil || len(encoded) > 4096 {
			return nil, errors.New("cannot read DEK file")
		}
		key, err := base64.StdEncoding.Strict().DecodeString(strings.TrimSpace(string(encoded)))
		if err != nil || len(key) != 32 {
			return nil, errors.New("DEK file must contain base64 of exactly 32 bytes")
		}
		return key, nil
	}
	return resolve, func() { _ = root.Close() }, nil
}

func ReadJSONFile(path string, dst any, limit int64, private bool) error {
	f, err := os.OpenFile(path, os.O_RDONLY|unix.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Size() > limit {
		return errors.New("expected a regular file within the size limit")
	}
	if private && info.Mode().Perm()&0o077 != 0 {
		return errors.New("credentials file must not be readable or writable by group/other (use mode 0600)")
	}
	decoder := json.NewDecoder(io.LimitReader(f, limit+1))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return errors.New("expected one JSON value")
	}
	return nil
}
