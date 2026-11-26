package storageupload

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"vnbui/agent/internal/models"
)

type S3 struct {
	core      *minio.Core
	request   models.StorageTransactionRequest
	keys      map[string]models.StorageArtifact
	transport *http.Transport
}

// Bound SDK XML/error parsing as well as headers. Exhausting the budget is an
// error, never a truncated-success EOF. Close cannot drain an unbounded body.
type controlBody struct {
	io.ReadCloser
	remaining int64
}

func (b *controlBody) Read(p []byte) (int, error) {
	if b.remaining == 0 {
		return 0, ErrHeld
	}
	if int64(len(p)) > b.remaining {
		p = p[:b.remaining]
	}
	n, e := b.ReadCloser.Read(p)
	b.remaining -= int64(n)
	return n, e
}

type controlTransport struct{ transport *http.Transport }

func (t controlTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	response, err := t.transport.RoundTrip(r)
	if err != nil {
		return nil, err
	}
	response.Body = &controlBody{ReadCloser: response.Body, remaining: 1 << 20}
	return response, nil
}

// NewS3 binds in-memory credentials to the committed target. One SDK attempt,
// path addressing and a fixed region prevent hidden producer retries or bucket
// location discovery. MinIO's client refuses redirects. Transport must retain
// default TLS verification (an existing mTLS/CA transport may be supplied).
func NewS3(request []byte, access, secret, token string, transport *http.Transport) (*S3, error) {
	r, e := models.DecodeStorageTransaction(request)
	if e != nil {
		return nil, e
	}
	// The selected Hetzner profile has no native scoped credential issuer.
	// It must use ControlledS3; static credentials cannot be its fallback.
	if r.Plan.CapabilityProfile == "db-rooted-consumer-verified/1" {
		return nil, ErrHeld
	}
	if access == "" || secret == "" || r.Plan.Target.Region == "" {
		return nil, ErrHeld
	}
	if transport == nil {
		transport = http.DefaultTransport.(*http.Transport).Clone()
	} else {
		transport = transport.Clone()
	}
	if transport.TLSClientConfig != nil && transport.TLSClientConfig.InsecureSkipVerify {
		return nil, ErrHeld
	}
	transport.MaxResponseHeaderBytes = 16 * 1024
	transport.ResponseHeaderTimeout = 30 * time.Second
	u, _ := url.Parse(r.Plan.Target.Endpoint)
	c, e := minio.NewCore(u.Host, &minio.Options{Creds: credentials.NewStaticV4(access, secret, token), Secure: true,
		Region: r.Plan.Target.Region, Transport: controlTransport{transport}, MaxRetries: 1, BucketLookup: minio.BucketLookupPath})
	if e != nil {
		return nil, ErrHeld
	}
	s := &S3{core: c, request: *r, keys: map[string]models.StorageArtifact{}, transport: transport}
	for _, a := range r.Plan.Artifacts {
		s.keys[a.Key] = a
	}
	return s, nil
}
func (s *S3) Target() models.StorageTarget { return s.request.Plan.Target }
func (s *S3) Close()                       { s.transport.CloseIdleConnections() }
func (s *S3) Begin(ctx context.Context, key string, meta map[string]string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	a, ok := s.keys[key]
	if !ok || !equalMetadata(meta, metadata(&s.request, a)) {
		return "", ErrHeld
	}
	m := map[string]string{}
	for k, v := range meta {
		m[k] = v
	}
	m["X-Amz-Checksum-Algorithm"] = "SHA256"
	id, e := s.core.NewMultipartUpload(ctx, s.request.Plan.Target.Bucket, key, minio.PutObjectOptions{UserMetadata: m, ContentType: "application/octet-stream"})
	if e != nil {
		return "", ErrHeld
	}
	return id, nil
}
func equalMetadata(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}
func (s *S3) Part(ctx context.Context, key, id string, n int, data []byte, checksum string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	a, ok := s.keys[key]
	size, err := plannedPartSize(a, s.request.Plan.TransferProfile)
	if !ok || err != nil || id == "" || n < 1 || n > 10000 || len(data) > size {
		return "", ErrHeld
	}
	raw, e := hex.DecodeString(digest(data))
	if e != nil || base64.StdEncoding.EncodeToString(raw) != checksum {
		return "", ErrHeld
	}
	h := http.Header{}
	h.Set("X-Amz-Checksum-Sha256", checksum)
	p, e := s.core.PutObjectPart(ctx, s.request.Plan.Target.Bucket, key, id, n, bytes.NewReader(data), int64(len(data)), minio.PutObjectPartOptions{Sha256Hex: digest(data), CustomHeader: h})
	if e != nil || (p.ChecksumSHA256 != "" && p.ChecksumSHA256 != checksum) {
		return "", ErrHeld
	}
	return p.ETag, nil
}
func (s *S3) Complete(ctx context.Context, key, id string, parts []Part) (ObjectInfo, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	if _, ok := s.keys[key]; !ok || id == "" || len(parts) < 1 || len(parts) > 10000 {
		return ObjectInfo{}, ErrHeld
	}
	items := make([]minio.CompletePart, len(parts))
	for i, p := range parts {
		b, e := hex.DecodeString(p.SHA256)
		if e != nil || len(b) != 32 || p.Number != i+1 || p.ETag == "" {
			return ObjectInfo{}, ErrHeld
		}
		items[i] = minio.CompletePart{PartNumber: p.Number, ETag: p.ETag, ChecksumSHA256: base64.StdEncoding.EncodeToString(b)}
	}
	opts := minio.PutObjectOptions{}
	opts.SetMatchETagExcept("*")
	info, e := s.core.CompleteMultipartUpload(ctx, s.request.Plan.Target.Bucket, key, id, items, opts)
	if e != nil || info.Bucket != s.request.Plan.Target.Bucket || info.Key != key {
		return ObjectInfo{}, ErrHeld
	}
	// The SDK strips HTTP entity-tag quotes. Restore the wire representation
	// used by C01 receipts and backend HEAD comparisons; the content is opaque.
	return ObjectInfo{ETag: strconv.Quote(info.ETag), VersionID: version(info.VersionID), Metadata: map[string]string{}}, nil
}
func version(v string) *string {
	if v == "" {
		return nil
	}
	return &v
}
func (s *S3) Head(ctx context.Context, key string, v *string, etag string) (ObjectInfo, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if _, ok := s.keys[key]; !ok || etag == "" {
		return ObjectInfo{}, ErrHeld
	}
	opts := minio.StatObjectOptions{}
	if v != nil {
		opts.VersionID = *v
	}
	value, err := strconv.Unquote(etag)
	if err != nil || value == "" || strconv.Quote(value) != etag || opts.SetMatchETag(value) != nil {
		return ObjectInfo{}, ErrHeld
	}
	opts.Set("X-Amz-Checksum-Mode", "ENABLED")
	i, e := s.core.StatObject(ctx, s.request.Plan.Target.Bucket, key, opts)
	if e != nil {
		return ObjectInfo{}, ErrHeld
	}
	m := map[string]string{}
	size := 0
	for k, v := range i.UserMetadata {
		k = strings.ToLower(k)
		size += len(k) + len(v)
		if _, ok := m[k]; ok {
			return ObjectInfo{}, ErrHeld
		}
		m[k] = v
	}
	if size > 2048 {
		return ObjectInfo{}, ErrHeld
	}
	hash := ""
	if i.ChecksumSHA256 != "" && i.ChecksumMode == "FULL_OBJECT" {
		raw, e := base64.StdEncoding.DecodeString(i.ChecksumSHA256)
		if e != nil || len(raw) != 32 {
			return ObjectInfo{}, ErrHeld
		}
		hash = hex.EncodeToString(raw)
	}
	return ObjectInfo{ETag: strconv.Quote(i.ETag), VersionID: version(i.VersionID), Bytes: i.Size, SHA256: hash, ChecksumType: i.ChecksumMode, Metadata: m}, nil
}
