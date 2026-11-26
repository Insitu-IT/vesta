package storageupload

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"vnbui/agent/internal/metrics"
	"vnbui/agent/internal/models"
)

// ControlledS3 never owns a provider credential. Create/complete/HEAD are
// bounded backend operations; only exact part writes receive temporary SigV4.
// The D03 journal persists intent before invoking this Provider and retains
// uncertainty on every failed call. Nothing here logs or journals authority.
type ControlledS3 struct {
	reservation     string
	attempt         string
	planHash        string
	transferProfile string
	backup          string
	target          models.StorageTarget
	encryption      models.StorageEncryption
	metadata        map[string]map[string]string
	base            string
	client          *http.Client
	provider        *http.Client
	agentKey        func(context.Context) (string, error)
	keys            map[string]models.StorageArtifact
	failureMu       sync.Mutex
	failure         *ControlFailure
}

// ControlFailure contains only fixed operation/stage names and HTTP status.
// It describes an observation; it never authorizes a replay of a write.
type ControlFailure struct {
	Operation, Stage string
	HTTPStatus       int
}

func (s *ControlledS3) Failure() *ControlFailure {
	s.failureMu.Lock()
	defer s.failureMu.Unlock()
	if s.failure == nil {
		return nil
	}
	f := *s.failure
	return &f
}

type signedPart struct {
	Method  string            `json:"method"`
	URL     string            `json:"url"`
	Headers map[string]string `json:"headers"`
	Expires int64             `json:"expires_at"`
}
type controlResponse struct {
	Schema       int         `json:"schema"`
	UploadID     string      `json:"upload_id,omitempty"`
	Authority    *signedPart `json:"authority,omitempty"`
	Object       *ObjectInfo `json:"object,omitempty"`
	Acknowledged bool        `json:"acknowledged,omitempty"`
}

// Fixed stage names and numeric status are safe to retain. Never include the
// transport error, response body, signed URL/headers or reusable credentials.
func (s *ControlledS3) heldControl(operation, stage string, status int) error {
	s.failureMu.Lock()
	s.failure = &ControlFailure{Operation: operation, Stage: stage, HTTPStatus: status}
	s.failureMu.Unlock()
	slog.Warn("storage control held", "backup_id", s.backup, "operation", operation, "stage", stage, "http_status", status)
	return ErrHeld
}

func boundedClient(client *http.Client) (*http.Client, error) {
	if client == nil {
		return nil, ErrHeld
	}
	result := *client
	transport := client.Transport
	if transport == nil {
		transport = http.DefaultTransport
	}
	if t, ok := transport.(*http.Transport); ok {
		t = t.Clone()
		if t.TLSClientConfig != nil && t.TLSClientConfig.InsecureSkipVerify {
			return nil, ErrHeld
		}
		t.MaxResponseHeaderBytes = 16384
		t.ResponseHeaderTimeout = 30 * time.Second
		result.Transport = t
	}
	result.Timeout = 0 // explicit per-operation contexts below
	result.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &result, nil
}

func NewControlledS3(request []byte, base string, client, provider *http.Client, agentKey func(context.Context) (string, error)) (*ControlledS3, error) {
	r, e := models.DecodeStorageTransaction(request)
	if e != nil {
		return nil, ErrHeld
	}
	s, e := newControlledS3(base, client, provider, agentKey)
	if e != nil {
		return nil, e
	}
	s.reservation = r.ReservationID
	s.attempt = r.Plan.AttemptID
	s.planHash = r.PlanSHA256
	s.transferProfile = r.Plan.TransferProfile
	s.backup = r.BackupID
	s.target = r.Plan.Target
	s.encryption = r.Plan.Encryption
	for _, a := range r.Plan.Artifacts {
		s.keys[a.Key] = a
		s.metadata[a.Key] = metadata(r, a)
	}
	return s, nil
}

func newControlledS3(base string, client, provider *http.Client, agentKey func(context.Context) (string, error)) (*ControlledS3, error) {
	u, e := url.Parse(base)
	if e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || agentKey == nil {
		return nil, ErrHeld
	}
	backend, e := boundedClient(client)
	if e != nil {
		return nil, e
	}
	storage, e := boundedClient(provider)
	if e != nil {
		return nil, e
	}
	s := &ControlledS3{base: base, client: backend, provider: storage, agentKey: agentKey, keys: map[string]models.StorageArtifact{}, metadata: map[string]map[string]string{}}
	return s, nil
}
func (s *ControlledS3) Target() models.StorageTarget { return s.target }
func (s *ControlledS3) Close()                       { s.client.CloseIdleConnections(); s.provider.CloseIdleConnections() }

func (s *ControlledS3) call(ctx context.Context, key, op string, args any) (controlResponse, error) {
	started := time.Now()
	defer func() {
		metrics.StorageStepSeconds.WithLabelValues("backend_" + op).Observe(time.Since(started).Seconds())
	}()
	var result controlResponse
	if _, ok := s.keys[key]; !ok {
		return result, ErrHeld
	}
	binding := map[string]any{"reservation_id": s.reservation, "attempt_id": s.attempt, "plan_sha256": s.planHash, "key_ref": s.encryption.KeyRef}
	body, e := json.Marshal(map[string]any{"schema": 1, "binding": binding, "artifact_key": key, "operation": op, "args": args})
	if e != nil || len(body) > 2*1024*1024 {
		return result, ErrHeld
	}
	credential, e := s.agentKey(ctx)
	if e != nil || credential == "" {
		return result, ErrHeld
	}
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	req, e := http.NewRequestWithContext(ctx, http.MethodPost, s.base+"/api/v1/agents/backups/"+s.backup+"/storage-control", bytes.NewReader(body))
	if e != nil {
		return result, ErrHeld
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Agent-Key", credential)
	response, e := s.client.Do(req)
	if e != nil {
		return result, s.heldControl(op, "backend_transport", 0)
	}
	defer response.Body.Close()
	if response.StatusCode != 200 || response.Header.Get("Cache-Control") != "no-store" {
		return result, s.heldControl(op, "backend_response", response.StatusCode)
	}
	data, e := io.ReadAll(io.LimitReader(response.Body, 1<<20+1))
	if e != nil || len(data) > 1<<20 {
		return result, s.heldControl(op, "backend_body", response.StatusCode)
	}
	value, e := models.DecodeStorageControlJSON(data)
	field := map[string]string{"create": "upload_id", "part": "authority", "part_ack": "acknowledged", "complete": "object", "head": "object"}[op]
	if e != nil || len(value) != 2 || value["schema"] == nil || value[field] == nil {
		return result, s.heldControl(op, "backend_shape", response.StatusCode)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&result) != nil || decoder.Decode(new(any)) != io.EOF || result.Schema != 1 {
		return controlResponse{}, s.heldControl(op, "backend_decode", response.StatusCode)
	}
	return result, nil
}

func (s *ControlledS3) Begin(ctx context.Context, key string, meta map[string]string) (string, error) {
	_, ok := s.keys[key]
	if !ok || !equalMetadata(meta, s.metadata[key]) {
		return "", ErrHeld
	}
	r, e := s.call(ctx, key, "create", map[string]any{})
	if e != nil || r.UploadID == "" || len(r.UploadID) > 1024 || strings.ContainsAny(r.UploadID, "\r\n") || r.Authority != nil || r.Object != nil {
		return "", ErrHeld
	}
	return r.UploadID, nil
}

func (s *ControlledS3) Part(ctx context.Context, key, id string, n int, data []byte, checksum string) (string, error) {
	a, ok := s.keys[key]
	size, e := plannedPartSize(a, s.transferProfile)
	hash := digest(data)
	raw, _ := hex.DecodeString(hash)
	if !ok || e != nil || len(data) > size || id == "" || n < 1 || n > 10000 || base64.StdEncoding.EncodeToString(raw) != checksum {
		return "", ErrHeld
	}
	args := map[string]any{"upload_id": id, "number": n, "bytes": len(data), "sha256": hash}
	r, e := s.call(ctx, key, "part", args)
	if e != nil {
		return "", e
	}
	if r.Authority == nil || r.Object != nil || r.UploadID != "" {
		return "", s.heldControl("part", "authority_response", 0)
	}
	signed := r.Authority
	if !s.validPart(signed, key, id, n, len(data), hash, checksum) {
		return "", s.heldControl("part", "authority_validation", 0)
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	req, e := http.NewRequestWithContext(ctx, http.MethodPut, signed.URL, bytes.NewReader(data))
	if e != nil {
		return "", s.heldControl("part", "provider_request", 0)
	}
	for k, v := range signed.Headers {
		req.Header.Set(k, v)
	}
	req.ContentLength = int64(len(data))
	started := time.Now()
	response, e := s.provider.Do(req)
	metrics.StorageStepSeconds.WithLabelValues("s3_part").Observe(time.Since(started).Seconds())
	if e != nil {
		return "", s.heldControl("part", "provider_transport", 0)
	}
	defer response.Body.Close()
	// Never expose the provider body, URL, signed headers or transport error.
	if response.StatusCode != 200 {
		return "", s.heldControl("part", "provider_response", response.StatusCode)
	}
	if c := response.Header.Get("X-Amz-Checksum-Sha256"); c != "" && c != checksum {
		return "", s.heldControl("part", "provider_checksum", response.StatusCode)
	}
	etag, e := strconv.Unquote(response.Header.Get("ETag"))
	if e != nil || etag == "" || len(etag) > 1022 || strings.ContainsAny(etag, "\r\n\"") {
		return "", s.heldControl("part", "provider_etag", response.StatusCode)
	}
	args["etag"] = etag
	ack, e := s.call(ctx, key, "part_ack", args)
	if e != nil {
		return "", e
	}
	if !ack.Acknowledged || ack.Authority != nil || ack.Object != nil {
		return "", s.heldControl("part_ack", "acknowledgment", 0)
	}
	return etag, nil
}

func (s *ControlledS3) validPart(a *signedPart, key, id string, n, size int, hash, checksum string) bool {
	u, e := url.Parse(a.URL)
	target, _ := url.Parse(s.target.Endpoint)
	if e != nil || u.Scheme != "https" || u.Host != target.Host || u.User != nil || u.Fragment != "" || u.Path != "/"+s.target.Bucket+"/"+key || a.Method != "PUT" {
		return false
	}
	now := time.Now().Unix()
	if a.Expires <= now || a.Expires > now+60 {
		return false
	}
	expected := map[string]string{"content-length": strconv.Itoa(size), "x-amz-checksum-sha256": checksum, "x-amz-content-sha256": hash}
	if !equalMetadata(a.Headers, expected) {
		return false
	}
	q, e := url.ParseQuery(u.RawQuery)
	if e != nil || len(q) != 8 {
		return false
	}
	for _, v := range q {
		if len(v) != 1 {
			return false
		}
	}
	if q.Get("uploadId") != id || q.Get("partNumber") != strconv.Itoa(n) || q.Get("X-Amz-Algorithm") != "AWS4-HMAC-SHA256" || q.Get("X-Amz-Expires") != "60" || q.Get("X-Amz-SignedHeaders") != "content-length;host;x-amz-checksum-sha256;x-amz-content-sha256" || !validHash(q.Get("X-Amz-Signature")) {
		return false
	}
	stamp, e := time.Parse("20060102T150405Z", q.Get("X-Amz-Date"))
	if e != nil || stamp.Unix()+60 != a.Expires {
		return false
	}
	credential := strings.Split(q.Get("X-Amz-Credential"), "/")
	return len(credential) == 5 && credential[0] != "" && credential[1] == stamp.Format("20060102") && credential[2] == s.target.Region && credential[3] == "s3" && credential[4] == "aws4_request"
}

func (s *ControlledS3) Complete(ctx context.Context, key, id string, parts []Part) (ObjectInfo, error) {
	r, e := s.call(ctx, key, "complete", map[string]any{"upload_id": id, "parts": parts})
	if e != nil || r.Object == nil || r.Authority != nil {
		return ObjectInfo{}, ErrHeld
	}
	if _, e = strconv.Unquote(r.Object.ETag); e != nil {
		return ObjectInfo{}, ErrHeld
	}
	return *r.Object, nil
}
func (s *ControlledS3) Head(ctx context.Context, key string, version *string, etag string) (ObjectInfo, error) {
	r, e := s.call(ctx, key, "head", map[string]any{"version_id": version, "etag": etag})
	if e != nil || r.Object == nil || r.Authority != nil {
		return ObjectInfo{}, ErrHeld
	}
	return *r.Object, nil
}
