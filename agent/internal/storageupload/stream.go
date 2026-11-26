package storageupload

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"hash"
	"io"
	"reflect"
	"time"

	"vnbui/agent/internal/encryption"
	"vnbui/agent/internal/metrics"
	"vnbui/agent/internal/models"
)

// All buffers have a fixed ceiling independent of source size. A part's size
// is selected once from the immutable maximum and journaled before creation.
const partSize = 8 * 1024 * 1024
const maxPartSize = 1024 * 1024 * 1024
const maxManifest = 16 * 1024 * 1024

func plannedPartSize(a models.StorageArtifact, profile string) (int, error) {
	if _, err := models.StorageSourceRangeBytes(profile); err != nil {
		return 0, ErrHeld
	}
	if a.CiphertextMax < 0 || a.CiphertextMax > int64(maxPartSize)*10000 {
		return 0, ErrHeld
	}
	size := (a.CiphertextMax + 9999) / 10000
	size = ((size + partSize - 1) / partSize) * partSize
	minimum := int64(partSize)
	if profile == models.KubevirtTransfer32 && a.Role == "volume_payload" {
		minimum = 32 << 20
	}
	if size < minimum {
		size = minimum
	}
	return int(size), nil
}

type ObjectInfo struct {
	ETag         string            `json:"etag"`
	VersionID    *string           `json:"version_id"`
	Bytes        int64             `json:"bytes"`
	SHA256       string            `json:"sha256"`
	ChecksumType string            `json:"checksum_type"`
	Metadata     map[string]string `json:"metadata"`
}

// Provider methods have exact identities only. There is intentionally no LIST,
// body GET, copy, broad delete, automatic retry or implicit credential lookup.
type Provider interface {
	Target() models.StorageTarget
	Begin(context.Context, string, map[string]string) (string, error)
	Part(context.Context, string, string, int, []byte, string) (string, error)
	Complete(context.Context, string, string, []Part) (ObjectInfo, error)
	Head(context.Context, string, *string, string) (ObjectInfo, error)
}

type Input struct {
	Artifact models.StorageArtifact
	Open     func() (io.ReadCloser, error)
}

func metadata(r *models.StorageTransactionRequest, a models.StorageArtifact) map[string]string {
	return map[string]string{
		"vnbui-protocol": "1", "vnbui-org-id": r.OrgID, "vnbui-backup-id": r.BackupID,
		"vnbui-reservation-id": r.ReservationID, "vnbui-plan-sha256": r.PlanSHA256,
		"vnbui-artifact-id": digest([]byte(a.VolumeID + ":" + a.Role)),
	}
}

func validHash(value string) bool {
	raw, err := hex.DecodeString(value)
	return err == nil && len(raw) == sha256.Size && hex.EncodeToString(raw) == value
}

func assurance(profile string, head ObjectInfo) string {
	// Consumer-verified profiles do not promise upload checksum enforcement,
	// even if a target echoes a checksum header. Their assurance stays weaker.
	if profile == "checksum-enforced/1" && head.ChecksumType == "FULL_OBJECT" && head.SHA256 != "" {
		return "provider_checksum_verified"
	}
	return "identity_metadata_only"
}

func validHead(r *models.StorageTransactionRequest, o ObjectState) bool {
	return validObjectHead(o, metadata(r, o.Artifact))
}

func validObjectHead(o ObjectState, expected map[string]string) bool {
	if o.Provider == nil || o.Receipt == nil {
		return false
	}
	h, receipt := o.Provider, o.Receipt
	if !reflect.DeepEqual(h.VersionID, receipt.VersionID) || h.ETag != receipt.ETag || h.Bytes != receipt.CiphertextBytes ||
		!equalMetadata(h.Metadata, expected) {
		return false
	}
	if h.ChecksumType != "" && h.ChecksumType != "COMPOSITE" && h.ChecksumType != "FULL_OBJECT" {
		return false
	}
	return h.SHA256 == "" || (h.ChecksumType == "FULL_OBJECT" && h.SHA256 == receipt.CiphertextSHA256)
}

type measuredReader struct {
	r      io.Reader
	h      hash.Hash
	n, max int64
}

func (r *measuredReader) Read(p []byte) (int, error) {
	remaining := r.max - r.n
	if int64(len(p)) > remaining+1 {
		p = p[:remaining+1]
	}
	n, e := r.r.Read(p)
	if int64(n) > remaining {
		return 0, ErrHeld
	}
	if n > 0 {
		_, _ = r.h.Write(p[:n])
		r.n += int64(n)
	}
	return n, e
}

type partWriter struct {
	cycleStarted time.Time
	o            *ObjectState
	save         func() error
	p            Provider
	ctx          context.Context
	buf          []byte
	h            hash.Hash
	n            int64
}

func (w *partWriter) Write(b []byte) (int, error) {
	o := w.o
	if int64(len(b)) > o.Artifact.CiphertextMax-w.n {
		return 0, ErrHeld
	}
	total := len(b)
	for len(b) > 0 {
		n := len(b)
		if n > o.PartSize-len(w.buf) {
			n = o.PartSize - len(w.buf)
		}
		w.buf = append(w.buf, b[:n]...)
		_, _ = w.h.Write(b[:n])
		w.n += int64(n)
		b = b[n:]
		if len(w.buf) == o.PartSize {
			if e := w.flush(); e != nil {
				return 0, e
			}
		}
	}
	return total, nil
}
func (w *partWriter) flush() error {
	o := w.o
	if len(o.Parts) >= 10000 {
		return ErrHeld
	}
	sum := sha256.Sum256(w.buf)
	part := Part{Number: len(o.Parts) + 1, Bytes: int64(len(w.buf)), SHA256: hex.EncodeToString(sum[:])}
	o.PendingPart = &part
	o.Phase = "part_intent"
	if e := w.save(); e != nil {
		return e
	}
	etag, e := w.p.Part(w.ctx, o.Artifact.Key, o.UploadID, part.Number, w.buf, base64.StdEncoding.EncodeToString(sum[:]))
	if e != nil || etag == "" || len(etag) > 1024 {
		return ErrHeld
	}
	part.ETag = etag
	o.Parts = append(o.Parts, part)
	o.PendingPart = nil
	o.Phase = "uploading"
	if e = w.save(); e != nil {
		return e
	}
	role := "native"
	switch o.Artifact.Role {
	case "volume_payload":
		role = "payload"
	case "volume_manifest":
		role = "manifest"
	}
	metrics.StoragePartCycleSeconds.WithLabelValues(role).Observe(time.Since(w.cycleStarted).Seconds())
	metrics.StorageUploadedBytes.WithLabelValues(role).Add(float64(part.Bytes))
	w.cycleStarted = time.Now()
	w.buf = w.buf[:0]
	return nil
}

// UploadAll validates the complete input set before opening any source or
// calling a provider. Reordering is harmless only because identity is matched
// by the entire exact artifact, never by position or basename.
func (j *Journal) UploadAll(ctx context.Context, p Provider, inputs []Input, key []byte) (err error) {
	return j.UploadAllWithProgress(ctx, p, inputs, key, nil)
}

// UploadAllWithProgress observes only acknowledged, durably saved payload
// parts. The callback must only replace an in-memory snapshot: no network IO,
// journal re-entry or lifecycle authority belongs in this observation.
func (j *Journal) UploadAllWithProgress(ctx context.Context, p Provider, inputs []Input, key []byte, observe func(UploadProgress)) (err error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	save := func() error {
		if err := j.save(); err != nil {
			return err
		}
		if observe != nil {
			observe(payloadProgress(&j.state))
		}
		return nil
	}
	if j.poisoned || j.state.Phase == "held" || !reflect.DeepEqual(p.Target(), j.state.Request.Plan.Target) {
		return ErrHeld
	}
	if len(inputs) != len(j.state.Objects) {
		return ErrHeld
	}
	byKey := map[string]Input{}
	for _, in := range inputs {
		if _, exists := byKey[in.Artifact.Key]; exists || in.Open == nil {
			return ErrHeld
		}
		byKey[in.Artifact.Key] = in
	}
	for _, o := range j.state.Objects {
		in, ok := byKey[o.Artifact.Key]
		if !ok || !reflect.DeepEqual(in.Artifact, o.Artifact) {
			return ErrHeld
		}
		// This fixed-memory implementation must refuse an unsupported maximum
		// before opening a source or creating an MPU, not at part 10001.
		if _, e := plannedPartSize(o.Artifact, j.state.Request.Plan.TransferProfile); e != nil {
			return ErrHeld
		}
	}
	if j.state.Phase == "prepared" || j.state.Phase == "submitting" || j.state.Phase == "accepted" {
		return j.save()
	}
	if j.state.Request.Plan.Encryption.Format != "none" {
		for _, o := range j.state.Objects {
			if o.Phase == "planned" && o.Artifact.Role == "volume_payload" && len(key) != 32 {
				return ErrHeld
			}
		}
	}
	defer func() {
		if err != nil {
			j.state.Phase = "held"
			_ = j.save()
		}
	}()
	for i := range j.state.Objects {
		o := &j.state.Objects[i]
		if o.Phase == "complete" {
			continue
		}
		if o.Phase != "planned" {
			return ErrHeld
		}
		// Bound manifests before any publication. A bounded manifest is the only
		// object we buffer in full; disk payloads remain single-pass streams.
		if e := j.save(); e != nil {
			return e
		}
		r, e := byKey[o.Artifact.Key].Open()
		if e != nil {
			return ErrHeld
		}
		if r == nil {
			return ErrHeld
		}
		if o.Artifact.Role == "volume_manifest" {
			body, readErr := io.ReadAll(io.LimitReader(r, maxManifest+1))
			closeErr := r.Close()
			if readErr != nil || closeErr != nil || len(body) > maxManifest {
				return ErrHeld
			}
			r = io.NopCloser(bytes.NewReader(body))
		}
		e = j.upload(ctx, p, i, r, key, save)
		closeErr := r.Close()
		if e != nil || closeErr != nil {
			return ErrHeld
		}
	}
	r := models.StorageReceipt{Protocol: models.StorageProtocol, Schema: 2, ReservationID: j.state.Request.ReservationID,
		BackupID: j.state.Request.BackupID, Endpoint: j.state.Request.Plan.Target.Endpoint, Bucket: j.state.Request.Plan.Target.Bucket, Objects: []models.StorageObjectReceipt{}}
	for _, o := range j.state.Objects {
		r.Objects = append(r.Objects, *o.Receipt)
	}
	if _, _, e := models.CanonicalReceipt(&j.state.Request, r); e != nil {
		return e
	}
	j.state.Receipt = &r
	j.state.Phase = "prepared"
	return save()
}

func (j *Journal) upload(ctx context.Context, p Provider, index int, source io.Reader, key []byte, save func() error) error {
	o := &j.state.Objects[index]
	return streamObject(ctx, p, o, source, key,
		o.Artifact.Role == "volume_payload" && j.state.Request.Plan.Encryption.Format != "none",
		metadata(&j.state.Request, o.Artifact), j.state.Request.Plan.CapabilityProfile, save)
}

// streamObject is the single multipart/hash/framing engine for both admitted
// representations. The caller persists its own exact identity projection at
// every save; the engine consumes only key and byte bounds, never invents IDs.
func streamObject(ctx context.Context, p Provider, o *ObjectState, source io.Reader, key []byte,
	encrypt bool, meta map[string]string, profile string, save func() error) error {
	o.Phase = "create_intent"
	if e := save(); e != nil {
		return e
	}
	id, e := p.Begin(ctx, o.Artifact.Key, meta)
	if e != nil || id == "" || len(id) > 2048 {
		return ErrHeld
	}
	o.UploadID = id
	o.Phase = "uploading"
	if e = save(); e != nil {
		return e
	}
	r := &measuredReader{r: source, h: sha256.New(), max: o.Artifact.PlaintextMax}
	w := &partWriter{cycleStarted: time.Now(), o: o, save: save, p: p, ctx: ctx, buf: make([]byte, 0, o.PartSize), h: sha256.New()}
	if encrypt {
		e = encryption.EncryptStreamChunked(r, w, key, 5242880)
	} else {
		_, e = io.CopyBuffer(w, r, make([]byte, 64*1024))
	}
	if e != nil {
		return ErrHeld
	}
	if len(w.buf) > 0 || len(o.Parts) == 0 {
		if e = w.flush(); e != nil {
			return e
		}
	}
	if r.n < o.Artifact.PlaintextMin || w.n < o.Artifact.CiphertextMin {
		return ErrHeld
	}
	o.Receipt = &models.StorageObjectReceipt{Key: o.Artifact.Key, VolumeID: o.Artifact.VolumeID, Role: o.Artifact.Role,
		PlaintextBytes: r.n, CiphertextBytes: w.n, PlaintextSHA256: hex.EncodeToString(r.h.Sum(nil)), CiphertextSHA256: hex.EncodeToString(w.h.Sum(nil))}
	o.Phase = "complete_intent"
	if e = save(); e != nil {
		return e
	}
	info, e := p.Complete(ctx, o.Artifact.Key, id, append([]Part{}, o.Parts...))
	if e != nil || info.ETag == "" {
		return ErrHeld
	}
	o.Receipt.ETag = info.ETag
	o.Receipt.VersionID = info.VersionID
	o.Provider = &info
	// Persist the acknowledged exact object identity before the metadata read.
	if e = save(); e != nil {
		return e
	}
	head, e := p.Head(ctx, o.Artifact.Key, info.VersionID, info.ETag)
	if e != nil {
		return ErrHeld
	}
	if models.ValidateStorageObject(o.Artifact, *o.Receipt) != nil {
		return ErrHeld
	}
	o.Provider = &head
	if !validObjectHead(*o, meta) {
		return ErrHeld
	}
	o.Assurance = assurance(profile, head)
	o.Phase = "complete"
	return save()
}
