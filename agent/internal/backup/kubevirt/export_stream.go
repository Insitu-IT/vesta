//go:build kubevirt

package kubevirt

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"path/filepath"
	"strconv"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"vnbui/agent/internal/metrics"
	"vnbui/agent/internal/models"
	"vnbui/agent/internal/storageupload"
)

// AcceptStorageTransaction is the production transaction entry through durable
// receipt acceptance only. HTTP activation stays held. It deliberately has no
// finalize, checkpoint report, completion event or destructive cleanup call.
func (e *Executor) AcceptStorageTransaction(ctx context.Context, body []byte, backend, provider *http.Client, credential func(context.Context) (string, error)) (*models.StorageAcceptance, error) {
	j, err := e.PrepareStorageTransaction(ctx, body)
	if err != nil {
		return nil, err
	}
	defer j.Close()
	s, err := j.Snapshot()
	if err != nil {
		return nil, storageupload.ErrHeld
	}
	if safetyFrom(ctx) == nil {
		g, err := openSafety(filepath.Join(filepath.Dir(e.cfg.KeyFilePath), "storage-transactions"), &s.Request)
		if err != nil {
			return nil, fault("admission", "safety_record_missing_or_invalid", "refused")
		}
		ctx = context.WithValue(ctx, safetyContextKey{}, g)
	}
	if err := checkSafety(ctx); err != nil {
		return nil, err
	}
	ctx, nativeCancel := nativeUploadContext(ctx, &s)
	defer nativeCancel()
	if s.Phase != "uploading" {
		if len(s.Maps) == 0 {
			return nil, storageupload.ErrHeld
		}
		if err := e.revalidateExport(ctx, &s); err != nil {
			return nil, err
		}
		return j.Submit(ctx, e.cfg.OrchestratorURL, backend, credential)
	}
	prep := safetyFrom(ctx).snapshot().Progress
	deadline, cancel := context.WithTimeout(ctx, prep.LastProgressAt.Add(time.Duration(prep.Budget.PreparationSeconds)*time.Second).Sub(nativeNow()))
	defer cancel()
	for {
		if err := checkSafety(deadline); err != nil {
			if deadline.Err() != nil && ctx.Err() == nil {
				return nil, fault("export", "export_readiness_budget_exhausted", "refused")
			}
			return nil, err
		}
		if err := e.admitNativeBoundary(deadline, j); err != nil {
			return nil, err
		}
		s, err = j.Snapshot()
		if err != nil {
			return nil, storageupload.ErrHeld
		}
		var x *storageupload.ExportState
		inspectErr := e.retryValidationObservation(deadline, &s, func(observation context.Context) error {
			var err error
			x, err = e.inspectExport(observation, &s)
			return err
		})
		if inspectErr == nil {
			if j.BindExport(*x) != nil {
				return nil, storageupload.ErrHeld
			}
			break
		}
		if inspectErr != exportPending {
			if inspectErr == errExportLifetime && s.Export == nil {
				_ = j.HoldBeforePayload()
				slog.Warn("native export lifetime refused before payload production", "reason", inspectErr)
			}
			if inspectErr == errExportLifetime {
				return nil, fault("export_admission", "export_lifetime_insufficient", "refused")
			}
			return nil, inspectErr
		}
		timer := time.NewTimer(time.Second)
		select {
		case <-deadline.Done():
			timer.Stop()
			return nil, fault("export", "export_readiness_budget_exhausted", "refused")
		case <-timer.C:
		}
	}
	s, err = j.Snapshot()
	if err != nil {
		return nil, storageupload.ErrHeld
	}
	ctx, exportCancel := nativeUploadContext(ctx, &s)
	defer exportCancel()
	store, err := storageupload.NewControlledS3(body, e.cfg.OrchestratorURL, backend, provider, credential)
	if err != nil {
		return nil, storageupload.ErrHeld
	}
	defer store.Close()
	if err := e.revalidateExport(ctx, &s); err != nil {
		return nil, err
	}
	key, err := store.ResolveKey(ctx)
	if err != nil {
		return nil, fault("preparing", "key_resolution_failed", "transient")
	}
	defer clear(key)
	if err = j.SealVMDefinition(key); err != nil {
		return nil, storageupload.ErrHeld
	}
	s, err = j.Snapshot()
	if err != nil {
		return nil, storageupload.ErrHeld
	}
	// Token reads follow re-admission and exact original secret UID/owner checks.
	if err := e.revalidateExport(ctx, &s); err != nil {
		return nil, err
	}
	n := s.Native
	secret, err := e.dynamic.Resource(coreV1Secret).Namespace(s.Request.Plan.Source.Namespace).Get(ctx, n.Objects[2].Name, metav1.GetOptions{})
	if err != nil || string(secret.GetUID()) != n.Objects[2].UID || !validNativeObject(secret, &s.Request, n, 2, true) {
		return nil, storageupload.ErrHeld
	}
	tokenBytes, err := base64.StdEncoding.Strict().DecodeString(textAt(secret, "data", "token"))
	if err != nil || len(tokenBytes) < 32 || len(tokenBytes) > 512 {
		return nil, storageupload.ErrHeld
	}
	defer clear(tokenBytes)
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(s.Export.CA)) {
		return nil, storageupload.ErrHeld
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool}, MaxResponseHeaderBytes: 16384, ResponseHeaderTimeout: 30 * time.Second, DisableCompression: true}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	read := &transactionExport{ctx: ctx, client: client, token: string(tokenBytes), validate: func() error {
		if err := checkSafety(ctx); err != nil {
			return err
		}
		return e.revalidateExport(ctx, &s)
	}}
	g := safetyFrom(ctx)
	read.firstByte = func() error {
		return g.update(func(s *safetyState) error {
			if s.Stop != nil {
				return storageupload.ErrHeld
			}
			if s.FirstByteAt == nil {
				now := nativeNow().UTC()
				s.FirstByteAt = &now
			}
			return nil
		})
	}
	defer func() { read.token = "" }()
	if len(s.Maps) == 0 {
		maps := make([]storageupload.ExportMap, 0, len(s.Export.Volumes))
		if err := safetyProgress(ctx, "mapping", 0); err != nil {
			return nil, err
		}
		remaining := storageupload.MaxExportRanges
		var covered int64
		for i, v := range s.Export.Volumes {
			read.mapProgress = func(page int, offset uint64, raw, stored int) error {
				return g.update(func(state *safetyState) error {
					if state.Stop != nil {
						return storageupload.ErrHeld
					}
					_, err := state.Progress.Advance(nativeNow(), "mapping", covered+int64(offset))
					state.Map = &operationFault{Stage: "mapping", Reason: "validated_page", Disposition: "progress", Volume: i + 1, Page: page, Offset: offset, RawRanges: raw, StoredRanges: stored}
					return err
				})
			}
			m, count, err := read.extents(v, uint64(s.Request.Plan.Source.Volumes[i].CapacityBytes), s.Request.Plan.BackupType, remaining)
			if err != nil {
				f := faultOf(err)
				f.Volume = i + 1
				return nil, f
			}
			covered += s.Request.Plan.Source.Volumes[i].CapacityBytes
			remaining -= count
			maps = append(maps, m)
		}
		if j.BindExportMaps(maps) != nil {
			return nil, storageupload.ErrHeld
		}
		s, err = j.Snapshot()
		if err != nil {
			return nil, storageupload.ErrHeld
		}
	}
	inputs, err := transactionInputs(read, &s)
	if err != nil {
		return nil, storageupload.ErrHeld
	}
	if err := safetyProgress(ctx, "transferring", 0); err != nil {
		return nil, err
	}
	if err = j.UploadAllWithProgress(ctx, &admittedProvider{Provider: store, validate: read.validate}, inputs, key, func(p storageupload.UploadProgress) {
		if err := g.update(func(state *safetyState) error {
			if state.Stop != nil {
				return storageupload.ErrHeld
			}
			if p.BytesTransferred > state.AcknowledgedBytes {
				now := nativeNow().UTC()
				if state.FirstACKAt == nil {
					state.FirstACKAt = &now
				}
				state.AcknowledgedBytes = p.BytesTransferred
				_, err := state.Progress.Advance(now, "transferring", p.BytesTransferred)
				return err
			}
			return nil
		}); err != nil {
			nativeCancel()
			return
		}
		e.observeTransactionUpload(&s.Request, p)
	}); err != nil {
		if control := store.Failure(); control != nil {
			return nil, &operationFault{Stage: "transferring", Reason: control.Operation + "_" + control.Stage, Disposition: "uncertain", HTTPStatus: control.HTTPStatus}
		}
		if read.failure != nil {
			f := *read.failure
			f.Disposition = "uncertain"
			return nil, &f
		}
		return nil, fault("transferring", "payload_transfer_failed", "uncertain")
	}
	if err := safetyProgress(ctx, "finalizing", 0); err != nil {
		return nil, err
	}
	e.observeTransactionFinalizing(&s.Request)
	if err := e.revalidateExport(ctx, &s); err != nil {
		return nil, err
	}
	return j.Submit(ctx, e.cfg.OrchestratorURL, backend, credential)
}

type transactionExport struct {
	ctx         context.Context
	client      *http.Client
	token       string
	validate    func() error
	mapProgress func(page int, offset uint64, raw, stored int) error
	firstByte   func() error
	failure     *operationFault
}
type exportBody struct {
	io.ReadCloser
	cancel      context.CancelFunc
	readTimeout time.Duration
}

func (b *exportBody) Close() error { b.cancel(); return b.ReadCloser.Close() }
func (b *exportBody) Read(p []byte) (int, error) {
	started := time.Now()
	defer func() {
		metrics.StorageStepSeconds.WithLabelValues("source_read").Observe(time.Since(started).Seconds())
	}()
	// Bound a stalled source read, not the time spent uploading a completed
	// chunk to S3. The latter can legitimately outlast the next read deadline.
	timer := time.AfterFunc(b.readTimeout, b.cancel)
	defer timer.Stop()
	return b.ReadCloser.Read(p)
}
func (x *transactionExport) get(endpoint string, query url.Values) (io.ReadCloser, error) {
	return x.getWithTimeout(endpoint, query, 60*time.Second)
}
func (x *transactionExport) getWithTimeout(endpoint string, query url.Values, timeout time.Duration) (io.ReadCloser, error) {
	if !storageupload.ExportURL(endpoint) {
		return nil, fault("source_read", "export_url_refused", "refused")
	}
	if x.validate() != nil {
		return nil, fault("source_read", "export_admission_failed", "transient")
	}
	u, _ := url.Parse(endpoint)
	u.RawQuery = query.Encode()
	ctx, cancel := context.WithCancel(x.ctx)
	r, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		cancel()
		return nil, fault("source_read", "export_request_invalid", "refused")
	}
	r.Header.Set(exportTokenHeader, x.token)
	headerTimer := time.AfterFunc(timeout, cancel)
	response, err := x.client.Do(r)
	headerTimer.Stop()
	if err != nil {
		cancel()
		return nil, fault("source_read", "export_transport_failed", "transient")
	}
	if response.StatusCode != http.StatusOK {
		response.Body.Close()
		cancel()
		f := fault("source_read", "export_http_refused", "refused")
		f.HTTPStatus = response.StatusCode
		if response.StatusCode == 408 || response.StatusCode == 429 || response.StatusCode >= 500 {
			f.Disposition = "transient"
		}
		return nil, f
	}
	return &exportBody{ReadCloser: response.Body, cancel: cancel, readTimeout: timeout}, nil
}

// Limit decoded input work separately from the persisted range representation.
// Clean ranges consume parser work but no payload-map entries. Both limits are
// hard bounds, not a reason to keep re-reading an unrepresentable map.
const maxRawExportRanges = 1 << 20

func (x *transactionExport) extents(v storageupload.ExportVolume, capacity uint64, kind string, remaining int) (storageupload.ExportMap, int, error) {
	result := storageupload.ExportMap{VolumeID: v.VolumeID, Ranges: []storageupload.ExportRange{}}
	var offset uint64
	raw, pages := 0, 0
	failed := func(err error) (storageupload.ExportMap, int, error) {
		f := faultOf(err)
		f.Stage, f.Page, f.Offset = "mapping", pages, offset
		f.RawRanges, f.StoredRanges = raw, len(result.Ranges)
		return result, len(result.Ranges), f
	}
	for {
		if x.ctx.Err() != nil {
			return failed(fault("mapping", "map_cancelled", "transient"))
		}
		body, err := x.get(v.MapURL, url.Values{"offset": {strconv.FormatUint(offset, 10)}, "page_size": {"512"}})
		if err != nil {
			return failed(err)
		}
		data, err := io.ReadAll(io.LimitReader(body, (1<<20)+1))
		closeErr := body.Close()
		if err != nil || closeErr != nil {
			return failed(fault("mapping", "map_body_read_failed", "transient"))
		}
		if len(data) > 1<<20 {
			return failed(fault("mapping", "map_body_limit", "refused"))
		}
		var page mapPage
		if models.DecodeStorageValue(data, &page, 1<<20) != nil || len(page.Extents) > 512 || len(page.Extents) == 0 {
			return failed(fault("mapping", "map_schema_invalid", "refused"))
		}
		if raw > maxRawExportRanges-len(page.Extents) {
			return failed(fault("mapping", "map_input_limit", "refused"))
		}
		// Validate the entire page before advancing the durable coverage cursor.
		next := offset
		for _, extent := range page.Extents {
			if extent.Length == 0 || extent.Offset != next || next > capacity || extent.Length > capacity-next {
				return failed(fault("mapping", "map_coverage_invalid", "refused"))
			}
			next += extent.Length
		}
		if page.NextOffset != nil && (*page.NextOffset != next || next >= capacity) {
			return failed(fault("mapping", "map_pagination_invalid", "refused"))
		}
		stored, err := storedExtents(page.Extents, kind)
		if err != nil {
			return failed(fault("mapping", "map_description_invalid", "refused"))
		}
		for _, r := range stored {
			n := len(result.Ranges)
			// Adjacent payload or zero ranges may be combined, including across
			// pages. Never combine across a clean gap or a dirty-zero boundary.
			if n > 0 && result.Ranges[n-1].Offset+result.Ranges[n-1].Length == r.DiskOffset && result.Ranges[n-1].ZeroFill == r.ZeroFill {
				result.Ranges[n-1].Length += r.Length
			} else {
				if n >= remaining {
					return failed(fault("mapping", "map_stored_range_limit", "refused"))
				}
				result.Ranges = append(result.Ranges, storageupload.ExportRange{Offset: r.DiskOffset, Length: r.Length, ZeroFill: r.ZeroFill})
			}
		}
		offset, raw, pages = next, raw+len(page.Extents), pages+1
		if x.mapProgress != nil {
			if err := x.mapProgress(pages, offset, raw, len(result.Ranges)); err != nil {
				return failed(err)
			}
		}
		if page.NextOffset == nil {
			// PVC capacity includes filesystem overhead; the final validated map
			// covers the guest-visible virtual disk, bounded by that capacity.
			result.VirtualSize = offset
			return result, len(result.Ranges), nil
		}
	}
}

// rangeReader fetches one bounded range synchronously and closes its response
// before yielding bytes. A slow S3 part must not leave unread data idle in an
// exporter/proxy connection. No goroutine reads ahead across an admission boundary.
type rangeReader struct {
	source     *transactionExport
	endpoint   string
	ranges     []storageupload.ExportRange
	index      int
	position   uint64
	buffer     []byte
	consumed   int
	closed     bool
	rangeBytes uint64
}

func (r *rangeReader) Close() error {
	r.closed = true
	clear(r.buffer)
	r.buffer = nil
	return nil
}
func (r *rangeReader) Read(p []byte) (int, error) {
	if r.closed || r.source.ctx.Err() != nil {
		_ = r.Close()
		return 0, storageupload.ErrHeld
	}
	if len(p) == 0 {
		return 0, nil
	}
	for r.consumed == len(r.buffer) {
		if r.index == len(r.ranges) {
			return 0, io.EOF
		}
		extent := r.ranges[r.index]
		if extent.ZeroFill || r.position == extent.Length {
			r.index++
			r.position = 0
			continue
		}
		n := extent.Length - r.position
		limit := r.rangeBytes
		if limit == 0 {
			limit = 8 << 20
		}
		if limit != 8<<20 && limit != 32<<20 {
			_ = r.Close()
			return 0, storageupload.ErrHeld
		}
		if n > limit {
			n = limit
		}
		body, err := r.source.get(r.endpoint, url.Values{"offset": {strconv.FormatUint(extent.Offset+r.position, 10)}, "length": {strconv.FormatUint(n, 10)}})
		if err != nil {
			r.source.failure = faultOf(err)
			_ = r.Close()
			return 0, storageupload.ErrHeld
		}
		clear(r.buffer)
		if uint64(cap(r.buffer)) < n {
			r.buffer = make([]byte, n)
		} else {
			r.buffer = r.buffer[:n]
		}
		// Validate the complete range, including its exact end, before any of
		// its bytes reach hashing/encryption or a provider part. Always close
		// the HTTP response, including on short/extra bodies and cancellation.
		_, readErr := io.ReadFull(body, r.buffer)
		var extra [1]byte
		var m int
		var end error
		if readErr == nil {
			m, end = body.Read(extra[:])
		}
		closeErr := body.Close()
		if readErr != nil || m != 0 || end != io.EOF || closeErr != nil || r.source.ctx.Err() != nil {
			r.source.failure = fault("source_read", "bounded_source_read_incomplete", "uncertain")
			slog.Warn("storage export range held", "stage", "bounded_source_read")
			_ = r.Close()
			return 0, storageupload.ErrHeld
		}
		if r.source.firstByte != nil {
			if err := r.source.firstByte(); err != nil {
				_ = r.Close()
				return 0, err
			}
			r.source.firstByte = nil
		}
		r.position += n
		r.consumed = 0
	}
	n := copy(p, r.buffer[r.consumed:])
	clear(r.buffer[r.consumed : r.consumed+n])
	r.consumed += n
	return n, nil
}

func transactionInputs(read *transactionExport, s *storageupload.State) ([]storageupload.Input, error) {
	rangeBytes, err := models.StorageSourceRangeBytes(s.Request.Plan.TransferProfile)
	if err != nil {
		return nil, storageupload.ErrHeld
	}
	inputs := make([]storageupload.Input, 0, len(s.Request.Plan.Artifacts))
	for _, a := range s.Request.Plan.Artifacts {
		i := -1
		for index, v := range s.Export.Volumes {
			if v.VolumeID == a.VolumeID {
				i = index
			}
		}
		if i < 0 {
			return nil, storageupload.ErrHeld
		}
		v, m := s.Export.Volumes[i], s.Maps[i]
		input := storageupload.Input{Artifact: a}
		if a.Role == "volume_payload" {
			input.Open = func() (io.ReadCloser, error) {
				if read.validate() != nil {
					return nil, storageupload.ErrHeld
				}
				return &rangeReader{source: read, endpoint: v.DataURL, ranges: m.Ranges, rangeBytes: rangeBytes}, nil
			}
		} else {
			payload := ""
			for _, item := range s.Request.Plan.Artifacts {
				if item.VolumeID == a.VolumeID && item.Role == "volume_payload" {
					payload = item.Key
				}
			}
			manifest := volumeManifest{VMNamespace: s.Request.Plan.Source.Namespace, VMUID: s.Request.Plan.Source.VMUID, Format: "vnbui-kubevirt-cbt-v1", BackupType: s.Request.Plan.BackupType, Checkpoint: s.Export.Checkpoint, Volume: v.Name, VirtualSize: m.VirtualSize, Encrypted: s.Request.Plan.Encryption.Format != "none", PayloadKey: payload, StoredExtents: []storedExtent{}}
			if s.Native != nil {
				manifest.VMDefinition = s.Native.EncodedVMDefinition
			}
			var position uint64
			for _, r := range m.Ranges {
				item := storedExtent{DiskOffset: r.Offset, Length: r.Length, ZeroFill: r.ZeroFill}
				if !r.ZeroFill {
					start := position
					item.PayloadOffset = &start
					position += r.Length
				}
				manifest.StoredExtents = append(manifest.StoredExtents, item)
			}
			data, err := json.Marshal(manifest)
			if err != nil || len(data) > 16<<20 {
				return nil, storageupload.ErrHeld
			}
			input.Open = func() (io.ReadCloser, error) {
				if read.validate() != nil {
					return nil, storageupload.ErrHeld
				}
				return io.NopCloser(bytes.NewReader(data)), nil
			}
		}
		inputs = append(inputs, input)
	}
	return inputs, nil
}

type admittedProvider struct {
	storageupload.Provider
	validate func() error
}

func (p *admittedProvider) Begin(ctx context.Context, k string, m map[string]string) (string, error) {
	if p.validate() != nil {
		return "", storageupload.ErrHeld
	}
	return p.Provider.Begin(ctx, k, m)
}
func (p *admittedProvider) Part(ctx context.Context, k, u string, n int, b []byte, h string) (string, error) {
	if p.validate() != nil {
		return "", storageupload.ErrHeld
	}
	return p.Provider.Part(ctx, k, u, n, b, h)
}
func (p *admittedProvider) Complete(ctx context.Context, k, u string, parts []storageupload.Part) (storageupload.ObjectInfo, error) {
	if p.validate() != nil {
		return storageupload.ObjectInfo{}, storageupload.ErrHeld
	}
	return p.Provider.Complete(ctx, k, u, parts)
}
func (p *admittedProvider) Head(ctx context.Context, k string, v *string, tag string) (storageupload.ObjectInfo, error) {
	if p.validate() != nil {
		return storageupload.ObjectInfo{}, storageupload.ErrHeld
	}
	return p.Provider.Head(ctx, k, v, tag)
}
