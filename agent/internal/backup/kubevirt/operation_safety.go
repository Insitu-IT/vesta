//go:build kubevirt

package kubevirt

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math"
	"os"
	"path/filepath"
	"sync"
	"time"

	"vnbui/agent/internal/models"
	"vnbui/agent/internal/operationbudget"
	"vnbui/agent/internal/storageupload"
)

type scratchReservation struct {
	Name                     string                         `json:"name"`
	UID                      string                         `json:"uid"`
	Node                     string                         `json:"node"`
	RequiredBytes            int64                          `json:"required_bytes"`
	LeaseName                string                         `json:"lease_name"`
	LeaseUID                 string                         `json:"lease_uid"`
	ProbeName                string                         `json:"probe_name"`
	ProbeImage               string                         `json:"probe_image"`
	ProbeUID                 string                         `json:"probe_uid"`
	Intent                   string                         `json:"intent"`
	Initial                  *operationbudget.ScratchSample `json:"initial,omitempty"`
	Latest                   *operationbudget.ScratchSample `json:"latest,omitempty"`
	PeakGrowthBytesPerSecond int64                          `json:"peak_growth_bytes_per_second"`
}

type nativeSafetyStop struct {
	At              time.Time `json:"at"`
	Phase           string    `json:"phase"`
	ResourceVersion string    `json:"resource_version,omitempty"`
	HTTPStatus      int       `json:"http_status,omitempty"`
}

type safetyObservation struct {
	At      time.Time                     `json:"at"`
	Scratch operationbudget.ScratchSample `json:"scratch"`
}

type observationUncertainty struct {
	StartedAt time.Time       `json:"started_at"`
	Deadline  time.Time       `json:"deadline"`
	Fault     *operationFault `json:"fault"`
}

type safetyState struct {
	LastObservation     *safetyObservation         `json:"last_observation,omitempty"`
	ReadUncertainty     *observationUncertainty    `json:"read_observation_uncertainty,omitempty"`
	Uncertainty         *observationUncertainty    `json:"observation_uncertainty,omitempty"`
	Schema              int                        `json:"schema"`
	RequestSHA256       string                     `json:"request_sha256"`
	Policy              operationbudget.Policy     `json:"policy"`
	Progress            operationbudget.Progress   `json:"progress"`
	Scratch             *scratchReservation        `json:"scratch,omitempty"`
	Native              *storageupload.NativeState `json:"native,omitempty"`
	Map                 *operationFault            `json:"map_progress,omitempty"`
	Fault               *operationFault            `json:"fault,omitempty"`
	Stop                *nativeSafetyStop          `json:"stop,omitempty"`
	SourceClosed        bool                       `json:"source_closed"`
	ServiceProbeURL     string                     `json:"service_probe_url,omitempty"`
	PublicationDeadline *time.Time                 `json:"publication_deadline,omitempty"`
	FirstByteAt         *time.Time                 `json:"first_byte_at,omitempty"`
	FirstACKAt          *time.Time                 `json:"first_ack_at,omitempty"`
	AcknowledgedBytes   int64                      `json:"acknowledged_bytes"`
}

// The safety record has an independent lock and fsync path. UploadAll owns the
// payload journal mutex while doing IO; a safety stop must not wait behind it.
// The runner owns the directory lock for the entire process lifetime.
type operationSafety struct {
	finalizeObservation *finalizeSafetyObservation // nonserialized, reconstructed only from a validated journal Snapshot
	mu                  sync.Mutex
	closeMu             sync.Mutex
	readMu              sync.Mutex
	path                string
	last                []byte
	state               safetyState
	poisoned            bool
}

func requestDigest(r *models.StorageTransactionRequest) string {
	b, _ := json.Marshal(r)
	d := sha256.Sum256(b)
	return hex.EncodeToString(d[:])
}

func selectedBytes(r *models.StorageTransactionRequest) (int64, error) {
	var total int64
	for _, v := range r.Plan.Source.Volumes {
		if v.CapacityBytes <= 0 || total > math.MaxInt64-v.CapacityBytes {
			return 0, operationbudget.ErrEstimate
		}
		total += v.CapacityBytes
	}
	if total == 0 {
		return 0, operationbudget.ErrEstimate
	}
	return total, nil
}

func openSafety(root string, r *models.StorageTransactionRequest) (*operationSafety, error) {
	g := &operationSafety{path: filepath.Join(root, r.ReservationID, "operation-safety.json")}
	info, err := os.Lstat(g.path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > 128<<10 {
		return nil, storageupload.ErrHeld
	}
	b, err := os.ReadFile(g.path)
	if err != nil {
		return nil, storageupload.ErrHeld
	}
	var disk struct {
		SHA256 string      `json:"sha256"`
		State  safetyState `json:"state"`
	}
	if decodeSafety(b, &disk, 128<<10) != nil {
		return nil, storageupload.ErrHeld
	}
	canonical, _ := json.Marshal(disk.State)
	hash := sha256.Sum256(canonical)
	if hex.EncodeToString(hash[:]) != disk.SHA256 || disk.State.Schema != 1 || disk.State.RequestSHA256 != requestDigest(r) || !disk.State.Policy.Valid() || !disk.State.Progress.Valid() {
		return nil, storageupload.ErrHeld
	}
	g.last, g.state = b, disk.State
	return g, nil
}

func decodeSafety(b []byte, dst any, limit int) error {
	if _, err := models.DecodeStorageControlJSONBounded(b, limit); err != nil {
		return err
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(dst); err != nil {
		return err
	}
	if d.Decode(new(interface{})) != io.EOF {
		return storageupload.ErrHeld
	}
	return nil
}

func (e *Executor) createSafety(root string, r *models.StorageTransactionRequest) (*operationSafety, error) {
	policy := e.cfg.SafetyPolicy()
	size, err := selectedBytes(r)
	if err != nil {
		return nil, err
	}
	part, err := models.StorageSourceRangeBytes(r.Plan.TransferProfile)
	if err != nil {
		return nil, err
	}
	ceiling := time.Duration(e.cfg.KubevirtNativeTTLSeconds) * time.Second
	if v := e.cfg.KubevirtTransactionTimeoutSeconds; v > 0 && time.Duration(v)*time.Second < ceiling {
		ceiling = time.Duration(v) * time.Second
	}
	b, err := policy.Estimate(size, int64(part), 0, ceiling)
	var refused *operationFault
	if errors.Is(err, operationbudget.ErrWindow) {
		// Persist the rejected estimate and its reason with the original
		// request, so an admission failure cannot disappear into generic
		// pending status. This window never authorizes native work.
		refused = fault("admission", "estimated_window_exceeds_native_limit", "refused")
		b, err = policy.Estimate(size, int64(part), 0, time.Duration(math.MaxInt64))
	}
	if err != nil {
		return nil, fault("admission", "operation_estimate_invalid", "refused")
	}
	now := nativeNow().UTC()
	probe, err := e.sourceHealthURL(r)
	if err != nil {
		return nil, err
	}
	g := &operationSafety{path: filepath.Join(root, r.ReservationID, "operation-safety.json"), state: safetyState{
		Schema: 1, RequestSHA256: requestDigest(r), Policy: policy, ServiceProbeURL: probe,
		Progress: operationbudget.Progress{StartedAt: now, LastProgressAt: now, Stage: "queued", Budget: b},
	}}
	if refused != nil {
		g.state.Fault = refused
		g.state.Stop = &nativeSafetyStop{At: now, Phase: "no_native_started"}
	}
	if err := g.update(func(*safetyState) error { return nil }); err != nil {
		return nil, err
	}
	return g, nil
}

func (g *operationSafety) snapshot() safetyState {
	g.mu.Lock()
	defer g.mu.Unlock()
	b, _ := json.Marshal(g.state)
	var out safetyState
	_ = json.Unmarshal(b, &out)
	return out
}

func (g *operationSafety) update(change func(*safetyState) error) (err error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.poisoned {
		return storageupload.ErrHeld
	}
	b, _ := json.Marshal(g.state)
	var next safetyState
	if json.Unmarshal(b, &next) != nil {
		return storageupload.ErrHeld
	}
	if err = change(&next); err != nil {
		return err
	}
	// Failed writes poison this handle; its in-memory state must not authorize
	// work that never reached stable storage.
	defer func() {
		if err != nil {
			g.poisoned = true
			g.finalizeObservation = nil
		}
	}()
	old, readErr := os.ReadFile(g.path)
	if g.last == nil {
		if !errors.Is(readErr, os.ErrNotExist) {
			return storageupload.ErrHeld
		}
	} else if readErr != nil || !bytes.Equal(old, g.last) {
		return storageupload.ErrHeld
	}
	if !next.Policy.Valid() || !next.Progress.Valid() {
		return storageupload.ErrHeld
	}
	b, err = json.Marshal(next)
	if err != nil {
		return storageupload.ErrHeld
	}
	hash := sha256.Sum256(b)
	data, err := json.Marshal(struct {
		SHA256 string      `json:"sha256"`
		State  safetyState `json:"state"`
	}{hex.EncodeToString(hash[:]), next})
	if err != nil || len(data) > 128<<10 {
		return storageupload.ErrHeld
	}
	f, err := os.CreateTemp(filepath.Dir(g.path), ".safety-")
	if err != nil {
		return storageupload.ErrHeld
	}
	defer os.Remove(f.Name())
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil || closeErr != nil {
		return storageupload.ErrHeld
	}
	if err = os.Rename(f.Name(), g.path); err != nil {
		return storageupload.ErrHeld
	}
	dir, err := os.Open(filepath.Dir(g.path))
	if err != nil {
		return storageupload.ErrHeld
	}
	err = dir.Sync()
	_ = dir.Close()
	if err != nil {
		return storageupload.ErrHeld
	}
	g.state, g.last = next, data
	if next.Stop != nil || next.Progress.Stage == "complete" {
		g.finalizeObservation = nil
	}
	return nil
}

func (g *operationSafety) advance(stage string, cursor int64) error {
	return g.update(func(s *safetyState) error {
		if s.Stop != nil {
			return storageupload.ErrHeld
		}
		_, err := s.Progress.Advance(nativeNow(), stage, cursor)
		return err
	})
}

var errOperationPublished = errors.New("operation publication already acknowledged")

// Only the runner's acknowledged publication path can make this transition.
// Keep any concurrent stop record as historical evidence, not current status.
func (g *operationSafety) published() error {
	return g.update(func(s *safetyState) error {
		s.SourceClosed = true
		_, err := s.Progress.Advance(nativeNow(), "complete", 0)
		return err
	})
}

func (g *operationSafety) stop(f *operationFault) error {
	if f == nil {
		f = fault("reconciling", "retained_safety_stop", "uncertain")
	}
	return g.update(func(s *safetyState) error {
		if s.Progress.Stage == "complete" {
			return errOperationPublished
		}
		if s.Stop == nil {
			s.Fault = f
			s.Stop = &nativeSafetyStop{At: nativeNow().UTC(), Phase: "requested"}
		}
		return nil
	})
}

func (g *operationSafety) diagnostic() map[string]interface{} {
	s := g.snapshot()
	f := s.Fault
	if f == nil {
		f = fault(s.Progress.Stage, "retained_safety_stop", "uncertain")
	}
	d := map[string]interface{}{"stage": f.Stage, "reason": f.Reason, "disposition": f.Disposition}
	if f.HTTPStatus != 0 {
		d["http_status"] = f.HTTPStatus
	}
	if f.Volume != 0 {
		d["volume"] = f.Volume
	}
	if f.Page != 0 {
		d["page"] = f.Page
	}
	if f.Offset != 0 {
		d["offset"] = f.Offset
	}
	if f.RawRanges != 0 {
		d["raw_ranges"] = f.RawRanges
	}
	if f.StoredRanges != 0 {
		d["stored_ranges"] = f.StoredRanges
	}
	if s.Uncertainty != nil {
		d["observation_uncertain_since"] = s.Uncertainty.StartedAt.UTC().Format(time.RFC3339Nano)
		d["observation_deadline"] = s.Uncertainty.Deadline.UTC().Format(time.RFC3339Nano)
		d["observation_reason"] = s.Uncertainty.Fault.Reason
	}
	if s.LastObservation != nil {
		d["last_trustworthy_observation_at"] = s.LastObservation.At.UTC().Format(time.RFC3339Nano)
	}
	if s.ReadUncertainty != nil {
		d["read_observation_uncertain_since"] = s.ReadUncertainty.StartedAt.UTC().Format(time.RFC3339Nano)
		d["read_observation_deadline"] = s.ReadUncertainty.Deadline.UTC().Format(time.RFC3339Nano)
		d["read_observation_reason"] = s.ReadUncertainty.Fault.Reason
	}
	if f.ExpectedNativeVolumes != nil {
		d["expected_native_volumes"] = *f.ExpectedNativeVolumes
	}
	if f.ObservedNativeVolumes != nil {
		d["observed_native_volumes"] = *f.ObservedNativeVolumes
	}
	if f.ObservedExportLinks != nil {
		d["observed_export_links"] = *f.ObservedExportLinks
	}
	d["acknowledged_bytes"] = s.AcknowledgedBytes
	d["last_progress_at"] = s.Progress.LastProgressAt.UTC().Format(time.RFC3339Nano)
	d["started_at"] = s.Progress.StartedAt.UTC().Format(time.RFC3339Nano)
	d["deadline"] = s.Progress.Deadline().UTC().Format(time.RFC3339Nano)
	d["no_progress_budget_seconds"] = s.Progress.Budget.SilenceSeconds
	if s.Progress.Stage == "queued" || s.Progress.Stage == "preparing" {
		d["no_progress_budget_seconds"] = s.Progress.Budget.PreparationSeconds
	}
	d["no_progress_seconds"] = max(int64(0), int64(nativeNow().Sub(s.Progress.LastProgressAt)/time.Second))
	if s.SourceClosed && s.PublicationDeadline != nil {
		d["producer_deadline"] = d["deadline"]
		d["deadline"] = s.PublicationDeadline.UTC().Format(time.RFC3339Nano)
	}
	d["run_budget_seconds"] = s.Progress.Budget.RunSeconds
	d["estimated_bytes"] = s.Progress.Budget.ExpectedBytes
	d["estimated_bytes_per_second"] = s.Progress.Budget.BytesPerSecond
	if s.FirstByteAt != nil {
		d["first_byte_at"] = s.FirstByteAt.UTC().Format(time.RFC3339Nano)
	}
	if s.FirstACKAt != nil {
		d["first_ack_at"] = s.FirstACKAt.UTC().Format(time.RFC3339Nano)
	}
	if s.Map != nil {
		d["last_map_volume"], d["last_map_page"], d["last_map_offset"] = s.Map.Volume, s.Map.Page, s.Map.Offset
		d["last_map_raw_ranges"], d["last_map_stored_ranges"] = s.Map.RawRanges, s.Map.StoredRanges
	}
	if s.Stop != nil {
		d["native_stop_phase"] = s.Stop.Phase
		d["stop_at"] = s.Stop.At.UTC().Format(time.RFC3339Nano)
		if s.Stop.HTTPStatus != 0 {
			d["native_stop_http_status"] = s.Stop.HTTPStatus
		}
	}
	if s.Scratch != nil {
		d["scratch_required_bytes"] = s.Scratch.RequiredBytes
		d["scratch_peak_growth_bytes_per_second"] = s.Scratch.PeakGrowthBytesPerSecond
		if s.Scratch.Latest != nil {
			d["scratch_available_bytes"] = s.Scratch.Latest.AvailableBytes
			if s.Scratch.PeakGrowthBytesPerSecond > 0 {
				d["scratch_time_to_full_seconds"] = s.Scratch.Latest.AvailableBytes / s.Scratch.PeakGrowthBytesPerSecond
			}
			d["scratch_sample_at"] = s.Scratch.Latest.At.UTC().Format(time.RFC3339Nano)
		}
	}
	return d
}

type safetyContextKey struct{}

func safetyFrom(ctx context.Context) *operationSafety {
	g, _ := ctx.Value(safetyContextKey{}).(*operationSafety)
	return g
}
func checkSafety(ctx context.Context) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if g := safetyFrom(ctx); g != nil {
		s := g.snapshot()
		if s.Stop != nil {
			return storageupload.ErrHeld
		}
		if reason := safetyExhausted(s, nativeNow()); reason != "" {
			return fault(s.Progress.Stage, reason, "refused")
		}
	}
	return nil
}

func (g *operationSafety) bindNative(n *storageupload.NativeState) error {
	if n == nil {
		return nil
	}
	return g.update(func(s *safetyState) error {
		if s.Native != nil {
			if len(s.Native.Objects) != len(n.Objects) {
				return storageupload.ErrHeld
			}
			for i, old := range s.Native.Objects {
				if old.Phase == "observed" && (n.Objects[i].UID != old.UID || n.Objects[i].Name != old.Name || n.Objects[i].Phase != "observed") {
					return storageupload.ErrHeld
				}
			}
		}
		copy := *n
		copy.VMDefinition = "" // no guest definition or credentials in this record
		s.Native = &copy
		return nil
	})
}

func safetyExhausted(s safetyState, now time.Time) string {
	if s.SourceClosed {
		if s.Progress.Stage == "complete" {
			return ""
		}
		if s.PublicationDeadline == nil || !now.Before(*s.PublicationDeadline) {
			return "publication_budget_exhausted"
		}
		return ""
	}
	if s.ReadUncertainty != nil && (now.Before(s.ReadUncertainty.StartedAt) || !now.Before(s.ReadUncertainty.Deadline)) {
		return "observation_budget_exhausted"
	}
	if s.Uncertainty != nil && (now.Before(s.Uncertainty.StartedAt) || !now.Before(s.Uncertainty.Deadline)) {
		return "observation_budget_exhausted"
	}
	return s.Progress.Exhausted(now)
}

func (g *operationSafety) sourceClosed(completed time.Time) error {
	return g.update(func(s *safetyState) error {
		if s.SourceClosed || s.Progress.Stage == "complete" {
			return nil
		}
		if s.Stop != nil {
			return storageupload.ErrHeld
		}
		// The terminal provider read may have started before a deadline and ended
		// after it. Recheck atomically before producer closure can grant publication.
		now := nativeNow()
		if now.Before(completed) {
			return fault("finalizing", "invalid_budget_or_clock", "refused")
		}
		if reason := safetyExhausted(*s, now); reason != "" {
			return fault("finalizing", reason, "refused")
		}
		if !s.SourceClosed {
			deadline := now.Add(time.Duration(max(s.Progress.Budget.ClosureSeconds, s.Progress.Budget.SilenceSeconds)) * time.Second).UTC()
			s.SourceClosed, s.PublicationDeadline = true, &deadline
			_, err := s.Progress.Advance(now, "publishing", 0)
			return err
		}
		return nil
	})
}
