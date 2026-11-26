//go:build kubevirt

package kubevirt

import (
	"context"
	"errors"
	"time"

	"vnbui/agent/internal/models"
	"vnbui/agent/internal/operationbudget"
	"vnbui/agent/internal/storageupload"
)

// Only unavailable observations qualify. A definitive API refusal, absence or
// malformed response never becomes permission to ignore lost identity evidence.
func safetyReadFault(err error, stage, reason string) *operationFault {
	f := observationFault(stage, err)
	f.Stage, f.Reason = stage, reason
	return f
}

// observationDeadline uses the last complete health inspection, never a partial
// retry's newer scratch measurement. The entire conservative scratch reservation
// remains free in addition to estimated growth and the original closure reserve.
func observationDeadline(s *safetyState, now time.Time) (time.Time, bool) {
	return observationDeadlineAt(s, *s, now, now)
}

// Capture baseline before the API call: freshness is evaluated when observation
// began, while its elapsed transport latency consumes the original window.
func observationDeadlineAt(current *safetyState, baseline safetyState, started, now time.Time) (time.Time, bool) {
	if now.Before(started) || baseline.LastObservation == nil || started.Before(baseline.LastObservation.At) ||
		current.Scratch == nil || baseline.Scratch == nil || current.Native == nil || baseline.Native == nil || len(current.Native.Objects) != 3 || len(baseline.Native.Objects) != 3 ||
		current.Scratch.UID != baseline.Scratch.UID || current.Scratch.LeaseUID != baseline.Scratch.LeaseUID || current.Scratch.ProbeUID != baseline.Scratch.ProbeUID || current.Native.Objects[1].UID != baseline.Native.Objects[1].UID {
		return time.Time{}, false
	}
	copy := *current
	copy.LastObservation = baseline.LastObservation
	s := &copy
	seconds, err := s.Policy.ObservationSeconds()
	o, a := s.LastObservation, s.Scratch
	if err != nil || o == nil || a == nil || now.Before(o.At) || o.Scratch.At.After(o.At) || o.Scratch.CapacityBytes <= 0 ||
		o.Scratch.AvailableBytes > o.Scratch.CapacityBytes || a.RequiredBytes <= 0 || o.Scratch.AvailableBytes <= a.RequiredBytes {
		return time.Time{}, false
	}
	// A new episode needs a currently fresh baseline. Once persisted, its
	// reserved window accounts for ageing evidence without renewing its deadline.
	if s.Uncertainty == nil && s.ReadUncertainty == nil && started.Sub(o.Scratch.At) > 20*time.Second {
		return time.Time{}, false
	}
	// Evidence that was already stale when inspected cannot establish grace.
	if o.At.Sub(o.Scratch.At) > 20*time.Second || now.Sub(o.At) >= time.Duration(seconds)*time.Second {
		return time.Time{}, false
	}
	deadline := started.Add(time.Duration(seconds) * time.Second)
	// Last successful evidence also has an absolute age bound; retries and
	// restarts cannot manufacture a fresh evidence timestamp.
	deadline = earlier(deadline, o.At.Add(time.Duration(seconds)*time.Second))
	deadline = earlier(deadline, o.Scratch.At.Add(time.Duration(seconds)*time.Second))
	deadline = earlier(deadline, s.Progress.Deadline())
	if s.Native != nil && s.Native.Lifetime != nil {
		if !s.Native.Lifetime.Valid() {
			return time.Time{}, false
		}
		if native := s.Native.Lifetime.Deadline(); !native.IsZero() {
			deadline = earlier(deadline, native.Add(-time.Duration(s.Progress.Budget.ClosureSeconds+20)*time.Second))
		}
	}
	silence := s.Progress.Budget.SilenceSeconds
	if s.Progress.Stage == "queued" || s.Progress.Stage == "preparing" {
		silence = s.Progress.Budget.PreparationSeconds
	}
	deadline = earlier(deadline, s.Progress.LastProgressAt.Add(time.Duration(silence)*time.Second))
	baselineSilence := baseline.Progress.Budget.SilenceSeconds
	if baseline.Progress.Stage == "queued" || baseline.Progress.Stage == "preparing" {
		baselineSilence = baseline.Progress.Budget.PreparationSeconds
	}
	deadline = earlier(deadline, baseline.Progress.LastProgressAt.Add(time.Duration(baselineSilence)*time.Second))
	if s.Uncertainty != nil {
		deadline = earlier(deadline, s.Uncertainty.Deadline)
	}
	if s.ReadUncertainty != nil {
		deadline = earlier(deadline, s.ReadUncertainty.Deadline)
	}
	// Bootstrap is an explicit conservative estimate, not a measured write-rate
	// guarantee. Full disk-capacity headroom above protects unobserved CBW growth.
	rate := max(a.PeakGrowthBytesPerSecond, s.Policy.BootstrapBytesPerSecond)
	available := o.Scratch.AvailableBytes - a.RequiredBytes
	fits := func(end time.Time) bool {
		// Include the existing inspection transport guard and next watchdog tick.
		detection := int64(end.Sub(o.Scratch.At)/time.Second) + 21
		reserve, err := operationbudget.GrowthReserve(rate, detection, s.Progress.Budget.ClosureSeconds, s.Policy.ScratchCoefficient)
		return err == nil && available > reserve
	}
	// Find the latest affordable whole second without overflowing byte products.
	lo, hi := int64(0), int64(deadline.Sub(now)/time.Second)
	if !now.Before(deadline) || hi < 1 || !fits(now.Add(time.Second)) {
		return time.Time{}, false
	}
	for lo < hi {
		mid := lo + (hi-lo+1)/2
		if fits(now.Add(time.Duration(mid) * time.Second)) {
			lo = mid
		} else {
			hi = mid - 1
		}
	}
	return now.Add(time.Duration(lo) * time.Second), lo > 0
}

func earlier(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

// observeSafety durably records uncertainty before permitting another read.
// It does not advance useful progress or authorize producer/mutation replay.
func (g *operationSafety) observeSafety(observed error, now time.Time) error {
	return g.observeSafetyAttempt(observed, g.snapshot(), now, now)
}

func (e *Executor) inspectSafetyObservation(ctx context.Context, r *models.StorageTransactionRequest, g *operationSafety) error {
	baseline := g.snapshot()
	started := nativeNow()
	observed := e.inspectSafety(ctx, r, g)
	return g.observeSafetyAttempt(observed, baseline, started, nativeNow())
}

func (g *operationSafety) observeSafetyAttempt(observed error, baseline safetyState, started, completed time.Time) error {
	err := g.update(func(s *safetyState) error {
		if s.Progress.Stage == "complete" || s.SourceClosed {
			return nil
		}
		if s.Stop != nil {
			return s.Fault
		}
		// Completion belongs to the observation; the clock used against current
		// progress must be sampled after acquiring the same lock as ACK writers.
		now := nativeNow()
		if completed.Before(started) || now.Before(completed) {
			return fault("observation", "invalid_budget_or_clock", "refused")
		}
		if reason := safetyExhausted(*s, now); reason != "" {
			return fault(s.Progress.Stage, reason, "refused")
		}
		if s.Uncertainty != nil && (!now.Before(s.Uncertainty.Deadline) || now.Before(s.Uncertainty.StartedAt)) {
			return fault("observation", "observation_budget_exhausted", "refused")
		}
		if observed == nil {
			return nil
		}
		var typed *operationFault
		if !errors.As(observed, &typed) {
			return observed
		}
		f := faultOf(observed)
		if f.Disposition != "transient" || !recoverableObservation(f.Reason) {
			return observed
		}
		deadline, ok := observationDeadlineAt(s, baseline, started, now)
		if !ok {
			return observed
		}
		if s.Uncertainty == nil {
			s.Uncertainty = &observationUncertainty{StartedAt: started.UTC(), Deadline: deadline.UTC(), Fault: f}
		} else if deadline.Before(s.Uncertainty.Deadline) {
			s.Uncertainty.Deadline = deadline.UTC()
		}
		return nil
	})
	return readObservationFailure(g, err)
}

// Only the complete inspector may establish health evidence. A concurrent native
// creation after an early no-native return must never manufacture a healthy view.
func (g *operationSafety) recordSafetyObservation(checked safetyState, sample operationbudget.ScratchSample, started, observedAt time.Time) error {
	return g.update(func(s *safetyState) error {
		if s.Progress.Stage == "complete" || s.SourceClosed {
			return nil
		}
		if s.Stop != nil {
			return s.Fault
		}
		now := nativeNow()
		if observedAt.Before(started) || now.Before(observedAt) {
			return fault("observation", "invalid_budget_or_clock", "refused")
		}
		if reason := safetyExhausted(*s, now); reason != "" {
			return fault("observation", reason, "refused")
		}
		if s.Scratch == nil || checked.Scratch == nil || s.Native == nil || checked.Native == nil || len(s.Native.Objects) != 3 || len(checked.Native.Objects) != 3 ||
			s.Scratch.UID != checked.Scratch.UID || s.Scratch.LeaseUID != checked.Scratch.LeaseUID || s.Scratch.ProbeUID != checked.Scratch.ProbeUID || s.Native.Objects[1].UID != checked.Native.Objects[1].UID {
			return fault("observation", "observation_identity_changed", "refused")
		}
		// Lock contention consumes freshness too. Do not stamp old measurements
		// with the later decision time or let an older inspector clear a newer
		// uncertainty episode.
		if sample.At.IsZero() || now.Sub(sample.At) > 20*time.Second {
			return fault("observation", "scratch_measurement_stale_or_invalid", "refused")
		}
		if (s.LastObservation != nil && s.LastObservation.At.After(started)) ||
			(s.Uncertainty != nil && s.Uncertainty.StartedAt.After(started)) {
			return nil
		}
		s.LastObservation = &safetyObservation{At: observedAt.UTC(), Scratch: sample}
		s.Uncertainty = nil
		return nil
	})
}

// An arbitrary held/persistence error or a known unhealthy probe is not an
// unavailable observation, even if a generic caller labels it transient.
func recoverableObservation(reason string) bool {
	switch reason {
	case "source_status_unavailable", "service_health_unavailable", "scratch_identity_unavailable", "scratch_reservation_unavailable", "scratch_probe_observation_unavailable", "scratch_measurement_unavailable", "native_health_unavailable":
		return true
	}
	return false
}

// retryValidationObservation retries only the caller's complete read-only
// validation. Producer effects and utility binding must remain outside callback.
func (e *Executor) retryValidationObservation(ctx context.Context, state *storageupload.State, observe func(context.Context) error) error {
	g := safetyFrom(ctx)
	if g != nil {
		g.readMu.Lock()
		defer g.readMu.Unlock()
	}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := checkSafety(ctx); err != nil {
			return readObservationFailure(g, err)
		}
		var baseline safetyState
		if g != nil {
			baseline = g.snapshot()
		}
		started := nativeNow()
		attempt, finish := validationObservationContext(ctx, g)
		observed := observe(attempt)
		finish()
		completed := nativeNow()
		if observed == nil {
			if g == nil {
				return nil
			}
			return readObservationFailure(g, g.update(func(s *safetyState) error {
				if s.SourceClosed || s.Progress.Stage == "complete" {
					return nil
				}
				if s.Stop != nil {
					return s.Fault
				}
				now := nativeNow()
				if completed.Before(started) || now.Before(completed) {
					return fault("observation", "invalid_budget_or_clock", "refused")
				}
				if reason := safetyExhausted(*s, now); reason != "" {
					return fault("observation", reason, "refused")
				}
				s.ReadUncertainty = nil
				return nil
			}))
		}
		var f *operationFault
		if g == nil || !errors.As(observed, &f) || f.Disposition != "transient" || !recoverableValidationObservation(f.Reason) {
			return refuseValidationObservation(observed)
		}
		// Persist FIRST uncertainty before any additional API observation. Missing or
		// stale prior safety evidence cannot be repaired by spending unbounded grace.
		if err := g.update(func(s *safetyState) error {
			if s.SourceClosed || s.Progress.Stage == "complete" {
				return observed
			}
			if s.Stop != nil {
				return s.Fault
			}
			now := nativeNow()
			if completed.Before(started) || now.Before(completed) {
				return fault("observation", "invalid_budget_or_clock", "refused")
			}
			if reason := safetyExhausted(*s, now); reason != "" {
				return fault("observation", reason, "refused")
			}
			deadline, ok := observationDeadlineAt(s, baseline, started, now)
			if !ok {
				return observed
			}
			if s.ReadUncertainty == nil {
				s.ReadUncertainty = &observationUncertainty{StartedAt: started.UTC(), Deadline: deadline.UTC(), Fault: faultOf(observed)}
			} else if deadline.Before(s.ReadUncertainty.Deadline) {
				s.ReadUncertainty.Deadline = deadline.UTC()
			}
			return nil
		}); err != nil {
			return readObservationFailure(g, err)
		}
		// Every retry must also pass the complete source/native/scratch inspector.
		// Healthy watchdog inspections never clear the independent read scope.
		health, finish := validationObservationContext(ctx, g)
		inspected := e.inspectSafetyObservation(health, &state.Request, g)
		finish()
		if err := inspected; err != nil {
			return readObservationFailure(g, err)
		}
		snapshot := g.snapshot()
		if snapshot.ReadUncertainty == nil {
			return refuseValidationObservation(observed)
		}
		deadline := snapshot.ReadUncertainty.Deadline
		delay := min(time.Second, deadline.Sub(nativeNow()))
		if delay <= 0 {
			return readObservationFailure(g, fault("observation", "observation_budget_exhausted", "refused"))
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func validationObservationContext(ctx context.Context, g *operationSafety) (context.Context, context.CancelFunc) {
	duration := 20 * time.Second
	if g != nil {
		s := g.snapshot()
		deadline := s.Progress.Deadline()
		if s.Uncertainty != nil {
			deadline = earlier(deadline, s.Uncertainty.Deadline)
		}
		if s.ReadUncertainty != nil {
			deadline = earlier(deadline, s.ReadUncertainty.Deadline)
		}
		duration = min(duration, max(time.Duration(0), deadline.Sub(nativeNow())))
	}
	return context.WithTimeout(ctx, duration)
}

func readObservationFailure(g *operationSafety, err error) error {
	if err == nil {
		return nil
	}
	if g == nil {
		return refuseValidationObservation(err)
	}
	var f *operationFault
	if errors.As(err, &f) && f.Reason == "observation_budget_exhausted" {
		if u := g.snapshot().ReadUncertainty; u != nil && u.Fault != nil {
			original := *u.Fault
			original.Stage, original.Disposition = "observation", "refused"
			return &original
		}
	}
	return refuseValidationObservation(err)
}

func recoverableValidationObservation(reason string) bool {
	switch reason {
	case "export_native_observation_unavailable", "export_candidates_observation_unavailable", "export_service_observation_unavailable", "export_vmi_observation_unavailable", "export_token_observation_unavailable",
		"native_tracker_observation_unavailable", "native_backup_observation_unavailable", "native_scratch_observation_unavailable", "native_vmi_observation_unavailable",
		"source_vm_observation_unavailable", "source_vmi_observation_unavailable", "source_volume_observation_unavailable", "parent_tracker_observation_unavailable":
		return true
	}
	return false
}

// The transaction runner retries transient step failures. Denied local grace is
// therefore a permanent refusal for this attempt, not another transient that
// could later acquire fresher evidence and resurrect an already unsafe episode.
func refuseValidationObservation(err error) error {
	if err == nil {
		return nil
	}
	// These exact control sentinels belong to the outer preparation/lifetime
	// state machine. Returning them grants no helper retry or renewed grace.
	if err == exportPending || err == errExportLifetime {
		return err
	}
	var f *operationFault
	if errors.As(err, &f) {
		if f.Disposition != "transient" {
			return err
		}
		out := *f
		out.Stage, out.Disposition = "observation", "refused"
		return &out
	}
	return fault("observation", "validation_observation_refused", "refused")
}
