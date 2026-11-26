//go:build kubevirt

package kubevirt

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/runtime"
	ktesting "k8s.io/client-go/testing"
	"vnbui/agent/internal/operationbudget"
	"vnbui/agent/internal/storageupload"
)

// Exercise the same ordering as the customer reproducer: the observer finishes,
// an ACK advances durable progress, then the observer acquires the state lock.
func TestObservationCompletionBeforeConcurrentACK(t *testing.T) {
	for _, kind := range []string{"healthy", "unavailable", "measurement", "closure"} {
		t.Run(kind, func(t *testing.T) {
			_, _, g := recoveryFixture(t)
			checked := g.snapshot()
			started := nativeNow()
			completed := started.Add(time.Second)
			decision := completed.Add(time.Millisecond)
			nativeNow = func() time.Time { return decision }
			locked, release := make(chan struct{}), make(chan struct{})
			ack := make(chan error, 1)
			go func() {
				ack <- g.update(func(s *safetyState) error {
					_, err := s.Progress.Advance(decision, "transferring", 1)
					close(locked)
					<-release
					return err
				})
			}()
			<-locked
			observation := make(chan error, 1)
			go func() {
				switch kind {
				case "healthy":
					observation <- g.observeSafetyAttempt(nil, checked, started, completed)
				case "unavailable":
					observation <- g.observeSafetyAttempt(fault("native", "native_health_unavailable", "transient"), checked, started, completed)
				case "measurement":
					observation <- g.recordSafetyObservation(checked, checked.LastObservation.Scratch, started, completed)
				case "closure":
					observation <- g.sourceClosed(completed)
				}
			}()
			close(release)
			if err := <-ack; err != nil {
				t.Fatal(err)
			}
			if err := <-observation; err != nil {
				t.Fatal("healthy ACK ordering was treated as clock regression", err)
			}
			after := g.snapshot()
			if after.Stop != nil || !after.Progress.Deadline().Equal(checked.Progress.Deadline()) || !after.Progress.LastProgressAt.Equal(decision) {
				t.Fatal("observer stopped or renewed original operation", after)
			}
			if kind == "measurement" && (!after.LastObservation.At.Equal(completed) || after.LastObservation.Scratch != checked.LastObservation.Scratch) {
				t.Fatal("measurement was retimestamped with decision time")
			}
			if kind == "unavailable" && (after.Uncertainty == nil || !after.Uncertainty.StartedAt.Equal(started)) {
				t.Fatal("uncertainty lost original acquisition time")
			}
		})
	}
}

func TestObservationDecisionRejectsRegressionAndExpiredLockWait(t *testing.T) {
	for _, kind := range []string{"healthy", "unavailable", "measurement", "closure"} {
		for _, boundary := range []string{"clock", "deadline", "silence", "uncertainty"} {
			t.Run(kind+"/"+boundary, func(t *testing.T) {
				_, _, g := recoveryFixture(t)
				checked := g.snapshot()
				started := nativeNow()
				completed := started.Add(time.Second)
				decision := completed.Add(-time.Millisecond)
				switch boundary {
				case "deadline":
					decision = checked.Progress.Deadline()
				case "silence":
					decision = checked.Progress.LastProgressAt.Add(time.Duration(checked.Progress.Budget.PreparationSeconds) * time.Second)
				case "uncertainty":
					decision = completed.Add(time.Second)
					if err := g.update(func(s *safetyState) error {
						s.Uncertainty = &observationUncertainty{StartedAt: started, Deadline: decision}
						return nil
					}); err != nil {
						t.Fatal(err)
					}
				}
				nativeNow = func() time.Time { return decision }
				var err error
				switch kind {
				case "healthy":
					err = g.observeSafetyAttempt(nil, checked, started, completed)
				case "unavailable":
					err = g.observeSafetyAttempt(fault("native", "native_health_unavailable", "transient"), checked, started, completed)
				case "measurement":
					err = g.recordSafetyObservation(checked, checked.LastObservation.Scratch, started, completed)
				case "closure":
					err = g.sourceClosed(completed)
				}
				if err == nil || (boundary == "clock" && faultOf(err).Reason != "invalid_budget_or_clock") {
					t.Fatal("invalid decision granted authority", err)
				}
				if after := g.snapshot(); after.SourceClosed || after.PublicationDeadline != nil || after.Progress != checked.Progress {
					t.Fatal("refusal altered progress or granted publication", after)
				}
			})
		}
	}
}

func TestValidationCompletionBeforeConcurrentACK(t *testing.T) {
	for _, unavailable := range []bool{false, true} {
		t.Run(map[bool]string{false: "healthy", true: "unavailable"}[unavailable], func(t *testing.T) {
			e, request, g := recoveryFixture(t)
			before := g.snapshot()
			completed := nativeNow().Add(time.Second)
			decision := completed.Add(time.Millisecond)
			calls := 0
			var sampled atomic.Bool
			err := e.retryValidationObservation(context.WithValue(context.Background(), safetyContextKey{}, g), &storageupload.State{Request: *request}, func(context.Context) error {
				calls++
				if calls == 1 {
					// Sample completion first, then acknowledge progress before the
					// caller can lock its state. Subsequent clock reads see decision.
					nativeNow = func() time.Time {
						if sampled.CompareAndSwap(false, true) {
							if err := g.advance("transferring", 1); err != nil {
								t.Fatal(err)
							}
							return completed
						}
						return decision
					}
					if unavailable {
						return fault("export_token", "export_token_observation_unavailable", "transient")
					}
				}
				return nil
			})
			if err != nil || calls != map[bool]int{false: 1, true: 2}[unavailable] {
				t.Fatal("ACK ordering broke validation recovery", err, calls)
			}
			after := g.snapshot()
			if after.Stop != nil || after.ReadUncertainty != nil || !after.Progress.Deadline().Equal(before.Progress.Deadline()) || !after.Progress.LastProgressAt.Equal(decision) {
				t.Fatal("validation changed progress or retained healthy read", after)
			}
		})
	}
}

func TestDelayedMeasurementKeepsAcquisitionFreshness(t *testing.T) {
	_, _, g := recoveryFixture(t)
	before := g.snapshot()
	completed := nativeNow()
	nativeNow = func() time.Time { return completed.Add(21 * time.Second) }
	if err := g.recordSafetyObservation(before, before.LastObservation.Scratch, completed, completed); faultOf(err).Reason != "scratch_measurement_stale_or_invalid" {
		t.Fatal("lock wait refreshed stale scratch measurement", err)
	}
	if !g.snapshot().LastObservation.At.Equal(before.LastObservation.At) {
		t.Fatal("stale measurement replaced healthy evidence")
	}
}

func TestOlderInspectorCannotClearNewerUncertainty(t *testing.T) {
	e, request, g := recoveryFixture(t)
	baseline := g.snapshot()
	base := nativeNow()
	now := base.Add(time.Second)
	nativeNow = func() time.Time { return now }
	var episode observationUncertainty
	dyn := e.dynamic.(interface {
		PrependReactor(string, string, ktesting.ReactionFunc)
	})
	dyn.PrependReactor("get", "virtualmachinebackups", func(ktesting.Action) (bool, runtime.Object, error) {
		// Inspector A already observed the source and scratch. A competing
		// inspector now reports unavailable source health before A finishes.
		now = base.Add(2 * time.Second)
		if err := g.observeSafetyAttempt(fault("source_health", "source_status_unavailable", "transient"), baseline, now, now); err != nil {
			t.Fatal(err)
		}
		episode = *g.snapshot().Uncertainty
		now = base.Add(3 * time.Second)
		return false, nil, nil
	})
	if err := e.inspectSafetyObservation(context.Background(), request, g); err != nil {
		t.Fatal(err)
	}
	after := g.snapshot()
	if after.Uncertainty == nil || !after.Uncertainty.StartedAt.Equal(episode.StartedAt) || !after.Uncertainty.Deadline.Equal(episode.Deadline) || after.Uncertainty.Fault.Reason != episode.Fault.Reason || !after.LastObservation.At.Equal(baseline.LastObservation.At) {
		t.Fatal("older source observation cleared newer outage or replaced evidence", after.Uncertainty)
	}
}

func TestOlderMeasurementCannotReplaceNewerInspection(t *testing.T) {
	_, _, g := recoveryFixture(t)
	baseline := g.snapshot()
	base := nativeNow()
	now := base.Add(2 * time.Second)
	nativeNow = func() time.Time { return now }
	newer := baseline.LastObservation.Scratch
	newer.At = now
	if err := g.recordSafetyObservation(baseline, newer, now, now); err != nil {
		t.Fatal(err)
	}
	now = base.Add(3 * time.Second)
	if err := g.recordSafetyObservation(baseline, baseline.LastObservation.Scratch, base.Add(time.Second), now); err != nil {
		t.Fatal(err)
	}
	if after := g.snapshot(); after.LastObservation.Scratch != newer || !after.LastObservation.At.Equal(newer.At) {
		t.Fatal("older inspection replaced newer evidence")
	}
}

func TestOutOfOrderScratchRetainsNewestAndConservativeGrowth(t *testing.T) {
	base := time.Date(2026, 11, 11, 6, 10, 31, 0, time.UTC)
	newer := operationbudget.ScratchSample{At: base.Add(time.Second), AvailableBytes: 800, CapacityBytes: 2000}
	s := safetyState{Scratch: &scratchReservation{Initial: &newer, Latest: &newer}}
	older := operationbudget.ScratchSample{At: base, AvailableBytes: 1000, CapacityBytes: 2000}
	if err := updateScratchGrowth(&s, older); err != nil {
		t.Fatal(err)
	}
	if *s.Scratch.Latest != newer || s.Scratch.PeakGrowthBytesPerSecond != 200 {
		t.Fatal("old sample reset newest evidence or hid observed growth", s.Scratch)
	}
	older.AvailableBytes = 700
	if err := updateScratchGrowth(&s, older); err != nil {
		t.Fatal(err)
	}
	if *s.Scratch.Latest != newer || s.Scratch.PeakGrowthBytesPerSecond != 200 {
		t.Fatal("late sample reduced conservative growth")
	}
}
