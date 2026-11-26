package operationbudget

import (
	"encoding/json"
	"errors"
	"math"
	"testing"
	"time"
)

func TestEstimateScalesWithBytesAndQualifiedThroughput(t *testing.T) {
	p := DefaultPolicy()
	p.BootstrapBytesPerSecond = 1 << 20
	small, err := p.Estimate(1<<30, 32<<20, 0, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	large, err := p.Estimate(2<<30, 32<<20, 0, 24*time.Hour)
	if err != nil || large.RunSeconds-small.RunSeconds != 3*1024 {
		t.Fatalf("budget did not scale with work: %+v %+v %v", small, large, err)
	}
	fast, err := p.Estimate(2<<30, 32<<20, 2<<20, 24*time.Hour)
	if err != nil || fast.RunSeconds != small.RunSeconds || fast.RateSource != "successful_same_scope" {
		t.Fatalf("qualified throughput not reflected: %+v %v", fast, err)
	}
	if small.RateSource != "configured_bootstrap" || small.ClosureSeconds != 180 {
		t.Fatalf("fallback/closure reserve missing: %+v", small)
	}
}

func TestEstimateRefusesInsufficientHardWindow(t *testing.T) {
	p := DefaultPolicy()
	b, err := p.Estimate(512<<20, 32<<20, 0, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	window := time.Duration(b.RunSeconds+b.ClosureSeconds) * time.Second
	if _, err = p.Estimate(512<<20, 32<<20, 0, window-time.Second); !errors.Is(err, ErrWindow) {
		t.Fatalf("expected explicit refusal, got %v", err)
	}
	if _, err = p.Estimate(512<<20, 32<<20, 0, window); err != nil {
		t.Fatal(err)
	}
}

func TestInvalidEstimatesCannotOverflowOrDisableLimits(t *testing.T) {
	for _, factor := range []float64{0, -1, math.NaN(), math.Inf(1), 101} {
		p := DefaultPolicy()
		p.TimeCoefficient = factor
		if _, err := p.Estimate(1, 1, 0, time.Hour); err == nil {
			t.Fatalf("invalid coefficient accepted: %v", factor)
		}
	}
	p := DefaultPolicy()
	p.BootstrapBytesPerSecond = 1
	if _, err := p.Estimate(math.MaxInt64, 32<<20, 0, 24*time.Hour); err == nil {
		t.Fatal("overflowing transfer estimate accepted")
	}
	if _, err := p.ScratchBytes(math.MaxInt64); err == nil {
		t.Fatal("overflowing scratch requirement accepted")
	}
	p.ScratchCoefficient = 1
	if actual, err := p.ScratchBytes(1<<53 + 1); err != nil || actual != 1<<53+1 {
		t.Fatalf("large byte count lost precision: %d %v", actual, err)
	}
}

func TestScratchAndGrowthReserveUseDistinctMetrics(t *testing.T) {
	p := DefaultPolicy()
	bytes, err := p.ScratchBytes(50 << 30)
	if err != nil || bytes != 60<<30 {
		t.Fatalf("wrong worst-case reserve: %d %v", bytes, err)
	}
	margin, err := GrowthReserve(4<<20, 5, 30, 3)
	if err != nil || margin != 420<<20 {
		t.Fatalf("wrong growth/detection/closure margin: %d %v", margin, err)
	}
	if _, err := GrowthReserve(math.MaxInt64, 5, 30, 3); err == nil {
		t.Fatal("growth overflow accepted")
	}
}

func TestProgressRetryAndRestartDoNotRenewDeadline(t *testing.T) {
	start := time.Date(2026, 11, 7, 0, 0, 0, 0, time.UTC)
	b, err := DefaultPolicy().Estimate(512<<20, 32<<20, 0, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	p := Progress{StartedAt: start, LastProgressAt: start, Stage: "queued", Budget: b}
	if reason := p.Exhausted(start.Add(time.Duration(b.PreparationSeconds) * time.Second)); reason != "admission_wait_exhausted" {
		t.Fatalf("unbounded queue wait: %s", reason)
	}
	if changed, err := p.Advance(start.Add(time.Second), "mapping", 512); err != nil || !changed {
		t.Fatal("valid map progress refused", err)
	}
	stamp := p.LastProgressAt
	for _, cursor := range []int64{0, 512} {
		if changed, err := p.Advance(stamp.Add(time.Minute), "mapping", cursor); err != nil || changed {
			t.Fatal("repeated or backward map reset progress", err)
		}
	}
	body, _ := json.Marshal(p)
	var reopened Progress
	if json.Unmarshal(body, &reopened) != nil || !reopened.Valid() || !reopened.Deadline().Equal(p.Deadline()) {
		t.Fatal("restart changed pinned budget")
	}
	if reason := reopened.Exhausted(stamp.Add(time.Duration(b.SilenceSeconds) * time.Second)); reason != "no_progress_budget_exhausted" {
		t.Fatalf("silence not bounded: %s", reason)
	}
	if changed, err := reopened.Advance(p.Deadline().Add(-time.Second), "transferring", 1); err != nil || !changed {
		t.Fatal(err)
	}
	if reason := reopened.Exhausted(p.Deadline()); reason != "operation_budget_exhausted" {
		t.Fatalf("progress renewed absolute budget: %s", reason)
	}
}

func TestObservationBudgetPolicyPreservesLegacyAndBoundsCoefficient(t *testing.T) {
	p := DefaultPolicy()
	if seconds, err := p.ObservationSeconds(); err != nil || seconds != 180 {
		t.Fatal(seconds, err)
	}
	p.ObservationCoefficient = 0
	if !p.Valid() {
		t.Fatal("older policy rejected")
	}
	if _, err := p.ObservationSeconds(); err == nil {
		t.Fatal("older policy silently enabled grace")
	}
	b, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]interface{}
	if json.Unmarshal(b, &fields) != nil {
		t.Fatal("invalid policy JSON")
	}
	if _, found := fields["observation_coefficient"]; found {
		t.Fatal("legacy canonical policy checksum changed")
	}
	for _, factor := range []float64{-1, 0.5, math.NaN(), math.Inf(1), 101} {
		p.ObservationCoefficient = factor
		if p.Valid() {
			t.Fatal("invalid observation coefficient accepted", factor)
		}
	}
}
