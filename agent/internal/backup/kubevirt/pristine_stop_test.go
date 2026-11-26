//go:build kubevirt

package kubevirt

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	dynamicfake "k8s.io/client-go/dynamic/fake"

	"vnbui/agent/internal/models"
	"vnbui/agent/internal/storageupload"
)

func queuedPristineFixture(t *testing.T, incremental bool) (*transactionRunner, *transactionWork, string) {
	t.Helper()
	e, body, request := runnerFixture(t)
	if incremental {
		request.Plan.BackupType = "incremental"
		request.Plan.Parent = &models.StorageParent{
			BackupID: "77777777-7777-4777-8777-777777777777", RootBackupID: "77777777-7777-4777-8777-777777777777",
			GenerationID: "88888888-8888-4888-8888-888888888888", ReceiptSHA256: nativeHash([]byte("parent")),
			TrackerUID: "parent-tracker", Checkpoint: "accepted-parent",
		}
		plan, err := models.StorageCanonical(request.Plan)
		if err != nil {
			t.Fatal(err)
		}
		request.PlanSHA256 = nativeHash(plan)
	}
	var err error
	body, err = json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(filepath.Dir(e.cfg.KeyFilePath), "storage-transactions")
	if err := os.MkdirAll(root, 0700); err != nil {
		t.Fatal(err)
	}
	j, err := storageupload.CreateWithKubevirtPrefix(root, body, e.cfg.KubevirtResourcePrefix)
	if err != nil {
		t.Fatal(err)
	}
	_ = j.Close()
	g, err := e.createSafety(root, request)
	if err != nil {
		t.Fatal(err)
	}
	work := &transactionWork{request: request, body: body, safety: g}
	r := &transactionRunner{executor: e, root: root, ctx: context.Background(),
		work: map[string]*transactionWork{request.BackupID: work}}
	return r, work, filepath.Join(root, request.ReservationID, "transaction.json")
}

func payloadPhase(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var value struct {
		State struct {
			Phase string `json:"phase"`
		} `json:"state"`
	}
	if err := json.Unmarshal(raw, &value); err != nil {
		t.Fatal(err)
	}
	return value.State.Phase
}

func assertNoPristineEffects(t *testing.T, r *transactionRunner, work *transactionWork) *atomic.Int32 {
	t.Helper()
	var calls atomic.Int32
	transport := exportTransport(func(*http.Request) (*http.Response, error) {
		calls.Add(1)
		return nil, errors.New("unexpected external call")
	})
	r.backend, r.provider = &http.Client{Transport: transport}, &http.Client{Transport: transport}
	r.step = func(context.Context, []byte, *http.Client, *http.Client, func(context.Context) (string, error)) (*storageupload.CheckpointProof, error) {
		calls.Add(1)
		return nil, errors.New("unexpected producer step")
	}
	r.process(work)
	if calls.Load() != 0 || len(r.executor.dynamic.(*dynamicfake.FakeDynamicClient).Actions()) != 0 {
		t.Fatal("stopped pristine work performed effects")
	}
	return &calls
}

func TestQueuedExpirySealsPristinePayloadWithoutEffects(t *testing.T) {
	for _, incremental := range []bool{false, true} {
		t.Run(map[bool]string{false: "full", true: "incremental"}[incremental], func(t *testing.T) {
			r, work, path := queuedPristineFixture(t, incremental)
			before := work.safety.snapshot()
			deadline := before.Progress.StartedAt.Add(time.Duration(before.Progress.Budget.PreparationSeconds) * time.Second)
			r.expireQueuedWithClock(func() time.Time { return deadline })
			stopped, _ := os.ReadFile(work.safety.path)
			if !work.finished || !work.held || payloadPhase(t, path) != "held" {
				t.Fatal("expired original was not locally held")
			}
			if work.safety.snapshot().Progress != before.Progress {
				t.Fatal("queue stop changed original progress or deadline")
			}
			assertNoPristineEffects(t, r, work)
			after, _ := os.ReadFile(work.safety.path)
			if !bytes.Equal(stopped, after) {
				t.Fatal("processing rewrote the original positive stop")
			}
			if _, err := storageupload.HeldJournalSHA256(r.root, work.body); err != nil {
				t.Fatal("sealed journal cannot be independently reviewed", err)
			}
		})
	}
}

func TestPreparationAtQueueDeadlineCannotRenewOriginalBudget(t *testing.T) {
	r, work, path := queuedPristineFixture(t, false)
	before := work.safety.snapshot()
	deadline := before.Progress.StartedAt.Add(time.Duration(before.Progress.Budget.PreparationSeconds) * time.Second)
	old := nativeNow
	nativeNow = func() time.Time { return deadline }
	defer func() { nativeNow = old }()
	if err := startTransactionPreparation(context.Background(), work.safety); err == nil {
		t.Fatal("newly available slot extended an expired queue budget")
	}
	assertNoPristineEffects(t, r, work)
	s := work.safety.snapshot()
	if s.Progress != before.Progress || s.Stop == nil || !s.Stop.At.Equal(deadline) || payloadPhase(t, path) != "held" {
		t.Fatal("exact deadline failed to preserve stopped custody")
	}
}

func TestQueueExpiryAndPreparationSerializeOnOriginalStop(t *testing.T) {
	r, work, path := queuedPristineFixture(t, false)
	before := work.safety.snapshot()
	deadline := before.Progress.StartedAt.Add(time.Duration(before.Progress.Budget.PreparationSeconds) * time.Second)
	old := nativeNow
	nativeNow = func() time.Time { return deadline }
	defer func() { nativeNow = old }()
	var group sync.WaitGroup
	group.Add(2)
	go func() {
		defer group.Done()
		if err := startTransactionPreparation(context.Background(), work.safety); err == nil {
			t.Error("preparation crossed expired queue deadline")
		}
	}()
	go func() { defer group.Done(); r.expireQueuedWithClock(func() time.Time { return deadline }) }()
	group.Wait()
	assertNoPristineEffects(t, r, work)
	if work.safety.snapshot().Progress != before.Progress || payloadPhase(t, path) != "held" {
		t.Fatal("racing expiry changed progress or failed to seal")
	}
}

func TestPreparationBeforeQueueDeadlineCannotBeExpiredAsQueued(t *testing.T) {
	r, work, path := queuedPristineFixture(t, false)
	before := work.safety.snapshot()
	deadline := before.Progress.StartedAt.Add(time.Duration(before.Progress.Budget.PreparationSeconds) * time.Second)
	old := nativeNow
	nativeNow = func() time.Time { return deadline.Add(-time.Nanosecond) }
	defer func() { nativeNow = old }()
	if err := startTransactionPreparation(context.Background(), work.safety); err != nil {
		t.Fatal(err)
	}
	r.expireQueuedWithClock(func() time.Time { return deadline })
	s := work.safety.snapshot()
	if s.Stop != nil || s.Progress.Stage != "preparing" || s.Progress.Budget != before.Progress.Budget ||
		!s.Progress.StartedAt.Equal(before.Progress.StartedAt) || payloadPhase(t, path) != "uploading" {
		t.Fatal("queue observer stopped work that had entered preparation on time")
	}
}

func TestCanceledPreparationBoundaryDoesNotAdvanceOriginalClock(t *testing.T) {
	r, work, path := queuedPristineFixture(t, false)
	before := work.safety.snapshot()
	priorSafety, _ := os.ReadFile(work.safety.path)
	priorPayload, _ := os.ReadFile(path)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := startTransactionPreparation(ctx, work.safety); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled boundary did not refuse", err)
	}
	if got := work.safety.snapshot(); got.Progress != before.Progress || got.Stop != nil {
		t.Fatal("cancellation advanced stage or replaced the clock")
	}
	afterSafety, _ := os.ReadFile(work.safety.path)
	afterPayload, _ := os.ReadFile(path)
	if !bytes.Equal(priorSafety, afterSafety) || !bytes.Equal(priorPayload, afterPayload) ||
		len(r.executor.dynamic.(*dynamicfake.FakeDynamicClient).Actions()) != 0 {
		t.Fatal("canceled boundary wrote evidence or touched native resources")
	}
}

func TestCanceledRunnerAfterSlotAcquisitionNeverCallsProducer(t *testing.T) {
	r, work, path := queuedPristineFixture(t, false)
	before := work.safety.snapshot()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r.ctx = ctx
	assertNoPristineEffects(t, r, work)
	s := work.safety.snapshot()
	if s.Progress != before.Progress || s.Native != nil || s.Scratch != nil || payloadPhase(t, path) != "uploading" {
		t.Fatal("shutdown crossed the preparation boundary or changed original progress")
	}
	if r.executor.resources.ActiveBackups() != 0 {
		t.Fatal("canceled runner leaked its acquired slot")
	}
}

func closeRecoveredRunner(r *transactionRunner) {
	r.cancel()
	r.backend.CloseIdleConnections()
	r.provider.CloseIdleConnections()
	_ = r.lock.Close()
}

func TestRestartSealsExactPristineStopWithoutRenewingSafety(t *testing.T) {
	for _, incremental := range []bool{false, true} {
		t.Run(map[bool]string{false: "full", true: "incremental"}[incremental], func(t *testing.T) {
			r, work, path := queuedPristineFixture(t, incremental)
			s := work.safety.snapshot()
			at := s.Progress.StartedAt.Add(time.Duration(s.Progress.Budget.PreparationSeconds) * time.Second)
			if err := work.safety.update(func(s *safetyState) error { recordQueuedStop(s, at); return nil }); err != nil {
				t.Fatal(err)
			}
			beforeSafety, _ := os.ReadFile(work.safety.path)
			for pass := 0; pass < 2; pass++ {
				beforeInfo, _ := os.Stat(path)
				recovered, err := newTransactionRunner(context.Background(), r.executor)
				if err != nil {
					t.Fatal(err)
				}
				w := recovered.work[work.request.BackupID]
				if w == nil || !w.finished || !w.held || len(recovered.queue) != 0 || payloadPhase(t, path) != "held" {
					t.Fatal("stopped pristine original was queued on restart")
				}
				closeRecoveredRunner(recovered)
				afterSafety, _ := os.ReadFile(work.safety.path)
				if !bytes.Equal(beforeSafety, afterSafety) {
					t.Fatal("restart renewed or rewrote positive safety stop")
				}
				afterInfo, _ := os.Stat(path)
				if pass > 0 && !os.SameFile(beforeInfo, afterInfo) {
					t.Fatal("already-held pristine payload was rewritten")
				}
			}
		})
	}
}

func TestRestartDoesNotShortcutNativePreparationFromPristineSafetyMirror(t *testing.T) {
	r, work, path := queuedPristineFixture(t, false)
	j, err := storageupload.Open(r.root, work.body)
	if err != nil {
		t.Fatal(err)
	}
	native := storageupload.NativeState{ScratchName: "scratch", ScratchUID: "scratch-uid",
		Objects: []storageupload.NativeObject{
			{Role: "tracker", Name: "tracker", Phase: "planned"},
			{Role: "backup", Name: "backup", Phase: "planned"},
			{Role: "export_token", Name: "token", Phase: "planned"},
		}}
	if err := j.PrepareNative(native); err != nil {
		t.Fatal(err)
	}
	_ = j.Close()
	s := work.safety.snapshot()
	if err := work.safety.update(func(s *safetyState) error { recordQueuedStop(s, s.Progress.StartedAt); return nil }); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(path)
	recovered, err := newTransactionRunner(context.Background(), r.executor)
	if err != nil {
		t.Fatal(err)
	}
	defer closeRecoveredRunner(recovered)
	got := recovered.work[work.request.BackupID]
	if got == nil || got.finished || got.safety.snapshot().Native == nil || len(recovered.queue) != 1 ||
		!got.safety.snapshot().Progress.StartedAt.Equal(s.Progress.StartedAt) {
		t.Fatal("native preparation was shortcut as pristine stopped custody")
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(before, after) {
		t.Fatal("recovery changed native preparation payload")
	}
}

func TestStoppedPristineSealRejectsSafetyEvidenceBeyondQueueAdmission(t *testing.T) {
	r, work, path := queuedPristineFixture(t, false)
	if err := work.safety.update(func(s *safetyState) error {
		recordQueuedStop(s, s.Progress.StartedAt)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	base, _ := json.Marshal(work.safety.snapshot())
	before, _ := os.ReadFile(path)
	for name, mutate := range map[string]func(*safetyState){
		"scratch":          func(s *safetyState) { s.Scratch = &scratchReservation{} },
		"native":           func(s *safetyState) { s.Native = &storageupload.NativeState{} },
		"map":              func(s *safetyState) { s.Map = &operationFault{} },
		"observation":      func(s *safetyState) { s.LastObservation = &safetyObservation{} },
		"uncertainty":      func(s *safetyState) { s.Uncertainty = &observationUncertainty{} },
		"read uncertainty": func(s *safetyState) { s.ReadUncertainty = &observationUncertainty{} },
		"ACK":              func(s *safetyState) { s.FirstACKAt = &s.Progress.StartedAt },
		"byte":             func(s *safetyState) { s.FirstByteAt = &s.Progress.StartedAt },
		"ACK bytes":        func(s *safetyState) { s.AcknowledgedBytes = 1 },
		"cursor":           func(s *safetyState) { s.Progress.Cursor = 1 },
		"prepared":         func(s *safetyState) { s.Progress.Stage = "preparing" },
		"stop intent":      func(s *safetyState) { s.Stop.ResourceVersion = "123" },
		"stop response":    func(s *safetyState) { s.Stop.HTTPStatus = 200 },
		"unknown reason":   func(s *safetyState) { s.Fault.Reason = "unknown" },
		"uncertain fault":  func(s *safetyState) { s.Fault.Disposition = "uncertain" },
	} {
		t.Run(name, func(t *testing.T) {
			var s safetyState
			_ = json.Unmarshal(base, &s)
			mutate(&s)
			work.safety.mu.Lock()
			work.safety.state = s
			work.safety.mu.Unlock()
			if r.sealStoppedPreNative(work) {
				t.Fatal("nonpristine safety evidence qualified")
			}
			after, _ := os.ReadFile(path)
			if !bytes.Equal(before, after) {
				t.Fatal("refused safety evidence changed payload journal")
			}
		})
	}
}

func TestQueuedExpiryUsesCurrentClockWithoutSealingClockUncertainty(t *testing.T) {
	for _, regression := range []bool{false, true} {
		t.Run(map[bool]string{false: "stale_tick", true: "clock_regression"}[regression], func(t *testing.T) {
			r, work, path := queuedPristineFixture(t, false)
			before := work.safety.snapshot()
			stale := before.Progress.StartedAt.Add(-time.Second)
			current := before.Progress.StartedAt.Add(time.Second)
			if regression {
				current = stale
			}
			old := nativeNow
			nativeNow = func() time.Time { return current }
			defer func() { nativeNow = old }()
			// The timer wake is older than this accepted item and waits for r.mu.
			r.mu.Lock()
			started, done := make(chan struct{}), make(chan struct{})
			go func() { close(started); r.expireQueued(stale); close(done) }()
			<-started
			r.mu.Unlock()
			<-done
			s := work.safety.snapshot()
			if s.Progress != before.Progress || payloadPhase(t, path) != "uploading" {
				t.Fatal("queue observation changed budget or sealed ambiguous custody")
			}
			if regression {
				if s.Stop == nil || s.Stop.Phase != "requested" || s.Fault == nil || s.Fault.Reason != "invalid_budget_or_clock" || !work.finished || !work.held {
					t.Fatal("real clock regression was not retained with its original reason", s)
				}
			} else if s.Stop != nil || work.finished || work.held {
				t.Fatal("stale timer wake stopped a newly accepted item")
			}
		})
	}
}

func TestQueuedExpiryResamplesClockUnderSafetyMutationLock(t *testing.T) {
	r, work, path := queuedPristineFixture(t, false)
	before := work.safety.snapshot()
	deadline := before.Progress.StartedAt.Add(time.Duration(before.Progress.Budget.PreparationSeconds) * time.Second)
	calls := 0
	r.expireQueuedWithClock(func() time.Time {
		calls++
		if calls == 2 && work.safety.mu.TryLock() {
			work.safety.mu.Unlock()
			t.Fatal("expiry decision sampled before safety mutation lock")
		}
		return deadline
	})
	if calls != 2 || work.safety.snapshot().Progress != before.Progress || payloadPhase(t, path) != "held" {
		t.Fatal("expiry did not use original budget and locked decision time")
	}
}
