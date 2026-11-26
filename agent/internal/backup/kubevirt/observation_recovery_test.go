//go:build kubevirt

package kubevirt

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	ktesting "k8s.io/client-go/testing"
	"vnbui/agent/internal/models"
	"vnbui/agent/internal/operationbudget"
	kvtypes "vnbui/agent/internal/provider/kubevirt"
	"vnbui/agent/internal/resources"
	"vnbui/agent/internal/storageupload"
)

func recoveryFixture(t *testing.T) (*Executor, *models.StorageTransactionRequest, *operationSafety) {
	t.Helper()
	e, body, request, _ := nativeFixture(t, false)
	j, err := e.PrepareStorageTransaction(context.Background(), body)
	if err != nil {
		t.Fatal(err)
	}
	j.Close()
	g, err := openSafety(filepath.Join(filepath.Dir(e.cfg.KeyFilePath), "storage-transactions"), request)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.inspectSafety(context.Background(), request, g); err != nil {
		t.Fatal(err)
	}
	if err := g.observeSafety(nil, nativeNow()); err != nil {
		t.Fatal(err)
	}
	if g.snapshot().LastObservation == nil {
		t.Fatal("healthy inspection not persisted")
	}
	return e, request, g
}

func TestObservationTimeoutThenSuccessDoesNotStopOrRenewProgress(t *testing.T) {
	e, request, g := recoveryFixture(t)
	before := g.snapshot().Progress
	// Inject a real API timeout at the same source observation used by the watcher.
	dyn := e.dynamic.(interface {
		PrependReactor(string, string, ktesting.ReactionFunc)
	})
	fail := true
	dyn.PrependReactor("get", "virtualmachineinstances", func(ktesting.Action) (bool, runtime.Object, error) {
		if fail {
			return true, nil, apierrors.NewTimeoutError("timeout", 1)
		}
		return false, nil, nil
	})
	err := e.inspectSafety(context.Background(), request, g)
	if faultOf(err).Disposition != "transient" {
		t.Fatal(err)
	}
	if err = g.observeSafety(err, nativeNow()); err != nil {
		t.Fatal(err)
	}
	if g.snapshot().Uncertainty == nil || g.snapshot().Stop != nil {
		t.Fatal("isolated timeout stopped backup")
	}
	fail = false
	if err := g.observeSafety(e.inspectSafety(context.Background(), request, g), nativeNow()); err != nil {
		t.Fatal(err)
	}
	after := g.snapshot()
	if after.Uncertainty != nil || after.Stop != nil || after.Progress != before {
		t.Fatal("success changed progress/stop", after)
	}
}

func TestObservationRestartAndChangedPolicyCannotRenewOriginalDeadline(t *testing.T) {
	e, request, g := recoveryFixture(t)
	timeout := fault("source_health", "source_status_unavailable", "transient")
	if err := g.observeSafety(timeout, nativeNow()); err != nil {
		t.Fatal(err)
	}
	original := *g.snapshot().Uncertainty
	e.cfg.OperationBudget.ObservationCoefficient = 100
	reopened, err := openSafety(filepath.Dir(filepath.Dir(g.path)), request)
	if err != nil {
		t.Fatal(err)
	}
	if reopened.snapshot().Policy.ObservationCoefficient != 3 {
		t.Fatal("restart adopted new policy")
	}
	now := original.StartedAt.Add(time.Second)
	nativeNow = func() time.Time { return now }
	if err := reopened.observeSafety(timeout, now); err != nil {
		t.Fatal(err)
	}
	if !reopened.snapshot().Uncertainty.Deadline.Equal(original.Deadline) {
		t.Fatal("retry renewed deadline")
	}
	now = original.Deadline
	if err := reopened.observeSafety(nil, now); faultOf(err).Reason != "observation_budget_exhausted" {
		t.Fatal("late success escaped exhaustion", err)
	}
}

func TestObservationGraceRequiresTrustworthyFreshHeadroom(t *testing.T) {
	for _, test := range []string{"none", "stale", "low", "peak", "old_policy", "future", "aged"} {
		t.Run(test, func(t *testing.T) {
			_, _, g := recoveryFixture(t)
			now := nativeNow()
			if err := g.update(func(s *safetyState) error {
				switch test {
				case "none":
					s.LastObservation = nil
				case "stale":
					s.LastObservation.Scratch.At = now.Add(-time.Minute)
				case "low":
					s.LastObservation.Scratch.AvailableBytes = s.Scratch.RequiredBytes
				case "peak":
					s.Scratch.PeakGrowthBytesPerSecond = 1 << 60
				case "old_policy":
					s.Policy.ObservationCoefficient = 0
				case "future":
					s.LastObservation.At = now.Add(time.Second)
				case "aged":
					s.LastObservation.At = now.Add(-21 * time.Second)
					s.LastObservation.Scratch.At = s.LastObservation.At
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			if err := g.observeSafety(fault("source_health", "source_status_unavailable", "transient"), now); err == nil {
				t.Fatal("unsafe grace admitted")
			}
			if g.snapshot().Uncertainty != nil {
				t.Fatal("unsafe uncertainty persisted")
			}
		})
	}
}

func TestObservationConfirmedFailuresAndIdentityChangeNeverReceiveGrace(t *testing.T) {
	e, request, g := recoveryFixture(t)
	pvc, err := e.dynamic.Resource(pvcResource).Namespace(request.Plan.Source.Namespace).Get(context.Background(), g.snapshot().Scratch.Name, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	pvc.SetUID("replacement")
	if _, err = e.dynamic.Resource(pvcResource).Namespace(request.Plan.Source.Namespace).Update(context.Background(), pvc, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	observed := e.inspectSafety(context.Background(), request, g)
	if err := g.observeSafety(observed, nativeNow()); err == nil || faultOf(err).Disposition != "refused" {
		t.Fatal("identity changed but grace granted", err)
	}
	for _, reason := range []string{"source_io_error_pause", "source_paused", "native_failed", "source_not_ready"} {
		expected := fault("source_health", reason, "refused")
		if err := g.observeSafety(expected, nativeNow()); !errors.Is(err, expected) {
			t.Fatal("confirmed failure received grace", err)
		}
	}
}

func TestObservationPublicationRemainsTerminal(t *testing.T) {
	_, _, g := recoveryFixture(t)
	if err := g.observeSafety(fault("native", "native_health_unavailable", "transient"), nativeNow()); err != nil {
		t.Fatal(err)
	}
	if err := g.published(); err != nil {
		t.Fatal(err)
	}
	if err := g.observeSafety(fault("source_health", "source_paused", "refused"), nativeNow().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if g.snapshot().Progress.Stage != "complete" || g.snapshot().Stop != nil {
		t.Fatal("terminal publication downgraded")
	}
}

func TestSafetyReadFaultSeparatesUnavailableFromRefusal(t *testing.T) {
	resource := schema.GroupResource{Resource: "virtualmachineinstances"}
	for _, test := range []struct {
		err         error
		disposition string
	}{
		{apierrors.NewTimeoutError("timeout", 1), "transient"},
		{apierrors.NewTooManyRequests("limited", 1), "transient"},
		{apierrors.NewServiceUnavailable("unavailable"), "transient"},
		{apierrors.NewNotFound(resource, "vm"), "refused"},
		{apierrors.NewForbidden(resource, "vm", errors.New("denied")), "refused"},
		{apierrors.NewUnauthorized("denied"), "refused"},
	} {
		if got := safetyReadFault(test.err, "source_health", "source_status_unavailable"); got.Disposition != test.disposition {
			t.Fatal(got)
		}
	}
	if got := safetyReadFault(apierrors.NewGenericServerResponse(http.StatusUnprocessableEntity, "get", resource, "vm", "invalid", 0, false), "source_health", "source_status_unavailable"); got.Disposition != "refused" {
		t.Fatal(got)
	}
}

func TestObservationUnknownOrPersistenceErrorsNeverReceiveGrace(t *testing.T) {
	_, _, g := recoveryFixture(t)
	for _, observed := range []error{errors.New("journal write failed"), fault("scratch", "scratch_probe_not_running", "transient"), fault("reconciling", "transaction_observation_unavailable", "transient")} {
		if err := g.observeSafety(observed, nativeNow()); err == nil {
			t.Fatal("unknown failure received grace", observed)
		}
	}
}

func TestObservationHeadroomAndOriginalUsefulProgressCapRecovery(t *testing.T) {
	_, _, g := recoveryFixture(t)
	s := g.snapshot()
	now := nativeNow()
	// Plenty of absolute run time does not extend the original useful-progress window.
	s.Progress.LastProgressAt = now.Add(-time.Duration(s.Progress.Budget.SilenceSeconds-7) * time.Second)
	s.Progress.StartedAt = s.Progress.LastProgressAt
	s.Progress.Stage = "transferring"
	deadline, ok := observationDeadline(&s, now)
	if !ok || !deadline.Equal(now.Add(7*time.Second)) {
		t.Fatal("useful progress deadline not retained", deadline, ok)
	}
	s = g.snapshot()
	if s.Native.Lifetime == nil {
		t.Fatal("fixture missing pinned native deadline")
	}
	s.Native.Lifetime.TransactionTimeoutSeconds = int(s.Progress.Budget.ClosureSeconds + 20 + 17)
	deadline, ok = observationDeadline(&s, now)
	if !ok || !deadline.Equal(now.Add(17*time.Second)) {
		t.Fatal("native deadline consumed closure reserve", deadline, ok)
	}
	s = g.snapshot()
	rate := max(s.Scratch.PeakGrowthBytesPerSecond, s.Policy.BootstrapBytesPerSecond)
	// Exactly enough remaining headroom for 30 seconds including telemetry and closure.
	reserve, err := operationbudget.GrowthReserve(rate, 51, s.Progress.Budget.ClosureSeconds, s.Policy.ScratchCoefficient)
	if err != nil {
		t.Fatal(err)
	}
	s.LastObservation.Scratch.AvailableBytes = s.Scratch.RequiredBytes + reserve + 1
	deadline, ok = observationDeadline(&s, now)
	if !ok || !deadline.Equal(now.Add(30*time.Second)) {
		t.Fatal("headroom did not cap recovery", deadline, ok)
	}
}

func TestObservationConfirmedSourcePauseOrNativeFailureDuringGrace(t *testing.T) {
	for _, test := range []string{"source_io_error_pause", "native_failed"} {
		t.Run(test, func(t *testing.T) {
			e, request, g := recoveryFixture(t)
			if err := g.observeSafety(fault("native", "native_health_unavailable", "transient"), nativeNow()); err != nil {
				t.Fatal(err)
			}
			resource, name, conditions := kvtypes.BackupResource, g.snapshot().Native.Objects[1].Name, []interface{}{map[string]interface{}{"type": "Failed", "status": "True"}}
			if test == "source_io_error_pause" {
				resource, name, conditions = kvtypes.VMIResource, request.Plan.VMName, []interface{}{map[string]interface{}{"type": "Paused", "status": "True", "reason": "PausedIOError"}}
			}
			obj, err := e.dynamic.Resource(resource).Namespace(request.Plan.Source.Namespace).Get(context.Background(), name, metav1.GetOptions{})
			if err != nil {
				t.Fatal(err)
			}
			if err := unstructured.SetNestedSlice(obj.Object, conditions, "status", "conditions"); err != nil {
				t.Fatal(err)
			}
			if _, err = e.dynamic.Resource(resource).Namespace(request.Plan.Source.Namespace).Update(context.Background(), obj, metav1.UpdateOptions{}); err != nil {
				t.Fatal(err)
			}
			observed := e.inspectSafety(context.Background(), request, g)
			if faultOf(observed).Reason != test {
				t.Fatal(observed)
			}
			if err := g.observeSafety(observed, nativeNow()); err == nil {
				t.Fatal("confirmed failure ignored during grace")
			}
		})
	}
}

func TestObservationEarlySuccessAndIdentityRaceCannotCreateTrust(t *testing.T) {
	_, _, g := recoveryFixture(t)
	checked := g.snapshot()
	if err := g.update(func(s *safetyState) error { s.LastObservation = nil; return nil }); err != nil {
		t.Fatal(err)
	}
	if err := g.observeSafety(nil, nativeNow()); err != nil {
		t.Fatal(err)
	}
	if g.snapshot().LastObservation != nil {
		t.Fatal("early return manufactured healthy evidence")
	}
	if err := g.update(func(s *safetyState) error { s.Scratch.LeaseUID = "replacement"; return nil }); err != nil {
		t.Fatal(err)
	}
	if err := g.recordSafetyObservation(checked, *checked.Scratch.Latest, nativeNow(), nativeNow()); faultOf(err).Reason != "observation_identity_changed" {
		t.Fatal("raced identity accepted", err)
	}
	if g.snapshot().LastObservation != nil {
		t.Fatal("identity race manufactured healthy evidence")
	}
}

func TestValidationObservationTimeoutThenSuccessClearsOnlyReadScope(t *testing.T) {
	e, request, g := recoveryFixture(t)
	ctx := context.WithValue(context.Background(), safetyContextKey{}, g)
	calls := 0
	before := g.snapshot().Progress
	err := e.retryValidationObservation(ctx, &storageupload.State{Request: *request}, func(context.Context) error {
		calls++
		if calls == 1 {
			return observationFault("export_token", apierrors.NewTimeoutError("timeout", 1))
		}
		return nil
	})
	if err != nil || calls != 2 || g.snapshot().ReadUncertainty != nil || g.snapshot().Progress != before {
		t.Fatal("read retry failed or renewed progress", err, calls)
	}
}

func TestValidationUncertaintySurvivesHealthyWatchAndExpiresOriginalReason(t *testing.T) {
	e, request, g := recoveryFixture(t)
	ctx := context.WithValue(context.Background(), safetyContextKey{}, g)
	calls := 0
	now := nativeNow()
	nativeNow = func() time.Time { return now }
	var original observationUncertainty
	err := e.retryValidationObservation(ctx, &storageupload.State{Request: *request}, func(context.Context) error {
		calls++
		if calls == 2 {
			original = *g.snapshot().ReadUncertainty
			now = now.Add(time.Second)
			if err := e.inspectSafety(context.Background(), request, g); err != nil {
				t.Fatal(err)
			}
			if got := g.snapshot().ReadUncertainty; got == nil || !got.StartedAt.Equal(original.StartedAt) || !got.Deadline.Equal(original.Deadline) {
				t.Fatal("healthy watchdog cleared or renewed read uncertainty")
			}
			// Restart and policy changes also preserve the independent scope.
			reopened, err := openSafety(filepath.Dir(filepath.Dir(g.path)), request)
			if err != nil {
				t.Fatal(err)
			}
			if !reopened.snapshot().ReadUncertainty.Deadline.Equal(original.Deadline) {
				t.Fatal("restart renewed read deadline")
			}
			now = original.Deadline
		}
		return observationFault("export_token", apierrors.NewTimeoutError("timeout", 1))
	})
	if calls != 2 || err == nil || faultOf(err).Stage != "observation" || faultOf(err).Reason != "export_token_observation_unavailable" {
		t.Fatal("read failure escaped bounded original scope", calls, err)
	}
	if !g.snapshot().ReadUncertainty.Deadline.Equal(original.Deadline) {
		t.Fatal("expiry renewed deadline")
	}
}

func TestValidationHardRejectionAndMissingEvidenceNeverReplay(t *testing.T) {
	for _, test := range []string{"hard", "no_baseline", "persistence"} {
		t.Run(test, func(t *testing.T) {
			e, request, g := recoveryFixture(t)
			if test == "no_baseline" {
				if err := g.update(func(s *safetyState) error { s.LastObservation = nil; return nil }); err != nil {
					t.Fatal(err)
				}
			}
			calls := 0
			err := e.retryValidationObservation(context.WithValue(context.Background(), safetyContextKey{}, g), &storageupload.State{Request: *request}, func(context.Context) error {
				calls++
				switch test {
				case "hard":
					return observationFault("export_token", apierrors.NewForbidden(schema.GroupResource{Resource: "secrets"}, "token", errors.New("denied")))
				case "persistence":
					return storageupload.ErrHeld
				default:
					return observationFault("export_token", apierrors.NewTimeoutError("timeout", 1))
				}
			})
			if err == nil || faultOf(err).Disposition == "transient" || calls != 1 || g.snapshot().ReadUncertainty != nil {
				t.Fatal("unsafe callback replay", err, calls)
			}
		})
	}
}

func TestValidationDeniedGraceStopsProductionRunnerWithoutReplayingStep(t *testing.T) {
	for _, test := range []string{"missing", "stale", "low", "legacy"} {
		t.Run(test, func(t *testing.T) {
			e, request, g := recoveryFixture(t)
			if err := g.update(func(s *safetyState) error {
				switch test {
				case "missing":
					s.LastObservation = nil
				case "stale":
					s.LastObservation.At = nativeNow().Add(-21 * time.Second)
					s.LastObservation.Scratch.At = s.LastObservation.At
				case "low":
					s.LastObservation.Scratch.AvailableBytes = s.Scratch.RequiredBytes
				case "legacy":
					s.Policy.ObservationCoefficient = 0
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			e.resources = resources.New(1, 1)
			body, err := json.Marshal(request)
			if err != nil {
				t.Fatal(err)
			}
			work := &transactionWork{request: request, body: body, safety: g}
			steps, reads := 0, 0
			runner := &transactionRunner{executor: e, root: filepath.Dir(filepath.Dir(g.path)), ctx: context.Background(), backend: &http.Client{}, provider: &http.Client{}, retry: time.Millisecond, work: map[string]*transactionWork{request.BackupID: work}, key: "fixture"}
			runner.step = func(ctx context.Context, _ []byte, _ *http.Client, _ *http.Client, _ func(context.Context) (string, error)) (*storageupload.CheckpointProof, error) {
				steps++
				if steps > 1 {
					return nil, fault("test", "unexpected_step_replay", "refused")
				}
				err := e.retryValidationObservation(ctx, &storageupload.State{Request: *request}, func(context.Context) error {
					reads++
					return observationFault("export_token", apierrors.NewTimeoutError("timeout", 1))
				})
				return nil, err
			}
			runner.process(work)
			if steps != 1 || reads != 1 || g.snapshot().Stop == nil || g.snapshot().Fault.Disposition != "refused" {
				t.Fatal("denied grace escaped into whole-step retry", steps, reads, g.snapshot().Fault)
			}
			// A later healthy view and changed policy must not resurrect this attempt.
			runner.process(work)
			if steps != 1 || reads != 1 {
				t.Fatal("stopped attempt replayed", steps, reads)
			}
		})
	}
}

func TestObservationExpiryDuringTerminalReadCannotGrantPublication(t *testing.T) {
	for _, scope := range []string{"health", "read"} {
		t.Run(scope, func(t *testing.T) {
			_, _, g := recoveryFixture(t)
			now := nativeNow()
			deadline := now.Add(time.Second)
			if err := g.update(func(s *safetyState) error {
				u := &observationUncertainty{StartedAt: now, Deadline: deadline, Fault: fault("native", "native_health_unavailable", "transient")}
				if scope == "health" {
					s.Uncertainty = u
				} else {
					s.ReadUncertainty = u
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			// Terminal read started in time; lock acquisition/publication happens too late.
			nativeNow = func() time.Time { return deadline }
			if err := g.sourceClosed(now); err == nil {
				t.Fatal("late terminal observation authorized publication")
			}
			if s := g.snapshot(); s.SourceClosed || s.PublicationDeadline != nil {
				t.Fatal("expiry granted publication window")
			}
			// Durable publication ACK remains terminal, including historical uncertainty.
			if err := g.published(); err != nil {
				t.Fatal(err)
			}
			if err := g.sourceClosed(deadline.Add(time.Hour)); err != nil {
				t.Fatal("published ACK downgraded", err)
			}
		})
	}
}

func constrainObservationHeadroom(t *testing.T, g *operationSafety, seconds int64) {
	t.Helper()
	if err := g.update(func(s *safetyState) error {
		rate := max(s.Scratch.PeakGrowthBytesPerSecond, s.Policy.BootstrapBytesPerSecond)
		reserve, err := operationbudget.GrowthReserve(rate, seconds+21, s.Progress.Budget.ClosureSeconds, s.Policy.ScratchCoefficient)
		if err != nil {
			return err
		}
		s.LastObservation.Scratch.AvailableBytes = s.Scratch.RequiredBytes + reserve + 1
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestObservationSlowAPITimeoutUsesFreshInspectionStart(t *testing.T) {
	for _, headroom := range []int64{180, 45} {
		t.Run((time.Duration(headroom) * time.Second).String(), func(t *testing.T) {
			e, request, g := recoveryFixture(t)
			sampled := nativeNow()
			now := sampled.Add(5 * time.Second)
			nativeNow = func() time.Time { return now }
			if headroom == 45 {
				constrainObservationHeadroom(t, g, headroom)
			}
			dyn := e.dynamic.(interface {
				PrependReactor(string, string, ktesting.ReactionFunc)
			})
			calls := 0
			dyn.PrependReactor("get", "virtualmachineinstances", func(ktesting.Action) (bool, runtime.Object, error) {
				calls++
				if calls == 1 {
					now = sampled.Add(25 * time.Second)
					return true, nil, apierrors.NewTimeoutError("timeout", 1)
				}
				if calls == 2 {
					now = sampled.Add(26 * time.Second)
					return true, nil, apierrors.NewTimeoutError("timeout", 1)
				}
				return false, nil, nil
			})
			// This is the exact combined inspector/episode path called by watchSafety.
			if err := e.inspectSafetyObservation(context.Background(), request, g); err != nil {
				t.Fatal("fresh-at-start timeout incorrectly refused", err)
			}
			original := *g.snapshot().Uncertainty
			if !original.StartedAt.Equal(sampled.Add(5*time.Second)) || !original.Deadline.Equal(sampled.Add(time.Duration(headroom)*time.Second)) {
				t.Fatal("latency renewed or escaped original headroom", original)
			}
			now = sampled.Add(26 * time.Second)
			if err := e.inspectSafetyObservation(context.Background(), request, g); err != nil {
				t.Fatal(err)
			}
			again := g.snapshot().Uncertainty
			if again == nil || !again.StartedAt.Equal(original.StartedAt) || !again.Deadline.Equal(original.Deadline) {
				t.Fatal("later timeout renewed original scope", again)
			}
			now = sampled.Add(30 * time.Second)
			if err := e.inspectSafetyObservation(context.Background(), request, g); err != nil {
				t.Fatal(err)
			}
			if g.snapshot().Uncertainty != nil || g.snapshot().Stop != nil {
				t.Fatal("timely health recovery stopped backup")
			}
		})
	}
}

func TestValidationSlowAPITimeoutPreservesFirstStartAndHeadroom(t *testing.T) {
	for _, headroom := range []int64{180, 45} {
		t.Run((time.Duration(headroom) * time.Second).String(), func(t *testing.T) {
			f := readyExportFixtureVolumes(t, false, false, 4096, 1)
			e, request := f.e, &f.state.Request
			g, err := openSafety(filepath.Join(filepath.Dir(e.cfg.KeyFilePath), "storage-transactions"), request)
			if err != nil {
				t.Fatal(err)
			}
			if err := e.inspectSafetyObservation(context.Background(), request, g); err != nil {
				t.Fatal(err)
			}
			state := f.state
			if err := e.admitNativeSnapshot(context.Background(), &state, func(u storageupload.BorrowedUtility) error { state.Utility = &u; return nil }); err != nil {
				t.Fatal(err)
			}
			state.Export, err = e.inspectExport(context.Background(), &state)
			if err != nil {
				t.Fatal(err)
			}
			if headroom == 45 {
				constrainObservationHeadroom(t, g, headroom)
			}
			sampled := nativeNow()
			now := sampled.Add(5 * time.Second)
			nativeNow = func() time.Time { return now }
			dyn := e.dynamic.(interface {
				PrependReactor(string, string, ktesting.ReactionFunc)
			})
			calls := 0
			dyn.PrependReactor("get", "secrets", func(ktesting.Action) (bool, runtime.Object, error) {
				calls++
				if calls == 1 {
					now = sampled.Add(25 * time.Second)
					return true, nil, apierrors.NewTimeoutError("timeout", 1)
				}
				original := g.snapshot().ReadUncertainty
				if original == nil || !original.StartedAt.Equal(sampled.Add(5*time.Second)) || !original.Deadline.Equal(sampled.Add(time.Duration(headroom)*time.Second)) {
					t.Fatal("worker latency or healthy inspector renewed original read scope", original)
				}
				now = sampled.Add(30 * time.Second)
				return false, nil, nil
			})
			if err := e.revalidateExport(context.WithValue(context.Background(), safetyContextKey{}, g), &state); err != nil {
				t.Fatal("fresh-at-start worker timeout incorrectly refused", err)
			}
			if calls != 2 || g.snapshot().ReadUncertainty != nil || g.snapshot().Stop != nil {
				t.Fatal("worker recovery replayed or stopped", calls)
			}
		})
	}
}

func TestObservationSlowFailureCannotRescueStaleStartOrExhaustedAllowance(t *testing.T) {
	for _, scope := range []string{"health", "read"} {
		for _, test := range []string{"stale_start", "exhausted", "no_baseline", "headroom_consumed"} {
			t.Run(scope+"/"+test, func(t *testing.T) {
				e, request, g := recoveryFixture(t)
				sampled := nativeNow()
				now := sampled.Add(5 * time.Second)
				if test == "stale_start" {
					now = sampled.Add(21 * time.Second)
				}
				if test == "no_baseline" {
					if err := g.update(func(s *safetyState) error { s.LastObservation = nil; return nil }); err != nil {
						t.Fatal(err)
					}
				}
				if test == "headroom_consumed" {
					constrainObservationHeadroom(t, g, 20)
				}
				nativeNow = func() time.Time { return now }
				dyn := e.dynamic.(interface {
					PrependReactor(string, string, ktesting.ReactionFunc)
				})
				resource := "virtualmachineinstances"
				if scope == "read" {
					resource = "secrets"
				}
				calls := 0
				dyn.PrependReactor("get", resource, func(ktesting.Action) (bool, runtime.Object, error) {
					calls++
					if test == "exhausted" {
						now = sampled.Add(180 * time.Second)
					} else {
						now = now.Add(20 * time.Second)
					}
					return true, nil, apierrors.NewTimeoutError("timeout", 1)
				})
				var observed error
				if scope == "health" {
					observed = e.inspectSafetyObservation(context.Background(), request, g)
				} else {
					observed = e.retryValidationObservation(context.WithValue(context.Background(), safetyContextKey{}, g), &storageupload.State{Request: *request}, func(ctx context.Context) error {
						_, err := e.dynamic.Resource(coreV1Secret).Namespace(request.Plan.Source.Namespace).Get(ctx, g.snapshot().Native.Objects[2].Name, metav1.GetOptions{})
						return observationFault("export_token", err)
					})
				}
				if observed == nil || faultOf(observed).Disposition != "refused" || calls != 1 {
					t.Fatal("late/stale evidence granted grace or replayed", calls, observed)
				}
				if err := g.stop(faultOf(observed)); err != nil {
					t.Fatal(err)
				}
				e.closeNativeSafety(context.Background(), request, g)
				if s := g.snapshot(); s.Stop == nil || s.Stop.Phase != "native_absent_unproven" || s.Uncertainty != nil || s.ReadUncertainty != nil {
					t.Fatal("late observation did not close original attempt", s.Stop)
				}
			})
		}
	}
}

func TestObservationSlowDeadlineChargesAgeOfOriginalScratchSample(t *testing.T) {
	_, _, g := recoveryFixture(t)
	baseline := g.snapshot()
	sampled := baseline.LastObservation.Scratch.At.Add(-10 * time.Second)
	baseline.LastObservation.Scratch.At = sampled
	start := sampled.Add(15 * time.Second)
	completed := sampled.Add(35 * time.Second)
	current := baseline
	deadline, ok := observationDeadlineAt(&current, baseline, start, completed)
	if !ok || !deadline.Equal(sampled.Add(180*time.Second)) {
		t.Fatal("API latency or pre-inspection sample age renewed allowance", deadline, ok)
	}
}
