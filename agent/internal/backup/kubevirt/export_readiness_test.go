//go:build kubevirt

package kubevirt

import (
	"context"
	"errors"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	ktesting "k8s.io/client-go/testing"
	kvtypes "vnbui/agent/internal/provider/kubevirt"
	"vnbui/agent/internal/resources"
	"vnbui/agent/internal/storageupload"
)

func exportReadiness(t *testing.T, b *unstructured.Unstructured, ready bool) {
	t.Helper()
	conditions, _, err := unstructured.NestedSlice(b.Object, "status", "conditions")
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, raw := range conditions {
		c := raw.(map[string]interface{})
		if c["type"] == "ExportReady" {
			c["status"] = "False"
			if ready {
				c["status"] = "True"
			}
			found = true
		}
	}
	if !found {
		t.Fatal("fixture missing ExportReady condition")
	}
	if err := unstructured.SetNestedSlice(b.Object, conditions, "status", "conditions"); err != nil {
		t.Fatal(err)
	}
}

func readinessGuard(t *testing.T, f *exportFixture) *operationSafety {
	t.Helper()
	g, err := openSafety(filepath.Join(filepath.Dir(f.e.cfg.KeyFilePath), "storage-transactions"), &f.state.Request)
	if err != nil {
		t.Fatal(err)
	}
	return g
}

func TestExportReadinessProductionWaitsThenAccepts(t *testing.T) {
	f := readyExportFixtureVolumes(t, false, false, 4096, 1)
	b, err := f.e.dynamic.Resource(kvtypes.BackupResource).Namespace("ns").Get(context.Background(), f.state.Native.Objects[1].Name, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	dyn := f.e.dynamic.(interface {
		PrependReactor(string, string, ktesting.ReactionFunc)
	})
	reads := 0
	dyn.PrependReactor("get", "virtualmachinebackups", func(ktesting.Action) (bool, runtime.Object, error) {
		reads++
		next := b.DeepCopy()
		// Keep controller readiness false over multiple complete admission passes,
		// then expose the same original object as ready. No object is recreated.
		exportReadiness(t, next, reads > 20)
		return true, next, nil
	})
	started := time.Now()
	acceptance, err := f.run()
	if err != nil || acceptance == nil {
		t.Fatal("initial pending export was permanently refused", err)
	}
	if time.Since(started) < time.Second || reads <= 20 {
		t.Fatalf("production path did not wait for ExportReady: reads=%d elapsed=%s", reads, time.Since(started))
	}
	s := f.disk(t)
	if s.Export == nil || s.Acceptance == nil || f.streams == 0 {
		t.Fatal("readiness did not progress into accepted upload")
	}
	if u := readinessGuard(t, f).snapshot().ReadUncertainty; u != nil {
		t.Fatal("ordinary readiness created uncertainty", u)
	}
}

func TestExportReadinessPermanentPendingKeepsOriginalPreparationBudget(t *testing.T) {
	f := readyExportFixtureVolumes(t, false, false, 4096, 1)
	g := readinessGuard(t, f)
	if err := g.update(func(s *safetyState) error { s.Progress.Budget.PreparationSeconds = 1; return nil }); err != nil {
		t.Fatal(err)
	}
	original := g.snapshot().Progress
	mutateExportObject(t, f, kvtypes.BackupResource, f.state.Native.Objects[1].Name, func(b *unstructured.Unstructured) { exportReadiness(t, b, false) })
	acceptance, err := f.run()
	if err == nil || acceptance != nil || faultOf(err).Reason != "export_readiness_budget_exhausted" {
		t.Fatal("pending export escaped original preparation budget", err)
	}
	after := readinessGuard(t, f).snapshot()
	if after.Progress != original || after.ReadUncertainty != nil {
		t.Fatal("pending observation renewed original budget")
	}
	s := f.disk(t)
	if s.Export != nil || s.Acceptance != nil || len(f.calls) != 0 || f.streams != 0 {
		t.Fatal("permanently pending export produced payload")
	}
}

func TestExportReadinessLifetimeSentinelRetainsHeldJournalAndTypedReason(t *testing.T) {
	f := readyExportFixtureVolumes(t, false, false, 4096, 1)
	mutateExportObject(t, f, kvtypes.ExportResource, "export-original", func(ex *unstructured.Unstructured) {
		if err := unstructured.SetNestedField(ex.Object, "30m", "spec", "ttlDuration"); err != nil {
			t.Fatal(err)
		}
	})
	acceptance, err := f.run()
	if err == nil || acceptance != nil || faultOf(err).Reason != "export_lifetime_insufficient" || faultOf(err).Disposition != "refused" {
		t.Fatal("lifetime sentinel lost its pre-payload refusal", err)
	}
	s := f.disk(t)
	if s.Phase != "held" || s.Export != nil || s.Acceptance != nil || len(s.Maps) != 0 || len(f.calls) != 0 || f.streams != 0 {
		t.Fatal("lifetime refusal did not retain pre-payload custody")
	}
	for _, o := range s.Objects {
		if o.Phase != "planned" || o.UploadID != "" {
			t.Fatal("lifetime refusal created upload custody")
		}
	}
}

func TestExportReadinessSentinelsNeverRetryOrClearReadUncertainty(t *testing.T) {
	for _, sentinel := range []error{exportPending, errExportLifetime} {
		t.Run(sentinel.Error(), func(t *testing.T) {
			e, request, g := recoveryFixture(t)
			now := nativeNow()
			if err := g.update(func(s *safetyState) error {
				s.ReadUncertainty = &observationUncertainty{StartedAt: now, Deadline: now.Add(time.Minute), Fault: fault("export", "export_token_observation_unavailable", "transient")}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			before := g.snapshot().ReadUncertainty
			calls := 0
			err := e.retryValidationObservation(context.WithValue(context.Background(), safetyContextKey{}, g), &storageupload.State{Request: *request}, func(context.Context) error { calls++; return sentinel })
			after := g.snapshot().ReadUncertainty
			if err != sentinel || calls != 1 || after == nil || !after.StartedAt.Equal(before.StartedAt) || !after.Deadline.Equal(before.Deadline) {
				t.Fatal("sentinel granted retry or cleared/renewed read scope", err, calls)
			}
		})
	}
	// Only the exact sentinels pass through. Arbitrary untyped errors stay refused.
	if err := refuseValidationObservation(errors.New("untyped transport failure")); faultOf(err).Disposition != "refused" {
		t.Fatal(err)
	}
}

func TestExportReadinessLossAfterBindingRemainsTypedRefusal(t *testing.T) {
	f := readyExportFixtureVolumes(t, false, false, 4096, 1)
	if _, err := f.run(); err != nil {
		t.Fatal(err)
	}
	s := f.disk(t)
	mutateExportObject(t, f, kvtypes.BackupResource, s.Native.Objects[1].Name, func(b *unstructured.Unstructured) { exportReadiness(t, b, false) })
	err := f.e.revalidateExport(context.WithValue(context.Background(), safetyContextKey{}, readinessGuard(t, f)), &s)
	if err == nil || err == exportPending || faultOf(err).Reason != "export_readiness_lost" || faultOf(err).Disposition != "refused" {
		t.Fatal("bound export readiness loss became initial pending", err)
	}
}

func TestExportReadinessBoundLifetimeLossStopsRunnerWithoutReplay(t *testing.T) {
	f := readyExportFixtureVolumes(t, false, false, 4096, 1)
	bindExportFixture(t, f)
	s := f.disk(t)
	g := readinessGuard(t, f)
	mutateExportObject(t, f, kvtypes.ExportResource, "export-original", func(ex *unstructured.Unstructured) {
		if err := unstructured.SetNestedField(ex.Object, "30m", "spec", "ttlDuration"); err != nil {
			t.Fatal(err)
		}
	})
	f.e.resources = resources.New(1, 1)
	work := &transactionWork{request: &s.Request, body: f.body, safety: g}
	runner := &transactionRunner{executor: f.e, root: filepath.Dir(filepath.Dir(g.path)), ctx: context.Background(), backend: f.backend, provider: f.provider, retry: time.Millisecond, work: map[string]*transactionWork{s.Request.BackupID: work}, key: "fixture"}
	steps := 0
	runner.step = func(ctx context.Context, _ []byte, _ *http.Client, _ *http.Client, _ func(context.Context) (string, error)) (*storageupload.CheckpointProof, error) {
		steps++
		if steps > 1 {
			return nil, fault("test", "unexpected_step_replay", "refused")
		}
		return nil, f.e.revalidateExport(ctx, &s)
	}
	runner.process(work)
	after := g.snapshot()
	if steps != 1 || after.Stop == nil || after.Fault == nil || after.Fault.Reason != "export_lifetime_insufficient" || after.Fault.Disposition != "refused" {
		t.Fatal("bound lifetime refusal escaped into whole-step retry", steps, after.Fault)
	}
	if f.streams != 0 || len(f.calls) != 0 || f.disk(t).Acceptance != nil {
		t.Fatal("changed lifetime authorized payload or acceptance")
	}
	runner.process(work)
	if steps != 1 {
		t.Fatal("stopped lifetime refusal was replayed", steps)
	}
}
