//go:build kubevirt

package kubevirt

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	k8stest "k8s.io/client-go/testing"
	kvtypes "vnbui/agent/internal/provider/kubevirt"
	"vnbui/agent/internal/resources"
)

func TestSafetyStopClosesOnlyOriginalBackupDespitePausedSource(t *testing.T) {
	e, body, request, dyn := nativeFixture(t, true)
	j, err := e.PrepareStorageTransaction(context.Background(), body)
	if err != nil {
		t.Fatal(err)
	}
	s, _ := j.Snapshot()
	_ = j.Close()
	g, err := openSafety(filepath.Join(filepath.Dir(e.cfg.KeyFilePath), "storage-transactions"), request)
	if err != nil {
		t.Fatal(err)
	}
	vmi, _ := dyn.Resource(kvtypes.VMIResource).Namespace("ns").Get(context.Background(), request.Plan.VMName, metav1.GetOptions{})
	_ = unstructured.SetNestedSlice(vmi.Object, []interface{}{map[string]interface{}{"type": "Paused", "status": "True", "reason": "PausedIOError"}}, "status", "conditions")
	_ = dyn.Tracker().Update(kvtypes.VMIResource, vmi, "ns")
	if err := g.stop(fault("mapping", "map_stored_range_limit", "refused")); err != nil {
		t.Fatal(err)
	}
	dyn.ClearActions()
	e.closeNativeSafety(context.Background(), request, g)
	deletes := 0
	for _, action := range dyn.Actions() {
		if action.GetVerb() == "delete" {
			deletes++
			delete := action.(k8stest.DeleteAction)
			if action.GetResource() != kvtypes.BackupResource || delete.GetName() != s.Native.Objects[1].Name || delete.GetDeleteOptions().Preconditions == nil || *delete.GetDeleteOptions().Preconditions.UID != types.UID(s.Native.Objects[1].UID) {
				t.Fatalf("unsafe deletion: %#v", action)
			}
		} else if action.GetVerb() != "get" {
			t.Fatalf("unexpected mutation: %#v", action)
		}
	}
	if deletes != 1 || g.snapshot().Stop.Phase != "native_absent_unproven" {
		t.Fatalf("native stop missing or falsely proved: %+v", g.snapshot().Stop)
	}
	if _, err := dyn.Resource(kvtypes.BackupTrackerResource).Namespace("ns").Get(context.Background(), s.Native.Objects[0].Name, metav1.GetOptions{}); err != nil {
		t.Fatal("accepted parent tracker lost", err)
	}
	if checkSafety(context.WithValue(context.Background(), safetyContextKey{}, g)) == nil {
		t.Fatal("stopped attempt admitted again")
	}
}

func TestSafetyStopRefusesReplacementAndSurvivesRestart(t *testing.T) {
	e, body, request, dyn := nativeFixture(t, false)
	j, err := e.PrepareStorageTransaction(context.Background(), body)
	if err != nil {
		t.Fatal(err)
	}
	s, _ := j.Snapshot()
	j.Close()
	root := filepath.Join(filepath.Dir(e.cfg.KeyFilePath), "storage-transactions")
	g, err := openSafety(root, request)
	if err != nil {
		t.Fatal(err)
	}
	before := g.snapshot().Progress.Deadline()
	if g.stop(fault("mapping", "map_schema_invalid", "refused")) != nil {
		t.Fatal("stop not saved")
	}
	b, _ := dyn.Resource(kvtypes.BackupResource).Namespace("ns").Get(context.Background(), s.Native.Objects[1].Name, metav1.GetOptions{})
	b.SetUID("replacement")
	dyn.Tracker().Update(kvtypes.BackupResource, b, "ns")
	g, err = openSafety(root, request)
	if err != nil {
		t.Fatal(err)
	}
	dyn.ClearActions()
	e.closeNativeSafety(context.Background(), request, g)
	for _, action := range dyn.Actions() {
		if action.GetVerb() != "get" {
			t.Fatal("replacement mutated")
		}
	}
	if !g.snapshot().Progress.Deadline().Equal(before) || g.snapshot().Stop.Phase != "native_identity_refused" {
		t.Fatal("restart reset authority/deadline")
	}
	data, _ := os.ReadFile(g.path)
	data[len(data)-2] ^= 1
	os.WriteFile(g.path, data, 0600)
	if _, err := openSafety(root, request); err == nil {
		t.Fatal("corrupted safety record accepted")
	}
}

func TestSafetyCloseRetriesOnlyDefiniteConflictAndKeepsOriginalDeadline(t *testing.T) {
	e, body, request, dyn := nativeFixture(t, false)
	j, err := e.PrepareStorageTransaction(context.Background(), body)
	if err != nil {
		t.Fatal(err)
	}
	j.Close()
	root := filepath.Join(filepath.Dir(e.cfg.KeyFilePath), "storage-transactions")
	g, err := openSafety(root, request)
	if err != nil {
		t.Fatal(err)
	}
	if err := g.stop(fault("scratch", "scratch_exhaustion_risk", "refused")); err != nil {
		t.Fatal(err)
	}
	original := g.snapshot()
	deletes := 0
	dyn.PrependReactor("delete", "virtualmachinebackups", func(a k8stest.Action) (bool, runtime.Object, error) {
		deletes++
		d := a.(k8stest.DeleteAction)
		if *d.GetDeleteOptions().Preconditions.UID != types.UID(original.Native.Objects[1].UID) {
			t.Fatal("delete changed original UID")
		}
		if deletes == 1 {
			obj, _ := dyn.Tracker().Get(kvtypes.BackupResource, "ns", d.GetName())
			b := obj.(*unstructured.Unstructured).DeepCopy()
			b.SetResourceVersion("99")
			_ = dyn.Tracker().Update(kvtypes.BackupResource, b, "ns")
			return true, nil, apierrors.NewConflict(kvtypes.BackupResource.GroupResource(), d.GetName(), errors.New("changed version"))
		}
		if *d.GetDeleteOptions().Preconditions.ResourceVersion != "99" {
			t.Fatal("conflict retry did not revalidate original object")
		}
		return false, nil, nil
	})
	e.closeNativeSafety(context.Background(), request, g)
	if deletes != 2 || g.snapshot().Stop.Phase != "native_absent_unproven" {
		t.Fatal("definite conflict did not converge", deletes, g.snapshot().Stop)
	}
	now := original.Stop.At.Add(time.Duration(original.Progress.Budget.ClosureSeconds) * time.Second)
	nativeNow = func() time.Time { return now }
	g, err = openSafety(root, request)
	if err != nil {
		t.Fatal(err)
	}
	dyn.ClearActions()
	e.closeNativeSafety(context.Background(), request, g)
	if len(dyn.Actions()) != 0 || !g.snapshot().Stop.At.Equal(original.Stop.At) || g.snapshot().Stop.Phase != "native_close_budget_exhausted" {
		t.Fatal("restart renewed native closure window", dyn.Actions(), g.snapshot().Stop)
	}
}

func TestScratchRefusesPausedSourceAndOtherClaimUsersBeforeNativeStart(t *testing.T) {
	for _, problem := range []string{"pause", "other_node", "shared_user"} {
		t.Run(problem, func(t *testing.T) {
			e, body, r, dyn := nativeFixture(t, false)
			if problem == "pause" {
				vmi, _ := dyn.Resource(kvtypes.VMIResource).Namespace("ns").Get(context.Background(), r.Plan.VMName, metav1.GetOptions{})
				unstructured.SetNestedSlice(vmi.Object, []interface{}{map[string]interface{}{"type": "Paused", "status": "True", "reason": "UserPaused"}}, "status", "conditions")
				dyn.Tracker().Update(kvtypes.VMIResource, vmi, "ns")
			} else {
				pod := &unstructured.Unstructured{Object: map[string]interface{}{"apiVersion": "v1", "kind": "Pod", "metadata": map[string]interface{}{"name": "other-user", "namespace": "ns", "uid": "other"}, "spec": map[string]interface{}{"nodeName": "other-node", "volumes": []interface{}{map[string]interface{}{"name": "scratch", "persistentVolumeClaim": map[string]interface{}{"claimName": "scratch"}}}}}}
				dyn.Tracker().Create(schema.GroupVersionResource{Version: "v1", Resource: "pods"}, pod, "ns")
			}
			dyn.ClearActions()
			if j, err := e.PrepareStorageTransaction(context.Background(), body); err == nil {
				j.Close()
				t.Fatal("unsafe source/scratch admitted")
			}
			for _, a := range dyn.Actions() {
				if a.GetVerb() == "create" && a.GetResource() == kvtypes.BackupResource {
					t.Fatal("native producer started before scratch admission")
				}
			}
		})
	}
}

func TestSafetyRepeatedMapObservationDoesNotRenewProgress(t *testing.T) {
	e, body, r, _ := nativeFixture(t, false)
	j, err := e.PrepareStorageTransaction(context.Background(), body)
	if err != nil {
		t.Fatal(err)
	}
	j.Close()
	g, _ := openSafety(filepath.Join(filepath.Dir(e.cfg.KeyFilePath), "storage-transactions"), r)
	if g.advance("mapping", 4096) != nil {
		t.Fatal("progress")
	}
	stamp := g.snapshot().Progress.LastProgressAt
	if g.advance("mapping", 4096) != nil {
		t.Fatal("repeat")
	}
	if !g.snapshot().Progress.LastProgressAt.Equal(stamp) {
		t.Fatal("retry renewed useful progress")
	}
	state := g.snapshot()
	if state.Progress.Exhausted(stamp.Add(time.Duration(state.Progress.Budget.SilenceSeconds)*time.Second)) != "no_progress_budget_exhausted" {
		t.Fatal("unbounded silence")
	}
}

func TestSafetyPublicationHasSeparatePersistedBudgetWithoutRenewal(t *testing.T) {
	e, body, request, _ := nativeFixture(t, false)
	j, err := e.PrepareStorageTransaction(context.Background(), body)
	if err != nil {
		t.Fatal(err)
	}
	j.Close()
	root := filepath.Join(filepath.Dir(e.cfg.KeyFilePath), "storage-transactions")
	g, _ := openSafety(root, request)
	closed := g.snapshot().Progress.Deadline().Add(-time.Second)
	nativeNow = func() time.Time { return closed }
	// Model useful work continuing until producer closure; an expired silence
	// window cannot acquire a fresh publication budget.
	if err := g.advance("finalizing", 0); err != nil {
		t.Fatal(err)
	}
	if err := g.sourceClosed(closed); err != nil {
		t.Fatal(err)
	}
	deadline := *g.snapshot().PublicationDeadline
	if reason := safetyExhausted(g.snapshot(), closed.Add(time.Minute)); reason != "" {
		t.Fatal("producer deadline blocked publication", reason)
	}
	g, err = openSafety(root, request)
	if err != nil {
		t.Fatal(err)
	}
	if err := g.sourceClosed(closed.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if !g.snapshot().PublicationDeadline.Equal(deadline) {
		t.Fatal("publication retry renewed deadline")
	}
	if reason := safetyExhausted(g.snapshot(), deadline); reason != "publication_budget_exhausted" {
		t.Fatal(reason)
	}
}

func TestStoppedRunnerRecoveryStillClosesOriginalWithinOriginalBudget(t *testing.T) {
	e, body, request, dyn := nativeFixture(t, false)
	j, err := e.PrepareStorageTransaction(context.Background(), body)
	if err != nil {
		t.Fatal(err)
	}
	_ = j.Close()
	root := filepath.Join(filepath.Dir(e.cfg.KeyFilePath), "storage-transactions")
	g, err := openSafety(root, request)
	if err != nil {
		t.Fatal(err)
	}
	if err := g.stop(fault("mapping", "map_schema_invalid", "refused")); err != nil {
		t.Fatal(err)
	}
	original := g.snapshot()
	e.cfg.AgentID, e.cfg.AgentAPIKey, e.cfg.OrchestratorAPIKey = request.AgentID, "registered-fixture-key", "orchestrator-fixture-key"
	e.cfg.OrchestratorURL, e.cfg.OrchestratorVerifySSL, e.cfg.EnableAPIKeyValidation = "https://backend.example.net", true, true
	e.resources = resources.New(1, 1)
	runner, err := newTransactionRunner(context.Background(), e)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		runner.cancel()
		runner.backend.CloseIdleConnections()
		runner.provider.CloseIdleConnections()
		_ = runner.lock.Close()
	}()
	work := runner.work[request.BackupID]
	if work == nil || work.finished || work.held || work.safety.finalizeObservation != nil {
		t.Fatal("durable stop bypassed closure recovery")
	}
	dyn.ClearActions()
	runner.process(work)
	deletes := 0
	for _, action := range dyn.Actions() {
		if action.GetVerb() == "delete" {
			deletes++
			a := action.(k8stest.DeleteAction)
			if action.GetResource() != kvtypes.BackupResource || a.GetDeleteOptions().Preconditions == nil || *a.GetDeleteOptions().Preconditions.UID != types.UID(original.Native.Objects[1].UID) {
				t.Fatal("closure touched foreign custody")
			}
		}
	}
	got := work.safety.snapshot()
	if deletes != 1 || got.Stop.Phase != "native_absent_unproven" || !got.Stop.At.Equal(original.Stop.At) || !got.Progress.Deadline().Equal(original.Progress.Deadline()) || !work.held {
		t.Fatal("original bounded closure changed", deletes, got.Stop)
	}
}
