//go:build kubevirt

package kubevirt

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	k8stest "k8s.io/client-go/testing"
	kvtypes "vnbui/agent/internal/provider/kubevirt"
	"vnbui/agent/internal/resources"
	"vnbui/agent/internal/storageupload"
)

func TestDeleteRefusedRestartKeepsIndependentWatchAndOriginalClosure(t *testing.T) {
	f := readyExportFixture(t, false, false, 1)
	if _, err := f.run(); err != nil {
		t.Fatal(err)
	}
	s := f.disk(t)
	f.backend.Transport = exportTransport(func(req *http.Request) (*http.Response, error) {
		if !strings.HasSuffix(req.URL.Path, "/finalize-intent") {
			t.Fatal("unexpected publication request")
		}
		var binding storageupload.FinalizeBinding
		if json.NewDecoder(req.Body).Decode(&binding) != nil {
			t.Fatal("binding")
		}
		resp := exportResponse(map[string]any{"intent_id": "refused-recovery-intent", "binding": binding})
		resp.Header.Set("Cache-Control", "no-store")
		return resp, nil
	})
	d := f.e.dynamic.(*dynamicfake.FakeDynamicClient)
	refused := 0
	d.PrependReactor("delete", "virtualmachinebackups", func(a k8stest.Action) (bool, runtime.Object, error) {
		refused++
		if refused == 1 {
			return true, nil, apierrors.NewForbidden(kvtypes.BackupResource.GroupResource(), a.(k8stest.DeleteAction).GetName(), errors.New("fixture refusal"))
		}
		return false, nil, nil
	})
	if p, err := f.e.ReconcileStorageTransaction(context.Background(), f.body, f.backend, f.provider, func(context.Context) (string, error) { return "fixture-agent", nil }); p != nil || err == nil {
		t.Fatal("refused delete became publication")
	}
	s = f.disk(t)
	root := filepath.Join(filepath.Dir(f.e.cfg.KeyFilePath), "storage-transactions")
	g, err := openSafety(root, &s.Request)
	if err != nil {
		t.Fatal(err)
	}
	original := g.snapshot()
	if s.Finalize == nil || !s.Finalize.DeleteRefused || s.Finalize.DeleteResourceVersion == "" || original.Stop != nil {
		t.Fatal("did not reach actual refusal-before-stop crash window")
	}
	service := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusServiceUnavailable) }))
	defer service.Close()
	if err := g.update(func(s *safetyState) error { s.ServiceProbeURL = service.URL; return nil }); err != nil {
		t.Fatal(err)
	}
	f.e.cfg.AgentID, f.e.cfg.AgentAPIKey, f.e.cfg.OrchestratorAPIKey = s.Request.AgentID, "registered-fixture-key", "orchestrator-fixture-key"
	f.e.cfg.OrchestratorURL, f.e.cfg.OrchestratorVerifySSL, f.e.cfg.EnableAPIKeyValidation = "https://backend.example.net", true, true
	f.e.resources = resources.New(1, 1)
	runner, err := newTransactionRunner(context.Background(), f.e)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		runner.cancel()
		runner.backend.CloseIdleConnections()
		runner.provider.CloseIdleConnections()
		_ = runner.lock.Close()
	}()
	work := runner.work[s.Request.BackupID]
	if work == nil || work.finished || work.held || work.safety == nil || work.safety.finalizeObservation != nil || len(runner.queue) != 1 {
		t.Fatal("refused finalize bypassed watch recovery")
	}
	// The original finalizer must remain refused even while its watcher is queued.
	if p, err := f.e.ReconcileStorageTransaction(context.WithValue(context.Background(), safetyContextKey{}, work.safety), f.body, f.backend, f.provider, func(context.Context) (string, error) { return "fixture-agent", nil }); p != nil || err == nil || refused != 1 {
		t.Fatal("refusal was weakened on replay")
	}
	d.ClearActions()
	done := make(chan struct{})
	watched := make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { defer close(watched); runner.watchSafety(work, cancel, done) }()
	select {
	case <-watched:
	case <-time.After(8 * time.Second):
		close(done)
		<-watched
		t.Fatal("independent watcher did not close refused native")
	}
	if ctx.Err() == nil {
		t.Fatal("watch did not cancel producer")
	}
	got := work.safety.snapshot()
	if got.Stop == nil || got.Fault.Reason != "service_health_refused" || got.Stop.Phase != "native_absent_unproven" || !got.Progress.Deadline().Equal(original.Progress.Deadline()) || !work.held || work.safety.finalizeObservation != nil {
		t.Fatal("bounded closure/custody changed", got.Stop)
	}
	deletes := 0
	for _, a := range d.Actions() {
		if a.GetVerb() == "delete" {
			deletes++
			p := a.(k8stest.DeleteAction).GetDeleteOptions().Preconditions
			if a.GetResource() != kvtypes.BackupResource || p == nil || p.UID == nil || *p.UID != types.UID(s.Native.Objects[1].UID) {
				t.Fatal("closure touched foreign custody")
			}
		}
	}
	if deletes != 1 {
		t.Fatal("missing original-only closure", deletes)
	}
	if _, err := d.Resource(kvtypes.BackupTrackerResource).Namespace(s.Request.Plan.Source.Namespace).Get(context.Background(), s.Native.Objects[0].Name, metav1.GetOptions{}); err != nil {
		t.Fatal("tracker custody removed", err)
	}
	final := f.disk(t)
	if !final.Finalize.DeleteRefused || final.Finalize.Proof != nil || final.Finalize.Reported || final.Finalize.TerminalResourceVersion != "" {
		t.Fatal("refused restart acquired publication proof")
	}
}
