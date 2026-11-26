//go:build kubevirt

package kubevirt

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"vnbui/agent/internal/models"
	kvtypes "vnbui/agent/internal/provider/kubevirt"
	"vnbui/agent/internal/resources"
	"vnbui/agent/internal/storageupload"
)

func TestSafetyWatchClosesNativeWhileS3AndPayloadJournalAreBlocked(t *testing.T) {
	f := readyExportFixtureVolumes(t, true, false, 4096, 1)
	root := filepath.Join(filepath.Dir(f.e.cfg.KeyFilePath), "storage-transactions")
	g, err := openSafety(root, &f.state.Request)
	if err != nil {
		t.Fatal(err)
	}
	service := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusServiceUnavailable) }))
	defer service.Close()
	if err := g.update(func(s *safetyState) error { s.ServiceProbeURL = service.URL; return nil }); err != nil {
		t.Fatal(err)
	}
	blocked := make(chan struct{})
	var once sync.Once
	transport := f.provider.Transport
	f.provider.Transport = exportTransport(func(req *http.Request) (*http.Response, error) {
		if req.Method == http.MethodPut && req.URL.Query().Get("partNumber") != "" {
			once.Do(func() { close(blocked) })
			<-req.Context().Done()
			return nil, req.Context().Err()
		}
		return transport.RoundTrip(req)
	})
	f.e.resources = resources.New(1, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	work := &transactionWork{request: &f.state.Request, body: f.body, safety: g}
	r := &transactionRunner{executor: f.e, root: root, ctx: ctx, backend: f.backend, provider: f.provider,
		key: "registered-agent-fixture", retry: time.Millisecond, work: map[string]*transactionWork{work.request.BackupID: work}, step: f.e.ReconcileStorageTransaction}
	done := make(chan struct{})
	go func() { defer close(done); r.process(work) }()
	select {
	case <-blocked:
	case <-time.After(3 * time.Second):
		cancel()
		<-done
		t.Fatal("upload did not reach blocked S3 part")
	}
	select {
	case <-done:
	case <-time.After(8 * time.Second):
		cancel()
		<-done
		t.Fatal("native closure waited for S3/backend")
	}
	s := g.snapshot()
	if s.Stop == nil || s.Fault.Reason != "service_health_refused" || s.Stop.Phase != "native_absent_unproven" {
		t.Fatalf("unexpected close: %+v %+v", s.Fault, s.Stop)
	}
	if p := f.e.GetProgress(work.request.BackupID); p == nil || p.Status != models.TaskStatusCleanupRequired {
		t.Fatal("unsafe running status", p)
	}
	if _, err := f.e.dynamic.Resource(kvtypes.BackupTrackerResource).Namespace("ns").Get(context.Background(), f.state.Native.Objects[0].Name, metav1.GetOptions{}); err != nil {
		t.Fatal("accepted tracker was removed", err)
	}
	state := f.disk(t)
	if state.Phase != "held" || state.Acceptance != nil || state.Finalize != nil {
		t.Fatal("failed upload published or lost custody")
	}
}

func TestSafetyQueuedJobExpiresWithoutWaitingForProducerAhead(t *testing.T) {
	e, body, request := runnerFixture(t)
	root := filepath.Join(filepath.Dir(e.cfg.KeyFilePath), "storage-transactions")
	if err := os.MkdirAll(root, 0700); err != nil {
		t.Fatal(err)
	}
	j, err := storageupload.CreateWithKubevirtPrefix(root, body, e.cfg.KubevirtResourcePrefix)
	if err != nil {
		t.Fatal(err)
	}
	j.Close()
	g, err := e.createSafety(root, request)
	if err != nil {
		t.Fatal(err)
	}
	work := &transactionWork{request: request, body: body, safety: g}
	r := &transactionRunner{executor: e, work: map[string]*transactionWork{request.BackupID: work}}
	s := g.snapshot()
	r.expireQueuedWithClock(func() time.Time {
		return s.Progress.StartedAt.Add(time.Duration(s.Progress.Budget.PreparationSeconds) * time.Second)
	})
	if !work.finished || !work.held || g.snapshot().Stop == nil || g.snapshot().Fault.Reason != "admission_wait_exhausted" {
		t.Fatal("expired queued job remained pending")
	}
	if e.GetProgress(request.BackupID).Status != models.TaskStatusCleanupRequired {
		t.Fatal("expired queue retained pending status")
	}
}
