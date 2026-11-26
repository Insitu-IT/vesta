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

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	ktesting "k8s.io/client-go/testing"
	"vnbui/agent/internal/config"
	"vnbui/agent/internal/operationbudget"
	kvtypes "vnbui/agent/internal/provider/kubevirt"
)

func TestScratchActualFreeBytesAndFreshnessGateNativeStart(t *testing.T) {
	for _, test := range []struct {
		name   string
		sample operationbudget.ScratchSample
		reason string
	}{
		{"exhausted", operationbudget.ScratchSample{AvailableBytes: 1, CapacityBytes: 1 << 40}, "scratch_reserve_insufficient"},
		{"stale", operationbudget.ScratchSample{AvailableBytes: 1 << 40, CapacityBytes: 1 << 40}, "scratch_measurement_stale_or_invalid"},
	} {
		t.Run(test.name, func(t *testing.T) {
			e, body, _, dyn := nativeFixture(t, false)
			sample := test.sample
			sample.At = nativeNow()
			if test.name == "stale" {
				sample.At = sample.At.Add(-time.Minute)
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _ = json.NewEncoder(w).Encode(sample) }))
			defer server.Close()
			e.core, _ = kubernetes.NewForConfig(&rest.Config{Host: server.URL})
			j, err := e.PrepareStorageTransaction(context.Background(), body)
			if err == nil {
				j.Close()
				t.Fatal("unsafe free-space measurement admitted")
			}
			if faultOf(err).Reason != test.reason {
				t.Fatal(err)
			}
			for _, a := range dyn.Actions() {
				if a.GetVerb() == "create" && a.GetResource() == kvtypes.BackupResource {
					t.Fatal("native job created")
				}
			}
		})
	}
}

func TestScratchProbeTamperingAndGrowthStopActiveJob(t *testing.T) {
	e, body, request, dyn := nativeFixture(t, false)
	j, err := e.PrepareStorageTransaction(context.Background(), body)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close() // Closer must not depend on the payload journal's writer lock.
	g, err := openSafety(filepath.Join(filepath.Dir(e.cfg.KeyFilePath), "storage-transactions"), request)
	if err != nil {
		t.Fatal(err)
	}
	pod, _ := dyn.Resource(exportPodResource).Namespace("ns").Get(context.Background(), g.snapshot().Scratch.ProbeName, metav1.GetOptions{})
	changed := pod.DeepCopy()
	containers, _, _ := unstructured.NestedSlice(changed.Object, "spec", "containers")
	containers[0].(map[string]interface{})["image"] = "different-image"
	unstructured.SetNestedSlice(changed.Object, containers, "spec", "containers")
	dyn.Tracker().Update(exportPodResource, changed, "ns")
	if err := e.inspectSafety(context.Background(), request, g); faultOf(err).Reason != "scratch_probe_identity_changed" {
		t.Fatal(err)
	}
	dyn.Tracker().Update(exportPodResource, pod, "ns")
	measuredAt := g.snapshot().Progress.StartedAt.Add(5 * time.Second)
	nativeNow = func() time.Time { return measuredAt }
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(operationbudget.ScratchSample{At: nativeNow(), AvailableBytes: 1, CapacityBytes: 1 << 40})
	}))
	defer server.Close()
	e.core, _ = kubernetes.NewForConfig(&rest.Config{Host: server.URL})
	err = e.inspectSafety(context.Background(), request, g)
	if faultOf(err).Reason != "scratch_exhaustion_risk" {
		t.Fatal(err)
	}
	if err := g.stop(faultOf(err)); err != nil {
		t.Fatal(err)
	}
	e.closeNativeSafety(context.Background(), request, g)
	if g.snapshot().Stop.Phase != "native_absent_unproven" {
		t.Fatal(g.snapshot().Stop)
	}
}

func TestNativeSafetyLostDeleteReplyNeverReplays(t *testing.T) {
	e, body, request, dyn := nativeFixture(t, false)
	j, err := e.PrepareStorageTransaction(context.Background(), body)
	if err != nil {
		t.Fatal(err)
	}
	j.Close()
	root := filepath.Join(filepath.Dir(e.cfg.KeyFilePath), "storage-transactions")
	g, _ := openSafety(root, request)
	_ = g.stop(fault("transferring", "payload_upload_failed", "uncertain"))
	deletes := 0
	dyn.PrependReactor("delete", "virtualmachinebackups", func(ktesting.Action) (bool, runtime.Object, error) {
		deletes++
		return true, nil, errors.New("lost reply")
	})
	e.closeNativeSafety(context.Background(), request, g)
	g, err = openSafety(root, request)
	if err != nil {
		t.Fatal(err)
	}
	e.closeNativeSafety(context.Background(), request, g)
	if deletes != 1 || g.snapshot().Stop.Phase != "native_delete_outcome_uncertain" {
		t.Fatal("uncertain mutation replayed", deletes, g.snapshot().Stop)
	}
}

func TestSourceHealthProbePinsEndpointAndDoesNotFollowRedirect(t *testing.T) {
	e, body, request, dyn := nativeFixture(t, false)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" || r.Header.Get("X-Agent-Key") != "" {
			t.Error("credentials forwarded")
		}
		w.Header().Set("Location", "https://must-not-follow.example/")
		w.WriteHeader(http.StatusFound)
	}))
	defer server.Close()
	raw, _ := json.Marshal([]config.SourceHealthProbe{{Namespace: "ns", VMName: request.Plan.VMName, URL: server.URL}})
	e.cfg.SourceHealthProbesJSON = string(raw)
	j, err := e.PrepareStorageTransaction(context.Background(), body)
	if err == nil {
		j.Close()
		t.Fatal("redirect admitted")
	}
	f := faultOf(err)
	if f.Reason != "service_health_refused" || f.HTTPStatus != 302 || strings.Contains(f.Error(), server.URL) {
		t.Fatal(err)
	}
	for _, a := range dyn.Actions() {
		if a.GetVerb() == "create" && a.GetResource() == kvtypes.BackupResource {
			t.Fatal("native started with unhealthy service")
		}
	}
	g, _ := openSafety(filepath.Join(filepath.Dir(e.cfg.KeyFilePath), "storage-transactions"), request)
	e.cfg.SourceHealthProbesJSON = "[]"
	if g.snapshot().ServiceProbeURL != server.URL {
		t.Fatal("accepted probe changed")
	}
}
