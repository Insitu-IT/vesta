//go:build kubevirt

package kubevirt

import (
	"context"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	dynamicfake "k8s.io/client-go/dynamic/fake"

	"vnbui/agent/internal/backup"
	"vnbui/agent/internal/config"
	"vnbui/agent/internal/models"
	kvtypes "vnbui/agent/internal/provider/kubevirt"
	"vnbui/agent/internal/resources"
)

func TestKubevirtTrackerNameIsStableAndDNSCompatible(t *testing.T) {
	got := kubevirtTrackerName("vm_name.with:characters")
	if got != "vnbui-34451fd515bfe6df" {
		t.Fatalf("tracker name = %q", got)
	}
}

func TestFetchExtentMapPaginatesAndAuthenticates(t *testing.T) {
	requests := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if got := r.Header.Get(exportTokenHeader); got != "secret-token" {
			t.Errorf("token header = %q", got)
		}
		switch r.URL.Query().Get("offset") {
		case "0":
			fmt.Fprint(w, `{"extents":[{"offset":0,"length":512,"type":0,"description":"data"}],"next_offset":512}`)
		case "512":
			fmt.Fprint(w, `{"extents":[{"offset":512,"length":512,"type":1,"description":"hole"}],"next_offset":null}`)
		default:
			http.Error(w, "unexpected offset", http.StatusBadRequest)
		}
	}))
	defer server.Close()

	extents, size, err := fetchExtentMap(context.Background(), server.Client(), server.URL, "secret-token")
	if err != nil {
		t.Fatal(err)
	}
	if requests != 2 || len(extents) != 2 || size != 1024 {
		t.Fatalf("requests=%d extents=%d size=%d", requests, len(extents), size)
	}
}

func TestFetchExtentMapRejectsNonAdvancingPage(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, `{"extents":[],"next_offset":0}`)
	}))
	defer server.Close()

	_, _, err := fetchExtentMap(context.Background(), server.Client(), server.URL, "token")
	if err == nil {
		t.Fatal("expected non-advancing next_offset to fail")
	}
}

func TestFetchExtentMapRejectsPlainHTTPBeforeSendingToken(t *testing.T) {
	called := false
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		called = true
	}))
	defer server.Close()

	_, _, err := fetchExtentMap(context.Background(), server.Client(), server.URL, "secret-token")
	if err == nil {
		t.Fatal("expected plain HTTP endpoint to fail")
	}
	if called {
		t.Fatal("request reached plain HTTP endpoint")
	}
}

func TestPullManifestStoresFullDataExtents(t *testing.T) {
	extents := []mapExtent{
		{Offset: 0, Length: 128, Description: "data"},
		{Offset: 128, Length: 256, Description: "hole"},
		{Offset: 384, Length: 64, Description: "data"},
	}
	stored, err := storedExtents(extents, "Full")
	if err != nil {
		t.Fatal(err)
	}
	if len(stored) != 2 {
		t.Fatalf("stored extents = %d", len(stored))
	}
	if stored[0].DiskOffset != 0 || stored[0].PayloadOffset == nil || *stored[0].PayloadOffset != 0 || stored[1].DiskOffset != 384 || stored[1].PayloadOffset == nil || *stored[1].PayloadOffset != 128 {
		t.Fatalf("unexpected stored extents: %#v", stored)
	}
}

func TestPullManifestSkipsCombinedHoleZeroFullExtent(t *testing.T) {
	stored, err := storedExtents([]mapExtent{
		{Offset: 0, Length: 64, Type: 0, Description: "data"},
		{Offset: 64, Length: 128, Type: 3, Description: "hole,zero"},
		{Offset: 192, Length: 64, Type: 0, Description: "data"},
	}, "Full")
	if err != nil {
		t.Fatal(err)
	}
	if len(stored) != 2 || stored[1].DiskOffset != 192 || stored[1].PayloadOffset == nil || *stored[1].PayloadOffset != 64 {
		t.Fatalf("unexpected full data extents: %#v", stored)
	}
	if _, err := storedExtents([]mapExtent{{Offset: 0, Length: 128, Type: 3, Description: "hole,zero"}}, "Incremental"); err == nil {
		t.Fatal("full allocation flags must not imply incremental cleanliness")
	}
}

func TestPullManifestStoresOnlyDirtyIncrementalExtents(t *testing.T) {
	extents := []mapExtent{
		{Offset: 0, Length: 128, Description: "clean"},
		{Offset: 128, Length: 64, Description: "dirty"},
		{Offset: 192, Length: 832, Description: "clean"},
	}
	stored, err := storedExtents(extents, "Incremental")
	if err != nil {
		t.Fatal(err)
	}
	if len(stored) != 1 || stored[0].DiskOffset != 128 || stored[0].Length != 64 {
		t.Fatalf("unexpected incremental extents: %#v", stored)
	}
}

func TestPullManifestRepresentsDirtyZeroAsZeroFill(t *testing.T) {
	stored, err := storedExtents([]mapExtent{
		{Offset: 128, Length: 64, Description: "dirty"},
		{Offset: 192, Length: 128, Description: "dirty,zero"},
		{Offset: 320, Length: 64, Description: "dirty"},
	}, "Incremental")
	if err != nil {
		t.Fatal(err)
	}
	if len(stored) != 3 || !stored[1].ZeroFill || stored[1].PayloadOffset != nil {
		t.Fatalf("unexpected zero-fill extent: %#v", stored)
	}
	if stored[2].PayloadOffset == nil || *stored[2].PayloadOffset != 64 {
		t.Fatalf("payload offset after zero-fill = %#v, want 64", stored[2].PayloadOffset)
	}
}

func TestPullManifestRejectsUnknownExtentDescriptions(t *testing.T) {
	for _, backupType := range []string{"Full", "Incremental"} {
		t.Run(backupType, func(t *testing.T) {
			_, err := storedExtents([]mapExtent{{Offset: 0, Length: 64, Description: "mystery"}}, backupType)
			if err == nil || !strings.Contains(err.Error(), "unknown") {
				t.Fatalf("error = %v, want explicit unknown-description failure", err)
			}
		})
	}
}

func TestPullManifestRejectsExtentLargerThanReaderSupports(t *testing.T) {
	_, err := storedExtents([]mapExtent{{Offset: 0, Length: uint64(math.MaxInt64) + 1, Description: "dirty"}}, "Incremental")
	if err == nil || !strings.Contains(err.Error(), "exceeds supported range") {
		t.Fatalf("error = %v, want explicit extent-length failure", err)
	}
}

func TestCreatePullBackupUsesMeasuredV184Contract(t *testing.T) {
	client := dynamicfake.NewSimpleDynamicClient(runtime.NewScheme())
	executor := &Executor{cfg: &config.Config{KubevirtBackupScratchPVC: "scratch-pvc", KubevirtNativeTTLSeconds: config.DefaultNativeBackupTTLSeconds}, dynamic: client}
	if _, err := executor.createPullBackup(context.Background(), "vm-ns", "backup-1", "tracker-1", "token-1", true); err != nil {
		t.Fatal(err)
	}
	obj, err := client.Resource(kvtypes.BackupResource).Namespace("vm-ns").Get(context.Background(), "backup-1", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	assertNestedString(t, obj, "backup.kubevirt.io", "spec", "source", "apiGroup")
	assertNestedString(t, obj, "VirtualMachineBackupTracker", "spec", "source", "kind")
	assertNestedString(t, obj, "tracker-1", "spec", "source", "name")
	assertNestedString(t, obj, "Pull", "spec", "mode")
	assertNestedString(t, obj, "scratch-pvc", "spec", "pvcName")
	assertNestedString(t, obj, "token-1", "spec", "tokenSecretRef")
	forceFull, found, err := unstructured.NestedBool(obj.Object, "spec", "forceFullBackup")
	if err != nil || !found || !forceFull {
		t.Fatalf("forceFullBackup = %v, found=%v, err=%v", forceFull, found, err)
	}
}

func TestStartBackupRequiresPullScratchPVCForEveryBackupType(t *testing.T) {
	for _, backupType := range []models.BackupType{models.BackupTypeFull, models.BackupTypeIncremental} {
		t.Run(string(backupType), func(t *testing.T) {
			executor := NewExecutor(&config.Config{KubeNamespace: "vm-ns", KubevirtNativeTTLSeconds: config.DefaultNativeBackupTTLSeconds}, resources.New(1, 1), dynamicfake.NewSimpleDynamicClient(runtime.NewScheme()), "vm-ns")
			executor.s3Config = &backup.S3Config{Endpoint: "s3.example.com", Bucket: "backups", UseSSL: true}
			_, err := executor.StartBackup(&models.BackupRequest{BackupID: "backup-1", VMName: "vm-1", VMNamespace: "vm-ns", VMUID: "stable", BackupType: backupType})
			if err == nil || !strings.Contains(err.Error(), "KUBEVIRT_BACKUP_SCRATCH_PVC is required") {
				t.Fatalf("error = %v, want explicit pull-mode scratch PVC failure", err)
			}
			if active := executor.ActiveCount(); active != 0 {
				t.Fatalf("active backups = %d after rejected request", active)
			}
		})
	}
}

func TestEnsureBackupTrackerReportsCheckpointCoverage(t *testing.T) {
	client := dynamicfake.NewSimpleDynamicClient(runtime.NewScheme())
	executor := &Executor{dynamic: client}
	hasCheckpoint, err := executor.ensureBackupTracker(context.Background(), "vm-ns", "tracker-1", "vm-1", "stable-uid")
	if err != nil || hasCheckpoint {
		t.Fatalf("new tracker: hasCheckpoint=%v err=%v", hasCheckpoint, err)
	}
	tracker, err := client.Resource(kvtypes.BackupTrackerResource).Namespace("vm-ns").Get(context.Background(), "tracker-1", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if err := unstructured.SetNestedField(tracker.Object, "checkpoint-1", "status", "latestCheckpoint", "name"); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Resource(kvtypes.BackupTrackerResource).Namespace("vm-ns").UpdateStatus(context.Background(), tracker, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	hasCheckpoint, err = executor.ensureBackupTracker(context.Background(), "vm-ns", "tracker-1", "vm-1", "stable-uid")
	if err != nil || !hasCheckpoint {
		t.Fatalf("seeded tracker: hasCheckpoint=%v err=%v", hasCheckpoint, err)
	}
}

func TestWaitForPullReadyStopsOnControllerRejection(t *testing.T) {
	rejected := &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "backup.kubevirt.io/v1alpha1",
		"kind":       "VirtualMachineBackup",
		"metadata": map[string]interface{}{
			"name": "backup-1", "namespace": "vm-ns",
		},
		"status": map[string]interface{}{
			"conditions": []interface{}{map[string]interface{}{
				"type":    "Progressing",
				"status":  "False",
				"reason":  "vm specimen-vm has no ChangedBlockTracking, cannot start backup",
				"message": "",
			}},
		},
	}}
	client := dynamicfake.NewSimpleDynamicClient(runtime.NewScheme(), rejected)
	executor := &Executor{dynamic: client}

	started := time.Now()
	_, err := executor.waitForPullReady(context.Background(), "vm-ns", "backup-1")
	if err == nil || !strings.Contains(err.Error(), "no ChangedBlockTracking") {
		t.Fatalf("error = %v, want controller rejection", err)
	}
	if elapsed := time.Since(started); elapsed >= 10*time.Second {
		t.Fatalf("terminal rejection took %v; want first poll, not timeout", elapsed)
	}
}

func assertNestedString(t *testing.T, obj *unstructured.Unstructured, want string, fields ...string) {
	t.Helper()
	got, found, err := unstructured.NestedString(obj.Object, fields...)
	if err != nil || !found || got != want {
		t.Fatalf("%v = %q, found=%v, err=%v; want %q", fields, got, found, err, want)
	}
}
