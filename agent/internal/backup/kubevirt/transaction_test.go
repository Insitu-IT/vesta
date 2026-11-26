//go:build kubevirt

package kubevirt

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	ktesting "k8s.io/client-go/testing"

	"vnbui/agent/internal/backup"
	"vnbui/agent/internal/config"
	"vnbui/agent/internal/models"
	kvtypes "vnbui/agent/internal/provider/kubevirt"
	"vnbui/agent/internal/resources"
)

func TestNativeAbortKeepsTrackerUntilControllerCleanup(t *testing.T) {
	e, s3, s, tx := transactionFixture(t)
	ctx := context.Background()
	tx.BackupUID = "vmb-original"
	tx.Phase = "cleanup_required"
	dyn := e.dynamic.(*dynamicfake.FakeDynamicClient)
	name := "vnbui-" + tx.BackupID
	obj := &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "backup.kubevirt.io/v1alpha1", "kind": "VirtualMachineBackup",
		"metadata": map[string]interface{}{"name": name, "namespace": "test", "uid": string(tx.BackupUID)},
	}}
	obj.SetFinalizers([]string{"backup.kubevirt.io/vmbackup-protection"})
	if _, err := dyn.Resource(kvtypes.BackupResource).Namespace("test").Create(ctx, obj, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	exportPresent, utilityAttached := true, true
	dyn.PrependReactor("delete", "virtualmachinebackups", func(a ktesting.Action) (bool, runtime.Object, error) {
		tracker, err := dyn.Tracker().Get(kvtypes.BackupTrackerResource, "test", tx.Tracker)
		if err != nil || tracker.(*unstructured.Unstructured).GetUID() != tx.TrackerUID {
			t.Fatal("native abort lost original tracker")
		}
		p := a.(ktesting.DeleteAction).GetDeleteOptions().Preconditions
		if p == nil || p.UID == nil || *p.UID != tx.BackupUID {
			t.Fatal("unfenced VMB delete")
		}
		deleting := obj.DeepCopy()
		now := metav1.Now()
		deleting.SetDeletionTimestamp(&now)
		return true, nil, dyn.Tracker().Update(kvtypes.BackupResource, deleting, "test")
	})
	dyn.PrependReactor("delete", "virtualmachinebackuptrackers", func(a ktesting.Action) (bool, runtime.Object, error) {
		if exportPresent || utilityAttached {
			t.Fatal("tracker deleted before controller cleanup")
		}
		if _, err := dyn.Tracker().Get(kvtypes.BackupResource, "test", name); !apierrors.IsNotFound(err) {
			t.Fatal("tracker deleted before VMB absence")
		}
		p := a.(ktesting.DeleteAction).GetDeleteOptions().Preconditions
		if p == nil || p.UID == nil || *p.UID != tx.TrackerUID {
			t.Fatal("unfenced tracker delete")
		}
		return false, nil, nil
	})
	s.objects[tx.Prefix+"payload"] = true
	if err := e.saveTransaction(tx); err != nil {
		t.Fatal(err)
	}
	e.recoverTransactions(s3)
	if e.recovered || e.GetProgress(tx.BackupID).Status != models.TaskStatusCleanupRequired {
		t.Fatal("accepted deletion treated as cleanup")
	}
	data, err := os.ReadFile(filepath.Join(e.transactionDir(), tx.BackupID+".json"))
	if err != nil {
		t.Fatal(err)
	}
	var saved pullTransaction
	if err := json.Unmarshal(data, &saved); err != nil {
		t.Fatal(err)
	}
	if saved.AbortPhase != "vmb_deleting" {
		t.Fatalf("phase %q", saved.AbortPhase)
	}
	// Controller reconciliation, not an agent mutation: abort advances checkpoint,
	// clears export/utility state, then releases the VMB protection finalizer.
	tracker, err := dyn.Tracker().Get(kvtypes.BackupTrackerResource, "test", tx.Tracker)
	if err != nil {
		t.Fatal(err)
	}
	updated := tracker.(*unstructured.Unstructured).DeepCopy()
	if err := unstructured.SetNestedField(updated.Object, "next", "status", "latestCheckpoint", "name"); err != nil {
		t.Fatal(err)
	}
	if err := dyn.Tracker().Update(kvtypes.BackupTrackerResource, updated, "test"); err != nil {
		t.Fatal(err)
	}
	exportPresent, utilityAttached = false, false
	if err := dyn.Tracker().Delete(kvtypes.BackupResource, "test", name); err != nil {
		t.Fatal(err)
	}
	restarted := NewExecutor(e.cfg, resources.New(1, 1), dyn, "test")
	restarted.recoverTransactions(s3)
	p := restarted.GetProgress(tx.BackupID)
	if !restarted.recovered || p.Status != models.TaskStatusFailed || p.CheckpointCommitted == nil || *p.CheckpointCommitted {
		t.Fatalf("abort promoted or not finished: %+v", p)
	}
	if _, err := dyn.Tracker().Get(kvtypes.BackupTrackerResource, "test", tx.Tracker); !apierrors.IsNotFound(err) {
		t.Fatal("abort checkpoint retained")
	}
}

func TestAbortRecoveryPhaseBoundaries(t *testing.T) {
	for _, phase := range []string{"", "vmb_deleting", "vmb_absent", "tracker_deleting", "invalidated", "unknown"} {
		for _, trackerState := range []string{"original", "missing", "replacement"} {
			t.Run(phase+"/"+trackerState, func(t *testing.T) {
				e, s3, _, tx := transactionFixture(t)
				dyn := e.dynamic.(*dynamicfake.FakeDynamicClient)
				tx.Phase, tx.AbortPhase = "cleanup_required", phase
				if trackerState != "original" {
					obj, err := dyn.Tracker().Get(kvtypes.BackupTrackerResource, "test", tx.Tracker)
					if err != nil {
						t.Fatal(err)
					}
					if err := dyn.Tracker().Delete(kvtypes.BackupTrackerResource, "test", tx.Tracker); err != nil {
						t.Fatal(err)
					}
					if trackerState == "replacement" {
						u := obj.(*unstructured.Unstructured).DeepCopy()
						u.SetUID("replacement")
						if err := dyn.Tracker().Create(kvtypes.BackupTrackerResource, u, "test"); err != nil {
							t.Fatal(err)
						}
					}
				}
				if err := e.saveTransaction(tx); err != nil {
					t.Fatal(err)
				}
				e.recoverTransactions(s3)
				want := phase == "invalidated" || (phase != "unknown" && (trackerState == "original" || (phase == "tracker_deleting" && trackerState == "missing")))
				if e.recovered != want {
					t.Fatalf("recovered=%v want=%v", e.recovered, want)
				}
				if trackerState == "replacement" {
					obj, err := dyn.Tracker().Get(kvtypes.BackupTrackerResource, "test", tx.Tracker)
					if err != nil || obj.(*unstructured.Unstructured).GetUID() != "replacement" {
						t.Fatal("replacement mutated")
					}
				}
			})
		}
	}
}

// Model the API server's finalizer semantics and the relevant missing-tracker
// branch in both v1.8.4 and v1.9.0: DELETE sets deletionTimestamp, while the
// controller returns before export/utility-volume cleanup or finalizer removal.
// This is deliberately not a claim to emulate the whole KubeVirt controller.
func TestMissingTrackerFinalizerHoldsAcrossRestart(t *testing.T) {
	for _, replacement := range []bool{false, true} {
		t.Run(fmt.Sprintf("replacement_tracker_%v", replacement), func(t *testing.T) {
			e, s3, s, tx := transactionFixture(t)
			ctx := context.Background()
			tx.BackupUID = "backup-original"
			tx.Phase = "cleanup_required"
			if !replacement {
				tx.Phase = "failed" // Historical false terminal record must be revalidated.
			}
			dyn := e.dynamic.(*dynamicfake.FakeDynamicClient)
			name := "vnbui-" + tx.BackupID
			obj := &unstructured.Unstructured{Object: map[string]interface{}{
				"apiVersion": "backup.kubevirt.io/v1alpha1", "kind": "VirtualMachineBackup",
				"metadata": map[string]interface{}{"name": name, "namespace": "test", "uid": string(tx.BackupUID)},
				"spec":     map[string]interface{}{"source": map[string]interface{}{"kind": "VirtualMachineBackupTracker", "name": tx.Tracker}},
			}}
			obj.SetFinalizers([]string{"backup.kubevirt.io/vmbackup-protection"})
			if _, err := dyn.Resource(kvtypes.BackupResource).Namespace("test").Create(ctx, obj, metav1.CreateOptions{}); err != nil {
				t.Fatal(err)
			}
			dyn.PrependReactor("delete", "virtualmachinebackups", func(action ktesting.Action) (bool, runtime.Object, error) {
				a := action.(ktesting.DeleteAction)
				if p := a.GetDeleteOptions().Preconditions; p == nil || p.UID == nil || *p.UID != tx.BackupUID {
					t.Fatal("VMB DELETE was not UID fenced")
				}
				stored, err := dyn.Tracker().Get(kvtypes.BackupResource, "test", name)
				if err != nil {
					return true, nil, err
				}
				deleting := stored.(*unstructured.Unstructured).DeepCopy()
				now := metav1.Now()
				deleting.SetDeletionTimestamp(&now)
				return true, nil, dyn.Tracker().Update(kvtypes.BackupResource, deleting, "test")
			})
			s.objects[tx.Prefix+"payload"] = true
			if err := e.saveTransaction(tx); err != nil {
				t.Fatal(err)
			}
			e.recoverTransactions(s3)
			stuck, err := dyn.Resource(kvtypes.BackupResource).Namespace("test").Get(ctx, name, metav1.GetOptions{})
			if err != nil || stuck.GetDeletionTimestamp() == nil || len(stuck.GetFinalizers()) != 1 {
				t.Fatalf("control did not retain terminating VMB: %v %v", stuck, err)
			}
			if replacement {
				if err := dyn.Tracker().Delete(kvtypes.BackupTrackerResource, "test", tx.Tracker); err != nil {
					t.Fatal(err)
				}
				tracker := &unstructured.Unstructured{Object: map[string]interface{}{
					"apiVersion": "backup.kubevirt.io/v1alpha1", "kind": "VirtualMachineBackupTracker",
					"metadata": map[string]interface{}{"name": tx.Tracker, "namespace": "test", "uid": "replacement"},
				}}
				if _, err := dyn.Resource(kvtypes.BackupTrackerResource).Namespace("test").Create(ctx, tracker, metav1.CreateOptions{}); err != nil {
					t.Fatal(err)
				}
			}
			dyn.ClearActions()
			restarted := NewExecutor(e.cfg, resources.New(1, 1), dyn, "test")
			restarted.recoverTransactions(s3)
			if restarted.recovered || restarted.GetProgress(tx.BackupID).Status != models.TaskStatusCleanupRequired {
				t.Fatal("accepted DELETE unblocked admission or reported compensation complete")
			}
			for _, a := range dyn.Actions() {
				if a.GetVerb() == "delete" || a.GetVerb() == "patch" || a.GetVerb() == "update" {
					t.Fatalf("held recovery mutated controller-owned state or replacement: %v", a)
				}
			}
			if s.objects[tx.Prefix+"payload"] || !s.objects["backups/other/keep"] {
				t.Fatal("wrong S3 compensation")
			}
			if !replacement {
				// Stand in for separately verified controller/operator cleanup. A
				// later heartbeat can release the hold only after actual absence.
				if err := dyn.Tracker().Delete(kvtypes.BackupResource, "test", name); err != nil {
					t.Fatal(err)
				}
				restarted.recoverTransactions(s3)
				if !restarted.recovered || restarted.GetProgress(tx.BackupID).Status != models.TaskStatusFailed {
					t.Fatal("absence did not release hold")
				}
			}
		})
	}
}

func TestAbortedBackupReplacementIsNotDeleted(t *testing.T) {
	e, _, _, tx := transactionFixture(t)
	tx.BackupUID = "original-backup"
	obj := &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "backup.kubevirt.io/v1alpha1", "kind": "VirtualMachineBackup",
		"metadata": map[string]interface{}{"name": "vnbui-" + tx.BackupID, "namespace": "test", "uid": "replacement-backup"},
	}}
	r := e.dynamic.Resource(kvtypes.BackupResource).Namespace("test")
	if _, err := r.Create(context.Background(), obj, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := e.removeAbortedBackup(context.Background(), tx); err == nil {
		t.Fatal("replacement accepted")
	}
	if _, err := r.Get(context.Background(), obj.GetName(), metav1.GetOptions{}); apierrors.IsNotFound(err) {
		t.Fatal("replacement deleted")
	}
}

// A minimal versioned S3 server exercises the real client, including prefix
// selection, object versions, manifest PUT and multipart completion.
type transactionS3 struct {
	mu            sync.Mutex
	objects       map[string]bool
	failDelete    bool
	afterManifest func()
}

func (s *transactionS3) serve(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := strings.TrimPrefix(r.URL.Path, "/bucket/")
	q := r.URL.Query()
	_, _ = io.Copy(io.Discard, r.Body)
	switch {
	case r.Method == "GET" && q.Has("uploads"):
		fmt.Fprint(w, `<ListMultipartUploadsResult><Bucket>bucket</Bucket><IsTruncated>false</IsTruncated></ListMultipartUploadsResult>`)
	case r.Method == "GET" && q.Has("versions"):
		fmt.Fprint(w, `<ListVersionsResult><Name>bucket</Name><IsTruncated>false</IsTruncated>`)
		for k := range s.objects {
			if strings.HasPrefix(k, q.Get("prefix")) {
				fmt.Fprintf(w, `<Version><Key>%s</Key><VersionId>v1</VersionId><IsLatest>true</IsLatest></Version>`, k)
			}
		}
		fmt.Fprint(w, `</ListVersionsResult>`)
	case r.Method == "DELETE":
		if s.failDelete {
			w.WriteHeader(403)
			fmt.Fprint(w, `<Error><Code>AccessDenied</Code><Message>denied</Message></Error>`)
			return
		}
		delete(s.objects, key)
		w.WriteHeader(204)
	case r.Method == "POST" && q.Has("uploads"):
		fmt.Fprintf(w, `<InitiateMultipartUploadResult><Bucket>bucket</Bucket><Key>%s</Key><UploadId>upload</UploadId></InitiateMultipartUploadResult>`, key)
	case r.Method == "POST" && q.Has("uploadId"):
		s.objects[key] = true
		fmt.Fprintf(w, `<CompleteMultipartUploadResult><Bucket>bucket</Bucket><Key>%s</Key><ETag>"etag"</ETag></CompleteMultipartUploadResult>`, key)
	case r.Method == "PUT":
		w.Header().Set("ETag", `"etag"`)
		if !q.Has("partNumber") {
			s.objects[key] = true
			if strings.HasSuffix(key, ".manifest.json") && s.afterManifest != nil {
				s.afterManifest()
			}
		}
	default:
		w.WriteHeader(400)
		fmt.Fprintf(w, "unexpected %s %s", r.Method, r.URL)
	}
}

func transactionFixture(t *testing.T) (*Executor, *backup.S3Config, *transactionS3, *pullTransaction) {
	t.Helper()
	tracker := &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "backup.kubevirt.io/v1alpha1", "kind": "VirtualMachineBackupTracker",
		"metadata": map[string]interface{}{"name": kubevirtTrackerName("test/stable"), "namespace": "test", "uid": "original", "annotations": map[string]interface{}{"vnbui.insitu/vm-uid": "stable"}},
		"spec":     map[string]interface{}{"source": map[string]interface{}{"name": "vm"}},
		"status":   map[string]interface{}{"latestCheckpoint": map[string]interface{}{"name": "previous"}},
	}}
	vm := &unstructured.Unstructured{Object: map[string]interface{}{"apiVersion": "kubevirt.io/v1", "kind": "VirtualMachine", "metadata": map[string]interface{}{"name": "vm", "namespace": "test", "uid": "stable"}}}
	dyn := dynamicfake.NewSimpleDynamicClient(runtime.NewScheme(), tracker, vm)
	cfg := &config.Config{KubeNamespace: "test", KeyFilePath: filepath.Join(t.TempDir(), "agent.key"), KubevirtBackupScratchPVC: "scratch", KubevirtNativeTTLSeconds: config.DefaultNativeBackupTTLSeconds}
	e := NewExecutor(cfg, resources.New(1, 1), dyn, "test")
	s := &transactionS3{objects: map[string]bool{"backups/other/keep": true}}
	server := httptest.NewServer(http.HandlerFunc(s.serve))
	t.Cleanup(server.Close)
	s3 := &backup.S3Config{Endpoint: strings.TrimPrefix(server.URL, "http://"), Bucket: "bucket", Prefix: "backups", Region: "us-east-1", AccessKey: "test", SecretKey: "test"}
	tx := &pullTransaction{BackupID: "test-backup", VMName: "vm", VMUID: "stable", Namespace: "test", Tracker: tracker.GetName(), TrackerUID: "original", Checkpoint: "next", Endpoint: s3.Endpoint, Bucket: s3.Bucket, Prefix: "backups/test-backup/", Phase: "prepared"}
	return e, s3, s, tx
}

func TestTrackerDisappearsAfterPayloadAndManifestPublication(t *testing.T) {
	for _, failDelete := range []bool{false, true} {
		t.Run(fmt.Sprintf("delete_failure_%v", failDelete), func(t *testing.T) {
			e, s3, s, _ := transactionFixture(t)
			s.failDelete = failDelete
			s.afterManifest = func() {
				if !s.objects["backups/test-backup/data.cbt.vnbu"] {
					t.Error("control fired before payload publication")
				}
				if err := e.dynamic.Resource(kvtypes.BackupTrackerResource).Namespace("test").Delete(context.Background(), kubevirtTrackerName("test/stable"), metav1.DeleteOptions{}); err != nil {
					t.Error(err)
				}
			}
			export := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/map" {
					fmt.Fprint(w, `{"extents":[{"offset":0,"length":4,"description":"data"}]}`)
					return
				}
				w.Header().Set("Content-Range", "bytes 0-3/4")
				w.WriteHeader(http.StatusPartialContent)
				fmt.Fprint(w, "data")
			}))
			defer export.Close()
			ca := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: export.Certificate().Raw}))
			e.dynamic.(*dynamicfake.FakeDynamicClient).PrependReactor("create", "virtualmachinebackups", func(action ktesting.Action) (bool, runtime.Object, error) {
				obj := action.(ktesting.CreateAction).GetObject().(*unstructured.Unstructured)
				obj.SetUID("backup-original")
				obj.Object["status"] = map[string]interface{}{"type": "Full", "checkpointName": "next", "endpointCert": ca,
					"includedVolumes": []interface{}{map[string]interface{}{"volumeName": "data", "dataEndpoint": export.URL + "/data", "mapEndpoint": export.URL + "/map"}}}
				return false, nil, nil
			})
			key := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("a", 32)))
			req := &models.BackupRequest{BackupID: "test-backup", VMName: "vm", VMNamespace: "test", VMUID: "stable", BackupType: models.BackupTypeFull, EncryptionType: models.EncryptionTypeAES256GCM, EncryptionKey: &key}
			p := &models.BackupProgress{}
			if err := e.resources.AcquireBackupSlot(); err != nil {
				t.Fatal(err)
			}
			e.transactionMu.Lock()
			ctx, cancel := context.WithCancel(context.Background())
			e.runPullBackup(ctx, cancel, req, p, s3)
			want := models.TaskStatusCleanupRequired // External tracker loss cannot certify native cleanup.
			if p.Status != want || p.CheckpointCommitted == nil || *p.CheckpointCommitted || p.S3Location == nil || *p.S3Location != "s3://bucket/backups/test-backup" {
				t.Fatalf("progress = %+v", p)
			}
			if p.ErrorMessage == nil || !strings.Contains(*p.ErrorMessage, "tracker disappeared") {
				t.Fatalf("wrong failure: %v", p.ErrorMessage)
			}
			s.mu.Lock()
			if !s.objects["backups/other/keep"] {
				t.Error("compensation escaped backup prefix")
			}
			if s.objects["backups/test-backup/data.cbt.vnbu"] != failDelete || s.objects["backups/test-backup/data.manifest.json"] != failDelete {
				t.Errorf("objects = %v", s.objects)
			}
			s.failDelete = false
			s.mu.Unlock()
			// Recreate executor, retaining only the durable journal and API/S3 state.
			restarted := NewExecutor(e.cfg, resources.New(1, 1), e.dynamic, "test")
			restarted.recoverTransactions(s3)
			if restarted.recovered || restarted.GetProgress(req.BackupID).Status != models.TaskStatusCleanupRequired {
				t.Fatal("restart released hold despite externally missing tracker")
			}
		})
	}
}

func TestRecoveryRequiresBothPublicationAndCheckpoint(t *testing.T) {
	for _, phase := range []string{"prepared", "published", "cleanup_required"} {
		t.Run(phase, func(t *testing.T) {
			e, s3, s, tx := transactionFixture(t)
			tx.Phase = phase
			s.objects[tx.Prefix+"payload"] = true
			obj, _ := e.dynamic.Resource(kvtypes.BackupTrackerResource).Namespace("test").Get(context.Background(), tx.Tracker, metav1.GetOptions{})
			_ = unstructured.SetNestedField(obj.Object, "next", "status", "latestCheckpoint", "name")
			_, _ = e.dynamic.Resource(kvtypes.BackupTrackerResource).Namespace("test").Update(context.Background(), obj, metav1.UpdateOptions{})
			if err := e.saveTransaction(tx); err != nil {
				t.Fatal(err)
			}
			e.recoverTransactions(s3)
			want := models.TaskStatusFailed
			if phase == "published" {
				want = models.TaskStatusCompleted
			}
			if got := e.GetProgress(tx.BackupID).Status; got != want {
				t.Fatalf("status %s want %s", got, want)
			}
			if s.objects[tx.Prefix+"payload"] != (phase == "published") {
				t.Fatal("wrong compensation decision")
			}
		})
	}
}

func TestJournalFailureAndDestinationChangeFailClosed(t *testing.T) {
	e, s3, _, tx := transactionFixture(t)
	if err := os.WriteFile(e.cfg.KeyFilePath, []byte("not a directory"), 0600); err != nil {
		t.Fatal(err)
	}
	e.cfg.KeyFilePath = filepath.Join(e.cfg.KeyFilePath, "agent.key")
	if err := e.saveTransaction(tx); err == nil {
		t.Fatal("unwritable journal accepted")
	}
	s3.Bucket = "different"
	if err := deleteBackupPrefix(context.Background(), s3, tx); err == nil {
		t.Fatal("changed destination accepted")
	}
	s3.Bucket = tx.Bucket
	s3.UseSSL = !tx.UseSSL
	if err := deleteBackupPrefix(context.Background(), s3, tx); err == nil {
		t.Fatal("changed destination protocol accepted")
	}
}

func TestAbortFencesReplacementAndStillCompensatesS3(t *testing.T) {
	e, s3, s, tx := transactionFixture(t)
	s.objects[tx.Prefix+"payload"] = true
	obj, _ := e.dynamic.Resource(kvtypes.BackupTrackerResource).Namespace("test").Get(context.Background(), tx.Tracker, metav1.GetOptions{})
	obj.SetUID("replacement")
	_, _ = e.dynamic.Resource(kvtypes.BackupTrackerResource).Namespace("test").Update(context.Background(), obj, metav1.UpdateOptions{})
	err := e.compensate(context.Background(), tx, s3)
	if err == nil || !strings.Contains(err.Error(), "refusing replacement") {
		t.Fatalf("replacement fence: %v", err)
	}
	if _, err := e.dynamic.Resource(kvtypes.BackupTrackerResource).Namespace("test").Get(context.Background(), tx.Tracker, metav1.GetOptions{}); err != nil {
		t.Fatal("replacement tracker removed")
	}
	if s.objects[tx.Prefix+"payload"] {
		t.Fatal("tracker failure prevented S3 compensation")
	}
}

func TestUnreadableJournalBlocksPreviouslyRecoveredExecutor(t *testing.T) {
	e, s3, _, _ := transactionFixture(t)
	e.recovered = true
	if err := os.WriteFile(e.transactionDir(), []byte("invalid directory"), 0600); err != nil {
		t.Fatal(err)
	}
	e.recoverTransactions(s3)
	if e.recovered {
		t.Fatal("journal read failure left admission enabled")
	}
}

func TestRepeatedBackupIDCannotOverwriteCommittedTransaction(t *testing.T) {
	e, s3, _, tx := transactionFixture(t)
	e.s3Config = s3
	e.recovered = true
	prior := &models.BackupProgress{BackupID: tx.BackupID, VMName: &tx.VMName, Status: models.TaskStatusCompleted}
	e.jobs[tx.BackupID] = prior
	if err := e.saveTransaction(tx); err != nil {
		t.Fatal(err)
	}
	got, err := e.StartBackup(&models.BackupRequest{BackupID: tx.BackupID, VMName: tx.VMName, VMNamespace: tx.Namespace, VMUID: tx.VMUID, BackupType: models.BackupTypeFull})
	if err != nil || got != prior || e.ActiveCount() != 0 {
		t.Fatalf("repeated delivery: got %v, error %v, active %d", got, err, e.ActiveCount())
	}
	if len(e.dynamic.(*dynamicfake.FakeDynamicClient).Actions()) != 0 {
		t.Fatal("repeated delivery reached cluster APIs")
	}
}
