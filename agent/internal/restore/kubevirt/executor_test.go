//go:build kubevirt

package kubevirt

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/dynamic/fake"
	ktesting "k8s.io/client-go/testing"
	"vnbui/agent/internal/config"
	"vnbui/agent/internal/models"
	"vnbui/agent/internal/operationbudget"
	"vnbui/agent/internal/resources"
	"vnbui/agent/internal/restore"
)

const testRestoreImage = "registry.example/vnbui/agent@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func TestQueuedRestoreReportsExhaustionWhileOtherReconciliationIsBlocked(t *testing.T) {
	e, state, client := controllerFixture(t)
	budget, err := operationbudget.DefaultPolicy().Begin(1, 8<<20, 24*time.Hour, time.Now().Add(-10*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	state.Phase, state.Budget = "prepared", budget
	e.states[state.Request.RestoreID] = state
	client.ClearActions()
	for range 2 {
		p := e.GetProgress(state.Request.RestoreID)
		if p.Status != models.TaskStatusCleanupRequired || p.ErrorMessage == nil || !strings.Contains(*p.ErrorMessage, "admission_wait_exhausted") {
			t.Fatal("expired queue remained running", p)
		}
	}
	if len(client.Actions()) != 0 || state.Progress.Status != models.TaskStatusRunning {
		t.Fatal("negative observation mutated Kubernetes or worker custody")
	}
}

func TestStartRestoresRequiresDigestPinnedWorkerImage(t *testing.T) {
	for _, image := range []string{
		"registry.example/vnbui/agent:release",
		"registry.example/vnbui/agent:latest",
		"registry.example/vnbui/agent@sha256:short",
		"registry.example/vnbui/agent@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaG",
		"registry.example/vnbui/agent@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa trailing",
	} {
		t.Run(image, func(t *testing.T) {
			cfg := &config.Config{
				AgentID: "agent", KeyFilePath: filepath.Join(t.TempDir(), "agent.key"),
				KubevirtRestoreImage: image, EnableAPIKeyValidation: true,
				KubevirtRestoreNamespaces: []string{"ns"},
				OrchestratorAPIKey:        "test", OrchestratorVerifySSL: true,
			}
			e := NewExecutor(cfg, resources.New(1, 1), nil, "ns")
			if err := e.StartRestores(context.Background()); err == nil {
				t.Fatal("mutable or malformed restore worker image admitted")
			}
		})
	}
}

func controllerFixture(t *testing.T) (*Executor, *restoreState, *fake.FakeDynamicClient) {
	return controllerFixtureInNamespace(t, "ns")
}

func controllerFixtureInNamespace(t *testing.T, namespace string) (*Executor, *restoreState, *fake.FakeDynamicClient) {
	t.Helper()
	req := restoreFixture(t)
	req.Target.Namespace = namespace
	bundle, digest, err := ValidatePlan(req)
	if err != nil {
		t.Fatal(err)
	}
	client := fake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), map[schema.GroupVersionResource]string{podGVR: "PodList"})
	serial := 0
	client.PrependReactor("create", "*", func(action ktesting.Action) (bool, runtime.Object, error) {
		obj := action.(ktesting.CreateAction).GetObject().(*unstructured.Unstructured)
		serial++
		obj.SetUID(types.UID(fmt.Sprintf("uid-%d", serial)))
		return false, nil, nil
	})
	vm, err := RenderVM(capturedFixture(), req.Target, bundle.Members[0].Request.Plan.Source)
	if err != nil {
		t.Fatal(err)
	}
	state := &restoreState{Schema: 1, Request: *req, PlanSHA: digest, Token: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Image: testRestoreImage, Phase: "provisioning", PVCUIDs: map[string]string{}, VM: vm, Progress: models.RestoreProgress{RestoreID: req.RestoreID, Status: models.TaskStatusRunning}}
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	executor := NewExecutor(&config.Config{KubevirtRestoreNamespaces: []string{namespace}}, resources.New(2, 1), client, "ns")
	executor.root = root
	executor.states[req.RestoreID] = state
	if err = executor.save(state); err != nil {
		t.Fatal(err)
	}
	return executor, state, client
}

func completeWorker(t *testing.T, s *restoreState, c *fake.FakeDynamicClient) {
	t.Helper()
	ctx := context.Background()
	job, err := c.Resource(jobGVR).Namespace(s.Request.Target.Namespace).Get(ctx, resourceName(s), metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	job.Object["status"] = map[string]interface{}{"conditions": []interface{}{map[string]interface{}{"type": "Complete", "status": "True"}}}
	if _, err = c.Resource(jobGVR).Namespace(s.Request.Target.Namespace).UpdateStatus(ctx, job, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	for _, disk := range s.Request.Target.Disks {
		pvc, _ := c.Resource(pvcGVR).Namespace(s.Request.Target.Namespace).Get(ctx, disk.PVCName, metav1.GetOptions{})
		pvc.Object["status"] = map[string]interface{}{"phase": "Bound"}
		if _, err = c.Resource(pvcGVR).Namespace(s.Request.Target.Namespace).UpdateStatus(ctx, pvc, metav1.UpdateOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	pod := &unstructured.Unstructured{Object: map[string]interface{}{"apiVersion": "v1", "kind": "Pod", "metadata": map[string]interface{}{"name": "worker", "namespace": s.Request.Target.Namespace, "labels": map[string]interface{}{"batch.kubernetes.io/controller-uid": s.JobUID}, "ownerReferences": []interface{}{map[string]interface{}{"apiVersion": "batch/v1", "kind": "Job", "name": resourceName(s), "uid": s.JobUID, "controller": true}}}, "status": map[string]interface{}{"phase": "Succeeded"}}}
	if _, err = c.Resource(podGVR).Namespace(s.Request.Target.Namespace).Create(ctx, pod, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
}

func TestFreshControllerCreatesMixedPVCsThenHaltedVM(t *testing.T) {
	e, state, client := controllerFixture(t)
	ctx := context.Background()
	if err := e.reconcile(ctx, state); err != nil {
		t.Fatal(err)
	}
	if state.JobUID == "" || state.SecretUID == "" || len(state.PVCUIDs) != 2 || state.VMUID != "" {
		t.Fatal("wrong resource progression", state)
	}
	job, _ := client.Resource(jobGVR).Namespace("ns").Get(ctx, resourceName(state), metav1.GetOptions{})
	podSpec, _, _ := unstructured.NestedMap(job.Object, "spec", "template", "spec")
	if podSpec["automountServiceAccountToken"] != false || podSpec["restartPolicy"] != "Never" || podSpec["serviceAccountName"] != "vnbui-restore-worker" {
		t.Fatal(podSpec)
	}
	container := podSpec["containers"].([]interface{})[0].(map[string]interface{})
	if len(container["volumeDevices"].([]interface{})) != 1 || len(container["volumeMounts"].([]interface{})) != 2 {
		t.Fatal(container)
	}
	completeWorker(t, state, client)
	if err := e.reconcile(ctx, state); err != nil {
		t.Fatal(err)
	}
	if state.Progress.Status != models.TaskStatusCompleted || state.VMUID == "" {
		t.Fatal(state.Progress)
	}
	vm, err := client.Resource(vmGVR).Namespace("ns").Get(ctx, "restored-vm", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	strategy, _, _ := unstructured.NestedString(vm.Object, "spec", "runStrategy")
	if strategy != "Halted" {
		t.Fatal(strategy)
	}
	for _, action := range client.Actions() {
		if (action.GetVerb() == "delete" && action.GetResource() != secretGVR) || action.GetVerb() == "patch" {
			t.Fatal("unexpected destructive action", action)
		}
	}
}

func TestControllerHoldsRetainedImplicitNetworkDefinitionBeforeEffects(t *testing.T) {
	for _, phase := range []string{"provisioning", "populating", "defining"} {
		for _, policy := range []string{"missing", "enabled", "malformed"} {
			t.Run(phase+"/"+policy, func(t *testing.T) {
				e, state, client := controllerFixture(t)
				state.Phase = phase
				path := []string{"spec", "template", "spec", "domain", "devices", "autoattachPodInterface"}
				switch policy {
				case "missing":
					unstructured.RemoveNestedField(state.VM, path...)
				case "enabled":
					_ = unstructured.SetNestedField(state.VM, true, path...)
				case "malformed":
					_ = unstructured.SetNestedField(state.VM, "false", path...)
				}
				before, _ := json.Marshal(state.VM)
				client.ClearActions()
				if err := e.reconcile(context.Background(), state); !errors.Is(err, errHeld) {
					t.Fatal("retained implicit attachment definition was not held", err)
				}
				after, _ := json.Marshal(state.VM)
				if len(client.Actions()) != 0 || string(before) != string(after) {
					t.Fatal("hold performed provider effects or rewrote retained definition")
				}
			})
		}
	}
}

func TestControllerCollisionAndUncertainAbsenceNeverAdopt(t *testing.T) {
	for _, problem := range []string{"vm-exists", "pvc-exists", "pvc-replaced", "job-failed", "job-mutated", "missing-worker-evidence", "inflight-absent"} {
		t.Run(problem, func(t *testing.T) {
			e, s, c := controllerFixture(t)
			ctx := context.Background()
			if problem == "vm-exists" || problem == "pvc-exists" {
				gvr, kind, name := vmGVR, "VirtualMachine", s.Request.Target.VMName
				if problem == "pvc-exists" {
					gvr, kind, name = pvcGVR, "PersistentVolumeClaim", s.Request.Target.Disks[0].PVCName
				}
				_, err := c.Resource(gvr).Namespace("ns").Create(ctx, &unstructured.Unstructured{Object: map[string]interface{}{"apiVersion": gvr.GroupVersion().String(), "kind": kind, "metadata": map[string]interface{}{"namespace": "ns", "name": name}}}, metav1.CreateOptions{})
				if err != nil {
					t.Fatal(err)
				}
			} else if problem == "inflight-absent" {
				s.Inflight = "secrets/" + resourceName(s)
			} else {
				if err := e.reconcile(ctx, s); err != nil {
					t.Fatal(err)
				}
				switch problem {
				case "pvc-replaced":
					pvc, _ := c.Resource(pvcGVR).Namespace("ns").Get(ctx, s.Request.Target.Disks[0].PVCName, metav1.GetOptions{})
					pvc.SetUID("replacement")
					_, _ = c.Resource(pvcGVR).Namespace("ns").Update(ctx, pvc, metav1.UpdateOptions{})
				case "job-failed", "job-mutated", "missing-worker-evidence":
					job, _ := c.Resource(jobGVR).Namespace("ns").Get(ctx, resourceName(s), metav1.GetOptions{})
					if problem == "job-mutated" {
						_ = unstructured.SetNestedField(job.Object, true, "spec", "suspend")
					} else {
						typ := "Failed"
						if problem == "missing-worker-evidence" {
							typ = "Complete"
						}
						job.Object["status"] = map[string]interface{}{"conditions": []interface{}{map[string]interface{}{"type": typ, "status": "True"}}}
					}
					_, _ = c.Resource(jobGVR).Namespace("ns").Update(ctx, job, metav1.UpdateOptions{})
				}
			}
			if err := e.reconcile(ctx, s); !errors.Is(err, errHeld) {
				t.Fatal("did not hold", err)
			}
			if s.VMUID != "" {
				t.Fatal("unsafe VM exposed")
			}
		})
	}
}

func TestJournalRestartAndIdempotentAdmission(t *testing.T) {
	for _, historical := range []bool{false, true} {
		name := "catalog"
		if historical {
			name = "verified-s3-recovery"
		}
		t.Run(name, func(t *testing.T) { testJournalRestartAndIdempotentAdmission(t, historical) })
	}
}

func TestHistoricalCaptureUsesEffectiveSigningRegionWithoutChangingBundle(t *testing.T) {
	objects := make(map[string][]byte)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, found := objects[r.URL.Path]
		if !found || r.Header.Get("If-Match") != `"etag"` ||
			!strings.Contains(r.Header.Get("Authorization"), "/us-east-1/s3/aws4_request,") {
			http.Error(w, "scope", http.StatusPreconditionFailed)
			return
		}
		w.Header().Set("ETag", `"etag"`)
		w.Header().Set("Last-Modified", "Thu, 01 Oct 2026 00:00:00 GMT")
		_, _ = w.Write(body)
	}))
	defer server.Close()
	executor, state, _ := controllerFixture(t)
	bundle, _, err := ValidatePlan(&state.Request)
	if err != nil {
		t.Fatal(err)
	}
	member := &bundle.Members[0]
	plan := &member.Request.Plan
	plan.Target.Endpoint, plan.Target.Region = server.URL, ""
	canonical, err := models.StorageCanonical(*plan)
	if err != nil {
		t.Fatal(err)
	}
	member.Request.PlanSHA256 = digest(canonical)
	member.Receipt.Endpoint = server.URL
	vm := capturedFixture()
	vm["metadata"] = map[string]any{
		"name": plan.VMName, "namespace": plan.Source.Namespace,
		"uid": plan.Source.VMUID, "resourceVersion": "10",
	}
	definition, err := json.Marshal(vm)
	if err != nil {
		t.Fatal(err)
	}
	for i, object := range member.Receipt.Objects {
		if object.Role != "volume_manifest" {
			continue
		}
		var volume string
		for _, match := range plan.Source.Volumes {
			if match.PVCUID == object.VolumeID {
				volume = match.Name
			}
		}
		var payload string
		for _, match := range member.Receipt.Objects {
			if match.VolumeID == object.VolumeID && match.Role == "volume_payload" {
				payload = match.Key
			}
		}
		body, err := json.Marshal(map[string]any{
			"vm_namespace": plan.Source.Namespace, "vm_uid": plan.Source.VMUID,
			"format": "vnbui-kubevirt-cbt-v1", "backup_type": "full", "checkpoint": "fixture",
			"volume": volume, "virtual_size": 1, "encrypted": false, "payload_key": payload,
			"stored_extents": []map[string]uint64{{"disk_offset": 0, "length": 1, "payload_offset": 0}},
			"vm_definition":  base64.StdEncoding.EncodeToString(definition),
		})
		if err != nil {
			t.Fatal(err)
		}
		object.PlaintextBytes, object.CiphertextBytes = int64(len(body)), int64(len(body))
		object.PlaintextSHA256, object.CiphertextSHA256 = digest(body), digest(body)
		member.Receipt.Objects[i] = object
		objects["/"+plan.Target.Bucket+"/"+object.Key] = body
	}
	input, err := json.Marshal(bundle)
	if err != nil {
		t.Fatal(err)
	}
	req := &state.Request
	req.RecoveryOrigin = &models.RestoreOrigin{OrgID: req.OrgID, AgentID: req.AgentID}
	req.OrgID, req.AgentID = "local-org", "local-agent"
	req.S3.Endpoint = server.URL
	req.Bundle = input
	expectedBundle := digest(input)
	state.CAPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}))
	if err := executor.capturedVM(context.Background(), state); err != nil {
		t.Fatal(err)
	}
	if state.Phase != "provisioning" || digest(req.Bundle) != expectedBundle {
		t.Fatal("historical restore mutated retained coordinates or failed to capture the VM")
	}
}

func testJournalRestartAndIdempotentAdmission(t *testing.T, historical bool) {
	req := restoreFixture(t)
	if historical {
		req.RecoveryOrigin = &models.RestoreOrigin{OrgID: req.OrgID, AgentID: req.AgentID}
		req.OrgID = "33333333-3333-4333-8333-333333333333"
		req.AgentID = "44444444-4444-4444-8444-444444444444"
	}
	root := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Keep background work from reaching provider.
	cfg := &config.Config{AgentID: req.AgentID, KeyFilePath: filepath.Join(root, "agent.key"), KubevirtRestoreImage: testRestoreImage, KubevirtRestoreNamespaces: []string{"ns"}, EnableAPIKeyValidation: true, OrchestratorAPIKey: "test", OrchestratorVerifySSL: true}
	c := fake.NewSimpleDynamicClient(runtime.NewScheme())
	e := NewExecutor(cfg, resources.New(1, 1), c, "ns")
	if err := e.StartRestores(context.Background()); err != nil {
		t.Fatal(err)
	}
	e.cancel()
	<-e.done
	// Persist a prepared request via the real admission before any remote work.
	e.mu.Lock()
	e.ctx = context.Background()
	e.mu.Unlock()
	p, err := e.StartRestore(&models.RestoreRequest{RestoreID: req.RestoreID, KubeVirt: req})
	if err != nil || p.Status != models.TaskStatusRunning {
		t.Fatal(p, err)
	}
	if _, err = e.StartRestore(&models.RestoreRequest{RestoreID: req.RestoreID, KubeVirt: req}); err != nil {
		t.Fatal(err)
	}
	changed := *req
	changed.Target.VMName = "other"
	if _, err = e.StartRestore(&models.RestoreRequest{RestoreID: req.RestoreID, KubeVirt: &changed}); err == nil {
		t.Fatal("different plan reused ID")
	}
	for _, problem := range []string{"vm", "pvc"} {
		conflict := *req
		conflict.RestoreID = "restore-" + problem
		if problem == "pvc" {
			conflict.Target.VMName = "another-vm"
		}
		if _, err = e.StartRestore(&models.RestoreRequest{RestoreID: conflict.RestoreID, KubeVirt: &conflict}); !errors.Is(err, restore.ErrPreJournalTargetReserved) {
			t.Fatal("target conflict did not produce a typed pre-journal refusal", problem, err)
		}
		if _, err = os.Stat(filepath.Join(root, "kubevirt-restores", conflict.RestoreID+".json")); !os.IsNotExist(err) {
			t.Fatal("target conflict wrote a restore journal", problem, err)
		}
	}
	second := NewExecutor(cfg, resources.New(1, 1), c, "ns")
	if err = second.StartRestores(ctx); err == nil {
		t.Fatal("concurrent journal owner admitted")
	}
	if err = e.CloseRestores(); err != nil {
		t.Fatal(err)
	}
	if err = second.StartRestores(ctx); err != nil {
		t.Fatal(err)
	}
	defer second.CloseRestores()
	if second.GetProgress(req.RestoreID) == nil {
		t.Fatal("durable restore not recovered")
	}
	if err = second.CloseRestores(); err != nil {
		t.Fatal(err)
	}
	journal := filepath.Join(root, "kubevirt-restores", req.RestoreID+".json")
	encoded, err := os.ReadFile(journal)
	if err != nil {
		t.Fatal(err)
	}
	var old restoreState
	if err = json.Unmarshal(encoded, &old); err != nil {
		t.Fatal(err)
	}
	old.Image = "registry.example/vnbui/agent:mutable"
	encoded, err = json.Marshal(old)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(journal, encoded, 0600); err != nil {
		t.Fatal(err)
	}
	third := NewExecutor(cfg, resources.New(1, 1), c, "ns")
	if err = third.StartRestores(ctx); !errors.Is(err, errHeld) {
		if err == nil {
			_ = third.CloseRestores()
		}
		t.Fatalf("mutable persisted worker image was not held: %v", err)
	}
	if _, err = os.Stat(journal); err != nil {
		t.Fatalf("held restore journal was lost: %v", err)
	}
}
