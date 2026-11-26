//go:build kubevirt

package kubevirt

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	k8stest "k8s.io/client-go/testing"
	"vnbui/agent/internal/config"
	"vnbui/agent/internal/models"
	"vnbui/agent/internal/resources"
	"vnbui/agent/internal/storageupload"
)

func runnerFixture(t *testing.T) (*Executor, []byte, *models.StorageTransactionRequest) {
	t.Helper()
	body, err := os.ReadFile("../../../contracts/storage_semantic_valid.json")
	if err != nil {
		t.Fatal(err)
	}
	request, err := models.DecodeStorageTransaction(body)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{
		KubeNamespace: request.Plan.Source.Namespace,
		AgentID:       request.AgentID, AgentAPIKey: "registered-fixture-key", OrchestratorAPIKey: "orchestrator-fixture-key",
		OrchestratorURL: "https://backend.example.net", OrchestratorVerifySSL: true, EnableAPIKeyValidation: true,
		KeyFilePath: filepath.Join(t.TempDir(), "agent.key"), KubevirtBackupScratchPVC: "scratch",
		KubevirtNativeTTLSeconds: config.DefaultNativeBackupTTLSeconds,
	}
	e := NewExecutor(cfg, resources.New(1, 1), dynamicfake.NewSimpleDynamicClient(runtime.NewScheme()), request.Plan.Source.Namespace)
	return e, body, request
}

func startTestRunner(t *testing.T, e *Executor, step func(context.Context, []byte) (*storageupload.CheckpointProof, error)) *transactionRunner {
	t.Helper()
	r, err := newTransactionRunner(context.Background(), e)
	if err != nil {
		t.Fatal(err)
	}
	r.retry = 5 * time.Millisecond
	r.step = func(ctx context.Context, body []byte, backend, provider *http.Client, key func(context.Context) (string, error)) (*storageupload.CheckpointProof, error) {
		credential, err := key(ctx)
		if err != nil {
			return nil, err
		}
		if credential != e.cfg.AgentAPIKey || backend == nil || provider == nil {
			t.Error("runner did not supply the registered credential and verified clients")
		}
		return step(ctx, body)
	}
	e.storageRunner = r
	go r.run()
	t.Cleanup(func() { _ = e.CloseStorageTransactions() })
	return r
}

func waitRunner(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for !condition() {
		if time.Now().After(deadline) {
			t.Fatal("runner did not reach expected state")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestTransactionRunnerDurableIdempotentAdmissionAndPublication(t *testing.T) {
	e, body, request := runnerFixture(t)
	var calls, events atomic.Int32
	e.SetEventCallback(func(map[string]interface{}) { events.Add(1) })
	entered, release := make(chan struct{}), make(chan struct{})
	r := startTestRunner(t, e, func(ctx context.Context, body []byte) (*storageupload.CheckpointProof, error) {
		calls.Add(1)
		j, err := storageupload.Open(filepath.Join(filepath.Dir(e.cfg.KeyFilePath), "storage-transactions"), body)
		if err != nil {
			t.Error("producer ran before request was durable", err)
			return nil, err
		}
		state, err := j.Snapshot()
		_ = j.Close()
		if err != nil || state.Request.BackupID != request.BackupID {
			t.Error("wrong persisted request", err)
		}
		close(entered)
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-release:
			return &storageupload.CheckpointProof{}, nil
		}
	})
	if err := e.StartStorageTransaction(context.Background(), body); err != nil {
		t.Fatal(err)
	}
	<-entered
	if err := e.StartStorageTransaction(context.Background(), body); err != nil || calls.Load() != 1 {
		t.Fatal("identical retry started another producer", err)
	}
	request.Plan.VMName = "changed-vm"
	plan, _ := models.StorageCanonical(request.Plan)
	request.PlanSHA256 = nativeHash(plan)
	conflict, _ := json.Marshal(request)
	if err := e.StartStorageTransaction(context.Background(), conflict); err == nil {
		t.Fatal("conflicting durable request was accepted")
	}
	close(release)
	waitRunner(t, func() bool {
		progress := e.GetProgress(request.BackupID)
		return progress != nil && progress.Status == models.TaskStatusCompleted && e.ActiveCount() == 0
	})
	if events.Load() != 0 || calls.Load() != 1 {
		t.Fatal("runner emitted a legacy completion event or ran twice")
	}
	if err := e.CloseStorageTransactions(); err != nil {
		t.Fatal(err)
	}
	requests, err := storageupload.RecoverRequests(r.root)
	if err != nil || len(requests) != 1 {
		t.Fatal("completed journal was not retained", err)
	}
}

func TestTransactionRunnerRestartAndExclusiveProcessOwner(t *testing.T) {
	e, body, request := runnerFixture(t)
	root := filepath.Join(filepath.Dir(e.cfg.KeyFilePath), "storage-transactions")
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	j, err := storageupload.Create(root, body)
	if err != nil {
		t.Fatal(err)
	}
	_ = j.Close()
	if _, err := e.createSafety(root, request); err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	startTestRunner(t, e, func(context.Context, []byte) (*storageupload.CheckpointProof, error) {
		calls.Add(1)
		return &storageupload.CheckpointProof{}, nil
	})
	waitRunner(t, func() bool { return calls.Load() == 1 && e.ActiveCount() == 0 })
	if err := e.StartStorageTransaction(context.Background(), body); err != nil {
		t.Fatal(err)
	}
	other := NewExecutor(e.cfg, resources.New(1, 1), e.dynamic, request.Plan.Source.Namespace)
	if runner, err := newTransactionRunner(context.Background(), other); err == nil {
		runner.lock.Close()
		t.Fatal("second process acquired live journal root")
	}
	if calls.Load() != 1 {
		t.Fatal("restart/idempotent retry duplicated work")
	}
}

func TestTransactionRunnerShutdownRetainsUncertainWork(t *testing.T) {
	e, body, request := runnerFixture(t)
	entered := make(chan struct{})
	var events atomic.Int32
	e.SetEventCallback(func(map[string]interface{}) { events.Add(1) })
	r := startTestRunner(t, e, func(ctx context.Context, _ []byte) (*storageupload.CheckpointProof, error) {
		close(entered)
		<-ctx.Done()
		return nil, ctx.Err()
	})
	if err := e.StartStorageTransaction(context.Background(), body); err != nil {
		t.Fatal(err)
	}
	<-entered
	if err := e.CloseStorageTransactions(); err != nil {
		t.Fatal(err)
	}
	requests, err := storageupload.RecoverRequests(r.root)
	if err != nil || len(requests) != 1 || events.Load() != 0 || e.ActiveCount() != 0 {
		t.Fatal("shutdown lost custody, emitted an event or leaked capacity", err)
	}
	if e.GetProgress(request.BackupID).Status != models.TaskStatusCleanupRequired {
		t.Fatal("uncertain stop was reported as success")
	}
	observations := e.StorageHoldEvents()
	if len(observations) != 1 || observations[0]["reservation_id"] != request.ReservationID || observations[0]["plan_sha256"] != request.PlanSHA256 {
		t.Fatal("held runner omitted exact heartbeat identity", observations)
	}
	if err := e.StartStorageTransaction(context.Background(), body); err == nil {
		t.Fatal("closed runner admitted work")
	}
}

func TestTransactionRunnerPublicationAcknowledgementWinsConcurrentShutdown(t *testing.T) {
	e, body, request := runnerFixture(t)
	entered := make(chan struct{})
	r := startTestRunner(t, e, func(ctx context.Context, _ []byte) (*storageupload.CheckpointProof, error) {
		close(entered)
		<-ctx.Done()
		// Model an already committed publication reply arriving after shutdown
		// has projected a negative observation. No producer is replayed.
		waitRunner(t, func() bool {
			return e.GetProgress(request.BackupID).Status == models.TaskStatusCleanupRequired
		})
		return &storageupload.CheckpointProof{}, nil
	})
	if err := e.StartStorageTransaction(context.Background(), body); err != nil {
		t.Fatal(err)
	}
	<-entered
	if err := e.CloseStorageTransactions(); err != nil {
		t.Fatal(err)
	}
	w := r.work[request.BackupID]
	if !w.finished || w.held || w.safety.snapshot().Progress.Stage != "complete" || len(e.StorageHoldEvents()) != 0 {
		t.Fatal("publication acknowledgement became a held attempt")
	}
	// A later stale observer cannot regress the acknowledged result either.
	r.retain(w, "stale shutdown observation")
	if p := e.GetProgress(request.BackupID); p.Status != models.TaskStatusCompleted || !*p.CheckpointCommitted {
		t.Fatal("confirmed publication was replaced by a negative observation")
	}
}

func TestSafetyWatchShutdownAfterPublicationHasNoEffects(t *testing.T) {
	e, body, request := runnerFixture(t)
	r := startTestRunner(t, e, func(context.Context, []byte) (*storageupload.CheckpointProof, error) {
		return &storageupload.CheckpointProof{}, nil
	})
	if err := e.StartStorageTransaction(context.Background(), body); err != nil {
		t.Fatal(err)
	}
	waitRunner(t, func() bool { return e.GetProgress(request.BackupID).Status == models.TaskStatusCompleted })
	if err := e.CloseStorageTransactions(); err != nil {
		t.Fatal(err)
	}
	w := r.work[request.BackupID]
	before, err := os.ReadFile(w.safety.path)
	if err != nil {
		t.Fatal(err)
	}
	r.watchSafety(w, func() { t.Error("completed producer was cancelled") }, make(chan struct{}))
	after, err := os.ReadFile(w.safety.path)
	if err != nil || !bytes.Equal(before, after) || w.held || len(e.StorageHoldEvents()) != 0 {
		t.Fatal("late shutdown changed completed custody", err)
	}
}

func TestTransactionRunnerPublicationSurvivesSafetyRecordFailure(t *testing.T) {
	e, body, request := runnerFixture(t)
	var calls atomic.Int32
	r := startTestRunner(t, e, func(ctx context.Context, _ []byte) (*storageupload.CheckpointProof, error) {
		calls.Add(1)
		guard := safetyFrom(ctx)
		if err := guard.sourceClosed(nativeNow()); err != nil {
			return nil, err
		}
		// The reconciliation contract returns a proof only after the backend
		// ACK is durable in the payload journal. Failure of its separate safety
		// mirror cannot revoke that publication or authorize more effects.
		if err := os.WriteFile(guard.path, []byte("safety mirror changed after publication\n"), 0600); err != nil {
			return nil, err
		}
		return &storageupload.CheckpointProof{}, nil
	})
	if err := e.StartStorageTransaction(context.Background(), body); err != nil {
		t.Fatal(err)
	}
	waitRunner(t, func() bool { return calls.Load() == 1 && e.ActiveCount() == 0 })
	if err := e.CloseStorageTransactions(); err != nil {
		t.Fatal(err)
	}
	w := r.work[request.BackupID]
	if !w.finished || w.held || len(e.StorageHoldEvents()) != 0 {
		t.Fatal("acknowledged publication became held after safety mirror failure")
	}
	r.retain(w, "stale safety mirror failure")
	if p := e.GetProgress(request.BackupID); p.Status != models.TaskStatusCompleted || !*p.CheckpointCommitted {
		t.Fatal("confirmed publication was replaced by a negative observation")
	}
	if calls.Load() != 1 {
		t.Fatal("publication was replayed")
	}
}

func TestTransactionRunnerRefusesInsecureOrWrongAgentConfiguration(t *testing.T) {
	for _, variant := range []string{"http", "tls-disabled", "key-missing", "auth-disabled", "scratch-missing"} {
		t.Run(variant, func(t *testing.T) {
			e, _, _ := runnerFixture(t)
			switch variant {
			case "http":
				e.cfg.OrchestratorURL = "http://backend.example.net"
			case "tls-disabled":
				e.cfg.OrchestratorVerifySSL = false
			case "key-missing":
				e.cfg.OrchestratorAPIKey = ""
			case "auth-disabled":
				e.cfg.EnableAPIKeyValidation = false
			case "scratch-missing":
				e.cfg.KubevirtBackupScratchPVC = ""
			}
			if err := e.StartStorageTransactions(context.Background()); err == nil {
				_ = e.CloseStorageTransactions()
				t.Fatal("insecure/incomplete configuration activated")
			}
		})
	}
	e, body, _ := runnerFixture(t)
	e.cfg.AgentID = "99999999-9999-4999-8999-999999999999"
	startTestRunner(t, e, func(context.Context, []byte) (*storageupload.CheckpointProof, error) {
		t.Error("wrong agent reached producer")
		return nil, storageupload.ErrHeld
	})
	if err := e.StartStorageTransaction(context.Background(), body); err == nil {
		t.Fatal("wrong agent accepted")
	}
}

func TestTransactionRunnerSupportedScopeBeforeJournal(t *testing.T) {
	for _, variant := range []string{"other-profile", "other-namespace"} {
		t.Run(variant, func(t *testing.T) {
			e, _, request := runnerFixture(t)
			r := startTestRunner(t, e, func(context.Context, []byte) (*storageupload.CheckpointProof, error) {
				t.Error("unsupported request reached provider")
				return nil, storageupload.ErrHeld
			})
			switch variant {
			case "other-profile":
				request.Plan.CapabilityProfile = "consumer-verified/1"
			case "other-namespace":
				request.Plan.Source.Namespace = "other-namespace"
			}
			plan, _ := models.StorageCanonical(request.Plan)
			request.PlanSHA256 = nativeHash(plan)
			body, _ := json.Marshal(request)
			if _, err := models.DecodeStorageTransaction(body); err != nil {
				t.Fatal("fixture must be valid protocol, outside runner activation scope", err)
			}
			if err := e.StartStorageTransaction(context.Background(), body); err == nil {
				t.Fatal("unsupported transaction scope admitted")
			}
			entries, err := os.ReadDir(r.root)
			if err != nil || len(entries) != 0 {
				t.Fatal("unsupported request persisted a journal", err)
			}
		})
	}
}

func TestTransactionRunnerAdmitsEncryptedPlanWithoutKeyMaterial(t *testing.T) {
	e, _, request := runnerFixture(t)
	ref := "kek:66666666-6666-4666-8666-666666666666:aaaaaaaaaaaaaaaa"
	request.Plan.Encryption = models.StorageEncryption{Format: "vnbu1-aes256gcm-chunk5242880", KeyRef: &ref}
	for i := range request.Plan.Artifacts {
		a := &request.Plan.Artifacts[i]
		if a.Role == "volume_payload" {
			a.CiphertextMin = 5
			a.CiphertextMax = 5 + a.PlaintextMax + 32*((a.PlaintextMax+5242880-1)/5242880)
		}
	}
	plan, _ := models.StorageCanonical(request.Plan)
	request.PlanSHA256 = nativeHash(plan)
	body, _ := json.Marshal(request)
	r := startTestRunner(t, e, func(context.Context, []byte) (*storageupload.CheckpointProof, error) {
		return nil, storageupload.ErrHeld
	})
	decoded, _, err := r.validate(body)
	if err != nil || decoded.Plan.Encryption.KeyRef == nil || *decoded.Plan.Encryption.KeyRef != ref {
		t.Fatal("encrypted request refused", err)
	}
	if bytes.Contains(body, []byte(`"dek"`)) {
		t.Fatal("DEK in transaction")
	}
}

// Exercise admission through the runner, rather than preparing a transaction
// directly: native preparation must reopen the already durable naming choice.
func TestTransactionRunnerPinsPrefixBeforeNativeHandoff(t *testing.T) {
	for _, configured := range []string{"", "vnbui", "vesta"} {
		t.Run("prefix="+configured, func(t *testing.T) {
			e, body, request, dyn := nativeRunnerFixture(t, configured)
			want := e.cfg.KubevirtPrefix()
			result := make(chan error, 1)
			// A terminal controller observation bounds real reconciliation after
			// native creation, without an export stream or any HTTP request.
			dyn.PrependReactor("create", "virtualmachinebackups", func(action k8stest.Action) (bool, runtime.Object, error) {
				obj := action.(k8stest.CreateAction).GetObject().(*unstructured.Unstructured)
				obj.Object["status"] = map[string]interface{}{"conditions": []interface{}{map[string]interface{}{"type": "Done", "status": "True"}}}
				return false, nil, nil
			})
			var runner *transactionRunner
			runner = startTestRunner(t, e, func(ctx context.Context, body []byte) (*storageupload.CheckpointProof, error) {
				root := filepath.Join(filepath.Dir(e.cfg.KeyFilePath), "storage-transactions")
				j, err := storageupload.Open(root, body)
				if err != nil {
					result <- err
					return nil, err
				}
				state, err := j.Snapshot()
				_ = j.Close()
				if err == nil && (state.ResourcePrefix != want || state.Native != nil || len(dyn.Actions()) != 0) {
					err = fmt.Errorf("initial runner journal did not pin %s before native effects", want)
				}
				if err == nil {
					_, reconcileErr := e.ReconcileStorageTransaction(ctx, body, runner.backend, runner.provider, func(context.Context) (string, error) {
						t.Error("native-only handoff unexpectedly requested HTTP credentials")
						return "", storageupload.ErrHeld
					})
					if !errors.Is(reconcileErr, storageupload.ErrHeld) {
						err = fmt.Errorf("terminal fixture must retain the attempt: %v", reconcileErr)
					}
				}
				if err == nil {
					j, err = storageupload.Open(root, body)
				}
				if err == nil {
					state, err = j.Snapshot()
					_ = j.Close()
					if err == nil && (state.ResourcePrefix != want || state.Native == nil || state.Native.Objects[1].Name != want+"-"+request.BackupID || state.Native.Objects[1].UID == "") {
						err = fmt.Errorf("ordinary native handoff changed naming authority")
					}
				}
				result <- err
				// This test stops at native preparation, not checkpoint completion.
				<-ctx.Done()
				return nil, ctx.Err()
			})
			if err := e.StartStorageTransaction(context.Background(), body); err != nil {
				t.Fatal(err)
			}
			select {
			case err := <-result:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("native runner handoff did not finish")
			}
			for _, action := range dyn.Actions() {
				if action.GetVerb() == "create" {
					obj := action.(k8stest.CreateAction).GetObject().(metav1.Object)
					if !strings.HasPrefix(obj.GetName(), want+"-") || obj.GetLabels()["app.kubernetes.io/managed-by"] != want {
						t.Fatal("native creation used a different prefix", obj.GetName())
					}
				}
			}
		})
	}
}

func nativeRunnerFixture(t *testing.T, prefix string) (*Executor, []byte, *models.StorageTransactionRequest, *dynamicfake.FakeDynamicClient) {
	t.Helper()
	e, body, request, dyn := nativeFixture(t, false)
	e.cfg.KubevirtResourcePrefix = prefix
	e.cfg.AgentID, e.cfg.AgentAPIKey, e.cfg.OrchestratorAPIKey = request.AgentID, "registered-fixture-key", "orchestrator-fixture-key"
	e.cfg.OrchestratorURL, e.cfg.OrchestratorVerifySSL, e.cfg.EnableAPIKeyValidation = "https://backend.example.net", true, true
	e.resources = resources.New(1, 1)
	return e, body, request, dyn
}

func TestTransactionRunnerRecoveryRetainsSavedPrefix(t *testing.T) {
	for _, saved := range []string{"", "vesta"} {
		for _, configured := range []string{"vnbui", "vesta"} {
			t.Run("saved="+saved+"/configured="+configured, func(t *testing.T) {
				e, body, request, dyn := nativeRunnerFixture(t, configured)
				root := filepath.Join(filepath.Dir(e.cfg.KeyFilePath), "storage-transactions")
				if err := os.Mkdir(root, 0700); err != nil {
					t.Fatal(err)
				}
				var j *storageupload.Journal
				var err error
				if saved == "" {
					j, err = storageupload.Create(root, body)
				} else {
					j, err = storageupload.CreateWithKubevirtPrefix(root, body, saved)
				}
				if err != nil {
					t.Fatal(err)
				}
				_ = j.Close()
				if _, err := e.createSafety(root, request); err != nil {
					t.Fatal(err)
				}
				path := filepath.Join(root, request.ReservationID, "transaction.json")
				before, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				r, err := newTransactionRunner(context.Background(), e)
				if err != nil {
					t.Fatal(err)
				}
				defer r.cancel()
				defer r.lock.Close()
				defer r.backend.CloseIdleConnections()
				defer r.provider.CloseIdleConnections()
				e.storageRunner = r
				if len(r.queue) != 1 || e.StartStorageTransaction(context.Background(), body) != nil || len(r.queue) != 1 {
					t.Fatal("recovery or exact redelivery duplicated/lost the original work")
				}
				matches := (saved == "" && configured == "vnbui") || saved == configured
				if matches {
					j, err = e.PrepareStorageTransaction(context.Background(), r.queue[0].body)
					if err != nil {
						t.Fatal("matching recovered work could not prepare", err)
					}
					state, err := j.Snapshot()
					_ = j.Close()
					if err != nil || state.ResourcePrefix != saved || state.Native == nil {
						t.Fatal("recovery adopted a prefix or lost native preparation", err)
					}
					return
				}
				// Use the actual ordinary reconcile callback: mismatch must stop
				// before Kubernetes, HTTP, migration or any journal rewrite.
				if _, err := r.step(context.Background(), r.queue[0].body, r.backend, r.provider, func(context.Context) (string, error) {
					t.Error("mismatched journal requested an HTTP credential")
					return "", storageupload.ErrHeld
				}); !errors.Is(err, storageupload.ErrHeld) {
					t.Fatal("cross-prefix recovery was allowed", err)
				}
				after, err := os.ReadFile(path)
				if err != nil || !bytes.Equal(before, after) || len(dyn.Actions()) != 0 {
					t.Fatal("cross-prefix recovery rewrote custody or accessed Kubernetes", err)
				}
			})
		}
	}
}

func TestTransactionRunnerInvalidPrefixCannotBecomeLegacy(t *testing.T) {
	e, body, _ := runnerFixture(t)
	e.cfg.KubevirtResourcePrefix = "unsupported"
	r := startTestRunner(t, e, func(context.Context, []byte) (*storageupload.CheckpointProof, error) {
		t.Error("invalid prefix reached native handoff")
		return nil, storageupload.ErrHeld
	})
	if err := e.StartStorageTransaction(context.Background(), body); !errors.Is(err, storageupload.ErrHeld) {
		t.Fatal("invalid prefix was accepted as legacy naming", err)
	}
	entries, err := os.ReadDir(r.root)
	if err != nil || len(entries) != 0 {
		t.Fatal("invalid prefix persisted an attempt", err)
	}
}
