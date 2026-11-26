//go:build kubevirt

package kubevirt

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	k8stest "k8s.io/client-go/testing"
	kvtypes "vnbui/agent/internal/provider/kubevirt"
	"vnbui/agent/internal/resources"
	"vnbui/agent/internal/storageupload"
)

func TestProductionFinalizeOriginalOnlyDurableReopen(t *testing.T) {
	for _, incremental := range []bool{false, true} {
		for _, encrypted := range []bool{false, true} {
			t.Run(strings.Join([]string{map[bool]string{true: "incremental", false: "full"}[incremental], map[bool]string{true: "encrypted", false: "plain"}[encrypted]}, "/"), func(t *testing.T) {
				f := readyExportFixture(t, incremental, encrypted, 9)
				s := f.disk(t)
				oldNow := nativeNow
				initial, err := f.e.dynamic.Resource(kvtypes.BackupResource).Namespace(s.Request.Plan.Source.Namespace).Get(context.Background(), s.Native.Objects[1].Name, metav1.GetOptions{})
				if err != nil {
					t.Fatal(err)
				}
				start := initial.GetCreationTimestamp().Time
				nativeNow = func() time.Time { return start.Add(30 * time.Second) }
				defer func() { nativeNow = oldNow }()
				d := f.e.dynamic.(*dynamicfake.FakeDynamicClient)
				ns := s.Request.Plan.Source.Namespace
				bname := s.Native.Objects[1].Name
				mutateExportObject(t, f, kvtypes.BackupResource, bname, func(b *unstructured.Unstructured) { b.SetResourceVersion("41") })
				guestWant := "unknown"
				deletes, reports, intents := 0, 0, 0
				var activeGuard *operationSafety
				var reportReply map[string]any
				d.PrependReactor("delete", "virtualmachinebackups", func(action k8stest.Action) (bool, runtime.Object, error) {
					a := action.(k8stest.DeleteAction)
					opts := a.GetDeleteOptions()
					saved := f.disk(t)
					if opts.Preconditions == nil || opts.Preconditions.UID == nil || string(*opts.Preconditions.UID) != s.Native.Objects[1].UID || opts.Preconditions.ResourceVersion == nil || *opts.Preconditions.ResourceVersion != "41" || saved.Finalize == nil || saved.Finalize.IntentID == "" || saved.Finalize.DeleteResourceVersion != "41" {
						t.Fatal("delete before exact durable intent")
					}
					deletes++
					obj, err := d.Tracker().Get(kvtypes.BackupResource, ns, bname)
					if err != nil {
						t.Fatal(err)
					}
					b := obj.(*unstructured.Unstructured).DeepCopy()
					now := metav1.NewTime(nativeNow())
					b.SetDeletionTimestamp(&now)
					b.SetResourceVersion("42")
					_ = unstructured.SetNestedSlice(b.Object, []any{
						map[string]any{"type": "Aborting", "status": "True"},
						map[string]any{"type": "Progressing", "status": "True"},
						map[string]any{"type": "Done", "status": "False"},
					}, "status", "conditions")
					if err = d.Tracker().Update(kvtypes.BackupResource, b, ns); err != nil {
						t.Fatal(err)
					}
					// Deterministically interleave the independent watch while the
					// payload journal remains locked by the DELETE caller.
					root := filepath.Join(filepath.Dir(f.e.cfg.KeyFilePath), "storage-transactions")
					if other, err := storageupload.Open(root, f.body); err == nil {
						_ = other.Close()
						t.Fatal("watch test did not retain payload journal lock")
					}
					// The active guard is supplied below through the caller context.
					if activeGuard == nil || !f.e.ownedFinalizeAborting(&s.Request, activeGuard, b) {
						t.Fatal("durable own finalize was not mirrored before DELETE")
					}
					if activeGuard.snapshot().SourceClosed || saved.Finalize.Proof != nil || saved.Finalize.TerminalResourceVersion != "" {
						t.Fatal("Aborting observation inferred closure or proof")
					}
					if incremental {
						return true, nil, io.ErrUnexpectedEOF
					}
					return true, nil, nil
				})
				original := f.backend.Transport
				f.backend.Transport = exportTransport(func(req *http.Request) (*http.Response, error) {
					saved := f.disk(t)
					if strings.HasSuffix(req.URL.Path, "/finalize-intent") {
						intents++
						var binding storageupload.FinalizeBinding
						if json.NewDecoder(req.Body).Decode(&binding) != nil || saved.Finalize == nil || !reflect.DeepEqual(binding, saved.Finalize.Binding) || saved.Acceptance == nil {
							t.Fatal("intent not durable")
						}
						resp := exportResponse(map[string]any{"intent_id": "intent-exact", "binding": binding})
						resp.Header.Set("Cache-Control", "no-store")
						if encrypted && intents == 1 {
							return nil, io.ErrUnexpectedEOF
						}
						return resp, nil
					}
					if strings.HasSuffix(req.URL.Path, "/checkpoint-proof") {
						reports++
						if saved.Finalize.Proof == nil || saved.Finalize.TerminalResourceVersion != "43" {
							t.Fatal("report before proof fsync")
						}
						reply := reportReply
						if reply == nil {
							reply = map[string]any{"intent_id": "intent-exact", "status": "completed", "completed": true}
						}
						resp := exportResponse(reply)
						resp.StatusCode = http.StatusAccepted
						resp.Header.Set("Cache-Control", "no-store")
						if reports == 1 {
							return nil, io.ErrUnexpectedEOF
						}
						return resp, nil
					}
					return original.RoundTrip(req)
				})
				run := func() (*storageupload.CheckpointProof, error) {
					root := filepath.Join(filepath.Dir(f.e.cfg.KeyFilePath), "storage-transactions")
					var err error
					activeGuard, err = openSafety(root, &s.Request)
					if err != nil {
						t.Fatal(err)
					}
					return f.e.ReconcileStorageTransaction(context.WithValue(context.Background(), safetyContextKey{}, activeGuard), f.body, f.backend, f.provider, func(context.Context) (string, error) { return "registered-agent-fixture", nil })
				}
				p, runErr := run()
				calls, streams := len(f.calls), f.streams
				if encrypted {
					if runErr == nil || p != nil || deletes != 0 {
						t.Fatal("lost intent acknowledgment authorized delete")
					}
					p, runErr = run()
				}
				if runErr == nil || p != nil || deletes != 1 {
					t.Fatal("delete was completion")
				}
				s = f.disk(t)
				// Recovery must restore the observation before process starts its
				// independent watcher; construction itself performs no native delete.
				f.e.cfg.AgentID, f.e.cfg.AgentAPIKey, f.e.cfg.OrchestratorAPIKey = s.Request.AgentID, "registered-fixture-key", "orchestrator-fixture-key"
				f.e.cfg.OrchestratorURL, f.e.cfg.OrchestratorVerifySSL, f.e.cfg.EnableAPIKeyValidation = "https://backend.example.net", true, true
				f.e.resources = resources.New(1, 1)
				recovered, err := newTransactionRunner(context.Background(), f.e)
				if err != nil {
					t.Fatal(err)
				}
				recoveredGuard := recovered.work[s.Request.BackupID].safety
				deleting, err := d.Resource(kvtypes.BackupResource).Namespace(ns).Get(context.Background(), bname, metav1.GetOptions{})
				if err != nil {
					t.Fatal(err)
				}
				if recovered.work[s.Request.BackupID].held || !f.e.ownedFinalizeAborting(&s.Request, recoveredGuard, deleting) {
					t.Fatal("restart failed to arm before watcher launch")
				}
				recovered.cancel()
				recovered.backend.CloseIdleConnections()
				recovered.provider.CloseIdleConnections()
				_ = recovered.lock.Close()
				for _, fault := range []string{"foreign-uid", "foreign-owner", "wrong-checkpoint", "not-deleting", "delete-rv", "failed-phase", "failed-condition", "expired"} {
					b := deleting.DeepCopy()
					switch fault {
					case "foreign-uid":
						b.SetUID(types.UID("foreign"))
					case "foreign-owner":
						b.SetAnnotations(map[string]string{})
					case "wrong-checkpoint":
						_ = unstructured.SetNestedField(b.Object, "foreign", "status", "checkpointName")
					case "not-deleting":
						b.SetDeletionTimestamp(nil)
					case "delete-rv":
						b.SetResourceVersion(s.Finalize.DeleteResourceVersion)
					case "failed-phase":
						_ = unstructured.SetNestedField(b.Object, "Failed", "status", "phase")
					case "failed-condition":
						_ = unstructured.SetNestedSlice(b.Object, []any{map[string]any{"type": "Failed", "status": "True"}}, "status", "conditions")
					case "expired":
						nativeNow = func() time.Time { return start.Add(48 * time.Hour) }
					}
					if f.e.ownedFinalizeAborting(&s.Request, activeGuard, b) {
						t.Fatal("unsafe observation authorized", fault)
					}
					nativeNow = func() time.Time { return start.Add(30 * time.Second) }
				}
				root := filepath.Join(filepath.Dir(f.e.cfg.KeyFilePath), "storage-transactions")
				journal, err := storageupload.Open(root, f.body)
				if err != nil {
					t.Fatal(err)
				}
				validated, err := journal.Snapshot()
				if err != nil {
					t.Fatal(err)
				}
				// The simulated second process rewrote its safety mirror; use its
				// fresh handle rather than the intentionally superseded first one.
				activeGuard = recoveredGuard
				if err := f.e.inspectSafety(context.Background(), &s.Request, activeGuard); err != nil {
					t.Fatal("normal Pull cleanup tripped independent watch with journal locked", err)
				}
				before, _ := os.ReadFile(activeGuard.path)
				if err := activeGuard.observeFinalize(validated); err != nil {
					t.Fatal(err)
				}
				// The detached snapshot may contain large payload metadata; none
				// is retained, and arming never changes the safety disk schema.
				validated.Native.Objects[1].UID = "mutated-snapshot"
				after, _ := os.ReadFile(activeGuard.path)
				if string(before) != string(after) || !f.e.ownedFinalizeAborting(&s.Request, activeGuard, deleting) {
					t.Fatal("mirror aliased snapshot or wrote disk")
				}
				for _, clear := range []string{"nil", "empty", "refused"} {
					validated, err = journal.Snapshot()
					if err != nil {
						t.Fatal(err)
					}
					if err := activeGuard.observeFinalize(validated); err != nil {
						t.Fatal(err)
					}
					switch clear {
					case "nil":
						validated.Finalize = nil
					case "empty":
						validated.Finalize.DeleteResourceVersion = ""
					case "refused":
						validated.Finalize.DeleteRefused = true
					}
					_ = activeGuard.observeFinalize(validated)
					if f.e.ownedFinalizeAborting(&s.Request, activeGuard, deleting) {
						t.Fatal("stale authority survived", clear)
					}
				}
				_ = journal.Close()
				if s.Acceptance == nil || s.Export == nil || f.streams == 0 {
					t.Fatal("production entry did not traverse upload and acceptance")
				}
				if s.Finalize.Binding.GuestConsistency != guestWant || s.Finalize.Binding.GuestEvidenceSource != "kubevirt/VMB.status.conditions" {
					t.Fatal("guest evidence was inferred from request")
				}
				// Deleting + unchanged tracker waits without another delete.
				if p, err := run(); err == nil || p != nil || deletes != 1 {
					t.Fatal("deleting repeated")
				}
				mutateExportObject(t, f, kvtypes.BackupResource, bname, func(b *unstructured.Unstructured) {
					b.SetResourceVersion("43")
					_ = unstructured.SetNestedSlice(b.Object, []any{
						map[string]any{"type": "Progressing", "status": "False", "reason": "Completed"}, map[string]any{"type": "Done", "status": "True", "reason": "Completed"},
					}, "status", "conditions")
				})
				mutateExportObject(t, f, kvtypes.BackupTrackerResource, s.Native.Objects[0].Name, func(b *unstructured.Unstructured) {
					b.SetResourceVersion("51")
					volumes := []any{}
					for _, v := range s.Export.Volumes {
						volumes = append(volumes, map[string]any{"volumeName": v.Name, "diskTarget": v.DiskTarget})
					}
					_ = unstructured.SetNestedMap(b.Object, map[string]any{"name": s.Export.Checkpoint, "creationTime": s.Utility.StartedAt, "volumes": volumes}, "status", "latestCheckpoint")
				})
				mutateExportObject(t, f, kvtypes.VMIResource, s.Request.Plan.VMName, func(b *unstructured.Unstructured) { unstructured.RemoveNestedField(b.Object, "spec", "utilityVolumes") })
				if p, err := run(); err == nil || p != nil || f.disk(t).Finalize.TerminalResourceVersion != "43" {
					t.Fatal("terminal observation")
				}
				if err := d.Tracker().Delete(kvtypes.BackupResource, ns, bname); err != nil {
					t.Fatal(err)
				}
				// Terminal success is durable and the producer is gone. Publication
				// retries stay inside their separate, original persisted window.
				nativeNow = func() time.Time { return start.Add(time.Minute) }
				if p, err := run(); err == nil || p != nil || f.disk(t).Finalize.Proof == nil {
					t.Fatal("lost report must retain proof")
				}
				for _, reply := range []map[string]any{
					{"intent_id": "intent-exact", "status": "awaiting_manifest", "completed": false},
					{"intent_id": "intent-exact", "status": "completed", "completed": false},
					{"intent_id": "other-intent", "status": "completed", "completed": true},
				} {
					reportReply = reply
					if p, err := run(); err == nil || p != nil || f.disk(t).Finalize.Reported {
						t.Fatal("non-completion acknowledgment stopped publication retries")
					}
				}
				reportReply = nil
				if p, err := run(); err != nil || p == nil {
					t.Fatal("identical report retry", err)
				}
				if _, err := run(); err != nil {
					t.Fatal(err)
				}
				if reports != 5 || deletes != 1 || intents < 2 || len(f.calls) != calls || f.streams != streams {
					t.Fatal("duplicate work during reopen")
				}
				// Recovery needs only the validated publication acknowledgement,
				// even for an old completed attempt without a safety record.
				f.e.cfg.AgentID, f.e.cfg.AgentAPIKey, f.e.cfg.OrchestratorAPIKey = s.Request.AgentID, "registered-fixture-key", "orchestrator-fixture-key"
				f.e.cfg.OrchestratorURL, f.e.cfg.OrchestratorVerifySSL, f.e.cfg.EnableAPIKeyValidation = "https://backend.example.net", true, true
				f.e.resources = resources.New(1, 1)
				nativeNow = func() time.Time { return start.Add(48 * time.Hour) }
				root = filepath.Join(filepath.Dir(f.e.cfg.KeyFilePath), "storage-transactions")
				for _, legacy := range []bool{false, true} {
					if legacy {
						if err := os.Remove(filepath.Join(root, s.Request.ReservationID, "operation-safety.json")); err != nil {
							t.Fatal(err)
						}
					}
					actions := len(d.Actions())
					if err := f.e.StartStorageTransactions(context.Background()); err != nil {
						t.Fatal(err)
					}
					runner := f.e.storageRunner
					work := runner.work[s.Request.BackupID]
					if len(runner.queue) != 0 || !work.finished || work.held || len(d.Actions()) != actions || !f.disk(t).Finalize.Reported {
						t.Fatal("published recovery renewed work or held a completed attempt")
					}
					if p := f.e.GetProgress(s.Request.BackupID); p == nil || p.Status != "completed" {
						t.Fatal("published recovery did not restore completed status")
					}
					if err := f.e.CloseStorageTransactions(); err != nil {
						t.Fatal(err)
					}
					f.e.storageRunner = nil
				}
			})
		}
	}
}

func TestProductionFinalizeMissingGuestEvidence(t *testing.T) {
	condition := func(name, status string) map[string]any {
		return map[string]any{"type": name, "status": status, "reason": "ExportReady"}
	}
	for _, tc := range []struct {
		name             string
		conditions       any
		missing, allowed bool
	}{
		{"missing", nil, true, false},
		{"no-quiesced", []any{condition("Progressing", "True"), condition("Done", "False"), condition("ExportReady", "True")}, false, true},
		{"empty", []any{}, false, false},
		{"unsupported-quiesced", []any{condition("Progressing", "True"), condition("Quiesced", "Unknown")}, false, false},
		{"null", nil, false, false},
		{"not-list", "invalid", false, false},
		{"not-object", []any{"invalid"}, false, false},
		{"empty-type", []any{condition("", "True")}, false, false},
		{"invalid-status", []any{condition("Quiesced", "invalid")}, false, false},
		{"duplicate", []any{condition("Quiesced", "Unknown"), condition("Quiesced", "Unknown")}, false, false},
		{"duplicate-invalid", []any{condition("Quiesced", "Unknown"), condition("Quiesced", "invalid")}, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := readyExportFixture(t, false, false, 1)
			if _, err := f.run(); err != nil {
				t.Fatal(err)
			}
			s := f.disk(t)
			start, err := time.Parse(time.RFC3339Nano, s.Utility.StartedAt)
			if err != nil {
				t.Fatal(err)
			}
			old := nativeNow
			nativeNow = func() time.Time { return start.Add(time.Minute) }
			defer func() { nativeNow = old }()
			mutateExportObject(t, f, kvtypes.BackupResource, s.Native.Objects[1].Name, func(b *unstructured.Unstructured) {
				b.SetResourceVersion("41")
				if tc.missing {
					unstructured.RemoveNestedField(b.Object, "status", "conditions")
				} else if err := unstructured.SetNestedField(b.Object, tc.conditions, "status", "conditions"); err != nil {
					t.Fatal(err)
				}
				if tc.missing || tc.name == "empty" || tc.allowed {
					if guest, ok := guestEvidence(b); !ok || guest != "unknown" {
						t.Fatal("well-formed absence must be unknown guest evidence")
					}
				} else if _, ok := guestEvidence(b); ok {
					t.Fatal("malformed guest evidence accepted")
				}
			})
			intents, deletes := 0, 0
			original := f.backend.Transport
			f.backend.Transport = exportTransport(func(req *http.Request) (*http.Response, error) {
				if strings.HasSuffix(req.URL.Path, "/checkpoint-proof") {
					t.Fatal("no terminal checkpoint proof exists")
				}
				if strings.HasSuffix(req.URL.Path, "/finalize-intent") {
					intents++
					var binding storageupload.FinalizeBinding
					if json.NewDecoder(req.Body).Decode(&binding) != nil {
						t.Fatal("binding decode")
					}
					saved := f.disk(t)
					if saved.Acceptance == nil || saved.Finalize == nil || !reflect.DeepEqual(binding, saved.Finalize.Binding) || binding.GuestConsistency != "unknown" || binding.GuestEvidenceSource != "kubevirt/VMB.status.conditions" {
						t.Fatal("unknown evidence not durable before intent")
					}
					resp := exportResponse(map[string]any{"intent_id": "exact-intent", "binding": binding})
					resp.Header.Set("Cache-Control", "no-store")
					return resp, nil
				}
				return original.RoundTrip(req)
			})
			d := f.e.dynamic.(*dynamicfake.FakeDynamicClient)
			d.PrependReactor("delete", "*", func(a k8stest.Action) (bool, runtime.Object, error) {
				deletes++
				p := a.(k8stest.DeleteAction).GetDeleteOptions().Preconditions
				saved := f.disk(t)
				if a.GetResource() != kvtypes.BackupResource || a.(k8stest.DeleteAction).GetName() != s.Native.Objects[1].Name || a.GetNamespace() != s.Request.Plan.Source.Namespace || p == nil || p.UID == nil || string(*p.UID) != s.Native.Objects[1].UID || p.ResourceVersion == nil || *p.ResourceVersion != "41" || saved.Finalize == nil || saved.Finalize.IntentID != "exact-intent" || saved.Finalize.DeleteResourceVersion != "41" {
					t.Fatal("unfenced delete")
				}
				return true, nil, nil
			})
			proof, err := f.e.ReconcileStorageTransaction(context.Background(), f.body, f.backend, f.provider, func(context.Context) (string, error) { return "registered-agent-fixture", nil })
			if err == nil || proof != nil {
				t.Fatal("absence of terminal evidence became success")
			}
			saved := f.disk(t)
			if tc.allowed {
				if intents != 1 || deletes != 1 || saved.Finalize == nil || saved.Finalize.Proof != nil {
					t.Fatalf("missing evidence did not reach fenced unknown intent: intents=%d deletes=%d finalize=%v error=%v", intents, deletes, saved.Finalize != nil, err)
				}
			} else if intents != 0 || deletes != 0 || saved.Finalize != nil {
				t.Fatal("invalid evidence authorized finalization")
			}
		})
	}
}

func TestProductionFinalizeUnsafeBoundaryHasNoDeleteOrProof(t *testing.T) {
	for _, fault := range []string{"receipt-ack-refused", "ttl", "vmb-replaced", "tracker-replaced", "vmi-replaced", "pvc-replaced", "vmb-absent", "aborting", "wrong-checkpoint"} {
		t.Run(fault, func(t *testing.T) {
			f := readyExportFixture(t, false, false, 1)
			if _, err := f.run(); err != nil {
				t.Fatal(err)
			}
			s := f.disk(t)
			start, _ := time.Parse(time.RFC3339Nano, s.Utility.StartedAt)
			old := nativeNow
			nativeNow = func() time.Time { return start.Add(time.Minute) }
			defer func() { nativeNow = old }()
			original := f.backend.Transport
			f.backend.Transport = exportTransport(func(req *http.Request) (*http.Response, error) {
				if strings.HasSuffix(req.URL.Path, "/storage-control") && f.disk(t).Compensation != nil {
					if fault != "vmb-replaced" && fault != "tracker-replaced" && fault != "vmb-absent" {
						t.Fatal("uncertainty authorized compensation")
					}
					saved := f.disk(t)
					return exportResponse(map[string]any{"schema": 1, "intent_id": saved.Compensation.AbortID, "s3_absent": false, "cleanup_required": true, "capacity_state": "reserved"}), nil
				}
				if strings.HasSuffix(req.URL.Path, "/finalize-intent") {
					if fault == "receipt-ack-refused" {
						return nil, io.ErrUnexpectedEOF
					}
					var b storageupload.FinalizeBinding
					_ = json.NewDecoder(req.Body).Decode(&b)
					response := exportResponse(map[string]any{"intent_id": "exact-intent", "binding": b})
					response.Header.Set("Cache-Control", "no-store")
					return response, nil
				}
				if strings.HasSuffix(req.URL.Path, "/checkpoint-proof") {
					t.Fatal("unsafe proof")
				}
				return original.RoundTrip(req)
			})
			d := f.e.dynamic.(*dynamicfake.FakeDynamicClient)
			deletes := 0
			d.PrependReactor("delete", "*", func(k8stest.Action) (bool, runtime.Object, error) { deletes++; return true, nil, nil })
			replace := func(o *unstructured.Unstructured) { o.SetUID(types.UID("replacement")) }
			switch fault {
			case "ttl":
				nativeNow = func() time.Time { return start.Add(s.Native.BackupTTL()) }
			case "vmb-replaced":
				mutateExportObject(t, f, kvtypes.BackupResource, s.Native.Objects[1].Name, replace)
			case "tracker-replaced":
				mutateExportObject(t, f, kvtypes.BackupTrackerResource, s.Native.Objects[0].Name, replace)
			case "vmi-replaced":
				mutateExportObject(t, f, kvtypes.VMIResource, s.Request.Plan.VMName, replace)
			case "pvc-replaced":
				mutateExportObject(t, f, pvcResource, s.Request.Plan.Source.Volumes[0].PVCName, replace)
			case "vmb-absent":
				if err := d.Tracker().Delete(kvtypes.BackupResource, s.Request.Plan.Source.Namespace, s.Native.Objects[1].Name); err != nil {
					t.Fatal(err)
				}
			case "aborting":
				mutateExportObject(t, f, kvtypes.BackupResource, s.Native.Objects[1].Name, func(o *unstructured.Unstructured) {
					_ = unstructured.SetNestedSlice(o.Object, []any{map[string]any{"type": "Progressing", "status": "True", "reason": "Aborting"}}, "status", "conditions")
				})
			case "wrong-checkpoint":
				mutateExportObject(t, f, kvtypes.BackupResource, s.Native.Objects[1].Name, func(o *unstructured.Unstructured) {
					_ = unstructured.SetNestedField(o.Object, "incidental", "status", "checkpointName")
				})
			}
			calls, streams := len(f.calls), f.streams
			for i := 0; i < 2; i++ {
				p, err := f.e.ReconcileStorageTransaction(context.Background(), f.body, f.backend, f.provider, func(context.Context) (string, error) { return "registered-agent-fixture", nil })
				if err == nil || p != nil || deletes != 0 {
					t.Fatal("unsafe finalization")
				}
			}
			if f.streams != streams || len(f.calls) != calls {
				t.Fatal("repeated storage/source effect")
			}
		})
	}
}

func TestTerminalEvidenceNeverInfersQuiesceOrAbortSuccess(t *testing.T) {
	f := readyExportFixture(t, false, false, 1)
	if _, err := f.run(); err != nil {
		t.Fatal(err)
	}
	s := f.disk(t)
	s.Finalize = &storageupload.FinalizeState{Binding: storageupload.FinalizeBinding{GuestConsistency: "unknown"}}
	b, _ := f.e.dynamic.Resource(kvtypes.BackupResource).Namespace(s.Request.Plan.Source.Namespace).Get(context.Background(), s.Native.Objects[1].Name, metav1.GetOptions{})
	for _, reason := range []string{"Aborting", "Failed", "ExportReady"} {
		_ = unstructured.SetNestedSlice(b.Object, []any{map[string]any{"type": "Done", "status": "False", "reason": reason}, map[string]any{"type": "Progressing", "status": "False", "reason": reason}}, "status", "conditions")
		if terminalSuccess(b, &s) {
			t.Fatal("non-success accepted", reason)
		}
	}
	for _, item := range []struct{ status, reason string }{{"True", "QuiesceSucceeded"}, {"False", "QuiesceFailed"}, {"False", "QuiesceSkipped"}, {"Unknown", "Unknown"}} {
		_ = unstructured.SetNestedSlice(b.Object, []any{map[string]any{"type": "Quiesced", "status": item.status, "reason": item.reason}}, "status", "conditions")
		if _, ok := guestEvidence(b); ok {
			t.Fatal("unsupported guest evidence accepted")
		}
	}
	_ = unstructured.SetNestedSlice(b.Object, []any{
		map[string]any{"type": "Progressing", "status": "False", "reason": "Completed VirtualMachineBackup, warning: guest agent unavailable"},
		map[string]any{"type": "Done", "status": "True", "reason": "Completed VirtualMachineBackup, warning: guest agent unavailable"},
		map[string]any{"type": "Aborting", "status": "False"},
		map[string]any{"type": "Deleting", "status": "True"},
	}, "status", "conditions")
	if !terminalSuccess(b, &s) {
		t.Fatal("HCO 1.8 successful deletion was not terminal proof")
	}
	failed := b.DeepCopy()
	_ = unstructured.SetNestedField(failed.Object, "Failed", "status", "phase")
	if terminalSuccess(failed, &s) {
		t.Fatal("Done plus Failed phase accepted")
	}
	conditions, _, _ := unstructured.NestedSlice(b.Object, "status", "conditions")
	_ = unstructured.SetNestedSlice(b.Object, append(conditions, map[string]any{"type": "Failed", "status": "True"}), "status", "conditions")
	if terminalSuccess(b, &s) {
		t.Fatal("Done plus Failed condition accepted")
	}
}

func TestProductionFinalizeLostDeleteOriginalPreconditionsAndIncidentalAdvance(t *testing.T) {
	for _, fault := range []string{"retry-original", "replacement", "absent-incidental", "ttl", "tracker-replaced", "stuck-finalizer", "delete-conflict"} {
		t.Run(fault, func(t *testing.T) {
			f := readyExportFixture(t, true, false, 1)
			if _, err := f.run(); err != nil {
				t.Fatal(err)
			}
			s := f.disk(t)
			start, _ := time.Parse(time.RFC3339Nano, s.Utility.StartedAt)
			oldNow := nativeNow
			nativeNow = func() time.Time { return start.Add(time.Minute) }
			defer func() { nativeNow = oldNow }()
			d := f.e.dynamic.(*dynamicfake.FakeDynamicClient)
			ns, name := s.Request.Plan.Source.Namespace, s.Native.Objects[1].Name
			mutateExportObject(t, f, kvtypes.BackupResource, name, func(b *unstructured.Unstructured) { b.SetResourceVersion("41") })
			f.backend.Transport = exportTransport(func(req *http.Request) (*http.Response, error) {
				if !strings.HasSuffix(req.URL.Path, "/finalize-intent") {
					t.Fatal("unexpected report/provider work")
				}
				var binding storageupload.FinalizeBinding
				if json.NewDecoder(req.Body).Decode(&binding) != nil {
					t.Fatal("binding")
				}
				return exportResponse(map[string]any{"intent_id": "exact-intent", "binding": binding}), nil
			})
			deletes := 0
			d.PrependReactor("delete", "virtualmachinebackups", func(a k8stest.Action) (bool, runtime.Object, error) {
				deletes++
				want := "41"
				if deletes == 2 {
					want = "42"
				}
				p := a.(k8stest.DeleteAction).GetDeleteOptions().Preconditions
				if p == nil || p.UID == nil || string(*p.UID) != s.Native.Objects[1].UID || p.ResourceVersion == nil || *p.ResourceVersion != want || f.disk(t).Finalize.DeleteResourceVersion != want {
					t.Fatal("retry without exact durable fresh precondition")
				}
				if fault == "delete-conflict" {
					return true, nil, apierrors.NewConflict(kvtypes.BackupResource.GroupResource(), name, errors.New("precondition refused"))
				}
				return true, nil, io.ErrUnexpectedEOF
			})
			run := func() {
				// New executor and journal handle on each observation.
				f.e = NewExecutor(f.e.cfg, nil, d, ns)
				p, err := f.e.ReconcileStorageTransaction(context.Background(), f.body, f.backend, f.provider, func(context.Context) (string, error) { return "registered-agent-fixture", nil })
				if err == nil || p != nil {
					t.Fatal("uncertainty became proof")
				}
			}
			run()
			if deletes != 1 {
				t.Fatal("missing initial exact delete")
			}
			switch fault {
			case "retry-original":
				mutateExportObject(t, f, kvtypes.BackupResource, name, func(b *unstructured.Unstructured) { b.SetResourceVersion("42") })
			case "replacement":
				mutateExportObject(t, f, kvtypes.BackupResource, name, func(b *unstructured.Unstructured) { b.SetUID(types.UID("replacement")) })
			case "absent-incidental":
				if d.Tracker().Delete(kvtypes.BackupResource, ns, name) != nil {
					t.Fatal("fixture")
				}
				mutateExportObject(t, f, kvtypes.BackupTrackerResource, s.Native.Objects[0].Name, func(b *unstructured.Unstructured) {
					_ = unstructured.SetNestedField(b.Object, s.Export.Checkpoint, "status", "latestCheckpoint", "name")
				})
			case "ttl":
				nativeNow = func() time.Time { return start.Add(s.Native.BackupTTL() + time.Hour) }
			case "tracker-replaced":
				mutateExportObject(t, f, kvtypes.BackupTrackerResource, s.Native.Objects[0].Name, func(b *unstructured.Unstructured) { b.SetUID(types.UID("replacement")) })
			case "stuck-finalizer":
				mutateExportObject(t, f, kvtypes.BackupResource, name, func(b *unstructured.Unstructured) {
					now := metav1.NewTime(nativeNow())
					b.SetDeletionTimestamp(&now)
					b.SetFinalizers([]string{"backup.kubevirt.io/vmbackup-protection"})
				})
			case "delete-conflict":
				if !f.disk(t).Finalize.DeleteRefused {
					t.Fatal("known refusal not durable")
				}
			}
			run()
			want := 1
			if fault == "retry-original" {
				want = 2
			}
			if deletes != want || f.disk(t).Finalize.Proof != nil {
				t.Fatal("unsafe repeat/proof")
			}
			for _, a := range d.Actions() {
				if a.GetVerb() == "patch" || (a.GetVerb() == "delete" && a.GetResource() != kvtypes.BackupResource) {
					t.Fatal("broadened native mutation")
				}
			}
		})
	}
}
