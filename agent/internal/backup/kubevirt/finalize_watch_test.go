//go:build kubevirt

package kubevirt

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/watch"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	k8stest "k8s.io/client-go/testing"
	kvtypes "vnbui/agent/internal/provider/kubevirt"
	"vnbui/agent/internal/storageupload"
)

func TestFinalizeWatchRecoversOriginalTerminalBeforeAbsence(t *testing.T) {
	for _, variant := range []string{
		"deleted", "modified", "wrong-uid", "wrong-owner", "wrong-spec", "wrong-guest", "wrong-checkpoint",
		"ttl-expired", "nonterminal", "not-deleting", "same-cursor", "watch-expired", "error-event", "closed-watch", "replacement-after-history",
	} {
		t.Run(variant, func(t *testing.T) {
			f := readyExportFixture(t, false, false, 9)
			state := f.disk(t)
			dynamic := f.e.dynamic.(*dynamicfake.FakeDynamicClient)
			namespace, name := state.Request.Plan.Source.Namespace, state.Native.Objects[1].Name
			initial, err := dynamic.Resource(kvtypes.BackupResource).Namespace(namespace).Get(context.Background(), name, metav1.GetOptions{})
			if err != nil {
				t.Fatal(err)
			}
			oldNow := nativeNow
			observationTime := initial.GetCreationTimestamp().Add(time.Minute)
			nativeNow = func() time.Time { return observationTime }
			defer func() { nativeNow = oldNow }()
			initial.SetResourceVersion("41")
			if err := dynamic.Tracker().Update(kvtypes.BackupResource, initial, namespace); err != nil {
				t.Fatal(err)
			}
			terminal := initial.DeepCopy()
			stamp := metav1.NewTime(observationTime)
			terminal.SetDeletionTimestamp(&stamp)
			terminal.SetResourceVersion("43")
			_ = unstructured.SetNestedSlice(terminal.Object, []any{
				map[string]any{"type": "Progressing", "status": "False", "reason": "Completed"},
				map[string]any{"type": "Done", "status": "True", "reason": "Completed"},
			}, "status", "conditions")
			deletes, reports, watches := 0, 0, 0
			dynamic.PrependReactor("delete", "virtualmachinebackups", func(action k8stest.Action) (bool, runtime.Object, error) {
				deletes++
				options := action.(k8stest.DeleteAction).GetDeleteOptions()
				if options.Preconditions == nil || options.Preconditions.UID == nil || string(*options.Preconditions.UID) != state.Native.Objects[1].UID || options.Preconditions.ResourceVersion == nil || *options.Preconditions.ResourceVersion != "41" || f.disk(t).Finalize.DeleteResourceVersion != "41" {
					t.Fatal("delete did not retain exact original cursor")
				}
				trackerRaw, err := dynamic.Tracker().Get(kvtypes.BackupTrackerResource, namespace, state.Native.Objects[0].Name)
				if err != nil {
					t.Fatal(err)
				}
				tracker := trackerRaw.(*unstructured.Unstructured).DeepCopy()
				tracker.SetResourceVersion("51")
				volumes := make([]any, 0, len(f.disk(t).Export.Volumes))
				for _, volume := range f.disk(t).Export.Volumes {
					volumes = append(volumes, map[string]any{"volumeName": volume.Name, "diskTarget": volume.DiskTarget})
				}
				saved := f.disk(t)
				_ = unstructured.SetNestedMap(tracker.Object, map[string]any{"name": saved.Export.Checkpoint, "creationTime": saved.Utility.StartedAt, "volumes": volumes}, "status", "latestCheckpoint")
				if err := dynamic.Tracker().Update(kvtypes.BackupTrackerResource, tracker, namespace); err != nil {
					t.Fatal(err)
				}
				instanceRaw, err := dynamic.Tracker().Get(kvtypes.VMIResource, namespace, state.Request.Plan.VMName)
				if err != nil {
					t.Fatal(err)
				}
				instance := instanceRaw.(*unstructured.Unstructured).DeepCopy()
				unstructured.RemoveNestedField(instance.Object, "spec", "utilityVolumes")
				if err := dynamic.Tracker().Update(kvtypes.VMIResource, instance, namespace); err != nil {
					t.Fatal(err)
				}
				// The whole terminal update disappears between observations; only
				// the later watch replay will expose the original object's event.
				return true, nil, dynamic.Tracker().Delete(kvtypes.BackupResource, namespace, name)
			})
			backend := f.backend.Transport
			f.backend.Transport = exportTransport(func(request *http.Request) (*http.Response, error) {
				if strings.HasSuffix(request.URL.Path, "/finalize-intent") {
					var binding storageupload.FinalizeBinding
					if json.NewDecoder(request.Body).Decode(&binding) != nil {
						t.Fatal("invalid finalize request")
					}
					response := exportResponse(map[string]any{"intent_id": "watch-intent", "binding": binding})
					response.Header.Set("Cache-Control", "no-store")
					return response, nil
				}
				if strings.HasSuffix(request.URL.Path, "/checkpoint-proof") {
					reports++
					saved := f.disk(t)
					if saved.Finalize.TerminalResourceVersion != "43" || saved.Finalize.Proof == nil {
						t.Fatal("checkpoint report preceded durable terminal history")
					}
					response := exportResponse(map[string]any{"intent_id": "watch-intent", "status": "completed", "completed": true})
					response.StatusCode = http.StatusAccepted
					response.Header.Set("Cache-Control", "no-store")
					return response, nil
				}
				return backend.RoundTrip(request)
			})
			run := func() (*storageupload.CheckpointProof, error) {
				return f.e.ReconcileStorageTransaction(context.Background(), f.body, f.backend, f.provider, func(context.Context) (string, error) { return "registered-agent-fixture", nil })
			}
			if proof, err := run(); err == nil || proof != nil || deletes != 1 || f.disk(t).Finalize.TerminalResourceVersion != "" {
				t.Fatal("delete/absence alone completed backup", err)
			}
			dynamic.PrependWatchReactor("virtualmachinebackups", func(action k8stest.Action) (bool, watch.Interface, error) {
				watches++
				restrictions := action.(k8stest.WatchAction).GetWatchRestrictions()
				if action.GetNamespace() != namespace || restrictions.Fields.String() != "metadata.name="+name || restrictions.ResourceVersion != "41" {
					t.Fatal("watch escaped durable original cursor")
				}
				if variant == "watch-expired" {
					return true, nil, apierrors.NewResourceExpired("original event history unavailable")
				}
				stream := watch.NewRaceFreeFake()
				if variant == "closed-watch" {
					stream.Stop()
					return true, stream, nil
				}
				if variant == "error-event" {
					stream.Error(&metav1.Status{Code: 410, Reason: metav1.StatusReasonExpired})
					return true, stream, nil
				}
				event := terminal.DeepCopy()
				switch variant {
				case "wrong-uid":
					event.SetUID(types.UID("replacement"))
				case "wrong-owner":
					event.SetOwnerReferences(nil)
				case "wrong-spec":
					_ = unstructured.SetNestedField(event.Object, "wrong-scratch", "spec", "pvcName")
				case "wrong-guest":
					rows, _, _ := unstructured.NestedSlice(event.Object, "status", "conditions")
					_ = unstructured.SetNestedSlice(event.Object, append(rows, map[string]any{"type": "Quiesced", "status": "True", "reason": "QuiesceSucceeded"}), "status", "conditions")
				case "wrong-checkpoint":
					_ = unstructured.SetNestedField(event.Object, "wrong-checkpoint", "status", "checkpointName")
				case "ttl-expired":
					event.SetCreationTimestamp(metav1.NewTime(observationTime.Add(-state.Native.BackupTTL() - time.Hour)))
				case "nonterminal":
					_ = unstructured.SetNestedSlice(event.Object, []any{}, "status", "conditions")
				case "not-deleting":
					event.SetDeletionTimestamp(nil)
				case "same-cursor":
					event.SetResourceVersion("41")
				case "replacement-after-history":
					replacement := initial.DeepCopy()
					replacement.SetUID(types.UID("replacement"))
					if err := dynamic.Tracker().Create(kvtypes.BackupResource, replacement, namespace); err != nil {
						t.Fatal(err)
					}
				}
				if variant == "modified" {
					stream.Modify(event)
				} else {
					stream.Delete(event)
				}
				return true, stream, nil
			})
			proof, err := run()
			success := variant == "deleted" || variant == "modified"
			if success {
				if err != nil || proof == nil || reports != 1 || f.disk(t).Finalize.TerminalResourceVersion != "43" || !f.disk(t).Finalize.Reported {
					t.Fatal("exact terminal history did not publish", err)
				}
			} else if err == nil || proof != nil || reports != 0 || f.disk(t).Finalize.Proof != nil {
				t.Fatal("unproven terminal state produced a checkpoint proof")
			}
			if watches != 1 || deletes != 1 {
				t.Fatal("watch retry repeated destructive work", watches, deletes)
			}
		})
	}
}
