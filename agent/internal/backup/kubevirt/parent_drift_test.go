//go:build kubevirt

package kubevirt

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	k8stest "k8s.io/client-go/testing"
	"vnbui/agent/internal/storageupload"
)

func TestMissingParentStopsBeforeNativePreparation(t *testing.T) {
	for _, variant := range []string{"missing", "replacement", "checkpoint", "transient"} {
		t.Run(variant, func(t *testing.T) {
			e, body, r, dyn := nativeFixture(t, true)
			resource := schema.GroupVersionResource{Group: "backup.kubevirt.io", Version: "v1alpha1", Resource: "virtualmachinebackuptrackers"}
			name := kubevirtTrackerName(r.Plan.Source.Namespace + "/" + r.Plan.Source.VMUID)
			tracker, err := dyn.Resource(resource).Namespace("ns").Get(context.Background(), name, metav1.GetOptions{})
			if err != nil {
				t.Fatal(err)
			}
			switch variant {
			case "missing":
				err = dyn.Resource(resource).Namespace("ns").Delete(context.Background(), name, metav1.DeleteOptions{})
			case "replacement":
				tracker.SetUID("replacement")
				_, err = dyn.Resource(resource).Namespace("ns").Update(context.Background(), tracker, metav1.UpdateOptions{})
			case "checkpoint":
				_ = unstructured.SetNestedField(tracker.Object, "foreign-checkpoint", "status", "latestCheckpoint", "name")
				_, err = dyn.Resource(resource).Namespace("ns").Update(context.Background(), tracker, metav1.UpdateOptions{})
			case "transient":
				dyn.PrependReactor("get", "virtualmachinebackuptrackers", func(k8stest.Action) (bool, runtime.Object, error) {
					return true, nil, errors.New("temporary API outage")
				})
			}
			if err != nil {
				t.Fatal(err)
			}
			dyn.ClearActions()
			if j, err := e.PrepareStorageTransaction(context.Background(), body); err == nil {
				j.Close()
				t.Fatal("invalid parent admitted")
			}
			for _, a := range dyn.Actions() {
				if a.GetVerb() != "get" {
					t.Fatal("provider mutation before source admission", a)
				}
			}
			root := filepath.Join(filepath.Dir(e.cfg.KeyFilePath), "storage-transactions")
			j, err := storageupload.Open(root, body)
			if err != nil {
				t.Fatal(err)
			}
			defer j.Close()
			state, err := j.Snapshot()
			if err != nil {
				t.Fatal(err)
			}
			want := "held"
			if variant == "transient" {
				want = "uploading"
			}
			if state.Phase != want {
				t.Fatalf("phase=%s, want %s", state.Phase, want)
			}
			if state.Native != nil || state.Acceptance != nil || state.Receipt != nil {
				t.Fatal("effects or acceptance on source refusal")
			}
		})
	}
}
