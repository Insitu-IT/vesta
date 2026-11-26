//go:build kubevirt

package kubevirt

import (
	"context"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	k8stest "k8s.io/client-go/testing"
	kvtypes "vnbui/agent/internal/provider/kubevirt"
	"vnbui/agent/internal/storageupload"
)

func TestNativeBoundaryUtilityAttachmentBetweenReads(t *testing.T) {
	for _, incremental := range []bool{false, true} {
		t.Run(map[bool]string{false: "full", true: "incremental"}[incremental], func(t *testing.T) {
			e, _, dyn, state := attachedFixture(t, incremental)
			attached, err := dyn.Resource(kvtypes.VMIResource).Namespace("ns").Get(context.Background(), state.Request.Plan.VMName, metav1.GetOptions{})
			if err != nil {
				t.Fatal(err)
			}
			beforeAttachment := attached.DeepCopy()
			unstructured.RemoveNestedField(beforeAttachment.Object, "spec", "utilityVolumes")
			unstructured.RemoveNestedField(beforeAttachment.Object, "status", "changedBlockTracking", "backupStatus")
			reads, bindings := 0, 0
			dyn.PrependReactor("get", kvtypes.VMIResource.Resource, func(k8stest.Action) (bool, runtime.Object, error) {
				reads++
				if reads == 1 {
					return true, beforeAttachment.DeepCopy(), nil
				}
				return true, attached.DeepCopy(), nil
			})
			dyn.ClearActions()
			bind := func(utility storageupload.BorrowedUtility) error {
				bindings++
				state.Utility = &utility
				return nil
			}
			// The controller attaches our utility immediately after the first
			// observation. Mixing that with an unbound comparison must not turn
			// ordinary preparation into a permanent source-mapping refusal.
			if err := e.admitNativeSnapshot(context.Background(), &state, bind); err != nil {
				t.Fatalf("attachment transition refused before it could be bound: %v", err)
			}
			if bindings != 0 || state.Utility != nil || reads != 1 {
				t.Fatalf("unobserved attachment bound or observation mixed: reads=%d bindings=%d", reads, bindings)
			}
			if err := e.admitNativeSnapshot(context.Background(), &state, bind); err != nil {
				t.Fatal(err)
			}
			if bindings != 1 || state.Utility == nil || reads != 2 || state.Utility.BackupUID != state.Native.Objects[1].UID {
				t.Fatal("next boundary did not freshly observe and bind the exact utility")
			}
			// A single observation is scoped to one boundary, never a cache.
			// A subsequent actual source replacement must still be refused.
			attached.SetUID("replacement-vmi")
			if err := e.admitNativeSnapshot(context.Background(), &state, bind); err == nil {
				t.Fatal("prior admission survived a source replacement")
			}
			if reads != 3 || bindings != 1 {
				t.Fatal("replacement changed custody")
			}
			for _, action := range dyn.Actions() {
				if action.GetVerb() != "get" || action.GetResource().Resource == "secrets" {
					t.Fatal("admission transition caused a native mutation or token read")
				}
			}
		})
	}
}
