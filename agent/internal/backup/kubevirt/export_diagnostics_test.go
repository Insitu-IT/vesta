//go:build kubevirt

package kubevirt

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	kvtypes "vnbui/agent/internal/provider/kubevirt"
)

func TestExportRefusalRetainsExactPredicateAndBoundedCounts(t *testing.T) {
	f := readyExportFixtureVolumes(t, false, false, 64, 1)
	bindExportFixture(t, f)
	mutateExportObject(t, f, kvtypes.BackupResource, f.state.Native.Objects[1].Name, func(o *unstructured.Unstructured) {
		_ = unstructured.SetNestedSlice(o.Object, []interface{}{}, "status", "includedVolumes")
	})
	_, err := f.run()
	fault := faultOf(err)
	if fault.Reason != "native_volume_count_mismatch" || fault.Disposition != "refused" ||
		fault.ExpectedNativeVolumes == nil || *fault.ExpectedNativeVolumes != 2 ||
		fault.ObservedNativeVolumes == nil || *fault.ObservedNativeVolumes != 0 || fault.ObservedExportLinks != nil {
		t.Fatal("predicate/counts lost before caller received refusal", fault)
	}
	if f.streams != 0 {
		t.Fatal("payload read after export refusal")
	}
}

func TestExportRefusalDoesNotRetainChangedEndpointText(t *testing.T) {
	f := readyExportFixtureVolumes(t, false, false, 64, 1)
	bindExportFixture(t, f)
	mutateExportObject(t, f, kvtypes.BackupResource, f.state.Native.Objects[1].Name, func(o *unstructured.Unstructured) {
		items, _, _ := unstructured.NestedSlice(o.Object, "status", "includedVolumes")
		items[1].(map[string]interface{})["dataEndpoint"] = "https://private-token:private-secret@untrusted/exports/data-two/data"
		_ = unstructured.SetNestedSlice(o.Object, items, "status", "includedVolumes")
	})
	state := f.disk(t)
	_, err := f.e.inspectExport(context.Background(), &state)
	fault := faultOf(err)
	if fault.Reason != "export_endpoint_changed" || fault.Disposition != "refused" {
		t.Fatal("lost endpoint refusal predicate", fault)
	}
	encoded, _ := json.Marshal(fault)
	if strings.Contains(string(encoded), "private-") || strings.Contains(string(encoded), "https://") {
		t.Fatal("provider text leaked into bounded diagnostics")
	}
}
