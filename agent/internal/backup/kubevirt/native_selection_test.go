//go:build kubevirt

package kubevirt

import (
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"vnbui/agent/internal/models"
	kvtypes "vnbui/agent/internal/provider/kubevirt"
)

func TestNativeSelectionFullControllerSetAndScratch(t *testing.T) {
	for _, incremental := range []bool{false, true} {
		f := readyExportFixtureVolumes(t, incremental, false, 64, 1)
		r := &f.state.Request
		native, err := nativeBytes(r)
		selected, _ := selectedBytes(r)
		if err != nil || native != selected+r.Plan.Source.NativeVolumes[1].CapacityBytes || native <= selected {
			t.Fatal("scratch did not account for excluded native disk", native, selected, err)
		}
		a, err := f.run()
		if err != nil || a == nil {
			t.Fatal(err)
		}
		state := f.disk(t)
		if len(state.Export.NativeVolumes) != 2 || len(state.Export.Volumes) != 1 || len(state.Maps) != 1 || len(state.Receipt.Objects) != 2 || f.streams != 2 {
			t.Fatal("controller set leaked into upload or omitted from custody")
		}
		for _, artifact := range state.Request.Plan.Artifacts {
			if artifact.VolumeID != state.Request.Plan.Source.Volumes[0].PVCUID {
				t.Fatal("excluded payload admitted")
			}
		}
	}
}

func TestNativeSelectionExcludedIdentityAndEndpointMutationsRefuse(t *testing.T) {
	for _, variant := range []string{"extra", "duplicate", "endpoint", "target", "replacement-pvc"} {
		t.Run(variant, func(t *testing.T) {
			f := readyExportFixtureVolumes(t, false, false, 64, 1)
			bindExportFixture(t, f)
			switch variant {
			case "replacement-pvc":
				mutateExportObject(t, f, pvcResource, "data-two", func(o *unstructured.Unstructured) { o.SetUID("replacement") })
			default:
				mutateExportObject(t, f, kvtypes.BackupResource, f.state.Native.Objects[1].Name, func(o *unstructured.Unstructured) {
					items, _, _ := unstructured.NestedSlice(o.Object, "status", "includedVolumes")
					excluded := items[1].(map[string]interface{})
					switch variant {
					case "extra":
						items = append(items, map[string]interface{}{"volumeName": "unknown", "diskTarget": "vdc", "dataEndpoint": "https://unknown/exports/unknown/data", "mapEndpoint": "https://unknown/exports/unknown/map"})
					case "duplicate":
						items = append(items, items[1])
					case "endpoint":
						excluded["dataEndpoint"] = "https://unknown/exports/data-two/data"
					case "target":
						excluded["diskTarget"] = "vda"
					}
					_ = unstructured.SetNestedSlice(o.Object, items, "status", "includedVolumes")
				})
			}
			if _, err := f.run(); err == nil {
				t.Fatal("accepted native participant mutation")
			}
			if f.streams != 0 {
				t.Fatal("read selected payload after native identity drift")
			}
		})
	}
}

func TestLegacyPersistentSelectionRefusesBeforeNativeEffects(t *testing.T) {
	r, objects := sourceAdmissionFixture()
	r.Plan.Source.Volumes = r.Plan.Source.Volumes[:1]
	r.Plan.Exclusions = []string{"data-two", "seed"}
	spec, _, _ := unstructured.NestedMap(objects[2].Object, "spec", "template", "spec")
	if matchesSourceSpec(spec, r) {
		t.Fatal("legacy selection admitted excluded persistent participant")
	}
	// Explicit schema2 binds both PVCs while preserving selected upload intent.
	r.Plan.Source.Schema = 2
	source, _ := sourceAdmissionFixture()
	r.Plan.Source.NativeVolumes = append([]models.StorageVolume(nil), source.Plan.Source.Volumes...)
	if !matchesSourceSpec(spec, r) {
		t.Fatal("complete native identities refused")
	}
}
