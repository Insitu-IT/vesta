package models

import (
	"encoding/json"
	"os"
	"testing"
)

func TestNativeDiskSourceRepresentation(t *testing.T) {
	baseline, err := os.ReadFile("../../contracts/storage_semantic_valid.json")
	if err != nil {
		t.Fatal(err)
	}
	legacy, err := DecodeStorageTransaction(baseline)
	if err != nil {
		t.Fatal(err)
	}
	old, _ := json.Marshal(legacy)
	var oldWire map[string]any
	_ = json.Unmarshal(old, &oldWire)
	if _, exists := oldWire["plan"].(map[string]any)["source"].(map[string]any)["native_volumes"]; exists {
		t.Fatal("legacy shape changed")
	}
	legacy.Plan.Source.Schema = 2
	extra := legacy.Plan.Source.Volumes[0]
	extra.Name, extra.PVCName, extra.PVCUID, extra.Mapping.DiskName = "excluded", "excluded", "excluded-uid", "excluded"
	legacy.Plan.Source.NativeVolumes = append(append([]StorageVolume(nil), legacy.Plan.Source.Volumes...), extra)
	legacy.Plan.Exclusions = []string{"excluded"}
	good := hashedStorageBody(t, *legacy)
	if _, err := DecodeStorageTransaction(good); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*StorageTransactionRequest){
		func(r *StorageTransactionRequest) { r.Plan.Source.Schema = 1 },
		func(r *StorageTransactionRequest) { r.Plan.Source.NativeVolumes = nil },
		func(r *StorageTransactionRequest) {
			r.Plan.Source.NativeVolumes = append(r.Plan.Source.NativeVolumes, r.Plan.Source.NativeVolumes[1])
		},
		func(r *StorageTransactionRequest) { r.Plan.Source.NativeVolumes[0].PVCUID = "replacement" },
		func(r *StorageTransactionRequest) { r.Plan.Source.NativeVolumes[1].CapacityBytes = 0 },
		func(r *StorageTransactionRequest) { r.Plan.Exclusions = []string{} },
	} {
		var r StorageTransactionRequest
		_ = json.Unmarshal(good, &r)
		mutate(&r)
		if _, err := DecodeStorageTransaction(hashedStorageBody(t, r)); err == nil {
			t.Fatal("accepted malformed native participant set")
		}
	}
}
