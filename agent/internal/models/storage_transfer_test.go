package models

import (
	"encoding/json"
	"os"
	"reflect"
	"testing"
)

func TestTransferProfileWirePreservesLegacyAndRejectsUnknown(t *testing.T) {
	baseline, err := os.ReadFile("../../contracts/storage_semantic_valid.json")
	if err != nil {
		t.Fatal(err)
	}
	original, err := DecodeStorageTransaction(baseline)
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(original)
	legacy, err := DecodeStorageTransaction(encoded)
	if err != nil || !reflect.DeepEqual(original, legacy) {
		t.Fatal("legacy plan changed", err)
	}
	var legacyWire map[string]any
	_ = json.Unmarshal(encoded, &legacyWire)
	if _, exists := legacyWire["plan"].(map[string]any)["transfer_profile"]; exists {
		t.Fatal("legacy profile was materialized")
	}
	original.Plan.TransferProfile = KubevirtTransfer32
	current := hashedStorageBody(t, *original)
	upgraded, err := DecodeStorageTransaction(current)
	if err != nil || upgraded.Plan.TransferProfile != KubevirtTransfer32 {
		t.Fatal(err)
	}
	for _, invalid := range []any{nil, "", "legacy", "kubevirt-64m/1", true, 32, []any{KubevirtTransfer32}, map[string]any{"profile": KubevirtTransfer32}} {
		var wire map[string]any
		_ = json.Unmarshal(current, &wire)
		wire["plan"].(map[string]any)["transfer_profile"] = invalid
		canonical, err := StorageCanonical(wire["plan"])
		if err != nil {
			t.Fatal(err)
		}
		wire["plan_sha256"] = storageHash(string(canonical))
		body, _ := json.Marshal(wire)
		if _, err := DecodeStorageTransaction(body); err == nil {
			t.Fatalf("accepted malformed profile %T", invalid)
		}
	}
	var stripped map[string]any
	_ = json.Unmarshal(current, &stripped)
	delete(stripped["plan"].(map[string]any), "transfer_profile")
	body, _ := json.Marshal(stripped)
	if _, err := DecodeStorageTransaction(body); err == nil {
		t.Fatal("profile stripped without invalidating digest")
	}
}
