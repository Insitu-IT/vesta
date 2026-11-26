package storagerestore

import (
	"encoding/json"
	"os"
	"testing"

	"vnbui/agent/internal/models"
)

func TestRestoreLineagePinsNativeParticipantsWithoutRestoringExcludedDisks(t *testing.T) {
	body, err := os.ReadFile("../../contracts/storage_semantic_valid.json")
	if err != nil {
		t.Fatal(err)
	}
	var root models.StorageTransactionRequest
	if json.Unmarshal(body, &root) != nil {
		t.Fatal("fixture")
	}
	root.Plan.Source.Schema = 2
	excluded := root.Plan.Source.Volumes[0]
	excluded.Name, excluded.PVCName, excluded.PVCUID, excluded.Mapping.DiskName = "excluded", "excluded", "excluded-uid", "excluded"
	root.Plan.Source.NativeVolumes = append(append([]models.StorageVolume(nil), root.Plan.Source.Volumes...), excluded)
	root.Plan.Exclusions = []string{"excluded"}
	clone := func() models.StorageTransactionRequest {
		b, _ := json.Marshal(root)
		var r models.StorageTransactionRequest
		_ = json.Unmarshal(b, &r)
		return r
	}
	next := clone()
	next.Plan.Source.NativeVolumes[1].PVCResourceVersion = "999"
	if !sameSource(root, next) {
		t.Fatal("observation churn rejected")
	}
	next.Plan.Source.NativeVolumes[1].PVCUID = "replacement"
	if sameSource(root, next) {
		t.Fatal("excluded native identity drift accepted in restore chain")
	}
	legacy := clone()
	legacy.Plan.Source.Schema = 1
	legacy.Plan.Source.NativeVolumes = nil
	if sameSource(root, legacy) {
		t.Fatal("native participant semantics silently crossed schema versions")
	}
	if len(root.Plan.Source.Volumes) != 1 {
		t.Fatal("restore disk selection expanded")
	}
}
