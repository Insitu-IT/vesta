//go:build kubevirt

package kubevirt

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"vnbui/agent/internal/storageupload"
)

func TestQueuedNamespaceNarrowingHoldsBeforeNativeCreate(t *testing.T) {
	e, body, r, client := nativeFixture(t, false)
	policy := filepath.Join(t.TempDir(), "scope.json")
	if err := os.WriteFile(policy, []byte(`{"source_namespaces":["ns"],"default_selected_namespaces":[],"restore_namespaces":["recovery"],"scratch_pvcs":{"ns":"scratch"}}`), 0600); err != nil {
		t.Fatal(err)
	}
	e.cfg.Provider = "kubevirt"
	if err := e.cfg.LoadNamespacePolicy(policy); err != nil {
		t.Fatal(err)
	}
	j, err := e.PrepareStorageTransaction(context.Background(), body)
	if j != nil || !errors.Is(err, storageupload.ErrHeld) {
		t.Fatalf("queued source started: %v %v", j, err)
	}
	for _, a := range client.Actions() {
		if a.GetVerb() == "create" {
			t.Fatal("out of scope native resource created")
		}
	}
	root := filepath.Join(filepath.Dir(e.cfg.KeyFilePath), "storage-transactions")
	retained, err := storageupload.Open(root, body)
	if err != nil {
		t.Fatal("journal custody lost", err)
	}
	defer retained.Close()
	state, err := retained.Snapshot()
	if err != nil || state.Native != nil || state.Request.ReservationID != r.ReservationID {
		t.Fatal("scope hold altered custody")
	}
}

func TestPolicySourceFenceOverridesLegacySingletonWithoutBreakingCustody(t *testing.T) {
	e, _, r, _ := nativeFixture(t, false)
	policy := filepath.Join(t.TempDir(), "scope.json")
	if err := os.WriteFile(policy, []byte(`{"source_namespaces":["ns"],"default_selected_namespaces":["ns"],"restore_namespaces":[],"scratch_pvcs":{"ns":"scratch"}}`), 0600); err != nil {
		t.Fatal(err)
	}
	e.cfg.Provider = "kubevirt"
	if err := e.cfg.LoadNamespacePolicy(policy); err != nil {
		t.Fatal(err)
	}
	e.namespace = "legacy-other"
	if err := e.verifyTransactionSource(context.Background(), r); err != nil {
		t.Fatal("installed multi-namespace policy blocked by legacy singleton", err)
	}
	if !e.cfg.ApplySourceSelection([]string{}, "narrowed") {
		t.Fatal("selection")
	}
	if err := e.verifyTransactionSource(context.Background(), r); err != nil {
		t.Fatal("observation of ongoing source custody must remain available", err)
	}
}

func TestUnconfiguredRunnerRejectsNewSourceBeforeJournalAdmission(t *testing.T) {
	e, body, _ := runnerFixture(t)
	e.cfg.KubeNamespace = ""
	runner := startTestRunner(t, e, func(context.Context, []byte) (*storageupload.CheckpointProof, error) {
		t.Error("unconfigured source reached producer")
		return nil, storageupload.ErrHeld
	})
	if err := e.StartStorageTransaction(context.Background(), body); err == nil {
		t.Fatal("unconfigured source admitted")
	}
	runner.mu.Lock()
	defer runner.mu.Unlock()
	if len(runner.work) != 0 || len(runner.queue) != 0 {
		t.Fatal("unconfigured source entered durable queue")
	}
}

func TestUnconfiguredSourceCannotEraseOrBlockExistingNativeCustodyObservation(t *testing.T) {
	e, body, _, client := nativeFixture(t, false)
	journal, err := e.PrepareStorageTransaction(context.Background(), body)
	if err != nil {
		t.Fatal(err)
	}
	original, err := journal.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if original.Native == nil {
		t.Fatal("fixture did not begin native custody")
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
	e.cfg.KubeNamespace = ""
	client.ClearActions()
	reopened, err := e.PrepareStorageTransaction(context.Background(), body)
	if err != nil {
		t.Fatal("existing custody observation refused", err)
	}
	defer reopened.Close()
	current, err := reopened.Snapshot()
	if err != nil || !reflect.DeepEqual(original, current) {
		t.Fatal("existing journal custody changed")
	}
	for _, action := range client.Actions() {
		if action.GetVerb() != "get" {
			t.Fatal("custody observation mutated native state")
		}
	}
}
