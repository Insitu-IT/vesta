//go:build kubevirt

package kubevirt

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"vnbui/agent/internal/models"
	kvtypes "vnbui/agent/internal/provider/kubevirt"
	"vnbui/agent/internal/resources"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	dynamicfake "k8s.io/client-go/dynamic/fake"
)

func TestReplacementCannotCommitOrAbortOldJournal(t *testing.T) {
	e, cfg, s3, tx := transactionFixture(t)
	ctx := context.Background()
	dyn := e.dynamic.(*dynamicfake.FakeDynamicClient)
	vm, err := dyn.Resource(kvtypes.VMResource).Namespace(tx.Namespace).Get(ctx, tx.VMName, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	vm.SetUID(types.UID("replacement"))
	if _, err := dyn.Resource(kvtypes.VMResource).Namespace(tx.Namespace).Update(ctx, vm, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	req := &models.BackupRequest{VMNamespace: tx.Namespace, VMName: tx.VMName, VMUID: tx.VMUID}
	if err := e.verifyVMIdentity(ctx, req); err == nil {
		t.Fatal("stale VM UID accepted")
	}
	if committed, err := e.checkpointCommitted(ctx, tx); err != nil || committed {
		t.Fatalf("old checkpoint promoted: %v %v", committed, err)
	}
	tx.Phase = "published"
	s3.objects[tx.Prefix+"payload"] = true
	if err := e.saveTransaction(tx); err != nil {
		t.Fatal(err)
	}
	dyn.ClearActions()
	restarted := NewExecutor(e.cfg, resources.New(1, 1), dyn, "test")
	restarted.recoverTransactions(cfg)
	p := restarted.GetProgress(tx.BackupID)
	if restarted.recovered || p == nil || p.Status != models.TaskStatusCleanupRequired {
		t.Fatalf("replacement released recovery: %+v", p)
	}
	if s3.objects[tx.Prefix+"payload"] {
		t.Fatal("original S3 prefix not compensated")
	}
	for _, a := range dyn.Actions() {
		if a.GetVerb() != "get" {
			t.Fatalf("replacement caused cluster mutation: %v", a)
		}
	}
	data, err := os.ReadFile(filepath.Join(e.transactionDir(), tx.BackupID+".json"))
	if err != nil {
		t.Fatal(err)
	}
	var saved pullTransaction
	if err := json.Unmarshal(data, &saved); err != nil {
		t.Fatal(err)
	}
	if saved.VMUID != "stable" || saved.TrackerUID != "original" || saved.Namespace != "test" {
		t.Fatalf("journal rebound: %+v", saved)
	}
}

func TestTrackerIdentitySeparatesNamespacesAndIncarnations(t *testing.T) {
	e, _, _, _ := transactionFixture(t)
	ctx := context.Background()
	old := kubevirtTrackerName("test/stable")
	if old == kubevirtTrackerName("other/stable") || old == kubevirtTrackerName("test/replacement") {
		t.Fatal("tracker identity collision")
	}
	if _, err := e.ensureBackupTracker(ctx, "test", old, "vm", "replacement"); err == nil {
		t.Fatal("old tracker adopted by replacement")
	}
	newName := kubevirtTrackerName("test/replacement")
	checkpoint, err := e.ensureBackupTracker(ctx, "test", newName, "vm", "replacement")
	if err != nil || checkpoint {
		t.Fatalf("replacement inherited baseline: %v %v", checkpoint, err)
	}
}
