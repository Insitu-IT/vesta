//go:build kubevirt

package kubevirt

import (
	"bytes"
	"context"
	"errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"vnbui/agent/internal/models"
	"vnbui/agent/internal/storageupload"
)

func TestNativeVestaNamesPersistAndCrossPrefixResumeHolds(t *testing.T) {
	e, body, r, dyn := nativeFixture(t, false)
	e.cfg.KubevirtResourcePrefix = "vesta"
	j, err := e.PrepareStorageTransaction(context.Background(), body)
	if err != nil {
		t.Fatal(err)
	}
	state, err := j.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if state.ResourcePrefix != "vesta" || state.Native.Objects[1].Name != "vesta-"+r.BackupID {
		t.Fatal("new prefix not pinned", state)
	}
	for _, o := range state.Native.Objects {
		if !strings.HasPrefix(o.Name, "vesta-") {
			t.Fatal(o.Name)
		}
		obj, err := dyn.Resource(nativeResource(o.Role)).Namespace(r.Plan.Source.Namespace).Get(context.Background(), o.Name, metav1.GetOptions{})
		if err != nil || obj.GetLabels()["app.kubernetes.io/managed-by"] != "vesta" {
			t.Fatal("wrong manager label", err)
		}
	}
	j.Close()
	e.cfg.KubevirtResourcePrefix = "vnbui"
	dyn.ClearActions()
	if _, err = e.PrepareStorageTransaction(context.Background(), body); !errors.Is(err, storageupload.ErrHeld) {
		t.Fatal("mixed prefix resumed", err)
	}
	if len(dyn.Actions()) != 0 {
		t.Fatal("mixed prefix accessed Kubernetes", dyn.Actions())
	}
	e.cfg.KubevirtResourcePrefix = "vesta"
	j, err = e.PrepareStorageTransaction(context.Background(), body)
	if err != nil {
		t.Fatal("same prefix reopen failed", err)
	}
	j.Close()
}

func TestLegacyPullNamesDoNotFollowProcessConfiguration(t *testing.T) {
	e, _, _, dyn := nativeFixture(t, false)
	e.cfg.KubevirtResourcePrefix = "vesta"
	old := &pullTransaction{BackupID: "old", Namespace: "ns"}
	if pullBackupName(old) != "vnbui-old" {
		t.Fatal("old journal renamed")
	}
	if err := e.abortNative(context.Background(), old); err == nil {
		t.Fatal("cross-prefix abort accepted")
	}
	if len(dyn.Actions()) != 0 {
		t.Fatal("cross-prefix abort touched cluster")
	}
	old.Tracker = "vesta-foreign"
	e.cfg.KubevirtResourcePrefix = "vnbui"
	if e.pullNamingMatches(old) {
		t.Fatal("missing prefix adopted other-profile tracker")
	}
	e.cfg.KubevirtResourcePrefix = "vesta"
	modern := &pullTransaction{BackupID: "new", ResourcePrefix: "vesta"}
	if pullBackupName(modern) != "vesta-new" || !e.pullNamingMatches(modern) {
		t.Fatal("new naming not pinned")
	}
}

func TestLegacyPullCompletedHistoryRemainsReadOnlyAcrossPrefixChange(t *testing.T) {
	e, _, _, dyn := nativeFixture(t, false)
	old := &pullTransaction{BackupID: "historical", Namespace: "ns", Phase: "committed", Tracker: "vnbui-original"}
	if err := e.saveTransaction(old); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(e.transactionDir(), old.BackupID+".json")
	before, _ := os.ReadFile(path)
	e.cfg.KubevirtResourcePrefix = "vesta"
	e.recoverTransactions(nil)
	after, _ := os.ReadFile(path)
	if p := e.GetProgress(old.BackupID); p == nil || p.Status != models.TaskStatusCompleted {
		t.Fatal("completed history lost", p)
	}
	if len(dyn.Actions()) != 0 || !bytes.Equal(before, after) {
		t.Fatal("history recovery caused effects")
	}
}
