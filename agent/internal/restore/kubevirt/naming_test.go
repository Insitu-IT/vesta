//go:build kubevirt

package kubevirt

import (
	"bytes"
	"context"
	"errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"os"
	"path/filepath"
	"testing"
	"vnbui/agent/internal/models"
	"vnbui/agent/internal/resources"
	"vnbui/agent/internal/restoreinput"
)

func TestRestoreVestaNamesLabelsAndWorkerAccount(t *testing.T) {
	e, s, c := controllerFixture(t)
	e.cfg.KubevirtResourcePrefix = "vesta"
	s.ResourcePrefix = "vesta"
	if err := e.reconcile(context.Background(), s); err != nil {
		t.Fatal(err)
	}
	if resourceName(s) != "vesta-restore-"+s.PlanSHA[:24] {
		t.Fatal(resourceName(s))
	}
	for _, action := range c.Actions() {
		if action.GetVerb() != "create" {
			continue
		}
		object := action.(interface{ GetObject() runtime.Object }).GetObject().(*unstructured.Unstructured)
		if object.GetLabels()["app.kubernetes.io/managed-by"] != "vesta" {
			t.Fatal("wrong manager", object.GetKind())
		}
		if object.GetKind() == "Job" {
			account, _, _ := unstructured.NestedString(object.Object, "spec", "template", "spec", "serviceAccountName")
			if account != "vesta-restore-worker" {
				t.Fatal(account)
			}
		}
	}
	if err := e.save(s); err != nil {
		t.Fatal(err)
	}
	var reopened restoreState
	if err := restoreinput.ReadJSONFile(filepath.Join(e.root, s.Request.RestoreID+".json"), &reopened, 4<<20, true); err != nil {
		t.Fatal(err)
	}
	if reopened.ResourcePrefix != "vesta" || resourceName(&reopened) != resourceName(s) {
		t.Fatal("saved prefix lost")
	}
}

func TestRestoreLegacyPrefixDoesNotAdoptChangedProcessConfig(t *testing.T) {
	e, s, c := controllerFixture(t)
	e.cfg.KubevirtResourcePrefix = "vesta"
	c.ClearActions()
	if resourceName(s) != "vnbui-restore-"+s.PlanSHA[:24] {
		t.Fatal("old journal renamed")
	}
	if err := e.reconcile(context.Background(), s); !errors.Is(err, errHeld) {
		t.Fatal(err)
	}
	if len(c.Actions()) != 0 {
		t.Fatal("mixed prefix restore touched Kubernetes")
	}
}

func TestLegacyRestoreCompletedHistoryLoadsUnderNewPrefixWithoutRewrite(t *testing.T) {
	e, s, c := controllerFixture(t)
	root := t.TempDir()
	e.root = filepath.Join(root, "kubevirt-restores")
	if err := os.Mkdir(e.root, 0700); err != nil {
		t.Fatal(err)
	}
	s.Progress.Status = models.TaskStatusCompleted
	if err := e.save(s); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(e.root, s.Request.RestoreID+".json")
	before, _ := os.ReadFile(path)
	cfg := e.cfg
	cfg.AgentID = s.Request.AgentID
	cfg.KeyFilePath = filepath.Join(root, "agent.key")
	cfg.KubevirtRestoreImage = testRestoreImage
	cfg.KubevirtResourcePrefix = "vesta"
	cfg.EnableAPIKeyValidation = true
	cfg.OrchestratorAPIKey = "test"
	cfg.OrchestratorVerifySSL = true
	reopened := NewExecutor(cfg, resources.New(1, 1), c, "ns")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := reopened.StartRestores(ctx); err != nil {
		t.Fatal(err)
	}
	defer reopened.CloseRestores()
	if p := reopened.GetProgress(s.Request.RestoreID); p == nil || p.Status != models.TaskStatusCompleted {
		t.Fatal("completed history lost", p)
	}
	after, _ := os.ReadFile(path)
	if len(c.Actions()) != 0 || !bytes.Equal(before, after) {
		t.Fatal("history load caused effects")
	}
}
