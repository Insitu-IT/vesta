//go:build kubevirt

package kubevirt

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"vnbui/agent/internal/config"
	"vnbui/agent/internal/models"
	"vnbui/agent/internal/resources"
)

func TestRestoreNamespacePolicyRequiresExplicitBoundedScopes(t *testing.T) {
	oversized := make([]string, 33)
	for i := range oversized {
		oversized[i] = fmt.Sprintf("destination-%d", i)
	}
	for _, scopes := range [][]string{nil, {}, {"*"}, {""}, {"ns", "ns"}, {"ns", " other"}, oversized} {
		cfg := &config.Config{AgentID: "agent", KeyFilePath: filepath.Join(t.TempDir(), "agent.key"),
			KubevirtRestoreImage: testRestoreImage, KubevirtRestoreNamespaces: scopes,
			EnableAPIKeyValidation: true, OrchestratorAPIKey: "test", OrchestratorVerifySSL: true}
		e := NewExecutor(cfg, resources.New(1, 1), nil, "ns")
		if err := e.StartRestores(context.Background()); err == nil {
			_ = e.CloseRestores()
			t.Fatalf("unbounded or implicit destination policy admitted: %v", scopes)
		}
	}
}

func TestCrossNamespaceRestoreRoutesEveryEffectToAuthorizedDestination(t *testing.T) {
	e, state, client := controllerFixtureInNamespace(t, "recovery")
	ctx := context.Background()
	if err := e.reconcile(ctx, state); err != nil {
		t.Fatal(err)
	}
	completeWorker(t, state, client)
	if err := e.reconcile(ctx, state); err != nil {
		t.Fatal(err)
	}
	if state.Progress.Status != models.TaskStatusCompleted || state.Progress.Result["namespace"] != "recovery" {
		t.Fatal("cross-namespace completion lost target identity", state.Progress)
	}
	vm, err := client.Resource(vmGVR).Namespace("recovery").Get(ctx, state.Request.Target.VMName, metav1.GetOptions{})
	if err != nil || vm.Object["spec"].(map[string]interface{})["runStrategy"] != "Halted" {
		t.Fatal("fresh recovery VM was not created Halted", err)
	}
	for _, action := range client.Actions() {
		if action.GetNamespace() != "recovery" {
			t.Fatalf("restore escaped destination namespace: %s %s %s", action.GetVerb(), action.GetResource().Resource, action.GetNamespace())
		}
	}
}

func TestUnlistedRestoreNamespaceHasNoProviderEffects(t *testing.T) {
	e, state, client := controllerFixture(t)
	state.Request.Target.Namespace = "unlisted"
	if err := e.reconcile(context.Background(), state); !errors.Is(err, errHeld) {
		t.Fatal("unlisted destination was not held", err)
	}
	if len(client.Actions()) != 0 {
		t.Fatal("unlisted destination caused Kubernetes IO")
	}
	// Mutating the original configuration cannot extend the executor's frozen scope.
	e.cfg.KubevirtRestoreNamespaces = append(e.cfg.KubevirtRestoreNamespaces, "unlisted")
	if e.namespaceAllowed("unlisted") {
		t.Fatal("configuration mutation expanded live restore authority")
	}
}

func TestRestoreAdmissionRejectsUnlistedDestinationBeforeJournal(t *testing.T) {
	_, _, client := controllerFixture(t)
	req := restoreFixture(t)
	cfg := &config.Config{AgentID: req.AgentID, KeyFilePath: filepath.Join(t.TempDir(), "agent.key"),
		KubevirtRestoreImage: testRestoreImage, KubevirtRestoreNamespaces: []string{"recovery"},
		EnableAPIKeyValidation: true, OrchestratorAPIKey: "test", OrchestratorVerifySSL: true}
	e := NewExecutor(cfg, resources.New(1, 1), client, "ns")
	if err := e.StartRestores(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer e.CloseRestores()
	for _, namespace := range []string{"ns", "unlisted"} {
		req.Target.Namespace = namespace
		if _, err := e.StartRestore(&models.RestoreRequest{RestoreID: req.RestoreID, KubeVirt: req}); err == nil {
			t.Fatalf("unlisted destination admitted: %s", namespace)
		}
		if _, err := os.Stat(filepath.Join(e.root, req.RestoreID+".json")); !os.IsNotExist(err) {
			t.Fatal("unlisted admission wrote a journal", err)
		}
	}
	if len(client.Actions()) != 0 || len(e.states) != 0 {
		t.Fatal("unlisted admission retained state or touched Kubernetes")
	}
}

func TestRestoreDestinationRevocationHoldsOriginalJournal(t *testing.T) {
	e, state, client := controllerFixtureInNamespace(t, "recovery")
	journal := filepath.Join(e.root, state.Request.RestoreID+".json")
	before, err := os.ReadFile(journal)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{AgentID: state.Request.AgentID, KeyFilePath: filepath.Join(filepath.Dir(e.root), "agent.key"),
		KubevirtRestoreImage: testRestoreImage, KubevirtRestoreNamespaces: []string{"ns"},
		EnableAPIKeyValidation: true, OrchestratorAPIKey: "test", OrchestratorVerifySSL: true}
	// Use the actual fixture root, retaining its original request and plan digest.
	cfg.KeyFilePath = filepath.Join(t.TempDir(), "agent.key")
	root := filepath.Join(filepath.Dir(cfg.KeyFilePath), "kubevirt-restores")
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	copyPath := filepath.Join(root, filepath.Base(journal))
	if err := os.WriteFile(copyPath, before, 0600); err != nil {
		t.Fatal(err)
	}
	restarted := NewExecutor(cfg, resources.New(1, 1), client, "ns")
	if err := restarted.StartRestores(context.Background()); !errors.Is(err, errHeld) {
		if err == nil {
			_ = restarted.CloseRestores()
		}
		t.Fatal("revoked journal destination did not hold startup", err)
	}
	after, err := os.ReadFile(copyPath)
	if err != nil || string(after) != string(before) || len(client.Actions()) != 0 {
		t.Fatal("revocation altered original journal or caused provider effects", err)
	}
}

func TestCompletedRestoreHistorySurvivesDestinationRevocationWithoutEffects(t *testing.T) {
	e, state, client := controllerFixtureInNamespace(t, "recovery")
	if err := e.reconcile(context.Background(), state); err != nil {
		t.Fatal(err)
	}
	completeWorker(t, state, client)
	if err := e.reconcile(context.Background(), state); err != nil {
		t.Fatal(err)
	}
	if state.Progress.Status != models.TaskStatusCompleted {
		t.Fatal("fixture restore did not complete")
	}
	if err := e.save(state); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(filepath.Join(e.root, state.Request.RestoreID+".json"))
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{AgentID: state.Request.AgentID, KeyFilePath: filepath.Join(t.TempDir(), "agent.key"),
		KubevirtRestoreImage: testRestoreImage, KubevirtRestoreNamespaces: []string{"ns"},
		EnableAPIKeyValidation: true, OrchestratorAPIKey: "test", OrchestratorVerifySSL: true}
	root := filepath.Join(filepath.Dir(cfg.KeyFilePath), "kubevirt-restores")
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	journal := filepath.Join(root, state.Request.RestoreID+".json")
	if err := os.WriteFile(journal, before, 0600); err != nil {
		t.Fatal(err)
	}
	client.ClearActions()
	restarted := NewExecutor(cfg, resources.New(1, 1), client, "ns")
	if err := restarted.StartRestores(context.Background()); err != nil {
		t.Fatal("completed history prevented destination revocation", err)
	}
	if err := restarted.CloseRestores(); err != nil {
		t.Fatal(err)
	}
	progress := restarted.GetProgress(state.Request.RestoreID)
	after, err := os.ReadFile(journal)
	if progress == nil || progress.Status != models.TaskStatusCompleted || err != nil || string(after) != string(before) || len(client.Actions()) != 0 {
		t.Fatal("completed history was lost, rewritten or caused provider effects", err)
	}
}
