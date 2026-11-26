//go:build kubevirt

package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/dynamic"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	kvbackup "vnbui/agent/internal/backup/kubevirt"
	"vnbui/agent/internal/config"
	kvprovider "vnbui/agent/internal/provider/kubevirt"
	"vnbui/agent/internal/resources"
	kvrestore "vnbui/agent/internal/restore/kubevirt"
)

// Inherit Capabilities from the real provider. Only cluster transport is fake;
// a changed production capability must still choose the correct startup path.
type startupKubevirtProvider struct {
	*kvprovider.Provider
	client dynamic.Interface
}

func (p startupKubevirtProvider) DynamicClient() interface{} { return p.client }

type startupNoHTTP struct{ t *testing.T }

func (r startupNoHTTP) RoundTrip(*http.Request) (*http.Response, error) {
	r.t.Error("held KubeVirt reconciliation unexpectedly attempted HTTP")
	return nil, fmt.Errorf("HTTP forbidden by startup test")
}

func TestRealKubevirtCapabilitySelectsTransactionExecutors(t *testing.T) {
	dyn := dynamicfake.NewSimpleDynamicClient(runtime.NewScheme())
	p := startupKubevirtProvider{Provider: kvprovider.New("", "ns"), client: dyn}
	cfg := &config.Config{KubeNamespace: "ns", KubevirtResourcePrefix: "vesta", AgentID: "11111111-1111-4111-8111-111111111111", AgentAPIKey: "agent-fixture-key", OrchestratorAPIKey: "orchestrator-fixture-key", OrchestratorURL: "https://backend.example.net", OrchestratorVerifySSL: true, EnableAPIKeyValidation: true, KeyFilePath: filepath.Join(t.TempDir(), "agent.key"), KubevirtBackupScratchPVC: "scratch"}
	manager := resources.New(1, 1)
	backupExec, restoreExec, reconcileFn, err := selectExecutors(cfg, manager, p)
	if err != nil {
		t.Fatal(err)
	}
	transactions, ok := backupExec.(*kvbackup.Executor)
	if !ok {
		t.Fatalf("real capability %q selected %T, not KubeVirt transactions", p.Capabilities().BackupMethod, backupExec)
	}
	if _, ok := restoreExec.(*kvrestore.Executor); !ok {
		t.Fatalf("real capability selected non-KubeVirt restore %T", restoreExec)
	}
	if _, ok := backupExec.(interface {
		StartStorageTransaction(context.Context, []byte) error
	}); !ok {
		t.Fatal("selected backup cannot admit the storage transaction API")
	}
	if _, ok := backupExec.(interface {
		StartNativeJob(context.Context, []byte) error
	}); ok {
		t.Fatal("selected backup exposes the libvirt native intent API")
	}
	if err := transactions.StartStorageTransactions(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer transactions.CloseStorageTransactions()
	root := filepath.Join(filepath.Dir(cfg.KeyFilePath), "storage-transactions")
	if info, err := os.Stat(root); err != nil || !info.IsDir() {
		t.Fatal("startup reported activation without the KubeVirt durable journal root", err)
	}
	// Real KubeVirt reconciliation refuses legacy orphan cleanup when current
	// transaction custody exists. The generic/native reconciler would contact HTTP.
	if err := os.WriteFile(filepath.Join(root, "retained-custody"), []byte("held"), 0600); err != nil {
		t.Fatal(err)
	}
	if reconcileFn == nil {
		t.Fatal("startup omitted reconciliation")
	}
	if _, err := reconcileFn(cfg, &http.Client{Transport: startupNoHTTP{t}}, manager); err != nil {
		t.Fatal(err)
	}
	if len(dyn.Actions()) != 0 {
		t.Fatal("startup/reconciliation accessed native resources despite retained custody")
	}
}
