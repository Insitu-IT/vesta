//go:build kubevirt

package main

import (
	"k8s.io/client-go/dynamic"

	"vnbui/agent/internal/backup"
	kvbackup "vnbui/agent/internal/backup/kubevirt"
	"vnbui/agent/internal/config"
	"vnbui/agent/internal/provider"
	"vnbui/agent/internal/provider/kubevirt"
	"vnbui/agent/internal/reconcile"
	"vnbui/agent/internal/resources"
	"vnbui/agent/internal/restore"
	kvrestore "vnbui/agent/internal/restore/kubevirt"
)

func init() {
	newKubevirtProvider = func(cfg *config.Config) provider.VMProvider {
		p := kubevirt.New(cfg.KubeconfigPath, cfg.KubeNamespace)
		p.SetTrackerPrefix(cfg.KubevirtPrefix())
		p.SetAPIBudget(cfg.KubeAPIQPS, cfg.KubeAPIBurst)
		return p
	}

	newKubevirtBackupExecutor = func(cfg *config.Config, res *resources.Manager, dynClient interface{}, namespace string) backup.ExecutorIface {
		return kvbackup.NewExecutor(cfg, res, dynClient.(dynamic.Interface), namespace)
	}

	newKubevirtRestoreExecutor = func(cfg *config.Config, res *resources.Manager, dynClient interface{}, namespace string) restore.ExecutorIface {
		return kvrestore.NewExecutor(cfg, res, dynClient.(dynamic.Interface), namespace)
	}

	newKubevirtReconciler = func(dynClient interface{}, namespace string) reconcile.ReconcileFunc {
		return reconcile.NewKubevirtReconciler(dynClient.(dynamic.Interface), namespace)
	}
}
