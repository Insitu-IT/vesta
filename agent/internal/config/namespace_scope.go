package config

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"slices"
	"sync"

	"vnbui/agent/internal/models"
)

// NamespaceScope is installation-owned. Only its selected subset is mutable.
type NamespaceScope struct {
	SourceNamespaces          []string          `json:"source_namespaces"`
	DefaultSelectedNamespaces []string          `json:"default_selected_namespaces"`
	RestoreNamespaces         []string          `json:"restore_namespaces"`
	ScratchPVCs               map[string]string `json:"scratch_pvcs"`
	mu                        sync.RWMutex
	selected                  []string
	revision                  string
}

var namespaceName = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)

func validNamespaces(values []string, required bool) bool {
	if len(values) > 32 || (required && len(values) == 0) {
		return false
	}
	seen := map[string]bool{}
	for _, v := range values {
		if len(v) > 63 || !namespaceName.MatchString(v) || seen[v] {
			return false
		}
		seen[v] = true
	}
	return true
}
func (c *Config) LoadNamespacePolicy(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	scope := &NamespaceScope{}
	decoder := json.NewDecoder(f)
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(scope); err != nil {
		return err
	}
	if !validNamespaces(scope.SourceNamespaces, true) || !validNamespaces(scope.DefaultSelectedNamespaces, false) || !validNamespaces(scope.RestoreNamespaces, false) {
		return fmt.Errorf("invalid installed namespace policy")
	}
	for _, ns := range scope.DefaultSelectedNamespaces {
		if !slices.Contains(scope.SourceNamespaces, ns) {
			return fmt.Errorf("selected namespace outside installed ceiling")
		}
	}
	for _, ns := range scope.SourceNamespaces {
		if !namespaceName.MatchString(scope.ScratchPVCs[ns]) {
			return fmt.Errorf("missing scratch PVC for source namespace %s", ns)
		}
	}
	scope.selected = slices.Clone(scope.DefaultSelectedNamespaces)
	c.NamespaceScope = scope
	c.KubevirtRestoreNamespaces = slices.Clone(scope.RestoreNamespaces)
	return nil
}
func (c *Config) SelectedSourceNamespaces() []string {
	if c.NamespaceScope == nil {
		if c.KubeNamespace != "" {
			return []string{c.KubeNamespace}
		}
		return nil
	}
	s := c.NamespaceScope
	s.mu.RLock()
	defer s.mu.RUnlock()
	return slices.Clone(s.selected)
}
func (c *Config) SourceNamespaceAllowed(ns string) bool {
	if c.NamespaceScope == nil {
		return ns != "" && c.KubeNamespace != "" && c.KubeNamespace == ns
	}
	return slices.Contains(c.SelectedSourceNamespaces(), ns)
}
func (c *Config) ScratchPVC(ns string) string {
	if c.NamespaceScope != nil {
		return c.NamespaceScope.ScratchPVCs[ns]
	}
	return c.KubevirtBackupScratchPVC
}
func (c *Config) ApplySourceSelection(raw interface{}, revision string) bool {
	if c.Provider != "kubevirt" || c.NamespaceScope == nil || revision == "" {
		return false
	}
	values := []string{}
	switch list := raw.(type) {
	case []interface{}:
		for _, v := range list {
			s, ok := v.(string)
			if !ok {
				return false
			}
			values = append(values, s)
		}
	case []string:
		values = list
	default:
		return false
	}
	if !validNamespaces(values, false) {
		return false
	}
	for _, ns := range values {
		if !slices.Contains(c.NamespaceScope.SourceNamespaces, ns) {
			return false
		}
	}
	s := c.NamespaceScope
	s.mu.Lock()
	defer s.mu.Unlock()
	s.selected = slices.Clone(values)
	s.revision = revision
	return true
}
func (c *Config) ScopeReport() map[string]interface{} {
	if c.NamespaceScope == nil {
		return nil
	}
	s := c.NamespaceScope
	s.mu.RLock()
	defer s.mu.RUnlock()
	return map[string]interface{}{"source_namespaces": slices.Clone(s.SourceNamespaces), "selected_source_namespaces": slices.Clone(s.selected), "restore_namespaces": slices.Clone(s.RestoreNamespaces), "scratch_pvcs": s.ScratchPVCs, "applied_revision": s.revision}
}

// CapabilityReport refreshes existing registrations after provider upgrades.
func (c *Config) CapabilityReport() map[string]interface{} {
	var report map[string]interface{}
	switch c.Provider {
	case "kubevirt", "libvirt":
		report = map[string]interface{}{
			"provider": c.Provider, "platform": map[string]string{"kubevirt": "KubeVirt", "libvirt": "KVM/QEMU"}[c.Provider],
			"backup_method":       map[string]string{"kubevirt": "kubevirt_pull_transaction", "libvirt": "native_push"}[c.Provider],
			"s3_recovery_restore": true,
			"incremental":         true, "stream_through": c.Provider == "kubevirt", "local_output": c.Provider == "libvirt",
		}
	case "none":
		report = map[string]interface{}{"provider": "none", "platform": "Linux"}
	default:
		return nil
	}
	if c.Provider == "kubevirt" {
		report["kubevirt_transfer_profiles"] = []string{models.KubevirtTransfer32}
		report["kubevirt_native_disk_profiles"] = []string{models.KubevirtNativeDisks}
		report["s3_recovery_restore_namespaces"] = slices.Clone(c.KubevirtRestoreNamespaces)
		report["kubevirt_restore_profiles"] = []string{models.KubeVirtSelectedDiskRestore}
	}
	if len(c.ManagedFileSets) > 0 {
		report["managed_file_sets"] = c.ManagedFileSets
		report["managed_file_storage"] = c.ManagedFileStorage
	}
	return report
}
