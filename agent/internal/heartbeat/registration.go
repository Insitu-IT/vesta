package heartbeat

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"vnbui/agent/internal/config"
	"vnbui/agent/internal/models"
	"vnbui/agent/internal/provider"
	"vnbui/agent/internal/sysutil"
)

// RequestVMSync queues an inventory refresh without blocking the provider's
// watch loop. Multiple lifecycle events coalesce into one pending refresh.
func RequestVMSync(requests chan<- struct{}) {
	select {
	case requests <- struct{}{}:
	default:
	}
}

// RunVMSyncLoop combines prompt lifecycle refreshes with bounded reconciliation.
// A lost event or failed delivery must not leave newly created/stopped VMs
// permanently absent. Inventory synchronization never starts a backup.
func RunVMSyncLoop(
	ctx context.Context,
	requests <-chan struct{},
	cfg *config.Config,
	vmProvider provider.VMProvider,
	client *http.Client,
) {
	runVMSyncLoop(ctx, requests, cfg, vmProvider, client, 5*time.Minute)
}

func runVMSyncLoop(ctx context.Context, requests <-chan struct{}, cfg *config.Config, vmProvider provider.VMProvider, client *http.Client, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case _, open := <-requests:
			if !open {
				requests = nil // Do not spin if lifecycle delivery is closed.
				continue
			}
		case <-ticker.C:
		}
		if ctx.Err() != nil {
			return
		}
		if err := SyncVMs(cfg, vmProvider, client); err != nil {
			slog.Warn("VM inventory sync failed; will reconcile", "error", err)
		}
	}
}

// RegistrationResult holds the result of agent registration.
type RegistrationResult struct {
	AgentID  string `json:"agent_id"`
	APIKey   string `json:"api_key"`
	Hostname string `json:"hostname"`
	// TLS data (nested object, if mTLS is configured)
	TLS *RegistrationTLS `json:"tls,omitempty"`
}

// RegistrationTLS holds TLS certificate data from registration.
type RegistrationTLS struct {
	CACert      string `json:"ca_cert,omitempty"`
	AgentCert   string `json:"agent_cert,omitempty"`
	AgentKey    string `json:"agent_key,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"`
}

// Register performs agent registration with the orchestrator.
func Register(cfg *config.Config, vmProvider provider.VMProvider, version string, client *http.Client) (*RegistrationResult, error) {
	ip := cfg.AgentIP
	if ip == "" {
		ip = sysutil.PrimaryIP()
	}

	libvirtURI := cfg.LibvirtURI
	if cfg.Provider == "kubevirt" || cfg.Provider == "none" {
		libvirtURI = ""
	}
	var capabilities provider.ProviderCapabilities
	if vmProvider != nil {
		capabilities = vmProvider.Capabilities()
	}
	reg := models.AgentRegistration{
		DisplayName: cfg.AgentDisplayName,
		Hostname:    cfg.Hostname,
		IPAddress:   ip,
		Port:        cfg.AgentPort,
		LibvirtURI:  libvirtURI,
		Version:     version,
		Capabilities: map[string]interface{}{
			"provider":       cfg.Provider,
			"platform":       map[string]string{"kubevirt": "KubeVirt", "libvirt": "KVM/QEMU", "none": "Linux"}[cfg.Provider],
			"incremental":    capabilities.SupportsIncremental,
			"checkpoints":    capabilities.SupportsCheckpoints,
			"block_jobs":     capabilities.SupportsBlockJobPoll,
			"backup_method":  capabilities.BackupMethod,
			"stream_through": capabilities.SupportsStreamThrough,
			"local_output":   capabilities.SupportsLocalOutput,
		},
	}

	if cfg.Provider == "kubevirt" {
		reg.Capabilities["kubevirt_transfer_profiles"] = []string{models.KubevirtTransfer32}
		reg.Capabilities["kubevirt_native_disk_profiles"] = []string{models.KubevirtNativeDisks}
		reg.Capabilities["kubevirt_restore_profiles"] = []string{models.KubeVirtSelectedDiskRestore}
	}
	body, err := json.Marshal(reg)
	if err != nil {
		return nil, fmt.Errorf("marshal registration: %w", err)
	}

	url := fmt.Sprintf("%s/api/v1/agents/register", cfg.OrchestratorURL)
	req, err := http.NewRequest("POST", url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if cfg.RegistrationKey != "" {
		req.Header.Set("X-API-Key", cfg.RegistrationKey)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("POST %s: %w", url, err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("registration failed: HTTP %d: %s", resp.StatusCode, string(respBody))
	}

	var result RegistrationResult
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}

	slog.Info("registered with orchestrator",
		"agent_id", result.AgentID,
		"has_cert", result.TLS != nil,
	)

	return &result, nil
}

// SyncVMs sends the current VM list to the orchestrator.
func SyncVMs(cfg *config.Config, vmProvider provider.VMProvider, client *http.Client) error {
	var vms []models.VMInfo
	var err error
	namespaces := cfg.SelectedSourceNamespaces()
	if scoped, ok := vmProvider.(interface {
		ListVMsWithNamespaces() ([]models.VMInfo, []string, error)
	}); ok {
		vms, namespaces, err = scoped.ListVMsWithNamespaces()
	} else {
		vms, err = vmProvider.ListVMs()
	}
	if err != nil {
		return fmt.Errorf("list VMs: %w", err)
	}
	if vms == nil {
		vms = []models.VMInfo{}
	}

	payload := map[string]interface{}{
		"vms":               vms,
		"complete":          true,
		"source_namespaces": namespaces,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal VMs: %w", err)
	}

	url := fmt.Sprintf("%s/api/v1/agents/%s/vms", cfg.OrchestratorURL, cfg.Hostname)
	req, err := http.NewRequest("POST", url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Agent-Key", cfg.AgentAPIKey)

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("POST %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("VM sync failed: HTTP %d: %s", resp.StatusCode, string(respBody))
	}

	slog.Info("synced VMs", "count", len(vms))
	return nil
}
