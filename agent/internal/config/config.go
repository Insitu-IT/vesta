package config

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"vnbui/agent/internal/operationbudget"
)

// UIConfigurableSettings are settings that can be changed via heartbeat config.
var UIConfigurableSettings = map[string]bool{
	"max_concurrent_backups": true,
	"backup_storage_path":    true,
	"virtnbdbackup_path":     true,
	"virtnbdrestore_path":    true,
	"virtnbd_scratch_dir":    true,
	"libvirt_uri":            true,
	"heartbeat_interval":     true,
	"log_level":              true,
	"compression_type":       true,
	"compression_level":      true,
}

// Config holds all agent configuration.
type Config struct {
	runtimeMu            sync.Mutex
	LogLevelControl      *slog.LevelVar
	NamespaceScope       *NamespaceScope
	NamespacePolicyError error
	AgentDisplayName     string
	// Identity
	Hostname    string
	AgentID     string
	AgentPort   int
	AgentHost   string
	AgentIP     string // Override IP reported to orchestrator
	Environment string

	// Compression
	CompressionType  string
	CompressionLevel string

	// Orchestrator
	OrchestratorURL    string
	AgentAPIKey        string
	OrchestratorAPIKey string

	// Registration
	RegistrationKey  string
	KeyFilePath      string
	KeystoreIdentity string

	// Libvirt
	LibvirtURI  string
	MockLibvirt bool

	// Backup
	BackupStoragePath          string
	NativeStagingRoot          string // optional operator-managed ext4 allocation profile
	NativeStagingSocket        string // local root allocation-only broker; never UI-configurable
	NativeRestoreRoot          string // installation-owned fresh native VM image root
	NativeRestoreCAFile        string // optional trusted S3 CA bundle
	VirtnbdbackupPath          string
	VirtnbdrestorePath         string
	VirtnbdScratchDir          string
	MaxConcurrentBackups       int
	VerificationTimeoutSeconds int // installation-owned read deadline, not heartbeat-configurable
	MockVirtnbdbackup          bool
	OperationBudget            operationbudget.Policy // installation-owned; pinned for each accepted operation
	SourceHealthProbesJSON     string

	// Security
	EnableAPIKeyValidation bool
	RequireTLS             bool
	AllowedOrchestratorIPs []string

	// TLS (outbound)
	OrchestratorVerifySSL  bool
	TLSCAFile              string // trusted API/server CA for outbound requests
	CallbackClientCertFile string
	CallbackClientKeyFile  string

	// mTLS (agent as server)
	TLSEnabled      bool
	TLSCertFile     string
	TLSKeyFile      string
	TLSClientCAFile string // trusted backend client CA for inbound requests
	TLSVerifyClient bool

	// Health
	HeartbeatInterval int
	HeartbeatEnabled  bool

	// Logging
	LogLevel string

	// Provider selection
	Provider string // "libvirt", "kubevirt", or "mock"

	// KubeVirt
	KubeconfigPath            string   // path to kubeconfig (empty = in-cluster)
	KubeNamespace             string   // namespace scope (empty = cluster-wide)
	KubevirtResourcePrefix    string   // installation-owned Kubernetes naming; empty retains legacy vnbui
	KubevirtBackupScratchPVC  string   // filesystem PVC used by KubeVirt pull-mode backup
	KubevirtRestoreImage      string   // installation-pinned image containing /vnbui-restore
	KubevirtRestoreCAFile     string   // optional trusted S3 CA bundle copied into the restore worker
	KubevirtRestoreNamespaces []string // installation-owned exact destination allowlist

	KubeAPIQPS                        int // one shared budget for typed and dynamic clients
	KubeAPIBurst                      int
	KubevirtTransactionTimeoutSeconds int // 0: no additional runner deadline; native lifetime remains bounded
	KubevirtNativeTTLSeconds          int // immutable lifetime for newly prepared native backups
}

// Load creates a Config from environment variables with defaults.
func Load() *Config {
	hostname, _ := os.Hostname()

	c := &Config{
		AgentDisplayName:           envStr("AGENT_DISPLAY_NAME", ""),
		Hostname:                   envStr("HOSTNAME", hostname),
		AgentID:                    envStr("AGENT_ID", ""),
		AgentPort:                  envInt("AGENT_PORT", 8090),
		AgentHost:                  envStr("AGENT_HOST", "0.0.0.0"),
		AgentIP:                    envStr("AGENT_IP_ADDRESS", ""),
		Environment:                envStr("ENVIRONMENT", "development"),
		CompressionType:            envStr("COMPRESSION_TYPE", "lz4"),
		CompressionLevel:           envStr("COMPRESSION_LEVEL", "default"),
		OrchestratorURL:            envStr("ORCHESTRATOR_URL", "http://localhost:8000"),
		AgentAPIKey:                envStr("AGENT_API_KEY", ""),
		OrchestratorAPIKey:         envStr("ORCHESTRATOR_API_KEY", ""),
		RegistrationKey:            envStr("REGISTRATION_KEY", ""),
		KeyFilePath:                envStr("KEY_FILE_PATH", "/var/lib/vnbui/agent.key"),
		KeystoreIdentity:           envStr("KEYSTORE_IDENTITY", ""),
		LibvirtURI:                 envStr("LIBVIRT_URI", "qemu:///system"),
		MockLibvirt:                envBool("MOCK_LIBVIRT", false),
		BackupStoragePath:          envStr("BACKUP_STORAGE_PATH", "/var/lib/vnbui/backups"),
		NativeStagingRoot:          envStr("NATIVE_STAGING_ROOT", ""),
		NativeStagingSocket:        envStr("NATIVE_STAGING_SOCKET", ""),
		NativeRestoreRoot:          envStr("NATIVE_RESTORE_ROOT", "/var/lib/vnbui/restores"),
		NativeRestoreCAFile:        envStr("NATIVE_RESTORE_CA_FILE", ""),
		VirtnbdbackupPath:          envStr("VIRTNBDBACKUP_PATH", "/usr/bin/virtnbdbackup"),
		VirtnbdrestorePath:         envStr("VIRTNBDRESTORE_PATH", "/usr/bin/virtnbdrestore"),
		VirtnbdScratchDir:          envStr("VIRTNBD_SCRATCH_DIR", "/var/tmp"),
		MaxConcurrentBackups:       envInt("MAX_CONCURRENT_BACKUPS", 2),
		VerificationTimeoutSeconds: envInt("VERIFICATION_TIMEOUT_SECONDS", 7200),
		MockVirtnbdbackup:          envBool("MOCK_VIRTNBDBACKUP", false),
		OperationBudget:            loadOperationBudget(),
		SourceHealthProbesJSON:     envStr("KUBEVIRT_SOURCE_HEALTH_PROBES", ""),
		EnableAPIKeyValidation:     envBool("ENABLE_API_KEY_VALIDATION", true),
		RequireTLS:                 envBool("REQUIRE_TLS", false),
		OrchestratorVerifySSL:      envBool("ORCHESTRATOR_VERIFY_SSL", true),
		CallbackClientCertFile:     envStr("CALLBACK_CLIENT_CERT_FILE", ""),
		CallbackClientKeyFile:      envStr("CALLBACK_CLIENT_KEY_FILE", ""),
		TLSEnabled:                 envBool("TLS_ENABLED", false),
		TLSCertFile:                envStr("TLS_CERT_FILE", ""),
		TLSKeyFile:                 envStr("TLS_KEY_FILE", ""),
		TLSCAFile:                  envStr("TLS_CA_FILE", ""),
		TLSClientCAFile:            envStr("TLS_CLIENT_CA_FILE", ""),
		TLSVerifyClient:            envBool("TLS_VERIFY_CLIENT", false),
		HeartbeatInterval:          envInt("HEARTBEAT_INTERVAL", 30),
		HeartbeatEnabled:           envBool("HEARTBEAT_ENABLED", true),
		LogLevel:                   envStr("LOG_LEVEL", "INFO"),
		Provider:                   envStr("PROVIDER", "libvirt"),
		KubeconfigPath:             envStr("KUBECONFIG", ""),
		KubeNamespace:              envStr("KUBE_NAMESPACE", ""),
		KubevirtResourcePrefix:     envStr("KUBEVIRT_RESOURCE_PREFIX", ""),
		KubevirtBackupScratchPVC:   envStr("KUBEVIRT_BACKUP_SCRATCH_PVC", ""),
		KubevirtRestoreImage:       envStr("KUBEVIRT_RESTORE_IMAGE", ""),
		KubevirtRestoreCAFile:      envStr("KUBEVIRT_RESTORE_CA_FILE", ""),

		KubeAPIQPS:                        envStrictInt("KUBE_API_QPS", 50),
		KubeAPIBurst:                      envStrictInt("KUBE_API_BURST", 100),
		KubevirtTransactionTimeoutSeconds: envStrictInt("KUBEVIRT_TRANSACTION_TIMEOUT_SECONDS", 0),
		KubevirtNativeTTLSeconds:          envStrictInt("KUBEVIRT_NATIVE_BACKUP_TTL_SECONDS", DefaultNativeBackupTTLSeconds),
	}

	if namespaces := envStr("KUBEVIRT_RESTORE_NAMESPACES", ""); namespaces != "" {
		c.KubevirtRestoreNamespaces = strings.Split(namespaces, ",")
	}

	if path := envStr("KUBEVIRT_SCOPE_POLICY_FILE", ""); path != "" {
		c.NamespacePolicyError = c.LoadNamespacePolicy(path)
	}

	// Parse allowed IPs
	if ips := envStr("ALLOWED_ORCHESTRATOR_IPS", ""); ips != "" {
		c.AllowedOrchestratorIPs = strings.Split(ips, ",")
	}

	return c
}

// ListenAddr returns the address the HTTP server should listen on.
func (c *Config) ListenAddr() string {
	return fmt.Sprintf("%s:%d", c.AgentHost, c.AgentPort)
}

// ValidateProduction checks for required production config.
func (c *Config) ValidateProduction() error {
	if !c.SafetyPolicy().Valid() {
		return fmt.Errorf("invalid operation budget policy")
	}
	if c.Provider == "kubevirt" {
		if _, err := ParseSourceHealthProbes(c.SourceHealthProbesJSON); err != nil {
			return err
		}
		if c.KubeAPIQPS < 1 || c.KubeAPIQPS > 200 || c.KubeAPIBurst < c.KubeAPIQPS || c.KubeAPIBurst > 400 {
			return fmt.Errorf("KUBE_API_QPS must be 1..200 and KUBE_API_BURST must be between QPS and 400")
		}
		if err := c.ValidateNativeLifetime(); err != nil {
			return err
		}
	}
	if _, err := NormalizeKubevirtResourcePrefix(c.KubevirtResourcePrefix); err != nil {
		return err
	}
	if c.NamespacePolicyError != nil {
		return fmt.Errorf("namespace policy: %w", c.NamespacePolicyError)
	}
	if c.Provider == "kubevirt" && c.NamespaceScope == nil && c.KubeNamespace == "" {
		return fmt.Errorf("KubeVirt requires explicit source namespace policy")
	}
	if c.Environment != "production" {
		return nil
	}
	if c.MockLibvirt || c.MockVirtnbdbackup {
		return fmt.Errorf("mock mode not allowed in production")
	}
	if c.RequireTLS && !strings.HasPrefix(c.OrchestratorURL, "https://") {
		return fmt.Errorf("HTTPS required for production orchestrator connection")
	}
	return nil
}

// LocalOverrides returns the set of UI-configurable settings overridden by env vars.
func (c *Config) LocalOverrides() map[string]bool {
	overrides := make(map[string]bool)
	for name := range UIConfigurableSettings {
		if _, ok := os.LookupEnv(strings.ToUpper(name)); ok {
			overrides[name] = true
		}
	}
	return overrides
}

// ApplyRemoteConfig applies config from heartbeat response, respecting local overrides.
func (c *Config) ApplyRemoteConfig(remote map[string]interface{}) (applied, skipped []string) {
	c.runtimeMu.Lock()
	defer c.runtimeMu.Unlock()
	overrides := c.LocalOverrides()
	if raw, ok := remote["selected_source_namespaces"]; ok {
		revision, _ := remote["scope_revision"].(string)
		if c.ApplySourceSelection(raw, revision) {
			applied = append(applied, "selected_source_namespaces", "scope_revision")
		} else {
			skipped = append(skipped, "selected_source_namespaces", "scope_revision")
		}
	}

	for key, val := range remote {
		if key == "selected_source_namespaces" || key == "scope_revision" {
			continue
		}
		if !c.SettingSupported(key) || !UIConfigurableSettings[key] {
			skipped = append(skipped, key)
			continue
		}
		if overrides[key] {
			skipped = append(skipped, key)
			continue
		}

		switch key {
		case "max_concurrent_backups":
			if v, ok := toInt(val); ok {
				c.MaxConcurrentBackups = v
				applied = append(applied, key)
			}
		case "backup_storage_path":
			if v, ok := val.(string); ok {
				c.BackupStoragePath = v
				applied = append(applied, key)
			}
		case "virtnbdbackup_path":
			if v, ok := val.(string); ok {
				c.VirtnbdbackupPath = v
				applied = append(applied, key)
			}
		case "virtnbdrestore_path":
			if v, ok := val.(string); ok {
				c.VirtnbdrestorePath = v
				applied = append(applied, key)
			}
		case "virtnbd_scratch_dir":
			if v, ok := val.(string); ok {
				c.VirtnbdScratchDir = v
				applied = append(applied, key)
			}
		case "libvirt_uri":
			if v, ok := val.(string); ok {
				c.LibvirtURI = v
				applied = append(applied, key)
			}
		case "heartbeat_interval":
			if v, ok := toInt(val); ok {
				if v < 5 || v > 3600 {
					skipped = append(skipped, key)
					continue
				}
				c.HeartbeatInterval = v
				applied = append(applied, key)
			}
		case "log_level":
			if v, ok := val.(string); ok {
				level := slog.LevelInfo
				if strings.EqualFold(v, "WARNING") {
					v = "WARN"
				}
				if err := level.UnmarshalText([]byte(strings.ToUpper(v))); err != nil {
					skipped = append(skipped, key)
					continue
				}
				c.LogLevel = strings.ToUpper(v)
				if c.LogLevelControl != nil {
					c.LogLevelControl.Set(level)
				}
				applied = append(applied, key)
			}
		case "compression_type":
			if v, ok := val.(string); ok {
				c.CompressionType = v
				applied = append(applied, key)
			}
		case "compression_level":
			if v, ok := val.(string); ok {
				c.CompressionLevel = v
				applied = append(applied, key)
			}
		}
	}
	return
}

func envStr(key, def string) string {
	if v, ok := os.LookupEnv(key); ok {
		return v
	}
	return def
}

func envInt(key string, def int) int {
	if v, ok := os.LookupEnv(key); ok {
		if i, err := strconv.Atoi(v); err == nil {
			return i
		}
	}
	return def
}

// Invalid startup budgets must be rejected, not silently select a new limit.
func envStrictInt(key string, def int) int {
	if value, ok := os.LookupEnv(key); ok {
		parsed, err := strconv.Atoi(value)
		if err != nil {
			return -1
		}
		return parsed
	}
	return def
}

func envBool(key string, def bool) bool {
	if v, ok := os.LookupEnv(key); ok {
		v = strings.ToLower(v)
		return v == "true" || v == "1" || v == "yes"
	}
	return def
}

func toInt(v interface{}) (int, bool) {
	switch val := v.(type) {
	case float64:
		return int(val), true
	case int:
		return val, true
	case string:
		i, err := strconv.Atoi(val)
		return i, err == nil
	}
	return 0, false
}

// StorageMeasurementPath is the durable control journal for KubeVirt, whose
// payload scratch lives in source-namespace worker PVCs rather than this pod.
func (c *Config) StorageMeasurementPath() string {
	if c.Provider == "kubevirt" {
		return filepath.Dir(c.KeyFilePath)
	}
	if c.NativeStagingRoot != "" {
		return c.NativeStagingRoot
	}
	return c.BackupStoragePath
}
func (c *Config) StorageRole() string {
	if c.Provider == "kubevirt" {
		return "journal"
	}
	return "native_capture"
}

// Startup-only executor paths cannot be safely reconfigured through heartbeat.
func (c *Config) SettingSupported(key string) bool {
	switch key {
	case "libvirt_uri", "virtnbdbackup_path", "virtnbdrestore_path", "virtnbd_scratch_dir", "backup_storage_path", "max_concurrent_backups", "compression_type", "compression_level":
		return false
	}
	if c.Provider == "kubevirt" && (key == "compression_type" || key == "compression_level") {
		return false
	}
	return true
}

// HeartbeatIntervalSeconds synchronizes the loop with concurrent immediate heartbeats.
func (c *Config) HeartbeatIntervalSeconds() int {
	c.runtimeMu.Lock()
	defer c.runtimeMu.Unlock()
	return c.HeartbeatInterval
}
