package models

// AgentHeartbeat is the heartbeat data sent from agent to backend.
// JSON tags must match Python AgentHeartbeat field names exactly.
type AgentHeartbeat struct {
	Scope                   map[string]interface{}   `json:"scope,omitempty"`
	Capabilities            map[string]interface{}   `json:"capabilities,omitempty"`
	Provider                string                   `json:"provider"`
	StorageRole             string                   `json:"storage_role"`
	StorageMeasurementError string                   `json:"storage_measurement_error,omitempty"`
	Status                  string                   `json:"status"`
	Version                 *string                  `json:"version"`
	IPAddress               *string                  `json:"ip_address"`
	Port                    *int                     `json:"port"`
	ActiveBackups           int                      `json:"active_backups"`
	ActiveRestores          int                      `json:"active_restores"`
	CPUUsagePercent         *float64                 `json:"cpu_usage_percent"`
	MemoryUsagePercent      *float64                 `json:"memory_usage_percent"`
	CPUCores                *int                     `json:"cpu_cores"`
	LoadAverage15m          *float64                 `json:"load_average_15m"`
	DiskUsagePercent        *float64                 `json:"disk_usage_percent"`
	BackupStoragePath       *string                  `json:"backup_storage_path"`
	BackupStorageFreeBytes  *int64                   `json:"backup_storage_free_bytes"`
	BackupStorageTotalBytes *int64                   `json:"backup_storage_total_bytes"`
	LibvirtAccessible       bool                     `json:"libvirt_accessible"`
	ProviderAccessible      bool                     `json:"provider_accessible"`
	LastError               *string                  `json:"last_error"`
	Events                  []map[string]interface{} `json:"events"`
}

// HeartbeatResponse is what the backend sends back to the agent.
type HeartbeatResponse struct {
	Status    string                 `json:"status"`
	Timestamp string                 `json:"timestamp"`
	AgentID   string                 `json:"agent_id"`
	Config    map[string]interface{} `json:"config"`
	S3Config  map[string]interface{} `json:"s3_config"`
}

// AgentRegistration is the registration data sent during agent registration.
// JSON tags must match Python AgentRegistration field names exactly.
type AgentRegistration struct {
	DisplayName  string                 `json:"display_name,omitempty"`
	Hostname     string                 `json:"hostname"`
	IPAddress    string                 `json:"ip_address"`
	Port         int                    `json:"port"`
	LibvirtURI   string                 `json:"libvirt_uri"`
	Version      string                 `json:"version"`
	Capabilities map[string]interface{} `json:"capabilities"`
}
