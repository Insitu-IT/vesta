package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
)

// Registry is the custom Prometheus registry (avoids default Go runtime metrics).
var Registry = prometheus.NewRegistry()

// System metrics
var (
	SystemCPUPercent = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "vnbui_agent_system_cpu_percent",
		Help: "Current CPU usage percentage",
	})
	SystemMemoryPercent = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "vnbui_agent_system_memory_percent",
		Help: "Current memory usage percentage",
	})
	SystemDiskPercent = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "vnbui_agent_system_disk_percent",
		Help: "Disk usage percentage",
	}, []string{"path"})
	SystemDiskBytes = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "vnbui_agent_system_disk_bytes",
		Help: "Disk bytes",
	}, []string{"path", "type"})
	SystemNetworkBytesTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "vnbui_agent_system_network_bytes_total",
		Help: "Network bytes transferred",
	}, []string{"direction"})
	SystemUptimeSeconds = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "vnbui_agent_system_uptime_seconds",
		Help: "System uptime in seconds",
	})
)

// Operation metrics
var (
	BackupOperationsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "vnbui_agent_backup_operations_total",
		Help: "Total backup operations",
	}, []string{"status", "backup_type"})
	BackupDurationSeconds = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "vnbui_agent_backup_duration_seconds",
		Help:    "Backup duration in seconds",
		Buckets: []float64{60, 300, 600, 1800, 3600, 7200},
	}, []string{"backup_type"})
	BackupSizeBytes = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "vnbui_agent_backup_size_bytes",
		Help:    "Backup size in bytes",
		Buckets: []float64{1e6, 1e7, 1e8, 1e9, 1e10, 1e11},
	}, []string{"backup_type"})
	BackupPhaseDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "vnbui_agent_backup_phase_duration_seconds",
		Help:    "Duration of each backup phase",
		Buckets: []float64{10, 60, 300, 600, 1800, 3600, 7200},
	}, []string{"phase"})
	BackupTransferRateMbps = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "vnbui_agent_backup_transfer_rate_mbps",
		Help: "Current backup transfer rate in Mbps",
	})
	ActiveBackups = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "vnbui_agent_active_backups",
		Help: "Number of active backups",
	})
	ActiveRestores = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "vnbui_agent_active_restores",
		Help: "Number of active restores",
	})
	OperationErrorsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "vnbui_agent_operation_errors_total",
		Help: "Total operation errors",
	}, []string{"operation_type", "error_type"})
)

// Libvirt metrics
var (
	LibvirtConnectionStatus = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "vnbui_agent_libvirt_connection_status",
		Help: "Libvirt connection status (1=connected, 0=disconnected)",
	})
	ProviderConnectionStatus = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "vnbui_agent_provider_connection_status",
		Help: "VM provider connection status (1=connected, 0=disconnected)",
	})
	LibvirtVMsTotal = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "vnbui_agent_libvirt_vms_total",
		Help: "Total VMs by state",
	}, []string{"state"})
	LibvirtOperationsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "vnbui_agent_libvirt_operations_total",
		Help: "Total libvirt operations",
	}, []string{"operation", "status"})
)

// Queue metrics
var (
	QueueBackupsWaiting = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "vnbui_agent_queue_backups_waiting",
		Help: "Number of backups waiting in queue",
	})
	ConcurrentOperations = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "vnbui_agent_concurrent_operations",
		Help: "Current concurrent operations",
	}, []string{"type"})
	MaxConcurrentOperations = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "vnbui_agent_max_concurrent_operations",
		Help: "Maximum concurrent operations allowed",
	}, []string{"type"})
)

// Auth metrics
var (
	HTTPRequestsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "vnbui_agent_http_requests_total",
		Help: "Total HTTP requests",
	}, []string{"method", "endpoint", "status_code"})
	AuthAttemptsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "vnbui_agent_authentication_attempts_total",
		Help: "Total authentication attempts",
	}, []string{"auth_type", "result"})
)

// Info metrics
var (
	AgentInfo = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "vnbui_agent",
		Help: "Agent information",
	}, []string{"version", "hostname"})
	HeartbeatSuccessTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "vnbui_agent_heartbeat_success_total",
		Help: "Total successful heartbeats",
	})
	HeartbeatFailureTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "vnbui_agent_heartbeat_failure_total",
		Help: "Total failed heartbeats",
	}, []string{"reason"})
)

func init() {
	// System
	Registry.MustRegister(SystemCPUPercent, SystemMemoryPercent, SystemDiskPercent,
		SystemDiskBytes, SystemNetworkBytesTotal, SystemUptimeSeconds)

	// Operations
	Registry.MustRegister(BackupOperationsTotal, BackupDurationSeconds, BackupSizeBytes,
		BackupPhaseDuration, BackupTransferRateMbps, ActiveBackups, ActiveRestores, OperationErrorsTotal)

	// Libvirt
	Registry.MustRegister(LibvirtConnectionStatus, ProviderConnectionStatus, LibvirtVMsTotal, LibvirtOperationsTotal)

	// Queue
	Registry.MustRegister(QueueBackupsWaiting, ConcurrentOperations, MaxConcurrentOperations)

	// Auth
	Registry.MustRegister(HTTPRequestsTotal, AuthAttemptsTotal)

	// Info
	Registry.MustRegister(AgentInfo, HeartbeatSuccessTotal, HeartbeatFailureTotal)
}
