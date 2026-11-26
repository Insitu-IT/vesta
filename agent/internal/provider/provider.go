package provider

import "vnbui/agent/internal/models"

// BlockJobProgress represents progress from a libvirt block job.
type BlockJobProgress struct {
	Percent    int
	Disk       string
	BytesDone  int64
	BytesTotal int64
}

// EventType classifies VM lifecycle events.
type EventType string

const (
	EventVMStarted        EventType = "vm_started"
	EventInventoryChanged EventType = "vm_inventory_changed"
	EventVMStopped        EventType = "vm_stopped"
	EventVMCrashed        EventType = "vm_crashed"
	EventVMPaused         EventType = "vm_paused"
	EventVMResumed        EventType = "vm_resumed"
	EventBlockJob         EventType = "block_job_completed"
)

// VMEvent represents a VM lifecycle event.
type VMEvent struct {
	Type   EventType
	VMName string
	Detail string
}

// EventHandler is called when a VM event occurs.
type EventHandler func(VMEvent)

// ProviderCapabilities describes what a VMProvider supports.
type ProviderCapabilities struct {
	SupportsIncremental   bool   // libvirt checkpoints and KubeVirt BackupTracker full/incremental flow
	SupportsBlockJobPoll  bool   // libvirt: true, kubevirt: false
	SupportsCheckpoints   bool   // libvirt: true (virsh checkpoints), kubevirt: false
	BackupMethod          string // "native_push" | "kubevirt_pull_transaction"
	SupportsStreamThrough bool   // true = backup+upload is one operation (kubevirt)
	SupportsLocalOutput   bool   // true = backup produces local files (libvirt)
}

// VMProvider abstracts VM discovery and monitoring.
// Libvirt implements it today; KubeVirt can implement it later.
type VMProvider interface {
	// Connect establishes a connection to the hypervisor.
	Connect() error

	// Disconnect closes the connection.
	Disconnect()

	// IsConnected returns true if connected.
	IsConnected() bool

	// ListVMs returns all known VMs.
	ListVMs() ([]models.VMInfo, error)

	// GetVM returns a single VM by name.
	GetVM(name string) (*models.VMInfo, error)

	// GetBlockJobProgress returns block job progress for a VM, or nil if none.
	GetBlockJobProgress(vmName string) (*BlockJobProgress, error)

	// ListCheckpoints returns checkpoint names for a VM.
	ListCheckpoints(vmName string) ([]string, error)

	// SubscribeEvents registers an event handler.
	SubscribeEvents(handler EventHandler) error

	// UnsubscribeEvents removes the event handler.
	UnsubscribeEvents()

	// Capabilities returns what this provider supports.
	Capabilities() ProviderCapabilities
}
