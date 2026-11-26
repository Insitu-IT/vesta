package mock

import (
	"fmt"
	"sync"

	"vnbui/agent/internal/models"
	"vnbui/agent/internal/provider"
)

// Provider is a mock VM provider for development and testing.
type Provider struct {
	mu        sync.RWMutex
	connected bool
	vms       []models.VMInfo
	handler   provider.EventHandler
}

// New creates a MockProvider with sample VMs.
func New() *Provider {
	return &Provider{
		vms: []models.VMInfo{
			{
				Name:      "mock-vm-01",
				UUID:      "11111111-1111-1111-1111-111111111111",
				State:     "running",
				MemoryKB:  2097152, // 2GB
				VCPUCount: 2,
				Disks: []map[string]interface{}{
					{"target": "vda", "source": "/var/lib/libvirt/images/mock-vm-01.qcow2", "size_bytes": 10737418240, "format": "qcow2"},
				},
				Metadata: map[string]interface{}{},
			},
			{
				Name:      "mock-vm-02",
				UUID:      "22222222-2222-2222-2222-222222222222",
				State:     "running",
				MemoryKB:  4194304, // 4GB
				VCPUCount: 4,
				Disks: []map[string]interface{}{
					{"target": "vda", "source": "/var/lib/libvirt/images/mock-vm-02.qcow2", "size_bytes": 21474836480, "format": "qcow2"},
					{"target": "vdb", "source": "/var/lib/libvirt/images/mock-vm-02-data.qcow2", "size_bytes": 53687091200, "format": "qcow2"},
				},
				Metadata: map[string]interface{}{},
			},
			{
				Name:      "mock-vm-03",
				UUID:      "33333333-3333-3333-3333-333333333333",
				State:     "shutoff",
				MemoryKB:  1048576, // 1GB
				VCPUCount: 1,
				Disks: []map[string]interface{}{
					{"target": "vda", "source": "/var/lib/libvirt/images/mock-vm-03.qcow2", "size_bytes": 5368709120, "format": "qcow2"},
				},
				Metadata: map[string]interface{}{},
			},
			{
				Name:      "mock-vm-04-raw",
				UUID:      "44444444-4444-4444-4444-444444444444",
				State:     "running",
				MemoryKB:  2097152,
				VCPUCount: 2,
				Disks: []map[string]interface{}{
					{"target": "sda", "source": "/dev/vg0/mock-vm-04", "size_bytes": 21474836480, "format": "raw"},
				},
				Metadata: map[string]interface{}{},
			},
		},
	}
}

func (p *Provider) Connect() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.connected = true
	return nil
}

func (p *Provider) Disconnect() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.connected = false
}

func (p *Provider) IsConnected() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.connected
}

func (p *Provider) ListVMs() ([]models.VMInfo, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if !p.connected {
		return nil, fmt.Errorf("not connected")
	}
	result := make([]models.VMInfo, len(p.vms))
	copy(result, p.vms)
	return result, nil
}

func (p *Provider) GetVM(name string) (*models.VMInfo, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if !p.connected {
		return nil, fmt.Errorf("not connected")
	}
	for _, vm := range p.vms {
		if vm.Name == name {
			v := vm
			return &v, nil
		}
	}
	return nil, fmt.Errorf("VM %q not found", name)
}

func (p *Provider) GetBlockJobProgress(vmName string) (*provider.BlockJobProgress, error) {
	// Mock: no active block jobs
	return nil, nil
}

func (p *Provider) ListCheckpoints(vmName string) ([]string, error) {
	// Mock: no checkpoints
	return nil, nil
}

func (p *Provider) SubscribeEvents(handler provider.EventHandler) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.handler = handler
	return nil
}

func (p *Provider) UnsubscribeEvents() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.handler = nil
}

func (p *Provider) Capabilities() provider.ProviderCapabilities {
	return provider.ProviderCapabilities{
		SupportsIncremental:   true,
		SupportsBlockJobPoll:  true,
		SupportsCheckpoints:   true,
		BackupMethod:          "virtnbdbackup",
		SupportsStreamThrough: false,
		SupportsLocalOutput:   true,
	}
}

// EmitEvent sends a mock event (for testing).
func (p *Provider) EmitEvent(evt provider.VMEvent) {
	p.mu.RLock()
	h := p.handler
	p.mu.RUnlock()
	if h != nil {
		h(evt)
	}
}
