//go:build libvirt

package libvirt

import (
	"encoding/xml"
	"fmt"
	"log/slog"
	"runtime"
	"sync"

	lv "libvirt.org/go/libvirt"

	"vnbui/agent/internal/models"
	"vnbui/agent/internal/provider"
)

// Provider implements provider.VMProvider using libvirt.
type Provider struct {
	uri       string
	mu        sync.RWMutex
	conn      *lv.Connect
	handler   provider.EventHandler
	eventStop chan struct{}
}

var defaultEventLoopOnce sync.Once
var defaultEventLoopError error

func initializeDefaultEvents() error {
	defaultEventLoopOnce.Do(func() {
		defaultEventLoopError = lv.EventRegisterDefaultImpl()
	})
	return defaultEventLoopError
}

// Libvirt requires an event implementation before the connection is opened.
// Registering one later in SubscribeEvents can leave remote lifecycle delivery
// unavailable even though ordinary domain reads succeed.
func connectWithEvents(uri string, initialize func() error, open func(string) (*lv.Connect, error)) (*lv.Connect, error) {
	if err := initialize(); err != nil {
		return nil, fmt.Errorf("initialize libvirt events: %w", err)
	}
	return open(uri)
}

// New creates a libvirt provider.
func New(uri string) *Provider {
	return &Provider{
		uri: uri,
	}
}

func (p *Provider) Connect() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	conn, err := connectWithEvents(p.uri, initializeDefaultEvents, lv.NewConnect)
	if err != nil {
		return fmt.Errorf("libvirt connect %q: %w", p.uri, err)
	}
	p.conn = conn

	slog.Info("connected to libvirt", "uri", p.uri)
	return nil
}

func (p *Provider) Disconnect() {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.eventStop != nil {
		close(p.eventStop)
		p.eventStop = nil
	}

	if p.conn != nil {
		p.conn.Close()
		p.conn = nil
	}
}

func (p *Provider) IsConnected() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.conn == nil {
		return false
	}
	alive, err := p.conn.IsAlive()
	return err == nil && alive
}

func (p *Provider) ListVMs() ([]models.VMInfo, error) {
	p.mu.RLock()
	conn := p.conn
	p.mu.RUnlock()

	if conn == nil {
		return nil, fmt.Errorf("not connected")
	}

	domains, err := conn.ListAllDomains(lv.CONNECT_LIST_DOMAINS_ACTIVE | lv.CONNECT_LIST_DOMAINS_INACTIVE)
	if err != nil {
		return nil, fmt.Errorf("list domains: %w", err)
	}

	vms := make([]models.VMInfo, 0, len(domains))
	for _, dom := range domains {
		vm, err := domainToVMInfo(&dom)
		dom.Free()
		if err != nil {
			slog.Warn("skipping domain", "error", err)
			continue
		}
		vms = append(vms, *vm)
	}

	return vms, nil
}

func (p *Provider) GetVM(name string) (*models.VMInfo, error) {
	p.mu.RLock()
	conn := p.conn
	p.mu.RUnlock()

	if conn == nil {
		return nil, fmt.Errorf("not connected")
	}

	dom, err := conn.LookupDomainByName(name)
	if err != nil {
		return nil, fmt.Errorf("lookup %q: %w", name, err)
	}
	defer dom.Free()

	return domainToVMInfo(dom)
}

func (p *Provider) GetBlockJobProgress(vmName string) (*provider.BlockJobProgress, error) {
	p.mu.RLock()
	conn := p.conn
	p.mu.RUnlock()

	if conn == nil {
		return nil, fmt.Errorf("not connected")
	}

	dom, err := conn.LookupDomainByName(vmName)
	if err != nil {
		return nil, nil // VM not found = no block job
	}
	defer dom.Free()

	xmlDesc, err := dom.GetXMLDesc(0)
	if err != nil {
		return nil, nil
	}

	var domXML domainXML
	if err := xml.Unmarshal([]byte(xmlDesc), &domXML); err != nil {
		return nil, nil
	}

	for _, disk := range domXML.Devices.Disks {
		if disk.Device != "disk" {
			continue
		}
		info, err := dom.GetBlockJobInfo(disk.Target.Dev, 0)
		if err != nil || info == nil || info.Type == 0 {
			continue
		}

		progress := &provider.BlockJobProgress{
			Disk:       disk.Target.Dev,
			BytesDone:  int64(info.Cur),
			BytesTotal: int64(info.End),
		}
		if info.End > 0 {
			progress.Percent = int(100 * info.Cur / info.End)
		}
		return progress, nil
	}

	return nil, nil
}

func (p *Provider) ListCheckpoints(vmName string) ([]string, error) {
	p.mu.RLock()
	conn := p.conn
	p.mu.RUnlock()

	if conn == nil {
		return nil, fmt.Errorf("not connected")
	}

	dom, err := conn.LookupDomainByName(vmName)
	if err != nil {
		return nil, fmt.Errorf("lookup %q: %w", vmName, err)
	}
	defer dom.Free()

	cps, err := dom.ListAllCheckpoints(0)
	if err != nil {
		return nil, nil // checkpoints not supported
	}

	names := make([]string, 0, len(cps))
	for _, cp := range cps {
		name, err := cp.GetName()
		cp.Free()
		if err == nil {
			names = append(names, name)
		}
	}

	return names, nil
}

func (p *Provider) SubscribeEvents(handler provider.EventHandler) error {
	p.mu.Lock()
	p.handler = handler
	p.eventStop = make(chan struct{})
	conn := p.conn
	p.mu.Unlock()

	if conn == nil {
		return fmt.Errorf("not connected")
	}

	// Run libvirt event loop on a locked OS thread
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()

		// Register domain lifecycle event callback
		lifecycleCBID, err := conn.DomainEventLifecycleRegister(nil,
			func(c *lv.Connect, d *lv.Domain, event *lv.DomainEventLifecycle) {
				name, _ := d.GetName()
				if name == "" {
					return
				}
				evtType, detail, relevant := lifecycleEvent(event.Event)
				if !relevant {
					return
				}

				p.mu.RLock()
				h := p.handler
				p.mu.RUnlock()
				if h != nil {
					h(provider.VMEvent{Type: evtType, VMName: name, Detail: detail})
				}
			},
		)
		if err != nil {
			slog.Warn("failed to register lifecycle event callback", "error", err)
		} else {
			defer conn.DomainEventDeregister(lifecycleCBID)
		}

		// Register block job event callback
		blockJobCBID, err := conn.DomainEventBlockJobRegister(nil,
			func(c *lv.Connect, d *lv.Domain, event *lv.DomainEventBlockJob) {
				name, _ := d.GetName()
				if name == "" {
					return
				}
				detail := fmt.Sprintf("disk=%s status=%d", event.Disk, event.Status)

				p.mu.RLock()
				h := p.handler
				p.mu.RUnlock()
				if h != nil {
					h(provider.VMEvent{Type: provider.EventBlockJob, VMName: name, Detail: detail})
				}
			},
		)
		if err != nil {
			slog.Warn("failed to register block job event callback", "error", err)
		} else {
			defer conn.DomainEventDeregister(blockJobCBID)
		}

		for {
			select {
			case <-p.eventStop:
				return
			default:
				lv.EventRunDefaultImpl()
			}
		}
	}()

	return nil
}

func lifecycleEvent(event lv.DomainEventType) (provider.EventType, string, bool) {
	switch event {
	case lv.DOMAIN_EVENT_DEFINED:
		return provider.EventInventoryChanged, "defined", true
	case lv.DOMAIN_EVENT_UNDEFINED:
		return provider.EventInventoryChanged, "undefined", true
	case lv.DOMAIN_EVENT_STARTED:
		return provider.EventVMStarted, "started", true
	case lv.DOMAIN_EVENT_STOPPED:
		return provider.EventVMStopped, "stopped", true
	case lv.DOMAIN_EVENT_SHUTDOWN:
		return provider.EventVMStopped, "shutdown", true
	case lv.DOMAIN_EVENT_CRASHED:
		return provider.EventVMCrashed, "crashed", true
	case lv.DOMAIN_EVENT_SUSPENDED:
		return provider.EventVMPaused, "paused", true
	case lv.DOMAIN_EVENT_RESUMED:
		return provider.EventVMResumed, "resumed", true
	default:
		return "", "", false
	}
}

func (p *Provider) UnsubscribeEvents() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.eventStop != nil {
		close(p.eventStop)
		p.eventStop = nil
	}
	p.handler = nil
}

func (p *Provider) Capabilities() provider.ProviderCapabilities {
	return provider.ProviderCapabilities{
		SupportsIncremental:   true,
		SupportsBlockJobPoll:  true,
		SupportsCheckpoints:   true,
		BackupMethod:          "native_push",
		SupportsStreamThrough: false,
		SupportsLocalOutput:   true,
	}
}

// domainXML structs for parsing libvirt domain XML.
type domainXML struct {
	XMLName xml.Name         `xml:"domain"`
	Name    string           `xml:"name"`
	UUID    string           `xml:"uuid"`
	Memory  domainMemory     `xml:"memory"`
	VCPU    domainVCPU       `xml:"vcpu"`
	Devices domainDevicesXML `xml:"devices"`
}

type domainMemory struct {
	Value uint64 `xml:",chardata"`
	Unit  string `xml:"unit,attr"`
}

type domainVCPU struct {
	Value int `xml:",chardata"`
}

type domainDevicesXML struct {
	Disks []domainDiskXML `xml:"disk"`
}

type domainDiskXML struct {
	Type   string           `xml:"type,attr"`
	Device string           `xml:"device,attr"`
	Driver domainDiskDriver `xml:"driver"`
	Source domainDiskSrc    `xml:"source"`
	Target domainDiskTgt    `xml:"target"`
}

type domainDiskDriver struct {
	Name string `xml:"name,attr"` // "qemu"
	Type string `xml:"type,attr"` // "qcow2", "raw"
}

type domainDiskSrc struct {
	File string `xml:"file,attr"`
	Dev  string `xml:"dev,attr"`
}

type domainDiskTgt struct {
	Dev string `xml:"dev,attr"`
	Bus string `xml:"bus,attr"`
}

func domainToVMInfo(dom *lv.Domain) (*models.VMInfo, error) {
	name, err := dom.GetName()
	if err != nil {
		return nil, fmt.Errorf("get name: %w", err)
	}

	uuid, err := dom.GetUUIDString()
	if err != nil {
		return nil, fmt.Errorf("get uuid: %w", err)
	}

	state, _, err := dom.GetState()
	if err != nil {
		return nil, fmt.Errorf("get state: %w", err)
	}

	info, err := dom.GetInfo()
	if err != nil {
		return nil, fmt.Errorf("get info: %w", err)
	}

	// Parse XML for disks
	xmlDesc, err := dom.GetXMLDesc(0)
	if err != nil {
		return nil, fmt.Errorf("get xml: %w", err)
	}

	var domXMLData domainXML
	if err := xml.Unmarshal([]byte(xmlDesc), &domXMLData); err != nil {
		return nil, fmt.Errorf("parse xml: %w", err)
	}

	disks := make([]map[string]interface{}, 0)
	for _, d := range domXMLData.Devices.Disks {
		if d.Device != "disk" {
			continue
		}
		source := d.Source.File
		if source == "" {
			source = d.Source.Dev
		}
		disks = append(disks, map[string]interface{}{
			"target": d.Target.Dev,
			"source": source,
			"bus":    d.Target.Bus,
			"format": d.Driver.Type,
		})
	}

	// One read-only metadata RPC per disk, with a fixed per-domain lookup budget.
	attachDiskCapacities(disks, func(target string) (uint64, error) {
		block, err := dom.GetBlockInfo(target, 0)
		if err != nil {
			return 0, err
		}
		return block.Capacity, nil
	})

	return &models.VMInfo{
		Name:      name,
		UUID:      uuid,
		State:     stateString(state),
		MemoryKB:  int64(info.Memory),
		VCPUCount: int(info.NrVirtCpu),
		Disks:     disks,
		Metadata:  map[string]interface{}{"memory": map[string]interface{}{"source": "libvirt.domain.info.memory", "known": info.Memory > 0}},
	}, nil
}

func stateString(state lv.DomainState) string {
	switch state {
	case lv.DOMAIN_RUNNING:
		return "running"
	case lv.DOMAIN_PAUSED:
		return "paused"
	case lv.DOMAIN_SHUTDOWN, lv.DOMAIN_SHUTOFF:
		return "shutoff"
	case lv.DOMAIN_CRASHED:
		return "crashed"
	case lv.DOMAIN_PMSUSPENDED:
		return "pmsuspended"
	default:
		return "unknown"
	}
}
