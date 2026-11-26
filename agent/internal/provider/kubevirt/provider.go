//go:build kubevirt

package kubevirt

import (
	"context"
	"fmt"
	"log/slog"
	"math"
	"sync"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"vnbui/agent/internal/models"
	"vnbui/agent/internal/provider"
)

// apiTimeout is the default timeout for k8s API calls.
const apiTimeout = 30 * time.Second

// Compile-time interface check.
var _ provider.VMProvider = (*Provider)(nil)

// Provider implements provider.VMProvider for KubeVirt clusters.
type Provider struct {
	kubeconfig          string
	namespace           string // legacy singleton scope
	scope               func() []string
	installedNamespaces []string

	k8s              kubernetes.Interface
	dynamic          dynamic.Interface
	config           *rest.Config
	apiQPS, apiBurst int
	trackerPrefix    string

	connected bool
	handler   provider.EventHandler
	stopCh    chan struct{}
	mu        sync.RWMutex
}

// New creates a KubeVirt provider.
func New(kubeconfig, namespace string) *Provider {
	return &Provider{
		kubeconfig: kubeconfig,
		namespace:  namespace,
		apiQPS:     50, apiBurst: 100,
	}
}

func (p *Provider) Connect() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	var cfg *rest.Config
	var err error

	if p.kubeconfig != "" {
		cfg, err = clientcmd.BuildConfigFromFlags("", p.kubeconfig)
	} else {
		cfg, err = rest.InClusterConfig()
	}
	if err != nil {
		return fmt.Errorf("build k8s config: %w", err)
	}
	if err := configureAPIBudget(cfg, p.apiQPS, p.apiBurst); err != nil {
		return err
	}

	k8sClient, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return fmt.Errorf("create k8s client: %w", err)
	}

	dynClient, err := dynamic.NewForConfig(cfg)
	if err != nil {
		return fmt.Errorf("create dynamic client: %w", err)
	}

	info, err := k8sClient.Discovery().ServerVersion()
	if err != nil {
		return fmt.Errorf("k8s server unreachable: %w", err)
	}

	p.k8s = k8sClient
	p.dynamic = dynClient
	p.config = cfg
	p.connected = true

	slog.Info("kubevirt provider connected",
		"k8s_version", info.GitVersion,
		"namespace", p.effectiveNamespace(),
		"api_qps", p.apiQPS, "api_burst", p.apiBurst,
	)
	return nil
}

func (p *Provider) Disconnect() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.stopCh != nil {
		close(p.stopCh)
		p.stopCh = nil
	}
	p.handler = nil
	p.connected = false
	slog.Info("kubevirt provider disconnected")
}

func (p *Provider) IsConnected() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if !p.connected {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := p.k8s.Discovery().RESTClient().Get().AbsPath("/healthz").DoRaw(ctx)
	return err == nil
}

func (p *Provider) ListVMs() ([]models.VMInfo, error) {
	vms, _, err := p.ListVMsWithNamespaces()
	return vms, err
}

// ListVMsWithNamespaces binds completeness to the exact successful list scope.
func (p *Provider) ListVMsWithNamespaces() ([]models.VMInfo, []string, error) {
	if p.scope == nil && p.namespace == "" {
		return nil, nil, fmt.Errorf("explicit source namespace scope is required")
	}
	namespaces := []string{p.effectiveNamespace()}
	if p.scope != nil {
		namespaces = p.scope()
	}
	vms, err := p.listVMs(namespaces)
	if err != nil {
		return nil, nil, err
	}
	return vms, append([]string{}, namespaces...), nil
}

func (p *Provider) listVMs(namespaces []string) ([]models.VMInfo, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if !p.connected {
		return nil, fmt.Errorf("not connected")
	}

	ctx, cancel := context.WithTimeout(context.Background(), apiTimeout)
	defer cancel()

	if len(namespaces) == 0 {
		return []models.VMInfo{}, nil
	}
	result := &unstructured.UnstructuredList{}
	instances := &unstructured.UnstructuredList{}
	for _, ns := range namespaces {
		listed, err := listInventory(ctx, p.dynamic.Resource(VMResource).Namespace(ns))
		if err != nil {
			return nil, fmt.Errorf("list VMs in %s: %w", ns, err)
		}
		result.Items = append(result.Items, listed.Items...)
		listed, err = listInventory(ctx, p.dynamic.Resource(VMIResource).Namespace(ns))
		if err != nil {
			return nil, fmt.Errorf("list VMIs in %s: %w", ns, err)
		}
		instances.Items = append(instances.Items, listed.Items...)
	}
	vms := []models.VMInfo{}
	for _, item := range result.Items {
		instance, ambiguous := inventoryInstance(&item, instances.Items)
		vm, err := vmToInfo(&item, instance)
		if err != nil {
			return nil, err
		}
		if err := p.attachPersistentSources(ctx, &item, instance, vm); err != nil {
			return nil, err
		}
		if ambiguous {
			vm.State = "unknown"
			delete(vm.Metadata, "changed_block_tracking")
			for _, disk := range vm.Disks {
				if disk["backup_eligible"] == true {
					disk["backup_eligible"] = false
					disk["source_error"] = "The current VMI identity is unresolved"
				}
			}
		}
		vms = append(vms, *vm)
	}
	p.describeBackupAPIs(ctx, vms)
	return vms, nil
}

// SetTrackerPrefix uses the same installation setting as the native executor.
func (p *Provider) SetTrackerPrefix(prefix string) {
	p.trackerPrefix = prefix
}

func (p *Provider) GetVM(name string) (*models.VMInfo, error) {
	vms, err := p.ListVMs()
	if err != nil {
		return nil, err
	}
	var found *models.VMInfo
	for i := range vms {
		if vms[i].Name == name {
			if found != nil {
				return nil, fmt.Errorf("VM name %s is ambiguous; use namespace and UID", name)
			}
			found = &vms[i]
		}
	}
	if found == nil {
		return nil, fmt.Errorf("VM %s not found", name)
	}
	return found, nil
}

func (p *Provider) GetBlockJobProgress(vmName string) (*provider.BlockJobProgress, error) {
	return nil, nil
}

func (p *Provider) ListCheckpoints(vmName string) ([]string, error) {
	return nil, nil
}

func (p *Provider) SubscribeEvents(handler provider.EventHandler) error {
	if p.scope == nil && p.namespace == "" {
		return fmt.Errorf("explicit source namespace scope is required")
	}
	p.mu.Lock()
	p.handler = handler
	p.stopCh = make(chan struct{})
	p.mu.Unlock()

	namespaces := p.installedNamespaces
	if len(namespaces) == 0 {
		namespaces = []string{p.namespace}
	}
	for _, ns := range namespaces {
		go p.watchResources(p.stopCh, VMIResource, ns)
		go p.watchResources(p.stopCh, VMResource, ns)
	}
	return nil
}

func (p *Provider) UnsubscribeEvents() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.handler = nil
	if p.stopCh != nil {
		close(p.stopCh)
		p.stopCh = nil
	}
}

func (p *Provider) Capabilities() provider.ProviderCapabilities {
	return provider.ProviderCapabilities{
		SupportsIncremental:   true,
		SupportsBlockJobPoll:  false,
		SupportsCheckpoints:   false,
		BackupMethod:          "kubevirt_pull_transaction",
		SupportsStreamThrough: true,
		SupportsLocalOutput:   false,
	}
}

// DynamicClient returns the dynamic k8s client for use by executors.
// Returns interface{} to avoid requiring k8s imports in non-tagged code.
func (p *Provider) DynamicClient() interface{} {
	return p.dynamic
}

// CoreClient shares the provider's QPS/burst limiter with dynamic calls.
func (p *Provider) CoreClient() interface{} { return p.k8s }

func (p *Provider) effectiveNamespace() string {
	return p.namespace
}

// watchResources watches VM or VMI events with exponential backoff on errors.
func (p *Provider) watchResources(stopCh <-chan struct{}, resource schema.GroupVersionResource, ns string) {
	backoff := 1.0
	maxBackoff := 60.0

	for {
		select {
		case <-stopCh:
			return
		default:
		}

		ctx, cancel := context.WithCancel(context.Background())
		watcher, err := p.dynamic.Resource(resource).Namespace(ns).Watch(ctx, metav1.ListOptions{})
		if err != nil {
			cancel()
			wait := time.Duration(backoff) * time.Second
			slog.Warn("inventory watch failed, retrying", "resource", resource.Resource, "error", err, "backoff_s", backoff)
			backoff = math.Min(backoff*2, maxBackoff)
			select {
			case <-stopCh:
				return
			case <-time.After(wait):
				continue
			}
		}

		backoff = 1.0 // reset on successful watch
		// Re-list after attachment, including reconnects, to cover changes made
		// between the previous snapshot and this watch becoming active.
		p.mu.RLock()
		handler := p.handler
		p.mu.RUnlock()
		if handler != nil {
			handler(provider.VMEvent{Type: provider.EventInventoryChanged})
		}
		p.handleWatchEvents(watcher, stopCh)
		watcher.Stop()
		cancel()
	}
}

func (p *Provider) handleWatchEvents(watcher watch.Interface, stopCh <-chan struct{}) {
	for {
		select {
		case <-stopCh:
			return
		case event, ok := <-watcher.ResultChan():
			if !ok {
				return
			}

			p.mu.RLock()
			handler := p.handler
			p.mu.RUnlock()
			if handler == nil {
				continue
			}

			// Safe type assertion — watch can return error objects
			obj, ok := event.Object.(*unstructured.Unstructured)
			if !ok {
				slog.Debug("watch event with non-unstructured object, skipping")
				continue
			}

			vmName := obj.GetName()
			phase, _, _ := unstructured.NestedString(obj.Object, "status", "phase")

			var evtType provider.EventType
			switch event.Type {
			case watch.Added, watch.Modified:
				evtStr := phaseToEventType(phase)
				if evtStr == "" {
					evtStr = string(provider.EventInventoryChanged)
				}
				if obj.GetKind() == "VirtualMachine" {
					evtStr = string(provider.EventInventoryChanged)
				}
				evtType = provider.EventType(evtStr)
			case watch.Deleted:
				evtType = provider.EventInventoryChanged
			default:
				continue
			}

			handler(provider.VMEvent{
				Type:   evtType,
				VMName: vmName,
				Detail: fmt.Sprintf("phase=%s", phase),
			})
		}
	}
}

// unstructuredToVMInfo converts a KubeVirt VMI unstructured object to models.VMInfo.
func unstructuredToVMInfo(obj *unstructured.Unstructured) (*models.VMInfo, error) {
	name := obj.GetName()
	uid := string(obj.GetUID())

	phase, _, _ := unstructured.NestedString(obj.Object, "status", "phase")
	state := mapPhaseToState(phase)

	memoryKB, memorySource := observedMemory(obj, "vmi", false)

	var vcpus int
	cores, found, _ := unstructured.NestedInt64(obj.Object, "spec", "domain", "cpu", "cores")
	if found {
		vcpus = int(cores)
	}
	if vcpus == 0 {
		vcpus = 1
	}

	disks := extractDisks(obj)

	meta := map[string]interface{}{
		"namespace": obj.GetNamespace(),
		"provider":  "kubevirt",
		"memory":    map[string]interface{}{"source": memorySource, "known": memoryKB > 0},
	}
	if nodeName, found, _ := unstructured.NestedString(obj.Object, "status", "nodeName"); found {
		meta["node"] = nodeName
	}

	return &models.VMInfo{
		Name:      name,
		UUID:      uid,
		State:     state,
		MemoryKB:  memoryKB,
		VCPUCount: vcpus,
		Disks:     disks,
		Metadata:  meta,
	}, nil
}

// extractDisks pulls disk info from VMI spec.
func extractDisks(obj *unstructured.Unstructured) []map[string]interface{} {
	rawDisks, found, _ := unstructured.NestedSlice(obj.Object, "spec", "domain", "devices", "disks")
	if !found {
		return nil
	}

	var disks []map[string]interface{}
	for _, d := range rawDisks {
		disk, ok := d.(map[string]interface{})
		if !ok {
			continue
		}
		dName, _, _ := unstructured.NestedString(disk, "name")
		info := map[string]interface{}{
			"target": dName,
		}
		if _, ok := disk["disk"]; ok {
			info["device"] = "disk"
			bus, _, _ := unstructured.NestedString(disk, "disk", "bus")
			var serial interface{}
			if value, found, _ := unstructured.NestedString(disk, "serial"); found {
				serial = value
			}
			info["mapping"] = map[string]interface{}{
				"disk_name": dName, "device": "disk", "bus": bus, "serial": serial,
			}
		} else if _, ok := disk["cdrom"]; ok {
			info["device"] = "cdrom"
		}
		disks = append(disks, info)
	}
	return disks
}

// SetNamespaceScope uses a live selection getter; watches cover the installed ceiling.
func (p *Provider) SetNamespaceScope(selected func() []string, installed []string) {
	p.scope = selected
	p.installedNamespaces = append([]string(nil), installed...)
}
