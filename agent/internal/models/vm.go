package models

// VMInfo represents virtual machine information from the VM provider.
// JSON tags must match Python VMInfo field names exactly.
type VMInfo struct {
	Provider  string                   `json:"provider,omitempty"`
	Namespace string                   `json:"namespace,omitempty"`
	VMUID     string                   `json:"vm_uid,omitempty"`
	VMIUID    string                   `json:"vmi_uid,omitempty"`
	Name      string                   `json:"name"`
	UUID      string                   `json:"uuid"`
	State     string                   `json:"state"`
	MemoryKB  int64                    `json:"memory_kb"`
	VCPUCount int                      `json:"vcpu_count"`
	Disks     []map[string]interface{} `json:"disks"`
	Metadata  map[string]interface{}   `json:"metadata"`
}
