package storageupload

import (
	"crypto/x509"
	"net"
	"net/url"
	"reflect"
	"strings"
	"vnbui/agent/internal/models"
)

// ExportState contains controller observations, not credentials or permission
// to delete/detach anything. Every resource is fenced by its original UID.
type ExportResource struct {
	Role     string `json:"role"`
	Name     string `json:"name"`
	UID      string `json:"uid"`
	OwnerUID string `json:"owner_uid"`
}
type ExportVolume struct {
	Name       string `json:"name"`
	VolumeID   string `json:"volume_id"`
	DiskTarget string `json:"disk_target"`
	DataURL    string `json:"data_url"`
	MapURL     string `json:"map_url"`
}
type ExportState struct {
	Resources     []ExportResource  `json:"resources"`
	Volumes       []ExportVolume    `json:"volumes"`
	NativeVolumes []ExportVolume    `json:"native_volumes,omitempty"`
	CA            string            `json:"ca"`
	Checkpoint    string            `json:"checkpoint"`
	ClusterIP     string            `json:"cluster_ip"`
	PodAddresses  []string          `json:"pod_addresses"`
	Selector      map[string]string `json:"selector"`
	Lifetime      *ExportLifetime   `json:"lifetime,omitempty"`
}
type ExportRange struct {
	Offset   uint64 `json:"offset"`
	Length   uint64 `json:"length"`
	ZeroFill bool   `json:"zero_fill"`
}
type ExportMap struct {
	VolumeID    string        `json:"volume_id"`
	VirtualSize uint64        `json:"virtual_size"`
	Ranges      []ExportRange `json:"ranges"`
}

// This aggregate map limit is tighter than the 16-MiB per-artifact bound:
// all selected maps must also fit the single durable 16-MiB journal. Refuse,
// never truncate, a fragmented source exceeding this supported profile.
const MaxExportRanges = 10000

func ExportURL(value string) bool {
	u, err := url.Parse(value)
	return err == nil && len(value) <= 4096 && u.Scheme == "https" && u.Hostname() != "" &&
		u.User == nil && u.RawQuery == "" && !u.ForceQuery && u.Fragment == "" && u.RawPath == "" &&
		u.Path != "" && !strings.ContainsAny(value, "\r\n\\")
}
func validExport(e *ExportState, s *State) bool {
	if s.Native == nil || (s.Native.Lifetime != nil && !e.Lifetime.Valid(s.Native.Lifetime)) || (s.Native.Lifetime == nil && e.Lifetime != nil) {
		return false
	}
	if s.Utility == nil || !validUtility(s.Utility, s) || len(e.Resources) < 4 || len(e.Resources) > 19 ||
		len(e.CA) == 0 || len(e.CA) > 65536 || !nativeID(e.Checkpoint) || net.ParseIP(e.ClusterIP) == nil ||
		len(e.PodAddresses) == 0 || len(e.PodAddresses) > 2 || len(e.Volumes) != len(s.Request.Plan.Source.Volumes) {
		return false
	}
	if !x509.NewCertPool().AppendCertsFromPEM([]byte(e.CA)) || strings.Contains(e.CA, "PRIVATE KEY") {
		return false
	}
	if len(e.Selector) == 0 || len(e.Selector) > 16 {
		return false
	}
	for k, v := range e.Selector {
		if k == "" || v == "" || len(k) > 253 || len(v) > 63 {
			return false
		}
	}
	seen := map[string]bool{}
	for i, r := range e.Resources {
		if !nativeID(r.Name) || !nativeID(r.UID) || seen[r.UID] {
			return false
		}
		seen[r.UID] = true
		role, owner := "endpointslice", e.Resources[1].UID
		switch i {
		case 0:
			role, owner = "export", s.Native.Objects[1].UID
		case 1:
			role, owner = "service", e.Resources[0].UID
		case 2:
			role, owner = "pod", e.Resources[0].UID
		}
		if r.Role != role || r.OwnerUID != owner {
			return false
		}
	}
	for i, ip := range e.PodAddresses {
		if net.ParseIP(ip) == nil || (i > 0 && e.PodAddresses[i-1] >= ip) {
			return false
		}
	}
	if !validExportVolumes(e.Volumes, s.Request.Plan.Source.Volumes) {
		return false
	}
	if s.Request.Plan.Source.Schema == 2 {
		if !validExportVolumes(e.NativeVolumes, s.Request.Plan.Source.NativeDisks()) {
			return false
		}
		native := map[string]ExportVolume{}
		for _, v := range e.NativeVolumes {
			native[v.Name] = v
		}
		for _, v := range e.Volumes {
			if native[v.Name] != v {
				return false
			}
		}
	} else if len(e.NativeVolumes) != 0 {
		return false
	}

	return true
}
func validExportMaps(maps []ExportMap, s *State) bool {
	if s.Export == nil || len(maps) != len(s.Request.Plan.Source.Volumes) {
		return false
	}
	total := 0
	for i, m := range maps {
		v := s.Request.Plan.Source.Volumes[i]
		if m.VolumeID != v.PVCUID || m.VirtualSize == 0 || m.VirtualSize > uint64(v.CapacityBytes) || m.Ranges == nil {
			return false
		}
		total += len(m.Ranges)
		if total > MaxExportRanges {
			return false
		}
		var end uint64
		for _, r := range m.Ranges {
			if r.Length == 0 || r.Offset < end || r.Offset > m.VirtualSize || r.Length > m.VirtualSize-r.Offset || (r.ZeroFill && s.Request.Plan.BackupType != "incremental") {
				return false
			}
			end = r.Offset + r.Length
		}
	}
	return true
}

func (j *Journal) BindExport(e ExportState) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.poisoned || j.state.Phase != "uploading" || !validExport(&e, &j.state) || (j.state.Export != nil && !reflect.DeepEqual(*j.state.Export, e)) {
		return ErrHeld
	}
	// Snapshot through the strict codec prevents caller slice mutation from
	// altering journal authority after validation.
	j.state.Export = &e
	if err := j.save(); err != nil {
		return err
	}
	var d diskJournal
	if decodeJournal(j.last, &d) != nil {
		j.poisoned = true
		return ErrHeld
	}
	j.state = d.State
	return nil
}
func (j *Journal) BindExportMaps(maps []ExportMap) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.poisoned || j.state.Phase != "uploading" || !validExportMaps(maps, &j.state) || (len(j.state.Maps) > 0 && !reflect.DeepEqual(j.state.Maps, maps)) {
		return ErrHeld
	}
	j.state.Maps = maps
	if err := j.save(); err != nil {
		return err
	}
	var d diskJournal
	if decodeJournal(j.last, &d) != nil {
		j.poisoned = true
		return ErrHeld
	}
	j.state = d.State
	return nil
}

func validExportVolumes(set []ExportVolume, planned []models.StorageVolume) bool {
	if len(set) != len(planned) {
		return false
	}
	urls := map[string]bool{}
	targets := map[string]bool{}
	for i, v := range set {
		p := planned[i]
		if v.Name != p.Name || v.VolumeID != p.PVCUID || !nativeID(v.DiskTarget) || targets[v.DiskTarget] {
			return false
		}
		targets[v.DiskTarget] = true
		for _, raw := range []string{v.DataURL, v.MapURL} {
			if !ExportURL(raw) || urls[raw] {
				return false
			}
			urls[raw] = true
		}
	}
	return true
}
