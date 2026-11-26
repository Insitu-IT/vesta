//go:build kubevirt

package kubevirt

import (
	"context"
	"errors"
	"net"
	"reflect"
	"sort"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"vnbui/agent/internal/metrics"
	kvtypes "vnbui/agent/internal/provider/kubevirt"
	"vnbui/agent/internal/storageupload"
)

var exportPending = errors.New("native export not ready")
var exportServiceResource = schema.GroupVersionResource{Version: "v1", Resource: "services"}
var exportPodResource = schema.GroupVersionResource{Version: "v1", Resource: "pods"}
var exportSliceResource = schema.GroupVersionResource{Group: "discovery.k8s.io", Version: "v1", Resource: "endpointslices"}

func textAt(o *unstructured.Unstructured, fields ...string) string {
	s, _, _ := unstructured.NestedString(o.Object, fields...)
	return s
}
func controllerOwned(o *unstructured.Unstructured, ns, kind, name, uid string) bool {
	if o.GetNamespace() != ns || o.GetUID() == "" || o.GetDeletionTimestamp() != nil {
		return false
	}
	refs := o.GetOwnerReferences()
	if len(refs) != 1 {
		return false
	}
	r := refs[0]
	version := r.APIVersion == "backup.kubevirt.io/v1alpha1"
	if kind == "VirtualMachineExport" {
		version = r.APIVersion == "export.kubevirt.io/v1" || r.APIVersion == "export.kubevirt.io/v1beta1"
	}
	if kind == "Service" {
		version = r.APIVersion == "v1"
	}
	return version && r.Kind == kind && r.Name == name && string(r.UID) == uid && r.Controller != nil && *r.Controller
}

// Lists locate candidates only. Authority comes from exact UID/controller and
// status references. A bounded incomplete listing holds, never selects a subset.
func (e *Executor) exportCandidates(ctx context.Context, resource schema.GroupVersionResource, ns string) ([]unstructured.Unstructured, error) {
	var out []unstructured.Unstructured
	continuation := ""
	for page := 0; page < 8; page++ {
		list, err := e.dynamic.Resource(resource).Namespace(ns).List(ctx, metav1.ListOptions{Limit: 128, Continue: continuation})
		if err != nil {
			return nil, observationFault("export_candidates", err)
		}
		if len(list.Items) > 1024-len(out) {
			return nil, fault("export_admission", "export_discovery_object_limit", "refused")
		}
		out = append(out, list.Items...)
		next := list.GetContinue()
		if next == "" {
			return out, nil
		}
		if next == continuation {
			return nil, fault("export_admission", "export_discovery_page_limit", "refused")
		}
		continuation = next
	}
	return nil, fault("export_admission", "export_discovery_page_limit", "refused")
}
func exportRef(role string, o *unstructured.Unstructured, owner string) storageupload.ExportResource {
	return storageupload.ExportResource{Role: role, Name: o.GetName(), UID: string(o.GetUID()), OwnerUID: owner}
}

// inspectExport re-derives only bounded non-secret facts. It never reads the
// native token, source bodies or provider. ResourceVersion-only churn does not
// change this projection; replacement UIDs and changed routes/maps do.
func (e *Executor) inspectExport(ctx context.Context, s *storageupload.State) (*storageupload.ExportState, error) {
	expected := len(s.Request.Plan.Source.NativeDisks())
	var nativeCount, linkCount *int
	refused := func(reason string) *operationFault {
		f := fault("export_admission", reason, "refused")
		f.ExpectedNativeVolumes, f.ObservedNativeVolumes, f.ObservedExportLinks = &expected, nativeCount, linkCount
		return f
	}
	if s.Native == nil || len(s.Native.Objects) != 3 {
		return nil, refused("native_record_invalid")
	}
	r, n := &s.Request, s.Native
	ns := r.Plan.Source.Namespace
	b, err := e.dynamic.Resource(kvtypes.BackupResource).Namespace(ns).Get(ctx, n.Objects[1].Name, metav1.GetOptions{})
	if err != nil {
		return nil, observationFault("export_native", err)
	}
	if string(b.GetUID()) != n.Objects[1].UID || !validNativeObject(b, r, n, 1, true) || !beforeNativeTTL(b, n) {
		return nil, refused("native_identity_or_lifetime_changed")
	}
	volumes, _, volumeErr := unstructured.NestedSlice(b.Object, "status", "includedVolumes")
	if volumeErr != nil {
		return nil, refused("native_volume_schema_invalid")
	}
	count := len(volumes)
	nativeCount = &count
	conditions, _, conditionErr := unstructured.NestedSlice(b.Object, "status", "conditions")
	if conditionErr != nil || len(conditions) > 16 {
		return nil, refused("native_conditions_invalid")
	}
	ready := false
	seenConditions := map[string]bool{}
	for _, raw := range conditions {
		m, ok := raw.(map[string]interface{})
		if !ok {
			return nil, refused("native_condition_shape_invalid")
		}
		kind, _ := m["type"].(string)
		if kind == "" || seenConditions[kind] || (m["status"] != "True" && m["status"] != "False" && m["status"] != "Unknown") {
			return nil, refused("native_condition_duplicate_or_invalid")
		}
		seenConditions[kind] = true
		if kind == "ExportReady" && m["status"] == "True" {
			ready = true
		}
		if (kind == "Done" || kind == "Aborting" || kind == "Deleting") && m["status"] == "True" {
			return nil, refused("native_terminal_or_aborting")
		}
	}
	if !ready {
		if s.Export == nil {
			return nil, exportPending
		}
		return nil, refused("export_readiness_lost")
	}
	if s.Utility == nil {
		return nil, refused("utility_binding_missing")
	}
	candidates, err := e.exportCandidates(ctx, kvtypes.ExportResource, ns)
	if err != nil {
		return nil, err
	}
	var ex *unstructured.Unstructured
	for i := range candidates {
		if controllerOwned(&candidates[i], ns, "VirtualMachineBackup", b.GetName(), string(b.GetUID())) {
			if ex != nil {
				return nil, refused("export_owner_ambiguous")
			}
			ex = &candidates[i]
		}
	}
	if ex == nil || ex.GetUID() == "" || textAt(ex, "status", "phase") != "Ready" ||
		textAt(ex, "spec", "source", "apiGroup") != "backup.kubevirt.io" || textAt(ex, "spec", "source", "kind") != "VirtualMachineBackup" || textAt(ex, "spec", "source", "name") != b.GetName() || textAt(ex, "spec", "tokenSecretRef") != n.Objects[2].Name {
		return nil, refused("export_identity_or_source_changed")
	}
	uid := string(ex.GetUID())
	serviceName := textAt(ex, "status", "serviceName")
	if serviceName == "" {
		return nil, refused("export_service_missing")
	}
	service, err := e.dynamic.Resource(exportServiceResource).Namespace(ns).Get(ctx, serviceName, metav1.GetOptions{})
	if err != nil {
		return nil, observationFault("export_service", err)
	}
	if !controllerOwned(service, ns, "VirtualMachineExport", ex.GetName(), uid) || textAt(service, "spec", "type") != "ClusterIP" || textAt(service, "spec", "externalName") != "" {
		return nil, refused("export_service_identity_changed")
	}
	ports, _, _ := unstructured.NestedSlice(service.Object, "spec", "ports")
	if len(ports) != 1 {
		return nil, refused("export_service_ports_invalid")
	}
	port, ok := ports[0].(map[string]interface{})
	if !ok || port["port"] != int64(443) || port["targetPort"] != int64(8443) || port["protocol"] != "TCP" || port["name"] != "export" {
		return nil, refused("export_service_port_changed")
	}
	pods, err := e.exportCandidates(ctx, exportPodResource, ns)
	if err != nil {
		return nil, err
	}
	var pod *unstructured.Unstructured
	for i := range pods {
		for _, owner := range pods[i].GetOwnerReferences() {
			if string(owner.UID) == uid {
				if pod != nil {
					return nil, refused("export_pod_ambiguous")
				}
				pod = &pods[i]
				break
			}
		}
	}
	if pod == nil || !controllerOwned(pod, ns, "VirtualMachineExport", ex.GetName(), uid) || textAt(pod, "status", "phase") != "Running" {
		return nil, refused("export_pod_identity_or_state_changed")
	}
	podConditions, _, _ := unstructured.NestedSlice(pod.Object, "status", "conditions")
	podReady := false
	if len(podConditions) > 16 {
		return nil, refused("export_pod_conditions_invalid")
	}
	for _, raw := range podConditions {
		m, ok := raw.(map[string]interface{})
		if !ok {
			return nil, refused("export_pod_condition_shape_invalid")
		}
		if m["type"] == "Ready" {
			if podReady || m["status"] != "True" {
				return nil, refused("export_pod_ready_condition_invalid")
			}
			podReady = true
		}
	}
	if !podReady {
		return nil, refused("export_pod_not_ready")
	}
	selector, found, err := unstructured.NestedStringMap(service.Object, "spec", "selector")
	if err != nil || !found || len(selector) == 0 || len(selector) > 16 {
		return nil, refused("export_selector_invalid")
	}
	for k, v := range selector {
		if pod.GetLabels()[k] != v {
			return nil, refused("export_selector_changed")
		}
	}
	addresses, _, _ := unstructured.NestedSlice(pod.Object, "status", "podIPs")
	if len(addresses) == 0 || len(addresses) > 2 {
		return nil, refused("export_pod_addresses_invalid")
	}
	x := &storageupload.ExportState{CA: textAt(b, "status", "endpointCert"), Checkpoint: textAt(b, "status", "checkpointName"), ClusterIP: textAt(service, "spec", "clusterIP"), Resources: []storageupload.ExportResource{exportRef("export", ex, string(b.GetUID())), exportRef("service", service, uid), exportRef("pod", pod, uid)}}
	if n.Lifetime != nil {
		x.Lifetime, err = inspectExportLifetime(ex, pod, n)
		if err != nil {
			return nil, err
		}
	}
	x.Selector = selector
	if r.Plan.Parent != nil && x.Checkpoint == r.Plan.Parent.Checkpoint {
		return nil, refused("export_checkpoint_not_advanced")
	}
	for _, raw := range addresses {
		m, ok := raw.(map[string]interface{})
		if !ok {
			return nil, refused("export_pod_address_shape_invalid")
		}
		ip, ok := m["ip"].(string)
		if !ok || net.ParseIP(ip) == nil {
			return nil, refused("export_pod_address_invalid")
		}
		x.PodAddresses = append(x.PodAddresses, ip)
	}
	sort.Strings(x.PodAddresses)
	slices, err := e.exportCandidates(ctx, exportSliceResource, ns)
	if err != nil {
		return nil, err
	}
	seenAddresses := map[string]bool{}
	for i := range slices {
		slice := &slices[i]
		related := false
		for _, owner := range slice.GetOwnerReferences() {
			if owner.UID == service.GetUID() {
				related = true
			}
		}
		if !related {
			continue
		}
		if !controllerOwned(slice, ns, "Service", service.GetName(), string(service.GetUID())) {
			return nil, refused("export_slice_owner_changed")
		}
		addressType := textAt(slice, "addressType")
		if addressType != "IPv4" && addressType != "IPv6" {
			return nil, refused("export_slice_address_type_invalid")
		}
		p, _, _ := unstructured.NestedSlice(slice.Object, "ports")
		if len(p) != 1 {
			return nil, refused("export_slice_ports_invalid")
		}
		pm, ok := p[0].(map[string]interface{})
		if !ok || pm["port"] != int64(8443) || pm["protocol"] != "TCP" || pm["name"] != "export" {
			return nil, refused("export_slice_port_changed")
		}
		endpoints, _, _ := unstructured.NestedSlice(slice.Object, "endpoints")
		if len(endpoints) == 0 || len(endpoints) > 2 {
			return nil, refused("export_slice_endpoints_invalid")
		}
		for _, raw := range endpoints {
			m, ok := raw.(map[string]interface{})
			if !ok {
				return nil, refused("export_slice_endpoint_shape_invalid")
			}
			ref, _, _ := unstructured.NestedMap(m, "targetRef")
			cond, _, _ := unstructured.NestedMap(m, "conditions")
			if ref["kind"] != "Pod" || ref["name"] != pod.GetName() || ref["namespace"] != ns || ref["uid"] != string(pod.GetUID()) || cond["ready"] != true || cond["terminating"] == true {
				return nil, refused("export_slice_endpoint_identity_changed")
			}
			ips, _, _ := unstructured.NestedStringSlice(m, "addresses")
			if len(ips) != 1 {
				return nil, refused("export_slice_addresses_invalid")
			}
			ip := ips[0]
			parsed := net.ParseIP(ip)
			if parsed == nil || (addressType == "IPv4") != (parsed.To4() != nil) {
				return nil, refused("export_slice_address_invalid")
			}
			found := false
			for _, p := range x.PodAddresses {
				if p == ip {
					found = true
				}
			}
			if !found || seenAddresses[ip] {
				return nil, refused("export_slice_address_unknown_or_duplicate")
			}
			seenAddresses[ip] = true
		}
		x.Resources = append(x.Resources, exportRef("endpointslice", slice, string(service.GetUID())))
	}
	if len(seenAddresses) != len(x.PodAddresses) {
		return nil, refused("export_slice_address_coverage_changed")
	}
	sort.Slice(x.Resources[3:], func(i, j int) bool { return x.Resources[3+i].Name < x.Resources[3+j].Name })
	if len(volumes) != len(r.Plan.Source.NativeDisks()) {
		return nil, refused("native_volume_count_mismatch")
	}
	vmi, err := e.dynamic.Resource(kvtypes.VMIResource).Namespace(ns).Get(ctx, r.Plan.VMName, metav1.GetOptions{})
	if err != nil {
		return nil, observationFault("export_vmi", err)
	}
	if r.Plan.Source.VMIUID == nil || string(vmi.GetUID()) != *r.Plan.Source.VMIUID {
		return nil, refused("export_vmi_identity_changed")
	}
	volumeStatus, _, _ := unstructured.NestedSlice(vmi.Object, "status", "volumeStatus")
	if len(volumeStatus) > 128 {
		return nil, refused("export_vmi_volume_status_limit")
	}
	targets := map[string]string{}
	for _, raw := range volumeStatus {
		m, ok := raw.(map[string]interface{})
		if !ok {
			return nil, refused("export_vmi_volume_status_invalid")
		}
		name, _ := m["name"].(string)
		target, _ := m["target"].(string)
		if _, exists := targets[name]; exists {
			return nil, refused("export_vmi_volume_status_duplicate")
		}
		targets[name] = target
	}
	byName := map[string]storageupload.ExportVolume{}
	for _, raw := range volumes {
		m, ok := raw.(map[string]interface{})
		if !ok || len(m) != 4 {
			return nil, refused("native_volume_shape_invalid")
		}
		v := storageupload.ExportVolume{}
		v.Name, _ = m["volumeName"].(string)
		v.DiskTarget, _ = m["diskTarget"].(string)
		v.DataURL, _ = m["dataEndpoint"].(string)
		v.MapURL, _ = m["mapEndpoint"].(string)
		if _, exists := byName[v.Name]; exists || v.Name == "" || v.DiskTarget == "" || targets[v.Name] != v.DiskTarget {
			return nil, refused("native_volume_identity_or_target_invalid")
		}
		byName[v.Name] = v
	}
	native := map[string]bool{}
	for _, v := range r.Plan.Source.NativeDisks() {
		if _, ok := byName[v.Name]; !ok {
			return nil, refused("native_volume_missing")
		}
		native[v.Name] = true
		if r.Plan.Source.Schema == 2 {
			item := byName[v.Name]
			item.VolumeID = v.PVCUID
			x.NativeVolumes = append(x.NativeVolumes, item)
		}
	}
	for name := range byName {
		if !native[name] {
			return nil, refused("native_volume_unexpected")
		}
	}
	for _, v := range r.Plan.Source.Volumes {
		item, ok := byName[v.Name]
		if !ok {
			return nil, refused("selected_volume_missing")
		}
		item.VolumeID = v.PVCUID
		x.Volumes = append(x.Volumes, item)
	}
	// The pinned controller prefers published external links when present.
	// Those are routing authority, not ownership of a proxy/Route. Match the
	// exact admitted export/VMB link and CA; no caller URL or redirect is used.
	link := "internal"
	external, _, _ := unstructured.NestedSlice(ex.Object, "status", "links", "external", "backups")
	if len(external) > 0 {
		link = "external"
	}
	if textAt(ex, "status", "links", link, "cert") != x.CA {
		return nil, refused("export_certificate_changed")
	}
	links, _, _ := unstructured.NestedSlice(ex.Object, "status", "links", link, "backups")
	linksObserved := len(links)
	linkCount = &linksObserved
	if len(links) != len(r.Plan.Source.NativeDisks()) {
		return nil, refused("export_link_count_mismatch")
	}
	seen := map[string]bool{}
	for _, raw := range links {
		m, ok := raw.(map[string]interface{})
		if !ok {
			return nil, refused("export_link_shape_invalid")
		}
		name, _ := m["name"].(string)
		v, ok := byName[name]
		if !ok || seen[name] {
			return nil, refused("export_link_unknown_or_duplicate")
		}
		seen[name] = true
		endpoints, _, _ := unstructured.NestedSlice(m, "endpoints")
		if len(endpoints) != 2 {
			return nil, refused("export_endpoint_count_invalid")
		}
		kinds := map[string]bool{}
		for _, raw := range endpoints {
			ep, ok := raw.(map[string]interface{})
			if !ok {
				return nil, refused("export_endpoint_shape_invalid")
			}
			kind, _ := ep["endpoint"].(string)
			u, _ := ep["url"].(string)
			if kinds[kind] || !storageupload.ExportURL(u) {
				return nil, refused("export_endpoint_invalid_or_duplicate")
			}
			kinds[kind] = true
			if (kind == "data" && u != v.DataURL) || (kind == "map" && u != v.MapURL) || (kind != "data" && kind != "map") || !strings.HasSuffix(u, "/exports/"+name+"/"+kind) {
				return nil, refused("export_endpoint_changed")
			}
		}
	}
	if s.Export != nil && !reflect.DeepEqual(s.Export, x) {
		return nil, refused("export_projection_changed")
	}
	return x, nil
}

func (e *Executor) revalidateExport(ctx context.Context, s *storageupload.State) error {
	started := time.Now()
	defer func() {
		metrics.StorageStepSeconds.WithLabelValues("export_validation").Observe(time.Since(started).Seconds())
	}()
	return e.retryValidationObservation(ctx, s, func(observation context.Context) error {
		if s.Export == nil || s.Utility == nil {
			return fault("export_admission", "export_binding_missing", "refused")
		}
		if err := e.admitNativeSnapshot(observation, s, nil); err != nil {
			return err
		}
		if _, err := e.inspectExport(observation, s); err != nil {
			if err == errExportLifetime {
				return fault("export_admission", "export_lifetime_insufficient", "refused")
			}
			return err
		}
		// Token reads follow complete source/export admission. Never retain token
		// bytes in diagnostic evidence or accept a replacement identity on retry.
		n := s.Native
		secret, err := e.dynamic.Resource(coreV1Secret).Namespace(s.Request.Plan.Source.Namespace).Get(observation, n.Objects[2].Name, metav1.GetOptions{})
		if err != nil {
			return observationFault("export_token", err)
		}
		if string(secret.GetUID()) != n.Objects[2].UID || !validNativeObject(secret, &s.Request, n, 2, true) {
			return fault("export_admission", "export_token_identity_changed", "refused")
		}
		return nil
	})
}
