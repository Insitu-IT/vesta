package kubevirt

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"regexp"
	"strings"

	"vnbui/agent/internal/models"
	"vnbui/agent/internal/storagerestore"
)

var dnsName = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)
var restoreID = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9-]{0,63}$`)

type Bundle struct {
	Schema  string                  `json:"schema"`
	Members []storagerestore.Member `json:"members"`
}

func validName(name string) bool {
	return len(name) > 0 && len(name) <= 63 && dnsName.MatchString(name)
}

// ValidatePlan establishes a single tenant/source and a complete, explicit fresh
// destination before a controller creates anything. Receipt semantics and data
// hashes are rechecked by the assembler before the VM can exist.
func ValidatePlan(req *models.KubeVirtRestoreRequest) (Bundle, string, error) {
	return validatePlan(req, true)
}

func validatePlan(req *models.KubeVirtRestoreRequest, requireCredentials bool) (Bundle, string, error) {
	var bundle Bundle
	if req == nil || req.Schema != models.KubeVirtRestoreSchema || !restoreID.MatchString(req.RestoreID) || req.OrgID == "" || req.AgentID == "" {
		return bundle, "", errors.New("explicit KubeVirt restore identity is required")
	}
	d := json.NewDecoder(bytes.NewReader(req.Bundle))
	d.DisallowUnknownFields()
	if err := d.Decode(&bundle); err != nil {
		return bundle, "", errors.New("invalid accepted restore bundle")
	}
	var extra any
	if d.Decode(&extra) != io.EOF || bundle.Schema != "vnbui-kubevirt-restore/1" || len(bundle.Members) == 0 || len(bundle.Members) > 256 {
		return bundle, "", errors.New("accepted full-to-selected chain is required")
	}
	target := req.Target
	if !validName(target.Namespace) || !validName(target.VMName) || len(target.Disks) == 0 || len(target.Disks) > 32 || target.Networks == nil || target.Dependencies == nil {
		return bundle, "", errors.New("explicit namespace, VM, disk, network and dependency mappings are required")
	}
	first := bundle.Members[0].Request
	if first.Plan.BackupType != "full" || first.Plan.Parent != nil {
		return bundle, "", errors.New("restore chain must start at a full baseline")
	}
	if len(target.Disks) != len(first.Plan.Source.Volumes) {
		return bundle, "", errors.New("every protected disk requires a fresh PVC mapping")
	}
	volumes := map[string]models.StorageVolume{}
	for _, v := range first.Plan.Source.Volumes {
		volumes[v.Name] = v
	}
	seen := map[string]bool{}
	for _, disk := range target.Disks {
		v, ok := volumes[disk.VolumeName]
		if !ok || seen["volume/"+disk.VolumeName] || seen["pvc/"+disk.PVCName] || !validName(disk.PVCName) || !validName(disk.StorageClass) ||
			(disk.VolumeMode != "Filesystem" && disk.VolumeMode != "Block") || (disk.AccessMode != "ReadWriteOnce" && disk.AccessMode != "ReadWriteMany") || disk.CapacityBytes < v.CapacityBytes || disk.CapacityBytes <= 0 {
			return bundle, "", errors.New("invalid, duplicate or undersized fresh PVC mapping")
		}
		if target.Namespace == first.Plan.Source.Namespace {
			for _, sourceVolume := range first.Plan.Source.NativeDisks() {
				if disk.PVCName == sourceVolume.PVCName {
					return bundle, "", errors.New("restoring onto a source PVC is forbidden")
				}
			}
		}
		seen["volume/"+disk.VolumeName], seen["pvc/"+disk.PVCName] = true, true
	}
	if target.Namespace == first.Plan.Source.Namespace && target.VMName == first.Plan.VMName {
		return bundle, "", errors.New("restoring onto the source VM is forbidden")
	}
	pods := 0
	for _, network := range target.Networks {
		if !validName(network.Name) || seen["network/"+network.Name] {
			return bundle, "", errors.New("invalid network mapping")
		}
		seen["network/"+network.Name] = true
		if network.Type == "pod" && network.NetworkName == "" {
			pods++
		} else if network.Type != "multus" || !validName(network.NetworkName) {
			return bundle, "", errors.New("network mapping requires pod or a target-namespace Multus network")
		}
	}
	if pods > 1 {
		return bundle, "", errors.New("only one pod network is supported")
	}
	for name, value := range target.Dependencies {
		parts := strings.Split(name, "/")
		if len(parts) != 2 || (parts[0] != "secret" && parts[0] != "configMap") || !validName(parts[1]) || !validName(value) {
			return bundle, "", errors.New("dependency mapping requires explicit secret/name or configMap/name")
		}
	}
	for i, member := range bundle.Members {
		request := member.Request
		body, _ := json.Marshal(request)
		parsed, err := models.DecodeStorageTransaction(body)
		if err != nil || parsed == nil || !req.RecoveryOrigin.Matches(req.OrgID, req.AgentID, request.OrgID, request.AgentID) || request.Plan.Provider != "kubevirt" {
			return bundle, "", errors.New("restore member belongs to another organization, agent or provider")
		}
		_, digest, err := models.CanonicalReceipt(parsed, member.Receipt)
		if err != nil {
			return bundle, "", errors.New("invalid accepted receipt")
		}
		if !reflect.DeepEqual(request.Plan.Target, first.Plan.Target) {
			return bundle, "", errors.New("chain changes S3 target")
		}
		if i > 0 {
			prev := bundle.Members[i-1]
			_, previousDigest, _ := models.CanonicalReceipt(&prev.Request, prev.Receipt)
			p := request.Plan.Parent
			if p == nil || p.BackupID != prev.Request.BackupID || p.RootBackupID != first.BackupID || p.ReceiptSHA256 != previousDigest || request.Plan.BackupType != "incremental" {
				return bundle, "", errors.New("chain membership order differs from accepted parents")
			}
		}
		_ = digest
		if requireCredentials && request.Plan.Encryption.Format != "none" {
			key, err := base64.StdEncoding.Strict().DecodeString(req.Keys[request.BackupID])
			clear(key)
			if err != nil || len(key) != 32 {
				return bundle, "", errors.New("restore requires the exact DEK for every encrypted member")
			}
		}
	}
	if req.S3.Endpoint != first.Plan.Target.Endpoint || req.S3.Bucket != first.Plan.Target.Bucket || req.S3.Region != req.RecoveryOrigin.SigningRegion(first.Plan.Target.Region) || req.S3.Region == "" || (requireCredentials && (req.S3.AccessKey == "" || req.S3.SecretKey == "")) {
		return bundle, "", errors.New("trusted read credentials must match the accepted S3 target")
	}
	// Credentials are deliberately excluded from immutable destination identity:
	// authorized retries can refresh read credentials without changing resources.
	identity := struct {
		Schema, OrgID, AgentID, RestoreID string
		Target                            models.KubeVirtRestoreTarget
		Bundle                            Bundle
		RecoveryOrigin                    *models.RestoreOrigin `json:"recovery_origin,omitempty"`
	}{req.Schema, req.OrgID, req.AgentID, req.RestoreID, req.Target, bundle, req.RecoveryOrigin}
	body, err := json.Marshal(identity)
	if err != nil {
		return bundle, "", err
	}
	hash := sha256.Sum256(body)
	return bundle, hex.EncodeToString(hash[:]), nil
}

// RenderVM preserves the captured guest definition but replaces every storage,
// network and supported external dependency reference with an explicit mapping.
// Runtime identities/owner references are never copied. No VM is started here.
func RenderVM(captured map[string]interface{}, target models.KubeVirtRestoreTarget, source models.StorageSource) (map[string]interface{}, error) {
	body, _ := json.Marshal(captured["spec"])
	var spec map[string]interface{}
	_ = json.Unmarshal(body, &spec)
	if spec == nil {
		return nil, errors.New("captured VM spec is missing")
	}
	if spec["instancetype"] != nil || spec["preference"] != nil {
		return nil, errors.New("restore requires a self-contained VM spec; expand instancetype/preference before backup")
	}
	template, _ := spec["template"].(map[string]interface{})
	if metadata, ok := template["metadata"].(map[string]interface{}); ok {
		if annotations, ok := metadata["annotations"].(map[string]interface{}); ok {
			for name := range annotations {
				if strings.HasPrefix(name, "hooks.kubevirt.io/") || strings.HasPrefix(name, "k8s.v1.cni.cncf.io/") {
					return nil, errors.New("restore requires explicit support for captured hook or CNI annotations")
				}
			}
		}
	}
	vmSpec, _ := template["spec"].(map[string]interface{})
	domain, _ := vmSpec["domain"].(map[string]interface{})
	devices, _ := domain["devices"].(map[string]interface{})
	if vmSpec == nil || domain == nil || devices == nil {
		return nil, errors.New("captured VM template/domain/devices are required")
	}
	for _, field := range []string{"hostDevices", "gpus", "filesystems"} {
		if values, ok := devices[field].([]interface{}); ok && len(values) > 0 {
			return nil, fmt.Errorf("restore requires explicit support for domain.devices.%s", field)
		}
	}
	for _, field := range []string{"affinity", "nodeSelector", "tolerations", "topologySpreadConstraints", "schedulerName", "serviceAccountName", "accessCredentials"} {
		if vmSpec[field] != nil {
			return nil, fmt.Errorf("restore requires removing or explicitly provisioning placement/dependency field %s before backup", field)
		}
	}
	if firmware, ok := domain["firmware"].(map[string]interface{}); ok {
		delete(firmware, "uuid")
		if bootloader, ok := firmware["bootloader"].(map[string]interface{}); ok {
			if efi, ok := bootloader["efi"].(map[string]interface{}); ok && efi["persistent"] == true {
				return nil, errors.New("persistent EFI state is not present in this disk backup")
			}
		}
	}
	if interfaces, ok := devices["interfaces"].([]interface{}); ok {
		for _, entry := range interfaces {
			if item, ok := entry.(map[string]interface{}); ok {
				delete(item, "macAddress")
			}
		}
	}
	if domain["launchSecurity"] != nil {
		return nil, errors.New("restore of launch-security-bound guests requires an explicit supported recovery profile")
	}
	if tpm, ok := devices["tpm"].(map[string]interface{}); ok && tpm["persistent"] == true {
		return nil, errors.New("persistent TPM state is not present in this disk backup")
	}
	if source.Schema == 2 {
		if err := selectCapturedDisks(vmSpec, devices, source); err != nil {
			return nil, err
		}
	} else if source.Schema != 1 || len(source.NativeVolumes) != 0 {
		return nil, errors.New("unsupported captured storage identity schema")
	}
	disks := map[string]models.KubeVirtRestoreDisk{}
	for _, disk := range target.Disks {
		if _, duplicate := disks[disk.VolumeName]; duplicate {
			return nil, errors.New("duplicate protected disk target")
		}
		if target.Namespace == source.Namespace {
			for _, participant := range source.NativeDisks() {
				if disk.PVCName == participant.PVCName {
					return nil, errors.New("restoring onto a source PVC is forbidden")
				}
			}
		}
		disks[disk.VolumeName] = disk
	}
	seenDisks := map[string]bool{}
	usedDeps := map[string]bool{}
	volumes, ok := vmSpec["volumes"].([]interface{})
	if !ok {
		return nil, errors.New("captured VM volumes are missing")
	}
	for _, entry := range volumes {
		volume, ok := entry.(map[string]interface{})
		if !ok {
			return nil, errors.New("invalid captured volume")
		}
		name, _ := volume["name"].(string)
		if disk, ok := disks[name]; ok {
			if seenDisks[name] || (volume["persistentVolumeClaim"] == nil && volume["dataVolume"] == nil) {
				return nil, errors.New("captured disk differs from protected PVC mapping")
			}
			for k := range volume {
				delete(volume, k)
			}
			volume["name"] = name
			volume["persistentVolumeClaim"] = map[string]interface{}{"claimName": disk.PVCName}
			seenDisks[name] = true
			continue
		}
		if volume["persistentVolumeClaim"] != nil || volume["dataVolume"] != nil {
			return nil, errors.New("captured VM contains an unprotected persistent disk")
		}
		allowed := false
		for kind, value := range volume {
			if kind == "name" {
				continue
			}
			switch kind {
			case "containerDisk":
				container, ok := value.(map[string]interface{})
				if !ok {
					return nil, errors.New("invalid containerDisk definition")
				}
				if secret, ok := container["imagePullSecret"].(string); ok && secret != "" {
					ref := map[string]interface{}{"name": secret}
					if err := mapDependency(ref, "name", "secret", target, usedDeps); err != nil {
						return nil, err
					}
					container["imagePullSecret"] = ref["name"]
				}
				allowed = true
			case "emptyDisk":
				allowed = true
			case "cloudInitNoCloud", "cloudInitConfigDrive":
				m, ok := value.(map[string]interface{})
				if !ok {
					return nil, errors.New("invalid cloud-init definition")
				}
				allowed = true
				for _, field := range []string{"secretRef", "networkDataSecretRef"} {
					if ref, ok := m[field].(map[string]interface{}); ok {
						if err := mapDependency(ref, "name", "secret", target, usedDeps); err != nil {
							return nil, err
						}
					}
				}
			case "secret", "configMap":
				m, ok := value.(map[string]interface{})
				if !ok {
					return nil, errors.New("invalid dependency volume")
				}
				field := "name"
				if kind == "secret" {
					field = "secretName"
				}
				if err := mapDependency(m, field, kind, target, usedDeps); err != nil {
					return nil, err
				}
				allowed = true
			default:
				return nil, fmt.Errorf("unsupported captured volume type %s; provision supported backup inputs", kind)
			}
		}
		if !allowed {
			return nil, errors.New("captured volume has no supported source")
		}
	}
	if len(seenDisks) != len(disks) || len(source.Volumes) != len(disks) {
		return nil, errors.New("not all protected disks appear in the captured VM")
	}
	if len(usedDeps) != len(target.Dependencies) {
		return nil, errors.New("unused dependency mappings are refused")
	}
	networks, ok := vmSpec["networks"].([]interface{})
	if !ok {
		networks = []interface{}{}
	}
	if len(networks) != len(target.Networks) {
		return nil, errors.New("every captured network needs an explicit mapping")
	}
	netmap := map[string]models.KubeVirtRestoreNetwork{}
	for _, n := range target.Networks {
		netmap[n.Name] = n
	}
	for i, entry := range networks {
		n, _ := entry.(map[string]interface{})
		name, _ := n["name"].(string)
		mapped, ok := netmap[name]
		if !ok {
			return nil, errors.New("captured network is unmapped")
		}
		delete(netmap, name)
		replacement := map[string]interface{}{"name": name}
		if mapped.Type == "pod" {
			replacement["pod"] = map[string]interface{}{}
		} else {
			replacement["multus"] = map[string]interface{}{"networkName": mapped.NetworkName}
		}
		networks[i] = replacement
	}
	// KubeVirt prunes an empty networks list on create. Keep the rendered
	// definition identical to the persisted API object for custody checks.
	if len(networks) == 0 {
		delete(vmSpec, "networks")
	} else {
		vmSpec["networks"] = networks
	}
	// Only explicitly mapped interfaces may be attached. Omitting networks
	// alone lets KubeVirt add a default pod interface when this VM is started.
	devices["autoattachPodInterface"] = false
	delete(spec, "running")
	delete(spec, "dataVolumeTemplates")
	spec["runStrategy"] = "Halted"
	// Source labels may select source services/policies, so use only target identity.
	template["metadata"] = map[string]interface{}{"labels": map[string]interface{}{"kubevirt.io/domain": target.VMName}}
	delete(vmSpec, "hostname")
	delete(vmSpec, "subdomain")
	return map[string]interface{}{"apiVersion": "kubevirt.io/v1", "kind": "VirtualMachine", "metadata": map[string]interface{}{"name": target.VMName, "namespace": target.Namespace}, "spec": spec}, nil
}

func mapDependency(ref map[string]interface{}, field, kind string, target models.KubeVirtRestoreTarget, used map[string]bool) error {
	name, _ := ref[field].(string)
	key := kind + "/" + name
	destination, ok := target.Dependencies[key]
	if !ok {
		return fmt.Errorf("explicit mapping required for dependency %s", key)
	}
	ref[field] = destination
	used[key] = true
	return nil
}
