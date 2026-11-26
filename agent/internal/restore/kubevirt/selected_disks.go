package kubevirt

import (
	"errors"
	"reflect"

	"vnbui/agent/internal/models"
)

// selectCapturedDisks validates all receipt-bound native participants before
// omitting only known unprotected participants from the fresh stopped guest.
// The caller supplies a deep copy; captured input and source custody stay intact.
func selectCapturedDisks(guest, devices map[string]interface{}, source models.StorageSource) error {
	refuse := func() error { return errors.New("captured native disk identities differ from the accepted selection") }
	if len(source.NativeVolumes) == 0 || len(source.NativeVolumes) > 256 || len(source.Volumes) == 0 {
		return refuse()
	}
	native := map[string]models.StorageVolume{}
	pvcs, ids := map[string]bool{}, map[string]bool{}
	for _, volume := range source.NativeVolumes {
		if _, duplicate := native[volume.Name]; duplicate || volume.Name == "" || volume.PVCName == "" || volume.PVCUID == "" || pvcs[volume.PVCName] || ids[volume.PVCUID] || volume.Mapping.DiskName != volume.Name || volume.Mapping.Device != "disk" {
			return refuse()
		}
		native[volume.Name], pvcs[volume.PVCName], ids[volume.PVCUID] = volume, true, true
	}
	selected := map[string]bool{}
	for _, volume := range source.Volumes {
		if selected[volume.Name] || !reflect.DeepEqual(native[volume.Name], volume) {
			return refuse()
		}
		selected[volume.Name] = true
	}
	volumes, ok := guest["volumes"].([]interface{})
	if !ok || len(volumes) > 512 {
		return refuse()
	}
	seen, persistent := map[string]bool{}, map[string]bool{}
	retainedVolumes := []interface{}{}
	for _, entry := range volumes {
		volume, ok := entry.(map[string]interface{})
		name, _ := volume["name"].(string)
		if !ok || name == "" || seen[name] {
			return refuse()
		}
		seen[name] = true
		pvc, pvcSource := volume["persistentVolumeClaim"].(map[string]interface{})
		dv, dvSource := volume["dataVolume"].(map[string]interface{})
		if volume["persistentVolumeClaim"] != nil || volume["dataVolume"] != nil {
			accepted, known := native[name]
			if !known || len(volume) != 2 || pvcSource == dvSource || (pvcSource && pvc["claimName"] != accepted.PVCName) || (dvSource && dv["name"] != accepted.PVCName) {
				return refuse()
			}
			persistent[name] = true
			if !selected[name] {
				continue
			}
		} else if _, known := native[name]; known {
			return refuse()
		}
		retainedVolumes = append(retainedVolumes, entry)
	}
	if len(persistent) != len(native) {
		return refuse()
	}
	disks, ok := devices["disks"].([]interface{})
	if !ok || len(disks) > 512 {
		return refuse()
	}
	seenDisks := map[string]bool{}
	retainedDisks := []interface{}{}
	for _, entry := range disks {
		disk, ok := entry.(map[string]interface{})
		name, _ := disk["name"].(string)
		if !ok || name == "" || seenDisks[name] || !seen[name] {
			return refuse()
		}
		seenDisks[name] = true
		if accepted, known := native[name]; known {
			device, ok := disk["disk"].(map[string]interface{})
			var serial interface{}
			if accepted.Mapping.Serial != nil {
				serial = *accepted.Mapping.Serial
			}
			if !ok || disk["lun"] != nil || disk["cdrom"] != nil || device["bus"] != accepted.Mapping.Bus || !reflect.DeepEqual(disk["serial"], serial) {
				return refuse()
			}
			if !selected[name] {
				continue
			}
		}
		retainedDisks = append(retainedDisks, entry)
	}
	for name := range native {
		if !seenDisks[name] {
			return refuse()
		}
	}
	guest["volumes"], devices["disks"] = retainedVolumes, retainedDisks
	return nil
}
