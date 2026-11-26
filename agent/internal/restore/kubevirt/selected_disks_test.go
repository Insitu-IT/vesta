package kubevirt

import (
	"encoding/json"
	"reflect"
	"testing"

	"vnbui/agent/internal/models"
)

func selectedRestoreFixture(t *testing.T, subset bool) (*models.KubeVirtRestoreRequest, models.StorageSource) {
	t.Helper()
	req := restoreFixture(t)
	var bundle Bundle
	if err := json.Unmarshal(req.Bundle, &bundle); err != nil {
		t.Fatal(err)
	}
	member := &bundle.Members[0]
	source := &member.Request.Plan.Source
	source.Schema = 2
	source.NativeVolumes = append([]models.StorageVolume(nil), source.Volumes...)
	if subset {
		source.Volumes = source.Volumes[:1]
		member.Request.Plan.Exclusions = []string{"extra"}
		artifacts := member.Request.Plan.Artifacts[:0]
		for _, artifact := range member.Request.Plan.Artifacts {
			if artifact.VolumeID == source.Volumes[0].PVCUID {
				artifacts = append(artifacts, artifact)
			}
		}
		member.Request.Plan.Artifacts = artifacts
		objects := member.Receipt.Objects[:0]
		for _, object := range member.Receipt.Objects {
			if object.VolumeID == source.Volumes[0].PVCUID {
				objects = append(objects, object)
			}
		}
		member.Receipt.Objects = objects
		req.Target.Disks = req.Target.Disks[:1]
	}
	body, err := models.StorageCanonical(member.Request.Plan)
	if err != nil {
		t.Fatal(err)
	}
	member.Request.PlanSHA256 = digest(body)
	req.Bundle, err = json.Marshal(bundle)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := ValidatePlan(req); err != nil {
		t.Fatal("schema-2 selected bundle refused", err)
	}
	return req, *source
}

func guestParts(captured map[string]interface{}) (map[string]interface{}, map[string]interface{}) {
	guest := captured["spec"].(map[string]interface{})["template"].(map[string]interface{})["spec"].(map[string]interface{})
	return guest, guest["domain"].(map[string]interface{})["devices"].(map[string]interface{})
}

func TestRenderSchema2RestoresExactlyProtectedDisks(t *testing.T) {
	for _, subset := range []bool{false, true} {
		t.Run(map[bool]string{false: "all", true: "subset"}[subset], func(t *testing.T) {
			req, source := selectedRestoreFixture(t, subset)
			captured := capturedFixture()
			guest, devices := guestParts(captured)
			guest["volumes"] = append(guest["volumes"].([]interface{}), map[string]interface{}{"name": "cloudinit", "cloudInitNoCloud": map[string]interface{}{"userData": "fixture"}})
			devices["disks"] = append(devices["disks"].([]interface{}), map[string]interface{}{"name": "cloudinit", "disk": map[string]interface{}{"bus": "virtio"}})
			before, _ := json.Marshal(captured)
			vm, err := RenderVM(captured, req.Target, source)
			if err != nil {
				t.Fatal(err)
			}
			after, _ := json.Marshal(captured)
			if string(before) != string(after) {
				t.Fatal("captured source was changed")
			}
			if vm["spec"].(map[string]interface{})["runStrategy"] != "Halted" {
				t.Fatal("fresh VM must remain stopped")
			}
			rendered, renderedDevices := guestParts(vm)
			volumes := rendered["volumes"].([]interface{})
			disks := renderedDevices["disks"].([]interface{})
			if len(volumes) != len(req.Target.Disks)+1 || len(disks) != len(volumes) {
				t.Fatal("wrong protected disk/device set", volumes, disks)
			}
			for i, disk := range req.Target.Disks {
				volume := volumes[i].(map[string]interface{})
				if volume["name"] != disk.VolumeName || !reflect.DeepEqual(volume["persistentVolumeClaim"], map[string]interface{}{"claimName": disk.PVCName}) || disks[i].(map[string]interface{})["name"] != disk.VolumeName {
					t.Fatal("protected disk not mapped to its fresh destination", volume)
				}
			}
			if volumes[len(volumes)-1].(map[string]interface{})["name"] != "cloudinit" {
				t.Fatal("unrelated nonpersistent volume removed")
			}
		})
	}
}

func TestRenderSelectedDisksRefusesUnboundCapturedIdentities(t *testing.T) {
	for _, problem := range []string{"unknown", "duplicate_volume", "duplicate_device", "missing_volume", "missing_device", "selected_pvc", "excluded_dv", "selected_bus", "excluded_serial", "duplicate_native", "selected_native_mismatch", "legacy"} {
		t.Run(problem, func(t *testing.T) {
			req, source := selectedRestoreFixture(t, true)
			captured := capturedFixture()
			guest, devices := guestParts(captured)
			volumes, disks := guest["volumes"].([]interface{}), devices["disks"].([]interface{})
			switch problem {
			case "unknown":
				guest["volumes"] = append(volumes, map[string]interface{}{"name": "unknown", "persistentVolumeClaim": map[string]interface{}{"claimName": "unknown"}})
				devices["disks"] = append(disks, map[string]interface{}{"name": "unknown", "disk": map[string]interface{}{"bus": "virtio"}})
			case "duplicate_volume":
				guest["volumes"] = append(volumes, volumes[0])
			case "duplicate_device":
				devices["disks"] = append(disks, disks[1])
			case "missing_volume":
				guest["volumes"] = volumes[:1]
			case "missing_device":
				devices["disks"] = disks[:1]
			case "selected_pvc":
				volumes[0].(map[string]interface{})["persistentVolumeClaim"] = map[string]interface{}{"claimName": "replacement"}
			case "excluded_dv":
				volumes[1].(map[string]interface{})["dataVolume"] = map[string]interface{}{"name": "replacement"}
			case "selected_bus":
				disks[0].(map[string]interface{})["disk"] = map[string]interface{}{"bus": "scsi"}
			case "excluded_serial":
				disks[1].(map[string]interface{})["serial"] = "unexpected"
			case "duplicate_native":
				source.NativeVolumes = append(source.NativeVolumes, source.NativeVolumes[1])
			case "selected_native_mismatch":
				source.NativeVolumes[0].PVCUID = "replacement"
			case "legacy":
				source.Schema, source.NativeVolumes = 1, nil
			}
			before, _ := json.Marshal(captured)
			if _, err := RenderVM(captured, req.Target, source); err == nil {
				t.Fatal("unsafe captured selection accepted")
			}
			after, _ := json.Marshal(captured)
			if string(before) != string(after) {
				t.Fatal("refusal mutated captured source")
			}
		})
	}
}

func TestSelectedRestoreCannotReuseExcludedSourcePVC(t *testing.T) {
	req, source := selectedRestoreFixture(t, true)
	req.Target.Namespace = source.Namespace
	req.Target.Disks[0].PVCName = source.NativeVolumes[1].PVCName
	if _, _, err := ValidatePlan(req); err == nil {
		t.Fatal("excluded source PVC accepted as destination")
	}
}
