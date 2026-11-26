package kubevirt

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"reflect"
	"testing"

	"vnbui/agent/internal/models"
	"vnbui/agent/internal/storagerestore"
)

func digest(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }
func restoreFixture(t *testing.T) *models.KubeVirtRestoreRequest {
	t.Helper()
	data, err := os.ReadFile("../../../contracts/storage_semantic_valid.json")
	if err != nil {
		t.Fatal(err)
	}
	var request models.StorageTransactionRequest
	if err = json.Unmarshal(data, &request); err != nil {
		t.Fatal(err)
	}
	request.Plan.Target.Region = "us-east-1"
	second := request.Plan.Source.Volumes[0]
	second.Name = "extra"
	second.PVCName = "extra-source"
	second.PVCUID = "pvc-uid-2"
	second.Mapping.DiskName = "extra"
	request.Plan.Source.Volumes = append(request.Plan.Source.Volumes, second)
	artifactTemplates := append([]models.StorageArtifact{}, request.Plan.Artifacts...)
	request.Plan.Artifacts = nil
	for _, volume := range request.Plan.Source.Volumes {
		for _, artifact := range artifactTemplates {
			artifact.VolumeID = volume.PVCUID
			artifact.Key = "vnbui-owned/v1/" + digest([]byte(request.OrgID)) + "/" + digest([]byte(request.BackupID)) + "/payload/" + request.ReservationID + "/" + digest([]byte(volume.PVCUID)) + "/" + artifact.Role
			request.Plan.Artifacts = append(request.Plan.Artifacts, artifact)
		}
	}
	body, err := models.StorageCanonical(request.Plan)
	if err != nil {
		t.Fatal(err)
	}
	request.PlanSHA256 = digest(body)
	receipt := models.StorageReceipt{Protocol: request.Protocol, Schema: 2, ReservationID: request.ReservationID, BackupID: request.BackupID, Endpoint: request.Plan.Target.Endpoint, Bucket: request.Plan.Target.Bucket}
	for _, artifact := range request.Plan.Artifacts {
		receipt.Objects = append(receipt.Objects, models.StorageObjectReceipt{Key: artifact.Key, VolumeID: artifact.VolumeID, Role: artifact.Role, ETag: "\"etag\"", PlaintextBytes: 1, CiphertextBytes: 1, PlaintextSHA256: digest([]byte("x")), CiphertextSHA256: digest([]byte("x"))})
	}
	bundle, _ := json.Marshal(Bundle{Schema: "vnbui-kubevirt-restore/1", Members: []storagerestore.Member{{Request: request, Receipt: receipt}}})
	return &models.KubeVirtRestoreRequest{Schema: models.KubeVirtRestoreSchema, OrgID: request.OrgID, AgentID: request.AgentID, RestoreID: "restore-one", Bundle: bundle,
		Target: models.KubeVirtRestoreTarget{Namespace: "ns", VMName: "restored-vm", Disks: []models.KubeVirtRestoreDisk{
			{VolumeName: "data", PVCName: "restored-data", StorageClass: "ceph", AccessMode: "ReadWriteOnce", VolumeMode: "Filesystem", CapacityBytes: 2 << 20},
			{VolumeName: "extra", PVCName: "restored-extra", StorageClass: "ceph", AccessMode: "ReadWriteOnce", VolumeMode: "Block", CapacityBytes: 1 << 20}},
			Networks: []models.KubeVirtRestoreNetwork{{Name: "default", Type: "pod"}}, Dependencies: map[string]string{}},
		S3: models.KubeVirtRestoreS3{Endpoint: request.Plan.Target.Endpoint, Bucket: request.Plan.Target.Bucket, Region: request.Plan.Target.Region, AccessKey: "test-access", SecretKey: "test-secret"}, Keys: map[string]string{}}
}

func capturedFixture() map[string]interface{} {
	return map[string]interface{}{"apiVersion": "kubevirt.io/v1", "kind": "VirtualMachine", "metadata": map[string]interface{}{"name": "source", "namespace": "ns", "uid": "source-uid", "resourceVersion": "10"}, "spec": map[string]interface{}{
		"running": true, "dataVolumeTemplates": []interface{}{map[string]interface{}{"old": "must-not-copy"}},
		"template": map[string]interface{}{"metadata": map[string]interface{}{"labels": map[string]interface{}{"service": "source"}}, "spec": map[string]interface{}{
			"domain": map[string]interface{}{"cpu": map[string]interface{}{"cores": float64(2)}, "memory": map[string]interface{}{"guest": "512Mi"}, "firmware": map[string]interface{}{"uuid": "source-uuid"},
				"devices": map[string]interface{}{"disks": []interface{}{map[string]interface{}{"name": "data", "disk": map[string]interface{}{"bus": "virtio"}}, map[string]interface{}{"name": "extra", "disk": map[string]interface{}{"bus": "virtio"}}},
					"interfaces": []interface{}{map[string]interface{}{"name": "default", "masquerade": map[string]interface{}{}, "macAddress": "00:11:22:33:44:55"}}}},
			"volumes":  []interface{}{map[string]interface{}{"name": "data", "persistentVolumeClaim": map[string]interface{}{"claimName": "pvc"}}, map[string]interface{}{"name": "extra", "dataVolume": map[string]interface{}{"name": "extra-source"}}},
			"networks": []interface{}{map[string]interface{}{"name": "default", "pod": map[string]interface{}{}}}}}}}
}

func TestFreshPlanAndRendering(t *testing.T) {
	req := restoreFixture(t)
	bundle, hash, err := ValidatePlan(req)
	if err != nil || len(hash) != 64 {
		t.Fatal(err, hash)
	}
	captured := capturedFixture()
	before, _ := json.Marshal(captured)
	vm, err := RenderVM(captured, req.Target, bundle.Members[0].Request.Plan.Source)
	if err != nil {
		t.Fatal(err)
	}
	after, _ := json.Marshal(captured)
	if string(before) != string(after) {
		t.Fatal("source template mutated")
	}
	spec := vm["spec"].(map[string]interface{})
	if spec["runStrategy"] != "Halted" || spec["running"] != nil || spec["dataVolumeTemplates"] != nil {
		t.Fatal(spec)
	}
	template := spec["template"].(map[string]interface{})
	guest := template["spec"].(map[string]interface{})
	domain := guest["domain"].(map[string]interface{})
	if domain["firmware"].(map[string]interface{})["uuid"] != nil {
		t.Fatal("source firmware identity copied")
	}
	for i, v := range guest["volumes"].([]interface{}) {
		if v.(map[string]interface{})["persistentVolumeClaim"].(map[string]interface{})["claimName"] != req.Target.Disks[i].PVCName {
			t.Fatal(v)
		}
	}
	if !reflect.DeepEqual(domain["memory"], map[string]interface{}{"guest": "512Mi"}) {
		t.Fatal("lost guest configuration")
	}
}

func TestFreshRenderOmitsEmptyNetworksForKubeVirtCustody(t *testing.T) {
	req := restoreFixture(t)
	req.Target.Networks = []models.KubeVirtRestoreNetwork{}
	bundle, _, err := ValidatePlan(req)
	if err != nil {
		t.Fatal(err)
	}
	captured := capturedFixture()
	guest := captured["spec"].(map[string]interface{})["template"].(map[string]interface{})["spec"].(map[string]interface{})
	delete(guest, "networks")
	delete(guest["domain"].(map[string]interface{})["devices"].(map[string]interface{}), "interfaces")
	vm, err := RenderVM(captured, req.Target, bundle.Members[0].Request.Plan.Source)
	if err != nil {
		t.Fatal(err)
	}
	rendered := vm["spec"].(map[string]interface{})["template"].(map[string]interface{})["spec"].(map[string]interface{})
	if _, present := rendered["networks"]; present {
		t.Fatal("empty networks list must not be persisted in the VM create request")
	}
	devices := rendered["domain"].(map[string]interface{})["devices"].(map[string]interface{})
	if devices["autoattachPodInterface"] != false {
		t.Fatal("an explicit empty mapping must disable KubeVirt's default pod interface")
	}
}

func TestFreshRenderDisablesImplicitNetworksButPreservesMappedInterfaces(t *testing.T) {
	for _, networkType := range []string{"pod", "multus"} {
		t.Run(networkType, func(t *testing.T) {
			req := restoreFixture(t)
			captured := capturedFixture()
			capturedGuest := captured["spec"].(map[string]interface{})["template"].(map[string]interface{})["spec"].(map[string]interface{})
			capturedDevices := capturedGuest["domain"].(map[string]interface{})["devices"].(map[string]interface{})
			binding := "masquerade"
			if networkType == "multus" {
				req.Target.Networks[0] = models.KubeVirtRestoreNetwork{Name: "default", Type: "multus", NetworkName: "restored-nad"}
				capturedGuest["networks"] = []interface{}{map[string]interface{}{"name": "default", "multus": map[string]interface{}{"networkName": "source-nad"}}}
				capturedDevices["interfaces"] = []interface{}{map[string]interface{}{"name": "default", "bridge": map[string]interface{}{}}}
				binding = "bridge"
			}
			bundle, _, err := ValidatePlan(req)
			if err != nil {
				t.Fatal(err)
			}
			capturedDevices["autoattachPodInterface"] = true
			vm, err := RenderVM(captured, req.Target, bundle.Members[0].Request.Plan.Source)
			if err != nil {
				t.Fatal(err)
			}
			guest := vm["spec"].(map[string]interface{})["template"].(map[string]interface{})["spec"].(map[string]interface{})
			devices := guest["domain"].(map[string]interface{})["devices"].(map[string]interface{})
			if devices["autoattachPodInterface"] != false {
				t.Fatal("restore must not inherit implicit network attachment")
			}
			interfaces := devices["interfaces"].([]interface{})
			if len(interfaces) != 1 || interfaces[0].(map[string]interface{})["name"] != "default" || interfaces[0].(map[string]interface{})[binding] == nil {
				t.Fatal("explicitly mapped interface was lost", interfaces)
			}
			if capturedDevices["autoattachPodInterface"] != true {
				t.Fatal("source attachment policy mutated")
			}
		})
	}
}

func TestFreshPlanRefusals(t *testing.T) {
	for _, problem := range []string{"tenant", "agent", "source-vm", "source-pvc", "other-source-pvc", "duplicate-pvc", "partial", "small", "mode", "extra-network", "cross-namespace-network", "credentials"} {
		t.Run(problem, func(t *testing.T) {
			req := restoreFixture(t)
			switch problem {
			case "tenant":
				req.OrgID = "other"
			case "agent":
				req.AgentID = "other"
			case "source-vm":
				req.Target.VMName = "vm"
			case "source-pvc":
				req.Target.Disks[0].PVCName = "pvc"
			case "other-source-pvc":
				req.Target.Disks[0].PVCName = "extra-source"
			case "duplicate-pvc":
				req.Target.Disks[1].PVCName = req.Target.Disks[0].PVCName
			case "partial":
				req.Target.Disks = req.Target.Disks[:1]
			case "small":
				req.Target.Disks[0].CapacityBytes = 1
			case "mode":
				req.Target.Disks[0].VolumeMode = "guess"
			case "extra-network":
				req.Target.Networks = append(req.Target.Networks, req.Target.Networks[0])
			case "cross-namespace-network":
				req.Target.Networks[0] = models.KubeVirtRestoreNetwork{Name: "default", Type: "multus", NetworkName: "other/net"}
			case "credentials":
				req.S3.Bucket = "other"
			}
			if _, _, err := ValidatePlan(req); err == nil {
				t.Fatal("invalid plan admitted")
			}
		})
	}
}

func TestCapturedDependenciesAndUnsupportedState(t *testing.T) {
	req := restoreFixture(t)
	bundle, _, _ := ValidatePlan(req)
	for _, problem := range []string{"instancetype", "unprotected-disk", "network", "dependency", "host-device", "tpm"} {
		t.Run(problem, func(t *testing.T) {
			vm := capturedFixture()
			spec := vm["spec"].(map[string]interface{})
			guest := spec["template"].(map[string]interface{})["spec"].(map[string]interface{})
			devices := guest["domain"].(map[string]interface{})["devices"].(map[string]interface{})
			switch problem {
			case "instancetype":
				spec["instancetype"] = map[string]interface{}{"name": "shared"}
			case "unprotected-disk":
				guest["volumes"] = append(guest["volumes"].([]interface{}), map[string]interface{}{"name": "unprotected", "persistentVolumeClaim": map[string]interface{}{"claimName": "old"}})
			case "network":
				guest["networks"] = []interface{}{map[string]interface{}{"name": "other", "pod": map[string]interface{}{}}}
			case "dependency":
				guest["volumes"] = append(guest["volumes"].([]interface{}), map[string]interface{}{"name": "init", "cloudInitNoCloud": map[string]interface{}{"secretRef": map[string]interface{}{"name": "old-secret"}}})
			case "host-device":
				devices["hostDevices"] = []interface{}{map[string]interface{}{"name": "gpu"}}
			case "tpm":
				devices["tpm"] = map[string]interface{}{"persistent": true}
			}
			if _, err := RenderVM(vm, req.Target, bundle.Members[0].Request.Plan.Source); err == nil {
				t.Fatal("unsupported capture admitted")
			}
		})
	}
}
