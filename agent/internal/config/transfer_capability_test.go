package config

import (
	"testing"
	"vnbui/agent/internal/models"
)

func TestKubevirtTransferCapabilityIsProviderSpecific(t *testing.T) {
	native := (&Config{Provider: "libvirt"}).CapabilityReport()
	if _, found := native["kubevirt_transfer_profiles"]; found {
		t.Fatal("native advertised KubeVirt wire")
	}
	if _, found := native["kubevirt_native_disk_profiles"]; found {
		t.Fatal("native advertised KubeVirt native-disk selection")
	}
	if _, found := native["kubevirt_restore_profiles"]; found {
		t.Fatal("native advertised KubeVirt selected-disk restore")
	}
	pull := (&Config{Provider: "kubevirt"}).CapabilityReport()
	restoreProfiles, ok := pull["kubevirt_restore_profiles"].([]string)
	if !ok || len(restoreProfiles) != 1 || restoreProfiles[0] != models.KubeVirtSelectedDiskRestore {
		t.Fatal("missing negotiated selected-disk restore profile")
	}
	nativeProfiles, ok := pull["kubevirt_native_disk_profiles"].([]string)
	if !ok || len(nativeProfiles) != 1 || nativeProfiles[0] != models.KubevirtNativeDisks {
		t.Fatal("missing negotiated native-disk profile")
	}
	profiles, ok := pull["kubevirt_transfer_profiles"].([]string)
	if !ok || len(profiles) != 1 || profiles[0] != models.KubevirtTransfer32 {
		t.Fatal("missing negotiated transfer profile")
	}
}
