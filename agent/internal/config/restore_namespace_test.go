package config

import (
	"reflect"
	"testing"
)

func TestRestoreNamespacesRequireIndependentInstallationConfiguration(t *testing.T) {
	t.Setenv("KUBE_NAMESPACE", "source")
	t.Setenv("KUBEVIRT_RESTORE_NAMESPACES", "")
	if got := Load().KubevirtRestoreNamespaces; len(got) != 0 {
		t.Fatalf("backup namespace implicitly authorized restore destinations: %v", got)
	}
	t.Setenv("KUBEVIRT_RESTORE_NAMESPACES", "source,recovery")
	if got := Load().KubevirtRestoreNamespaces; !reflect.DeepEqual(got, []string{"source", "recovery"}) {
		t.Fatalf("explicit restore namespace list lost: %v", got)
	}
	if UIConfigurableSettings["kubevirt_restore_namespaces"] {
		t.Fatal("heartbeat settings may not expand installation restore scope")
	}
}
