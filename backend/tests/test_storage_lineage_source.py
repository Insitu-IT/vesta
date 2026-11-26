"""Stable KubeVirt chain identity across a running VMI replacement."""

from copy import deepcopy

from core.storage_lineage import stable_source


def source(*, vmi_uid="old-vmi", vm_uid="stable-vm", pvc_uid="stable-pvc"):
    return {
        "vm_uid": vm_uid,
        "vmi_uid": vmi_uid,
        "volumes": [
            {
                "name": "data",
                "pvc_uid": pvc_uid,
                "pvc_resource_version": "123",
                "capacity_bytes": 268435456,
            }
        ],
    }


def test_vmi_restart_is_not_a_new_chain_source():
    original = source()
    snapshot = deepcopy(original)
    restarted = source(vmi_uid="replacement-vmi")
    restarted["volumes"][0]["pvc_resource_version"] = "456"

    assert stable_source(original) == stable_source(restarted)
    assert original == snapshot


def test_vm_or_pvc_replacement_is_a_new_chain_source():
    original = stable_source(source())

    assert stable_source(source(vm_uid="replacement-vm")) != original
    assert stable_source(source(pvc_uid="replacement-pvc")) != original
