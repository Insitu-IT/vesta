"""Transfer changes render and use the existing reconfiguration transaction."""

from copy import deepcopy

import pytest

from backend.tests.test_portable_okd import renderer, sample_config
from backend.tests.test_reconfigure import reconfigure, Cluster


def environment(config, stage):
    item = next(
        x for x in renderer.render(config, stage)["items"] if x["kind"] == "Deployment"
    )
    return {
        x["name"]: x.get("value")
        for x in item["spec"]["template"]["spec"]["containers"][0]["env"]
    }


def test_transfer_defaults_preserve_api_budget_and_negotiate_new_profile():
    config = sample_config()
    agent = environment(config, "agent")
    assert (agent["KUBE_API_QPS"], agent["KUBE_API_BURST"]) == ("50", "100")
    assert environment(config, "api")["KUBEVIRT_TRANSFER_PROFILE"] == "kubevirt-32m/1"


@pytest.mark.parametrize(
    "field,value",
    [
        ("kube_api_qps", True),
        ("kube_api_qps", 0),
        ("kube_api_qps", 201),
        ("kube_api_qps", "100"),
        ("kube_api_burst", False),
        ("kube_api_burst", 49),
        ("kube_api_burst", 401),
        ("kubevirt_transfer_profile", "unknown"),
        ("kubevirt_transfer_profile", None),
        ("kubevirt_transfer_profile", []),
    ],
)
def test_invalid_transfer_settings_refuse_before_render(field, value):
    config = sample_config()
    config[field] = value
    with pytest.raises(ValueError, match="kube"):
        renderer.validate(config)


def test_transfer_changes_are_reconfiguration_inputs():
    old = sample_config()
    new = deepcopy(old)
    new.update(kube_api_qps=100, kube_api_burst=200, kubevirt_transfer_profile="legacy")
    reconfigure.changed(old, new)
    assert environment(new, "agent")["KUBE_API_QPS"] == "100"
    assert environment(new, "agent")["KUBE_API_BURST"] == "200"
    assert environment(new, "api")["KUBEVIRT_TRANSFER_PROFILE"] == "legacy"
    # Only backend and agent workloads receive changed settings. The renderer
    # retains database, credential, namespace and storage object identities.
    previous = Cluster(old).items
    proposed = Cluster(new).items
    changed = []
    for key in previous:
        before, after = deepcopy(previous[key]), deepcopy(proposed[key])
        for item in (before, after):
            item["metadata"].pop("resourceVersion", None)
            item["metadata"].pop("uid", None)
        if before != after:
            changed.append(key)
    assert {(kind, name) for kind, _, name in changed} == {
        ("Deployment", "vnbui-backend"),
        ("Deployment", "vnbui-agent"),
    }
