"""Fresh Vesta names and retained legacy names must work through real kit paths."""

import base64
import copy
import json
import shutil
import subprocess
import sys

import pytest
import yaml

from backend.tests.test_portable_okd import ROOT, renderer, sample_config
from backend.tests.test_reconfigure import Cluster, proposal, reconfigure
from backend.tests.test_installation_tools import diagnostics, pg_config, postgres
from backend.tests.test_product_appearance import appearance, manifest, write_pack
from backend.tests.test_license_key_projection import license_keys


@pytest.fixture
def fresh():
    # Read the delivered new-customer entry point, not a synthetic prefix fixture.
    value = json.loads((ROOT / "packaging/okd/config.example.json").read_text())
    assert (value["namespace"], value["agent_namespace"], value["resource_prefix"]) == (
        "vesta",
        "vesta-agent",
        "vesta",
    )
    value["images"] = sample_config()["images"]
    value["journal_storage_class"] = "journal-csi"
    value["scratch_storage_class"] = "scratch-csi"
    return value


def indexed(items):
    return {
        (x["kind"], x["metadata"]["namespace"], x["metadata"]["name"]): x for x in items
    }


def env_of(deployment):
    return {
        x["name"]: x.get("value")
        for x in deployment["spec"]["template"]["spec"]["containers"][0]["env"]
    }


def test_fresh_names_and_local_references_agree_across_stages(fresh):
    items = [
        x
        for stage in renderer.STAGES
        for x in renderer.render(fresh, stage, structural=True)["items"]
    ]
    objects = indexed(items)
    assert all(x["metadata"]["name"].startswith("vesta-") for x in items)
    assert all(
        x["metadata"]["labels"]["app.kubernetes.io/part-of"] == "vesta" for x in items
    )
    for item in items:
        kind, ns = item["kind"], item["metadata"]["namespace"]
        if kind == "Service":
            candidates = [
                x
                for x in items
                if x["kind"] == "Deployment" and x["metadata"]["namespace"] == ns
            ]
            assert any(
                all(
                    x["spec"]["template"]["metadata"]["labels"].get(k) == v
                    for k, v in item["spec"]["selector"].items()
                )
                for x in candidates
            )
        if kind == "Route":
            assert ("Service", ns, item["spec"]["to"]["name"]) in objects
        if kind == "RoleBinding":
            role = item["roleRef"]
            if role["kind"] == "Role":
                assert ("Role", ns, role["name"]) in objects
            for subject in item.get("subjects", []):
                if subject["kind"] == "ServiceAccount":
                    assert (
                        "ServiceAccount",
                        subject["namespace"],
                        subject["name"],
                    ) in objects
        if kind not in {"Deployment", "Job"}:
            continue
        template = item["spec"]["template"]
        pod = template["spec"]
        if pod.get("serviceAccountName"):
            assert ("ServiceAccount", ns, pod["serviceAccountName"]) in objects
        if kind == "Deployment":
            assert all(
                template["metadata"]["labels"].get(k) == v
                for k, v in item["spec"]["selector"]["matchLabels"].items()
            )
        for volume in pod.get("volumes", []):
            for key, resource, field in (
                ("configMap", "ConfigMap", "name"),
                ("persistentVolumeClaim", "PersistentVolumeClaim", "claimName"),
            ):
                if key in volume:
                    assert (resource, ns, volume[key][field]) in objects
    for component, ns in (
        ("backend", fresh["namespace"]),
        ("agent", fresh["agent_namespace"]),
    ):
        env = env_of(objects[("Deployment", ns, "vesta-" + component)])
        assert env["KUBEVIRT_RESOURCE_PREFIX"] == "vesta"
    agent_env = env_of(objects[("Deployment", fresh["agent_namespace"], "vesta-agent")])
    assert agent_env["AGENT_IP_ADDRESS"] == "vesta-agent.vesta-agent.svc"
    assert agent_env["KUBEVIRT_BACKUP_SCRATCH_PVC"] == "vesta-scratch"
    scope = json.loads(
        objects[("ConfigMap", fresh["agent_namespace"], "vesta-agent-scope")]["data"][
            "policy.json"
        ]
    )
    assert set(scope["scratch_pvcs"].values()) == {"vesta-scratch"}
    nginx = objects[("ConfigMap", fresh["namespace"], "vesta-frontend")]["data"][
        "nginx.conf"
    ]
    assert "https://vesta-backend.vesta.svc:8000" in nginx


@pytest.mark.parametrize("mode", ["fresh", "legacy-omitted", "legacy-explicit"])
@pytest.mark.parametrize("stage", renderer.STAGES)
def test_actual_kustomize_matches_render_for_both_naming_families(
    fresh, mode, stage, tmp_path
):
    oc = shutil.which("oc")
    assert oc, "oc is required for actual offline Kustomize parity"
    config = fresh if mode == "fresh" else sample_config()
    if mode == "legacy-explicit":
        config["resource_prefix"] = "vnbui"
    if stage in {"upgrade", "rollback-schema"}:
        config["upgrade_installation_id"] = "10111111-1111-4111-8111-111111111111"
    destination = tmp_path / stage
    renderer.write_kustomize(config, stage, destination)
    output = subprocess.check_output([oc, "kustomize", str(destination)], text=True)
    assert indexed(yaml.safe_load_all(output)) == indexed(
        renderer.render(config, stage)["items"]
    )


def test_retained_57_fixture_omission_and_explicit_legacy_are_identical():
    legacy = sample_config()
    assert "resource_prefix" not in legacy
    explicit = {**legacy, "resource_prefix": "vnbui"}
    for stage in renderer.STAGES:
        actual = renderer.render(legacy, stage)
        assert actual == renderer.render(explicit, stage)
        assert all(x["metadata"]["name"].startswith("vnbui-") for x in actual["items"])
    # An explicit default must not change runtime env or force a rollout.
    assert "KUBEVIRT_RESOURCE_PREFIX" not in env_of(
        next(
            x
            for x in renderer.render(legacy, "api")["items"]
            if x["kind"] == "Deployment" and x["metadata"]["name"] == "vnbui-backend"
        )
    )


@pytest.mark.parametrize("prefix", [None, "", "Vesta", "custom", 1, True, [], {}])
def test_invalid_prefix_refuses_render(fresh, prefix):
    fresh["resource_prefix"] = prefix
    with pytest.raises(ValueError, match="resource_prefix"):
        renderer.render(fresh, "api")


def test_reconfiguration_keeps_effective_installed_prefix(fresh):
    legacy = sample_config()
    proposed = proposal(legacy)
    proposed["resource_prefix"] = "vnbui"
    reconfigure.changed(
        legacy, proposed
    )  # Legitimate hostname change plus explicit legacy default.
    with pytest.raises(ValueError, match="No configuration changes"):
        reconfigure.changed(legacy, {**legacy, "resource_prefix": "vnbui"})
    for old, new in (
        (legacy, {**proposed, "resource_prefix": "vesta"}),
        (fresh, {**proposal(fresh), "resource_prefix": "vnbui"}),
    ):
        with pytest.raises(ValueError, match="resource_prefix"):
            reconfigure.changed(old, new)


def test_vesta_hostname_redirect_and_new_restore_account_plan(
    fresh, tmp_path, monkeypatch
):
    target = next(
        x
        for x in renderer.render(fresh, "api")["items"]
        if x["kind"] == "Deployment" and x["metadata"]["name"] == "vesta-backend"
    )
    target["spec"]["template"]["spec"]["containers"][0]["env"].append(
        {"name": "FRONTEND_URL", "value": "https://" + fresh["ui_host"] + "/"}
    )
    proposed = proposal(fresh)
    reconfigure.update_frontend_redirect(target, fresh, proposed)
    assert env_of(target)["FRONTEND_URL"] == "https://" + proposed["ui_host"] + "/"
    live = Cluster(fresh)
    monkeypatch.setattr(reconfigure, "get", live.get)
    monkeypatch.setattr(reconfigure, "call", lambda *a, **kw: "")
    monkeypatch.setattr(reconfigure.reconcile_inputs, "source_versions", lambda *a: {})
    expanded = copy.deepcopy(fresh)
    expanded["restore_namespaces"].append("fresh-restore")
    state = reconfigure.plan(fresh, expanded, tmp_path / "transaction", "oc")
    accounts = [x for x in state["changes"] if x["desired"]["kind"] == "ServiceAccount"]
    assert len(accounts) == 1
    assert reconfigure.key(accounts[0]["desired"]) == (
        "ServiceAccount",
        "fresh-restore",
        "vesta-restore-worker",
    )
    assert accounts[0]["uid"] is None and accounts[0]["before"] is None
    assert not live.calls


@pytest.mark.parametrize("prefix", ["vesta", "vnbui"])
def test_postgres_names_mounts_service_and_network_policy_agree(fresh, prefix):
    fresh["resource_prefix"] = prefix
    objects = indexed(postgres.render(fresh, pg_config())["items"])
    ns = fresh["namespace"]
    stateful = objects[("StatefulSet", ns, prefix + "-postgres")]
    service = objects[("Service", ns, stateful["spec"]["serviceName"])]
    labels = stateful["spec"]["template"]["metadata"]["labels"]
    assert all(labels.get(k) == v for k, v in service["spec"]["selector"].items())
    for volume in stateful["spec"]["template"]["spec"]["volumes"]:
        for key, kind, field in (
            ("configMap", "ConfigMap", "name"),
            ("persistentVolumeClaim", "PersistentVolumeClaim", "claimName"),
        ):
            if key in volume:
                assert (kind, ns, volume[key][field]) in objects
    policy = objects[("NetworkPolicy", ns, prefix + "-postgres")]["spec"]
    assert all(
        labels.get(k) == v for k, v in policy["podSelector"]["matchLabels"].items()
    )
    allowed = {
        entry["podSelector"]["matchLabels"]["app"]
        for rule in policy["ingress"]
        for entry in rule["from"]
    }
    assert allowed == {prefix + "-backend", prefix + "-migration"}
    assert all(
        x["metadata"]["labels"]["app.kubernetes.io/part-of"] == prefix
        for x in objects.values()
    )


@pytest.mark.parametrize("prefix", ["vesta", "vnbui"])
def test_diagnostics_queries_actual_agent_all_sources_and_restore_once(
    fresh, prefix, monkeypatch
):
    fresh.update(
        resource_prefix=prefix,
        source_namespaces=["source-a", "source-b"],
        selected_namespaces=[],
        restore_namespaces=["source-b", "restore-only"],
    )
    calls = []

    def query(argv, **kwargs):
        calls.append(argv)
        return {"items": []}

    monkeypatch.setattr(diagnostics, "query", query)
    result = diagnostics.collect(fresh)
    expected = {
        fresh["namespace"],
        fresh["agent_namespace"],
        "source-a",
        "source-b",
        "restore-only",
    }
    assert {x["namespace"] for x in result["sections"]} == expected
    assert len(calls) == len(expected) * 5
    assert all(
        argv[argv.index("-l") + 1] == "app.kubernetes.io/part-of=" + prefix
        for argv in calls
    )
    assert all("secrets" not in argv for argv in calls)
    assert not result["partial"]


@pytest.mark.parametrize(
    "option,prefix", [(None, "vesta"), ("vesta", "vesta"), ("vnbui", "vnbui")]
)
def test_optional_resource_helpers_default_and_explicit_cli_names(
    tmp_path, option, prefix
):
    pack = write_pack(tmp_path, manifest())
    trust = {
        "schema_version": 1,
        "keys": {"issuer": base64.b64encode(bytes(range(32))).decode()},
    }
    resource, projection = appearance.prepare(
        pack, None, "site-app", *([option] if option else [])
    )
    assert resource["metadata"]["name"] == projection["config_map"]
    assert resource["metadata"]["name"].startswith(prefix + "-appearance-")
    keys = tmp_path / "public.json"
    keys.write_text(json.dumps(trust))
    args = ["--resource-prefix", option] if option else []
    output = tmp_path / "trust"
    subprocess.run(
        [
            sys.executable,
            str(ROOT / "packaging/okd/license_keys.py"),
            "--public-keys",
            str(keys),
            "--namespace",
            "site-app",
            "--out",
            str(output),
            *args,
        ],
        check=True,
        capture_output=True,
    )
    generated = json.loads((output / "configmap.json").read_text())
    direct, projected = license_keys.prepare(
        trust, "site-app", *([option] if option else [])
    )
    assert generated == direct
    assert direct["metadata"]["name"] == projected["config_map"]
    assert direct["metadata"]["name"].startswith(prefix + "-license-keys-")
    appearance_output, projection_output = (
        tmp_path / "appearance.json",
        tmp_path / "projection.json",
    )
    subprocess.run(
        [
            sys.executable,
            str(ROOT / "packaging/okd/appearance.py"),
            "--active",
            str(pack),
            "--namespace",
            "site-app",
            "--output",
            str(appearance_output),
            "--projection-output",
            str(projection_output),
            *args,
        ],
        check=True,
        capture_output=True,
    )
    assert json.loads(appearance_output.read_text()) == resource
    assert json.loads(projection_output.read_text()) == projection


def test_optional_projections_attach_to_fresh_vesta_workloads(fresh, tmp_path):
    pack = write_pack(tmp_path, manifest())
    appearance_resource, fresh["appearance"] = appearance.prepare(
        pack, None, fresh["namespace"]
    )
    trust = {
        "schema_version": 1,
        "keys": {"issuer": base64.b64encode(bytes(range(32))).decode()},
    }
    trust_resource, fresh["licensing"] = license_keys.prepare(trust, fresh["namespace"])
    objects = indexed(renderer.render(fresh, "api")["items"])
    for component in ("frontend", "backend"):
        pod = objects[("Deployment", fresh["namespace"], "vesta-" + component)]["spec"][
            "template"
        ]["spec"]
        config_maps = {
            v["configMap"]["name"] for v in pod["volumes"] if "configMap" in v
        }
        assert appearance_resource["metadata"]["name"] in config_maps
        if component == "backend":
            assert trust_resource["metadata"]["name"] in config_maps
            assert (
                env_of(objects[("Deployment", fresh["namespace"], "vesta-backend")])[
                    "LICENSE_KEYS_FILE"
                ]
                == "/etc/vnbui/license-keys.json"
            )
        else:
            assert trust_resource["metadata"]["name"] not in config_maps
