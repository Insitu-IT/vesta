"""The portable renderer is offline and cannot smuggle owner credentials into APIs."""

import importlib.util
import json
from pathlib import Path
import shutil
import subprocess

import pytest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location(
    "okd_render", ROOT / "packaging/okd/render.py"
)
renderer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(renderer)


def sample_config():
    c = json.loads(
        (ROOT / "backend/tests/fixtures/okd-site-customized.json").read_text()
    )
    # Exercise backward-compatible old site files throughout existing tests.
    for optional in (
        "agent_namespace",
        "source_namespaces",
        "selected_namespaces",
        "agent_id",
        "agent_display_name",
    ):
        c.pop(optional, None)
    c["images"] = {
        component: f"registry.test/{component}@sha256:" + "a" * 64
        for component in ("backend", "frontend", "agent")
    }
    c["journal_storage_class"] = "journal-csi"
    c["scratch_storage_class"] = "scratch-csi"
    return c


@pytest.fixture
def config():
    return sample_config()


@pytest.fixture
def oc_binary():
    binary = shutil.which("oc")
    assert (
        binary
    ), "oc is required for offline Kustomize parity; install the pinned CI client"
    return binary


def test_kustomize_parity_refuses_missing_client(monkeypatch):
    monkeypatch.setattr(shutil, "which", lambda name: None)
    with pytest.raises(AssertionError, match="oc is required"):
        oc_binary.__wrapped__()


def test_stages_do_not_start_workloads_with_owner_credential(config):
    migration = renderer.render(config, "migrate")["items"]
    assert [obj["kind"] for obj in migration] == ["Job"]
    assert "vnbui-db-owner" in json.dumps(migration)
    assert (
        "--fresh"
        in migration[0]["spec"]["template"]["spec"]["containers"][0]["command"]
    )
    api = renderer.render(config, "api")["items"]
    assert "vnbui-db-owner" not in json.dumps(api)
    assert "vnbui-db-runtime" in json.dumps(api)
    assert all(obj["kind"] not in {"Secret", "Job"} for obj in api)
    workloads = [obj for obj in api if obj["kind"] == "Deployment"]
    assert all(
        not obj["spec"]["template"]["spec"]["automountServiceAccountToken"]
        for obj in workloads
    )
    backend = next(
        obj for obj in workloads if obj["metadata"]["name"] == "vnbui-backend"
    )
    env = {
        v["name"]: v.get("value")
        for v in backend["spec"]["template"]["spec"]["containers"][0]["env"]
    }
    assert (
        env["USE_REAL_BACKUP_EXECUTOR"]
        == env["AGENT_VERIFY_SSL"]
        == env["ENABLE_ENCRYPTION"]
        == "true"
    )
    assert env["METRICS_ENABLED"] == "false"
    assert env["STORAGE_CAPABILITY_PROFILE"] == "db-rooted-consumer-verified/1"


@pytest.mark.parametrize(
    "ttl,timeout", [(None, None), (36000, 0), (64800, 0), (259200, 86400)]
)
def test_native_lifetime_settings_are_validated_and_rendered(config, ttl, timeout):
    if ttl is None:
        config.pop("kubevirt_native_backup_ttl_seconds", None)
        config.pop("kubevirt_transaction_timeout_seconds", None)
        ttl, timeout = 36000, 0
    else:
        config["kubevirt_native_backup_ttl_seconds"] = ttl
        config["kubevirt_transaction_timeout_seconds"] = timeout
    renderer.validate(config)
    deployment = next(
        x
        for x in renderer.render(config, "agent")["items"]
        if x["kind"] == "Deployment"
    )
    env = {
        v["name"]: v.get("value")
        for v in deployment["spec"]["template"]["spec"]["containers"][0]["env"]
    }
    assert env["KUBEVIRT_NATIVE_BACKUP_TTL_SECONDS"] == str(ttl)
    assert env["KUBEVIRT_TRANSACTION_TIMEOUT_SECONDS"] == str(timeout)


@pytest.mark.parametrize(
    "ttl,timeout",
    [
        (True, 0),
        (0, 0),
        (3599, 0),
        (2592001, 0),
        (64800, -1),
        (64800, 64801),
        (64800, False),
    ],
)
def test_native_lifetime_invalid_policy_refuses_render(config, ttl, timeout):
    config["kubevirt_native_backup_ttl_seconds"] = ttl
    config["kubevirt_transaction_timeout_seconds"] = timeout
    with pytest.raises(ValueError, match="kubevirt_.*seconds"):
        renderer.validate(config)


def test_restored_grants_are_separate_from_fresh_migration(config):
    (job,) = renderer.render(config, "restore-grants")["items"]
    command = job["spec"]["template"]["spec"]["containers"][0]["command"]
    assert "--restored" in command and "--fresh" not in command


@pytest.mark.parametrize(
    "stage,flag",
    [
        ("upgrade", "--upgrade-operation-safety"),
        ("rollback-schema", "--rollback-operation-safety"),
    ],
)
def test_reviewed_schema_transition_uses_only_owner_job(config, stage, flag):
    (job,) = renderer.render(config, stage)["items"]
    assert job["kind"] == "Job" and job["spec"]["backoffLimit"] == 0
    container = job["spec"]["template"]["spec"]["containers"][0]
    assert flag in container["command"] and "--fresh" not in container["command"]
    database = next(item for item in container["env"] if item["name"] == "DATABASE_URL")
    assert (
        database["valueFrom"]["secretKeyRef"]["name"]
        == config["secrets"]["database_owner"]
    )


@pytest.mark.parametrize("stage", renderer.STAGES)
def test_kustomize_target_matches_reviewed_stage(config, stage, tmp_path, oc_binary):
    config["namespace"] = "site-app"
    config["vm_namespace"] = "site-vms"
    config["api_host"] = "api.site.example"
    config["ui_host"] = "ui.site.example"
    config["secrets"] = {
        key: value + "-site" for key, value in config["secrets"].items()
    }
    config["database"] = "site_db"
    config["runtime_role"] = "site_runtime"
    config["admin_username"] = "site-admin"
    config["journal_size"] = "2Gi"
    config["scratch_size"] = "128Gi"
    config["resources"]["backend"]["requests"]["cpu"] = "300m"
    target = tmp_path / stage
    renderer.write_kustomize(config, stage, target)
    assert "resources:\n  - base\n" in (target / "kustomization.yaml").read_text()
    expected = renderer.render(config, stage)["items"]
    base = renderer.render(renderer.base_config(), stage)["items"]
    for index, (before, after) in enumerate(zip(base, expected)):
        assert (
            json.loads(
                (target / "base" / renderer.resource_name(index, before)).read_text()
            )
            == before
        )
        patch_name = (
            renderer.resource_name(index, before).removesuffix(".json") + ".patch.json"
        )
        if (target / patch_name).exists():
            ops = json.loads((target / patch_name).read_text())
            assert ops == renderer.replacement_ops(before, after)
        else:
            assert before == after
    import yaml

    actual = list(
        yaml.safe_load_all(
            subprocess.check_output([oc_binary, "kustomize", str(target)], text=True)
        )
    )

    def identity(obj):
        return (obj["kind"], obj["metadata"]["name"])

    assert {identity(obj): obj for obj in actual} == {
        identity(obj): obj for obj in expected
    }
    assert not any(item["kind"] == "Secret" for item in expected)
    with pytest.raises(ValueError, match="already exists"):
        renderer.write_kustomize(config, stage, target)


@pytest.mark.parametrize("stage", renderer.STAGES)
def test_checked_in_base_matches_renderer(stage, tmp_path):
    generated = tmp_path / stage
    renderer.write_base_stage(stage, generated)
    checked_in = renderer.BASE_ROOT / stage
    assert {p.name: p.read_bytes() for p in generated.iterdir()} == {
        p.name: p.read_bytes() for p in checked_in.iterdir()
    }


def test_portable_public_listener_can_disable_metrics(monkeypatch):
    import asyncio
    from fastapi import HTTPException
    from routers.public import prometheus_metrics

    monkeypatch.setenv("METRICS_ENABLED", "false")
    with pytest.raises(HTTPException) as refused:
        asyncio.run(prometheus_metrics())
    assert refused.value.status_code == 404


def test_routes_preserve_backend_tls_and_nginx_verifies(config):
    items = renderer.render(config, "api")["items"]
    routes = {r["metadata"]["name"]: r for r in items if r["kind"] == "Route"}
    assert routes["vnbui-backend"]["spec"]["tls"]["termination"] == "passthrough"
    assert routes["vnbui-frontend"]["spec"]["tls"]["termination"] == "edge"
    nginx = renderer.nginx(config)
    assert "proxy_ssl_verify on" in nginx
    assert "registry.test" not in nginx
    assert "X-Client-Cert" not in nginx


def test_agent_has_bounded_rbac_and_durable_custody(config):
    items = renderer.render(config, "agent")["items"]
    assert all(obj["metadata"]["namespace"] == config["vm_namespace"] for obj in items)
    assert not any(
        obj["kind"] in {"ClusterRole", "ClusterRoleBinding", "Secret"} for obj in items
    )
    role = next(obj for obj in items if obj["kind"] == "Role")
    assert '"*"' not in json.dumps(role)
    deployment = next(obj for obj in items if obj["kind"] == "Deployment")
    assert deployment["spec"]["strategy"] == {"type": "Recreate"}
    assert deployment["spec"]["replicas"] == 1
    agent = deployment["spec"]["template"]["spec"]["containers"][0]
    env = {v["name"]: v.get("value") for v in agent["env"]}
    assert env["KUBEVIRT_RESTORE_IMAGE"] == config["images"]["agent"]
    assert env["KUBE_NAMESPACE"] == config["vm_namespace"]
    assert env["KEY_FILE_PATH"].startswith("/var/lib/vnbui/")
    assert agent["securityContext"]["readOnlyRootFilesystem"] is True


def test_agent_stage_can_be_rendered_for_separate_vm_namespaces(config):
    first = renderer.render(config, "agent")["items"]
    other = {
        **config,
        "vm_namespace": "other-protected-vms",
        "restore_namespaces": ["other-protected-vms"],
    }
    second = renderer.render(other, "agent")["items"]
    assert all(
        item["metadata"]["namespace"] == config["vm_namespace"] for item in first
    )
    assert all(
        item["metadata"]["namespace"] == other["vm_namespace"] for item in second
    )
    first_names = {(item["kind"], item["metadata"]["name"]) for item in first}
    second_names = {(item["kind"], item["metadata"]["name"]) for item in second}
    # All product names are stable except the source-specific destination grant.
    assert first_names - second_names == {
        ("RoleBinding", "vnbui-restore-" + config["vm_namespace"])
    }
    assert second_names - first_names == {
        ("RoleBinding", "vnbui-restore-" + other["vm_namespace"])
    }
    assert not any(item["kind"] in {"Job", "Route", "Secret"} for item in second)
    agent = next(item for item in second if item["kind"] == "Deployment")
    env = {
        item["name"]: item.get("value")
        for item in agent["spec"]["template"]["spec"]["containers"][0]["env"]
    }
    assert env["KUBE_NAMESPACE"] == other["vm_namespace"]
    assert env["AGENT_IP_ADDRESS"] == "vnbui-agent.other-protected-vms.svc"


def test_mtls_mode_mounts_separate_peer_identities_and_trust(config, tmp_path):
    config["mtls"] = {
        "backend_client_ca": "backend-peer-ca",
        "backend_client_tls": "backend-peer-keypair",
        "agent_client_ca": "agent-peer-ca",
    }
    backend = next(
        item
        for item in renderer.render(config, "api")["items"]
        if item["kind"] == "Deployment" and item["metadata"]["name"] == "vnbui-backend"
    )
    agent = next(
        item
        for item in renderer.render(config, "agent")["items"]
        if item["kind"] == "Deployment" and item["metadata"]["name"] == "vnbui-agent"
    )
    backend_pod = backend["spec"]["template"]["spec"]
    agent_pod = agent["spec"]["template"]["spec"]
    backend_env = {
        item["name"]: item["value"]
        for item in backend_pod["containers"][0]["env"]
        if "value" in item
    }
    agent_env = {
        item["name"]: item["value"]
        for item in agent_pod["containers"][0]["env"]
        if "value" in item
    }
    assert backend_env["REQUIRE_MTLS"] == agent_env["TLS_VERIFY_CLIENT"] == "true"
    assert backend_env["BACKEND_TLS_CLIENT_CA_FILE"] == "/client-ca/ca.crt"
    # Site-issued serving certificates and enrolled callback identities may
    # have different issuers. Never reuse inbound client trust for this hop.
    assert backend_env["AGENT_CA_CERT"] == "/trust/ca.crt"
    assert backend_env["AGENT_VERIFY_SSL"] == "true"
    assert len(backend_pod["containers"][0]["env"]) == len(
        {entry["name"] for entry in backend_pod["containers"][0]["env"]}
    )
    trust_mount = next(
        entry for entry in backend_pod["volumes"] if entry["name"] == "trust"
    )
    assert trust_mount["secret"]["secretName"] == config["secrets"]["trust"]
    assert backend_env["ORCHESTRATOR_CLIENT_CERT"] == "/client-tls/tls.crt"
    assert agent_env["TLS_CA_FILE"] == "/trust/ca.crt"
    assert agent_env["TLS_CLIENT_CA_FILE"] == "/client-ca/ca.crt"
    assert agent_env["CALLBACK_CLIENT_CERT_FILE"] == "/var/lib/vnbui/certs/agent.crt"
    assert agent_env["CALLBACK_CLIENT_KEY_FILE"] == "/var/lib/vnbui/certs/agent.key"
    assert agent_env["TLS_CERT_FILE"] == "/tls/tls.crt"
    assert agent_pod["containers"][0]["readinessProbe"]["exec"]["command"] == [
        "/vnbui-agent",
        "-probe-ready",
    ]
    for pod, expected in (
        (backend_pod, {"backend-peer-ca", "backend-peer-keypair"}),
        (agent_pod, {"agent-peer-ca"}),
    ):
        mounted = {
            item["secret"]["secretName"] for item in pod["volumes"] if "secret" in item
        }
        assert expected <= mounted
    for stage in ("api", "agent"):
        target = tmp_path / stage
        renderer.write_kustomize(config, stage, target)
        assert (target / "kustomization.yaml").is_file()


def test_mtls_mode_requires_all_three_distinct_secret_names(config):
    config["mtls"] = {"agent_client_ca": "partial"}
    with pytest.raises(ValueError, match="three distinct"):
        renderer.render(config, "agent")


@pytest.mark.parametrize("collision", ["client-peer-ca", "vnbui-trust"])
def test_mtls_client_trust_cannot_alias_site_server_trust(config, collision):
    config["mtls"] = {
        "backend_client_ca": collision,
        "backend_client_tls": "client-peer-keypair",
        "agent_client_ca": "client-peer-ca",
    }
    assert config["secrets"]["trust"] == "vnbui-trust"
    with pytest.raises(ValueError, match="three distinct"):
        renderer.render(config, "api")


@pytest.mark.parametrize(
    "mutation",
    [
        lambda c: c["images"].update(agent="registry.test/agent:latest"),
        lambda c: c["secrets"].update(database_runtime=c["secrets"]["database_owner"]),
        lambda c: c.update(vm_namespace=""),
        lambda c: c.pop("restore_namespaces"),
        lambda c: c.update(restore_namespaces=[]),
        lambda c: c.update(restore_namespaces=["*"]),
        lambda c: c.update(restore_namespaces=["recovery", "recovery"]),
        lambda c: c.update(restore_namespaces=[f"recovery-{i}" for i in range(33)]),
        lambda c: c.update(api_host="api.test; injected"),
        lambda c: c.update(api_host=c["ui_host"]),
        lambda c: c.update(scratch_size="0Gi"),
        lambda c: c["resources"]["agent"].update(limits={"cpu": "0", "memory": "1Gi"}),
        lambda c: c.update(password="never in the config"),
        lambda c: c.update(mtls={"backend_client_ca": "invalid/path"}),
    ],
)
def test_invalid_configuration_is_rejected_before_any_output(config, mutation):
    mutation(config)
    with pytest.raises(ValueError):
        renderer.render(config, "api")


def test_restore_destinations_get_only_explicit_namespaced_authority(config):
    config["restore_namespaces"] = ["recovery-a", "recovery-b"]
    items = renderer.render(config, "agent")["items"]
    agent = next(i for i in items if i["kind"] == "Deployment")
    env = {
        i["name"]: i.get("value")
        for i in agent["spec"]["template"]["spec"]["containers"][0]["env"]
    }
    assert env["KUBE_NAMESPACE"] == config["vm_namespace"]
    assert env["KUBEVIRT_RESTORE_NAMESPACES"] == "recovery-a,recovery-b"
    for destination in config["restore_namespaces"]:
        scoped = [i for i in items if i["metadata"]["namespace"] == destination]
        assert sorted(i["kind"] for i in scoped) == [
            "Role",
            "RoleBinding",
            "RoleBinding",
            "ServiceAccount",
        ]
        role = next(i for i in scoped if i["kind"] == "Role")
        assert '"*"' not in json.dumps(role)
        assert not any("backup.kubevirt.io" in r["apiGroups"] for r in role["rules"])
        assert all(
            "delete" not in r["verbs"] or r["resources"] == ["secrets"]
            for r in role["rules"]
        )
        binding = next(
            i
            for i in scoped
            if i["kind"] == "RoleBinding"
            and i["metadata"]["name"] == "vnbui-restore-" + config["vm_namespace"]
        )
        assert binding["subjects"] == [
            {
                "kind": "ServiceAccount",
                "name": "vnbui-agent",
                "namespace": config["vm_namespace"],
            }
        ]
    source = next(
        i
        for i in items
        if i["kind"] == "Role" and i["metadata"]["name"] == "vnbui-agent"
    )
    assert not any("jobs" in r["resources"] for r in source["rules"])
    assert not any(
        "virtualmachines" in r["resources"] and "create" in r["verbs"]
        for r in source["rules"]
    )


def test_multi_namespace_kustomize_preserves_each_destination(
    config, tmp_path, oc_binary
):
    # Include the base's placeholder namespace as a later scope: a broad patch
    # selector must not accidentally retarget its worker account to the first.
    config["restore_namespaces"] = [
        "recovery",
        renderer.base_config()["vm_namespace"],
        "other-recovery",
    ]
    target = tmp_path / "multi"
    renderer.write_kustomize(config, "agent", target)
    assert (target / "site" / "kustomization.yaml").exists()
    import yaml

    actual = list(
        yaml.safe_load_all(
            subprocess.check_output([oc_binary, "kustomize", str(target)], text=True)
        )
    )
    expected = renderer.render(config, "agent")["items"]

    def identity(obj):
        return obj["kind"], obj["metadata"]["namespace"], obj["metadata"]["name"]

    assert {identity(i): i for i in actual} == {identity(i): i for i in expected}


def test_multi_namespace_scope_policy_rbac_scratch_and_stable_identity(
    config, tmp_path, oc_binary
):
    import yaml

    config.update(
        agent_namespace="agent-system",
        source_namespaces=["source-a", "source-b"],
        selected_namespaces=["source-b"],
        restore_namespaces=["restore-a"],
        agent_display_name="KubeVirt agent 1",
    )
    items = renderer.render(config, "agent")["items"]
    policy_cm = next(item for item in items if item["kind"] == "ConfigMap")
    assert policy_cm["metadata"]["namespace"] == "agent-system"
    policy = json.loads(policy_cm["data"]["policy.json"])
    assert policy == {
        "source_namespaces": ["source-a", "source-b"],
        "default_selected_namespaces": ["source-b"],
        "restore_namespaces": ["restore-a"],
        "scratch_pvcs": {"source-a": "vnbui-scratch", "source-b": "vnbui-scratch"},
    }
    deployment = next(item for item in items if item["kind"] == "Deployment")
    assert deployment["metadata"]["namespace"] == "agent-system"
    env = {
        item["name"]: item.get("value")
        for item in deployment["spec"]["template"]["spec"]["containers"][0]["env"]
    }
    assert env["HOSTNAME"] == "vnbui-kubevirt-" + config["vm_namespace"]
    assert env["AGENT_DISPLAY_NAME"] == "KubeVirt agent 1"
    assert env["KUBEVIRT_SCOPE_POLICY_FILE"] == "/scope/policy.json"
    assert {
        (item["metadata"]["namespace"], item["metadata"]["name"])
        for item in items
        if item["kind"] == "PersistentVolumeClaim"
    } == {
        ("agent-system", "vnbui-journal"),
        ("source-a", "vnbui-scratch"),
        ("source-b", "vnbui-scratch"),
    }
    for binding in (
        item
        for item in items
        if item["kind"] == "RoleBinding"
        and item["metadata"]["name"].startswith("vnbui-agent-")
    ):
        assert binding["metadata"]["namespace"] in {"source-a", "source-b"}
        assert binding["subjects"][0]["namespace"] == "agent-system"
    target = tmp_path / "agent"
    renderer.write_kustomize(config, "agent", target)
    actual = list(
        yaml.safe_load_all(
            subprocess.check_output([oc_binary, "kustomize", str(target)], text=True)
        )
    )

    def identity(item):
        return (item["kind"], item["metadata"]["namespace"], item["metadata"]["name"])

    assert {identity(i): i for i in actual} == {identity(i): i for i in items}


def test_explicit_empty_selection_protects_nothing(config):
    config.update(source_namespaces=["protected-vms"], selected_namespaces=[])
    items = renderer.render(config, "agent")["items"]
    policy = json.loads(
        next(i for i in items if i["kind"] == "ConfigMap")["data"]["policy.json"]
    )
    assert policy["default_selected_namespaces"] == []
    config["selected_namespaces"] = ["outside-ceiling"]
    with pytest.raises(ValueError, match="subset"):
        renderer.validate(config)


def test_new_source_ceiling_cannot_reach_application_credentials(config):
    config.update(source_namespaces=["protected-vms", config["namespace"]])
    with pytest.raises(ValueError, match="Application namespace must be separate"):
        renderer.validate(config)


@pytest.mark.parametrize(
    "aliases",
    [
        ["*"],
        ["https://alias.example.org"],
        ["a.example.org", "a.example.org"],
        ["backup.example.org"],
        ["backup-api.example.org"],
        [str(i) + ".example.org" for i in range(17)],
    ],
)
def test_ui_alias_origins_are_explicit_bounded_and_distinct(config, aliases):
    config["ui_aliases"] = aliases
    with pytest.raises(ValueError, match="ui_aliases"):
        renderer.validate(config)


def test_frontend_static_misses_are_404_and_api_keeps_tls(config):
    rendered = renderer.nginx(config)
    assert "location /assets/ { try_files $uri =404; }" in rendered
    assert "location /locales/ { try_files $uri =404; }" in rendered
    assert "location = /api { return 404; }" in rendered
    assert "location = /metrics { return 404; }" in rendered
    assert "location ^~ /metrics/ { return 404; }" in rendered
    assert r"location ~* \.map$ { return 404; }" in rendered
    assert "location / { try_files $uri $uri/ /index.html; }" in rendered
    # API paths win over the static extension regex, including API .js paths.
    assert rendered.index("location ~ ^/(api/|ws)") < rendered.index(
        r"location ~* \.map$"
    )
    assert "proxy_ssl_verify on" in rendered
    assert "proxy_ssl_trusted_certificate /trust/ca.crt" in rendered
    assert "location /docs" not in rendered


def test_installed_profile_defaults_and_explicit_commercial(config):
    config.pop("edition", None)
    config.pop("operating_profile", None)
    assert renderer.installed_profile(config) == {
        "edition": "community",
        "auth_mode": "single_organization",
        "enabled_modules": [],
    }
    config["edition"] = "commercial"
    with pytest.raises(ValueError, match="operating_profile"):
        renderer.validate(config)
    config["operating_profile"] = {
        "auth_mode": "multi_organization",
        "enabled_modules": ["multi_tenancy", "billing_api"],
    }
    renderer.validate(config)
    for stage in ("migrate", "restore-grants", "api"):
        items = renderer.render(config, stage)["items"]
        workload = next(item for item in items if item["kind"] in {"Job", "Deployment"})
        values = {
            item["name"]: item.get("value")
            for item in workload["spec"]["template"]["spec"]["containers"][0]["env"]
        }
        assert values["VESTA_EDITION"] == "commercial"
        assert values["VESTA_AUTH_MODE"] == "multi_organization"
        assert json.loads(values["VESTA_ENABLED_MODULES"]) == [
            "billing_api",
            "multi_tenancy",
        ]
        names = list(values)
        for setting in ("EDITION", "AUTH_MODE", "ENABLED_MODULES"):
            canonical = f"VESTA_{setting}"
            legacy = f"VNBUI_{setting}"
            assert values[legacy] == f"$({canonical})"
            assert names.index(legacy) == names.index(canonical) + 1


@pytest.mark.parametrize(
    "edition,profile",
    [
        ("unknown", {}),
        (True, {}),
        (
            "community",
            {"auth_mode": "multi_organization", "enabled_modules": ["multi_tenancy"]},
        ),
        (
            "commercial",
            {"auth_mode": "single_organization", "enabled_modules": ["multi_tenancy"]},
        ),
        ("commercial", {"auth_mode": "multi_organization", "enabled_modules": []}),
        (
            "commercial",
            {"auth_mode": "single_organization", "enabled_modules": ["unshipped"]},
        ),
        (
            "commercial",
            {
                "auth_mode": "single_organization",
                "enabled_modules": ["billing_api", "billing_api"],
            },
        ),
    ],
)
def test_installed_profile_refuses_invalid_or_unavailable_modules(
    config, edition, profile
):
    config["edition"], config["operating_profile"] = edition, profile
    with pytest.raises(ValueError):
        renderer.validate(config)


def test_operation_coefficients_and_probe_grants_are_portable(config):
    config["operation_budget"] = {"time_coefficient": 4, "scratch_coefficient": 1.3}
    renderer.validate(config)
    objects = renderer.render(config, "agent")["items"]
    deployment = next(o for o in objects if o["kind"] == "Deployment")
    env = {
        v["name"]: v.get("value")
        for v in deployment["spec"]["template"]["spec"]["containers"][0]["env"]
    }
    assert env["OPERATION_TIME_COEFFICIENT"] == "4"
    assert env["OPERATION_SCRATCH_COEFFICIENT"] == "1.3"
    assert env["OPERATION_BOOTSTRAP_BYTES_PER_SECOND"] == "8388608"
    rules = [r for o in objects if o["kind"] == "Role" for r in o["rules"]]
    assert any(r["resources"] == ["leases"] and "create" in r["verbs"] for r in rules)
    assert any(r["resources"] == ["pods/log"] and r["verbs"] == ["get"] for r in rules)
    assert not any(
        "nodes/proxy" in r["resources"] or "pods/exec" in r["resources"] for r in rules
    )


@pytest.mark.parametrize(
    "budget,expected",
    [
        (None, "3"),
        ({"time_coefficient": 4}, "3"),
        ({"observation_coefficient": 1}, "1"),
        ({"observation_coefficient": 1.5}, "1.5"),
        ({"observation_coefficient": 7}, "7"),
        ({"observation_coefficient": 100}, "100"),
    ],
)
def test_observation_budget_reaches_both_api_and_agent(config, budget, expected):
    if budget is None:
        config.pop("operation_budget", None)
    else:
        config["operation_budget"] = budget
    # Both sides consume the same control-observation window. A renderer that
    # validates a site field but drops it from either workload changes runtime
    # safety behavior; cover the emitted deployment contract, including old sites.
    for stage, name in (("api", "vnbui-backend"), ("agent", "vnbui-agent")):
        deployment = next(
            item
            for item in renderer.render(config, stage)["items"]
            if item["kind"] == "Deployment" and item["metadata"]["name"] == name
        )
        environment = {
            item["name"]: item.get("value")
            for item in deployment["spec"]["template"]["spec"]["containers"][0]["env"]
        }
        assert environment["OPERATION_OBSERVATION_COEFFICIENT"] == expected
        assert environment["OPERATION_CONTROL_ESTIMATE_SECONDS"] == "60"


@pytest.mark.parametrize(
    "coefficient",
    [0, -1, 0.5, 100.5, 101, True, None, "3", float("nan"), float("inf")],
)
def test_invalid_observation_budget_refuses_render(config, coefficient):
    config["operation_budget"] = {"observation_coefficient": coefficient}
    for stage in ("api", "agent"):
        with pytest.raises(
            ValueError, match=r"operation_budget\.observation_coefficient"
        ):
            renderer.render(config, stage)


@pytest.mark.parametrize(
    "policy",
    [
        {"time_coefficient": 0},
        {"time_coefficient": True},
        {"time_coefficient": float("inf")},
        {"scratch_coefficient": 0.9},
        {"bootstrap_bytes_per_second": 0},
        {"preparation_estimate_seconds": 1.5},
        {"control_estimate_seconds": 3601},
        {"unknown": 3},
        [],
    ],
)
def test_invalid_operation_policy_is_rejected(config, policy):
    config["operation_budget"] = policy
    with pytest.raises(ValueError):
        renderer.validate(config)


def test_source_health_probes_and_rollback_target_are_explicit(config):
    config["source_health_probes"] = [
        {
            "namespace": "protected-vms",
            "vm_name": "database",
            "url": "http://database-health.protected-vms.svc/ready",
        }
    ]
    config["rollback_schema_revision"] = "backup_verification"
    objects = renderer.render(config, "agent")["items"]
    deployment = next(o for o in objects if o["kind"] == "Deployment")
    environment = {
        v["name"]: v.get("value")
        for v in deployment["spec"]["template"]["spec"]["containers"][0]["env"]
    }
    assert (
        json.loads(environment["KUBEVIRT_SOURCE_HEALTH_PROBES"])
        == config["source_health_probes"]
    )
    job = renderer.render(config, "rollback-schema")["items"][0]
    command = job["spec"]["template"]["spec"]["containers"][0]["command"]
    assert command[-2:] == ["--rollback-revision", "backup_verification"]
    for endpoint in (
        "http://user:secret@host/ready",
        "http://@host/ready",
        "http://host/ready?token=secret",
        "file:///tmp/ready",
        "http://host:99999/ready",
    ):
        config["source_health_probes"][0]["url"] = endpoint
        with pytest.raises(ValueError):
            renderer.validate(config)


def test_current_schema_upgrade_keeps_operator_ledger_rollback_selectable(config):
    from alembic.script import ScriptDirectory

    # The kit's migration graph must include the new guard after the retained
    # request ledger. Selecting that predecessor must reach the owner job rather
    # than falling back to an older empty-ledger-only rollback boundary.
    migrations = ScriptDirectory(str(ROOT / "backend/alembic"))
    assert migrations.get_heads() == ["backup_admission_pause"]
    assert (
        migrations.get_revision("backup_admission_pause").down_revision
        == "operator_requests"
    )
    config["rollback_schema_revision"] = "operator_requests"
    for stage, flag in (
        ("upgrade", "--upgrade-operation-safety"),
        ("rollback-schema", "--rollback-operation-safety"),
    ):
        (job,) = renderer.render(config, stage)["items"]
        container = job["spec"]["template"]["spec"]["containers"][0]
        assert flag in container["command"]
        assert "--fresh" not in container["command"]
        if stage == "rollback-schema":
            assert container["command"][-2:] == [
                "--rollback-revision",
                "operator_requests",
            ]
        database = next(
            item for item in container["env"] if item["name"] == "DATABASE_URL"
        )
        assert (
            database["valueFrom"]["secretKeyRef"]["name"]
            == config["secrets"]["database_owner"]
        )
