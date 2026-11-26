"""Bounded installer transactions use fake cluster identities and actual rendering."""

import copy
import importlib.util
import json
import sys
from unittest.mock import patch

import pytest
from backend.tests.test_portable_okd import ROOT, renderer, sample_config


def load(name):
    spec = importlib.util.spec_from_file_location(
        name, ROOT / "packaging/okd" / (name + ".py")
    )
    module = importlib.util.module_from_spec(spec)
    with patch.dict(sys.modules, {"render": renderer}):
        if name == "reconfigure":
            with patch.dict(
                sys.modules, {"reconcile_inputs": load("reconcile_inputs")}
            ):
                spec.loader.exec_module(module)
        else:
            spec.loader.exec_module(module)
    return module


reconfigure = load("reconfigure")
bootstrap = load("bootstrap_admin")


class Cluster:
    def __init__(self, config):
        self.items = {}
        self.serial = 0
        self.calls = []
        self.fail = None
        for item in reconfigure.resources(config):
            self.put(item)

    def put(self, item):
        item = copy.deepcopy(item)
        identity = reconfigure.key(item)
        previous = self.items.get(identity)
        self.serial += 1
        item["metadata"].update(
            uid=previous["metadata"]["uid"] if previous else str(self.serial),
            resourceVersion=str(self.serial),
        )
        self.items[identity] = item

    def get(self, oc, item):
        return copy.deepcopy(self.items.get(reconfigure.key(item)))

    def apply(self, oc, item, uid=None, *, expected=None):
        actual = reconfigure.assert_identity(oc, item, uid)
        if expected is not None:
            assert reconfigure.clean(actual) == reconfigure.normalize_empty_annotations(
                expected
            )
        self.calls.append(copy.deepcopy(item))
        self.put(item)
        if self.fail:
            error, self.fail = self.fail, None
            raise error
        return self.get(oc, item)


@pytest.fixture
def cluster(monkeypatch):
    config = sample_config()
    cluster = Cluster(config)
    monkeypatch.setattr(reconfigure, "get", cluster.get)
    monkeypatch.setattr(reconfigure, "apply_object", cluster.apply)
    monkeypatch.setattr(reconfigure, "call", lambda *a, **k: "")
    monkeypatch.setattr(reconfigure, "namespace_uid", lambda oc, ns: "uid-" + ns)
    monkeypatch.setattr(reconfigure, "probe", lambda *a, **k: None)
    monkeypatch.setattr(reconfigure.socket, "getaddrinfo", lambda *a, **k: [(None,)])
    monkeypatch.setattr(reconfigure.reconcile_inputs, "run", lambda *a, **k: 0)
    monkeypatch.setattr(
        reconfigure.reconcile_inputs,
        "source_versions",
        lambda oc, ns, refs: {
            kind + "/" + name: ["input-uid", "1"] for kind, name in refs
        },
    )

    def delete(oc, item, uid, *, expected=None):
        actual = reconfigure.assert_identity(oc, item, uid)
        if actual:
            if expected is not None:
                assert reconfigure.clean(
                    actual
                ) == reconfigure.normalize_empty_annotations(expected)
            del cluster.items[reconfigure.key(item)]

    monkeypatch.setattr(reconfigure, "delete_object", delete)
    return config, cluster


def proposal(config):
    new = copy.deepcopy(config)
    new.update(
        ui_host="new-ui.example.org",
        api_host="new-api.example.org",
        ui_aliases=[config["ui_host"], *config.get("ui_aliases", [])],
    )
    new["secrets"]["backend_tls"] += "-v2"
    new["secrets"]["trust"] += "-v2"
    return new


def test_hostname_apply_keeps_old_routes_and_credentials(cluster, tmp_path):
    config, live = cluster
    state = reconfigure.plan(config, proposal(config), tmp_path / "txn", "oc")
    reconfigure.apply(state, tmp_path / "txn", "oc")
    assert state["status"] == "awaiting-external-verification"
    assert (
        live.items[("Route", config["namespace"], "vnbui-backend")]["spec"]["host"]
        == config["api_host"]
    )
    assert len([item for item in live.items.values() if item["kind"] == "Route"]) == 4
    assert not {item["kind"] for item in live.calls} & {
        "Secret",
        "Job",
        "PersistentVolumeClaim",
    }
    for item in live.calls:
        if item["kind"] == "Deployment" and item["metadata"]["name"] == "vnbui-backend":
            env = item["spec"]["template"]["spec"]["containers"][0]["env"]
            assert (
                next(v["value"] for v in env if v["name"] == "INITIAL_ADMIN_USERNAME")
                == config["admin_username"]
            )
            assert (
                next(v["value"] for v in env if v["name"] == "ALLOWED_ORIGINS")
                == "https://new-ui.example.org,https://backup.example.org"
            )


@pytest.mark.parametrize("error", [RuntimeError("failed apply"), KeyboardInterrupt()])
def test_partial_apply_or_interrupt_restores_and_verifies_old_paths(
    cluster, tmp_path, monkeypatch, error
):
    config, live = cluster
    path = tmp_path / "txn"
    state = reconfigure.plan(config, proposal(config), path, "oc")
    probes = []
    monkeypatch.setattr(
        reconfigure, "probe", lambda c, ca: probes.append(c["api_host"])
    )
    live.fail = error
    with pytest.raises(type(error)):
        reconfigure.apply(state, path, "oc")
    assert (
        json.loads((path / "transaction.json").read_text())["status"]
        == "rolled-back-verified"
    )
    assert probes[-1] == config["api_host"]
    for expected in reconfigure.resources(config):
        assert reconfigure.subset(expected, live.get("oc", expected))


def test_plan_and_apply_refuse_stale_resource_identity(cluster, tmp_path):
    config, live = cluster
    path = tmp_path / "txn"
    state = reconfigure.plan(config, proposal(config), path, "oc")
    target = state["changes"][0]["desired"]
    live.items[reconfigure.key(target)]["metadata"]["uid"] = "replacement"
    with pytest.raises(ValueError, match="identity"):
        reconfigure.apply(state, path, "oc")
    assert not live.calls


@pytest.mark.parametrize(
    "field,value",
    [
        ("database", "other"),
        ("admin_username", "replacement"),
        ("journal_size", "5Gi"),
        ("agent_id", "replacement"),
    ],
)
def test_reconfigure_refuses_identity_database_credentials_storage(field, value):
    old = sample_config()
    new = proposal(old)
    new[field] = value
    with pytest.raises(ValueError):
        reconfigure.changed(old, new)


def test_candidate_lifetime_reconfiguration_updates_only_backend(cluster, tmp_path):
    config, live = cluster
    proposed = copy.deepcopy(config)
    proposed["agent_key_rotation_ttl_hours"] = 48
    state = reconfigure.plan(config, proposed, tmp_path / "candidate-ttl", "oc")
    deployments = [
        change["desired"]
        for change in state["changes"]
        if change["desired"]["kind"] == "Deployment"
    ]
    assert [item["metadata"]["name"] for item in deployments] == [
        renderer.kube_name(config, "backend")
    ]
    env = deployments[0]["spec"]["template"]["spec"]["containers"][0]["env"]
    assert (
        next(
            item["value"]
            for item in env
            if item["name"] == "AGENT_KEY_ROTATION_TTL_HOURS"
        )
        == "48"
    )
    assert not live.calls


def test_scope_narrowing_reconciles_policy_and_revokes_binding(cluster, tmp_path):
    config, live = cluster
    config["restore_namespaces"].append("other-target")
    for item in reconfigure.resources(config):
        live.put(item)
    new = copy.deepcopy(config)
    new["restore_namespaces"] = ["protected-vms"]
    state = reconfigure.plan(config, new, tmp_path / "txn", "oc")
    assert state["removals"]
    assert all(e["before"]["kind"] == "RoleBinding" for e in state["removals"])
    reconfigure.apply(state, tmp_path / "txn", "oc")
    assert not any(
        k[0] == "RoleBinding"
        and k[1] == "other-target"
        and k[2].startswith("vnbui-restore-protected")
        for k in live.items
    )
    reconfigure.rollback(state, tmp_path / "txn", "oc")
    assert state["status"] == "rolled-back-verified"
    reconfigure.rollback(state, tmp_path / "txn", "oc")
    assert state["status"] == "rolled-back-verified"


def test_older_accepted_scope_cannot_regrant_after_a_disjoint_change(cluster, tmp_path):
    original, live = cluster
    original["restore_namespaces"].append("retired")
    for item in reconfigure.resources(original):
        live.put(item)
    narrower = copy.deepcopy(original)
    narrower["restore_namespaces"].remove("retired")
    first_path = tmp_path / "scope"
    first = reconfigure.plan(original, narrower, first_path, "oc")
    reconfigure.apply(first, first_path, "oc")
    reconfigure.accept(first, first_path, "oc")
    assert first["removals"]

    later = {**narrower, "agent_key_rotation_ttl_hours": 48}
    second_path = tmp_path / "lifetime"
    second = reconfigure.plan(narrower, later, second_path, "oc")
    reconfigure.apply(second, second_path, "oc")
    reconfigure.accept(second, second_path, "oc")
    before = copy.deepcopy(live.items)
    writes = len(live.calls)
    with pytest.raises(ValueError, match="superseded"):
        reconfigure.rollback(first, first_path, "oc")
    assert live.items == before and len(live.calls) == writes
    assert first["status"] == "accepted"

    reconfigure.rollback(second, second_path, "oc")
    reconfigure.rollback(first, first_path, "oc")
    assert first["status"] == second["status"] == "rolled-back-verified"
    before = copy.deepcopy(live.items)
    reconfigure.rollback(second, second_path, "oc")
    assert live.items == before


@pytest.mark.parametrize(
    "drift", ["deployment", "replacement-binding", "replacement-namespace"]
)
def test_accepted_rollback_checks_all_objects_before_regrant(
    cluster, tmp_path, monkeypatch, drift
):
    original, live = cluster
    original["restore_namespaces"].append("retired")
    for item in reconfigure.resources(original):
        live.put(item)
    next_config = copy.deepcopy(original)
    next_config["restore_namespaces"].remove("retired")
    path = tmp_path / "txn"
    state = reconfigure.plan(original, next_config, path, "oc")
    reconfigure.apply(state, path, "oc")
    reconfigure.accept(state, path, "oc")
    if drift == "deployment":
        entry = next(
            e for e in state["changes"] if e["desired"]["kind"] == "Deployment"
        )
        obj = live.get("oc", entry["desired"])
        obj["metadata"].setdefault("annotations", {})["site.example/change"] = "later"
        live.put(obj)
    elif drift == "replacement-binding":
        obj = copy.deepcopy(state["removals"][0]["before"])
        obj["subjects"][0]["namespace"] = "different-namespace"
        live.put(obj)
    else:
        monkeypatch.setattr(reconfigure, "namespace_uid", lambda oc, ns: "replacement")
    before = copy.deepcopy(live.items)
    with pytest.raises(ValueError, match="changed"):
        reconfigure.rollback(state, path, "oc")
    assert live.items == before and state["status"] == "accepted"


def test_bootstrap_password_private_policy_compliant_and_exclusive(tmp_path, capsys):
    config = sample_config()
    output = tmp_path / "admin.json"
    bootstrap.generate(config, output)
    value = json.loads(output.read_text())
    password = value["stringData"]["password"]
    assert output.stat().st_mode & 0o777 == 0o600
    assert len(password) >= 24
    assert all(
        any(c in chars for c in password)
        for chars in [
            "abcdefghijklmnopqrstuvwxyz",
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
            "0123456789",
            '!@#$%^&*(),.?":{}|<>',
        ]
    )
    with pytest.raises(FileExistsError):
        bootstrap.generate(config, output)
    bootstrap.report(config)
    report = capsys.readouterr().out
    assert password not in report
    assert "https://" + config["ui_host"] in report
    assert config["admin_username"] in report
    assert "get secret " + config["secrets"]["admin"] in report


def test_actual_probe_uses_verified_context_and_health_paths(monkeypatch):
    calls = []

    class Response:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def read(self, limit):
            assert limit == 65536

    monkeypatch.setattr(reconfigure.socket, "getaddrinfo", lambda *a, **k: [(None,)])

    def open_url(url, context, timeout):
        assert (
            context.check_hostname
            and context.verify_mode == reconfigure.ssl.CERT_REQUIRED
        )
        assert timeout == 15
        calls.append(url)
        return Response()

    monkeypatch.setattr(reconfigure.urllib.request, "urlopen", open_url)
    reconfigure.probe(sample_config())
    assert calls == [
        "https://backup.example.org/",
        "https://backup.example.org/api/v1/version",
        "https://backup-api.example.org/health",
        "https://backup-api.example.org/ready",
    ]


def test_accept_and_second_hostname_transaction_are_repeatable(cluster, tmp_path):
    config, live = cluster
    next_config = proposal(config)
    path = tmp_path / "first"
    state = reconfigure.plan(config, next_config, path, "oc")
    reconfigure.apply(state, path, "oc")
    reconfigure.accept(state, path, "oc")
    assert state["status"] == "accepted"
    third_config = copy.deepcopy(next_config)
    third_config.update(
        ui_host="third-ui.example.org",
        api_host="third-api.example.org",
        ui_aliases=[next_config["ui_host"], *next_config["ui_aliases"]],
    )
    second = reconfigure.plan(next_config, third_config, tmp_path / "second", "oc")
    reconfigure.apply(second, tmp_path / "second", "oc")
    reconfigure.rollback(second, tmp_path / "second", "oc")
    assert second["status"] == "rolled-back-verified"


@pytest.mark.parametrize(
    "kind,api,plural",
    [
        ("RoleBinding", "rbac.authorization.k8s.io/v1", "rolebindings"),
        ("Role", "rbac.authorization.k8s.io/v1", "roles"),
        ("ServiceAccount", "v1", "serviceaccounts"),
    ],
)
def test_oc_raw_delete_sends_uid_preconditions(
    tmp_path, monkeypatch, kind, api, plural
):
    """Exercise the installed client against a local HTTP fake, never a cluster."""
    import http.server
    import shutil
    import threading

    received = []

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_DELETE(self):
            if self.headers.get("Transfer-Encoding") == "chunked":
                chunks = []
                while True:
                    size = int(self.rfile.readline().strip(), 16)
                    if not size:
                        self.rfile.readline()
                        break
                    chunks.append(self.rfile.read(size))
                    self.rfile.read(2)
                raw = b"".join(chunks)
            else:
                raw = self.rfile.read(int(self.headers["Content-Length"]))
            received.append((self.path, json.loads(raw)))
            body = b'{"apiVersion":"v1","kind":"Status","status":"Success"}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    config = tmp_path / "kubeconfig"
    config.write_text(
        json.dumps(
            {
                "apiVersion": "v1",
                "kind": "Config",
                "clusters": [
                    {
                        "name": "fake",
                        "cluster": {"server": f"http://127.0.0.1:{server.server_port}"},
                    }
                ],
                "contexts": [
                    {"name": "fake", "context": {"cluster": "fake", "user": "fake"}}
                ],
                "current-context": "fake",
                "users": [{"name": "fake", "user": {}}],
            }
        )
    )
    monkeypatch.setenv("KUBECONFIG", str(config))
    item = renderer.obj(kind, "vnbui-agent", "source", api=api)
    monkeypatch.setattr(
        reconfigure,
        "get",
        lambda *a: {
            **item,
            "metadata": {
                **item["metadata"],
                "uid": "exact-uid",
                "resourceVersion": "19",
            },
        },
    )
    try:
        reconfigure.delete_object(shutil.which("oc"), item, "exact-uid", expected=item)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
    assert received == [
        (
            ("/api/v1" if api == "v1" else "/apis/" + api)
            + "/namespaces/source/"
            + plural
            + "/vnbui-agent",
            {
                "apiVersion": "v1",
                "kind": "DeleteOptions",
                "preconditions": {"uid": "exact-uid", "resourceVersion": "19"},
            },
        )
    ]


def test_mutations_use_conditional_replace_or_exclusive_create(monkeypatch):
    item = renderer.obj(
        "ConfigMap", "policy", "agent-system", {"data": {"policy": "{}"}}
    )
    calls = []

    def api_call(*args, value):
        calls.append((args, {"value": value}))
        return json.dumps(value)

    monkeypatch.setattr(reconfigure, "call", api_call)
    monkeypatch.setattr(
        reconfigure,
        "get",
        lambda *a: {
            **item,
            "metadata": {
                **item["metadata"],
                "uid": "existing",
                "resourceVersion": "123",
            },
        },
    )
    reconfigure.apply_object("oc", item, "existing")
    assert calls[-1][0][1] == "replace"
    assert calls[-1][1]["value"]["metadata"]["resourceVersion"] == "123"
    assert calls[-1][1]["value"]["metadata"]["uid"] == "existing"
    monkeypatch.setattr(reconfigure, "get", lambda *a: None)
    reconfigure.apply_object("oc", item)
    assert calls[-1][0][1] == "create"


def test_secret_metadata_drift_refuses_apply_before_mutation(
    cluster, tmp_path, monkeypatch
):
    config, live = cluster
    state = reconfigure.plan(config, proposal(config), tmp_path / "txn", "oc")
    monkeypatch.setattr(
        reconfigure.reconcile_inputs,
        "source_versions",
        lambda oc, ns, refs: {
            kind + "/" + name: ["replaced-input", "2"] for kind, name in refs
        },
    )
    with pytest.raises(ValueError, match="Secret input metadata changed"):
        reconfigure.apply(state, tmp_path / "txn", "oc")
    assert not live.calls


def test_failed_external_probe_rolls_back_and_checks_old_endpoint(
    cluster, tmp_path, monkeypatch
):
    config, live = cluster
    state = reconfigure.plan(config, proposal(config), tmp_path / "txn", "oc")
    probes = []

    def probe(c, ca):
        probes.append(c["api_host"])
        if c["api_host"] != config["api_host"]:
            raise ValueError("new endpoint TLS not ready")

    monkeypatch.setattr(reconfigure, "probe", probe)
    with pytest.raises(ValueError, match="new endpoint"):
        reconfigure.apply(state, tmp_path / "txn", "oc")
    assert state["status"] == "rolled-back-verified"
    assert probes == [
        config["api_host"],
        state["proposed"]["api_host"],
        config["api_host"],
    ]


def test_plan_accepts_server_default_fields_inside_container_lists(cluster, tmp_path):
    config, live = cluster
    for item in live.items.values():
        if item["kind"] == "Deployment":
            container = item["spec"]["template"]["spec"]["containers"][0]
            container["terminationMessagePath"] = "/dev/termination-log"
            container["terminationMessagePolicy"] = "File"
    reconfigure.plan(config, proposal(config), tmp_path / "txn", "oc")
    target = live.items[("Deployment", config["namespace"], "vnbui-backend")]
    target["spec"]["template"]["spec"]["containers"].append(
        {"name": "unexpected-sidecar"}
    )
    with pytest.raises(ValueError, match="does not match"):
        reconfigure.plan(config, proposal(config), tmp_path / "other", "oc")


def test_uncertain_created_route_still_restores_previous_deployments(cluster, tmp_path):
    config, live = cluster
    state = reconfigure.plan(config, proposal(config), tmp_path / "txn", "oc")
    reconfigure.apply(state, tmp_path / "txn", "oc")
    route = next(e for e in state["changes"] if e["desired"]["kind"] == "Route")
    route.pop("created_uid")  # simulate a process loss before UID receipt was durable
    with pytest.raises(ValueError, match="Rollback incomplete"):
        reconfigure.rollback(state, tmp_path / "txn", "oc")
    assert state["status"] == "rollback-incomplete"
    for item in reconfigure.resources(config):
        if item["kind"] == "Deployment":
            assert reconfigure.subset(item, live.get("oc", item))
    assert live.get("oc", route["desired"]) is not None


def test_primary_change_must_preserve_all_prior_ui_origins():
    old = sample_config()
    old["ui_aliases"] = ["earlier-ui.example.org"]
    new = proposal(old)
    new["ui_aliases"] = [old["ui_host"]]
    with pytest.raises(ValueError, match="retaining"):
        reconfigure.changed(old, new)
    new["ui_aliases"].append("earlier-ui.example.org")
    reconfigure.changed(old, new)
    retired = copy.deepcopy(new)
    retired["ui_aliases"] = []
    reconfigure.changed(new, retired)  # intentional later retirement, primary unchanged


def test_accept_keeps_configured_old_and_new_origins(cluster, tmp_path):
    config, live = cluster
    proposed = proposal(config)
    path = tmp_path / "txn"
    state = reconfigure.plan(config, proposed, path, "oc")
    reconfigure.apply(state, path, "oc")
    calls_before_accept = len(live.calls)
    reconfigure.accept(state, path, "oc")
    assert len(live.calls) == calls_before_accept
    backend = live.items[("Deployment", config["namespace"], "vnbui-backend")]
    env = backend["spec"]["template"]["spec"]["containers"][0]["env"]
    assert (
        next(v["value"] for v in env if v["name"] == "ALLOWED_ORIGINS")
        == "https://new-ui.example.org,https://backup.example.org"
    )


def test_additive_site_env_volumes_and_mounts_survive_apply_accept_rollback(
    cluster, tmp_path
):
    config, live = cluster
    backend = live.items[("Deployment", config["namespace"], "vnbui-backend")]
    pod = backend["spec"]["template"]["spec"]
    env = pod["containers"][0]["env"]
    env.extend(
        [
            {"name": "JWT_ALGORITHM", "value": "HS256"},
            {
                "name": "OIDC_CLIENT_SECRET",
                "valueFrom": {
                    "secretKeyRef": {"name": "oidc-site", "key": "client-secret"}
                },
            },
            {"name": "FRONTEND_URL", "value": "https://" + config["ui_host"] + "/"},
        ]
    )
    pod["volumes"].append(
        {"name": "site-s3", "secret": {"secretName": "site-s3", "defaultMode": 288}}
    )
    pod["containers"][0]["volumeMounts"].append(
        {"name": "site-s3", "mountPath": "/site-s3", "readOnly": True}
    )
    backend["spec"]["template"]["metadata"]["annotations"] = {
        reconfigure.reconcile_inputs.ANNOTATION: "old-input-marker",
        "site-owned": "keep",
    }
    backend["metadata"]["annotations"] = {
        "deployment.kubernetes.io/revision": "7",
        "site-owned": "keep",
    }
    original = copy.deepcopy(backend)
    path = tmp_path / "txn"
    state = reconfigure.plan(config, proposal(config), path, "oc")
    assert config["namespace"] + "/secret/oidc-site" in state["secret_inputs"]
    assert config["namespace"] + "/secret/site-s3" in state["secret_inputs"]
    reconfigure.apply(state, path, "oc")
    reconfigure.accept(state, path, "oc")
    applied = live.items[reconfigure.key(backend)]
    actual_env = {
        v["name"]: v
        for v in applied["spec"]["template"]["spec"]["containers"][0]["env"]
    }
    assert actual_env["FRONTEND_URL"]["value"] == "https://new-ui.example.org/"
    assert actual_env["JWT_ALGORITHM"]["value"] == "HS256"
    assert (
        actual_env["OIDC_CLIENT_SECRET"]["valueFrom"]["secretKeyRef"]["name"]
        == "oidc-site"
    )
    assert applied["spec"]["template"]["spec"]["volumes"][-1] == pod["volumes"][-1]
    assert (
        applied["spec"]["template"]["spec"]["containers"][0]["volumeMounts"][-1][
            "mountPath"
        ]
        == "/site-s3"
    )
    assert applied["spec"]["template"]["metadata"]["annotations"] == {
        "site-owned": "keep"
    }
    assert applied["metadata"]["annotations"] == {
        "site-owned": "keep",
        reconfigure.REVISION_ANNOTATION: reconfigure.revision(applied),
    }
    reconfigure.rollback(state, path, "oc")
    assert reconfigure.subset(
        reconfigure.clean(original), live.items[reconfigure.key(backend)]
    )


@pytest.mark.parametrize(
    "frontend",
    [
        {"value": "https://other.example.org/path"},
        {"valueFrom": {"configMapKeyRef": {"name": "site", "key": "frontend"}}},
    ],
)
def test_hostname_change_refuses_unowned_external_frontend_redirect(
    cluster, tmp_path, frontend
):
    config, live = cluster
    backend = live.items[("Deployment", config["namespace"], "vnbui-backend")]
    backend["spec"]["template"]["spec"]["containers"][0]["env"].append(
        {"name": "FRONTEND_URL", **frontend}
    )
    with pytest.raises(ValueError, match="FRONTEND_URL"):
        reconfigure.plan(config, proposal(config), tmp_path / "txn", "oc")
    assert not live.calls


def test_owned_agent_hostname_override_is_not_silently_adopted(cluster, tmp_path):
    config, live = cluster
    backend = live.items[("Deployment", config["vm_namespace"], "vnbui-agent")]
    for variable in backend["spec"]["template"]["spec"]["containers"][0]["env"]:
        if variable["name"] == "HOSTNAME":
            variable["value"] = "different-technical-identity"
    with pytest.raises(ValueError, match="does not match"):
        reconfigure.plan(config, proposal(config), tmp_path / "txn", "oc")
    assert not live.calls


def test_deployment_match_accepts_only_omitted_volume_mount_false_default():
    config = sample_config()
    expected = next(
        i
        for i in reconfigure.resources(config)
        if i["kind"] == "Deployment" and i["metadata"]["name"] == "vnbui-backend"
    )
    actual = copy.deepcopy(expected)
    pod = actual["spec"]["template"]["spec"]
    tmp = next(
        m for m in pod["containers"][0]["volumeMounts"] if m["mountPath"] == "/tmp"
    )
    assert tmp.pop("readOnly") is False
    assert reconfigure.deployment_matches(expected, actual)
    pod.pop("automountServiceAccountToken")
    assert not reconfigure.deployment_matches(expected, actual)
    pod["automountServiceAccountToken"] = False
    tls = next(
        m for m in pod["containers"][0]["volumeMounts"] if m["mountPath"] == "/tls"
    )
    tls.pop("readOnly")
    assert not reconfigure.deployment_matches(expected, actual)


def restore_expansion(config):
    proposed = copy.deepcopy(config)
    proposed["restore_namespaces"].append("restore-new")
    return proposed


def test_new_empty_restore_namespace_creates_worker_and_rolls_back(cluster, tmp_path):
    config, live = cluster
    original = copy.deepcopy(live.items)
    state = reconfigure.plan(config, restore_expansion(config), tmp_path / "txn", "oc")
    accounts = [e for e in state["changes"] if e["desired"]["kind"] == "ServiceAccount"]
    assert len(accounts) == 1
    account = accounts[0]
    assert reconfigure.key(account["desired"]) == (
        "ServiceAccount",
        "restore-new",
        "vnbui-restore-worker",
    )
    assert account["before"] is None and account["uid"] is None
    reconfigure.apply(state, tmp_path / "txn", "oc")
    assert (
        live.get("oc", account["desired"])["metadata"]["uid"] == account["created_uid"]
    )
    reconfigure.rollback(state, tmp_path / "txn", "oc")
    assert state["status"] == "rolled-back-verified"
    assert set(live.items) == set(original)
    for identity, before in original.items():
        assert live.items[identity]["metadata"]["uid"] == before["metadata"]["uid"]
        assert reconfigure.subset(reconfigure.clean(before), live.items[identity])


def test_matching_existing_restore_worker_is_readonly_prerequisite(cluster, tmp_path):
    config, live = cluster
    worker = renderer.obj(
        "ServiceAccount",
        "vnbui-restore-worker",
        "restore-new",
        {
            "automountServiceAccountToken": False,
            "imagePullSecrets": [{"name": "site-pull"}],
        },
    )
    live.put(worker)
    before = live.get("oc", worker)
    state = reconfigure.plan(config, restore_expansion(config), tmp_path / "txn", "oc")
    assert len(state["prerequisites"]) == 1
    assert state["prerequisites"][0]["uid"] == before["metadata"]["uid"]
    assert not any(e["desired"]["kind"] == "ServiceAccount" for e in state["changes"])
    reconfigure.apply(state, tmp_path / "txn", "oc")
    reconfigure.rollback(state, tmp_path / "txn", "oc")
    assert live.get("oc", worker) == before
    assert not any(i["kind"] == "ServiceAccount" for i in live.calls)


@pytest.mark.parametrize("problem", ["unlabelled", "controller-owned", "terminating"])
def test_unrelated_existing_restore_worker_refuses_plan(cluster, tmp_path, problem):
    config, live = cluster
    worker = renderer.obj("ServiceAccount", "vnbui-restore-worker", "restore-new")
    if problem == "unlabelled":
        worker["metadata"]["labels"] = {}
    elif problem == "controller-owned":
        worker["metadata"]["ownerReferences"] = [
            {
                "apiVersion": "v1",
                "kind": "ConfigMap",
                "name": "other",
                "uid": "other-owner",
            }
        ]
    else:
        worker["metadata"]["deletionTimestamp"] = "2026-10-30T12:00:00Z"
    live.put(worker)
    with pytest.raises(ValueError, match="ServiceAccount"):
        reconfigure.plan(config, restore_expansion(config), tmp_path / "txn", "oc")
    assert not live.calls


def test_existing_restore_worker_replacement_stops_before_any_mutation(
    cluster, tmp_path
):
    config, live = cluster
    worker = renderer.obj("ServiceAccount", "vnbui-restore-worker", "restore-new")
    live.put(worker)
    state = reconfigure.plan(config, restore_expansion(config), tmp_path / "txn", "oc")
    live.items[reconfigure.key(worker)]["metadata"]["uid"] = "replacement"
    with pytest.raises(ValueError, match="identity"):
        reconfigure.apply(state, tmp_path / "txn", "oc")
    assert not live.calls


def test_created_restore_worker_replacement_is_never_deleted(cluster, tmp_path):
    config, live = cluster
    state = reconfigure.plan(config, restore_expansion(config), tmp_path / "txn", "oc")
    reconfigure.apply(state, tmp_path / "txn", "oc")
    account = next(
        e for e in state["changes"] if e["desired"]["kind"] == "ServiceAccount"
    )
    live.items[reconfigure.key(account["desired"])]["metadata"][
        "uid"
    ] = "unrelated-replacement"
    before = copy.deepcopy(live.items)
    with pytest.raises(ValueError, match="Rollback incomplete"):
        reconfigure.rollback(state, tmp_path / "txn", "oc")
    assert live.items == before


def test_full_source_restore_expansion_failure_removes_created_grants_only(
    cluster, tmp_path, monkeypatch
):
    config, live = cluster
    proposed = restore_expansion(config)
    proposed["source_namespaces"] = [config["vm_namespace"], "source-new"]
    proposed["selected_namespaces"] = list(proposed["source_namespaces"])
    scratch = next(
        i
        for i in reconfigure.resources(proposed)
        if reconfigure.key(i)
        == ("PersistentVolumeClaim", "source-new", "vnbui-scratch")
    )
    live.put(scratch)  # independent explicit prerequisite, never transaction-owned
    unrelated = renderer.obj(
        "ConfigMap", "operator-owned", "restore-new", {"data": {"note": "preserve"}}
    )
    live.put(unrelated)
    original = copy.deepcopy(live.items)
    state = reconfigure.plan(config, proposed, tmp_path / "txn", "oc")
    created = {
        reconfigure.key(e["desired"]) for e in state["changes"] if e["before"] is None
    }
    assert {i[0] for i in created} == {"Role", "RoleBinding", "ServiceAccount"}
    verify = reconfigure.verify

    def fail_after_all_resources(state, oc, rollback=False):
        if not rollback:
            assert created <= set(live.items)
            raise ValueError("simulated failed rollout after grants were created")
        return verify(state, oc, rollback=True)

    monkeypatch.setattr(reconfigure, "verify", fail_after_all_resources)
    with pytest.raises(ValueError, match="simulated failed rollout"):
        reconfigure.apply(state, tmp_path / "txn", "oc")
    assert state["status"] == "rolled-back-verified"
    assert not created & set(live.items)
    assert set(live.items) == set(original)
    assert live.get("oc", scratch) == original[reconfigure.key(scratch)]
    assert live.get("oc", unrelated) == original[reconfigure.key(unrelated)]
    for identity, before in original.items():
        assert live.items[identity]["metadata"]["uid"] == before["metadata"]["uid"]
        assert reconfigure.subset(reconfigure.clean(before), live.items[identity])


def test_alternating_ui_api_ui_accepted_transactions_find_own_routes(cluster, tmp_path):
    config, live = cluster
    ui_first = copy.deepcopy(config)
    ui_first.update(ui_host="first-ui.example.org", ui_aliases=[config["ui_host"]])
    first_path = tmp_path / "ui-first"
    first = reconfigure.plan(config, ui_first, first_path, "oc")
    first_routes = [e for e in first["changes"] if e["desired"]["kind"] == "Route"]
    assert len(first_routes) == 1
    first_ui_route = first_routes[0]["desired"]
    assert first_ui_route["spec"]["host"] == ui_first["ui_host"]
    reconfigure.apply(first, first_path, "oc")
    reconfigure.accept(first, first_path, "oc")
    first_ui_live = live.get("oc", first_ui_route)

    api_next = copy.deepcopy(ui_first)
    api_next["api_host"] = "next-api.example.org"
    api_next["secrets"]["backend_tls"] += "-v2"
    second_path = tmp_path / "api-next"
    second = reconfigure.plan(ui_first, api_next, second_path, "oc")
    second_routes = [e for e in second["changes"] if e["desired"]["kind"] == "Route"]
    assert len(second_routes) == 1
    assert second_routes[0]["desired"]["spec"]["host"] == api_next["api_host"]
    reconfigure.apply(second, second_path, "oc")
    reconfigure.accept(second, second_path, "oc")
    assert live.get("oc", first_ui_route) == first_ui_live

    ui_again = copy.deepcopy(api_next)
    ui_again.update(
        ui_host="another-ui.example.org",
        ui_aliases=[api_next["ui_host"], *api_next["ui_aliases"]],
    )
    third_path = tmp_path / "ui-again"
    third = reconfigure.plan(api_next, ui_again, third_path, "oc")
    third_routes = [e for e in third["changes"] if e["desired"]["kind"] == "Route"]
    assert len(third_routes) == 1
    assert third_routes[0]["desired"]["spec"]["host"] == ui_again["ui_host"]
    reconfigure.apply(third, third_path, "oc")
    reconfigure.accept(third, third_path, "oc")
    assert first["status"] == second["status"] == third["status"] == "accepted"
    assert live.get("oc", first_ui_route) == first_ui_live
    assert len([i for i in live.items.values() if i["kind"] == "Route"]) == 5


@pytest.mark.parametrize("fault", [None, "annotation", "data", "uid"])
def test_archived_rollback_handles_api_omitted_empty_annotations(
    cluster, tmp_path, monkeypatch, fault
):
    config, live = cluster
    target_key = ("ConfigMap", config["namespace"], "vnbui-frontend")
    live.items[target_key]["metadata"]["annotations"] = {"site-owned": "keep"}
    original = copy.deepcopy(live.items)
    path = tmp_path / "txn"
    state = reconfigure.plan(config, proposal(config), path, "oc")
    reconfigure.apply(state, path, "oc")
    # Reopen a persisted pre-fix transaction: cleaning its client marker left
    # an empty annotations map, even though the API omits it on replacement.
    for entry in state["changes"]:
        if entry["before"] and entry["before"]["kind"] == "ConfigMap":
            entry["before"]["metadata"].setdefault("annotations", {})
    state["status"] = "rollback-incomplete"
    reconfigure.save(path, state)
    state = json.loads((path / "transaction.json").read_text())
    put = live.put

    def server_replace(item):
        item = copy.deepcopy(item)
        if item["metadata"].get("annotations") == {}:
            item["metadata"].pop("annotations")
        if reconfigure.key(item) == target_key:
            if fault == "annotation":
                item["metadata"]["annotations"]["site-owned"] = "changed"
            elif fault == "data":
                item["data"]["nginx.conf"] += "\n# unexpected configuration"
        put(item)

    monkeypatch.setattr(live, "put", server_replace)
    if fault == "uid":
        live.items[target_key]["metadata"]["uid"] = "unrelated-replacement"
    if fault:
        with pytest.raises(ValueError, match="Rollback incomplete"):
            reconfigure.rollback(state, path, "oc")
        assert state["status"] == "rollback-incomplete"
        if fault == "uid":
            assert live.items[target_key]["metadata"]["uid"] == "unrelated-replacement"
    else:
        reconfigure.rollback(state, path, "oc")
        assert state["status"] == "rolled-back-verified"
        assert set(live.items) == set(original)
        for identity, before in original.items():
            assert live.items[identity]["metadata"]["uid"] == before["metadata"]["uid"]
            assert reconfigure.configuration_matches(
                reconfigure.clean(before), live.items[identity]
            )
        policy = live.items[("ConfigMap", config["vm_namespace"], "vnbui-agent-scope")]
        assert "annotations" not in policy["metadata"]


@pytest.mark.parametrize(
    "expected,actual",
    [
        ({"metadata": {"labels": {}}}, {"metadata": {}}),
        ({"data": {}}, {}),
        ({"spec": {}}, {}),
        ({"spec": {"annotations": {}}}, {"spec": {}}),
        ({"metadata": {"annotations": None}}, {"metadata": {}}),
        ({"metadata": {"annotations": {"site": "keep"}}}, {"metadata": {}}),
        (
            {"metadata": {"annotations": {"site": "keep"}}},
            {"metadata": {"annotations": {"site": "changed"}}},
        ),
        ({"metadata": {"uid": "original"}}, {"metadata": {"uid": "other"}}),
    ],
)
def test_annotation_normalization_keeps_other_configuration_checks_strict(
    expected, actual
):
    assert not reconfigure.configuration_matches(expected, actual)


def test_future_snapshots_omit_only_empty_metadata_annotations():
    item = renderer.obj("Deployment", "test", "test")
    item["metadata"]["annotations"] = {
        "kubectl.kubernetes.io/last-applied-configuration": "client state"
    }
    item["metadata"]["labels"] = {}
    item["spec"] = {
        "template": {
            "metadata": {
                "annotations": {reconfigure.reconcile_inputs.ANNOTATION: "old"}
            },
            "spec": {},
        }
    }
    cleaned = reconfigure.clean(item)
    assert "annotations" not in cleaned["metadata"]
    assert "annotations" not in cleaned["spec"]["template"]["metadata"]
    assert cleaned["metadata"]["labels"] == {}
    assert cleaned["spec"]["template"]["spec"] == {}
    # Generic subset remains strict; equivalence is confined to resource checks.
    assert not reconfigure.subset({"metadata": {"annotations": {}}}, {"metadata": {}})


def test_reconfiguration_cannot_switch_authentication_namespace():
    previous = sample_config()
    proposed = copy.deepcopy(previous)
    proposed["edition"] = "commercial"
    proposed["operating_profile"] = {
        "auth_mode": "multi_organization",
        "enabled_modules": ["multi_tenancy"],
    }
    with pytest.raises(ValueError, match="operating profile"):
        reconfigure.changed(previous, proposed)


def test_old_community_config_can_keep_explicit_equivalent_profile_on_other_edit():
    previous = sample_config()
    previous.pop("edition", None)
    previous.pop("operating_profile", None)
    proposed = copy.deepcopy(previous)
    proposed["edition"] = "community"
    proposed["operating_profile"] = {
        "auth_mode": "single_organization",
        "enabled_modules": [],
    }
    proposed["ui_aliases"] = ["retained-ui.example.org"]
    reconfigure.changed(previous, proposed)
