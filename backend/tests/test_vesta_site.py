"""Run the stock launcher from assembled kits and exercise its safety guards."""

import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys

import pytest

from backend.tests.test_portable_kit import kit, oci_fixture


@pytest.fixture(params=["full", "customer-postgresql"])
def release(request, tmp_path):
    image_kit = tmp_path / "oci"
    image_kit.mkdir()
    images = {}
    components = ("backend", "frontend", "agent")
    if request.param == "full":
        components += ("postgres",)
    for component in components:
        images[component] = oci_fixture(image_kit / component, component.encode())
        (image_kit / f"{component}.digest").write_text(images[component] + "\n")
    kit.finish(
        image_kit, "images", {"images": images, "delivery_profile": request.param}
    )
    root = tmp_path / "release"
    kit.assemble_release(image_kit, root, "0" * 40)
    return root, request.param


def run(root, *args, cwd=None, env=None):
    return subprocess.run(
        [root / "vesta", *args],
        cwd=cwd or root,
        env=env,
        text=True,
        capture_output=True,
    )


def fill_manifest(path):
    document = json.loads(path.read_text())
    document["context"] = "test-context"
    document["registry"] = "registry.test/backup"
    document["site"]["journal_storage_class"] = "journal"
    document["site"]["scratch_storage_class"] = "scratch"
    if "postgres" in document:
        document["postgres"]["storage_class"] = "db"
    path.write_text(json.dumps(document))
    return document


def test_stock_kit_launcher_and_explicit_manifest(release, tmp_path):
    root, profile = release
    manifest = kit.verify(root)
    assert {"vesta", "install/vesta_site.py", "runbooks/site-manifest.md"} <= set(
        manifest["files"]
    )
    assert os.access(root / "vesta", os.X_OK)
    assert run(root, "--help").returncode == 0
    assert run(root, "init").returncode == 0
    path = root / "vesta.json"
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert run(root, "init").returncode == 2
    assert run(root, "plan").returncode == 2
    fill_manifest(path)
    plan = run(root, "plan")
    assert plan.returncode == 0, plan.stderr
    expected = ["postgres"] if profile == "full" else []
    assert json.loads(plan.stdout)["install_order"] == expected + ["migrate", "api"]
    assert json.loads(plan.stdout)["images"]["agent"].startswith(
        "registry.test/backup/agent@sha256:"
    )
    assert run(root, "verify").returncode == 0
    targets = tmp_path / "targets"
    prepare = run(root, "prepare-upgrade", "--output-dir", targets)
    assert prepare.returncode == 0, prepare.stderr
    assert {entry.name for entry in targets.iterdir()} == {"agent", "api"}
    assert run(root, "plan", cwd=tmp_path).returncode == 2
    assert run(root, "plan", "--manifest", path, cwd=tmp_path).stdout == plan.stdout
    assert not (root / "install/__pycache__").exists()
    (root / "vesta").chmod(0o644)
    with pytest.raises(ValueError, match="not executable"):
        kit.verify(root, local_site_manifest=True)


def test_new_kit_verifier_reads_previous_profiled_release(release):
    root, _ = release
    metadata = kit.verify(root)["metadata"]
    for path in kit.SITE_LAUNCHER_ASSETS:
        (root / path).unlink()
    (root / "manifest.json").unlink()
    metadata.pop("site_launcher")
    metadata.pop("vm_preflight")
    (root / "install" / kit.VM_PREFLIGHT_ASSET).unlink()
    kit.finish(root, "release", metadata)
    verified = kit.verify(root)
    assert verified["metadata"]["delivery_profile"] == metadata["delivery_profile"]
    assert "site_launcher" not in verified["metadata"]


FAKE_OC = r"""
import base64
import json
import os
from pathlib import Path
import subprocess
import sys

args = sys.argv[1:]
if args[0] == "--request-timeout=20s":
    assert args[1:3] == ["--context", "test-context"]
    call = args[3:]
    selector = {"namespaceLabelSelector": {"matchLabels": {"backup": "enabled"}}}
    group = call[1] if len(call) > 1 else ""
    items = []
    if group == "hyperconvergeds.v1.hco.kubevirt.io" and not os.getenv("FIXTURE_HCO_MISSING"):
        items = [{"apiVersion": "hco.kubevirt.io/v1", "spec": {
          "featureGates": [{"name": "IncrementalBackup"}],
          "virtualization": {"changedBlockTrackingLabelSelectors": selector}}}]
    if group == "kubevirts.kubevirt.io":
        items = [{"spec": {"configuration": {"changedBlockTrackingLabelSelectors": selector,
                  "developerConfiguration": {"featureGates": ["IncrementalBackup", "UtilityVolumes"]}}}}]
    if group == "customresourcedefinitions.apiextensions.k8s.io":
        items = [{"metadata": {"name": kind.lower()}, "spec": {"group": group, "names": {"kind": kind},
                 "versions": [{"name": version, "served": True}]}} for kind, group, version in (
            ("VirtualMachineBackup", "backup.kubevirt.io", "v1alpha1"),
            ("VirtualMachineBackupTracker", "backup.kubevirt.io", "v1alpha1"),
            ("VirtualMachineExport", "export.kubevirt.io", "v1beta1"))]
    print(json.dumps({"metadata": {"labels": {}}, "items": items}))
    sys.exit(0)
assert args[:2] == ["--context", "test-context"], args
args = args[2:]
with open(os.environ["FIXTURE_OC_LOG"], "a") as events:
    events.write(json.dumps(args) + "\n")
if args[0] == "create":
    assert "--save-config" in args
    assert "--dry-run=server" in args or os.environ.get("FIXTURE_INSTALL_WRITES") == "yes"
    subprocess.run([os.environ["FIXTURE_REAL_OC"], "kustomize", args[-1]], check=True, stdout=subprocess.DEVNULL)
elif args[0] == "-n" and args[2] in ("wait", "rollout"):
    assert os.environ.get("FIXTURE_INSTALL_WRITES") == "yes"
elif args[:2] == ["get", "--raw"]:
    names = ["virtualmachinebackups", "virtualmachinebackuptrackers", "virtualmachineexports"]
    print(json.dumps({"resources": [{"name": name} for name in names]}))
elif args[0] == "get":
    assert args[1] in ("namespace", "storageclass")
    print(f"{args[1]}/{args[2]}")
elif args[3] == "secret":
    keys = (
        "DATABASE_URL JWT_SECRET VESTA_ENCRYPTION_KEY ORCHESTRATOR_TO_AGENT_KEY "
        "password tls.crt tls.key ca.crt POSTGRES_PASSWORD OWNER_PASSWORD RUNTIME_PASSWORD"
    ).split()
    data = {key: base64.b64encode(b"fixture-only").decode() for key in keys}
    mode = os.environ.get("FIXTURE_PG_MODE", "verify-full")
    url = "postgresql://user:dummy-value@db.test/vesta?sslmode=" + mode
    data["DATABASE_URL"] = base64.b64encode(url.encode()).decode()
    print(json.dumps({"data": data}))
else:
    assert args[0] == "-n" and args[2] == "get", args
    if os.environ.get("FIXTURE_COLLISION"):
        print("persistentvolumeclaim/vesta-journal")
"""


def test_packaged_check_renders_real_targets_and_refuses_collisions(release, tmp_path):
    real_oc = shutil.which("oc")
    if not real_oc or not shutil.which("jq"):
        pytest.skip("requires oc with Kustomize and jq")
    root, profile = release
    assert run(root, "init").returncode == 0
    fill_manifest(root / "vesta.json")
    binary = tmp_path / "oc"
    binary.write_text(f"#!{sys.executable}\n" + FAKE_OC)
    binary.chmod(0o700)
    log = tmp_path / "oc.jsonl"
    env = {
        **os.environ,
        "PATH": f"{tmp_path}:{os.environ['PATH']}",
        "FIXTURE_REAL_OC": real_oc,
        "FIXTURE_OC_LOG": str(log),
    }
    report = tmp_path / "report"
    check = run(root, "check", "--preflight-output", report, env=env)
    assert check.returncode == 0, check.stderr
    assert (
        json.loads((report / "vesta-gates.json").read_text())["configuration_result"]
        == "PASS"
    )
    assert (report / "vesta-scope.json").is_file()
    calls = [json.loads(line) for line in log.read_text().splitlines()]
    stages = [Path(call[-1]).name for call in calls if call[0] == "create"]
    assert stages == (["postgres"] if profile == "full" else []) + [
        "migrate",
        "api",
        "agent",
    ]
    log.unlink()
    install = run(root, "install", env={**env, "FIXTURE_COLLISION": "yes"})
    assert install.returncode == 2
    assert "Existing Vesta resources" in install.stderr
    assert all(json.loads(line)[0] != "create" for line in log.read_text().splitlines())
    report = tmp_path / "failed-preflight"
    install = run(
        root,
        "install",
        "--preflight-output",
        report,
        env={**env, "FIXTURE_HCO_MISSING": "yes"},
    )
    assert install.returncode == 2
    assert "KubeVirt configuration gates did not pass" in install.stderr
    assert (
        json.loads((report / "vesta-gates.json").read_text())["configuration_result"]
        != "PASS"
    )
    assert all(json.loads(line)[0] != "create" for line in log.read_text().splitlines())
    refused = run(root, "check", env={**env, "FIXTURE_PG_MODE": "disable"})
    assert refused.returncode == 2
    assert "verified TLS" in refused.stderr and "dummy-value" not in refused.stderr


INSTALL_HTTPS_FIXTURE = r"""
from contextlib import nullcontext
from http.client import IncompleteRead
import json
import os
from pathlib import Path
import runpy
import ssl
import sys
from types import SimpleNamespace
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit

launcher = Path(sys.argv[1])
sys.argv = sys.argv[1:]
sys.path.insert(0, str(launcher.parent / "install"))
sys.dont_write_bytecode = True
import vesta_site

https_log = Path(os.environ["FIXTURE_HTTPS_LOG"])
scenario = os.environ["FIXTURE_HTTPS_SCENARIO"]
endpoint_calls = 0
clock = 0.0

def log(row):
    with https_log.open("a") as stream:
        stream.write(json.dumps(row) + "\n")

def sleep(seconds):
    global clock
    log({"sleep": seconds})
    clock += seconds

class Response:
    status = 200

    def __init__(self, truncated=None):
        self.truncated = truncated

    def read(self, size):
        assert size == 65536
        if self.truncated == "chunked":
            raise IncompleteRead(b"partial")
        return b"ready"

    def getheader(self, name):
        assert name == "Content-Length"
        return "12" if self.truncated == "fixed" else None

class Client:
    def open(self, request, *, timeout):
        global endpoint_calls
        assert request.get_method() == "GET"
        assert 0 < timeout <= min(15, 180 - clock)
        url = request.full_url
        assert urlsplit(url).scheme == "https"
        log({"url": url, "clock": clock, "timeout": timeout})
        if urlsplit(url).path == "/health":
            endpoint_calls += 1
            if scenario == "converges" and endpoint_calls == 1:
                raise URLError(ssl.SSLEOFError(8, "unexpected EOF"))
            if scenario == "converges" and endpoint_calls == 2:
                raise ConnectionResetError("ingress closed")
            if scenario == "transport":
                if endpoint_calls == 1:
                    raise URLError(ConnectionRefusedError("ingress not listening"))
                if endpoint_calls == 2:
                    raise TimeoutError("read interrupted")
                if endpoint_calls in (3, 4):
                    return nullcontext(Response("chunked" if endpoint_calls == 3 else "fixed"))
            if scenario == "certificate":
                raise URLError(ssl.SSLCertVerificationError(1, "PRIVATE_CERT_DIAGNOSTIC"))
            if scenario == "semantic":
                raise HTTPError(url, 302, "PRIVATE_REDIRECT_DIAGNOSTIC", None, None)
            if scenario == "deadline" or scenario == "converges" and endpoint_calls == 3:
                raise HTTPError(url, 503, "PRIVATE_GATEWAY_DIAGNOSTIC", None, None)
        return nullcontext(Response())

def opener(https_handler, redirect_handler):
    assert https_handler._context.check_hostname
    assert https_handler._context.verify_mode == ssl.CERT_REQUIRED
    assert isinstance(redirect_handler, vesta_site.NoRedirect)
    return Client()

vesta_site.build_opener = opener
vesta_site.time = SimpleNamespace(monotonic=lambda: clock, sleep=sleep)
runpy.run_path(str(launcher), run_name="__main__")
"""


@pytest.mark.parametrize(
    "scenario", ["converges", "transport", "certificate", "semantic", "deadline"]
)
def test_packaged_install_waits_only_for_transient_route_failures(
    release, tmp_path, scenario
):
    real_oc = shutil.which("oc")
    if not real_oc:
        pytest.skip("requires oc with Kustomize")
    root, profile = release
    assert run(root, "init").returncode == 0
    manifest_path = root / "vesta.json"
    manifest = fill_manifest(manifest_path)
    manifest["agent"] = "external"
    manifest_path.write_text(json.dumps(manifest))
    shim = tmp_path / "oc"
    shim.write_text(f"#!{sys.executable}\n" + FAKE_OC)
    shim.chmod(0o700)
    oc_log = tmp_path / "oc.jsonl"
    https_log = tmp_path / "https.jsonl"
    env = {
        **os.environ,
        "PATH": f"{tmp_path}:{os.environ['PATH']}",
        "FIXTURE_REAL_OC": real_oc,
        "FIXTURE_OC_LOG": str(oc_log),
        "FIXTURE_INSTALL_WRITES": "yes",
        "FIXTURE_HTTPS_LOG": str(https_log),
        "FIXTURE_HTTPS_SCENARIO": scenario,
    }
    result = subprocess.run(
        [sys.executable, "-c", INSTALL_HTTPS_FIXTURE, root / "vesta", "install"],
        cwd=root,
        env=env,
        text=True,
        capture_output=True,
    )
    calls = [json.loads(line) for line in oc_log.read_text().splitlines()]
    stages = (["postgres"] if profile == "full" else []) + ["migrate", "api"]
    assert [Path(call[-1]).name for call in calls if call[0] == "create"] == stages * 2
    assert [
        Path(call[-1]).name
        for call in calls
        if call[0] == "create" and "--dry-run=server" not in call
    ] == stages

    events = [json.loads(line) for line in https_log.read_text().splitlines()]
    target = "https://" + manifest["site"]["api_host"] + "/health"
    timings = [event["clock"] for event in events if event.get("url") == target]
    delays = [event["sleep"] for event in events if "sleep" in event]
    assert "PRIVATE_" not in result.stdout + result.stderr
    if scenario == "converges":
        assert result.returncode == 0, result.stderr
        assert "TLS connection closed before readiness" in result.stdout
        assert "connection reset" in result.stdout
        assert "HTTP 503" in result.stdout
        assert (
            "Application HTTPS routes are ready after ingress convergence"
            in result.stdout
        )
        assert timings == [0, 2, 6, 14]
        assert delays == [2, 4, 8]
        return

    if scenario == "transport":
        assert result.returncode == 0, result.stderr
        for state in (
            "connection refused",
            "HTTPS request timed out",
            "HTTPS response ended early",
        ):
            assert state in result.stdout
        assert (
            "Application HTTPS routes are ready after ingress convergence"
            in result.stdout
        )
        assert timings == [0, 2, 6, 14, 22]
        assert delays == [2, 4, 8, 8]
        return

    assert result.returncode == 2
    assert target in result.stderr
    if scenario == "deadline":
        assert sum(delays) == 180 and max(delays) == 8 and timings[-1] < 180
        assert "did not become ready within 180s" in result.stderr
        assert "HTTP 503" in result.stderr
        assert "vesta status" in result.stderr
    else:
        assert timings == [0] and not delays
        expected = (
            "failed TLS certificate verification"
            if scenario == "certificate"
            else "returned HTTP 302"
        )
        assert expected in result.stderr


def test_recovery_only_site_configures_reader_without_writer_probe(
    monkeypatch, tmp_path
):
    import vesta_site

    site = object.__new__(vesta_site.Site)
    site.integrations = vesta_site.integration_settings(
        {
            "s3": {
                "endpoint": "https://objects.test",
                "bucket": "fixture",
                "region": "test",
                "prefix": "a/b",
                "recovery_secret": "recovery-fixture",
            }
        }
    )
    site.namespace = "vesta"
    site.agent = "external"

    def read_secret(namespace, name, keys):
        assert namespace == "vesta" and name == "recovery-fixture"
        return {key: "reader-" + key for key in keys}

    monkeypatch.setattr(site, "secret", read_secret)
    calls = []

    class Api:
        def request(self, method, path, patch=None):
            calls.append((method, path))
            if method == "PUT":
                assert patch["storage.s3.recovery_access_key"] == "reader-access_key"
                assert patch["storage.s3.recovery_secret_key"] == "reader-secret_key"
                assert "storage.s3.access_key" not in patch
                assert patch["storage.s3.bucket"] == "fixture"
            else:
                return {
                    "settings": {"storage.type": "s3"},
                    "secrets": {
                        "storage.s3.recovery_access_key": {"configured": False},
                        "storage.s3.recovery_secret_key": {"configured": False},
                    },
                    "encryption_configured": True,
                }

    site.configure(Api(), tmp_path, False)
    assert calls == [("GET", "/settings/v3"), ("PUT", "/settings/v3")]


def test_settings_apply_once_and_refuse_repointing(monkeypatch, tmp_path):
    import vesta_site

    site = object.__new__(vesta_site.Site)
    site.integrations = vesta_site.integration_settings(
        {
            "s3": {
                "endpoint": "https://objects.test",
                "bucket": "fixture",
                "region": "test",
                "prefix": "a/b",
                "secret": "in-s3",
            },
            "oidc": {
                "issuer": "https://issuer.test",
                "client_id": "client",
                "secret": "in-oidc",
            },
        }
    )
    site.namespace = "vesta"
    site.agent = "external"
    monkeypatch.setattr(
        site,
        "secret",
        lambda namespace, name, keys: {key: "sensitive-fixture" for key in keys},
    )
    secret_fields = {
        key for _, _, fields in site.integrations.values() for key in fields
    }
    state = {
        "settings": {"storage.type": "s3"},
        "secrets": {key: {"configured": False} for key in secret_fields},
        "encryption_configured": True,
    }
    calls = []

    class Api:
        def request(self, method, path, value=None):
            calls.append((method, path))
            if method == "GET":
                return state
            if method == "PUT":
                for field, choice in value.items():
                    if field in secret_fields:
                        state["secrets"][field]["configured"] = True
                    else:
                        state["settings"][field] = choice

    site.configure(Api(), tmp_path, False)
    site.configure(Api(), tmp_path, False)
    assert calls.count(("PUT", "/settings/v3")) == 1
    assert calls.count(("POST", "/settings/test-s3")) == 2
    site.configure(Api(), tmp_path, True)
    assert calls.count(("PUT", "/settings/v3")) == 2
    state["settings"]["storage.s3.bucket"] = "retained-other-bucket"
    with pytest.raises(vesta_site.SiteError, match="storage migration"):
        site.configure(Api(), tmp_path, True)
    assert calls.count(("PUT", "/settings/v3")) == 2


def test_agent_key_is_scoped_private_and_never_overwritten(tmp_path, capsys):
    import vesta_site

    output = tmp_path / "agent-key"
    calls = []

    class Api:
        def request(self, method, path, value=None, request_id=None):
            if method == "GET":
                return [] if path == "/agents" else {"items": []}
            calls.append(value)
            assert request_id
            assert path == "/registration-keys"
            return {"api_key": "one-time-secret"}

    vesta_site.issue_agent_key(Api(), "pilot-native-1", output)
    assert calls[0]["agent_hostname"] == "pilot-native-1"
    assert calls[0]["max_uses"] == 1 and calls[0]["expires_at"]
    assert output.read_text() == "one-time-secret\n"
    assert stat.S_IMODE(output.stat().st_mode) == 0o600
    assert "one-time-secret" not in capsys.readouterr().out
    with pytest.raises(FileExistsError):
        vesta_site.issue_agent_key(Api(), "pilot-native-1", output)
    assert len(calls) == 1


def test_packaged_reconfigure_requires_manual_evidence_flags(release, tmp_path):
    root, _ = release
    transaction = tmp_path / "transaction"
    for action, arguments, missing in (
        ("apply", ("--quiesced", "--external-ready"), "--custody-confirmed"),
        ("accept", ("--quiesced",), "--paths-verified"),
        ("rollback", (), "--quiesced"),
    ):
        attempt = run(root, "reconfigure", action, "--state", transaction, *arguments)
        assert attempt.returncode == 2 and missing in attempt.stderr
    assert not transaction.exists()


def test_reconfigure_uses_original_target_and_durable_phases(
    release, monkeypatch, tmp_path
):
    from argparse import Namespace
    from backend.tests.test_reconfigure import Cluster, reconfigure, proposal
    import vesta_site

    root, _ = release
    assert run(root, "init").returncode == 0
    accepted_file = root / "vesta.json"
    accepted = fill_manifest(accepted_file)
    accepted_site = vesta_site.Site(root, accepted_file)
    cluster = Cluster(accepted_site.config)
    proposed_file = tmp_path / "desired.json"
    desired = proposal({**accepted["site"], "images": accepted_site.config["images"]})
    del desired["images"]
    proposed_file.write_text(json.dumps({**accepted, "site": desired}))
    monkeypatch.setattr(vesta_site, "reconfigure", reconfigure)
    monkeypatch.setattr(reconfigure, "get", cluster.get)
    monkeypatch.setattr(reconfigure, "apply_object", cluster.apply)
    monkeypatch.setattr(reconfigure, "call", lambda *args, **kwargs: "")
    monkeypatch.setattr(reconfigure, "probe", lambda *args: None)
    monkeypatch.setattr(
        reconfigure.socket, "getaddrinfo", lambda *args, **kwargs: [(None,)]
    )
    monkeypatch.setattr(reconfigure.reconcile_inputs, "run", lambda *args: 0)
    monkeypatch.setattr(
        reconfigure.reconcile_inputs,
        "source_versions",
        lambda oc, ns, refs: {
            f"{kind}/{name}": ["input-uid", "1"] for kind, name in refs
        },
    )
    monkeypatch.setattr(
        reconfigure,
        "delete_object",
        lambda oc, item, uid, **kwargs: cluster.items.pop(reconfigure.key(item), None),
    )
    server = ["https://fixture-cluster.test:6443"]

    def access(context):
        assert context == accepted["context"]
        return {"context": context, "server": server[0]}, [
            "oc",
            "--context",
            context,
            "--server",
            server[0],
        ]

    monkeypatch.setattr(vesta_site, "cluster_access", access)
    transaction = tmp_path / "state"
    vesta_site.run_reconfiguration(
        root,
        Namespace(
            change="plan",
            state=transaction,
            previous=accepted_file,
            manifest=proposed_file,
        ),
    )
    assert stat.S_IMODE(transaction.stat().st_mode) == 0o700
    assert (
        json.loads((transaction / "transaction.json").read_text())["status"]
        == "planned"
    )
    assert not cluster.calls
    server[0] = "https://different-cluster.test:6443"
    with pytest.raises(vesta_site.SiteError, match="different API server"):
        vesta_site.run_reconfiguration(
            root, Namespace(change="apply", state=transaction)
        )
    assert not cluster.calls
    server[0] = "https://fixture-cluster.test:6443"
    for change, phase in (
        ("apply", "awaiting-external-verification"),
        ("accept", "accepted"),
        ("rollback", "rolled-back-verified"),
    ):
        vesta_site.run_reconfiguration(
            root, Namespace(change=change, state=transaction)
        )
        assert (
            json.loads((transaction / "transaction.json").read_text())["status"]
            == phase
        )
    assert (
        cluster.items[("Route", accepted_site.namespace, "vesta-backend")]["spec"][
            "host"
        ]
        == accepted_site.config["api_host"]
    )


def test_wait_for_heartbeat_requires_advancing_same_agent(monkeypatch):
    from datetime import datetime, timedelta, timezone
    from unittest.mock import Mock
    import importlib.util

    path = Path(__file__).resolve().parents[2] / "packaging/okd/vesta_site.py"
    monkeypatch.syspath_prepend(str(path.parent))
    spec = importlib.util.spec_from_file_location("site_heartbeat_fixture", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    now = datetime.now(timezone.utc)

    def row(identity, seconds):
        return [
            {
                "hostname": "agent-a",
                "id": identity,
                "last_heartbeat": (now + timedelta(seconds=seconds)).isoformat(),
            }
        ]

    api = Mock()
    api.request.side_effect = [
        row("previous", -5),
        row("current", -2),
        row("current", -2),
        row("current", 0),
    ]
    monkeypatch.setattr(module.time, "sleep", lambda _: None)
    site = object.__new__(module.Site)
    site.agent_id = "agent-a"
    site.wait_heartbeat(api)
    assert api.request.call_count == 4


VM_PREFLIGHT_OC = r"""
import json
import os
import sys

args = sys.argv[1:]
assert args[:3] == ["--request-timeout=20s", "--context", "test-context"]
get, resource, *tail = args[3:]
assert get == "get", args
with open(os.environ["FIXTURE_OC_LOG"], "a") as log:
    log.write(json.dumps(args[3:]) + "\n")
mode = os.environ["VM_PREFLIGHT_MODE"]
ns = "protected-vms"
vm = "private-pilot-name"
selector = {"namespaceLabelSelector": {"matchLabels": {"backup": "enabled"}}}
if mode.startswith("selector_vm"):
    selector = {"virtualMachineLabelSelector": {"matchLabels": {"pilot.example.org/backup": "enabled"}}}
if mode == "selector_vm_complex":
    selector["virtualMachineLabelSelector"]["matchExpressions"] = [
        {"key": "vm-type", "operator": "Exists"}]
group_version = "groupsnapshot.storage.k8s.io/v1beta1"
if resource == "kubevirts.kubevirt.io":
    doc = {"items": [{"spec": {"configuration": {"changedBlockTrackingLabelSelectors": selector,
            "developerConfiguration": {"featureGates": ["IncrementalBackup", "UtilityVolumes"]}}}}]}
elif resource == "hyperconvergeds.v1.hco.kubevirt.io":
    doc = {"items": [{"apiVersion": "hco.kubevirt.io/v1", "spec": {
        "featureGates": [{"name": "IncrementalBackup"}],
        "virtualization": {"changedBlockTrackingLabelSelectors": selector}}}]}
elif resource == "namespace":
    assert tail == [ns, "-o", "json"]
    doc = {"metadata": {"name": ns, "labels": {
        "backup": "off" if mode == "selector" else "enabled"
    }}}
elif resource in ("virtualmachines.kubevirt.io", "virtualmachineinstances.kubevirt.io"):
    assert tail == [vm, "-n", ns, "--ignore-not-found", "-o", "json"], tail
    if (resource == "virtualmachines.kubevirt.io" and mode == "missing_vm") or (
        resource == "virtualmachineinstances.kubevirt.io" and mode == "missing_vmi"
    ):
        sys.exit(0)
    if resource == "virtualmachineinstances.kubevirt.io" and mode == "unknown_vmi":
        print("forbidden -- private-server-message", file=sys.stderr)
        sys.exit(1)
    kind = "VirtualMachine" if resource == "virtualmachines.kubevirt.io" else "VirtualMachineInstance"
    doc = {"apiVersion": "kubevirt.io/v1", "kind": kind,
           "metadata": {"name": vm, "namespace": ns, "uid": "fixture-" + kind}}
    if mode == "selector_vm_conflict" and kind == "VirtualMachine":
        doc["metadata"]["labels"] = {"pilot.example.org/backup": "different"}
    if kind == "VirtualMachineInstance":
        doc["metadata"]["ownerReferences"] = [{
            "apiVersion": "kubevirt.io/v1", "kind": "VirtualMachine", "name": vm,
            "uid": "replaced-vm" if mode == "stale" else "fixture-VirtualMachine",
            "controller": True,
        }]
        conditions = [{"type": "Ready", "status": "True"}]
        if mode == "not_ready": conditions[0]["status"] = "False"
        if mode == "readiness_missing": conditions = []
        if mode == "paused": conditions.append({"type": "Paused", "status": "True", "reason":"PausedIOError"})
        doc["status"] = {"phase": "Running", "nodeName": "" if mode == "no_node" else "node",
                         "conditions": conditions, "changedBlockTracking": {
            "state": {"pending": "Initializing", "disabled": "Disabled"}.get(mode, "Enabled")
        }}
        volumes = [
            {"name": "boot", "containerDisk": {"image": "private-boot-image"}},
            {"name": "data-a", "persistentVolumeClaim": {"claimName": "private-claim-a"}},
        ]
        if mode.startswith("group_"):
            volumes.append({"name": "data-b", "dataVolume": {"name": "private-claim-b"}})
        doc["spec"] = {"volumes": volumes,
            "domain": {"devices": {"disks": [{"name": item["name"]} for item in volumes]}}}
elif resource == "--raw":
    path, = tail
    if path == "/apis":
        versions = ["backup.kubevirt.io/v1alpha1", "export.kubevirt.io/v1beta1"]
        if mode.startswith("group_") and mode != "group_no_api":
            versions.append(group_version)
        doc = {"groups": [{"versions": [{"groupVersion": version}]} for version in versions]}
    elif path == "/apis/backup.kubevirt.io/v1alpha1":
        if mode == "unknown":
            print("forbidden -- private-server-message", file=sys.stderr)
            sys.exit(1)
        resources = [{"name": "virtualmachinebackups", "kind": "VirtualMachineBackup", "namespaced": True}]
        if mode != "missing_tracker":
            resources.append({
                "name": "virtualmachinebackuptrackers", "kind": "VirtualMachineBackupTracker", "namespaced": True,
            })
        doc = {"groupVersion": "backup.kubevirt.io/v1alpha1", "resources": resources}
    elif path == "/apis/export.kubevirt.io/v1beta1":
        doc = {"groupVersion": "export.kubevirt.io/v1beta1", "resources": [
            {"name": "virtualmachineexports", "kind": "VirtualMachineExport", "namespaced": True}
        ]}
    elif path == f"/apis/{group_version}":
        doc = {"groupVersion": group_version, "resources": [
            {"name": "volumegroupsnapshots", "kind": "VolumeGroupSnapshot", "namespaced": True},
            {"name": "volumegroupsnapshotcontents", "kind": "VolumeGroupSnapshotContent", "namespaced": False},
            {"name": "volumegroupsnapshotclasses", "kind": "VolumeGroupSnapshotClass", "namespaced": False},
        ]}
    elif path == f"/apis/{group_version}/volumegroupsnapshotclasses":
        driver = "other.csi.test" if mode == "group_no_class" else "sample.csi.test"
        doc = {"apiVersion": group_version, "kind": "VolumeGroupSnapshotClassList",
               "items": [{"driver": driver, "metadata": {"name": "private-group-class"}}]}
    else:
        raise AssertionError(args)
elif resource == "persistentvolumeclaim":
    claim, *options = tail
    assert options == ["-n", ns, "-o", "json"] and claim in ("private-claim-a", "private-claim-b")
    doc = {"apiVersion": "v1", "kind": "PersistentVolumeClaim",
           "metadata": {"name": claim, "namespace": ns, "uid": claim + "-uid"},
           "spec": {"volumeName": claim + "-pv"}, "status": {"phase": "Bound"}}
elif resource == "persistentvolume":
    volume, *options = tail
    assert options == ["-o", "json"] and volume in ("private-claim-a-pv", "private-claim-b-pv")
    if mode == "group_denied":
        print("forbidden -- private-server-message", file=sys.stderr)
        sys.exit(1)
    claim = volume.removesuffix("-pv")
    driver = "other.csi.test" if mode == "group_mixed" and claim.endswith("-b") else "sample.csi.test"
    uid = "stale-claim" if mode == "group_stale" and claim.endswith("-b") else claim + "-uid"
    doc = {"apiVersion": "v1", "kind": "PersistentVolume", "metadata": {"name": volume},
           "spec": {"claimRef": {"name": claim, "namespace": ns, "uid": uid},
                    "csi": {"driver": driver, "volumeHandle": "private-volume-handle"}},
           "status": {"phase": "Bound"}}
else:
    raise AssertionError(args)
print(json.dumps(doc))
"""


@pytest.fixture
def vm_preflight_fixture(release, tmp_path):
    if not shutil.which("jq"):
        pytest.skip("requires jq")
    root, _ = release
    assert run(root, "init").returncode == 0
    manifest = root / "vesta.json"
    document = fill_manifest(manifest)
    document["site"]["source_namespaces"].append("unrelated-source")
    manifest.write_text(json.dumps(document))
    binary = tmp_path / "oc"
    binary.write_text(f"#!{sys.executable}\n" + VM_PREFLIGHT_OC)
    binary.chmod(0o700)
    log = tmp_path / "scoped-oc.jsonl"
    env = {
        **os.environ,
        "PATH": f"{tmp_path}:{os.environ['PATH']}",
        "FIXTURE_OC_LOG": str(log),
        "VM_PREFLIGHT_MODE": "healthy",
        "TMPDIR": str(tmp_path),
    }
    return root, env, log


@pytest.mark.parametrize(
    "mode,status,code,group",
    [
        ("healthy", "ready", None, "not_applicable"),
        ("missing_vm", "action_required", "vm_absent", "not_observed"),
        ("missing_vmi", "action_required", "vmi_absent", "not_observed"),
        ("unknown_vmi", "unknown", "vmi_unknown", "not_observed"),
        (
            "missing_tracker",
            "action_required",
            "tracker_api_unavailable",
            "not_applicable",
        ),
        ("unknown", "unknown", "api_evidence_unknown", "not_applicable"),
        ("selector", "action_required", "cbt_selector_not_matched", "not_applicable"),
        (
            "selector_vm",
            "action_required",
            "cbt_selector_not_matched",
            "not_applicable",
        ),
        (
            "selector_vm_conflict",
            "action_required",
            "cbt_selector_not_matched",
            "not_applicable",
        ),
        (
            "selector_vm_complex",
            "action_required",
            "cbt_selector_not_matched",
            "not_applicable",
        ),
        ("stale", "unknown", "vmi_owner_unknown", "not_observed"),
        ("not_ready", "action_required", "vmi_not_ready", "not_observed"),
        ("no_node", "action_required", "vmi_not_ready", "not_observed"),
        ("readiness_missing", "unknown", "vmi_health_unknown", "not_observed"),
        ("paused", "action_required", "vmi_paused", "not_observed"),
        ("pending", "action_required", "cbt_pending", "not_applicable"),
        ("disabled", "action_required", "cbt_disabled", "not_applicable"),
        ("group_ok", "ready", None, "candidate"),
        ("group_no_api", "ready", None, "not_observed"),
        ("group_no_class", "ready", None, "not_observed"),
        ("group_mixed", "ready", None, "not_observed"),
        ("group_stale", "ready", None, "not_observed"),
        ("group_denied", "ready", None, "not_observed"),
    ],
)
def test_scoped_vm_preflight_from_kit(
    vm_preflight_fixture, tmp_path, mode, status, code, group
):
    root, env, events = vm_preflight_fixture
    report = tmp_path / "private-report"
    result = run(
        root,
        "preflight",
        "--vm",
        "protected-vms/private-pilot-name",
        "--output-dir",
        report,
        env={**env, "VM_PREFLIGHT_MODE": mode},
    )
    assert result.returncode == (0 if status == "ready" else 2), result.stderr
    assert stat.S_IMODE(report.stat().st_mode) == 0o700
    summary = report / "vesta-readiness.json"
    assert stat.S_IMODE(summary.stat().st_mode) == 0o600
    assert json.loads(summary.read_text()) == {
        "schema": 1,
        "kind": "vesta-vm-readiness",
        "status": status,
        "findings": [{"code": code, "status": status}] if code else [],
        "checkpoint": "not_checked",
        "group_snapshot": group,
    }
    assert ("group-snapshot candidate" in result.stdout) is (group == "candidate")
    if mode == "healthy":
        assert result.stdout.splitlines() == [
            "KubeVirt VM readiness: ready",
            f"Private report saved to {report}",
        ]
    if mode == "selector_vm":
        assert (
            "oc --context test-context -n protected-vms label vm private-pilot-name "
            "pilot.example.org/backup=enabled --dry-run=server -o name"
        ) in result.stdout
        observed = summary.read_text() + result.stderr
    else:
        assert "dry run:" not in result.stdout
        observed = summary.read_text() + result.stdout + result.stderr
    assert all(
        value not in observed
        for value in (
            "private-pilot-name",
            "private-claim",
            "private-group-class",
            "private-server-message",
        )
    )
    assert all(
        "private-volume-handle" not in path.read_text() for path in report.iterdir()
    )
    calls = [json.loads(line) for line in events.read_text().splitlines()]
    assert all(call[0] == "get" and "unrelated-source" not in call for call in calls)
    if mode in (
        "healthy",
        "group_no_api",
        "group_stale",
        "group_mixed",
        "group_denied",
    ):
        assert not any("volumegroupsnapshotclasses" in call[-1] for call in calls)
    assert run(root, "verify").returncode == 0


def test_scoped_vm_preflight_refuses_out_of_scope_and_cleans_temp_report(
    vm_preflight_fixture, tmp_path
):
    root, env, events = vm_preflight_fixture
    for target in ("other-namespace/pilot", "protected-vms", "protected-vms/a/b"):
        result = run(root, "preflight", "--vm", target, env=env)
        assert result.returncode == 2
    assert not events.exists()
    for mode, expected in (("healthy", 0), ("unknown", 2)):
        result = run(
            root,
            "preflight",
            "--vm",
            "protected-vms/private-pilot-name",
            env={**env, "VM_PREFLIGHT_MODE": mode},
        )
        assert result.returncode == expected, result.stderr
        assert "Private report saved" not in result.stdout
        assert not list(tmp_path.glob("vesta-preflight-*"))


FAKE_UPGRADE_OC = r"""
import json
import os
import sys

args = sys.argv[1:]
assert args[:2] == ["--context", "test-context"]
args = args[2:]
assert args == ["whoami", "--show-server"] or args[:2] == ["--server", "https://cluster.test"]
if args == ["whoami", "--show-server"]:
    print("https://cluster.test")
    sys.exit(0)
args = args[2:]
with open(os.environ["FIXTURE_OC_LOG"], "a") as events:
    events.write(json.dumps(args) + "\n")
if args[0] == "--request-timeout=45s":
    assert args[1:9] == [
        "-n", "vesta", "exec", "deployment/vesta-backend", "-c", "backend", "--", "python"
    ]
    assert args[9] == "-c"
    assert "REPEATABLE READ READ ONLY" in args[10]
    assert "assert_non_bypass_role" in args[10] and "assert_schema_current" in args[10]
    if os.environ.get("FIXTURE_SCHEMA_DRIFT"):
        print("private driver diagnostic", file=sys.stderr)
        sys.exit(1)
    print(os.environ["FIXTURE_UPGRADE_OBSERVED"])
    sys.exit(0)
assert args[2] == "get", args
if args[3] == "route":
    print(json.dumps({"spec": {"host": "vesta-api.example.org", "to": {"name": "vesta-backend"}}}))
else:
    assert args[3] == "deployment", args
    component = args[4].removeprefix("vesta-")
    images = json.loads(os.environ["FIXTURE_UPGRADE_IMAGES"])
    image = images[component]
    print(json.dumps({
        "metadata": {"generation": 1},
        "status": {"observedGeneration": 1, "updatedReplicas": 1, "readyReplicas": 1},
        "spec": {"template": {"spec": {"containers": [{
          "image": image, "name": component,
          "env": [{"name": "DATABASE_URL", "valueFrom": {"secretKeyRef": {
              "name": "vesta-db-runtime", "key": "DATABASE_URL"
          }}}]
        }]}}}
    }))
"""


@pytest.mark.parametrize(
    "version,revision,drift,expected",
    [
        ("6.1.0", "backup_admission_pause", False, ["upgrade", "api", "agent"]),
        ("6.1.1", "backup_admission_pause", False, ["upgrade", "api", "agent"]),
        ("6.2.0", "managed_file_backups", False, []),
        ("6.1.0", "operator_requests", False, None),
        ("6.0.0", "backup_admission_pause", False, None),
        ("6.1.1", "backup_admission_pause", True, None),
    ],
)
def test_observed_upgrade_prepares_only_reviewed_stages(
    release, tmp_path, version, revision, drift, expected
):
    root, _ = release
    assert run(root, "init").returncode == 0
    fill_manifest(root / "vesta.json")
    binary = tmp_path / "oc"
    binary.write_text(f"#!{sys.executable}\n" + FAKE_UPGRADE_OC)
    binary.chmod(0o700)
    log = tmp_path / "oc-upgrade.jsonl"
    offline = json.loads(run(root, "plan").stdout)
    installation = "10111111-1111-4111-8111-111111111111"
    env = {
        **os.environ,
        "PATH": f"{tmp_path}:{os.environ['PATH']}",
        "FIXTURE_OC_LOG": str(log),
        "FIXTURE_UPGRADE_IMAGES": json.dumps(offline["images"]),
        "FIXTURE_UPGRADE_OBSERVED": json.dumps(
            {
                "version": version,
                "revision": revision,
                "database": "vesta",
                "role": "vesta_runtime",
                "installation_id": installation,
            }
        ),
    }
    if drift:
        env["FIXTURE_SCHEMA_DRIFT"] = "yes"
    planned = run(root, "upgrade", "plan", env=env)
    output = tmp_path / "prepared"
    prepared = run(root, "upgrade", "prepare", "--output-dir", output, env=env)
    if expected is None:
        assert planned.returncode == prepared.returncode == 2, prepared.stderr
        assert not output.exists()
        assert "private driver diagnostic" not in prepared.stderr
    else:
        assert planned.returncode == prepared.returncode == 0, prepared.stderr
        plan = json.loads((output / "upgrade-plan.json").read_text())
        assert plan == json.loads(planned.stdout)
        assert (
            plan["stages"] == expected
            and plan["target"]["server"] == "https://cluster.test"
        )
        assert {entry.name for entry in output.iterdir()} == {
            *expected,
            "upgrade-plan.json",
        }
        assert stat.S_IMODE(output.stat().st_mode) == 0o700
        assert stat.S_IMODE((output / "upgrade-plan.json").stat().st_mode) == 0o600
        if expected:
            stage = "\n".join(
                path.read_text()
                for path in (output / "upgrade").rglob("*")
                if path.is_file()
            )
            assert "--upgrade-managed-files" in stage and "--installation-id" in stage
            assert installation in stage and "--fresh" not in stage
        else:
            assert plan["status"] == "already_current"
    calls = [json.loads(line) for line in log.read_text().splitlines()]
    assert all(call[0] in ("-n", "--request-timeout=45s") for call in calls)
    assert all(call[0] == "--request-timeout=45s" or call[2] == "get" for call in calls)
