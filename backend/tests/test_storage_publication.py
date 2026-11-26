"""Generation writes use exact reserved bytes and conditional creates."""

from copy import deepcopy
import hashlib
import io
from types import SimpleNamespace

from botocore.exceptions import ClientError
import pytest

from core.storage_publication import _publish_object
from core.storage_receipt_v2 import canonical
from core.s3_ownership import StorageOwnershipError


class MemoryS3:
    def __init__(self, endpoint="https://store.invalid", *, lost_reply=False):
        self.meta = SimpleNamespace(endpoint_url=endpoint)
        self.objects = {}
        self.puts = []
        self.reads = []
        self.lost_reply = lost_reply

    def close(self):
        pass

    def put_object(self, **args):
        assert args["IfNoneMatch"] == "*"
        self.puts.append(deepcopy(args))
        key = (args["Bucket"], args["Key"])
        if key in self.objects:
            raise ClientError({"Error": {"Code": "PreconditionFailed"}}, "PutObject")
        identity = dict(ETag='"generation-etag"', VersionId="generation-version")
        self.objects[key] = dict(
            body=args["Body"],
            Metadata=args["Metadata"],
            ContentLength=len(args["Body"]),
            **identity,
        )
        if self.lost_reply:
            raise OSError("response lost after conditional create")
        return identity

    def get_object(self, **args):
        self.reads.append(deepcopy(args))
        key = (args["Bucket"], args["Key"])
        if key not in self.objects:
            raise ClientError({"Error": {"Code": "NoSuchKey"}}, "GetObject")
        obj = deepcopy(self.objects[key])
        if (
            args.get("IfMatch", obj["ETag"]) != obj["ETag"]
            or args.get("VersionId", obj["VersionId"]) != obj["VersionId"]
        ):
            raise ClientError({"Error": {"Code": "PreconditionFailed"}}, "GetObject")
        return dict(Body=io.BytesIO(obj.pop("body")), **obj)


def snapshot():
    manifest = dict(generation_id="generation", predecessor_id=None, members=[{}])
    body = canonical(manifest)
    return dict(
        id="generation",
        backup_id="backup",
        org_id="org",
        endpoint="https://store.invalid",
        bucket="owned",
        key="exact/generation.json",
        plan=dict(
            schema=4,
            generation_id="generation",
            predecessor_id=None,
            manifest_canonical=body.decode(),
            manifest_sha256=hashlib.sha256(body).hexdigest(),
        ),
    )


@pytest.mark.parametrize("lost_reply", [False, True])
def test_conditional_create_and_lost_response_reconcile_same_bytes(lost_reply):
    store, intent = MemoryS3(lost_reply=lost_reply), snapshot()
    accepted = _publish_object(store, intent)
    assert accepted["sha256"] == intent["plan"]["manifest_sha256"]
    assert accepted["assurance"] == "consumer_sha256_verified"
    assert _publish_object(store, intent) == accepted
    assert len(store.puts) == 1
    assert {r["Key"] for r in store.reads} == {intent["key"]}


@pytest.mark.parametrize("changed", ["bytes", "metadata", "length", "etag"])
def test_collision_never_overwrites_different_generation(changed):
    store, intent = MemoryS3(), snapshot()
    _publish_object(store, intent)
    obj = store.objects[(intent["bucket"], intent["key"])]
    if changed == "bytes":
        obj["body"] = b"foreign"
    elif changed == "metadata":
        obj["Metadata"] = {}
    elif changed == "length":
        obj["ContentLength"] += 1
    else:
        obj["ETag"] = "unquoted"
    with pytest.raises(StorageOwnershipError):
        _publish_object(store, intent)
    assert len(store.puts) == 1


def test_other_target_refused_before_io():
    store = MemoryS3(endpoint="https://other.invalid")
    with pytest.raises(StorageOwnershipError, match="target"):
        _publish_object(store, snapshot())
    assert not store.reads and not store.puts


def test_corrupt_intent_refused_before_provider_put():
    store, intent = MemoryS3(), snapshot()
    intent["plan"]["manifest_sha256"] = "0" * 64
    with pytest.raises(StorageOwnershipError):
        _publish_object(store, intent)
    assert not store.puts


def test_generation_migration_preserves_latest_capacity_release_vetoes():
    import runpy
    from pathlib import Path
    from unittest.mock import Mock

    path = Path(__file__).resolve().parents[1] / "alembic" / "versions"
    migration = runpy.run_path(str(path / "20261001_storage_generation_publication.py"))
    latest = runpy.run_path(str(path / "20260927_callback_provider_create.py"))
    sql = latest["OWNER"]
    for field in (
        "receipt_verification_intent",
        "attempt_key_preparation_intent",
        "attempt_key_disclosure_intent",
        "provider_create",
    ):
        assert field + " IS NOT NULL" in sql
    # Capture the real upgrade's emitted function, not a duplicated SQL builder.
    migration["upgrade"].__globals__["op"] = op = Mock()
    op.get_bind.return_value.scalar.return_value = migration["OWNERSHIP_OLD"]
    script = Mock()
    script.get_revision.return_value.module.OWNER = sql
    migration["upgrade"].__globals__["ScriptDirectory"] = Mock()
    migration["upgrade"].__globals__[
        "ScriptDirectory"
    ].from_config.return_value = script
    migration["upgrade"]()
    emitted = [str(call.args[0]) for call in op.execute.call_args_list]
    owner = next(
        value for value in emitted if "FUNCTION vnbui_capacity_owner()" in value
    )
    for field in (
        "receipt_verification_intent",
        "attempt_key_preparation_intent",
        "attempt_key_disclosure_intent",
        "provider_create",
    ):
        assert field + " IS NOT NULL" in owner
    assert "generation_committed" in owner


def test_pinned_sdk_puts_exact_generation_over_verified_tls(monkeypatch, tmp_path):
    """Exercise real SDK serialization/transport, not just a fake S3 method."""
    from datetime import datetime, timedelta, timezone
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    import ipaddress
    import ssl
    import threading

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    from core.storage_transaction import _recorded_target_client

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")])
    now = datetime.now(timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(hours=1))
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]
            ),
            critical=False,
        )
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    cert_path, key_path = tmp_path / "ca.pem", tmp_path / "key.pem"
    cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    observed = {}

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *args):
            pass

        def do_GET(self):
            if "body" not in observed:
                body = b"<Error><Code>NoSuchKey</Code></Error>"
                self.send_response(404)
            else:
                body = observed["body"]
                self.send_response(200)
                self.send_header("ETag", '"generation-etag"')
                self.send_header("x-amz-version-id", "generation-version")
                for name, value in observed["headers"].items():
                    if name.startswith("x-amz-meta-"):
                        self.send_header(name, value)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_PUT(self):
            observed["headers"] = {k.lower(): v for k, v in self.headers.items()}
            observed["path"] = self.path
            length = self.headers.get("Content-Length")
            if length is None:
                self.send_error(400, "Exact generation requires a fixed-length body")
                return
            observed["body"] = self.rfile.read(int(length))
            self.send_response(200)
            self.send_header("ETag", '"generation-etag"')
            self.send_header("x-amz-version-id", "generation-version")
            self.send_header("Content-Length", "0")
            self.end_headers()

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.load_cert_chain(cert_path, key_path)
    server.socket = tls.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    intent = snapshot()
    intent["endpoint"] = f"https://127.0.0.1:{server.server_port}"
    monkeypatch.setenv("AWS_CA_BUNDLE", str(cert_path))
    monkeypatch.setenv("NO_PROXY", "127.0.0.1")
    monkeypatch.setattr(
        "core.settings_service.SettingsService.get_s3_config",
        lambda _: dict(
            endpoint=intent["endpoint"],
            bucket=intent["bucket"],
            access_key="local-test",
            secret_key="local-test",
        ),
    )
    client = _recorded_target_client(
        None,
        SimpleNamespace(
            endpoint=intent["endpoint"],
            bucket=intent["bucket"],
        ),
    )
    try:
        result = _publish_object(client, intent)
        assert result["sha256"] == intent["plan"]["manifest_sha256"]
        assert observed["body"] == intent["plan"]["manifest_canonical"].encode()
        assert observed["path"] == "/owned/exact/generation.json"
        headers = observed["headers"]
        assert headers["if-none-match"] == "*"
        assert (
            "if-none-match"
            in headers["authorization"].split("SignedHeaders=")[1].split(",")[0]
        )
        assert int(headers["content-length"]) == len(observed["body"])
        assert (
            not {"content-encoding", "transfer-encoding", "x-amz-trailer"}
            & headers.keys()
        )
        assert "STREAMING" not in headers.get("x-amz-content-sha256", "")
    finally:
        client.close()
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
