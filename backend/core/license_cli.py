"""Offline Vesta certificate issuer and audited installation-operator commands."""

import argparse
import base64
from datetime import datetime, timedelta
import json
import os
from pathlib import Path
import pwd
import re
import stat
import tempfile

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

MAX_BYTES = 65536
KEY_ID = r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}"


def no_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON field")
        result[key] = value
    return result


def read_file(path, private=False):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_BYTES:
            raise ValueError("Input must be a regular local file up to 65536 bytes")
        if private and info.st_mode & 0o077:
            raise ValueError("Private issuer key must have mode 0600 or stricter")
        data = stream.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise ValueError("Input exceeds 65536 bytes")
    return data


def read_json(path):
    return json.loads(read_file(path), object_pairs_hook=no_duplicates)


def write_new(path, content, mode=0o600):
    """Create only an explicitly named new file; never replace an issuer key."""
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(content)
        stream.flush()
        os.fsync(stream.fileno())


def json_bytes(value):
    return (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()


def require_key_id(value):
    if not re.fullmatch(KEY_ID, value):
        raise ValueError("Use a public signing key ID of 1 to 64 slug characters")


def intended_start(payload):
    """Issuer validation uses the intended activation instant, not import time."""
    dates = []
    for field in ("issued_at", "not_before"):
        if field not in payload and field == "not_before":
            continue
        value = payload.get(field)
        if not isinstance(value, str):
            raise ValueError("Certificate dates require explicit UTC timestamps")
        date = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if date.tzinfo is None or date.utcoffset() != timedelta(0):
            raise ValueError("Certificate dates require explicit UTC timestamps")
        dates.append(date)
    return max(dates)


def keygen(args):
    require_key_id(args.key_id)
    private, public = Path(args.private_key), Path(args.public_keys)
    if (
        private.resolve() == public.resolve()
        or private.exists()
        or private.is_symlink()
        or public.exists()
        or public.is_symlink()
    ):
        raise ValueError("Issuer key output paths must be distinct new local files")
    key = Ed25519PrivateKey.generate()
    write_new(
        private,
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ),
    )
    raw = key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    write_new(
        public,
        json_bytes(
            {
                "schema_version": 1,
                "keys": {
                    args.key_id: base64.b64encode(raw).decode("ascii"),
                },
            }
        ),
        0o644,
    )
    return {
        "key_id": args.key_id,
        "private_key_created": True,
        "public_manifest_created": True,
    }


def issue(args):
    # Importing the issuer command itself never initializes a database session.
    from core.license_registration import canonical_signed_bytes, verify_certificate

    require_key_id(args.key_id)
    payload = read_json(args.payload_file)
    key = serialization.load_pem_private_key(
        read_file(args.private_key, private=True), password=None
    )
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("Issuer key must be Ed25519")
    unsigned = {"schema_version": 1, "key_id": args.key_id, "payload": payload}
    envelope = {
        **unsigned,
        "signature": base64.b64encode(
            key.sign(canonical_signed_bytes(unsigned))
        ).decode("ascii"),
    }
    text = json_bytes(envelope)
    public = key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    # The exact runtime verifier validates the complete signed schema locally.
    with tempfile.TemporaryDirectory(prefix="vesta-issuer-check-") as folder:
        trust = Path(folder) / "public-keys.json"
        write_new(
            trust,
            json_bytes(
                {
                    "schema_version": 1,
                    "keys": {
                        args.key_id: base64.b64encode(public).decode("ascii"),
                    },
                }
            ),
        )
        verify_certificate(
            text.decode(),
            keys_path=str(trust),
            installation_id=payload.get("installation_id"),
            now=intended_start(payload),
        )
    write_new(args.output, text)
    return {
        "license_id": payload["license_id"],
        "class": payload["class"],
        "certificate_created": True,
    }


def operator_label(reason):
    if not reason or len(reason) > 80 or any(ord(char) < 32 for char in reason):
        raise ValueError(
            "Provide a non-secret operator reason of 1 to 80 printable characters"
        )
    uid = os.getuid()
    try:
        name = pwd.getpwuid(uid).pw_name[:24]
    except KeyError:
        name = str(uid)
    return f"os:{name} uid:{uid}; {reason}"


def run_operator(args, session_factory=None):
    from core.license_registration import LicensingActor, LicensingService
    from core.tenant_context import PlatformContext

    if session_factory is None:
        from database import SessionLocal

        session_factory = SessionLocal
    actor = LicensingActor(
        user_id=args.actor_user_id, label=operator_label(args.reason), kind="operator"
    )
    with PlatformContext(), session_factory() as db:
        service = LicensingService(db, actor=actor)
        try:
            if args.command == "status":
                result = service.status()
                service.record_operator_access("status")
                return result
            if args.command == "details":
                result = service.details()
                service.record_operator_access("details")
                return result
            if args.command == "import":
                return service.import_certificate(
                    read_file(args.certificate_file).decode("utf-8")
                )
            if args.command == "set-registration-url":
                return service.set_registration_url(args.url)
            if args.command == "ack-prepare":
                if not args.confirm_review:
                    raise ValueError(
                        "First review confirmation requires --confirm-review"
                    )
                challenge = service.prepare_acknowledgement(confirm=True)
                write_new(args.challenge_file, json_bytes(challenge))
                return {
                    "challenge_file_created": True,
                    "expires_at": challenge.get("expires_at"),
                    "status": challenge.get("status"),
                }
            if args.command == "ack-confirm":
                if not args.confirm_hide:
                    raise ValueError(
                        "Second confirmation requires --confirm-hide and an explicit phrase file"
                    )
                challenge = read_json(args.challenge_file)
                phrase = read_file(args.phrase_file).decode("utf-8").rstrip("\r\n")
                return service.confirm_acknowledgement(
                    challenge["challenge"], phrase, confirm=True
                )
            if args.command == "ack-clear":
                return service.clear_acknowledgement()
            raise ValueError("Unknown operator command")
        except Exception:
            db.rollback()
            raise


def build_parser():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    generate = commands.add_parser(
        "keygen", help="explicit issuer-only action; never called at deployment"
    )
    generate.add_argument("--key-id", required=True)
    generate.add_argument("--private-key", required=True)
    generate.add_argument("--public-keys", required=True)
    issuer = commands.add_parser(
        "issue", help="sign an exact local Vesta payload using a custodied issuer key"
    )
    issuer.add_argument("--key-id", required=True)
    issuer.add_argument("--private-key", required=True)
    issuer.add_argument("--payload-file", required=True)
    issuer.add_argument("--output", required=True)
    for name in (
        "status",
        "details",
        "import",
        "set-registration-url",
        "ack-prepare",
        "ack-confirm",
        "ack-clear",
    ):
        command = commands.add_parser(name)
        command.add_argument(
            "--actor-user-id",
            required=True,
            help="existing active installation administrator UUID",
        )
        command.add_argument(
            "--reason",
            required=True,
            help="non-secret operator audit reason; keep identical across acknowledgement steps",
        )
        if name == "import":
            command.add_argument("--certificate-file", required=True)
        elif name == "set-registration-url":
            command.add_argument(
                "--url", required=True, help="display link only; never fetched"
            )
        elif name == "ack-prepare":
            command.add_argument("--confirm-review", action="store_true")
            command.add_argument(
                "--challenge-file", required=True, help="new private local output file"
            )
        elif name == "ack-confirm":
            command.add_argument("--challenge-file", required=True)
            command.add_argument(
                "--phrase-file",
                required=True,
                help="explicitly prepared local confirmation phrase",
            )
            command.add_argument("--confirm-hide", action="store_true")
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        result = (
            keygen(args)
            if args.command == "keygen"
            else issue(args) if args.command == "issue" else run_operator(args)
        )
    except Exception as error:
        # Inputs and issuer material never appear in traceback/exception output.
        print(
            json.dumps(
                {
                    "error": getattr(error, "code", "operator_command_refused"),
                    "type": type(error).__name__,
                }
            )
        )
        return 1
    print(json.dumps(result, sort_keys=True, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
