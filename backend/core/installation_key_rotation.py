"""Rewrap an isolated PostgreSQL 17 restore before installing its post-data objects."""

import argparse
import base64
import hashlib
import hmac
import io
import json
import os
import re
import stat
import sys
from contextlib import closing
from pathlib import Path
from tempfile import NamedTemporaryFile
from uuid import UUID

import psycopg2
from alembic.script import ScriptDirectory
from cryptography.fernet import Fernet, InvalidToken, MultiFernet
from psycopg2.extensions import parse_dsn

from core.installation_config import RECOVERY_SIGNER_IDENTITY, RECOVERY_SIGNING_SEED
from core.recovery_key_identity import verify_signing_seed


class RotationError(Exception):
    """Only fixed error strings may be reported by the maintenance command."""


MANIFEST_FIELDS = {
    "installation_id",
    "source_database",
    "target_database",
    "owner_dsn_file",
    "old_key_file",
    "new_key_file",
    "receipt_file",
}


def private_file(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        mode = os.fstat(descriptor).st_mode
        # A private projected Secret can grant read access to the pod's fsGroup.
        if not stat.S_ISREG(mode) or mode & 0o037:
            raise RotationError("Input files must be private regular files")
        data = stream.read(65537)
    if len(data) > 65536:
        raise RotationError("Input file exceeds the supported size")
    return data


def write_private_file(path, data):
    # Publish a complete file without replacing an existing name, even on retry.
    # The receipt must survive loss of the database connection during COMMIT.
    directory_stat = path.parent.stat()
    if directory_stat.st_uid != os.geteuid() or directory_stat.st_mode & 0o077:
        raise RotationError(
            "Output directory must be private and owned by the maintenance user"
        )
    with NamedTemporaryFile(dir=path.parent) as stream:
        stream.write(data + b"\n")
        stream.flush()
        os.fsync(stream.fileno())
        os.link(stream.name, path)
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def load_manifest(path):
    manifest = json.loads(private_file(path))
    if (
        not isinstance(manifest, dict)
        or manifest.keys() != MANIFEST_FIELDS
        or any(not isinstance(value, str) or not value for value in manifest.values())
    ):
        raise RotationError("Manifest fields are missing or invalid")
    installation_id = UUID(manifest["installation_id"])
    if not installation_id.int or str(installation_id) != manifest["installation_id"]:
        raise RotationError("Installation UUID must be canonical")
    source = manifest["source_database"]
    target = manifest["target_database"]
    if source == target:
        raise RotationError("Source and target database names must differ")
    if any(len(name.encode()) > 63 or "\0" in name for name in (source, target)):
        raise RotationError("Database names are invalid")
    for field in MANIFEST_FIELDS - {
        "installation_id",
        "source_database",
        "target_database",
    }:
        reference = Path(manifest[field])
        if not reference.is_absolute():
            raise RotationError("File references must be absolute")
        manifest[field] = reference
    return manifest


def load_root(path):
    key = private_file(path).strip()
    decoded = base64.urlsafe_b64decode(key)
    if len(decoded) != 32 or base64.urlsafe_b64encode(decoded) != key:
        raise RotationError("Root key file must contain one Fernet key")
    return key


def connect_target(manifest):
    parameters = parse_dsn(private_file(manifest["owner_dsn_file"]).decode().strip())
    host = parameters.get("host", "")
    if (
        parameters.get("dbname") != manifest["target_database"]
        or not parameters.get("user")
        or not host
        or "," in host
        or parameters.keys()
        - {
            "dbname",
            "user",
            "host",
            "port",
            "password",
            "passfile",
            "sslmode",
            "sslrootcert",
            "sslcert",
            "sslkey",
            "gssencmode",
        }
    ):
        raise RotationError(
            "Owner connection requires a single explicit target, host and login"
        )
    if not host.startswith("/") and (
        parameters.get("sslmode") != "verify-full" or not parameters.get("sslrootcert")
    ):
        raise RotationError(
            "TCP owner connection requires verify-full TLS and a CA file"
        )
    parameters.update(
        hostaddr="",
        options="-c search_path=pg_catalog",
        gssencmode="disable",
        connect_timeout=10,
        application_name="vesta-installation-key-rotation",
    )
    connection = psycopg2.connect(**parameters)
    if not host.startswith("/") and not connection.info.ssl_in_use:
        connection.close()
        raise RotationError("TCP owner connection must use TLS")
    return connection


def require_isolated_clone(cursor, manifest):
    cursor.execute(
        """
        SELECT d.oid, d.datdba
        FROM pg_database d
        WHERE d.datname = current_database() AND d.datname = %s
          AND session_user = current_user
          AND pg_get_userbyid(d.datdba) = current_user
          AND EXISTS (
              SELECT FROM pg_roles WHERE oid = d.datdba
                AND NOT rolsuper AND NOT rolbypassrls AND NOT rolreplication
          )
          AND NOT EXISTS (SELECT FROM pg_auth_members WHERE roleid = d.datdba)
          AND NOT EXISTS (
              SELECT FROM aclexplode(coalesce(d.datacl, acldefault('d', d.datdba))) a
              WHERE a.privilege_type = 'CONNECT' AND a.grantee <> d.datdba
          )
        """,
        (manifest["target_database"],),
    )
    identity = cursor.fetchone()
    if identity is None:
        raise RotationError(
            "Target must be the distinct database owned by this login with owner-only CONNECT"
        )
    database_oid, owner = identity
    require_pre_data(cursor, owner, database_oid)
    cursor.execute("""
        LOCK TABLE public.alembic_version, public.storage_configuration_clock,
                   public.encryption_keys, public.secrets_v3, public.settings_v3,
                   public.recovery_publications
        IN ACCESS EXCLUSIVE MODE NOWAIT
        """)
    require_pre_data(cursor, owner, database_oid)
    cursor.execute("SELECT version_num FROM public.alembic_version")
    expected = ScriptDirectory(
        str(Path(__file__).resolve().parents[1] / "alembic")
    ).get_current_head()
    if cursor.fetchall() != [(expected,)]:
        raise RotationError("Target schema revision differs from this API image")
    cursor.execute(
        "SELECT slot, installation_id, revision FROM public.storage_configuration_clock"
    )
    clock = cursor.fetchall()
    if (
        len(clock) != 1
        or clock[0][:2] != (1, manifest["installation_id"])
        or clock[0][2] is None
        or clock[0][2] <= 0
    ):
        raise RotationError(
            "Target installation identity or configuration revision differs"
        )
    return database_oid, clock[0][2]


def require_pre_data(cursor, owner, database_oid):
    cursor.execute("SELECT pg_stat_clear_snapshot()")
    cursor.execute(
        """
        SELECT EXISTS (
            SELECT FROM pg_stat_activity
            WHERE datid = %s AND pid <> pg_backend_pid()
        ) OR EXISTS (
            SELECT FROM pg_prepared_xacts WHERE database = current_database()
        )
        """,
        (database_oid,),
    )
    if cursor.fetchone()[0]:
        raise RotationError(
            "Target has another database session or a prepared transaction"
        )
    # pg_restore creates the FORCE flag with the table, before RLS is enabled.
    cursor.execute(
        """
        SELECT EXISTS (
            SELECT
            FROM pg_class c JOIN pg_namespace n ON c.relnamespace = n.oid
            WHERE n.nspname = 'public'
              AND (c.relowner <> %s OR c.relrowsecurity OR c.relhassubclass
                   OR c.relkind IN ('i', 'I', 'p', 'f', 'v', 'm')
                   OR EXISTS (SELECT FROM pg_trigger WHERE tgrelid = c.oid)
                   OR EXISTS (SELECT FROM pg_policy WHERE polrelid = c.oid)
                   OR EXISTS (SELECT FROM pg_rewrite WHERE ev_class = c.oid)
                   OR EXISTS (
                       SELECT FROM aclexplode(c.relacl) a WHERE a.grantee <> %s
                   ))
        ) OR EXISTS (SELECT FROM pg_event_trigger) OR EXISTS (
            SELECT
            FROM pg_proc p JOIN pg_namespace n ON p.pronamespace = n.oid
            WHERE n.nspname = 'public' AND (
                p.proowner <> %s OR EXISTS (
                    SELECT FROM aclexplode(coalesce(p.proacl, acldefault('f', p.proowner))) a
                    WHERE a.grantee <> %s
                )
            )
        )
        """,
        (owner,) * 4,
    )
    if cursor.fetchone()[0]:
        raise RotationError(
            "Target contains installed post-data objects or unexpected ownership or grants"
        )


def open_token(token, old, new):
    try:
        payload = old.decrypt(token)
    except InvalidToken:
        try:
            return "new", new.decrypt(token)
        except InvalidToken:
            raise RotationError(
                "An encrypted record cannot be opened with the supplied roots"
            ) from None
    return "old", payload


def inspect_envelopes(cursor, old, new, apply, installation_id):
    cursor.execute("""
        SELECT id, ctid, encrypted_material, provider, provider_key_ref, algorithm, key_hash, status
        FROM public.encryption_keys ORDER BY id
        """)
    keys = cursor.fetchall()
    cursor.execute(
        "SELECT key, ctid, encrypted_value, source, vault_path FROM public.secrets_v3 ORDER BY key"
    )
    secrets = cursor.fetchall()
    cursor.execute(
        "SELECT value, value_type, source FROM public.settings_v3 WHERE key = %s",
        (RECOVERY_SIGNER_IDENTITY,),
    )
    markers = cursor.fetchall()
    has_seed = any(row[0] == RECOVERY_SIGNING_SEED for row in secrets)
    if has_seed or markers:
        if (
            not has_seed
            or len(markers) != 1
            or markers[0][1:] != ("json", "installation")
        ):
            raise RotationError(
                "The installation recovery signer has incomplete custody"
            )
    else:
        cursor.execute(
            "SELECT EXISTS (SELECT FROM public.recovery_publications "
            "WHERE envelope IS NOT NULL OR published_at IS NOT NULL)"
        )
        if cursor.fetchone()[0]:
            raise RotationError(
                "The retained recovery records have no installation signer"
            )
    if len({row[0] for row in keys}) != len(keys) or len(
        {row[0] for row in secrets}
    ) != len(secrets):
        raise RotationError("Target contains duplicate protected record identities")

    states = set()
    inventory = hashlib.sha256()
    rewrap = MultiFernet([new, old])
    counts = {"local_keks": 0, "stored_secrets": 0}
    updates = {"local_keks": [], "stored_secrets": []}

    def inspect(kind, identity, row_pointer, token, *, key_hash=None):
        armored = token.encode("ascii")
        state, plaintext = open_token(armored, old, new)
        digest = hashlib.sha256(plaintext).hexdigest()
        if key_hash is not None:
            if len(plaintext) != 32 or not hmac.compare_digest(digest[:16], key_hash):
                raise RotationError(
                    "A local KEK does not match its recorded material hash or length"
                )
        elif identity == RECOVERY_SIGNING_SEED:
            try:
                verify_signing_seed(plaintext, markers[0][0], installation_id)
            except (ValueError, TypeError) as exc:
                raise RotationError(
                    "The recovery signing seed differs from its public identity"
                ) from exc
        else:
            plaintext.decode("utf-8")
        states.add(state)
        inventory.update(json.dumps([kind, identity, digest]).encode() + b"\n")
        counts[kind] += 1
        if apply and state == "old":
            rotated = rewrap.rotate(armored)
            if not hmac.compare_digest(new.decrypt(rotated), plaintext):
                raise RotationError("Rewrapped material failed verification")
            updates[kind].append(f"{row_pointer}\t{rotated.decode('ascii')}\n")

    for (
        identity,
        row_pointer,
        token,
        provider,
        external_ref,
        algorithm,
        key_hash,
        status,
    ) in keys:
        if provider != "local" or external_ref is not None:
            raise RotationError(
                "Target contains a KEK provider outside local root-key custody"
            )
        if (
            not identity
            or algorithm != "aes-256-gcm"
            or not re.fullmatch("[0-9a-f]{16}", key_hash or "")
            or status not in {"active", "rotated", "revoked"}
            or (status == "active" and token is None)
        ):
            raise RotationError(
                "Target contains malformed or unsupported local KEK metadata"
            )
        if token is not None:
            inspect("local_keks", identity, row_pointer, token, key_hash=key_hash)

    for identity, row_pointer, token, source, vault_path in secrets:
        if identity == RECOVERY_SIGNING_SEED:
            if source != "installation" or vault_path is not None or token is None:
                raise RotationError(
                    "The installation recovery signer has invalid secret custody"
                )
            inspect("stored_secrets", identity, row_pointer, token)
            continue
        if (
            not identity
            or source not in {"ui", "vault"}
            or (
                (source == "vault" and token is not None)
                or (source == "ui" and vault_path is not None)
            )
        ):
            raise RotationError("Target contains malformed stored secret metadata")
        if token is not None:
            inspect("stored_secrets", identity, row_pointer, token)

    if not states:
        raise RotationError(
            "Target has no encrypted records to authenticate the old root"
        )
    if len(states) != 1:
        raise RotationError("Target mixes old-root and new-root encrypted records")
    return states.pop(), counts, inventory.hexdigest(), updates


def update_envelopes(cursor, updates):
    # COPY keeps ciphertext and row identifiers out of SQL statement text.
    # A locked heap's row pointers remain valid until their respective updates.
    cursor.execute(
        "CREATE TEMP TABLE rotation_envelopes (row_pointer tid, ciphertext text) ON COMMIT DROP"
    )
    for kind, table, column in (
        ("local_keks", "encryption_keys", "encrypted_material"),
        ("stored_secrets", "secrets_v3", "encrypted_value"),
    ):
        rows = updates[kind]
        cursor.execute("TRUNCATE pg_temp.rotation_envelopes")
        cursor.copy_expert(
            "COPY pg_temp.rotation_envelopes FROM STDIN", io.StringIO("".join(rows))
        )
        cursor.execute(
            f"UPDATE public.{table} AS restored SET {column} = staged.ciphertext "
            "FROM pg_temp.rotation_envelopes AS staged WHERE restored.ctid = staged.row_pointer"
        )
        if cursor.rowcount != len(rows):
            raise RotationError("Rewrapped record count differs")


def rotate(manifest, apply):
    old_key = load_root(manifest["old_key_file"])
    new_key = load_root(manifest["new_key_file"])
    if hmac.compare_digest(old_key, new_key):
        raise RotationError("Old and new root keys must differ")
    old, new = Fernet(old_key), Fernet(new_key)
    receipt_file = manifest["receipt_file"]
    with closing(
        connect_target(manifest)
    ) as connection, connection, connection.cursor() as cursor:
        if connection.server_version // 10000 != 17:
            raise RotationError("Rotation requires PostgreSQL 17")
        cursor.execute("SET LOCAL statement_timeout = '5min'")
        database_oid, revision = require_isolated_clone(cursor, manifest)
        state, counts, inventory, updates = inspect_envelopes(
            cursor, old, new, apply, manifest["installation_id"]
        )
        evidence = json.dumps(
            {
                "format": 1,
                "source_database": manifest["source_database"],
                "target_database": manifest["target_database"],
                "installation_id": manifest["installation_id"],
                "target_oid": database_oid,
                "configuration_revision": revision,
                "inventory": inventory,
                **counts,
            },
            sort_keys=True,
        ).encode()
        try:
            receipt = private_file(receipt_file).strip()
        except FileNotFoundError:
            if state == "new":
                raise RotationError(
                    "New-root records have no matching rotation receipt"
                ) from None
            if apply:
                write_private_file(receipt_file, old.encrypt(new.encrypt(evidence)))
        else:
            try:
                recorded = new.decrypt(old.decrypt(receipt))
            except InvalidToken:
                raise RotationError(
                    "Rotation receipt does not authenticate both supplied roots"
                ) from None
            if not hmac.compare_digest(recorded, evidence):
                raise RotationError(
                    "Rotation receipt does not match this clone and protected inventory"
                )

        if apply and state == "old":
            update_envelopes(cursor, updates)
            verified = inspect_envelopes(
                cursor, old, new, False, manifest["installation_id"]
            )
            if verified[:3] != ("new", counts, inventory):
                raise RotationError("Stored rewrapped inventory failed verification")
            result = "rotated"
        elif state == "new":
            result = "already_rotated"
        else:
            result = "ready"
    return {"state": result, "configuration_revision": revision, **counts}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("plan", "apply", "new-key"))
    parser.add_argument(
        "file", type=Path, help="private manifest or new-key output path"
    )
    args = parser.parse_args(argv)
    try:
        if args.command == "new-key":
            write_private_file(args.file, Fernet.generate_key())
            result = {"state": "key_created"}
        else:
            result = rotate(load_manifest(args.file), args.command == "apply")
    except RotationError as error:
        print(f"Installation key rotation refused. {error}.", file=sys.stderr)
        return 1
    except Exception:
        # DSN, SQL, encoding and filesystem exceptions can include private values.
        print(
            "Installation key rotation failed. Check private files, clone access and restore stage.",
            file=sys.stderr,
        )
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
