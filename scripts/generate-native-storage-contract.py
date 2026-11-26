#!/usr/bin/env python3
"""Generate review-only native wire examples, never local/provider evidence."""

import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

from core.native_inventory import digest  # noqa: E402
from core.native_storage import build_artifacts, validate_receipt  # noqa: E402
from core.native_storage_wire import NativeTransactionRequest  # noqa: E402
from core.storage_wire import plan_digest  # noqa: E402


def examples():
    inventory = json.loads(
        (
            ROOT / "tests/fixtures/storage-contract-v1/libvirt-native-fileset.json"
        ).read_text()
    )
    # Synthetic custody and content commitments, not a completed native job.
    inventory["checkpoint"] = "vnbui-" + inventory["attempt_id"]
    inventory["job_id"] = "vnbui-native-" + inventory["attempt_id"]
    for member, size in zip(inventory["files"], (0, 5242881, 4, 5, 1), strict=True):
        member["size"] = size
        member["member_checkpoint"] = inventory["checkpoint"]
        member["artifact_id"] = digest(
            [
                inventory[k]
                for k in (
                    "format",
                    "domain_uuid",
                    "backup_id",
                    "attempt_id",
                    "job_id",
                    "checkpoint",
                )
            ]
            + [
                member[k]
                for k in (
                    "member_backup_id",
                    "member_checkpoint",
                    "path",
                    "role",
                    "disk_id",
                )
            ]
        )
    source = {
        "representation": inventory["format"],
        "agent_id": "44444444-4444-4444-8444-444444444444",
        "vm_id": "55555555-5555-4555-8555-555555555555",
        "inventory_sha256": digest(inventory),
        "inventory": inventory,
    }
    org = "66666666-6666-4666-8666-666666666666"
    target = {
        "endpoint": "https://storage.example.invalid",
        "bucket": "fixture-bucket",
        "region": "eu-central",
        "configuration_prefix": "fixture",
    }
    result = []
    for use_encryption in (False, True):
        encryption = {
            "format": "vnbu1-aes256gcm-chunk5242880" if use_encryption else "none",
            "key_ref": (
                "kek:77777777-7777-4777-8777-777777777777:aaaaaaaaaaaaaaaa"
                if use_encryption
                else None
            ),
        }
        artifacts = build_artifacts(
            source, org, inventory["backup_id"], inventory["attempt_id"], encryption
        )
        objects = []
        for a in artifacts:
            objects.append(
                {
                    **{k: a[k] for k in ("artifact_id", "disk_id", "role", "key")},
                    "version_id": None,
                    "etag": "fixture-opaque-identity",
                    "plaintext_bytes": a["plaintext_max"],
                    "ciphertext_bytes": a["ciphertext_max"],
                    "plaintext_sha256": "a" * 64,
                    "ciphertext_sha256": ("b" if use_encryption else "a") * 64,
                }
            )
        receipt = {
            "protocol": "vnbui-storage-transaction/1",
            "schema": 2,
            "representation": source["representation"],
            "reservation_id": inventory["attempt_id"],
            "backup_id": inventory["backup_id"],
            "endpoint": target["endpoint"],
            "bucket": target["bucket"],
            "objects": objects,
        }
        _, receipt_hash = validate_receipt(
            receipt,
            artifacts,
            inventory["backup_id"],
            inventory["attempt_id"],
            target,
            encryption,
        )
        plan = dict(
            attempt_id=inventory["attempt_id"],
            capability_profile="db-rooted-consumer-verified/1",
            provider="libvirt",
            source=source,
            backup_type="full",
            parent=None,
            exclusions=[],
            target=target,
            credential_ref="installation/storage.s3",
            encryption=encryption,
            artifacts=artifacts,
            checksum_policy="sha256-parts-receipt-v2",
        )
        request = dict(
            protocol="vnbui-storage-transaction/1",
            org_id=org,
            agent_id=source["agent_id"],
            backup_id=inventory["backup_id"],
            reservation_id=inventory["attempt_id"],
            plan_sha256=plan_digest(plan),
            plan=plan,
        )
        NativeTransactionRequest.model_validate(request)
        result.append(
            {
                "request": request,
                "source": source,
                "org_id": org,
                "target": target,
                "encryption": encryption,
                "artifacts": artifacts,
                "receipt": receipt,
                "receipt_sha256": receipt_hash,
                "source_sha256": digest(source),
            }
        )
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    output = ROOT / "agent/contracts/native_storage_examples.json"
    body = json.dumps(examples(), indent=2, ensure_ascii=False) + "\n"
    if args.check:
        if output.read_text() != body:
            raise SystemExit(
                "Native contract drift: run python3 scripts/generate-native-storage-contract.py"
            )
    else:
        output.write_text(body)
