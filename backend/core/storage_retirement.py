"""Return an exact DB-reviewed release to the original authenticated agent.

This callback grants no capacity release. The migration-owner review already
made that decision; ordinary runtime can only read its immutable evidence.
"""

import re

from sqlalchemy import text

from core.s3_ownership import StorageOwnershipError
from core.storage_wire import validate_transaction
from models import Backup, S3Publication, VM

HASH = re.compile(r"[0-9a-f]{64}\Z")


def retirement_proof(db, backup_id, agent_id, binding, credential):
    from core.storage_attempt_key import _credential

    if (
        type(binding) is not dict
        or set(binding)
        != {
            "reservation_id",
            "attempt_id",
            "plan_sha256",
            "journal_sha256",
        }
        or any(type(value) is not str for value in binding.values())
        or not all(binding[key] for key in binding)
        or HASH.fullmatch(binding["plan_sha256"]) is None
        or HASH.fullmatch(binding["journal_sha256"]) is None
    ):
        raise StorageOwnershipError("Retirement binding unavailable")

    _credential(db, agent_id, credential)
    backup = (
        db.query(Backup)
        .filter_by(id=backup_id)
        .populate_existing()
        .with_for_update()
        .one_or_none()
    )
    if (
        backup is None
        or backup.status != "failed"
        or backup.capacity_state != "released"
    ):
        raise StorageOwnershipError("Reviewed release unavailable")
    vm = db.query(VM).filter_by(id=backup.vm_id).one_or_none()
    if (
        vm is None
        or vm.agent_id != agent_id
        or vm.provider not in {"kubevirt", "libvirt"}
    ):
        raise StorageOwnershipError("Original agent unavailable")

    release = backup.capacity_release or {}
    reviews = backup.capacity_modern_reviews or []
    review = reviews[-1] if type(reviews) is list and reviews else {}
    if (
        release.get("reason") != "reviewed_modern_quiescence"
        or release.get("schema") != 1
        or release.get("capacity_id") != str(backup.capacity_id)
        or release.get("operation_id") != review.get("operation_id")
        or release.get("journal_sha256") != binding["journal_sha256"]
        or review.get("classification") != "released"
        or review.get("journal_sha256") != binding["journal_sha256"]
    ):
        raise StorageOwnershipError("Release and held journal disagree")

    publications = (
        db.query(S3Publication)
        .filter_by(backup_id=backup_id)
        .populate_existing()
        .with_for_update()
        .all()
    )
    if (
        not publications
        or sorted(item.id for item in publications) != review.get("publication_ids")
        or any(item.state != "deleted" for item in publications)
    ):
        raise StorageOwnershipError("Publication custody disagrees")
    payload = next((item for item in publications if item.kind == "payload"), None)
    request = (payload.expected_plan or {}).get("transaction") if payload else None
    try:
        if type(request) is not dict:
            raise ValueError()
        validate_transaction(request)
    except (ValueError, TypeError, KeyError) as error:
        raise StorageOwnershipError("Original transaction unavailable") from error
    if (
        request.get("org_id") != backup.org_id
        or request.get("backup_id") != backup.id
        or request.get("agent_id") != agent_id
        or request.get("reservation_id") != binding["reservation_id"]
        or request.get("plan_sha256") != binding["plan_sha256"]
        or request.get("plan", {}).get("attempt_id") != binding["attempt_id"]
        or request["plan"]["provider"] != vm.provider
        or request["plan"]["capability_profile"] != "db-rooted-consumer-verified/1"
        or request["plan"]["source"]["vm_id"] != backup.vm_id
        or payload.id != binding["reservation_id"]
        or payload.org_id != backup.org_id
    ):
        raise StorageOwnershipError("Original transaction disagrees")

    if vm.provider == "libvirt":
        from core.native_inventory import digest
        from core.native_manifest import bind_inventory

        intent, closed = backup.native_job_intent, backup.native_inventory
        try:
            if (
                not intent
                or not closed
                or intent["backup_id"] != backup.id
                or intent["org_id"] != backup.org_id
                or intent["agent_id"] != agent_id
                or intent["attempt_id"] != binding["attempt_id"]
                or closed["intent_sha256"] != digest(intent)
                or closed["inventory_sha256"] != digest(closed["inventory"])
                or request["plan"]["source"]["inventory"] != closed["inventory"]
            ):
                raise ValueError("Native closure disagrees")
            bind_inventory(closed["push_result"], closed["inventory"], intent)
        except (ValueError, TypeError, KeyError) as error:
            raise StorageOwnershipError(
                "Original native closure unavailable"
            ) from error

    release_hash = db.scalar(
        text(
            "SELECT encode(sha256(convert_to(capacity_release::text,'UTF8')),'hex') "
            "FROM public.backups WHERE id=:id AND org_id=:org"
        ),
        {"id": backup.id, "org": backup.org_id},
    )
    if not release_hash or HASH.fullmatch(release_hash) is None:
        raise StorageOwnershipError("Release digest unavailable")
    return {
        "schema": 1,
        "org_id": backup.org_id,
        "backup_id": backup.id,
        "reservation_id": binding["reservation_id"],
        "attempt_id": binding["attempt_id"],
        "plan_sha256": binding["plan_sha256"],
        "operation_id": release["operation_id"],
        "capacity_id": release["capacity_id"],
        "journal_sha256": binding["journal_sha256"],
        "release_sha256": release_hash,
    }
