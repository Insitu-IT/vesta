"""Persist native inventory/target authority before the first upload control.

No native launch, payload read, credential resolution or publication happens here.
All repeat delivery refers to the one original agent/attempt and custody token.
"""

from copy import deepcopy
import uuid

from core.native_inventory import digest, exact, refuse
from core.native_storage import FORMAT, build_artifacts
from core.native_storage_wire import NativeTransactionRequest
from core.s3_ownership import reserve_publication
from core.storage_encryption import select_encryption
from core.storage_wire import plan_digest


def commit_native_source_plan(
    db, backup_id, config, *, dispatch_token=None, revalidate_token=None
):
    from core.native_job import admit
    from core.native_manifest import FORMAT as PUSH_FORMAT, bind_inventory

    try:
        if dispatch_token is not None and revalidate_token is not None:
            refuse()
        backup, actor, agent, source = admit(db, backup_id)
        intent, saved = backup.native_job_intent, backup.native_inventory
        if (
            not intent
            or not saved
            or not backup.native_inventory_transaction_id
            or intent.get("source") != source
            or intent.get("actor_id") != (actor.id if actor else None)
            or intent.get("producer") != PUSH_FORMAT
            or intent.get("checkpoint") != "vnbui-" + intent["attempt_id"]
            or source["backup_type"] not in {"full", "incremental"}
            or saved.get("intent_sha256") != digest(intent)
            or saved.get("inventory_sha256") != digest(saved["inventory"])
        ):
            refuse()
        bind_inventory(saved["push_result"], saved["inventory"], intent)
        parent = None
        if source["backup_type"] == "incremental":
            from core.native_lineage import select_parent

            parent, push_parent = select_parent(db, backup, source)
            if parent != intent.get("parent") or push_parent != intent.get(
                "push_parent"
            ):
                refuse()
        elif source["parent_backup_id"] is not None or intent.get("parent") is not None:
            refuse()
        native = dict(
            representation=FORMAT,
            agent_id=agent.id,
            vm_id=source["vm_id"],
            inventory_sha256=saved["inventory_sha256"],
            inventory=deepcopy(saved["inventory"]),
        )
        claim = reserve_publication(
            db, backup.id, "payload", config, reservation_id=intent["attempt_id"]
        )
        if claim.state != "reserved":
            refuse()
        encryption = select_encryption(
            db, backup, read_only=claim.expected_plan is not None
        )
        if intent.get("target") != config or intent.get("encryption") != encryption:
            refuse()
        plan = dict(
            attempt_id=claim.id,
            capability_profile=config["capability_profile"],
            provider="libvirt",
            source=native,
            backup_type=source["backup_type"],
            parent=deepcopy(parent),
            exclusions=source["exclusions"],
            target=dict(
                endpoint=config["endpoint"],
                bucket=config["bucket"],
                region=config["region"],
                configuration_prefix=config["prefix"],
            ),
            credential_ref="installation/storage.s3",
            encryption=encryption,
            artifacts=build_artifacts(
                native, backup.org_id, backup.id, claim.id, encryption
            ),
            checksum_policy="sha256-parts-receipt-v2",
        )
        if parent is not None:
            from models import StorageLineageGeneration

            accepted = db.get(
                StorageLineageGeneration, parent["generation_id"]
            ).accepted_request["plan"]
            if any(
                accepted[key] != plan[key]
                for key in ("target", "capability_profile", "encryption", "exclusions")
            ):
                refuse()  # configuration/key-policy change requires a fresh full
        request = dict(
            protocol="vnbui-storage-transaction/1",
            org_id=backup.org_id,
            agent_id=agent.id,
            backup_id=backup.id,
            reservation_id=claim.id,
            plan_sha256=plan_digest(plan),
            plan=plan,
        )
        NativeTransactionRequest.model_validate(request)
        expected = dict(schema=3, transaction=request)
        if claim.expected_plan is not None and claim.expected_plan != expected:
            refuse()
        if revalidate_token is not None:
            if (
                claim.expected_plan != expected
                or claim.dispatch_token != revalidate_token
            ):
                refuse()
            if backup.authority_kind == "scheduler":
                from core.scheduler_admission import validate_same_intent

                validate_same_intent(
                    db, backup.id, revalidate_token, request, callback=True
                )
            return claim  # caller retains locks until its own commit/rollback
        if dispatch_token is not None:
            if claim.expected_plan != expected or claim.dispatch_token is not None:
                refuse()
            claim.dispatch_token = dispatch_token
        claim.expected_plan = expected
        db.commit()
        return claim
    except Exception:
        db.rollback()
        raise


def resolve_native_transaction(db, backup_id, agent_id, binding, credential):
    """Mounted delivery with two durable boundaries: whole plan, then custody.

    A lost response may recover the identical request, never allocate a new key
    or transfer the original custody. Each subsequent provider call re-admits.
    """
    from core.native_job import admit
    from core.storage_attempt_key import _credential
    from core.storage_dispatch import read_target
    from core.settings_service import SettingsService

    try:
        backup, _, agent, _ = admit(db, backup_id)
        _credential(db, agent.id, credential)
        exact(binding, {"attempt_id", "inventory_sha256"})
        if (
            agent.id != agent_id
            or not backup.native_inventory
            or binding
            != dict(
                attempt_id=backup.native_job_intent["attempt_id"],
                inventory_sha256=backup.native_inventory["inventory_sha256"],
            )
        ):
            refuse()
        # End the initial authentication transaction before clean-plan admission.
        db.rollback()
        config = read_target(SettingsService(db))
        claim = commit_native_source_plan(db, backup_id, config)
        token = claim.dispatch_token
        if token is None:
            claim = commit_native_source_plan(
                db, backup_id, config, dispatch_token=str(uuid.uuid4())
            )
            token = claim.dispatch_token
        if backup.authority_kind == "scheduler" and claim.dispatch_admission is None:
            # Native production precedes the whole S3 plan. Its original T2
            # grant admitted the producer; bind the now-complete request before
            # any credential, attempt key or provider control can be disclosed.
            from core.scheduler_admission import record_dispatch_admission

            record_dispatch_admission(
                db, backup_id, token, deepcopy(claim.expected_plan["transaction"])
            )
            db.commit()
        # Recheck credential and persisted authority after both commits.
        claim = commit_native_source_plan(
            db, backup_id, read_target(SettingsService(db)), revalidate_token=token
        )
        _credential(db, agent_id, credential)
        if claim.expected_plan["transaction"]["agent_id"] != agent_id:
            refuse()
        result = deepcopy(claim.expected_plan["transaction"])
        db.commit()
        return result
    except Exception:
        db.rollback()
        raise
