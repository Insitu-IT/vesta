"""Accepted-receipt finalize custody. No Kubernetes or publication operation."""

from copy import deepcopy
import os
import re
import uuid

from core.s3_ownership import StorageOwnershipError
from core.settings_service import SettingsService
from core.storage_attempt_key import _credential
from core.storage_dispatch import read_target
from core.storage_source import readmit_kubevirt_callback
from core.storage_wire import TransactionRequest
from models import S3Publication


def refuse():
    raise StorageOwnershipError("Finalize evidence unavailable; retain journal")


def admit(db, backup_id, agent_id, credential):
    if db.new or db.dirty or db.deleted:
        refuse()
    claim = (
        db.query(S3Publication)
        .filter_by(backup_id=backup_id, kind="payload")
        .populate_existing()
        .one_or_none()
    )
    if claim is None or (claim.expected_plan or {}).get("schema") != 3:
        refuse()
    request = claim.expected_plan["transaction"]
    TransactionRequest.model_validate(request)
    if request["agent_id"] != agent_id or not claim.dispatch_token:
        refuse()
    admitted = readmit_kubevirt_callback(
        db,
        backup_id,
        read_target(SettingsService(db)),
        revalidate_token=claim.dispatch_token,
    )
    db.refresh(admitted)
    _credential(db, agent_id, credential)
    if admitted.id != claim.id or admitted.expected_plan["transaction"] != request:
        refuse()
    if admitted.state != "reserved" or admitted.prepared_receipt is None:
        refuse()
    saved = admitted.prepared_receipt
    if saved.get("plan_sha256") != request["plan_sha256"] or not saved.get(
        "response", {}
    ).get("accepted"):
        refuse()
    return admitted, request, saved


def validate_binding(value, request, saved):
    fields = {
        "protocol",
        "reservation_id",
        "attempt_id",
        "plan_sha256",
        "receipt_sha256",
        "acceptance_id",
        "namespace",
        "vm_uid",
        "vmi_uid",
        "tracker_name",
        "tracker_uid",
        "vmb_name",
        "vmb_uid",
        "checkpoint",
        "parent",
        "volumes",
        "started_at",
        "guest_consistency",
        "guest_evidence_source",
    }
    if type(value) is not dict or set(value) != fields:
        refuse()
    prefix = os.environ.get("KUBEVIRT_RESOURCE_PREFIX") or "vnbui"
    if prefix not in {"vnbui", "vesta"}:
        refuse()
    source = request["plan"]["source"]
    expected = dict(
        protocol=request["protocol"],
        reservation_id=request["reservation_id"],
        attempt_id=request["plan"]["attempt_id"],
        plan_sha256=request["plan_sha256"],
        receipt_sha256=saved["receipt_sha256"],
        acceptance_id=saved["response"]["acceptance_id"],
        namespace=source["namespace"],
        vm_uid=source["vm_uid"],
        vmi_uid=source["vmi_uid"],
        parent=request["plan"]["parent"],
        volumes=source["volumes"],
        vmb_name=prefix + "-" + request["backup_id"],
        guest_evidence_source="kubevirt/VMB.status.conditions",
    )
    if any(value[k] != v for k, v in expected.items()):
        refuse()
    for key in ("tracker_name", "tracker_uid", "vmb_uid", "checkpoint"):
        if (
            type(value[key]) is not str
            or re.fullmatch(r"[A-Za-z0-9_.:-]{1,253}", value[key]) is None
        ):
            refuse()
    from datetime import datetime

    try:
        stamp = datetime.fromisoformat(value["started_at"].replace("Z", "+00:00"))
        if stamp.tzinfo is None:
            refuse()
    except (ValueError, AttributeError, TypeError):
        refuse()
    parent = request["plan"]["parent"]
    if parent and (
        parent["tracker_uid"] != value["tracker_uid"]
        or parent["checkpoint"] == value["checkpoint"]
    ):
        refuse()
    # Fixed controller outcomes, never requested skipQuiesce or raw messages.
    if value["guest_consistency"] not in (
        "quiesced",
        "failed",
        "crash-consistent",
        "unknown",
    ):
        refuse()


def finalize_intent(db, backup_id, agent_id, value, credential):
    try:
        claim, request, saved = admit(db, backup_id, agent_id, credential)
        validate_binding(value, request, saved)
        if claim.finalize_intent is not None:
            if claim.finalize_intent["binding"] != value:
                refuse()
        else:
            claim.finalize_intent = dict(
                intent_id=str(uuid.uuid4()), binding=deepcopy(value)
            )
        result = deepcopy(claim.finalize_intent)
        db.commit()
        return result
    except Exception:
        db.rollback()
        raise


def checkpoint_proof(db, backup_id, agent_id, value, credential):
    try:
        from core.storage_publication import (
            completed_publication,
            publish_checkpointed_backup,
        )

        completed = completed_publication(db, backup_id, agent_id, credential, value)
        if completed is not None:
            return {key: completed[key] for key in ("intent_id", "status", "completed")}
        claim, request, saved = admit(db, backup_id, agent_id, credential)
        intent = claim.finalize_intent
        if (
            intent is None
            or type(value) is not dict
            or set(value)
            != {
                "intent_id",
                "checkpoint",
                "tracker_resource_version",
                "terminal_resource_version",
                "checkpoint_creation_time",
                "vmb_absent",
                "guest_consistency",
            }
        ):
            refuse()
        binding = intent["binding"]
        validate_binding(binding, request, saved)
        if (
            value["intent_id"] != intent["intent_id"]
            or value["checkpoint"] != binding["checkpoint"]
            or value["checkpoint_creation_time"] != binding["started_at"]
            or value["guest_consistency"] != binding["guest_consistency"]
            or value["vmb_absent"] is not True
        ):
            refuse()
        for name in ("tracker_resource_version", "terminal_resource_version"):
            if (
                type(value[name]) is not str
                or re.fullmatch(r"[A-Za-z0-9_.:-]{1,253}", value[name]) is None
            ):
                refuse()
        if claim.checkpoint_proof is not None and claim.checkpoint_proof != value:
            refuse()
        claim.checkpoint_proof = deepcopy(value)
        db.commit()
        try:
            completed = publish_checkpointed_backup(db, backup_id, agent_id, credential)
            return {key: completed[key] for key in ("intent_id", "status", "completed")}
        except StorageOwnershipError:
            # The checkpoint fact is already durable. A provider outage leaves
            # a retryable exact generation intent; an identical proof retries it.
            # Never manufacture completion from agent status or S3 presence.
            pass
        return dict(
            intent_id=intent["intent_id"], status="awaiting_manifest", completed=False
        )
    except Exception:
        db.rollback()
        raise
