"""Explicit same-attempt redelivery; never replace custody or a producer.

The requester is audited separately from the original human/scheduler authority.
The agent may wake only a resumable original journal; uncertain phases stay held.
"""

import asyncio
import threading
from copy import deepcopy

from core.s3_ownership import StorageOwnershipError
from core.task_lifetime import run_owned_worker
from core.tenant_context import TenantContext
from models import (
    ActivityLog,
    Backup,
    Organization,
    S3Publication,
    SystemEvent,
    User,
    VM,
)


class RecoveryHeld(StorageOwnershipError):
    def __init__(self, reason):
        super().__init__(reason)
        self.reason = reason


def _locked(db, model, **where):
    return (
        db.query(model)
        .filter_by(**where)
        .populate_existing()
        .with_for_update()
        .one_or_none()
    )


def _requester(db, backup_id, org_id, caller_id):
    org = _locked(db, Organization, id=org_id)
    caller = _locked(db, User, id=caller_id, org_id=org_id)
    if (
        org is None
        or not org.enabled
        or caller is None
        or not caller.is_active
        or caller.role not in {"operator", "admin"}
    ):
        raise RecoveryHeld("requester_unavailable")
    backup = (
        db.query(Backup)
        .filter_by(id=backup_id, org_id=org_id)
        .populate_existing()
        .one_or_none()
    )
    if backup is None:
        raise RecoveryHeld("backup_unavailable")
    return backup


def _readmit(db, backup):
    """Return only the immutable original envelope after fresh owner admission."""
    from core.settings_service import SettingsService
    from core.storage_dispatch import read_target

    target = read_target(SettingsService(db))
    if (
        target["capability_profile"] != "db-rooted-consumer-verified/1"
        or not target["region"]
    ):
        raise RecoveryHeld("supported_storage_configuration_required")
    vm = db.query(VM).filter_by(id=backup.vm_id, org_id=backup.org_id).one_or_none()
    if vm is None:
        raise RecoveryHeld("original_source_unavailable")
    if vm.provider == "kubevirt":
        from core.storage_source import readmit_kubevirt_callback

        claim = (
            db.query(S3Publication)
            .filter_by(backup_id=backup.id, org_id=backup.org_id, kind="payload")
            .one_or_none()
        )
        if (
            claim is None
            or not claim.dispatch_token
            or (claim.expected_plan or {}).get("schema") != 3
        ):
            raise RecoveryHeld("original_dispatch_custody_required")
        claim = readmit_kubevirt_callback(
            db, backup.id, target, revalidate_token=claim.dispatch_token
        )
        request = deepcopy(claim.expected_plan["transaction"])
        expected = dict(
            status="accepted",
            **{k: request[k] for k in ("backup_id", "reservation_id", "plan_sha256")},
        )
        return request["agent_id"], request, expected
    if vm.provider == "libvirt":
        from core.native_inventory import digest
        from core.native_job import readmit_job

        intent = deepcopy(backup.native_job_intent)
        if not intent or not backup.native_job_transaction_id:
            raise RecoveryHeld("original_native_intent_required")
        readmit_job(db, backup.id, intent)
        request = dict(
            protocol="vnbui-native-job/1", intent=intent, intent_sha256=digest(intent)
        )
        expected = dict(
            status="accepted",
            backup_id=backup.id,
            attempt_id=intent["attempt_id"],
            intent_sha256=request["intent_sha256"],
        )
        return intent["agent_id"], request, expected
    raise RecoveryHeld("unsupported_backup_provider")


async def resume_backup_attempt(factory, executor, backup_id, org_id, caller_id):
    """One bounded, authenticated redelivery. No new IDs, plans or capacity.

    Transport completion is not backup completion. Existing callback admission
    checks current authority again before agent-side effects and publication.
    """
    # This admission belongs to the API loop through shutdown. The sync
    # requester/source locks and loop-neutral AgentHTTP send run together on a
    # worker loop, so one contended row cannot starve /health or /ready.
    cancelled = threading.Event()
    with executor.dispatch_lifetime.admission():
        return await run_owned_worker(
            lambda: asyncio.run(
                _resume_backup_attempt_worker(
                    factory, executor, backup_id, org_id, caller_id, cancelled
                )
            ),
            on_cancel=cancelled.set,
        )


async def _resume_backup_attempt_worker(
    factory, executor, backup_id, org_id, caller_id, cancellation
):
    with TenantContext(org_id):
        with factory() as db:
            try:
                backup = _requester(db, backup_id, org_id, caller_id)
                if backup.status == "completed":
                    return dict(status="completed", backup_id=backup_id, resumed=False)
                result = await _deliver_original(db, executor, backup, cancellation)
            except RecoveryHeld:
                raise
            except Exception as error:
                # Do not expose provider URLs, credentials or implementation
                # errors. Every failure leaves prior reservation and state intact.
                raise RecoveryHeld(
                    "original_authority_or_attempt_readmission_required"
                ) from error
            finally:
                db.rollback()
        # Attribution never replaces the initiating human or scheduler grant.
        # A failed audit commit cannot cause another send in this invocation.
        with factory() as db:
            db.add(
                ActivityLog(
                    user_id=caller_id,
                    action="backup_attempt_resumed",
                    resource_type="backup",
                    resource_id=backup_id,
                    details={
                        "org_id": org_id,
                        "attempt_id": result["attempt_id"],
                        "same_attempt": True,
                    },
                )
            )
            db.commit()
        return result


async def _deliver_original(db, executor, backup, cancellation):
    """Re-admit and deliver only the frozen request under its original locks."""
    agent_id, request, expected = _readmit(db, backup)
    # Original authority/capacity locks remain held through bounded exact-peer
    # admission. The transport rechecks the current leaf before publishing.
    response = await executor._post_certified_vm_backup(
        db, agent_id, backup.org_id, request, cancellation=cancellation
    )
    if response.status_code == 423:
        raise RecoveryHeld("agent_attempt_not_resumable_unsealed_or_uncertain")
    if response.status_code != 202 or response.json() != expected:
        raise RecoveryHeld("same_attempt_delivery_unacknowledged")
    return dict(
        status="accepted",
        backup_id=backup.id,
        resumed=True,
        attempt_id=expected.get("attempt_id", expected.get("reservation_id")),
    )


async def recover_original_attempt(
    factory, executor, backup_id, org_id, *, previous_outcome=None
):
    """Owned post-restart redelivery under persisted original authority.

    No requester, new backup, capacity reservation, producer token or source
    selection is synthesized. A failed admission remains held for later retry;
    accepted transport is never confused with completed backup or publication.
    """
    cancelled = threading.Event()
    with executor.dispatch_lifetime.admission():
        return await run_owned_worker(
            lambda: asyncio.run(
                _recover_original_worker(
                    factory,
                    executor,
                    backup_id,
                    org_id,
                    cancelled,
                    previous_outcome,
                )
            ),
            on_cancel=cancelled.set,
        )


async def _recover_original_worker(
    factory, executor, backup_id, org_id, cancellation, previous_outcome
):
    with TenantContext(org_id):
        with factory() as db:
            try:
                # Discovery is not admission. _readmit takes the original
                # organization/principal/source locks in their defined order;
                # pre-locking Backup here would invert that order.
                backup = (
                    db.query(Backup)
                    .filter_by(id=backup_id, org_id=org_id)
                    .one_or_none()
                )
                if backup is None or backup.status not in {"pending", "running"}:
                    return dict(status="inactive", backup_id=backup_id)
                result = await _deliver_original(db, executor, backup, cancellation)
            except RecoveryHeld as held:
                result = dict(status="held", backup_id=backup_id, reason=held.reason)
            except Exception:
                result = dict(
                    status="held",
                    backup_id=backup_id,
                    reason="original_authority_or_attempt_readmission_required",
                )
            finally:
                db.rollback()
        # A system event, not a user action: the persisted actor/grant still
        # controls admission, while the process owns this recovery attempt.
        outcome = result["status"], result.get("reason")
        if result["status"] != "inactive" and outcome != previous_outcome:
            with factory() as db:
                db.add(
                    SystemEvent(
                        attribution="tenant",
                        org_id=org_id,
                        event_type="backup_attempt_recovery",
                        source="system",
                        resource_type="backup",
                        resource_id=backup_id,
                        details={
                            "disposition": result["status"],
                            "reason": result.get("reason"),
                            "same_attempt": True,
                        },
                    )
                )
                db.commit()
        return result
