"""Bounded asynchronous scrub transport; all authority remains in original DB custody."""

import asyncio
from contextlib import suppress
from datetime import datetime, timedelta
import logging

from core import backup_verification as scrub
from core.s3_ownership import StorageOwnershipError
from core.operation_budget import verification_admission_exhausted
from core.task_lifetime import DispatchLifetime, owned_dispatch, run_owned_worker
from core.tenant_context import PlatformContext, TenantContext
from core.vm_agent_peer import AgentPeerUnavailable, vm_agent_peer
from database import SessionLocal
from models import Agent, BackupVerification

logger = logging.getLogger(__name__)


def _defer(row):
    row.verification_next_poll_at = (
        None
        if row.status in scrub.TERMINAL
        else datetime.utcnow() + timedelta(seconds=300 if row.status == "held" else 10)
    )


def _record(db, identity, org_id, actor_id):
    row = (
        db.query(BackupVerification)
        .filter_by(
            id=identity,
            org_id=org_id,
            created_by=actor_id,
            verification_type=scrub.TYPE,
        )
        .populate_existing()
        .one_or_none()
    )
    if row is None or row.status in scrub.TERMINAL:
        return None
    scrub.load_plan(row)
    return row


def _agent(db, row):
    agent = (
        db.query(Agent)
        .filter_by(id=row.verification_agent_id, org_id=row.org_id)
        .one_or_none()
    )
    if agent is None:
        raise StorageOwnershipError("Original verification agent unavailable")
    return agent


def _prepare(identity, org_id, actor_id):
    with TenantContext(org_id, actor_id), SessionLocal() as db:
        row = _record(db, identity, org_id, actor_id)
        if row is None:
            return None
        plan, _ = scrub.load_plan(row)
        allowed = not row.verification_cancel_requested
        if allowed:
            try:
                scrub.readmit(db, row)
            except StorageOwnershipError:
                allowed = False
        if not allowed:
            db.refresh(row, with_for_update=True)
            if row.status in scrub.TERMINAL:
                return None
            row.verification_cancel_requested = True
            if (
                row.verification_read_attempts == 0
                and row.verification_worker_id is None
            ):
                row.status = "cancelled"
                row.result_message = "Verification cancelled before any read admission"
                row.completed_at = datetime.utcnow()
                _defer(row)
                db.commit()
                return None
            row.status, row.result_message = (
                "held",
                "Original verification authority unavailable; no further reads admitted",
            )
        try:
            peer = vm_agent_peer(db, _agent(db, row))
        except (AgentPeerUnavailable, StorageOwnershipError):
            row.status = "held"
            row.result_message = "Original enrolled verification peer unavailable"
            _defer(row)
            db.commit()
            return None
        info = dict(
            id=row.id,
            org_id=org_id,
            actor_id=actor_id,
            agent_id=row.verification_agent_id,
            provider=plan["provider"],
            peer=peer,
            worker_id=row.verification_worker_id,
            plan_sha256=row.verification_plan_sha256,
            action="observe" if allowed else "cancel",
            read_attempts=row.verification_read_attempts,
        )
        _defer(row)
        db.commit()
        return info


def _recheck_peer(info):
    with TenantContext(info["org_id"], info["actor_id"]), SessionLocal() as db:
        row = _record(db, info["id"], info["org_id"], info["actor_id"])
        if row is None or vm_agent_peer(db, _agent(db, row)) != info["peer"]:
            raise StorageOwnershipError("Original verification agent transport changed")


def _hydrated(info):
    with TenantContext(info["org_id"], info["actor_id"]), SessionLocal() as db:
        row = _record(db, info["id"], info["org_id"], info["actor_id"])
        if row is None or vm_agent_peer(db, _agent(db, row)) != info["peer"]:
            return None
        scrub.readmit(db, row)
        db.refresh(row, with_for_update=True)
        if row.verification_cancel_requested or row.status in scrub.TERMINAL:
            return None
        if verification_admission_exhausted(row):
            row.status, row.result_message = (
                "held",
                "Verification admission budget exhausted or unavailable; "
                "retained results may still be observed, but no new reads are admitted",
            )
            _defer(row)
            db.commit()
            return None
        if row.verification_read_attempts >= row.verification_read_limit:
            row.status, row.result_message = (
                "held",
                "Automatic verification read attempts exhausted; original operator resume required",
            )
            _defer(row)
            db.commit()
            return None
        request = scrub.hydrate_request(db, row)
        row.verification_read_attempts += 1
        attempt = row.verification_read_attempts
        db.commit()
        return request, attempt


def _busy(info, attempt, value):
    """Credit only an exact authenticated no-admission reply, once per attempt."""
    if value != dict(
        schema="vnbui-backup-verification-admission/1",
        verification_id=info["id"],
        org_id=info["org_id"],
        agent_id=info["agent_id"],
        plan_sha256=info["plan_sha256"],
        status="not_admitted",
        reason="agent_busy",
    ):
        raise StorageOwnershipError("Original no-admission reply unavailable")
    with TenantContext(info["org_id"], info["actor_id"]), SessionLocal() as db:
        row = _record(db, info["id"], info["org_id"], info["actor_id"])
        if row is None or vm_agent_peer(db, _agent(db, row)) != info["peer"]:
            return
        scrub.readmit(db, row)
        db.refresh(row, with_for_update=True)
        if (
            row.verification_cancel_requested
            or row.status in scrub.TERMINAL
            or row.verification_read_attempts != attempt
            or row.verification_last_busy_attempt >= attempt
        ):
            return
        row.verification_last_busy_attempt = attempt
        row.verification_read_limit += 1
        row.status = "held"
        row.result_message = "Original agent busy; queued without admitting a read"
        _defer(row)
        db.commit()


def _hold(info, message):
    with TenantContext(info["org_id"], info["actor_id"]), SessionLocal() as db:
        row = _record(db, info["id"], info["org_id"], info["actor_id"])
        if row is None:
            return
        row.status, row.result_message = "held", message
        _defer(row)
        db.commit()


def _observe(info, value):
    """Persist one observation; never hold row locks across awaited transport."""
    with TenantContext(info["org_id"], info["actor_id"]), SessionLocal() as db:
        row = _record(db, info["id"], info["org_id"], info["actor_id"])
        if row is None:
            return "terminal"
        if vm_agent_peer(db, _agent(db, row)) != info["peer"]:
            return "cancel"
        if row.verification_cancel_requested:
            scrub.apply_progress(row, value)
            terminal = row.status in scrub.TERMINAL
            _defer(row)
            db.commit()
            return "terminal" if terminal else "cancel"
        if isinstance(value, dict) and value.get("status") in {"failed", "held"}:
            # Negative facts do not borrow a revoked principal's read authority.
            # Validate their original binding and retain them before re-admission.
            scrub.apply_progress(row, value)
            state = row.status
            _defer(row)
            db.commit()
            if state == "failed":
                return "failed"
            if value.get("message") in {
                "operation_budget_exhausted",
                "operation_budget_exhausted_or_missing",
            }:
                return "held"
            try:
                scrub.readmit(db, row)
            except StorageOwnershipError:
                return "cancel"
            return "readmit"
        try:
            scrub.readmit(db, row)
        except StorageOwnershipError:
            row.verification_cancel_requested = True
            row.status, row.result_message = (
                "held",
                "Original verification authority unavailable; no result accepted",
            )
            _defer(row)
            db.commit()
            return "cancel"
        db.refresh(row, with_for_update=True)
        if row.status in scrub.TERMINAL:
            return "terminal"
        scrub.apply_progress(row, value)
        state = row.status
        _defer(row)
        db.commit()
        return "readmit" if value["status"] == "held" and state == "held" else state


def _work_ids(cursor=None):
    # Only IDs leave privileged enumeration, including disabled scopes whose
    # known workers still need fencing. Mutable work uses original tenant scope;
    # read admission separately enforces the supported OSS assignment.
    with PlatformContext(), SessionLocal() as db:
        query = db.query(
            BackupVerification.id,
            BackupVerification.org_id,
            BackupVerification.created_by,
        ).filter(
            BackupVerification.verification_type == scrub.TYPE,
            BackupVerification.status.notin_(scrub.TERMINAL),
            (
                BackupVerification.verification_next_poll_at.is_(None)
                | (BackupVerification.verification_next_poll_at <= datetime.utcnow())
            ),
        )
        if cursor:
            query = query.filter(BackupVerification.id > cursor)
        return tuple(query.order_by(BackupVerification.id).limit(16).all())


class VerificationExecutor:
    def __init__(self):
        self.dispatch_lifetime = DispatchLifetime()
        self.loop = None
        self.task = None
        self.wake = None
        self.cursor = None

    def start(self):
        if self.task is not None and not self.task.done():
            return
        self.dispatch_lifetime = DispatchLifetime()
        self.loop = asyncio.get_running_loop()
        self.wake = asyncio.Event()
        self.task = self.loop.create_task(self._recover_loop())

    def notify(self):
        if (
            self.loop is not None
            and self.wake is not None
            and not self.dispatch_lifetime.closed
        ):
            try:
                self.loop.call_soon_threadsafe(self.wake.set)
            except RuntimeError:
                pass  # The committed original request is recovered at startup.

    def close_admission(self):
        self.dispatch_lifetime.close_admission()

    async def cleanup(self):
        self.close_admission()
        if self.task is not None:
            self.task.cancel()
            with suppress(asyncio.CancelledError):
                await self.task
        await self.dispatch_lifetime.drain()

    async def _recover_loop(self):
        while not self.dispatch_lifetime.closed:
            try:
                rows = await run_owned_worker(_work_ids, self.cursor)
                if not rows and self.cursor is not None:
                    self.cursor = None
                    rows = await run_owned_worker(_work_ids)
                if rows:
                    self.cursor = rows[-1][0]
                semaphore = asyncio.Semaphore(4)

                async def visit(row):
                    async with semaphore:
                        try:
                            await self.once(*row)
                        except Exception:
                            logger.warning(
                                "Verification reconciliation retained original custody"
                            )

                await asyncio.gather(*(visit(row) for row in rows))
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.warning("Verification recovery discovery unavailable")
            try:
                await asyncio.wait_for(self.wake.wait(), timeout=10)
                self.wake.clear()
            except TimeoutError:
                pass

    @staticmethod
    def _transport():
        from core.restore_executor import restore_executor
        from config import settings

        return restore_executor._transport(), {
            "X-Orchestrator-Key": settings.orchestrator_to_agent_key
        }

    @owned_dispatch
    async def once(self, identity, org_id, actor_id):
        info = await run_owned_worker(_prepare, identity, org_id, actor_id)
        if info is None:
            return
        try:
            client, headers = self._transport()
            peer = info["peer"]
            headers = {**headers, "X-Vesta-Agent-ID": info["agent_id"]}
            base = "/api/verifications"

            async def recheck():
                await run_owned_worker(_recheck_peer, info)

            scope = {"org_id": info["org_id"]}
            cancel_scope = dict(scope, plan_sha256=info["plan_sha256"])
            await recheck()
            capability = await client.get(peer, base + "/capability", headers=headers)
            capability.raise_for_status()
            if capability.json() != {
                "schema": scrub.SCHEMA,
                "agent_id": info["agent_id"],
                "provider": info["provider"],
            }:
                raise StorageOwnershipError(
                    "Original verification agent capability unavailable"
                )
            await recheck()
            response = await client.get(
                peer, base + f"/{identity}", params=scope, headers=headers
            )
            if info["action"] == "cancel":
                if response.status_code == 404:
                    return
                response.raise_for_status()
                value = response.json()
                if (
                    not isinstance(value, dict)
                    or value.get("schema") != scrub.PROGRESS_SCHEMA
                    or value.get("verification_id") != identity
                    or value.get("org_id") != org_id
                    or value.get("agent_id") != info["agent_id"]
                    or value.get("plan_sha256") != info["plan_sha256"]
                    or not scrub._id(value.get("worker_id"))
                    or (info["worker_id"] and value["worker_id"] != info["worker_id"])
                ):
                    raise StorageOwnershipError(
                        "Original worker identity unavailable for cancellation"
                    )
                action = await run_owned_worker(_observe, info, value)
                if action == "terminal":
                    return
                await client.post(
                    peer,
                    base + f"/{identity}/cancel",
                    params=cancel_scope,
                    headers=headers,
                    recheck=recheck,
                )
                return
            if response.status_code == 404:
                if info["worker_id"]:
                    await run_owned_worker(
                        _hold,
                        info,
                        "Known verification worker journal is missing; original custody held",
                    )
                    return
                action = "readmit"
            else:
                response.raise_for_status()
                action = await run_owned_worker(_observe, info, response.json())
            if action == "cancel":
                await client.post(
                    peer,
                    base + f"/{identity}/cancel",
                    params=cancel_scope,
                    headers=headers,
                    recheck=recheck,
                )
            elif action == "readmit":
                admitted = await run_owned_worker(_hydrated, info)
                if admitted is None:
                    return
                request, attempt = admitted
                del admitted
                response = await client.post(
                    peer, base, json=request, headers=headers, recheck=recheck
                )
                del request
                if response.status_code == 429:
                    await run_owned_worker(_busy, info, attempt, response.json())
                    return
                response.raise_for_status()
                action = await run_owned_worker(_observe, info, response.json())
                if action == "cancel":
                    await client.post(
                        peer,
                        base + f"/{identity}/cancel",
                        params=cancel_scope,
                        headers=headers,
                        recheck=recheck,
                    )
        except asyncio.CancelledError:
            raise  # Journal/DB custody survives; never invent a terminal result.
        except Exception:
            await run_owned_worker(
                _hold,
                info,
                "Verification transport or authority uncertain; original custody retained",
            )


verification_executor = VerificationExecutor()
