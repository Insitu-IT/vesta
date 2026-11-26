"""Durable delivery of admitted identities, with conservative interruption holds.

The request transaction never sends effects. A per-record PostgreSQL session lock
excludes live duplicate delivery. A lost lock/worker is NOT permission to repeat a
send: an interrupted dispatch is held for original-attempt reconciliation.
"""

import asyncio
from datetime import datetime, timezone
import hashlib
import logging

from sqlalchemy import text

from core.task_lifetime import run_owned_worker
from core.tenant_context import PlatformContext, TenantContext
from core.tenant_work import organization_work_ids
from models import OperatorDispatch

logger = logging.getLogger(__name__)


def _lock_key(identity):
    return int.from_bytes(
        hashlib.sha256(("vesta.operator.dispatch/1/" + identity).encode()).digest()[:8],
        "big",
        signed=True,
    )


class OperatorDispatcher:
    def __init__(self, factory=None, engine=None):
        self.factory, self.engine = factory, engine
        self.closed = True
        self.task = None
        self.children = set()
        self.active_ids = set()

    def start(self):
        if self.task is not None or self.children:
            raise RuntimeError("Operator dispatch already has an owner")
        if self.factory is None:
            from database import SessionLocal, sync_engine

            self.factory, self.engine = SessionLocal, sync_engine
        self.closed = False
        self.task = asyncio.create_task(self._loop())

    def close_admission(self):
        self.closed = True

    async def cleanup(self):
        self.close_admission()
        if self.task is not None:
            self.task.cancel()
        children = tuple(self.children)
        for child in children:
            child.cancel()
        tasks = children + ((self.task,) if self.task else ())
        await asyncio.gather(*tasks, return_exceptions=True)
        self.task = None
        self.children.clear()
        self.active_ids.clear()

    def _candidates(self):
        from core.settings_reader import get_max_concurrent_backups

        organizations = organization_work_ids(self.factory)
        with PlatformContext(), self.factory() as db:
            # Worker parallelism follows the installation's admission capacity;
            # the cap bounds local dispatch/connection work, not job duration.
            parallelism = min(16, max(1, get_max_concurrent_backups(db)))
            rows = (
                db.query(OperatorDispatch.id, OperatorDispatch.org_id)
                .filter(
                    OperatorDispatch.state.in_(("pending", "dispatching")),
                    OperatorDispatch.org_id.in_(organizations),
                )
                .order_by(OperatorDispatch.created_at, OperatorDispatch.id)
                .limit(parallelism * 2)
                .all()
            )
            return parallelism, tuple(rows)

    async def _loop(self):
        while not self.closed:
            try:
                parallelism, candidates = await run_owned_worker(self._candidates)
                for work_id, org_id in candidates:
                    if work_id in self.active_ids:
                        continue
                    if self.closed or len(self.children) >= parallelism:
                        break
                    task = asyncio.create_task(self.deliver(work_id, org_id))
                    self.children.add(task)
                    self.active_ids.add(work_id)
                    task.add_done_callback(self.children.discard)
                    task.add_done_callback(
                        lambda _task, identity=work_id: self.active_ids.discard(
                            identity
                        )
                    )
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.warning("Operator dispatch inventory unavailable")
            await asyncio.sleep(2)

    def _acquire(self, work_id, holder):
        if self.engine.dialect.name != "postgresql":
            raise RuntimeError("Durable operator dispatch requires PostgreSQL")
        with PlatformContext():
            connection = self.engine.connect()
            holder["connection"] = connection
            holder["key"] = _lock_key(work_id)
            holder["acquired"] = bool(
                connection.execute(
                    text("SELECT pg_try_advisory_lock(:key)"),
                    {"key": holder["key"]},
                ).scalar_one()
            )
            connection.rollback()
            return holder["acquired"]

    def _release(self, holder):
        connection = holder.get("connection")
        if connection is None:
            return
        try:
            if holder.get("acquired"):
                with PlatformContext():
                    released = connection.execute(
                        text("SELECT pg_advisory_unlock(:key)"), {"key": holder["key"]}
                    ).scalar_one()
                    connection.rollback()
                if not released:
                    connection.invalidate()
        except BaseException:
            connection.invalidate()
            raise
        finally:
            connection.close()

    def _claim(self, work_id):
        with self.factory() as db:
            work = (
                db.query(OperatorDispatch)
                .filter_by(id=work_id)
                .with_for_update()
                .one_or_none()
            )
            if work is None or work.state not in {"pending", "dispatching"}:
                return None
            if work.state == "dispatching":
                # The previous owner is no longer holding the lock. It may
                # already have sent effects: neither a timer nor pending status
                # proves absence. Existing original-attempt recovery owns this.
                work.state, work.reason = "held", "dispatch_outcome_unknown"
                work.updated_at = datetime.now(timezone.utc)
                db.commit()
                return None
            work.state = "dispatching"
            work.updated_at = datetime.now(timezone.utc)
            result = (work.kind, work.resource_id, work.org_id, work.actor_id)
            db.commit()
            return result

    def _finish(self, work_id, state, reason=None):
        with self.factory() as db:
            work = (
                db.query(OperatorDispatch)
                .filter_by(id=work_id)
                .with_for_update()
                .one_or_none()
            )
            if work is not None and work.state == "dispatching":
                work.state, work.reason = state, reason
                work.updated_at = datetime.now(timezone.utc)
                db.commit()

    async def deliver(self, work_id, org_id):
        holder = {}
        try:
            if self.closed or not await run_owned_worker(
                self._acquire, work_id, holder
            ):
                return
            with TenantContext(org_id):
                if self.closed:
                    return
                original = await run_owned_worker(self._claim, work_id)
                if original is None:
                    return
                kind, resource_id, original_org, actor_id = original
                with TenantContext(original_org, actor_id):
                    try:
                        if kind == "backup":
                            from core.backup_executor import backup_executor

                            result = await backup_executor.execute_backup(resource_id)
                        else:
                            from core.restore_executor import restore_executor

                            result = await restore_executor.execute_restore(
                                resource_id, original_org, actor_id
                            )
                        held = (
                            isinstance(result, dict) and result.get("status") == "held"
                        )
                        await run_owned_worker(
                            self._finish,
                            work_id,
                            "held" if held else "delivered",
                            "original_attempt_held" if held else None,
                        )
                    except asyncio.CancelledError:
                        # Retain dispatching, including when commit ACK was lost.
                        raise
                    except Exception:
                        await run_owned_worker(
                            self._finish, work_id, "held", "dispatch_outcome_unknown"
                        )
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.warning("Operator dispatch retained for reconciliation")
        finally:
            await run_owned_worker(self._release, holder)


operator_dispatcher = OperatorDispatcher()
