"""Organization scheduler dispatch for the current native push producer."""

import asyncio
from copy import deepcopy
import uuid

from core.native_inventory import digest
from core.native_job import prepare_job
from core.scheduler_admission import _locked, lock_original_authority
from core.scheduler_scope import refuse
from core.scheduler_transactions import claim_queue
from core.settings_service import SettingsService
from core.storage_dispatch import read_target
from core.task_lifetime import DispatchLifetime, run_owned_worker
from models import BackupQueue


class ConnectedNativeDispatch:
    """T2 and durable local-producer intent, followed by one authenticated send.

    A duplicate/lost T2 acknowledgement cannot authorize another launch. The
    accepted agent journal owns recovery. The whole S3 request is bound to the
    same original grant after its closed inventory arrives, before key/control
    disclosure; no human principal is minted for either phase.
    """

    def __init__(self, factory, send):
        self._factory, self._send = factory, send
        self.dispatch_lifetime = DispatchLifetime()

    async def close(self):
        await self.dispatch_lifetime.drain()

    def _claim_original_queue(self, key, queue_id):
        return claim_queue(self._factory, key, queue_id, reserve=True)

    async def dispatch(self, key, queue_id):
        from core.backup_capacity import validate_reserved_capacity

        with self.dispatch_lifetime.admission():
            owner = asyncio.current_task()
            sent = False

            def alive():
                if self.dispatch_lifetime.closed or owner.cancelling() or sent:
                    refuse("dispatch_continuation_unavailable")

            async def checkpoint():
                await asyncio.sleep(0)
                alive()

            alive()
            binding = await run_owned_worker(self._claim_original_queue, key, queue_id)
            if (
                binding.state != "claimed"
                or not binding.claim_id
                or not binding.backup_id
            ):
                refuse("original_claim_unavailable")
            await checkpoint()

            def prepare():
                with self._factory() as db:
                    if db.in_transaction() or db.new or db.dirty or db.deleted:
                        refuse("clean_transaction_required")
                    if db.get_bind().dialect.name != "postgresql":
                        refuse("postgresql_dispatch_required")
                    db.connection(
                        execution_options={"isolation_level": "READ COMMITTED"}
                    )
                    _, backup, vm, _, _, grant, occurrence = lock_original_authority(
                        db, binding.backup_id
                    )
                    queue = _locked(db, BackupQueue, id=queue_id)
                    if (
                        grant is None
                        or grant.id != key.grant_id
                        or occurrence.schedule_id != key.schedule_id
                        or backup.org_id != key.org_id
                        or vm.provider != "libvirt"
                        or backup.backup_type not in ("full", "incremental")
                        or queue.claim_id != binding.claim_id
                        or queue.started_backup_id != binding.backup_id
                        or queue.claimed_at != binding.claimed_at
                        or queue.status != "claimed"
                    ):
                        refuse("original_claim_unavailable")
                    capacity = uuid.UUID(str(backup.capacity_id))
                    validate_reserved_capacity(db, backup.id, capacity)
                    target = read_target(SettingsService(db))
                    if (
                        target["capability_profile"] != "db-rooted-consumer-verified/1"
                        or not target["region"]
                    ):
                        refuse("native_storage_prerequisite_unavailable")
                    # prepare_job commits the immutable intent before any send.
                    return prepare_job(db, backup.id), capacity

            def read_intent():
                return prepare()

            alive()
            intent, capacity = await run_owned_worker(read_intent)
            await checkpoint()
            if await run_owned_worker(read_intent) != (intent, capacity):
                refuse("native_intent_changed")
            await checkpoint()
            request = dict(
                protocol="vnbui-native-job/1",
                intent=deepcopy(intent),
                intent_sha256=digest(intent),
            )
            with self.dispatch_lifetime.lock:
                alive()
                sent = True
            response = await self._send(intent["agent_id"], request)
            return dict(
                backup_id=binding.backup_id,
                claim_id=binding.claim_id,
                capacity_id=capacity,
                response=response,
            )
