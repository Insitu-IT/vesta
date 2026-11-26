"""KubeVirt dispatch: durable selection before credentials or transport."""

from copy import deepcopy
import hashlib
import os
import uuid

from core.s3_ownership import StorageOwnershipError, storage_identity
from core.storage_wire import PROTOCOL, TransactionRequest, plan_digest
from core.task_lifetime import run_owned_worker


def compile_request(
    claim,
    source,
    vm,
    backup,
    config,
    *,
    encryption=None,
    db=None,
    capability_evidence=None,
    transfer_profile=None,
):
    """Build solely from locked persisted selection and a non-secret target."""
    if backup.parent_backup_id or backup.backup_type not in (
        None,
        "full",
        "incremental",
    ):
        raise StorageOwnershipError(
            "A committed generation/checkpoint parent is required; request a fresh full"
        )
    encryption = encryption or dict(format="none", key_ref=None)
    if (
        os.getenv("ENABLE_ENCRYPTION", "false").lower() == "true"
        and encryption["format"] == "none"
    ):
        raise StorageOwnershipError(
            "Transaction encryption requires persisted key selection"
        )
    observed = deepcopy(source)
    observed["vmi_uid"] = vm.vmi_uid
    if vm.state == "running" and not vm.vmi_uid:
        raise StorageOwnershipError("Running source has no persisted VMI identity")
    disks = {disk["target"]: disk for disk in vm.disks}
    for volume in observed["volumes"] + observed.get("native_volumes", []):
        disk = disks[volume["name"]]
        mapping = disk.get("mapping")
        if (
            type(mapping) is not dict
            or set(mapping) != {"disk_name", "device", "bus", "serial"}
            or mapping["disk_name"] != volume["name"]
            or mapping["device"] != "disk"
            or mapping["bus"] not in {"virtio", "sata", "scsi", "usb"}
            or (
                mapping["serial"] is not None
                and (type(mapping["serial"]) is not str or not mapping["serial"])
            )
        ):
            raise StorageOwnershipError("Selected disk lacks canonical mapping")
        volume["mapping"] = deepcopy(mapping)
    from core.storage_source import source_artifacts

    artifacts = source_artifacts(source)
    for artifact in artifacts:
        # The encrypted pull writer adds its header/chunk framing to payloads;
        # manifests remain plain. With no encryption both byte domains match.
        if encryption["format"] == "none":
            artifact["ciphertext_max"] = artifact["plaintext_max"]
        elif artifact["role"] == "volume_payload":
            artifact["ciphertext_min"] = 5
        volume = hashlib.sha256(artifact["volume_id"].encode()).hexdigest()
        artifact["key"] = f"{claim.object_key}{claim.id}/{volume}/{artifact['role']}"
    plan = dict(
        attempt_id=claim.id,
        capability_profile=config.get("capability_profile"),
        source=observed,
        provider="kubevirt",
        vm_name=vm.name,
        backup_type=backup.backup_type or "full",
        exclusions=sorted(backup.exclude_disks or []),
        parent=None,
        target=dict(
            endpoint=claim.endpoint,
            bucket=claim.bucket,
            region=config.get("region") or "",
            configuration_prefix=config.get("prefix") or "",
        ),
        credential_ref="installation/storage.s3",
        encryption=deepcopy(encryption),
        artifacts=sorted(artifacts, key=lambda item: item["key"]),
        checksum_policy="sha256-parts-receipt-v2",
    )
    if transfer_profile is not None:
        plan["transfer_profile"] = transfer_profile
    if capability_evidence is not None:
        plan.update(
            evidence_schema=2,
            capability_evidence=deepcopy(capability_evidence),
        )
    if plan["backup_type"] == "incremental":
        from core.storage_lineage import select_parent

        if db is None:
            raise StorageOwnershipError(
                "Incremental requires durable lineage admission"
            )
        plan["parent"] = select_parent(db, backup, vm, plan)
    request = dict(
        protocol=PROTOCOL,
        org_id=backup.org_id,
        agent_id=vm.agent_id,
        backup_id=backup.id,
        reservation_id=claim.id,
        plan_sha256=plan_digest(plan),
        plan=plan,
    )
    return TransactionRequest.model_validate(request).model_dump()


def read_target(settings):
    """No secret resolution and no inference of a provider capability."""
    fields = ("endpoint", "bucket", "region", "prefix")
    values = settings.get_many(("storage.type", *(f"storage.s3.{k}" for k in fields)))
    if values["storage.type"] != "s3":
        raise StorageOwnershipError("Transaction backup requires an S3 target")
    target = dict(
        **{k: values[f"storage.s3.{k}"] for k in fields},
        capability_profile=os.getenv("STORAGE_CAPABILITY_PROFILE"),
    )
    # Transaction identities are literal, not legacy convenience inputs. Do not
    # erase a changed authority spelling (port, slash, case) on replay or accept
    # non-string settings by stringifying them in storage_identity.
    if any(type(target[k]) is not str for k in target):
        raise StorageOwnershipError("Invalid literal storage destination")
    endpoint, bucket = storage_identity(target)
    if target["endpoint"] != endpoint or not endpoint.startswith("https://"):
        raise StorageOwnershipError(
            "Storage destination must be a literal HTTPS origin"
        )
    target.update(endpoint=endpoint, bucket=bucket)
    from typing import get_args
    from core.storage_wire import Profile

    if target["capability_profile"] not in get_args(Profile):
        raise StorageOwnershipError("A reviewed storage capability profile is required")
    return target


async def dispatch_kubevirt(db, backup_id, send):
    from core.settings_service import SettingsService
    from core.storage_source import commit_kubevirt_source_plan

    settings = SettingsService(db)
    target = read_target(settings)
    claim = commit_kubevirt_source_plan(db, backup_id, target, transaction=True)
    # Repeat persisted admission and literal configuration comparison before
    # credential lookup. No secret or authenticated transport precedes commit.
    current = read_target(settings)
    if current != target:
        raise StorageOwnershipError("Destination changed after plan commit")
    # One-way durable custody, never a time-expiring lease. Once committed, a
    # lost reply/restart must reconcile this attempt; it cannot authorize a new
    # producer at these literal keys. A failed/uncertain commit reaches no IO.
    claim = commit_kubevirt_source_plan(
        db, backup_id, current, transaction=True, dispatch_token=str(uuid.uuid4())
    )
    token = claim.dispatch_token
    try:
        # Custody is already durable and visible to observers. Re-admit under
        # row locks and hold those locks through secret resolution and send;
        # revocation/cancellation that won before these locks prevents the send.
        current = read_target(settings)
        if current != target:
            raise StorageOwnershipError("Destination changed after custody commit")
        claim = commit_kubevirt_source_plan(
            db, backup_id, current, transaction=True, revalidate_token=token
        )
        request = deepcopy(claim.expected_plan["transaction"])
        if not settings.get_secret("storage.s3.access_key") or not settings.get_secret(
            "storage.s3.secret_key"
        ):
            raise StorageOwnershipError("Recorded target credentials unavailable")
        # Secret lookup can run external/configuration code. It does not make
        # environment state transactional; refuse an observed change during
        # resolution rather than dispatching a plan against that new target.
        if read_target(settings) != target:
            raise StorageOwnershipError(
                "Destination changed during credential resolution"
            )
        return await send(request["agent_id"], request)
    finally:
        # Release only final-admission locks. Previously committed plan/custody
        # survive both a successful response and an uncertain delivery outcome.
        db.rollback()


async def _dispatch_yield():
    import asyncio

    await asyncio.sleep(0)


class ConnectedKubevirtDispatch:
    """Single-invocation scheduler T2 through authenticated transaction transport.

    No API accepts a ClaimBinding, token, admission or continuation. The only
    continuation is this coroutine's private stack after acknowledged commits.
    Re-entering, including with a new instance, must run T2 again and cannot
    recover a send right from custody. The scheduler injects the verified sender.
    """

    def __init__(self, factory, send, *, capability_evidence=None):
        self._capability_evidence = deepcopy(capability_evidence)
        from core.task_lifetime import DispatchLifetime

        self._factory = factory
        self._send = send
        self.dispatch_lifetime = DispatchLifetime()

    async def close(self):
        await self.dispatch_lifetime.drain()

    async def dispatch(self, key, queue_id):
        import asyncio
        from core.scheduler_transactions import claim_queue
        from core.backup_capacity import reserve_capacity, validate_reserved_capacity
        from core.scheduler_admission import (
            lock_original_authority,
            _locked,
            record_dispatch_admission,
            validate_same_intent,
        )
        from core.scheduler_scope import refuse
        from core.settings_service import SettingsService
        from core.storage_source import (
            prepare_kubevirt_source_flush,
            validate_kubevirt_source_plan,
        )
        from models import S3Publication

        with self.dispatch_lifetime.admission():
            owner = asyncio.current_task()
            loop = asyncio.get_running_loop()
            state = "preparing"

            def alive():
                with self.dispatch_lifetime.lock:
                    if (
                        self.dispatch_lifetime.closed
                        or asyncio.get_running_loop() is not loop
                        or asyncio.current_task() is not owner
                        or owner.cancelling()
                        or state in {"send_started", "finished"}
                    ):
                        refuse("dispatch_continuation_unavailable")

            async def checkpoint():
                # Cancellation is delivered only after the previous session has
                # closed. There is no suspended DB transaction at this boundary.
                await _dispatch_yield()
                alive()

            def transaction(work):
                with self._factory() as db:
                    if db.in_transaction() or db.new or db.dirty or db.deleted:
                        refuse("clean_transaction_required")
                    if db.get_bind().dialect.name != "postgresql":
                        refuse("postgresql_dispatch_required")
                    db.connection(
                        execution_options={"isolation_level": "READ COMMITTED"}
                    )
                    result = work(db)
                    db.commit()
                    return result

            async def bounded_transaction(work):
                alive()
                result = await run_owned_worker(transaction, work)
                # A shutdown/cancellation may have won while synchronous SQL
                # was waiting. Committed custody remains, but cannot send.
                alive()
                return result

            try:
                alive()
                # Only the actual acknowledged T2 creator returns claimed.
                # A duplicate claim is held by T2 and cannot reach preparation.
                binding = await run_owned_worker(
                    claim_queue, self._factory, key, queue_id, reserve=True
                )
                if (
                    binding.state != "claimed"
                    or not binding.claim_id
                    or not binding.backup_id
                ):
                    refuse("original_claim_unavailable")
                await checkpoint()
                capacity = await run_owned_worker(
                    reserve_capacity, self._factory, binding.backup_id
                )
                capacity_id = capacity["capacity_id"]
                await checkpoint()

                def authority(db):
                    values = lock_original_authority(db, binding.backup_id)
                    _, backup, vm, agent, _, grant, occurrence = values
                    from models import BackupQueue

                    queue = _locked(db, BackupQueue, id=queue_id)
                    if (
                        grant is None
                        or grant.id != key.grant_id
                        or occurrence.schedule_id != key.schedule_id
                        or backup.org_id != key.org_id
                        or queue.claim_id != binding.claim_id
                        or queue.started_backup_id != binding.backup_id
                        or queue.claimed_at != binding.claimed_at
                        or queue.status != "claimed"
                        or vm.provider != "kubevirt"
                        or backup.backup_type not in ("full", "incremental")
                        or backup.parent_backup_id is not None
                    ):
                        refuse("original_claim_unavailable")
                    from core.agent_scope import source_allowed

                    if not source_allowed(agent, vm.namespace):
                        refuse("source_namespace_outside_selection")
                    validate_reserved_capacity(db, backup.id, capacity_id)
                    return backup, vm, agent

                def prepare(db):
                    backup, vm, _ = authority(db)
                    config = read_target(SettingsService(db))
                    claim = prepare_kubevirt_source_flush(
                        db,
                        backup,
                        vm,
                        config,
                        capability_evidence=self._capability_evidence,
                    )
                    if (
                        claim.dispatch_token is not None
                        or claim.dispatch_admission is not None
                    ):
                        refuse("existing_dispatch_custody")
                    return deepcopy(claim.expected_plan["transaction"])

                request = await bounded_transaction(prepare)
                await checkpoint()
                token = str(uuid.uuid4())

                def frozen(db):
                    backup, vm, agent = authority(db)
                    claim = _locked(
                        db,
                        S3Publication,
                        id=request["reservation_id"],
                        backup_id=backup.id,
                        org_id=backup.org_id,
                        kind="payload",
                    )
                    validate_kubevirt_source_plan(
                        db,
                        backup,
                        vm,
                        agent,
                        claim,
                        read_target(SettingsService(db)),
                        request,
                    )
                    return claim

                def custody(db):
                    claim = frozen(db)
                    if claim.dispatch_token is not None:
                        refuse("existing_dispatch_custody")
                    claim.dispatch_token = token
                    db.flush()

                await bounded_transaction(custody)
                await checkpoint()

                def admit(db):
                    claim = frozen(db)
                    if (
                        claim.dispatch_token != token
                        or claim.dispatch_admission is not None
                    ):
                        refuse("existing_dispatch_custody")
                    return record_dispatch_admission(
                        db, binding.backup_id, token, request
                    )

                admission = await bounded_transaction(admit)
                state = "acknowledged"
                await checkpoint()
                state = "validating"

                def validate(db):
                    frozen(db)
                    if (
                        validate_same_intent(db, binding.backup_id, token, request)
                        != admission
                    ):
                        refuse("dispatch_admission_changed")

                await bounded_transaction(validate)
                await checkpoint()
                # No await between consuming this private continuation and the
                # single transport call. A fence after V can race the socket;
                # neither a DB lock nor a cancellation promise spans that gap.
                with self.dispatch_lifetime.lock:
                    if (
                        self.dispatch_lifetime.closed
                        or owner.cancelling()
                        or state != "validating"
                    ):
                        refuse("dispatch_continuation_unavailable")
                    state = "send_started"
                response = await self._send(request["agent_id"], deepcopy(request))
                return dict(
                    backup_id=binding.backup_id,
                    claim_id=binding.claim_id,
                    capacity_id=capacity_id,
                    admission=admission,
                    response=response,
                )
            finally:
                # No outcome, including a lost commit ACK, can reset this frame.
                # Durable custody is left for explicit authenticated recovery.
                state = "finished"
