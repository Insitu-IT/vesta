"""Compile an owned KubeVirt plan from persisted source evidence, before dispatch."""

from copy import deepcopy

from models import Agent, Organization, OrganizationDefault, User, VM
from core.tenant_context import identity
from core.s3_ownership import StorageOwnershipError, _backup, reserve_publication
from core.storage_plan import build_plan, MAX_BYTES

CHUNK_BYTES = 5 * 1024 * 1024  # VNBU pull writer's plaintext chunk size
MANIFEST_LIMIT = 16 * 1024 * 1024  # Producer must refuse larger manifests


def source_artifacts(source):
    """Validate a stored snapshot without consulting mutable inventory/config."""
    fields = {"schema", "agent_id", "vm_id", "vm_uid", "namespace", "volumes"}
    if type(source) is dict and source.get("schema") == 2:
        fields.add("native_volumes")
    if (
        type(source) is not dict
        or set(source) != fields
        or type(source["schema"]) is not int
        or source["schema"] not in (1, 2)
    ):
        raise StorageOwnershipError("Invalid source snapshot")
    if any(
        type(source[k]) is not str or not source[k]
        for k in fields - {"schema", "volumes", "native_volumes"}
    ):
        raise StorageOwnershipError("Incomplete source identity")
    volumes = source["volumes"]
    if type(volumes) is not list or not 0 < len(volumes) <= 256:
        raise StorageOwnershipError("Source volume inventory is empty or unbounded")
    names, uids, artifacts = set(), set(), []
    for volume in volumes:
        if type(volume) is not dict or set(volume) != {
            "name",
            "pvc_name",
            "pvc_uid",
            "pvc_resource_version",
            "capacity_bytes",
        }:
            raise StorageOwnershipError("Invalid persistent volume snapshot")
        if any(
            type(volume[k]) is not str or not volume[k]
            for k in volume
            if k != "capacity_bytes"
        ):
            raise StorageOwnershipError("Incomplete persistent volume identity")
        size = volume["capacity_bytes"]
        if type(size) is not int or not 0 < size <= MAX_BYTES // 2:
            raise StorageOwnershipError("Invalid measured volume capacity")
        if volume["name"] in names or volume["pvc_uid"] in uids:
            raise StorageOwnershipError("Duplicate selected disk or PVC")
        names.add(volume["name"])
        uids.add(volume["pvc_uid"])
        encrypted_max = 5 + size + 32 * ((size + CHUNK_BYTES - 1) // CHUNK_BYTES)
        for role, maximum, ciphertext_max in (
            ("volume_payload", size, encrypted_max),
            ("volume_manifest", MANIFEST_LIMIT, MANIFEST_LIMIT),
        ):
            artifacts.append(
                dict(
                    volume_id=volume["pvc_uid"],
                    role=role,
                    plaintext_min=0,
                    plaintext_max=maximum,
                    ciphertext_min=0,
                    ciphertext_max=ciphertext_max,
                )
            )
    return artifacts


def commit_kubevirt_source_plan(
    db,
    backup_id,
    config,
    *,
    transaction=False,
    dispatch_token=None,
    revalidate_token=None,
):
    """Commit locked inventory selection and exact target/keys in one transaction.

    An existing snapshot is retry authority, never refreshed from a heartbeat.
    Current source evidence must still match before returning that authority.
    This helper performs no dispatch and no storage I/O.
    """
    if dispatch_token is not None and not transaction:
        raise StorageOwnershipError("Legacy selection cannot acquire producer custody")
    if revalidate_token is not None and (not transaction or dispatch_token is not None):
        raise StorageOwnershipError("Invalid producer custody revalidation")
    org_id, user_id, platform = identity()
    if platform:
        raise StorageOwnershipError("Source selection requires tenant scope")
    if org_id is None or org_id == "default":
        assignment = db.get(OrganizationDefault, "oss", populate_existing=True)
        if assignment is None:
            raise StorageOwnershipError("No persisted default organization")
        org_id = assignment.org_id
    organization = (
        db.query(Organization)
        .filter(Organization.id == org_id)
        .populate_existing()
        .with_for_update()
        .one_or_none()
    )
    if organization is None or organization.enabled is not True:
        raise StorageOwnershipError("Source organization is unavailable")
    if user_id is not None:
        actor = (
            db.query(User)
            .filter(User.id == user_id, User.org_id == org_id)
            .populate_existing()
            .with_for_update()
            .one_or_none()
        )
        if actor is None or actor.is_active is not True:
            raise StorageOwnershipError("Source principal is unavailable")
    backup = _backup(db, backup_id)
    # The session may retain a pre-cancellation ORM instance. The row lock must
    # be paired with a refresh before deciding whether producer admission exists.
    db.refresh(backup)
    if backup.org_id != org_id:
        raise StorageOwnershipError("Backup does not belong to source organization")
    if backup.status not in {"pending", "running"}:
        raise StorageOwnershipError("Backup lifecycle does not permit source dispatch")
    if transaction:
        # Worker scope only selects a tenant. Dispatch authority remains the
        # original persisted principal, even after the queue row is removed.
        initiating_user_id = backup.initiating_user_id
        if not initiating_user_id:
            raise StorageOwnershipError(
                "Legacy request has no initiating principal; held"
            )
        if user_id is not None and user_id != initiating_user_id:
            raise StorageOwnershipError(
                "Worker principal differs from initiating principal"
            )
        initiator = (
            db.query(User)
            .filter(User.id == initiating_user_id, User.org_id == org_id)
            .populate_existing()
            .with_for_update()
            .one_or_none()
        )
        if (
            initiator is None
            or initiator.is_active is not True
            or initiator.role not in {"admin", "operator"}
        ):
            raise StorageOwnershipError("Initiating principal is unavailable")
    vm = (
        db.query(VM)
        .filter(VM.id == backup.vm_id)
        .populate_existing()
        .with_for_update()
        .one_or_none()
    )
    if (
        vm is None
        or vm.org_id != backup.org_id
        or not vm.inventory_present
        or vm.provider != "kubevirt"
        or not vm.vm_uid
        or not vm.namespace
    ):
        raise StorageOwnershipError("No present stable KubeVirt source")
    agent = (
        db.query(Agent)
        .filter(Agent.id == vm.agent_id, Agent.org_id == org_id)
        .populate_existing()
        .with_for_update()
        .one_or_none()
    )
    if agent is None or agent.status != "online":
        raise StorageOwnershipError("Source agent is unavailable in this organization")
    claim = prepare_kubevirt_source_flush(
        db,
        backup,
        vm,
        config,
        transaction=transaction,
        dispatch_token=dispatch_token,
        revalidate_token=revalidate_token,
    )
    if revalidate_token is None:
        db.commit()
    return claim


def prepare_kubevirt_source_flush(
    db,
    backup,
    vm,
    config,
    *,
    transaction=True,
    dispatch_token=None,
    revalidate_token=None,
    capability_evidence=None,
):
    """Stage from caller-locked authority; caller owns final flush/commit/rollback.

    This is not an admission or send entrypoint. Manual and connected callers
    establish their respective original authority before entering this helper.
    """
    backup_id = backup.id
    if revalidate_token is None:
        from core.agent_scope import source_allowed

        agent = db.get(Agent, vm.agent_id)
        if agent is None or not source_allowed(agent, vm.namespace):
            raise StorageOwnershipError(
                "Source namespace is outside the applied selection; upgrade agent scope configuration if unavailable"
            )
    validate_native_disk_selection(backup, vm, db.get(Agent, vm.agent_id), db=db)
    # This is intentionally after persisted admission, including on replay.
    # A retained plan is not authority to resurrect an unavailable principal.
    claim = reserve_publication(db, backup_id, "payload", config)
    if revalidate_token is not None and (
        claim.dispatch_token != revalidate_token or claim.expected_plan is None
    ):
        raise StorageOwnershipError("Producer custody no longer matches the attempt")
    if claim.state != "reserved":
        raise StorageOwnershipError("Source selection requires a reserved publication")
    excluded = backup.exclude_disks or []
    if (
        type(excluded) is not list
        or any(type(x) is not str for x in excluded)
        or len(set(excluded)) != len(excluded)
    ):
        raise StorageOwnershipError("Invalid persisted disk exclusions")
    disks = vm.disks or []
    if (
        type(disks) is not list
        or len(disks) > 256
        or any(type(d) is not dict for d in disks)
    ):
        raise StorageOwnershipError("Invalid persisted disk inventory")
    targets = [d.get("target") for d in disks]
    if any(type(t) is not str or not t for t in targets) or len(set(targets)) != len(
        targets
    ):
        raise StorageOwnershipError("Ambiguous persisted disk identities")
    if not set(excluded) <= {d.get("target") for d in disks}:
        raise StorageOwnershipError("Excluded disk absent from inventory")
    selected, native = [], []
    for disk in disks:
        persistent = disk.get("source_type") in {"persistentVolumeClaim", "dataVolume"}
        if not persistent and disk.get("target") in excluded:
            continue
        if not persistent:
            # Unsupported non-persistent sources must be explicitly excluded.
            raise StorageOwnershipError("Explicitly exclude unsupported source disks")
        if (
            disk.get("backup_eligible") is not True
            or disk.get("pvc_namespace") != vm.namespace
        ):
            raise StorageOwnershipError("Selected PVC lacks usable ownership evidence")
        native.append(
            {
                "name": disk.get("target"),
                **{
                    k: disk.get(k)
                    for k in (
                        "pvc_name",
                        "pvc_uid",
                        "pvc_resource_version",
                        "capacity_bytes",
                    )
                },
            }
        )
        if disk.get("target") not in excluded:
            selected.append(deepcopy(native[-1]))
    source = dict(
        schema=1,
        agent_id=vm.agent_id,
        vm_id=vm.id,
        vm_uid=vm.vm_uid,
        namespace=vm.namespace,
        volumes=selected,
    )
    if transaction:
        # Freeze the original representation on replay, independently of an
        # agent upgrade. Never add native identities to an old journal/hash.
        if claim.expected_plan is None:
            use_native = (
                select_native_source_schema(db, backup, vm, db.get(Agent, vm.agent_id))
                == 2
            )
        else:
            use_native = (
                claim.expected_plan.get("transaction", {})
                .get("plan", {})
                .get("source", {})
                .get("schema")
                == 2
            )
        if use_native:
            source.update(schema=2, native_volumes=native)
        elif len(selected) != len(native):
            raise StorageOwnershipError(
                "Persistent disk selection requires kubevirt-native-disks/1; retained legacy attempt is held"
            )
    artifacts = source_artifacts(source)
    if transaction:
        from core.storage_dispatch import compile_request

        from core.storage_encryption import select_encryption
        from core.storage_transfer import select_transfer_profile
        from core.storage_wire import validate_transaction

        encryption = select_encryption(db, backup)
        if claim.expected_plan is None:
            transfer_profile = select_transfer_profile(db.get(Agent, vm.agent_id))
        else:
            if claim.expected_plan.get("schema") != 3:
                raise StorageOwnershipError(
                    "Legacy reservation cannot acquire transaction ownership"
                )
            try:
                original_request = validate_transaction(
                    claim.expected_plan["transaction"]
                )
            except (KeyError, TypeError, ValueError) as error:
                raise StorageOwnershipError(
                    "Invalid retained transaction; reconcile without redispatch"
                ) from error
            transfer_profile = original_request["plan"].get("transfer_profile")
        request = compile_request(
            claim,
            source,
            vm,
            backup,
            config,
            encryption=encryption,
            db=db,
            capability_evidence=capability_evidence,
            transfer_profile=transfer_profile,
        )
        if claim.expected_plan is not None:
            if claim.expected_plan.get("schema") != 3:
                raise StorageOwnershipError(
                    "Legacy reservation cannot acquire transaction ownership"
                )
            original = deepcopy(claim.expected_plan["transaction"])
            observed = deepcopy(request)
            for candidate in (original, observed):
                candidate.pop("plan_sha256")
                for key in ("volumes", "native_volumes"):
                    for volume in candidate["plan"]["source"].get(key, []):
                        volume.pop("pvc_resource_version")
            if original != observed:
                raise StorageOwnershipError("Transaction source or destination changed")
        else:
            claim.expected_plan = {"schema": 3, "transaction": request}
        if dispatch_token is not None:
            if claim.dispatch_token is not None:
                raise StorageOwnershipError(
                    "Attempt already has producer custody; reconcile without redispatch"
                )
            claim.dispatch_token = dispatch_token
        # Final send admission keeps the persisted actor/source/key row locks
        # until transport returns. It never creates or transfers custody.
        return claim
    plan = build_plan(claim, artifacts)
    plan.update(schema=2, source=deepcopy(source))
    if claim.expected_plan is not None:
        from core.storage_plan import validate_plan

        validate_plan(claim, claim.expected_plan)
        if claim.expected_plan["schema"] != 2:
            raise StorageOwnershipError("Existing reservation has no source snapshot")
        # Resource versions record observations, not incarnations. Re-read all
        # persisted identity/capacity facts, but preserve the original plan and
        # its original observation counter when only that counter changed.
        observed = deepcopy(plan)
        original = deepcopy(claim.expected_plan)
        for candidate in (observed, original):
            for volume in candidate["source"]["volumes"]:
                volume.pop("pvc_resource_version")
        if observed != original:
            raise StorageOwnershipError(
                "Persisted source changed; retain original plan"
            )
        return claim
    claim.expected_plan = plan
    return claim


def validate_kubevirt_source_plan(
    db, backup, vm, agent, claim, config, request, *, allow_receipt=False
):
    """Read-only validation of an already frozen plan under caller-owned locks."""
    from core.scheduler_admission import _validate_source
    from core.storage_encryption import select_encryption
    from core.storage_wire import validate_transaction, plan_digest

    validate_transaction(request)
    if claim.dispatch_token is None:
        from core.agent_scope import source_allowed

        if not source_allowed(agent, vm.namespace):
            raise StorageOwnershipError(
                "Source namespace is outside the applied selection"
            )
    if (
        claim.state != "reserved"
        or (claim.prepared_receipt is not None and not allow_receipt)
        or claim.expected_plan != {"schema": 3, "transaction": request}
        or request["backup_id"] != backup.id
        or request["org_id"] != backup.org_id
        or request["agent_id"] != agent.id
        or request["reservation_id"] != claim.id
        or request["plan_sha256"] != plan_digest(request["plan"])
    ):
        raise StorageOwnershipError("Frozen source request changed")
    target = dict(request["plan"]["target"])
    target["prefix"] = target.pop("configuration_prefix")
    target["capability_profile"] = request["plan"]["capability_profile"]
    if target != config or (claim.endpoint, claim.bucket) != (
        config["endpoint"],
        config["bucket"],
    ):
        raise StorageOwnershipError("Frozen destination changed")
    if select_encryption(db, backup, read_only=True) != request["plan"]["encryption"]:
        raise StorageOwnershipError("Frozen encryption identity changed")
    _validate_source(backup, vm, agent, request["plan"])


def readmit_kubevirt_callback(db, backup_id, config, *, revalidate_token):
    """Revalidate frozen callback custody under its original human or org grant.

    No source selection, plan refresh, producer token or send right is created.
    Callers retain these row locks through their own commit/rollback boundary.
    """
    import json
    import uuid
    from sqlalchemy import text
    from core.backup_capacity import validate_reserved_capacity
    from core.scheduler_admission import lock_original_authority, _locked
    from models import S3Publication

    org, backup, vm, agent, _, grant, occurrence = lock_original_authority(
        db, backup_id, callback=True
    )
    claim = _locked(
        db, S3Publication, backup_id=backup.id, org_id=org.id, kind="payload"
    )
    request = (claim.expected_plan or {}).get("transaction")
    if not revalidate_token or claim.dispatch_token != revalidate_token or not request:
        raise StorageOwnershipError("Original callback custody unavailable")
    if backup.capacity_state != "reserved" or backup.capacity_id is None:
        raise StorageOwnershipError("Original capacity reservation unavailable")
    validate_reserved_capacity(db, backup.id, uuid.UUID(str(backup.capacity_id)))
    validate_kubevirt_source_plan(
        db,
        backup,
        vm,
        agent,
        claim,
        config,
        request,
        allow_receipt=True,
    )
    if grant is not None:
        expected = dict(
            schema=1,
            effect_kind="storage_dispatch",
            dispatch_token=revalidate_token,
            backup_id=backup.id,
            reservation_id=claim.id,
            attempt_id=request["plan"]["attempt_id"],
            authority_kind="scheduler",
            user_id=None,
            occurrence_id=occurrence.id,
            grant_id=grant.id,
            scope_sha256=grant.scope_sha256,
            org_epoch=org.scheduler_epoch,
            request_sha256=db.scalar(
                text(
                    "SELECT encode(sha256(convert_to(CAST(:value AS jsonb)::text,'UTF8')),'hex')"
                ),
                dict(value=json.dumps(request, allow_nan=False)),
            ),
        )
        saved = claim.dispatch_admission or {}
        if {k: v for k, v in saved.items() if k != "admission_order"} != expected:
            raise StorageOwnershipError(
                "Original scheduler dispatch admission unavailable"
            )
    return claim


NATIVE_DISK_PROFILE = "kubevirt-native-disks/1"


def supports_native_disks(agent):
    capabilities = (agent.capabilities or {}) if agent is not None else {}
    if type(capabilities) is not dict:
        raise StorageOwnershipError("Invalid agent native disk capabilities")
    profiles = capabilities.get("kubevirt_native_disk_profiles", [])
    if (
        type(profiles) is not list
        or len(profiles) > 8
        or any(type(p) is not str for p in profiles)
        or len(set(profiles)) != len(profiles)
    ):
        raise StorageOwnershipError("Invalid agent native disk capabilities")
    return NATIVE_DISK_PROFILE in profiles


def validate_native_disk_selection(backup, vm, agent, *, db=None):
    """Read-only compatibility gate, before capacity/publication/effects.

    Native KubeVirt backs up all persistent disks. Old agents cannot validate
    an excluded persistent disk's identity, endpoints or scratch demand.
    """
    if vm.provider != "kubevirt":
        return
    excluded = backup.exclude_disks or []
    if any(
        d.get("target") in excluded
        and d.get("source_type") in {"persistentVolumeClaim", "dataVolume"}
        for d in (vm.disks or [])
    ):
        if not supports_native_disks(agent):
            raise StorageOwnershipError(
                "Persistent disk selection requires kubevirt-native-disks/1 agent capability"
            )
        if db is not None and select_native_source_schema(db, backup, vm, agent) == 1:
            raise StorageOwnershipError(
                "Persistent disk selection requires a fresh full with kubevirt-native-disks/1"
            )


def select_native_source_schema(db, backup, vm, agent):
    """Choose a representation, never establish parent publication authority.

    A current schema-1 parent can retain that representation across an agent
    upgrade only when the compiler subsequently proves all native disks are
    selected. select_parent still validates the complete accepted ancestry.
    """
    if backup.backup_type == "incremental":
        from models import StorageLineageHead, StorageLineageGeneration
        from core.storage_wire import TransactionRequest

        head = (
            db.query(StorageLineageHead)
            .filter_by(vm_id=vm.id, org_id=backup.org_id, state="current")
            .populate_existing()
            .one_or_none()
        )
        if head is not None:
            generation = (
                db.query(StorageLineageGeneration)
                .filter_by(
                    id=head.generation_id,
                    vm_id=vm.id,
                    org_id=backup.org_id,
                    state="accepted",
                )
                .populate_existing()
                .one_or_none()
            )
            if generation is not None:
                try:
                    parent = TransactionRequest.model_validate(
                        generation.accepted_request
                    )
                except (ValueError, TypeError) as error:
                    raise StorageOwnershipError(
                        "Accepted current incremental lineage unavailable"
                    ) from error
                if parent.plan.source.schema == 1:
                    return 1
    return 2 if supports_native_disks(agent) else 1
