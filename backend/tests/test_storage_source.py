"""Source snapshots survive inventory changes and constrain receipt plans."""

from copy import deepcopy

import pytest

from core.s3_ownership import StorageOwnershipError
from core.storage_source import commit_kubevirt_source_plan
from core.storage_plan import validate_plan
from core.scheduler_admission import _validate_source
from core.scheduler_scope import ScopeRefused
from models import Agent, Organization, VM, Backup, S3Publication
from core.tenant_context import PlatformContext


def source(db):
    agent = Agent(
        hostname="source-plan",
        capabilities={"provider": "kubevirt"},
        config={"kube_namespace": "fixture"},
    )
    db.add(agent)
    db.flush()
    vm = VM(
        agent_id=agent.id,
        name="source",
        provider="kubevirt",
        namespace="fixture",
        vm_uid="vm-original",
        inventory_present=True,
        disks=[
            dict(
                target="data",
                source_type="persistentVolumeClaim",
                pvc_namespace="fixture",
                pvc_name="data",
                pvc_uid="pvc-original",
                pvc_resource_version="42",
                capacity_bytes=104857600,
                backup_eligible=True,
            )
        ],
    )
    db.add(vm)
    db.flush()
    backup = Backup(vm_id=vm.id, status="pending")
    db.add(backup)
    db.flush()
    backup.chain_id = backup.id
    return vm, backup, dict(endpoint="https://store.example", bucket="owned")


def test_snapshot_committed_before_dispatch_and_preserved_on_retry(
    db_session, session_factory
):
    vm, backup, config = source(db_session)
    claim = commit_kubevirt_source_plan(db_session, backup.id, config)
    plan = deepcopy(claim.expected_plan)
    assert plan["source"]["volumes"][0]["pvc_uid"] == "pvc-original"
    assert len(plan["artifacts"]) == 2
    vm.disks = [dict(vm.disks[0], pvc_resource_version="43")]
    db_session.commit()
    with session_factory() as restarted:
        restored = commit_kubevirt_source_plan(restarted, backup.id, config)
        assert restored.expected_plan == plan
        assert restarted.get(S3Publication, claim.id).state == "reserved"
        assert restarted.get(Backup, backup.id).status == "pending"
        with pytest.raises(StorageOwnershipError):
            commit_kubevirt_source_plan(
                restarted, backup.id, dict(config, bucket="other")
            )
    altered = deepcopy(plan)
    altered["artifacts"].pop()
    with pytest.raises(StorageOwnershipError, match="differs"):
        validate_plan(claim, altered)


@pytest.mark.parametrize(
    "field,value",
    [
        ("pvc_uid", None),
        ("capacity_bytes", 0),
        ("capacity_bytes", True),
        ("pvc_namespace", "other"),
        ("backup_eligible", False),
        ("source_type", "containerDisk"),
    ],
)
def test_incomplete_sources_refuse_selection(db_session, field, value):
    vm, backup, config = source(db_session)
    vm.disks = [dict(vm.disks[0], **{field: value})]
    with pytest.raises(StorageOwnershipError):
        commit_kubevirt_source_plan(db_session, backup.id, config)
    db_session.rollback()


def test_explicit_exclusion(db_session):
    vm, backup, config = source(db_session)
    vm.disks = vm.disks + [dict(target="boot", source_type="containerDisk")]
    backup.exclude_disks = ["boot"]
    claim = commit_kubevirt_source_plan(db_session, backup.id, config)
    assert len(claim.expected_plan["source"]["volumes"]) == 1


def test_datavolume_backing_pvc_is_selected(db_session):
    vm, backup, config = source(db_session)
    vm.disks = [dict(vm.disks[0], source_type="dataVolume")]
    claim = commit_kubevirt_source_plan(db_session, backup.id, config)
    assert claim.expected_plan["source"]["volumes"][0]["pvc_uid"] == "pvc-original"


@pytest.mark.parametrize("source_type", ["persistentVolumeClaim", "dataVolume"])
def test_persistent_backing_pvc_survives_callback_readmission(db_session, source_type):
    vm, backup, config = source(db_session)
    vm.disks = [dict(vm.disks[0], source_type=source_type)]
    claim = commit_kubevirt_source_plan(db_session, backup.id, config)
    plan = dict(
        claim.expected_plan,
        provider="kubevirt",
        vm_name=vm.name,
        source=dict(
            claim.expected_plan["source"],
            vmi_uid=vm.vmi_uid,
            volumes=[
                dict(volume, mapping=None)
                for volume in claim.expected_plan["source"]["volumes"]
            ],
        ),
    )
    agent = db_session.get(Agent, vm.agent_id)
    _validate_source(backup, vm, agent, plan)
    vm.disks = [dict(vm.disks[0], source_type="containerDisk")]
    with pytest.raises(ScopeRefused, match="request_source_drift"):
        _validate_source(backup, vm, agent, plan)


@pytest.mark.parametrize("duplicate", ["target", "pvc_uid"])
def test_duplicate_selection_refused(db_session, duplicate):
    vm, backup, config = source(db_session)
    second = dict(vm.disks[0], target="second", pvc_uid="second-pvc")
    second[duplicate] = vm.disks[0][duplicate]
    vm.disks = vm.disks + [second]
    with pytest.raises(StorageOwnershipError, match="Ambiguous|Duplicate"):
        commit_kubevirt_source_plan(db_session, backup.id, config)


@pytest.mark.parametrize(
    "change",
    ["missing", "uid", "capacity", "namespace", "exclusion", "duplicate_exclusion"],
)
def test_retry_refuses_changed_source_without_rewriting_plan(db_session, change):
    vm, backup, config = source(db_session)
    claim = commit_kubevirt_source_plan(db_session, backup.id, config)
    original = deepcopy(claim.expected_plan)
    if change == "missing":
        vm.disks = []
    elif change == "uid":
        vm.disks = [dict(vm.disks[0], pvc_uid="replacement")]
    elif change == "capacity":
        vm.disks = [dict(vm.disks[0], capacity_bytes=209715200)]
    elif change == "namespace":
        vm.disks = [dict(vm.disks[0], pvc_namespace="foreign")]
    else:
        backup.exclude_disks = ["data"] * (2 if change == "duplicate_exclusion" else 1)
    db_session.commit()
    with pytest.raises(StorageOwnershipError):
        commit_kubevirt_source_plan(db_session, backup.id, config)
    db_session.rollback()
    assert db_session.get(S3Publication, claim.id).expected_plan == original


@pytest.mark.parametrize("replay", [False, True])
@pytest.mark.parametrize(
    "refusal", ["disabled_org", "offline_agent", "foreign_agent", "platform"]
)
def test_admission_refuses_before_reservation(db_session, monkeypatch, replay, refusal):
    vm, backup, config = source(db_session)
    db_session.commit()
    original = None
    if replay:
        original = deepcopy(
            commit_kubevirt_source_plan(db_session, backup.id, config).expected_plan
        )
    if refusal == "disabled_org":
        db_session.get(Organization, backup.org_id).enabled = False
    elif refusal == "offline_agent":
        db_session.get(Agent, vm.agent_id).status = "offline"
    elif refusal == "foreign_agent":
        db_session.get(Agent, vm.agent_id).org_id = "foreign"
    db_session.commit()

    def forbidden(*args, **kwargs):
        pytest.fail("Reservation reached before persisted admission")

    monkeypatch.setattr("core.storage_source.reserve_publication", forbidden)
    if refusal == "platform":
        with PlatformContext(), pytest.raises(StorageOwnershipError):
            commit_kubevirt_source_plan(db_session, backup.id, config)
    else:
        with pytest.raises(StorageOwnershipError):
            commit_kubevirt_source_plan(db_session, backup.id, config)
    db_session.rollback()
    claim = db_session.query(S3Publication).filter_by(backup_id=backup.id).one_or_none()
    assert (claim.expected_plan if claim else None) == original


def test_namespace_narrowing_refuses_new_reservation(db_session):
    vm, backup, config = source(db_session)
    agent = db_session.get(Agent, vm.agent_id)
    agent.metrics = {
        "provider": "kubevirt",
        "scope": {
            "source_namespaces": ["fixture"],
            "selected_source_namespaces": ["fixture"],
        },
    }
    agent.config = {"selected_source_namespaces": []}
    db_session.flush()
    with pytest.raises(StorageOwnershipError, match="outside the applied selection"):
        commit_kubevirt_source_plan(db_session, backup.id, config)
    assert db_session.query(S3Publication).count() == 0


@pytest.mark.parametrize(
    "malformation", ["bounds", "profile", "null_profile", "digest", "missing"]
)
def test_invalid_retained_transaction_refuses_before_recompilation(
    db_session, monkeypatch, malformation
):
    from backend.tests.test_storage_wire import request
    from core.s3_ownership import reserve_publication
    from core.storage_source import prepare_kubevirt_source_flush
    from core.storage_wire import plan_digest

    monkeypatch.setenv("ENABLE_ENCRYPTION", "false")
    vm, backup, config = source(db_session)
    wire = request()
    if malformation == "bounds":
        wire["plan"]["artifacts"][0]["ciphertext_max"] += 32
    elif malformation in {"profile", "null_profile"}:
        wire["plan"]["transfer_profile"] = (
            "unknown/1" if malformation == "profile" else None
        )
    wire["plan_sha256"] = (
        "0" * 64 if malformation == "digest" else plan_digest(wire["plan"])
    )
    claim = reserve_publication(db_session, backup.id, "payload", config)
    original = {"schema": 3}
    if malformation != "missing":
        original["transaction"] = wire
    claim.expected_plan = deepcopy(original)
    db_session.commit()

    def forbidden(*args, **kwargs):
        pytest.fail("Invalid retained plan reached new request compilation")

    monkeypatch.setattr("core.storage_dispatch.compile_request", forbidden)
    with pytest.raises(StorageOwnershipError, match="Invalid retained transaction"):
        prepare_kubevirt_source_flush(
            db_session, backup, vm, config, dispatch_token="not-authorized"
        )
    db_session.rollback()
    retained = db_session.get(S3Publication, claim.id)
    assert retained.expected_plan == original
    assert retained.dispatch_token is None
    assert retained.state == "reserved"
    assert db_session.get(Backup, backup.id).status == "pending"
