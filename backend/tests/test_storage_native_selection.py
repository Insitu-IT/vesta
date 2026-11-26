"""Complete native capture remains distinct from selected publication/restore."""

from copy import deepcopy
from types import SimpleNamespace

import pytest

from backend.tests.test_storage_wire import request
from core.storage_wire import TransactionRequest, plan_digest
from core.storage_source import validate_native_disk_selection
from core.storage_lineage import stable_source
from core.storage_transfer import refreshed_capabilities
from core.s3_ownership import StorageOwnershipError


def selected_request():
    value = request()
    source = value["plan"]["source"]
    extra = dict(
        deepcopy(source["volumes"][0]),
        name="excluded",
        pvc_name="excluded",
        pvc_uid="excluded-uid",
    )
    extra["mapping"]["disk_name"] = "excluded"
    source.update(schema=2, native_volumes=deepcopy(source["volumes"]) + [extra])
    value["plan"]["exclusions"] = ["excluded"]
    value["plan_sha256"] = plan_digest(value["plan"])
    return value


def test_native_selection_preserves_legacy_and_selected_artifacts():
    legacy = request()
    assert TransactionRequest.model_validate(legacy).model_dump() == legacy
    value = selected_request()
    assert TransactionRequest.model_validate(value).model_dump() == value
    assert value["plan"]["artifacts"] == legacy["plan"]["artifacts"]
    assert value["plan"]["source"]["volumes"] == legacy["plan"]["source"]["volumes"]


def test_both_source_schemas_are_required_in_openapi_and_decoding():
    from core.storage_wire import Source, NativeDiskSource

    for model, source in (
        (Source, request()["plan"]["source"]),
        (NativeDiskSource, selected_request()["plan"]["source"]),
    ):
        assert "schema" in model.model_json_schema()["required"]
        del source["schema"]
        with pytest.raises(ValueError):
            model.model_validate(source)


@pytest.mark.parametrize(
    "change", ["legacy", "missing", "duplicate", "replacement", "unexcluded", "zero"]
)
def test_native_identity_set_strictness(change):
    value = selected_request()
    source = value["plan"]["source"]
    if change == "legacy":
        source["schema"] = 1
    elif change == "missing":
        del source["native_volumes"]
    elif change == "duplicate":
        source["native_volumes"].append(source["native_volumes"][1])
    elif change == "replacement":
        source["native_volumes"][0]["pvc_uid"] = "replacement"
    elif change == "unexcluded":
        value["plan"]["exclusions"] = []
    elif change == "zero":
        source["native_volumes"][1]["capacity_bytes"] = 0
    value["plan_sha256"] = plan_digest(value["plan"])
    with pytest.raises(ValueError):
        TransactionRequest.model_validate(value)


def test_lineage_covers_excluded_persistent_identity_and_schema():
    source = selected_request()["plan"]["source"]
    observed = deepcopy(source)
    observed["native_volumes"][1]["pvc_resource_version"] = "999"
    assert stable_source(source) == stable_source(observed)
    observed["native_volumes"][1]["pvc_uid"] = "replacement"
    assert stable_source(source) != stable_source(observed)
    assert stable_source(source) != stable_source(request()["plan"]["source"])


def test_selection_refuses_legacy_agent_before_any_custody():
    backup = SimpleNamespace(exclude_disks=["excluded"])
    vm = SimpleNamespace(
        provider="kubevirt",
        disks=[dict(target="excluded", source_type="persistentVolumeClaim")],
    )
    old = SimpleNamespace(capabilities={"provider": "kubevirt"})
    with pytest.raises(StorageOwnershipError, match="kubevirt-native-disks/1"):
        validate_native_disk_selection(backup, vm, old)
    current = {
        "provider": "kubevirt",
        "kubevirt_native_disk_profiles": ["kubevirt-native-disks/1"],
    }
    validate_native_disk_selection(backup, vm, SimpleNamespace(capabilities=current))
    assert "kubevirt_native_disk_profiles" not in refreshed_capabilities(
        current, old.capabilities
    )


def test_compiler_freezes_complete_native_set_and_selected_uploads(
    db_session, monkeypatch
):
    from backend.tests.test_storage_source import source as inventory
    from core.storage_source import prepare_kubevirt_source_flush
    from models import Agent

    monkeypatch.setenv("ENABLE_ENCRYPTION", "false")
    vm, backup, config = inventory(db_session)
    vm.vmi_uid = "original-vmi"
    agent = db_session.get(Agent, vm.agent_id)
    agent.capabilities = dict(
        agent.capabilities, kubevirt_native_disk_profiles=["kubevirt-native-disks/1"]
    )
    disks = deepcopy(vm.disks)
    disks.append(
        dict(disks[0], target="excluded", pvc_name="excluded", pvc_uid="excluded-uid")
    )
    for disk in disks:
        disk["mapping"] = dict(
            disk_name=disk["target"], device="disk", bus="virtio", serial=None
        )
    vm.disks = disks
    backup.exclude_disks = ["excluded"]
    config["capability_profile"] = "db-rooted-consumer-verified/1"
    claim = prepare_kubevirt_source_flush(db_session, backup, vm, config)
    original = deepcopy(claim.expected_plan)
    frozen = original["transaction"]["plan"]
    assert frozen["source"]["schema"] == 2
    assert len(frozen["source"]["native_volumes"]) == 2
    assert len(frozen["source"]["volumes"]) == 1
    assert len(frozen["artifacts"]) == 2
    # A selected disk's observation counter can churn without changing either
    # immutable representation; the complete native identity remains fenced.
    vm.disks = [dict(d, pvc_resource_version="99") for d in vm.disks]
    prepare_kubevirt_source_flush(db_session, backup, vm, config)
    assert claim.expected_plan == original
    vm.disks = [
        dict(d, pvc_uid="replacement") if d["target"] == "excluded" else d
        for d in vm.disks
    ]
    with pytest.raises(StorageOwnershipError, match="changed"):
        prepare_kubevirt_source_flush(db_session, backup, vm, config)
    assert claim.expected_plan == original


def test_existing_legacy_plan_never_upgrades_with_agent_capability(
    db_session, monkeypatch
):
    from backend.tests.test_storage_source import source as inventory
    from core.storage_source import prepare_kubevirt_source_flush
    from models import Agent

    monkeypatch.setenv("ENABLE_ENCRYPTION", "false")
    vm, backup, config = inventory(db_session)
    vm.vmi_uid = "original-vmi"
    vm.disks = [
        dict(
            vm.disks[0],
            mapping=dict(disk_name="data", device="disk", bus="virtio", serial=None),
        )
    ]
    config["capability_profile"] = "db-rooted-consumer-verified/1"
    claim = prepare_kubevirt_source_flush(db_session, backup, vm, config)
    original = deepcopy(claim.expected_plan)
    assert original["transaction"]["plan"]["source"]["schema"] == 1
    agent = db_session.get(Agent, vm.agent_id)
    agent.capabilities = dict(
        agent.capabilities, kubevirt_native_disk_profiles=["kubevirt-native-disks/1"]
    )
    prepare_kubevirt_source_flush(db_session, backup, vm, config)
    assert claim.expected_plan == original


def test_legacy_incremental_chain_retains_schema_after_agent_upgrade(
    db_session, monkeypatch
):
    from backend.tests.test_storage_source import source as inventory
    from core.storage_source import prepare_kubevirt_source_flush
    from models import Agent, Backup, StorageLineageGeneration, StorageLineageHead
    import uuid

    monkeypatch.setenv("ENABLE_ENCRYPTION", "false")
    vm, first, config = inventory(db_session)
    vm.vmi_uid = "original-vmi"
    vm.disks = [
        dict(
            vm.disks[0],
            mapping=dict(disk_name="data", device="disk", bus="virtio", serial=None),
        )
    ]
    config["capability_profile"] = "db-rooted-consumer-verified/1"
    claim = prepare_kubevirt_source_flush(db_session, first, vm, config)
    accepted = deepcopy(claim.expected_plan["transaction"])
    first.status = "completed"
    generation = StorageLineageGeneration(
        id=str(uuid.uuid4()),
        org_id=first.org_id,
        vm_id=vm.id,
        backup_id=first.id,
        root_backup_id=first.id,
        state="accepted",
        receipt_sha256="a" * 64,
        root_receipt_sha256="a" * 64,
        manifest_receipt_sha256="b" * 64,
        tracker_uid="tracker-original",
        checkpoint="checkpoint-original",
        accepted_request=accepted,
    )
    db_session.add(generation)
    db_session.flush()
    db_session.add(
        StorageLineageHead(
            vm_id=vm.id,
            org_id=first.org_id,
            generation_id=generation.id,
            state="current",
            manifest_receipt_sha256=generation.manifest_receipt_sha256,
            root_backup_id=first.id,
            tracker_uid=generation.tracker_uid,
            checkpoint=generation.checkpoint,
        )
    )
    agent = db_session.get(Agent, vm.agent_id)
    agent.capabilities = dict(
        agent.capabilities, kubevirt_native_disk_profiles=["kubevirt-native-disks/1"]
    )
    child = Backup(
        vm_id=vm.id, org_id=first.org_id, status="pending", backup_type="incremental"
    )
    db_session.add(child)
    db_session.flush()
    next_claim = prepare_kubevirt_source_flush(db_session, child, vm, config)
    request = next_claim.expected_plan["transaction"]
    assert request["plan"]["source"]["schema"] == 1
    assert "native_volumes" not in request["plan"]["source"]
    assert request["plan"]["parent"]["backup_id"] == first.id

    child.exclude_disks = ["data"]
    with pytest.raises(StorageOwnershipError, match="fresh full"):
        validate_native_disk_selection(child, vm, agent, db=db_session)
