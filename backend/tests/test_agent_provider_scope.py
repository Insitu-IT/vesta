from types import SimpleNamespace
import pytest
from fastapi import HTTPException
from core.agent_scope import source_allowed, validate_settings
from core.agent_health import assess_agent_health


def agent(selected=None, requested=None):
    return SimpleNamespace(
        capabilities={"provider": "kubevirt"},
        metrics={
            "scope": {
                "source_namespaces": ["one", "two"],
                "selected_source_namespaces": ["one"] if selected is None else selected,
                "restore_namespaces": ["recovery"],
                "applied_revision": "old",
            }
        },
        config=(
            {}
            if requested is None
            else {"selected_source_namespaces": requested, "scope_revision": "new"}
        ),
    )


def test_direct_settings_cannot_widen_installation_ceiling():
    with pytest.raises(HTTPException) as error:
        validate_settings(agent(), {"selected_source_namespaces": ["outside"]})
    assert error.value.status_code == 422
    validate_settings(agent(), {"selected_source_namespaces": []})


def test_narrowing_blocks_immediately_widening_waits_for_agent_ack():
    assert source_allowed(agent(), "one")
    assert not source_allowed(agent(requested=[]), "one")
    assert not source_allowed(agent(requested=["one", "two"]), "two")
    assert source_allowed(
        agent(selected=["one", "two"], requested=["one", "two"]), "two"
    )
    assert not source_allowed(agent(), "recovery")


@pytest.mark.parametrize(
    "field",
    [
        "libvirt_uri",
        "virtnbdbackup_path",
        "virtnbdrestore_path",
        "virtnbd_scratch_dir",
        "backup_storage_path",
        "compression_type",
    ],
)
def test_kubevirt_refuses_irrelevant_or_startup_only_setting(field):
    with pytest.raises(HTTPException):
        validate_settings(agent(), {field: "value"})


def test_journal_uses_percentage_instead_of_native_payload_gib_threshold():
    thresholds = dict(
        storage_free_gb_threshold=10,
        storage_free_percent_threshold=10,
        load_percent_threshold=80,
    )
    reading = dict(
        storage_role="journal",
        backup_storage_free_bytes=900 * 1024**2,
        backup_storage_total_bytes=1024**3,
    )
    assert assess_agent_health(reading, **thresholds) == ([], [])
    reading["storage_role"] = "native_capture"
    assert assess_agent_health(reading, **thresholds)[1] == ["storage_low"]
    reading.update(storage_role="journal", backup_storage_free_bytes=0)
    assert assess_agent_health(reading, **thresholds)[1] == ["storage_low"]


def test_failed_measurement_is_unknown_not_low_storage():
    thresholds = dict(
        storage_free_gb_threshold=10,
        storage_free_percent_threshold=10,
        load_percent_threshold=80,
    )
    reading = dict(
        storage_role="journal",
        backup_storage_free_bytes=None,
        backup_storage_total_bytes=None,
        storage_measurement_error="stat unavailable",
    )
    assert assess_agent_health(reading, **thresholds)[1] == ["storage_unknown"]


@pytest.mark.asyncio
async def test_admin_settings_route_validates_direct_request_and_ack_revision(
    db_session, monkeypatch
):
    from routers import agents
    from schemas import AgentSettingsUpdate
    from .conftest import make_agent

    record = make_agent(
        db_session, capabilities={"provider": "kubevirt"}, metrics=agent().metrics
    )
    monkeypatch.setattr(agents, "log_activity", lambda *args, **kwargs: None)
    with pytest.raises(HTTPException) as rejected:
        await agents.update_agent_settings(
            record.id,
            AgentSettingsUpdate(selected_source_namespaces=["outside"]),
            db_session,
            SimpleNamespace(),
        )
    assert rejected.value.status_code == 422
    result = await agents.update_agent_settings(
        record.id,
        AgentSettingsUpdate(selected_source_namespaces=[]),
        db_session,
        SimpleNamespace(),
    )
    assert result["config"]["selected_source_namespaces"] == []
    assert result["config"]["scope_revision"]
    assert record.metrics["scope"]["applied_revision"] == "old"
    assert not source_allowed(record, "one")


def test_legacy_requires_proven_nonempty_singleton_and_never_cluster_fallback():
    record = SimpleNamespace(
        capabilities={"backup_method": "vmexport"},
        metrics={},
        config={"kube_namespace": "one"},
    )
    assert source_allowed(record, "one")
    assert not source_allowed(record, "two")
    record.config = {"kube_namespace": ""}
    assert not source_allowed(record, "one")
    record.config = {}
    assert not source_allowed(record, "one")


def test_fresh_storage_defaults_to_supported_s3_and_preserves_explicit_choice(
    db_session, monkeypatch
):
    from core.settings_service import SettingsService

    monkeypatch.delenv("VNBUI_STORAGE_TYPE", raising=False)
    settings = SettingsService(db_session)
    assert settings.get("storage.type") == "s3"
    assert settings.get_s3_config() is None
    settings.set("storage.type", "local")
    assert settings.get("storage.type") == "local"
    monkeypatch.setenv("VNBUI_STORAGE_TYPE", "s3")
    assert settings.get("storage.type") == "local"


def test_common_manual_and_queue_admission_refuses_narrowed_namespace(db_session):
    from core.backup_service import BackupService
    from .conftest import make_agent, make_vm

    record = make_agent(
        db_session,
        capabilities={"provider": "kubevirt"},
        metrics=agent().metrics,
        config={"selected_source_namespaces": []},
    )
    vm = make_vm(
        db_session,
        record,
        provider="kubevirt",
        namespace="one",
        vm_uid="stable",
        inventory_present=True,
        disks=[
            {
                "target": "data",
                "source_type": "persistentVolumeClaim",
                "backup_eligible": True,
            }
        ],
    )
    service = BackupService(db_session)
    allowed, error, code = service.can_start_backup(
        vm.id, check_maintenance=False, check_concurrent=False
    )
    assert not allowed and code == 409 and "outside" in error
    result = service.create_backup(
        vm.id, check_maintenance=False, check_concurrent=False
    )
    assert not result.success and result.error_code == 409
