"""Actual handler/serializer contracts with SQLite and provider fakes only.

This suite checks wire descriptions, not PostgreSQL concurrency, module admission,
installed profiles or interoperability.
"""

import asyncio
from contextlib import nullcontext
from datetime import datetime
import inspect
from types import SimpleNamespace as NS
from uuid import uuid4

import jsonschema
import pytest
from ci.openapi_validation import contract_format_checker
from fastapi import BackgroundTasks, FastAPI, HTTPException, Response
from fastapi.encoders import jsonable_encoder

from core.settings_service import SettingsService
from models import (
    Agent,
    Backup,
    BackupQueue,
    BackupVerification,
    User,
    VM,
)
from operator_contracts import install_operator_contracts
from routers import (
    api_keys,
    backups,
    bulk,
    config,
    encryption,
    queue,
    s3_import,
    users,
    verification,
)
from schemas import (
    UserCreate,
    UserUpdate,
    OrchestratorAPIKeyCreate,
    OrchestratorAPIKeyUpdate,
    AgentRegistrationKeyCreate,
    AgentRegistrationKeyUpdate,
)


def run(value):
    return asyncio.run(value) if inspect.isawaitable(value) else value


@pytest.fixture(scope="session")
def schema():
    # Explicit router inclusion is a mock schema fixture, not installed-module admission.
    app = FastAPI()
    for module in (
        queue,
        backups,
        bulk,
        config,
        users,
        api_keys,
        verification,
        s3_import,
        encryption,
    ):
        app.include_router(module.router)
    install_operator_contracts(
        app, SettingsService.DEFINITIONS, SettingsService.SECRET_DEFINITIONS
    )
    return app.openapi()


def validate(schema, path, method, payload, status=200):
    response = schema["paths"]["/api/v1" + path][method]["responses"][str(status)]
    selected = response["content"]["application/json"]["schema"]
    validator = jsonschema.Draft202012Validator(
        {**selected, "components": schema["components"]},
        format_checker=contract_format_checker(),
    )
    validator.validate(jsonable_encoder(payload))
    return selected


@pytest.fixture
def actor(db_session):
    user = User(
        id=str(uuid4()),
        username="contract-admin",
        password_hash="unused-test-hash",
        role="admin",
        is_active=True,
        auth_source="local",
        role_source="local",
        is_platform_admin=True,
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user


@pytest.fixture
def inventory(db_session):
    agent = Agent(
        id=str(uuid4()),
        hostname="contract.test",
        status="online",
        ip_address="127.0.0.1",
        port=8090,
    )
    db_session.add(agent)
    db_session.flush()
    vm = VM(
        id=str(uuid4()),
        name="contract-vm",
        uuid=str(uuid4()),
        agent_id=agent.id,
        state="running",
        provider="libvirt",
        disks=[],
    )
    db_session.add(vm)
    db_session.commit()
    return agent, vm


def backup_row(db, vm, **kw):
    row = Backup(
        id=str(uuid4()),
        vm_id=vm.id,
        status="completed",
        backup_type="full",
        tags={},
        capacity_state="unreserved",
        **kw,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


def test_nonempty_queue_serializes_state_and_deterministic_ties(
    schema, db_session, actor, inventory, monkeypatch
):
    _, vm = inventory
    instant = datetime(2026, 1, 1)
    ids = [
        "00000000-0000-4000-8000-000000000002",
        "00000000-0000-4000-8000-000000000001",
    ]
    for item_id in ids:
        db_session.add(
            BackupQueue(
                id=item_id,
                vm_id=vm.id,
                priority=7,
                queued_at=instant,
                status="queued",
                created_by=actor.id,
            )
        )
    db_session.commit()
    monkeypatch.setattr(queue, "get_max_concurrent_backups", lambda db: 3)
    result = run(queue.get_backup_queue(db=db_session, current_user=actor))
    validate(schema, "/backups/queue", "get", result)
    assert [item["id"] for item in result["queue"]] == sorted(ids)
    assert [item["position"] for item in result["queue"]] == [1, 2]
    assert result["queue"][0]["created_by"] == actor.username
    assert all(
        item["status"] == "queued"
        and item["hold_reason"] is None
        and item["started_backup_id"] is None
        for item in result["queue"]
    )
    assert result["available_slots"] == 3


def test_settings_empty_accepted_read_null_but_patch_null_refused(
    schema, db_session, actor
):
    patch = {"storage.s3.endpoint": "   ", "storage.s3.bucket": "", "oidc.issuer": ""}
    result = run(
        config.update_settings_v3(
            settings_data=patch, current_user=actor, db=db_session
        )
    )
    validate(schema, "/settings/v3", "put", result)
    result = run(config.get_settings_v3(current_user=actor, db=db_session))
    validate(schema, "/settings/v3", "get", result)
    assert all(result["settings"][key] is None for key in patch)
    request = schema["paths"]["/api/v1/settings/v3"]["put"]["requestBody"]["content"][
        "application/json"
    ]["schema"]
    for key in patch:
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate({key: None}, request)
        with pytest.raises(HTTPException) as exc:
            run(
                config.update_settings_v3(
                    settings_data={key: None}, current_user=actor, db=db_session
                )
            )
        assert exc.value.status_code == 400


@pytest.mark.parametrize("mode", ["completed", "accepted", "held"])
def test_resume_handler_actual_worker_transport_fakes(
    schema, db_session, actor, inventory, monkeypatch, mode
):
    import threading

    from backend.tests.test_manual_kubevirt_execution import (
        install_certified_backup_transport,
    )
    from core import backup_recovery as recovery
    from core.backup_executor import BackupExecutor

    agent, vm = inventory
    row = backup_row(db_session, vm)
    if mode != "completed":
        row.status = "running"
    db_session.commit()
    expected = {"status": "accepted", "attempt_id": "original-attempt"}
    executor = BackupExecutor()
    transport = install_certified_backup_transport(
        db_session,
        executor,
        agent,
        monkeypatch,
        NS(status_code=423 if mode == "held" else 202, json=lambda: expected),
    )
    monkeypatch.setattr(
        recovery,
        "_readmit",
        lambda db, backup: (inventory[0].id, {"frozen": "original"}, expected),
    )

    # Worker uses the real handler's requester checks and original delivery branch.
    def factory():
        return nullcontext(db_session)

    async def local_worker(
        factory_ignored, executor_ignored, backup_id, org_id, caller_id
    ):
        return await recovery._resume_backup_attempt_worker(
            factory, executor, backup_id, org_id, caller_id, threading.Event()
        )

    monkeypatch.setattr(recovery, "resume_backup_attempt", local_worker)
    response = Response(status_code=202)
    if mode == "held":
        with pytest.raises(HTTPException) as exc:
            run(backups.resume_attempt(row.id, response, actor))
        assert exc.value.status_code == 423
        validate(
            schema,
            "/backups/{backup_id}/resume",
            "post",
            {"detail": exc.value.detail},
            423,
        )
        assert exc.value.detail["capacity_retained"] is True
    else:
        result = run(backups.resume_attempt(row.id, response, actor))
        validate(
            schema,
            "/backups/{backup_id}/resume",
            "post",
            result,
            200 if mode == "completed" else 202,
        )
        assert response.status_code == (200 if mode == "completed" else 202)
        assert result["resumed"] == (mode == "accepted")
    if mode == "completed":
        transport.assert_not_contacted()
    else:
        assert transport.assert_sent() == {"frozen": "original"}
    if mode == "held":
        assert (
            exc.value.detail["reason"]
            == "agent_attempt_not_resumable_unsealed_or_uncertain"
        )
    assert response.headers["Cache-Control"] == "no-store"


def test_retry_upload_has_no_success_and_never_schedules(
    schema, db_session, actor, inventory, monkeypatch
):
    from core import upload_retry

    _, vm = inventory
    row = backup_row(db_session, vm)
    monkeypatch.setattr(
        upload_retry, "record_retry_hold", lambda *a: "producer_reconciliation_required"
    )
    tasks = BackgroundTasks()
    with pytest.raises(HTTPException) as exc:
        backups.retry_upload(row.id, tasks, db_session, actor)
    assert exc.value.status_code == 423 and not tasks.tasks
    validate(
        schema,
        "/backups/{backup_id}/retry-upload",
        "post",
        {"detail": exc.value.detail},
        423,
    )
    assert not any(
        status.startswith("2")
        for status in schema["paths"]["/api/v1/backups/{backup_id}/retry-upload"][
            "post"
        ]["responses"]
    )


def test_bulk_mixed_deleted_held_missing_provider_failure_and_tags(
    schema, db_session, actor, inventory, monkeypatch
):
    _, vm = inventory
    good = backup_row(db_session, vm)
    held = backup_row(db_session, vm)
    held.capacity_state = "legacy_held"
    held.capacity_id = str(uuid4())
    held.capacity_reserved_at = datetime(2026, 1, 1)
    bad = backup_row(db_session, vm)
    db_session.commit()

    async def delete_payload(db, row):
        if row.id == bad.id:
            raise RuntimeError("provider refused")
        row.status = "deleted"
        return 321

    monkeypatch.setattr(bulk.backup_deletion_service, "delete_payload", delete_payload)
    result = bulk.bulk_delete_backups(
        NS(backup_ids=[good.id, held.id, "missing", bad.id]), db_session, actor
    )
    validate(schema, "/backups/bulk-delete", "post", result)
    assert result["summary"] == {"total": 4, "deleted": 1, "skipped": 1, "failed": 2}
    assert result["details"]["deleted"][0]["deleted_bytes"] == 321
    result = bulk.bulk_tag_backups(
        NS(backup_ids=[held.id, "missing"], tags={"purpose": "test"}, overwrite=False),
        db_session,
        actor,
    )
    validate(schema, "/backups/bulk-tag", "post", result)
    assert result["summary"] == {"total": 2, "updated": 1, "failed": 1}


def test_user_crud_exact_projection(schema, db_session, actor, monkeypatch):
    monkeypatch.setattr(users, "validate_password", lambda *a: (True, []))
    monkeypatch.setattr(users, "hash_password", lambda _: "unused-test-hash")
    result = run(
        users.create_user(
            UserCreate(
                username="contract-viewer", password="test-password", role="viewer"
            ),
            db_session,
            actor,
        )
    )
    validate(schema, "/users", "post", result, 201)
    user_id = result["id"]
    result = run(users.get_user(user_id, db_session, actor))
    validate(schema, "/users/{user_id}", "get", result)
    assert "last_login" in result and "org_id" not in result
    # PostgreSQL advisory lock is covered elsewhere; retain actual mutation/projection with SQLite.
    monkeypatch.setattr(
        users, "locked_user_mutation", lambda db, admin, uid: (admin, db.get(User, uid))
    )
    result = run(
        users.update_user(
            user_id,
            UserUpdate(full_name=None, email=None, role="operator"),
            db_session,
            actor,
        )
    )
    validate(schema, "/users/{user_id}", "put", result)
    assert result["full_name"] is None and "last_login" not in result
    result = run(users.delete_user(user_id, db_session, actor))
    validate(schema, "/users/{user_id}", "delete", result)


@pytest.mark.parametrize("registration", [False, True])
def test_key_create_update_list_delete_exact_shapes(
    schema, db_session, actor, monkeypatch, registration
):
    # Fake only durable PostgreSQL admission plumbing; handlers construct actual SQL rows/projections.
    class Admission:
        replay = False

        def finish(self, payload, *, status, secret_fields):
            db_session.commit()
            return {
                **payload,
                "request_id": str(uuid4()),
                "secret_delivery": "one_time",
            }

    monkeypatch.setattr(api_keys, "begin_admission", lambda *a: Admission())
    if registration:
        key_data = AgentRegistrationKeyCreate(
            name="key", agent_hostname="contract.test"
        )
        create, update, listing, delete = (
            api_keys.create_registration_key,
            api_keys.update_registration_key,
            api_keys.list_registration_keys,
            api_keys.delete_registration_key,
        )
        data = AgentRegistrationKeyUpdate(name="updated", enabled=False)
        path = "/registration-keys"
    else:
        key_data = OrchestratorAPIKeyCreate(name="key")
        create, update, listing, delete = (
            api_keys.create_orchestrator_key,
            api_keys.update_orchestrator_key,
            api_keys.list_orchestrator_keys,
            api_keys.delete_orchestrator_key,
        )
        data = OrchestratorAPIKeyUpdate(name="updated", enabled=False)
        path = "/orchestrator-keys"
    result = create(key_data, db_session, actor, str(uuid4()))
    validate(schema, path, "post", result, 201)
    key_id = result["id"]
    assert "api_key" in result
    result = run(update(key_id, data, db_session, actor))
    validate(schema, path + "/{key_id}", "patch", result)
    assert result["is_valid"] is False and "api_key" not in result
    result = run(listing(db_session, actor))
    validate(schema, path, "get", result)
    assert all("api_key" not in item for item in result["items"])
    result = run(delete(key_id, db_session, actor))
    validate(schema, path + "/{key_id}", "delete", result)


def test_verification_cancel_terminal_race_omits_type(
    schema, db_session, actor, inventory, monkeypatch
):
    _, vm = inventory
    backup = backup_row(db_session, vm)
    row = BackupVerification(
        id=str(uuid4()),
        backup_id=backup.id,
        created_by=actor.id,
        verification_type=verification.scrub.TYPE,
        status="running",
        verification_cancel_requested=False,
    )
    db_session.add(row)
    db_session.commit()
    original_refresh = db_session.refresh

    def terminal_refresh(value, *a, **kw):
        original_refresh(
            value, *a, **{k: v for k, v in kw.items() if k != "with_for_update"}
        )
        if value is row:
            value.status = "cancelled"
            value.completed_at = datetime(2026, 1, 1)

    monkeypatch.setattr(db_session, "refresh", terminal_refresh)
    notified = []
    monkeypatch.setattr(
        verification.verification_executor, "notify", lambda: notified.append(True)
    )
    result = verification.verify_backup(
        backup.id,
        verification.VerificationCommand(verification_id=row.id, action="cancel"),
        Response(),
        actor,
        db_session,
    )
    validate(schema, "/backups/{backup_id}/verify", "post", result, 202)
    assert (
        result["status"] == "cancelled"
        and "verification_type" not in result
        and not notified
    )
    # An already-terminal observation takes the normal return path and includes type.
    result = verification.verify_backup(
        backup.id,
        verification.VerificationCommand(verification_id=row.id, action="cancel"),
        Response(),
        actor,
        db_session,
    )
    validate(schema, "/backups/{backup_id}/verify", "post", result, 202)
    assert result["verification_type"] == verification.scrub.TYPE and len(notified) == 1


def test_retired_s3_family_declares_no_success_responses(schema):
    result = schema["paths"]["/api/v1/s3/import"]["post"]
    assert result["deprecated"] is True
    assert "410" in result["responses"]
    assert not any(code.startswith("2") for code in result["responses"])
    assert "200" in schema["paths"]["/api/v1/s3/discover"]["get"]["responses"]
