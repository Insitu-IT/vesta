"""Endpoint commit ownership controls; PostgreSQL rollback is tested separately."""

from datetime import datetime
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from models import ActivityLog
from routers import users
from schemas import UserCreate, UserUpdate
from fastapi import HTTPException
from pydantic import ValidationError


@pytest.mark.asyncio
@pytest.mark.parametrize("operation", ["create", "update", "delete"])
@pytest.mark.parametrize("failure", [None, "construct", "add", "flush", "commit"])
async def test_user_mutation_owns_one_audited_commit(monkeypatch, operation, failure):
    actor = SimpleNamespace(id="actor", org_id="org", is_platform_admin=False)
    target = SimpleNamespace(
        id="target",
        username="before",
        full_name=None,
        email=None,
        role="viewer",
        is_active=True,
        auth_source="local",
        role_source="local",
        is_platform_admin=False,
        oidc_subject=None,
        oidc_issuer=None,
        created_at=datetime(2026, 1, 1),
    )
    db = MagicMock()
    # Transaction controls isolate commit ownership; restricted PG executes the
    # real lock and persisted revalidation separately.
    monkeypatch.setattr(users, "locked_user_mutation", lambda *_: (actor, target))
    db.query.return_value.filter.return_value.first.return_value = (
        None if operation == "create" else target
    )
    monkeypatch.setattr(users, "validate_password", lambda *args: (True, []))
    monkeypatch.setattr(users, "hash_password", lambda value: "private-hash")
    staged = []
    audit_started = False

    def add(instance):
        nonlocal audit_started
        if isinstance(instance, ActivityLog):
            audit_started = True
            assert "Private1!Password" not in str(instance.details)
            assert "private-hash" not in str(instance.details)
            if failure == "add":
                raise RuntimeError("audit add refused")
        staged.append(instance)

    def flush():
        if audit_started and failure == "flush":
            raise RuntimeError("audit flush refused")

    def refuse(*args, **kwargs):
        raise RuntimeError("injected failure")

    db.add.side_effect = add
    db.flush.side_effect = flush
    if failure == "construct":
        monkeypatch.setattr(users, "log_activity", refuse)
    if failure == "commit":
        db.commit.side_effect = refuse

    async def invoke():
        if operation == "create":
            return await users.create_user(
                UserCreate(username="new", password="Private1!Password"), db, actor
            )
        if operation == "update":
            return await users.update_user(
                target.id, UserUpdate(full_name="after"), db, actor
            )
        return await users.delete_user(target.id, db, actor)

    if failure:
        with pytest.raises(RuntimeError):
            await invoke()
        db.rollback.assert_called_once()
    else:
        assert await invoke()
        db.rollback.assert_not_called()
        assert len([row for row in staged if isinstance(row, ActivityLog)]) == 1
    assert db.commit.call_count == (1 if failure in (None, "commit") else 0)
    db.refresh.assert_not_called()


@pytest.mark.parametrize("schema", [UserCreate, UserUpdate])
@pytest.mark.parametrize(
    "field",
    [
        "org_id",
        "is_platform_admin",
        "auth_source",
        "oidc_subject",
        "oidc_issuer",
        "password_hash",
    ],
)
def test_user_schemas_reject_authority_and_provider_fields(schema, field):
    body = (
        {"username": "user", "password": "Private1!Password"}
        if schema is UserCreate
        else {}
    )
    with pytest.raises(ValidationError):
        schema(**body, **{field: "forged"})


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "source,role_source,body,self_edit",
    [
        ("oidc", "oidc", {"username": "before"}, False),
        ("oidc", "oidc", {"email": None}, False),
        ("oidc", "oidc", {"full_name": "other"}, False),
        ("oidc", "oidc", {"password": "Private1!Password"}, False),
        ("oidc", "oidc", {"role_source": "local"}, False),
        ("oidc", "local", {"role_source": "oidc", "role": "admin"}, False),
        ("oidc", "oidc", {"role": "admin"}, False),
        ("local", "local", {"role_source": "oidc"}, False),
        ("local", "local", {"is_active": False}, True),
        ("local", "local", {"password": "weak", "full_name": "after"}, False),
    ],
)
async def test_user_validation_refuses_before_mutation(
    monkeypatch, source, role_source, body, self_edit
):
    actor = SimpleNamespace(id="actor", org_id="org", is_platform_admin=False)
    target = SimpleNamespace(
        id="actor" if self_edit else "target",
        auth_source=source,
        role_source=role_source,
        is_platform_admin=False,
    )
    before = vars(target).copy()
    monkeypatch.setattr(users, "locked_user_mutation", lambda *_: (actor, target))
    db = MagicMock()
    db.query.return_value.filter.return_value.first.return_value = target
    monkeypatch.setattr(
        users, "validate_password", lambda *args: (False, ["weak password"])
    )
    with pytest.raises(HTTPException) as denied:
        await users.update_user(target.id, UserUpdate(**body), db, actor)
    assert denied.value.status_code == 400
    assert vars(target) == before
    db.flush.assert_not_called()
    db.commit.assert_not_called()
    db.add.assert_not_called()


@pytest.mark.parametrize("count", [0, 1, 2])
def test_remaining_admin_count_refuses_empty(count):
    db = MagicMock()
    db.query.return_value.filter.return_value.count.return_value = count
    if count:
        users.require_remaining_admin(db, "org")
    else:
        with pytest.raises(HTTPException) as denied:
            users.require_remaining_admin(db, "org")
        assert denied.value.status_code == 409
    db.commit.assert_not_called()


@pytest.mark.asyncio
async def test_delete_referenced_user_is_generic_conflict(monkeypatch):
    from sqlalchemy.exc import IntegrityError

    actor = SimpleNamespace(id="actor", org_id="org", is_platform_admin=False)
    target = SimpleNamespace(id="target", username="same", is_platform_admin=False)
    monkeypatch.setattr(users, "locked_user_mutation", lambda *_: (actor, target))
    db = MagicMock()
    db.flush.side_effect = IntegrityError(
        "private SQL", {}, Exception("private reference")
    )
    with pytest.raises(HTTPException) as denied:
        await users.delete_user("target", db, actor)
    assert denied.value.status_code == 409
    assert "private" not in denied.value.detail
    db.rollback.assert_called_once()
    db.commit.assert_not_called()
    db.add.assert_not_called()
