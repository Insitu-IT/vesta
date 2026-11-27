"""Behavioral tests execute source handlers with isolated database fakes.

Run from backend: python3 -m pytest -q tests/test_operator_surface_contracts.py
No server, network, SMTP, object storage or database is contacted.
"""

import ast
import asyncio
from copy import deepcopy
from datetime import datetime, timezone, timedelta
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4
import sys

import jsonschema
import pytest
from ci.openapi_validation import contract_format_checker

from operator_surface_contracts import apply_surface_contracts

BACKEND = Path(__file__).resolve().parents[1]


def source_function(module, name, namespace):
    """Execute the real function body; replace dependency defaults, never its logic."""
    source = ast.parse((BACKEND / module).read_text())
    node = deepcopy(
        next(
            n
            for n in ast.walk(source)
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == name
        )
    )
    node.decorator_list = []
    node.args.defaults = [ast.Constant(None) for _ in node.args.defaults]
    for index, value in enumerate(node.args.kw_defaults):
        if value is not None:
            node.args.kw_defaults[index] = ast.Constant(None)
    tree = ast.Module(
        body=[
            ast.ImportFrom(
                module="__future__", names=[ast.alias(name="annotations")], level=0
            ),
            node,
        ],
        type_ignores=[],
    )
    exec(
        compile(ast.fix_missing_locations(tree), str(BACKEND / module), "exec"),
        namespace,
    )
    return namespace[name]


class Expr:
    def __getattr__(self, _):
        return lambda *a, **kw: self

    def __eq__(self, _):
        return self

    def __ne__(self, _):
        return self

    def __or__(self, _):
        return self

    def __and__(self, _):
        return self

    def __ge__(self, _):
        return self

    def __le__(self, _):
        return self

    def __lt__(self, _):
        return self


class Model(type):
    def __getattr__(cls, _):
        return Expr()


class Row(metaclass=Model):
    def __init__(self, **kw):
        self.__dict__.update(kw)


class Query:
    def __init__(self, rows):
        self.rows = rows

    def __getattr__(self, name):
        return lambda *a, **kw: self

    def first(self):
        return self.rows[0] if self.rows else None

    def one_or_none(self):
        return self.first()

    def all(self):
        return self.rows

    def count(self):
        return len(self.rows)


class DB:
    def __init__(self, *queries):
        self.queries = list(queries)

    def query(self, *args):
        return Query(self.queries.pop(0))

    def add(self, row):
        pass

    def delete(self, row):
        pass

    def commit(self):
        pass

    def refresh(self, row):
        for key, value in {
            "id": "new-id",
            "created_at": datetime(2026, 1, 1),
            "updated_at": None,
            "enabled": True,
            "file_path": None,
            "file_size_bytes": None,
            "error_message": None,
        }.items():
            if not hasattr(row, key):
                setattr(row, key, value)


def iso(value):
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def ns(**overrides):
    values = dict(
        iso_utc=iso,
        datetime=datetime,
        timedelta=timedelta,
        VM=Row,
        Backup=Row,
        VMGroup=Row,
        SavedSearch=Row,
        Schedule=Row,
        NotificationRule=Row,
        NotificationLog=Row,
        Report=Row,
        ReportExecution=Row,
        User=Row,
        SystemSettings=Row,
        log_activity=lambda *a, **kw: None,
        check_role=lambda *a, **kw: None,
        logger=SimpleNamespace(
            info=lambda *a: None, warning=lambda *a: None, exception=lambda *a: None
        ),
    )
    values.update(overrides)
    return values


def document():
    doc = {"paths": {}, "components": {"schemas": {}}}
    for name in (
        "groups",
        "notifications",
        "search",
        "schedules",
        "reports",
        "config",
        "stats",
        "dashboard",
        "demo",
        "licensing",
    ):
        tree = ast.parse((BACKEND / "routers" / (name + ".py")).read_text())
        prefix = (
            "/api/v1/demo"
            if name == "demo"
            else "/api/v1/licensing" if name == "licensing" else "/api/v1"
        )
        for node in tree.body:
            for dec in getattr(node, "decorator_list", []):
                if not isinstance(dec, ast.Call) or not isinstance(
                    dec.func, ast.Attribute
                ):
                    continue
                if dec.func.attr not in {"get", "put", "post", "delete"}:
                    continue
                path = prefix + ast.literal_eval(dec.args[0])
                status = "200"
                for kw in dec.keywords:
                    if kw.arg == "status_code":
                        status = (
                            "201"
                            if "201" in ast.unparse(kw.value)
                            else (
                                "204"
                                if "204" in ast.unparse(kw.value)
                                else str(ast.literal_eval(kw.value))
                            )
                        )
                doc["paths"].setdefault(path, {})[dec.func.attr] = {
                    "responses": {
                        status: {
                            "content": (
                                {}
                                if status == "204"
                                else {"application/json": {"schema": {}}}
                            )
                        }
                    }
                }
    # Seed only the reusable audited list schemas from the existing enricher.
    from operator_contracts import (
        obj,
        nullable,
        page,
        STRING,
        TIME,
        INTEGER,
        BOOLEAN,
        STRINGS,
    )

    metadata = {
        "type": "object",
        "additionalProperties": True,
        "description": "Report filters",
        "x-open-schema-reason": "Report-defined filter keys.",
    }
    report = obj(
        {
            "id": STRING,
            "name": STRING,
            "report_type": STRING,
            "schedule": nullable(STRING),
            "format": STRING,
            "recipients": nullable(STRINGS),
            "filters": nullable(metadata),
            "enabled": BOOLEAN,
            "last_run_at": TIME,
            "next_run_at": TIME,
            "created_at": TIME,
            "created_by_user": nullable(obj({"id": STRING, "username": STRING})),
        }
    )
    execution = obj(
        {
            "id": STRING,
            "status": STRING,
            "file_path": nullable(STRING),
            "file_size_bytes": nullable(INTEGER),
            "file_size_mb": {"type": "number"},
            "error_message": nullable(STRING),
            "started_at": TIME,
            "completed_at": TIME,
            "created_at": TIME,
        }
    )
    doc["paths"]["/api/v1/reports"]["get"]["responses"]["200"]["content"][
        "application/json"
    ]["schema"] = page(report, "reports", paged=False)
    doc["paths"]["/api/v1/reports/{report_id}/executions"]["get"]["responses"]["200"][
        "content"
    ]["application/json"]["schema"] = page(
        execution, "executions", offset="offset", has_more=False
    )
    return apply_surface_contracts(doc)


@pytest.fixture
def doc():
    return document()


def validate(doc, path, method, result, status="200"):
    schema = doc["paths"]["/api/v1" + path][method]["responses"][status]["content"][
        "application/json"
    ]["schema"]
    jsonschema.Draft202012Validator(
        schema, format_checker=contract_format_checker()
    ).validate(result)
    return schema


def invoke(module, name, kwargs, **overrides):
    fn = source_function("routers/" + module + ".py", name, ns(**overrides))
    result = fn(**kwargs)
    return asyncio.run(result) if asyncio.iscoroutine(result) else result


def test_all_owned_response_envelopes_are_described_and_absent_routes_not_added(doc):
    # Existing download description is supplied by the prior enricher and intentionally preserved.
    for path, methods in doc["paths"].items():
        for method, op in methods.items():
            if path.endswith("/download") or path == "/api/v1/settings/v3":
                continue
            for status, response in op["responses"].items():
                if status == "204":
                    continue
                schema = response["content"]["application/json"]["schema"]
                assert schema, (method, path)
                jsonschema.Draft202012Validator.check_schema(schema)
    tiny = {"paths": {}}
    assert apply_surface_contracts(tiny) == tiny


def test_group_handlers_summary_detail_membership_and_preview(doc):
    vm = Row(id="vm", name="vm", state=None, agent=Row(hostname="host"))
    group = Row(
        id="g",
        name="group",
        description=None,
        tags=[],
        group_type="static",
        rules=None,
        rules_match=None,
        created_at=None,
        vms=[vm],
    )
    summary_ns = ns()
    summary = source_function(
        "routers/groups.py", "_serialize_group_summary", summary_ns
    )
    result = invoke(
        "groups",
        "list_groups",
        dict(
            skip=0,
            limit=50,
            search=None,
            group_type=None,
            db=DB([group]),
            current_user=Row(),
        ),
        _serialize_group_summary=summary,
    )
    validate(doc, "/groups", "get", result)
    detail = invoke(
        "groups",
        "get_group",
        dict(group_id="g", skip=0, limit=50, db=DB([group]), current_user=Row()),
        resolve_group_members=lambda *a: [vm],
    )
    validate(doc, "/groups/{group_id}", "get", detail)
    preview = invoke(
        "groups",
        "preview_group_rules",
        dict(
            group_id="g",
            body={"rules": [{"field": "name", "op": "eq", "value": "vm"}]},
            db=DB(),
            current_user=Row(),
        ),
        validate_rules=lambda rules: [],
        build_rule_query=lambda *a: Query([vm]),
    )
    validate(doc, "/groups/{group_id}/preview", "post", preview)
    result = invoke(
        "groups",
        "add_vms_to_group",
        dict(
            group_id="g",
            vm_data=Row(vm_ids=["vm", "absent"]),
            db=DB([group], [vm], []),
            current_user=Row(username="u"),
        ),
        resolve_group_members=lambda *a: [vm],
    )
    validate(doc, "/groups/{group_id}/vms", "post", result)
    assert result["already_in_group"] == ["vm"] and result["not_found"] == ["absent"]


def test_search_empty_and_both_entity_branches(doc):
    validate(
        doc,
        "/search",
        "post",
        invoke(
            "search",
            "global_search",
            dict(search_data={"query": " "}, db=DB(), current_user=Row()),
        ),
    )
    vm = Row(id="vm", name="VM", state=None, agent=None)
    backup = Row(id="b", vm=None, status="completed", created_at=None)
    result = invoke(
        "search",
        "global_search",
        dict(search_data={"query": "VM"}, db=DB([vm], [backup]), current_user=Row()),
    )
    validate(doc, "/search", "post", result)
    for kind, rows in (("vm", [vm]), ("backup", [backup]), ("unsupported", None)):
        search = Row(
            name="saved", search_type=kind, filters={}, created_by="u", is_public=False
        )
        db = DB([search], rows) if rows is not None else DB([search])
        result = invoke(
            "search",
            "execute_saved_search",
            dict(search_id="s", skip=0, limit=50, db=db, current_user=Row(id="u")),
        )
        validate(doc, "/saved-searches/{search_id}/execute", "post", result)
        assert ("search_name" in result) == (kind != "unsupported")


def test_notification_logs_inbox_and_jsonb_pass_through(doc):
    log = Row(
        id="n",
        rule_id=None,
        event_type="backup_completed",
        recipient="a",
        subject=None,
        body=None,
        status=None,
        read=False,
        sent_at=None,
    )
    for handler, path in (
        ("list_notification_logs", "/notifications/logs"),
        ("list_notifications", "/notifications"),
    ):
        result = invoke(
            "notifications",
            handler,
            dict(skip=0, limit=50, db=DB([log], [log]), current_user=Row()),
        )
        validate(doc, path, "get", result)
    # The actual manual create handler stores JSONB values without narrowing them.
    result = invoke(
        "notifications",
        "create_notification_rule",
        dict(
            rule_data={"name": "n", "event_type": "x", "recipients": {"legacy": True}},
            db=DB(),
            current_user=Row(id="u"),
        ),
    )
    validate(doc, "/notifications/rules", "post", result, "201")
    assert result["recipients"] == {"legacy": True}


@pytest.mark.parametrize("outcome", ["completed", "empty", "value_error", "error"])
def test_report_generation_optional_size_error_and_zero_size(doc, outcome):
    report = Row(id="r", format="json", last_run_at=None)

    def generate(*args):
        if outcome == "value_error":
            raise ValueError("unsupported")
        if outcome == "error":
            raise RuntimeError("broken")
        return (b"" if outcome == "empty" else b"{}"), "report.json"

    result = invoke(
        "reports",
        "generate_report",
        dict(report_id="r", current_user=Row(id="u"), db=DB([report])),
        generate_report_content=generate,
    )
    validate(doc, "/reports/{report_id}/generate", "post", result)
    assert ("file_size_bytes" in result) == (outcome == "completed")
    assert ("error" in result) == (outcome in {"value_error", "error"})


def test_report_detail_creator_role_and_missing_execution(doc):
    report = Row(
        id="r",
        name="Report",
        report_type="health",
        schedule=None,
        format="json",
        recipients=None,
        filters=None,
        enabled=True,
        last_run_at=None,
        next_run_at=None,
        created_by="u",
        created_at=None,
        updated_at=None,
    )
    user = Row(id="u", username="user", role="admin")
    result = invoke(
        "reports",
        "get_report",
        dict(report_id="r", current_user=user, db=DB([report], [user], [])),
    )
    validate(doc, "/reports/{report_id}", "get", result)
    assert (
        result["created_by_user"]["role"] == "admin"
        and result["last_execution"] is None
    )


def test_schedule_variants_and_run_now_acknowledgement(doc):
    schedule = Row(
        id="s",
        name="Schedule",
        vm_id=None,
        vm_group_id="g",
        vm=None,
        vm_group=None,
        cron_expression="0 1 * * *",
        backup_type="full",
        backup_policy=None,
        exclude_disks=None,
        workers=None,
        retention_days=None,
        tags=None,
        enabled=False,
        last_run_at=None,
        next_run_at=None,
        created_at=None,
        updated_at=None,
    )

    def authority(*a):
        return {
            "authority_revision": 1,
            "current_grant_id": None,
            "authority_state": "unenrolled",
        }

    result = invoke(
        "schedules",
        "get_schedule",
        dict(schedule_id="s", db=DB([schedule]), current_user=Row()),
        _authority=authority,
    )
    validate(doc, "/schedules/{schedule_id}", "get", result)
    result = invoke(
        "schedules",
        "list_schedules",
        dict(skip=0, limit=50, enabled=None, db=DB([schedule]), current_user=Row()),
        _authority=authority,
    )
    validate(doc, "/schedules", "get", result)
    tasks = []
    result = invoke(
        "schedules",
        "run_schedule_now",
        dict(
            schedule_id="s",
            background_tasks=Row(add_task=lambda *a: tasks.append(a)),
            db=DB([schedule]),
            current_user=Row(id="u", org_id="o"),
        ),
        execute_scheduled_backup=lambda *a: None,
    )
    validate(doc, "/schedules/{schedule_id}/run-now", "post", result)
    assert len(tasks) == 1


def test_demo_fixture_and_every_mutation_shape(doc):
    # Import pure fixture/executor helpers, and execute real Journey class with only config/models substituted.
    import demo.fixture as fixture
    import demo.executor as executor

    tree = ast.parse((BACKEND / "demo/journey.py").read_text())
    selected = [
        deepcopy(n) for n in tree.body if isinstance(n, (ast.FunctionDef, ast.ClassDef))
    ]
    namespace = dict(
        deepcopy=deepcopy,
        datetime=datetime,
        timezone=timezone,
        uuid4=uuid4,
        settings=Row(
            demo_max_activity=100,
            demo_max_groups=100,
            demo_max_schedules=100,
            demo_max_backups=100,
            demo_max_restores=100,
        ),
        DemoExecutionError=executor.DemoExecutionError,
        backup_plan=executor.backup_plan,
        retry_upload_plan=executor.retry_upload_plan,
        restore_plan=executor.restore_plan,
    )
    mod = ast.Module(
        body=[
            ast.ImportFrom(
                module="__future__", names=[ast.alias(name="annotations")], level=0
            ),
            *selected,
        ],
        type_ignores=[],
    )
    exec(
        compile(
            ast.fix_missing_locations(mod), str(BACKEND / "demo/journey.py"), "exec"
        ),
        namespace,
    )
    state = fixture.build_fixture(datetime(2026, 1, 1, tzinfo=timezone.utc)).as_dict()
    validate(doc, "/demo/state", "get", state)
    session = Row(state=state)
    journey = namespace["DemoJourney"](session, DB())
    rules = [{"field": "name", "op": "eq", "value": "billing-db"}]
    group = journey.create_group("New group", rules, "all")
    validate(doc, "/demo/groups", "post", group, "201")
    updated = journey.update_group(state["groups"][2]["id"], "Updated", rules, "all")
    validate(doc, "/demo/groups/{group_id}", "put", updated)
    vm = next(vm for vm in state["vms"] if vm["name"] == "billing-db")
    schedule = journey.create_schedule(
        dict(
            name="S",
            vm_id=vm["id"],
            cron_expression="0 1 * * *",
            retention_days=30,
            backup_type="full",
            enabled=True,
        )
    )
    validate(doc, "/demo/schedules", "post", schedule, "201")
    backup = journey.run_schedule(schedule["id"])
    validate(doc, "/demo/schedules/{schedule_id}/run", "post", backup, "201")
    for kind in ("full", "incremental"):
        backup = journey.create_backup(vm["id"], kind, "upload_failure")
        validate(doc, "/demo/backups", "post", backup, "201")
        backup = journey.retry_backup(backup["id"])
        validate(doc, "/demo/backups/{backup_id}/retry", "post", backup)
    seeded_failed = next(b for b in state["backups"] if b["status"] == "upload_failed")
    validate(
        doc,
        "/demo/backups/{backup_id}/retry",
        "post",
        journey.retry_backup(seeded_failed["id"]),
    )
    restored = journey.create_restore(backup["id"])
    validate(doc, "/demo/restores", "post", restored, "201")
    validate(doc, "/demo/state", "get", session.state)


def test_negative_envelope_controls(doc):
    schema = validate(doc, "/search", "post", {"vms": [], "backups": []})
    for bad in (
        {"vms": []},
        {"vms": [], "backups": [], "guessed": True},
        {"vms": [{}], "backups": []},
    ):
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(bad, schema)


def test_stats_and_dashboard_nested_rows(doc):
    result = invoke(
        "stats",
        "get_stats",
        dict(
            db=DB([Row()], [Row()], [], [Row()], [], [Row(size_bytes=1024)]),
            current_user=Row(),
        ),
    )
    validate(doc, "/stats", "get", result)
    result = invoke(
        "dashboard",
        "get_backup_trends",
        dict(days=2, db=DB([Row()], [], [], [Row()]), current_user=Row(org_id="o")),
    )
    validate(doc, "/dashboard/backup-trends", "get", result)
    assert result["data"][0]["completed"] == 1

    # Storage helper scalar results may be zero, unlike nullable raw SUM SQL.
    class StorageQuery(Query):
        def scalar(self):
            return None

    class StorageDB(DB):
        def query(self, *a):
            return StorageQuery(self.queries.pop(0))

    result = invoke(
        "dashboard",
        "get_storage_usage",
        dict(
            db=StorageDB([Row(id="a", hostname="h")], [], []),
            current_user=Row(org_id="o"),
        ),
        Agent=Row,
        func=Row(sum=lambda *a: None),
    )
    validate(doc, "/dashboard/storage-usage", "get", result)
    assert result["by_agent"][0]["size_bytes"] == 0


def test_licensing_actual_status_branches_and_details(doc, monkeypatch):
    config = SimpleNamespace(
        settings=Row(license_registration_url="https://registration.example")
    )
    monkeypatch.setitem(sys.modules, "config", config)
    namespace = dict(
        hashlib=__import__("hashlib"),
        POLICY_VERSION="registration-v1",
        canonical_signed_bytes=lambda value: __import__("json").dumps(value).encode(),
        _now=lambda _: datetime.now(timezone.utc),
    )
    status_fn = source_function("core/license_registration.py", "_status", namespace)

    class RegistrationError(Exception):
        def __init__(self, code):
            self.code = code

    namespace["RegistrationError"] = RegistrationError
    service = Row(
        _installation_id=lambda: None,
        _authorized=lambda: True,
        now=None,
        keys_path=None,
        profile=Row(edition="commercial", enabled_modules=set(), public=lambda: {}),
    )
    states = [
        {},
        {"envelope": "valid"},
        {"envelope": "expired"},
        {"envelope": "unknown_key"},
    ]

    def verify(envelope, *_):
        if envelope in ("expired", "unknown_key"):
            raise RegistrationError(envelope)
        return {"class": "free", "coverage": {"modules": []}}

    namespace["verify_certificate"] = verify
    for state in states:
        result = status_fn(service, state)
        validate(doc, "/licensing/status", "get", result)
    service.profile.enabled_modules = {"storage"}
    assert status_fn(service, {})["notice_required"]
    assert (
        status_fn(service, {"envelope": "valid"})["status"] == "insufficient_coverage"
    )
    # Details pass through signed payload optional timestamps, trust and nullable acknowledgement.
    service._status = lambda state, usage=None: status_fn(service, state, usage)
    service._actor = lambda: {"user_id": "u", "label": "User", "kind": "user"}
    service._read = lambda: (None, {"envelope": "valid"})
    from contextlib import nullcontext

    payload = {
        "product": "vesta",
        "license_id": "id",
        "customer_id": "customer",
        "class": "free",
        "issued_at": "2026-01-01T00:00:00+00:00",
        "coverage": {"modules": []},
    }
    namespace.update(
        PlatformContext=nullcontext,
        _json=lambda _: {"payload": payload},
        load_trusted_keys=lambda _: (
            {},
            {"state": "unprovisioned", "key_ids": [], "fingerprints": {}},
        ),
    )
    service.keys_path = None
    details_fn = source_function("core/license_registration.py", "details", namespace)
    result = details_fn(service)
    validate(doc, "/licensing", "get", result)


def test_legacy_config_serialization_and_setting_write(doc):
    import json

    rows = [
        Row(key="a", value="3", value_type="integer"),
        Row(key="b", value="true", value_type="boolean"),
        Row(key="c", value="[1,null]", value_type="json"),
        Row(key="empty", value="", value_type="integer"),
    ]
    result = invoke(
        "config",
        "get_settings",
        dict(category=None, db=DB(rows), current_user=Row()),
        json=json,
    )
    validate(doc, "/settings", "get", result)
    assert result["settings"] == {"a": 3, "b": True, "c": [1, None], "empty": ""}
    for kind, value, expected in (
        ("integer", 3, "3"),
        ("boolean", False, "false"),
        ("json", [1, None], "[1, null]"),
        ("string", None, "prior"),
    ):
        row = Row(id="s", key="key", category="general", value="prior", value_type=kind)
        result = invoke(
            "config",
            "update_setting",
            dict(
                setting_id="s",
                update_data={"value": value},
                db=DB([row]),
                current_user=Row(id="u"),
            ),
            json=json,
        )
        validate(doc, "/settings/{setting_id}", "put", result)
        assert result["setting"]["value"] == expected


def test_scheduler_preview_helper_full_scope_and_authority_variants(doc):
    import hashlib
    import json

    scope = dict(
        schema=1,
        org_id="o",
        schedule_id="s",
        revision=1,
        configuration_sha256="0" * 64,
        members=[
            dict(
                vm_id="vm",
                agent_id="a",
                provider="libvirt",
                vm_uid="uid",
                namespace="",
                source_sha256="0" * 64,
            )
        ],
        target=dict(
            endpoint="https://objects.example",
            bucket="bucket",
            region="region",
            prefix="",
            capability_profile="db-rooted-consumer-verified/1",
        ),
        encryption=dict(format="none", key_ref=None),
        options=dict(
            backup_type="full", retention_days=30, exclude_disks=[], workers=None
        ),
    )
    helper_ns = dict(
        scope_for_schedule=lambda *a: scope,
        digest=lambda value: hashlib.sha256(json.dumps(value).encode()).hexdigest(),
    )
    preview = source_function("core/scheduler_grants.py", "preview_grant", helper_ns)
    authority_fn = source_function(
        "core/backup_authority.py", "schedule_authority_state", {}
    )
    schedule = Row(
        id="s",
        org_id="o",
        current_grant_id=None,
        authority_revision=1,
        retired_at=None,
        enabled=False,
    )
    org = Row(id="o", enabled=True, scheduler_epoch=1)
    grant = Row(
        id="g",
        org_id="o",
        schedule_id="s",
        schedule_revision=1,
        state="active",
        org_epoch=1,
    )
    assert authority_fn(schedule, None, org) == "unenrolled"
    schedule.current_grant_id = "g"
    assert authority_fn(schedule, None, org) == "binding_invalid"
    assert authority_fn(schedule, grant, org) == "paused"
    schedule.enabled = True
    assert authority_fn(schedule, grant, org) == "active"
    org.enabled = False
    assert authority_fn(schedule, grant, org) == "org_epoch_held"
    grant.state = "revoked"
    assert authority_fn(schedule, grant, org) == "revoked"
    schedule.retired_at = datetime.now(timezone.utc)
    assert authority_fn(schedule, grant, org) == "retired"
    for kind in ("full", "automatic"):
        if kind == "automatic":
            scope["options"].update(
                backup_type="automatic",
                backup_policy=dict(schema=1, full_every_days=7, max_incrementals=6),
            )
        result = preview(None, schedule)
        result.update(authority_revision=1, authority_state="retired")
        validate(doc, "/schedules/{schedule_id}/grant", "get", result)


def test_dashboard_summary_null_rate_and_detached_job(doc):
    class DashboardQuery(Query):
        def __init__(self, rows=None):
            super().__init__(rows or [])

        def with_entities(self, *a):
            return DashboardQuery()

        def scalar(self):
            return None

    class DashboardDB:
        def query(self, *a):
            if len(a) > 1:
                return DashboardQuery()
            # Reused backup query supplies a missing-related-row job to job_row.
            if a[0] is backup_model:
                return DashboardQuery(
                    [
                        Row(
                            id="b",
                            vm_id="vm",
                            vm=None,
                            status="failed",
                            backup_type=None,
                            size_bytes=None,
                            progress=None,
                            created_at=None,
                        )
                    ]
                )
            return DashboardQuery()

    backup_model = type("BackupModel", (Row,), {})
    result = invoke(
        "dashboard",
        "get_dashboard_summary",
        dict(db=DashboardDB(), current_user=Row(org_id="o")),
        Backup=backup_model,
        Agent=Row,
        BackupQueue=Row,
        FileSchedule=Row,
        Organization=Row,
        timezone=timezone,
        func=Row(count=lambda *a: None, sum=lambda *a: None),
        or_=lambda *a: None,
    )
    validate(doc, "/dashboard/summary", "get", result)
    assert result["backups"]["success_rate_24h"] is None
    assert result["recent_backups"][0]["agent_name"] is None
