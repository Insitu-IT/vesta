"""Local controls for the acceptance instrument; no PostgreSQL substitute."""

import importlib.util
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest


def contract():
    path = (
        Path(__file__).resolve().parents[2]
        / "tests/integration/test_schema_parity_pg.py"
    )
    spec = importlib.util.spec_from_file_location("schema_policy_acceptance", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize(
    "defect",
    [
        None,
        "missing",
        "extra",
        "command",
        "forced",
        "predicate",
        "check",
        "roles",
        "part-platform",
        "part-check",
        "result-platform",
        "result-check",
        "scan-platform",
        "scan-check",
        "page-platform",
        "page-check",
        "evidence-platform",
        "evidence-check",
        "qualifications-platform",
        "qualifications-check",
        "revocations-platform",
        "revocations-check",
        "generations-platform",
        "generations-check",
        "activations-platform",
        "activations-check",
        "clock-read",
        "clock-write",
        "clock-check",
    ],
)
def test_policy_acceptance_rejects_drift(defect):
    module = contract()
    predicate = (
        "((org_id)::text = NULLIF(current_setting('app.current_org'::text, true), ''::text))"
        " OR (current_setting('app.platform_admin'::text, true) = 'true'::text)"
    )
    rows = [
        SimpleNamespace(
            tablename=table,
            policyname=name,
            cmd=cmd,
            roles=["public"],
            qual=predicate,
            with_check=predicate,
            permissive="PERMISSIVE",
        )
        for (table, name), cmd in module.EXPECTED_POLICIES.items()
    ]
    part = next(row for row in rows if row.tablename == "s3_upload_parts")
    part.qual = part.with_check = (
        "((org_id)::text = NULLIF(current_setting('app.current_org'::text, true), ''::text))"
    )
    result = next(row for row in rows if row.tablename == "s3_upload_results")
    result.qual = result.with_check = part.qual
    for table in (
        "s3_part_observation_scans",
        "s3_part_observation_pages",
        "storage_capability_evidence",
        "storage_capability_qualifications",
        "storage_capability_revocations",
        "storage_configuration_generations",
        "storage_configuration_activations",
        "file_schedules",
        "file_backups",
    ):
        row = next(row for row in rows if row.tablename == table)
        row.qual = row.with_check = part.qual
        prefix = (
            ("scan" if table.endswith("scans") else "page")
            if table.startswith("s3_")
            else table.rsplit("_", 1)[-1]
        )
        if defect == prefix + "-platform":
            row.qual = predicate
        elif defect == prefix + "-check":
            row.with_check = "true"
    clock = {
        row.policyname: row
        for row in rows
        if row.tablename == "storage_configuration_clock"
    }
    clock["configuration_clock_read"].qual = "true"
    clock["configuration_clock_read"].with_check = None
    clock["configuration_clock_write"].qual = clock[
        "configuration_clock_write"
    ].with_check = "current_setting('app.platform_admin', true) = 'true'"
    if defect == "clock-read":
        clock["configuration_clock_read"].with_check = "true"
    elif defect == "clock-write":
        clock["configuration_clock_write"].qual = "true"
    elif defect == "clock-check":
        clock["configuration_clock_write"].with_check = "true"
    if defect == "result-platform":
        result.qual = predicate
    elif defect == "result-check":
        result.with_check = "true"
    custody = next(row for row in rows if row.tablename == "oidc_login_states")
    forced = {row.tablename: True for row in rows}
    if defect == "part-platform":
        part.qual = predicate
    elif defect == "part-check":
        part.with_check = "true"
    elif defect == "missing":
        rows.remove(custody)
    elif defect == "extra":
        rows.append(
            SimpleNamespace(
                tablename="oidc_login_states", policyname="unexpected_bypass", cmd="ALL"
            )
        )
    elif defect == "command":
        custody.cmd = "SELECT"
    elif defect == "forced":
        forced["oidc_login_states"] = False
    elif defect == "predicate":
        custody.qual = "true"
    elif defect == "check":
        custody.with_check = "true"
    elif defect == "roles":
        custody.roles = ["unexpected_role"]
    connection = MagicMock()
    connection.execute.side_effect = [
        MagicMock(all=lambda: rows),
        MagicMock(all=lambda: list(forced.items())),
    ]
    if defect:
        with pytest.raises(AssertionError):
            module.assert_current_policy_contract(connection)
    else:
        module.assert_current_policy_contract(connection)
