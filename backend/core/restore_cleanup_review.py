"""Migration-owner review of one quiesced held KubeVirt restore.

This command records evidence, never deletes a VM, PVC, Job, Secret, journal
or S3 object. The operator must independently fence and inspect them first.
"""

import argparse
import json
import os
from pathlib import Path
import re

from sqlalchemy import create_engine, text

from core.postgres_profile import connection_parameters

FIELDS = {
    "schema",
    "operation_id",
    "restore_id",
    "org_id",
    "backup_id",
    "target_namespace",
    "target_vm_name",
    "target_pvc_names",
    "plan_sha256",
    "result_sha256",
    "journal_sha256",
    "producer_quiescence_sha256",
    "resource_quiescence_sha256",
    "evidence_sha256",
    "approved_by",
    "ticket",
}
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
UUID = re.compile(r"[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}\Z")


def validate(document):
    if (
        type(document) is not dict
        or set(document) != FIELDS
        or type(document["schema"]) is not int
        or document["schema"] != 1
    ):
        raise ValueError("Expected exact restore cleanup review schema 1")
    for key in ("operation_id", "restore_id"):
        if type(document[key]) is not str or UUID.fullmatch(document[key]) is None:
            raise ValueError(f"Invalid {key}")
    for key in (
        "plan_sha256",
        "result_sha256",
        "journal_sha256",
        "producer_quiescence_sha256",
        "resource_quiescence_sha256",
        "evidence_sha256",
    ):
        if type(document[key]) is not str or HEX64.fullmatch(document[key]) is None:
            raise ValueError(f"Invalid {key}")
    for key in (
        "org_id",
        "backup_id",
        "target_namespace",
        "target_vm_name",
        "approved_by",
        "ticket",
    ):
        value = document[key]
        if type(value) is not str or not value.strip() or len(value) > 200:
            raise ValueError(f"Invalid {key}")
    names = document["target_pvc_names"]
    if (
        type(names) is not list
        or not names
        or names != sorted(set(names))
        or any(type(name) is not str or not name or len(name) > 200 for name in names)
    ):
        raise ValueError("Expected sorted unique target PVC names")
    return document


def run(connection, review, expected_database, apply):
    if connection.dialect.name != "postgresql":
        raise RuntimeError("PostgreSQL required")
    if not apply:
        connection.execute(text("SET TRANSACTION READ ONLY"))
    database, owner = connection.execute(
        text("SELECT current_database(), current_user")
    ).one()
    if database != expected_database or owner != connection.scalar(
        text(
            "SELECT pg_get_userbyid(relowner) FROM pg_class WHERE oid='public.restores'::regclass"
        )
    ):
        raise RuntimeError("Named database and migration-owner identity required")
    if apply:
        return connection.scalar(
            text("SELECT public.vnbui_review_restore_cleanup(CAST(:review AS jsonb))"),
            {"review": json.dumps(review, sort_keys=True)},
        )
    connection.execute(
        text("SELECT set_config('app.current_org',:org,true)"),
        {"org": review["org_id"]},
    )
    row = connection.execute(
        text(
            "SELECT backup_id,status,kubevirt_cleanup_review IS NOT NULL,"
            "kubevirt_plan->'target'->>'namespace',"
            "kubevirt_plan->'target'->>'vm_name',"
            "encode(sha256(convert_to(kubevirt_plan::text,'UTF8')),'hex'),"
            "encode(sha256(convert_to(COALESCE(kubevirt_result,'null'::jsonb)::text,'UTF8')),'hex'),"
            "(SELECT COALESCE(jsonb_agg(d->>'pvc_name' ORDER BY d->>'pvc_name'),'[]'::jsonb) "
            "FROM jsonb_array_elements(kubevirt_plan->'target'->'disks') d) "
            "FROM public.restores WHERE id=:restore AND org_id=:org"
        ),
        {"restore": review["restore_id"], "org": review["org_id"]},
    ).one_or_none()
    if (
        row is None
        or row[0] != review["backup_id"]
        or row[1] != "cleanup_required"
        or row[2]
        or row[3] != review["target_namespace"]
        or row[4] != review["target_vm_name"]
        or row[5] != review["plan_sha256"]
        or row[6] != review["result_sha256"]
        or row[7] != review["target_pvc_names"]
    ):
        raise RuntimeError("Unreviewed held restore plan identity unavailable")
    return {
        "disposition": "preview_only",
        "restore_status": row[1],
        "operation_id": review["operation_id"],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", required=True, type=Path)
    parser.add_argument("--database", required=True)
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    try:
        review = validate(json.loads(args.plan.read_text(encoding="utf-8")))
        url = os.environ.get("DATABASE_URL")
        if not url:
            raise RuntimeError("Migration-owner DATABASE_URL required")
        url, connect_args = connection_parameters(url)
        engine = create_engine(url, connect_args=connect_args, hide_parameters=True)
        try:
            with engine.begin() as connection:
                result = run(connection, review, args.database, args.apply)
        finally:
            engine.dispose()
    except Exception as exc:
        raise SystemExit(
            f"Restore cleanup review refused ({type(exc).__name__}); no record changed"
        ) from None
    print(result["operation_id"], result["disposition"], result["restore_status"])


if __name__ == "__main__":
    main()
