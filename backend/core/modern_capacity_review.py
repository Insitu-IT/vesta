"""Owner-only disposition of a held storage backup; never a runtime API.

The operator must settle producer, chain, object and journal custody first.
The database validates identity and policy again under locks. A preview is
read-only; --apply commits the entire plan atomically.
"""

import argparse
import json
import os
from pathlib import Path
import re

from sqlalchemy import create_engine, text

from core.postgres_profile import connection_parameters

COMMON = {
    "schema",
    "operation_id",
    "backup_id",
    "org_id",
    "vm_id",
    "capacity_id",
    "classification",
    "evidence_sha256",
    "approved_by",
    "ticket",
}
RELEASE = {
    "producer_quiescence_sha256",
    "chain_custody_sha256",
    "object_custody_sha256",
    "journal_sha256",
    "publication_ids",
}
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
UUID = re.compile(r"[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}\Z")


def validate(document):
    if type(document) is not dict or set(document) != {"schema", "reviews"}:
        raise ValueError("Expected only schema and reviews")
    if type(document["schema"]) is not int or document["schema"] != 1:
        raise ValueError("Unsupported review plan schema")
    reviews = document["reviews"]
    if type(reviews) is not list or not 1 <= len(reviews) <= 100:
        raise ValueError("Expected 1-100 explicit row reviews")
    operations = set()
    for review in reviews:
        if type(review) is not dict or review.get("classification") not in {
            "uncertain",
            "occupied",
            "released",
        }:
            raise ValueError("Unknown review classification")
        expected = COMMON | (
            RELEASE if review["classification"] == "released" else set()
        )
        if (
            set(review) != expected
            or type(review["schema"]) is not int
            or review["schema"] != 1
        ):
            raise ValueError("Review fields differ from its exact schema")
        for key in ("operation_id", "capacity_id"):
            if type(review[key]) is not str or UUID.fullmatch(review[key]) is None:
                raise ValueError(f"Invalid {key}")
        for key in ("evidence_sha256", *(RELEASE & expected - {"publication_ids"})):
            if type(review[key]) is not str or HEX64.fullmatch(review[key]) is None:
                raise ValueError(f"Invalid {key}")
        for key in ("backup_id", "org_id", "vm_id", "approved_by", "ticket"):
            if (
                type(review[key]) is not str
                or not 1 <= len(review[key]) <= 200
                or not review[key].strip()
            ):
                raise ValueError(f"Invalid {key}")
        if review["classification"] == "released":
            ids = review["publication_ids"]
            if (
                type(ids) is not list
                or not ids
                or any(type(value) is not str or not value for value in ids)
                or ids != sorted(set(ids))
            ):
                raise ValueError("Expected sorted, unique publication IDs")
        if review["operation_id"] in operations:
            raise ValueError("Duplicate operation ID in plan")
        operations.add(review["operation_id"])
    return reviews


def run(connection, reviews, expected_database, apply):
    if connection.dialect.name != "postgresql":
        raise RuntimeError("PostgreSQL required")
    if not apply:
        connection.execute(text("SET TRANSACTION READ ONLY"))
    identity = connection.execute(text("SELECT current_database(),current_user")).one()
    if identity[0] != expected_database:
        raise RuntimeError("Database identity differs from operator plan")
    owner = connection.scalar(
        text(
            "SELECT pg_get_userbyid(relowner) FROM pg_class WHERE oid='public.backups'::regclass"
        )
    )
    if identity[1] != owner:
        raise RuntimeError("Migration-owner database identity required")
    results = []
    for review in reviews:
        if apply:
            results.append(
                connection.scalar(
                    text(
                        "SELECT public.vnbui_review_modern_capacity(CAST(:review AS jsonb))"
                    ),
                    {"review": json.dumps(review, sort_keys=True)},
                )
            )
        else:
            connection.execute(
                text("SELECT set_config('app.current_org',:org,true)"),
                {"org": review["org_id"]},
            )
            row = connection.execute(
                text(
                    "SELECT capacity_id::text,capacity_state FROM public.backups "
                    "WHERE id=:backup AND org_id=:org AND vm_id=:vm"
                ),
                {
                    "backup": review["backup_id"],
                    "org": review["org_id"],
                    "vm": review["vm_id"],
                },
            ).one_or_none()
            if row is None or row[0] != review["capacity_id"]:
                raise RuntimeError("A planned held row or capacity ID is unavailable")
            results.append(
                {
                    "operation_id": review["operation_id"],
                    "capacity_state": row[1],
                    "disposition": "preview_only",
                }
            )
    return results


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--database", required=True)
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    try:
        reviews = validate(json.loads(args.plan.read_text(encoding="utf-8")))
        url = os.environ.get("DATABASE_URL")
        if not url:
            raise RuntimeError("Migration-owner DATABASE_URL required")
        url, connect_args = connection_parameters(url)
        engine = create_engine(url, connect_args=connect_args, hide_parameters=True)
        try:
            with engine.begin() as connection:
                result = run(connection, reviews, args.database, args.apply)
        finally:
            engine.dispose()
    except Exception as exc:
        raise SystemExit(
            f"Modern review refused ({type(exc).__name__}); no partial batch committed"
        ) from None
    for item in result:
        print(f"{item['operation_id']} {item['disposition']} {item['capacity_state']}")


if __name__ == "__main__":
    main()
