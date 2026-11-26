"""Unmounted evidence integrity and explicit operation qualification.

No installation approval writer and no provider discovery. Call only after
original tenant-visible owner admission; release the transaction before IO.
"""

from sqlalchemy import text
import time
from core.s3_ownership import StorageOwnershipError

ADAPTER = "vnbui-callback-provider/1"
WIRE = "vnbui-storage-transaction/1"
OPERATIONS = frozenset(
    {
        "create",
        "part_sign",
        "complete",
        "head",
        "list_parts",
        "normal_publication",
        "uncertain_recovery",
    }
)


def require_evidence(db, request, operation=None, *, signing_window=False):
    from core.storage_wire import CapabilityEvidenceRef, CapabilityEvidenceRefV2
    from core import storage_evidence_v2 as contract

    if signing_window and operation != "part_sign":
        raise StorageOwnershipError("Signing window requires part admission")

    plan = request["plan"]
    try:
        schema = plan.get("evidence_schema")
        if type(schema) is not int or schema not in (1, 2):
            raise ValueError("Unsupported schema")
        model = CapabilityEvidenceRefV2 if schema == 2 else CapabilityEvidenceRef
        ref = model.model_validate(plan["capability_evidence"]).model_dump()
    except (KeyError, ValueError, TypeError):
        raise StorageOwnershipError("Committed capability evidence required") from None
    org = request["org_id"]
    if db.scalar(text("SELECT current_setting('app.current_org',true)")) != org:
        raise StorageOwnershipError("Capability evidence owner unavailable")
    # Tenant visibility precedes advisory serialization; no arbitrary-ID lock oracle.
    row = (
        db.execute(
            text(
                "SELECT revision, facts, sha256 FROM storage_capability_evidence "
                "WHERE org_id=:org AND id=:id"
            ),
            dict(org=org, id=ref["id"]),
        )
        .mappings()
        .one_or_none()
    )
    if row is None:
        raise StorageOwnershipError("Capability evidence unavailable")
    facts = row["facts"]
    if (
        facts["schema"] != schema
        or row["revision"] != ref["revision"]
        or row["sha256"] != ref["sha256"]
        or facts["target"] != plan["target"]
        or facts["profile"] != plan["capability_profile"]
        or facts["adapter"] != ref["adapter"]
        or facts["wire"] != ref["wire"]
    ):
        raise StorageOwnershipError("Capability evidence binding differs")
    if operation is None:
        return ref
    if operation not in OPERATIONS or operation in {
        "normal_publication",
        "uncertain_recovery",
    }:
        raise StorageOwnershipError("Capability operation remains dormant")
    if schema != 2:
        raise StorageOwnershipError("Schema 1 custody is read only")
    try:
        contract.validate_facts(facts)
    except (ValueError, TypeError, KeyError):
        raise StorageOwnershipError("Capability facts invalid") from None
    if not contract.qualified(facts, operation):
        raise StorageOwnershipError("Capability operation dependencies unavailable")
    from core.storage_configuration import require_generation

    require_generation(db, org, facts)
    db.execute(
        text("SELECT pg_advisory_xact_lock(1447977558,hashtext(:id))"),
        dict(id=ref["id"]),
    )
    # A fresh statement after waiting sees a winning revocation at READ COMMITTED.
    if (
        db.scalar(text("SELECT current_setting('transaction_isolation')"))
        != "read committed"
    ):
        raise StorageOwnershipError("Capability admission requires READ COMMITTED")
    qualified = db.scalar(
        text(
            "SELECT EXISTS(SELECT 1 FROM storage_capability_qualifications q "
            "WHERE q.org_id=:org AND q.evidence_id=:id AND q.operation=:op "
            "AND q.approval->>'dependency_policy_revision'='unmounted-custody/2' "
            "AND q.approval->>'validity_policy_revision'='unmounted-fixture-86400s/1') AND NOT EXISTS("
            "SELECT 1 FROM storage_capability_revocations r WHERE r.org_id=:org "
            "AND r.evidence_id=:id AND r.operation IN (:op,'all'))"
        ),
        dict(org=org, id=ref["id"], op=operation),
    )
    if not qualified:
        raise StorageOwnershipError("Capability operation unqualified or revoked")
    # A waiting transaction must not borrow its pre-lock transaction/statement time.
    monotonic_start = time.monotonic()
    admission_now = db.scalar(text("SELECT clock_timestamp()"))
    if not contract.in_window(facts, admission_now):
        raise StorageOwnershipError("Capability evidence outside validity window")
    if signing_window:
        from core.storage_signing import SigningWindow

        window = SigningWindow(
            ref["id"],
            ref["sha256"],
            admission_now,
            int(contract.stamp(facts["validity"]["not_after_utc"]).timestamp()),
            monotonic_start,
        )
        window.interval()
        return window
    return ref
