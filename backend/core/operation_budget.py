"""Persisted admission windows; never publication or cleanup authority."""

from datetime import datetime, timedelta
from decimal import Decimal, InvalidOperation, ROUND_CEILING
import os

from core.s3_ownership import StorageOwnershipError


def verification_admission_budget(bundle):
    try:
        coefficient = Decimal(os.environ.get("OPERATION_TIME_COEFFICIENT", "3"))
        rate = int(os.environ.get("OPERATION_BOOTSTRAP_BYTES_PER_SECOND", "8388608"))
        preparation = int(
            os.environ.get("OPERATION_PREPARATION_ESTIMATE_SECONDS", "180")
        )
        control = int(os.environ.get("OPERATION_CONTROL_ESTIMATE_SECONDS", "60"))
        if (
            not coefficient.is_finite()
            or not 1 <= coefficient <= 100
            or not 1 <= rate <= 2**40
            or not 1 <= preparation <= 86400
            or not 1 <= control <= 3600
        ):
            raise ValueError
        size = 0
        for member in bundle["members"]:
            for item in member["receipt"]["objects"]:
                value = item["ciphertext_bytes"]
                if type(value) is not int or not 0 <= value < 2**63:
                    raise ValueError
                size += value
        if size >= 2**63:
            raise ValueError
        estimate = (size + rate - 1) // rate + preparation + control
        seconds = int(
            (coefficient * estimate).to_integral_value(rounding=ROUND_CEILING)
        )
        # A backend admission window cannot promise an unbounded agent queue.
        # The worker independently checks its configured provider ceiling.
        if not 1 <= seconds <= 30 * 86400:
            raise ValueError
        now = datetime.utcnow()
        return dict(
            schema=1,
            started_at=now.isoformat(),
            deadline=(now + timedelta(seconds=seconds)).isoformat(),
            estimated_bytes=size,
            bytes_per_second=rate,
            estimated_seconds=estimate,
            coefficient=str(coefficient),
        )
    except (ValueError, KeyError, TypeError, InvalidOperation, OverflowError):
        raise StorageOwnershipError(
            "Verification admission estimate is invalid or exceeds its supported window"
        ) from None


def verification_admission_exhausted(record, now=None):
    value = record.verification_admission_budget
    try:
        if not isinstance(value, dict) or value.get("schema") != 1:
            return True
        started = datetime.fromisoformat(value["started_at"])
        deadline = datetime.fromisoformat(value["deadline"])
        now = now or datetime.utcnow()
        return not started <= now < deadline or deadline - started > timedelta(days=30)
    except (ValueError, KeyError, TypeError, OverflowError):
        return True
