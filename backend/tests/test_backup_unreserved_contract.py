"""Typed closeout input and retained-admission response schema."""

import pytest
from pydantic import ValidationError
from jsonschema import Draft202012Validator, ValidationError as SchemaValidationError

from operator_admission_contracts import ACTIONS, apply_admission_contracts
from schemas.models import BackupCloseUnreservedRequest, BackupCloseUnreservedResponse


def test_closeout_accepts_no_caller_proof_or_override():
    assert BackupCloseUnreservedRequest().model_dump() == {}
    for key in ("force", "capacity_state", "native_no_effect", "backup_id"):
        with pytest.raises(ValidationError):
            BackupCloseUnreservedRequest.model_validate({key: True})


def test_closeout_contract_is_typed_and_has_its_own_admission_identity():
    path = "/api/v1/backups/{backup_id}/close-unreserved"
    assert ACTIONS[path, "post"] == "backup.close_unreserved"
    document = {"paths": {path: {"post": {}}}}
    apply_admission_contracts(document)
    operation = document["paths"][path]["post"]
    assert operation["x-operator-action"] == "backup.close_unreserved"
    schema = operation["responses"]["200"]["content"]["application/json"]["schema"]
    body = dict(
        backup_id="backup",
        status="failed",
        reason="pre_dispatch_no_effect",
        capacity_state="unreserved",
        request_id="c8118007-61d4-4de6-a4df-a891b0ca9073",
    )
    assert BackupCloseUnreservedResponse.model_validate(body)
    Draft202012Validator(schema).validate(body)
    with pytest.raises(SchemaValidationError):
        Draft202012Validator(schema).validate(dict(body, capacity_state="released"))
