"""Finite maximum-size traversal only; authority evidence is restricted PG."""

from contextlib import nullcontext
from types import SimpleNamespace
import uuid

from core import callback_receipt_io as service
from core.storage_plan import MAX_ARTIFACTS


def test_maximum_artifact_batch_visits_every_object_once(monkeypatch):
    """Scale control with stubbed custody, not a real plan/producer positive."""
    assert MAX_ARTIFACTS == 4096
    objects = [
        dict(key=f"object/{i}", version_id=None, etag='"same"')
        for i in range(MAX_ARTIFACTS)
    ]
    request = dict(
        plan=dict(
            artifacts=[dict(key=o["key"]) for o in objects],
            attempt_id="attempt",
            encryption=dict(format="none"),
        ),
        plan_sha256="digest",
    )
    receipt = dict(objects=objects)
    intent = dict(capacity_id=str(uuid.uuid4()))
    row = SimpleNamespace(
        id="reservation", receipt_verification_intent=intent, prepared_receipt=None
    )
    identity = SimpleNamespace(org_id="org", agent_id="agent")
    heads, boundaries, committed = [], [], []
    closed = []

    class Session:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def connection(self, **kwargs):
            pass

        def commit(self):
            committed.append(row.prepared_receipt)

    monkeypatch.setattr(service, "TenantContext", lambda _: nullcontext())
    monkeypatch.setattr(
        service, "_read", lambda *a: (request, receipt, "receipt-digest", None)
    )
    monkeypatch.setattr(
        service, "admit_intent", lambda *a: dict(disposition="created", intent=intent)
    )

    def boundary(*args, require_start_window):
        boundaries.append(require_start_window)
        return row, request

    monkeypatch.setattr(service, "_boundary", boundary)
    monkeypatch.setattr(
        service,
        "_client",
        lambda *a: SimpleNamespace(close=lambda: closed.append(True)),
    )
    monkeypatch.setattr(service, "lock_original_authority", lambda *a, **k: None)
    monkeypatch.setattr(service, "validate_identity", lambda *a: None)
    monkeypatch.setattr(service, "validate_reserved_capacity", lambda *a: None)
    monkeypatch.setattr(service, "_claim", lambda *a: (row, request))

    def verify(claim, expected, partial, client):
        assert expected is request and len(partial["objects"]) == 1
        key = partial["objects"][0]["key"]
        heads.append(key)
        return [dict(key=key, assurance="provider_checksum_verified")]

    monkeypatch.setattr(service, "verify", verify)
    response = service.verify_callback_receipt(Session, identity, "backup", receipt)
    assert heads == [o["key"] for o in objects]
    assert len(set(heads)) == MAX_ARTIFACTS
    assert boundaries == [True] + [False] * MAX_ARTIFACTS
    assert len(committed) == 1 and committed[0]["response"] == response
    assert closed == [True] and response["accepted"]
