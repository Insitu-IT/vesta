"""The session signing key must come from the environment, or nothing works.

Origin (#51): ``deps.JWT_SECRET`` fell back to the literal
``"change-this-secret-key-in-production"`` when the environment did not supply
one. On OKD that fallback was unreachable — the manifest injects a non-optional
secret — but the guarantee lived in a different repository, and the OSS/compose
path shipped the literal as a working value. A default signing key in published
source is a key held by everyone who can read the repo.

Origin (#52): ``core/tenant_context`` imported ``JWT_SECRET`` from ``config``,
which never defined it, inside ``except Exception``. The multi-tenancy token path
could not succeed and said so only in a warning log.

Both are one question — *which module owns the signing key, and what happens when
it is absent* — so they are tested together.

Note on why these tests exist at all: when the fallback was removed, the whole
342-test backend suite still passed. Nothing in it exercised token creation or
verification, so a green suite said nothing about the change. That is the gap
this file closes.
"""

import pytest
import jwt
from fastapi import HTTPException


@pytest.fixture
def deps_module():
    """Use the same dependency functions already bound by FastAPI routers."""
    import deps

    return deps


def test_missing_secret_raises_rather_than_defaulting(deps_module, monkeypatch):
    """The defect itself. Absence must stop the process, not pick a value."""
    monkeypatch.delenv("JWT_SECRET", raising=False)

    with pytest.raises(RuntimeError) as exc:
        deps_module.jwt_secret()

    assert "JWT_SECRET is not set" in str(exc.value)
    # The message must be actionable: someone hitting this at 3am needs the fix,
    # not just the diagnosis.
    assert "openssl rand" in str(exc.value)


def test_empty_secret_is_treated_as_missing(deps_module, monkeypatch):
    """JWT_SECRET="" is the shape a half-configured deployment actually has.

    An empty string is falsy but present, so a naive `os.getenv("JWT_SECRET")`
    check that only tests for None would sail past it and sign tokens with "".
    """
    monkeypatch.setenv("JWT_SECRET", "")

    with pytest.raises(RuntimeError):
        deps_module.jwt_secret()


def test_configured_secret_is_returned(deps_module, monkeypatch):
    """Positive control.

    Without this, every assertion above passes against a function that raises
    unconditionally — fail-closed in the useless sense.
    """
    monkeypatch.setenv("JWT_SECRET", "a-real-secret")
    assert deps_module.jwt_secret() == "a-real-secret"


def test_no_literal_default_survives_in_the_source(deps_module):
    """Pinned by absence, because this is the thing that must never come back.

    The behavioural tests above would all still pass if someone reintroduced a
    default under a different name, so long as the env var kept winning.
    """
    import inspect

    source = inspect.getsource(deps_module)
    assert "change-this-secret-key-in-production" not in source


def test_token_creation_fails_loudly_when_unconfigured(deps_module, monkeypatch):
    """The integration-level consequence: no silent signing with a junk key."""
    monkeypatch.delenv("JWT_SECRET", raising=False)

    with pytest.raises(RuntimeError):
        deps_module.create_access_token({"sub": "someone"})


def test_round_trip_with_a_configured_secret(deps_module, monkeypatch):
    """A token minted with the configured key verifies with it."""
    monkeypatch.setenv("JWT_SECRET", "round-trip-secret")

    token = deps_module.create_access_token({"sub": "alice"})
    claims = jwt.decode(
        token, "round-trip-secret", algorithms=[deps_module.JWT_ALGORITHM]
    )
    assert claims["sub"] == "alice"


def test_a_token_signed_with_another_key_does_not_verify(deps_module, monkeypatch):
    """Guards against the accessor silently returning a constant.

    If jwt_secret() ever stopped reading the environment, the round-trip test
    above would still pass — both sides would use the same wrong key.
    """
    monkeypatch.setenv("JWT_SECRET", "the-real-key")
    token = deps_module.create_access_token({"sub": "bob"})

    with pytest.raises(Exception):
        jwt.decode(token, "a-different-key", algorithms=[deps_module.JWT_ALGORITHM])


def test_unconfigured_token_algorithm_never_reaches_user_lookup(
    deps_module, monkeypatch
):
    """A valid MAC under the same key cannot widen the verifier's algorithm."""
    monkeypatch.setenv("JWT_SECRET", "test-secret-with-at-least-thirty-two-bytes")
    monkeypatch.setattr(deps_module, "JWT_ALGORITHM", "HS256")
    token = jwt.encode(
        {"sub": "alice", "user_id": "user-1"},
        deps_module.jwt_secret(),
        algorithm="HS384",
    )

    class UnreachableDatabase:
        def query(self, *args):
            raise AssertionError("Untrusted token reached user lookup")

    with pytest.raises(HTTPException) as exc:
        deps_module.get_current_user(token, UnreachableDatabase())
    assert exc.value.status_code == 401


def test_tenant_context_can_actually_read_a_token(monkeypatch):
    """Regression pin for #52.

    extract_org_from_jwt imported JWT_SECRET from `config`, which does not define
    it. The ImportError was swallowed by `except Exception`, so the function
    always returned "default" — indistinguishable from a token that legitimately
    carried no org. This asserts the non-default path is reachable at all.
    """
    monkeypatch.setenv("JWT_SECRET", "tenant-secret")

    import deps
    from core.tenant_context import extract_org_from_jwt

    org_id = "687d2141-0bc5-4565-9fb7-5f8ea9ec1f72"
    token = jwt.encode(
        {"org_id": org_id, "sub": "u1"}, "tenant-secret", algorithm=deps.JWT_ALGORITHM
    )

    assert extract_org_from_jwt(token) == org_id, (
        "extract_org_from_jwt returned the fallback for a token that carries an "
        "org — the import it depends on is broken again and the failure is being "
        "swallowed"
    )


def test_tenant_context_rejects_junk_instead_of_selecting_default(monkeypatch):
    """Malformed credentials carry no tenant identity; HTTP middleware maps to 401."""
    monkeypatch.setenv("JWT_SECRET", "tenant-secret")

    from core.tenant_context import extract_org_from_jwt

    with pytest.raises(jwt.InvalidTokenError):
        extract_org_from_jwt("not-a-jwt")
