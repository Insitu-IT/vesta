"""Tests for OIDC role mapping (core.oidc_service.OIDCService.map_role).

Focus: role_claim resolution, including Keycloak's nested realm_access.roles
token shape, which a flat claims.get() cannot read.
"""

from core.oidc_service import OIDCService
import time
import pytest


def _svc(**overrides):
    """Build a configured OIDCService with sane role-mapping defaults."""
    config = {
        "enabled": True,
        "issuer": "https://kc.example/realms/r",
        "client_id": "vnbui",
        "client_secret": "secret",
        "scopes": "openid profile email",
        "role_claim": "",
        "admin_values": "",
        "operator_values": "",
        "default_role": "viewer",
    }
    config.update(overrides)
    svc = OIDCService()
    svc.configure(config)
    return svc


def test_no_role_claim_returns_default():
    svc = _svc(role_claim="", default_role="operator")
    assert svc.map_role({"realm_access": {"roles": ["anything"]}}) == "operator"


@pytest.mark.parametrize("default", ["admin", "unknown", "", None])
@pytest.mark.parametrize("groups", [[], ["admin"]])
def test_unsupported_persisted_default_fails_closed(default, groups):
    svc = _svc(default_role=default, role_claim="groups", admin_values="admin")
    with pytest.raises(ValueError, match="Invalid OIDC default role"):
        svc.map_role({"groups": groups})


def test_nested_realm_access_roles_admin():
    # Keycloak default token shape: realm roles nested under realm_access.roles.
    svc = _svc(role_claim="realm_access.roles", admin_values="vnbui-admin")
    claims = {"realm_access": {"roles": ["offline_access", "vnbui-admin"]}}
    assert svc.map_role(claims) == "admin"


def test_nested_realm_access_roles_operator():
    svc = _svc(role_claim="realm_access.roles", operator_values="vnbui-operator")
    assert svc.map_role({"realm_access": {"roles": ["vnbui-operator"]}}) == "operator"


def test_nested_missing_falls_back_to_default():
    svc = _svc(
        role_claim="realm_access.roles",
        admin_values="vnbui-admin",
        default_role="viewer",
    )
    # No realm_access claim at all -> default.
    assert svc.map_role({"sub": "u1"}) == "viewer"
    # realm_access present but no roles key -> default.
    assert svc.map_role({"realm_access": {}}) == "viewer"


def test_flat_claim_still_works():
    svc = _svc(role_claim="groups", operator_values="ops")
    assert svc.map_role({"groups": ["ops", "eng"]}) == "operator"


@pytest.mark.parametrize("claim", ["groups", "nested.groups"])
@pytest.mark.parametrize(
    "groups,expected", [(["admin"], "admin"), (["operator"], "viewer"), ([], "viewer")]
)
def test_supported_installation_groups_contract(claim, groups, expected):
    svc = _svc(
        role_claim=claim,
        admin_values="admin",
        operator_values="",
        default_role="viewer",
    )
    claims = {"groups": groups} if claim == "groups" else {"nested": {"groups": groups}}
    assert svc.map_role(claims) == expected


@pytest.mark.parametrize(
    "claim,claims",
    [
        ("groups", {"groups": ["fixture-operator"]}),
        ("nested.groups", {"nested": {"groups": ["fixture-operator"]}}),
    ],
)
def test_groups_mapping_retains_local_pin(monkeypatch, claim, claims):
    import asyncio
    from types import SimpleNamespace
    from unittest.mock import MagicMock
    from core import tenant_context

    monkeypatch.setattr(tenant_context, "resolved_organization", lambda: "test-org")
    svc = _svc(role_claim=claim, operator_values="fixture-operator")
    assert svc.map_role(claims) == "operator"
    db = MagicMock()
    db.get.return_value = SimpleNamespace(enabled=True)
    user = SimpleNamespace(
        is_active=True,
        auth_source="oidc",
        role_source="local",
        role="viewer",
        is_platform_admin=False,
    )
    db.query.return_value.filter.return_value.one_or_none.return_value = user
    result, created = asyncio.run(
        svc.get_or_create_user(
            {
                "sub": "fixture-sub",
                "issuer": svc._config["issuer"],
                "claims": claims,
            },
            db,
            commit=False,
        )
    )
    assert result is user and not created
    assert user.role == "viewer" and user.is_platform_admin is False
    db.flush.assert_called_once()
    db.commit.assert_not_called()


def test_flat_claim_with_literal_dotted_name_wins():
    # An IdP that emits a single claim literally named "a.b" (with a dot).
    svc = _svc(role_claim="a.b", admin_values="root")
    assert svc.map_role({"a.b": ["root"]}) == "admin"


def test_string_claim_value_coerced_to_list():
    svc = _svc(role_claim="role", admin_values="vnbui-admin")
    assert svc.map_role({"role": "vnbui-admin"}) == "admin"


def test_admin_precedence_over_operator():
    svc = _svc(
        role_claim="realm_access.roles",
        admin_values="vnbui-admin",
        operator_values="vnbui-operator",
    )
    claims = {"realm_access": {"roles": ["vnbui-operator", "vnbui-admin"]}}
    assert svc.map_role(claims) == "admin"


def test_no_match_returns_default():
    svc = _svc(
        role_claim="realm_access.roles",
        admin_values="vnbui-admin",
        default_role="viewer",
    )
    assert svc.map_role({"realm_access": {"roles": ["random"]}}) == "viewer"


def test_resolve_claim_helper():
    assert OIDCService._resolve_claim({"a": {"b": {"c": 1}}}, "a.b.c") == 1
    assert OIDCService._resolve_claim({"a": {"b": 1}}, "a.x") is None
    assert OIDCService._resolve_claim({"flat": 5}, "flat") == 5
    # Literal dotted key wins over traversal.
    assert OIDCService._resolve_claim({"a.b": 9}, "a.b") == 9


@pytest.mark.parametrize(
    "override",
    [
        {"iss": "https://other.invalid"},
        {"aud": "other-client"},
        {"aud": ["vnbui", "other-client"]},
        {"azp": "other-client"},
        {"exp": 0},
        {"exp": True},
        {"exp": None},
        {"sub": ""},
        {"sub": 123},
        {"sub": "   "},
        {"exp": float("nan")},
        {"exp": float("inf")},
    ],
)
def test_oidc_code_exchange_rejects_wrong_identity_binding(override):
    claims = {
        "iss": "https://kc.example/realms/r",
        "aud": "vnbui",
        "sub": "subject",
        "exp": time.time() + 300,
    }
    _svc().validate_token_claims(claims)
    with pytest.raises(ValueError):
        _svc().validate_token_claims({**claims, **override})


def test_oidc_multiple_audiences_require_our_authorized_party():
    _svc().validate_token_claims(
        {
            "iss": "https://kc.example/realms/r",
            "aud": ["vnbui", "other-client"],
            "azp": "vnbui",
            "sub": "subject",
            "exp": time.time() + 300,
        }
    )


@pytest.mark.parametrize("value", [123, True, {"admin": True}, ["admin", 1]])
def test_malformed_role_claim_is_refused(value):
    with pytest.raises(ValueError):
        _svc(role_claim="roles", admin_values="admin").map_role({"roles": value})


@pytest.mark.parametrize("role", ["platform_admin", "superuser", "", None])
def test_unknown_default_role_cannot_become_authority(role):
    with pytest.raises(ValueError):
        _svc(default_role=role).map_role({})


@pytest.mark.asyncio
@pytest.mark.parametrize("outcome", ["valid", "expired", "wrong-issuer", "refused"])
async def test_code_exchange_uses_verified_transport_and_sanitizes_failure(
    monkeypatch, caplog, outcome
):
    from types import SimpleNamespace
    from unittest.mock import AsyncMock, MagicMock
    import jwt
    import httpx

    service = _svc()
    service._discovery_cache = {"token_endpoint": "https://kc.example/token"}
    claims = {
        "iss": service._config["issuer"],
        "aud": "vnbui",
        "sub": "subject",
        "exp": time.time() + 60,
    }
    if outcome == "expired":
        claims["exp"] = 0
    if outcome == "wrong-issuer":
        claims["iss"] = "https://other.invalid"
    encoded = jwt.encode(claims, "synthetic-fixture-key", algorithm="HS256")
    transport = MagicMock()
    transport.__aenter__ = AsyncMock(return_value=transport)
    transport.__aexit__ = AsyncMock(return_value=None)
    transport.post = AsyncMock(
        return_value=SimpleNamespace(
            status_code=400 if outcome == "refused" else 200,
            text="private-provider-body",
            json=lambda: {"id_token": encoded},
        )
    )
    factory = MagicMock(return_value=transport)
    monkeypatch.setattr(httpx, "AsyncClient", factory)
    data, error = await service.handle_callback(
        "fixture-code", "https://app.invalid/callback", "fixture-verifier"
    )
    assert factory.call_args.kwargs == {"timeout": 10.0}  # default TLS verification
    sent = transport.post.call_args.kwargs["data"]
    assert sent["code_verifier"] == "fixture-verifier"
    assert sent["client_id"] == "vnbui"
    assert sent["redirect_uri"] == "https://app.invalid/callback"
    assert (data is not None) == (outcome == "valid")
    assert (error is None) == (outcome == "valid")
    for private in (
        encoded,
        "fixture-code",
        "fixture-verifier",
        "private-provider-body",
    ):
        assert private not in caplog.text
        assert private not in (error or "")
