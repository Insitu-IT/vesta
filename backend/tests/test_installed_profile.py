"""Installed capabilities and credential scope must survive advisory license changes."""

from types import SimpleNamespace

import pytest

from core.installed_profile import InstalledProfile
from core.licensing import FeatureFlags


class AdvisoryCertificate:
    def __init__(self, tier, state):
        self.tier, self.state = tier, state

    def has_feature(self, feature):
        raise AssertionError("certificate must not select installed capabilities")


def commercial_profile():
    return InstalledProfile(
        "commercial",
        "multi_organization",
        frozenset({"multi_tenancy", "billing_api", "white_labeling"}),
    )


def test_old_community_environment_preserves_single_organization():
    assert InstalledProfile.from_environment({}) == InstalledProfile()


def test_vesta_profile_settings_take_precedence_over_legacy_aliases():
    env = {
        "VESTA_ARTIFACT_EDITION": "community",
        "VNBUI_ARTIFACT_EDITION": "commercial",
        "VESTA_EDITION": "community",
        "VNBUI_EDITION": "commercial",
        "VESTA_AUTH_MODE": "single_organization",
        "VNBUI_AUTH_MODE": "multi_organization",
        "VESTA_ENABLED_MODULES": "[]",
        "VNBUI_ENABLED_MODULES": '["multi_tenancy"]',
    }
    assert InstalledProfile.from_environment(env) == InstalledProfile()
    env["VESTA_EDITION"] = ""
    with pytest.raises(ValueError):
        InstalledProfile.from_environment(env)


def test_persistent_encryption_key_rejects_different_alias_values(monkeypatch):
    from core.vesta_environment import vesta_encryption_key

    monkeypatch.delenv("VESTA_ENCRYPTION_KEY", raising=False)
    monkeypatch.setenv("VNBUI_ENCRYPTION_KEY", "legacy-test-key")
    assert vesta_encryption_key() == "legacy-test-key"
    monkeypatch.setenv("VESTA_ENCRYPTION_KEY", "legacy-test-key")
    assert vesta_encryption_key() == "legacy-test-key"
    monkeypatch.setenv("VESTA_ENCRYPTION_KEY", "current-test-key")
    with pytest.raises(ValueError, match="VESTA_ENCRYPTION_KEY conflicts") as exc:
        vesta_encryption_key()
    assert "legacy-test-key" not in str(exc.value)
    assert "current-test-key" not in str(exc.value)


@pytest.mark.parametrize("state", ["paid", "expired", "invalid", "missing"])
@pytest.mark.parametrize("commercial", [False, True])
def test_certificate_import_never_changes_profile_or_loaded_modules(
    monkeypatch, state, commercial
):
    from core import licensing, tenant_context

    profile = commercial_profile() if commercial else InstalledProfile()
    flags = FeatureFlags(AdvisoryCertificate("oss", "missing"), profile)
    for module in profile.enabled_modules:
        flags.activate(module)
    monkeypatch.setattr(licensing, "features", flags)
    before = flags.get_available_features()
    flags.configure_license(AdvisoryCertificate("enterprise", state))
    assert flags.profile is profile
    assert flags.get_available_features() == before
    assert tenant_context.commercial_mode() is commercial
    assert flags.backup_restore and flags.scheduling and flags.basic_oidc
    assert flags.multi_tenancy is commercial
    assert flags.billing_api is commercial and flags.white_labeling is commercial
    assert flags.get_edition_name() == (
        "Commercial Edition" if commercial else "Community Edition"
    )


@pytest.mark.parametrize(
    "patch",
    [
        {"VNBUI_EDITION": "commercial"},
        {"VNBUI_ARTIFACT_EDITION": "commercial"},
        {"VNBUI_AUTH_MODE": "multi_organization"},
        {"VNBUI_ENABLED_MODULES": '["billing_api"]'},
        {"VNBUI_ENABLED_MODULES": '["unknown"]'},
        {"VNBUI_ENABLED_MODULES": '["billing_api","billing_api"]'},
        {"VNBUI_ENABLED_MODULES": "[true]"},
        {"VNBUI_ENABLED_MODULES": "{}"},
        {"VNBUI_ENABLED_MODULES": "broken"},
    ],
)
def test_invalid_or_implicit_profile_is_configuration_error(patch):
    with pytest.raises(ValueError):
        InstalledProfile.from_environment(patch)


def test_explicit_commercial_profile_without_certificate():
    profile = InstalledProfile.from_environment(
        {
            "VNBUI_ARTIFACT_EDITION": "commercial",
            "VNBUI_EDITION": "commercial",
            "VNBUI_AUTH_MODE": "multi_organization",
            "VNBUI_ENABLED_MODULES": '["multi_tenancy","billing_api"]',
        }
    )
    assert profile.edition == "commercial" and profile.auth_mode == "multi_organization"


@pytest.mark.parametrize("profile", [InstalledProfile(), commercial_profile()])
@pytest.mark.parametrize("oidc", [False, True])
def test_bootstrap_contains_only_installed_login_information(
    monkeypatch, profile, oidc
):
    from routers import public

    flags = FeatureFlags(AdvisoryCertificate("enterprise", "expired"), profile)
    monkeypatch.setattr(public, "features", flags)
    monkeypatch.setattr(public, "_local_oidc_login_available", lambda db: oidc)
    assert public.get_bootstrap(object()) == {
        "schema_version": 1,
        "edition": profile.edition,
        "auth_mode": profile.auth_mode,
        "login_methods": {"password": True, "oidc": oidc},
    }


@pytest.mark.parametrize(
    "enabled,binding_exists,want",
    [(False, True, False), (True, False, False), (True, True, True)],
)
def test_bootstrap_oidc_reads_only_local_configuration(
    monkeypatch, enabled, binding_exists, want
):
    from core.settings_service import SettingsService
    from models import OrganizationDefault
    from routers import public

    monkeypatch.setattr(public, "features", FeatureFlags(profile=InstalledProfile()))
    monkeypatch.setattr(
        SettingsService,
        "get_oidc_config",
        lambda self: {"enabled": True} if enabled else None,
    )

    def get(model, key):
        if model is OrganizationDefault:
            return SimpleNamespace(org_id="persisted-default")
        return SimpleNamespace(enabled=True) if binding_exists else None

    assert public._local_oidc_login_available(SimpleNamespace(get=get)) is want
