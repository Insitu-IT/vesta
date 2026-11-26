import json
import os
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace

import pytest
from fastapi import FastAPI

from core import commercial
from core.licensing import FeatureFlags, License
from core.installed_profile import InstalledProfile
from routers import public


class AdvisoryCertificate:
    def __init__(self, state):
        self.state = state

    def has_feature(self, feature):
        raise AssertionError("Certificate must not select installed capabilities")


def test_configured_module_is_not_reported_until_implementation_loads(monkeypatch):
    flags = FeatureFlags(
        AdvisoryCertificate("absent"),
        InstalledProfile(
            "commercial", "multi_organization", frozenset({"multi_tenancy"})
        ),
    )
    app = FastAPI()

    assert flags.multi_tenancy is False

    monkeypatch.setattr(
        commercial,
        "COMMERCIAL_MODULES",
        (commercial.CommercialModule("multi_tenancy", "test.module", "init"),),
    )
    monkeypatch.setattr(
        commercial,
        "import_module",
        lambda _path: SimpleNamespace(init=lambda _app: None),
    )

    assert commercial.load_commercial_modules(app, flags) == ["multi_tenancy"]
    assert flags.multi_tenancy is True


def test_configured_missing_module_fails_startup(monkeypatch):
    flags = FeatureFlags(
        AdvisoryCertificate("absent"),
        InstalledProfile(
            "commercial", "single_organization", frozenset({"billing_api"})
        ),
    )
    app = FastAPI()
    monkeypatch.setattr(
        commercial,
        "COMMERCIAL_MODULES",
        (commercial.CommercialModule("billing_api", "missing.module", "init"),),
    )

    def missing(_path):
        raise ModuleNotFoundError("missing.module")

    monkeypatch.setattr(commercial, "import_module", missing)

    with pytest.raises(commercial.CommercialModuleLoadError, match="billing_api"):
        commercial.load_commercial_modules(app, flags)
    assert flags.billing_api is False


@pytest.mark.asyncio
async def test_public_capabilities_report_loaded_and_configured_modules(monkeypatch):
    flags = FeatureFlags(
        AdvisoryCertificate("absent"),
        InstalledProfile(
            "commercial", "multi_organization", frozenset({"multi_tenancy"})
        ),
    )
    monkeypatch.setattr(public, "features", flags)

    response = await public.get_features()
    assert response["tier"] == "commercial"
    assert response["configured_modules"] == ["multi_tenancy"]
    assert response["loaded_modules"] == []
    assert response["flags"]["multi_tenancy"] is False

    flags.activate("multi_tenancy")
    response = await public.get_features()
    assert response["flags"]["multi_tenancy"] is True


def test_community_loader_never_resolves_private_modules(monkeypatch):
    def unexpected_import(path):
        pytest.fail(f"Community tried to resolve {path}")

    monkeypatch.setattr(commercial, "import_module", unexpected_import)
    flags = FeatureFlags(AdvisoryCertificate("valid"), InstalledProfile())
    assert commercial.load_commercial_modules(FastAPI(), flags) == []
    assert flags.get_loaded_modules() == []


@pytest.mark.parametrize("edition", ["community", "commercial"])
def test_installed_capabilities_ignore_unreadable_legacy_input(tmp_path, edition):
    root = Path(__file__).resolve().parents[2]
    legacy = tmp_path / "legacy-license"
    modules = ["billing_api"] if edition == "commercial" else []
    env = {
        **os.environ,
        "PYTHONPATH": os.pathsep.join(
            (str(root / "backend"), os.environ.get("PYTHONPATH", ""))
        ),
        "LICENSE_FILE": str(legacy),
        "VNBUI_ARTIFACT_EDITION": edition,
        "VNBUI_EDITION": edition,
        "VNBUI_AUTH_MODE": "single_organization",
        "VNBUI_ENABLED_MODULES": json.dumps(modules),
    }
    check = """
import json

from core.licensing import FeatureFlags, features

for flags in (features, FeatureFlags()):
    for module in flags.profile.enabled_modules:
        flags.activate(module)
    print(json.dumps({
        'profile': flags.profile.public(),
        'features': flags.get_available_features(),
        'loaded': flags.get_loaded_modules(),
    }))
"""

    def read_capabilities():
        result = subprocess.run(
            [sys.executable, "-c", check],
            cwd=root,
            env=env,
            text=True,
            capture_output=True,
            timeout=5,
            check=True,
        )
        return [json.loads(line) for line in result.stdout.splitlines()]

    absent = read_capabilities()
    legacy.write_text("{")
    assert read_capabilities() == absent
    legacy.unlink()
    os.mkfifo(legacy, 0o600)
    assert read_capabilities() == absent
    assert len(absent) == 2
    for observed in absent:
        assert observed["profile"]["edition"] == edition
        assert observed["loaded"] == modules
        assert {"backup_restore", "scheduling", "client_encryption"} <= set(
            observed["features"]
        )
        assert ("billing_api" in observed["features"]) is bool(modules)


def test_explicit_legacy_license_reader_remains_available(monkeypatch, tmp_path):
    legacy = tmp_path / "legacy-license.json"
    legacy.write_text(json.dumps({"tier": "msp"}))
    monkeypatch.setenv("LICENSE_FILE", str(legacy))
    assert License().tier == "msp"
    assert FeatureFlags().license.tier == "oss"
