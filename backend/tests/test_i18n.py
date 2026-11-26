"""Validate i18n locale files: key parity, non-empty values, metadata, placeholders, plurals."""

import json
import re
from pathlib import Path

import pytest

FRONTEND = Path(__file__).resolve().parents[2] / "frontend"
LOCALES_DIR = FRONTEND / "public" / "locales"
EN_PATH = LOCALES_DIR / "en.json"
HE_PATH = LOCALES_DIR / "he.json"

PLACEHOLDER_RE = re.compile(r"\{\{(\w+)\}\}")


def load_locale(path: Path) -> dict:
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def flatten_keys(data: dict, prefix: str = "") -> dict:
    """Flatten nested dict to dot-notation keys, skipping _metadata."""
    result = {}
    for key, value in data.items():
        if key == "_metadata":
            continue
        full_key = f"{prefix}.{key}" if prefix else key
        if isinstance(value, dict):
            result.update(flatten_keys(value, full_key))
        else:
            result[full_key] = value
    return result


@pytest.fixture(scope="module")
def en():
    return load_locale(EN_PATH)


@pytest.fixture(scope="module")
def he():
    return load_locale(HE_PATH)


@pytest.fixture(scope="module")
def en_flat(en):
    return flatten_keys(en)


@pytest.fixture(scope="module")
def he_flat(he):
    return flatten_keys(he)


class TestLocaleFiles:
    def test_en_json_parses(self):
        data = load_locale(EN_PATH)
        assert isinstance(data, dict)

    def test_he_json_parses(self):
        data = load_locale(HE_PATH)
        assert isinstance(data, dict)

    def test_en_has_metadata(self, en):
        assert "_metadata" in en
        meta = en["_metadata"]
        assert meta["locale"] == "en"
        assert meta["name"] == "English"
        assert meta["direction"] == "ltr"

    def test_he_has_metadata(self, he):
        assert "_metadata" in he
        meta = he["_metadata"]
        assert meta["locale"] == "he"
        assert meta["direction"] == "rtl"


class TestKeyParity:
    def test_en_keys_exist_in_he(self, en_flat, he_flat):
        missing = set(en_flat.keys()) - set(he_flat.keys())
        assert (
            not missing
        ), f"Keys in en.json but missing from he.json: {sorted(missing)}"

    def test_he_keys_exist_in_en(self, en_flat, he_flat):
        extra = set(he_flat.keys()) - set(en_flat.keys())
        assert not extra, f"Keys in he.json but missing from en.json: {sorted(extra)}"


class TestValues:
    def test_en_no_empty_values(self, en_flat):
        empty = [
            k for k, v in en_flat.items() if not isinstance(v, str) or not v.strip()
        ]
        assert not empty, f"Empty values in en.json: {empty}"

    def test_he_no_empty_values(self, he_flat):
        empty = [
            k for k, v in he_flat.items() if not isinstance(v, str) or not v.strip()
        ]
        assert not empty, f"Empty values in he.json: {empty}"

    def test_all_values_are_strings(self, en_flat, he_flat):
        en_bad = [k for k, v in en_flat.items() if not isinstance(v, str)]
        he_bad = [k for k, v in he_flat.items() if not isinstance(v, str)]
        assert not en_bad, f"Non-string values in en.json: {en_bad}"
        assert not he_bad, f"Non-string values in he.json: {he_bad}"


class TestPlaceholders:
    def test_placeholder_parity(self, en_flat, he_flat):
        """Each key's {{var}} placeholders must match between locales."""
        mismatches = []
        for key in en_flat:
            if key not in he_flat:
                continue
            en_vars = set(PLACEHOLDER_RE.findall(en_flat[key]))
            he_vars = set(PLACEHOLDER_RE.findall(he_flat[key]))
            if en_vars != he_vars:
                mismatches.append(f"{key}: en={en_vars}, he={he_vars}")
        assert not mismatches, "Placeholder mismatches:\n" + "\n".join(mismatches)


class TestPlurals:
    def test_plural_pairs(self, en_flat):
        """Keys ending in _one must have a matching _other and vice versa."""
        unpaired = []
        for key in en_flat:
            if key.endswith("_one") and key.replace("_one", "_other") not in en_flat:
                unpaired.append(f"{key} missing _other")
            if key.endswith("_other") and key.replace("_other", "_one") not in en_flat:
                unpaired.append(f"{key} missing _one")
        assert not unpaired, f"Unpaired plural keys in en.json: {unpaired}"

    def test_plural_pairs_he(self, he_flat):
        """Hebrew plural pairs must also match."""
        unpaired = []
        for key in he_flat:
            if key.endswith("_one") and key.replace("_one", "_other") not in he_flat:
                unpaired.append(f"{key} missing _other")
            if key.endswith("_other") and key.replace("_other", "_one") not in he_flat:
                unpaired.append(f"{key} missing _one")
        assert not unpaired, f"Unpaired plural keys in he.json: {unpaired}"


T_CALL_RE = re.compile(r"""(?:window\.t|(?<!\w)t)\(\s*['"]([^'"]+)['"]\s*[,)]""")


def extract_t_keys(js_dir):
    """Extract literal translation key references from source JavaScript."""
    return {
        match.group(1)
        for js_file in js_dir.rglob("*.js")
        for match in T_CALL_RE.finditer(js_file.read_text(encoding="utf-8"))
    }


class TestKeyUsage:
    """Validate that all t() calls in frontend JS reference existing locale keys."""

    def test_frontend_keys_exist_in_en(self, en_flat):
        """Every t('key') call in frontend JS must have a matching key in en.json."""
        used_keys = extract_t_keys(FRONTEND / "src")
        missing = set()
        for key in used_keys:
            # Key exists directly, or has _one/_other plural variants
            if key not in en_flat and f"{key}_one" not in en_flat:
                missing.add(key)
        assert (
            not missing
        ), "i18n keys used in frontend but missing from en.json:\n" + "\n".join(
            f"  - {k}" for k in sorted(missing)
        )

    def test_frontend_keys_exist_in_he(self, he_flat):
        """Every t('key') call in frontend JS must have a matching key in he.json."""
        used_keys = extract_t_keys(FRONTEND / "src")
        missing = set()
        for key in used_keys:
            if key not in he_flat and f"{key}_one" not in he_flat:
                missing.add(key)
        assert (
            not missing
        ), "i18n keys used in frontend but missing from he.json:\n" + "\n".join(
            f"  - {k}" for k in sorted(missing)
        )


class TestStructure:
    def test_top_level_sections(self, en):
        """Verify expected top-level sections exist."""
        expected = {
            "common",
            "nav",
            "login",
            "profile",
            "dashboard",
            "vms",
            "backup_modal",
            "backups",
            "restore_modal",
            "restores",
            "schedules",
            "agents",
            "groups",
            "users",
            "settings",
            "health",
            "reports",
            "activity",
            "notifications",
            "verification",
            "status",
            "time",
            "compat_banner",
        }
        actual = {k for k in en.keys() if k != "_metadata"}
        missing = expected - actual
        assert not missing, f"Missing top-level sections in en.json: {missing}"

    def test_he_matches_en_sections(self, en, he):
        en_sections = {k for k in en.keys() if k != "_metadata"}
        he_sections = {k for k in he.keys() if k != "_metadata"}
        assert en_sections == he_sections, (
            f"Section mismatch. Only in en: {en_sections - he_sections}, "
            f"Only in he: {he_sections - en_sections}"
        )
