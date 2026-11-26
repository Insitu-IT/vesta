"""
v3.0 Unified Settings Service with Vault + UI support.

Credential resolution order:
1. UI-entered value (encrypted in secrets_v3 table)
2. Environment variable (ENV seeds initial config, UI overrides)
3. Default value

Usage:
    from core.settings_service import SettingsService

    svc = SettingsService(db)
    storage_type = svc.get('storage.type')
    s3_key = svc.get_secret('storage.s3.access_key')
"""

import os
import json
import logging
from typing import Optional, Any, Dict
from datetime import datetime
from cryptography.fernet import Fernet, InvalidToken
from sqlalchemy.orm import Session
from core.vesta_environment import vesta_encryption_key
from core.installation_config import read_configuration

logger = logging.getLogger(__name__)

# Encryption key from environment (set via ESO or manually)
# Generate with: python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
ENCRYPTION_KEY = vesta_encryption_key()
_fernet: Optional[Fernet] = None

if ENCRYPTION_KEY:
    try:
        _fernet = Fernet(
            ENCRYPTION_KEY.encode()
            if isinstance(ENCRYPTION_KEY, str)
            else ENCRYPTION_KEY
        )
    except Exception as e:
        logger.error(f"Invalid VESTA_ENCRYPTION_KEY: {e}")


class SettingsService:
    """Manages settings from multiple sources with encrypted secret storage."""

    # Setting definitions with defaults and types
    DEFINITIONS: Dict[str, Dict[str, Any]] = {
        # No default admission: the installation administrator chooses capacity.
        "backup.capacity_admission": {"default": None, "type": "json"},
        # Separate from maintenance: already reserved backups may drain.
        "backup.admission_pause": {"default": None, "type": "json"},
        # Storage settings
        "storage.type": {"default": "s3", "type": "string"},
        "storage.path": {"default": "/var/lib/vnbui/backups", "type": "string"},
        "storage.s3.endpoint": {"default": "", "type": "string"},
        "storage.s3.bucket": {"default": "", "type": "string"},
        "storage.s3.region": {"default": "us-east-1", "type": "string"},
        "storage.s3.prefix": {
            "default": "backups",
            "type": "string",
        },  # S3 key prefix (no trailing slash)
        "storage.s3.delete_local": {"default": False, "type": "bool"},
        # PKI / mTLS settings
        "pki.ca_cert": {"default": "", "type": "string"},
        "pki.require_mtls": {"default": False, "type": "bool"},
        # OIDC settings
        "oidc.enabled": {"default": False, "type": "bool"},
        "oidc.issuer": {"default": "", "type": "string"},
        "oidc.client_id": {"default": "", "type": "string"},
        "oidc.scopes": {"default": "openid profile email", "type": "string"},
        "oidc.role_claim": {"default": "", "type": "string"},
        "oidc.admin_values": {"default": "", "type": "string"},
        "oidc.operator_values": {"default": "", "type": "string"},
        "oidc.default_role": {"default": "viewer", "type": "string"},
    }

    # Secret definitions (credentials) - mapped to env vars and vault paths
    SECRET_DEFINITIONS: Dict[str, Dict[str, str]] = {
        "storage.s3.access_key": {
            "env": "S3_ACCESS_KEY",
        },
        "storage.s3.secret_key": {
            "env": "S3_SECRET_KEY",
        },
        "oidc.client_secret": {
            "env": "OIDC_CLIENT_SECRET",
        },
        "pki.ca_key": {"env": "TLS_CA_KEY_PEM"},
    }

    def __init__(self, db: Session, *, secret_snapshot=None):
        self.db = db
        self._secret_snapshot = secret_snapshot

    def validate_update(self, values: dict) -> dict:
        """Validate a complete flat patch before any persistence or encryption.

        Empty/masked credential inputs mean retain. Existing secrets are read only
        to check an effective enabled OIDC configuration, never returned.
        """
        if type(values) is not dict:
            raise ValueError("Expected a settings object")
        normalized = {}
        for key, value in values.items():
            definition = self.DEFINITIONS.get(key)
            if definition is not None:
                if key == "backup.admission_pause":
                    if (
                        type(value) is not dict
                        or set(value) != {"schema", "revision", "paused"}
                        or type(value["schema"]) is not int
                        or value["schema"] != 1
                        or type(value["revision"]) is not int
                        or not 0 < value["revision"] < 2**63
                        or type(value["paused"]) is not bool
                    ):
                        raise ValueError("Invalid backup admission pause")
                    prior = self.get(key)
                    if (
                        prior is not None
                        and prior != value
                        and (
                            type(prior) is not dict
                            or type(prior.get("revision")) is not int
                            or value["revision"] <= prior["revision"]
                        )
                    ):
                        raise ValueError(
                            "A changed backup admission pause requires an increased revision"
                        )
                    normalized[key] = dict(value)
                    continue
                if key == "backup.capacity_admission":
                    if (
                        type(value) is not dict
                        or set(value) != {"schema", "revision", "limit", "maintenance"}
                        or type(value["schema"]) is not int
                        or value["schema"] != 1
                        or type(value["revision"]) is not int
                        or not 0 < value["revision"] < 2**63
                        or type(value["limit"]) is not int
                        or not 1 <= value["limit"] <= 100000
                        or type(value["maintenance"]) is not bool
                    ):
                        raise ValueError("Invalid capacity policy")
                    prior = self.get(key)
                    if (
                        prior
                        and prior != value
                        and (
                            type(prior) is not dict
                            or value["revision"] <= prior.get("revision", 0)
                        )
                    ):
                        raise ValueError(
                            "A changed capacity policy requires an increased revision"
                        )
                    normalized[key] = dict(value)
                    continue
                expected = bool if definition["type"] == "bool" else str
                if type(value) is not expected:
                    raise ValueError("Invalid setting type")
                normalized[key] = value.strip() if expected is str else value
            elif key in self.SECRET_DEFINITIONS:
                if type(value) is not str:
                    raise ValueError("Invalid secret type")
                value = value.strip()
                if value and not set(value) <= {"*", "•"}:
                    normalized[key] = value
            else:
                raise ValueError("Unknown setting")
        enabled = normalized.get("oidc.enabled", self.get("oidc.enabled"))
        effective = dict(normalized)
        if enabled:
            for key in ("oidc.scopes", "oidc.default_role"):
                effective.setdefault(key, self.get(key))
        if "oidc.default_role" in effective and effective["oidc.default_role"] not in {
            "viewer",
            "operator",
        }:
            raise ValueError("Invalid OIDC default role")
        if "oidc.scopes" in effective:
            if not isinstance(effective["oidc.scopes"], str):
                raise ValueError("Invalid OIDC scopes")
            scopes = effective["oidc.scopes"].split()
            if (
                not scopes
                or "openid" not in scopes
                or any(
                    not all(
                        0x21 <= ord(char) <= 0x7E and char not in '\\"'
                        for char in scope
                    )
                    for scope in scopes
                )
            ):
                raise ValueError("Invalid OIDC scopes")
            if "oidc.scopes" in normalized:
                normalized["oidc.scopes"] = " ".join(dict.fromkeys(scopes))
        if enabled:
            if not isinstance(enabled, bool):
                raise ValueError("Invalid OIDC enabled state")
            from core.oidc_service import OIDCService

            issuer = normalized.get("oidc.issuer", self.get("oidc.issuer"))
            client_id = normalized.get("oidc.client_id", self.get("oidc.client_id"))
            secret = normalized.get("oidc.client_secret") or self.get_secret(
                "oidc.client_secret"
            )
            OIDCService.validate_endpoint(issuer, issuer=True)
            if (
                not isinstance(client_id, str)
                or not client_id.strip()
                or not isinstance(secret, str)
                or not secret.strip()
            ):
                raise ValueError("Incomplete OIDC configuration")
        return normalized

    def get(self, key: str) -> Any:
        """Get a non-secret setting value.

        Resolution order:
        1. Database (settings_v3 table — UI-entered values win)
        2. Environment variable (seeds initial config)
        3. Default value
        """
        from models import SettingV3

        # 1. Check database (UI-entered values take priority)
        rows = read_configuration(self.db, SettingV3, key)
        setting = rows[0] if rows else None
        if setting and setting.value is not None:
            return self._cast(setting.value, setting.value_type)

        # 2. Check environment variable (fallback for initial config)
        env_key = f"VNBUI_{key.upper().replace('.', '_')}"
        env_val = os.getenv(env_key)
        if env_val is not None and env_val != "":
            return self._cast(
                env_val, self.DEFINITIONS.get(key, {}).get("type", "string")
            )

        # 3. Return default
        return self.DEFINITIONS.get(key, {}).get("default")

    def set(
        self, key: str, value: Any, updated_by: str = None, *, commit: bool = True
    ) -> None:
        """Persist a setting; commit=False flushes into the caller's transaction."""
        from models import SettingV3

        setting = self.db.query(SettingV3).filter(SettingV3.key == key).first()
        value_type = self.DEFINITIONS.get(key, {}).get("type", "string")

        # Convert value to string for storage
        if isinstance(value, bool):
            str_value = "true" if value else "false"
        elif isinstance(value, (dict, list)):
            str_value = json.dumps(value)
        else:
            str_value = str(value) if value is not None else ""

        if setting:
            setting.value = str_value
            setting.value_type = value_type
            setting.source = "ui"
            setting.updated_at = datetime.utcnow()
            setting.updated_by = updated_by
        else:
            setting = SettingV3(
                key=key,
                value=str_value,
                value_type=value_type,
                source="ui",
                updated_by=updated_by,
            )
            self.db.add(setting)

        if commit:
            self.db.commit()
        else:
            self.db.flush()

    def get_secret(self, key: str) -> Optional[str]:
        """Get a secret value (credential).

        Resolution order:
        1. Database (UI-entered, encrypted — user overrides win)
        2. Environment variable (seeds initial config)
        """
        from models import SecretV3

        # 1. Check database (UI-entered values take priority)
        rows = (
            ([self._secret_snapshot[key]] if key in self._secret_snapshot else [])
            if self._secret_snapshot is not None
            else read_configuration(self.db, SecretV3, key)
        )
        secret = rows[0] if rows else None
        if secret and secret.encrypted_value:
            if not _fernet:
                logger.warning(
                    f"VESTA_ENCRYPTION_KEY not set, cannot decrypt secret: {key}"
                )
                return None
            try:
                return _fernet.decrypt(secret.encrypted_value.encode()).decode()
            except InvalidToken:
                logger.error(f"Failed to decrypt secret {key} - invalid token")
                return None
            except Exception as e:
                logger.error(f"Failed to decrypt secret {key}: {e}")
                return None

        if self._secret_snapshot is not None:
            return None

        # 2. Check environment (fallback for initial config)
        defn = self.SECRET_DEFINITIONS.get(key, {})
        env_key = defn.get("env")
        if env_key:
            env_val = os.getenv(env_key)
            if env_val:
                return env_val

        return None

    def set_secret(self, key: str, value: str, *, commit: bool = True) -> None:
        """Encrypt locally and persist; commit=False leaves ownership with caller.

        This writes only secrets_v3, never ENV or an external secret store.
        """
        from models import SecretV3

        if not _fernet:
            raise ValueError("VESTA_ENCRYPTION_KEY not set, cannot encrypt secrets")

        encrypted = _fernet.encrypt(value.encode()).decode()

        secret = self.db.query(SecretV3).filter(SecretV3.key == key).first()
        if secret:
            secret.encrypted_value = encrypted
            secret.source = "ui"
            secret.updated_at = datetime.utcnow()
        else:
            secret = SecretV3(key=key, encrypted_value=encrypted, source="ui")
            self.db.add(secret)

        if commit:
            self.db.commit()
            logger.info(f"Secret {key} updated via UI")
        else:
            self.db.flush()

    def delete_secret(self, key: str) -> None:
        """Delete a secret from the database (doesn't affect env-based secrets)."""
        from models import SecretV3

        secret = self.db.query(SecretV3).filter(SecretV3.key == key).first()
        if secret:
            self.db.delete(secret)
            self.db.commit()
            logger.info(f"Secret {key} deleted")

    def get_many(self, keys) -> Dict[str, Any]:
        """Read recognized non-secret fields from one database snapshot.

        Multi-field destination decisions must not combine independently
        committed settings revisions. Environment defaults are process inputs,
        not part of the database transaction or a credential-scope assertion.
        """
        from models import SettingV3

        keys = tuple(keys)
        if len(set(keys)) != len(keys) or any(k not in self.DEFINITIONS for k in keys):
            raise ValueError("Unknown or duplicate configuration field")
        rows = {row.key: row for row in read_configuration(self.db, SettingV3)}
        result = {}
        for key in keys:
            row = rows.get(key)
            if row is not None and row.value is not None:
                result[key] = self._cast(row.value, row.value_type)
                continue
            definition = self.DEFINITIONS[key]
            value = os.getenv(f"VNBUI_{key.upper().replace('.', '_')}")
            result[key] = (
                self._cast(value, definition.get("type", "string"))
                if value is not None and value != ""
                else definition["default"]
            )
        return result

    def get_all(self) -> Dict[str, Any]:
        """Get all settings as a dict (for API response)."""
        result = {}
        for key in self.DEFINITIONS:
            result[key] = self.get(key)
        return result

    def get_secret_status(self) -> Dict[str, Dict[str, Any]]:
        """Get status of secrets (configured or not, source) without exposing values.

        Source reflects effective priority: UI wins over ENV.
        """
        from models import SecretV3

        result = {}
        for key, defn in self.SECRET_DEFINITIONS.items():
            # Check if set via database (higher priority)
            rows = read_configuration(self.db, SecretV3, key)
            secret = rows[0] if rows else None
            has_db = bool(secret and secret.encrypted_value)

            # Check if set via env (fallback)
            env_key = defn.get("env", "")
            has_env = bool(os.getenv(env_key)) if env_key else False

            result[key] = {
                "configured": has_db or has_env,
                "source": "ui" if has_db else ("env" if has_env else None),
            }
        return result

    def get_s3_config(self) -> Optional[Dict[str, Any]]:
        """Get S3 configuration for agent heartbeat response.

        Returns None if storage type is not S3 or not properly configured.
        """
        if self.get("storage.type") != "s3":
            return None

        access_key = self.get_secret("storage.s3.access_key")
        secret_key = self.get_secret("storage.s3.secret_key")
        bucket = self.get("storage.s3.bucket")

        # Must have credentials and bucket to be considered configured
        if not all([access_key, secret_key, bucket]):
            return None

        return {
            "enabled": True,
            "endpoint": self.get("storage.s3.endpoint") or None,
            "bucket": bucket,
            "region": self.get("storage.s3.region"),
            "prefix": self.get("storage.s3.prefix") or "backups",
            "access_key": access_key,
            "secret_key": secret_key,
            "delete_local": self.get("storage.s3.delete_local"),
        }

    def get_oidc_config(self) -> Optional[Dict[str, Any]]:
        """Get OIDC configuration for auth endpoints.

        Returns None if OIDC is not enabled or not properly configured.
        """
        if not self.get("oidc.enabled"):
            return None

        issuer = self.get("oidc.issuer")
        client_id = self.get("oidc.client_id")
        client_secret = self.get_secret("oidc.client_secret")

        # Must have issuer, client_id, and client_secret
        if not all([issuer, client_id, client_secret]):
            return None

        return {
            "enabled": True,
            "issuer": issuer,
            "client_id": client_id,
            "client_secret": client_secret,
            "scopes": self.get("oidc.scopes"),
            "role_claim": self.get("oidc.role_claim"),
            "admin_values": self.get("oidc.admin_values"),
            "operator_values": self.get("oidc.operator_values"),
            "default_role": self.get("oidc.default_role"),
        }

    def _cast(self, value: str, value_type: str) -> Any:
        """Convert string value to appropriate Python type."""
        if value is None or value == "":
            return self.DEFINITIONS.get(value_type, {}).get("default")

        if value_type == "bool":
            return value.lower() in ("true", "1", "yes", "on")
        elif value_type == "int":
            try:
                return int(value)
            except ValueError:
                return 0
        elif value_type == "json":
            try:
                return json.loads(value)
            except json.JSONDecodeError:
                return {}
        return value


def is_encryption_configured() -> bool:
    """Check if encryption key is configured (for API status checks)."""
    return _fernet is not None


def generate_encryption_key() -> str:
    """Generate a new Fernet encryption key (for setup scripts)."""
    return Fernet.generate_key().decode()
