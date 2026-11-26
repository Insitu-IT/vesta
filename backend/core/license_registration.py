"""Local signed registration and durable advisory notices; never feature gates."""

import base64
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import uuid
from urllib.parse import urlsplit

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from sqlalchemy import text

from core import community_usage
from core.installed_profile import MODULES
from core.tenant_context import PlatformContext
from models import (
    ActivityLog,
    Organization,
    OrganizationDefault,
    SettingV3,
    StorageConfigurationClock,
    User,
)

MAX_ENVELOPE_BYTES = 65536
STATE_KEY = "licensing.registration.v1"
POLICY_VERSION = "registration-v1"
ACKNOWLEDGEMENT_PHRASE = "HIDE LICENSING NOTICE"
KEY_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")


class RegistrationError(ValueError):
    def __init__(self, code, message=None, status_code=422):
        self.code, self.status_code = code, status_code
        self.message = message or code.replace("_", " ")
        super().__init__(self.message)


def _require(condition, code):
    if not condition:
        raise RegistrationError(code)


def _pairs(items):
    result = {}
    for key, value in items:
        _require(key not in result, "duplicate_field")
        result[key] = value
    return result


def _json(value, limit=MAX_ENVELOPE_BYTES):
    _require(type(value) is str, "invalid_json")
    try:
        _require(len(value.encode("utf-8")) <= limit, "document_too_large")
        return json.loads(
            value,
            object_pairs_hook=_pairs,
            parse_constant=lambda _: (_ for _ in ()).throw(
                RegistrationError("invalid_json")
            ),
        )
    except (UnicodeError, ValueError, RecursionError) as exc:
        if isinstance(exc, RegistrationError):
            raise
        raise RegistrationError("invalid_json") from exc


def canonical_signed_bytes(unsigned_envelope):
    return b"vesta-license-v1\n" + json.dumps(
        unsigned_envelope,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


def _string(value, maximum):
    if type(value) is not str or not 0 < len(value) <= maximum:
        return False
    try:
        value.encode("utf-8")
    except UnicodeError:
        return False
    return not re.search(r"[\x00-\x1f\x7f]", value)


def _base64(value, length):
    _require(type(value) is str and len(value) <= 128, "invalid_base64")
    try:
        raw = base64.b64decode(value, validate=True)
    except (ValueError, TypeError) as exc:
        raise RegistrationError("invalid_base64") from exc
    _require(
        len(raw) == length and base64.b64encode(raw).decode("ascii") == value,
        "invalid_base64",
    )
    return raw


def _utc(value):
    _require(_string(value, 40), "invalid_date")
    try:
        date = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise RegistrationError("invalid_date") from exc
    _require(
        date.tzinfo is not None and date.utcoffset() == timedelta(0), "invalid_date"
    )
    return date.astimezone(timezone.utc)


def _now(value=None):
    result = value if value is not None else datetime.now(timezone.utc)
    _require(
        result.tzinfo is not None and result.utcoffset() == timedelta(0),
        "invalid_clock",
    )
    return result.astimezone(timezone.utc)


def load_trusted_keys(keys_path=None):
    from config import settings

    path = Path(keys_path or settings.license_keys_file)
    descriptor = None
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            return {}, {"state": "invalid", "key_ids": [], "fingerprints": {}}
        with os.fdopen(descriptor, "rb") as stream:
            descriptor = None
            raw = stream.read(MAX_ENVELOPE_BYTES + 1)
    except FileNotFoundError:
        return {}, {"state": "unprovisioned", "key_ids": [], "fingerprints": {}}
    except OSError:
        return {}, {"state": "invalid", "key_ids": [], "fingerprints": {}}
    finally:
        if descriptor is not None:
            os.close(descriptor)
    try:
        _require(len(raw) <= MAX_ENVELOPE_BYTES, "document_too_large")
        document = _json(raw.decode("utf-8"))
        _require(
            type(document) is dict and set(document) == {"schema_version", "keys"},
            "invalid_trust_store",
        )
        _require(
            type(document["schema_version"]) is int and document["schema_version"] == 1,
            "invalid_trust_store",
        )
        keys = document["keys"]
        _require(type(keys) is dict and len(keys) <= 64, "invalid_trust_store")
        parsed = {}
        for key_id, public in keys.items():
            _require(
                type(key_id) is str and KEY_ID.fullmatch(key_id), "invalid_trust_store"
            )
            parsed[key_id] = _base64(public, 32)
        return parsed, {
            "state": "configured" if parsed else "unprovisioned",
            "key_ids": sorted(parsed),
            "fingerprints": {
                key: hashlib.sha256(value).hexdigest() for key, value in parsed.items()
            },
        }
    except (RegistrationError, UnicodeError):
        return {}, {"state": "invalid", "key_ids": [], "fingerprints": {}}


def verify_certificate(envelope_text, keys_path=None, installation_id=None, now=None):
    envelope = _json(envelope_text)
    _require(
        type(envelope) is dict
        and set(envelope) == {"schema_version", "key_id", "payload", "signature"},
        "invalid_envelope",
    )
    _require(
        type(envelope["schema_version"]) is int and envelope["schema_version"] == 1,
        "unsupported_schema",
    )
    key_id = envelope["key_id"]
    _require(type(key_id) is str and KEY_ID.fullmatch(key_id), "invalid_key_id")
    payload = envelope["payload"]
    required = {
        "product",
        "license_id",
        "customer_id",
        "class",
        "issued_at",
        "coverage",
    }
    optional = {"not_before", "expires_at", "installation_id", "policy_version"}
    _require(
        type(payload) is dict
        and required <= set(payload)
        and not set(payload) - required - optional,
        "invalid_payload",
    )
    _require(payload["product"] == "vesta", "wrong_product")
    _require(
        _string(payload["license_id"], 128) and _string(payload["customer_id"], 255),
        "invalid_identity",
    )
    _require(
        type(payload["class"]) is str and payload["class"] in {"free", "paid"},
        "invalid_class",
    )
    coverage = payload["coverage"]
    _require(
        type(coverage) is dict and set(coverage) == {"modules"}, "invalid_coverage"
    )
    modules = coverage["modules"]
    _require(
        type(modules) is list and all(type(item) is str for item in modules),
        "invalid_coverage",
    )
    _require(
        len(modules) == len(set(modules)) and set(modules) <= MODULES,
        "invalid_coverage",
    )
    if "policy_version" in payload:
        _require(_string(payload["policy_version"], 64), "invalid_policy_version")
        _require(payload["policy_version"] == POLICY_VERSION, "unsupported_policy")
    issued = _utc(payload["issued_at"])
    beginning = _utc(payload["not_before"]) if "not_before" in payload else issued
    expiry = _utc(payload["expires_at"]) if "expires_at" in payload else None
    _require(expiry is None or expiry > max(issued, beginning), "invalid_date_range")
    if "installation_id" in payload:
        try:
            _require(
                type(payload["installation_id"]) is str
                and str(uuid.UUID(payload["installation_id"]))
                == payload["installation_id"],
                "invalid_installation_id",
            )
        except (ValueError, AttributeError) as exc:
            if isinstance(exc, RegistrationError):
                raise
            raise RegistrationError("invalid_installation_id") from exc
    keys, _ = load_trusted_keys(keys_path)
    _require(key_id in keys, "unknown_key")
    unsigned = {key: envelope[key] for key in ("schema_version", "key_id", "payload")}
    try:
        Ed25519PublicKey.from_public_bytes(keys[key_id]).verify(
            _base64(envelope["signature"], 64), canonical_signed_bytes(unsigned)
        )
    except InvalidSignature as exc:
        raise RegistrationError("invalid_signature") from exc
    current = _now(now)
    _require(current >= max(beginning, issued), "not_yet_valid")
    _require(expiry is None or current < expiry, "expired")
    _require(
        "installation_id" not in payload
        or payload["installation_id"] == installation_id,
        "wrong_installation",
    )
    return payload


@dataclass(frozen=True)
class LicensingActor:
    user_id: str
    label: str
    kind: str = "user"


class LicensingService:
    def __init__(self, db, actor=None, profile=None, now=None, keys_path=None):
        from core.licensing import features

        self.db, self.actor = db, actor
        self.profile = profile if profile is not None else features.profile
        self.now, self.keys_path = now, keys_path

    def _installation_id(self):
        row = self.db.get(StorageConfigurationClock, 1)
        if row is None:
            return None
        try:
            return str(uuid.UUID(row.installation_id))
        except (ValueError, TypeError, AttributeError):
            return None

    def _authorized(self, lock=False):
        if (
            not isinstance(self.actor, LicensingActor)
            or self.actor.kind not in {"user", "operator"}
            or not _string(self.actor.label, 128)
        ):
            return False
        query = (
            self.db.query(User)
            .filter(User.id == self.actor.user_id)
            .populate_existing()
        )
        user = (
            query.with_for_update(read=True).one_or_none()
            if lock
            else query.one_or_none()
        )
        if user is None or not user.is_active:
            return False
        organization_query = (
            self.db.query(Organization)
            .filter(Organization.id == user.org_id)
            .populate_existing()
        )
        organization = (
            organization_query.with_for_update(read=True).one_or_none()
            if lock
            else organization_query.one_or_none()
        )
        if organization is None or not organization.enabled:
            return False
        if self.profile.auth_mode == "multi_organization":
            return bool(user.is_platform_admin)
        assignment = self.db.get(OrganizationDefault, "oss")
        return bool(
            user.role == "admin"
            and assignment is not None
            and assignment.org_id == user.org_id
        )

    def _actor(self, lock=False):
        if not self._authorized(lock):
            raise RegistrationError("installation_authority_required", status_code=403)
        return {
            "user_id": self.actor.user_id,
            "label": self.actor.label,
            "kind": self.actor.kind,
        }

    def _read(self, lock=False):
        if lock and self.db.get_bind().dialect.name == "postgresql":
            self.db.execute(text("SELECT pg_advisory_xact_lock(785493102441)"))
        query = self.db.query(SettingV3).filter(SettingV3.key == STATE_KEY)
        row = (
            query.with_for_update().populate_existing().one_or_none()
            if lock
            else query.populate_existing().one_or_none()
        )
        state = _json(row.value, 262144) if row is not None else {}
        _require(type(state) is dict, "invalid_registration_state")
        return row, state

    def _status(self, state, usage=None):
        from config import settings

        installation = self._installation_id()
        community = self.profile.edition == "community"
        scope = {
            "policy": POLICY_VERSION,
            "installation_id": installation,
            "profile": self.profile.public(),
        }
        if community:
            scope["usage_schedule"] = community_usage.SCHEDULE_VERSION
        notice_scope = hashlib.sha256(canonical_signed_bytes(scope)).hexdigest()
        needed = self.profile.enabled_modules
        if needed:
            status, reason, notice = "required", "paid_module_coverage_required", True
        elif community:
            if usage is None:
                usage = community_usage.observe_usage(self.db, exact=False)
            notice = usage["threshold_reached"]
            status = "required" if notice else "not_required"
            reason = (
                "community_usage_threshold_reached"
                if notice
                else "community_usage_below_threshold"
            )
        else:
            status, reason, notice = "not_required", "usage_policy_unconfigured", False
        payload = None
        if state.get("envelope"):
            try:
                payload = verify_certificate(
                    state["envelope"], self.keys_path, installation, _now(self.now)
                )
                if needed and (
                    payload["class"] != "paid"
                    or not needed <= set(payload["coverage"]["modules"])
                ):
                    status, reason, notice = (
                        "insufficient_coverage",
                        "paid_module_coverage_required",
                        True,
                    )
                else:
                    status, reason, notice = (
                        "valid_" + payload["class"],
                        "certificate_valid",
                        False,
                    )
            except RegistrationError as exc:
                status = (
                    exc.code
                    if exc.code in {"expired", "not_yet_valid", "wrong_installation"}
                    else "invalid"
                )
                reason, notice = exc.code, True
        ack = state.get("acknowledgement") or {}
        return {
            "schema_version": 1,
            "status": status,
            "reason_code": reason,
            "notice_required": notice,
            "acknowledged": ack.get("notice_scope") == notice_scope,
            "can_manage": self._authorized(),
            "registration_url": state.get(
                "registration_url", settings.license_registration_url
            ),
            "notice_scope": notice_scope,
            "policy": {"version": POLICY_VERSION, "usage_rules_configured": community},
        }

    def status(self):
        with PlatformContext():
            _, state = self._read()
            return self._status(state)

    def details(self):
        with PlatformContext():
            self._actor()
            _, state = self._read()
            payload = (
                _json(state["envelope"])["payload"] if state.get("envelope") else None
            )
            _, trust = load_trusted_keys(self.keys_path)
            usage = (
                community_usage.observe_usage(self.db, exact=True)
                if self.profile.edition == "community"
                else None
            )
            return {
                "status": self._status(state, usage),
                "community_usage": usage,
                "certificate": payload,
                "installation_id": self._installation_id(),
                "trust_store": trust,
                "acknowledgement": state.get("acknowledgement"),
            }

    def _mutate(self, action, change):
        try:
            with PlatformContext():
                actor = self._actor(lock=True)
                row, state = self._read(lock=True)
                result, audit = change(state)
                if row is None:
                    row = SettingV3(key=STATE_KEY, value_type="json", source="ui")
                    self.db.add(row)
                row.value = json.dumps(state, sort_keys=True, separators=(",", ":"))
                row.updated_by = self.actor.user_id
                self.db.add(
                    ActivityLog(
                        user_id=self.actor.user_id,
                        action=action,
                        resource_type="licensing",
                        resource_id=self._installation_id(),
                        details={"actor": actor, **audit},
                    )
                )
                self.db.commit()
                return result
        except Exception:
            self.db.rollback()
            raise

    def record_operator_access(self, action):
        _require(action in {"status", "details"}, "invalid_operator_action")
        try:
            with PlatformContext():
                actor = self._actor(lock=True)
                _require(self.actor.kind == "operator", "operator_identity_required")
                self.db.add(
                    ActivityLog(
                        user_id=self.actor.user_id,
                        action="licensing_operator_" + action,
                        resource_type="licensing",
                        resource_id=self._installation_id(),
                        details={"actor": actor},
                    )
                )
                self.db.commit()
        except Exception:
            self.db.rollback()
            raise

    def import_certificate(self, envelope_text):
        def change(state):
            payload = verify_certificate(
                envelope_text, self.keys_path, self._installation_id(), _now(self.now)
            )
            state["envelope"] = json.dumps(
                _json(envelope_text), sort_keys=True, separators=(",", ":")
            )
            return None, {"license_id": payload["license_id"]}

        self._mutate("licensing_certificate_imported", change)
        return self.details()

    def set_registration_url(self, value):
        _require(value == "" or _string(value, 2048), "invalid_registration_url")
        if value:
            try:
                parsed = urlsplit(value)
            except ValueError as exc:
                raise RegistrationError("invalid_registration_url") from exc
            _require(
                parsed.scheme == "https"
                and parsed.hostname
                and not parsed.username
                and not parsed.password
                and not re.search(r"[\s\x00-\x1f\x7f]", value),
                "invalid_registration_url",
            )

        def change(state):
            state["registration_url"] = value
            return None, {"registration_url": value}

        self._mutate("licensing_registration_url_changed", change)
        return self.details()

    def prepare_acknowledgement(self, confirm):
        _require(confirm is True, "first_confirmation_required")

        def change(state):
            status = self._status(state)
            _require(status["notice_required"], "no_active_notice")
            token = secrets.token_urlsafe(32)
            expiry = (_now(self.now) + timedelta(minutes=10)).isoformat()
            state["challenge"] = {
                "digest": hashlib.sha256(token.encode()).hexdigest(),
                "actor": self._actor(),
                "notice_scope": status["notice_scope"],
                "expires_at": expiry,
            }
            return {
                "challenge": token,
                "expected_phrase": ACKNOWLEDGEMENT_PHRASE,
                "notice_scope": status["notice_scope"],
                "expires_at": expiry,
                "status": status,
            }, {"notice_scope": status["notice_scope"]}

        return self._mutate("licensing_acknowledgement_prepared", change)

    def confirm_acknowledgement(self, challenge, phrase, confirm):
        _require(
            confirm is True and phrase == ACKNOWLEDGEMENT_PHRASE,
            "second_confirmation_required",
        )
        _require(
            type(challenge) is str and 16 <= len(challenge) <= 128, "invalid_challenge"
        )

        def change(state):
            pending = state.get("challenge") or {}
            status = self._status(state)
            _require(
                pending.get("actor") == self._actor()
                and pending.get("notice_scope") == status["notice_scope"]
                and status["notice_required"],
                "challenge_scope_changed",
            )
            _require(
                secrets.compare_digest(
                    pending.get("digest", ""),
                    hashlib.sha256(challenge.encode()).hexdigest(),
                ),
                "invalid_challenge",
            )
            _require(_now(self.now) < _utc(pending["expires_at"]), "challenge_expired")
            state["acknowledgement"] = {
                "schema_version": 1,
                "notice_scope": status["notice_scope"],
                "actor": self._actor(),
                "acknowledged_at": _now(self.now).isoformat(),
                "policy_version": POLICY_VERSION,
            }
            state.pop("challenge", None)
            return self._status(state), {"notice_scope": status["notice_scope"]}

        return self._mutate("licensing_notice_acknowledged", change)

    def clear_acknowledgement(self):
        def change(state):
            state.pop("acknowledgement", None)
            state.pop("challenge", None)
            return self._status(state), {}

        return self._mutate("licensing_acknowledgement_removed", change)
