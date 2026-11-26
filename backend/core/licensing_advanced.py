"""
Advanced licensing system with signatures, local revocation, and offline activation
Implements complete architecture from TECHNICAL_DESIGN_SUPPLEMENT.md

This replaces the simple JSON licensing in licensing.py for production use
"""

import os
import json
import logging
import hashlib
import base64
from datetime import datetime, timedelta
from typing import Dict
from pathlib import Path
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend

logger = logging.getLogger(__name__)


class LicenseError(Exception):
    """Base exception for license errors"""

    pass


class LicenseExpiredError(LicenseError):
    """License has expired"""

    pass


class LicenseRevokedError(LicenseError):
    """License has been revoked"""

    pass


class LicenseValidator:
    """
    Local license validation with offline activation and revocation cache support

    Features:
    - RSA signature verification
    - Key rotation support
    - Local revocation cache checks without network access
    - Offline activation
    - Hardware binding
    - Grace periods
    """

    # Embedded public keys (versioned for rotation)
    PUBLIC_KEYS = {
        "vnbui-signing-key-2025-v1": """-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA4gnqzO+r4Do+uC+ZFRif
54N2yhJNHn6z2jTk0IPCprC5iQf1rI4Vdlms5zfG2W4B2HFNmlpS87DIrL15GvgG
aTUwD88RS9jZfAu4s9St9/NxmczGx/jSj0ZvhLZ2CIPTIYJcKXYEkiENaf/ICHLo
GAiA014B1l9d3/zsTDeNLKvipelY6mbwC6KACrwq8roj6QqStM5GwSa6LY8/z1Y/
bv7ppQNYz5P/ObtsLqvsRsx1qrifZy+CdEyf33UDENwY5JSFWgCUlfNi2OAPI4LS
fjihn8RLEDyZjLHOEqijXcGD+JKu2gdKBSfpJHDtbrVPekITIB7HsMBjw/OAauCR
ZOdUCYcFOkJNWnmR8wonopn7U8Ip3kfWjne7t9hYAkATvOGH2dAOUVHSKAushOwx
meVFge6HYoFAEtPrnYLs+xcaEfhqH3Ypu6ov1ms/wFxw8mWxvVUpXSbn52f7gFUV
1usZYXHbMYafa1EsLT5aITU4gZnDt4denzwPjOjgjnGoKZE/B0HkIMP9CSaFTA6S
y6Ivfs4X6HU2VA/Gs3/KqGegxxVnLW1koEsA8vByF/ugzUq3v7TiNK3CeQB9zOrr
mOaWuGnoEpZUdXXZ59/+w/YZj9ZjAOkDrWsQlVCFDQ+GbW+fHD2+G7S07BG9Rxso
8leQLE2cP15eT0nM65oYDaUCAwEAAQ==
-----END PUBLIC KEY-----""",
    }

    def __init__(self):
        self.license_path = os.getenv("LICENSE_FILE", "/etc/vnbui/license.jwt")
        self.revocation_cache_path = "/var/lib/vnbui/crl.cache"
        self.grace_period_days = 7

        # Load any additional public keys from filesystem
        self._load_additional_keys()

    def _load_additional_keys(self):
        """Load public keys from /etc/vnbui/keys/ for key rotation"""
        key_dir = Path("/etc/vnbui/keys")
        if not key_dir.exists():
            return

        for keyfile in key_dir.glob("*.pem"):
            key_id = keyfile.stem
            with open(keyfile, "rb") as f:
                self.PUBLIC_KEYS[key_id] = f.read().decode()

    def validate(self) -> Dict:
        """
        Complete license validation pipeline

        Returns: License payload or raises LicenseError
        """
        # No license = OSS edition
        if not os.path.exists(self.license_path):
            logger.info("No license file, running as OSS edition")
            return {"tier": "oss", "features": []}

        # Load license file
        license_data = self._load_license_file()

        # Validate all checks
        self._verify_signature(license_data)
        self._check_expiration(license_data)
        self._check_hardware_binding(license_data)
        self._check_revocation(license_data)
        self._verify_features(license_data)

        # Record usage for audit
        self._record_usage(license_data)

        logger.info(f"License validated: {license_data['payload']['tier']} edition")
        return license_data["payload"]

    def _load_license_file(self) -> Dict:
        """Load and parse license file"""
        try:
            with open(self.license_path, "r") as f:
                return json.load(f)
        except json.JSONDecodeError as e:
            raise LicenseError(f"Invalid license file format: {e}")
        except Exception as e:
            raise LicenseError(f"Failed to load license: {e}")

    def _verify_signature(self, license_data: Dict):
        """Verify RSA signature with support for key rotation"""
        if "signature" not in license_data:
            raise LicenseError("License missing signature")

        signature_info = license_data["signature"]
        key_id = signature_info.get("keyid")
        signature_b64 = signature_info.get("value")

        if not key_id or not signature_b64:
            raise LicenseError("Invalid signature format")

        # Get public key
        if key_id not in self.PUBLIC_KEYS:
            raise LicenseError(f"Unknown signing key: {key_id}")

        public_key_pem = self.PUBLIC_KEYS[key_id]
        public_key = serialization.load_pem_public_key(
            public_key_pem.encode(), backend=default_backend()
        )

        # Decode signature
        try:
            signature = base64.b64decode(signature_b64)
        except Exception as e:
            raise LicenseError(f"Invalid signature encoding: {e}")

        # Create canonical JSON for verification
        canonical = json.dumps(
            license_data["payload"], sort_keys=True, separators=(",", ":")
        ).encode()

        # Verify signature
        try:
            public_key.verify(
                signature,
                canonical,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA256(),
            )
            logger.debug("License signature verified")
        except Exception as e:
            raise LicenseError(f"Invalid signature: {e}")

    def _check_expiration(self, license_data: Dict):
        """Check expiration with grace period"""
        payload = license_data["payload"]
        expires_at_str = payload.get("expires_at")

        if not expires_at_str:
            # No expiration = perpetual license
            return

        try:
            expires_at = datetime.fromisoformat(expires_at_str.replace("Z", "+00:00"))
        except ValueError as e:
            raise LicenseError(f"Invalid expiration date format: {e}")

        now = datetime.utcnow()

        if now > expires_at:
            # Check if within grace period
            grace_expires = expires_at + timedelta(days=self.grace_period_days)
            if now > grace_expires:
                raise LicenseExpiredError(
                    f"License expired on {expires_at.isoformat()}"
                )
            else:
                # Log warning but allow operation
                logger.warning(
                    f"License expired on {expires_at.isoformat()}, "
                    f"grace period ends {grace_expires.isoformat()}"
                )

    def _check_hardware_binding(self, license_data: Dict):
        """Verify license is bound to this hardware"""
        binding = license_data["payload"].get("hardware_binding", {})

        if not binding.get("enabled"):
            return  # No binding required

        expected_fingerprint = binding.get("fingerprint")
        if not expected_fingerprint:
            return

        actual_fingerprint = self._get_hardware_fingerprint()

        if expected_fingerprint != actual_fingerprint:
            raise LicenseError(
                "Hardware binding mismatch. " "License bound to different hardware."
            )

    def _get_hardware_fingerprint(self) -> str:
        """
        Generate stable hardware fingerprint
        Uses /etc/machine-id which is stable across reboots
        """
        components = []

        # Machine ID (most stable)
        try:
            with open("/etc/machine-id") as f:
                components.append(f"machine-id:{f.read().strip()}")
        except Exception:
            pass

        # Product UUID (from DMI)
        try:
            with open("/sys/class/dmi/id/product_uuid") as f:
                components.append(f"product-uuid:{f.read().strip()}")
        except Exception:
            pass

        # Sort and hash
        components.sort()
        fingerprint = hashlib.sha256("|".join(components).encode()).hexdigest()

        return f"sha256:{fingerprint}"

    def _check_revocation(self, license_data: Dict):
        """
        Check local revocation state without contacting a license service.

        Legacy signed payloads may still contain crl_url/check_interval. Those
        fields remain accepted but never trigger DNS, HTTP or a cache refresh.
        """
        revocation_config = license_data["payload"].get("revocation_check", {})

        if not revocation_config.get("enabled"):
            return  # Revocation checking disabled

        license_id = license_data["payload"]["license_id"]

        # Check cached revocation list
        if self._is_revoked_cached(license_id):
            raise LicenseRevokedError(f"License {license_id} has been revoked (cached)")

    def _load_revocation_cache(self) -> Dict:
        """Load revocation cache from disk"""
        cache_path = Path(self.revocation_cache_path)

        if not cache_path.exists():
            return {}

        try:
            with open(cache_path, "r") as f:
                return json.load(f)
        except Exception:
            return {}

    def _update_revocation_cache(self, license_id: str, revoked: bool):
        """Update local revocation cache"""
        cache = self._load_revocation_cache()
        cache[license_id] = {
            "revoked": revoked,
            "checked_at": datetime.utcnow().isoformat(),
        }

        # Ensure directory exists
        cache_dir = Path(self.revocation_cache_path).parent
        cache_dir.mkdir(parents=True, exist_ok=True)

        with open(self.revocation_cache_path, "w") as f:
            json.dump(cache, f)

    def _is_revoked_cached(self, license_id: str) -> bool:
        """Check if license is revoked according to cache"""
        cache = self._load_revocation_cache()
        entry = cache.get(license_id)

        if not entry:
            return False

        return entry.get("revoked", False)

    def _verify_features(self, license_data: Dict):
        """Verify that features match tier"""
        payload = license_data["payload"]
        tier = payload.get("tier")
        features = payload.get("features", [])

        # Define valid features per tier
        valid_features = {
            "oss": [],
            "msp": ["multi_tenancy", "white_labeling", "billing_api", "advanced_rbac"],
            "enterprise": [
                "multi_tenancy",
                "white_labeling",
                "billing_api",
                "advanced_rbac",
                "compliance",
                "client_encryption",
                "vault",
                "ldap",
                "saml",
                "dr_orchestration",
                "storage_tiering",
                "hsm",
            ],
        }

        tier_features = valid_features.get(tier, [])

        # Check for invalid features
        for feature in features:
            if feature not in tier_features:
                logger.warning(
                    f"Feature '{feature}' not valid for tier '{tier}', ignoring"
                )

    def _record_usage(self, license_data: Dict):
        """Record license usage for audit trail"""
        usage_log = {
            "license_id": license_data["payload"]["license_id"],
            "validated_at": datetime.utcnow().isoformat(),
            "tier": license_data["payload"]["tier"],
            "expires_at": license_data["payload"].get("expires_at"),
            "features": license_data["payload"]["features"],
        }

        # Ensure log directory exists
        log_dir = Path("/var/log/vnbui")
        log_dir.mkdir(parents=True, exist_ok=True)

        # Append to audit log (JSONL format)
        with open(log_dir / "license-usage.jsonl", "a") as f:
            f.write(json.dumps(usage_log) + "\n")


class OfflineLicenseActivation:
    """
    Handle offline/air-gapped license activation
    For Enterprise customers who cannot phone home
    """

    def generate_activation_request(self) -> str:
        """
        Generate activation request for offline environments

        Customer sends this file to vnbui support
        Support sends back activation response with license
        """
        request = {
            "request_id": self._generate_request_id(),
            "timestamp": datetime.utcnow().isoformat(),
            "hardware_fingerprint": self._get_hardware_fingerprint(),
            "deployment_info": {
                "version": self._get_version(),
                "hostname": os.getenv("HOSTNAME", "unknown"),
                "environment": os.getenv("ENVIRONMENT", "production"),
            },
        }

        # Encode for transport
        encoded = base64.b64encode(json.dumps(request, indent=2).encode()).decode()

        # Write to file
        output_file = "/tmp/vnbui-activation-request.txt"
        with open(output_file, "w") as f:
            f.write(encoded)

        logger.info(f"Activation request generated: {output_file}")
        print(f"\n{'='*60}")
        print("OFFLINE ACTIVATION REQUEST GENERATED")
        print(f"{'='*60}")
        print(f"File: {output_file}")
        print("\nSend this file to vnbui support for offline activation")
        print(f"{'='*60}\n")

        return encoded

    def install_activation_response(self, response_file: str):
        """
        Install license from offline activation response

        Support provides signed license file
        Customer installs it here
        """
        # Decode response
        with open(response_file) as f:
            encoded = f.read().strip()

        try:
            response_data = json.loads(base64.b64decode(encoded))
        except Exception as e:
            raise LicenseError(f"Invalid activation response: {e}")

        # Extract license
        if "license" not in response_data:
            raise LicenseError("Activation response missing license")

        license_data = response_data["license"]

        # Write license file
        license_dir = Path(os.getenv("LICENSE_FILE", "/etc/vnbui/license.jwt")).parent
        license_dir.mkdir(parents=True, exist_ok=True)

        with open(os.getenv("LICENSE_FILE", "/etc/vnbui/license.jwt"), "w") as f:
            json.dump(license_data, f, indent=2)

        # Validate immediately
        validator = LicenseValidator()
        payload = validator.validate()

        logger.info("✅ Offline license installed and validated successfully")
        print(f"\n{'='*60}")
        print("LICENSE ACTIVATED SUCCESSFULLY")
        print(f"{'='*60}")
        print(f"Edition: {payload['tier']}")
        print(f"Customer: {payload.get('customer_name', 'N/A')}")
        print(f"Expires: {payload.get('expires_at', 'Never')}")
        print(f"Features: {', '.join(payload.get('features', []))}")
        print(f"{'='*60}\n")

        return payload

    def _generate_request_id(self) -> str:
        """Generate unique request ID"""
        import uuid

        return str(uuid.uuid4())

    def _get_hardware_fingerprint(self) -> str:
        """Get hardware fingerprint (delegates to validator)"""
        validator = LicenseValidator()
        return validator._get_hardware_fingerprint()

    def _get_version(self) -> str:
        """Get vnbui version"""
        try:
            from version import __version__

            return __version__
        except Exception:
            return "unknown"


# CLI tool for license management
if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage:")
        print("  python licensing_advanced.py validate")
        print("  python licensing_advanced.py generate-request")
        print("  python licensing_advanced.py install <response-file>")
        print("  python licensing_advanced.py fingerprint")
        sys.exit(1)

    command = sys.argv[1]

    if command == "validate":
        try:
            validator = LicenseValidator()
            payload = validator.validate()
            print(f"✅ Valid {payload['tier']} license")
            print(f"   Features: {', '.join(payload.get('features', []))}")
            print(f"   Expires: {payload.get('expires_at', 'Never')}")
        except LicenseError as e:
            print(f"❌ License validation failed: {e}")
            sys.exit(1)

    elif command == "generate-request":
        activation = OfflineLicenseActivation()
        activation.generate_activation_request()

    elif command == "install":
        if len(sys.argv) < 3:
            print("Error: Response file required")
            sys.exit(1)

        activation = OfflineLicenseActivation()
        try:
            activation.install_activation_response(sys.argv[2])
        except LicenseError as e:
            print(f"❌ Installation failed: {e}")
            sys.exit(1)

    elif command == "fingerprint":
        validator = LicenseValidator()
        fingerprint = validator._get_hardware_fingerprint()
        print(f"Hardware fingerprint: {fingerprint}")

    else:
        print(f"Unknown command: {command}")
        sys.exit(1)
