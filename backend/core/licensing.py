"""
License management and feature flags
Implements the architecture from TECHNICAL_DESIGN_SUPPLEMENT.md
"""

import os
import json
import logging
from typing import Optional, List, Set

from core.installed_profile import InstalledProfile

logger = logging.getLogger(__name__)


class License:
    """
    Legacy advisory license metadata.

    Historical tiers:
    - oss: Community edition (default)
    - msp: MSP/SaaS edition
    - enterprise: Enterprise edition
    """

    def __init__(self, *, read_legacy_file: bool = True):
        self.license_data = (
            self._load_license()
            if read_legacy_file
            else {"tier": "oss", "features": ["core"], "expires": None}
        )

    def _load_license(self) -> dict:
        """
        Load and validate license file

        For MVP: Simple file-based licensing
        TODO: Implement full JWT-based licensing per TECHNICAL_DESIGN_SUPPLEMENT.md
        """
        license_file = os.getenv("LICENSE_FILE", "/etc/vnbui/license.json")

        if not os.path.exists(license_file):
            logger.info("No legacy license file found")
            return {"tier": "oss", "features": ["core"], "expires": None}

        try:
            with open(license_file, "r") as f:
                data = json.load(f)

            # TODO: Verify signature
            # TODO: Check expiration
            # TODO: Check revocation

            logger.info(
                "Loaded legacy license metadata for tier %s", data.get("tier", "oss")
            )
            return data

        except Exception as e:
            logger.error("Failed to read legacy license metadata: %s", e)
            return {"tier": "oss", "features": ["core"]}

    @property
    def tier(self) -> str:
        """Get current license tier"""
        return self.license_data.get("tier", "oss")

    def has_feature(self, feature: str) -> bool:
        """
        Check if feature is available in current license

        Historical certificate feature mappings, for advisory use only.
        Installed capabilities are reported by FeatureFlags.

        - multi_tenancy: MSP, Enterprise
        - white_labeling: MSP, Enterprise
        - billing_api: MSP, Enterprise
        - compliance: Enterprise
        - client_encryption: Enterprise
        - vault: Enterprise
        - ldap: Enterprise
        - dr_orchestration: Enterprise
        """
        feature_map = {
            "multi_tenancy": ["msp", "enterprise"],
            "white_labeling": ["msp", "enterprise"],
            "billing_api": ["msp", "enterprise"],
            "advanced_rbac": ["msp", "enterprise"],
            "compliance": ["enterprise"],
            "client_encryption": ["enterprise"],
            "vault": ["enterprise"],
            "ldap": ["enterprise"],
            "saml": ["enterprise"],
            "dr_orchestration": ["enterprise"],
            "storage_tiering": ["enterprise"],
            "hsm": ["enterprise"],
        }

        allowed_tiers = feature_map.get(feature, [])
        return self.tier in allowed_tiers


class FeatureFlags:
    """
    Loaded implementation registry for an immutable installed operating profile.
    License information is advisory and never changes implementation availability.
    """

    def __init__(
        self,
        license: Optional[License] = None,
        profile: Optional[InstalledProfile] = None,
    ):
        self.license = (
            license if license is not None else License(read_legacy_file=False)
        )
        self.profile = (
            profile if profile is not None else InstalledProfile.from_environment()
        )
        self._active_commercial_features: Set[str] = set()

    def configure_license(self, license: License) -> None:
        """Replace advisory certificate data without changing the installed profile."""
        self.license = license

    def is_requested(self, feature: str) -> bool:
        return feature in self.profile.enabled_modules

    def activate(self, feature: str) -> None:
        """Mark a successfully loaded commercial implementation as available."""
        if not self.is_requested(feature):
            raise ValueError(f"Cannot activate unconfigured feature '{feature}'")
        self._active_commercial_features.add(feature)

    def is_active(self, feature: str) -> bool:
        return feature in self._active_commercial_features

    def get_loaded_modules(self) -> List[str]:
        return sorted(self._active_commercial_features)

    # ========================================================================
    # OSS Features (always available)
    # ========================================================================

    @property
    def backup_restore(self) -> bool:
        """Basic backup and restore"""
        return True

    @property
    def scheduling(self) -> bool:
        """Backup scheduling"""
        return True

    @property
    def basic_s3(self) -> bool:
        """Basic S3 storage support"""
        return True

    @property
    def basic_oidc(self) -> bool:
        """Basic OIDC authentication"""
        return True

    @property
    def basic_rbac(self) -> bool:
        """3-role RBAC (Admin/Operator/Viewer)"""
        return True

    @property
    def agent_management(self) -> bool:
        """Agent registration and monitoring"""
        return True

    @property
    def reports_csv(self) -> bool:
        """CSV/JSON reports"""
        return True

    @property
    def client_encryption(self) -> bool:
        """Client-side encryption with locally managed keys."""
        return True

    # ========================================================================
    # MSP Features
    # ========================================================================

    @property
    def multi_tenancy(self) -> bool:
        """Multi-organization support"""
        return self.is_active("multi_tenancy")

    @property
    def white_labeling(self) -> bool:
        """Custom branding per organization"""
        return self.is_active("white_labeling")

    @property
    def billing_api(self) -> bool:
        """Billing and metering APIs"""
        return self.is_active("billing_api")

    @property
    def advanced_rbac(self) -> bool:
        """Custom roles and delegated admin"""
        return self.is_active("advanced_rbac")

    # ========================================================================
    # Enterprise Features
    # ========================================================================

    @property
    def compliance_reports(self) -> bool:
        """Signed compliance reports"""
        return self.is_active("compliance")

    @property
    def vault_integration(self) -> bool:
        """HashiCorp Vault integration"""
        return self.is_active("vault")

    @property
    def ldap_auth(self) -> bool:
        """LDAP/Active Directory"""
        return self.is_active("ldap")

    @property
    def saml_auth(self) -> bool:
        """SAML 2.0 authentication"""
        return self.is_active("saml")

    @property
    def dr_orchestration(self) -> bool:
        """Disaster recovery workflows"""
        return self.is_active("dr_orchestration")

    @property
    def storage_tiering(self) -> bool:
        """Hot/cold storage tiers"""
        return self.is_active("storage_tiering")

    @property
    def hsm_support(self) -> bool:
        """Hardware security module support"""
        return self.is_active("hsm")

    def get_edition_name(self) -> str:
        """Display installed distribution independently of certificate status."""
        return (
            "Community Edition"
            if self.profile.edition == "community"
            else "Commercial Edition"
        )

    def get_available_features(self) -> List[str]:
        """Get list of all available features"""
        features = []

        # Check all properties
        for attr in dir(self):
            if attr.startswith("_"):
                continue
            if attr in ["license", "get_edition_name", "get_available_features"]:
                continue

            try:
                value = getattr(self, attr)
                if isinstance(value, bool) and value:
                    features.append(attr)
            except Exception:
                pass

        return features


# Installed capabilities never read legacy licence metadata at startup.
license_manager = License(read_legacy_file=False)
features = FeatureFlags(license_manager)


# Decorator for protecting endpoints
def require_feature(feature: str):
    """
    Decorator to check feature flag before allowing access

    Usage:
        @require_feature('multi_tenancy')
        async def create_organization(...):
            ...
    """
    from functools import wraps
    from fastapi import HTTPException

    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            if not features.is_active(feature):
                raise HTTPException(
                    status_code=403,
                    detail=f"Feature '{feature}' not available in {features.get_edition_name()}",
                )
            return await func(*args, **kwargs)

        return wrapper

    return decorator
