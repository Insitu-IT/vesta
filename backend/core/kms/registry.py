"""
KMS provider registry — selects provider based on settings.
"""

import logging
from core.kms.base import KMSProvider

logger = logging.getLogger(__name__)

# Cached provider instance
_provider: KMSProvider = None


def get_kms_provider() -> KMSProvider:
    """
    Get the configured KMS provider.

    Currently only 'local' is supported. Future providers:
    - vault: HashiCorp Vault Transit backend
    - aws-kms: AWS Key Management Service
    """
    global _provider
    if _provider is not None:
        return _provider

    # Future: read provider_type from settings_v3 table
    # For now, always use local provider
    from core.kms.local import LocalKMSProvider

    _provider = LocalKMSProvider()
    logger.info("KMS provider initialized: local")
    return _provider


def reset_provider():
    """Reset cached provider (for testing)."""
    global _provider
    _provider = None
