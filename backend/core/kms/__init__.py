"""
KMS (Key Management Service) provider abstraction for envelope encryption.

Supports pluggable providers:
- local: DB-backed KEKs encrypted with VNBUI_ENCRYPTION_KEY (Fernet)
- Future: vault (HashiCorp Vault Transit), aws-kms, etc.
"""

from core.kms.base import KMSProvider, KeyMetadata
from core.kms.registry import get_kms_provider

__all__ = ["KMSProvider", "KeyMetadata", "get_kms_provider"]
