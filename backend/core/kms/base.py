"""
Abstract KMS provider interface.

All KMS providers (local, Vault Transit, AWS KMS, etc.) implement this interface.
The backend only interacts with keys through this abstraction.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime
from typing import Optional, List


@dataclass
class KeyMetadata:
    """Metadata about a KEK (Key Encryption Key)"""

    id: str
    name: str
    algorithm: str
    key_hash: str  # SHA256 of raw key material (for verification)
    status: str  # active, rotated, revoked
    provider: str  # local, vault, aws-kms
    provider_key_ref: Optional[str]  # External reference (Vault path, AWS ARN)
    created_at: datetime
    created_by: Optional[str]
    rotated_at: Optional[datetime]
    replaced_by_id: Optional[str]
    backed_up: bool
    backed_up_at: Optional[datetime]
    backed_up_locations: List[str]


class KMSProvider(ABC):
    """Abstract interface for key management providers"""

    @abstractmethod
    async def create_key(
        self,
        name: str,
        algorithm: str = "aes-256-gcm",
        created_by: Optional[str] = None,
    ) -> KeyMetadata:
        """Create a new KEK. For local provider, generates key material and stores encrypted in DB."""
        ...

    @abstractmethod
    async def get_key(self, key_id: str) -> KeyMetadata:
        """Get key metadata by ID. Never returns raw key material."""
        ...

    @abstractmethod
    async def list_keys(self) -> List[KeyMetadata]:
        """List all keys (metadata only)."""
        ...

    @abstractmethod
    async def get_active_key(self) -> Optional[KeyMetadata]:
        """Get the current active key for new backups. Returns None if no key exists."""
        ...

    @abstractmethod
    async def rotate_key(
        self, old_key_id: str, new_name: str, created_by: Optional[str] = None
    ) -> KeyMetadata:
        """
        Rotate a key: create new active key, mark old as 'rotated'.
        Old key remains usable for unwrapping existing backups.
        """
        ...

    @abstractmethod
    async def revoke_key(self, key_id: str) -> None:
        """
        Revoke a key (soft delete). Revoked keys cannot wrap or unwrap.
        Raises ValueError if key is still in use by backups.
        """
        ...

    @abstractmethod
    async def wrap_dek(self, dek: bytes, kek_id: str) -> bytes:
        """
        Wrap (encrypt) a DEK using the specified KEK.
        Returns the wrapped DEK bytes.
        """
        ...

    @abstractmethod
    async def unwrap_dek(self, wrapped_dek: bytes, kek_id: str) -> bytes:
        """
        Unwrap (decrypt) a DEK using the specified KEK.
        Returns the raw DEK bytes.
        """
        ...

    @abstractmethod
    async def export_keys(self, key_ids: List[str], password: str) -> bytes:
        """
        Export keys as password-protected archive without asserting custody.
        Raises NotImplementedError for external providers (Vault, AWS KMS).
        """
        ...

    @abstractmethod
    async def confirm_export_custody(
        self, data: bytes, password: str, location: str
    ) -> List[str]:
        """Verify a saved export against current keys and attest its custody."""
        ...

    @abstractmethod
    async def import_keys(self, data: bytes, password: str) -> List[str]:
        """
        Import keys from password-protected archive.
        Returns list of imported key IDs. Skips duplicates (by key_hash).
        """
        ...

    @property
    @abstractmethod
    def supports_export(self) -> bool:
        """Whether this provider supports key export/import. False for external KMS."""
        ...

    @abstractmethod
    async def mark_backed_up(self, key_id: str, location: str) -> None:
        """Mark a key as backed up to a specific location."""
        ...

    @abstractmethod
    async def get_backup_count(self, key_id: str) -> int:
        """Get count of backups using this key."""
        ...
