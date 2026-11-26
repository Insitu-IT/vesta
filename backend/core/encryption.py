"""Legacy file encryption providers configured independently of registration."""

import os
import subprocess
import logging
from typing import Optional
from cryptography.fernet import Fernet
import base64

logger = logging.getLogger(__name__)


class EncryptionProvider:
    """
    Base class for encryption providers
    """

    def encrypt_file(self, input_path: str, output_path: str) -> str:
        """Encrypt file, return output path"""
        raise NotImplementedError

    def decrypt_file(self, input_path: str, output_path: str) -> str:
        """Decrypt file, return output path"""
        raise NotImplementedError


class SimpleEncryption(EncryptionProvider):
    """
    Simple Fernet-based encryption
    Suitable for at-rest encryption with basic key management
    """

    def __init__(self, key: Optional[bytes] = None):
        """Build a Fernet cipher from an explicit key or ENCRYPTION_KEY.

        Raises rather than generating a key when neither is supplied. The
        previous behaviour minted a fresh key per process and logged it at
        WARNING, which is two failures in a product whose job is backups:

        - A key that lives for one process encrypts backups nobody can restore.
          The backup succeeds, reports success, and is unreadable after the next
          restart — the worst possible shape for this particular product,
          because the loss is discovered at restore time.
        - The key was written to the log stream. Log lines are shipped, indexed
          and retained; a key that reaches them is disclosed, and no rotation
          undoes what was already collected.

        Both were reachable through get_encryption_provider() with
        ENABLE_ENCRYPTION=true and no ENCRYPTION_KEY set. Refusing to start is
        the only outcome that leaves the operator able to act.
        """
        if key is not None:
            self.key = key
        else:
            key_b64 = os.getenv("ENCRYPTION_KEY")
            if not key_b64:
                raise RuntimeError(
                    "ENCRYPTION_KEY is not set. Refusing to generate an ephemeral "
                    "key: backups encrypted with it could not be restored after a "
                    "restart. Generate one with: python -c "
                    "'from cryptography.fernet import Fernet; "
                    "print(Fernet.generate_key().decode())'"
                )
            self.key = base64.urlsafe_b64decode(key_b64)

        self.cipher = Fernet(self.key)

    def encrypt_file(self, input_path: str, output_path: str) -> str:
        """Encrypt file using Fernet"""
        with open(input_path, "rb") as f:
            data = f.read()

        encrypted = self.cipher.encrypt(data)

        with open(output_path, "wb") as f:
            f.write(encrypted)

        logger.info(f"Encrypted {input_path} -> {output_path}")
        return output_path

    def decrypt_file(self, input_path: str, output_path: str) -> str:
        """Decrypt file using Fernet"""
        with open(input_path, "rb") as f:
            encrypted = f.read()

        decrypted = self.cipher.decrypt(encrypted)

        with open(output_path, "wb") as f:
            f.write(decrypted)

        logger.info(f"Decrypted {input_path} -> {output_path}")
        return output_path


class AgeEncryption(EncryptionProvider):
    """
    Age-based client-side encryption
    Requires Age CLI tool: https://github.com/FiloSottile/age

    Features:
    - Client-side encryption (data encrypted before leaving host)
    - Public key encryption
    - Multiple recipients support
    - Secure key management
    """

    def __init__(
        self, public_key: Optional[str] = None, private_key: Optional[str] = None
    ):
        self.public_key = public_key or os.getenv("AGE_PUBLIC_KEY")
        self.private_key = private_key or os.getenv("AGE_PRIVATE_KEY")

        # Verify Age is installed
        try:
            subprocess.run(["age", "--version"], capture_output=True, check=True)
        except (subprocess.CalledProcessError, FileNotFoundError):
            logger.error(
                "Age encryption tool not found. Install: https://github.com/FiloSottile/age"
            )
            raise RuntimeError("Age CLI not available")

    def encrypt_file(self, input_path: str, output_path: str) -> str:
        """
        Encrypt file using Age public key

        age -r <public-key> -o output.age input.file
        """
        if not self.public_key:
            raise ValueError("Public key required for encryption")

        try:
            subprocess.run(
                ["age", "-r", self.public_key, "-o", output_path, input_path],
                capture_output=True,
                text=True,
                check=True,
            )

            logger.info(f"Age encrypted: {input_path} -> {output_path}")
            return output_path

        except subprocess.CalledProcessError as e:
            logger.error(f"Age encryption failed: {e.stderr}")
            raise RuntimeError(f"Encryption failed: {e.stderr}")

    def decrypt_file(self, input_path: str, output_path: str) -> str:
        """
        Decrypt file using Age private key

        age -d -i <private-key-file> -o output.file input.age
        """
        if not self.private_key:
            raise ValueError("Private key required for decryption")

        # Write private key to temporary file (Age expects a file)
        key_file = "/tmp/age_key.txt"
        try:
            with open(key_file, "w") as f:
                f.write(self.private_key)

            os.chmod(key_file, 0o600)  # Restrict permissions

            subprocess.run(
                ["age", "-d", "-i", key_file, "-o", output_path, input_path],
                capture_output=True,
                text=True,
                check=True,
            )

            logger.info(f"Age decrypted: {input_path} -> {output_path}")
            return output_path

        except subprocess.CalledProcessError as e:
            logger.error(f"Age decryption failed: {e.stderr}")
            raise RuntimeError(f"Decryption failed: {e.stderr}")

        finally:
            # Clean up key file
            if os.path.exists(key_file):
                os.remove(key_file)


def get_encryption_provider() -> Optional[EncryptionProvider]:
    """
    Select a legacy encryption provider from explicit configuration

    Returns None if encryption is disabled
    """
    encryption_enabled = os.getenv("ENABLE_ENCRYPTION", "false").lower() == "true"

    if not encryption_enabled:
        return None

    encryption_type = os.getenv("ENCRYPTION_TYPE", "simple")

    if encryption_type == "simple":
        return SimpleEncryption()
    if encryption_type == "age":
        return AgeEncryption()

    logger.warning(f"Unknown encryption type: {encryption_type}, disabling encryption")
    return None


# Global encryption provider (lazy-loaded)
_encryption = None


def get_encryption():
    """Get global encryption provider"""
    global _encryption
    if _encryption is None:
        _encryption = get_encryption_provider()
    return _encryption
