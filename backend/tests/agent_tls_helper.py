"""
TLS manager for agent certificate lifecycle (test helper).

Originally in agent/vnbui_agent/tls.py (Python agent). Kept as a test utility
for PKI integration tests after the Go agent rewrite.
"""

import logging
import os
import ssl
import stat
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


class TLSManager:
    """Manages agent TLS certificates."""

    def __init__(self, cert_dir: Optional[Path] = None):
        self.cert_dir = cert_dir or Path("/var/lib/vnbui/certs")
        self.ca_cert = self.cert_dir / "ca.crt"
        self.agent_cert = self.cert_dir / "agent.crt"
        self.agent_key = self.cert_dir / "agent.key"

    def has_certs(self) -> bool:
        return (
            self.ca_cert.exists()
            and self.agent_cert.exists()
            and self.agent_key.exists()
        )

    def save_certs(self, ca_cert: str, agent_cert: str, agent_key: str):
        self.cert_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(self.cert_dir, stat.S_IRWXU)

        self.ca_cert.write_text(ca_cert)
        os.chmod(self.ca_cert, stat.S_IRUSR | stat.S_IWUSR)

        self.agent_cert.write_text(agent_cert)
        os.chmod(self.agent_cert, stat.S_IRUSR | stat.S_IWUSR)

        self.agent_key.write_text(agent_key)
        os.chmod(self.agent_key, stat.S_IRUSR | stat.S_IWUSR)

    def get_client_ssl_context(self) -> Optional[ssl.SSLContext]:
        if not self.has_certs():
            return None
        ctx = ssl.create_default_context(cafile=str(self.ca_cert))
        ctx.load_cert_chain(certfile=str(self.agent_cert), keyfile=str(self.agent_key))
        return ctx

    def get_server_ssl_config(self) -> dict:
        if not self.has_certs():
            return {}
        return {
            "ssl_certfile": str(self.agent_cert),
            "ssl_keyfile": str(self.agent_key),
            "ssl_ca_certs": str(self.ca_cert),
            "ssl_cert_reqs": ssl.CERT_OPTIONAL,
        }

    def needs_renewal(self, days_before: int = 30) -> bool:
        if not self.agent_cert.exists():
            return False
        try:
            from cryptography import x509

            cert_data = self.agent_cert.read_bytes()
            cert = x509.load_pem_x509_certificate(cert_data)
            expiry = getattr(cert, "not_valid_after_utc", None)
            if expiry is None:
                expiry = cert.not_valid_after.replace(tzinfo=timezone.utc)
            remaining = expiry - datetime.now(timezone.utc)
            return remaining.days <= days_before
        except Exception as e:
            logger.error(f"Failed to check cert expiry: {e}")
            return False

    def generate_csr(self) -> Optional[str]:
        if not self.agent_key.exists() or not self.agent_cert.exists():
            return None
        try:
            from cryptography import x509
            from cryptography.hazmat.primitives import hashes, serialization

            key_data = self.agent_key.read_bytes()
            key = serialization.load_pem_private_key(key_data, password=None)

            cert_data = self.agent_cert.read_bytes()
            cert = x509.load_pem_x509_certificate(cert_data)

            builder = x509.CertificateSigningRequestBuilder().subject_name(cert.subject)
            # The production Go agent requests its existing subject without
            # caller-selected extensions; the signer supplies authorized SANs.
            csr = builder.sign(key, hashes.SHA256())
            return csr.public_bytes(serialization.Encoding.PEM).decode()
        except Exception as e:
            logger.error(f"Failed to generate CSR: {e}")
            return None

    def get_fingerprint(self) -> Optional[str]:
        if not self.agent_cert.exists():
            return None
        try:
            import hashlib

            from cryptography import x509
            from cryptography.hazmat.primitives import serialization

            cert_data = self.agent_cert.read_bytes()
            cert = x509.load_pem_x509_certificate(cert_data)
            der = cert.public_bytes(serialization.Encoding.DER)
            return hashlib.sha256(der).hexdigest()
        except Exception as e:
            logger.error(f"Failed to get cert fingerprint: {e}")
            return None


def create_tls_manager(tmp_path: Path) -> TLSManager:
    """Create a TLSManager using a temporary directory."""
    cert_dir = tmp_path / "certs"
    cert_dir.mkdir(exist_ok=True)
    return TLSManager(cert_dir=cert_dir)
