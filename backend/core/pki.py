"""
PKI Manager for mTLS certificate management.

Self-contained CA that can issue and sign agent/backend certificates.
CA key stored Fernet-encrypted in secrets_v3 table or loaded from file paths.
"""

import hashlib
import logging
import os
from datetime import datetime, timedelta
from ipaddress import IPv4Address
from typing import Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID

logger = logging.getLogger(__name__)

# Env vars for file-based CA (alternative to DB storage)
TLS_CA_CERT_FILE = os.getenv("TLS_CA_CERT_FILE")
TLS_CA_KEY_FILE = os.getenv("TLS_CA_KEY_FILE")


def retire_agent_certificates(db, agent_id: str) -> None:
    """Retire previous credentials inside the new certificate's DB transaction."""
    from models import AgentCertificate

    now = datetime.utcnow()
    active = (
        db.query(AgentCertificate)
        .filter(
            AgentCertificate.agent_id == agent_id,
            AgentCertificate.status == "active",
        )
        .with_for_update()
        .all()
    )
    for certificate in active:
        certificate.status = "revoked"
        certificate.revoked_at = now


class PKIManager:
    """Manages CA operations: init, issue, sign, revoke."""

    def __init__(self, ca_cert_pem: bytes, ca_key_pem: bytes):
        self.ca_cert = x509.load_pem_x509_certificate(ca_cert_pem)
        self.ca_key = serialization.load_pem_private_key(ca_key_pem, password=None)

    @classmethod
    def initialize_ca(cls, cn: str = "vnbui-ca", validity_days: int = 3650) -> tuple:
        """Generate self-signed CA key+cert.

        Returns:
            (ca_cert_pem, ca_key_pem) as bytes
        """
        key = rsa.generate_private_key(public_exponent=65537, key_size=4096)

        subject = issuer = x509.Name(
            [
                x509.NameAttribute(NameOID.COMMON_NAME, cn),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "vnbui"),
            ]
        )

        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.utcnow())
            .not_valid_after(datetime.utcnow() + timedelta(days=validity_days))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_cert_sign=True,
                    crl_sign=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
                critical=False,
            )
            .sign(key, hashes.SHA256())
        )

        ca_cert_pem = cert.public_bytes(serialization.Encoding.PEM)
        ca_key_pem = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        return ca_cert_pem, ca_key_pem

    def issue_agent_cert(
        self, hostname: str, ip: Optional[str] = None, validity_days: int = 365
    ) -> dict:
        """Generate keypair and sign cert for an agent.

        Returns dict with cert_pem, key_pem, serial, fingerprint, expires_at.
        """
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        subject = x509.Name(
            [
                x509.NameAttribute(NameOID.COMMON_NAME, hostname),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "vnbui-agent"),
            ]
        )

        # Build SANs
        sans = [x509.DNSName(hostname)]
        if ip:
            try:
                sans.append(x509.IPAddress(IPv4Address(ip)))
            except ValueError:
                pass

        expires_at = datetime.utcnow() + timedelta(days=validity_days)

        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(self.ca_cert.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.utcnow())
            .not_valid_after(expires_at)
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None), critical=True
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_encipherment=True,
                    content_commitment=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    data_encipherment=False,
                    key_agreement=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.ExtendedKeyUsage(
                    [
                        ExtendedKeyUsageOID.CLIENT_AUTH,
                        ExtendedKeyUsageOID.SERVER_AUTH,
                    ]
                ),
                critical=False,
            )
            .add_extension(x509.SubjectAlternativeName(sans), critical=False)
            .sign(self.ca_key, hashes.SHA256())
        )

        cert_pem = cert.public_bytes(serialization.Encoding.PEM)
        key_pem = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        fingerprint = hashlib.sha256(
            cert.public_bytes(serialization.Encoding.DER)
        ).hexdigest()
        serial = format(cert.serial_number, "x")

        return {
            "cert_pem": cert_pem.decode(),
            "key_pem": key_pem.decode(),
            "serial": serial,
            "fingerprint": fingerprint,
            "expires_at": expires_at,
        }

    def issue_backend_cert(
        self, cn: str = "vnbui-backend", validity_days: int = 365
    ) -> dict:
        """Issue orchestrator client cert for backend->agent mTLS."""
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        subject = x509.Name(
            [
                x509.NameAttribute(NameOID.COMMON_NAME, cn),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "vnbui-backend"),
            ]
        )

        expires_at = datetime.utcnow() + timedelta(days=validity_days)

        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(self.ca_cert.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.utcnow())
            .not_valid_after(expires_at)
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None), critical=True
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_encipherment=True,
                    content_commitment=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    data_encipherment=False,
                    key_agreement=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),
                critical=False,
            )
            .sign(self.ca_key, hashes.SHA256())
        )

        cert_pem = cert.public_bytes(serialization.Encoding.PEM)
        key_pem = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        fingerprint = hashlib.sha256(
            cert.public_bytes(serialization.Encoding.DER)
        ).hexdigest()
        serial = format(cert.serial_number, "x")

        return {
            "cert_pem": cert_pem.decode(),
            "key_pem": key_pem.decode(),
            "serial": serial,
            "fingerprint": fingerprint,
            "expires_at": expires_at,
        }

    def sign_csr(
        self, csr_pem: bytes, expected_common_name: str, validity_days: int = 365
    ) -> dict:
        """Renew only the authenticated agent's existing TLS identity.

        Returns dict with cert_pem, serial, fingerprint, expires_at.
        """
        csr = x509.load_pem_x509_csr(csr_pem)
        if not csr.is_signature_valid:
            raise ValueError("CSR signature is invalid")
        common_names = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        if (
            len(common_names) != 1
            or common_names[0].value != expected_common_name
            or not expected_common_name
            or len(expected_common_name) > 255
        ):
            raise ValueError("CSR common name does not match authenticated agent")
        if len(csr.extensions):
            raise ValueError("CSR extensions are not accepted for agent renewal")

        expires_at = datetime.utcnow() + timedelta(days=validity_days)

        # The agent also serves HTTPS, so retain both EKUs. Never copy a
        # caller-selected SAN or subject into a CA-signed server identity.
        builder = (
            x509.CertificateBuilder()
            .subject_name(
                x509.Name(
                    [
                        x509.NameAttribute(NameOID.COMMON_NAME, expected_common_name),
                        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "vnbui-agent"),
                    ]
                )
            )
            .issuer_name(self.ca_cert.subject)
            .public_key(csr.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.utcnow())
            .not_valid_after(expires_at)
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None), critical=True
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_encipherment=True,
                    content_commitment=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    data_encipherment=False,
                    key_agreement=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.ExtendedKeyUsage(
                    [
                        ExtendedKeyUsageOID.CLIENT_AUTH,
                        ExtendedKeyUsageOID.SERVER_AUTH,
                    ]
                ),
                critical=False,
            )
            .add_extension(
                x509.SubjectAlternativeName([x509.DNSName(expected_common_name)]),
                critical=False,
            )
        )

        cert = builder.sign(self.ca_key, hashes.SHA256())

        cert_pem = cert.public_bytes(serialization.Encoding.PEM)
        fingerprint = hashlib.sha256(
            cert.public_bytes(serialization.Encoding.DER)
        ).hexdigest()
        serial = format(cert.serial_number, "x")

        return {
            "cert_pem": cert_pem.decode(),
            "serial": serial,
            "fingerprint": fingerprint,
            "expires_at": expires_at,
        }

    def get_ca_cert_pem(self) -> str:
        return self.ca_cert.public_bytes(serialization.Encoding.PEM).decode()

    def get_ca_info(self) -> dict:
        return {
            "subject": self.ca_cert.subject.rfc4514_string(),
            "issuer": self.ca_cert.issuer.rfc4514_string(),
            "serial": format(self.ca_cert.serial_number, "x"),
            "not_before": self.ca_cert.not_valid_before.isoformat() + "Z",
            "not_after": self.ca_cert.not_valid_after.isoformat() + "Z",
            "fingerprint": hashlib.sha256(
                self.ca_cert.public_bytes(serialization.Encoding.DER)
            ).hexdigest(),
        }


def get_pki_manager(db) -> Optional[PKIManager]:
    """Load PKI manager from file or DB. Returns None if CA not initialized."""
    # 1. Try file-based CA
    if TLS_CA_CERT_FILE and TLS_CA_KEY_FILE:
        try:
            with open(TLS_CA_CERT_FILE, "rb") as f:
                ca_cert_pem = f.read()
            with open(TLS_CA_KEY_FILE, "rb") as f:
                ca_key_pem = f.read()
            return PKIManager(ca_cert_pem, ca_key_pem)
        except Exception as e:
            logger.error(f"Failed to load CA from files: {e}")
            return None

    # 2. Try DB-stored CA
    from core.settings_service import SettingsService

    svc = SettingsService(db)

    ca_cert_pem_str = svc.get("pki.ca_cert")
    if not ca_cert_pem_str:
        return None

    ca_key_encrypted = svc.get_secret("pki.ca_key")
    if not ca_key_encrypted:
        logger.warning("CA cert found in DB but key is missing")
        return None

    try:
        return PKIManager(ca_cert_pem_str.encode(), ca_key_encrypted.encode())
    except Exception as e:
        logger.error(f"Failed to load CA from DB: {e}")
        return None


def is_ca_initialized(db) -> bool:
    """Check if CA is available (file or DB)."""
    if TLS_CA_CERT_FILE and TLS_CA_KEY_FILE:
        return os.path.exists(TLS_CA_CERT_FILE) and os.path.exists(TLS_CA_KEY_FILE)

    from core.settings_service import SettingsService

    svc = SettingsService(db)
    return bool(svc.get("pki.ca_cert"))
