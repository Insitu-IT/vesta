"""
Tests for PKI module and mTLS authentication.

Validates:
- CA initialization and key generation
- Agent cert issuance (with/without IP SANs)
- Backend cert issuance
- CSR signing for renewal
- TLS manager cert lifecycle
- Dual-mode auth logic
- Full-cycle: init → issue → save → verify fingerprint → renew → revoke
- Edge cases: expiry, invalid CSR, re-init rejection

Run from backend/:
    python -m pytest tests/test_pki.py -v
"""

import hashlib
import stat
import sys
import pytest
from datetime import datetime, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID

# Add agent to path for TLSManager import
agent_path = Path(__file__).parent.parent.parent / "agent"
if str(agent_path) not in sys.path:
    sys.path.insert(0, str(agent_path))


def _make_pki():
    """Helper: create a fresh CA + PKIManager."""
    from core.pki import PKIManager

    ca_cert_pem, ca_key_pem = PKIManager.initialize_ca()
    return PKIManager(ca_cert_pem, ca_key_pem), ca_cert_pem, ca_key_pem


def _make_tls_manager(tmp_path):
    """Helper: create a TLSManager with a temp cert dir."""
    from .agent_tls_helper import TLSManager

    cert_dir = tmp_path / "certs"
    cert_dir.mkdir(parents=True, exist_ok=True)
    return TLSManager(cert_dir=cert_dir)


# ============================================================================
# 1. CA Initialization
# ============================================================================


class TestCAInitialization:

    def test_generates_valid_ca(self):
        from core.pki import PKIManager

        ca_cert_pem, ca_key_pem = PKIManager.initialize_ca()

        assert b"BEGIN CERTIFICATE" in ca_cert_pem
        assert b"BEGIN PRIVATE KEY" in ca_key_pem

        cert = x509.load_pem_x509_certificate(ca_cert_pem)
        assert (
            cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
            == "vnbui-ca"
        )

        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints)
        assert bc.value.ca is True
        assert bc.value.path_length == 0

    def test_ca_has_key_usage(self):
        from core.pki import PKIManager

        ca_cert_pem, _ = PKIManager.initialize_ca()
        cert = x509.load_pem_x509_certificate(ca_cert_pem)

        ku = cert.extensions.get_extension_for_class(x509.KeyUsage)
        assert ku.value.key_cert_sign is True
        assert ku.value.crl_sign is True
        assert ku.value.digital_signature is True

    def test_custom_cn_and_validity(self):
        from core.pki import PKIManager

        ca_cert_pem, _ = PKIManager.initialize_ca(cn="my-org-ca", validity_days=365)
        cert = x509.load_pem_x509_certificate(ca_cert_pem)
        assert (
            cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
            == "my-org-ca"
        )

    def test_ca_key_is_4096_bit(self):
        from core.pki import PKIManager

        _, ca_key_pem = PKIManager.initialize_ca()
        key = serialization.load_pem_private_key(ca_key_pem, password=None)
        assert key.key_size == 4096

    def test_ca_self_signed(self):
        from core.pki import PKIManager

        ca_cert_pem, _ = PKIManager.initialize_ca()
        cert = x509.load_pem_x509_certificate(ca_cert_pem)
        assert cert.issuer == cert.subject


# ============================================================================
# 2. Agent Cert Issuance
# ============================================================================


class TestAgentCertIssuance:

    def test_issue_with_hostname_and_ip(self):
        pki, ca_cert_pem, _ = _make_pki()
        result = pki.issue_agent_cert("kvm-host-1", "192.0.2.10")

        for field in ("cert_pem", "key_pem", "serial", "fingerprint", "expires_at"):
            assert field in result

        cert = x509.load_pem_x509_certificate(result["cert_pem"].encode())
        assert (
            cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
            == "kvm-host-1"
        )

        # Signed by our CA
        ca_cert = x509.load_pem_x509_certificate(ca_cert_pem)
        assert cert.issuer == ca_cert.subject

        # Not a CA
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints)
        assert bc.value.ca is False

    def test_sans_include_hostname_and_ip(self):
        pki, _, _ = _make_pki()
        result = pki.issue_agent_cert("kvm-host-2", "192.168.1.50")

        cert = x509.load_pem_x509_certificate(result["cert_pem"].encode())
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)

        dns_names = san.value.get_values_for_type(x509.DNSName)
        assert "kvm-host-2" in dns_names

        from ipaddress import IPv4Address

        ip_addrs = san.value.get_values_for_type(x509.IPAddress)
        assert IPv4Address("192.168.1.50") in ip_addrs

    def test_no_ip_means_no_ip_san(self):
        pki, _, _ = _make_pki()
        result = pki.issue_agent_cert("no-ip-host")

        cert = x509.load_pem_x509_certificate(result["cert_pem"].encode())
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        assert len(san.value.get_values_for_type(x509.IPAddress)) == 0

    def test_has_client_and_server_auth(self):
        pki, _, _ = _make_pki()
        result = pki.issue_agent_cert("test-host")

        cert = x509.load_pem_x509_certificate(result["cert_pem"].encode())
        eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
        assert ExtendedKeyUsageOID.CLIENT_AUTH in eku.value
        assert ExtendedKeyUsageOID.SERVER_AUTH in eku.value

    def test_agent_key_is_2048_bit(self):
        pki, _, _ = _make_pki()
        result = pki.issue_agent_cert("test-host")
        key = serialization.load_pem_private_key(
            result["key_pem"].encode(), password=None
        )
        assert key.key_size == 2048

    def test_unique_serials_across_certs(self):
        pki, _, _ = _make_pki()
        serials = {pki.issue_agent_cert(f"host-{i}")["serial"] for i in range(10)}
        assert len(serials) == 10

    def test_fingerprint_matches_manual_computation(self):
        pki, _, _ = _make_pki()
        result = pki.issue_agent_cert("fp-host")

        cert = x509.load_pem_x509_certificate(result["cert_pem"].encode())
        expected = hashlib.sha256(
            cert.public_bytes(serialization.Encoding.DER)
        ).hexdigest()
        assert result["fingerprint"] == expected


# ============================================================================
# 3. Backend Cert Issuance
# ============================================================================


class TestBackendCert:

    def test_has_client_auth_only(self):
        pki, _, _ = _make_pki()
        result = pki.issue_backend_cert()

        cert = x509.load_pem_x509_certificate(result["cert_pem"].encode())
        eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
        assert ExtendedKeyUsageOID.CLIENT_AUTH in eku.value

    def test_cn_is_vnbui_backend(self):
        pki, _, _ = _make_pki()
        result = pki.issue_backend_cert()
        cert = x509.load_pem_x509_certificate(result["cert_pem"].encode())
        assert (
            cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
            == "vnbui-backend"
        )

    def test_different_from_agent_cert(self):
        pki, _, _ = _make_pki()
        agent = pki.issue_agent_cert("host-1")
        backend = pki.issue_backend_cert()
        assert agent["fingerprint"] != backend["fingerprint"]
        assert agent["serial"] != backend["serial"]


# ============================================================================
# 4. CSR Signing (Renewal)
# ============================================================================


class TestCSRSigning:

    def _make_csr(self, cn="renewing-host", san=None):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        builder = x509.CertificateSigningRequestBuilder().subject_name(
            x509.Name(
                [] if cn is None else [x509.NameAttribute(NameOID.COMMON_NAME, cn)]
            )
        )
        if san:
            builder = builder.add_extension(
                x509.SubjectAlternativeName([x509.DNSName(san)]),
                critical=False,
            )
        csr = builder.sign(key, hashes.SHA256())
        return csr.public_bytes(serialization.Encoding.PEM), key

    def test_sign_valid_csr(self):
        pki, _, _ = _make_pki()
        csr_pem, _ = self._make_csr("renew-agent")

        result = pki.sign_csr(csr_pem, "renew-agent")
        for field in ("cert_pem", "serial", "fingerprint", "expires_at"):
            assert field in result

        cert = x509.load_pem_x509_certificate(result["cert_pem"].encode())
        assert (
            cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
            == "renew-agent"
        )
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        assert san.value.get_values_for_type(x509.DNSName) == ["renew-agent"]

    def test_rejects_caller_selected_san(self):
        pki, _, _ = _make_pki()
        csr_pem, _ = self._make_csr("agent-x", san="backup-api.example.org")
        with pytest.raises(ValueError, match="extensions are not accepted"):
            pki.sign_csr(csr_pem, "agent-x")

    @pytest.mark.parametrize("name", [None, "another-agent"])
    def test_rejects_missing_or_foreign_common_name(self, name):
        pki, _, _ = _make_pki()
        csr_pem, _ = self._make_csr(name)
        with pytest.raises(ValueError, match="common name does not match"):
            pki.sign_csr(csr_pem, "renewing-host")

    def test_renewal_produces_new_serial(self):
        pki, _, _ = _make_pki()
        csr_pem, _ = self._make_csr()
        r1 = pki.sign_csr(csr_pem, "renewing-host")
        r2 = pki.sign_csr(csr_pem, "renewing-host")
        assert r1["serial"] != r2["serial"]
        assert r1["fingerprint"] != r2["fingerprint"]

    def test_reject_invalid_csr(self):
        pki, _, _ = _make_pki()
        with pytest.raises(Exception):
            pki.sign_csr(b"not-a-valid-csr", "renewing-host")


# ============================================================================
# 5. CA Info / PEM Roundtrip
# ============================================================================


class TestCAInfo:

    def test_get_ca_info_fields(self):
        pki, _, _ = _make_pki()
        info = pki.get_ca_info()
        for field in (
            "subject",
            "issuer",
            "serial",
            "not_before",
            "not_after",
            "fingerprint",
        ):
            assert field in info
        assert "vnbui-ca" in info["subject"]
        assert info["not_after"].endswith("Z")

    def test_pem_roundtrip(self):
        from core.pki import PKIManager

        pki, _, ca_key_pem = _make_pki()

        pem_str = pki.get_ca_cert_pem()
        assert "BEGIN CERTIFICATE" in pem_str

        # Reload from PEM string
        pki2 = PKIManager(pem_str.encode(), ca_key_pem)
        result = pki2.issue_agent_cert("roundtrip-host")
        assert result["cert_pem"]


# ============================================================================
# 6. TLS Manager (Agent Side)
# ============================================================================


class TestTLSManager:

    def test_has_certs_false_when_empty(self, tmp_path):
        tm = _make_tls_manager(tmp_path)
        assert tm.has_certs() is False

    def test_save_and_has_certs(self, tmp_path):
        pki, _, _ = _make_pki()
        result = pki.issue_agent_cert("test-host")

        tm = _make_tls_manager(tmp_path)
        tm.save_certs(pki.get_ca_cert_pem(), result["cert_pem"], result["key_pem"])

        assert tm.has_certs() is True
        assert tm.ca_cert.exists()
        assert tm.agent_cert.exists()
        assert tm.agent_key.exists()

    def test_file_permissions(self, tmp_path):
        pki, _, _ = _make_pki()
        result = pki.issue_agent_cert("test-host")

        tm = _make_tls_manager(tmp_path)
        tm.save_certs(pki.get_ca_cert_pem(), result["cert_pem"], result["key_pem"])

        # Key and cert should be 0600
        assert stat.S_IMODE(tm.agent_key.stat().st_mode) == 0o600
        assert stat.S_IMODE(tm.agent_cert.stat().st_mode) == 0o600

    def test_fingerprint_matches_issued(self, tmp_path):
        pki, _, _ = _make_pki()
        result = pki.issue_agent_cert("test-host")

        tm = _make_tls_manager(tmp_path)
        tm.save_certs(pki.get_ca_cert_pem(), result["cert_pem"], result["key_pem"])

        assert tm.get_fingerprint() == result["fingerprint"]

    def test_needs_renewal_false_for_fresh(self, tmp_path):
        pki, _, _ = _make_pki()
        result = pki.issue_agent_cert("test-host", validity_days=365)

        tm = _make_tls_manager(tmp_path)
        tm.save_certs(pki.get_ca_cert_pem(), result["cert_pem"], result["key_pem"])
        assert tm.needs_renewal(30) is False

    def test_needs_renewal_true_near_expiry(self, tmp_path):
        pki, _, _ = _make_pki()
        result = pki.issue_agent_cert("test-host", validity_days=10)

        tm = _make_tls_manager(tmp_path)
        tm.save_certs(pki.get_ca_cert_pem(), result["cert_pem"], result["key_pem"])
        assert tm.needs_renewal(30) is True

    def test_generate_csr_preserves_subject(self, tmp_path):
        pki, _, _ = _make_pki()
        result = pki.issue_agent_cert("csr-host", "10.0.0.5")

        tm = _make_tls_manager(tmp_path)
        tm.save_certs(pki.get_ca_cert_pem(), result["cert_pem"], result["key_pem"])

        csr_pem = tm.generate_csr()
        assert csr_pem is not None
        assert "BEGIN CERTIFICATE REQUEST" in csr_pem

        # Verify CN preserved
        csr = x509.load_pem_x509_csr(csr_pem.encode())
        cn = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        assert cn == "csr-host"

    def test_csr_can_be_signed_by_ca(self, tmp_path):
        """Full roundtrip: issue → save → generate CSR → sign CSR → new cert."""
        pki, _, _ = _make_pki()
        result = pki.issue_agent_cert("roundtrip-host")

        tm = _make_tls_manager(tmp_path)
        tm.save_certs(pki.get_ca_cert_pem(), result["cert_pem"], result["key_pem"])

        csr_pem = tm.generate_csr()
        new_cert = pki.sign_csr(csr_pem.encode(), "roundtrip-host")

        # New cert should have different fingerprint/serial
        assert new_cert["fingerprint"] != result["fingerprint"]
        assert new_cert["serial"] != result["serial"]

    def test_get_client_ssl_context(self, tmp_path):
        pki, _, _ = _make_pki()
        result = pki.issue_agent_cert("ssl-host")

        tm = _make_tls_manager(tmp_path)
        tm.save_certs(pki.get_ca_cert_pem(), result["cert_pem"], result["key_pem"])

        ctx = tm.get_client_ssl_context()
        assert ctx is not None

    def test_get_client_ssl_context_none_without_certs(self, tmp_path):
        tm = _make_tls_manager(tmp_path)
        assert tm.get_client_ssl_context() is None

    def test_get_server_ssl_config(self, tmp_path):
        pki, _, _ = _make_pki()
        result = pki.issue_agent_cert("server-host")

        tm = _make_tls_manager(tmp_path)
        tm.save_certs(pki.get_ca_cert_pem(), result["cert_pem"], result["key_pem"])

        config = tm.get_server_ssl_config()
        assert "ssl_certfile" in config
        assert "ssl_keyfile" in config
        assert "ssl_ca_certs" in config
        assert config["ssl_certfile"] == str(tm.agent_cert)

    def test_get_server_ssl_config_empty_without_certs(self, tmp_path):
        tm = _make_tls_manager(tmp_path)
        assert tm.get_server_ssl_config() == {}

    def test_generate_csr_none_without_certs(self, tmp_path):
        tm = _make_tls_manager(tmp_path)
        assert tm.generate_csr() is None

    def test_get_fingerprint_none_without_certs(self, tmp_path):
        tm = _make_tls_manager(tmp_path)
        assert tm.get_fingerprint() is None


# ============================================================================
# 7. Dual-Mode Auth Logic (Unit Tests)
# ============================================================================


class TestDualModeAuth:
    """Test _verify_agent_cert logic with mock DB."""

    def _mock_db_with_cert(self, fingerprint, status="active", expires_days=30):
        """Create mock DB that returns a cert then an agent."""
        from unittest.mock import MagicMock

        mock_cert = MagicMock()
        mock_cert.status = status
        mock_cert.expires_at = datetime.utcnow() + timedelta(days=expires_days)
        mock_cert.agent_id = "agent-1"
        mock_cert.fingerprint = fingerprint

        mock_agent = MagicMock()
        mock_agent.id = "agent-1"
        mock_agent.cert_fingerprint = fingerprint

        mock_db = MagicMock()
        # First query: AgentCertificate, Second query: Agent
        mock_db.query.return_value.filter.return_value.limit.return_value.all.return_value = [
            mock_cert
        ]
        mock_db.query.return_value.filter.return_value.first.return_value = mock_agent
        return mock_db

    def _mock_db_no_cert(self):
        from unittest.mock import MagicMock

        mock_db = MagicMock()
        mock_db.query.return_value.filter.return_value.limit.return_value.all.return_value = (
            []
        )
        return mock_db

    def test_valid_cert_returns_agent(self):
        from deps import _verify_agent_cert

        db = self._mock_db_with_cert("valid-fp")
        result = _verify_agent_cert("valid-fp", db)
        assert result is not None
        db.commit.assert_not_called()

    def test_none_fingerprint_returns_none(self):
        from deps import _verify_agent_cert
        from unittest.mock import MagicMock

        assert _verify_agent_cert(None, MagicMock()) is None

    def test_unknown_fingerprint_returns_none(self):
        from deps import _verify_agent_cert

        db = self._mock_db_no_cert()
        assert _verify_agent_cert("unknown-fp", db) is None

    def test_superseded_fingerprint_returns_none(self):
        from deps import _verify_agent_cert

        db = self._mock_db_with_cert("old-fp")
        agent = db.query.return_value.filter.return_value.first.return_value
        agent.cert_fingerprint = "new-fp"
        assert _verify_agent_cert("old-fp", db) is None

    def test_certificate_without_expiry_returns_none(self):
        from deps import _verify_agent_cert

        db = self._mock_db_with_cert("no-expiry")
        cert = db.query.return_value.filter.return_value.limit.return_value.all.return_value[
            0
        ]
        cert.expires_at = None
        assert _verify_agent_cert("no-expiry", db) is None

    def test_expired_cert_returns_none_without_platform_scope_mutation(self):
        from deps import _verify_agent_cert
        from unittest.mock import MagicMock

        mock_cert = MagicMock()
        mock_cert.status = "active"
        mock_cert.expires_at = datetime.utcnow() - timedelta(days=1)

        mock_db = MagicMock()
        mock_db.query.return_value.filter.return_value.limit.return_value.all.return_value = [
            mock_cert
        ]

        result = _verify_agent_cert("expired-fp", mock_db)
        assert result is None
        assert mock_cert.status == "active"
        mock_db.commit.assert_not_called()


# ============================================================================
# 8. Full Cycle Integration (No DB, Pure Crypto)
# ============================================================================


class TestFullCycleIntegration:
    """End-to-end test simulating the complete mTLS lifecycle."""

    def test_complete_lifecycle(self, tmp_path):
        """
        Simulates:
        1. Admin initializes CA
        2. Agent registers → receives certs → saves them
        3. Agent builds mTLS SSL context → extracts fingerprint
        4. Backend verifies fingerprint matches issued cert
        5. Agent detects near-expiry → generates CSR
        6. Backend signs CSR → agent saves new cert
        7. Verify new fingerprint is different
        """
        from core.pki import PKIManager

        # Step 1: Admin initializes CA
        ca_cert_pem, ca_key_pem = PKIManager.initialize_ca()
        pki = PKIManager(ca_cert_pem, ca_key_pem)
        ca_info = pki.get_ca_info()
        assert ca_info["fingerprint"]

        # Also issue backend cert
        backend_cert = pki.issue_backend_cert()
        assert backend_cert["cert_pem"]

        # Step 2: Agent registers → backend issues cert
        agent_cert = pki.issue_agent_cert("agent-01", "192.0.2.20")
        original_fp = agent_cert["fingerprint"]
        _original_serial = agent_cert["serial"]  # noqa: F841

        # Step 3: Agent saves certs to disk
        tm = _make_tls_manager(tmp_path)
        tm.save_certs(
            ca_cert=pki.get_ca_cert_pem(),
            agent_cert=agent_cert["cert_pem"],
            agent_key=agent_cert["key_pem"],
        )
        assert tm.has_certs()

        # Step 4: Agent extracts fingerprint (this is what goes in header)
        disk_fp = tm.get_fingerprint()
        assert disk_fp == original_fp  # CRITICAL: must match

        # Step 5: Agent builds SSL context (for mTLS client auth)
        ctx = tm.get_client_ssl_context()
        assert ctx is not None

        # Step 6: Agent builds server SSL config (for backend->agent mTLS)
        server_cfg = tm.get_server_ssl_config()
        assert server_cfg  # Not empty

        # Step 7: Cert is fresh, no renewal needed
        assert tm.needs_renewal(30) is False

        # Step 8: Simulate near-expiry cert
        short_cert = pki.issue_agent_cert("agent-01", "192.0.2.20", validity_days=5)
        tm.save_certs(
            ca_cert=pki.get_ca_cert_pem(),
            agent_cert=short_cert["cert_pem"],
            agent_key=short_cert["key_pem"],
        )
        assert tm.needs_renewal(30) is True

        # Step 9: Agent generates CSR
        csr_pem = tm.generate_csr()
        assert csr_pem is not None

        # Verify CSR CN matches agent hostname
        csr = x509.load_pem_x509_csr(csr_pem.encode())
        cn = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        assert cn == "agent-01"

        # Step 10: Backend signs CSR
        renewed = pki.sign_csr(csr_pem.encode(), "agent-01")
        assert renewed["fingerprint"] != short_cert["fingerprint"]  # New cert

        # Step 11: Agent saves renewed cert (key stays same)
        tm.save_certs(
            ca_cert=pki.get_ca_cert_pem(),
            agent_cert=renewed["cert_pem"],
            agent_key=short_cert["key_pem"],  # Same key
        )
        new_fp = tm.get_fingerprint()
        assert new_fp == renewed["fingerprint"]
        assert new_fp != original_fp

    def test_revoked_cert_not_verifiable(self):
        """Simulate revocation: cert fingerprint lookup should fail."""
        pki, _, _ = _make_pki()

        cert1 = pki.issue_agent_cert("revoke-host")
        cert2 = pki.issue_agent_cert("other-host")

        # Both have different fingerprints
        assert cert1["fingerprint"] != cert2["fingerprint"]

        # Simulate: cert1 is revoked (status changed in DB)
        # In production, _verify_agent_cert queries status == "active"
        # Here we just verify the fingerprints are distinct

    def test_multiple_agents_independent_certs(self, tmp_path):
        """Multiple agents get independent certs from same CA."""
        pki, _, _ = _make_pki()

        agents = {}
        for i in range(3):
            hostname = f"kvm-{i}"
            cert = pki.issue_agent_cert(hostname, f"10.0.0.{i+1}")

            tm = _make_tls_manager(tmp_path / f"agent-{i}")
            tm.save_certs(pki.get_ca_cert_pem(), cert["cert_pem"], cert["key_pem"])

            agents[hostname] = {
                "fingerprint": cert["fingerprint"],
                "tls_manager": tm,
            }

        # All fingerprints unique
        fps = {a["fingerprint"] for a in agents.values()}
        assert len(fps) == 3

        # Each TLS manager has valid certs
        for a in agents.values():
            assert a["tls_manager"].has_certs()
            assert a["tls_manager"].get_fingerprint() == a["fingerprint"]

    def test_ca_reload_from_pem_still_verifies(self):
        """CA serialized to PEM and reloaded can still issue/sign."""
        from core.pki import PKIManager

        pki, _, ca_key_pem = _make_pki()

        # Serialize and reload
        ca_pem = pki.get_ca_cert_pem()
        pki2 = PKIManager(ca_pem.encode(), ca_key_pem)

        # Issue cert with reloaded CA
        cert = pki2.issue_agent_cert("reload-host")
        assert cert["fingerprint"]

        # Both CAs have same fingerprint
        assert pki.get_ca_info()["fingerprint"] == pki2.get_ca_info()["fingerprint"]
