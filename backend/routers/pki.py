"""
PKI endpoints: CA initialization, cert listing, revocation, renewal.
"""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from datetime import datetime
import logging

from database import get_db
from models import AgentCertificate, Agent
from deps import get_admin_user, verify_agent_api_key, iso_utc, log_activity
from deps import get_installation_admin, get_installation_db
from core.pki import (
    PKIManager,
    get_pki_manager,
    is_ca_initialized,
    retire_agent_certificates,
)
from core.settings_service import SettingsService

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/pki", tags=["pki"])


@router.post("/initialize")
async def initialize_ca(
    db: Session = Depends(get_installation_db),
    admin_user=Depends(get_installation_admin),
):
    """Initialize the built-in CA (one-time operation)."""
    if is_ca_initialized(db):
        raise HTTPException(status_code=409, detail="CA already initialized")

    ca_cert_pem, ca_key_pem = PKIManager.initialize_ca()

    # Store in settings DB
    svc = SettingsService(db)
    svc.set("pki.ca_cert", ca_cert_pem.decode(), updated_by=admin_user.username)
    svc.set_secret("pki.ca_key", ca_key_pem.decode())

    # Also issue a backend client cert for orchestrator->agent mTLS
    pki = PKIManager(ca_cert_pem, ca_key_pem)
    backend_cert = pki.issue_backend_cert()

    # Store backend cert in secrets for later use
    svc.set_secret("pki.backend_cert", backend_cert["cert_pem"])
    svc.set_secret("pki.backend_key", backend_cert["key_pem"])

    log_activity(
        db,
        admin_user,
        action="pki_ca_initialized",
        resource_type="pki",
        details={"fingerprint": pki.get_ca_info()["fingerprint"]},
    )

    return {
        "message": "CA initialized successfully",
        "ca": pki.get_ca_info(),
    }


@router.get("/ca")
async def get_ca_cert(db: Session = Depends(get_db)):
    """Download CA certificate (public, no auth required for trust distribution)."""
    pki = get_pki_manager(db)
    if not pki:
        raise HTTPException(status_code=404, detail="CA not initialized")

    from fastapi.responses import Response

    return Response(
        content=pki.get_ca_cert_pem(),
        media_type="application/x-pem-file",
        headers={"Content-Disposition": "attachment; filename=vesta-ca.crt"},
    )


@router.get("/backend-cert")
async def get_backend_cert(
    db: Session = Depends(get_installation_db),
    admin_user=Depends(get_installation_admin),
):
    """Download backend client cert+key for OKD secret mounting (admin only).

    Returns JSON with cert and key PEM for manual deployment.
    """
    svc = SettingsService(db)
    cert_pem = svc.get_secret("pki.backend_cert")
    key_pem = svc.get_secret("pki.backend_key")

    if not cert_pem or not key_pem:
        raise HTTPException(
            status_code=404, detail="Backend cert not found. Initialize CA first."
        )

    return {
        "cert_pem": cert_pem,
        "key_pem": key_pem,
        "usage": "Set ORCHESTRATOR_CLIENT_CERT and ORCHESTRATOR_CLIENT_KEY env vars, or mount as OKD secret",
    }


@router.get("/status")
async def get_pki_status(
    db: Session = Depends(get_db),
    admin_user=Depends(get_admin_user),
):
    """Get CA status and certificate statistics."""
    initialized = is_ca_initialized(db)

    result = {
        "initialized": initialized,
        "ca": None,
        "certificates": {"total": 0, "active": 0, "expired": 0, "revoked": 0},
    }

    if initialized:
        pki = get_pki_manager(db)
        if pki:
            result["ca"] = pki.get_ca_info()

        # Cert stats
        result["certificates"]["total"] = db.query(AgentCertificate).count()
        result["certificates"]["active"] = (
            db.query(AgentCertificate)
            .filter(AgentCertificate.status == "active")
            .count()
        )
        result["certificates"]["expired"] = (
            db.query(AgentCertificate)
            .filter(AgentCertificate.status == "expired")
            .count()
        )
        result["certificates"]["revoked"] = (
            db.query(AgentCertificate)
            .filter(AgentCertificate.status == "revoked")
            .count()
        )

        # Check require_mtls setting
        svc = SettingsService(db)
        result["require_mtls"] = svc.get("pki.require_mtls")

    return result


@router.get("/certificates")
async def list_certificates(
    db: Session = Depends(get_db),
    admin_user=Depends(get_admin_user),
):
    """List all issued certificates."""
    certs = db.query(AgentCertificate).order_by(AgentCertificate.issued_at.desc()).all()

    return {
        "items": [
            {
                "id": cert.id,
                "agent_id": cert.agent_id,
                "serial_number": cert.serial_number,
                "fingerprint": cert.fingerprint,
                "common_name": cert.common_name,
                "issued_at": iso_utc(cert.issued_at),
                "expires_at": iso_utc(cert.expires_at),
                "status": cert.status,
                "revoked_at": iso_utc(cert.revoked_at),
                "expiring_soon": cert.status == "active"
                and cert.expires_at
                and (cert.expires_at - datetime.utcnow()).days <= 30,
            }
            for cert in certs
        ]
    }


@router.post("/certificates/{cert_id}/revoke")
async def revoke_certificate(
    cert_id: str,
    db: Session = Depends(get_db),
    admin_user=Depends(get_admin_user),
):
    """Revoke an agent certificate."""
    cert = db.query(AgentCertificate).filter(AgentCertificate.id == cert_id).first()
    if not cert:
        raise HTTPException(status_code=404, detail="Certificate not found")

    if cert.status == "revoked":
        raise HTTPException(status_code=409, detail="Certificate already revoked")

    cert.status = "revoked"
    cert.revoked_at = datetime.utcnow()

    # Update agent's cert tracking if this was their active cert
    agent = db.query(Agent).filter(Agent.id == cert.agent_id).first()
    if agent and agent.cert_fingerprint == cert.fingerprint:
        agent.cert_fingerprint = None
        agent.cert_expires_at = None
        agent.mtls_enabled = False

    db.commit()

    log_activity(
        db,
        admin_user,
        action="pki_cert_revoked",
        resource_type="certificate",
        resource_id=cert_id,
        details={
            "agent_id": cert.agent_id,
            "common_name": cert.common_name,
            "fingerprint": cert.fingerprint,
        },
    )

    return {"message": "Certificate revoked", "id": cert_id}


@router.post("/renew")
async def renew_certificate(
    body: dict,
    agent: Agent = Depends(verify_agent_api_key),
    db: Session = Depends(get_db),
):
    """Agent submits CSR for certificate renewal."""
    csr_pem = body.get("csr")
    if not isinstance(csr_pem, str) or not csr_pem:
        raise HTTPException(status_code=400, detail="CSR required")

    pki = get_pki_manager(db)
    if not pki:
        raise HTTPException(status_code=503, detail="CA not initialized")

    try:
        result = pki.sign_csr(csr_pem.encode(), agent.hostname)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    retire_agent_certificates(db, agent.id)
    # Record new certificate
    cert_record = AgentCertificate(
        agent_id=agent.id,
        serial_number=result["serial"],
        fingerprint=result["fingerprint"],
        common_name=agent.hostname,
        expires_at=result["expires_at"],
    )
    db.add(cert_record)

    # Update agent tracking
    agent.cert_fingerprint = result["fingerprint"]
    agent.cert_expires_at = result["expires_at"]
    db.commit()

    logger.info(f"Renewed certificate for agent {agent.hostname}")

    return {
        "cert_pem": result["cert_pem"],
        "fingerprint": result["fingerprint"],
        "expires_at": iso_utc(result["expires_at"]),
    }
