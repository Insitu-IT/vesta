"""
Public endpoints: health, version, bootstrap, metrics and installed capabilities.
Compatibility inventory requires a persisted user; other handlers are public.
"""

from fastapi import APIRouter, Depends, Request, HTTPException
from fastapi.responses import Response, JSONResponse
import os
from sqlalchemy import text
from sqlalchemy.orm import Session

from database import get_db
from deps import get_current_user
from models import Agent, User
from core.tenant_context import PlatformContext
from version import API_SERVICE_NAME, __version__, get_version_info, check_compatibility
from core import metrics

from core.licensing import features

router = APIRouter(tags=["public"])


@router.get("/health")
async def health_check():
    """Shallow liveness check — always 200 while the process is up.

    Must stay dependency-free: liveness gates pod restarts, and coupling it to
    an external dependency (DB/S3) turns a dependency outage into a restart
    kill-loop. Deep dependency checks belong in /ready.
    """
    return {"status": "ok", "service": API_SERVICE_NAME}


@router.get("/ready")
def readiness_check(db: Session = Depends(get_db)):
    """Deep readiness check — verifies required dependencies (PostgreSQL).

    Readiness gates Service endpoints, so a Postgres outage drains traffic from
    the pod instead of masking the degradation behind 'Running 1/1'. Liveness
    must NOT use this endpoint (a DB outage should drain, not kill-loop).
    """
    checks: dict = {}
    ready = True

    # PostgreSQL — required. Bound the probe query with a server-side
    # statement_timeout so a degraded backing store returns 503 *fast* instead of
    # hanging past the probe timeout (which would read as a probe failure anyway,
    # but slowly). Postgres-only; harmless to skip on SQLite (tests).
    try:
        # Installation probe only: no tenant tables or caller-selected SQL.
        # End scope before returning; no mutable tenant work runs here.
        with PlatformContext():
            if db.get_bind().dialect.name == "postgresql":
                db.execute(text("SET LOCAL statement_timeout = '2000ms'"))
            db.execute(text("SELECT 1"))
        checks["database"] = {"status": "ok", "required": True}
    except Exception:
        ready = False
        checks["database"] = {
            "status": "error",
            "required": True,
            "code": "DATABASE_UNAVAILABLE",
        }

    body = {"status": "ready" if ready else "not_ready", "checks": checks}
    if not ready:
        return JSONResponse(status_code=503, content=body)
    return body


@router.get("/api/v1/version")
async def get_version():
    """Get API version information"""
    return get_version_info()


@router.get("/metrics")
async def prometheus_metrics():
    """Prometheus metrics endpoint for monitoring"""
    if os.getenv("METRICS_ENABLED", "true").lower() != "true":
        raise HTTPException(status_code=404, detail="Not found")
    return Response(
        content=metrics.get_metrics(), media_type=metrics.get_content_type()
    )


@router.get("/api/v1/compatibility")
async def get_compatibility(
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Check API/frontend and online agents owned by the persisted user's organization.

    Returns overall system compatibility status and per-component details.
    Frontend can pass its version via X-Frontend-Version header.
    """
    api_info = get_version_info()
    warnings = []
    overall_status = "aligned"

    # Check frontend version from header
    frontend_version = request.headers.get("X-Frontend-Version")
    frontend_compat = None
    if frontend_version:
        frontend_compat = check_compatibility(frontend_version)
        frontend_compat["version"] = frontend_version
        if frontend_compat["status"] == "incompatible":
            overall_status = "incompatible"
            warnings.append(
                f"Frontend {frontend_version} incompatible with API {__version__}"
            )
        elif frontend_compat["status"] == "degraded" and overall_status == "aligned":
            overall_status = "degraded"
            warnings.append(
                f"Frontend {frontend_version} may have limited compatibility with API {__version__}"
            )
    else:
        overall_status = "degraded"
        warnings.append("Frontend version not supplied; alignment is unverified")

    # Explicit ownership predicate supplements RLS; platform authority does not
    # turn this tenant inventory into an installation-wide read.
    agents_compat = []
    try:
        agents = (
            db.query(Agent)
            .filter(Agent.status == "online", Agent.org_id == current_user.org_id)
            .all()
        )
        for agent in agents:
            agent_version = agent.version or "unknown"
            compat = check_compatibility(agent_version)
            agents_compat.append(
                {
                    "hostname": agent.hostname,
                    "version": agent_version,
                    "compatible": compat["compatible"],
                    "status": compat["status"],
                    "reason": compat["reason"],
                }
            )
            if compat["status"] == "incompatible":
                overall_status = "incompatible"
                warnings.append(
                    f"Agent {agent.hostname} ({agent_version}) incompatible with API {__version__}"
                )
            elif compat["status"] == "degraded" and overall_status == "aligned":
                overall_status = "degraded"
                warnings.append(
                    f"Agent {agent.hostname} ({agent_version}) may have limited compatibility"
                )
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(503, "Compatibility inventory unavailable") from None

    return {
        "contract_version": 6,
        "scope": "organization-online-agents",
        "organization_id": current_user.org_id,
        "status": overall_status,
        "api": {
            "version": api_info["version"],
            "major": api_info["major"],
            "minor": api_info["minor"],
            "patch": api_info["patch"],
        },
        "frontend": frontend_compat,
        "agents": agents_compat,
        "expected_version": api_info["expected_compatible"],
        "warnings": warnings,
        "degraded_mode": overall_status != "aligned",
    }


def _local_oidc_login_available(db: Session) -> bool:
    """Read the same local config and organization binding as OIDC login.

    No discovery, issuer contact or certificate evaluation belongs here.
    """
    from core.settings_service import SettingsService
    from core.tenant_context import _validate_org_id
    from models import Organization, OrganizationDefault

    with PlatformContext():
        config = SettingsService(db).get_oidc_config()
        if not config:
            return False
        if features.profile.auth_mode == "multi_organization":
            org_id = os.getenv("OIDC_ORGANIZATION_ID")
            try:
                if not org_id or org_id == "default":
                    return False
                _validate_org_id(org_id)
            except ValueError:
                return False
        else:
            default = db.get(OrganizationDefault, "oss")
            org_id = default.org_id if default is not None else None
        organization = db.get(Organization, org_id) if org_id else None
        return bool(organization is not None and organization.enabled)


@router.get("/api/v1/bootstrap")
def get_bootstrap(db: Session = Depends(get_db)):
    """Minimal prelogin installation data without license or customer details."""
    return {
        "schema_version": 1,
        "edition": features.profile.edition,
        "auth_mode": features.profile.auth_mode,
        "login_methods": {"password": True, "oidc": _local_oidc_login_available(db)},
    }


@router.get("/api/v1/features")
async def get_features():
    """
    Report configured versus successfully loaded installed capabilities.

    License status is advisory. The installed distribution determines these flags.
    """
    return {
        "edition": features.get_edition_name(),
        "tier": "oss" if features.profile.edition == "community" else "commercial",
        "tier_source": "installed_distribution",
        "installed_profile": features.profile.public(),
        "license_enforcement": "advisory",
        "features": features.get_available_features(),
        "configured_modules": sorted(features.profile.enabled_modules),
        "loaded_modules": features.get_loaded_modules(),
        # Explicit feature flags for frontend convenience
        "flags": {
            "multi_tenancy": features.multi_tenancy,
            "white_labeling": features.white_labeling,
            "billing_api": features.billing_api,
            "advanced_rbac": features.advanced_rbac,
            "compliance_reports": features.compliance_reports,
            "client_encryption": features.client_encryption,
        },
    }


@router.get("/api/v1/license/info")
async def get_license_info():
    """Report the capabilities of this installation. License information is advisory."""
    return {
        "tier": "oss" if features.profile.edition == "community" else "commercial",
        "tier_source": "installed_distribution",
        "installed_profile": features.profile.public(),
        "license_enforcement": "advisory",
        "edition_name": features.get_edition_name(),
        "features": {
            # MSP Features
            "multi_tenancy": features.multi_tenancy,
            "white_labeling": features.white_labeling,
            "billing_api": features.billing_api,
            "advanced_rbac": features.advanced_rbac,
            "client_encryption": features.client_encryption,
            # Enterprise Features
            "compliance_reports": features.compliance_reports,
            "vault_integration": features.vault_integration,
            "ldap_auth": features.ldap_auth,
            "saml_auth": features.saml_auth,
            "dr_orchestration": features.dr_orchestration,
            "storage_tiering": features.storage_tiering,
            "hsm_support": features.hsm_support,
        },
    }
