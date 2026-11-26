"""
v3.0 OIDC Authentication Service

Provides OpenID Connect authentication with:
- JIT (Just-In-Time) user provisioning
- Hybrid role mapping (OIDC claim or admin-pinned)
- Session management

Usage:
    from core.oidc_service import oidc_service

    # Get login redirect URL
    url = await oidc_service.get_login_url(callback_url)

    # Handle callback
    token_data = await oidc_service.handle_callback(code, state, callback_url)

    # Get or create user from token
    user = await oidc_service.get_or_create_user(token_data, db)
"""

import logging
import httpx
import hashlib
import base64
import secrets
import time
import math
from typing import Optional, Dict, Any, Tuple
from datetime import datetime
import jwt
from urllib.parse import urlencode, urlsplit

logger = logging.getLogger(__name__)


class OIDCService:
    """OpenID Connect authentication service."""

    def __init__(self):
        self._config: Optional[Dict] = None
        self._discovery_cache: Optional[Dict] = None

    @staticmethod
    def validate_endpoint(value: str, *, issuer: bool = False) -> None:
        """Never send credentials to plaintext or credential-bearing URLs."""
        parsed = urlsplit(value)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username
            or parsed.password
            or (issuer and parsed.query)
            or parsed.fragment
        ):
            raise ValueError("Invalid HTTPS OIDC endpoint")

    @classmethod
    def validate_discovery(cls, discovery: Dict, issuer: str) -> None:
        if discovery.get("issuer") != issuer:
            raise ValueError("OIDC discovery issuer mismatch")
        for name in ("issuer", "authorization_endpoint", "token_endpoint"):
            cls.validate_endpoint(discovery.get(name, ""), issuer=name == "issuer")
        for name in ("userinfo_endpoint", "jwks_uri"):
            if discovery.get(name):
                cls.validate_endpoint(discovery[name])

    def configure(self, config: Dict) -> None:
        """Configure OIDC from SettingsService.get_oidc_config()."""
        if not config or not config.get("enabled"):
            self._config = None
            self._discovery_cache = None
            return

        self._config = config
        self._discovery_cache = None  # Force re-discovery
        logger.info("OIDC configuration loaded")

    @property
    def is_configured(self) -> bool:
        """Check if OIDC is properly configured."""
        return self._config is not None and self._config.get("enabled")

    def generate_pkce(self) -> Tuple[str, str]:
        """Generate PKCE code_verifier and code_challenge (S256).

        Returns:
            Tuple of (code_verifier, code_challenge)
        """
        # Generate random code_verifier (43-128 chars, URL-safe)
        code_verifier = secrets.token_urlsafe(32)

        # Compute code_challenge = BASE64URL(SHA256(code_verifier))
        digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
        code_challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")

        return code_verifier, code_challenge

    async def get_discovery_document(self) -> Optional[Dict]:
        """Fetch OpenID Connect discovery document from issuer."""
        if not self._config:
            return None

        if self._discovery_cache:
            return self._discovery_cache

        issuer = self._config.get("issuer", "").rstrip("/")
        discovery_url = f"{issuer}/.well-known/openid-configuration"

        try:
            self.validate_endpoint(issuer, issuer=True)
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.get(discovery_url)
                response.raise_for_status()
                discovery = response.json()
                self.validate_discovery(discovery, issuer)
                self._discovery_cache = discovery
                logger.debug("OIDC discovery successful")
                return self._discovery_cache
        except Exception:
            logger.error("OIDC discovery failed")
            return None

    async def get_login_url(
        self, callback_url: str, state: str, code_challenge: str
    ) -> Optional[str]:
        """Generate OIDC authorization URL for login redirect.

        Args:
            callback_url: Full URL for OIDC callback (e.g., https://app/api/v1/auth/oidc/callback)
            state: Random state for CSRF protection
            code_challenge: PKCE code_challenge (S256)

        Returns:
            Authorization URL to redirect user to, or None if not configured
        """
        discovery = await self.get_discovery_document()
        if not discovery:
            return None

        auth_endpoint = discovery.get("authorization_endpoint")
        if not auth_endpoint:
            logger.error("No authorization_endpoint in discovery document")
            return None

        params = {
            "client_id": self._config.get("client_id"),
            "redirect_uri": callback_url,
            "response_type": "code",
            "scope": self._config.get("scopes", "openid profile email"),
            "state": state,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
        }

        return f"{auth_endpoint}?{urlencode(params)}"

    async def handle_callback(
        self, code: str, callback_url: str, code_verifier: str
    ) -> Tuple[Optional[Dict], Optional[str]]:
        """Exchange authorization code for tokens and user info.

        Args:
            code: Authorization code from callback
            callback_url: Same callback URL used in login request
            code_verifier: PKCE code_verifier (must match code_challenge from login)

        Returns:
            Tuple of (token_data dict, error message) - one will be None
        """
        discovery = await self.get_discovery_document()
        if not discovery:
            return None, "OIDC not configured"

        token_endpoint = discovery.get("token_endpoint")
        if not token_endpoint:
            return None, "No token_endpoint in discovery"

        try:
            # Verification is deliberately left at httpx's default (on). The trust
            # store comes from SSL_CERT_FILE, which the deployment points at the
            # cluster's trusted-ca-bundle — that is what lets an internal issuer
            # verify. Turning it off here would put client_secret, the auth code and
            # the PKCE code_verifier on an unauthenticated channel, and would also
            # remove the precondition the id_token handling below depends on.
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.post(
                    token_endpoint,
                    data={
                        "grant_type": "authorization_code",
                        "code": code,
                        "redirect_uri": callback_url,
                        "client_id": self._config.get("client_id"),
                        "client_secret": self._config.get("client_secret"),
                        "code_verifier": code_verifier,
                    },
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                )

                if response.status_code != 200:
                    logger.error("OIDC token exchange rejected")
                    return None, "OIDC token exchange rejected"

                tokens = response.json()

        except Exception:
            logger.error("OIDC token exchange failed")
            return None, "OIDC token exchange failed"

        # The id_token signature is not checked here, which OIDC Core 1.0 §3.1.3.7
        # item 6 permits: this is the authorization-code flow, so the token arrives
        # over direct client-to-token-endpoint communication, and validated TLS
        # server identity MAY stand in for checking the signature.
        #
        # That permission is conditional on the TLS validation actually happening.
        # It is therefore load-bearing that the request above verifies — these two
        # are one mechanism split across thirty lines, and disabling verification
        # there silently invalidates the reasoning here rather than this line.
        # Anything obtained other than straight from the token endpoint must have
        # its signature verified against the issuer's JWKs.
        id_token = tokens.get("id_token")
        if not id_token:
            return None, "No id_token in response"

        try:
            claims = jwt.decode(
                id_token,
                options={
                    "verify_signature": False,
                    "verify_exp": False,
                    "verify_aud": False,
                    "verify_iss": False,
                    "verify_nbf": False,
                    "verify_iat": False,
                },
            )
            self.validate_token_claims(claims)
        except Exception:
            logger.error("Invalid OIDC identity token")
            return None, "Invalid OIDC identity token"

        # Build token data with claims
        token_data = {
            "access_token": tokens.get("access_token"),
            "id_token": id_token,
            "refresh_token": tokens.get("refresh_token"),
            "sub": claims.get("sub"),
            "email": claims.get("email"),
            "name": claims.get("name") or claims.get("preferred_username"),
            "issuer": claims.get("iss"),
            "claims": claims,
        }

        return token_data, None

    def validate_token_claims(self, claims):
        """TLS-authenticated code exchange still requires issuer/audience/time checks."""
        if not self._config or claims.get("iss") != self._config["issuer"]:
            raise ValueError("OIDC issuer mismatch")
        audience = claims.get("aud")
        audiences = [audience] if isinstance(audience, str) else audience
        if (
            not isinstance(audiences, list)
            or self._config["client_id"] not in audiences
        ):
            raise ValueError("OIDC audience mismatch")
        if (len(audiences) > 1 or "azp" in claims) and claims.get(
            "azp"
        ) != self._config["client_id"]:
            raise ValueError("OIDC authorized party mismatch")
        expiry = claims.get("exp")
        if (
            isinstance(expiry, bool)
            or not isinstance(expiry, (int, float))
            or not math.isfinite(expiry)
            or expiry <= time.time()
        ):
            raise ValueError("OIDC token expired or missing expiry")
        if not isinstance(claims.get("sub"), str) or not claims["sub"].strip():
            raise ValueError("OIDC subject missing")

    def map_role(self, claims: Dict) -> str:
        """Map OIDC claims to vnbui role.

        Uses configured role_claim and value mappings.
        Returns 'viewer' if no mapping found.
        """
        default_role = self._config.get("default_role", "viewer")
        if default_role not in ("viewer", "operator"):
            raise ValueError("Invalid OIDC default role")
        role_claim = self._config.get("role_claim")
        if not role_claim:
            return default_role
        if not isinstance(role_claim, str):
            raise ValueError("Invalid OIDC role claim configuration")

        # Resolve the claim value — supports nested dot-paths such as
        # "realm_access.roles" (Keycloak's default token shape), as well as flat keys.
        claim_value = self._resolve_claim(claims, role_claim)
        if claim_value is None:
            claim_value = []
        if isinstance(claim_value, str):
            claim_value = [claim_value]
        if not isinstance(claim_value, list) or any(
            not isinstance(value, str) for value in claim_value
        ):
            raise ValueError("Invalid OIDC role claim")
        if any(
            not isinstance(self._config.get(key, ""), str)
            for key in ("admin_values", "operator_values")
        ):
            raise ValueError("Invalid OIDC role mapping")

        # Check admin mapping
        admin_values = self._config.get("admin_values", "").split(",")
        admin_values = [v.strip() for v in admin_values if v.strip()]
        for value in claim_value:
            if value in admin_values:
                return "admin"

        # Check operator mapping
        operator_values = self._config.get("operator_values", "").split(",")
        operator_values = [v.strip() for v in operator_values if v.strip()]
        for value in claim_value:
            if value in operator_values:
                return "operator"

        return default_role

    @staticmethod
    def _resolve_claim(claims: Dict, path: str) -> Any:
        """Resolve a claim by dot-path, supporting nested objects.

        OIDC providers differ in token shape: Keycloak nests realm roles under
        realm_access.roles, while a custom protocol mapper may emit a flat
        top-level claim. A literal key wins first (some IdPs really do emit a
        claim whose name contains dots); otherwise the path is traversed segment
        by segment. Returns None if any segment is missing or a segment is not an
        object, so map_role falls back to default_role.
        """
        # Exact/flat key wins (handles claim names that literally contain dots).
        if path in claims:
            return claims[path]

        node: Any = claims
        for part in path.split("."):
            if isinstance(node, dict) and part in node:
                node = node[part]
            else:
                return None
        return node

    async def get_or_create_user(
        self, token_data: Dict, db, *, commit: bool = True
    ) -> Tuple[Any, bool]:
        """Get existing user or create new one from OIDC token data.

        Implements JIT provisioning with hybrid role mapping:
        - If user has role_source='oidc', role is updated from claims on each login
        - If user has role_source='local', role is preserved (admin-pinned)

        Args:
            token_data: Token data from handle_callback()
            db: Database session

        Returns:
            Tuple of (User object, is_new_user bool)
        """
        from models import User, Organization
        from core.tenant_context import resolved_organization

        org_id = resolved_organization()
        # Unsupported legacy defaults require explicit administrator repair;
        # neither an existing pin nor a matching claim makes that config valid.
        if (self._config or {}).get("default_role", "viewer") not in (
            "viewer",
            "operator",
        ):
            raise ValueError("Invalid OIDC default role")
        organization = db.get(Organization, org_id)
        if organization is None or not organization.enabled:
            raise ValueError("OIDC organization unavailable")

        sub = token_data.get("sub")
        issuer = token_data.get("issuer")
        email = token_data.get("email")
        name = token_data.get("name")
        claims = token_data.get("claims", {})

        if not isinstance(sub, str) or not sub.strip() or not issuer:
            raise ValueError("Missing sub or issuer in token data")
        if not self._config or issuer != self._config["issuer"]:
            raise ValueError("OIDC issuer does not match configured identity source")

        # Look up by OIDC subject+issuer
        user = (
            db.query(User)
            .filter(
                User.org_id == org_id,
                User.oidc_subject == sub,
                User.oidc_issuer == issuer,
            )
            .one_or_none()
        )

        is_new = False
        if not user:
            # JIT provisioning: create new user
            # Generate username from email or sub
            username = email.split("@")[0] if email else f"oidc_{sub[:8]}"

            # Check for username collision
            existing = (
                db.query(User)
                .filter(User.org_id == org_id, User.username == username)
                .one_or_none()
            )
            if existing:
                # Append random suffix
                import secrets

                username = f"{username}_{secrets.token_hex(4)}"

            # Map role from claims
            role = self.map_role(claims)

            user = User(
                org_id=org_id,
                username=username,
                password_hash="",  # No password for OIDC users
                email=email,
                full_name=name,
                role=role,
                is_active=True,
                auth_source="oidc",
                role_source="oidc",  # Role synced from OIDC by default
                oidc_subject=sub,
                oidc_issuer=issuer,
                is_platform_admin=False,
            )
            db.add(user)
            is_new = True
        else:
            # Existing user - check if active
            if not user.is_active:
                raise ValueError("User account is disabled")
            if user.auth_source != "oidc" or user.role_source not in ("oidc", "local"):
                raise ValueError("Invalid persisted OIDC identity source")

            # Update last login and optionally role
            user.last_login = datetime.utcnow()

            # Update email/name if changed
            if email and user.email != email:
                user.email = email
            if name and user.full_name != name:
                user.full_name = name

            # Update role if role_source is 'oidc' (not admin-pinned)
            if user.role_source == "oidc":
                new_role = self.map_role(claims)
                if user.role != new_role:
                    user.role = new_role

        if commit:
            db.commit()
        else:
            db.flush()
        return user, is_new


# Global instance
oidc_service = OIDCService()
