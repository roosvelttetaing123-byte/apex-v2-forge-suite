"""Dashboard authentication — JWT-based token auth for the War Room.

Provides token generation, validation, and middleware for the
FastAPI dashboard server. Supports operator roles (viewer/operator/admin).
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import secrets
import time
import base64
from dataclasses import dataclass
from enum import Enum
from typing import Any
from urllib.parse import urlencode

log = logging.getLogger("forge.dashboard.auth")

# ── Secret key — generated once per server start ──────────────────────
_SERVER_SECRET: str = secrets.token_hex(32)


class Role(str, Enum):
    """Operator access levels."""
    VIEWER   = "viewer"     # Read-only dashboard access
    OPERATOR = "operator"   # Can issue scan controls (pause/resume/abort)
    ADMIN    = "admin"      # Full access including C2 operations


@dataclass
class TokenPayload:
    """Decoded JWT-like token payload."""
    username: str
    role: Role
    issued_at: float
    expires_at: float
    session_id: str

    def is_expired(self) -> bool:
        return time.time() > self.expires_at

    def has_role(self, required: Role) -> bool:
        role_hierarchy = {Role.VIEWER: 0, Role.OPERATOR: 1, Role.ADMIN: 2}
        return role_hierarchy.get(self.role, 0) >= role_hierarchy.get(required, 0)


@dataclass(frozen=True)
class SSOConfig:
    """OIDC SSO settings loaded from environment."""
    enabled: bool
    provider_name: str
    client_id: str
    client_secret: str
    issuer: str
    authorization_endpoint: str
    token_endpoint: str
    userinfo_endpoint: str
    jwks_uri: str
    redirect_uri: str
    scopes: str
    default_role: Role
    allowed_domains: tuple[str, ...]
    admin_emails: tuple[str, ...]
    operator_groups: tuple[str, ...]
    viewer_groups: tuple[str, ...]
    use_pkce: bool = True

    def public_dict(self) -> dict[str, Any]:
        return {
            "enabled": self.enabled,
            "provider_name": self.provider_name,
            "issuer": self.issuer,
            "authorization_endpoint": self.authorization_endpoint,
            "redirect_uri": self.redirect_uri,
            "scopes": self.scopes,
            "use_pkce": self.use_pkce,
        }


# ── Default credentials (override via environment) ────────────────────
_DEFAULT_USERS: dict[str, dict[str, str]] = {
    "operator": {
        "password_hash": hashlib.sha256(b"forge2026").hexdigest(),
        "role": "admin",
    },
}


def _get_users() -> dict[str, dict[str, str]]:
    """Get user database — defaults + environment overrides."""
    users = dict(_DEFAULT_USERS)
    env_pass = os.environ.get("FORGE_DASHBOARD_PASSWORD")
    if env_pass:
        users["operator"]["password_hash"] = hashlib.sha256(
            env_pass.encode()
        ).hexdigest()
    return users


def _hmac_sign(payload_json: str) -> str:
    """Sign a payload string with HMAC-SHA256."""
    return hmac.new(
        _SERVER_SECRET.encode(), payload_json.encode(), hashlib.sha256,
    ).hexdigest()


def issue_identity_token(
    username: str,
    role: Role | str = Role.VIEWER,
    ttl_hours: float = 24.0,
    claims: dict[str, Any] | None = None,
) -> str:
    """Issue a dashboard token for a previously authenticated identity."""
    resolved_role = role if isinstance(role, Role) else Role(str(role))
    now = time.time()
    payload = {
        "username": username,
        "role": resolved_role.value,
        "iat": now,
        "exp": now + (ttl_hours * 3600),
        "sid": secrets.token_hex(8),
    }
    if claims:
        payload["claims"] = {
            key: value
            for key, value in claims.items()
            if key in {"iss", "sub", "email", "name", "preferred_username"}
        }
    payload_json = json.dumps(payload, separators=(",", ":"))
    b64_payload = base64.urlsafe_b64encode(payload_json.encode()).decode()
    signature = _hmac_sign(payload_json)
    log.info("Token issued for '%s' (role=%s, ttl=%.1fh)", username, resolved_role.value, ttl_hours)
    return f"{b64_payload}.{signature}"


def generate_token(
    username: str,
    password: str,
    ttl_hours: float = 24.0,
) -> str | None:
    """Authenticate and generate a bearer token.

    Args:
        username: Login username.
        password: Plain text password.
        ttl_hours: Token time-to-live in hours.

    Returns:
        Token string on success, None on auth failure.
    """
    users = _get_users()
    user = users.get(username)
    if not user:
        log.warning("Auth failed: unknown user '%s'", username)
        return None

    pw_hash = hashlib.sha256(password.encode()).hexdigest()
    if not hmac.compare_digest(pw_hash, user["password_hash"]):
        log.warning("Auth failed: bad password for '%s'", username)
        return None

    return issue_identity_token(username, Role(user["role"]), ttl_hours=ttl_hours)


def validate_token(token: str) -> TokenPayload | None:
    """Validate a bearer token and return the payload.

    Args:
        token: The bearer token string.

    Returns:
        TokenPayload on success, None on validation failure.
    """
    try:
        parts = token.split(".")
        if len(parts) != 2:
            return None
        b64_payload, signature = parts
        import base64
        payload_json = base64.urlsafe_b64decode(b64_payload).decode()
        expected_sig = _hmac_sign(payload_json)
        if not hmac.compare_digest(signature, expected_sig):
            log.warning("Token validation failed: bad signature")
            return None
        payload = json.loads(payload_json)
        tp = TokenPayload(
            username=payload["username"],
            role=Role(payload["role"]),
            issued_at=payload["iat"],
            expires_at=payload["exp"],
            session_id=payload["sid"],
        )
        if tp.is_expired():
            log.debug("Token expired for '%s'", tp.username)
            return None
        return tp
    except Exception as exc:
        log.debug("Token validation error: %s", exc)
        return None


def require_role(token: str | None, role: Role) -> TokenPayload | None:
    """Validate token AND check role permission.

    Returns TokenPayload if valid + authorized, None otherwise.
    """
    if not token:
        return None
    payload = validate_token(token)
    if not payload:
        return None
    if not payload.has_role(role):
        log.warning("Role check failed: '%s' needs %s, has %s",
                     payload.username, role.value, payload.role.value)
        return None
    return payload


# ── SSO / OIDC helpers ────────────────────────────────────────────────

_SSO_STATES: dict[str, dict[str, Any]] = {}
_SSO_LOGIN_CODES: dict[str, dict[str, Any]] = {}


def _env_bool(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _csv_env(name: str) -> tuple[str, ...]:
    return tuple(
        item.strip().lower()
        for item in os.environ.get(name, "").split(",")
        if item.strip()
    )


def _role_env(name: str, default: Role) -> Role:
    raw = os.environ.get(name, default.value).strip().lower()
    try:
        return Role(raw)
    except ValueError:
        log.warning("Invalid %s=%r; falling back to %s", name, raw, default.value)
        return default


def get_sso_config() -> SSOConfig:
    """Return current OIDC SSO settings from environment."""
    issuer = os.environ.get("FORGE_SSO_ISSUER", "").rstrip("/")
    auth_url = os.environ.get("FORGE_SSO_AUTH_URL", "")
    token_url = os.environ.get("FORGE_SSO_TOKEN_URL", "")
    userinfo_url = os.environ.get("FORGE_SSO_USERINFO_URL", "")
    jwks_uri = os.environ.get("FORGE_SSO_JWKS_URI", "")
    client_id = os.environ.get("FORGE_SSO_CLIENT_ID", "")
    client_secret = os.environ.get("FORGE_SSO_CLIENT_SECRET", "")
    enabled = _env_bool("FORGE_SSO_ENABLED") and bool(client_id and auth_url and token_url)
    return SSOConfig(
        enabled=enabled,
        provider_name=os.environ.get("FORGE_SSO_PROVIDER_NAME", "SSO"),
        client_id=client_id,
        client_secret=client_secret,
        issuer=issuer,
        authorization_endpoint=auth_url,
        token_endpoint=token_url,
        userinfo_endpoint=userinfo_url,
        jwks_uri=jwks_uri,
        redirect_uri=os.environ.get("FORGE_SSO_REDIRECT_URI", ""),
        scopes=os.environ.get("FORGE_SSO_SCOPES", "openid email profile"),
        default_role=_role_env("FORGE_SSO_DEFAULT_ROLE", Role.OPERATOR),
        allowed_domains=_csv_env("FORGE_SSO_ALLOWED_DOMAINS"),
        admin_emails=_csv_env("FORGE_SSO_ADMIN_EMAILS"),
        operator_groups=_csv_env("FORGE_SSO_OPERATOR_GROUPS"),
        viewer_groups=_csv_env("FORGE_SSO_VIEWER_GROUPS"),
        use_pkce=_env_bool("FORGE_SSO_PKCE", True),
    )


def configure_sso_from_discovery(discovery: dict[str, Any]) -> None:
    """Populate missing OIDC endpoint env vars from discovery metadata."""
    for env_name, claim_name in (
        ("FORGE_SSO_AUTH_URL", "authorization_endpoint"),
        ("FORGE_SSO_TOKEN_URL", "token_endpoint"),
        ("FORGE_SSO_USERINFO_URL", "userinfo_endpoint"),
        ("FORGE_SSO_JWKS_URI", "jwks_uri"),
    ):
        if not os.environ.get(env_name) and discovery.get(claim_name):
            os.environ[env_name] = str(discovery[claim_name])


def cleanup_sso_states(now: float | None = None) -> None:
    now = now or time.time()
    expired = [state for state, data in _SSO_STATES.items() if data.get("expires_at", 0) < now]
    for state in expired:
        _SSO_STATES.pop(state, None)
    expired_codes = [code for code, data in _SSO_LOGIN_CODES.items() if data.get("expires_at", 0) < now]
    for code in expired_codes:
        _SSO_LOGIN_CODES.pop(code, None)


def build_sso_authorization_url(
    redirect_uri: str,
    next_path: str = "/",
    ttl_seconds: int = 600,
) -> str:
    """Build an OIDC authorization URL and remember callback state."""
    cfg = get_sso_config()
    if not cfg.enabled:
        raise RuntimeError("SSO is not enabled or is missing required endpoints")
    cleanup_sso_states()
    state = secrets.token_urlsafe(24)
    nonce = secrets.token_urlsafe(16)
    code_verifier = secrets.token_urlsafe(48)
    _SSO_STATES[state] = {
        "nonce": nonce,
        "next": next_path if next_path.startswith("/") else "/",
        "redirect_uri": redirect_uri,
        "code_verifier": code_verifier,
        "expires_at": time.time() + ttl_seconds,
    }
    params = {
        "client_id": cfg.client_id,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": cfg.scopes,
        "state": state,
        "nonce": nonce,
    }
    if cfg.use_pkce:
        digest = hashlib.sha256(code_verifier.encode()).digest()
        params["code_challenge"] = base64.urlsafe_b64encode(digest).decode().rstrip("=")
        params["code_challenge_method"] = "S256"
    return f"{cfg.authorization_endpoint}?{urlencode(params)}"


def consume_sso_state(state: str) -> dict[str, Any] | None:
    cleanup_sso_states()
    data = _SSO_STATES.pop(state, None)
    if not data or data.get("expires_at", 0) < time.time():
        return None
    return data


def issue_sso_login_code(token: str, ttl_seconds: int = 60) -> str:
    cleanup_sso_states()
    code = secrets.token_urlsafe(24)
    _SSO_LOGIN_CODES[code] = {
        "token": token,
        "expires_at": time.time() + ttl_seconds,
    }
    return code


def consume_sso_login_code(code: str) -> str | None:
    cleanup_sso_states()
    data = _SSO_LOGIN_CODES.pop(code, None)
    if not data or data.get("expires_at", 0) < time.time():
        return None
    return str(data.get("token") or "")


def role_from_sso_claims(claims: dict[str, Any], cfg: SSOConfig | None = None) -> Role:
    """Map SSO claims to dashboard role without trusting client input."""
    cfg = cfg or get_sso_config()
    email = str(claims.get("email") or "").lower()
    groups_raw = claims.get("groups") or claims.get("roles") or []
    if isinstance(groups_raw, str):
        groups = {groups_raw.lower()}
    else:
        groups = {str(group).lower() for group in groups_raw}

    if email and cfg.allowed_domains:
        domain = email.rsplit("@", 1)[-1]
        if domain not in cfg.allowed_domains:
            return Role.VIEWER

    if email in cfg.admin_emails:
        return Role.ADMIN
    if groups.intersection(cfg.operator_groups):
        return Role.OPERATOR
    if groups.intersection(cfg.viewer_groups):
        return Role.VIEWER
    return cfg.default_role


class TestDashboardAuth:
    """Unit tests for dashboard auth."""

    def test_generate_and_validate(self) -> None:
        token = generate_token("operator", "forge2026")
        assert token is not None
        payload = validate_token(token)
        assert payload is not None
        assert payload.username == "operator"
        assert payload.role == Role.ADMIN

    def test_bad_password(self) -> None:
        token = generate_token("operator", "wrong")
        assert token is None

    def test_unknown_user(self) -> None:
        token = generate_token("nobody", "password")
        assert token is None

    def test_role_hierarchy(self) -> None:
        token = generate_token("operator", "forge2026")
        assert token is not None
        # Admin should pass viewer check
        payload = require_role(token, Role.VIEWER)
        assert payload is not None
        # Admin should pass operator check
        payload = require_role(token, Role.OPERATOR)
        assert payload is not None
        # Admin should pass admin check
        payload = require_role(token, Role.ADMIN)
        assert payload is not None

    def test_expired_token(self) -> None:
        token = generate_token("operator", "forge2026", ttl_hours=-1)
        assert token is not None
        payload = validate_token(token)
        assert payload is None
