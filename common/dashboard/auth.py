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
import re
import struct
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
    tenant_id: str

    def is_expired(self) -> bool:
        return time.time() >= self.expires_at

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


_HASH_ALGORITHM = "pbkdf2_sha256"
_PBKDF2_ITERATIONS = 260_000
_AUTH_FAILURES: dict[str, dict[str, float | int]] = {}
_TENANT_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,99}$")


def _identity_log_ref(username: Any) -> str:
    """Return a stable opaque identifier for logs/audit denial correlation."""
    raw = str(username or "").encode("utf-8", errors="replace")
    return f"identity:{hashlib.sha256(raw).hexdigest()[:16]}"


def _token_tenant_id(value: str | None = None) -> str:
    raw_value = (
        value if value is not None else os.environ.get("FORGE_TENANT_ID", "default")
    )
    tenant_id = str(raw_value).strip()
    if value is None and not tenant_id:
        tenant_id = "default"
    if not _TENANT_ID_RE.fullmatch(tenant_id):
        raise ValueError("invalid dashboard tenant identifier")
    return tenant_id


def _hash_password(password: str, salt: str | None = None) -> str:
    """Return a salted password verifier suitable for local dashboard auth."""
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("ascii"),
        _PBKDF2_ITERATIONS,
    ).hex()
    return f"{_HASH_ALGORITHM}${_PBKDF2_ITERATIONS}${salt}${digest}"


def _verify_password(password: str, password_hash: str) -> bool:
    """Verify a dashboard password hash.

    Supports local PBKDF2 hashes plus Argon2/bcrypt hashes when the matching
    optional library is installed. Plain SHA-256 remains only for legacy
    externally supplied env hashes.
    """
    if password_hash.startswith(f"{_HASH_ALGORITHM}$"):
        try:
            _, iterations_raw, salt, expected = password_hash.split("$", 3)
            iterations = int(iterations_raw)
            digest = hashlib.pbkdf2_hmac(
                "sha256",
                password.encode("utf-8"),
                salt.encode("ascii"),
                iterations,
            ).hex()
            return hmac.compare_digest(digest, expected)
        except (ValueError, TypeError):
            return False

    if password_hash.startswith("$argon2"):
        try:
            from argon2 import PasswordHasher
            from argon2.exceptions import VerifyMismatchError, VerificationError
            try:
                return bool(PasswordHasher().verify(password_hash, password))
            except (VerifyMismatchError, VerificationError):
                return False
        except ImportError:
            log.warning("Argon2 password hash configured but argon2-cffi is not installed")
            return False

    if password_hash.startswith(("$2a$", "$2b$", "$2y$")):
        try:
            import bcrypt
            return bool(bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("utf-8")))
        except ImportError:
            log.warning("bcrypt password hash configured but bcrypt is not installed")
            return False

    # Legacy compatibility for externally supplied SHA-256 hashes only.
    legacy_hash = hashlib.sha256(password.encode()).hexdigest()
    return hmac.compare_digest(legacy_hash, password_hash)


def _auth_lockout_key(username: str) -> str:
    return username.strip().lower() or "<empty>"


def _lockout_config() -> tuple[int, int, int]:
    def _int_env(name: str, default: int) -> int:
        try:
            return max(int(os.environ.get(name, default)), 1)
        except (TypeError, ValueError):
            return default

    return (
        _int_env("FORGE_DASHBOARD_LOCKOUT_ATTEMPTS", 5),
        _int_env("FORGE_DASHBOARD_LOCKOUT_SECONDS", 300),
        _int_env("FORGE_DASHBOARD_RATE_WINDOW_SECONDS", 60),
    )


def _is_locked_out(username: str, now: float | None = None) -> bool:
    now = now or time.time()
    key = _auth_lockout_key(username)
    data = _AUTH_FAILURES.get(key)
    if not data:
        return False
    locked_until = float(data.get("locked_until", 0))
    if locked_until and locked_until > now:
        return True
    if locked_until and locked_until <= now:
        _AUTH_FAILURES.pop(key, None)
    return False


def _record_auth_failure(username: str, now: float | None = None) -> None:
    now = now or time.time()
    attempts, lockout_seconds, window_seconds = _lockout_config()
    key = _auth_lockout_key(username)
    data = _AUTH_FAILURES.get(key, {"count": 0, "first_failure": now, "locked_until": 0})
    if now - float(data.get("first_failure", now)) > window_seconds:
        data = {"count": 0, "first_failure": now, "locked_until": 0}
    data["count"] = int(data.get("count", 0)) + 1
    if int(data["count"]) >= attempts:
        data["locked_until"] = now + lockout_seconds
    _AUTH_FAILURES[key] = data


def _clear_auth_failures(username: str) -> None:
    _AUTH_FAILURES.pop(_auth_lockout_key(username), None)


def _totp_secret_for_user(username: str) -> str:
    env_specific = f"FORGE_DASHBOARD_TOTP_SECRET_{username.strip().upper().replace('-', '_')}"
    return os.environ.get(env_specific, "") or os.environ.get("FORGE_DASHBOARD_TOTP_SECRET", "")


def _totp_code(secret: str, counter: int, digits: int = 6) -> str:
    """Return the RFC 6238 TOTP code for a base32 secret/counter."""
    normalized = "".join(secret.split()).upper()
    padding = "=" * (-len(normalized) % 8)
    key = base64.b32decode((normalized + padding).encode("ascii"), casefold=True)
    msg = struct.pack(">Q", counter)
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(value % (10 ** digits)).zfill(digits)


def verify_totp(username: str, code: str, now: float | None = None) -> bool:
    """Verify an optional dashboard TOTP code for one user."""
    secret = _totp_secret_for_user(username)
    if not secret:
        return True
    supplied = "".join(str(code or "").split())
    if not supplied.isdigit():
        return False
    now = now or time.time()
    step = int(now // 30)
    digits = len(supplied)
    for skew in (-1, 0, 1):
        try:
            if hmac.compare_digest(_totp_code(secret, step + skew, digits=digits), supplied):
                return True
        except Exception:
            log.warning("Invalid dashboard TOTP secret configured")
            return False
    return False


def _get_users() -> dict[str, dict[str, str]]:
    """Get user database from environment.

    Password auth is disabled unless FORGE_DASHBOARD_PASSWORD or
    FORGE_DASHBOARD_PASSWORD_HASH is set. The dashboard has no unauthenticated
    API or WebSocket identity mode.
    """
    env_pass = os.environ.get("FORGE_DASHBOARD_PASSWORD")
    env_hash = os.environ.get("FORGE_DASHBOARD_PASSWORD_HASH")
    if not env_pass and not env_hash:
        return {}

    username = os.environ.get("FORGE_DASHBOARD_USER", "operator").strip() or "operator"
    role_raw = os.environ.get("FORGE_DASHBOARD_ROLE", Role.ADMIN.value).strip().lower()
    try:
        role = Role(role_raw)
    except ValueError:
        log.warning("Invalid FORGE_DASHBOARD_ROLE=%r; falling back to admin", role_raw)
        role = Role.ADMIN

    return {
        username: {
            "password_hash": env_hash or _hash_password(env_pass or ""),
            "role": role.value,
        },
    }


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
    tenant_id: str | None = None,
) -> str:
    """Issue a dashboard token for a previously authenticated identity."""
    resolved_role = role if isinstance(role, Role) else Role(str(role))
    now = time.time()
    payload: dict[str, Any] = {
        "username": username,
        "role": resolved_role.value,
        "iat": now,
        "exp": now + (ttl_hours * 3600),
        "sid": secrets.token_hex(8),
        "tenant_id": _token_tenant_id(tenant_id),
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
    log.info(
        "Token issued for %s (role=%s, ttl=%.1fh)",
        _identity_log_ref(username),
        resolved_role.value,
        ttl_hours,
    )
    return f"{b64_payload}.{signature}"


def generate_token(
    username: str,
    password: str,
    ttl_hours: float = 24.0,
    totp_code: str = "",
) -> str | None:
    """Authenticate and generate a bearer token.

    Args:
        username: Login username.
        password: Plain text password.
        ttl_hours: Token time-to-live in hours.

    Returns:
        Token string on success, None on auth failure.
    """
    if _is_locked_out(username):
        log.warning("Auth failed: %s is temporarily locked out", _identity_log_ref(username))
        return None

    users = _get_users()
    user = users.get(username)
    if not user:
        log.warning("Auth failed: unknown %s", _identity_log_ref(username))
        _record_auth_failure(username)
        return None

    if not _verify_password(password, user["password_hash"]):
        log.warning("Auth failed: bad password for %s", _identity_log_ref(username))
        _record_auth_failure(username)
        return None

    if not verify_totp(username, totp_code):
        log.warning("Auth failed: bad TOTP code for %s", _identity_log_ref(username))
        _record_auth_failure(username)
        return None

    _clear_auth_failures(username)
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
            tenant_id=_token_tenant_id(payload["tenant_id"]),
        )
        if tp.is_expired():
            log.debug("Token expired for %s", _identity_log_ref(tp.username))
            return None
        return tp
    except Exception as exc:
        log.debug("Token validation error reason=%s", type(exc).__name__)
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
        log.warning(
            "Role check failed: %s needs %s, has %s",
            _identity_log_ref(payload.username),
            role.value,
            payload.role.value,
        )
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
        original = os.environ.get("FORGE_DASHBOARD_PASSWORD")
        os.environ["FORGE_DASHBOARD_PASSWORD"] = "test-password"
        try:
            token = generate_token("operator", "test-password")
            assert token is not None
            payload = validate_token(token)
            assert payload is not None
            assert payload.username == "operator"
            assert payload.role == Role.ADMIN
        finally:
            if original is None:
                os.environ.pop("FORGE_DASHBOARD_PASSWORD", None)
            else:
                os.environ["FORGE_DASHBOARD_PASSWORD"] = original

    def test_bad_password(self) -> None:
        os.environ["FORGE_DASHBOARD_PASSWORD"] = "test-password"
        try:
            _clear_auth_failures("operator")
            token = generate_token("operator", "wrong")
            assert token is None
        finally:
            _clear_auth_failures("operator")
            os.environ.pop("FORGE_DASHBOARD_PASSWORD", None)

    def test_unknown_user(self) -> None:
        os.environ["FORGE_DASHBOARD_PASSWORD"] = "test-password"
        try:
            _clear_auth_failures("nobody")
            token = generate_token("nobody", "password")
            assert token is None
        finally:
            _clear_auth_failures("nobody")
            os.environ.pop("FORGE_DASHBOARD_PASSWORD", None)

    def test_role_hierarchy(self) -> None:
        os.environ["FORGE_DASHBOARD_PASSWORD"] = "test-password"
        try:
            token = generate_token("operator", "test-password")
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
        finally:
            os.environ.pop("FORGE_DASHBOARD_PASSWORD", None)

    def test_expired_token(self) -> None:
        os.environ["FORGE_DASHBOARD_PASSWORD"] = "test-password"
        try:
            token = generate_token("operator", "test-password", ttl_hours=-1)
            assert token is not None
            payload = validate_token(token)
            assert payload is None
        finally:
            os.environ.pop("FORGE_DASHBOARD_PASSWORD", None)

    def test_totp_secret_requires_code(self) -> None:
        original_pass = os.environ.get("FORGE_DASHBOARD_PASSWORD")
        original_totp = os.environ.get("FORGE_DASHBOARD_TOTP_SECRET")
        os.environ["FORGE_DASHBOARD_PASSWORD"] = "test-password"
        os.environ["FORGE_DASHBOARD_TOTP_SECRET"] = "JBSWY3DPEHPK3PXP"
        try:
            _clear_auth_failures("operator")
            assert generate_token("operator", "test-password") is None
            code = _totp_code("JBSWY3DPEHPK3PXP", int(time.time() // 30))
            assert generate_token("operator", "test-password", totp_code=code) is not None
        finally:
            _clear_auth_failures("operator")
            if original_pass is None:
                os.environ.pop("FORGE_DASHBOARD_PASSWORD", None)
            else:
                os.environ["FORGE_DASHBOARD_PASSWORD"] = original_pass
            if original_totp is None:
                os.environ.pop("FORGE_DASHBOARD_TOTP_SECRET", None)
            else:
                os.environ["FORGE_DASHBOARD_TOTP_SECRET"] = original_totp
