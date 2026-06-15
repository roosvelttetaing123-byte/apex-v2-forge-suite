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
from dataclasses import dataclass
from enum import Enum
from typing import Any

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

    now = time.time()
    payload = {
        "username": username,
        "role": user["role"],
        "iat": now,
        "exp": now + (ttl_hours * 3600),
        "sid": secrets.token_hex(8),
    }
    payload_json = json.dumps(payload, separators=(",", ":"))
    import base64
    b64_payload = base64.urlsafe_b64encode(payload_json.encode()).decode()
    signature = _hmac_sign(payload_json)
    token = f"{b64_payload}.{signature}"
    log.info("Token issued for '%s' (role=%s, ttl=%.1fh)", username, user["role"], ttl_hours)
    return token


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
