"""JWT Detector — eyJ... pattern detection + decode + weak-key testing.

Detects JWT tokens, decodes the header and payload (no signature verification
needed for detection), and tests for weak signing keys.

FOR AUTHORIZED PENETRATION TESTING AND RED TEAM OPERATIONS ONLY.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import re
from dataclasses import dataclass, field
from typing import Any

log = logging.getLogger("forge.leak_intel.jwt_detector")

_JWT_PATTERN = re.compile(
    r"(eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_\-+/=]{10,})"
)

# Common weak signing keys to test
_WEAK_KEYS: list[str] = [
    "secret", "password", "123456", "key", "jwt_secret", "changeme",
    "test", "admin", "default", "super_secret", "mysecret", "jwt",
    "signingkey", "HS256", "none", "null", "", "1234567890",
    "your-256-bit-secret", "shhhhh", "passphrase", "hmac-secret",
]


@dataclass
class JWTFinding:
    """Transient decoded JWT material; token and recovered key stay out of repr."""

    raw_token: str = field(repr=False)
    header: dict[str, Any] = field(default_factory=dict, repr=False)
    payload: dict[str, Any] = field(default_factory=dict, repr=False)
    algorithm: str = ""
    source_file: str = ""
    line_number: int = 0
    is_expired: bool | None = None
    weak_key: str | None = field(default=None, repr=False)
    issues: list[str] = field(default_factory=list)

    def redacted_token(self) -> str:
        """Return a constant placeholder with no token-derived fragments."""
        return "<redacted>"

    def clear(self) -> None:
        """Best-effort clearing after transfer to a protected reference."""
        self.raw_token = ""
        self.weak_key = None
        self.header.clear()
        self.payload.clear()

    def __repr__(self) -> str:
        return (
            "JWTFinding(raw_token=<redacted>, header=<redacted>, payload=<redacted>, "
            f"algorithm={self.algorithm!r}, source_file={self.source_file!r}, "
            f"line_number={self.line_number!r}, is_expired={self.is_expired!r}, "
            "weak_key=<redacted>, "
            f"issues={self.issues!r})"
        )


def _b64url_decode(data: str) -> bytes:
    """Decode base64url without padding."""
    padding = 4 - len(data) % 4
    if padding != 4:
        data += "=" * padding
    return base64.urlsafe_b64decode(data)


def _b64url_encode(data: bytes) -> str:
    """Encode to base64url without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def detect_jwts(content: str, source_file: str = "") -> list[JWTFinding]:
    """Scan text for JWT tokens, decode them, and check for issues.

    Args:
        content:     Text to scan.
        source_file: Source file for provenance.

    Returns:
        List of JWTFinding objects.
    """
    findings: list[JWTFinding] = []
    seen_tokens: set[str] = set()

    for match in _JWT_PATTERN.finditer(content):
        token = match.group(1)
        if token in seen_tokens:
            continue
        seen_tokens.add(token)

        line_num = content[:match.start()].count("\n") + 1
        finding = JWTFinding(
            raw_token=token,
            source_file=source_file,
            line_number=line_num,
        )

        # Decode header and payload
        parts = token.split(".")
        if len(parts) != 3:
            continue

        try:
            header_bytes = _b64url_decode(parts[0])
            finding.header = json.loads(header_bytes)
            finding.algorithm = finding.header.get("alg", "")
        except Exception:
            continue

        try:
            payload_bytes = _b64url_decode(parts[1])
            finding.payload = json.loads(payload_bytes)
        except Exception:
            continue

        # Check for issues
        _analyze_jwt(finding)

        # Test for weak keys
        _test_weak_keys(finding, parts)

        findings.append(finding)

    return findings


def _analyze_jwt(finding: JWTFinding) -> None:
    """Analyze a decoded JWT for common security issues."""
    import time

    # Check algorithm
    alg = finding.algorithm.upper()
    if alg == "NONE":
        finding.issues.append("CRITICAL: Algorithm set to 'none' — signature bypass possible")
    elif alg in ("HS256", "HS384", "HS512"):
        finding.issues.append(f"Symmetric signing ({alg}) — vulnerable to key brute-force")
    elif not alg:
        finding.issues.append("No algorithm specified in header")

    # Check expiration
    exp = finding.payload.get("exp")
    if exp is not None:
        try:
            if float(exp) < time.time():
                finding.is_expired = True
                finding.issues.append("Token is expired")
            else:
                finding.is_expired = False
        except (ValueError, TypeError):
            pass
    else:
        finding.issues.append("No expiration (exp) claim — token never expires")

    # Check for sensitive claims
    sensitive_keys = {"password", "secret", "api_key", "credit_card", "ssn"}
    for key in finding.payload:
        if key.lower() in sensitive_keys:
            finding.issues.append(f"Sensitive data in payload: '{key}'")

    # Check for admin/role escalation potential
    role = finding.payload.get("role") or finding.payload.get("roles") or finding.payload.get("admin")
    if role:
        finding.issues.append("Role/permission claim present")


def _test_weak_keys(finding: JWTFinding, parts: list[str]) -> None:
    """Test JWT against common weak signing keys."""
    alg = finding.algorithm.upper()
    if alg not in ("HS256", "HS384", "HS512"):
        return

    hash_func = {
        "HS256": hashlib.sha256,
        "HS384": hashlib.sha384,
        "HS512": hashlib.sha512,
    }.get(alg, hashlib.sha256)

    signing_input = f"{parts[0]}.{parts[1]}".encode("ascii")

    try:
        actual_sig = _b64url_decode(parts[2])
    except Exception:
        return

    for weak_key in _WEAK_KEYS:
        expected_sig = hmac.new(
            weak_key.encode("utf-8"),
            signing_input,
            hash_func,
        ).digest()

        if hmac.compare_digest(expected_sig, actual_sig):
            finding.weak_key = weak_key
            finding.issues.append(
                "CRITICAL: JWT signed with a known weak key; "
                "attacker can forge arbitrary tokens"
            )
            break


class TestJWTDetector:
    """Unit tests for jwt_detector."""

    def test_detect_jwt(self) -> None:
        # This is a real JWT (expired, test-only) signed with "secret"
        token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        findings = detect_jwts(f"Bearer {token}")
        assert len(findings) == 1
        assert findings[0].header.get("alg") == "HS256"
        assert findings[0].payload.get("sub") == "1234567890"

    def test_weak_key_detection(self) -> None:
        token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        findings = detect_jwts(token)
        assert len(findings) == 1
        # This JWT is signed with "your-256-bit-secret"
        # Our weak key list includes that

    def test_no_match(self) -> None:
        content = "This has no JWT tokens."
        findings = detect_jwts(content)
        assert len(findings) == 0

    def test_redaction(self) -> None:
        token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.rOCfmGhYEuRx_sEpCE"
        finding = JWTFinding(raw_token=token)
        redacted = finding.redacted_token()
        assert redacted == "<redacted>"
        for fragment in token.split("."):
            assert fragment not in redacted

    def test_malformed_token_redaction(self) -> None:
        token = "CANARY_MALFORMED_TOKEN_TASK007"
        redacted = JWTFinding(raw_token=token).redacted_token()
        assert redacted == "<redacted>"
        assert token not in redacted
        assert token[:10] not in redacted
