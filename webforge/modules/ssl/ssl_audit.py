"""SSL/TLS auditor — weak ciphers, protocol versions, certificate issues, key size."""
from __future__ import annotations

import asyncio
import socket
import ssl
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity
from common.fp_reducer import FPReducer, Confidence

CVSS_EXPIRED     = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
CVSS40_EXPIRED   = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N"
CVSS_WEAK_PROTO  = "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N"
CVSS40_WEAK_PROTO = "CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N"
CVSS_SELF_SIGNED = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N"
CVSS40_SELF_SIGNED = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N"
CVSS_WEAK_CIPHER = "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N"
CVSS40_WEAK_CIPHER = "CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N"
CVSS_WEAK_KEY    = "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N"
CVSS40_WEAK_KEY  = "CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N"
# Cipher suite name substrings indicating weak/broken ciphers
WEAK_CIPHER_PATTERNS = [
    ("RC4",      "RC4 — stream cipher, statistically biased and cryptographically broken (RFC 7465)"),
    ("DES",      "DES/3DES — block cipher with 56-bit/112-bit key, vulnerable to brute force and SWEET32 (CVE-2016-2183)"),
    ("3DES",     "Triple-DES — vulnerable to SWEET32 birthday attack"),
    ("NULL",     "NULL cipher — no encryption, data transmitted in cleartext"),
    ("EXPORT",   "EXPORT cipher — deliberately weakened (40/56-bit), vulnerable to FREAK/LOGJAM"),
    ("anon",     "Anonymous DH/ECDH — no server authentication, trivially MITMed"),
    ("ADH",      "Anonymous Diffie-Hellman — no server authentication"),
    ("AECDH",    "Anonymous ECDH — no server authentication"),
    ("SEED",     "SEED cipher — deprecated Korean cipher, limited hardware acceleration"),
    ("IDEA",     "IDEA cipher — deprecated, not recommended"),
    ("MD5",      "MD5 MAC — collision-prone, deprecated for HMAC in TLS"),
    ("_SHA ",    "SHA-1 MAC — deprecated, prefer SHA-256 or better"),
    ("_SHA\t",   "SHA-1 MAC — deprecated"),
    ("_SHA$",    "SHA-1 MAC — deprecated"),
    ("CAMELLIA", "Camellia — not broken but rarely audited; prefer AES-GCM"),
]


class SslAudit(BaseModule):
    """SSL/TLS configuration auditor."""

    NAME        = "ssl_audit"
    DESCRIPTION = "Audit SSL/TLS: certificate validity, weak protocols, weak ciphers, key size"
    PHASE       = 2
    TAGS        = ["ssl", "tls", "certificate", "cwe-326", "cwe-295"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        target = self.config.target
        if not self.check_scope(target):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        self._fp = FPReducer(
            collab_client=self.config.extra.get("collab_client"),
            headers=self.config.extra.get("session_headers", {}),
        )
        from urllib.parse import urlparse
        parsed = urlparse(target)
        host   = parsed.netloc.split(":")[0]
        port   = int(parsed.port or 443)

        if parsed.scheme != "https":
            self.log.info("Target is not HTTPS — checking if HTTPS is available on 443")
            port = 443

        self.log.info("SSL audit on %s:%d", host, port)

        await asyncio.gather(
            self._check_certificate(host, port),
            self._check_protocols(host, port),
        )
        # Cipher check is sequential due to socket resource usage
        await self._check_negotiated_cipher(host, port)
        return self._make_result(start)

    async def _check_certificate(self, host: str, port: int) -> None:
        """Check certificate validity, expiry, self-sign, hostname, key size."""
        try:
            loop = asyncio.get_event_loop()
            cert, key_bits = await loop.run_in_executor(None, self._get_cert_and_key, host, port)
            if not cert:
                return

            subject = dict(x[0] for x in cert.get("subject", []))
            issuer  = dict(x[0] for x in cert.get("issuer", []))

            # Expiry check
            not_after_str = cert.get("notAfter", "")
            if not_after_str:
                try:
                    not_after = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
                    not_after = not_after.replace(tzinfo=timezone.utc)
                    now = datetime.now(timezone.utc)
                    days_left = (not_after - now).days

                    if days_left < 0:
                        self._report_cert_issue(
                            host, port, cert,
                            f"Certificate Expired {-days_left} Day(s) Ago",
                            Severity.CRITICAL, CVSS_EXPIRED,
                            f"The SSL/TLS certificate for {host} expired {-days_left} day(s) ago "
                            f"(on {not_after_str}). Browsers will show security warnings and connections "
                            "may be blocked.",
                        )
                    elif days_left < 14:
                        self._report_cert_issue(
                            host, port, cert,
                            f"Certificate Expiring Critically Soon ({days_left} Days)",
                            Severity.HIGH, CVSS_EXPIRED,
                            f"Certificate expires in {days_left} day(s) — CRITICAL. Renew immediately.",
                        )
                    elif days_left < 30:
                        self._report_cert_issue(
                            host, port, cert,
                            f"Certificate Expiring Soon ({days_left} Days)",
                            Severity.MEDIUM, CVSS_EXPIRED,
                            f"Certificate expires in {days_left} day(s). Renew before it lapses.",
                        )
                except ValueError:
                    pass

            # Self-signed check
            if (subject.get("commonName") == issuer.get("commonName")
                    and subject.get("organizationName") == issuer.get("organizationName")):
                self._report_cert_issue(
                    host, port, cert,
                    "Self-Signed Certificate",
                    Severity.MEDIUM, CVSS_SELF_SIGNED,
                    f"Certificate for {host} appears to be self-signed (subject == issuer). "
                    "Browsers will warn users and the certificate cannot be trusted. "
                    "Subject: " + str(subject),
                )

            # Hostname mismatch
            san = cert.get("subjectAltName", ())
            cn  = subject.get("commonName", "")
            names = [v for t, v in san if t == "DNS"] or ([cn] if cn else [])
            if not any(self._hostname_matches(host, n) for n in names):
                self._report_cert_issue(
                    host, port, cert,
                    f"Certificate Hostname Mismatch ({host})",
                    Severity.HIGH, CVSS_EXPIRED,
                    f"Certificate CN/SAN does not match hostname {host}. "
                    f"Certificate valid for: {', '.join(names[:5])}",
                )

            # Weak signature algorithm
            sig_alg = cert.get("signatureAlgorithm", "")
            if "sha1" in sig_alg.lower():
                self._report_cert_issue(
                    host, port, cert,
                    f"Weak Certificate Signature Algorithm (SHA-1)",
                    Severity.MEDIUM, CVSS_WEAK_CIPHER,
                    f"Certificate uses SHA-1 signature algorithm: {sig_alg}. "
                    "SHA-1 is cryptographically broken. Upgrade to SHA-256 or better.",
                )
            elif "md5" in sig_alg.lower():
                self._report_cert_issue(
                    host, port, cert,
                    f"Weak Certificate Signature Algorithm (MD5)",
                    Severity.HIGH, CVSS_WEAK_CIPHER,
                    f"Certificate uses MD5 signature algorithm: {sig_alg}. "
                    "MD5 is cryptographically broken and allows certificate forgery.",
                )

            # Weak key size
            if key_bits and key_bits < 2048:
                ev = Evidence(extra={
                    "host": host, "port": port, "key_bits": key_bits,
                })
                self.new_finding(
                    title=f"SSL/TLS — Weak RSA Key Size ({key_bits} bits)",
                    severity=Severity.HIGH,
                    description=(
                        f"The certificate for {host} uses a {key_bits}-bit RSA key. "
                        "Keys below 2048 bits are considered insecure and can be factored "
                        "by adversaries with sufficient resources."
                    ),
                    reproduction_steps=[
                        f"openssl s_client -connect {host}:{port} 2>/dev/null | openssl x509 -text -noout | grep 'Public-Key'",
                    ],
                    remediation="Reissue the certificate with a minimum 2048-bit RSA key or use ECDSA P-256+.",
                    references=["CWE-326", "NIST SP 800-57"],
                    evidence=ev,
                    cvss_v31_vector=CVSS_WEAK_KEY,
                    cvss_v40_vector=CVSS40_WEAK_KEY,
                    target=f"{host}:{port}",
                )

        except Exception as exc:
            self.log.debug("Certificate check failed: %s", exc)

    def _get_cert_and_key(self, host: str, port: int) -> tuple[dict | None, int | None]:
        """Retrieve certificate and attempt to extract RSA key size."""
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with ctx.wrap_socket(
                socket.create_connection((host, port), timeout=10),
                server_hostname=host
            ) as s:
                cert = s.getpeercert()
                # Try to get key size via DER and cryptography library
                key_bits = None
                try:
                    der = s.getpeercert(binary_form=True)
                    from cryptography import x509 as cx509
                    from cryptography.hazmat.backends import default_backend
                    c = cx509.load_der_x509_certificate(der, default_backend())
                    key_bits = c.public_key().key_size
                except Exception:
                    pass
                return cert, key_bits
        except Exception:
            return None, None

    def _get_cert(self, host: str, port: int) -> dict | None:
        cert, _ = self._get_cert_and_key(host, port)
        return cert

    def _report_cert_issue(
        self, host: str, port: int, cert: dict,
        title: str, severity: Severity, cvss: str, description: str
    ) -> None:
        ev = Evidence(extra={
            "host": host, "port": port,
            "subject": str(cert.get("subject", "")),
            "issuer":  str(cert.get("issuer", "")),
            "notAfter": cert.get("notAfter", ""),
            "san":      str(cert.get("subjectAltName", "")),
        })
        self.new_finding(
            title=f"SSL/TLS — {title}",
            severity=severity,
            description=description,
            reproduction_steps=[
                f"openssl s_client -connect {host}:{port} -servername {host} 2>/dev/null | openssl x509 -text -noout",
            ],
            remediation=(
                "Use a trusted CA certificate (e.g., Let's Encrypt). "
                "Ensure certificate covers all served hostnames. "
                "Configure auto-renewal. Use SHA-256 or better for signing."
            ),
            references=["CWE-295", "CWE-326", "OWASP TLS Cheat Sheet"],
            evidence=ev,
            cvss_v31_vector=cvss,
            cvss_v40_vector=CVSS40_EXPIRED,
            target=f"{host}:{port}",
            port=port,
            service="https",
        )

    async def _check_protocols(self, host: str, port: int) -> None:
        """Check for support of weak/deprecated TLS versions."""
        weak_found: list[str] = []
        for proto_name in ["TLSv1.0", "TLSv1.1"]:
            supported = await self._test_protocol(host, port, proto_name)
            if supported:
                weak_found.append(proto_name)

        if weak_found:
            ev = Evidence(extra={"host": host, "port": port, "weak_protocols": weak_found})
            self.new_finding(
                title=f"Weak TLS Protocol(s) Supported — {', '.join(weak_found)}",
                severity=Severity.HIGH,
                description=(
                    f"{host}:{port} supports deprecated protocol(s): {', '.join(weak_found)}. "
                    "TLS 1.0 and 1.1 are deprecated by RFC 8996 and vulnerable to downgrade attacks "
                    "(BEAST, POODLE-style). PCI DSS v3.2+ prohibits TLS 1.0."
                ),
                reproduction_steps=[
                    f"nmap --script ssl-enum-ciphers -p {port} {host}",
                    f"openssl s_client -tls1 -connect {host}:{port}",
                    f"openssl s_client -tls1_1 -connect {host}:{port}",
                ],
                remediation=(
                    "Disable TLS 1.0 and TLS 1.1. "
                    "Require TLS 1.2 minimum; prefer TLS 1.3. "
                    "Update Nginx: ssl_protocols TLSv1.2 TLSv1.3; "
                    "Update Apache: SSLProtocol -all +TLSv1.2 +TLSv1.3"
                ),
                references=["CVE-2014-3566", "RFC 8996", "PCI DSS 3.2.1"],
                evidence=ev,
                cvss_v31_vector=CVSS_WEAK_PROTO,
                cvss_v40_vector=CVSS40_WEAK_PROTO,
                mitre_attack=["TA0009/T1557"],
                target=f"{host}:{port}",
                port=port,
                service="https",
            )

    async def _test_protocol(self, host: str, port: int, proto_name: str) -> bool:
        """Test if a specific TLS version is supported by the server."""
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            if proto_name == "TLSv1.0":
                ctx.maximum_version = ssl.TLSVersion.TLSv1
                ctx.minimum_version = ssl.TLSVersion.TLSv1
            elif proto_name == "TLSv1.1":
                ctx.maximum_version = ssl.TLSVersion.TLSv1_1
                ctx.minimum_version = ssl.TLSVersion.TLSv1_1
            else:
                return False

            loop = asyncio.get_event_loop()

            def _connect() -> bool:
                with ctx.wrap_socket(
                    socket.create_connection((host, port), timeout=5),
                    server_hostname=host
                ):
                    return True

            return await loop.run_in_executor(None, _connect)
        except Exception:
            return False

    async def _check_negotiated_cipher(self, host: str, port: int) -> None:
        """Check the negotiated cipher suite for known weaknesses."""
        try:
            loop = asyncio.get_event_loop()
            cipher_info = await loop.run_in_executor(None, self._get_negotiated_cipher, host, port)
            if not cipher_info:
                return
            cipher_name, tls_version, key_bits = cipher_info

            for pattern, description in WEAK_CIPHER_PATTERNS:
                if pattern.upper() in cipher_name.upper():
                    ev = Evidence(extra={
                        "host":        host,
                        "port":        port,
                        "cipher":      cipher_name,
                        "tls_version": tls_version,
                        "key_bits":    key_bits,
                    })
                    self.new_finding(
                        title=f"Weak Cipher Suite Negotiated — {cipher_name}",
                        severity=Severity.HIGH,
                        description=(
                            f"The server negotiated cipher suite {cipher_name!r} ({tls_version}). "
                            f"Issue: {description}. "
                            "Weak ciphers can be exploited by MITM adversaries to decrypt traffic."
                        ),
                        reproduction_steps=[
                            f"openssl s_client -connect {host}:{port} -servername {host}",
                            "Observe 'Cipher is ...' in output",
                            f"nmap --script ssl-enum-ciphers -p {port} {host}",
                        ],
                        remediation=(
                            "Configure the server to prefer ECDHE-ECDSA-AES256-GCM-SHA384 or "
                            "ECDHE-RSA-AES256-GCM-SHA384. Disable all RC4, DES, 3DES, NULL, "
                            "EXPORT, and anonymous cipher suites. "
                            "Use Mozilla SSL Configuration Generator for recommended configs."
                        ),
                        references=["CWE-326", "RFC 7465 (RC4)", "CVE-2016-2183 (SWEET32)"],
                        evidence=ev,
                        cvss_v31_vector=CVSS_WEAK_CIPHER,
                        cvss_v40_vector=CVSS40_WEAK_CIPHER,
                        target=f"{host}:{port}",
                        port=port,
                        service="https",
                    )
                    break  # One finding per connection

        except Exception as exc:
            self.log.debug("Cipher check failed: %s", exc)

    def _get_negotiated_cipher(self, host: str, port: int) -> tuple[str, str, int] | None:
        """Return (cipher_name, tls_version, key_bits) for the negotiated connection."""
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with ctx.wrap_socket(
                socket.create_connection((host, port), timeout=10),
                server_hostname=host
            ) as s:
                c = s.cipher()
                if c:
                    return c[0], s.version() or "unknown", c[2] or 0
        except Exception:
            pass
        return None

    def _hostname_matches(self, hostname: str, pattern: str) -> bool:
        if pattern.startswith("*."):
            suffix = pattern[2:]
            parts  = hostname.split(".")
            return len(parts) > 1 and ".".join(parts[1:]) == suffix
        return hostname == pattern


class TestSslAudit:
    def test_hostname_match_wildcard(self) -> None:
        mod = SslAudit.__new__(SslAudit)
        assert mod._hostname_matches("api.example.com", "*.example.com")
        assert not mod._hostname_matches("example.com", "*.example.com")
        assert not mod._hostname_matches("a.b.example.com", "*.example.com")

    def test_hostname_match_exact(self) -> None:
        mod = SslAudit.__new__(SslAudit)
        assert mod._hostname_matches("example.com", "example.com")
        assert not mod._hostname_matches("other.com", "example.com")

    def test_weak_cipher_patterns_defined(self) -> None:
        patterns = [p[0] for p in WEAK_CIPHER_PATTERNS]
        assert "RC4" in patterns
        assert "NULL" in patterns
        assert "EXPORT" in patterns
        assert "3DES" in patterns

    def test_cvss_vectors_valid(self) -> None:
        for v in (CVSS_EXPIRED, CVSS_WEAK_PROTO, CVSS_SELF_SIGNED, CVSS_WEAK_CIPHER, CVSS_WEAK_KEY):
            assert v.startswith("CVSS:3.1/")
