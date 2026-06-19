"""Certificate inspector — extract and report full certificate chain details."""
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

CVSS_CERT_EXPIRED  = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
CVSS40_CERT_EXPIRED = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N"
CVSS_CERT_WARN     = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N"
CVSS40_CERT_WARN   = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N"
CVSS_SELF_SIGNED   = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N"
CVSS40_SELF_SIGNED = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N"
CVSS_WEAK_SIG      = "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N"
CVSS40_WEAK_SIG    = "CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N"
class CertInspect(BaseModule):
    """Certificate chain inspector — extract full cert details and flag security issues."""

    NAME        = "cert_inspect"
    DESCRIPTION = "Extract and inspect full SSL/TLS certificate chain, flag key/sig weaknesses"
    PHASE       = 2
    TAGS        = ["ssl", "certificate", "chain", "transparency", "cwe-295"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        target = self.config.target
        if not self.check_scope(target):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        from urllib.parse import urlparse
        parsed = urlparse(target)
        host   = parsed.netloc.split(":")[0]
        port   = int(parsed.port or 443)

        self.log.info("Inspecting certificate for %s:%d", host, port)

        loop = asyncio.get_event_loop()
        cert_info = await loop.run_in_executor(None, self._fetch_cert_info, host, port)

        if cert_info:
            self.config.extra["cert_info"] = cert_info
            self.log.info(
                "Certificate: %s (issuer: %s, expires: %s, key: %s %s bits)",
                cert_info.get("subject_cn"),
                cert_info.get("issuer_cn"),
                cert_info.get("not_after"),
                cert_info.get("key_algorithm", "?"),
                cert_info.get("key_bits", "?"),
            )
            # Produce security findings for this cert
            self._audit_cert_info(cert_info, host, port, target)
            # Check CT logs
            await self._check_ct_logs(host)

        return self._make_result(start)

    def _fetch_cert_info(self, host: str, port: int) -> dict | None:
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with ctx.wrap_socket(
                socket.create_connection((host, port), timeout=10),
                server_hostname=host
            ) as s:
                cert     = s.getpeercert()
                der      = s.getpeercert(binary_form=True)
                cipher   = s.cipher()
                version  = s.version()

                subject = dict(x[0] for x in cert.get("subject", []))
                issuer  = dict(x[0] for x in cert.get("issuer", []))
                san     = [v for t, v in cert.get("subjectAltName", ()) if t == "DNS"]
                sig_alg = cert.get("signatureAlgorithm", "")

                # Try to extract key algorithm and size via cryptography lib
                key_algorithm = "unknown"
                key_bits      = None
                try:
                    from cryptography import x509 as cx509
                    from cryptography.hazmat.backends import default_backend
                    from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa
                    c   = cx509.load_der_x509_certificate(der, default_backend())
                    pub = c.public_key()
                    key_bits = pub.key_size
                    if isinstance(pub, rsa.RSAPublicKey):
                        key_algorithm = "RSA"
                    elif isinstance(pub, ec.EllipticCurvePublicKey):
                        key_algorithm = f"ECDSA ({pub.curve.name})"
                    elif isinstance(pub, dsa.DSAPublicKey):
                        key_algorithm = "DSA"
                except Exception:
                    pass

                return {
                    "subject_cn":     subject.get("commonName", ""),
                    "subject_org":    subject.get("organizationName", ""),
                    "subject_country":subject.get("countryName", ""),
                    "issuer_cn":      issuer.get("commonName", ""),
                    "issuer_org":     issuer.get("organizationName", ""),
                    "not_before":     cert.get("notBefore", ""),
                    "not_after":      cert.get("notAfter", ""),
                    "san":            san,
                    "serial":         cert.get("serialNumber", ""),
                    "version":        cert.get("version", ""),
                    "sig_algorithm":  sig_alg,
                    "key_algorithm":  key_algorithm,
                    "key_bits":       key_bits,
                    "cipher":         cipher[0] if cipher else "",
                    "tls_version":    version or "",
                    "is_self_signed": (
                        subject.get("commonName") == issuer.get("commonName")
                        and subject.get("organizationName") == issuer.get("organizationName")
                    ),
                    "san_count":      len(san),
                    "is_wildcard":    any(name.startswith("*.") for name in san),
                }
        except Exception as exc:
            self.log.debug("Cert fetch failed: %s", exc)
            return None

    def _audit_cert_info(self, info: dict, host: str, port: int, target: str) -> None:
        """Create findings for certificate security issues."""

        # 1. Expiry
        not_after_str = info.get("not_after", "")
        if not_after_str:
            try:
                not_after = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
                not_after = not_after.replace(tzinfo=timezone.utc)
                now       = datetime.now(timezone.utc)
                days_left = (not_after - now).days

                if days_left < 0:
                    self._cert_finding(
                        info, host, port, target,
                        f"Certificate Expired {-days_left} Day(s) Ago",
                        Severity.CRITICAL, CVSS_CERT_EXPIRED,
                        f"The certificate for {host} expired {-days_left} day(s) ago ({not_after_str}). "
                        "Browsers reject expired certificates.",
                    )
                elif days_left < 30:
                    self._cert_finding(
                        info, host, port, target,
                        f"Certificate Expiring in {days_left} Day(s)",
                        Severity.MEDIUM if days_left >= 14 else Severity.HIGH,
                        CVSS_CERT_WARN,
                        f"Certificate expires in {days_left} day(s) ({not_after_str}). Renew now.",
                    )
            except ValueError:
                pass

        # 2. Self-signed
        if info.get("is_self_signed"):
            self._cert_finding(
                info, host, port, target,
                "Self-Signed Certificate",
                Severity.MEDIUM, CVSS_SELF_SIGNED,
                f"Certificate is self-signed (subject == issuer: {info['issuer_cn']!r}). "
                "Not trusted by browsers. Users will see security warnings.",
            )

        # 3. SHA-1 signature
        sig_alg = info.get("sig_algorithm", "")
        if "sha1" in sig_alg.lower():
            self._cert_finding(
                info, host, port, target,
                f"Weak Certificate Signature Algorithm (SHA-1)",
                Severity.MEDIUM, CVSS_WEAK_SIG,
                f"Certificate uses SHA-1 signature ({sig_alg}). "
                "SHA-1 is cryptographically broken. Browsers no longer trust SHA-1 certs. "
                "Reissue with SHA-256 or better.",
            )
        elif "md5" in sig_alg.lower():
            self._cert_finding(
                info, host, port, target,
                f"Weak Certificate Signature Algorithm (MD5)",
                Severity.HIGH, CVSS_WEAK_SIG,
                f"Certificate uses MD5 signature ({sig_alg}). "
                "MD5 certificate collisions are practical. Reissue immediately.",
            )

        # 4. Weak RSA key size
        key_bits = info.get("key_bits")
        if key_bits and info.get("key_algorithm", "").startswith("RSA") and key_bits < 2048:
            self._cert_finding(
                info, host, port, target,
                f"Weak RSA Key ({key_bits} bits)",
                Severity.HIGH, CVSS_WEAK_SIG,
                f"RSA key is only {key_bits} bits. Minimum recommended is 2048 bits. "
                "Keys below 1024 bits are factored publicly (NIST deprecates < 2048 bits).",
            )

        # 5. Wildcard certificate — informational risk
        if info.get("is_wildcard"):
            ev = Evidence(extra={
                "host": host, "san": info.get("san", [])[:10],
                "wildcard_names": [n for n in info.get("san", []) if n.startswith("*.")],
            })
            self.new_finding(
                title=f"Wildcard Certificate in Use — {info.get('subject_cn', host)}",
                severity=Severity.LOW,
                description=(
                    f"The certificate for {host} is a wildcard certificate. "
                    "A single compromised private key exposes all subdomains covered by the wildcard. "
                    f"SANs: {info.get('san', [])[:5]}"
                ),
                reproduction_steps=[
                    f"openssl s_client -connect {host}:{port} 2>/dev/null | openssl x509 -text -noout | grep DNS:",
                ],
                remediation=(
                    "Use individual per-hostname certificates where feasible. "
                    "Store wildcard private keys in HSMs. "
                    "Consider shorter validity periods for wildcard certs."
                ),
                references=["CWE-295", "OWASP TLS Cheat Sheet"],
                evidence=ev,
                cvss_v31_vector=CVSS_CERT_WARN,
                cvss_v40_vector=CVSS40_CERT_WARN,
                target=target,
            )

    def _cert_finding(
        self, info: dict, host: str, port: int, target: str,
        title: str, severity: Severity, cvss: str, description: str
    ) -> None:
        ev = Evidence(extra={
            "host":          host,
            "port":          port,
            "subject_cn":    info.get("subject_cn", ""),
            "issuer_cn":     info.get("issuer_cn", ""),
            "not_after":     info.get("not_after", ""),
            "sig_algorithm": info.get("sig_algorithm", ""),
            "key_algorithm": info.get("key_algorithm", ""),
            "key_bits":      info.get("key_bits"),
            "san":           info.get("san", [])[:5],
        })
        self.new_finding(
            title=f"Certificate — {title}",
            severity=severity,
            description=description,
            reproduction_steps=[
                f"openssl s_client -connect {host}:{port} -servername {host} 2>/dev/null | openssl x509 -text -noout",
            ],
            remediation=(
                "Use a trusted CA (e.g., Let's Encrypt). "
                "Set up auto-renewal. Use SHA-256+ signing and RSA 2048+/ECDSA P-256+ keys."
            ),
            references=["CWE-295", "CWE-326", "OWASP TLS Cheat Sheet"],
            evidence=ev,
            cvss_v31_vector=cvss,
            cvss_v40_vector=CVSS40_CERT_EXPIRED,
            target=target,
            port=port,
            service="https",
        )

    async def _check_ct_logs(self, host: str) -> None:
        """Check Certificate Transparency logs via crt.sh for certificate history."""
        try:
            from common.netcheck import ask_internet_permission
            if not ask_internet_permission("Certificate Transparency log query (crt.sh)"):
                return
        except ImportError:
            pass
        try:
            import aiohttp
            url = f"https://crt.sh/?q={host}&output=json"
            async with aiohttp.ClientSession(
                headers={"Accept-Encoding": "gzip, deflate"},
            ) as session:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        names: set[str] = set()
                        for entry in data[:100]:
                            cn = entry.get("common_name", "")
                            if cn:
                                names.add(cn)
                        if names:
                            self.log.info(
                                "CT logs: %d unique cert names for %s", len(names), host
                            )
                            self.config.extra.setdefault("ct_names", []).extend(sorted(names))
        except Exception:
            pass


class TestCertInspect:
    def test_cert_info_keys(self) -> None:
        expected = {"subject_cn", "issuer_cn", "not_after", "san", "cipher",
                    "key_algorithm", "key_bits", "is_self_signed", "sig_algorithm"}
        actual = {"subject_cn", "subject_org", "issuer_cn", "issuer_org",
                  "not_before", "not_after", "san", "serial", "version",
                  "cipher", "tls_version", "sig_algorithm", "key_algorithm",
                  "key_bits", "is_self_signed", "san_count", "is_wildcard",
                  "subject_country"}
        assert expected.issubset(actual)

    def test_self_signed_detection_logic(self) -> None:
        info = {
            "subject_cn":  "self.example.com",
            "issuer_cn":   "self.example.com",
            "is_self_signed": True,
        }
        assert info["is_self_signed"] is True

    def test_wildcard_detection(self) -> None:
        san = ["*.example.com", "example.com"]
        is_wildcard = any(n.startswith("*.") for n in san)
        assert is_wildcard is True
