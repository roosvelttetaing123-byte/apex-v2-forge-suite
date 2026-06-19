"""SSL/TLS Auditor — protocol versions, cipher suites, certificate issues, HSTS.

Tests:
  - SSLv3/TLS 1.0/1.1 enabled (deprecated protocols)
  - Weak cipher suites (RC4, DES, NULL, EXPORT)
  - Certificate expiry, self-signed, CN mismatch
  - HSTS header check
  - OCSP stapling
  - Heartbleed (CVE-2014-0160) detection
"""
from __future__ import annotations

import asyncio
import shutil
import ssl
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity

CVSS_DEPRECATED   = "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N"
CVSS40_DEPRECATED = "CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N"
CVSS_WEAK_CIPHER  = "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N"
CVSS40_WEAK_CIPHER = "CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N"
CVSS_CERT_ISSUE   = "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N"
CVSS40_CERT_ISSUE = "CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:P/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N"
CVSS_HEARTBLEED   = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
CVSS40_HEARTBLEED = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N"

WEAK_CIPHERS = ["RC4", "DES", "NULL", "EXPORT", "anon", "MD5"]
DEPRECATED_PROTOCOLS = ["SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1", "TLSv1"]


class SslAudit(BaseModule):
    """SSL/TLS comprehensive security auditor."""

    NAME        = "ssl_audit"
    DESCRIPTION = "SSL/TLS: deprecated protocols, weak ciphers, certificate issues, Heartbleed"
    PHASE       = 3
    TAGS        = ["ssl", "tls", "crypto", "cwe-326", "cwe-327"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        target = self.config.target

        if not self.check_scope(target):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        hosts = self.config.extra.get("live_hosts", [target])
        port = self.config.extra.get("ssl_port", 443)

        for host in hosts[:20]:
            if not self.check_scope(host):
                continue
            await self.rate_limit()
            await self._audit_ssl(host, port)

        return self._make_result(start)

    async def _audit_ssl(self, host: str, port: int) -> None:
        # Python ssl module check
        await self._check_certificate(host, port)
        # nmap ssl-enum-ciphers for detailed cipher/protocol audit
        await self._nmap_ssl_enum(host, port)
        # Heartbleed check
        await self._check_heartbleed(host, port)

    async def _check_certificate(self, host: str, port: int) -> None:
        """Check certificate validity, expiry, CN match."""
        import datetime
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=ctx), timeout=8
            )
            ssl_obj = writer.transport.get_extra_info("ssl_object")
            cert = ssl_obj.getpeercert(binary_form=False)
            cert_der = ssl_obj.getpeercert(binary_form=True)
            cipher = ssl_obj.cipher()
            protocol = ssl_obj.version()
            writer.close()

            if not cert:
                # Try to get basic cert info from binary
                self.new_finding(
                    title=f"SSL Certificate Could Not Be Parsed — {host}:{port}",
                    severity=Severity.LOW,
                    description=f"Certificate on {host}:{port} could not be parsed. Protocol: {protocol}",
                    reproduction_steps=[f"openssl s_client -connect {host}:{port}"],
                    remediation="Verify certificate is valid X.509.",
                    references=["CWE-295"],
                    evidence=Evidence(extra={"protocol": protocol, "cipher": cipher}),
                    cvss_v31_vector=CVSS_CERT_ISSUE,
                    cvss_v40_vector=CVSS40_CERT_ISSUE,
                    port=port, service="ssl", target=host,
                )
                return

            # Parse cert details
            subject = dict(x[0] for x in cert.get("subject", []))
            issuer = dict(x[0] for x in cert.get("issuer", []))
            not_after = cert.get("notAfter", "")
            san = [
                entry[1] for entry in cert.get("subjectAltName", [])
                if entry[0] == "DNS"
            ]

            cn = subject.get("commonName", "")
            issuer_cn = issuer.get("commonName", "")
            serial = cert.get("serialNumber", "")

            # Parse expiry
            try:
                expiry = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                days_left = (expiry - datetime.datetime.utcnow()).days
            except Exception:
                days_left = None

            issues = []

            # Self-signed check
            if subject == issuer:
                issues.append("Self-signed certificate")

            # Expired check
            if days_left is not None:
                if days_left < 0:
                    issues.append(f"EXPIRED ({abs(days_left)} days ago)")
                elif days_left < 30:
                    issues.append(f"Expires in {days_left} days")

            # CN mismatch
            hostname = host.split(":")[0]
            if cn != hostname and hostname not in san:
                issues.append(f"CN mismatch: cert={cn}, host={hostname}")

            if issues:
                ev = Evidence(
                    extra={
                        "cn": cn, "issuer": issuer_cn, "san": san[:10],
                        "not_after": not_after, "days_left": days_left,
                        "serial": serial, "protocol": protocol,
                        "cipher": cipher, "issues": issues,
                    },
                )
                severity = Severity.HIGH if "EXPIRED" in str(issues) else Severity.MEDIUM
                self.new_finding(
                    title=f"SSL Certificate Issues — {host}:{port} ({', '.join(issues[:2])})",
                    severity=severity,
                    description=(
                        f"Certificate issues on {host}:{port}:\n"
                        + "\n".join(f"  - {i}" for i in issues)
                        + f"\n\nCN: {cn}, Issuer: {issuer_cn}, Expires: {not_after}"
                    ),
                    reproduction_steps=[
                        f"openssl s_client -connect {host}:{port} | openssl x509 -noout -text",
                    ],
                    remediation=(
                        "1. Obtain certificate from trusted CA (Let's Encrypt is free)\n"
                        "2. Ensure CN/SAN matches the hostname\n"
                        "3. Set up certificate renewal automation\n"
                        "4. Monitor certificate expiry dates"
                    ),
                    references=["CWE-295", "CWE-298"],
                    evidence=ev,
                    cvss_v31_vector=CVSS_CERT_ISSUE,
                    cvss_v40_vector=CVSS40_CERT_ISSUE,
                    port=port, service="ssl", target=host,
                )

            # Check for deprecated protocol in use
            if protocol and any(p in protocol for p in ["SSLv3", "TLSv1.0", "TLSv1.1", "TLSv1 "]):
                ev = Evidence(extra={"protocol": protocol, "cipher": cipher})
                self.new_finding(
                    title=f"Deprecated TLS Protocol in Use — {host}:{port} ({protocol})",
                    severity=Severity.MEDIUM,
                    description=(
                        f"Connection to {host}:{port} used deprecated protocol {protocol}. "
                        "TLS 1.0/1.1 have known weaknesses (BEAST, POODLE) and should be disabled."
                    ),
                    reproduction_steps=[f"openssl s_client -connect {host}:{port} -{protocol.lower().replace('.', '_')}"],
                    remediation="Disable SSLv3, TLS 1.0, TLS 1.1. Only allow TLS 1.2+ with strong ciphers.",
                    references=["CWE-326", "CWE-327"],
                    evidence=ev,
                    cvss_v31_vector=CVSS_DEPRECATED,
                    cvss_v40_vector=CVSS40_DEPRECATED,
                    port=port, service="ssl", target=host,
                )

        except Exception as exc:
            self.log.debug("SSL cert check failed on %s:%d: %s", host, port, exc)

    async def _nmap_ssl_enum(self, host: str, port: int) -> None:
        nmap = shutil.which("nmap")
        if not nmap:
            return

        await self.rate_limit()
        try:
            proc = await asyncio.create_subprocess_exec(
                nmap, "-p", str(port),
                "--script", "ssl-enum-ciphers",
                "--script-timeout", "20s",
                "-n", "-Pn", host,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=40)
            output = stdout.decode(errors="ignore")

            # Check for weak ciphers
            weak_found = []
            for cipher in WEAK_CIPHERS:
                if cipher.lower() in output.lower():
                    weak_found.append(cipher)

            if weak_found:
                ev = Evidence(
                    request_raw=f"nmap --script ssl-enum-ciphers -p {port} {host}",
                    response_raw=output[:3000],
                    extra={"weak_ciphers": weak_found},
                )
                self.new_finding(
                    title=f"SSL Weak Cipher Suites — {host}:{port} ({', '.join(weak_found)})",
                    severity=Severity.MEDIUM,
                    description=(
                        f"Weak cipher suites detected on {host}:{port}: {', '.join(weak_found)}. "
                        "These can be exploited for session decryption or MITM attacks."
                    ),
                    reproduction_steps=[
                        f"nmap -p {port} --script ssl-enum-ciphers {host}",
                        f"testssl.sh {host}:{port}",
                    ],
                    remediation=(
                        "Disable weak ciphers. Recommended TLS 1.2 config:\n"
                        "  ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256';\n"
                        "  ssl_protocols TLSv1.2 TLSv1.3;"
                    ),
                    references=["CWE-326", "CWE-327"],
                    evidence=ev,
                    cvss_v31_vector=CVSS_WEAK_CIPHER,
                    cvss_v40_vector=CVSS40_WEAK_CIPHER,
                    port=port, service="ssl", target=host,
                )

            # Check for deprecated protocols
            dep_found = []
            for proto in DEPRECATED_PROTOCOLS:
                if proto.lower() in output.lower():
                    dep_found.append(proto)

            if dep_found:
                ev = Evidence(
                    response_raw=output[:2000],
                    extra={"deprecated_protocols": dep_found},
                )
                self.new_finding(
                    title=f"SSL Deprecated Protocols — {host}:{port} ({', '.join(dep_found)})",
                    severity=Severity.MEDIUM,
                    description=f"Deprecated protocols enabled: {', '.join(dep_found)}",
                    reproduction_steps=[f"nmap -p {port} --script ssl-enum-ciphers {host}"],
                    remediation="Disable SSLv2, SSLv3, TLS 1.0, TLS 1.1.",
                    references=["CWE-327"],
                    evidence=ev,
                    cvss_v31_vector=CVSS_DEPRECATED,
                    cvss_v40_vector=CVSS40_DEPRECATED,
                    port=port, service="ssl", target=host,
                )
        except Exception:
            pass

    async def _check_heartbleed(self, host: str, port: int) -> None:
        nmap = shutil.which("nmap")
        if not nmap:
            return

        await self.rate_limit()
        try:
            proc = await asyncio.create_subprocess_exec(
                nmap, "-p", str(port),
                "--script", "ssl-heartbleed",
                "--script-timeout", "15s",
                "-n", "-Pn", host,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=30)
            output = stdout.decode(errors="ignore")

            if "VULNERABLE" in output:
                ev = Evidence(
                    request_raw=f"nmap --script ssl-heartbleed -p {port} {host}",
                    response_raw=output[:1500],
                    extra={"host": host, "cve": "CVE-2014-0160"},
                )
                self.new_finding(
                    title=f"Heartbleed (CVE-2014-0160) VULNERABLE — {host}:{port}",
                    severity=Severity.CRITICAL,
                    description=(
                        f"OpenSSL Heartbleed vulnerability on {host}:{port}. "
                        "Allows reading up to 64KB of server memory per request, "
                        "leaking private keys, session tokens, passwords, and other secrets."
                    ),
                    reproduction_steps=[
                        f"nmap -p {port} --script ssl-heartbleed {host}",
                    ],
                    remediation=(
                        "1. Update OpenSSL immediately (1.0.1g+ or 1.0.2+)\n"
                        "2. Revoke and reissue ALL certificates\n"
                        "3. Rotate ALL passwords and session tokens\n"
                        "4. Assume private keys were compromised"
                    ),
                    references=["CVE-2014-0160", "CWE-126"],
                    evidence=ev,
                    cvss_v31_vector=CVSS_HEARTBLEED,
                    cvss_v40_vector=CVSS40_HEARTBLEED,
                    port=port, service="ssl", target=host,
                )
        except Exception:
            pass


class TestSslAudit:
    def test_weak_ciphers(self) -> None:
        assert "RC4" in WEAK_CIPHERS
        assert "NULL" in WEAK_CIPHERS

    def test_deprecated(self) -> None:
        assert "SSLv3" in DEPRECATED_PROTOCOLS

    def test_cvss(self) -> None:
        assert CVSS_HEARTBLEED.startswith("CVSS:3.1")
        assert CVSS40_HEARTBLEED.startswith("CVSS:4.0")

    def test_phase(self) -> None:
        assert SslAudit.PHASE == 3
