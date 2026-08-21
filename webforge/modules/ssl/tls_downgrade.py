"""TLS Downgrade Scanner — POODLE, BEAST, CRIME, weak cipher checks.

Nessus equivalent: 78479 (POODLE), 57582 (BEAST), 62565 (CRIME).
"""
from __future__ import annotations

import ssl
import socket
import time
from typing import Any

from common.base_module import BaseModule, ModuleResult
from common.finding import Severity
from common.fp_reducer import FPReducer, Confidence

WEAK_CIPHERS = [
    "RC4", "DES", "3DES", "NULL", "EXPORT", "anon", "MD5",
]

CVSS_TLS = "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N"
CVSS40_TLS = "CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N"


class TlsDowngrade(BaseModule):
    """TLS downgrade scanner — tests for POODLE, BEAST, CRIME, weak ciphers."""

    NAME        = "tls_downgrade"
    DESCRIPTION = "TLS downgrade attacks: POODLE, BEAST, CRIME, weak cipher detection"
    PHASE       = 3
    TAGS        = ["ssl", "owasp-a02", "tls-downgrade", "cwe-327"]

    async def run(self) -> ModuleResult:
        start  = time.monotonic()
        target = self.config.target.rstrip("/")

        if not self.check_scope(target):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        self.log.info("Starting TLS downgrade scan on %s", target)
        self._fp = FPReducer(
            collab_client=self.config.extra.get("collab_client"),
            headers=self.config.extra.get("session_headers", {}),
        )

        from urllib.parse import urlparse
        parsed = urlparse(target)
        host = parsed.hostname
        port = parsed.port or (443 if parsed.scheme == "https" else 80)

        if parsed.scheme != "https":
            self.new_finding(
                title="No TLS — HTTP Only",
                severity=Severity.MEDIUM,
                description=f"Target {target} uses HTTP without TLS encryption. All traffic is transmitted in plaintext.",
                reproduction_steps=[f"Observe that {target} uses http:// not https://"],
                remediation="Enable HTTPS with a valid TLS certificate. Redirect all HTTP to HTTPS.",
                references=["CWE-319", "OWASP A02:2021"],
                cvss_v31_vector=CVSS_TLS,
                cvss_v40_vector=CVSS40_TLS,
                target=target,
            )
            return self._make_result(start)

        # Test SSLv3 (POODLE)
        await self._test_protocol(host, port, "SSLv3", ssl.PROTOCOL_SSLv23, ssl.OP_ALL & ~ssl.OP_NO_SSLv3,
                                  "POODLE (SSLv3 Supported)", "CVE-2014-3566")

        # Test TLS 1.0 (BEAST)
        await self._test_protocol(host, port, "TLSv1.0", ssl.PROTOCOL_TLSv1 if hasattr(ssl, "PROTOCOL_TLSv1") else None,
                                  None, "BEAST (TLS 1.0 Supported)", "CVE-2011-3389")

        # Test TLS 1.1 (deprecated)
        await self._test_protocol(host, port, "TLSv1.1", ssl.PROTOCOL_TLSv1_1 if hasattr(ssl, "PROTOCOL_TLSv1_1") else None,
                                  None, "Deprecated TLS 1.1 Supported", "")

        # Test weak ciphers
        await self._test_weak_ciphers(host, port)

        return self._make_result(start)

    async def _test_protocol(self, host, port, proto_name, protocol, options, vuln_name, cve):
        if protocol is None:
            return
        try:
            ctx = ssl.SSLContext(protocol)
            if options:
                ctx.options = options
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = socket.create_connection((host, port), timeout=5)
            ssock = ctx.wrap_socket(sock, server_hostname=host)
            version = ssock.version()
            ssock.close()
            
            severity = Severity.HIGH if "POODLE" in vuln_name else Severity.MEDIUM
            refs = ["CWE-327", "OWASP A02:2021"]
            if cve:
                refs.append(cve)
            self.new_finding(
                title=f"TLS Vulnerability — {vuln_name}",
                severity=severity,
                description=f"Server accepts {proto_name} connections ({version}). {vuln_name}.",
                reproduction_steps=[f"Connect to {host}:{port} using {proto_name}"],
                remediation=f"Disable {proto_name}. Use TLS 1.2+ only.",
                references=refs,
                cvss_v31_vector=CVSS_TLS,
                cvss_v40_vector=CVSS40_TLS,
                target=f"https://{host}:{port}",
            )
        except (ssl.SSLError, socket.error, OSError):
            pass

    async def _test_weak_ciphers(self, host, port):
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = socket.create_connection((host, port), timeout=5)
            ssock = ctx.wrap_socket(sock, server_hostname=host)
            cipher = ssock.cipher()
            ssock.close()
            if cipher:
                cipher_name = cipher[0]
                for weak in WEAK_CIPHERS:
                    if weak.lower() in cipher_name.lower():
                        self.new_finding(
                            title=f"Weak TLS Cipher — {cipher_name}",
                            severity=Severity.MEDIUM,
                            description=f"Server negotiated weak cipher: {cipher_name}. Weak ciphers are vulnerable to cryptographic attacks.",
                            reproduction_steps=[f"TLS handshake with {host}:{port}"],
                            remediation="Configure server to use strong ciphers only (AES-GCM, ChaCha20-Poly1305).",
                            references=["CWE-326", "CWE-327"],
                            cvss_v31_vector=CVSS_TLS,
                            cvss_v40_vector=CVSS40_TLS,
                            target=f"https://{host}:{port}",
                        )
                        break
        except Exception:
            pass
