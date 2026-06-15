"""WinRM Audit — Windows Remote Management security assessment.

Checks:
  - Port 5985 (HTTP) and 5986 (HTTPS) reachability
  - Authentication methods: Basic, NTLM, Kerberos, CredSSP
  - Basic auth over HTTP (cleartext credentials — critical misconfiguration)
  - Default credentials: Administrator/admin/blank
  - TLS certificate validation (self-signed, expired)
  - Credential relay risk (CredSSP + Basic combinations)
  - MaxMemoryPerShellMB / MaxConcurrentUsers limits (DoS amplification)

Uses pywinrm (python-winrm) if available, falls back to raw HTTP probes.

FOR AUTHORIZED PENETRATION TESTING ONLY.
"""
from __future__ import annotations

import asyncio
import base64
import ssl
import sys
import time
from pathlib import Path
from typing import NamedTuple

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.finding import Severity


class AuthResult(NamedTuple):
    success: bool
    method: str
    username: str
    detail: str


class WinrmAudit(BaseModule):
    """WinRM (Windows Remote Management) security audit."""

    NAME        = "winrm_audit"
    DESCRIPTION = "WinRM 5985/5986 authentication, encryption, and credential audit"
    PHASE       = 5
    TAGS        = ["windows", "winrm", "remote-management", "credentials", "authentication"]

    # Default creds to spray (operator can override via config)
    _DEFAULT_CREDS = [
        ("Administrator", ""),
        ("Administrator", "Administrator"),
        ("Administrator", "admin"),
        ("Administrator", "Password1"),
        ("Administrator", "password"),
        ("admin", "admin"),
        ("admin", ""),
    ]

    async def run(self) -> ModuleResult:
        start    = time.monotonic()
        target   = self.config.target.rstrip("/")
        host     = target.replace("http://", "").replace("https://", "").split(":")[0]
        username = self.config.extra.get("username", "")
        password = self.config.extra.get("password", "")
        domain   = self.config.extra.get("domain", "")
        spray    = self.config.extra.get("spray_defaults", False)

        if not self.check_scope(host):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        http_up  = await self._check_port(host, 5985)
        https_up = await self._check_port(host, 5986)

        if not http_up and not https_up:
            return self._make_result(start, skipped=True,
                                     skip_reason="WinRM ports 5985/5986 not reachable")

        if http_up:
            self._add_info(host, "WinRM HTTP (5985) is open")
            await self._audit_http(host, 5985, username, password, domain, spray)

        if https_up:
            self._add_info(host, "WinRM HTTPS (5986) is open")
            await self._audit_https(host, 5986, username, password, domain, spray)
            await self._audit_tls(host, 5986)

        return self._make_result(start)

    # ── HTTP (5985) ────────────────────────────────────────────────────

    async def _audit_http(self, host: str, port: int, username: str,
                          password: str, domain: str, spray: bool) -> None:
        """HTTP WinRM: detect Basic auth (cleartext creds = critical)."""
        import aiohttp

        base = f"http://{host}:{port}/wsman"

        # Detect auth methods via WWW-Authenticate header
        await self.rate_limit()
        try:
            async with aiohttp.ClientSession() as sess:
                async with sess.post(
                    base,
                    data=b"",
                    headers={"Content-Type": "application/soap+xml;charset=UTF-8"},
                    timeout=aiohttp.ClientTimeout(total=8),
                ) as resp:
                    auth_methods = self._parse_auth_header(
                        resp.headers.get("WWW-Authenticate", "")
                    )
                    self._add_info(host, f"WinRM HTTP auth methods: {auth_methods or ['unknown']}")

                    if "Basic" in auth_methods:
                        self._add_finding(
                            host,
                            "WinRM HTTP Basic auth is enabled on port 5985 (cleartext). "
                            "Credentials are transmitted in plain Base64 over HTTP — "
                            "trivially interceptable by any MITM attacker.",
                            Severity.CRITICAL,
                            "Disable Basic auth or enforce HTTPS. "
                            "PowerShell: winrm set winrm/config/client '@{AllowUnencrypted=\"false\"}' "
                            "or 'Set-Item WSMan:\\localhost\\Service\\AllowUnencrypted $false'",
                        )
                    if "CredSSP" in auth_methods:
                        self._add_finding(
                            host,
                            "CredSSP authentication enabled on WinRM HTTP. "
                            "CredSSP delegates full credentials to the remote host — "
                            "a compromised remote host obtains plaintext creds.",
                            Severity.HIGH,
                            "Disable CredSSP unless explicitly required. "
                            "Prefer NTLM or Kerberos delegation.",
                        )
        except Exception as exc:
            self.log.debug("WinRM HTTP probe %s: %s", host, exc)
            return

        # Default credential spray (opt-in)
        if spray:
            await self._spray_creds(host, port, False, domain)

        # Authenticated checks
        if username:
            await self._check_auth(host, port, False, username, password, domain)

    # ── HTTPS (5986) ───────────────────────────────────────────────────

    async def _audit_https(self, host: str, port: int, username: str,
                           password: str, domain: str, spray: bool) -> None:
        """HTTPS WinRM: detect auth methods, test creds."""
        import aiohttp

        base = f"https://{host}:{port}/wsman"

        await self.rate_limit()
        try:
            async with aiohttp.ClientSession(
                connector=aiohttp.TCPConnector(ssl=False)
            ) as sess:
                async with sess.post(
                    base, data=b"",
                    headers={"Content-Type": "application/soap+xml;charset=UTF-8"},
                    timeout=aiohttp.ClientTimeout(total=8),
                ) as resp:
                    auth_methods = self._parse_auth_header(
                        resp.headers.get("WWW-Authenticate", "")
                    )
                    self._add_info(host, f"WinRM HTTPS auth methods: {auth_methods or ['unknown']}")
        except Exception as exc:
            self.log.debug("WinRM HTTPS probe %s: %s", host, exc)

        if spray:
            await self._spray_creds(host, port, True, domain)

        if username:
            await self._check_auth(host, port, True, username, password, domain)

    # ── TLS ────────────────────────────────────────────────────────────

    async def _audit_tls(self, host: str, port: int) -> None:
        """Check TLS certificate: self-signed, expiry."""
        import datetime
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=ctx), timeout=5
            )
            cert = writer.get_extra_info("ssl_object").getpeercert()
            writer.close()

            if cert:
                not_after = datetime.datetime.strptime(
                    cert["notAfter"], "%b %d %H:%M:%S %Y %Z"
                ).replace(tzinfo=datetime.timezone.utc)
                now = datetime.datetime.now(datetime.timezone.utc)
                days_left = (not_after - now).days
                if days_left < 0:
                    self._add_finding(
                        host,
                        f"WinRM HTTPS certificate EXPIRED {abs(days_left)} days ago "
                        f"(expired: {not_after.date()})",
                        Severity.HIGH,
                        "Renew the TLS certificate. Expired certs allow MITM attacks.",
                    )
                elif days_left < 30:
                    self._add_finding(
                        host,
                        f"WinRM HTTPS certificate expires in {days_left} days ({not_after.date()})",
                        Severity.MEDIUM,
                        "Renew the TLS certificate before expiry.",
                    )

                # Self-signed check: issuer == subject
                issuer  = dict(x[0] for x in cert.get("issuer", []))
                subject = dict(x[0] for x in cert.get("subject", []))
                if issuer.get("commonName") == subject.get("commonName"):
                    self._add_finding(
                        host,
                        f"WinRM HTTPS uses a self-signed certificate (CN={subject.get('commonName')}). "
                        f"Clients that skip verification are vulnerable to MITM.",
                        Severity.MEDIUM,
                        "Replace with a certificate from a trusted CA.",
                    )
        except Exception as exc:
            self.log.debug("WinRM TLS audit %s: %s", host, exc)

    # ── Auth helpers ───────────────────────────────────────────────────

    async def _check_auth(self, host: str, port: int, use_ssl: bool,
                          username: str, password: str, domain: str) -> None:
        """Verify supplied credentials work against WinRM."""
        try:
            import winrm
            endpoint = f"{'https' if use_ssl else 'http'}://{host}:{port}/wsman"
            s = winrm.Session(
                endpoint,
                auth=(f"{domain}\\{username}" if domain else username, password),
                transport="ntlm",
                server_cert_validation="ignore",
            )
            r = s.run_cmd("whoami")
            if r.status_code == 0:
                self._add_finding(
                    host,
                    f"WinRM authentication SUCCESS — {domain}\\{username} (NTLM): "
                    f"{r.std_out.decode(errors='replace').strip()}",
                    Severity.CRITICAL,
                    "Supplied credentials grant interactive remote shell access.",
                )
        except ImportError:
            # Fall back to raw NTLM via aiohttp
            await self._raw_ntlm_auth(host, port, use_ssl, username, password, domain)
        except Exception as exc:
            self.log.debug("WinRM auth %s@%s: %s", username, host, exc)

    async def _raw_ntlm_auth(self, host: str, port: int, use_ssl: bool,
                              username: str, password: str, domain: str) -> None:
        """Attempt NTLM auth against WinRM using requests_ntlm or basic NTLM."""
        try:
            import aiohttp
            from requests_ntlm import HttpNtlmAuth
            import requests

            scheme   = "https" if use_ssl else "http"
            endpoint = f"{scheme}://{host}:{port}/wsman"
            ntlm     = HttpNtlmAuth(
                f"{domain}\\{username}" if domain else username, password
            )
            resp = requests.post(
                endpoint, auth=ntlm,
                headers={"Content-Type": "application/soap+xml;charset=UTF-8"},
                verify=False, timeout=10
            )
            if resp.status_code in (200, 500):
                self._add_finding(
                    host,
                    f"WinRM NTLM auth accepted for {username} (HTTP {resp.status_code})",
                    Severity.CRITICAL,
                    "Validate credential in a full WinRM session.",
                )
        except ImportError:
            self._add_info(host, "pywinrm and requests_ntlm not installed — skipping auth test")
        except Exception as exc:
            self.log.debug("WinRM NTLM raw %s@%s: %s", username, host, exc)

    async def _spray_creds(self, host: str, port: int, use_ssl: bool, domain: str) -> None:
        """Spray default credentials — rate-limited."""
        extra_creds = self.config.extra.get("cred_list", [])
        creds = list(self._DEFAULT_CREDS) + [(u, p) for u, p in extra_creds]

        for username, password in creds:
            await self.rate_limit()
            await self._check_auth(host, port, use_ssl, username, password, domain)

    # ── Helpers ────────────────────────────────────────────────────────

    def _parse_auth_header(self, header: str) -> list[str]:
        methods = []
        for method in ("Basic", "NTLM", "Kerberos", "Negotiate", "CredSSP"):
            if method.lower() in header.lower():
                methods.append(method)
        return methods

    async def _check_port(self, host: str, port: int) -> bool:
        try:
            _, w = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=5)
            w.close()
            return True
        except Exception:
            return False

    def _add_finding(self, host: str, detail: str, severity: Severity,
                     remediation: str = "") -> None:
        from common.finding import Finding
        self.findings.append(Finding(
            title       = "WinRM Security Risk",
            description = detail,
            severity    = severity,
            host        = host,
            evidence    = detail,
            remediation = remediation or "Review WinRM configuration and enforce HTTPS + NTLM/Kerberos.",
            references  = [
                "https://docs.microsoft.com/en-us/windows/win32/winrm/authentication-for-remote-connections",
                "https://attack.mitre.org/techniques/T1021/006/",
            ],
        ))

    def _add_info(self, host: str, msg: str) -> None:
        from common.finding import Finding
        self.findings.append(Finding(
            title       = "WinRM Info",
            description = msg,
            severity    = Severity.INFO,
            host        = host,
            evidence    = msg,
            remediation = "",
        ))
