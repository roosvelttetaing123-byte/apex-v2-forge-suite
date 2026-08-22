"""Credential Sprayer — low-and-slow password spray across multiple protocols.

Sprays a single password against many accounts to avoid lockout:
  - SSH, FTP, RDP, HTTP Basic, SMB
  - Configurable delay between attempts
  - Lockout-aware pacing
"""
from __future__ import annotations

import asyncio
import sys
import time
from pathlib import Path
from typing import NoReturn

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.action_authorization import protected_credential_reference
from common.evidence import Evidence
from common.finding import Severity
from common.outbound_policy import OutboundDenied, OutboundReason
from common.redaction import redact_secret_fragments

CVSS_SPRAY      = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
CVSS40_SPRAY    = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N"

SPRAY_PASSWORDS = [
    "Password1", "Welcome1", "Changeme1", "Company123",
    "Summer2024", "Winter2024", "P@ssw0rd", "Password123",
]


def _deny_unmigrated_credential_effect() -> NoReturn:
    """Keep legacy credential transports inert pending protected adapters."""
    raise OutboundDenied(OutboundReason.OUTBOUND_POLICY_UNSUPPORTED)


class CredSpray(BaseModule):
    """Low-and-slow credential spray across protocols."""

    NAME        = "cred_spray"
    DESCRIPTION = "Credential spray: low-and-slow password spray (SSH, SMB, HTTP)"
    PHASE       = 5
    TAGS        = ["bruteforce", "spray", "cwe-307"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        target = self.config.target

        if not self.check_scope(target):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        hosts = self.config.extra.get("live_hosts", [target])
        usernames = self.config.extra.get("spray_users", [])
        passwords = self.config.extra.get("spray_passwords", SPRAY_PASSWORDS)
        delay = self.config.extra.get("spray_delay_seconds", 30)

        if not usernames:
            self.log.info("No usernames provided for spray — skipping")
            return self._make_result(start, skipped=True, skip_reason="no usernames")

        # Spray one password at a time across all users
        for password in passwords[:5]:
            self.log.info(
                "Spraying one protected credential candidate across %d users",
                len(usernames),
            )
            for host in hosts[:5]:
                if not self.check_scope(host):
                    continue
                for username in usernames[:50]:
                    await self.rate_limit()
                    # Try SSH
                    if await self._try_ssh(host, username, password):
                        self._report_success(host, 22, "ssh", username, password)
                    # Try SMB
                    if await self._try_smb(host, username, password):
                        self._report_success(host, 445, "smb", username, password)

            # Delay between password rounds to avoid lockout
            if delay > 0:
                self.log.info("Spray delay: waiting %ds before next password", delay)
                await asyncio.sleep(delay)

        return self._make_result(start)

    async def _try_ssh(self, host: str, username: str, password: str) -> bool:
        _deny_unmigrated_credential_effect()
        try:
            import paramiko
            client = paramiko.SSHClient()
            client.load_system_host_keys()
            client.set_missing_host_key_policy(paramiko.RejectPolicy())
            client.connect(
                host, port=22, username=username, password=password,
                timeout=5, look_for_keys=False, allow_agent=False,
            )
            client.close()
            return True
        except Exception:
            return False

    async def _try_smb(self, host: str, username: str, password: str) -> bool:
        _deny_unmigrated_credential_effect()
        try:
            from impacket.smbconnection import SMBConnection
            conn = SMBConnection(host, host, timeout=5)
            conn.login(username, password)
            conn.close()
            return True
        except Exception:
            return False

    def _report_success(
        self, host: str, port: int, service: str, username: str, password: str
    ) -> None:
        secret_values = (password,)
        safe_host = redact_secret_fragments(host, secret_values)
        safe_service = redact_secret_fragments(service, secret_values)
        safe_username = redact_secret_fragments(username, secret_values)
        reference = protected_credential_reference(
            {
                "host": safe_host,
                "service": safe_service,
                "username": safe_username,
                "source": self.NAME,
            }
        )
        cred_engine = self.config.extra.get("cred_engine")
        if cred_engine is not None and callable(getattr(cred_engine, "add", None)):
            try:
                stored = cred_engine.add(
                    safe_host,
                    safe_service,
                    safe_username,
                    password=password,
                    source=self.NAME,
                )
                safe = stored.to_dict()
                reference = str(safe.get("credential_reference") or reference)
            except Exception:
                self.log.debug("Credential reference storage failed")
        ev = Evidence(
            extra={
                "host": safe_host, "port": port, "service": safe_service,
                "username": safe_username, "credential_reference": reference,
            },
        )
        self.new_finding(
            title=(
                f"Password Spray Success — "
                f"{safe_username}@{safe_host}/{safe_service}"
            ),
            severity=Severity.CRITICAL,
            description=(
                f"Credential spray found valid login:\n"
                f"  {safe_username} on {safe_host}:{port} ({safe_service})\n"
                f"  Credential reference: {reference}\n\n"
                "Password spraying bypasses account lockout by trying one password "
                "against many accounts before moving to the next password."
            ),
            reproduction_steps=[
                f"Use the protected credential reference for {safe_service}: {reference}",
            ],
            remediation=(
                "1. Change the password immediately\n"
                "2. Enforce strong password policy\n"
                "3. Enable MFA for all remote access\n"
                "4. Implement smart lockout (Azure AD) or progressive delays"
            ),
            references=["CWE-307", "CWE-521", "MITRE T1110.003"],
            evidence=ev,
            cvss_v31_vector=CVSS_SPRAY,
            cvss_v40_vector=CVSS40_SPRAY,
            mitre_attack=["TA0006/T1110.003"],
            port=port, service=safe_service, target=safe_host,
        )


class TestCredSpray:
    def test_passwords(self) -> None:
        assert "Password1" in SPRAY_PASSWORDS

    def test_cvss(self) -> None:
        assert CVSS_SPRAY.startswith("CVSS:3.1")

    def test_phase(self) -> None:
        assert CredSpray.PHASE == 5
