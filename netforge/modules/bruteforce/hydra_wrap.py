"""Hydra Wrapper — credential brute force via THC-Hydra.

Wraps hydra CLI for:
  - Multi-protocol credential brute force (SSH, FTP, RDP, HTTP, etc.)
  - Wordlist-based and spray attacks
  - Rate-limited execution
  - Result parsing
"""
from __future__ import annotations

import asyncio
import re
import shutil
import sys
import time
from pathlib import Path
from typing import NoReturn

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.action_authorization import protected_credential_reference
from common.credential_boundary import protected_artifact
from common.evidence import Evidence
from common.finding import Severity
from common.outbound_policy import OutboundDenied, OutboundReason
from common.redaction import redact_secret_fragments

CVSS_BRUTE      = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
CVSS40_BRUTE    = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N"

# Default small wordlists for non-destructive testing
DEFAULT_USERS = ["admin", "root", "test", "user", "guest", "operator"]
DEFAULT_PASSWORDS = [
    "admin", "password", "123456", "root", "test", "guest",
    "changeme", "default", "letmein", "welcome", "P@ssw0rd",
]


def _deny_unmigrated_credential_effect() -> NoReturn:
    """Keep legacy credential transports inert pending protected adapters."""
    raise OutboundDenied(OutboundReason.OUTBOUND_POLICY_UNSUPPORTED)


class HydraWrap(BaseModule):
    """THC-Hydra credential brute force wrapper."""

    NAME        = "hydra_wrap"
    DESCRIPTION = "Hydra: multi-protocol credential brute force (SSH, FTP, RDP, HTTP)"
    PHASE       = 5
    TAGS        = ["bruteforce", "credentials", "cwe-307"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        target = self.config.target

        if not self.check_scope(target):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        hydra = shutil.which("hydra")
        if not hydra:
            self.log.info("hydra not found — using built-in brute force")
            await self._builtin_brute(target)
            return self._make_result(start)

        # Get services to brute force from service_map
        service_map = self.config.extra.get("service_map", {})
        hosts = self.config.extra.get("live_hosts", [target])

        for host in hosts[:5]:
            if not self.check_scope(host):
                continue
            services = service_map.get(host, [])
            for svc in services:
                service = svc.get("service", "")
                port = svc.get("port", 0)
                if service in ["ssh", "ftp", "rdp", "mysql", "mssql", "postgresql", "vnc"]:
                    await self.rate_limit()
                    await self._run_hydra(hydra, host, port, service)

        return self._make_result(start)

    async def _run_hydra(
        self, hydra: str, host: str, port: int, service: str
    ) -> None:
        _deny_unmigrated_credential_effect()
        users = self.config.extra.get("brute_users", DEFAULT_USERS)
        passwords = self.config.extra.get("brute_passwords", DEFAULT_PASSWORDS)
        user_data = "\n".join(users).encode("utf-8")
        password_data = "\n".join(passwords).encode("utf-8")

        with (
            protected_artifact(user_data, suffix=".txt") as user_artifact,
            protected_artifact(password_data, suffix=".txt") as password_artifact,
        ):
            # Map service names to hydra protocols
            hydra_service = {
                "ssh": "ssh", "ftp": "ftp", "rdp": "rdp",
                "mysql": "mysql", "mssql": "mssql",
                "postgresql": "postgres", "vnc": "vnc",
            }.get(service, service)

            threads = self.config.extra.get("hydra_threads", 4)
            cmd = [
                hydra,
                "-L", str(user_artifact.path),
                "-P", str(password_artifact.path),
                "-s", str(port),
                "-t", str(threads),
                "-f",  # Stop after first valid pair
                "-o", "-",  # Output to stdout
                f"{host}", hydra_service,
            ]

            self.log.info("Running hydra: %s:%d/%s", host, port, service)

            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=120)
            output = stdout.decode(errors="ignore")

            # Parse hydra output for successful logins
            # Format: [port][service] host:   login: user   password: pass
            for m in re.finditer(
                r"\[(\d+)\]\[(\S+)\]\s+host:\s+(\S+)\s+login:\s+(\S+)\s+password:\s+(\S*)",
                output,
            ):
                _found_port, _found_svc, _found_host, user, password = m.groups()
                # Target/service facts come from the authorized invocation,
                # never from subprocess-controlled output text.
                self._report_success(host, port, service, user, password)

    async def _builtin_brute(self, target: str) -> None:
        """Minimal built-in SSH brute force when hydra is not available."""
        _deny_unmigrated_credential_effect()
        try:
            import paramiko
        except ImportError:
            return

        for user in DEFAULT_USERS[:3]:
            for password in DEFAULT_PASSWORDS[:5]:
                await self.rate_limit()
                try:
                    client = paramiko.SSHClient()
                    client.load_system_host_keys()
                    client.set_missing_host_key_policy(paramiko.RejectPolicy())
                    client.connect(
                        target, port=22, username=user, password=password,
                        timeout=5, look_for_keys=False, allow_agent=False,
                    )
                    client.close()

                    self._report_success(target, 22, "ssh", user, password)
                    return
                except Exception:
                    pass

    def _report_success(
        self,
        host: str,
        port: int,
        service: str,
        username: str,
        password: str,
    ) -> None:
        """Report only a protected reference; keep parsed plaintext transient."""
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
            request_raw=(
                f"credential attempt via protected reference {reference} "
                f"for {safe_host}:{port}/{safe_service}"
            ),
            extra={
                "host": safe_host,
                "port": port,
                "service": safe_service,
                "username": safe_username,
                "credential_reference": reference,
            },
        )
        self.new_finding(
            title=(
                f"Brute Force Success — "
                f"{safe_username}@{safe_host}:{port}/{safe_service}"
            ),
            severity=Severity.CRITICAL,
            description=(
                "Valid credentials were found via bounded authentication attempts.\n"
                f"Host: {safe_host}:{port}\nService: {safe_service}\n"
                f"Username: {safe_username}\nCredential reference: {reference}"
            ),
            reproduction_steps=[
                f"Use the protected credential reference for retest: {reference}",
            ],
            remediation=(
                "1. Change the password immediately\n"
                "2. Implement account lockout after failed attempts\n"
                "3. Enable MFA where possible\n"
                "4. Use strong password policy"
            ),
            references=["CWE-307", "CWE-521"],
            evidence=ev,
            cvss_v31_vector=CVSS_BRUTE,
            cvss_v40_vector=CVSS40_BRUTE,
            mitre_attack=["TA0006/T1110"],
            port=port,
            service=safe_service,
            target=safe_host,
        )


class TestHydraWrap:
    def test_defaults(self) -> None:
        assert "admin" in DEFAULT_USERS
        assert "password" in DEFAULT_PASSWORDS

    def test_cvss(self) -> None:
        assert CVSS_BRUTE.startswith("CVSS:3.1")

    def test_phase(self) -> None:
        assert HydraWrap.PHASE == 5
