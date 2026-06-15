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

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity

CVSS_BRUTE      = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
CVSS40_BRUTE    = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N"

# Default small wordlists for non-destructive testing
DEFAULT_USERS = ["admin", "root", "test", "user", "guest", "operator"]
DEFAULT_PASSWORDS = [
    "admin", "password", "123456", "root", "test", "guest",
    "changeme", "default", "letmein", "welcome", "P@ssw0rd",
]


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
        # Create temp user/pass files
        import tempfile
        import os

        user_file = tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False)
        pass_file = tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False)

        users = self.config.extra.get("brute_users", DEFAULT_USERS)
        passwords = self.config.extra.get("brute_passwords", DEFAULT_PASSWORDS)

        user_file.write("\n".join(users))
        user_file.close()
        pass_file.write("\n".join(passwords))
        pass_file.close()

        try:
            # Map service names to hydra protocols
            hydra_service = {
                "ssh": "ssh", "ftp": "ftp", "rdp": "rdp",
                "mysql": "mysql", "mssql": "mssql",
                "postgresql": "postgres", "vnc": "vnc",
            }.get(service, service)

            threads = self.config.extra.get("hydra_threads", 4)
            cmd = [
                hydra,
                "-L", user_file.name,
                "-P", pass_file.name,
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
                found_port, found_svc, found_host, user, password = m.groups()
                ev = Evidence(
                    request_raw=f"hydra -l {user} -p {password} {host} {service}",
                    extra={
                        "host": host, "port": port, "service": service,
                        "username": user, "password": password or "(empty)",
                    },
                )
                self.new_finding(
                    title=f"Brute Force Success — {user}:{password}@{host}:{port}/{service}",
                    severity=Severity.CRITICAL,
                    description=(
                        f"Valid credentials found via brute force:\n"
                        f"  Host: {host}:{port}\n"
                        f"  Service: {service}\n"
                        f"  Username: {user}\n"
                        f"  Password: {password or '(empty)'}"
                    ),
                    reproduction_steps=[
                        f"hydra -l {user} -p '{password}' -s {port} {host} {service}",
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
                    port=port, service=service, target=host,
                )
        finally:
            os.unlink(user_file.name)
            os.unlink(pass_file.name)

    async def _builtin_brute(self, target: str) -> None:
        """Minimal built-in SSH brute force when hydra is not available."""
        try:
            import paramiko
        except ImportError:
            return

        for user in DEFAULT_USERS[:3]:
            for password in DEFAULT_PASSWORDS[:5]:
                await self.rate_limit()
                try:
                    client = paramiko.SSHClient()
                    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    client.connect(
                        target, port=22, username=user, password=password,
                        timeout=5, look_for_keys=False, allow_agent=False,
                    )
                    client.close()

                    ev = Evidence(
                        extra={"username": user, "password": password, "service": "ssh"},
                    )
                    self.new_finding(
                        title=f"SSH Brute Force Success — {user}@{target}:22",
                        severity=Severity.CRITICAL,
                        description=f"SSH login with {user}:{password} on {target}:22",
                        reproduction_steps=[f"ssh {user}@{target}  # password: {password}"],
                        remediation="Change password. Enable MFA. Disable password auth (use keys).",
                        references=["CWE-307"],
                        evidence=ev,
                        cvss_v31_vector=CVSS_BRUTE,
                        cvss_v40_vector=CVSS40_BRUTE,
                        port=22, service="ssh", target=target,
                    )
                    return
                except Exception:
                    pass


class TestHydraWrap:
    def test_defaults(self) -> None:
        assert "admin" in DEFAULT_USERS
        assert "password" in DEFAULT_PASSWORDS

    def test_cvss(self) -> None:
        assert CVSS_BRUTE.startswith("CVSS:3.1")

    def test_phase(self) -> None:
        assert HydraWrap.PHASE == 5
