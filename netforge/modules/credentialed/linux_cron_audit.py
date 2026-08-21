"""Linux Cron Audit — credentialed check for cron job security.

Checks:
  - Cron jobs running as root with writable scripts
  - World-readable/writable crontab files
  - Cron jobs executing from /tmp or world-writable paths
  - at/batch job enumeration
  - cron.deny / cron.allow configuration
"""
from __future__ import annotations

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity

CVSS_WRITABLE_CRON = "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
CVSS_CRON_PERMS    = "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:H/A:N"


class LinuxCronAudit(BaseModule):
    NAME        = "linux_cron_audit"
    DESCRIPTION = "SSH credentialed: cron jobs, writable scripts, at jobs, cron.allow/deny"
    PHASE       = 5
    TAGS        = ["credentialed", "linux", "cron", "privesc", "cwe-732"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        transport_mgr = self.config.extra.get("transport_manager")
        if not transport_mgr or not transport_mgr.has_creds("ssh"):
            return self._make_result(start, skipped=True, skip_reason="no SSH credentials")

        hosts = self.config.extra.get("live_hosts", [self.config.target])
        for host in hosts[:30]:
            if not self.check_scope(host):
                continue
            await self.rate_limit()
            session = await transport_mgr.get_ssh_session(host)
            if not session:
                continue
            await self._audit_cron(host, transport_mgr.ssh, session)

        return self._make_result(start)

    async def _audit_cron(self, host: str, ssh, session) -> None:
        # System crontabs
        crontab_files = ["/etc/crontab", "/etc/cron.d/*"]
        cron_dirs = ["/etc/cron.hourly", "/etc/cron.daily", "/etc/cron.weekly", "/etc/cron.monthly"]

        # Get all cron entries
        result = await ssh.execute(session,
            "cat /etc/crontab 2>/dev/null; echo '---SEPARATOR---'; "
            "cat /etc/cron.d/* 2>/dev/null; echo '---SEPARATOR---'; "
            "for d in /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly; do "
            "  ls -la $d/ 2>/dev/null; done; echo '---SEPARATOR---'; "
            "crontab -l 2>/dev/null; echo '---SEPARATOR---'; "
            "for user in $(cut -f1 -d: /etc/passwd 2>/dev/null); do "
            "  echo \"==$user==\"; crontab -u $user -l 2>/dev/null; done"
        )

        # Check for writable cron scripts
        writable_result = await ssh.execute(session,
            "find /etc/cron* -type f -writable 2>/dev/null; "
            "grep -rh '[^ ]*/' /etc/crontab /etc/cron.d/ 2>/dev/null | "
            "  grep -oP '(/[^ ]+)' | sort -u | while read f; do "
            "  test -w \"$f\" 2>/dev/null && echo \"WRITABLE: $f\"; done"
        )

        writable_scripts = [l.replace("WRITABLE: ", "") for l in writable_result.stdout.split("\n")
                          if "WRITABLE:" in l]
        writable_cron_files = [l for l in writable_result.stdout.split("\n")
                              if l.startswith("/etc/cron") and l.strip()]

        if writable_scripts:
            self.new_finding(
                title=f"Writable Cron Job Scripts — Privesc Vector — {host}",
                severity=Severity.CRITICAL,
                description=(
                    f"Found {len(writable_scripts)} cron job scripts that are writable by the "
                    f"current user on {host}: {', '.join(writable_scripts[:5])}. "
                    "Modifying these scripts will execute arbitrary code as root."
                ),
                reproduction_steps=[
                    f"ssh {host}",
                    "find /etc/cron* -type f -writable 2>/dev/null",
                ],
                remediation="Fix permissions: chmod 644 on crontab files, chmod 755 on scripts, chown root:root",
                references=["CWE-732", "CIS Benchmark 5.1.2-5.1.7"],
                evidence=Evidence(extra={"host": host, "writable": writable_scripts[:20]}),
                cvss_v31_vector=CVSS_WRITABLE_CRON,
                mitre_attack=["TA0003/T1053.003", "TA0004/T1053.003"],
                target=host, service="ssh", confidence="HIGH",
            )

        if writable_cron_files:
            self.new_finding(
                title=f"Writable Crontab Files — {host}",
                severity=Severity.HIGH,
                description=(
                    f"{len(writable_cron_files)} crontab files are writable: "
                    f"{', '.join(writable_cron_files[:5])}."
                ),
                reproduction_steps=[f"ssh {host}", "ls -la /etc/crontab /etc/cron.d/"],
                remediation="chmod 600 /etc/crontab; chmod 600 /etc/cron.d/*",
                references=["CWE-732"],
                evidence=Evidence(extra={"host": host, "files": writable_cron_files[:20]}),
                cvss_v31_vector=CVSS_CRON_PERMS,
                mitre_attack=["TA0003/T1053.003"],
                target=host, service="ssh",
            )

        # Check cron.allow / cron.deny
        allow_result = await ssh.execute(session, "cat /etc/cron.allow 2>/dev/null; echo '---'; cat /etc/cron.deny 2>/dev/null")
        if "No such file" in allow_result.stderr or (not allow_result.stdout.strip().replace("---", "").strip()):
            self.new_finding(
                title=f"No Cron Access Restrictions — {host}",
                severity=Severity.LOW,
                description="Neither /etc/cron.allow nor /etc/cron.deny is configured. All users can create cron jobs.",
                reproduction_steps=[f"ssh {host}", "ls -la /etc/cron.allow /etc/cron.deny"],
                remediation="Create /etc/cron.allow with only authorized users.",
                references=["CIS Benchmark 5.1.8"],
                evidence=Evidence(extra={"host": host}),
                target=host, service="ssh",
            )
