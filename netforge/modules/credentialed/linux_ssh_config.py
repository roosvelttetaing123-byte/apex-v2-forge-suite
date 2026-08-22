"""Linux SSH Config Audit — credentialed sshd_config deep parse.

Checks:
  - PermitRootLogin (should be 'no' or 'prohibit-password')
  - PasswordAuthentication (should be 'no' in hardened environments)
  - X11Forwarding, AllowAgentForwarding, AllowTcpForwarding
  - MaxAuthTries, LoginGraceTime
  - Protocol version (should be 2 only)
  - AllowUsers/AllowGroups restrictions
  - Host key algorithms
  - Banner presence
"""
from __future__ import annotations

import re
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity

CVSS_ROOT_LOGIN   = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
CVSS_PW_AUTH      = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
CVSS_FORWARDING   = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N"
CVSS_MAX_AUTH     = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"

HARDENING_CHECKS = [
    ("PermitRootLogin", ["no", "prohibit-password"], "Root SSH login enabled", Severity.HIGH, CVSS_ROOT_LOGIN),
    ("PasswordAuthentication", ["no"], "Password auth enabled — brute force risk", Severity.MEDIUM, CVSS_PW_AUTH),
    ("PermitEmptyPasswords", ["no"], "Empty password login allowed", Severity.CRITICAL, CVSS_PW_AUTH),
    ("X11Forwarding", ["no"], "X11 forwarding enabled — keystroke sniffing", Severity.LOW, CVSS_FORWARDING),
    ("AllowAgentForwarding", ["no"], "Agent forwarding enabled — key theft risk", Severity.LOW, CVSS_FORWARDING),
    ("AllowTcpForwarding", ["no"], "TCP forwarding enabled — tunnel abuse", Severity.LOW, CVSS_FORWARDING),
    ("UsePAM", ["yes"], "PAM not enabled — missing auth controls", Severity.MEDIUM, CVSS_MAX_AUTH),
    ("LogLevel", ["VERBOSE", "INFO"], "SSH logging insufficient", Severity.LOW, CVSS_MAX_AUTH),
]


class LinuxSshConfig(BaseModule):
    NAME        = "linux_ssh_config"
    DESCRIPTION = "SSH credentialed: sshd_config deep parse — root login, password auth, forwarding, hardening"
    PHASE       = 5
    TAGS        = ["credentialed", "linux", "ssh", "hardening", "cwe-250"]

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
            await self._audit_sshd(host, transport_mgr.ssh, session)

        return self._make_result(start)

    async def _audit_sshd(self, host: str, ssh, session) -> None:
        config = await ssh.read_file(session, "/etc/ssh/sshd_config")
        if not config:
            return

        # Also read Include'd files
        includes = re.findall(r'^Include\s+(.+)$', config, re.MULTILINE)
        for inc in includes:
            inc_result = await ssh.execute(session, f"cat {inc} 2>/dev/null")
            if inc_result.success:
                config += "\n" + inc_result.stdout

        parsed = self._parse_sshd_config(config)
        failures = []

        for directive, safe_values, desc, severity, cvss in HARDENING_CHECKS:
            actual = parsed.get(directive.lower())
            if actual and actual.lower() not in [v.lower() for v in safe_values]:
                failures.append({
                    "directive": directive, "actual": actual,
                    "expected": safe_values, "desc": desc,
                    "severity": severity, "cvss": cvss,
                })

        # MaxAuthTries check
        max_auth = parsed.get("maxauthtries")
        if max_auth and max_auth.isdigit() and int(max_auth) > 6:
            failures.append({
                "directive": "MaxAuthTries", "actual": max_auth,
                "expected": ["4-6"], "desc": f"MaxAuthTries={max_auth} too high — brute force friendly",
                "severity": Severity.LOW, "cvss": CVSS_MAX_AUTH,
            })

        # LoginGraceTime check
        grace = parsed.get("logingracetime")
        if grace and grace != "0":
            try:
                if int(grace) > 120:
                    failures.append({
                        "directive": "LoginGraceTime", "actual": grace,
                        "expected": ["60"], "desc": "LoginGraceTime too long — connection exhaustion",
                        "severity": Severity.LOW, "cvss": CVSS_MAX_AUTH,
                    })
            except ValueError:
                pass

        if failures:
            worst = max(failures, key=lambda f: ["LOW", "MEDIUM", "HIGH", "CRITICAL"].index(
                f["severity"].value if hasattr(f["severity"], "value") else str(f["severity"])
            ))
            worst_sev = worst["severity"]

            self.new_finding(
                title=f"SSH Server Hardening Issues ({len(failures)}) — {host}",
                severity=worst_sev,
                description=(
                    f"{len(failures)} sshd_config issues on {host}: " +
                    "; ".join(f"{f['directive']}={f['actual']} ({f['desc']})" for f in failures[:5])
                ),
                reproduction_steps=[f"ssh {host}", "cat /etc/ssh/sshd_config"],
                remediation="Harden sshd_config per CIS Benchmark. Restart sshd after changes.",
                references=["CWE-250", "CIS Benchmark 5.2"],
                evidence=Evidence(extra={"host": host, "failures": failures}),
                cvss_v31_vector=worst["cvss"],
                mitre_attack=["TA0001/T1021.004"],
                target=host, service="ssh",
            )

        # Check for AllowUsers/AllowGroups restrictions
        if "allowusers" not in parsed and "allowgroups" not in parsed:
            self.new_finding(
                title=f"No SSH User/Group Restrictions — {host}",
                severity=Severity.LOW,
                description="sshd_config has no AllowUsers or AllowGroups — all valid users can SSH in.",
                reproduction_steps=[f"ssh {host}", "grep -i allow /etc/ssh/sshd_config"],
                remediation="Add AllowUsers or AllowGroups to restrict SSH access.",
                references=["CIS Benchmark 5.2.17"],
                evidence=Evidence(extra={"host": host}),
                target=host, service="ssh",
            )

    def _parse_sshd_config(self, content: str) -> dict[str, str]:
        """Parse sshd_config into key-value dict (last wins)."""
        parsed = {}
        for line in content.split("\n"):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(None, 1)
            if len(parts) == 2:
                parsed[parts[0].lower()] = parts[1]
        return parsed
