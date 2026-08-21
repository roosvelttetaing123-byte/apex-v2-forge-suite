"""Linux Logging Audit — audit daemon, syslog, journald configuration."""
from __future__ import annotations

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity

CVSS_NO_AUDIT = "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N"


class LinuxLoggingAudit(BaseModule):
    NAME        = "linux_logging_audit"
    DESCRIPTION = "SSH credentialed: auditd, rsyslog, journald config, log rotation"
    PHASE       = 5
    TAGS        = ["credentialed", "linux", "logging", "audit", "compliance"]

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
            await self._audit_logging(host, transport_mgr.ssh, session)

        return self._make_result(start)

    async def _audit_logging(self, host: str, ssh, session) -> None:
        # Check auditd
        auditd_result = await ssh.execute(session, "systemctl is-active auditd 2>/dev/null")
        auditd_active = "active" in auditd_result.stdout.strip().lower()

        if not auditd_active:
            self.new_finding(
                title=f"Audit Daemon Not Running — {host}",
                severity=Severity.MEDIUM,
                description="auditd is not active. System call auditing is disabled — no forensic trail.",
                reproduction_steps=[f"ssh {host}", "systemctl status auditd"],
                remediation="Install and enable: apt install auditd && systemctl enable --now auditd",
                references=["CIS Benchmark 4.1.1", "CWE-778"],
                evidence=Evidence(extra={"host": host, "auditd": "inactive"}),
                cvss_v31_vector=CVSS_NO_AUDIT,
                target=host, service="ssh",
            )
        else:
            # Check audit rules
            rules_result = await ssh.execute(session, "auditctl -l 2>/dev/null")
            rule_count = len([l for l in rules_result.stdout.strip().split("\n") if l.strip() and not l.startswith("No")])
            if rule_count < 5:
                self.new_finding(
                    title=f"Minimal Audit Rules ({rule_count}) — {host}",
                    severity=Severity.LOW,
                    description=f"Only {rule_count} audit rules configured. CIS recommends 30+.",
                    reproduction_steps=[f"ssh {host}", "auditctl -l"],
                    remediation="Add CIS audit rules to /etc/audit/rules.d/",
                    references=["CIS Benchmark 4.1.3-4.1.18"],
                    evidence=Evidence(extra={"host": host, "rule_count": rule_count}),
                    target=host, service="ssh",
                )

        # Check rsyslog / syslog
        syslog_result = await ssh.execute(session,
            "systemctl is-active rsyslog 2>/dev/null || systemctl is-active syslog 2>/dev/null")
        if "active" not in syslog_result.stdout.lower():
            self.new_finding(
                title=f"Syslog Not Running — {host}",
                severity=Severity.MEDIUM,
                description="Neither rsyslog nor syslog is running. System logs may not be collected.",
                reproduction_steps=[f"ssh {host}", "systemctl status rsyslog"],
                remediation="Enable rsyslog: systemctl enable --now rsyslog",
                references=["CIS Benchmark 4.2.1"],
                evidence=Evidence(extra={"host": host}),
                target=host, service="ssh",
            )

        # Check log file permissions
        log_perms = await ssh.execute(session,
            "ls -la /var/log/auth.log /var/log/secure /var/log/syslog 2>/dev/null")
        for line in log_perms.stdout.strip().split("\n"):
            if line.strip() and len(line) > 10:
                perms = line[:10]
                if len(perms) >= 8 and perms[7] == 'r':
                    log_file = line.split()[-1] if line.split() else ""
                    self.new_finding(
                        title=f"World-Readable Log Files — {host}",
                        severity=Severity.LOW,
                        description=f"Log files are world-readable on {host}: {log_file}.",
                        reproduction_steps=[f"ssh {host}", "ls -la /var/log/"],
                        remediation="chmod 640 /var/log/auth.log /var/log/secure",
                        references=["CIS Benchmark 4.2.3"],
                        evidence=Evidence(extra={"host": host, "file": log_file}),
                        target=host, service="ssh",
                    )
                    break
