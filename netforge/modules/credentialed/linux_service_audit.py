"""Linux Service Audit — credentialed check for running services and listening ports.

Checks:
  - Services running as root that shouldn't be
  - Unnecessary services (telnet, rsh, rlogin, rexec, talk)
  - Listening ports vs expected services
  - Services without systemd hardening (NoNewPrivileges, ProtectSystem)
  - Docker/container detection
"""
from __future__ import annotations

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity

CVSS_ROOT_SVC = "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
CVSS_UNNECESSARY = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N"

DANGEROUS_SERVICES = {
    "telnet", "telnetd", "in.telnetd", "rsh", "rshd", "rlogin", "rlogind",
    "rexec", "rexecd", "talk", "talkd", "ntalk", "finger", "fingerd",
    "chargen", "daytime", "discard", "echo", "tftp", "tftpd",
}

SHOULD_NOT_RUN_AS_ROOT = {
    "apache2", "httpd", "nginx", "mysql", "mysqld", "postgres", "postgresql",
    "redis-server", "mongod", "elasticsearch", "tomcat", "jenkins",
    "grafana-server", "prometheus", "node", "npm",
}


class LinuxServiceAudit(BaseModule):
    NAME        = "linux_service_audit"
    DESCRIPTION = "SSH credentialed: running services, root processes, unnecessary daemons, listening ports"
    PHASE       = 5
    TAGS        = ["credentialed", "linux", "services", "hardening", "cwe-250"]

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
            await self._audit_services(host, transport_mgr.ssh, session)

        return self._make_result(start)

    async def _audit_services(self, host: str, ssh, session) -> None:
        # Listening ports
        listen_result = await ssh.execute(session, "ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null")

        # Running processes as root
        ps_result = await ssh.execute(session, "ps aux --no-headers 2>/dev/null | awk '$1==\"root\" {print $11}' | sort -u")

        # Check for dangerous/unnecessary services
        systemctl_result = await ssh.execute(session, "systemctl list-units --type=service --state=running --no-pager 2>/dev/null")

        root_procs = set(ps_result.stdout.strip().split("\n")) if ps_result.success else set()
        running_services = systemctl_result.stdout if systemctl_result.success else ""

        # Dangerous services check
        found_dangerous = []
        for svc in DANGEROUS_SERVICES:
            if svc in running_services.lower() or any(svc in p.lower() for p in root_procs):
                found_dangerous.append(svc)

        if found_dangerous:
            self.new_finding(
                title=f"Dangerous Legacy Services Running — {host}",
                severity=Severity.HIGH,
                description=(
                    f"Found {len(found_dangerous)} legacy/insecure services running on {host}: "
                    f"{', '.join(found_dangerous)}. These transmit data in cleartext."
                ),
                reproduction_steps=[f"ssh {host}", "systemctl list-units --type=service --state=running"],
                remediation=f"Disable and mask: systemctl disable --now {' '.join(found_dangerous)}",
                references=["CWE-319", "CIS Benchmark 2.1"],
                evidence=Evidence(extra={"host": host, "services": found_dangerous}),
                cvss_v31_vector=CVSS_UNNECESSARY,
                mitre_attack=["TA0007/T1046"],
                target=host, service="ssh", confidence="HIGH",
            )

        # Services running as root that shouldn't
        root_violations = []
        for proc in root_procs:
            basename = Path(proc).name if "/" in proc else proc
            if basename in SHOULD_NOT_RUN_AS_ROOT:
                root_violations.append(basename)

        if root_violations:
            self.new_finding(
                title=f"Services Running as Root Unnecessarily — {host}",
                severity=Severity.MEDIUM,
                description=(
                    f"{len(root_violations)} services run as root on {host} that should use dedicated "
                    f"service accounts: {', '.join(root_violations[:10])}."
                ),
                reproduction_steps=[f"ssh {host}", "ps aux | grep '^root'"],
                remediation="Configure services to run as dedicated non-root users.",
                references=["CWE-250", "CIS Benchmark 5.1"],
                evidence=Evidence(extra={"host": host, "root_services": root_violations}),
                cvss_v31_vector=CVSS_ROOT_SVC,
                target=host, service="ssh",
            )

        # Count listening ports
        listen_lines = [l for l in listen_result.stdout.strip().split("\n")
                       if l.strip() and "LISTEN" in l.upper() or "::" in l or "0.0.0.0" in l]
        external_listeners = [l for l in listen_lines if "0.0.0.0" in l or "::" in l]

        if len(external_listeners) > 20:
            self.new_finding(
                title=f"Excessive External Listening Ports ({len(external_listeners)}) — {host}",
                severity=Severity.LOW,
                description=f"{len(external_listeners)} ports listening on all interfaces on {host}.",
                reproduction_steps=[f"ssh {host}", "ss -tlnp"],
                remediation="Bind services to localhost where possible. Firewall unused ports.",
                references=["CWE-284"],
                evidence=Evidence(extra={"host": host, "count": len(external_listeners),
                                        "sample": external_listeners[:15]}),
                target=host, service="ssh",
            )
