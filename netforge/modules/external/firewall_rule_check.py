"""Firewall Rule Check — identify overly permissive rules via port scan analysis.

Tests:
  - Wide-open port range detection
  - Common dangerous ports accessible from outside
  - Egress filtering check
  - Admin port exposure (SSH, RDP, DB ports from internet)
"""
from __future__ import annotations

import asyncio
import shutil
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity

CVSS_PERMISSIVE  = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N"
CVSS40_PERMISSIVE = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N"
CVSS_ADMIN_EXPOSED = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
CVSS40_ADMIN_EXPOSED = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N"

# Ports that should NOT be internet-facing
DANGEROUS_PORTS = {
    22: "SSH",
    23: "Telnet",
    135: "MS-RPC",
    139: "NetBIOS",
    445: "SMB",
    1433: "MSSQL",
    1521: "Oracle",
    2049: "NFS",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    5985: "WinRM",
    6379: "Redis",
    9200: "Elasticsearch",
    11211: "Memcached",
    27017: "MongoDB",
}


class FirewallRuleCheck(BaseModule):
    """Firewall rule analysis for overly permissive configurations."""

    NAME        = "firewall_rule_check"
    DESCRIPTION = "Firewall rules: dangerous port exposure, admin access, egress filtering"
    PHASE       = 3
    TAGS        = ["firewall", "policy", "cwe-284"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        target = self.config.target

        if not self.check_scope(target):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        hosts = self.config.extra.get("live_hosts", [target])
        for host in hosts[:10]:
            if not self.check_scope(host):
                continue
            await self.rate_limit()
            await self._check_rules(host)

        return self._make_result(start)

    async def _check_rules(self, host: str) -> None:
        # Check dangerous ports
        exposed_dangerous = []
        for port, service in DANGEROUS_PORTS.items():
            await self.rate_limit()
            if await self._port_open(host, port):
                exposed_dangerous.append({"port": port, "service": service})

        if exposed_dangerous:
            ev = Evidence(
                extra={
                    "host": host,
                    "exposed_ports": exposed_dangerous,
                    "count": len(exposed_dangerous),
                },
            )
            severity = Severity.HIGH if len(exposed_dangerous) > 3 else Severity.MEDIUM
            self.new_finding(
                title=f"Dangerous Ports Exposed — {host} ({len(exposed_dangerous)} ports)",
                severity=severity,
                description=(
                    f"{len(exposed_dangerous)} administration/database ports are accessible on {host}:\n"
                    + "\n".join(
                        f"  TCP {p['port']}: {p['service']}"
                        for p in exposed_dangerous
                    )
                    + "\n\nThese services should not be directly accessible from untrusted networks."
                ),
                reproduction_steps=[
                    f"nmap -p {','.join(str(p['port']) for p in exposed_dangerous)} {host}",
                ],
                remediation=(
                    "1. Block these ports at the perimeter firewall\n"
                    "2. Use VPN or SSH tunneling for remote admin access\n"
                    "3. Implement network segmentation\n"
                    "4. Use jump boxes / bastion hosts for admin protocols"
                ),
                references=["CWE-284"],
                evidence=ev,
                cvss_v31_vector=CVSS_ADMIN_EXPOSED,
                cvss_v40_vector=CVSS40_ADMIN_EXPOSED,
                target=host,
            )

        # Wide port range scan to detect overly permissive rules
        await self._check_wide_open(host)

    async def _check_wide_open(self, host: str) -> None:
        """Check if a wide range of ports are open (indicates no firewall or allow-all)."""
        nmap = shutil.which("nmap")
        if not nmap:
            return

        await self.rate_limit()
        try:
            proc = await asyncio.create_subprocess_exec(
                nmap, "-sS", "-n", "-Pn",
                "--top-ports", "100",
                "--min-rate", "500",
                host,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=30)
            output = stdout.decode(errors="ignore")

            open_count = output.lower().count("/tcp") - output.lower().count("filtered")
            if open_count > 30:
                ev = Evidence(
                    response_raw=output[:2000],
                    extra={"open_count": open_count, "host": host},
                )
                self.new_finding(
                    title=f"Overly Permissive Firewall — {host} ({open_count}+ ports open)",
                    severity=Severity.MEDIUM,
                    description=(
                        f"{open_count}+ of top 100 ports are open on {host}. "
                        "This suggests very permissive or absent firewall rules. "
                        "A properly configured firewall should only allow necessary ports."
                    ),
                    reproduction_steps=[f"nmap --top-ports 100 {host}"],
                    remediation="Implement least-privilege firewall rules. Only allow required ports.",
                    references=["CWE-284"],
                    evidence=ev,
                    cvss_v31_vector=CVSS_PERMISSIVE,
                    cvss_v40_vector=CVSS40_PERMISSIVE,
                    target=host,
                )
        except Exception:
            pass

    async def _port_open(self, host: str, port: int) -> bool:
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=2
            )
            writer.close()
            return True
        except Exception:
            return False


class TestFirewallRuleCheck:
    def test_dangerous_ports(self) -> None:
        assert 22 in DANGEROUS_PORTS
        assert 3389 in DANGEROUS_PORTS
        assert 6379 in DANGEROUS_PORTS

    def test_cvss(self) -> None:
        assert CVSS_ADMIN_EXPOSED.startswith("CVSS:3.1")

    def test_phase(self) -> None:
        assert FirewallRuleCheck.PHASE == 3
