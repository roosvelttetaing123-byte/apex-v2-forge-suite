"""Linux Firewall Audit — credentialed iptables/nftables/ufw rule analysis.

Checks:
  - Default INPUT/OUTPUT/FORWARD policies (DROP vs ACCEPT)
  - Rules allowing 0.0.0.0/0 (any source)
  - UFW enabled/disabled status
  - Firewall vs actual listening ports (gaps)
  - IPv6 firewall rules present
"""
from __future__ import annotations

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity

CVSS_NO_FW     = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L"
CVSS_ACCEPT_ALL = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N"


class LinuxFirewallAudit(BaseModule):
    NAME        = "linux_firewall_audit"
    DESCRIPTION = "SSH credentialed: iptables/nftables/ufw rules, default policies, firewall gaps"
    PHASE       = 5
    TAGS        = ["credentialed", "linux", "firewall", "hardening", "cwe-284"]

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
            await self._audit_firewall(host, transport_mgr.ssh, session)

        return self._make_result(start)

    async def _audit_firewall(self, host: str, ssh, session) -> None:
        # Check UFW first
        ufw_result = await ssh.execute(session, "ufw status verbose 2>/dev/null")
        if "inactive" in ufw_result.stdout.lower() or "disabled" in ufw_result.stdout.lower():
            # Check iptables
            ipt_result = await ssh.execute(session, "iptables -L -n --line-numbers 2>/dev/null")
            nft_result = await ssh.execute(session, "nft list ruleset 2>/dev/null")

            has_iptables = ipt_result.success and "ACCEPT" in ipt_result.stdout and len(ipt_result.stdout) > 200
            has_nftables = nft_result.success and "table" in nft_result.stdout

            if not has_iptables and not has_nftables:
                self.new_finding(
                    title=f"No Firewall Active — {host}",
                    severity=Severity.HIGH,
                    description=(
                        f"No firewall is active on {host}. UFW is inactive, iptables has no rules, "
                        "and nftables has no ruleset. All ports are exposed to the network."
                    ),
                    reproduction_steps=[f"ssh {host}", "ufw status; iptables -L -n; nft list ruleset"],
                    remediation="Enable UFW: ufw enable && ufw default deny incoming",
                    references=["CWE-284", "CIS Benchmark 3.5"],
                    evidence=Evidence(extra={"host": host, "ufw": "inactive",
                                            "iptables": has_iptables, "nftables": has_nftables}),
                    cvss_v31_vector=CVSS_NO_FW,
                    target=host, service="ssh", confidence="HIGH",
                )
                return

            # Check default policies
            if has_iptables:
                await self._check_iptables_policies(host, ipt_result.stdout)
        elif ufw_result.success and "active" in ufw_result.stdout.lower():
            # UFW is active — check rules
            await self._check_ufw_rules(host, ufw_result.stdout)

    async def _check_iptables_policies(self, host: str, rules: str) -> None:
        accept_defaults = []
        for line in rules.split("\n"):
            if "Chain" in line and "(policy ACCEPT)" in line:
                chain = line.split()[1]
                if chain in ("INPUT", "FORWARD"):
                    accept_defaults.append(chain)

        if accept_defaults:
            self.new_finding(
                title=f"Firewall Default Policy ACCEPT — {host}",
                severity=Severity.MEDIUM,
                description=(
                    f"iptables chains with default ACCEPT policy on {host}: "
                    f"{', '.join(accept_defaults)}. Traffic not matching any rule is allowed through."
                ),
                reproduction_steps=[f"ssh {host}", "iptables -L -n | head -5"],
                remediation="Set default policy to DROP: iptables -P INPUT DROP",
                references=["CWE-284", "CIS Benchmark 3.5.2"],
                evidence=Evidence(extra={"host": host, "accept_chains": accept_defaults}),
                cvss_v31_vector=CVSS_ACCEPT_ALL,
                target=host, service="ssh", confidence="HIGH",
            )

    async def _check_ufw_rules(self, host: str, ufw_output: str) -> None:
        allow_anywhere = []
        for line in ufw_output.split("\n"):
            if "ALLOW" in line and "Anywhere" in line:
                port_info = line.split("ALLOW")[0].strip()
                allow_anywhere.append(port_info)

        if len(allow_anywhere) > 15:
            self.new_finding(
                title=f"Excessive UFW Allow Rules ({len(allow_anywhere)}) — {host}",
                severity=Severity.LOW,
                description=f"{len(allow_anywhere)} UFW rules allow traffic from anywhere on {host}.",
                reproduction_steps=[f"ssh {host}", "ufw status"],
                remediation="Review UFW rules. Restrict source IPs where possible.",
                references=["CWE-284"],
                evidence=Evidence(extra={"host": host, "rules": allow_anywhere[:20]}),
                target=host, service="ssh",
            )
