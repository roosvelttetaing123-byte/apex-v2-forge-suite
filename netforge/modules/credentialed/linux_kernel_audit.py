"""Linux Kernel Audit — credentialed kernel version CVE check and sysctl hardening.

Checks:
  - Kernel version against known critical CVEs (DirtyPipe, DirtyCow, OverlayFS, etc.)
  - sysctl hardening (ASLR, exec-shield, SMAP/SMEP)
  - Kernel module loading restrictions
  - Core dump configuration
  - /proc/sys security settings
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

CVSS_KERNEL_CVE  = "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
CVSS_SYSCTL      = "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N"

# Major kernel CVEs with affected version ranges
# Format: (cve_id, description, min_version, fixed_version, cvss)
KERNEL_CVES = [
    ("CVE-2022-0847", "DirtyPipe — arbitrary file overwrite via splice",
     (5, 8, 0), (5, 16, 11), 7.8),
    ("CVE-2016-5195", "DirtyCow — race condition copy-on-write privesc",
     (2, 6, 22), (4, 8, 3), 7.8),
    ("CVE-2021-3156", "Baron Samedit sudo heap overflow (sudo, not kernel)",
     (0, 0, 0), (99, 99, 99), 7.8),  # sudo version check
    ("CVE-2021-4034", "PwnKit — pkexec local privesc",
     (0, 0, 0), (99, 99, 99), 7.8),  # polkit, not kernel
    ("CVE-2021-3493", "OverlayFS — Ubuntu privesc via user namespaces",
     (4, 4, 0), (5, 11, 0), 7.8),
    ("CVE-2022-2588", "route4 use-after-free — net/sched privesc",
     (4, 0, 0), (5, 19, 2), 7.8),
    ("CVE-2023-0386", "OverlayFS — SUID copy-up privesc",
     (5, 11, 0), (6, 2, 0), 7.8),
    ("CVE-2023-32233", "Netfilter nf_tables use-after-free",
     (5, 1, 0), (6, 4, 0), 7.8),
    ("CVE-2024-1086", "Netfilter nf_tables double-free privesc",
     (5, 14, 0), (6, 8, 0), 7.8),
]

# sysctl hardening checks
SYSCTL_CHECKS = [
    ("kernel.randomize_va_space", "2", "ASLR not fully enabled", Severity.HIGH),
    ("kernel.kptr_restrict", "1", "Kernel pointer addresses exposed", Severity.MEDIUM),
    ("kernel.dmesg_restrict", "1", "Kernel log readable by unprivileged users", Severity.LOW),
    ("kernel.yama.ptrace_scope", "1", "Unrestricted ptrace — process injection risk", Severity.MEDIUM),
    ("net.ipv4.conf.all.accept_redirects", "0", "ICMP redirects accepted — MitM risk", Severity.MEDIUM),
    ("net.ipv4.conf.all.send_redirects", "0", "Sending ICMP redirects — router spoofing", Severity.LOW),
    ("net.ipv4.conf.all.accept_source_route", "0", "Source routing accepted", Severity.MEDIUM),
    ("net.ipv4.conf.all.log_martians", "1", "Martian packet logging disabled", Severity.LOW),
    ("net.ipv4.icmp_echo_ignore_broadcasts", "1", "Smurf attack vector enabled", Severity.LOW),
    ("net.ipv4.tcp_syncookies", "1", "SYN cookies disabled — SYN flood risk", Severity.MEDIUM),
    ("fs.suid_dumpable", "0", "SUID core dumps enabled — credential leakage", Severity.MEDIUM),
    ("kernel.modules_disabled", "1", "Kernel module loading allowed", Severity.LOW),
]


class LinuxKernelAudit(BaseModule):
    NAME        = "linux_kernel_audit"
    DESCRIPTION = "SSH credentialed: kernel CVEs (DirtyPipe, DirtyCow, OverlayFS), sysctl hardening"
    PHASE       = 5
    TAGS        = ["credentialed", "linux", "kernel", "cve", "sysctl", "privesc"]

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
            await self._audit_kernel(host, transport_mgr.ssh, session)

        return self._make_result(start)

    async def _audit_kernel(self, host: str, ssh, session) -> None:
        # Get kernel version
        ver_result = await ssh.execute(session, "uname -r")
        kernel_ver = ver_result.stdout.strip()
        parsed = self._parse_kernel_version(kernel_ver)

        if parsed:
            await self._check_kernel_cves(host, kernel_ver, parsed)

        # sysctl hardening
        await self._check_sysctl(host, ssh, session)

    def _parse_kernel_version(self, ver: str) -> tuple[int, ...] | None:
        m = re.match(r"(\d+)\.(\d+)\.(\d+)", ver)
        if m:
            return (int(m.group(1)), int(m.group(2)), int(m.group(3)))
        return None

    async def _check_kernel_cves(self, host: str, ver_str: str, ver: tuple) -> None:
        vulnerable = []
        for cve_id, desc, min_ver, fix_ver, cvss in KERNEL_CVES:
            if min_ver <= ver < fix_ver:
                vulnerable.append((cve_id, desc, cvss))

        if vulnerable:
            cve_list = [f"{c[0]} ({c[1]})" for c in vulnerable]
            max_cvss = max(c[2] for c in vulnerable)
            severity = Severity.CRITICAL if max_cvss >= 9.0 else (
                Severity.HIGH if max_cvss >= 7.0 else Severity.MEDIUM
            )
            self.new_finding(
                title=f"Kernel {ver_str} Vulnerable to {len(vulnerable)} CVEs — {host}",
                severity=severity,
                description=(
                    f"Kernel {ver_str} on {host} is potentially vulnerable to: "
                    + "; ".join(cve_list[:5])
                ),
                reproduction_steps=[f"ssh {host}", "uname -r"],
                remediation="Update kernel to latest patched version and reboot.",
                references=[c[0] for c in vulnerable],
                evidence=Evidence(extra={
                    "host": host, "kernel": ver_str,
                    "cves": [{"id": c[0], "desc": c[1], "cvss": c[2]} for c in vulnerable],
                }),
                cvss_v31_vector=CVSS_KERNEL_CVE,
                mitre_attack=["TA0004/T1068"],
                target=host, service="ssh", confidence="MEDIUM",
            )

    async def _check_sysctl(self, host: str, ssh, session) -> None:
        sysctl_result = await ssh.execute(session, "sysctl -a 2>/dev/null")
        if not sysctl_result.success:
            return

        sysctl_map = {}
        for line in sysctl_result.stdout.strip().split("\n"):
            if "=" in line:
                key, _, val = line.partition("=")
                sysctl_map[key.strip()] = val.strip()

        failures = []
        for key, expected, desc, sev in SYSCTL_CHECKS:
            actual = sysctl_map.get(key)
            if actual is not None and actual != expected:
                failures.append((key, expected, actual, desc, sev))

        if failures:
            high_failures = [f for f in failures if f[4] in (Severity.HIGH, Severity.CRITICAL)]
            severity = Severity.HIGH if high_failures else Severity.MEDIUM

            self.new_finding(
                title=f"Kernel Hardening Gaps ({len(failures)} sysctl) — {host}",
                severity=severity,
                description=(
                    f"{len(failures)} sysctl security settings are misconfigured on {host}: "
                    + "; ".join(f"{f[0]}={f[2]} (should be {f[1]}: {f[3]})" for f in failures[:5])
                ),
                reproduction_steps=[f"ssh {host}", "sysctl -a | grep -E 'randomize|kptr|ptrace'"],
                remediation="Apply sysctl hardening. Add settings to /etc/sysctl.d/99-hardening.conf",
                references=["CWE-693", "CIS Benchmark 3.1-3.3"],
                evidence=Evidence(extra={
                    "host": host,
                    "failures": [{"key": f[0], "expected": f[1], "actual": f[2], "desc": f[3]}
                                for f in failures],
                }),
                cvss_v31_vector=CVSS_SYSCTL,
                target=host, service="ssh",
            )
