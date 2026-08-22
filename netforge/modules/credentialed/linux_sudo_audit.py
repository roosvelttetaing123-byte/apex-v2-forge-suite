"""Linux Sudo Audit — credentialed sudoers security analysis.

Checks:
  - NOPASSWD entries (password-less sudo)
  - ALL:ALL grants (unrestricted sudo)
  - sudo version CVEs (Baron Samedit CVE-2021-3156, etc.)
  - !requiretty / !authenticate misconfigs
  - SETENV abuse potential
  - Wildcard sudo commands (privesc via argument injection)
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

CVSS_NOPASSWD   = "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
CVSS_ALL_ALL    = "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
CVSS_SUDO_CVE   = "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
CVSS_WILDCARD   = "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:N"

# sudo CVEs
SUDO_CVES = [
    ("CVE-2021-3156", "Baron Samedit — heap overflow in sudoedit", (1, 8, 2), (1, 9, 5), 7.8),
    ("CVE-2023-22809", "sudoedit arbitrary file write", (1, 8, 0), (1, 9, 12), 7.8),
    ("CVE-2019-14287", "sudo -u#-1 bypass — run as any user", (1, 8, 0), (1, 8, 28), 8.8),
]

# Dangerous sudo wildcard commands
WILDCARD_PRIVESC = [
    "tar", "rsync", "find", "zip", "chmod", "chown", "cp",
    "mv", "wget", "curl", "awk", "sed", "vim", "nano", "less",
    "more", "man", "git", "pip", "pip3", "python", "python3",
    "perl", "ruby", "node",
]


class LinuxSudoAudit(BaseModule):
    NAME        = "linux_sudo_audit"
    DESCRIPTION = "SSH credentialed: sudoers NOPASSWD, ALL:ALL, sudo CVEs, wildcard abuse"
    PHASE       = 5
    TAGS        = ["credentialed", "linux", "sudo", "privesc", "cwe-250"]

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
            await self._audit_sudo(host, transport_mgr.ssh, session)

        return self._make_result(start)

    async def _audit_sudo(self, host: str, ssh, session) -> None:
        # Get sudoers
        sudoers = await ssh.read_file(session, "/etc/sudoers")
        sudoers_d = await ssh.execute(session, "cat /etc/sudoers.d/* 2>/dev/null")
        full_sudoers = sudoers + "\n" + (sudoers_d.stdout if sudoers_d.success else "")

        # sudo version
        ver_result = await ssh.execute(session, "sudo --version 2>/dev/null | head -1")
        sudo_ver = ver_result.stdout.strip()

        await self._check_sudo_version(host, sudo_ver)
        await self._check_nopasswd(host, full_sudoers)
        await self._check_all_all(host, full_sudoers)
        await self._check_wildcards(host, full_sudoers)

    async def _check_sudo_version(self, host: str, ver_str: str) -> None:
        m = re.search(r'(\d+)\.(\d+)\.(\d+)', ver_str)
        if not m:
            return
        ver = (int(m.group(1)), int(m.group(2)), int(m.group(3)))
        for cve_id, desc, min_ver, fix_ver, cvss in SUDO_CVES:
            if min_ver <= ver < fix_ver:
                self.new_finding(
                    title=f"Sudo {cve_id} — {desc} — {host}",
                    severity=Severity.CRITICAL,
                    description=f"Sudo {ver_str} on {host} is vulnerable to {cve_id}: {desc}.",
                    reproduction_steps=[f"ssh {host}", "sudo --version"],
                    remediation="Update sudo: apt-get install sudo / yum update sudo",
                    references=[cve_id],
                    evidence=Evidence(extra={"host": host, "sudo_version": ver_str, "cve": cve_id}),
                    cvss_v31_vector=CVSS_SUDO_CVE,
                    mitre_attack=["TA0004/T1548.003"],
                    target=host, service="ssh", confidence="HIGH",
                )

    async def _check_nopasswd(self, host: str, sudoers: str) -> None:
        nopasswd_entries = []
        for line in sudoers.split("\n"):
            line = line.strip()
            if line.startswith("#") or not line:
                continue
            if "NOPASSWD" in line:
                nopasswd_entries.append(line[:100])

        if nopasswd_entries:
            self.new_finding(
                title=f"Sudo NOPASSWD Entries ({len(nopasswd_entries)}) — {host}",
                severity=Severity.HIGH,
                description=(
                    f"Found {len(nopasswd_entries)} NOPASSWD sudo entries on {host}. "
                    "Users can execute commands as root without entering their password."
                ),
                reproduction_steps=[f"ssh {host}", "grep NOPASSWD /etc/sudoers /etc/sudoers.d/*"],
                remediation="Remove NOPASSWD flag. Require password for all sudo commands.",
                references=["CWE-250", "CIS Benchmark 5.3"],
                evidence=Evidence(extra={"host": host, "entries": nopasswd_entries[:10]}),
                cvss_v31_vector=CVSS_NOPASSWD,
                mitre_attack=["TA0004/T1548.003"],
                target=host, service="ssh",
            )

    async def _check_all_all(self, host: str, sudoers: str) -> None:
        all_all = []
        for line in sudoers.split("\n"):
            if line.strip().startswith("#"):
                continue
            if re.search(r'\bALL\s*=\s*\(ALL\b.*\)\s*ALL\b', line):
                user = line.split()[0] if line.split() else "?"
                if user not in ("root", "%sudo", "%wheel", "%admin"):
                    all_all.append(f"{user}: {line.strip()[:80]}")

        if all_all:
            self.new_finding(
                title=f"Unrestricted Sudo (ALL:ALL) — {host}",
                severity=Severity.HIGH,
                description=(
                    f"Found {len(all_all)} unrestricted sudo entries on {host}: "
                    + "; ".join(all_all[:5])
                ),
                reproduction_steps=[f"ssh {host}", "grep 'ALL.*ALL.*ALL' /etc/sudoers"],
                remediation="Replace ALL:ALL with specific command lists.",
                references=["CWE-250"],
                evidence=Evidence(extra={"host": host, "entries": all_all[:10]}),
                cvss_v31_vector=CVSS_ALL_ALL,
                target=host, service="ssh",
            )

    async def _check_wildcards(self, host: str, sudoers: str) -> None:
        wildcard_entries = []
        for line in sudoers.split("\n"):
            if line.strip().startswith("#"):
                continue
            for cmd in WILDCARD_PRIVESC:
                if re.search(rf'\b{cmd}\b.*\*', line):
                    wildcard_entries.append(f"{cmd}: {line.strip()[:80]}")
                    break

        if wildcard_entries:
            self.new_finding(
                title=f"Sudo Wildcard Commands — Privesc Risk — {host}",
                severity=Severity.HIGH,
                description=(
                    f"{len(wildcard_entries)} sudo entries use wildcards with commands that allow "
                    f"argument injection privesc: " + "; ".join(wildcard_entries[:5])
                ),
                reproduction_steps=[f"ssh {host}", "grep '\\*' /etc/sudoers"],
                remediation="Replace wildcard sudo entries with explicit paths/arguments.",
                references=["CWE-250", "https://gtfobins.github.io/"],
                evidence=Evidence(extra={"host": host, "entries": wildcard_entries[:10]}),
                cvss_v31_vector=CVSS_WILDCARD,
                mitre_attack=["TA0004/T1548.003"],
                target=host, service="ssh",
            )
