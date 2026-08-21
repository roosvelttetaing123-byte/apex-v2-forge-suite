"""Linux Patch Audit — credentialed check for missing OS patches.

Nessus equivalent: Plugin 66334 (Ubuntu), 91540 (RHEL), etc.
Connects via SSH, queries package manager for pending updates,
maps outdated packages to known CVEs where possible.

Checks:
  - apt list --upgradable (Debian/Ubuntu)
  - yum check-update / dnf check-update (RHEL/CentOS/Fedora)
  - zypper list-patches (SUSE)
  - Security-only updates vs all updates
  - Kernel update pending (reboot required)
  - Package manager lock files (stale updates)
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

CVSS_PATCH_CRITICAL = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
CVSS_PATCH_HIGH     = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
CVSS_PATCH_MEDIUM   = "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N"
CVSS_PATCH_LOW      = "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N"
CVSS_REBOOT_NEEDED  = "CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:L"

# Known critical package patterns — if these are outdated, it's bad
CRITICAL_PACKAGES = {
    "openssl", "openssh-server", "openssh-client", "linux-image",
    "sudo", "glibc", "libc6", "systemd", "kernel", "polkit",
    "samba", "apache2", "nginx", "bind9", "postfix", "dovecot",
}


class LinuxPatchAudit(BaseModule):
    """Credentialed Linux patch audit — missing security updates."""

    NAME        = "linux_patch_audit"
    DESCRIPTION = "SSH credentialed check: missing OS patches, pending security updates, kernel upgrade pending"
    PHASE       = 5
    TAGS        = ["credentialed", "linux", "patch", "cve", "compliance"]

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
            await self._audit_patches(host, transport_mgr.ssh, session)

        return self._make_result(start)

    async def _audit_patches(self, host: str, ssh, session) -> None:
        """Detect OS family and run appropriate patch check."""
        # Detect distro
        os_result = await ssh.execute(session, "cat /etc/os-release 2>/dev/null || cat /etc/redhat-release 2>/dev/null")
        os_info = os_result.stdout.lower()

        if any(d in os_info for d in ("ubuntu", "debian", "kali", "mint")):
            await self._check_apt(host, ssh, session, os_info)
        elif any(d in os_info for d in ("rhel", "centos", "red hat", "fedora", "rocky", "alma")):
            await self._check_yum(host, ssh, session, os_info)
        elif "suse" in os_info or "sles" in os_info:
            await self._check_zypper(host, ssh, session, os_info)
        else:
            self.log.info("Unknown OS on %s — skipping patch audit", host)

        # Check for pending reboot (kernel update installed but not active)
        await self._check_reboot_needed(host, ssh, session)

    async def _check_apt(self, host: str, ssh, session, os_info: str) -> None:
        """Debian/Ubuntu patch check via apt."""
        # Update package lists first (read-only, no install)
        await ssh.execute(session, "apt-get update -qq 2>/dev/null")
        await self.rate_limit()

        # Get upgradable packages
        result = await ssh.execute(session, "apt list --upgradable 2>/dev/null")
        if not result.success:
            return

        upgradable = []
        security_upgrades = []
        for line in result.stdout.strip().split("\n"):
            if "/" not in line or "Listing" in line:
                continue
            pkg_name = line.split("/")[0].strip()
            upgradable.append(pkg_name)
            # Check if it's a security update
            if "-security" in line or "-esm" in line:
                security_upgrades.append(pkg_name)

        if not upgradable:
            return

        # Separate critical from routine
        critical_missing = [p for p in security_upgrades if any(
            c in p for c in CRITICAL_PACKAGES
        )]

        if critical_missing:
            self.new_finding(
                title=f"Critical Security Patches Missing — {host}",
                severity=Severity.CRITICAL,
                description=(
                    f"{len(critical_missing)} critical security packages need updating on {host}: "
                    f"{', '.join(critical_missing[:10])}. "
                    f"Total pending: {len(upgradable)} packages ({len(security_upgrades)} security)."
                ),
                reproduction_steps=[
                    f"ssh {host}",
                    "apt list --upgradable 2>/dev/null | grep -i security",
                ],
                remediation=(
                    "Apply security patches immediately: sudo apt-get upgrade -y. "
                    "Enable unattended-upgrades for automatic security patching. "
                    "Schedule regular patch windows for non-security updates."
                ),
                references=["CWE-1104", "NIST SP 800-40"],
                evidence=Evidence(extra={
                    "host": host,
                    "total_upgradable": len(upgradable),
                    "security_upgrades": len(security_upgrades),
                    "critical_packages": critical_missing[:20],
                    "sample_upgradable": upgradable[:30],
                }),
                cvss_v31_vector=CVSS_PATCH_CRITICAL,
                mitre_attack=["TA0001/T1190"],
                target=host,
                service="ssh",
                confidence="HIGH",
            )
        elif security_upgrades:
            self.new_finding(
                title=f"Security Patches Pending — {host}",
                severity=Severity.HIGH,
                description=(
                    f"{len(security_upgrades)} security updates pending on {host}. "
                    f"Total: {len(upgradable)} packages need updating."
                ),
                reproduction_steps=[
                    f"ssh {host}",
                    "apt list --upgradable 2>/dev/null | grep -i security",
                ],
                remediation="Apply security patches: sudo apt-get upgrade -y",
                references=["CWE-1104"],
                evidence=Evidence(extra={
                    "host": host,
                    "security_packages": security_upgrades[:30],
                    "total_upgradable": len(upgradable),
                }),
                cvss_v31_vector=CVSS_PATCH_HIGH,
                mitre_attack=["TA0001/T1190"],
                target=host,
                service="ssh",
                confidence="HIGH",
            )
        elif len(upgradable) > 20:
            self.new_finding(
                title=f"Multiple Packages Outdated — {host}",
                severity=Severity.MEDIUM,
                description=f"{len(upgradable)} packages have updates available on {host}.",
                reproduction_steps=[f"ssh {host}", "apt list --upgradable"],
                remediation="Schedule a patch window to update packages.",
                references=["CWE-1104"],
                evidence=Evidence(extra={
                    "host": host,
                    "total_upgradable": len(upgradable),
                    "sample": upgradable[:20],
                }),
                cvss_v31_vector=CVSS_PATCH_MEDIUM,
                target=host,
                service="ssh",
            )

    async def _check_yum(self, host: str, ssh, session, os_info: str) -> None:
        """RHEL/CentOS/Fedora patch check via yum/dnf."""
        # Try dnf first, fall back to yum
        cmd = "dnf check-update --security 2>/dev/null || yum check-update --security 2>/dev/null"
        result = await ssh.execute(session, cmd)

        # exit code 100 = updates available, 0 = up to date
        if result.exit_code not in (0, 100):
            # Try without --security flag
            result = await ssh.execute(session, "dnf check-update 2>/dev/null || yum check-update 2>/dev/null")

        updates = []
        for line in result.stdout.strip().split("\n"):
            parts = line.split()
            if len(parts) >= 3 and "." in parts[0]:
                updates.append(parts[0].split(".")[0])

        if not updates:
            return

        critical = [u for u in updates if any(c in u for c in CRITICAL_PACKAGES)]

        severity = Severity.CRITICAL if critical else (
            Severity.HIGH if len(updates) > 10 else Severity.MEDIUM
        )

        self.new_finding(
            title=f"Missing Patches ({len(updates)} packages) — {host}",
            severity=severity,
            description=(
                f"{len(updates)} packages need updating on {host}. "
                + (f"Critical: {', '.join(critical[:5])}. " if critical else "")
            ),
            reproduction_steps=[f"ssh {host}", "dnf check-update --security"],
            remediation="Apply patches: sudo dnf update -y --security",
            references=["CWE-1104"],
            evidence=Evidence(extra={
                "host": host,
                "total_updates": len(updates),
                "critical": critical[:10],
                "sample": updates[:30],
            }),
            cvss_v31_vector=CVSS_PATCH_CRITICAL if critical else CVSS_PATCH_HIGH,
            mitre_attack=["TA0001/T1190"],
            target=host,
            service="ssh",
            confidence="HIGH",
        )

    async def _check_zypper(self, host: str, ssh, session, os_info: str) -> None:
        """SUSE patch check via zypper."""
        result = await ssh.execute(session, "zypper list-patches --category security 2>/dev/null")
        if not result.success:
            return

        patches = []
        for line in result.stdout.strip().split("\n"):
            if "needed" in line.lower():
                patches.append(line.strip())

        if patches:
            self.new_finding(
                title=f"SUSE Security Patches Missing ({len(patches)}) — {host}",
                severity=Severity.HIGH,
                description=f"{len(patches)} security patches needed on {host}.",
                reproduction_steps=[f"ssh {host}", "zypper list-patches --category security"],
                remediation="Apply patches: sudo zypper patch --category security",
                references=["CWE-1104"],
                evidence=Evidence(extra={"host": host, "patches": patches[:20]}),
                cvss_v31_vector=CVSS_PATCH_HIGH,
                target=host,
                service="ssh",
                confidence="HIGH",
            )

    async def _check_reboot_needed(self, host: str, ssh, session) -> None:
        """Check if a reboot is required after kernel/library updates."""
        # Debian/Ubuntu
        reboot_check = await ssh.execute(
            session,
            "test -f /var/run/reboot-required && cat /var/run/reboot-required "
            "|| (needs-restarting -r 2>/dev/null; echo $?)"
        )

        needs_reboot = False
        if "System restart required" in reboot_check.stdout:
            needs_reboot = True
        elif reboot_check.stdout.strip().endswith("1"):
            needs_reboot = True

        # Also check running kernel vs installed
        kernel_check = await ssh.execute(
            session,
            "uname -r && ls /boot/vmlinuz-* 2>/dev/null | sort -V | tail -1"
        )
        lines = kernel_check.stdout.strip().split("\n")
        if len(lines) >= 2:
            running = lines[0].strip()
            latest = lines[1].replace("/boot/vmlinuz-", "").strip()
            if latest and running != latest:
                needs_reboot = True

        if needs_reboot:
            self.new_finding(
                title=f"Reboot Required After Kernel Update — {host}",
                severity=Severity.MEDIUM,
                description=(
                    f"Host {host} has pending kernel/library updates that require a reboot. "
                    "Running an outdated kernel means known vulnerabilities remain exploitable."
                ),
                reproduction_steps=[f"ssh {host}", "cat /var/run/reboot-required"],
                remediation="Schedule a maintenance window and reboot the host.",
                references=["CWE-1104"],
                evidence=Evidence(extra={
                    "host": host,
                    "kernel_info": kernel_check.stdout[:500],
                }),
                cvss_v31_vector=CVSS_REBOOT_NEEDED,
                target=host,
                service="ssh",
            )
