"""macOS Security and Patch Audit — SSH credentialed check.

Audits macOS security posture via SSH including:
  - macOS version and pending software updates
  - System Integrity Protection (SIP) status
  - Gatekeeper status
  - FileVault encryption
  - Firewall status
  - SSH root login
  - Remote Apple Events
  - Screen sharing / VNC
  - Unsigned kernel extensions
  - Automatic update configuration
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

CVSS_CRIT = "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H"
CVSS_HIGH = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
CVSS_MED  = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
CVSS_LOW  = "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N"

# macOS 15.x Sequoia is current in 2026
MACOS_LATEST_MAJOR = 15
MACOS_LATEST_NAME = "Sequoia"

# Known EOL macOS versions (no longer receiving security updates as of 2026)
MACOS_EOL_MAJOR = {
    12: "Monterey (EOL 2025)",
    11: "Big Sur (EOL 2024)",
    10: "Catalina and earlier (EOL)",
}


class MacosPatchAudit(BaseModule):
    NAME        = "macos_patch_audit"
    DESCRIPTION = "SSH credentialed: macOS missing updates, SIP status, Gatekeeper, FileVault, Firewall"
    PHASE       = 5
    TAGS        = ["credentialed", "macos", "patch", "compliance", "sip", "gatekeeper"]

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

            # Verify this is macOS before running macOS-specific checks
            os_check = await transport_mgr.ssh.execute(session, "uname -s")
            if "Darwin" not in (os_check.stdout or ""):
                continue

            await self._audit_host(host, transport_mgr.ssh, session)

        return self._make_result(start)

    async def _audit_host(self, host: str, ssh, session) -> None:
        """Run all macOS security checks on a confirmed Darwin host."""
        await self._check_macos_version(host, ssh, session)
        await self._check_software_updates(host, ssh, session)
        await self._check_sip(host, ssh, session)
        await self._check_gatekeeper(host, ssh, session)
        await self._check_filevault(host, ssh, session)
        await self._check_firewall(host, ssh, session)
        await self._check_ssh_root_login(host, ssh, session)
        await self._check_remote_apple_events(host, ssh, session)
        await self._check_screen_sharing(host, ssh, session)
        await self._check_unsigned_kexts(host, ssh, session)
        await self._check_auto_updates(host, ssh, session)

    # ── Check 1: macOS version ───────────────────────────────────────────────

    async def _check_macos_version(self, host: str, ssh, session) -> None:
        """Check macOS version and flag EOL or outdated major versions."""
        result = await ssh.execute(session, "sw_vers -productVersion")
        if not result.success:
            return

        version_str = (result.stdout or "").strip()
        if not version_str:
            return

        parts = version_str.split(".")
        try:
            major = int(parts[0])
            minor = int(parts[1]) if len(parts) > 1 else 0
        except (ValueError, IndexError):
            return

        # Log version as info
        self.new_finding(
            title=f"macOS Version Identified — {version_str} — {host}",
            severity=Severity.INFO,
            description=(
                f"Host {host} is running macOS {version_str}. "
                f"Current latest stable release is macOS {MACOS_LATEST_MAJOR}.x ({MACOS_LATEST_NAME}). "
                f"Verify this is the latest available version including security patches."
            ),
            reproduction_steps=["sw_vers"],
            remediation="Keep macOS updated to the latest available release.",
            references=["https://support.apple.com/en-us/100100"],
            evidence=Evidence(extra={"host": host, "macos_version": version_str}),
            cvss_v31_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
            target=host, service="ssh", confidence="HIGH",
        )

        # EOL check
        if major in MACOS_EOL_MAJOR:
            self.new_finding(
                title=f"macOS End-of-Life Version — {version_str} ({MACOS_EOL_MAJOR[major]}) — {host}",
                severity=Severity.CRITICAL,
                description=(
                    f"Host {host} is running macOS {version_str} which is {MACOS_EOL_MAJOR[major]}. "
                    f"Apple no longer provides security updates for this macOS version. "
                    f"Known vulnerabilities affecting this macOS version cannot be patched and "
                    f"remain exploitable. In 2026, this includes multiple kernel, Safari, WebKit, "
                    f"and CoreBluetooth vulnerabilities. EOL macOS endpoints are primary targets "
                    f"for macOS-targeting threat actors (including Silver Sparrow, XCSSET, Atomic Stealer)."
                ),
                reproduction_steps=[
                    f"ssh {host}",
                    "sw_vers -productVersion",
                    "# Verify version against Apple security releases:",
                    "# https://support.apple.com/en-us/100100",
                ],
                remediation=(
                    f"Upgrade to macOS {MACOS_LATEST_MAJOR}.x ({MACOS_LATEST_NAME}) immediately. "
                    f"If hardware is not compatible with {MACOS_LATEST_NAME}, consider device replacement. "
                    f"As interim control: enforce strict network access control, disable remote access "
                    f"services, and ensure endpoint security agent (CrowdStrike Falcon, SentinelOne) "
                    f"is deployed and updated."
                ),
                references=[
                    "https://support.apple.com/en-us/100100",
                    "https://endoflife.date/macos",
                ],
                evidence=Evidence(extra={
                    "host": host,
                    "version": version_str,
                    "eol_status": MACOS_EOL_MAJOR[major],
                }),
                cvss_v31_vector=CVSS_CRIT,
                mitre_attack=["TA0001/T1190", "TA0005/T1562"],
                target=host, service="ssh", confidence="HIGH",
            )
        elif major < MACOS_LATEST_MAJOR:
            self.new_finding(
                title=f"macOS Not Updated to Latest Major Version — {version_str} — {host}",
                severity=Severity.HIGH,
                description=(
                    f"Host {host} is running macOS {version_str} (major version {major}), "
                    f"while macOS {MACOS_LATEST_MAJOR}.x ({MACOS_LATEST_NAME}) is the current release. "
                    f"Older macOS major versions may lack security fixes available only in newer releases. "
                    f"Apple backports critical fixes to N-1 and sometimes N-2 major versions, but "
                    f"non-critical vulnerabilities are only fixed in the latest major version."
                ),
                reproduction_steps=["sw_vers -productVersion"],
                remediation=f"Upgrade to macOS {MACOS_LATEST_MAJOR}.x ({MACOS_LATEST_NAME}) via System Settings → Software Update.",
                references=["https://support.apple.com/en-us/100100"],
                evidence=Evidence(extra={"host": host, "version": version_str}),
                cvss_v31_vector=CVSS_HIGH,
                target=host, service="ssh", confidence="HIGH",
            )

    # ── Check 2: Pending software updates ────────────────────────────────────

    async def _check_software_updates(self, host: str, ssh, session) -> None:
        """Check for available software updates."""
        result = await ssh.execute(
            session,
            "softwareupdate -l 2>&1 | grep -E '(\\* |Title:|Size:|Action:)' | head -50"
        )
        raw = (result.stdout or "").strip()

        # If no output or "No new software available", nothing to report
        if not raw or "No new software available" in raw or not result.success:
            return

        # Count update entries
        update_lines = [l for l in raw.splitlines() if l.strip().startswith("*") or "Title:" in l]
        update_count = len(update_lines)

        if update_count > 0:
            # Check if any are security updates
            is_security = any(
                "security" in l.lower() or "Safari" in l or "macOS" in l
                for l in raw.splitlines()
            )
            severity = Severity.HIGH if is_security else Severity.MEDIUM

            self.new_finding(
                title=f"macOS Pending Software Updates ({update_count}) — {host}",
                severity=severity,
                description=(
                    f"Host {host} has {update_count} pending software update(s) available. "
                    + ("Security updates are included in the pending list. " if is_security else "")
                    + f"Unpatched systems are vulnerable to publicly known CVEs targeting the "
                    f"installed software versions. macOS security updates often address zero-days "
                    f"(e.g., kernel, WebKit, CoreAudio vulnerabilities) actively exploited by "
                    f"advanced threat actors.\n\nPending updates:\n"
                    + "\n".join(f"  {l}" for l in raw.splitlines()[:20])
                ),
                reproduction_steps=[
                    f"ssh {host}",
                    "softwareupdate -l",
                ],
                remediation=(
                    "Apply all pending updates: sudo softwareupdate -ia --verbose. "
                    "Enable automatic security updates (see Automatic Updates check). "
                    "Schedule maintenance windows for regular patch cycles."
                ),
                references=[
                    "https://support.apple.com/en-us/102662",
                    "https://support.apple.com/en-us/100100",
                ],
                evidence=Evidence(extra={
                    "host": host,
                    "update_count": update_count,
                    "updates_raw": raw[:1000],
                }),
                cvss_v31_vector=CVSS_HIGH if is_security else CVSS_MED,
                mitre_attack=["TA0001/T1190"],
                target=host, service="ssh", confidence="HIGH",
            )

    # ── Check 3: SIP status ──────────────────────────────────────────────────

    async def _check_sip(self, host: str, ssh, session) -> None:
        """Check System Integrity Protection (SIP) status."""
        result = await ssh.execute(session, "csrutil status 2>/dev/null")
        raw = (result.stdout or "").strip()
        if not raw:
            return

        if "disabled" in raw.lower():
            self.new_finding(
                title=f"System Integrity Protection (SIP) Disabled — {host}",
                severity=Severity.CRITICAL,
                description=(
                    f"System Integrity Protection (SIP) is DISABLED on {host}. "
                    f"SIP is a macOS security feature (introduced in El Capitan) that restricts "
                    f"root from modifying protected system directories (/System, /usr, /bin, /sbin), "
                    f"loading unsigned kernel extensions, and attaching debuggers to system processes. "
                    f"With SIP disabled, any process running as root can modify core OS components, "
                    f"install persistent rootkits, and bypass macOS security mechanisms. "
                    f"SIP can only be disabled by booting into Recovery Mode — its presence "
                    f"indicates intentional or attacker-achieved physical access."
                ),
                reproduction_steps=[
                    f"ssh {host}",
                    "csrutil status",
                    "# Output: System Integrity Protection status: disabled.",
                ],
                remediation=(
                    "Re-enable SIP by booting into macOS Recovery Mode (hold Cmd+R at startup), "
                    "opening Terminal, and running: csrutil enable. "
                    "Reboot to apply. Investigate why/when SIP was disabled — "
                    "this may indicate prior compromise or unauthorized physical access."
                ),
                references=[
                    "https://support.apple.com/en-us/102149",
                    "https://attack.mitre.org/techniques/T1562/",
                ],
                evidence=Evidence(extra={"host": host, "sip_status": raw, "sip_disabled": True}),
                cvss_v31_vector=CVSS_CRIT,
                mitre_attack=["TA0005/T1562.001", "TA0004/T1068"],
                target=host, service="ssh", confidence="HIGH",
            )
        elif "enabled" not in raw.lower():
            # Unexpected output — flag for investigation
            self.new_finding(
                title=f"SIP Status Unclear — Manual Verification Required — {host}",
                severity=Severity.MEDIUM,
                description=(
                    f"csrutil status on {host} returned an unexpected response: '{raw}'. "
                    f"Manual verification of SIP status is required."
                ),
                reproduction_steps=[f"ssh {host}", "csrutil status"],
                remediation="Run csrutil status interactively to verify SIP state.",
                references=["https://support.apple.com/en-us/102149"],
                evidence=Evidence(extra={"host": host, "sip_output": raw}),
                cvss_v31_vector=CVSS_MED,
                target=host, service="ssh", confidence="LOW",
            )

    # ── Check 4: Gatekeeper ──────────────────────────────────────────────────

    async def _check_gatekeeper(self, host: str, ssh, session) -> None:
        """Check Gatekeeper status."""
        result = await ssh.execute(session, "spctl --status 2>/dev/null")
        raw = (result.stdout or "").strip()
        if not raw:
            return

        if "disabled" in raw.lower() or "assessments disabled" in raw.lower():
            self.new_finding(
                title=f"Gatekeeper Disabled — Unsigned Apps Allowed — {host}",
                severity=Severity.HIGH,
                description=(
                    f"Gatekeeper is DISABLED on {host} (spctl --status: '{raw}'). "
                    f"Gatekeeper enforces Apple's code signing and notarization requirements, "
                    f"preventing unsigned and non-notarized applications from executing. "
                    f"With Gatekeeper disabled, any downloaded binary — including malware — "
                    f"can execute without warning. This bypasses a key macOS defense against "
                    f"malware distribution (T1204.002). "
                    f"Attackers and malware frequently attempt to disable Gatekeeper as a "
                    f"persistence mechanism."
                ),
                reproduction_steps=[
                    f"ssh {host}",
                    "spctl --status",
                    "# Expected: assessments enabled",
                    "# Got: assessments disabled",
                ],
                remediation=(
                    "Re-enable Gatekeeper: sudo spctl --master-enable. "
                    "Verify: spctl --status should return 'assessments enabled'. "
                    "Investigate any software that required Gatekeeper to be disabled."
                ),
                references=[
                    "https://support.apple.com/en-us/102445",
                    "https://attack.mitre.org/techniques/T1204/002/",
                ],
                evidence=Evidence(extra={"host": host, "gatekeeper_status": raw}),
                cvss_v31_vector=CVSS_HIGH,
                mitre_attack=["TA0005/T1562.001", "TA0002/T1204.002"],
                target=host, service="ssh", confidence="HIGH",
            )

    # ── Check 5: FileVault ───────────────────────────────────────────────────

    async def _check_filevault(self, host: str, ssh, session) -> None:
        """Check FileVault full-disk encryption status."""
        result = await ssh.execute(session, "fdesetup status 2>/dev/null")
        raw = (result.stdout or "").strip()
        if not raw:
            return

        if "off" in raw.lower() or "not enabled" in raw.lower():
            self.new_finding(
                title=f"FileVault Disk Encryption Disabled — {host}",
                severity=Severity.HIGH,
                description=(
                    f"FileVault full-disk encryption is DISABLED on {host}. "
                    f"Without FileVault, the disk can be read directly if the device is lost, "
                    f"stolen, or accessed via DMA attacks (Thunderbolt/PCIe). "
                    f"For macOS endpoints containing business data, HIPAA, PCI-DSS, SOC 2, "
                    f"and most enterprise security policies mandate full-disk encryption. "
                    f"An attacker with physical access can boot from external media, mount "
                    f"the filesystem, and read all data without authentication."
                ),
                reproduction_steps=[
                    f"ssh {host}",
                    "fdesetup status",
                    "# Should say: FileVault is On.",
                ],
                remediation=(
                    "Enable FileVault: System Settings → Privacy & Security → FileVault → Turn On. "
                    "Store the recovery key in a secure location (e.g., MDM/Jamf escrow). "
                    "For enterprise deployments, use MDM to enforce and escrow FileVault keys."
                ),
                references=[
                    "https://support.apple.com/guide/mac-help/protect-data-on-your-mac-with-filevault-mh11785/mac",
                    "CIS macOS Benchmark",
                ],
                evidence=Evidence(extra={"host": host, "filevault_status": raw}),
                cvss_v31_vector=CVSS_HIGH,
                mitre_attack=["TA0006/T1530"],
                target=host, service="ssh", confidence="HIGH",
            )

    # ── Check 6: Firewall status ─────────────────────────────────────────────

    async def _check_firewall(self, host: str, ssh, session) -> None:
        """Check macOS application firewall status."""
        result = await ssh.execute(
            session,
            "/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null"
        )
        raw = (result.stdout or "").strip()
        if not raw:
            return

        if "disabled" in raw.lower():
            self.new_finding(
                title=f"macOS Application Firewall Disabled — {host}",
                severity=Severity.MEDIUM,
                description=(
                    f"The macOS Application Firewall is disabled on {host}. "
                    f"The macOS firewall controls which applications can accept incoming network "
                    f"connections. Without it, any process (including malware) that binds to a "
                    f"network port can accept external connections. While macOS relies on PF "
                    f"for packet-level filtering, the Application Firewall provides process-level "
                    f"control and stealth mode (blocking ICMP probes). For endpoints not acting "
                    f"as servers, enabling the firewall in stealth mode reduces network exposure."
                ),
                reproduction_steps=[
                    f"ssh {host}",
                    "/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate",
                    "# Should say: Firewall is enabled. (State = 1)",
                ],
                remediation=(
                    "Enable the firewall: "
                    "sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on. "
                    "Enable stealth mode: "
                    "sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode on. "
                    "Or: System Settings → Network → Firewall → Turn On."
                ),
                references=[
                    "https://support.apple.com/guide/mac-help/change-firewall-settings-on-mac-mh11783/mac",
                    "CIS macOS Benchmark 3.6",
                ],
                evidence=Evidence(extra={"host": host, "firewall_status": raw}),
                cvss_v31_vector=CVSS_MED,
                mitre_attack=["TA0005/T1562.004"],
                target=host, service="ssh", confidence="HIGH",
            )

    # ── Check 7: SSH root login ──────────────────────────────────────────────

    async def _check_ssh_root_login(self, host: str, ssh, session) -> None:
        """Check if PermitRootLogin is enabled in sshd_config."""
        result = await ssh.execute(
            session,
            "grep -i PermitRootLogin /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null"
        )
        raw = (result.stdout or "").strip()
        if not raw:
            return

        # Find active (non-commented) PermitRootLogin setting
        for line in raw.splitlines():
            line = line.strip()
            if line.startswith("#"):
                continue
            # Line may be from a file:  /path/file:PermitRootLogin yes
            if ":" in line:
                _, _, setting = line.partition(":")
            else:
                setting = line

            setting = setting.strip()
            if re.match(r'(?i)PermitRootLogin\s+yes', setting):
                self.new_finding(
                    title=f"SSH Root Login Permitted — {host}",
                    severity=Severity.HIGH,
                    description=(
                        f"PermitRootLogin is set to 'yes' in sshd_config on {host}. "
                        f"This allows direct SSH authentication as the root account. "
                        f"Combined with a weak root password or exposed key, this provides "
                        f"immediate full system access to an attacker. Additionally, SSH sessions "
                        f"as root are harder to audit (no su/sudo trail). "
                        f"macOS does not normally have a root account enabled, but on managed "
                        f"enterprise Macs it may be explicitly enabled. "
                        f"Source configuration: {line[:200]}"
                    ),
                    reproduction_steps=[
                        f"ssh root@{host}",
                        "grep -i PermitRootLogin /etc/ssh/sshd_config",
                    ],
                    remediation=(
                        "Set PermitRootLogin no in /etc/ssh/sshd_config. "
                        "If root access via SSH is required, use PermitRootLogin prohibit-password "
                        "(key-based only, no password). "
                        "Restart SSHD: sudo launchctl kickstart -k system/com.openssh.sshd"
                    ),
                    references=[
                        "CWE-264",
                        "CIS macOS Benchmark 5.2.7",
                        "https://attack.mitre.org/techniques/T1078/003/",
                    ],
                    evidence=Evidence(extra={"host": host, "sshd_line": line[:200]}),
                    cvss_v31_vector=CVSS_HIGH,
                    mitre_attack=["TA0001/T1078.003"],
                    target=host, service="ssh", confidence="HIGH",
                )
                break

    # ── Check 8: Remote Apple Events ─────────────────────────────────────────

    async def _check_remote_apple_events(self, host: str, ssh, session) -> None:
        """Check if Remote Apple Events is enabled."""
        result = await ssh.execute(
            session,
            "systemsetup -getremoteappleevents 2>/dev/null"
        )
        raw = (result.stdout or "").strip()
        if not raw:
            return

        if "on" in raw.lower():
            self.new_finding(
                title=f"Remote Apple Events Enabled — {host}",
                severity=Severity.MEDIUM,
                description=(
                    f"Remote Apple Events is enabled on {host} (systemsetup -getremoteappleevents: '{raw}'). "
                    f"Remote Apple Events allows remote applications to send Apple Events to "
                    f"applications on this Mac, which can be used for remote automation and "
                    f"potentially for inter-process exploitation. If not required for legitimate "
                    f"business purposes, this feature increases the network attack surface and "
                    f"can be abused via AppleScript (T1059.002) for command execution."
                ),
                reproduction_steps=[
                    f"ssh {host}",
                    "systemsetup -getremoteappleevents",
                    "# Should say: Remote Apple Events: Off",
                ],
                remediation=(
                    "Disable Remote Apple Events: "
                    "sudo systemsetup -setremoteappleevents off. "
                    "Or: System Settings → Sharing → disable Remote Apple Events."
                ),
                references=[
                    "CIS macOS Benchmark 2.4.3",
                    "https://attack.mitre.org/techniques/T1059/002/",
                ],
                evidence=Evidence(extra={"host": host, "remote_apple_events": raw}),
                cvss_v31_vector=CVSS_MED,
                mitre_attack=["TA0002/T1059.002"],
                target=host, service="ssh", confidence="HIGH",
            )

    # ── Check 9: Screen sharing / VNC ────────────────────────────────────────

    async def _check_screen_sharing(self, host: str, ssh, session) -> None:
        """Check if screen sharing (VNC/ARD) is enabled."""
        result = await ssh.execute(
            session,
            "launchctl list 2>/dev/null | grep -E '(screensharing|VNC|vnc|com.apple.screensharing)'"
        )
        raw = (result.stdout or "").strip()
        if not raw or not result.success:
            # Also check via system configuration
            result2 = await ssh.execute(
                session,
                "defaults read /Library/Preferences/com.apple.ScreenSharing.plist 2>/dev/null; "
                "ls -la /System/Library/LaunchDaemons/com.apple.screensharing.plist 2>/dev/null"
            )
            raw2 = (result2.stdout or "").strip()
            if not raw2:
                return
            raw = raw2

        # Check if screen sharing daemon is running (PID present in launchctl list)
        # launchctl list format: PID  Status  Label
        screensharing_active = False
        for line in raw.splitlines():
            if "screensharing" in line.lower() or "vnc" in line.lower():
                parts = line.split()
                if parts and parts[0] != "-" and parts[0].isdigit():
                    screensharing_active = True
                    break
                elif "screensharing.plist" in line and "-rw" in line:
                    # File exists — may not mean it's enabled; treat as medium confidence
                    screensharing_active = True

        if screensharing_active:
            self.new_finding(
                title=f"Screen Sharing / VNC Service Running — {host}",
                severity=Severity.HIGH,
                description=(
                    f"Screen sharing (VNC / Apple Remote Desktop) appears to be active on {host}. "
                    f"Screen sharing listens on TCP 5900 (VNC) and optionally TCP 3283 (ARD). "
                    f"If exposed to the network, this allows an attacker with credentials (or via "
                    f"VNC brute-force/authentication bypass CVEs) to gain a graphical desktop "
                    f"session on the host. VNC implementations have a history of critical "
                    f"vulnerabilities (CVE-2019-9755, LibVNCServer CVEs)."
                ),
                reproduction_steps=[
                    f"nmap -sV -p 5900 {host}",
                    f"vncviewer {host}:5900",
                    f"# Or attempt connection via Apple Remote Desktop client",
                ],
                remediation=(
                    "1. Disable screen sharing if not required: "
                    "System Settings → Sharing → uncheck Screen Sharing. "
                    "sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.screensharing.plist. "
                    "2. If required, restrict access to specific IP addresses via firewall rules. "
                    "3. Require VPN for any remote desktop access. "
                    "4. Enforce strong password for VNC and consider switching to SSH tunnel."
                ),
                references=[
                    "CVE-2019-9755",
                    "CIS macOS Benchmark 2.4.6",
                    "https://attack.mitre.org/techniques/T1021/005/",
                ],
                evidence=Evidence(extra={"host": host, "screen_sharing_raw": raw[:500]}),
                cvss_v31_vector=CVSS_HIGH,
                mitre_attack=["TA0001/T1021.005", "TA0008/T1021.005"],
                target=host, service="ssh", confidence="MEDIUM",
            )

    # ── Check 10: Unsigned kernel extensions ─────────────────────────────────

    async def _check_unsigned_kexts(self, host: str, ssh, session) -> None:
        """Check for third-party / unsigned kernel extensions."""
        result = await ssh.execute(
            session,
            "kextstat 2>/dev/null | grep -v 'com.apple' | grep -v '^Index'"
        )
        raw = (result.stdout or "").strip()
        if not raw or not result.success:
            return

        lines = [l for l in raw.splitlines() if l.strip()]
        if not lines:
            return

        kexts = []
        for line in lines[:20]:
            parts = line.split()
            # kextstat format: Index  Refs  Address  Size  Wired  Name (Version) <BundleID>
            if len(parts) >= 6:
                name = parts[5] if len(parts) > 5 else line[:60]
                kexts.append(name)

        if kexts:
            self.new_finding(
                title=f"Third-Party Kernel Extensions Loaded ({len(kexts)}) — {host}",
                severity=Severity.MEDIUM,
                description=(
                    f"Found {len(kexts)} third-party (non-Apple) kernel extension(s) loaded on {host}:\n"
                    + "\n".join(f"  {k}" for k in kexts[:10])
                    + "\n\nKernel extensions (kexts) run at ring-0 with full kernel privileges. "
                    f"Malicious kexts are a primary macOS rootkit technique (T1014). "
                    f"macOS 11+ requires user approval for kexts and Apple Silicon requires "
                    f"kexts to be signed and notarized. However, legacy x86 Macs may load "
                    f"older unsigned kexts. Verify each kext is from a legitimate vendor "
                    f"and is required for business functionality."
                ),
                reproduction_steps=[
                    f"ssh {host}",
                    "kextstat | grep -v com.apple",
                    "# Review each third-party kext bundle identifier",
                ],
                remediation=(
                    "1. Identify the source of each third-party kext. "
                    "2. Remove kexts from unknown or unverified vendors. "
                    "3. Keep all security/endpoint agents updated (CrowdStrike, Carbon Black, etc.). "
                    "4. Where possible, migrate to DriverKit-based drivers instead of kexts. "
                    "5. Review Kernel Extension User Consents: "
                    "sudo sqlite3 /private/var/db/SystemPolicyConfiguration/KextPolicy 'select * from kext_policy;'"
                ),
                references=[
                    "https://support.apple.com/guide/security/kernel-extensions-sec8e454101b/web",
                    "https://attack.mitre.org/techniques/T1014/",
                ],
                evidence=Evidence(extra={"host": host, "third_party_kexts": kexts[:20]}),
                cvss_v31_vector=CVSS_MED,
                mitre_attack=["TA0003/T1547.006", "TA0005/T1014"],
                target=host, service="ssh", confidence="MEDIUM",
            )

    # ── Check 11: Automatic updates ──────────────────────────────────────────

    async def _check_auto_updates(self, host: str, ssh, session) -> None:
        """Check if automatic macOS security updates are disabled."""
        result = await ssh.execute(
            session,
            "defaults read /Library/Preferences/com.apple.SoftwareUpdate "
            "AutomaticCheckEnabled 2>/dev/null; "
            "defaults read /Library/Preferences/com.apple.SoftwareUpdate "
            "AutomaticallyInstallMacOSUpdates 2>/dev/null; "
            "defaults read /Library/Preferences/com.apple.SoftwareUpdate "
            "CriticalUpdateInstall 2>/dev/null"
        )
        raw = (result.stdout or "").strip()
        if not raw or not result.success:
            return

        lines = [l.strip() for l in raw.splitlines() if l.strip()]

        # lines[0] = AutomaticCheckEnabled (0=off, 1=on)
        # lines[1] = AutomaticallyInstallMacOSUpdates (0=off, 1=on)
        # lines[2] = CriticalUpdateInstall (0=off, 1=on)
        auto_check = lines[0] if len(lines) > 0 else "1"
        auto_install = lines[1] if len(lines) > 1 else "1"
        critical_install = lines[2] if len(lines) > 2 else "1"

        issues = []
        if auto_check == "0":
            issues.append("AutomaticCheckEnabled=0 — system does not check for updates automatically")
        if critical_install == "0":
            issues.append("CriticalUpdateInstall=0 — critical security patches are NOT auto-installed")

        if issues:
            self.new_finding(
                title=f"macOS Automatic Security Updates Disabled — {host}",
                severity=Severity.MEDIUM,
                description=(
                    f"Automatic software update settings on {host} are misconfigured:\n"
                    + "\n".join(f"  - {i}" for i in issues)
                    + "\n\nWithout automatic security update checks and installation, "
                    f"the system relies on manual patching which is often delayed or missed. "
                    f"Apple frequently releases Rapid Security Responses (RSRs) for actively "
                    f"exploited zero-days — these require automatic update checking to be enabled."
                ),
                reproduction_steps=[
                    f"ssh {host}",
                    "defaults read /Library/Preferences/com.apple.SoftwareUpdate",
                ],
                remediation=(
                    "Enable automatic update checking: "
                    "sudo defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticCheckEnabled -bool true. "
                    "Enable critical security update auto-install: "
                    "sudo defaults write /Library/Preferences/com.apple.SoftwareUpdate CriticalUpdateInstall -bool true. "
                    "Or: System Settings → General → Software Update → enable Automatic Updates."
                ),
                references=[
                    "CIS macOS Benchmark 1.1",
                    "https://support.apple.com/en-us/102662",
                ],
                evidence=Evidence(extra={
                    "host": host,
                    "auto_check_enabled": auto_check,
                    "critical_update_install": critical_install,
                    "issues": issues,
                }),
                cvss_v31_vector=CVSS_MED,
                target=host, service="ssh", confidence="HIGH",
            )
