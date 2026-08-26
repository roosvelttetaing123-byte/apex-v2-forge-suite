"""Passive CIS Benchmark evaluator for supplied host facts.

This module intentionally does not open SSH, WinRM, WMI, or any other network
transport. It evaluates facts and safe command output already collected by an
authorized credentialed workflow, fixture, or operator import.
"""
from __future__ import annotations

import json
import re
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity


CVSS_MEDIUM_LOCAL = "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N"
CVSS_HIGH_LOCAL = "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"


@dataclass(frozen=True)
class CisCheck:
    """One deterministic CIS control definition."""

    check_id: str
    platform: str
    level: int
    title: str
    section: str
    severity: Severity
    description: str
    remediation: str
    references: tuple[str, ...]
    fact_key: str
    expected: Any
    comparator: str = "eq"
    evidence_commands: tuple[str, ...] = ()


@dataclass(frozen=True)
class CisCheckResult:
    """Evaluation result for one CIS control."""

    check: CisCheck
    host: str
    status: str
    actual: Any = None
    reason: str = ""
    evidence: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "check_id": self.check.check_id,
            "platform": self.check.platform,
            "level": self.check.level,
            "title": self.check.title,
            "section": self.check.section,
            "status": self.status,
            "actual": self.actual,
            "reason": self.reason,
            "evidence": self.evidence or {},
        }


class CisBenchmarkEvaluator:
    """Evaluate a bounded CIS L1/L2 subset from supplied host facts."""

    LINUX_CHECKS: tuple[CisCheck, ...] = (
        CisCheck(
            check_id="linux-1.1.1.1",
            platform="linux",
            level=1,
            title="Unused cramfs filesystem disabled",
            section="1.1.1.1",
            severity=Severity.MEDIUM,
            description="The cramfs filesystem kernel module is loadable.",
            remediation="Add 'install cramfs /bin/true' to a file under /etc/modprobe.d/ and unload the module.",
            references=("CIS Ubuntu Linux Benchmark 1.1.1.1", "CIS Debian Linux Benchmark 1.1.1.1", "CIS RHEL Benchmark 1.1.1.1"),
            fact_key="kernel_modules.cramfs.disabled",
            expected=True,
            evidence_commands=("modprobe -n -v cramfs",),
        ),
        CisCheck(
            check_id="linux-1.1.2.1",
            platform="linux",
            level=1,
            title="/tmp is configured as a separate or tmpfs mount",
            section="1.1.2.1",
            severity=Severity.MEDIUM,
            description="/tmp is not isolated with a dedicated mount or tmpfs.",
            remediation="Mount /tmp separately or as tmpfs with restrictive options in /etc/fstab.",
            references=("CIS Ubuntu Linux Benchmark 1.1.2.1", "CIS Debian Linux Benchmark 1.1.2.1", "CIS RHEL Benchmark 1.1.2.1"),
            fact_key="mounts./tmp.separate",
            expected=True,
            evidence_commands=("findmnt --target /tmp --json", "grep -E '\\s/tmp\\s' /etc/fstab"),
        ),
        CisCheck(
            check_id="linux-1.1.2.2",
            platform="linux",
            level=1,
            title="/tmp mounted with nodev",
            section="1.1.2.2",
            severity=Severity.MEDIUM,
            description="/tmp is mounted without the nodev option.",
            remediation="Add nodev to the /tmp mount options and remount /tmp.",
            references=("CIS Ubuntu Linux Benchmark 1.1.2.2", "CIS Debian Linux Benchmark 1.1.2.2", "CIS RHEL Benchmark 1.1.2.2"),
            fact_key="mounts./tmp.options",
            expected="nodev",
            comparator="contains",
            evidence_commands=("findmnt --target /tmp --json", "mount | grep ' /tmp '"),
        ),
        CisCheck(
            check_id="linux-3.3.1",
            platform="linux",
            level=1,
            title="IPv4 forwarding disabled",
            section="3.3.1",
            severity=Severity.MEDIUM,
            description="IPv4 forwarding is enabled on a host that is not declared as a router.",
            remediation="Set net.ipv4.ip_forward=0 in sysctl configuration unless routing is explicitly required.",
            references=("CIS Ubuntu Linux Benchmark 3.3.1", "CIS Debian Linux Benchmark 3.3.1", "CIS RHEL Benchmark 3.3.1"),
            fact_key="sysctl.net.ipv4.ip_forward",
            expected=0,
            comparator="int_eq",
            evidence_commands=("sysctl net.ipv4.ip_forward",),
        ),
        CisCheck(
            check_id="linux-4.1.1.1",
            platform="linux",
            level=1,
            title="auditd installed",
            section="4.1.1.1",
            severity=Severity.MEDIUM,
            description="auditd is not installed.",
            remediation="Install auditd and configure audit rules for the host baseline.",
            references=("CIS Ubuntu Linux Benchmark 4.1.1.1", "CIS Debian Linux Benchmark 4.1.1.1", "CIS RHEL Benchmark 4.1.1.1"),
            fact_key="packages.auditd.installed",
            expected=True,
            evidence_commands=("dpkg -s auditd", "rpm -q audit"),
        ),
        CisCheck(
            check_id="linux-5.4.1.1",
            platform="linux",
            level=1,
            title="Password maximum age is 365 days or less",
            section="5.4.1.1",
            severity=Severity.HIGH,
            description="Password maximum age is not configured or exceeds 365 days.",
            remediation="Set PASS_MAX_DAYS to 365 or lower in /etc/login.defs and update existing accounts.",
            references=("CIS Ubuntu Linux Benchmark 5.4.1.1", "CIS Debian Linux Benchmark 5.4.1.1", "CIS RHEL Benchmark 5.4.1.1"),
            fact_key="password_policy.max_days",
            expected=365,
            comparator="int_lte",
            evidence_commands=("grep '^PASS_MAX_DAYS' /etc/login.defs",),
        ),
        CisCheck(
            check_id="linux-5.4.1.2",
            platform="linux",
            level=2,
            title="Password minimum age is 7 days or more",
            section="5.4.1.2",
            severity=Severity.MEDIUM,
            description="Password minimum age is below 7 days.",
            remediation="Set PASS_MIN_DAYS to 7 or higher in /etc/login.defs and update existing accounts.",
            references=("CIS Ubuntu Linux Benchmark 5.4.1.2", "CIS Debian Linux Benchmark 5.4.1.2", "CIS RHEL Benchmark 5.4.1.2"),
            fact_key="password_policy.min_days",
            expected=7,
            comparator="int_gte",
            evidence_commands=("grep '^PASS_MIN_DAYS' /etc/login.defs",),
        ),
        CisCheck(
            check_id="linux-5.6.1",
            platform="linux",
            level=1,
            title="SSH root login disabled",
            section="5.6.1",
            severity=Severity.HIGH,
            description="SSH permits direct root login.",
            remediation="Set PermitRootLogin no in sshd_config and reload sshd.",
            references=("CIS Ubuntu Linux Benchmark 5.6.1", "CIS Debian Linux Benchmark 5.6.1", "CIS RHEL Benchmark 5.6.1"),
            fact_key="ssh.permit_root_login",
            expected=False,
            evidence_commands=("sshd -T | grep permitrootlogin",),
        ),
    )

    WINDOWS_CHECKS: tuple[CisCheck, ...] = (
        CisCheck(
            check_id="windows-1.1.1",
            platform="windows",
            level=1,
            title="Password history is 24 or more",
            section="1.1.1",
            severity=Severity.HIGH,
            description="Password history is below 24 remembered passwords.",
            remediation="Configure Enforce password history to 24 through Group Policy or local security policy.",
            references=("CIS Microsoft Windows Server Benchmark 1.1.1",),
            fact_key="password_policy.history_count",
            expected=24,
            comparator="int_gte",
            evidence_commands=("net accounts", "Get-ADDefaultDomainPasswordPolicy"),
        ),
        CisCheck(
            check_id="windows-1.1.4",
            platform="windows",
            level=1,
            title="Minimum password length is 14 or more",
            section="1.1.4",
            severity=Severity.HIGH,
            description="Minimum password length is below 14 characters.",
            remediation="Configure Minimum password length to 14 or greater.",
            references=("CIS Microsoft Windows Server Benchmark 1.1.4",),
            fact_key="password_policy.min_length",
            expected=14,
            comparator="int_gte",
            evidence_commands=("net accounts", "Get-ADDefaultDomainPasswordPolicy"),
        ),
        CisCheck(
            check_id="windows-1.2.1",
            platform="windows",
            level=1,
            title="Account lockout threshold is 5 or fewer attempts",
            section="1.2.1",
            severity=Severity.HIGH,
            description="Account lockout threshold is disabled or greater than 5 attempts.",
            remediation="Configure Account lockout threshold to 5 or fewer invalid attempts.",
            references=("CIS Microsoft Windows Server Benchmark 1.2.1",),
            fact_key="password_policy.lockout_threshold",
            expected=5,
            comparator="int_between_1_lte",
            evidence_commands=("net accounts", "Get-ADDefaultDomainPasswordPolicy"),
        ),
        CisCheck(
            check_id="windows-2.3.1.2",
            platform="windows",
            level=1,
            title="Guest account disabled",
            section="2.3.1.2",
            severity=Severity.MEDIUM,
            description="The built-in Guest account is enabled.",
            remediation="Disable the Guest account through security policy or Group Policy.",
            references=("CIS Microsoft Windows Server Benchmark 2.3.1.2",),
            fact_key="accounts.guest.enabled",
            expected=False,
            evidence_commands=("Get-LocalUser Guest",),
        ),
        CisCheck(
            check_id="windows-2.3.9.4",
            platform="windows",
            level=1,
            title="Microsoft network server digitally signs communications",
            section="2.3.9.4",
            severity=Severity.MEDIUM,
            description="SMB server signing is not required.",
            remediation="Set Microsoft network server: Digitally sign communications (always) to Enabled.",
            references=("CIS Microsoft Windows Server Benchmark 2.3.9.4",),
            fact_key="smb.server_signing_required",
            expected=True,
            evidence_commands=("Get-SmbServerConfiguration | Select RequireSecuritySignature",),
        ),
        CisCheck(
            check_id="windows-9.1.1",
            platform="windows",
            level=1,
            title="Domain firewall profile enabled",
            section="9.1.1",
            severity=Severity.MEDIUM,
            description="The Windows Defender Firewall domain profile is disabled.",
            remediation="Enable the Windows Defender Firewall domain profile.",
            references=("CIS Microsoft Windows Server Benchmark 9.1.1",),
            fact_key="firewall.domain.enabled",
            expected=True,
            evidence_commands=("Get-NetFirewallProfile -Profile Domain",),
        ),
        CisCheck(
            check_id="windows-18.9.45.4.1",
            platform="windows",
            level=1,
            title="Defender real-time protection enabled",
            section="18.9.45.4.1",
            severity=Severity.HIGH,
            description="Microsoft Defender real-time protection is disabled.",
            remediation="Enable Defender real-time protection and enforce it through policy.",
            references=("CIS Microsoft Windows Server Benchmark 18.9.45.4.1",),
            fact_key="defender.realtime_protection_enabled",
            expected=True,
            evidence_commands=("Get-MpPreference", "Get-MpComputerStatus"),
        ),
        CisCheck(
            check_id="windows-18.9.102.1",
            platform="windows",
            level=2,
            title="PowerShell script block logging enabled",
            section="18.9.102.1",
            severity=Severity.MEDIUM,
            description="PowerShell script block logging is disabled.",
            remediation="Enable Turn on PowerShell Script Block Logging through Group Policy.",
            references=("CIS Microsoft Windows Server Benchmark 18.9.102.1",),
            fact_key="powershell.script_block_logging_enabled",
            expected=True,
            evidence_commands=("Get-ItemProperty HKLM:\\Software\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging",),
        ),
    )

    def __init__(self, level: int = 1) -> None:
        if level not in (1, 2):
            raise ValueError("CIS benchmark level must be 1 or 2")
        self.level = level

    def evaluate_host(self, host_facts: dict[str, Any]) -> list[CisCheckResult]:
        host = str(host_facts.get("host") or host_facts.get("target") or "unknown")
        platform = self._normalise_platform(str(host_facts.get("platform") or host_facts.get("os") or ""))
        facts = dict(host_facts.get("facts") or {})
        outputs = dict(host_facts.get("command_outputs") or {})
        self._merge_safe_outputs(platform, facts, outputs)

        checks = [check for check in self._checks_for(platform) if check.level <= self.level]
        return [self._evaluate_check(host, facts, outputs, check) for check in checks]

    def _checks_for(self, platform: str) -> tuple[CisCheck, ...]:
        if platform == "windows":
            return self.WINDOWS_CHECKS
        if platform in {"ubuntu", "debian", "rhel", "linux"}:
            return self.LINUX_CHECKS
        return ()

    @staticmethod
    def _normalise_platform(value: str) -> str:
        platform = value.strip().lower()
        if "win" in platform:
            return "windows"
        if any(token in platform for token in ("ubuntu", "debian", "rhel", "red hat", "rocky", "alma", "centos")):
            return "linux"
        return platform

    def _evaluate_check(
        self,
        host: str,
        facts: dict[str, Any],
        outputs: dict[str, Any],
        check: CisCheck,
    ) -> CisCheckResult:
        actual = self._get_nested(facts, check.fact_key)
        evidence = self._evidence_for(check, outputs)
        if actual is None:
            return CisCheckResult(check, host, "not_tested", actual, "required fact missing", evidence)
        passed = self._compare(actual, check.expected, check.comparator)
        return CisCheckResult(
            check=check,
            host=host,
            status="pass" if passed else "fail",
            actual=actual,
            reason="" if passed else f"expected {check.comparator} {check.expected!r}, got {actual!r}",
            evidence=evidence,
        )

    @staticmethod
    def _compare(actual: Any, expected: Any, comparator: str) -> bool:
        if comparator == "eq":
            return actual == expected
        if comparator == "contains":
            if isinstance(actual, str):
                values = [item.strip().lower() for item in re.split(r"[,\\s]+", actual) if item.strip()]
            else:
                values = [str(item).lower() for item in (actual or [])]
            return str(expected).lower() in values
        try:
            actual_int = int(actual)
            expected_int = int(expected)
        except (TypeError, ValueError):
            return False
        if comparator == "int_eq":
            return actual_int == expected_int
        if comparator == "int_gte":
            return actual_int >= expected_int
        if comparator == "int_lte":
            return actual_int <= expected_int
        if comparator == "int_between_1_lte":
            return 1 <= actual_int <= expected_int
        return False

    @staticmethod
    def _get_nested(data: dict[str, Any], path: str) -> Any:
        current: Any = data
        for part in path.split("."):
            if isinstance(current, dict) and part in current:
                current = current[part]
            else:
                return None
        return current

    @staticmethod
    def _set_nested(data: dict[str, Any], path: str, value: Any) -> None:
        current = data
        parts = path.split(".")
        for part in parts[:-1]:
            current = current.setdefault(part, {})
        current.setdefault(parts[-1], value)

    @staticmethod
    def _evidence_for(check: CisCheck, outputs: dict[str, Any]) -> dict[str, Any]:
        evidence = {}
        for command in check.evidence_commands:
            if command in outputs:
                value = str(outputs[command])
                evidence[command] = value[:1000]
        return evidence

    def _merge_safe_outputs(self, platform: str, facts: dict[str, Any], outputs: dict[str, Any]) -> None:
        if platform == "windows":
            self._merge_windows_outputs(facts, outputs)
        elif platform in {"ubuntu", "debian", "rhel", "linux"}:
            self._merge_linux_outputs(facts, outputs)

    def _merge_linux_outputs(self, facts: dict[str, Any], outputs: dict[str, Any]) -> None:
        modprobe = str(outputs.get("modprobe -n -v cramfs", ""))
        if modprobe:
            disabled = "install /bin/true" in modprobe or "install /bin/false" in modprobe or "not found" in modprobe.lower()
            self._set_nested(facts, "kernel_modules.cramfs.disabled", disabled)

        sysctl = str(outputs.get("sysctl net.ipv4.ip_forward", ""))
        match = re.search(r"=\s*(\d+)", sysctl)
        if match:
            self._set_nested(facts, "sysctl.net.ipv4.ip_forward", int(match.group(1)))

        login_defs = str(outputs.get("grep '^PASS_MAX_DAYS' /etc/login.defs", ""))
        match = re.search(r"PASS_MAX_DAYS\s+(\d+)", login_defs)
        if match:
            self._set_nested(facts, "password_policy.max_days", int(match.group(1)))
        login_defs_min = str(outputs.get("grep '^PASS_MIN_DAYS' /etc/login.defs", ""))
        match = re.search(r"PASS_MIN_DAYS\s+(\d+)", login_defs_min)
        if match:
            self._set_nested(facts, "password_policy.min_days", int(match.group(1)))

        sshd = str(outputs.get("sshd -T | grep permitrootlogin", "")).lower()
        match = re.search(r"permitrootlogin\s+(\S+)", sshd)
        if match:
            self._set_nested(facts, "ssh.permit_root_login", match.group(1) not in {"no", "prohibit-password", "forced-commands-only"})

        findmnt = str(outputs.get("findmnt --target /tmp --json", ""))
        if findmnt:
            parsed = self._parse_findmnt_tmp(findmnt)
            if parsed:
                self._set_nested(facts, "mounts./tmp.separate", True)
                self._set_nested(facts, "mounts./tmp.options", parsed.get("options", []))

        for command in ("dpkg -s auditd", "rpm -q audit"):
            output = str(outputs.get(command, ""))
            if output:
                installed = "Status: install ok installed" in output or bool(re.search(r"^audit-\d", output.strip()))
                self._set_nested(facts, "packages.auditd.installed", installed)

    def _merge_windows_outputs(self, facts: dict[str, Any], outputs: dict[str, Any]) -> None:
        net_accounts = str(outputs.get("net accounts", ""))
        if net_accounts:
            patterns = {
                "password_policy.min_length": r"Minimum password length\s*:\s*(\d+)",
                "password_policy.history_count": r"Length of password history maintained\s*:\s*(\d+)",
                "password_policy.lockout_threshold": r"Lockout threshold\s*:\s*(Never|\d+)",
            }
            for path, pattern in patterns.items():
                match = re.search(pattern, net_accounts, re.IGNORECASE)
                if match:
                    value = 0 if match.group(1).lower() == "never" else int(match.group(1))
                    self._set_nested(facts, path, value)

        smb = str(outputs.get("Get-SmbServerConfiguration | Select RequireSecuritySignature", ""))
        if smb:
            self._set_nested(facts, "smb.server_signing_required", self._looks_true(smb))

        firewall = str(outputs.get("Get-NetFirewallProfile -Profile Domain", ""))
        if firewall:
            self._set_nested(facts, "firewall.domain.enabled", self._looks_true(firewall))

        defender = str(outputs.get("Get-MpPreference", "") or outputs.get("Get-MpComputerStatus", ""))
        if defender:
            if re.search(r"DisableRealtimeMonitoring\s*[:=]\s*True", defender, re.IGNORECASE):
                self._set_nested(facts, "defender.realtime_protection_enabled", False)
            elif re.search(r"(RealTimeProtectionEnabled|AMServiceEnabled)\s*[:=]\s*True", defender, re.IGNORECASE):
                self._set_nested(facts, "defender.realtime_protection_enabled", True)

        guest = str(outputs.get("Get-LocalUser Guest", ""))
        if guest:
            if re.search(r"Enabled\s*[:=]\s*True", guest, re.IGNORECASE):
                self._set_nested(facts, "accounts.guest.enabled", True)
            elif re.search(r"Enabled\s*[:=]\s*False", guest, re.IGNORECASE):
                self._set_nested(facts, "accounts.guest.enabled", False)

    @staticmethod
    def _parse_findmnt_tmp(output: str) -> dict[str, Any] | None:
        try:
            data = json.loads(output)
        except json.JSONDecodeError:
            return None
        filesystems = data.get("filesystems") or []
        if not filesystems:
            return None
        first = filesystems[0]
        options = first.get("options") or ""
        if isinstance(options, str):
            options = [item.strip() for item in options.split(",") if item.strip()]
        return {"options": options}

    @staticmethod
    def _looks_true(output: str) -> bool:
        return bool(re.search(r"\b(True|Enabled|1)\b", output, re.IGNORECASE))


class CisBenchmark(BaseModule):
    """NetForge module wrapper for passive CIS Benchmark evaluation."""

    NAME = "cis_benchmark"
    DESCRIPTION = "Passive CIS Level 1/2 evaluator for supplied Linux and Windows host facts"
    PHASE = 5
    TAGS = ["credentialed", "compliance", "cis", "benchmark", "passive"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        host_inputs = self._host_inputs()
        if not host_inputs:
            return self._make_result(
                start,
                skipped=True,
                skip_reason="no supplied CIS facts or safe command outputs",
            )

        level = int(self.config.extra.get("cis_level", 1))
        evaluator = CisBenchmarkEvaluator(level=level)
        evaluated = 0
        failed = 0
        not_tested = 0
        for host_facts in host_inputs:
            host = str(host_facts.get("host") or host_facts.get("target") or self.config.target)
            if not self.check_scope(host):
                continue
            results = evaluator.evaluate_host(host_facts)
            evaluated += len(results)
            not_tested += len([result for result in results if result.status == "not_tested"])
            for result in results:
                if result.status == "fail":
                    failed += 1
                    self._finding_from_result(result)

        self._emit_event(
            "module_complete",
            name=self.NAME,
            evaluated=evaluated,
            failed=failed,
            not_tested=not_tested,
            passive=True,
        )
        return self._make_result(start)

    def _host_inputs(self) -> list[dict[str, Any]]:
        raw = self.config.extra.get("cis_hosts")
        if raw is None:
            raw = self.config.extra.get("cis_facts")
        if raw is None:
            raw = self.config.extra.get("cis_command_outputs")
            if raw:
                raw = {"host": self.config.target, "platform": self.config.extra.get("cis_platform", "linux"), "command_outputs": raw}
        if raw is None:
            return []
        if isinstance(raw, dict):
            if "hosts" in raw and isinstance(raw["hosts"], list):
                return [dict(item) for item in raw["hosts"] if isinstance(item, dict)]
            return [dict(raw)]
        if isinstance(raw, list):
            return [dict(item) for item in raw if isinstance(item, dict)]
        return []

    def _finding_from_result(self, result: CisCheckResult) -> None:
        check = result.check
        self.new_finding(
            title=f"CIS {check.section} - {check.title} - {result.host}",
            severity=check.severity,
            description=f"{check.description} Evaluation reason: {result.reason}",
            reproduction_steps=[
                "Review the supplied credentialed facts or safe command output.",
                *check.evidence_commands,
            ],
            remediation=check.remediation,
            references=list(check.references),
            evidence=Evidence(
                extra={
                    "host": result.host,
                    "check_id": check.check_id,
                    "check": result.to_dict(),
                    "passive": True,
                    "network_activity": "none",
                }
            ),
            cvss_v31_vector=CVSS_HIGH_LOCAL if check.severity == Severity.HIGH else CVSS_MEDIUM_LOCAL,
            target=result.host,
            service="local-facts",
            confidence="HIGH",
            tags=["cis", "compliance", check.platform, f"cis-level-{check.level}", check.section],
        )
