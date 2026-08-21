"""BeaconAPI — BOF Communication Shim.

Provides the Beacon API functions that BOFs call to:
    - Output text to the operator (BeaconPrintf, BeaconOutput)
    - Parse packed arguments (BeaconDataParse, BeaconDataExtract, etc.)
    - Allocate memory (BeaconCalloc, BeaconFree)
    - Get beacon metadata (BeaconGetSpawnTo, BeaconIsAdmin)
    - Format output (BeaconFormatAlloc, BeaconFormatPrintf, BeaconFormatToString)

These map 1:1 with Cobalt Strike's BOF API, so community BOFs work out of the box.

Usage::
    api = BeaconAPI()
    # BOF calls api functions during execution
    # After execution, collect output:
    output = api.get_output()

FOR AUTHORIZED RED TEAM OPERATIONS ONLY.
"""
from __future__ import annotations

import ctypes
import logging
import os
import struct
import sys
from dataclasses import dataclass, field
from typing import Any

log = logging.getLogger("forge.c2.bof.api")


# ══════════════════════════════════════════════════════════════════════
# BEACON DATA PARSER — argument unpacking for BOFs
# ══════════════════════════════════════════════════════════════════════

class BeaconDataParser:
    """Parse packed BOF argument buffers.

    BOF arguments are packed as:
        [4-byte length][data][4-byte length][data]...

    Types:
        - int (4 bytes, little-endian)
        - short (2 bytes, little-endian)
        - z-string (4-byte length + UTF-8 bytes + null)
        - Z-string (4-byte length + UTF-16LE bytes + null)
        - b-blob (4-byte length + raw bytes)
    """

    def __init__(self, data: bytes = b"") -> None:
        self.data = data
        self.offset = 0
        self.length = len(data)

    def extract_int(self) -> int:
        """Extract a 4-byte little-endian integer."""
        if self.offset + 4 > self.length:
            return 0
        val = struct.unpack_from("<i", self.data, self.offset)[0]
        self.offset += 4
        return val

    def extract_short(self) -> int:
        """Extract a 2-byte little-endian short."""
        if self.offset + 2 > self.length:
            return 0
        val = struct.unpack_from("<h", self.data, self.offset)[0]
        self.offset += 2
        return val

    def extract_str(self) -> str:
        """Extract a length-prefixed UTF-8 string (z-string)."""
        length = self.extract_int()
        if length <= 0 or self.offset + length > self.length:
            return ""
        raw = self.data[self.offset:self.offset + length]
        self.offset += length
        return raw.rstrip(b"\x00").decode("utf-8", errors="replace")

    def extract_wstr(self) -> str:
        """Extract a length-prefixed UTF-16LE string (Z-string)."""
        length = self.extract_int()
        if length <= 0 or self.offset + length > self.length:
            return ""
        raw = self.data[self.offset:self.offset + length]
        self.offset += length
        # Remove UTF-16LE null terminator (exactly 2 zero bytes at end)
        if raw.endswith(b"\x00\x00"):
            raw = raw[:-2]
        return raw.decode("utf-16-le", errors="replace")

    def extract_blob(self) -> bytes:
        """Extract a length-prefixed binary blob."""
        length = self.extract_int()
        if length <= 0 or self.offset + length > self.length:
            return b""
        raw = self.data[self.offset:self.offset + length]
        self.offset += length
        return raw

    def remaining(self) -> int:
        """How many bytes remain unparsed."""
        return max(0, self.length - self.offset)

    def is_empty(self) -> bool:
        """True if no data remains."""
        return self.offset >= self.length


class BeaconDataPacker:
    """Pack arguments into the BOF argument format.

    Used by the operator shell to build arg buffers before sending to beacon.

    Usage::
        packer = BeaconDataPacker()
        packer.add_int(1337)
        packer.add_str("hello")
        packer.add_wstr("wide string")
        args = packer.build()
    """

    def __init__(self) -> None:
        self._parts: list[bytes] = []

    def add_int(self, value: int) -> "BeaconDataPacker":
        """Add a 4-byte integer."""
        self._parts.append(struct.pack("<i", value))
        return self

    def add_short(self, value: int) -> "BeaconDataPacker":
        """Add a 2-byte short."""
        self._parts.append(struct.pack("<h", value))
        return self

    def add_str(self, value: str) -> "BeaconDataPacker":
        """Add a length-prefixed UTF-8 string."""
        encoded = value.encode("utf-8") + b"\x00"
        self._parts.append(struct.pack("<I", len(encoded)))
        self._parts.append(encoded)
        return self

    def add_wstr(self, value: str) -> "BeaconDataPacker":
        """Add a length-prefixed UTF-16LE string."""
        encoded = value.encode("utf-16-le") + b"\x00\x00"
        self._parts.append(struct.pack("<I", len(encoded)))
        self._parts.append(encoded)
        return self

    def add_blob(self, data: bytes) -> "BeaconDataPacker":
        """Add a length-prefixed binary blob."""
        self._parts.append(struct.pack("<I", len(data)))
        self._parts.append(data)
        return self

    def build(self) -> bytes:
        """Build the final packed argument buffer."""
        return b"".join(self._parts)

    def reset(self) -> None:
        """Clear all packed data."""
        self._parts.clear()


# ══════════════════════════════════════════════════════════════════════
# BEACON FORMAT API — structured output formatting
# ══════════════════════════════════════════════════════════════════════

class BeaconFormatBuffer:
    """Format buffer for structured BOF output.

    Maps to Cobalt Strike's BeaconFormatAlloc/BeaconFormatPrintf/etc.
    """

    def __init__(self, size: int = 4096) -> None:
        self.buffer: list[str] = []
        self.max_size = size

    def printf(self, fmt: str, *args: Any) -> None:
        """Printf-style append to the format buffer."""
        try:
            self.buffer.append(fmt % args if args else fmt)
        except (TypeError, ValueError):
            self.buffer.append(fmt)

    def append(self, data: str) -> None:
        """Append raw text."""
        self.buffer.append(data)

    def to_string(self) -> str:
        """Get the formatted output as a string."""
        return "".join(self.buffer)

    def reset(self) -> None:
        """Clear the buffer."""
        self.buffer.clear()


# ══════════════════════════════════════════════════════════════════════
# BEACON API — the full shim
# ══════════════════════════════════════════════════════════════════════

# Output type constants (match CS)
CALLBACK_OUTPUT = 0
CALLBACK_OUTPUT_OEM = 0x1e
CALLBACK_OUTPUT_UTF8 = 0x20
CALLBACK_ERROR = 0x0d


class BeaconAPI:
    """Full Beacon API shim for BOF execution.

    Provides all functions a BOF can call, matching Cobalt Strike's API:
        - Output: BeaconPrintf, BeaconOutput, BeaconOutputType
        - Data: BeaconDataParse, BeaconDataInt, BeaconDataStr, etc.
        - Format: BeaconFormatAlloc, BeaconFormatPrintf, BeaconFormatToString
        - Memory: BeaconCalloc, BeaconFree
        - Info: BeaconIsAdmin, BeaconGetSpawnTo, BeaconUseToken

    Each function is registered by name so the BOF loader can resolve
    __imp_BeaconPrintf etc. to the correct ctypes function pointer.
    """

    def __init__(self) -> None:
        self._output_buffer: list[str] = []
        self._error_buffer: list[str] = []
        self._parser: BeaconDataParser | None = None
        self._format_buffers: dict[int, BeaconFormatBuffer] = {}
        self._format_counter = 0
        self._allocated: dict[int, ctypes.Array] = {}

        # Register all API functions with their ctypes function pointers
        self._function_map: dict[str, int] = {}
        self._callbacks: dict[str, Any] = {}
        self._register_functions()

    def reset(self) -> None:
        """Reset all state for a new BOF execution."""
        self._output_buffer.clear()
        self._error_buffer.clear()
        self._parser = None
        self._format_buffers.clear()
        self._format_counter = 0
        self._allocated.clear()

    def get_output(self) -> str:
        """Get all collected output from the BOF."""
        return "".join(self._output_buffer)

    def get_errors(self) -> str:
        """Get all collected errors."""
        return "".join(self._error_buffer)

    def resolve(self, name: str) -> int | None:
        """Resolve a Beacon API function name to its address.

        The BOF loader calls this during symbol resolution.
        """
        return self._function_map.get(name)

    # ── Output functions ──────────────────────────────────────────────

    def BeaconPrintf(self, callback_type: int, fmt: str, *args: Any) -> None:
        """Printf to the beacon output."""
        try:
            msg = fmt % args if args else fmt
        except (TypeError, ValueError):
            msg = fmt
        if callback_type == CALLBACK_ERROR:
            self._error_buffer.append(msg)
        else:
            self._output_buffer.append(msg)

    def BeaconOutput(self, callback_type: int, data: str | bytes, length: int = 0) -> None:
        """Raw output to the beacon."""
        if isinstance(data, bytes):
            text = data[:length].decode("utf-8", errors="replace") if length > 0 else data.decode("utf-8", errors="replace")
        else:
            text = data
        if callback_type == CALLBACK_ERROR:
            self._error_buffer.append(text)
        else:
            self._output_buffer.append(text)

    # ── Data parsing functions ────────────────────────────────────────

    def BeaconDataParse(self, parser_ptr: Any, data: bytes, length: int) -> None:
        """Initialize the data parser with BOF arguments."""
        self._parser = BeaconDataParser(data[:length] if length > 0 else data)

    def BeaconDataInt(self, parser_ptr: Any = None) -> int:
        """Extract an int from the argument buffer."""
        if self._parser:
            return self._parser.extract_int()
        return 0

    def BeaconDataShort(self, parser_ptr: Any = None) -> int:
        """Extract a short from the argument buffer."""
        if self._parser:
            return self._parser.extract_short()
        return 0

    def BeaconDataLength(self, parser_ptr: Any = None) -> int:
        """Get remaining data length."""
        if self._parser:
            return self._parser.remaining()
        return 0

    def BeaconDataExtract(self, parser_ptr: Any = None, size_ptr: Any = None) -> str:
        """Extract a string from the argument buffer."""
        if self._parser:
            return self._parser.extract_str()
        return ""

    def BeaconDataBlob(self, parser_ptr: Any = None, size_ptr: Any = None) -> bytes:
        """Extract a blob from the argument buffer."""
        if self._parser:
            return self._parser.extract_blob()
        return b""

    # ── Format buffer functions ───────────────────────────────────────

    def BeaconFormatAlloc(self, format_ptr: Any = None, size: int = 4096) -> int:
        """Allocate a format buffer."""
        self._format_counter += 1
        buf = BeaconFormatBuffer(size)
        self._format_buffers[self._format_counter] = buf
        return self._format_counter

    def BeaconFormatPrintf(self, format_id: int = 0, fmt: str = "", *args: Any) -> None:
        """Printf into a format buffer."""
        buf = self._format_buffers.get(format_id)
        if buf:
            buf.printf(fmt, *args)

    def BeaconFormatAppend(self, format_id: int = 0, data: str = "") -> None:
        """Append to a format buffer."""
        buf = self._format_buffers.get(format_id)
        if buf:
            buf.append(data)

    def BeaconFormatToString(self, format_id: int = 0, size_ptr: Any = None) -> str:
        """Convert format buffer to string and add to output."""
        buf = self._format_buffers.get(format_id)
        if buf:
            text = buf.to_string()
            self._output_buffer.append(text)
            return text
        return ""

    def BeaconFormatFree(self, format_id: int = 0) -> None:
        """Free a format buffer."""
        self._format_buffers.pop(format_id, None)

    def BeaconFormatReset(self, format_id: int = 0) -> None:
        """Reset a format buffer without freeing."""
        buf = self._format_buffers.get(format_id)
        if buf:
            buf.reset()

    # ── Memory functions ──────────────────────────────────────────────

    def BeaconCalloc(self, count: int, size: int) -> int:
        """Allocate zeroed memory."""
        total = count * size
        buf = (ctypes.c_ubyte * total)()
        addr = ctypes.addressof(buf)
        self._allocated[addr] = buf
        return addr

    def BeaconFree(self, ptr: int) -> None:
        """Free allocated memory."""
        self._allocated.pop(ptr, None)

    # ── Info functions ────────────────────────────────────────────────

    def BeaconIsAdmin(self) -> int:
        """Check if beacon is running elevated."""
        if sys.platform == "win32":
            try:
                return int(ctypes.windll.shell32.IsUserAnAdmin())
            except (AttributeError, OSError):
                pass
        return 1 if os.geteuid() == 0 else 0

    def BeaconGetSpawnTo(self, x86: int = 0) -> str:
        """Get the configured spawnto binary."""
        if x86:
            return r"C:\Windows\SysWOW64\rundll32.exe"
        return r"C:\Windows\System32\rundll32.exe"

    def BeaconUseToken(self, token_handle: int) -> int:
        """Impersonate with a token (Windows only)."""
        log.debug("BeaconUseToken called with handle %d", token_handle)
        return 1

    def BeaconRevertToken(self) -> None:
        """Revert to original token."""
        log.debug("BeaconRevertToken called")

    def BeaconInjectProcess(
        self, pid: int, payload: bytes, payload_len: int,
        offset: int = 0, arg: bytes = b"", arg_len: int = 0,
    ) -> None:
        """Inject into a remote process (stub)."""
        log.info("BeaconInjectProcess: pid=%d, payload=%d bytes", pid, payload_len)

    def BeaconInjectTemporaryProcess(
        self, si: Any, payload: bytes, payload_len: int,
        offset: int = 0, arg: bytes = b"", arg_len: int = 0,
    ) -> None:
        """Inject into a temporary process (stub)."""
        log.info("BeaconInjectTemporaryProcess: payload=%d bytes", payload_len)

    def BeaconCleanupProcess(self, si: Any) -> None:
        """Cleanup a spawned process (stub)."""
        log.debug("BeaconCleanupProcess called")

    # ── Utility functions ─────────────────────────────────────────────

    def toWideChar(self, text: str) -> bytes:
        """Convert UTF-8 string to UTF-16LE."""
        return text.encode("utf-16-le") + b"\x00\x00"

    # ── Internal: register all functions ──────────────────────────────

    def _register_functions(self) -> None:
        """Build the function name → address mapping.

        Creates ctypes callback wrappers for each API function so BOFs
        can call them via function pointers resolved during COFF loading.
        """
        # Map all public Beacon* methods
        api_methods = [
            "BeaconPrintf", "BeaconOutput",
            "BeaconDataParse", "BeaconDataInt", "BeaconDataShort",
            "BeaconDataLength", "BeaconDataExtract", "BeaconDataBlob",
            "BeaconFormatAlloc", "BeaconFormatPrintf", "BeaconFormatAppend",
            "BeaconFormatToString", "BeaconFormatFree", "BeaconFormatReset",
            "BeaconCalloc", "BeaconFree",
            "BeaconIsAdmin", "BeaconGetSpawnTo",
            "BeaconUseToken", "BeaconRevertToken",
            "BeaconInjectProcess", "BeaconInjectTemporaryProcess",
            "BeaconCleanupProcess",
            "toWideChar",
        ]

        for method_name in api_methods:
            method = getattr(self, method_name, None)
            if method is None:
                continue

            # We store the Python callable — the BOF loader will create
            # ctypes function pointers from these during resolution.
            # For now, use id() as a unique token.
            self._function_map[method_name] = id(method)
            self._callbacks[method_name] = method

        log.debug("Registered %d Beacon API functions", len(self._function_map))

    def get_callback(self, name: str) -> Any | None:
        """Get the Python callable for a Beacon API function."""
        return self._callbacks.get(name)
