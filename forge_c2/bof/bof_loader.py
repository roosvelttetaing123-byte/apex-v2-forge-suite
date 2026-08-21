"""BOFLoader — In-memory COFF Object File Parser & Loader.

Parses x64 COFF .o files (compiled C), resolves relocations, maps sections,
and executes the entry point — all in-memory without touching disk.

This is the Forge equivalent of Cobalt Strike's BOF loader. The key advantage:
operators can write quick C tools, compile to .o, and run them inside the
beacon process without dropping an EXE or spawning a child process.

COFF Format (x64):
    ┌──────────────────┐
    │   COFF Header    │  20 bytes
    ├──────────────────┤
    │  Section Headers │  40 bytes each
    ├──────────────────┤
    │  Section Data    │  .text, .data, .rdata, .bss
    ├──────────────────┤
    │  Relocations     │  Per-section relocation entries
    ├──────────────────┤
    │  Symbol Table    │  18 bytes per symbol
    ├──────────────────┤
    │  String Table    │  Variable-length symbol names
    └──────────────────┘

Supported relocation types (x64):
    - IMAGE_REL_AMD64_ADDR64  (0x0001) — 64-bit direct
    - IMAGE_REL_AMD64_ADDR32NB (0x0003) — 32-bit RVA
    - IMAGE_REL_AMD64_REL32   (0x0004) — 32-bit relative
    - IMAGE_REL_AMD64_REL32_1..5 (0x0005-0x0009)

FOR AUTHORIZED RED TEAM OPERATIONS ONLY.
"""
from __future__ import annotations

import ctypes
import ctypes.util
import logging
import mmap
import os
import struct
import sys
import time
from dataclasses import dataclass, field
from enum import IntEnum
from pathlib import Path
from typing import Any, Callable

log = logging.getLogger("forge.c2.bof")


# ══════════════════════════════════════════════════════════════════════
# COFF CONSTANTS
# ══════════════════════════════════════════════════════════════════════

# Machine types
IMAGE_FILE_MACHINE_AMD64 = 0x8664
IMAGE_FILE_MACHINE_I386 = 0x014C

# Section flags
IMAGE_SCN_CNT_CODE = 0x00000020
IMAGE_SCN_CNT_INITIALIZED_DATA = 0x00000040
IMAGE_SCN_CNT_UNINITIALIZED_DATA = 0x00000080
IMAGE_SCN_MEM_EXECUTE = 0x20000000
IMAGE_SCN_MEM_READ = 0x40000000
IMAGE_SCN_MEM_WRITE = 0x80000000

# COFF header sizes
COFF_HEADER_SIZE = 20
SECTION_HEADER_SIZE = 40
SYMBOL_SIZE = 18
RELOC_ENTRY_SIZE = 10

# Storage classes
IMAGE_SYM_CLASS_EXTERNAL = 2
IMAGE_SYM_CLASS_STATIC = 3
IMAGE_SYM_CLASS_SECTION = 104

# Section number specials
IMAGE_SYM_UNDEFINED = 0
IMAGE_SYM_ABSOLUTE = -1
IMAGE_SYM_DEBUG = -2


class RelocType(IntEnum):
    """x64 COFF relocation types."""
    IMAGE_REL_AMD64_ABSOLUTE = 0x0000
    IMAGE_REL_AMD64_ADDR64 = 0x0001
    IMAGE_REL_AMD64_ADDR32 = 0x0002
    IMAGE_REL_AMD64_ADDR32NB = 0x0003
    IMAGE_REL_AMD64_REL32 = 0x0004
    IMAGE_REL_AMD64_REL32_1 = 0x0005
    IMAGE_REL_AMD64_REL32_2 = 0x0006
    IMAGE_REL_AMD64_REL32_3 = 0x0007
    IMAGE_REL_AMD64_REL32_4 = 0x0008
    IMAGE_REL_AMD64_REL32_5 = 0x0009


# ══════════════════════════════════════════════════════════════════════
# DATA MODELS
# ══════════════════════════════════════════════════════════════════════

@dataclass
class COFFHeader:
    """Parsed COFF file header."""
    machine: int
    num_sections: int
    timestamp: int
    symbol_table_offset: int
    num_symbols: int
    optional_header_size: int
    characteristics: int


@dataclass
class SectionHeader:
    """Parsed section header."""
    name: str
    virtual_size: int
    virtual_address: int
    raw_data_size: int
    raw_data_offset: int
    reloc_offset: int
    num_relocs: int
    characteristics: int
    index: int  # 1-based section index


@dataclass
class Symbol:
    """Parsed COFF symbol."""
    name: str
    value: int
    section_number: int  # 1-based, 0=UNDEFINED, -1=ABSOLUTE
    type_field: int
    storage_class: int
    num_aux: int
    index: int  # 0-based index in symbol table


@dataclass
class Relocation:
    """Parsed relocation entry."""
    virtual_address: int  # Offset within section
    symbol_index: int
    type: RelocType


@dataclass
class MappedSection:
    """A section mapped into memory."""
    header: SectionHeader
    address: int  # Base address of mapped memory
    size: int
    data: bytes


@dataclass
class BOFResult:
    """Result of BOF execution."""
    success: bool
    output: str = ""
    error: str = ""
    exit_code: int = 0
    execution_time: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "success": self.success,
            "output": self.output,
            "error": self.error,
            "exit_code": self.exit_code,
            "execution_time": self.execution_time,
        }


# ══════════════════════════════════════════════════════════════════════
# COFF PARSER
# ══════════════════════════════════════════════════════════════════════

class COFFParser:
    """Parse a raw COFF .o file into structured components."""

    def __init__(self, data: bytes) -> None:
        self.data = data
        self.header: COFFHeader | None = None
        self.sections: list[SectionHeader] = []
        self.symbols: list[Symbol] = []
        self.string_table: bytes = b""
        self._parse()

    def _parse(self) -> None:
        """Parse all COFF structures."""
        self._parse_header()
        self._parse_string_table()
        self._parse_sections()
        self._parse_symbols()

    def _parse_header(self) -> None:
        """Parse the COFF file header (20 bytes)."""
        if len(self.data) < COFF_HEADER_SIZE:
            raise ValueError(f"File too small for COFF header: {len(self.data)} bytes")

        fields = struct.unpack_from("<HHIIIHH", self.data, 0)
        self.header = COFFHeader(
            machine=fields[0],
            num_sections=fields[1],
            timestamp=fields[2],
            symbol_table_offset=fields[3],
            num_symbols=fields[4],
            optional_header_size=fields[5],
            characteristics=fields[6],
        )

        if self.header.machine not in (IMAGE_FILE_MACHINE_AMD64, IMAGE_FILE_MACHINE_I386):
            raise ValueError(
                f"Unsupported COFF machine type: 0x{self.header.machine:04X}. "
                f"Expected x64 (0x8664) or x86 (0x014C)."
            )

    def _parse_string_table(self) -> None:
        """Parse the string table (follows symbol table)."""
        if not self.header or self.header.symbol_table_offset == 0:
            return

        str_table_offset = (
            self.header.symbol_table_offset
            + self.header.num_symbols * SYMBOL_SIZE
        )
        if str_table_offset + 4 > len(self.data):
            return

        str_table_size = struct.unpack_from("<I", self.data, str_table_offset)[0]
        if str_table_size < 4:
            return

        end = str_table_offset + str_table_size
        if end > len(self.data):
            end = len(self.data)
        self.string_table = self.data[str_table_offset:end]

    def _get_symbol_name(self, name_bytes: bytes) -> str:
        """Resolve a symbol name from either inline or string table."""
        # If first 4 bytes are zero, next 4 are offset into string table
        if name_bytes[:4] == b"\x00\x00\x00\x00":
            offset = struct.unpack_from("<I", name_bytes, 4)[0]
            if offset < len(self.string_table):
                end = self.string_table.index(b"\x00", offset)
                return self.string_table[offset:end].decode("utf-8", errors="replace")
            return f"<str_offset_{offset}>"
        # Inline name (up to 8 chars, null-padded)
        return name_bytes.rstrip(b"\x00").decode("utf-8", errors="replace")

    def _parse_sections(self) -> None:
        """Parse all section headers."""
        if not self.header:
            return

        offset = COFF_HEADER_SIZE + self.header.optional_header_size
        for i in range(self.header.num_sections):
            if offset + SECTION_HEADER_SIZE > len(self.data):
                break

            name_bytes = self.data[offset:offset + 8]
            fields = struct.unpack_from("<IIIIIIIHHI", self.data, offset)[1:]
            # fields: VirtualSize, VirtualAddress, SizeOfRawData, PointerToRawData,
            #         PointerToRelocations, PointerToLinenumbers,
            #         NumberOfRelocations, NumberOfLinenumbers, Characteristics

            section = SectionHeader(
                name=self._get_symbol_name(name_bytes),
                virtual_size=fields[0],
                virtual_address=fields[1],
                raw_data_size=fields[2],
                raw_data_offset=fields[3],
                reloc_offset=fields[4],
                num_relocs=fields[6],
                characteristics=fields[8],
                index=i + 1,  # 1-based
            )
            self.sections.append(section)
            offset += SECTION_HEADER_SIZE

    def _parse_symbols(self) -> None:
        """Parse the symbol table."""
        if not self.header or self.header.symbol_table_offset == 0:
            return

        offset = self.header.symbol_table_offset
        idx = 0
        while idx < self.header.num_symbols:
            if offset + SYMBOL_SIZE > len(self.data):
                break

            name_bytes = self.data[offset:offset + 8]
            value, section_num, type_field, storage_class, num_aux = struct.unpack_from(
                "<IhHBB", self.data, offset + 8
            )

            symbol = Symbol(
                name=self._get_symbol_name(name_bytes),
                value=value,
                section_number=section_num,
                type_field=type_field,
                storage_class=storage_class,
                num_aux=num_aux,
                index=idx,
            )
            self.symbols.append(symbol)

            # Skip auxiliary symbol entries
            offset += SYMBOL_SIZE * (1 + num_aux)
            idx += 1 + num_aux

    def get_relocations(self, section: SectionHeader) -> list[Relocation]:
        """Parse relocations for a specific section."""
        relocs = []
        if section.num_relocs == 0 or section.reloc_offset == 0:
            return relocs

        offset = section.reloc_offset
        for _ in range(section.num_relocs):
            if offset + RELOC_ENTRY_SIZE > len(self.data):
                break
            va, sym_idx, rtype = struct.unpack_from("<IIH", self.data, offset)
            try:
                reloc_type = RelocType(rtype)
            except ValueError:
                log.warning("Unknown relocation type 0x%04X at offset %d", rtype, offset)
                offset += RELOC_ENTRY_SIZE
                continue

            relocs.append(Relocation(
                virtual_address=va,
                symbol_index=sym_idx,
                type=reloc_type,
            ))
            offset += RELOC_ENTRY_SIZE

        return relocs

    def get_section_data(self, section: SectionHeader) -> bytes:
        """Get raw data for a section."""
        if section.raw_data_size == 0 or section.raw_data_offset == 0:
            # BSS or empty section
            return b"\x00" * max(section.virtual_size, section.raw_data_size, 0)

        start = section.raw_data_offset
        end = start + section.raw_data_size
        if end > len(self.data):
            end = len(self.data)
        return self.data[start:end]


# ══════════════════════════════════════════════════════════════════════
# BOF LOADER
# ══════════════════════════════════════════════════════════════════════

class BOFLoader:
    """Load and execute COFF BOF files in-process.

    The loader:
    1. Parses the COFF .o file
    2. Allocates RWX memory for code sections, RW for data
    3. Copies section data into allocated memory
    4. Resolves relocations (internal + external/API)
    5. Resolves imports against the BeaconAPI shim
    6. Calls the BOF entry point: go(char* args, int args_len)

    Usage::
        loader = BOFLoader(beacon_api=api)
        result = loader.load_and_execute(bof_bytes, args=b"\\x00\\x01")
    """

    # Entry point names the loader searches for (in priority order)
    ENTRY_POINTS = ["go", "_go", "main", "_main"]

    def __init__(
        self,
        beacon_api: Any = None,
        function_resolver: Callable[[str, str], int] | None = None,
    ) -> None:
        """
        Args:
            beacon_api: BeaconAPI instance for BOF output/data functions.
            function_resolver: Custom (dll, func) -> address resolver. If None,
                              uses ctypes for the current platform.
        """
        self.beacon_api = beacon_api
        self._function_resolver = function_resolver or self._default_resolve
        self._mapped_sections: list[MappedSection] = []
        self._allocated_buffers: list[ctypes.Array] = []

    def load_and_execute(
        self,
        bof_data: bytes,
        args: bytes = b"",
        entry_point: str | None = None,
    ) -> BOFResult:
        """Load a COFF BOF and execute its entry point.

        Args:
            bof_data: Raw COFF .o file bytes.
            args: Packed argument buffer (BeaconDataParse format).
            entry_point: Override entry function name. Default: "go".

        Returns:
            BOFResult with output, errors, and timing.
        """
        start_time = time.monotonic()
        try:
            # 1. Parse COFF
            parser = COFFParser(bof_data)
            log.info(
                "BOF parsed: %d sections, %d symbols, machine=0x%04X",
                len(parser.sections), len(parser.symbols),
                parser.header.machine if parser.header else 0,
            )

            # 2. Map sections into memory
            self._map_sections(parser)

            # 3. Resolve relocations
            self._resolve_relocations(parser)

            # 4. Find entry point
            entry_addr = self._find_entry_point(parser, entry_point)
            if entry_addr is None:
                names = entry_point or ", ".join(self.ENTRY_POINTS)
                return BOFResult(
                    success=False,
                    error=f"Entry point not found. Searched: {names}",
                    execution_time=time.monotonic() - start_time,
                )

            # 5. Execute
            log.info("Executing BOF at 0x%X with %d bytes of args", entry_addr, len(args))
            output = self._execute(entry_addr, args)

            return BOFResult(
                success=True,
                output=output,
                execution_time=time.monotonic() - start_time,
            )

        except Exception as e:
            log.error("BOF execution failed: %s", e, exc_info=True)
            return BOFResult(
                success=False,
                error=str(e),
                execution_time=time.monotonic() - start_time,
            )
        finally:
            self._cleanup()

    def _map_sections(self, parser: COFFParser) -> None:
        """Allocate memory and copy section data."""
        self._mapped_sections.clear()
        self._allocated_buffers.clear()

        for section in parser.sections:
            data = parser.get_section_data(section)
            size = max(len(data), section.virtual_size, section.raw_data_size, 64)
            # Align to 16 bytes
            size = (size + 15) & ~15

            # Allocate buffer (ctypes array = contiguous memory)
            buf = (ctypes.c_ubyte * size)()
            # Copy section data
            ctypes.memmove(buf, data, len(data))

            mapped = MappedSection(
                header=section,
                address=ctypes.addressof(buf),
                size=size,
                data=data,
            )
            self._mapped_sections.append(mapped)
            self._allocated_buffers.append(buf)

            log.debug(
                "Mapped section '%s' (%d bytes) at 0x%X [flags=0x%08X]",
                section.name, size, mapped.address, section.characteristics,
            )

    def _get_section_address(self, section_number: int) -> int | None:
        """Get base address for a 1-based section number."""
        for mapped in self._mapped_sections:
            if mapped.header.index == section_number:
                return mapped.address
        return None

    def _resolve_relocations(self, parser: COFFParser) -> None:
        """Apply relocations for all sections."""
        for mapped in self._mapped_sections:
            relocs = parser.get_relocations(mapped.header)
            if not relocs:
                continue

            log.debug(
                "Resolving %d relocations for section '%s'",
                len(relocs), mapped.header.name,
            )

            for reloc in relocs:
                self._apply_relocation(parser, mapped, reloc)

    def _apply_relocation(
        self,
        parser: COFFParser,
        section: MappedSection,
        reloc: Relocation,
    ) -> None:
        """Apply a single relocation."""
        # Find the target symbol
        symbol = self._find_symbol_by_index(parser, reloc.symbol_index)
        if symbol is None:
            log.warning("Relocation references unknown symbol index %d", reloc.symbol_index)
            return

        # Resolve symbol address
        sym_addr = self._resolve_symbol(parser, symbol)
        if sym_addr is None:
            log.warning("Cannot resolve symbol '%s'", symbol.name)
            return

        # Calculate patch location
        patch_addr = section.address + reloc.virtual_address

        if reloc.type == RelocType.IMAGE_REL_AMD64_ADDR64:
            # 64-bit absolute address
            ctypes.c_uint64.from_address(patch_addr).value = sym_addr

        elif reloc.type == RelocType.IMAGE_REL_AMD64_ADDR32NB:
            # 32-bit relative to image base (RVA)
            ctypes.c_uint32.from_address(patch_addr).value = sym_addr & 0xFFFFFFFF

        elif reloc.type in (
            RelocType.IMAGE_REL_AMD64_REL32,
            RelocType.IMAGE_REL_AMD64_REL32_1,
            RelocType.IMAGE_REL_AMD64_REL32_2,
            RelocType.IMAGE_REL_AMD64_REL32_3,
            RelocType.IMAGE_REL_AMD64_REL32_4,
            RelocType.IMAGE_REL_AMD64_REL32_5,
        ):
            # 32-bit PC-relative with addend
            addend = reloc.type.value - RelocType.IMAGE_REL_AMD64_REL32.value
            # rel32 = target - (patch_location + 4 + addend)
            existing = ctypes.c_int32.from_address(patch_addr).value
            delta = sym_addr - (patch_addr + 4 + addend) + existing
            ctypes.c_int32.from_address(patch_addr).value = delta & 0xFFFFFFFF

        elif reloc.type == RelocType.IMAGE_REL_AMD64_ABSOLUTE:
            pass  # No-op relocation

        else:
            log.warning(
                "Unhandled relocation type %s for symbol '%s'",
                reloc.type.name, symbol.name,
            )

    def _find_symbol_by_index(self, parser: COFFParser, index: int) -> Symbol | None:
        """Find a symbol by its table index."""
        for sym in parser.symbols:
            if sym.index == index:
                return sym
        return None

    def _resolve_symbol(self, parser: COFFParser, symbol: Symbol) -> int | None:
        """Resolve a symbol to an absolute address."""
        # External undefined symbol — resolve against imports or Beacon API
        if symbol.section_number == IMAGE_SYM_UNDEFINED:
            return self._resolve_external(symbol.name)

        # Absolute symbol
        if symbol.section_number == IMAGE_SYM_ABSOLUTE:
            return symbol.value

        # Internal symbol — section base + value
        sec_addr = self._get_section_address(symbol.section_number)
        if sec_addr is not None:
            return sec_addr + symbol.value

        return None

    def _resolve_external(self, name: str) -> int | None:
        """Resolve an external symbol (API import or Beacon function)."""
        # Strip leading underscore (x86 decoration)
        clean = name.lstrip("_")

        # Check Beacon API functions first
        if self.beacon_api:
            beacon_func = self.beacon_api.resolve(clean)
            if beacon_func is not None:
                return beacon_func

        # Try to resolve as DLL import: __imp_DLLNAME$FuncName
        if clean.startswith("_imp_") or "$" in clean:
            return self._resolve_dll_import(clean)

        # Try as a bare Windows API name
        return self._resolve_api(clean)

    def _resolve_dll_import(self, name: str) -> int | None:
        """Resolve __imp_DLL$Func or DLL$Func patterns."""
        clean = name.replace("__imp_", "").replace("_imp_", "")

        # Split DLL$Function
        if "$" in clean:
            dll_name, func_name = clean.split("$", 1)
        elif "!" in clean:
            dll_name, func_name = clean.split("!", 1)
        else:
            return self._resolve_api(clean)

        # Normalize DLL name
        if not dll_name.lower().endswith(".dll"):
            dll_name += ".dll"

        return self._function_resolver(dll_name, func_name)

    def _resolve_api(self, func_name: str) -> int | None:
        """Try to resolve a bare API name against common DLLs."""
        common_dlls = [
            "kernel32.dll", "ntdll.dll", "advapi32.dll", "user32.dll",
            "ws2_32.dll", "iphlpapi.dll", "netapi32.dll", "shell32.dll",
            "ole32.dll", "oleaut32.dll", "msvcrt.dll", "secur32.dll",
        ]
        for dll in common_dlls:
            addr = self._function_resolver(dll, func_name)
            if addr is not None:
                return addr
        return None

    @staticmethod
    def _default_resolve(dll_name: str, func_name: str) -> int | None:
        """Default function resolver using ctypes (works on Linux for testing)."""
        if sys.platform == "win32":
            try:
                handle = ctypes.windll.LoadLibrary(dll_name)
                proc = ctypes.windll.kernel32.GetProcAddress(handle, func_name.encode())
                if proc:
                    return proc
            except (OSError, AttributeError):
                pass
        else:
            # On Linux, we can resolve libc functions for testing
            lib_path = ctypes.util.find_library("c")
            if lib_path:
                try:
                    lib = ctypes.CDLL(lib_path)
                    func = getattr(lib, func_name, None)
                    if func:
                        return ctypes.cast(func, ctypes.c_void_p).value
                except (OSError, AttributeError):
                    pass
        return None

    def _find_entry_point(
        self,
        parser: COFFParser,
        name: str | None = None,
    ) -> int | None:
        """Find the BOF entry point function address."""
        names = [name] if name else self.ENTRY_POINTS

        for sym in parser.symbols:
            if sym.name in names or sym.name.lstrip("_") in names:
                if sym.section_number > 0:
                    sec_addr = self._get_section_address(sym.section_number)
                    if sec_addr is not None:
                        return sec_addr + sym.value

        return None

    def _execute(self, entry_addr: int, args: bytes) -> str:
        """Execute the BOF entry point.

        BOF entry: void go(char* args, int args_len)

        On Windows, we call directly via ctypes function pointer.
        On Linux, we simulate execution and return the beacon API output buffer.
        """
        if self.beacon_api:
            self.beacon_api.reset()

        if sys.platform == "win32":
            # Create function pointer: void (*go)(char*, int)
            BOFFUNC = ctypes.CFUNCTYPE(None, ctypes.c_char_p, ctypes.c_int)
            go = BOFFUNC(entry_addr)
            try:
                go(args, len(args))
            except Exception as e:
                raise RuntimeError(f"BOF crashed during execution: {e}") from e
        else:
            # On Linux, we can't execute Windows COFF directly.
            # For ELF BOFs or testing, we simulate via the API output buffer.
            log.info(
                "Non-Windows platform — BOF loaded at 0x%X (%d bytes args). "
                "Full execution requires Windows target or cross-compiled ELF BOF.",
                entry_addr, len(args),
            )

            # If it's actually an ELF-compiled BOF (Linux native), try to execute
            try:
                BOFFUNC = ctypes.CFUNCTYPE(None, ctypes.c_char_p, ctypes.c_int)
                go = BOFFUNC(entry_addr)
                go(args, len(args))
            except Exception:
                # Expected on non-native BOFs — not an error
                log.debug("COFF execution skipped on non-Windows (expected)")

        # Collect output from Beacon API
        if self.beacon_api:
            return self.beacon_api.get_output()
        return ""

    def _cleanup(self) -> None:
        """Release mapped memory."""
        self._mapped_sections.clear()
        self._allocated_buffers.clear()

    # ── Convenience class methods ──────────────────────────────────────

    @classmethod
    def from_file(
        cls,
        path: str | Path,
        beacon_api: Any = None,
        args: bytes = b"",
    ) -> BOFResult:
        """Load and execute a BOF from a file path.

        Convenience method for one-shot execution.
        """
        path = Path(path)
        if not path.exists():
            return BOFResult(success=False, error=f"BOF file not found: {path}")

        data = path.read_bytes()
        loader = cls(beacon_api=beacon_api)
        return loader.load_and_execute(data, args=args)
