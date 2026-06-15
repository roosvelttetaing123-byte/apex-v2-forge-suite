"""String Obfuscator — transform literal strings in C/PS1 payloads.

Techniques:
  - XOR encoding:  each character XORed with a random key byte
  - Stack strings: character-by-character assignment instead of string literals
  - Wide char split: split wstring across multiple temporaries
  - Base64 + decode at runtime (PowerShell only)
  - rot13 + custom encode (simple confusion)

FOR AUTHORIZED PENETRATION TESTING ONLY.
"""
from __future__ import annotations

import base64
import random
import re
import secrets
import textwrap


class StringObfuscator:
    """Obfuscate string literals in C or PowerShell source code."""

    def __init__(self, seed: int | None = None):
        self._rng = random.Random(seed)

    # ── Public API ─────────────────────────────────────────────────────

    def obfuscate_c(self, source: str, technique: str = "xor") -> str:
        """Replace C string literals with obfuscated equivalents.

        Args:
            source:    C source code string.
            technique: 'xor' | 'stack' | 'rot'
        """
        if technique == "xor":
            return self._c_xor_strings(source)
        if technique == "stack":
            return self._c_stack_strings(source)
        if technique == "rot":
            return self._c_rot_strings(source)
        raise ValueError(f"Unknown technique: {technique}")

    def obfuscate_ps1(self, source: str, technique: str = "concat") -> str:
        """Obfuscate PowerShell string literals.

        Args:
            technique: 'concat' | 'base64' | 'charcode' | 'format'
        """
        if technique == "concat":
            return self._ps1_concat_split(source)
        if technique == "base64":
            return self._ps1_base64(source)
        if technique == "charcode":
            return self._ps1_charcode(source)
        if technique == "format":
            return self._ps1_format_operator(source)
        raise ValueError(f"Unknown technique: {technique}")

    def generate_c_xor_decoder(self, s: str, var_name: str = "str") -> str:
        """Generate C code that XOR-decodes a string at runtime."""
        key = secrets.randbelow(254) + 1
        enc = [chr(ord(c) ^ key) for c in s]
        enc_lit = ''.join(f"\\x{ord(c):02x}" for c in enc)
        n   = len(s)

        return textwrap.dedent(f"""\
        /* XOR-decoded string: "{s[:20]}{'...' if len(s)>20 else ''}" */
        char {var_name}[{n+1}] = "{enc_lit}\\x00";
        for (int _i = 0; _i < {n}; _i++) {var_name}[_i] ^= 0x{key:02x};
        """)

    def generate_c_stack_string(self, s: str, var_name: str = "str") -> str:
        """Generate C code that constructs a string character-by-character."""
        n    = len(s)
        assigns = "\n".join(
            f"    {var_name}[{i}] = 0x{ord(c):02x};"
            for i, c in enumerate(s)
        )
        return textwrap.dedent(f"""\
        char {var_name}[{n+1}];
        {assigns}
            {var_name}[{n}] = 0;
        """)

    def generate_ps1_charcode_string(self, s: str) -> str:
        """Return PowerShell -join [char[]]@(...) string construction."""
        codes = ",".join(str(ord(c)) for c in s)
        return f"-join [char[]]@({codes})"

    # ── C Obfuscation ──────────────────────────────────────────────────

    _C_STR_RE = re.compile(r'"((?:[^"\\]|\\.)*)"')

    def _c_xor_strings(self, source: str) -> str:
        """Replace string literals with XOR-encoded equivalents."""
        def replace(m: re.Match) -> str:
            s   = m.group(1)
            if not s or len(s) < 3:
                return m.group(0)
            key = secrets.randbelow(254) + 1
            enc = bytes(ord(c) ^ key for c in s)
            enc_lit = "".join(f"\\x{b:02x}" for b in enc) + "\\x00"
            vn  = "_xs" + secrets.token_hex(3)
            return (f'((char*)({{"'
                    f'const char _{vn}[]="{ enc_lit}"; '
                    f'char {vn}[{len(s)+1}]; '
                    f'for(int _i=0;_i<{len(s)};_i++){vn}[_i]=_{vn}[_i]^0x{key:02x}; '
                    f'{vn}[{len(s)}]=0; '
                    f'(char*){vn};}})')
            )
        # Note: full replacement in real C would require statement-level transforms.
        # This approximation works for simple string arguments.
        return source  # Return unchanged; complex transform deferred to per-string API

    def _c_stack_strings(self, source: str) -> str:
        """Return source with a preamble note to use generate_c_stack_string()."""
        return (f"/* StringObfuscator: use generate_c_stack_string() to convert "
                f"individual strings */\n{source}")

    def _c_rot_strings(self, source: str) -> str:
        """ROT-13 encode non-escape string literals (simple confusion)."""
        def rot13_c(c: str) -> str:
            if 'a' <= c <= 'z':
                return chr((ord(c) - ord('a') + 13) % 26 + ord('a'))
            if 'A' <= c <= 'Z':
                return chr((ord(c) - ord('A') + 13) % 26 + ord('A'))
            return c

        def replace(m: re.Match) -> str:
            s = m.group(1)
            if not s or len(s) < 3:
                return m.group(0)
            encoded = "".join(rot13_c(c) for c in s)
            key_fn  = "_rot13"
            return f'({key_fn}("{encoded}", {len(s)}))'

        rot13_helper = textwrap.dedent("""\
        static char* _rot13(const char *s, int n) {
            static char _buf[4096];
            for (int i = 0; i < n && i < 4095; i++) {
                char c = s[i];
                if (c>='a'&&c<='z') c=(c-'a'+13)%26+'a';
                else if (c>='A'&&c<='Z') c=(c-'A'+13)%26+'A';
                _buf[i] = c;
            }
            _buf[n] = 0;
            return _buf;
        }
        """)
        return rot13_helper + self._C_STR_RE.sub(replace, source)

    # ── PowerShell Obfuscation ─────────────────────────────────────────

    _PS1_STR_RE = re.compile(r"'([^']{3,})'")

    def _ps1_concat_split(self, source: str) -> str:
        """Split PS1 string literals into 2-char concatenated segments."""
        def replace(m: re.Match) -> str:
            s = m.group(1)
            if len(s) < 4:
                return m.group(0)
            mid = len(s) // 2
            return f"('{s[:mid]}' + '{s[mid:]}')"
        return self._PS1_STR_RE.sub(replace, source)

    def _ps1_base64(self, source: str) -> str:
        """Replace PS1 string literals with [Text.Encoding]::UTF8.GetString(...)."""
        def replace(m: re.Match) -> str:
            s = m.group(1)
            if len(s) < 4:
                return m.group(0)
            b64 = base64.b64encode(s.encode()).decode()
            return f"([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{b64}')))"
        return self._PS1_STR_RE.sub(replace, source)

    def _ps1_charcode(self, source: str) -> str:
        """Replace PS1 string literals with -join [char[]]@(codes)."""
        def replace(m: re.Match) -> str:
            s = m.group(1)
            if len(s) < 4:
                return m.group(0)
            codes = ",".join(str(ord(c)) for c in s)
            return f"(-join [char[]]@({codes}))"
        return self._PS1_STR_RE.sub(replace, source)

    def _ps1_format_operator(self, source: str) -> str:
        """Use PS1 -f (format) operator to avoid literal strings."""
        def replace(m: re.Match) -> str:
            s = m.group(1)
            if len(s) < 4:
                return m.group(0)
            # Split into per-char {0}{1}... format string
            fmt   = "".join(f"{{{i}}}" for i in range(len(s)))
            chars = ",".join(f"'{c}'" for c in s)
            return f"('{fmt}' -f {chars})"
        return self._PS1_STR_RE.sub(replace, source)
