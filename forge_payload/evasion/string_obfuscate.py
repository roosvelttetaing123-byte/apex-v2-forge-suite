"""String obfuscation for payloads — defeats static string-based AV detection.

Techniques:
    1. PowerShell: concatenation, backtick insertion, -join, char code
    2. C/C++: XOR at compile time, runtime assembly
    3. Python: chr() join, bytes literal
    4. VBScript: Chr() concatenation

FOR AUTHORIZED PENETRATION TESTING AND RED TEAM OPERATIONS ONLY.
"""
from __future__ import annotations

import random
import string


def obfuscate_powershell_string(s: str) -> str:
    """Obfuscate a PowerShell string using multiple techniques.

    Randomly applies: backtick insertion, concatenation, char codes.

    Args:
        s: Plain string to obfuscate.

    Returns:
        Obfuscated PowerShell expression producing the same string.
    """
    technique = random.randint(0, 2)

    if technique == 0:
        # Char code join: [char]72+[char]101...
        codes = "+".join(f"[char]{ord(c)}" for c in s)
        return f"({codes})"

    elif technique == 1:
        # Concatenation split at random points
        parts = _random_split(s)
        return "+".join(f'"{p}"' for p in parts)

    else:
        # Backtick insertion at random positions
        result = list(s)
        pos = sorted(random.sample(range(len(s)), min(3, len(s))), reverse=True)
        safe_chars = set(string.ascii_letters + string.digits)
        for p in pos:
            if s[p] in safe_chars:
                result.insert(p, "`")
        return '"' + "".join(result) + '"'


def obfuscate_strings(script: str, lang: str = "ps1") -> str:
    """Obfuscate string literals in a script.

    Finds quoted string literals and replaces them with obfuscated equivalents.

    Args:
        script: Script text to process.
        lang:   Language: 'ps1', 'python', 'vbs'.

    Returns:
        Script with obfuscated strings.
    """
    if lang == "ps1":
        return _obfuscate_ps1_strings(script)
    elif lang == "python":
        return _obfuscate_python_strings(script)
    elif lang == "vbs":
        return _obfuscate_vbs_strings(script)
    return script


def _obfuscate_ps1_strings(script: str) -> str:
    """Replace PS1 double-quoted string literals with char-code joins.

    Only replaces strings over 6 chars to avoid breaking operators.
    """
    import re
    def replace_match(m: re.Match) -> str:
        content = m.group(1)
        if len(content) < 6 or any(c in content for c in ['$', '`', '\n', '\r']):
            return m.group(0)  # Skip complex strings
        codes = "+".join(f"[char]{ord(c)}" for c in content)
        return f"({codes})"

    return re.sub(r'"([^"$`\r\n]{6,})"', replace_match, script)


def _obfuscate_python_strings(script: str) -> str:
    """Replace Python string literals with chr() joins."""
    import re
    def replace_match(m: re.Match) -> str:
        content = m.group(1)
        if len(content) < 6 or any(c in content for c in ["'", "\\"]):
            return m.group(0)
        codes = "+".join(f"chr({ord(c)})" for c in content)
        return f"({codes})"

    return re.sub(r"'([^'\\]{6,})'", replace_match, script)


def _obfuscate_vbs_strings(script: str) -> str:
    """Replace VBS string literals with Chr() concatenation."""
    import re
    def replace_match(m: re.Match) -> str:
        content = m.group(1)
        if len(content) < 6:
            return m.group(0)
        codes = "&Chr(".join(str(ord(c)) for c in content)
        return f'Chr({codes})'

    return re.sub(r'"([^"]{6,})"', replace_match, script)


def _random_split(s: str, parts: int = 3) -> list[str]:
    """Split string into N random-length parts."""
    if len(s) < parts:
        return [s]
    cuts = sorted(random.sample(range(1, len(s)), min(parts - 1, len(s) - 1)))
    result = []
    prev = 0
    for cut in cuts:
        result.append(s[prev:cut])
        prev = cut
    result.append(s[prev:])
    return [p for p in result if p]


def obfuscate_import_names(script: str, lang: str = "ps1") -> str:
    """Obfuscate API/import names using string concatenation.

    Replaces known suspicious API names with concatenated forms.
    E.g., 'VirtualAlloc' → 'Virt' + 'ualAlloc'

    Args:
        script: Script text.
        lang:   Language hint.

    Returns:
        Script with obfuscated API names.
    """
    _SUSPICIOUS_APIS = [
        "VirtualAlloc",
        "VirtualProtect",
        "CreateThread",
        "WriteProcessMemory",
        "OpenProcess",
        "AmsiScanBuffer",
        "EtwEventWrite",
        "NtAllocateVirtualMemory",
        "NtWriteVirtualMemory",
    ]

    result = script
    for api in _SUSPICIOUS_APIS:
        if api in result:
            # Split at a random midpoint
            mid = random.randint(3, len(api) - 2)
            if lang == "ps1":
                replacement = f'("{api[:mid]}"+"{ api[mid:]}")'
            elif lang == "python":
                replacement = f'("{api[:mid]}"+"{ api[mid:]}")'
            else:
                replacement = f'"{api[:mid]}" & "{api[mid:]}"'
            result = result.replace(f'"{api}"', replacement)

    return result
