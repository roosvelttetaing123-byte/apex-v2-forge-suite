"""Windows Exchange Server Audit — credentialed WinRM check.

Detects Exchange Server version vulnerabilities (ProxyLogon, ProxyShell, ProxyNotShell,
CVE-2023-21529), OWA/ECP misconfigurations, open relay, webshells, and Autodiscover issues.
"""
from __future__ import annotations

import re
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity

CVSS_CRIT = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
CVSS_HIGH = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N"
CVSS_MED  = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N"

# Versions below which Exchange is vulnerable (build numbers)
# ProxyLogon: CVE-2021-26855 — Exchange 2013 CU23 March 2021 SU / 2016 CU18 SU / 2019 CU7 SU
# ProxyShell:  CVE-2021-34473/34523/31196 — 2016 CU21 / 2019 CU10
# ProxyNotShell: CVE-2022-41040/41082 — 2013-2019 (URL rewrite mitigation required)
# CVE-2023-21529: Exchange 2016 < CU23 SU4 / Exchange 2019 < CU12 SU4

PROXYLOGON_VULN = {
    # major version -> max safe build (exclusive)
    15: 1206,   # Exchange 2016 CU19 build 15.1.2176 minimum; 2016 < CU19 = vuln
    # Exchange 2019 CU8 = 15.2.792; 2019 < CU8 = vuln
}

# Simplified version fingerprint: AdminDisplayVersion contains "Version 15.X (Build YYYYY)"
_PS_CHECK_EXCHANGE = (
    "try { "
    "if (Get-Command Get-ExchangeServer -ErrorAction SilentlyContinue) { 'FOUND' } "
    "else { 'NOT_FOUND' } "
    "} catch { 'NOT_FOUND' }"
)

_PS_EXCHANGE_VERSION = (
    "try { "
    "Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn -ErrorAction SilentlyContinue; "
    "Get-ExchangeServer | Select-Object Name,Edition,AdminDisplayVersion | "
    "ConvertTo-Json -Depth 2 "
    "} catch { '{}' }"
)

_PS_OWA_VDIR = (
    "try { "
    "Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn -ErrorAction SilentlyContinue; "
    "Get-OwaVirtualDirectory | "
    "Select-Object Identity,InternalUrl,ExternalUrl,BasicAuthentication,WindowsAuthentication | "
    "ConvertTo-Json -Depth 2 "
    "} catch { '{}' }"
)

_PS_ECP_VDIR = (
    "try { "
    "Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn -ErrorAction SilentlyContinue; "
    "Get-EcpVirtualDirectory | "
    "Select-Object Identity,InternalUrl,ExternalUrl,BasicAuthentication | "
    "ConvertTo-Json -Depth 2 "
    "} catch { '{}' }"
)

_PS_RECEIVE_CONNECTORS = (
    "try { "
    "Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn -ErrorAction SilentlyContinue; "
    "Get-ReceiveConnector | "
    "Select-Object Name,Bindings,PermissionGroups,RemoteIPRanges,TransportRole | "
    "ConvertTo-Json -Depth 3 "
    "} catch { '{}' }"
)

_PS_PROXYNOTSHELL_MITIG = (
    "try { "
    "Import-Module WebAdministration -ErrorAction Stop; "
    "$rules = Get-WebConfiguration -Filter 'system.webServer/rewrite/rules/rule' "
    "-PSPath 'IIS:\\sites\\Exchange Back End' -ErrorAction SilentlyContinue; "
    "if ($rules) { "
    "($rules | Where-Object { $_.name -match 'MSEX' -or $_.name -match 'Proxy' -or "
    "$_.name -match 'Block' }) | Select-Object name | ConvertTo-Json "
    "} else { '[]' } "
    "} catch { '[]' }"
)

_PS_WEBSHELL_SCAN = (
    "$paths = @("
    "'C:\\inetpub\\wwwroot\\aspnet_client',"
    "'C:\\Program Files\\Microsoft\\Exchange Server\\V15\\ClientAccess\\OWA\\auth'"
    "); "
    "foreach ($p in $paths) { "
    "if (Test-Path $p) { "
    "Get-ChildItem -Path $p -Filter '*.aspx' -Recurse -ErrorAction SilentlyContinue | "
    "Select-Object FullName,LastWriteTime,Length "
    "} "
    "} | ConvertTo-Json -Depth 2"
)

_PS_AUTODISCOVER = (
    "try { "
    "Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn -ErrorAction SilentlyContinue; "
    "Get-AutodiscoverVirtualDirectory | "
    "Select-Object Identity,InternalUrl,ExternalUrl,BasicAuthentication,WindowsAuthentication | "
    "ConvertTo-Json -Depth 2 "
    "} catch { '{}' }"
)


def _parse_json_safe(raw: str):
    """Parse JSON output safely, return None on failure."""
    try:
        import json
        raw = raw.strip()
        if not raw or raw in ("{}", "[]", "NOT_FOUND", "UNAVAILABLE"):
            return None
        return json.loads(raw)
    except (ValueError, TypeError):
        return None


def _ensure_list(data) -> list:
    """Ensure data is a list."""
    if data is None:
        return []
    if isinstance(data, dict):
        return [data]
    if isinstance(data, list):
        return data
    return []


def _parse_exchange_build(version_str: str) -> tuple[int, int, int]:
    """Parse 'Version 15.1 (Build 2375.7)' -> (15, 1, 2375).
    Returns (0, 0, 0) on failure."""
    m = re.search(r'Version\s+(\d+)\.(\d+)\s+\(Build\s+(\d+)', version_str)
    if m:
        return (int(m.group(1)), int(m.group(2)), int(m.group(3)))
    return (0, 0, 0)


class WinExchangeAudit(BaseModule):
    NAME        = "win_exchange_audit"
    DESCRIPTION = "WinRM credentialed: Exchange Server vulnerability and misconfiguration audit"
    PHASE       = 5
    TAGS        = ["credentialed", "windows", "exchange", "email", "owa"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        transport_mgr = self.config.extra.get("transport_manager")
        if not transport_mgr or not transport_mgr.has_creds("winrm"):
            return self._make_result(start, skipped=True, skip_reason="no WinRM credentials")

        hosts = self.config.extra.get("live_hosts", [self.config.target])
        for host in hosts[:20]:
            if not self.check_scope(host):
                continue
            await self.rate_limit()
            session = await transport_mgr.get_winrm_session(host)
            if not session:
                continue
            await self._audit_host(host, transport_mgr.winrm, session)

        return self._make_result(start)

    async def _audit_host(self, host: str, winrm, session) -> None:
        # Check if Exchange is installed on this host
        check = await winrm.execute(session, _PS_CHECK_EXCHANGE)
        if not check.success or "FOUND" not in (check.stdout or ""):
            return

        # Get Exchange version first — used for CVE checks
        ver_result = await winrm.execute(session, _PS_EXCHANGE_VERSION)
        ver_raw = ver_result.stdout or ""
        exchange_servers = _ensure_list(_parse_json_safe(ver_raw))

        await self._check_version_cves(host, exchange_servers)
        await self._check_proxynotshell_mitigation(host, winrm, session, exchange_servers)
        await self._check_owa(host, winrm, session)
        await self._check_ecp(host, winrm, session)
        await self._check_relay(host, winrm, session)
        await self._check_webshells(host, winrm, session)
        await self._check_autodiscover(host, winrm, session)

    # ── Version CVE mapping ──────────────────────────────────────────────────

    async def _check_version_cves(self, host: str, exchange_servers: list) -> None:
        """Check Exchange version against known CVE-vulnerable build thresholds."""
        for srv in exchange_servers:
            name = srv.get("Name", host)
            version_str = srv.get("AdminDisplayVersion", "")
            if not version_str:
                continue

            major, minor, build = _parse_exchange_build(version_str)

            self.new_finding(
                title=f"Exchange Server Version Identified — {name} ({host})",
                severity=Severity.INFO,
                description=(
                    f"Exchange Server '{name}' on {host} is running version: {version_str}. "
                    f"Parsed build: {major}.{minor} Build {build}. "
                    f"This version information is used to determine CVE exposure below."
                ),
                reproduction_steps=[
                    "Get-ExchangeServer | Select-Object Name,Edition,AdminDisplayVersion",
                ],
                remediation="Ensure Exchange is patched to the latest CU and Security Update.",
                references=[
                    "https://docs.microsoft.com/en-us/exchange/new-features/build-numbers-and-release-dates",
                ],
                evidence=Evidence(extra={
                    "host": host,
                    "server_name": name,
                    "version": version_str,
                    "build": build,
                }),
                cvss_v31_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
                mitre_attack=["TA0043/T1592.002"],
                target=host, service="winrm", confidence="HIGH",
            )

            # ProxyLogon: CVE-2021-26855
            # Exchange 2016 < 15.1.2106 or Exchange 2019 < 15.2.858 or Exchange 2013 < 15.0.1497
            proxylogon_vuln = False
            if major == 15 and minor == 1 and build < 2106:
                proxylogon_vuln = True  # Exchange 2016 < CU19
            elif major == 15 and minor == 2 and build < 858:
                proxylogon_vuln = True  # Exchange 2019 < CU8
            elif major == 15 and minor == 0 and build < 1497:
                proxylogon_vuln = True  # Exchange 2013 < CU23 SU

            if proxylogon_vuln:
                self.new_finding(
                    title=f"ProxyLogon (CVE-2021-26855) — Exchange Pre-Auth RCE — {host}",
                    severity=Severity.CRITICAL,
                    description=(
                        f"Exchange Server '{name}' on {host} (build {major}.{minor}.{build}) "
                        f"is vulnerable to ProxyLogon (CVE-2021-26855), a pre-authentication "
                        f"SSRF vulnerability in the Exchange Client Access Service that allows "
                        f"attackers to bypass authentication and access mailboxes. Combined with "
                        f"CVE-2021-27065 (post-auth arbitrary file write), this enables "
                        f"unauthenticated remote code execution via webshell upload. "
                        f"This was exploited by HAFNIUM and multiple ransomware groups in 2021."
                    ),
                    reproduction_steps=[
                        "# PoC tooling:",
                        f"python proxylogon.py --host {host} --email admin@domain.com",
                        "# Metasploit:",
                        "use exploit/windows/http/exchange_proxylogon_rce",
                        f"set RHOSTS {host}",
                        "run",
                    ],
                    remediation=(
                        "Apply security updates IMMEDIATELY. Minimum safe versions: "
                        "Exchange 2016: CU19 + March 2021 SU (15.1.2176.2+); "
                        "Exchange 2019: CU8 + March 2021 SU (15.2.858.5+); "
                        "Exchange 2013: CU23 + March 2021 SU (15.0.1497.12+). "
                        "Check for existing webshells in OWA and aspnet_client directories. "
                        "Run Microsoft's Safety Scanner (MSERT) immediately."
                    ),
                    references=[
                        "CVE-2021-26855",
                        "CVE-2021-27065",
                        "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-26855",
                        "https://www.microsoft.com/security/blog/2021/03/02/hafnium-targeting-exchange-servers/",
                    ],
                    evidence=Evidence(extra={
                        "host": host,
                        "server": name,
                        "version": version_str,
                        "build": f"{major}.{minor}.{build}",
                        "cve": "CVE-2021-26855",
                    }),
                    cvss_v31_vector=CVSS_CRIT,
                    mitre_attack=["TA0001/T1190", "TA0003/T1505.003"],
                    target=host, service="winrm", confidence="HIGH",
                )

            # ProxyShell: CVE-2021-34473/34523/31196
            # Exchange 2016 < 15.1.2375 (CU21) or Exchange 2019 < 15.2.986 (CU10)
            proxyshell_vuln = False
            if major == 15 and minor == 1 and build < 2375:
                proxyshell_vuln = True  # Exchange 2016 < CU21
            elif major == 15 and minor == 2 and build < 986:
                proxyshell_vuln = True  # Exchange 2019 < CU10
            elif major == 15 and minor == 0 and build < 1497:
                proxyshell_vuln = True  # Exchange 2013

            if proxyshell_vuln and not proxylogon_vuln:
                self.new_finding(
                    title=f"ProxyShell (CVE-2021-34473/34523/31196) — Exchange RCE — {host}",
                    severity=Severity.CRITICAL,
                    description=(
                        f"Exchange Server '{name}' on {host} (build {major}.{minor}.{build}) "
                        f"is vulnerable to ProxyShell — a chain of three vulnerabilities: "
                        f"CVE-2021-34473 (pre-auth path confusion), CVE-2021-34523 (privilege "
                        f"elevation via Exchange PowerShell backend), and CVE-2021-31196 (post-auth "
                        f"arbitrary file write). Together they allow unauthenticated RCE. "
                        f"Exploited by LockFile, Conti, and multiple APT groups through 2022."
                    ),
                    reproduction_steps=[
                        f"# Using proxyshell PoC:",
                        f"python proxyshell.py --url https://{host}/autodiscover/autodiscover.json",
                        f"# Tooling: https://github.com/dmaasland/proxyshell-poc",
                    ],
                    remediation=(
                        "Apply security updates: "
                        "Exchange 2016: CU21 July 2021 SU or later (15.1.2375.7+); "
                        "Exchange 2019: CU10 July 2021 SU or later (15.2.986.5+). "
                        "Minimum: install July 2021 Security Update on top of supported CU."
                    ),
                    references=[
                        "CVE-2021-34473",
                        "CVE-2021-34523",
                        "CVE-2021-31196",
                        "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34473",
                        "https://github.com/dmaasland/proxyshell-poc",
                    ],
                    evidence=Evidence(extra={
                        "host": host,
                        "server": name,
                        "version": version_str,
                        "build": f"{major}.{minor}.{build}",
                        "cve": "CVE-2021-34473/34523/31196",
                    }),
                    cvss_v31_vector=CVSS_CRIT,
                    mitre_attack=["TA0001/T1190", "TA0003/T1505.003"],
                    target=host, service="winrm", confidence="HIGH",
                )

            # CVE-2023-21529: Exchange 2016 < CU23 SU4 (15.1.2507.17) / Exchange 2019 < CU12 SU4 (15.2.1118.20)
            cve_2023_vuln = False
            if major == 15 and minor == 1 and build < 2507:
                cve_2023_vuln = True  # Exchange 2016 < CU23
            elif major == 15 and minor == 2 and build < 1118:
                cve_2023_vuln = True  # Exchange 2019 < CU12

            if cve_2023_vuln:
                self.new_finding(
                    title=f"CVE-2023-21529 — Exchange RCE via PowerShell Remoting — {host}",
                    severity=Severity.CRITICAL,
                    description=(
                        f"Exchange Server '{name}' on {host} (build {major}.{minor}.{build}) "
                        f"is vulnerable to CVE-2023-21529, a remote code execution vulnerability "
                        f"in Microsoft Exchange Server affecting Exchange 2016 and 2019. "
                        f"An attacker with valid Exchange credentials can achieve RCE via "
                        f"Exchange PowerShell remoting. CVSS 8.8 (High). Patched January 2023."
                    ),
                    reproduction_steps=[
                        "# Requires valid Exchange/domain credentials",
                        f"# Target: https://{host}/PowerShell/",
                        "# See Microsoft MSRC advisory for PoC details (not publicly released)",
                    ],
                    remediation=(
                        "Install January 2023 Security Update: "
                        "Exchange 2016 CU23 SU4 (15.1.2507.17+); "
                        "Exchange 2019 CU12 SU4 (15.2.1118.20+). "
                        "As interim mitigation, restrict PowerShell remoting access."
                    ),
                    references=[
                        "CVE-2023-21529",
                        "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-21529",
                    ],
                    evidence=Evidence(extra={
                        "host": host,
                        "server": name,
                        "version": version_str,
                        "cve": "CVE-2023-21529",
                    }),
                    cvss_v31_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
                    mitre_attack=["TA0001/T1190", "TA0002/T1059.001"],
                    target=host, service="winrm", confidence="HIGH",
                )

    # ── ProxyNotShell URL rewrite mitigation check ───────────────────────────

    async def _check_proxynotshell_mitigation(
        self, host: str, winrm, session, exchange_servers: list
    ) -> None:
        """Check if ProxyNotShell URL rewrite mitigations are applied."""
        if not exchange_servers:
            return

        result = await winrm.execute(session, _PS_PROXYNOTSHELL_MITIG)
        raw = (result.stdout or "").strip()

        mitigation_present = False
        if raw and raw not in ("[]", "{}", "UNAVAILABLE"):
            data = _parse_json_safe(raw)
            if data:
                mitigation_present = True

        if not mitigation_present:
            self.new_finding(
                title=f"ProxyNotShell (CVE-2022-41040/41082) — URL Rewrite Mitigation Missing — {host}",
                severity=Severity.CRITICAL,
                description=(
                    f"Exchange Server on {host} does not appear to have the ProxyNotShell "
                    f"URL rewrite mitigation rules applied to the 'Exchange Back End' IIS site. "
                    f"CVE-2022-41040 is an SSRF vulnerability and CVE-2022-41082 is an "
                    f"authenticated RCE via PowerShell. Chained together, an authenticated attacker "
                    f"(any valid Exchange mailbox user) can achieve remote code execution. "
                    f"Exploited in the wild before patches were available (October 2022). "
                    f"Patches were released in November 2022 Patch Tuesday."
                ),
                reproduction_steps=[
                    "# Verify mitigation status:",
                    "Get-WebConfiguration -Filter 'system.webServer/rewrite/rules/rule' "
                    "-PSPath 'IIS:\\sites\\Exchange Back End'",
                    "# Should contain rules blocking autodiscover.json?Powershell=",
                    "# Exploitation requires valid mailbox credentials:",
                    f"# POST https://{host}/autodiscover/autodiscover.json?@evil.com/mapi/nspi/?",
                ],
                remediation=(
                    "1. PREFERRED: Apply November 2022 Security Update — patches both CVEs. "
                    "2. INTERIM: Apply URL Rewrite mitigation per Microsoft guidance: "
                    "Add IIS URL Rewrite rule to block requests matching "
                    "'.*autodiscover\\.json.*\\@.*Powershell.*' on Exchange Back End site. "
                    "Script: https://aka.ms/EOMitigation — run as admin on Exchange server. "
                    "3. Restrict PowerShell remoting to specific admin IPs."
                ),
                references=[
                    "CVE-2022-41040",
                    "CVE-2022-41082",
                    "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-41040",
                    "https://aka.ms/EOMitigation",
                    "https://msrc-blog.microsoft.com/2022/09/29/customer-guidance-for-reported-zero-day-vulnerabilities-in-microsoft-exchange-server/",
                ],
                evidence=Evidence(extra={
                    "host": host,
                    "mitigation_present": mitigation_present,
                    "cve": "CVE-2022-41040/CVE-2022-41082",
                }),
                cvss_v31_vector=CVSS_CRIT,
                mitre_attack=["TA0001/T1190", "TA0002/T1059.001"],
                target=host, service="winrm", confidence="MEDIUM",
            )

    # ── OWA auth check ───────────────────────────────────────────────────────

    async def _check_owa(self, host: str, winrm, session) -> None:
        """Check OWA for Basic Authentication enabled without MFA indication."""
        result = await winrm.execute(session, _PS_OWA_VDIR)
        raw = (result.stdout or "").strip()
        if not result.success or not raw or raw in ("{}", "[]"):
            return

        data = _parse_json_safe(raw)
        vdirs = _ensure_list(data)

        for vdir in vdirs:
            identity = vdir.get("Identity", "unknown")
            basic_auth = str(vdir.get("BasicAuthentication", "False")).lower()
            external_url = vdir.get("ExternalUrl", "")

            if basic_auth == "true" and external_url:
                self.new_finding(
                    title=f"OWA BasicAuthentication Enabled — No MFA Evidence — {host}",
                    severity=Severity.HIGH,
                    description=(
                        f"Outlook Web App (OWA) virtual directory '{identity}' on {host} has "
                        f"BasicAuthentication=True and an external URL configured: {external_url}. "
                        f"Basic authentication sends credentials in base64 (cleartext over HTTP, "
                        f"or interceptable over HTTPS before TLS termination). Without MFA, "
                        f"OWA is a direct credential brute-force and password-spray target "
                        f"reachable from the internet. This is a primary initial access vector "
                        f"for BEC (business email compromise) and ransomware operators."
                    ),
                    reproduction_steps=[
                        f"# Password spray against OWA:",
                        f"Ruler --domain domain.com --users users.txt --password Winter2024! brute --delay 0 --stop-on-success",
                        f"# Or using o365spray (if Exchange Online hybrid):",
                        f"python o365spray.py --spray --userfile users.txt --password Password1 --domain domain.com",
                    ],
                    remediation=(
                        "1. Disable BasicAuthentication on OWA virtual directories: "
                        "Set-OwaVirtualDirectory -Identity '<identity>' -BasicAuthentication $False. "
                        "2. Enable WindowsAuthentication or FBA (forms-based). "
                        "3. Implement MFA via ADFS or Azure AD Conditional Access. "
                        "4. Rate-limit authentication attempts at the WAF/load balancer level."
                    ),
                    references=[
                        "CWE-308",
                        "https://attack.mitre.org/techniques/T1078/",
                        "https://learn.microsoft.com/en-us/exchange/clients/outlook-on-the-web/virtual-directories",
                    ],
                    evidence=Evidence(extra={
                        "host": host,
                        "identity": identity,
                        "basic_auth": True,
                        "external_url": external_url,
                    }),
                    cvss_v31_vector=CVSS_HIGH,
                    mitre_attack=["TA0001/T1078", "TA0006/T1110.003"],
                    target=host, service="winrm", confidence="HIGH",
                )

    # ── ECP exposure check ───────────────────────────────────────────────────

    async def _check_ecp(self, host: str, winrm, session) -> None:
        """Check Exchange Control Panel (ECP) external exposure."""
        result = await winrm.execute(session, _PS_ECP_VDIR)
        raw = (result.stdout or "").strip()
        if not result.success or not raw or raw in ("{}", "[]"):
            return

        data = _parse_json_safe(raw)
        vdirs = _ensure_list(data)

        for vdir in vdirs:
            identity = vdir.get("Identity", "unknown")
            external_url = vdir.get("ExternalUrl", "")

            if external_url and external_url.strip() not in ("", "null"):
                self.new_finding(
                    title=f"Exchange Control Panel (ECP) Externally Accessible — {host}",
                    severity=Severity.HIGH,
                    description=(
                        f"The Exchange Control Panel (ECP) at '{identity}' is configured with "
                        f"an external URL: {external_url}. ECP is the Exchange admin interface and "
                        f"should not be exposed to external networks. ECP was directly exploited "
                        f"in ProxyLogon (CVE-2021-26855/27065) chains to write webshells. "
                        f"Limiting ECP access to internal management networks significantly reduces "
                        f"the attack surface for Exchange-targeting threats."
                    ),
                    reproduction_steps=[
                        f"curl -s -I {external_url}",
                        f"# Verify ECP is reachable externally",
                        f"nmap -p 443 --script http-auth-finder {host}",
                    ],
                    remediation=(
                        "1. Remove the ExternalUrl from ECP: "
                        "Set-EcpVirtualDirectory -Identity '<identity>' -ExternalUrl $null. "
                        "2. Restrict ECP access to internal management IP ranges via IIS IP restrictions "
                        "or network-layer firewall rules. "
                        "3. Consider requiring VPN or jump host access for ECP."
                    ),
                    references=[
                        "CVE-2021-26855",
                        "CVE-2021-27065",
                        "https://learn.microsoft.com/en-us/exchange/clients/exchange-admin-center",
                    ],
                    evidence=Evidence(extra={
                        "host": host,
                        "identity": identity,
                        "external_url": external_url,
                    }),
                    cvss_v31_vector=CVSS_HIGH,
                    mitre_attack=["TA0001/T1190", "TA0043/T1592"],
                    target=host, service="winrm", confidence="HIGH",
                )

    # ── Open relay check ─────────────────────────────────────────────────────

    async def _check_relay(self, host: str, winrm, session) -> None:
        """Check for Exchange receive connectors allowing anonymous relay."""
        result = await winrm.execute(session, _PS_RECEIVE_CONNECTORS)
        raw = (result.stdout or "").strip()
        if not result.success or not raw or raw in ("{}", "[]"):
            return

        data = _parse_json_safe(raw)
        connectors = _ensure_list(data)

        # Standard Exchange connectors that legitimately accept anonymous connections
        # for inbound internet mail — flagging these would be a false positive.
        # "Default Frontend <ServerName>" accepts anonymous SMTP from the internet but
        # Exchange's recipient validation prevents relay to external addresses.
        # "Client Frontend" uses authenticated submission; it should NOT have AnonymousUsers.
        _DEFAULT_FRONTEND_PREFIXES = (
            "default frontend",
            "client frontend",
            "outbound proxy frontend",
        )

        open_relays = []
        for conn in connectors:
            name = conn.get("Name", "unknown")
            perms = str(conn.get("PermissionGroups", ""))
            remote_ips = conn.get("RemoteIPRanges", [])
            transport_role = str(conn.get("TransportRole", "")).lower()

            # Skip standard frontend transport connectors — they accept anonymous
            # connections for inbound internet mail by design (not an open relay).
            name_lower = name.lower()
            if any(name_lower.startswith(pfx) for pfx in _DEFAULT_FRONTEND_PREFIXES):
                continue

            # Also skip any FrontendTransport role connector named like a default
            # to catch locale-renamed defaults (e.g. French/German Exchange installs).
            if transport_role == "frontendtransport" and (
                "anonymous" not in perms.lower() or
                not any("0.0.0.0" in str(r) or "255.255.255.255" in str(r)
                        for r in (remote_ips if isinstance(remote_ips, list) else [str(remote_ips)]))
            ):
                continue

            if "AnonymousUsers" in perms or "Anonymous" in perms:
                ip_ranges = remote_ips if isinstance(remote_ips, list) else [str(remote_ips)]
                is_wide_open = any("0.0.0.0" in str(r) or "255.255.255.255" in str(r)
                                   for r in ip_ranges)
                open_relays.append({
                    "name": name,
                    "permission_groups": perms,
                    "remote_ip_ranges": ip_ranges[:5],
                    "transport_role": transport_role,
                    "wide_open": is_wide_open,
                })

        if open_relays:
            severity = Severity.CRITICAL if any(r["wide_open"] for r in open_relays) else Severity.HIGH
            self.new_finding(
                title=f"Exchange Open Relay — Anonymous SMTP Relay Enabled — {host}",
                severity=severity,
                description=(
                    f"{len(open_relays)} Exchange receive connector(s) on {host} permit anonymous "
                    f"SMTP relay: {', '.join(r['name'] for r in open_relays[:5])}. "
                    f"An open relay allows any unauthenticated party to send email through this "
                    f"Exchange server to any recipient. This enables phishing campaigns using your "
                    f"domain's trusted reputation, spam delivery, and can cause the server's IP "
                    f"to be blacklisted. Open relays are commonly abused by ransomware operators "
                    f"for BEC and phishing (T1566)."
                ),
                reproduction_steps=[
                    f"# Test open relay from external host:",
                    f"telnet {host} 25",
                    "EHLO test.com",
                    "MAIL FROM: <external@attacker.com>",
                    "RCPT TO: <victim@anydomain.com>",
                    "DATA",
                    "Subject: Relay test",
                    ".",
                    "# Or using swaks:",
                    f"swaks --to victim@external.com --from attacker@spoofed.com --server {host}",
                ],
                remediation=(
                    "1. Remove AnonymousUsers from PermissionGroups on all receive connectors "
                    "unless specifically required for unauthenticated sending (e.g., internal "
                    "devices that cannot authenticate). "
                    "2. If unauthenticated relay is required for specific devices, restrict "
                    "RemoteIPRanges to only those device IPs. "
                    "3. Require SMTP authentication for all external relay: "
                    "Set-ReceiveConnector -Identity '<name>' -PermissionGroups '' "
                    "-AuthMechanism TLS,Integrated,BasicAuth."
                ),
                references=[
                    "CWE-183",
                    "https://attack.mitre.org/techniques/T1566/",
                    "https://learn.microsoft.com/en-us/exchange/mail-flow/connectors/receive-connectors",
                ],
                evidence=Evidence(extra={"host": host, "open_relays": open_relays[:10]}),
                cvss_v31_vector=CVSS_CRIT if any(r["wide_open"] for r in open_relays) else CVSS_HIGH,
                mitre_attack=["TA0001/T1566", "TA0010/T1048"],
                target=host, service="winrm", confidence="HIGH",
            )

    # ── Webshell scan ────────────────────────────────────────────────────────

    async def _check_webshells(self, host: str, winrm, session) -> None:
        """Scan known Exchange webshell drop locations for .aspx files."""
        result = await winrm.execute(session, _PS_WEBSHELL_SCAN)
        raw = (result.stdout or "").strip()
        if not result.success or not raw or raw in ("{}", "[]"):
            return

        data = _parse_json_safe(raw)
        files = _ensure_list(data)

        if not files:
            return

        # Any .aspx in aspnet_client or Exchange OWA auth directory is suspicious
        suspicious = []
        for f in files:
            full_name = f.get("FullName", "")
            last_write = f.get("LastWriteTime", "")
            size = f.get("Length", 0)
            suspicious.append({
                "path": full_name,
                "last_modified": last_write,
                "size_bytes": size,
            })

        self.new_finding(
            title=f"Potential Exchange Webshells Detected — {host}",
            severity=Severity.CRITICAL,
            description=(
                f"Found {len(suspicious)} .aspx file(s) in Exchange webshell drop directories "
                f"on {host}. These directories (aspnet_client, OWA auth) should contain only "
                f"Microsoft-signed files. .aspx files here are a strong indicator of compromise — "
                f"this is where ProxyLogon/ProxyShell exploits drop webshells for persistent access. "
                f"Files found: "
                + "\n".join(f"  {s['path']} (modified: {s['last_modified']}, {s['size_bytes']} bytes)"
                             for s in suspicious[:10])
            ),
            reproduction_steps=[
                "# Verify files are not legitimate Microsoft files:",
                "Get-FileHash -Algorithm SHA256 -Path '<path>'",
                "# Compare hash against Microsoft's known good file list",
                "# Check file content for webshell indicators:",
                "Select-String -Path '<path>' -Pattern 'cmd|exec|Process|shell|eval' -CaseSensitive",
            ],
            remediation=(
                "1. TREAT AS ACTIVE COMPROMISE — initiate IR procedures. "
                "2. Isolate the Exchange server from the network. "
                "3. Run Microsoft Safety Scanner (MSERT): "
                "https://learn.microsoft.com/en-us/microsoft-365/security/intelligence/safety-scanner-download. "
                "4. Verify file hashes against known-good Exchange files. "
                "5. Review IIS access logs for web requests to the identified paths. "
                "6. After cleaning, patch Exchange to latest CU+SU to prevent reinfection."
            ),
            references=[
                "CVE-2021-26855",
                "CVE-2021-27065",
                "https://www.microsoft.com/security/blog/2021/03/02/hafnium-targeting-exchange-servers/",
                "https://attack.mitre.org/techniques/T1505/003/",
            ],
            evidence=Evidence(extra={
                "host": host,
                "suspicious_files": suspicious[:20],
            }),
            cvss_v31_vector=CVSS_CRIT,
            mitre_attack=["TA0003/T1505.003", "TA0008/T1021.001"],
            target=host, service="winrm", confidence="HIGH",
        )

    # ── Autodiscover check ───────────────────────────────────────────────────

    async def _check_autodiscover(self, host: str, winrm, session) -> None:
        """Check Autodiscover virtual directory for Basic Authentication and external exposure."""
        result = await winrm.execute(session, _PS_AUTODISCOVER)
        raw = (result.stdout or "").strip()
        if not result.success or not raw or raw in ("{}", "[]"):
            return

        data = _parse_json_safe(raw)
        vdirs = _ensure_list(data)

        for vdir in vdirs:
            identity = vdir.get("Identity", "unknown")
            external_url = vdir.get("ExternalUrl", "")
            basic_auth = str(vdir.get("BasicAuthentication", "False")).lower()

            if basic_auth == "true":
                self.new_finding(
                    title=f"Autodiscover BasicAuthentication Enabled — {host}",
                    severity=Severity.MEDIUM,
                    description=(
                        f"The Autodiscover virtual directory '{identity}' on {host} has "
                        f"BasicAuthentication=True. Autodiscover with Basic Auth over plain HTTP "
                        f"will send credentials in cleartext. This is exploitable via "
                        f"'Autodiscover Hell' — misconfigured TLDs where Autodiscover queries "
                        f"resolve to attacker-controlled servers, resulting in credential "
                        f"harvesting from Outlook clients connecting to domain.com (T1557). "
                        f"External URL: {external_url or 'not configured'}"
                    ),
                    reproduction_steps=[
                        "# Autodiscover credential harvesting (research: Shlomo Abusis 2021):",
                        "# Set up rogue autodiscover.<tld> for owned TLDs",
                        "# Host Basic Auth Autodiscover endpoint to capture credentials",
                        f"# Check: curl -v http://{host}/autodiscover/autodiscover.xml",
                    ],
                    remediation=(
                        "1. Disable Basic Authentication on Autodiscover: "
                        "Set-AutodiscoverVirtualDirectory -Identity '<identity>' "
                        "-BasicAuthentication $False. "
                        "2. Require HTTPS for all Autodiscover endpoints. "
                        "3. Configure ExcludeHttpsRootDomain and ExcludeHttpsAutodiscoverDomain "
                        "registry keys to prevent plaintext Autodiscover fallback."
                    ),
                    references=[
                        "CWE-319",
                        "https://autodiscoverblog.com/",
                        "https://attack.mitre.org/techniques/T1557/",
                    ],
                    evidence=Evidence(extra={
                        "host": host,
                        "identity": identity,
                        "basic_auth": True,
                        "external_url": external_url,
                    }),
                    cvss_v31_vector=CVSS_MED,
                    mitre_attack=["TA0006/T1557", "TA0006/T1110"],
                    target=host, service="winrm", confidence="HIGH",
                )
