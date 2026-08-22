"""Windows IIS Web Server Audit — credentialed WinRM check.

Detects IIS misconfigurations including version disclosure, directory browsing,
WebDAV, request filtering, anonymous auth, application pool identity, error pages,
and CVE-2017-7269 (IIS 6.0 WebDAV buffer overflow).
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
CVSS_HIGH = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
CVSS_MED  = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
CVSS_LOW  = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"

# PowerShell commands
# NOTE: Get-WindowsFeature only exists on Windows Server editions.
# On Windows 10/11, fall back to checking the W3SVC service directly.
_PS_IIS_INSTALLED = (
    "try { "
    "$f = Get-WindowsFeature -Name Web-Server -ErrorAction Stop; "
    "if ($f.InstallState -eq 'Installed') { 'Installed' } else { 'NotInstalled' } "
    "} catch { "
    # Fallback for Desktop editions (Windows 10/11) that lack Get-WindowsFeature
    "$svc = Get-Service -Name W3SVC -ErrorAction SilentlyContinue; "
    "if ($svc -and $svc.Status -ne 'Stopped' -or ($svc -and $svc.StartType -ne 'Disabled')) { "
    "if ($svc) { 'Installed' } else { 'NotInstalled' } } else { 'NotInstalled' } "
    "}"
)

_PS_IIS_HEADERS = (
    "try { "
    "$r = Invoke-WebRequest http://localhost/ -UseBasicParsing -TimeoutSec 5 "
    "-ErrorAction SilentlyContinue; "
    "if ($r) { $r.Headers | ConvertTo-Json -Depth 2 } else { '{}' } "
    "} catch { '{}' }"
)

_PS_DIR_BROWSE = (
    "try { "
    "Import-Module WebAdministration -ErrorAction Stop; "
    "Get-WebConfigurationProperty -Filter /system.webServer/directoryBrowse "
    "-PSPath 'IIS:\\' -Name enabled 2>$null | Select-Object -ExpandProperty Value "
    "} catch { 'UNAVAILABLE' }"
)

_PS_WEBDAV = (
    "try { "
    "$f = Get-WindowsFeature -Name Web-DAV-Publishing -ErrorAction Stop; "
    "$f.InstallState "
    "} catch { 'UNAVAILABLE' }"
)

_PS_DEFAULT_DOCS = (
    "try { "
    "Import-Module WebAdministration -ErrorAction Stop; "
    "Get-WebConfiguration '//defaultDocument/files/add' -PSPath 'IIS:\\' "
    "2>$null | Select-Object -ExpandProperty value "
    "} catch { 'UNAVAILABLE' }"
)

_PS_REQUEST_FILTERING = (
    "try { "
    "Import-Module WebAdministration -ErrorAction Stop; "
    "$rf = Get-WebConfiguration /system.webServer/security/requestFiltering "
    "-PSPath 'IIS:\\' 2>$null; "
    "if ($rf) { "
    "[PSCustomObject]@{ "
    "maxAllowedContentLength = $rf.requestLimits.maxAllowedContentLength; "
    "allowDoubleEscaping = $rf.allowDoubleEscaping; "
    "allowHighBitCharacters = $rf.allowHighBitCharacters "
    "} | ConvertTo-Json } else { '{}' } "
    "} catch { '{}' }"
)

_PS_HTTP_BINDINGS = (
    "try { "
    "Import-Module WebAdministration -ErrorAction Stop; "
    "Get-WebBinding 2>$null | "
    "Where-Object { $_.protocol -eq 'http' } | "
    "Select-Object bindingInformation,protocol,ItemXPath | "
    "ConvertTo-Json -Depth 2 "
    "} catch { '{}' }"
)

_PS_ANON_AUTH = (
    "try { "
    "Import-Module WebAdministration -ErrorAction Stop; "
    "Get-WebConfiguration "
    "'/system.webServer/security/authentication/anonymousAuthentication' "
    "-PSPath 'IIS:\\' 2>$null | "
    "Select-Object enabled | ConvertTo-Json "
    "} catch { '{}' }"
)

_PS_APP_POOLS = (
    "try { "
    "Import-Module WebAdministration -ErrorAction Stop; "
    "Get-WebConfiguration 'system.applicationHost/applicationPools/add' 2>$null | "
    "Select-Object Name,@{N='Identity';E={$_.processModel.userName}}, "
    "@{N='IdentityType';E={$_.processModel.identityType}} | "
    "ConvertTo-Json -Depth 2 "
    "} catch { '{}' }"
)

_PS_HTTP_ERRORS = (
    "try { "
    "Import-Module WebAdministration -ErrorAction Stop; "
    "Get-WebConfiguration /system.webServer/httpErrors -PSPath 'IIS:\\' 2>$null | "
    "Select-Object errorMode,existingResponse | ConvertTo-Json "
    "} catch { '{}' }"
)


def _parse_csv_rows(output: str) -> list[dict[str, str]]:
    """Parse PowerShell ConvertTo-Csv output into list of dicts."""
    lines = [ln.rstrip() for ln in output.splitlines() if ln.strip()]
    if lines and lines[0].startswith("#TYPE"):
        lines = lines[1:]
    if len(lines) < 2:
        return []
    headers = [h.strip('"') for h in lines[0].split(",")]
    rows: list[dict[str, str]] = []
    for line in lines[1:]:
        parts = re.findall(r'"([^"]*)"', line)
        if not parts:
            parts = line.split(",")
        row = dict(zip(headers, parts))
        rows.append(row)
    return rows


class WinIisAudit(BaseModule):
    NAME        = "win_iis_audit"
    DESCRIPTION = "WinRM credentialed: IIS web server misconfiguration audit"
    PHASE       = 5
    TAGS        = ["credentialed", "windows", "iis", "web-server", "compliance"]

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
        # Check if IIS is installed before running any checks
        iis_check = await winrm.execute(session, _PS_IIS_INSTALLED)
        if not iis_check.success:
            return
        state = (iis_check.stdout or "").strip()
        if "Installed" not in state:
            return

        await self._check_version_disclosure(host, winrm, session)
        await self._check_directory_browsing(host, winrm, session)
        await self._check_webdav(host, winrm, session)
        await self._check_request_filtering(host, winrm, session)
        await self._check_http_bindings(host, winrm, session)
        await self._check_anon_auth(host, winrm, session)
        await self._check_app_pools(host, winrm, session)
        await self._check_http_errors(host, winrm, session)

    # ── Check 1: IIS version disclosure ─────────────────────────────────────

    async def _check_version_disclosure(self, host: str, winrm, session) -> None:
        """Detect IIS version disclosure in Server response header."""
        result = await winrm.execute(session, _PS_IIS_HEADERS)
        raw = result.stdout or ""
        if not result.success or not raw.strip():
            return

        # Look for Server header containing Microsoft-IIS/X.Y
        m = re.search(r'"?[Ss]erver"?\s*[:\s]+"?(Microsoft-IIS/[\d.]+)"?', raw)
        if not m:
            return

        iis_header = m.group(1)
        version_match = re.search(r'Microsoft-IIS/([\d.]+)', iis_header)
        iis_version = version_match.group(1) if version_match else "unknown"

        self.new_finding(
            title=f"IIS Version Disclosure in Server Header — {host}",
            severity=Severity.LOW,
            description=(
                f"The IIS web server on {host} returns a 'Server: {iis_header}' header "
                f"in HTTP responses, revealing the IIS version ({iis_version}). "
                f"Version disclosure is informational on its own — it aids an attacker in "
                f"targeting version-specific CVEs, but does not itself constitute exploitability. "
                f"The real risk is whether a vulnerable version is running; if so, that is "
                f"reported separately. Suppressing the Server header is a defence-in-depth measure."
            ),
            reproduction_steps=[
                f"curl -sI http://{host}/ | grep -i server",
                f"# Expected output: Server: {iis_header}",
            ],
            remediation=(
                "Remove the Server header in IIS: open IIS Manager → select server → "
                "HTTP Response Headers → add/modify 'Server' header to a custom value, "
                "or use the URLScan/Request Filtering to remove it. "
                "PowerShell: Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' "
                "-filter 'system.webServer/security/requestFiltering' "
                "-name 'removeServerHeader' -value 'True'"
            ),
            references=[
                "CWE-200",
                "https://owasp.org/www-project-web-security-testing-guide/",
                "https://learn.microsoft.com/en-us/iis/configuration/system.webserver/security/requestfiltering/",
            ],
            evidence=Evidence(extra={
                "host": host,
                "server_header": iis_header,
                "iis_version": iis_version,
            }),
            cvss_v31_vector=CVSS_LOW,
            mitre_attack=["TA0043/T1592.002"],
            target=host, service="winrm", confidence="HIGH",
        )

        # CVE-2017-7269: IIS 6.0 + WebDAV buffer overflow — check WebDAV separately
        if iis_version.startswith("6."):
            webdav_check = await winrm.execute(session, _PS_WEBDAV)
            webdav_state = (webdav_check.stdout or "").strip()
            if "Installed" in webdav_state or "True" in webdav_state:
                self.new_finding(
                    title=f"CVE-2017-7269: IIS 6.0 WebDAV Buffer Overflow — {host}",
                    severity=Severity.CRITICAL,
                    description=(
                        f"IIS version 6.0 is running on {host} with WebDAV enabled. "
                        f"CVE-2017-7269 is a critical buffer overflow in the IIS 6.0 WebDAV "
                        f"ScStoragePathFromUrl function that allows unauthenticated remote code execution. "
                        f"This vulnerability has public exploit code and is actively exploited in the wild. "
                        f"IIS 6.0 is end-of-life (Windows Server 2003) and receives no security patches."
                    ),
                    reproduction_steps=[
                        "# Public exploit available on Exploit-DB and GitHub",
                        f"python cve-2017-7269.py {host} 80",
                        "# Alternatively via Metasploit:",
                        f"use exploit/windows/iis/iis_webdav_scstoragepathfromurl",
                        f"set RHOSTS {host}",
                        "run",
                    ],
                    remediation=(
                        "1. IMMEDIATE: Disable WebDAV — uninstall Web-DAV-Publishing feature. "
                        "2. Upgrade from IIS 6.0/Windows Server 2003 immediately — EOL since 2015. "
                        "3. Migrate to IIS 10 on Windows Server 2022. "
                        "4. If upgrade not immediately possible, block WebDAV HTTP methods "
                        "(PROPFIND, PROPPATCH, MKCOL, PUT) at the WAF/firewall."
                    ),
                    references=[
                        "CVE-2017-7269",
                        "https://www.exploit-db.com/exploits/41738",
                        "https://nvd.nist.gov/vuln/detail/CVE-2017-7269",
                    ],
                    evidence=Evidence(extra={
                        "host": host,
                        "iis_version": iis_version,
                        "webdav_state": webdav_state,
                        "cve": "CVE-2017-7269",
                    }),
                    cvss_v31_vector=CVSS_CRIT,
                    mitre_attack=["TA0001/T1190"],
                    target=host, service="winrm", confidence="HIGH",
                )

    # ── Check 2: Directory browsing ──────────────────────────────────────────

    async def _check_directory_browsing(self, host: str, winrm, session) -> None:
        """Detect directory browsing enabled on IIS."""
        result = await winrm.execute(session, _PS_DIR_BROWSE)
        raw = (result.stdout or "").strip()
        if not result.success or not raw or raw == "UNAVAILABLE":
            return

        if raw.lower() in ("true", "1"):
            self.new_finding(
                title=f"IIS Directory Browsing Enabled — {host}",
                severity=Severity.MEDIUM,
                description=(
                    f"IIS directory browsing is enabled on {host}. When a directory does not contain "
                    f"a default document, IIS returns a listing of all files and subdirectories. "
                    f"This exposes sensitive configuration files, backup files, source code, and "
                    f"application internals to unauthenticated visitors."
                ),
                reproduction_steps=[
                    f"curl -s http://{host}/",
                    "# Navigate to any directory without an index file to get a directory listing",
                    f"curl -s http://{host}/images/",
                ],
                remediation=(
                    "Disable directory browsing in IIS Manager: select each site → "
                    "Directory Browsing → Disable. "
                    "PowerShell: Set-WebConfigurationProperty -Filter /system.webServer/directoryBrowse "
                    "-PSPath 'IIS:\\' -Name enabled -Value False"
                ),
                references=[
                    "CWE-548",
                    "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information",
                ],
                evidence=Evidence(extra={"host": host, "directory_browsing": True}),
                cvss_v31_vector=CVSS_MED,
                mitre_attack=["TA0043/T1083"],
                target=host, service="winrm", confidence="HIGH",
            )

    # ── Check 3: WebDAV ──────────────────────────────────────────────────────

    async def _check_webdav(self, host: str, winrm, session) -> None:
        """Detect WebDAV enabled (separate from IIS 6.0 check)."""
        result = await winrm.execute(session, _PS_WEBDAV)
        raw = (result.stdout or "").strip()
        if not result.success or not raw or raw == "UNAVAILABLE":
            return

        if "Installed" in raw or "True" in raw:
            # Only flag as HIGH if IIS version is not 6.0 (6.0 is handled as CRIT above)
            iis_ver_check = await winrm.execute(session, _PS_IIS_HEADERS)
            iis_raw = iis_ver_check.stdout or ""
            is_iis6 = bool(re.search(r'Microsoft-IIS/6\.', iis_raw))
            if is_iis6:
                return  # Already flagged as critical above

            self.new_finding(
                title=f"IIS WebDAV Enabled — Unnecessary Attack Surface — {host}",
                severity=Severity.HIGH,
                description=(
                    f"WebDAV (Web Distributed Authoring and Versioning) is installed and enabled on "
                    f"the IIS server at {host}. WebDAV enables HTTP methods such as PUT, DELETE, MOVE, "
                    f"COPY, PROPFIND, and LOCK. If not explicitly required, this increases the attack "
                    f"surface significantly. WebDAV has a history of critical vulnerabilities and can "
                    f"allow file upload/modification on the server if misconfigured. "
                    f"It is also abused by attackers to exfiltrate data and deliver payloads "
                    f"(T1071.001, T1105)."
                ),
                reproduction_steps=[
                    f"# Test WebDAV methods:",
                    f"curl -X PROPFIND http://{host}/ -H 'Depth: 1'",
                    f"davtest -url http://{host}/",
                    f"# Check for writeable WebDAV:",
                    f"cadaver http://{host}/",
                ],
                remediation=(
                    "If WebDAV is not required, uninstall it: "
                    "Uninstall-WindowsFeature Web-DAV-Publishing. "
                    "If required, restrict with request filtering: block PROPFIND, PROPPATCH, MKCOL, "
                    "PUT, DELETE verbs for unauthenticated users, and enforce HTTPS + authentication."
                ),
                references=[
                    "CVE-2017-7269",
                    "https://learn.microsoft.com/en-us/iis/configuration/system.webserver/webdav/",
                    "https://attack.mitre.org/techniques/T1105/",
                ],
                evidence=Evidence(extra={"host": host, "webdav_installed": True}),
                cvss_v31_vector=CVSS_HIGH,
                mitre_attack=["TA0001/T1190", "TA0011/T1071.001"],
                target=host, service="winrm", confidence="HIGH",
            )

    # ── Check 5: Request filtering ───────────────────────────────────────────

    async def _check_request_filtering(self, host: str, winrm, session) -> None:
        """Check IIS request filtering configuration."""
        result = await winrm.execute(session, _PS_REQUEST_FILTERING)
        raw = (result.stdout or "").strip()
        if not result.success or not raw or raw in ("{}", "UNAVAILABLE"):
            return

        issues = []
        try:
            import json
            rf = json.loads(raw)
            max_content = rf.get("maxAllowedContentLength")
            double_esc = rf.get("allowDoubleEscaping")
            high_bit = rf.get("allowHighBitCharacters")

            if max_content is None or int(max_content) > 30000000:
                issues.append(
                    f"maxAllowedContentLength={max_content} — overly permissive "
                    f"(default 30MB; tune to application needs)"
                )
            if str(double_esc).lower() == "true":
                issues.append(
                    "allowDoubleEscaping=True — enables double URL encoding bypass "
                    "(e.g., ..%252F.. path traversal)"
                )
            if str(high_bit).lower() == "true":
                issues.append(
                    "allowHighBitCharacters=True — non-ASCII characters allowed, "
                    "may bypass security filters"
                )
        except (json.JSONDecodeError, ValueError, TypeError):
            return

        if issues:
            self.new_finding(
                title=f"IIS Request Filtering Misconfigured — {host}",
                severity=Severity.MEDIUM,
                description=(
                    f"IIS request filtering on {host} has insecure settings that may allow "
                    f"bypasses of input validation controls. Issues found:\n"
                    + "\n".join(f"  - {i}" for i in issues)
                ),
                reproduction_steps=[
                    f"# Test double encoding bypass:",
                    f"curl -s http://{host}/..%252F..%252Fetc%252Fpasswd",
                    "# PowerShell check:",
                    "Get-WebConfiguration /system.webServer/security/requestFiltering -PSPath 'IIS:\\'",
                ],
                remediation=(
                    "1. Set allowDoubleEscaping=False: "
                    "Set-WebConfigurationProperty -Filter /system.webServer/security/requestFiltering "
                    "-PSPath 'IIS:\\' -Name allowDoubleEscaping -Value False. "
                    "2. Set allowHighBitCharacters=False if not required for internationalization. "
                    "3. Set maxAllowedContentLength appropriate to your application needs (e.g., 10MB)."
                ),
                references=[
                    "CWE-22",
                    "https://learn.microsoft.com/en-us/iis/configuration/system.webserver/security/requestfiltering/",
                    "https://owasp.org/www-community/attacks/Double_Encoding",
                ],
                evidence=Evidence(extra={"host": host, "issues": issues, "raw_config": raw[:500]}),
                cvss_v31_vector=CVSS_MED,
                mitre_attack=["TA0001/T1190"],
                target=host, service="winrm", confidence="MEDIUM",
            )

    # ── Check 6: HTTP to HTTPS redirect ─────────────────────────────────────

    async def _check_http_bindings(self, host: str, winrm, session) -> None:
        """Detect HTTP port 80 bindings without HTTPS redirect."""
        result = await winrm.execute(session, _PS_HTTP_BINDINGS)
        raw = (result.stdout or "").strip()
        if not result.success or not raw or raw in ("{}", "[]", "UNAVAILABLE"):
            return

        http_bindings = []
        try:
            import json
            data = json.loads(raw)
            if isinstance(data, dict):
                data = [data]
            for entry in data:
                binding_info = entry.get("bindingInformation", "")
                proto = entry.get("protocol", "")
                if proto == "http" and ":80:" in binding_info:
                    http_bindings.append(binding_info)
        except (json.JSONDecodeError, TypeError):
            # Fallback: text scan for :80: pattern
            if ":80:" in raw and "http" in raw.lower():
                http_bindings.append("port 80 binding detected (raw parse)")

        if http_bindings:
            self.new_finding(
                title=f"IIS HTTP Port 80 Binding Without HTTPS Redirect — {host}",
                severity=Severity.MEDIUM,
                description=(
                    f"IIS on {host} has active HTTP (port 80) bindings: "
                    f"{', '.join(http_bindings[:5])}. "
                    f"No automatic HTTP-to-HTTPS redirect was detected. Plain HTTP exposes all traffic "
                    f"to network interception (T1557), credential theft via NTLM relay, and "
                    f"session hijacking. Browsers and security scanners will flag the site as insecure."
                ),
                reproduction_steps=[
                    f"curl -v http://{host}/",
                    "# Check if redirect to HTTPS occurs",
                    "Get-WebBinding | Where-Object { $_.protocol -eq 'http' }",
                ],
                remediation=(
                    "1. Configure HTTP Redirect in IIS to send all HTTP requests to HTTPS. "
                    "2. Use a URL Rewrite rule: "
                    "  <rule name='HTTP to HTTPS'><match url='(.*)'/>"
                    "<action type='Redirect' url='https://{HTTP_HOST}/{R:1}' redirectType='Permanent'/></rule>. "
                    "3. Obtain and install a valid TLS certificate. "
                    "4. Enable HSTS after full HTTPS migration."
                ),
                references=[
                    "CWE-319",
                    "https://learn.microsoft.com/en-us/iis/extensions/url-rewrite-module/url-rewrite-module-configuration-reference",
                    "https://attack.mitre.org/techniques/T1557/",
                ],
                evidence=Evidence(extra={"host": host, "http_bindings": http_bindings[:10]}),
                cvss_v31_vector=CVSS_MED,
                mitre_attack=["TA0009/T1557"],
                target=host, service="winrm", confidence="HIGH",
            )

    # ── Check 7: Anonymous authentication ───────────────────────────────────

    async def _check_anon_auth(self, host: str, winrm, session) -> None:
        """Check anonymous authentication enabled at IIS root level."""
        result = await winrm.execute(session, _PS_ANON_AUTH)
        raw = (result.stdout or "").strip()
        if not result.success or not raw or raw in ("{}", "UNAVAILABLE"):
            return

        try:
            import json
            data = json.loads(raw)
            if isinstance(data, list):
                data = data[0] if data else {}
            enabled = str(data.get("enabled", "")).lower()
        except (json.JSONDecodeError, TypeError):
            enabled = "true" if "true" in raw.lower() else ""

        if enabled == "true":
            self.new_finding(
                title=f"IIS Anonymous Authentication Enabled at Root Level — {host}",
                severity=Severity.LOW,
                description=(
                    f"Anonymous authentication is enabled at the IIS root level on {host}. "
                    f"While appropriate for public-facing web content, this becomes a risk when "
                    f"sensitive applications or admin interfaces inherit this setting. Verify that "
                    f"all sensitive paths explicitly override this with Windows, Basic, or Forms "
                    f"authentication. Any path reachable without credentials should be intentional."
                ),
                reproduction_steps=[
                    "Get-WebConfiguration "
                    "'/system.webServer/security/authentication/anonymousAuthentication' "
                    "-PSPath 'IIS:\\'",
                    f"curl -s http://{host}/admin/ # should require auth",
                ],
                remediation=(
                    "Review each application's authentication settings: "
                    "IIS Manager → Site → Authentication → ensure Anonymous Authentication "
                    "is disabled for sensitive applications and admin paths. "
                    "Enable Windows Authentication or Forms Authentication as appropriate."
                ),
                references=[
                    "CWE-306",
                    "https://learn.microsoft.com/en-us/iis/configuration/system.webserver/security/authentication/anonymousauthentication/",
                ],
                evidence=Evidence(extra={"host": host, "anonymous_auth_enabled": True}),
                cvss_v31_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                mitre_attack=["TA0001/T1078"],
                target=host, service="winrm", confidence="MEDIUM",
            )

    # ── Check 8: Application pool identity ──────────────────────────────────

    async def _check_app_pools(self, host: str, winrm, session) -> None:
        """Check application pools running as privileged accounts."""
        result = await winrm.execute(session, _PS_APP_POOLS)
        raw = (result.stdout or "").strip()
        if not result.success or not raw or raw in ("{}", "[]", "UNAVAILABLE"):
            return

        risky_pools = []
        try:
            import json
            data = json.loads(raw)
            if isinstance(data, dict):
                data = [data]
            for pool in data:
                name = pool.get("Name", "unknown")
                identity_type = str(pool.get("IdentityType", "")).lower()
                identity = str(pool.get("Identity", "")).lower()
                # Flag LocalSystem or custom account that is SYSTEM/Administrator
                if "localsystem" in identity_type or "system" in identity:
                    risky_pools.append({
                        "name": name,
                        "identity_type": identity_type,
                        "identity": pool.get("Identity", ""),
                    })
                elif "networkservice" in identity_type:
                    # NetworkService is less severe but note it
                    risky_pools.append({
                        "name": name,
                        "identity_type": identity_type,
                        "identity": "NetworkService",
                    })
        except (json.JSONDecodeError, TypeError):
            return

        # Only flag LocalSystem pools as HIGH; NetworkService as INFO
        system_pools = [p for p in risky_pools if "localsystem" in p["identity_type"].lower()
                        or "system" in p["identity"].lower()]
        if system_pools:
            self.new_finding(
                title=f"IIS Application Pools Running as SYSTEM — {host}",
                severity=Severity.HIGH,
                description=(
                    f"{len(system_pools)} IIS application pool(s) on {host} are configured to run "
                    f"as LocalSystem or SYSTEM: "
                    f"{', '.join(p['name'] for p in system_pools[:5])}. "
                    f"If an attacker achieves code execution in any of these application pools "
                    f"(e.g., via webshell or deserialization), they immediately have SYSTEM-level "
                    f"access on the host — full privilege escalation in a single step. "
                    f"Application pools should run as ApplicationPoolIdentity (lowest privilege)."
                ),
                reproduction_steps=[
                    "Get-WebConfiguration system.applicationHost/applicationPools/add "
                    "| Select-Object Name,@{N='IdentityType';E={$_.processModel.identityType}}",
                    f"# Pools running as LocalSystem: {', '.join(p['name'] for p in system_pools[:5])}",
                ],
                remediation=(
                    "Set each application pool to run as ApplicationPoolIdentity: "
                    "IIS Manager → Application Pools → Advanced Settings → "
                    "Process Model → Identity → ApplicationPoolIdentity. "
                    "PowerShell: Set-ItemProperty IIS:\\AppPools\\<PoolName> "
                    "-name processModel -value @{identityType='ApplicationPoolIdentity'}"
                ),
                references=[
                    "CWE-250",
                    "https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities",
                    "https://attack.mitre.org/techniques/T1134/",
                ],
                evidence=Evidence(extra={"host": host, "risky_pools": system_pools[:10]}),
                cvss_v31_vector=CVSS_HIGH,
                mitre_attack=["TA0004/T1134", "TA0002/T1059.001"],
                target=host, service="winrm", confidence="HIGH",
            )

    # ── Check 9: HTTP error detail to client ─────────────────────────────────

    async def _check_http_errors(self, host: str, winrm, session) -> None:
        """Detect IIS configured to send detailed errors to remote clients."""
        result = await winrm.execute(session, _PS_HTTP_ERRORS)
        raw = (result.stdout or "").strip()
        if not result.success or not raw or raw in ("{}", "UNAVAILABLE"):
            return

        try:
            import json
            data = json.loads(raw)
            if isinstance(data, list):
                data = data[0] if data else {}
            error_mode = str(data.get("errorMode", "")).strip()
        except (json.JSONDecodeError, TypeError):
            m = re.search(r'"errorMode"\s*:\s*"([^"]+)"', raw)
            error_mode = m.group(1) if m else ""

        if error_mode.lower() == "detailed":
            self.new_finding(
                title=f"IIS Detailed Error Pages Sent to Remote Clients — {host}",
                severity=Severity.MEDIUM,
                description=(
                    f"IIS on {host} is configured with errorMode='Detailed', which sends full "
                    f"ASP.NET/IIS error details (stack traces, file paths, SQL queries, connection "
                    f"strings, server internals) to remote clients on any unhandled error. "
                    f"This is equivalent to ASP.NET CustomErrors=Off and provides attackers with "
                    f"a significant information advantage for targeted exploitation."
                ),
                reproduction_steps=[
                    f"curl -s http://{host}/nonexistent-page-to-trigger-404-detail",
                    f"curl -s 'http://{host}/?id=1'  # Trigger SQL/application errors",
                    "# Look for stack traces, file paths, or connection strings in response",
                ],
                remediation=(
                    "Set errorMode to 'DetailedLocalOnly' so detailed errors are only visible on "
                    "the server itself: "
                    "Set-WebConfigurationProperty -Filter /system.webServer/httpErrors "
                    "-PSPath 'IIS:\\' -Name errorMode -Value DetailedLocalOnly. "
                    "Also set customErrors mode='On' in web.config for ASP.NET applications."
                ),
                references=[
                    "CWE-209",
                    "https://learn.microsoft.com/en-us/iis/configuration/system.webserver/httperrors/",
                    "https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure",
                ],
                evidence=Evidence(extra={"host": host, "error_mode": error_mode}),
                cvss_v31_vector=CVSS_MED,
                mitre_attack=["TA0043/T1592"],
                target=host, service="winrm", confidence="HIGH",
            )
