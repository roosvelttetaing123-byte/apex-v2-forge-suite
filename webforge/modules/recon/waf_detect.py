"""WAF Detection Scanner — fingerprints web application firewalls.

Nessus equivalent: 62820 (WAF detection).
"""
from __future__ import annotations

import re
import time
from typing import Any

from common.base_module import BaseModule, ModuleResult
from common.finding import Severity
from common.fp_reducer import FPReducer, Confidence

WAF_SIGNATURES = {
    "Cloudflare": {
        "headers": {"Server": "cloudflare", "CF-RAY": ""},
        "cookies": ["__cfduid", "__cf_bm", "cf_clearance"],
        "body_markers": ["cloudflare", "attention required"],
    },
    "AWS WAF": {
        "headers": {"x-amzn-RequestId": "", "x-amz-apigw-id": ""},
        "cookies": ["awsalb", "awsalbcors"],
        "body_markers": [],
    },
    "Akamai": {
        "headers": {"X-Akamai-Transformed": "", "Akamai-Origin-Hop": ""},
        "cookies": ["akamai_session"],
        "body_markers": ["akamai", "reference #"],
    },
    "Imperva/Incapsula": {
        "headers": {"X-CDN": "Imperva", "X-Iinfo": ""},
        "cookies": ["incap_ses", "visid_incap"],
        "body_markers": ["incapsula", "imperva"],
    },
    "ModSecurity": {
        "headers": {"Server": "ModSecurity"},
        "cookies": [],
        "body_markers": ["mod_security", "modsecurity", "NOYB"],
    },
    "Sucuri": {
        "headers": {"X-Sucuri-ID": "", "X-Sucuri-Cache": ""},
        "cookies": ["sucuri_cloudproxy"],
        "body_markers": ["sucuri", "cloudproxy"],
    },
    "F5 BIG-IP ASM": {
        "headers": {"X-WA-Info": ""},
        "cookies": ["TS", "BIGipServer"],
        "body_markers": ["the requested url was rejected"],
    },
    "Barracuda": {
        "headers": {},
        "cookies": ["barra_counter_session"],
        "body_markers": ["barracuda"],
    },
}

CVSS_WAF = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"
CVSS40_WAF = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N"


class WafDetect(BaseModule):
    """WAF Detection scanner — fingerprints web application firewalls."""

    NAME        = "waf_detect"
    DESCRIPTION = "WAF detection and fingerprinting (Cloudflare, AWS, Akamai, etc.)"
    PHASE       = 1
    TAGS        = ["recon", "waf", "fingerprint"]

    async def run(self) -> ModuleResult:
        start  = time.monotonic()
        target = self.config.target.rstrip("/")

        if not self.check_scope(target):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        self.log.info("Starting WAF detection on %s", target)
        self._fp = FPReducer(
            collab_client=self.config.extra.get("collab_client"),
            headers=self.config.extra.get("session_headers", {}),
        )

        from webforge.core.session import ForgeSession
        async with ForgeSession.from_config(self.config) as session:
            detected_wafs = []

            # Normal request
            await self.rate_limit()
            resp = await session.get(target)
            headers = dict(resp.headers)
            body = await resp.text()
            cookies = {c.key: c.value for c in resp.cookies.values()} if hasattr(resp, "cookies") else {}

            # Malicious request to trigger WAF
            await self.rate_limit()
            evil_resp = await session.get(
                f"{target}/?id=1' OR 1=1--&<script>alert(1)</script>",
                allow_redirects=False,
            )
            evil_headers = dict(evil_resp.headers)
            evil_body = await evil_resp.text()

            for waf_name, sigs in WAF_SIGNATURES.items():
                score = 0
                # Check headers
                for h, v in sigs.get("headers", {}).items():
                    if h in headers or h in evil_headers:
                        val = headers.get(h, evil_headers.get(h, ""))
                        if not v or v.lower() in val.lower():
                            score += 2
                # Check cookies
                for cookie in sigs.get("cookies", []):
                    if any(cookie.lower() in k.lower() for k in cookies):
                        score += 2
                # Check body markers
                for marker in sigs.get("body_markers", []):
                    if marker.lower() in body.lower() or marker.lower() in evil_body.lower():
                        score += 1

                if score >= 2:
                    detected_wafs.append((waf_name, score))

            # Was the malicious request blocked?
            waf_blocked = evil_resp.status in {403, 406, 429, 451, 503}

            if detected_wafs:
                detected_wafs.sort(key=lambda x: -x[1])
                waf_list = ", ".join(f"{w} (confidence: {s})" for w, s in detected_wafs)
                self.new_finding(
                    title=f"WAF Detected — {detected_wafs[0][0]}",
                    severity=Severity.INFORMATIONAL,
                    description=f"Web Application Firewall detected: {waf_list}. Blocked malicious request: {waf_blocked}. This affects scanner accuracy — some findings may be WAF-filtered.",
                    reproduction_steps=[f"GET {target}", "Check response headers and cookies for WAF signatures"],
                    remediation="WAF presence is noted for scan accuracy. No action required.",
                    references=["OWASP WAF Bypass"],
                    cvss_v31_vector=CVSS_WAF,
                    cvss_v40_vector=CVSS40_WAF,
                    target=target,
                )
                # Store WAF info for other modules to use
                self.config.extra["waf_detected"] = detected_wafs[0][0]
                self.config.extra["waf_blocks_injection"] = waf_blocked

        return self._make_result(start)
