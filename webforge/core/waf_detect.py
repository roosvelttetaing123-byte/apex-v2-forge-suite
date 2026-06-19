"""WAF detection and payload evasion engine."""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any

log = logging.getLogger(__name__)

WAF_SIGNATURES: dict[str, dict[str, Any]] = {
    "Cloudflare": {
        "headers":  {"server": "cloudflare", "cf-ray": None},
        "body":     ["cloudflare", "Attention Required!", "cf-browser-verification"],
        "status":   [403, 503],
    },
    "AWS WAF": {
        "headers":  {"x-amzn-requestid": None, "x-amz-id": None},
        "body":     ["AWS WAF", "Request blocked"],
        "status":   [403],
    },
    "Akamai": {
        "headers":  {"x-akamai-transformed": None, "akamai-origin-hop": None},
        "body":     ["Access Denied", "Reference #"],
        "status":   [403],
    },
    "ModSecurity": {
        "headers":  {"x-mod-security-message": None},
        "body":     ["ModSecurity", "mod_security", "Not Acceptable!"],
        "status":   [406, 501],
    },
    "F5 BIG-IP": {
        "headers":  {"x-waf-status": None, "x-cnection": None},
        "body":     ["The requested URL was rejected", "Please consult with your administrator"],
        "status":   [403],
    },
    "Imperva": {
        "headers":  {"x-iinfo": None, "x-cdn": "incapsula"},
        "body":     ["incapsula incident", "Powered By Incapsula", "_Incapsula_Resource"],
        "status":   [403],
    },
    "Sucuri": {
        "headers":  {"x-sucuri-id": None, "x-sucuri-cache": None},
        "body":     ["Sucuri WebSite Firewall", "Access Denied - Sucuri Website Firewall"],
        "status":   [403],
    },
}

# Evasion payload transformations
EVASION_TRANSFORMS: dict[str, Any] = {
    "url_encode":    lambda p: p.replace("<", "%3C").replace(">", "%3E").replace("'", "%27").replace('"', "%22"),
    "double_encode": lambda p: p.replace("<", "%253C").replace(">", "%253E"),
    "html_entity":   lambda p: p.replace("<", "&lt;").replace(">", "&gt;"),
    "case_vary":     lambda p: "".join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(p)),
    "comment_break": lambda p: p.replace("SELECT", "SEL/**/ECT").replace("UNION", "UN/**/ION"),
    "space_to_plus": lambda p: p.replace(" ", "+"),
    "null_byte":     lambda p: p.replace(" ", "%00"),
}


@dataclass
class WafResult:
    detected: bool = False
    vendor:   str  = "Unknown"
    confidence: int = 0       # 0-100
    evasion_mode: bool = False
    details: dict[str, Any] = field(default_factory=dict)


def detect_waf(
    status_code: int,
    headers: dict[str, str],
    body: str,
) -> WafResult:
    """Detect WAF presence from HTTP response.

    Args:
        status_code: HTTP response status code.
        headers:     Response headers dict (lowercase keys).
        body:        Response body string.

    Returns:
        WafResult with detection details.
    """
    body_lower = body.lower()
    headers_lower = {k.lower(): v.lower() for k, v in headers.items()}

    best: WafResult | None = None
    best_score = 0

    for vendor, sigs in WAF_SIGNATURES.items():
        score = 0
        details: dict[str, list[str]] = {"matched_headers": [], "matched_body": []}

        for h_key, h_val in (sigs.get("headers") or {}).items():
            if h_key in headers_lower:
                if h_val is None or h_val in headers_lower[h_key]:
                    score += 30
                    details["matched_headers"].append(h_key)

        for pattern in (sigs.get("body") or []):
            if pattern.lower() in body_lower:
                score += 20
                details["matched_body"].append(pattern)

        if status_code in (sigs.get("status") or []):
            score += 10

        if score > best_score:
            best_score = score
            best = WafResult(
                detected=True,
                vendor=vendor,
                confidence=min(score, 100),
                evasion_mode=True,
                details=details,
            )

    if best and best_score >= 20:
        log.warning("WAF detected: %s (confidence: %d%%)", best.vendor, best.confidence)
        return best

    return WafResult(detected=False)


def evade_payload(payload: str, waf_vendor: str | None = None) -> list[str]:
    """Generate evasion variants of a payload for WAF bypass.

    Args:
        payload:    Original payload string.
        waf_vendor: Detected WAF vendor (optional, for targeted evasion).

    Returns:
        List of evasion payload variants.
    """
    variants = [payload]
    for name, transform in EVASION_TRANSFORMS.items():
        try:
            variant = transform(payload)
            if variant != payload:
                variants.append(variant)
        except Exception:
            pass
    return list(dict.fromkeys(variants))  # deduplicate preserving order


class TestWafDetect:
    def test_cloudflare_detection(self) -> None:
        result = detect_waf(
            403,
            {"server": "cloudflare", "cf-ray": "abc123"},
            "cloudflare security check",
        )
        assert result.detected is True
        assert result.vendor == "Cloudflare"

    def test_no_waf(self) -> None:
        result = detect_waf(200, {"server": "nginx"}, "Hello World")
        assert result.detected is False

    def test_evade_payload(self) -> None:
        variants = evade_payload("<script>alert(1)</script>")
        assert len(variants) > 1
        assert "<script>alert(1)</script>" in variants
