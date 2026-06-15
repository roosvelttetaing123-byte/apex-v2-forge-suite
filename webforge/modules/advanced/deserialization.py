"""Insecure deserialization scanner — Java, PHP, Python pickle detection."""
from __future__ import annotations

import asyncio
import base64
import re
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity

CVSS_DESER = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"

# Java serialized object magic bytes (base64 prefix)
JAVA_SERIAL_MAGIC      = b"\xac\xed\x00\x05"
JAVA_SERIAL_B64_PREFIX = base64.b64encode(JAVA_SERIAL_MAGIC)[:10].decode()

# PHP serialized object patterns
PHP_SERIAL_PATTERN = re.compile(
    r'[Oa]:\d+:"[^"]+":[\d]+:\{', re.IGNORECASE
)

# Detection patterns for deserialization usage
DESER_COOKIE_PATTERNS = [
    re.compile(r'rO0', re.IGNORECASE),           # Java base64 serialized
    re.compile(r'O:[0-9]+:', re.IGNORECASE),     # PHP serialized object
    re.compile(r'a:[0-9]+:\{', re.IGNORECASE),  # PHP serialized array
    re.compile(r'gASV', re.IGNORECASE),          # Python pickle (proto 2+)
    re.compile(r'\\x80\\x04', re.IGNORECASE),   # Python pickle magic
]

ERROR_INDICATORS = [
    "ClassNotFoundException", "java.io.InvalidClassException",
    "NotSerializableException", "UnserializationException",
    "unserialize()", "PickleError", "pickle.loads",
    "ObjectInputStream", "readObject",
]


class Deserialization(BaseModule):
    """Insecure deserialization vulnerability scanner."""

    NAME        = "deserialization"
    DESCRIPTION = "Detect insecure deserialization in cookies, headers, and POST bodies"
    PHASE       = 10
    TAGS        = ["advanced", "deserialization", "rce", "cwe-502", "owasp-a08"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        target = self.config.target.rstrip("/")
        if not self.check_scope(target):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        await asyncio.gather(
            self._check_serialized_cookies(target),
            self._check_viewstate(target),
            self._probe_deser_endpoints(target),
        )
        return self._make_result(start)

    async def _check_serialized_cookies(self, target: str) -> None:
        """Detect serialized objects in cookies."""
        await self.rate_limit()
        try:
            import aiohttp
            jar = aiohttp.CookieJar(unsafe=True)
            async with aiohttp.ClientSession(
                connector=aiohttp.TCPConnector(ssl=False), cookie_jar=jar
            ) as session:
                async with session.get(
                    target, timeout=aiohttp.ClientTimeout(total=10), allow_redirects=True
                ) as resp:
                    body = await resp.text(errors="ignore")
                    cookies = {c.key: c.value for c in jar}

            for cookie_name, cookie_value in cookies.items():
                for pattern in DESER_COOKIE_PATTERNS:
                    if pattern.search(cookie_value):
                        deser_type = self._identify_format(cookie_value)
                        ev = Evidence(
                            response_raw=f"Set-Cookie: {cookie_name}={cookie_value[:60]}...",
                            extra={
                                "cookie":    cookie_name,
                                "format":    deser_type,
                                "value":     cookie_value[:50],
                            },
                        )
                        self.new_finding(
                            title=f"Serialized Object in Cookie — {cookie_name} ({deser_type})",
                            severity=Severity.HIGH,
                            description=(
                                f"Cookie '{cookie_name}' contains a {deser_type} serialized object. "
                                "If the server deserializes this value without signature verification, "
                                "it may be vulnerable to insecure deserialization (RCE)."
                            ),
                            reproduction_steps=[
                                f"Cookie: {cookie_name}={cookie_value[:50]}",
                                f"Format identified as: {deser_type}",
                                "Use ysoserial (Java) or pickle payloads to test for RCE",
                            ],
                            remediation=(
                                "Never trust serialized data from client-side. "
                                "Sign all serialized objects with HMAC. "
                                "Use safe serialization formats (JSON) instead of language-native ones. "
                                "For Java: implement object input validation."
                            ),
                            references=["CWE-502", "OWASP A08:2021"],
                            evidence=ev,
                            cvss_v31_vector=CVSS_DESER,
                            mitre_attack=["TA0002/T1059"],
                            target=target,
                        )
                        break
        except Exception:
            pass

    async def _check_viewstate(self, target: str) -> None:
        """Check ASP.NET ViewState for MAC validation."""
        await self.rate_limit()
        try:
            import aiohttp
            async with aiohttp.ClientSession(
                connector=aiohttp.TCPConnector(ssl=False)
            ) as session:
                async with session.get(
                    target, timeout=aiohttp.ClientTimeout(total=10)
                ) as resp:
                    body = await resp.text(errors="ignore")

            # Find ViewState
            vs_match = re.search(
                r'<input[^>]+name="__VIEWSTATE"[^>]+value="([^"]+)"', body, re.IGNORECASE
            )
            if vs_match:
                viewstate = vs_match.group(1)
                # Check if MAC is enabled (ViewState without MAC has no HMAC)
                mac_match = re.search(
                    r'<input[^>]+name="__VIEWSTATEGENERATOR"', body, re.IGNORECASE
                )
                ev = Evidence(
                    extra={
                        "viewstate":     viewstate[:50] + "...",
                        "mac_enabled":   bool(mac_match),
                    }
                )
                if not mac_match:
                    self.new_finding(
                        title="ASP.NET ViewState Without MAC Validation",
                        severity=Severity.HIGH,
                        description=(
                            f"ASP.NET ViewState found at {target} without MAC validation indicators. "
                            "If EnableViewStateMac=False, the ViewState can be manipulated by attackers, "
                            "potentially leading to RCE via deserialization."
                        ),
                        reproduction_steps=[
                            "Extract ViewState from page",
                            "Use ViewState decoder tool",
                            "Craft malicious ViewState with ysoserial.net",
                        ],
                        remediation=(
                            "Enable ViewState MAC: <pages enableViewStateMac='true' />\n"
                            "Set machineKey in web.config with strong random values."
                        ),
                        references=["CWE-502"],
                        evidence=ev,
                        cvss_v31_vector=CVSS_DESER,
                        target=target,
                    )
        except Exception:
            pass

    async def _probe_deser_endpoints(self, target: str) -> None:
        """Send serialized data and watch for deserialization errors."""
        await self.rate_limit()
        # Send benign-looking but malformed Java serialized object
        probe = JAVA_SERIAL_MAGIC + b"\x00" * 20
        try:
            import aiohttp
            async with aiohttp.ClientSession(
                connector=aiohttp.TCPConnector(ssl=False)
            ) as session:
                async with session.post(
                    target,
                    data=probe,
                    headers={
                        "Content-Type": "application/octet-stream",
                        "Content-Length": str(len(probe)),
                    },
                    timeout=aiohttp.ClientTimeout(total=8),
                ) as resp:
                    body = await resp.text(errors="ignore")

            if any(err in body for err in ERROR_INDICATORS):
                ev = Evidence(
                    response_raw=body[:300],
                    extra={"probe": "Java serialized magic bytes"},
                )
                self.new_finding(
                    title="Deserialization Error Exposed — Java ObjectInputStream",
                    severity=Severity.HIGH,
                    description=(
                        f"Sending Java serialized bytes to {target} triggered a deserialization error. "
                        "Server appears to process Java serialized objects, and errors are exposed."
                    ),
                    reproduction_steps=[
                        "Send Java serialized magic bytes (0xaced0005) to endpoint",
                        "Observe ClassNotFoundException or similar errors",
                    ],
                    remediation="Use ysoserial to test for gadget chains. Update Java libraries.",
                    references=["CWE-502", "ysoserial"],
                    evidence=ev,
                    cvss_v31_vector=CVSS_DESER,
                    target=target,
                )
        except Exception:
            pass

    def _identify_format(self, value: str) -> str:
        if re.search(r'^rO0', value):
            return "Java (base64)"
        if re.search(r'^O:[0-9]', value):
            return "PHP object"
        if re.search(r'^a:[0-9]', value):
            return "PHP array"
        if re.search(r'^gASV', value):
            return "Python pickle"
        return "Unknown serialized"


class TestDeserialization:
    def test_identify_java_serial(self) -> None:
        mod = Deserialization.__new__(Deserialization)
        b64 = base64.b64encode(JAVA_SERIAL_MAGIC + b"\x00").decode()
        assert "Java" in mod._identify_format(b64)

    def test_identify_php_object(self) -> None:
        mod = Deserialization.__new__(Deserialization)
        assert "PHP object" in mod._identify_format('O:7:"MyClass":1:{s:3:"foo";s:3:"bar";}')

    def test_java_magic_bytes(self) -> None:
        assert JAVA_SERIAL_MAGIC == b"\xac\xed\x00\x05"
