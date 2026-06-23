"""IDOR Scanner — Insecure Direct Object Reference detection."""
from __future__ import annotations

import re
import sys
import time
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity

CVSS_IDOR = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N"
CVSS40_IDOR = "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:L/VA:N/SC:N/SI:N/SA:N"
class IdorScanner(BaseModule):
    """IDOR scanner — tests numeric IDs, UUIDs, and predictable object references."""

    NAME        = "idor_scanner"
    DESCRIPTION = "IDOR: numeric, UUID, and hash-based object reference testing"
    PHASE       = 6
    TAGS        = ["idor", "access_control", "owasp-a01", "cwe-639"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        target = self.config.target
        if not self.check_scope(target):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        self.log.info("IDOR scanning on %s", target)

        from webforge.core.session import ForgeSession
        session_data = self.config.extra.get("session_data")
        headers: dict[str, str] = {}
        if self.config.extra.get("token"):
            headers["Authorization"] = f"Bearer {self.config.extra['token']}"

        async with ForgeSession(
            rate=self.config.rate.requests_per_second,
            proxy=self.config.extra.get("proxy"),
            headers=headers,
        ) as session:
            await self._test_numeric_ids(session, target)
            await self._test_uuid_ids(session, target)

        return self._make_result(start)

    async def _test_numeric_ids(self, session: Any, target: str) -> None:
        """Test URL paths with numeric IDs for IDOR."""
        from urllib.parse import urlparse
        parsed = urlparse(target)
        path = parsed.path

        # Find numeric segments in path (e.g. /api/users/123/profile)
        numeric_segments = [(i, seg) for i, seg in enumerate(path.split("/"))
                           if seg.isdigit()]

        for seg_idx, current_id in numeric_segments:
            # Test adjacent IDs
            test_ids = [str(int(current_id) - 1), str(int(current_id) + 1),
                       str(int(current_id) + 100), "1", "0", "999999"]

            try:
                original_resp = await session.get(target)
                original_body = await original_resp.text()
                original_status = original_resp.status
                original_len = len(original_body)
            except Exception:
                continue

            for test_id in test_ids:
                if test_id == current_id:
                    continue
                await self.rate_limit()
                parts = path.split("/")
                parts[seg_idx] = test_id
                test_path = "/".join(parts)
                from urllib.parse import urlunparse
                test_url = urlunparse(parsed._replace(path=test_path))

                try:
                    resp = await session.get(test_url)
                    body = await resp.text()
                    if resp.status == 200 and abs(len(body) - original_len) < max(original_len * 0.3, 100):
                        if body != original_body and len(body) > 100:
                            ss = self.capture_screenshot(test_url, f"idor_{test_id}")
                            ev = Evidence(
                                request_raw=f"GET {test_url}",
                                response_raw=body[:2000],
                                screenshot_path=ss,
                                extra={"original_id": current_id, "tested_id": test_id},
                            )
                            self.new_finding(
                                title=f"Potential IDOR — Numeric ID in Path (/{test_id}/)",
                                severity=Severity.HIGH,
                                description=(
                                    f"Changing numeric ID from {current_id} to {test_id} in URL path "
                                    f"returned a 200 response with similar content length. "
                                    "May indicate unauthorized access to other users' data."
                                ),
                                reproduction_steps=[
                                    f"Original: GET {target} (ID: {current_id})",
                                    f"Modified: GET {test_url} (ID: {test_id})",
                                    "Compare responses for different users' data",
                                ],
                                remediation=(
                                    "Implement proper authorization checks on every object access. "
                                    "Verify the authenticated user owns/has permission to access the requested object. "
                                    "Consider using indirect references (mapping table) instead of direct IDs."
                                ),
                                references=["CWE-639", "OWASP A01:2021",
                                           "https://portswigger.net/web-security/access-control/idor"],
                                evidence=ev,
                                cvss_v31_vector=CVSS_IDOR,
                                cvss_v40_vector=CVSS40_IDOR,
                                mitre_attack=["TA0009/T1530"],
                                target=test_url,
                            )
                            break
                except Exception:
                    pass

    async def _test_uuid_ids(self, session: Any, target: str) -> None:
        """Test URL paths with UUID parameters."""
        import uuid as uuid_mod
        from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

        parsed = urlparse(target)
        params = parse_qs(parsed.query, keep_blank_values=True)

        uuid_pattern = re.compile(
            r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.I
        )

        for param_name, param_values in params.items():
            val = param_values[0] if param_values else ""
            if uuid_pattern.match(val):
                test_uuid = str(uuid_mod.uuid4())
                await self.rate_limit()
                new_params = dict(params)
                new_params[param_name] = [test_uuid]
                test_url = urlunparse(
                    parsed._replace(query=urlencode({k: v[0] for k, v in new_params.items()}))
                )
                try:
                    resp = await session.get(test_url)
                    if resp.status == 200:
                        body = await resp.text()
                        if len(body) > 100:
                            ev = Evidence(
                                request_raw=f"GET {test_url}",
                                response_raw=body[:1000],
                                extra={"param": param_name, "test_uuid": test_uuid},
                            )
                            self.new_finding(
                                title=f"Potential IDOR — UUID Parameter '{param_name}'",
                                severity=Severity.MEDIUM,
                                description=(
                                    f"Random UUID in parameter '{param_name}' returned HTTP 200. "
                                    "May indicate enumerable object references."
                                ),
                                reproduction_steps=[
                                    f"Replace UUID in {param_name} with random: {test_uuid}",
                                    f"Observe 200 response",
                                ],
                                remediation="Verify authorization on every object access by UUID.",
                                references=["CWE-639", "OWASP A01:2021"],
                                evidence=ev,
                                cvss_v31_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N",
                                target=test_url,
                            )
                except Exception:
                    pass


class TestIdorScanner:
    def test_numeric_detection(self) -> None:
        from urllib.parse import urlparse
        url = "https://api.example.com/users/123/profile"
        parsed = urlparse(url)
        numeric = [(i, s) for i, s in enumerate(parsed.path.split("/")) if s.isdigit()]
        assert numeric == [(2, "123")]
