"""Security.txt Scanner — RFC 9116 compliance check.

Nessus equivalent: 157288 (Missing security.txt).
"""
from __future__ import annotations

import re
import time
from typing import Any

from common.base_module import BaseModule, ModuleResult
from common.finding import Severity
from common.fp_reducer import FPReducer, Confidence

REQUIRED_FIELDS = ["Contact", "Expires"]
RECOMMENDED_FIELDS = ["Encryption", "Preferred-Languages", "Canonical", "Policy"]

CVSS_SEC_TXT = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"
CVSS40_SEC_TXT = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N"


class SecurityTxt(BaseModule):
    """Security.txt scanner — RFC 9116 compliance verification."""

    NAME        = "security_txt"
    DESCRIPTION = "RFC 9116 security.txt presence and compliance check"
    PHASE       = 2
    TAGS        = ["recon", "compliance", "rfc-9116"]

    async def run(self) -> ModuleResult:
        start  = time.monotonic()
        target = self.config.target.rstrip("/")

        if not self.check_scope(target):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        self.log.info("Checking security.txt on %s", target)
        self._fp = FPReducer(
            collab_client=self.config.extra.get("collab_client"),
            headers=self.config.extra.get("session_headers", {}),
        )

        from webforge.core.session import ForgeSession
        async with ForgeSession.from_config(self.config) as session:
            found = False
            for path in ["/.well-known/security.txt", "/security.txt"]:
                try:
                    await self.rate_limit()
                    resp = await session.get(f"{target}{path}", allow_redirects=True)
                    if resp.status == 200:
                        body = await resp.text()
                        if "contact:" in body.lower():
                            found = True
                            self._validate_content(body, f"{target}{path}")
                            break
                except Exception:
                    continue

            if not found:
                self.new_finding(
                    title="Missing security.txt (RFC 9116)",
                    severity=Severity.INFORMATIONAL,
                    description="No security.txt file found. RFC 9116 recommends providing a security.txt at /.well-known/security.txt with contact information for responsible disclosure.",
                    reproduction_steps=[f"GET {target}/.well-known/security.txt"],
                    remediation="Create a security.txt file per RFC 9116. Place at /.well-known/security.txt.",
                    references=["RFC 9116", "https://securitytxt.org/"],
                    cvss_v31_vector=CVSS_SEC_TXT,
                    cvss_v40_vector=CVSS40_SEC_TXT,
                    target=target,
                )

        return self._make_result(start)

    def _validate_content(self, body: str, url: str) -> None:
        """Validate security.txt content per RFC 9116."""
        lines = body.strip().split("\n")
        fields_present = set()
        for line in lines:
            if ":" in line and not line.startswith("#"):
                field = line.split(":")[0].strip()
                fields_present.add(field)

        missing_required = [f for f in REQUIRED_FIELDS if f not in fields_present]
        if missing_required:
            self.new_finding(
                title=f"Incomplete security.txt — Missing: {', '.join(missing_required)}",
                severity=Severity.LOW,
                description=f"security.txt at {url} is missing required fields: {', '.join(missing_required)}. RFC 9116 requires Contact and Expires fields.",
                reproduction_steps=[f"GET {url}"],
                remediation=f"Add missing fields: {', '.join(missing_required)}",
                references=["RFC 9116"],
                cvss_v31_vector=CVSS_SEC_TXT,
                cvss_v40_vector=CVSS40_SEC_TXT,
                target=self.config.target,
            )
