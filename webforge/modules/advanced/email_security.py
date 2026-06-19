"""Email Security — SPF, DKIM, DMARC, mail header analysis."""
from __future__ import annotations
import asyncio, sys, time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))
from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity

CVSS_NO_DMARC = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N"
CVSS40_NO_DMARC = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:H/VA:N/SC:N/SI:N/SA:N"
CVSS_INFO = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
CVSS40_INFO = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N"

class EmailSecurity(BaseModule):
    NAME = "email_security"
    DESCRIPTION = "Email: SPF, DKIM, DMARC record analysis and spoofing assessment"
    PHASE = 10
    TAGS = ["advanced", "email", "spf", "dmarc", "cwe-290"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        target = self.config.target.rstrip("/")
        if not self.check_scope(target):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        # Extract domain from target
        from urllib.parse import urlparse
        parsed = urlparse(target)
        domain = parsed.hostname or target
        # Strip www prefix
        if domain.startswith("www."):
            domain = domain[4:]

        records = {}

        # Query DNS records
        import socket

        # SPF check (TXT record)
        await self.rate_limit()
        try:
            proc = await asyncio.create_subprocess_exec(
                "nslookup", "-type=TXT", domain,
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
            output = stdout.decode(errors="ignore")
            import re
            spf_match = re.search(r'"(v=spf1[^"]*)"', output)
            if spf_match:
                records["spf"] = spf_match.group(1)
        except Exception:
            pass

        # DMARC check
        await self.rate_limit()
        try:
            proc = await asyncio.create_subprocess_exec(
                "nslookup", "-type=TXT", f"_dmarc.{domain}",
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
            output = stdout.decode(errors="ignore")
            import re
            dmarc_match = re.search(r'"(v=DMARC1[^"]*)"', output)
            if dmarc_match:
                records["dmarc"] = dmarc_match.group(1)
        except Exception:
            pass

        # DKIM check (common selectors)
        for selector in ["default", "google", "selector1", "selector2", "k1", "mail"]:
            await self.rate_limit()
            try:
                proc = await asyncio.create_subprocess_exec(
                    "nslookup", "-type=TXT", f"{selector}._domainkey.{domain}",
                    stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=5)
                output = stdout.decode(errors="ignore")
                if "v=DKIM1" in output or "p=" in output:
                    import re
                    dkim_match = re.search(r'"([^"]*v=DKIM1[^"]*)"', output)
                    records["dkim"] = f"{selector}: {dkim_match.group(1)[:80] if dkim_match else 'found'}"
                    break
            except Exception:
                pass

        # Analyze results
        missing = []
        if "spf" not in records:
            missing.append("SPF")
        elif "+all" in records.get("spf", ""):
            missing.append("SPF (+all = accept all)")
        if "dmarc" not in records:
            missing.append("DMARC")
        elif "p=none" in records.get("dmarc", ""):
            missing.append("DMARC (p=none = monitor only)")
        if "dkim" not in records:
            missing.append("DKIM")

        if missing:
            ev = Evidence(extra={"records": records, "missing": missing, "domain": domain})
            self.new_finding(
                title=f"Email Security Gaps — {', '.join(missing)} for {domain}",
                severity=Severity.MEDIUM if "SPF" in str(missing) and "DMARC" in str(missing) else Severity.LOW,
                description=(
                    f"Email authentication records for {domain}:\n"
                    f"  SPF: {records.get('spf', 'MISSING')}\n"
                    f"  DMARC: {records.get('dmarc', 'MISSING')}\n"
                    f"  DKIM: {records.get('dkim', 'NOT FOUND (checked common selectors)')}\n\n"
                    f"Missing: {', '.join(missing)}. Domain may be spoofable."
                ),
                reproduction_steps=[
                    f"nslookup -type=TXT {domain}",
                    f"nslookup -type=TXT _dmarc.{domain}",
                ],
                remediation="Implement SPF, DKIM, and DMARC with p=reject.",
                references=["CWE-290"],
                evidence=ev, cvss_v31_vector=CVSS_NO_DMARC, cvss_v40_vector=CVSS40_NO_DMARC,
                target=target)
        else:
            ev = Evidence(extra={"records": records, "domain": domain})
            self.new_finding(
                title=f"Email Security — SPF/DKIM/DMARC present for {domain}",
                severity=Severity.INFORMATIONAL,
                description=f"All email authentication records found for {domain}.",
                reproduction_steps=[f"nslookup -type=TXT {domain}"],
                remediation="Ensure DMARC policy is p=reject.",
                references=["CWE-290"],
                evidence=ev, cvss_v31_vector=CVSS_INFO, cvss_v40_vector=CVSS40_INFO,
                target=target)

        return self._make_result(start)

class TestEmailSecurity:
    def test_phase(self) -> None: assert EmailSecurity.PHASE == 10
