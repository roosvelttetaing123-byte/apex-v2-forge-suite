"""Source Audit — static analysis of exposed source code for vulnerabilities."""
from __future__ import annotations
import re, sys, time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))
from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity
from common.fp_reducer import FPReducer, Confidence
import aiohttp

CVSS = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
CVSS40 = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N"

DANGEROUS_PATTERNS = [
    (r'eval\s*\([^)]*(?:req|input|param|query|body)', "eval() with user input", "CWE-95"),
    (r'exec\s*\([^)]*(?:req|input|param|query|body)', "exec() with user input", "CWE-78"),
    (r'(?:password|secret|api_key)\s*=\s*["\'][^"\']{3,}', "Hardcoded credential", "CWE-798"),
    (r'(?:SELECT|INSERT|UPDATE|DELETE).*\+.*(?:req|input|param|query)', "SQL concatenation", "CWE-89"),
    (r'innerHTML\s*=\s*.*(?:req|input|param|query|location)', "innerHTML with user input", "CWE-79"),
    (r'child_process|subprocess|os\.system|os\.popen', "Command execution import", "CWE-78"),
    (r'pickle\.loads|yaml\.load\s*\(', "Unsafe deserialization", "CWE-502"),
    (r'(?:md5|sha1)\s*\(', "Weak hash algorithm", "CWE-328"),
    (r'TODO|FIXME|HACK|XXX|BUG', "Developer note", "CWE-1078"),
]

SOURCE_EXPOSURE_PATHS = [
    "/.git/HEAD", "/.svn/entries", "/.env", "/.env.local",
    "/package.json", "/composer.json", "/Gemfile",
    "/.DS_Store", "/web.config", "/crossdomain.xml",
    "/WEB-INF/web.xml", "/config.php.bak", "/wp-config.php~",
]

class SourceAudit(BaseModule):
    NAME = "source_audit"
    DESCRIPTION = "Whitebox: scan exposed source for vulns, secrets, dangerous patterns"
    PHASE = 11
    TAGS = ["whitebox", "source", "sast", "cwe-798"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        target = self.config.target.rstrip("/")
        if not self.check_scope(target):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        self._fp = FPReducer(
            collab_client=self.config.extra.get("collab_client"),
            headers=self.config.extra.get("session_headers", {}),
        )
        async with aiohttp.ClientSession(
            connector=aiohttp.TCPConnector(ssl=False),
            timeout=aiohttp.ClientTimeout(total=8),
        ) as session:
            exposed_sources = []

            # Check for exposed source files
            for path in SOURCE_EXPOSURE_PATHS:
                await self.rate_limit()
                try:
                    async with session.get(f"{target}{path}") as resp:
                        if resp.status == 200:
                            body = await resp.text(errors="ignore")
                            if len(body) > 10 and "404" not in body[:100].lower():
                                exposed_sources.append({"path": path, "size": len(body), "content": body[:500]})
                except Exception:
                    pass

            # Analyze exposed source for dangerous patterns
            findings_by_pattern = []
            for source in exposed_sources:
                content = source.get("content", "")
                for pattern, desc, cwe in DANGEROUS_PATTERNS:
                    matches = re.findall(pattern, content, re.I)
                    if matches:
                        findings_by_pattern.append({
                            "file": source["path"],
                            "pattern": desc,
                            "cwe": cwe,
                            "matches": len(matches),
                        })

            # Also check inline JavaScript in main page
            await self.rate_limit()
            try:
                async with session.get(target) as resp:
                    body = await resp.text(errors="ignore")
                    scripts = re.findall(r'<script[^>]*>(.*?)</script>', body, re.S | re.I)
                    for script in scripts:
                        for pattern, desc, cwe in DANGEROUS_PATTERNS[:5]:
                            if re.search(pattern, script, re.I):
                                findings_by_pattern.append({
                                    "file": "inline-script",
                                    "pattern": desc,
                                    "cwe": cwe,
                                    "matches": 1,
                                })
            except Exception:
                pass

            if exposed_sources:
                ev = Evidence(extra={"exposed": [{"path": s["path"], "size": s["size"]} for s in exposed_sources]})
                self.new_finding(
                    title=f"Source Code Exposure — {len(exposed_sources)} file(s)",
                    severity=Severity.HIGH,
                    description=(
                        f"Exposed source/config files:\n"
                        + "\n".join(f"  {target}{s['path']} ({s['size']} bytes)" for s in exposed_sources[:10])
                    ),
                    reproduction_steps=[f"curl {target}{exposed_sources[0]['path']}"],
                    remediation="Block access to source files. Remove .git, .env, backups from webroot.",
                    references=["CWE-538"],
                    evidence=ev, cvss_v31_vector=CVSS, cvss_v40_vector=CVSS40,
                    target=target)

            if findings_by_pattern:
                ev = Evidence(extra={"patterns": findings_by_pattern[:20]})
                self.new_finding(
                    title=f"Dangerous Code Patterns — {len(findings_by_pattern)} issue(s)",
                    severity=Severity.MEDIUM,
                    description=(
                        f"Dangerous patterns in exposed code:\n"
                        + "\n".join(f"  [{f['cwe']}] {f['file']}: {f['pattern']}" for f in findings_by_pattern[:10])
                    ),
                    reproduction_steps=["Review exposed source code for vulnerability patterns"],
                    remediation="Fix identified code patterns. Remove source files from production.",
                    references=list({f["cwe"] for f in findings_by_pattern[:5]}),
                    evidence=ev,
                    cvss_v31_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
                    cvss_v40_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N",
                    target=target)

        return self._make_result(start)

class TestSourceAudit:
    def test_patterns(self) -> None: assert len(DANGEROUS_PATTERNS) >= 5
    def test_phase(self) -> None: assert SourceAudit.PHASE == 11
