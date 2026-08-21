"""Code Flow — trace data flow from sources to sinks for vulnerability detection."""
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

# Source → Sink pairs (taint tracking)
TAINT_FLOWS = [
    {"source": r"(?:req\.(?:query|body|params|headers)\[|request\.(?:GET|POST|args)\[|params\[)",
     "sink": r"(?:eval|exec|system|popen|subprocess\.call)\(",
     "vuln": "Command Injection", "cwe": "CWE-78"},
    {"source": r"(?:req\.(?:query|body|params)\[|request\.(?:GET|POST|args)\[)",
     "sink": r"(?:\.query\(|\.execute\(|cursor\.execute\(|SELECT\s|INSERT\s|UPDATE\s|DELETE\s).*\+",
     "vuln": "SQL Injection", "cwe": "CWE-89"},
    {"source": r"(?:req\.(?:query|body|params)\[|request\.(?:GET|POST)\[)",
     "sink": r"(?:innerHTML|document\.write|\.html\(|render_template_string)",
     "vuln": "Cross-Site Scripting", "cwe": "CWE-79"},
    {"source": r"(?:req\.(?:query|body|params)\[|request\.(?:GET|POST)\[)",
     "sink": r"(?:open\(|readFile\(|fs\.read|file_get_contents|include\(|require\()",
     "vuln": "Path Traversal/LFI", "cwe": "CWE-22"},
    {"source": r"(?:req\.(?:query|body|params)\[|request\.(?:GET|POST)\[)",
     "sink": r"(?:redirect\(|\.redirect\(|header\(['\"]Location|res\.redirect)",
     "vuln": "Open Redirect", "cwe": "CWE-601"},
]

class CodeFlow(BaseModule):
    NAME = "code_flow"
    DESCRIPTION = "Whitebox: source-to-sink taint flow analysis in exposed code"
    PHASE = 11
    TAGS = ["whitebox", "taint", "cwe-79", "cwe-89"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        target = self.config.target.rstrip("/")
        if not self.check_scope(target):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        self._fp = FPReducer(
            collab_client=self.config.extra.get("collab_client"),
            headers=self.config.extra.get("session_headers", {}),
        )
        # Collect source code from various endpoints
        source_files = {}
        code_paths = [
            "/.git/HEAD", "/package.json", "/app.js", "/server.js",
            "/index.js", "/main.py", "/app.py", "/config.py",
        ]

        async with aiohttp.ClientSession(
            connector=aiohttp.TCPConnector(ssl=False),
            timeout=aiohttp.ClientTimeout(total=8),
        ) as session:
            # Collect any exposed source
            for path in code_paths:
                await self.rate_limit()
                try:
                    async with session.get(f"{target}{path}") as resp:
                        if resp.status == 200:
                            body = await resp.text(errors="ignore")
                            if len(body) > 20 and "<html" not in body[:200].lower():
                                source_files[path] = body
                except Exception:
                    pass

            # Also collect inline scripts from main page
            await self.rate_limit()
            try:
                async with session.get(target) as resp:
                    body = await resp.text(errors="ignore")
                    scripts = re.findall(r'<script[^>]*>(.*?)</script>', body, re.S | re.I)
                    for i, script in enumerate(scripts):
                        if len(script) > 50:
                            source_files[f"inline_script_{i}"] = script

                    # Check for source map references
                    for m in re.finditer(r'//# sourceMappingURL=(\S+)', body):
                        map_url = m.group(1)
                        if not map_url.startswith("data:"):
                            await self.rate_limit()
                            try:
                                full_url = f"{target}/{map_url}" if not map_url.startswith("http") else map_url
                                async with session.get(full_url) as resp2:
                                    if resp2.status == 200:
                                        source_files[map_url] = await resp2.text(errors="ignore")
                            except Exception:
                                pass
            except Exception:
                pass

        # Analyze taint flows
        taint_findings = []
        for filepath, content in source_files.items():
            for flow in TAINT_FLOWS:
                source_matches = list(re.finditer(flow["source"], content, re.I))
                sink_matches = list(re.finditer(flow["sink"], content, re.I))

                if source_matches and sink_matches:
                    # Check proximity (within ~20 lines of each other)
                    for src in source_matches[:3]:
                        src_line = content[:src.start()].count("\n")
                        for sink in sink_matches[:3]:
                            sink_line = content[:sink.start()].count("\n")
                            if abs(src_line - sink_line) < 20:
                                taint_findings.append({
                                    "file": filepath,
                                    "vuln": flow["vuln"],
                                    "cwe": flow["cwe"],
                                    "source_line": src_line + 1,
                                    "sink_line": sink_line + 1,
                                    "source_text": content[max(0, src.start()-20):src.end()+20][:60],
                                    "sink_text": content[max(0, sink.start()-20):sink.end()+20][:60],
                                })

        if taint_findings:
            ev = Evidence(extra={"taint_flows": taint_findings[:20]})
            self.new_finding(
                title=f"Taint Flow Analysis — {len(taint_findings)} source→sink paths",
                severity=Severity.HIGH,
                description=(
                    f"Source-to-sink data flow vulnerabilities:\n"
                    + "\n".join(
                        f"  [{f['cwe']}] {f['file']}:{f['source_line']}→{f['sink_line']}: {f['vuln']}"
                        for f in taint_findings[:10])
                ),
                reproduction_steps=["Review identified source→sink paths for input validation gaps"],
                remediation="Sanitize all user input at sink points. Use parameterized queries.",
                references=list({f["cwe"] for f in taint_findings[:5]}),
                evidence=ev, cvss_v31_vector=CVSS, cvss_v40_vector=CVSS40,
                target=target)

        return self._make_result(start)

class TestCodeFlow:
    def test_flows(self) -> None: assert len(TAINT_FLOWS) >= 5
    def test_phase(self) -> None: assert CodeFlow.PHASE == 11
