"""Dangerous function usage tracer — eval, exec, system, shell_exec, etc."""
from __future__ import annotations

import re
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity

CVSS_CODE_EXEC   = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
CVSS_DESER       = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
CVSS_PATH_CONCAT = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
CVSS_SQL_RAW     = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:L"

DANGEROUS_PATTERNS: list[dict] = [
    {
        "name": "eval() usage",
        "pattern": r"\beval\s*\(",
        "languages": [".py", ".php", ".js", ".rb"],
        "severity": Severity.HIGH,
        "cvss": CVSS_CODE_EXEC,
        "cwe": "CWE-95",
        "description": "eval() executes arbitrary code from a string. If user input reaches eval(), it leads to Remote Code Execution.",
        "remediation": "Remove eval() entirely. Use safe alternatives: JSON.parse() for data, importlib for dynamic imports.",
    },
    {
        "name": "exec() usage",
        "pattern": r"\bexec\s*\(",
        "languages": [".py", ".php"],
        "severity": Severity.HIGH,
        "cvss": CVSS_CODE_EXEC,
        "cwe": "CWE-78",
        "description": "exec() runs OS commands or executes code strings. User-controlled input may lead to RCE.",
        "remediation": "Use subprocess with argument lists (no shell=True) for OS commands. Avoid exec() for code evaluation.",
    },
    {
        "name": "shell_exec()/system() in PHP",
        "pattern": r"\b(?:shell_exec|system|passthru|popen|proc_open|exec)\s*\(",
        "languages": [".php"],
        "severity": Severity.HIGH,
        "cvss": CVSS_CODE_EXEC,
        "cwe": "CWE-78",
        "description": "PHP shell execution functions may execute arbitrary OS commands if user input is unsanitized.",
        "remediation": "Avoid shell execution functions. If required, use escapeshellarg() and whitelist allowed commands.",
    },
    {
        "name": "subprocess with shell=True",
        "pattern": r"subprocess\.[^(]+\([^)]*shell\s*=\s*True",
        "languages": [".py"],
        "severity": Severity.HIGH,
        "cvss": CVSS_CODE_EXEC,
        "cwe": "CWE-78",
        "description": "subprocess(shell=True) interprets the command via the shell, enabling shell injection if user input is concatenated.",
        "remediation": "Use subprocess with shell=False and pass arguments as a list.",
    },
    {
        "name": "Pickle deserialization",
        "pattern": r"\bpickle\.loads?\s*\(",
        "languages": [".py"],
        "severity": Severity.HIGH,
        "cvss": CVSS_DESER,
        "cwe": "CWE-502",
        "description": "pickle.load() deserializes arbitrary Python objects, enabling RCE if the input is user-controlled.",
        "remediation": "Never deserialize untrusted pickle data. Use JSON or other safe formats.",
    },
    {
        "name": "yaml.load() without Loader",
        "pattern": r"\byaml\.load\s*\([^,)]+\)",
        "languages": [".py"],
        "severity": Severity.HIGH,
        "cvss": CVSS_DESER,
        "cwe": "CWE-502",
        "description": "yaml.load() without a SafeLoader can deserialize arbitrary Python objects, leading to RCE.",
        "remediation": "Use yaml.safe_load() or yaml.load(data, Loader=yaml.SafeLoader).",
    },
    {
        "name": "Raw SQL string concatenation",
        "pattern": r'(?:execute|cursor\.execute)\s*\(\s*["\'].*%s.*["\']',
        "languages": [".py", ".php", ".rb", ".js"],
        "severity": Severity.HIGH,
        "cvss": CVSS_SQL_RAW,
        "cwe": "CWE-89",
        "description": "SQL query built with string concatenation/formatting may be vulnerable to SQL injection.",
        "remediation": "Use parameterized queries / prepared statements exclusively.",
    },
    {
        "name": "Path traversal via string join",
        "pattern": r"os\.path\.join\s*\([^)]*request\.",
        "languages": [".py"],
        "severity": Severity.MEDIUM,
        "cvss": CVSS_PATH_CONCAT,
        "cwe": "CWE-22",
        "description": "User-controlled input passed to os.path.join() may enable path traversal.",
        "remediation": "Validate and normalize paths. Use Path.resolve() and assert result is within allowed base directory.",
    },
    {
        "name": "open() with user-controlled path",
        "pattern": r"\bopen\s*\(\s*(?:request|user|input|param)",
        "languages": [".py"],
        "severity": Severity.MEDIUM,
        "cvss": CVSS_PATH_CONCAT,
        "cwe": "CWE-73",
        "description": "open() with user-controlled filename may allow arbitrary file reads.",
        "remediation": "Whitelist allowed filenames. Resolve and validate paths before opening.",
    },
]

SOURCE_EXTENSIONS = [".py", ".php", ".js", ".ts", ".rb", ".java", ".go"]


class CodeFlow(BaseModule):
    """Dangerous function usage tracer for whitebox source analysis."""

    NAME        = "code_flow"
    DESCRIPTION = "Trace dangerous function usage (eval/exec/pickle/raw-SQL) in source code"
    PHASE       = 11
    TAGS        = ["whitebox", "code-flow", "sast", "owasp-a03", "cwe-95"]

    async def run(self) -> ModuleResult:
        """Scan source directory for dangerous function patterns."""
        start      = time.monotonic()
        target     = self.config.target.rstrip("/")
        source_dir = self.config.extra.get("source", "")

        if not self.check_scope(target):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        if not source_dir:
            self.log.warning("code_flow requires --source; skipping")
            return self._make_result(start, skipped=True, skip_reason="no source directory")

        src_path = Path(source_dir).expanduser().resolve()
        if not src_path.exists():
            return self._make_result(start, skipped=True, skip_reason="source dir not found")

        source_files = self._collect_source_files(src_path)
        self.log.info("Scanning %d source files", len(source_files))

        for sf in source_files:
            await self._scan_file(sf, target)

        return self._make_result(start)

    def _collect_source_files(self, root: Path) -> list[Path]:
        """Collect all source files with relevant extensions."""
        files: list[Path] = []
        for ext in SOURCE_EXTENSIONS:
            files.extend(root.rglob(f"*{ext}"))
        return files[:500]

    async def _scan_file(self, path: Path, target: str) -> None:
        """Scan a single source file for dangerous patterns."""
        ext = path.suffix.lower()
        try:
            content = path.read_text(errors="ignore")
            lines   = content.splitlines()
        except Exception:
            return

        for pattern_def in DANGEROUS_PATTERNS:
            # Only check if file extension is in scope for this pattern
            if pattern_def["languages"] and ext not in pattern_def["languages"]:
                continue

            matches = [
                (lineno + 1, line)
                for lineno, line in enumerate(lines)
                if re.search(pattern_def["pattern"], line)
            ]

            if not matches:
                continue

            lineno, line = matches[0]
            ev = Evidence(
                request_raw=f"Read {path}",
                response_raw=f"Line {lineno}: {line.strip()[:300]}",
                extra={
                    "file": str(path),
                    "line": lineno,
                    "pattern": pattern_def["name"],
                    "total_occurrences": len(matches),
                },
            )
            self.new_finding(
                title=f"[code-flow] {pattern_def['name']}: {path.name}:{lineno}",
                severity=pattern_def["severity"],
                description=(
                    f"{pattern_def['description']}\n\n"
                    f"File: {path}:{lineno}\n"
                    f"Total occurrences: {len(matches)}\n"
                    f"First match: {line.strip()[:200]}"
                ),
                reproduction_steps=[
                    f"Open {path}:{lineno}",
                    f"Review usage of: {pattern_def['name']}",
                ],
                remediation=pattern_def["remediation"],
                references=[pattern_def["cwe"], "OWASP A03:2021"],
                evidence=ev,
                cvss_v31_vector=pattern_def["cvss"],
                target=target,
            )


class TestCodeFlow:
    def test_dangerous_patterns_non_empty(self) -> None:
        assert len(DANGEROUS_PATTERNS) >= 6

    def test_each_pattern_has_cvss(self) -> None:
        for p in DANGEROUS_PATTERNS:
            assert p["cvss"].startswith("CVSS:3.1/")

    def test_source_extensions(self) -> None:
        assert ".py" in SOURCE_EXTENSIONS
        assert ".php" in SOURCE_EXTENSIONS
