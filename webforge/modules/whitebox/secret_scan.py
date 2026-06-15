"""Secret scanner — find hardcoded secrets in source code files."""
from __future__ import annotations

import asyncio
import re
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity

CVSS_SECRET = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"

# Secret patterns — (pattern, name, severity)
SECRET_PATTERNS: list[tuple[str, str, Severity]] = [
    (r"AKIA[0-9A-Z]{16}", "AWS Access Key ID", Severity.CRITICAL),
    (r"(?i)aws.{0,20}secret.{0,20}['\"][0-9A-Za-z/+=]{40}['\"]", "AWS Secret", Severity.CRITICAL),
    (r"sk_(live|test)_[0-9a-zA-Z]{24,}", "Stripe API Key", Severity.CRITICAL),
    (r"ghp_[0-9a-zA-Z]{36}", "GitHub Personal Access Token", Severity.CRITICAL),
    (r"gho_[0-9a-zA-Z]{36}", "GitHub OAuth Token", Severity.CRITICAL),
    (r"AIza[0-9A-Za-z\-_]{35}", "Google API Key", Severity.HIGH),
    (r"(?i)(password|passwd|pwd)\s*[=:]\s*['\"]([^'\"\s]{8,})['\"]", "Hardcoded Password", Severity.HIGH),
    (r"(?i)(api[_\-]?key|apikey)\s*[=:]\s*['\"]([a-zA-Z0-9_\-]{20,})['\"]", "API Key", Severity.HIGH),
    (r"(?i)(secret[_\-]?key|secretkey)\s*[=:]\s*['\"]([a-zA-Z0-9_\-]{16,})['\"]", "Secret Key", Severity.HIGH),
    (r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----", "Private Key", Severity.CRITICAL),
    (r"eyJ[a-zA-Z0-9_\-]+\.eyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+", "JWT Token", Severity.MEDIUM),
    (r"(?i)(db|database)[_\-]?(password|passwd|pwd)\s*[=:]\s*['\"]([^'\"\s]{4,})['\"]", "DB Password", Severity.CRITICAL),
    (r"(?i)private[_\-]?key\s*[=:]\s*['\"]([a-zA-Z0-9_\-/+=]{16,})['\"]", "Private Key (var)", Severity.HIGH),
    (r"xox[baprs]-[0-9]{12}-[0-9]{12}-[a-zA-Z0-9]{24}", "Slack Token", Severity.HIGH),
    (r"(?i)smtp[_\-]?(password|pass)\s*[=:]\s*['\"]([^'\"\s]{4,})['\"]", "SMTP Password", Severity.HIGH),
    (r"[a-zA-Z0-9+/]{88}={0,2}", "Possible base64 Secret (88 chars)", Severity.LOW),
]

# Files to skip (binary, vendored, etc.)
SKIP_EXTENSIONS = {
    ".jpg", ".jpeg", ".png", ".gif", ".ico", ".svg", ".woff", ".woff2",
    ".eot", ".ttf", ".otf", ".pdf", ".zip", ".tar", ".gz", ".jar",
    ".war", ".ear", ".class", ".pyc", ".pyo", ".so", ".dll", ".exe",
    ".min.js", ".map",
}

# High-priority files to scan
PRIORITY_FILES = [
    ".env", ".env.local", ".env.production", ".env.staging",
    "config.py", "settings.py", "config.js", "config.json",
    "application.properties", "application.yml", "database.yml",
    "credentials.json", "secrets.json", "secrets.yaml",
    "wp-config.php", "configuration.php",
]


class SecretScan(BaseModule):
    """Source code secret scanner for whitebox testing."""

    NAME        = "secret_scan"
    DESCRIPTION = "Scan source code files for hardcoded secrets and credentials"
    PHASE       = 11
    TAGS        = ["whitebox", "secrets", "credentials", "cwe-798", "cwe-312"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        target = self.config.target.rstrip("/")

        # Determine source directory
        source_dir = Path(self.config.extra.get("source_dir", "."))
        if not source_dir.exists():
            self.log.info("Source directory not found — secret scan skipped")
            return self._make_result(start, skipped=True, skip_reason="no source directory")

        self.log.info("Scanning secrets in %s", source_dir)
        await self._scan_directory(source_dir, target)

        return self._make_result(start)

    async def _scan_directory(self, source_dir: Path, target: str) -> None:
        """Walk directory and scan each file."""
        files_scanned = 0
        findings_count = 0

        for file_path in source_dir.rglob("*"):
            if not file_path.is_file():
                continue
            if any(file_path.suffix.lower() in SKIP_EXTENSIONS or
                   str(file_path).endswith(ext) for ext in SKIP_EXTENSIONS):
                continue
            if any(part in str(file_path) for part in
                   [".git", "node_modules", "vendor", "__pycache__", ".tox", "venv"]):
                continue

            # Skip large files (> 1MB)
            if file_path.stat().st_size > 1024 * 1024:
                continue

            findings_count += await self._scan_file(file_path, source_dir, target)
            files_scanned += 1

            if files_scanned % 100 == 0:
                await asyncio.sleep(0)  # Yield control

        self.log.info("Scanned %d files, found %d secret(s)", files_scanned, findings_count)

    async def _scan_file(
        self, file_path: Path, source_dir: Path, target: str
    ) -> int:
        count = 0
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
            is_priority = file_path.name in PRIORITY_FILES

            found_in_file: set[str] = set()
            for pattern, name, severity in SECRET_PATTERNS:
                for match in re.finditer(pattern, content):
                    if name in found_in_file:
                        continue
                    found_in_file.add(name)

                    # Get context around match
                    start_pos = max(0, match.start() - 40)
                    end_pos   = min(len(content), match.end() + 40)
                    context   = content[start_pos:end_pos].replace("\n", " ")

                    # Calculate line number
                    line_num = content[:match.start()].count("\n") + 1

                    relative_path = str(file_path.relative_to(source_dir))

                    ev = Evidence(
                        extra={
                            "file":    relative_path,
                            "line":    line_num,
                            "pattern": name,
                            "context": context[:80],
                            "match":   match.group()[:40],
                        }
                    )
                    self.new_finding(
                        title=f"Secret Found — {name} in {file_path.name}:{line_num}",
                        severity=severity if not is_priority else Severity.CRITICAL,
                        description=(
                            f"{name} found in {relative_path} at line {line_num}. "
                            f"Context: ...{context[:60]}..."
                        ),
                        reproduction_steps=[
                            f"grep -n '{pattern[:30]}' {relative_path}",
                        ],
                        remediation=(
                            "Remove hardcoded secrets immediately. "
                            "Use environment variables or secrets managers (HashiCorp Vault, AWS Secrets Manager). "
                            "Rotate any exposed credentials immediately. "
                            "Add .env to .gitignore — consider secret scanning in CI/CD."
                        ),
                        references=["CWE-798", "CWE-312", "OWASP A02:2021"],
                        evidence=ev,
                        cvss_v31_vector=CVSS_SECRET,
                        mitre_attack=["TA0006/T1552.001"],
                        target=target,
                    )
                    count += 1
        except Exception:
            pass
        return count


class TestSecretScan:
    def test_aws_key_pattern(self) -> None:
        pattern = "AKIA[0-9A-Z]{16}"
        test_key = "AKIAIOSFODNN7EXAMPLE"
        assert re.match(pattern, test_key)

    def test_private_key_pattern(self) -> None:
        content = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAK...\n-----END RSA PRIVATE KEY-----"
        pattern = "-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"
        assert re.search(pattern, content)

    def test_skip_extensions_set(self) -> None:
        assert ".jpg" in SKIP_EXTENSIONS
        assert ".pyc" in SKIP_EXTENSIONS
