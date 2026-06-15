"""Configuration file security audit — env, yaml, json, ini files."""
from __future__ import annotations

import re
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity

CVSS_HARDCODED_SECRET = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
CVSS_DEBUG_ENABLED    = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
CVSS_WEAK_TLS         = "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N"
CVSS_PERMISSIVE_CORS  = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N"

SECRET_PATTERNS: list[tuple[str, str]] = [
    (r'(?i)password\s*[=:]\s*["\']?([^\s"\']{6,})', "Hardcoded password"),
    (r'(?i)secret(?:_key)?\s*[=:]\s*["\']?([^\s"\']{8,})', "Hardcoded secret"),
    (r'(?i)api[_-]?key\s*[=:]\s*["\']?([A-Za-z0-9\-_]{16,})', "Hardcoded API key"),
    (r'(?i)(?:access|private)[_-]?token\s*[=:]\s*["\']?([^\s"\']{8,})', "Hardcoded token"),
    (r'(?i)aws[_-]?(?:access[_-]?key|secret)\s*[=:]\s*["\']?([A-Z0-9]{16,})', "AWS credential"),
    (r'-----BEGIN (?:RSA )?PRIVATE KEY-----', "Private key in file"),
    (r'(?i)db[_-]?(?:password|pass)\s*[=:]\s*["\']?([^\s"\']{4,})', "DB password"),
]

DEBUG_PATTERNS: list[tuple[str, str]] = [
    (r'(?i)debug\s*[=:]\s*(?:true|1|yes|on)', "Debug mode enabled"),
    (r'(?i)display_errors\s*=\s*(?:On|1|true)', "PHP error display enabled"),
    (r'(?i)DJANGO_DEBUG\s*=\s*True', "Django debug mode"),
]

CONFIG_EXTENSIONS = [".env", ".yaml", ".yml", ".json", ".ini", ".conf",
                     ".cfg", ".properties", ".xml", ".toml"]


class ConfigAudit(BaseModule):
    """Configuration file auditor — secrets, debug flags, TLS settings."""

    NAME        = "config_audit"
    DESCRIPTION = "Audit config files for hardcoded secrets, debug flags, weak TLS/crypto settings"
    PHASE       = 11
    TAGS        = ["whitebox", "config", "secrets", "owasp-a02", "cwe-312"]

    async def run(self) -> ModuleResult:
        """Scan source/config directory for security misconfigurations."""
        start      = time.monotonic()
        target     = self.config.target.rstrip("/")
        source_dir = self.config.extra.get("source", "")

        if not self.check_scope(target):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        if not source_dir:
            self.log.warning("config_audit requires --source; skipping")
            return self._make_result(start, skipped=True, skip_reason="no source directory")

        src_path = Path(source_dir).expanduser().resolve()
        if not src_path.exists():
            return self._make_result(start, skipped=True, skip_reason="source dir not found")

        config_files = self._collect_config_files(src_path)
        self.log.info("Auditing %d config files in %s", len(config_files), src_path)

        for cf in config_files:
            await self._audit_file(cf, target)

        return self._make_result(start)

    def _collect_config_files(self, root: Path) -> list[Path]:
        """Collect all config files recursively."""
        files: list[Path] = []
        for ext in CONFIG_EXTENSIONS:
            files.extend(root.rglob(f"*{ext}"))
        # Also explicitly named files
        for name in [".env", ".env.local", ".env.production", "secrets.yaml"]:
            explicit = root / name
            if explicit.exists() and explicit not in files:
                files.append(explicit)
        return files[:200]  # cap at 200 files

    async def _audit_file(self, path: Path, target: str) -> None:
        """Audit a single config file for security issues."""
        try:
            content = path.read_text(errors="ignore")
        except Exception as exc:
            self.log.debug("Cannot read %s: %s", path, exc)
            return

        lines = content.splitlines()

        # Secret patterns
        for pattern, label in SECRET_PATTERNS:
            for lineno, line in enumerate(lines, start=1):
                m = re.search(pattern, line)
                if m:
                    value = m.group(0)[:80]
                    ev = Evidence(
                        request_raw=f"Read file: {path}",
                        response_raw=f"Line {lineno}: {line.strip()[:200]}",
                        extra={"file": str(path), "line": lineno, "pattern": label},
                    )
                    self.new_finding(
                        title=f"[config] {label} in {path.name}:{lineno}",
                        severity=Severity.HIGH,
                        description=(
                            f"A potential {label} was found in configuration file "
                            f"'{path}' at line {lineno}. "
                            "Hardcoded credentials in config files may be exposed via "
                            "version control or file disclosure vulnerabilities."
                        ),
                        reproduction_steps=[
                            f"Read {path}",
                            f"Inspect line {lineno}: {line.strip()[:100]}",
                        ],
                        remediation=(
                            "Move secrets to a secrets manager (Vault, AWS Secrets Manager). "
                            "Use environment variables injected at runtime. "
                            "Add *.env and secrets.yaml to .gitignore."
                        ),
                        references=["CWE-312", "CWE-798", "OWASP A02:2021"],
                        evidence=ev,
                        cvss_v31_vector=CVSS_HARDCODED_SECRET,
                        target=target,
                    )
                    break  # one finding per file per pattern type

        # Debug flags
        for pattern, label in DEBUG_PATTERNS:
            if re.search(pattern, content):
                ev = Evidence(
                    request_raw=f"Read file: {path}",
                    response_raw=content[:300],
                    extra={"file": str(path), "pattern": label},
                )
                self.new_finding(
                    title=f"[config] {label} in {path.name}",
                    severity=Severity.MEDIUM,
                    description=(
                        f"'{label}' detected in {path}. "
                        "Debug mode in production exposes stack traces, "
                        "configuration details, and internal paths to users."
                    ),
                    reproduction_steps=[
                        f"Read {path}",
                        f"Search for debug=true or equivalent",
                    ],
                    remediation=(
                        "Disable debug mode in production configuration. "
                        "Use separate config files per environment (dev/staging/prod)."
                    ),
                    references=["CWE-200", "OWASP A05:2021"],
                    evidence=ev,
                    cvss_v31_vector=CVSS_DEBUG_ENABLED,
                    target=target,
                )

        # Weak TLS/crypto settings
        weak_tls = re.search(r"(?i)(ssl_?version|tlsv1[^23]|sslv[23]|TLSv1\b)", content)
        if weak_tls:
            ev = Evidence(
                request_raw=f"Read file: {path}",
                response_raw=weak_tls.group(0),
                extra={"file": str(path), "match": weak_tls.group(0)},
            )
            self.new_finding(
                title=f"[config] Weak TLS Version in {path.name}",
                severity=Severity.HIGH,
                description=(
                    f"Configuration file '{path}' references a weak TLS version "
                    f"({weak_tls.group(0)}). TLS 1.0 and 1.1 are deprecated and "
                    "vulnerable to BEAST, POODLE, and other attacks."
                ),
                reproduction_steps=[
                    f"Read {path}",
                    f"Search for: {weak_tls.group(0)}",
                ],
                remediation=(
                    "Use TLS 1.2 minimum, prefer TLS 1.3. "
                    "Remove explicit version pins for old protocols."
                ),
                references=["CWE-326", "CWE-327", "OWASP A02:2021"],
                evidence=ev,
                cvss_v31_vector=CVSS_WEAK_TLS,
                target=target,
            )


class TestConfigAudit:
    def test_secret_patterns_non_empty(self) -> None:
        assert len(SECRET_PATTERNS) >= 5

    def test_config_extensions_includes_env(self) -> None:
        assert ".env" in CONFIG_EXTENSIONS

    def test_cvss_vectors(self) -> None:
        for v in (CVSS_HARDCODED_SECRET, CVSS_DEBUG_ENABLED, CVSS_WEAK_TLS, CVSS_PERMISSIVE_CORS):
            assert v.startswith("CVSS:3.1/")
