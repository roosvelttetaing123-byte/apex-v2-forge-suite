"""Config Audit — scan for exposed configuration files and misconfigurations."""
from __future__ import annotations
import re, sys, time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))
from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity
from common.fp_reducer import FPReducer, Confidence
import aiohttp

CVSS = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
CVSS40 = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N"

CONFIG_PATHS = [
    ("/.env", "Environment variables"),
    ("/.env.production", "Production env"),
    ("/config.json", "JSON config"),
    ("/config.yml", "YAML config"),
    ("/application.properties", "Spring Boot config"),
    ("/application.yml", "Spring Boot YAML"),
    ("/appsettings.json", "ASP.NET config"),
    ("/wp-config.php.bak", "WordPress config backup"),
    ("/settings.py", "Django settings"),
    ("/database.yml", "Rails database config"),
    ("/.npmrc", "NPM config (may contain tokens)"),
    ("/.dockerenv", "Docker environment"),
    ("/Dockerfile", "Docker build file"),
    ("/docker-compose.yml", "Docker compose"),
]

SECRET_PATTERNS = [
    (r'(?:password|passwd|pwd)\s*[=:]\s*["\']?(\S{3,})', "password"),
    (r'(?:api[_-]?key|apikey)\s*[=:]\s*["\']?(\S{8,})', "api_key"),
    (r'(?:secret|token)\s*[=:]\s*["\']?(\S{8,})', "secret/token"),
    (r'(?:aws_access_key_id)\s*[=:]\s*["\']?(AKIA\S+)', "aws_key"),
    (r'(?:PRIVATE KEY-----)', "private_key"),
    (r'(?:mongodb|mysql|postgres|redis)://\S+:\S+@', "connection_string"),
]

class ConfigAudit(BaseModule):
    NAME = "config_audit"
    DESCRIPTION = "Whitebox: scan for exposed configs, secrets, and misconfigurations"
    PHASE = 11
    TAGS = ["whitebox", "config", "cwe-312"]

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
            exposed_configs = []
            secrets_found = []

            for path, desc in CONFIG_PATHS:
                await self.rate_limit()
                try:
                    async with session.get(f"{target}{path}") as resp:
                        if resp.status == 200:
                            body = await resp.text(errors="ignore")
                            if len(body) > 10 and "404" not in body[:100].lower() and "<html" not in body[:200].lower():
                                exposed_configs.append({"path": path, "desc": desc, "size": len(body)})

                                # Scan for secrets
                                for pattern, secret_type in SECRET_PATTERNS:
                                    for m in re.finditer(pattern, body, re.I):
                                        value = m.group(1) if m.lastindex else m.group(0)
                                        if value not in ("example", "changeme", "xxx", "null"):
                                            secrets_found.append({
                                                "file": path,
                                                "type": secret_type,
                                                "preview": value[:8] + "***",
                                            })
                except Exception:
                    pass

            if exposed_configs:
                ev = Evidence(extra={"configs": exposed_configs, "secrets": len(secrets_found)})
                self.new_finding(
                    title=f"Exposed Configuration Files — {len(exposed_configs)} file(s)",
                    severity=Severity.HIGH if secrets_found else Severity.MEDIUM,
                    description=(
                        f"Publicly accessible configuration files:\n"
                        + "\n".join(f"  {target}{c['path']} ({c['desc']}, {c['size']}B)" for c in exposed_configs[:10])
                        + (f"\n\n{len(secrets_found)} secret(s) found in configs." if secrets_found else "")
                    ),
                    reproduction_steps=[f"curl {target}{exposed_configs[0]['path']}"],
                    remediation="Block access to all configuration files. Move configs outside webroot.",
                    references=["CWE-312", "CWE-538"],
                    evidence=ev, cvss_v31_vector=CVSS, cvss_v40_vector=CVSS40,
                    target=target)

            if secrets_found:
                # Deduplicate
                seen = set()
                unique = []
                for s in secrets_found:
                    key = f"{s['type']}:{s['preview']}"
                    if key not in seen:
                        seen.add(key)
                        unique.append(s)

                ev = Evidence(extra={"secrets": unique[:20]})
                self.new_finding(
                    title=f"Secrets in Config Files — {len(unique)} credential(s)",
                    severity=Severity.CRITICAL,
                    description=(
                        f"Credentials/secrets found in exposed configs:\n"
                        + "\n".join(f"  [{s['type']}] {s['file']}: {s['preview']}" for s in unique[:10])
                    ),
                    reproduction_steps=[f"curl {target}{unique[0]['file']}"],
                    remediation="Rotate ALL exposed credentials immediately. Remove configs from webroot.",
                    references=["CWE-798", "CWE-312"],
                    evidence=ev, cvss_v31_vector=CVSS, cvss_v40_vector=CVSS40,
                    target=target)

        return self._make_result(start)

class TestConfigAudit:
    def test_paths(self) -> None: assert len(CONFIG_PATHS) >= 10
    def test_phase(self) -> None: assert ConfigAudit.PHASE == 11
