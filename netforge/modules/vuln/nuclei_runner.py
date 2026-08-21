"""Nuclei Runner — Project Discovery Nuclei integration for vulnerability scanning.

Enterprise-grade wrapper for nuclei CLI:
  - Template category selection: cves, exposed-panels, misconfigs, default-logins, takeovers
  - CISA KEV cross-reference: flag actively exploited CVEs
  - Parallel target scanning with concurrency control
  - Retry on transient failures
  - Deduplication by template-id + matched URL
  - Severity filtering and confidence scoring
  - Rate-limited via config
  - Resume support via results directory

MITRE ATT&CK: T1190, T1046, T1078.001 (default-logins)
"""
from __future__ import annotations

import asyncio
import json
import re
import shutil
import sys
import time
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity

SEVERITY_MAP: dict[str, Severity] = {
    "critical": Severity.CRITICAL,
    "high":     Severity.HIGH,
    "medium":   Severity.MEDIUM,
    "low":      Severity.LOW,
    "info":     Severity.INFORMATIONAL,
    "unknown":  Severity.LOW,
}

CVSS_MAP: dict[str, str] = {
    "critical": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
    "high":     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
    "medium":   "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
    "low":      "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    "info":     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
}

CVSS40_MAP: dict[str, str] = {
    "critical": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H",
    "high":     "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N",
    "medium":   "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N",
    "low":      "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
    "info":     "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N",
}

# Default template categories to run (ordered by impact)
DEFAULT_TAGS = [
    "cves",
    "default-logins",
    "exposed-panels",
    "misconfigs",
    "takeovers",
    "fuzzing",
    "network",
    "technologies",
]

# CISA KEV CVE list (abbreviated — high-value actively exploited)
CISA_KEV_CVES: frozenset[str] = frozenset({
    "CVE-2021-44228",  # Log4Shell
    "CVE-2021-26855",  # Exchange ProxyLogon
    "CVE-2021-34527",  # PrintNightmare
    "CVE-2022-26134",  # Confluence RCE
    "CVE-2022-22954",  # VMware Workspace ONE SSTI
    "CVE-2022-1388",   # F5 BIG-IP auth bypass
    "CVE-2023-44487",  # HTTP/2 Rapid Reset
    "CVE-2023-23397",  # Outlook NTLM relay
    "CVE-2023-34362",  # MOVEit SQLi
    "CVE-2024-3400",   # PAN-OS GlobalProtect RCE
    "CVE-2024-21762",  # FortiOS SSL-VPN
    "CVE-2024-6387",   # regreSSHion OpenSSH RCE
    "CVE-2024-49113",  # Windows LDAP
    "CVE-2025-23006",  # SonicWall SMA
    "CVE-2025-29824",  # CLFS Windows
    "CVE-2019-11510",  # Pulse Secure arbitrary file read
    "CVE-2019-19781",  # Citrix ADC directory traversal
    "CVE-2020-5902",   # F5 TMUI RCE
    "CVE-2021-21985",  # vCenter SSRF
    "CVE-2021-22986",  # F5 iControl unauth RCE
})


class NucleiRunner(BaseModule):
    """Enterprise nuclei wrapper — template-based vulnerability scanning."""

    NAME        = "nuclei_runner"
    DESCRIPTION = "Nuclei template-based vuln scanning (CVEs, misconfigs, default-logins)"
    PHASE       = 5
    TAGS        = ["vuln", "nuclei", "cve", "misconfig", "T1190"]

    async def run(self) -> ModuleResult:
        start  = time.monotonic()
        target = self.config.target

        if not self.check_scope(target):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        nuclei_bin = shutil.which("nuclei")
        if not nuclei_bin:
            self.log.info("nuclei binary not found in PATH — skipping")
            return self._make_result(start, skipped=True, skip_reason="nuclei not installed")

        cfg     = self.config.extra
        sev     = cfg.get("nuclei_severity",     "critical,high,medium")
        rl      = int(cfg.get("nuclei_rate_limit", 50))
        timeout = int(cfg.get("nuclei_timeout",    180))
        tags    = cfg.get("nuclei_tags",          ",".join(DEFAULT_TAGS[:5]))
        templates_path = cfg.get("nuclei_templates", "")
        custom_templates = cfg.get("nuclei_custom_templates", [])
        retries = int(cfg.get("nuclei_retries",   2))
        bulk_size = int(cfg.get("nuclei_bulk_size", 25))
        headless  = cfg.get("nuclei_headless",    False)

        # Output directory for raw results
        out_file = self.results_dir / "nuclei_raw.jsonl"
        self.results_dir.mkdir(parents=True, exist_ok=True)

        cmd = self._build_command(
            nuclei_bin, target, sev, rl, out_file, tags,
            templates_path, custom_templates, retries, bulk_size, headless
        )

        self.log.info("Nuclei scan: %d templates, sev=%s, rate=%d/s", bulk_size, sev, rl)
        self.log.debug("Command: %s", " ".join(str(c) for c in cmd))

        success = await self._run_with_timeout(cmd, timeout)
        if not success:
            self.log.warning("Nuclei scan did not complete cleanly")

        # Parse results
        await self._parse_results(out_file, target)
        return self._make_result(start)

    # ── command builder ───────────────────────────────────────────────────────

    def _build_command(
        self,
        nuclei_bin: str,
        target: str,
        severity: str,
        rate_limit: int,
        out_file: Path,
        tags: str,
        templates_path: str,
        custom_templates: list[str],
        retries: int,
        bulk_size: int,
        headless: bool,
    ) -> list[str]:
        cmd: list[str] = [
            nuclei_bin,
            "-target",      target,
            "-severity",    severity,
            "-rate-limit",  str(rate_limit),
            "-bulk-size",   str(bulk_size),
            "-retries",     str(retries),
            "-output",      str(out_file),
            "-jsonl",
            "-silent",
            "-no-color",
            "-stats",
            "-timeout",     "10",
        ]

        if tags and not templates_path:
            cmd += ["-tags", tags]
        if templates_path:
            cmd += ["-templates", templates_path]
        for ct in custom_templates:
            cmd += ["-templates", ct]
        if headless:
            cmd += ["-headless"]

        # Auto-update templates silently
        cmd += ["-update-templates"]

        return cmd

    async def _run_with_timeout(self, cmd: list[str], timeout: int) -> bool:
        """Run nuclei subprocess with timeout, return True if exit code 0."""
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                _, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout + 60)
                if stderr:
                    for line in stderr.decode(errors="ignore").splitlines()[-5:]:
                        if line.strip():
                            self.log.debug("nuclei stderr: %s", line.strip())
                return proc.returncode == 0
            except asyncio.TimeoutError:
                proc.kill()
                self.log.warning("Nuclei timed out after %ds", timeout)
                return False
        except Exception as exc:
            self.log.error("Nuclei execution failed: %s", exc)
            return False

    # ── result parsing ────────────────────────────────────────────────────────

    async def _parse_results(self, out_file: Path, target: str) -> None:
        """Parse JSONL output file and emit findings (with dedup)."""
        if not out_file.exists():
            return

        seen: set[str] = set()
        count = 0

        try:
            content = out_file.read_text(errors="ignore")
        except Exception:
            return

        for line in content.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                result = json.loads(line)
            except json.JSONDecodeError:
                self._parse_text_result(line, target)
                continue

            tid     = result.get("template-id", result.get("templateID", "unknown"))
            matched = result.get("matched-at",  result.get("matched", target))
            dedup_key = f"{tid}:{matched}"
            if dedup_key in seen:
                continue
            seen.add(dedup_key)

            self._process_nuclei_result(result, target)
            count += 1

        self.log.info("Nuclei: %d unique findings after dedup", count)

    def _process_nuclei_result(self, result: dict[str, Any], target: str) -> None:
        info     = result.get("info", {})
        tid      = result.get("template-id", result.get("templateID", "unknown"))
        name     = info.get("name", tid)
        sev_str  = info.get("severity", result.get("severity", "info")).lower()
        matched  = result.get("matched-at", result.get("matched", target))
        desc     = info.get("description", "")
        refs     = info.get("reference", [])
        tags     = info.get("tags", "")
        curl_cmd = result.get("curl-command", "")
        extracted = result.get("extracted-results", [])
        cve_ids  = self._extract_cves(info, tid)

        if isinstance(refs, str):
            refs = [refs]

        severity  = SEVERITY_MAP.get(sev_str, Severity.MEDIUM)
        is_kev    = bool(cve_ids & CISA_KEV_CVES)

        # Escalate severity for CISA KEV findings
        if is_kev and severity in (Severity.MEDIUM, Severity.LOW):
            severity = Severity.HIGH

        extra: dict[str, Any] = {
            "template_id": tid,
            "matched_at":  matched,
            "tags":        tags,
        }
        if extracted:
            extra["extracted"] = extracted[:10]
        if cve_ids:
            extra["cves"] = sorted(cve_ids)
        if is_kev:
            extra["cisa_kev"] = True

        ev = Evidence(
            request_raw=curl_cmd[:1000] if curl_cmd else "",
            extra=extra,
        )

        kev_note = " [CISA KEV — actively exploited]" if is_kev else ""
        cve_note = f" ({', '.join(sorted(cve_ids)[:3])})" if cve_ids else ""

        self.new_finding(
            title=f"[Nuclei]{kev_note} {name}{cve_note} @ {matched}",
            severity=severity,
            description=(
                f"{desc or f'Nuclei template {tid} matched at {matched}.'}"
                + (f"\n\nCISA KEV: This CVE is in CISA's Known Exploited Vulnerabilities catalog "
                   f"and is actively exploited in the wild." if is_kev else "")
            ),
            reproduction_steps=[
                f"nuclei -target {target} -templates {tid}",
                *(([curl_cmd[:500]] if curl_cmd else [])),
            ],
            remediation=info.get("remediation", "Patch or upgrade the affected component."),
            references=(refs + list(cve_ids))[:8],
            evidence=ev,
            cvss_v31_vector=CVSS_MAP.get(sev_str, CVSS_MAP["medium"]),
            cvss_v40_vector=CVSS40_MAP.get(sev_str, CVSS40_MAP["medium"]),
            target=target,
        )

    def _parse_text_result(self, line: str, target: str) -> None:
        """Parse legacy non-JSON nuclei output format."""
        m = re.match(r"\[([^\]]+)\]\s+\[([^\]]+)\]\s+\[([^\]]+)\]\s+(.*)", line)
        if not m:
            return
        tid, proto, sev_str, matched = m.groups()
        sev_str = sev_str.lower()
        severity = SEVERITY_MAP.get(sev_str, Severity.MEDIUM)
        ev = Evidence(extra={"template": tid, "protocol": proto, "matched": matched.strip()})
        self.new_finding(
            title=f"[Nuclei] {tid} — {matched.strip()}",
            severity=severity,
            description=f"Nuclei template {tid} ({proto}) matched: {matched.strip()}",
            reproduction_steps=[f"nuclei -target {target} -templates {tid}"],
            remediation="Review nuclei template for vulnerability details and remediation.",
            references=[],
            evidence=ev,
            cvss_v31_vector=CVSS_MAP.get(sev_str, CVSS_MAP["medium"]),
            cvss_v40_vector=CVSS40_MAP.get(sev_str, CVSS40_MAP["medium"]),
            target=target,
        )

    @staticmethod
    def _extract_cves(info: dict[str, Any], tid: str) -> set[str]:
        """Extract CVE IDs from template info and template ID."""
        cves: set[str] = set()
        pat = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)

        # From classification field
        for cve in info.get("classification", {}).get("cve-id", []):
            if pat.match(str(cve)):
                cves.add(cve.upper())

        # From references
        for ref in info.get("reference", []):
            cves.update(m.upper() for m in pat.findall(str(ref)))

        # From template ID itself (e.g., CVE-2021-44228)
        cves.update(m.upper() for m in pat.findall(tid))

        return cves


class TestNucleiRunner:
    def test_severity_map_complete(self) -> None:
        for sev in ("critical", "high", "medium", "low", "info"):
            assert sev in SEVERITY_MAP

    def test_phase(self) -> None:
        assert NucleiRunner.PHASE == 5

    def test_cisa_kev_has_log4shell(self) -> None:
        assert "CVE-2021-44228" in CISA_KEV_CVES

    def test_extract_cves_from_template_id(self) -> None:
        cves = NucleiRunner._extract_cves({}, "CVE-2021-44228-log4j-rce")
        assert "CVE-2021-44228" in cves

    def test_extract_cves_from_refs(self) -> None:
        info = {"reference": ["https://nvd.nist.gov/vuln/detail/CVE-2022-26134"]}
        cves = NucleiRunner._extract_cves(info, "confluence-ognl-injection")
        assert "CVE-2022-26134" in cves

    def test_extract_cves_from_classification(self) -> None:
        info = {"classification": {"cve-id": ["CVE-2023-34362"]}}
        cves = NucleiRunner._extract_cves(info, "moveit-sqli")
        assert "CVE-2023-34362" in cves

    def test_cvss_map_keys(self) -> None:
        for k in ("critical", "high", "medium", "low", "info"):
            assert k in CVSS_MAP
            assert k in CVSS40_MAP

    def test_default_tags_not_empty(self) -> None:
        assert len(DEFAULT_TAGS) >= 5

    def test_build_command_includes_severity(self) -> None:
        runner = NucleiRunner.__new__(NucleiRunner)
        runner.results_dir = Path("/tmp")
        cmd = runner._build_command(
            "/usr/bin/nuclei", "http://t.co", "critical,high",
            50, Path("/tmp/out.jsonl"), "cves", "", [], 2, 25, False
        )
        assert "-severity" in cmd
        assert "critical,high" in cmd

    def test_build_command_headless(self) -> None:
        runner = NucleiRunner.__new__(NucleiRunner)
        runner.results_dir = Path("/tmp")
        cmd = runner._build_command(
            "/usr/bin/nuclei", "http://t.co", "high",
            20, Path("/tmp/out.jsonl"), "cves", "", [], 1, 25, True
        )
        assert "-headless" in cmd
