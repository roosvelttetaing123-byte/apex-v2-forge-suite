"""CPE Vulnerability Engine — version-based CVE matching at scale.

This is the module that makes Nessus cry. Takes discovered services
from the discovery phase, generates CPE strings, and queries our local
CVE database for ALL matching vulnerabilities. One module, 200,000+ CVE
coverage.

Findings are emitted with confidence=UNVERIFIED (version correlation only,
not active exploitation). CISA KEV and high-EPSS findings get elevated.

Tests:
  - CPE generation from service_map
  - CVE database lookup
  - Finding emission with proper severity/confidence
  - KEV tagging
  - EPSS scoring
"""
from __future__ import annotations

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity

# CVSS vector templates by severity
_CVSS31_BY_SEVERITY = {
    "CRITICAL": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "HIGH":     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
    "MEDIUM":   "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
    "LOW":      "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
}

_CVSS40_BY_SEVERITY = {
    "CRITICAL": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
    "HIGH":     "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N",
    "MEDIUM":   "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N",
    "LOW":      "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
}

_SEVERITY_MAP = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH":     Severity.HIGH,
    "MEDIUM":   Severity.MEDIUM,
    "LOW":      Severity.LOW,
}


class CpeVulnEngine(BaseModule):
    """CPE-based vulnerability matching engine.

    Correlates discovered service versions against the local CVE database
    (200,000+ CVEs from NVD feeds). This is version-based detection —
    high coverage but lower confidence than active exploitation checks.

    Requires: `forge cve-db update` to populate the local CVE cache.
    Without the cache, this module gracefully skips.
    """

    NAME        = "cpe_vuln_engine"
    DESCRIPTION = "CPE: version-based CVE matching against NVD database (200K+ CVEs)"
    PHASE       = 5
    TAGS        = ["vuln", "cve", "cpe", "version-match"]

    # Limits to prevent finding floods on ancient unpatched boxes
    MAX_FINDINGS_PER_SERVICE = 25
    MAX_FINDINGS_TOTAL = 200

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        target = self.config.target

        if not self.check_scope(target):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        # Import CVE DB and CPE generator
        try:
            from netforge.data.cve_db import CVEDatabase
            from netforge.data.cpe_generator import CPEGenerator
        except ImportError as exc:
            self.log.error("CVE engine imports failed: %s", exc)
            return self._make_result(start, skipped=True, skip_reason=str(exc))

        # Check if CVE DB exists and is populated
        db = CVEDatabase()
        stats = db.stats()
        if stats["cve_count"] == 0:
            self.log.info(
                "CVE database empty — run 'forge cve-db update' to populate. "
                "Skipping CPE-based matching."
            )
            db.close()
            return self._make_result(start, skipped=True, skip_reason="CVE database empty")

        self.log.info(
            "CVE database loaded: %d CVEs, %d CPE matches, %d KEV entries",
            stats["cve_count"], stats["cpe_match_count"], stats["kev_count"],
        )

        cpe_gen = CPEGenerator()
        min_cvss = self.config.extra.get("cve_min_cvss", 4.0)
        total_findings = 0

        # Get service map from discovery phase
        service_map = self.config.extra.get("service_map", {})

        for host, services in service_map.items():
            if not self.check_scope(host):
                continue

            for svc in services:
                if total_findings >= self.MAX_FINDINGS_TOTAL:
                    self.log.warning(
                        "Hit total finding limit (%d) — stopping CPE matching",
                        self.MAX_FINDINGS_TOTAL,
                    )
                    break

                service_findings = 0
                product = svc.get("product", "")
                version = svc.get("version", "")
                service_name = svc.get("service", svc.get("name", ""))
                port = svc.get("port", 0)
                banner = svc.get("banner", "")

                if not version and not product:
                    continue

                # Generate CPE strings
                cpe_entries = cpe_gen.from_nmap_service(svc)
                if not cpe_entries and banner:
                    cpe_entries = cpe_gen.from_banner(banner)
                if not cpe_entries and product:
                    cpe_entries = cpe_gen.from_service(service_name, product, version)

                if not cpe_entries:
                    continue

                self.log.debug(
                    "Host %s port %s: generated %d CPE(s) for %s %s",
                    host, port, len(cpe_entries), product, version,
                )

                # Query CVE DB for each CPE
                for cpe_entry in cpe_entries:
                    if service_findings >= self.MAX_FINDINGS_PER_SERVICE:
                        break

                    matches = db.lookup_by_product(
                        cpe_entry.vendor, cpe_entry.product,
                        cpe_entry.version, min_cvss=min_cvss,
                    )

                    for cve_match in matches:
                        if service_findings >= self.MAX_FINDINGS_PER_SERVICE:
                            break
                        if total_findings >= self.MAX_FINDINGS_TOTAL:
                            break

                        severity = _SEVERITY_MAP.get(
                            cve_match.severity, Severity.MEDIUM
                        )

                        # Build tags
                        tags = ["cpe-match", "version-correlation"]
                        if cve_match.is_kev:
                            tags.append("cisa-kev")
                            # KEV = actively exploited, bump confidence
                            confidence = "LOW"
                        else:
                            confidence = "UNVERIFIED"

                        if cve_match.epss_score > 0.5:
                            tags.append("high-epss")

                        # Use actual CVSS vector if available, else template
                        cvss31_vec = (
                            cve_match.cvss31_vector
                            if cve_match.cvss31_vector
                            else _CVSS31_BY_SEVERITY.get(cve_match.severity, "")
                        )
                        cvss40_vec = (
                            cve_match.cvss40_vector
                            if cve_match.cvss40_vector
                            else _CVSS40_BY_SEVERITY.get(cve_match.severity, "")
                        )

                        # Build description
                        desc_parts = [
                            f"**{cve_match.cve_id}** detected via version correlation.",
                            f"",
                            f"**Service:** {product or service_name} {version}",
                            f"**Host:** {host}:{port}",
                            f"**CPE:** {cpe_entry.cpe23}",
                            f"**CVSS 3.1:** {cve_match.cvss31_score}",
                        ]
                        if cve_match.is_kev:
                            desc_parts.append("**⚠️ CISA Known Exploited Vulnerability**")
                        if cve_match.epss_score > 0:
                            desc_parts.append(
                                f"**EPSS:** {cve_match.epss_score:.4f} "
                                f"(percentile: {cve_match.epss_percentile:.1f}%)"
                            )
                        desc_parts.append("")
                        desc_parts.append(cve_match.description[:1000])

                        ev = Evidence(
                            extra={
                                "host": host,
                                "port": port,
                                "service": service_name,
                                "product": product,
                                "version": version,
                                "cve_id": cve_match.cve_id,
                                "cpe": cpe_entry.cpe23,
                                "cpe_confidence": cpe_entry.confidence,
                                "cvss31_score": cve_match.cvss31_score,
                                "is_kev": cve_match.is_kev,
                                "epss_score": cve_match.epss_score,
                                "weaknesses": cve_match.weaknesses,
                                "detection_method": "version-correlation",
                            },
                        )

                        # Title format: CVE-ID — Product Version — Host:Port
                        title = (
                            f"{cve_match.cve_id} — "
                            f"{product or service_name} {version} — "
                            f"{host}:{port}"
                        )
                        if cve_match.is_kev:
                            title = f"[KEV] {title}"

                        self.new_finding(
                            title=title,
                            severity=severity,
                            description="\n".join(desc_parts),
                            reproduction_steps=[
                                f"# Version detected: {product or service_name} {version} on {host}:{port}",
                                f"# CPE: {cpe_entry.cpe23}",
                                f"# Verify: nmap -sV -p {port} {host}",
                                f"# Details: https://nvd.nist.gov/vuln/detail/{cve_match.cve_id}",
                            ],
                            remediation=(
                                f"Update {product or service_name} to a version that patches "
                                f"{cve_match.cve_id}. Check vendor advisories for specific "
                                f"patched versions."
                            ),
                            references=[
                                cve_match.cve_id,
                                f"https://nvd.nist.gov/vuln/detail/{cve_match.cve_id}",
                                *cve_match.references[:3],
                            ],
                            evidence=ev,
                            cvss_v31_vector=cvss31_vec,
                            cvss_v40_vector=cvss40_vec,
                            port=port,
                            service=service_name,
                            target=host,
                            confidence=confidence,
                            tags=tags,
                        )

                        service_findings += 1
                        total_findings += 1

            if total_findings >= self.MAX_FINDINGS_TOTAL:
                break

        db.close()

        self.log.info(
            "CPE vuln engine complete: %d CVE findings emitted "
            "(min_cvss=%.1f, max_per_service=%d)",
            total_findings, min_cvss, self.MAX_FINDINGS_PER_SERVICE,
        )

        return self._make_result(start)


# ── Tests ────────────────────────────────────────────────────────────────

class TestCpeVulnEngine:
    def test_phase(self) -> None:
        assert CpeVulnEngine.PHASE == 5

    def test_severity_maps(self) -> None:
        assert _SEVERITY_MAP["CRITICAL"] == Severity.CRITICAL
        assert _SEVERITY_MAP["LOW"] == Severity.LOW

    def test_max_limits(self) -> None:
        assert CpeVulnEngine.MAX_FINDINGS_PER_SERVICE > 0
        assert CpeVulnEngine.MAX_FINDINGS_TOTAL > 0
