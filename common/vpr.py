"""VPR — Vulnerability Priority Rating.

Replaces raw CVSS for finding prioritization. Combines:
    - CVSS base score (60% weight)
    - Exploit maturity (20%): public PoC, KEV, weaponized
    - Impact adjustment (15%): RCE > auth bypass > info leak
    - Asset criticality (5%): DC, database, edge device

VPR = (CVSS_Base * 0.6) + (Exploit_Maturity * 0.2) + (Impact * 0.15) + (Asset * 0.05)

VPR ranges:
    8.0-10.0  Critical  → Fix within 24h
    5.0-7.9   High      → Fix within 7 days
    2.0-4.9   Medium    → Next sprint
    0.0-1.9   Low       → Backlog

Integrates with Intel Pipeline for real-time exploit availability checks.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any


class AssetCriticality(str, Enum):
    """Asset criticality tiers for VPR calculation."""
    CRITICAL = "critical"   # Domain controller, SCADA, HSM, payment system
    HIGH     = "high"       # Database server, API gateway, auth server
    MEDIUM   = "medium"     # Web server, app server, internal service
    LOW      = "low"        # Workstation, test host, printer
    UNKNOWN  = "unknown"    # Not tagged


class ExploitMaturity(str, Enum):
    """Exploit maturity tiers."""
    WEAPONIZED     = "weaponized"     # Active exploitation in the wild (KEV)
    FUNCTIONAL     = "functional"     # Public working PoC
    POC_ONLY       = "poc_only"       # Proof-of-concept only
    THEORETICAL    = "theoretical"    # No public exploit
    UNKNOWN        = "unknown"        # Not checked


@dataclass
class VPRScore:
    """VPR calculation result."""
    vpr:                float
    cvss_base:          float
    exploit_score:      float
    impact_score:       float
    asset_score:        float
    priority:           str
    recommended_sla:    str
    exploit_maturity:   ExploitMaturity
    asset_criticality:  AssetCriticality

    def to_dict(self) -> dict[str, Any]:
        return {
            "vpr": round(self.vpr, 2),
            "cvss_base": self.cvss_base,
            "exploit_score": self.exploit_score,
            "impact_score": self.impact_score,
            "asset_score": self.asset_score,
            "priority": self.priority,
            "recommended_sla": self.recommended_sla,
            "exploit_maturity": self.exploit_maturity.value,
            "asset_criticality": self.asset_criticality.value,
        }


# Exploit maturity scores (0-10)
_EXPLOIT_SCORES: dict[ExploitMaturity, float] = {
    ExploitMaturity.WEAPONIZED:   10.0,
    ExploitMaturity.FUNCTIONAL:    8.0,
    ExploitMaturity.POC_ONLY:      5.0,
    ExploitMaturity.THEORETICAL:   2.0,
    ExploitMaturity.UNKNOWN:       3.0,
}

# Asset criticality scores (0-10)
_ASSET_SCORES: dict[AssetCriticality, float] = {
    AssetCriticality.CRITICAL: 10.0,
    AssetCriticality.HIGH:      8.0,
    AssetCriticality.MEDIUM:    5.0,
    AssetCriticality.LOW:       2.0,
    AssetCriticality.UNKNOWN:   5.0,
}

# Impact type scores (0-10)
_IMPACT_SCORES: dict[str, float] = {
    "rce":             10.0,
    "code_execution":  10.0,
    "privilege_esc":    9.0,
    "sqli":             8.5,
    "auth_bypass":      8.0,
    "ssrf":             7.5,
    "xxe":              7.5,
    "deserialization":  7.5,
    "file_upload":      7.0,
    "lfi":              6.5,
    "cmdi":             9.0,
    "xss":              5.5,
    "csrf":             5.0,
    "open_redirect":    4.0,
    "info_leak":        4.0,
    "sensitive_data":   6.0,
    "dos":              5.5,
    "ssti":             8.0,
    "idor":             6.5,
    "path_traversal":   6.5,
    "default_creds":    9.0,
    "unauth_access":    8.5,
}


def calculate_vpr(
    cvss_base: float,
    vuln_type: str = "",
    exploit_maturity: ExploitMaturity = ExploitMaturity.UNKNOWN,
    asset_criticality: AssetCriticality = AssetCriticality.UNKNOWN,
    cve_id: str = "",
    has_public_exploit: bool = False,
    is_kev: bool = False,
) -> VPRScore:
    """Calculate VPR score for a finding.

    Args:
        cvss_base:          CVSS v3.1 or v4.0 base score (0-10).
        vuln_type:          Vulnerability type string (e.g., 'sqli', 'rce').
        exploit_maturity:   Known exploit availability.
        asset_criticality:  Target host criticality.
        cve_id:             CVE identifier for intel lookup.
        has_public_exploit: Shortcut flag — sets FUNCTIONAL if True.
        is_kev:             In CISA KEV → WEAPONIZED.

    Returns:
        VPRScore with full breakdown.
    """
    # Override exploit maturity from flags
    if is_kev:
        exploit_maturity = ExploitMaturity.WEAPONIZED
    elif has_public_exploit and exploit_maturity == ExploitMaturity.UNKNOWN:
        exploit_maturity = ExploitMaturity.FUNCTIONAL

    # Normalize CVSS to 0-10
    cvss = max(0.0, min(10.0, float(cvss_base)))

    # Exploit score
    exploit_score = _EXPLOIT_SCORES.get(exploit_maturity, 3.0)

    # Impact score from vuln type
    vt_clean = vuln_type.lower().replace("-", "_").replace(" ", "_")
    impact_score = _IMPACT_SCORES.get(vt_clean, cvss * 0.8)

    # Asset score
    asset_score = _ASSET_SCORES.get(asset_criticality, 5.0)

    # Weighted VPR formula
    vpr = (cvss * 0.6) + (exploit_score * 0.2) + (impact_score * 0.15) + (asset_score * 0.05)
    vpr = max(0.0, min(10.0, vpr))

    # Priority and SLA
    if vpr >= 8.0:
        priority = "Critical"
        sla = "Fix within 24h"
    elif vpr >= 5.0:
        priority = "High"
        sla = "Fix within 7 days"
    elif vpr >= 2.0:
        priority = "Medium"
        sla = "Fix in next sprint"
    else:
        priority = "Low"
        sla = "Backlog"

    return VPRScore(
        vpr=vpr,
        cvss_base=cvss,
        exploit_score=exploit_score,
        impact_score=impact_score,
        asset_score=asset_score,
        priority=priority,
        recommended_sla=sla,
        exploit_maturity=exploit_maturity,
        asset_criticality=asset_criticality,
    )


def vpr_from_finding(
    finding: dict[str, Any],
    asset_criticality: AssetCriticality = AssetCriticality.UNKNOWN,
    intel_engine: Any = None,
) -> VPRScore:
    """Calculate VPR directly from a finding dict.

    Extracts CVSS, vuln type, CVE, and optionally queries the intel
    engine for KEV status and exploit availability.

    Args:
        finding:          Finding dict (from EngagementBus or BaseModule).
        asset_criticality: Asset criticality tier.
        intel_engine:     Optional IntelEngine for CVE/KEV lookup.

    Returns:
        VPRScore.
    """
    cvss = float(finding.get("cvss_score") or finding.get("cvss") or 5.0)
    vuln_type = finding.get("vuln_type") or finding.get("type") or finding.get("category", "")
    cve_id = finding.get("cve_id") or finding.get("cve", "")

    exploit_maturity = ExploitMaturity.UNKNOWN
    is_kev = False
    has_exploit = False

    if intel_engine and cve_id:
        try:
            results = intel_engine.search(query=cve_id, limit=1)
            if results:
                cve_info = results[0] if isinstance(results[0], dict) else {}
                is_kev = cve_info.get("is_kev", False)
                has_exploit = cve_info.get("has_exploit", False)
        except Exception:
            pass

    return calculate_vpr(
        cvss_base=cvss,
        vuln_type=vuln_type,
        exploit_maturity=exploit_maturity,
        asset_criticality=asset_criticality,
        cve_id=cve_id,
        has_public_exploit=has_exploit,
        is_kev=is_kev,
    )


def sort_by_vpr(
    findings: list[dict[str, Any]],
    asset_criticality_map: dict[str, AssetCriticality] | None = None,
    intel_engine: Any = None,
) -> list[dict[str, Any]]:
    """Sort a list of findings by VPR score (highest first).

    Adds 'vpr_score' and 'vpr_priority' fields to each finding in place.

    Args:
        findings:               List of finding dicts.
        asset_criticality_map:  Map from host/target to AssetCriticality.
        intel_engine:           Optional intel engine for KEV/exploit data.

    Returns:
        Sorted findings list (mutated in place and returned).
    """
    if not findings:
        return findings

    asset_map = asset_criticality_map or {}

    for f in findings:
        target = f.get("target") or f.get("host", "")
        criticality = asset_map.get(target, AssetCriticality.UNKNOWN)
        score = vpr_from_finding(f, asset_criticality=criticality, intel_engine=intel_engine)
        f["vpr_score"] = round(score.vpr, 2)
        f["vpr_priority"] = score.priority
        f["vpr_sla"] = score.recommended_sla
        f["exploit_maturity"] = score.exploit_maturity.value

    return sorted(findings, key=lambda x: x.get("vpr_score", 0.0), reverse=True)
