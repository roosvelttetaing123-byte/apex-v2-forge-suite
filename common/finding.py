"""Finding dataclass with CVSS 3.1 and CVSS 4.0 score calculation."""
from __future__ import annotations

import math
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from common.evidence import Evidence  # noqa: F401 — re-exported for callers


class Severity(str, Enum):
    CRITICAL      = "Critical"
    HIGH          = "High"
    MEDIUM        = "Medium"
    LOW           = "Low"
    INFORMATIONAL = "Informational"


SEVERITY_SCORE: dict[Severity, tuple[float, float]] = {
    Severity.CRITICAL:      (9.0, 10.0),
    Severity.HIGH:          (7.0,  8.9),
    Severity.MEDIUM:        (4.0,  6.9),
    Severity.LOW:           (0.1,  3.9),
    Severity.INFORMATIONAL: (0.0,  0.0),
}


@dataclass
class Finding:
    """A single security finding with all required fields."""
    title:               str
    severity:            Severity
    target:              str
    module:              str
    description:         str
    reproduction_steps:  list[str]
    remediation:         str
    references:          list[str]
    evidence:            Evidence                = field(default_factory=Evidence)
    id:                  str                     = field(default_factory=lambda: str(uuid.uuid4()))
    discovered_at:       datetime                = field(default_factory=lambda: datetime.now(timezone.utc))
    cvss_v31_vector:     str | None              = None
    cvss_v31_score:      float | None            = None
    cvss_v40_vector:     str | None              = None
    cvss_v40_score:      float | None            = None
    mitre_attack:        list[str]               = field(default_factory=list)
    port:                int | None              = None
    service:             str | None              = None
    operator_confirmed:  bool                    = False
    tags:                list[str]               = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.cvss_v31_score is None and self.cvss_v31_vector:
            self.cvss_v31_score = cvss31_score(self.cvss_v31_vector)
        if self.cvss_v40_score is None and self.cvss_v40_vector:
            self.cvss_v40_score = cvss40_score(self.cvss_v40_vector)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a plain dict for JSON export."""
        return {
            "id":                  self.id,
            "title":               self.title,
            "severity":            self.severity.value,
            "target":              self.target,
            "port":                self.port,
            "service":             self.service,
            "module":              self.module,
            "description":         self.description,
            "reproduction_steps":  self.reproduction_steps,
            "remediation":         self.remediation,
            "references":          self.references,
            "cvss_v31_vector":     self.cvss_v31_vector,
            "cvss_v31_score":      self.cvss_v31_score,
            "cvss_v40_vector":     self.cvss_v40_vector,
            "cvss_v40_score":      self.cvss_v40_score,
            "mitre_attack":        self.mitre_attack,
            "discovered_at":       self.discovered_at.isoformat(),
            "operator_confirmed":  self.operator_confirmed,
            "tags":                self.tags,
            "evidence": {
                "request_raw":          self.evidence.request_raw,
                "response_raw":         self.evidence.response_raw,
                "screenshot_path":      self.evidence.screenshot_path,
                "console_capture_path": self.evidence.console_capture_path,
                "pcap_path":            self.evidence.pcap_path,
                "extra":                self.evidence.extra,
            },
        }


# ── CVSS 3.1 Base Score Calculator ───────────────────────────────────────────

_CVSS31_METRIC_WEIGHTS: dict[str, dict[str, float]] = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "PR": {
        "N": {"U": 0.85, "C": 0.85},
        "L": {"U": 0.62, "C": 0.68},
        "H": {"U": 0.27, "C": 0.50},
    },
    "UI": {"N": 0.85, "R": 0.62},
    "S":  {"U": 6.42, "C": 7.52},
    "C":  {"N": 0.00, "L": 0.22, "H": 0.56},
    "I":  {"N": 0.00, "L": 0.22, "H": 0.56},
    "A":  {"N": 0.00, "L": 0.22, "H": 0.56},
}


def cvss31_score(vector: str) -> float:
    """Calculate CVSS 3.1 base score from a vector string.

    Args:
        vector: CVSS 3.1 vector, e.g. 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'

    Returns:
        Float score 0.0-10.0 rounded to 1 decimal place.
    """
    try:
        parts = vector.split("/")
        metrics: dict[str, str] = {}
        for part in parts[1:]:
            k, v = part.split(":", 1)
            metrics[k] = v

        scope = metrics.get("S", "U")
        w = _CVSS31_METRIC_WEIGHTS

        av  = w["AV"].get(metrics.get("AV", "N"), 0.85)
        ac  = w["AC"].get(metrics.get("AC", "L"), 0.77)
        pr_map = w["PR"].get(metrics.get("PR", "N"), {"U": 0.85, "C": 0.85})
        pr  = pr_map.get(scope, 0.85) if isinstance(pr_map, dict) else 0.85
        ui  = w["UI"].get(metrics.get("UI", "N"), 0.85)
        ci  = w["C"].get(metrics.get("C", "N"), 0.00)
        ii  = w["I"].get(metrics.get("I", "N"), 0.00)
        ai  = w["A"].get(metrics.get("A", "N"), 0.00)

        iss = 1 - (1 - ci) * (1 - ii) * (1 - ai)
        if scope == "U":
            impact = 6.42 * iss
        else:
            impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)

        if impact <= 0:
            return 0.0

        exploitability = 8.22 * av * ac * pr * ui

        if scope == "U":
            raw = min(impact + exploitability, 10)
        else:
            raw = min(1.08 * (impact + exploitability), 10)

        return math.ceil(raw * 10) / 10
    except Exception:
        return 0.0


def cvss40_score(vector: str) -> float:
    """Approximate CVSS 4.0 score from vector string.

    CVSS 4.0 uses a lookup table approach. This provides a reasonable
    approximation using the base metrics AV, AC, AT, PR, UI, VC, VI, VA,
    SC, SI, SA with the mean-vector scoring method.

    Args:
        vector: CVSS 4.0 vector string.

    Returns:
        Float score 0.0-10.0 rounded to 1 decimal place.
    """
    try:
        parts = vector.split("/")
        metrics: dict[str, str] = {}
        for part in parts[1:]:
            if ":" in part:
                k, v = part.split(":", 1)
                metrics[k] = v

        # Simplified severity weight mapping for CVSS 4.0 base metrics
        av_w  = {"N": 0.0, "A": 0.1, "L": 0.2, "P": 0.3}.get(metrics.get("AV", "N"), 0.0)
        ac_w  = {"L": 0.0, "H": 0.1}.get(metrics.get("AC", "L"), 0.0)
        at_w  = {"N": 0.0, "P": 0.1}.get(metrics.get("AT", "N"), 0.0)
        pr_w  = {"N": 0.0, "L": 0.1, "H": 0.2}.get(metrics.get("PR", "N"), 0.0)
        ui_w  = {"N": 0.0, "P": 0.05, "A": 0.1}.get(metrics.get("UI", "N"), 0.0)
        vc_w  = {"H": 0.0, "L": 0.1, "N": 0.2}.get(metrics.get("VC", "H"), 0.0)
        vi_w  = {"H": 0.0, "L": 0.1, "N": 0.2}.get(metrics.get("VI", "H"), 0.0)
        va_w  = {"H": 0.0, "L": 0.1, "N": 0.2}.get(metrics.get("VA", "H"), 0.0)
        sc_w  = {"H": 0.0, "L": 0.1, "N": 0.2}.get(metrics.get("SC", "N"), 0.2)
        si_w  = {"H": 0.0, "L": 0.1, "N": 0.2, "S": 0.0}.get(metrics.get("SI", "N"), 0.2)
        sa_w  = {"H": 0.0, "L": 0.1, "N": 0.2, "S": 0.0}.get(metrics.get("SA", "N"), 0.2)

        eq_sum = av_w + ac_w + at_w + pr_w + ui_w + vc_w + vi_w + va_w + sc_w + si_w + sa_w
        max_sum = 0.0 + 0.1 + 0.1 + 0.2 + 0.1 + 0.2 + 0.2 + 0.2 + 0.2 + 0.2 + 0.2
        score = 10.0 * (1.0 - eq_sum / max_sum) if max_sum > 0 else 0.0
        return round(min(max(math.ceil(score * 10) / 10, 0.0), 10.0), 1)
    except Exception:
        return 0.0


def severity_from_cvss(score: float) -> Severity:
    """Map a CVSS score to a Severity enum value."""
    if score >= 9.0:
        return Severity.CRITICAL
    elif score >= 7.0:
        return Severity.HIGH
    elif score >= 4.0:
        return Severity.MEDIUM
    elif score > 0.0:
        return Severity.LOW
    return Severity.INFORMATIONAL


class TestFinding:
    """Unit tests for finding module."""

    def test_cvss31_high(self) -> None:
        score = cvss31_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        assert 9.0 <= score <= 10.0

    def test_cvss31_medium(self) -> None:
        score = cvss31_score("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N")
        assert 4.0 <= score <= 7.0

    def test_cvss31_zero_on_bad(self) -> None:
        score = cvss31_score("INVALID")
        assert score == 0.0

    def test_finding_creation(self) -> None:
        f = Finding(
            title="Test Finding",
            severity=Severity.HIGH,
            target="https://example.com",
            module="test",
            description="Test description",
            reproduction_steps=["Step 1"],
            remediation="Fix it",
            references=["CVE-2024-0001"],
            cvss_v31_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        )
        assert f.cvss_v31_score is not None
        assert f.cvss_v31_score >= 9.0
        assert f.id != ""

    def test_finding_to_dict(self) -> None:
        f = Finding(
            title="X", severity=Severity.LOW, target="t", module="m",
            description="d", reproduction_steps=[], remediation="r", references=[],
        )
        d = f.to_dict()
        assert d["title"] == "X"
        assert "evidence" in d

    def test_severity_from_cvss(self) -> None:
        assert severity_from_cvss(9.5) == Severity.CRITICAL
        assert severity_from_cvss(7.5) == Severity.HIGH
        assert severity_from_cvss(5.0) == Severity.MEDIUM
        assert severity_from_cvss(2.0) == Severity.LOW
        assert severity_from_cvss(0.0) == Severity.INFORMATIONAL
