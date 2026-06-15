"""Burp Suite XML issue export for WebForge findings."""
from __future__ import annotations

import sys
import time
import xml.etree.ElementTree as ET
from pathlib import Path
from xml.dom import minidom

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult

_BURP_SEVERITY = {
    "Critical": "High",
    "High": "High",
    "Medium": "Medium",
    "Low": "Low",
    "Informational": "Information",
}
_BURP_CONFIDENCE = {
    "Critical": "Certain",
    "High": "Firm",
    "Medium": "Firm",
    "Low": "Tentative",
    "Informational": "Tentative",
}


def findings_to_burp_xml(findings: list[dict], target: str) -> str:
    root = ET.Element("issues", burpVersion="2024.x", exportTime=__import__("datetime").datetime.utcnow().isoformat())
    for f in findings:
        sev = f.get("severity", "Informational")
        issue = ET.SubElement(root, "issue")
        ET.SubElement(issue, "serialNumber").text = f.get("id", "")
        ET.SubElement(issue, "type").text         = "134217728"
        ET.SubElement(issue, "name").text         = f.get("title", "")
        ET.SubElement(issue, "host", ip=target).text = f.get("target", target)
        ET.SubElement(issue, "path").text         = "/"
        ET.SubElement(issue, "location").text     = f.get("target", "")
        ET.SubElement(issue, "severity").text      = _BURP_SEVERITY.get(sev, "Information")
        ET.SubElement(issue, "confidence").text    = _BURP_CONFIDENCE.get(sev, "Tentative")
        ET.SubElement(issue, "issueBackground").text    = f.get("description", "")
        ET.SubElement(issue, "remediationBackground").text = f.get("remediation", "")
        detail = (
            f'CVSS: {f.get("cvss_v31_score","")} ({f.get("cvss_v31_vector","")})\n'
            f'MITRE: {", ".join(f.get("mitre_attack",[]))}\n'
            f'Module: {f.get("module","")}'
        )
        ET.SubElement(issue, "issueDetail").text   = detail
        steps = "\n".join(f"{i+1}. {s}" for i, s in enumerate(f.get("reproduction_steps", [])))
        ET.SubElement(issue, "requestresponses").text = steps

    raw = ET.tostring(root, encoding="unicode")
    return minidom.parseString(raw).toprettyxml(indent="  ")


class BurpExport(BaseModule):
    NAME        = "burp_export"
    DESCRIPTION = "Export findings as Burp Suite XML issue format"
    PHASE       = 99
    TAGS        = ["reporting"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        findings_raw: list[dict] = self.config.extra.get("findings", [])
        if not findings_raw:
            return self._make_result(start, skipped=True, skip_reason="no findings")

        out_dir = Path(self.config.extra.get("output_dir", self.results_dir))
        out_dir.mkdir(parents=True, exist_ok=True)
        out_file = out_dir / "webforge_burp_issues.xml"
        out_file.write_text(findings_to_burp_xml(findings_raw, self.config.target), encoding="utf-8")
        self.log.info("Burp XML exported: %s", out_file)
        return self._make_result(start)
