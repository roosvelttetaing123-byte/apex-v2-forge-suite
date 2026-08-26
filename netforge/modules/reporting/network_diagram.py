"""NetForge Network Diagram — SVG topology visualization from scan data.

Generates a self-contained SVG network diagram showing discovered hosts,
services, vulnerability severity, and connectivity. Embeddable in HTML
reports or viewable standalone in a browser.

Uses pure Python SVG generation — no external graphviz dependency.
"""
from __future__ import annotations

import hashlib
import math
import sys
import time
from collections import defaultdict
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.evidence import ordinary_finding_projection


# ── Severity colors for nodes ────────────────────────────────────────────────

_NODE_COLORS = {
    "critical": "#7030A0",
    "high":     "#CC3300",
    "medium":   "#FF8C00",
    "low":      "#4CAF50",
    "info":     "#2196F3",
    "clean":    "#90CAF9",
}

_SEV_RANK = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Informational": 4}


def _host_color(findings: list[dict]) -> str:
    """Determine node color based on worst finding severity."""
    if not findings:
        return _NODE_COLORS["clean"]
    worst = min(findings, key=lambda f: _SEV_RANK.get(f.get("severity", "Informational"), 99))
    sev = worst.get("severity", "Informational").lower()
    if sev == "informational":
        sev = "info"
    return _NODE_COLORS.get(sev, _NODE_COLORS["clean"])


def _hash_position(hostname: str, idx: int, total: int, width: int, height: int) -> tuple[float, float]:
    """Deterministic node placement using hash + circular layout."""
    # Use a circular layout with some hash-based jitter
    angle = (2 * math.pi * idx / max(total, 1)) - math.pi / 2
    radius_x = width * 0.35
    radius_y = height * 0.35
    cx = width / 2
    cy = height / 2

    # Add small hash-based offset for visual variety
    h = int(hashlib.md5(hostname.encode()).hexdigest()[:8], 16)
    jitter_x = (h % 40) - 20
    jitter_y = ((h >> 8) % 40) - 20

    x = cx + radius_x * math.cos(angle) + jitter_x
    y = cy + radius_y * math.sin(angle) + jitter_y

    return x, y


def generate_svg(
    findings: list[dict],
    live_hosts: list[str] | None = None,
    open_ports: dict[str, Any] | None = None,
    target: str = "",
    width: int = 1200,
    height: int = 800,
) -> str:
    """Generate an SVG network topology diagram."""
    findings = [ordinary_finding_projection(finding) for finding in findings]

    # Group findings by host
    host_findings: dict[str, list[dict]] = defaultdict(list)
    for f in findings:
        host = f.get("target", "unknown")
        host_findings[host].append(f)

    # Merge with live_hosts to include hosts with no findings
    all_hosts = set(host_findings.keys())
    if live_hosts:
        all_hosts.update(live_hosts)

    hosts = sorted(all_hosts)
    if not hosts:
        # Empty diagram
        return (
            f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}">'
            f'<rect width="{width}" height="{height}" fill="#f8f9fa"/>'
            f'<text x="{width//2}" y="{height//2}" text-anchor="middle" '
            f'font-family="Arial" font-size="16" fill="#999">No hosts discovered</text>'
            f'</svg>'
        )

    # Calculate positions
    positions: dict[str, tuple[float, float]] = {}
    for idx, host in enumerate(hosts):
        positions[host] = _hash_position(host, idx, len(hosts), width, height)

    # Build SVG
    svg_parts: list[str] = []

    # SVG header with embedded styles
    svg_parts.append(f"""<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}"
     font-family="'Segoe UI', Arial, sans-serif">
  <defs>
    <filter id="shadow" x="-20%" y="-20%" width="140%" height="140%">
      <feDropShadow dx="2" dy="2" stdDeviation="3" flood-opacity="0.15"/>
    </filter>
    <radialGradient id="bgGrad" cx="50%" cy="50%" r="60%">
      <stop offset="0%" stop-color="#f0f2f5"/>
      <stop offset="100%" stop-color="#e0e4e8"/>
    </radialGradient>
  </defs>
  <rect width="{width}" height="{height}" fill="url(#bgGrad)"/>
  <text x="{width//2}" y="30" text-anchor="middle" font-size="18" font-weight="bold" fill="#1a237e">
    NetForge Network Topology — {_svg_escape(target)}
  </text>""")

    # Draw edges (connections between hosts on same subnet)
    # Simple heuristic: connect hosts that share findings from same module
    drawn_edges: set[tuple[str, str]] = set()
    for h1 in hosts:
        for h2 in hosts:
            if h1 >= h2:
                continue
            pair = (h1, h2)
            if pair in drawn_edges:
                continue
            # Connect if they share any module findings (suggests network relationship)
            h1_modules = {f.get("module") for f in host_findings.get(h1, [])}
            h2_modules = {f.get("module") for f in host_findings.get(h2, [])}
            shared = h1_modules & h2_modules - {None, ""}
            if shared and len(hosts) <= 30:
                x1, y1 = positions[h1]
                x2, y2 = positions[h2]
                svg_parts.append(
                    f'  <line x1="{x1:.0f}" y1="{y1:.0f}" x2="{x2:.0f}" y2="{y2:.0f}" '
                    f'stroke="#ccc" stroke-width="1" stroke-dasharray="4,4" opacity="0.5"/>'
                )
                drawn_edges.add(pair)

    # Draw nodes
    for host in hosts:
        x, y = positions[host]
        h_findings = host_findings.get(host, [])
        color = _host_color(h_findings)
        finding_count = len(h_findings)

        # Node size scales with finding count
        radius = min(28 + finding_count * 2, 50)

        # Collect port info
        ports = sorted({f.get("port") for f in h_findings if f.get("port")})
        port_label = ", ".join(str(p) for p in ports[:5])
        if len(ports) > 5:
            port_label += f"... (+{len(ports) - 5})"

        svg_parts.append(f"""
  <g transform="translate({x:.0f},{y:.0f})">
    <circle r="{radius}" fill="{color}" stroke="#fff" stroke-width="2" filter="url(#shadow)" opacity="0.9"/>
    <text y="-{radius + 8}" text-anchor="middle" font-size="11" font-weight="bold" fill="#333">
      {_svg_escape(host)}
    </text>
    <text y="4" text-anchor="middle" font-size="{min(12, radius//2)}" fill="#fff" font-weight="bold">
      {finding_count}
    </text>
    <text y="{radius + 14}" text-anchor="middle" font-size="8" fill="#666">
      {_svg_escape(port_label)}
    </text>
  </g>""")

    # Legend
    legend_y = height - 60
    legend_items = [
        ("Critical", _NODE_COLORS["critical"]),
        ("High", _NODE_COLORS["high"]),
        ("Medium", _NODE_COLORS["medium"]),
        ("Low", _NODE_COLORS["low"]),
        ("Info", _NODE_COLORS["info"]),
        ("Clean", _NODE_COLORS["clean"]),
    ]
    svg_parts.append(f'  <text x="20" y="{legend_y - 10}" font-size="10" font-weight="bold" fill="#555">Legend:</text>')
    for i, (label, color) in enumerate(legend_items):
        lx = 20 + i * 100
        svg_parts.append(
            f'  <circle cx="{lx + 8}" cy="{legend_y + 8}" r="6" fill="{color}"/>'
            f'  <text x="{lx + 18}" y="{legend_y + 12}" font-size="9" fill="#555">{label}</text>'
        )

    svg_parts.append("</svg>")
    return "\n".join(svg_parts)


def _svg_escape(text: str) -> str:
    return (text
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
            .replace("'", "&apos;"))


# ── Module wrapper ───────────────────────────────────────────────────────────

class NetworkDiagram(BaseModule):
    """Generate SVG network topology diagram from scan results."""

    NAME        = "network_diagram"
    DESCRIPTION = "Generate SVG network diagram from discovery data"
    PHASE       = 14
    TAGS        = ["reporting", "diagram"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        findings_raw: list = self.config.extra.get("findings", self.findings)

        out_path = self.results_dir / "network_diagram.svg"
        out_path.parent.mkdir(parents=True, exist_ok=True)

        svg = generate_svg(
            findings=findings_raw,
            live_hosts=self.config.extra.get("live_hosts"),
            open_ports=self.config.extra.get("open_ports"),
            target=self.config.target,
        )
        out_path.write_text(svg, encoding="utf-8")
        self.log.info(
            "Network diagram written: %s (%d findings)",
            out_path,
            len(findings_raw),
        )

        # Also generate an HTML wrapper for easy viewing
        html_path = self.results_dir / "network_diagram.html"
        html_path.write_text(
            f"""<!DOCTYPE html>
<html><head><title>NetForge Network Topology</title>
<style>body{{margin:0;background:#f0f2f5;display:flex;justify-content:center;padding:20px}}
svg{{max-width:100%;height:auto}}</style></head>
<body>{svg}</body></html>""",
            encoding="utf-8",
        )

        return self._make_result(start)


# ── Tests ────────────────────────────────────────────────────────────────────

class TestNetworkDiagram:
    def test_phase(self) -> None:
        assert NetworkDiagram.PHASE == 14

    def test_empty_svg(self) -> None:
        svg = generate_svg([], target="10.0.0.0/24")
        assert "<svg" in svg
        assert "No hosts discovered" in svg

    def test_svg_with_findings(self) -> None:
        findings = [
            {"target": "10.0.0.1", "severity": "High", "port": 22, "module": "ssh_audit"},
            {"target": "10.0.0.1", "severity": "Medium", "port": 80, "module": "http_check"},
            {"target": "10.0.0.2", "severity": "Critical", "port": 445, "module": "smb_audit"},
        ]
        svg = generate_svg(findings, target="10.0.0.0/24")
        assert "10.0.0.1" in svg
        assert "10.0.0.2" in svg
        assert "#7030A0" in svg  # Critical color

    def test_svg_escape(self) -> None:
        assert "&lt;" in _svg_escape("<test>")
