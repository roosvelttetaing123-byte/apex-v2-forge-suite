"""Attack Path SVG — generate visual attack path diagram from findings."""
from __future__ import annotations
import html, sys, time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))
from common.base_module import BaseModule, ModuleResult
from common.finding import Severity

SEVERITY_COLORS = {
    "CRITICAL": "#dc2626", "HIGH": "#ea580c", "MEDIUM": "#ca8a04",
    "LOW": "#2563eb", "INFORMATIONAL": "#6b7280",
}

class AttackPathSvg(BaseModule):
    NAME = "attack_path_svg"
    DESCRIPTION = "Generate SVG attack path diagram from AD findings"
    PHASE = 14
    TAGS = ["reporting", "svg"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        findings = self.config.extra.get("findings", [])
        if not findings:
            return self._make_result(start, skipped=True, skip_reason="no findings")

        out_dir = Path(self.config.extra.get("output_dir", self.results_dir))
        out_dir.mkdir(parents=True, exist_ok=True)

        # Build attack chains from findings
        chains = self._build_chains(findings)

        # Generate SVG
        svg = self._render_svg(chains, findings)
        out_file = out_dir / "attack_path.svg"
        out_file.write_text(svg, encoding="utf-8")
        self.log.info("Attack path SVG: %s (%d nodes)", out_file, len(findings))
        return self._make_result(start)

    def _build_chains(self, findings: list) -> list[list[dict]]:
        chains = []
        by_phase: dict[int, list] = {}
        for f in findings:
            phase = f.get("phase", 0) if isinstance(f, dict) else getattr(f, "phase", 0)
            by_phase.setdefault(phase, []).append(f)

        # Build sequential chain by phase
        chain = []
        for phase in sorted(by_phase.keys()):
            for f in by_phase[phase][:3]:  # Top 3 per phase
                chain.append(f)
        if chain:
            chains.append(chain)
        return chains

    def _render_svg(self, chains: list, findings: list) -> str:
        node_width = 220
        node_height = 60
        x_gap = 40
        y_gap = 30
        padding = 20

        nodes = findings[:20]
        cols = min(5, len(nodes))
        rows = (len(nodes) + cols - 1) // cols

        width = cols * (node_width + x_gap) + padding * 2
        height = rows * (node_height + y_gap) + padding * 2 + 40

        parts = [
            f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
            f'viewBox="0 0 {width} {height}">',
            '<style>',
            '  .node { rx: 8; ry: 8; stroke-width: 2; }',
            '  .title { font: bold 11px sans-serif; fill: white; }',
            '  .sev { font: 10px sans-serif; fill: rgba(255,255,255,0.8); }',
            '  .arrow { stroke: #475569; stroke-width: 2; marker-end: url(#arrowhead); fill: none; }',
            '  .header { font: bold 16px sans-serif; fill: #1e293b; }',
            '</style>',
            '<defs><marker id="arrowhead" markerWidth="10" markerHeight="7" '
            'refX="10" refY="3.5" orient="auto"><polygon points="0 0, 10 3.5, 0 7" fill="#475569"/></marker></defs>',
            f'<text x="{padding}" y="25" class="header">AD Attack Path — {len(findings)} findings</text>',
        ]

        positions = []
        for i, finding in enumerate(nodes):
            col = i % cols
            row = i // cols
            x = padding + col * (node_width + x_gap)
            y = 40 + padding + row * (node_height + y_gap)
            positions.append((x, y))

            sev = finding.get("severity", "INFORMATIONAL") if isinstance(finding, dict) else str(getattr(finding, "severity", "INFORMATIONAL"))
            sev_name = str(sev).split(".")[-1].upper()
            color = SEVERITY_COLORS.get(sev_name, "#6b7280")
            title = finding.get("title", "?") if isinstance(finding, dict) else str(getattr(finding, "title", "?"))
            title = html.escape(title[:28])

            parts.append(f'<rect x="{x}" y="{y}" width="{node_width}" height="{node_height}" '
                         f'fill="{color}" class="node" stroke="{color}"/>')
            parts.append(f'<text x="{x+10}" y="{y+22}" class="title">{title}</text>')
            parts.append(f'<text x="{x+10}" y="{y+42}" class="sev">{sev_name}</text>')

        # Draw arrows between sequential nodes
        for i in range(len(positions) - 1):
            x1, y1 = positions[i]
            x2, y2 = positions[i + 1]
            if y1 == y2:  # Same row
                parts.append(f'<line x1="{x1+node_width}" y1="{y1+node_height//2}" '
                             f'x2="{x2}" y2="{y2+node_height//2}" class="arrow"/>')
            else:  # Next row
                mid_y = y1 + node_height + y_gap // 2
                parts.append(f'<path d="M{x1+node_width//2},{y1+node_height} '
                             f'L{x1+node_width//2},{mid_y} L{x2+node_width//2},{mid_y} '
                             f'L{x2+node_width//2},{y2}" class="arrow"/>')

        parts.append('</svg>')
        return "\n".join(parts)

class TestAttackPathSvg:
    def test_colors(self) -> None: assert "CRITICAL" in SEVERITY_COLORS
    def test_phase(self) -> None: assert AttackPathSvg.PHASE == 14
