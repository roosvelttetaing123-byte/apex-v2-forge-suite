"""Host scorer — ranks hosts by attack priority."""
from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from netforge.core.network_map import NetworkMap, HostInfo

_HIGH_VALUE_PORTS = {
    22: 5, 23: 8, 25: 4, 53: 3, 80: 2, 110: 3, 135: 7, 139: 8, 443: 2,
    445: 10, 389: 8, 636: 8, 1433: 9, 3306: 7, 3389: 10, 5432: 7,
    5985: 8, 5986: 8, 6379: 7, 8080: 3, 8443: 3, 27017: 7, 9200: 7,
}
_RISK_TAGS = {"dc": 20, "domain-controller": 20, "critical": 15, "sql": 10, "web": 5}


@dataclass
class ScoredHost:
    ip: str
    score: int
    reasons: list[str]


def score_host(host: "HostInfo") -> ScoredHost:
    score = 0
    reasons: list[str] = []

    for port, info in host.ports.items():
        if info.get("state") != "open":
            continue
        pts = _HIGH_VALUE_PORTS.get(port, 1)
        if pts > 1:
            reasons.append(f"port {port}/{info.get('service','?')} (+{pts})")
        score += pts

    vuln_count = len(host.vulns)
    if vuln_count:
        pts = min(vuln_count * 3, 30)
        score += pts
        reasons.append(f"{vuln_count} vulns (+{pts})")

    for tag in host.tags:
        pts = _RISK_TAGS.get(tag.lower(), 0)
        if pts:
            score += pts
            reasons.append(f"tag:{tag} (+{pts})")

    score = min(score, 100)
    return ScoredHost(ip=host.ip, score=score, reasons=reasons)


def rank_hosts(network_map: "NetworkMap") -> list[ScoredHost]:
    """Return hosts sorted by score descending."""
    scored = [score_host(h) for h in network_map.hosts()]
    return sorted(scored, key=lambda s: s.score, reverse=True)
