"""Attack path analyzer — finds privilege escalation routes in the AD graph."""
from __future__ import annotations

import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from adforge.core.ad_graph import ADGraph

log = logging.getLogger("forge.adforge.attack_path")

_DA_GROUPS = {"domain admins", "domain controllers", "enterprise admins", "schema admins", "administrators"}
_ESCALATION_RELS = {"GenericAll", "GenericWrite", "WriteDACL", "WriteOwner", "AdminTo",
                    "CanRDP", "CanPSRemote", "AllExtendedRights", "ForceChangePassword",
                    "AddMember", "AddSelf", "Owns", "MemberOf"}


from dataclasses import dataclass


@dataclass
class AttackPath:
    source: str
    target: str
    path: list[str]
    relations: list[str]
    hop_count: int
    description: str


def find_paths_to_da(graph: "ADGraph", source_ids: list[str] | None = None) -> list[AttackPath]:
    """Find all shortest paths from source_ids (or all users) to any DA group."""
    da_nodes = [
        n.id for n in graph.nodes_by_type("group")
        if any(da in n.label.lower() for da in _DA_GROUPS)
    ]
    if not da_nodes:
        log.info("No DA groups found in graph")
        return []

    sources = source_ids or [n.id for n in graph.nodes_by_type("user")]
    paths: list[AttackPath] = []

    for src in sources:
        for da_id in da_nodes:
            node_path = graph.find_path(src, da_id)
            if not node_path or len(node_path) < 2:
                continue
            rels = []
            for i in range(len(node_path) - 1):
                edges_out = graph._adj.get(node_path[i], [])
                rel = next((e.relation for e in edges_out if e.dst == node_path[i + 1]), "?")
                rels.append(rel)

            src_node  = graph.get_node(src)
            da_node   = graph.get_node(da_id)
            src_label = src_node.label if src_node else src
            da_label  = da_node.label  if da_node else da_id

            paths.append(AttackPath(
                source=src,
                target=da_id,
                path=node_path,
                relations=rels,
                hop_count=len(node_path) - 1,
                description=(
                    f"{src_label} → {'  →  '.join(rels)}  →  {da_label} "
                    f"({len(node_path)-1} hop{'s' if len(node_path) > 2 else ''})"
                ),
            ))

    paths.sort(key=lambda p: p.hop_count)
    return paths


def suggest_next_hop(graph: "ADGraph", current_id: str) -> list[dict]:
    """Given current compromised node, suggest exploitable next hops."""
    suggestions = []
    for dst_id, relation in graph.neighbors(current_id):
        if relation in _ESCALATION_RELS:
            dst = graph.get_node(dst_id)
            suggestions.append({
                "target_id": dst_id,
                "target_label": dst.label if dst else dst_id,
                "target_type":  dst.type  if dst else "?",
                "relation": relation,
            })
    return suggestions
