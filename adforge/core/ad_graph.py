"""AD relationship graph — nodes and directed edges for attack path analysis."""
from __future__ import annotations

import json
from collections import defaultdict, deque
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class ADNode:
    id: str
    label: str
    type: str               # user, group, computer, ou, domain, gpo
    properties: dict = field(default_factory=dict)


@dataclass
class ADEdge:
    src: str
    dst: str
    relation: str           # MemberOf, GenericAll, WriteDACL, AdminTo, HasSession, CanRDP, etc.
    properties: dict = field(default_factory=dict)


class ADGraph:
    def __init__(self) -> None:
        self._nodes: dict[str, ADNode] = {}
        self._edges: list[ADEdge] = []
        self._adj: dict[str, list[ADEdge]] = defaultdict(list)

    def add_node(self, id: str, label: str, type: str, **props) -> ADNode:
        node = ADNode(id=id, label=label, type=type, properties=props)
        self._nodes[id] = node
        return node

    def add_edge(self, src: str, dst: str, relation: str, **props) -> ADEdge:
        edge = ADEdge(src=src, dst=dst, relation=relation, properties=props)
        self._edges.append(edge)
        self._adj[src].append(edge)
        return edge

    def get_node(self, id: str) -> ADNode | None:
        return self._nodes.get(id)

    def neighbors(self, node_id: str) -> list[tuple[str, str]]:
        """Return [(dst_id, relation), ...] for outgoing edges."""
        return [(e.dst, e.relation) for e in self._adj.get(node_id, [])]

    def find_path(self, src: str, dst: str) -> list[str] | None:
        """BFS shortest path from src to dst, returns list of node IDs."""
        if src not in self._nodes or dst not in self._nodes:
            return None
        visited = {src}
        queue: deque[list[str]] = deque([[src]])
        while queue:
            path = queue.popleft()
            current = path[-1]
            if current == dst:
                return path
            for nxt, _ in self.neighbors(current):
                if nxt not in visited:
                    visited.add(nxt)
                    queue.append(path + [nxt])
        return None

    def nodes_by_type(self, node_type: str) -> list[ADNode]:
        return [n for n in self._nodes.values() if n.type == node_type]

    def export_dot(self) -> str:
        lines = ["digraph ADGraph {", "  rankdir=LR;", "  node [shape=box];"]
        for node in self._nodes.values():
            shape = {"domain": "ellipse", "group": "diamond", "computer": "box", "user": "circle"}.get(node.type, "box")
            lines.append(f'  "{node.id}" [label="{node.label}" shape={shape}];')
        for edge in self._edges:
            lines.append(f'  "{edge.src}" -> "{edge.dst}" [label="{edge.relation}"];')
        lines.append("}")
        return "\n".join(lines)

    def to_json(self) -> str:
        return json.dumps({
            "nodes": [{"id": n.id, "label": n.label, "type": n.type, "props": n.properties} for n in self._nodes.values()],
            "edges": [{"src": e.src, "dst": e.dst, "rel": e.relation, "props": e.properties} for e in self._edges],
        }, indent=2)

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(self.to_json())

    def __len__(self) -> int:
        return len(self._nodes)
