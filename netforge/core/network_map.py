"""Network map — stores and merges scan results per host."""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class HostInfo:
    ip: str
    hostnames: list[str]       = field(default_factory=list)
    os: str                    = ""
    ports: dict[int, dict]     = field(default_factory=dict)   # port -> {state, service, version, banner}
    vulns: list[dict]          = field(default_factory=list)
    tags: list[str]            = field(default_factory=list)
    extra: dict[str, Any]      = field(default_factory=dict)

    def add_port(self, port: int, state: str = "open", service: str = "", version: str = "", banner: str = "") -> None:
        self.ports[port] = {"state": state, "service": service, "version": version, "banner": banner}

    def to_dict(self) -> dict:
        return {
            "ip": self.ip, "hostnames": self.hostnames, "os": self.os,
            "ports": {str(p): v for p, v in self.ports.items()},
            "vulns": self.vulns, "tags": self.tags, "extra": self.extra,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "HostInfo":
        h = cls(ip=d["ip"], hostnames=d.get("hostnames", []), os=d.get("os", ""),
                vulns=d.get("vulns", []), tags=d.get("tags", []), extra=d.get("extra", {}))
        for p_str, v in d.get("ports", {}).items():
            h.ports[int(p_str)] = v
        return h


class NetworkMap:
    """In-memory map of all discovered hosts."""

    def __init__(self) -> None:
        self._hosts: dict[str, HostInfo] = {}

    def get_or_create(self, ip: str) -> HostInfo:
        if ip not in self._hosts:
            self._hosts[ip] = HostInfo(ip=ip)
        return self._hosts[ip]

    def hosts(self) -> list[HostInfo]:
        return list(self._hosts.values())

    def ips(self) -> list[str]:
        return list(self._hosts.keys())

    def merge(self, other: "NetworkMap") -> None:
        for ip, info in other._hosts.items():
            existing = self.get_or_create(ip)
            existing.ports.update(info.ports)
            existing.hostnames = list(set(existing.hostnames + info.hostnames))
            if not existing.os and info.os:
                existing.os = info.os
            existing.vulns.extend(info.vulns)
            existing.tags = list(set(existing.tags + info.tags))

    def to_json(self) -> str:
        return json.dumps({ip: h.to_dict() for ip, h in self._hosts.items()}, indent=2)

    @classmethod
    def from_json(cls, s: str) -> "NetworkMap":
        nm = cls()
        for ip, d in json.loads(s).items():
            nm._hosts[ip] = HostInfo.from_dict(d)
        return nm

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(self.to_json())

    @classmethod
    def load(cls, path: Path) -> "NetworkMap":
        return cls.from_json(path.read_text())

    def __len__(self) -> int:
        return len(self._hosts)

    def __repr__(self) -> str:
        return f"NetworkMap({len(self)} hosts)"
