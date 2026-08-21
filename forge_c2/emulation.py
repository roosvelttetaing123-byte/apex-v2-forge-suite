"""Lab-safe C2 emulation helpers.

This module models high-risk C2 roadmap items as non-executing control-plane
state. It never creates payloads, performs process injection, opens peer
transports, or queues beacon tasks.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from common.verification_policy import validate_simulation_serialization
from forge_c2.beacon.beacon_core import BeaconRegistry


@dataclass(frozen=True)
class ProcessInjectionTechnique:
    """Metadata for an inert process-injection emulation target."""

    technique_id: str
    name: str
    attack_id: str
    validation_goal: str
    expected_detections: tuple[str, ...]
    supported_mode: str = "dry_run_emulation"

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.technique_id,
            "name": self.name,
            "attack_id": self.attack_id,
            "validation_goal": self.validation_goal,
            "expected_detections": list(self.expected_detections),
            "supported_mode": self.supported_mode,
            "safety": "metadata_only_no_injection",
        }


PROCESS_INJECTION_TECHNIQUES: dict[str, ProcessInjectionTechnique] = {
    "early_bird_apc": ProcessInjectionTechnique(
        technique_id="early_bird_apc",
        name="Early bird APC injection",
        attack_id="T1055",
        validation_goal="Validate detections for APC-style process-injection telemetry.",
        expected_detections=(
            "suspicious_thread_start",
            "apc_queue_to_untrusted_process",
            "cross_process_memory_intent",
        ),
    ),
    "threadless_callback": ProcessInjectionTechnique(
        technique_id="threadless_callback",
        name="Threadless callback-based injection",
        attack_id="T1055",
        validation_goal="Validate detections for callback-oriented injection patterns.",
        expected_detections=(
            "callback_registration_anomaly",
            "unexpected_executable_memory_intent",
        ),
    ),
    "module_stomping": ProcessInjectionTechnique(
        technique_id="module_stomping",
        name="Module stomping",
        attack_id="T1055",
        validation_goal="Validate detections for module image tampering attempts.",
        expected_detections=(
            "module_section_mismatch",
            "image_integrity_alert",
        ),
    ),
    "ntqueueapcthread": ProcessInjectionTechnique(
        technique_id="ntqueueapcthread",
        name="NtQueueApcThread variant",
        attack_id="T1055.004",
        validation_goal="Validate detections for native APC queueing intent.",
        expected_detections=(
            "native_api_apc_queue_intent",
            "cross_process_thread_manipulation",
        ),
    ),
    "atombombing": ProcessInjectionTechnique(
        technique_id="atombombing",
        name="AtomBombing",
        attack_id="T1055",
        validation_goal="Validate detections for atom-table abuse patterns.",
        expected_detections=(
            "global_atom_table_anomaly",
            "unexpected_atom_payload_flow",
        ),
    ),
}

P2P_TRANSPORTS = {
    "smb_named_pipe": "SMB named pipe P2P emulation",
    "tcp": "TCP P2P emulation",
}


def list_process_injection_techniques() -> list[dict[str, Any]]:
    """Return supported process-injection emulations."""

    return [tech.to_dict() for tech in PROCESS_INJECTION_TECHNIQUES.values()]


def build_process_injection_emulation_plan(
    technique_id: str,
    *,
    beacon_id: str,
    target_process: str = "",
    operator: str = "",
    dry_run: bool = True,
) -> dict[str, Any]:
    """Build an inert validation plan for a high-risk injection technique.

    Non-dry-run mode is intentionally rejected. The returned plan is suitable
    for dashboard display, audit logging, and defensive validation workflows.
    """

    if not dry_run:
        raise ValueError("process injection roadmap support is emulation-only")
    technique = PROCESS_INJECTION_TECHNIQUES.get(technique_id)
    if not technique:
        raise ValueError(f"unknown process injection technique: {technique_id}")
    return validate_simulation_serialization({
        "id": f"emu-{technique.technique_id}-{beacon_id or 'unassigned'}",
        "kind": "process_injection_emulation",
        "technique": technique.to_dict(),
        "beacon_id": beacon_id,
        "target_process": target_process,
        "operator": operator,
        "safety_mode": "dry_run_emulation",
        "verification_state": "simulation",
        "proof_type": "simulation",
        "maturity": "simulation",
        "requires_confirmation": False,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "actions": [
            "record technique selection",
            "map expected telemetry",
            "publish dashboard status",
        ],
        "forbidden_actions": [
            "process injection",
            "remote thread creation",
            "payload staging",
            "memory tampering",
        ],
    })


@dataclass
class P2PLink:
    """Control-plane representation of an emulated relay relationship."""

    parent: str
    child: str
    transport: str
    operator: str = ""
    status: str = "emulated"
    linked_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict[str, Any]:
        return validate_simulation_serialization({
            "parent": self.parent,
            "child": self.child,
            "transport": self.transport,
            "status": self.status,
            "verification_state": "simulation",
            "proof_type": "simulation",
            "maturity": "simulation",
            "operator": self.operator,
            "linked_at": self.linked_at,
            "safety": "control_plane_only_no_peer_transport",
        })


class P2PTopology:
    """Manage emulated P2P relay relationships in a BeaconRegistry."""

    def __init__(self, registry: BeaconRegistry) -> None:
        self.registry = registry

    def link(
        self,
        parent_id: str,
        child_id: str,
        *,
        transport: str = "tcp",
        operator: str = "",
    ) -> P2PLink:
        parent = self.registry.get(parent_id)
        child = self.registry.get(child_id)
        if not parent or not child:
            raise ValueError("parent and child beacons must exist")
        if parent_id == child_id:
            raise ValueError("a beacon cannot relay to itself")
        if transport not in P2P_TRANSPORTS:
            raise ValueError(f"unsupported emulated P2P transport: {transport}")
        if self._would_create_cycle(parent_id, child_id):
            raise ValueError("P2P relay link would create a cycle")

        previous_parent = child.parent_beacon
        if previous_parent and previous_parent != parent_id:
            old_parent = self.registry.get(previous_parent)
            if old_parent and child_id in old_parent.child_beacons:
                old_parent.child_beacons.remove(child_id)

        child.parent_beacon = parent_id
        if child_id not in parent.child_beacons:
            parent.child_beacons.append(child_id)
        child.transport = f"p2p:{transport}:emulated"
        return P2PLink(parent=parent_id, child=child_id, transport=transport, operator=operator)

    def unlink(self, child_id: str) -> dict[str, Any]:
        child = self.registry.get(child_id)
        if not child:
            raise ValueError("child beacon must exist")
        parent_id = child.parent_beacon
        if parent_id:
            parent = self.registry.get(parent_id)
            if parent and child_id in parent.child_beacons:
                parent.child_beacons.remove(child_id)
        child.parent_beacon = None
        if child.transport.startswith("p2p:"):
            child.transport = "https"
        return {
            "child": child_id,
            "previous_parent": parent_id,
            "status": "unlinked",
            "safety": "control_plane_only_no_peer_transport",
        }

    def tree(self) -> dict[str, Any]:
        beacons = self.registry.all_beacons()
        nodes = [
            {
                "id": beacon.beacon_id,
                "hostname": beacon.metadata.hostname,
                "state": beacon.state.value,
                "transport": beacon.transport,
                "parent": beacon.parent_beacon,
                "children": list(beacon.child_beacons),
            }
            for beacon in beacons
        ]
        links = [
            {
                "parent": beacon.parent_beacon,
                "child": beacon.beacon_id,
                "transport": beacon.transport.replace("p2p:", "").replace(":emulated", ""),
                "status": "emulated",
                "safety": "control_plane_only_no_peer_transport",
            }
            for beacon in beacons
            if beacon.parent_beacon
        ]
        roots = [beacon.beacon_id for beacon in beacons if not beacon.parent_beacon]
        return {
            "mode": "emulation",
            "nodes": nodes,
            "links": links,
            "roots": roots,
            "transports": dict(P2P_TRANSPORTS),
            "safety": "no peer listeners or relay sockets are created",
        }

    def _would_create_cycle(self, parent_id: str, child_id: str) -> bool:
        current = parent_id
        seen: set[str] = set()
        while current:
            if current == child_id:
                return True
            if current in seen:
                return True
            seen.add(current)
            beacon = self.registry.get(current)
            current = beacon.parent_beacon if beacon else ""
        return False
