"""Attack-chain data types and an inert legacy compatibility surface.

Unpersisted findings are not planning authority.  Until this adapter is wired
to the canonical advisory-plan boundary it retains only zero-state status and
rendering compatibility; it never recommends actions or exposes credentials.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

log = logging.getLogger("forge.netforge.attack_chain")


class ChainPhase(str, Enum):
    """Attack chain phases — Red Team progression."""
    RECON       = "recon"
    INITIAL_ACCESS = "initial_access"
    EXECUTION   = "execution"
    PERSISTENCE = "persistence"
    PRIV_ESC    = "privilege_escalation"
    LATERAL     = "lateral_movement"
    COLLECTION  = "collection"
    EXFIL       = "exfiltration"
    IMPACT      = "impact"


@dataclass
class ChainAction:
    """A recommended next action in the attack chain."""
    action_id: str
    phase: ChainPhase
    module: str
    target: str
    port: int = 0
    description: str = ""
    requires_creds: bool = False
    requires_confirm: bool = True
    priority: int = 5          # 1 = highest
    prerequisites: list[str] = field(default_factory=list)
    auto_execute: bool = False  # Can run without operator approval

    def to_dict(self) -> dict:
        return {
            "action_id": self.action_id,
            "phase": self.phase.value,
            "module": self.module,
            "target": self.target,
            "port": self.port,
            "description": self.description,
            "priority": self.priority,
            "requires_confirm": self.requires_confirm,
        }


@dataclass
class ChainIntelligence:
    """Accumulated intelligence from the attack chain."""
    compromised_hosts: set = field(default_factory=set)
    valid_credentials: list[dict] = field(default_factory=list)
    exploitable_vulns: list[dict] = field(default_factory=list)
    smb_signing_disabled: set = field(default_factory=set)
    no_nla_hosts: set = field(default_factory=set)
    redis_noauth: set = field(default_factory=set)
    ssh_accessible: set = field(default_factory=set)
    pivot_candidates: set = field(default_factory=set)
    domain_info: dict = field(default_factory=dict)
    current_phase: ChainPhase = ChainPhase.RECON


class AttackChain:
    """Inert compatibility adapter for the legacy NetForge chain surface."""

    def __init__(self, cred_engine: Any = None) -> None:
        self.intel = ChainIntelligence()
        self.cred_engine = cred_engine
        self.executed_actions: list[str] = []
        self.pending_actions: list[ChainAction] = []
        self._action_counter = 0

    def _next_id(self) -> str:
        self._action_counter += 1
        return f"chain-{self._action_counter:04d}"

    # ------------------------------------------------------------------
    # Intelligence ingestion
    # ------------------------------------------------------------------

    def ingest_finding(self, finding: dict) -> None:
        """Reject transient finding input as planning authority.

        NetForge has no canonical advisory-plan sink on this path. Task 106
        therefore leaves the legacy intelligence and compromise state empty.
        """
        del finding

    def ingest_findings(self, findings: list[dict]) -> None:
        """Batch ingest findings."""
        for f in findings:
            self.ingest_finding(f)

    # ------------------------------------------------------------------
    # Recommendation engine — what to do next
    # ------------------------------------------------------------------

    def recommend_next(self) -> list[ChainAction]:
        """Return no actions until canonical advisory persistence is wired.

        Caller/model finding text cannot populate an in-memory execution queue.
        """
        self.pending_actions = []
        return []

    # ------------------------------------------------------------------
    # Credential distribution
    # ------------------------------------------------------------------

    def get_creds_for_host(self, host: str) -> list[dict]:
        """Return no credential material from the disabled planner path.

        Credential use requires a separate canonical authorized action.
        """
        del host
        return []

    # ------------------------------------------------------------------
    # Status
    # ------------------------------------------------------------------

    @property
    def stats(self) -> dict:
        return {
            "phase": self.intel.current_phase.value,
            "compromised_hosts": len(self.intel.compromised_hosts),
            "valid_creds": len(self.intel.valid_credentials),
            "exploitable_vulns": len(self.intel.exploitable_vulns),
            "pending_actions": len(self.pending_actions),
            "executed_actions": len(self.executed_actions),
            "smb_signing_disabled": len(self.intel.smb_signing_disabled),
            "redis_noauth": len(self.intel.redis_noauth),
            "pivot_candidates": len(self.intel.pivot_candidates),
        }

    def render_status(self) -> str:
        """Render attack chain status for console."""
        s = self.stats
        lines = [
            f"[CHAIN] Phase: {s['phase']}",
            f"  Compromised: {s['compromised_hosts']} hosts",
            f"  Valid creds: {s['valid_creds']}",
            f"  Exploitable: {s['exploitable_vulns']} vulns",
            f"  Pending actions: {s['pending_actions']}",
        ]
        return "\n".join(lines)


# ======================================================================
# Tests
# ======================================================================

class TestAttackChain:
    """Unit tests for attack chain engine."""

    def test_ingest_smb_signing(self) -> None:
        chain = AttackChain()
        chain.ingest_finding({
            "title": "SMB Signing Not Required — 10.0.0.5",
            "service": "smb",
            "target": "10.0.0.5",
            "port": 445,
        })
        assert chain.intel == ChainIntelligence()
        assert chain.stats["smb_signing_disabled"] == 0

    def test_ingest_redis(self) -> None:
        chain = AttackChain()
        chain.ingest_finding({
            "title": "Redis Unauthenticated Access",
            "service": "redis",
            "target": "10.0.0.10",
            "port": 6379,
        })
        assert chain.intel == ChainIntelligence()
        assert chain.stats["redis_noauth"] == 0

    def test_ingest_creds(self) -> None:
        chain = AttackChain()
        chain.ingest_finding({
            "title": "Valid Credentials Found — admin@10.0.0.1",
            "target": "10.0.0.1",
            "port": 22,
        })
        assert chain.intel == ChainIntelligence()
        assert chain.intel.current_phase == ChainPhase.RECON

    def test_recommend_redis_rce(self) -> None:
        chain = AttackChain()
        chain.ingest_finding({
            "title": "Redis Unauthenticated Access",
            "service": "redis",
            "target": "10.0.0.10",
            "port": 6379,
        })
        assert chain.recommend_next() == []
        assert chain.pending_actions == []
        assert chain._action_counter == 0

    def test_recommend_ntlm_relay(self) -> None:
        chain = AttackChain()
        chain.ingest_finding({
            "title": "SMB Signing Disabled — 10.0.0.5",
            "service": "smb",
            "target": "10.0.0.5",
        })
        chain.pending_actions.append(ChainAction(
            action_id="legacy-action",
            phase=ChainPhase.LATERAL,
            module="ntlm_relay",
            target="10.0.0.5",
        ))
        assert chain.recommend_next() == []
        assert chain.pending_actions == []

    def test_stats(self) -> None:
        chain = AttackChain(cred_engine=object())
        assert chain.get_creds_for_host("10.0.0.1") == []
        s = chain.stats
        assert s == {
            "phase": "recon",
            "compromised_hosts": 0,
            "valid_creds": 0,
            "exploitable_vulns": 0,
            "pending_actions": 0,
            "executed_actions": 0,
            "smb_signing_disabled": 0,
            "redis_noauth": 0,
            "pivot_candidates": 0,
        }
        assert chain.render_status() == (
            "[CHAIN] Phase: recon\n"
            "  Compromised: 0 hosts\n"
            "  Valid creds: 0\n"
            "  Exploitable: 0 vulns\n"
            "  Pending actions: 0"
        )
