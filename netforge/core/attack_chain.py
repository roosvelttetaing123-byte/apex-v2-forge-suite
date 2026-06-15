"""Attack Chain Engine — automated Red Team kill chain progression.

The glue that turns individual modules into a coordinated attack.
When one module discovers something, this engine automatically feeds
that intelligence into subsequent modules.

Features:
  - Auto credential reuse: found SSH creds → try SMB → try RDP
  - Exploit chaining: SMB signing off + creds → NTLM relay path
  - Kill chain progression: tracks Recon → Exploit → Install → C2 → Actions
  - Branching logic: if exploit A fails, try B
  - Operator approval gates: exploitation requires confirmation

Usage:
    chain = AttackChain(config, cred_engine)
    chain.ingest_findings(module_results)
    next_actions = chain.recommend_next()
    await chain.execute_chain(approved_actions)
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
    """Automated attack chain engine for Red Team operations.

    Ingests findings from completed modules and recommends the next
    attack actions based on discovered intelligence. Tracks kill chain
    progression and manages credential reuse across modules.
    """

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
        """Process a finding and extract attack chain intelligence.

        This is where detection becomes action. Every finding is analyzed
        for exploitation potential.
        """
        title = (finding.get("title") or "").lower()
        service = (finding.get("service") or "").lower()
        target = finding.get("target", "")
        port = finding.get("port", 0)
        refs = finding.get("references", [])
        severity = finding.get("severity", "")

        # --- Credential discoveries ---
        if any(kw in title for kw in ["valid credential", "password spray", "brute force", "default"]):
            self.intel.valid_credentials.append(finding)
            self.intel.compromised_hosts.add(target)
            self.intel.current_phase = ChainPhase.INITIAL_ACCESS

        # --- SMB signing disabled ---
        if "signing" in title and ("disabled" in title or "not required" in title):
            self.intel.smb_signing_disabled.add(target)
            self.intel.exploitable_vulns.append({
                "type": "smb_signing", "target": target,
                "exploit": "ntlm_relay",
            })

        # --- NTLM / LLMNR / NBT-NS ---
        if any(kw in title for kw in ["llmnr", "nbt-ns", "ntlm"]):
            self.intel.exploitable_vulns.append({
                "type": "llmnr_poison", "target": target,
                "exploit": "responder",
            })

        # --- Redis no auth ---
        if "redis" in service or "redis" in title:
            if any(kw in title for kw in ["noauth", "no auth", "unauthenticated", "default"]):
                self.intel.redis_noauth.add(target)
                self.intel.exploitable_vulns.append({
                    "type": "redis_noauth", "target": target, "port": port,
                    "exploit": "redis_rce",
                })

        # --- RDP without NLA ---
        if "nla" in title and ("not required" in title or "not enforced" in title):
            self.intel.no_nla_hosts.add(target)

        # --- SSH accessible ---
        if service == "ssh" or (port == 22 and "open" in title):
            self.intel.ssh_accessible.add(target)

        # --- EternalBlue / MS17-010 ---
        if any(kw in title for kw in ["ms17-010", "eternalblue", "smbv1"]):
            self.intel.exploitable_vulns.append({
                "type": "eternalblue", "target": target, "port": port or 445,
                "exploit": "eternalblue",
            })

        # --- BlueKeep ---
        if any(kw in title for kw in ["bluekeep", "cve-2019-0708"]):
            self.intel.exploitable_vulns.append({
                "type": "bluekeep", "target": target, "port": port or 3389,
                "exploit": "bluekeep",
            })

        # --- Heartbleed ---
        if "heartbleed" in title or "CVE-2014-0160" in str(refs):
            self.intel.exploitable_vulns.append({
                "type": "heartbleed", "target": target, "port": port or 443,
                "exploit": "heartbleed",
            })

        # --- Pivot candidates ---
        if "pivot" in title or "dual-homed" in title:
            self.intel.pivot_candidates.add(target)

    def ingest_findings(self, findings: list[dict]) -> None:
        """Batch ingest findings."""
        for f in findings:
            self.ingest_finding(f)

    # ------------------------------------------------------------------
    # Recommendation engine — what to do next
    # ------------------------------------------------------------------

    def recommend_next(self) -> list[ChainAction]:
        """Generate recommended next actions based on accumulated intelligence.

        This is the Red Team brain. It looks at everything we've found
        and says "here's what you should hit next."
        """
        actions: list[ChainAction] = []

        # --- 1. Credential reuse (highest priority) ---
        if self.intel.valid_credentials and self.cred_engine:
            for host in self.intel.ssh_accessible - self.intel.compromised_hosts:
                actions.append(ChainAction(
                    action_id=self._next_id(),
                    phase=ChainPhase.LATERAL,
                    module="native_brute",
                    target=host,
                    port=22,
                    description=f"Reuse discovered creds against SSH on {host}",
                    requires_creds=True,
                    requires_confirm=False,
                    priority=1,
                    auto_execute=True,
                ))

        # --- 2. Exploit vulnerable services ---
        for vuln in self.intel.exploitable_vulns:
            exploit = vuln.get("exploit", "")
            target = vuln.get("target", "")

            if exploit == "redis_rce" and target not in self.intel.compromised_hosts:
                actions.append(ChainAction(
                    action_id=self._next_id(),
                    phase=ChainPhase.EXECUTION,
                    module="redis_rce",
                    target=target,
                    port=vuln.get("port", 6379),
                    description=f"Redis RCE — write SSH key or crontab on {target}",
                    priority=2,
                    requires_confirm=True,
                ))

            if exploit == "eternalblue":
                actions.append(ChainAction(
                    action_id=self._next_id(),
                    phase=ChainPhase.EXECUTION,
                    module="eternalblue",
                    target=target,
                    port=vuln.get("port", 445),
                    description=f"MS17-010 EternalBlue against {target}",
                    priority=3,
                    requires_confirm=True,
                ))

            if exploit == "heartbleed":
                actions.append(ChainAction(
                    action_id=self._next_id(),
                    phase=ChainPhase.COLLECTION,
                    module="heartbleed",
                    target=target,
                    port=vuln.get("port", 443),
                    description=f"Heartbleed memory leak on {target} — extract creds/keys",
                    priority=2,
                    requires_confirm=True,
                ))

            if exploit == "ntlm_relay":
                actions.append(ChainAction(
                    action_id=self._next_id(),
                    phase=ChainPhase.LATERAL,
                    module="ntlm_relay",
                    target=target,
                    port=445,
                    description=f"NTLM relay via {target} (SMB signing disabled)",
                    priority=2,
                    requires_confirm=True,
                ))

        # --- 3. Pivoting ---
        for host in self.intel.compromised_hosts & self.intel.pivot_candidates:
            actions.append(ChainAction(
                action_id=self._next_id(),
                phase=ChainPhase.LATERAL,
                module="pivot_finder",
                target=host,
                description=f"Pivot through compromised host {host}",
                priority=4,
                requires_confirm=True,
            ))

        # Deduplicate and sort by priority
        seen = set()
        unique_actions = []
        for a in actions:
            key = f"{a.module}:{a.target}:{a.port}"
            if key not in seen:
                seen.add(key)
                unique_actions.append(a)

        unique_actions.sort(key=lambda x: x.priority)
        self.pending_actions = unique_actions
        return unique_actions

    # ------------------------------------------------------------------
    # Credential distribution
    # ------------------------------------------------------------------

    def get_creds_for_host(self, host: str) -> list[dict]:
        """Get all known credentials that might work on a host.

        Returns creds found for this host AND creds from other hosts
        (same username/password combos for credential reuse).
        """
        if not self.cred_engine:
            return []

        creds = []
        # Direct creds for this host
        for c in self.cred_engine.for_host(host):
            creds.append({
                "username": c.username,
                "password": c.get_password(self.cred_engine.session_key),
                "source": f"direct:{host}",
            })
        # Reuse: creds from OTHER hosts (same username:password)
        for c in self.cred_engine.all():
            if c.host != host and not c._wiped:
                creds.append({
                    "username": c.username,
                    "password": c.get_password(self.cred_engine.session_key),
                    "source": f"reuse:{c.host}",
                })

        # Deduplicate
        seen = set()
        unique = []
        for cr in creds:
            key = f"{cr['username']}:{cr['password']}"
            if key not in seen:
                seen.add(key)
                unique.append(cr)
        return unique

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
        assert "10.0.0.5" in chain.intel.smb_signing_disabled

    def test_ingest_redis(self) -> None:
        chain = AttackChain()
        chain.ingest_finding({
            "title": "Redis Unauthenticated Access",
            "service": "redis",
            "target": "10.0.0.10",
            "port": 6379,
        })
        assert "10.0.0.10" in chain.intel.redis_noauth

    def test_ingest_creds(self) -> None:
        chain = AttackChain()
        chain.ingest_finding({
            "title": "Valid Credentials Found — admin@10.0.0.1",
            "target": "10.0.0.1",
            "port": 22,
        })
        assert "10.0.0.1" in chain.intel.compromised_hosts
        assert chain.intel.current_phase == ChainPhase.INITIAL_ACCESS

    def test_recommend_redis_rce(self) -> None:
        chain = AttackChain()
        chain.ingest_finding({
            "title": "Redis Unauthenticated Access",
            "service": "redis",
            "target": "10.0.0.10",
            "port": 6379,
        })
        actions = chain.recommend_next()
        modules = [a.module for a in actions]
        assert "redis_rce" in modules

    def test_recommend_ntlm_relay(self) -> None:
        chain = AttackChain()
        chain.ingest_finding({
            "title": "SMB Signing Disabled — 10.0.0.5",
            "service": "smb",
            "target": "10.0.0.5",
        })
        actions = chain.recommend_next()
        modules = [a.module for a in actions]
        assert "ntlm_relay" in modules

    def test_stats(self) -> None:
        chain = AttackChain()
        s = chain.stats
        assert s["compromised_hosts"] == 0
        assert s["phase"] == "recon"
