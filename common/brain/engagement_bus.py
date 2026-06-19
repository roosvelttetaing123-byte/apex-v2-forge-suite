"""EngagementBus — Cross-framework finding exchange and chain orchestration.

Singleton engagement bus that connects all 4 frameworks (NetForge, WebForge,
ADForge, AIForge) through a shared SQLite-backed finding store. Any framework
can publish findings, any can subscribe, and the bus handles:

    - publish(framework, finding)    → store + notify all subscribers
    - subscribe(callback)            → register for cross-framework findings
    - get_all_findings()             → all findings across all frameworks
    - get_credentials()              → all credentials across all frameworks
    - get_intel()                    → full EngagementIntelligence for the planner
    - Cross-framework chain triggers → SQLi→cred spray, SSRF→internal scan, etc.
    - Brain integration              → auto-analyze each published finding
    - Planner integration            → trigger plan_next() after N findings
    - EventBus integration           → emit FINDING_NEW, BRAIN_VERDICT, CHAIN_ACTION

Graceful degradation: works without brain (no analysis), without event bus
(no dashboard push). The finding store always works.

FOR AUTHORIZED PENETRATION TESTING AND RED TEAM OPERATIONS ONLY.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import sqlite3
import threading
import time
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Coroutine

log = logging.getLogger("forge.brain.engagement_bus")


# ══════════════════════════════════════════════════════════════════════
# DATA MODELS
# ══════════════════════════════════════════════════════════════════════

class FindingSource(str, Enum):
    """Framework source for a finding."""
    NETFORGE = "netforge"
    WEBFORGE = "webforge"
    ADFORGE  = "adforge"
    AIFORGE  = "aiforge"
    C2       = "forge_c2"
    MANUAL   = "manual"


class ChainType(str, Enum):
    """Cross-framework attack chain types."""
    SQLI_TO_CRED_SPRAY           = "sqli_to_cred_spray"
    XSS_TO_SESSION_HIJACK        = "xss_to_session_hijack"
    SMB_SIGNING_TO_RELAY         = "smb_signing_to_relay"
    HOST_COMPROMISE_TO_C2        = "host_compromise_to_c2"
    DOMAIN_CREDS_TO_LATERAL      = "domain_creds_to_lateral"
    SSRF_TO_INTERNAL_RECON       = "ssrf_to_internal_recon"
    UPLOAD_TO_WEBSHELL           = "upload_to_webshell"
    ADCS_ESC_TO_DOMAIN_ADMIN     = "adcs_esc_to_domain_admin"
    ZEROLOGON_TO_DOMAIN_COMPROMISE = "zerologon_to_domain_compromise"


@dataclass
class ChainAction:
    """A cross-framework chain action triggered by a finding."""
    chain_type:       ChainType
    source_finding:   str           # finding ID that triggered this
    source_framework: str
    target_framework: str
    target_module:    str
    target:           str           # target URL/IP for the action
    rationale:        str
    auto_execute:     bool = False
    triggered_at:     str  = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


@dataclass
class EngagementIntelligence:
    """Full engagement intelligence struct for the planner.

    Aggregates all findings, credentials, shells, and metadata
    across all frameworks into a single intelligence package.
    """
    findings:       list[dict[str, Any]] = field(default_factory=list)
    credentials:    list[dict[str, Any]] = field(default_factory=list)
    shells:         list[dict[str, Any]] = field(default_factory=list)
    persistence:    list[dict[str, Any]] = field(default_factory=list)
    lateral_moves:  list[dict[str, Any]] = field(default_factory=list)
    collection:     list[dict[str, Any]] = field(default_factory=list)
    chain_actions:  list[dict[str, Any]] = field(default_factory=list)
    frameworks_active: list[str]         = field(default_factory=list)
    total_findings:    int = 0
    severity_counts:   dict[str, int]    = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dict for brain/planner consumption."""
        return asdict(self)


# ══════════════════════════════════════════════════════════════════════
# SUBSCRIBER TYPES
# ══════════════════════════════════════════════════════════════════════

# Sync subscriber: called with (framework: str, finding: dict)
FindingSubscriber = Callable[[str, dict[str, Any]], None]
# Async subscriber: called with (framework: str, finding: dict)
AsyncFindingSubscriber = Callable[[str, dict[str, Any]], Coroutine[Any, Any, None]]


# ══════════════════════════════════════════════════════════════════════
# SQLITE FINDING STORE
# ══════════════════════════════════════════════════════════════════════

_SCHEMA = """
CREATE TABLE IF NOT EXISTS findings (
    id          TEXT PRIMARY KEY,
    framework   TEXT NOT NULL,
    title       TEXT NOT NULL,
    severity    TEXT NOT NULL DEFAULT 'Informational',
    target      TEXT NOT NULL DEFAULT '',
    module      TEXT NOT NULL DEFAULT '',
    description TEXT DEFAULT '',
    remediation TEXT DEFAULT '',
    confidence  TEXT DEFAULT 'MEDIUM',
    data_json   TEXT DEFAULT '{}',
    created_at  TEXT NOT NULL DEFAULT (datetime('now')),
    brain_verdict   TEXT DEFAULT '',
    brain_confidence TEXT DEFAULT '',
    brain_reasoning  TEXT DEFAULT ''
);

CREATE TABLE IF NOT EXISTS credentials (
    id          TEXT PRIMARY KEY,
    framework   TEXT NOT NULL,
    host        TEXT DEFAULT '',
    service     TEXT DEFAULT '',
    username    TEXT DEFAULT '',
    password    TEXT DEFAULT '',
    hash_value  TEXT DEFAULT '',
    hash_type   TEXT DEFAULT '',
    domain      TEXT DEFAULT '',
    source      TEXT DEFAULT '',
    data_json   TEXT DEFAULT '{}',
    created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS chain_actions (
    id              TEXT PRIMARY KEY,
    chain_type      TEXT NOT NULL,
    source_finding  TEXT NOT NULL,
    source_framework TEXT NOT NULL,
    target_framework TEXT NOT NULL,
    target_module    TEXT NOT NULL,
    target          TEXT DEFAULT '',
    rationale       TEXT DEFAULT '',
    auto_execute    INTEGER DEFAULT 0,
    executed        INTEGER DEFAULT 0,
    triggered_at    TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_findings_framework ON findings(framework);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_credentials_framework ON credentials(framework);
CREATE INDEX IF NOT EXISTS idx_chain_source ON chain_actions(source_finding);
"""


class _FindingStore:
    """SQLite-backed finding store for the engagement bus.

    Thread-safe via a dedicated connection per instance with WAL mode.
    """

    def __init__(self, db_path: str = "engagement.db") -> None:
        self._db_path = db_path
        self._lock = threading.Lock()
        self._conn: sqlite3.Connection | None = None
        self._init_db()

    def _init_db(self) -> None:
        """Initialize the SQLite database and schema."""
        self._conn = sqlite3.connect(self._db_path, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._conn.executescript(_SCHEMA)
        self._conn.commit()
        log.debug("EngagementBus SQLite store initialized: %s", self._db_path)

    def store_finding(self, framework: str, finding: dict[str, Any]) -> str:
        """Store a finding and return its ID."""
        finding_id = finding.get("id") or str(uuid.uuid4())
        data = {k: v for k, v in finding.items()
                if k not in ("id", "framework", "title", "severity", "target",
                             "module", "description", "remediation", "confidence")}

        with self._lock:
            self._conn.execute(
                """INSERT OR REPLACE INTO findings
                   (id, framework, title, severity, target, module,
                    description, remediation, confidence, data_json)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    finding_id,
                    framework,
                    finding.get("title", ""),
                    finding.get("severity", "Informational"),
                    finding.get("target", ""),
                    finding.get("module", ""),
                    finding.get("description", ""),
                    finding.get("remediation", ""),
                    finding.get("confidence", "MEDIUM"),
                    json.dumps(data, default=str),
                ),
            )
            self._conn.commit()
        return finding_id

    def update_brain_verdict(
        self, finding_id: str, verdict: str, confidence: str, reasoning: str
    ) -> None:
        """Update brain analysis results for a finding."""
        with self._lock:
            self._conn.execute(
                """UPDATE findings SET brain_verdict=?, brain_confidence=?,
                   brain_reasoning=? WHERE id=?""",
                (verdict, confidence, reasoning, finding_id),
            )
            self._conn.commit()

    def store_credential(self, framework: str, cred: dict[str, Any]) -> str:
        """Store a credential and return its ID."""
        cred_id = cred.get("id") or str(uuid.uuid4())
        data = {k: v for k, v in cred.items()
                if k not in ("id", "framework", "host", "service", "username",
                             "password", "hash_value", "hash_type", "domain", "source")}

        with self._lock:
            self._conn.execute(
                """INSERT OR REPLACE INTO credentials
                   (id, framework, host, service, username, password,
                    hash_value, hash_type, domain, source, data_json)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    cred_id,
                    framework,
                    cred.get("host", ""),
                    cred.get("service", ""),
                    cred.get("username", ""),
                    cred.get("password", ""),
                    cred.get("hash_value", cred.get("hash", "")),
                    cred.get("hash_type", ""),
                    cred.get("domain", ""),
                    cred.get("source", ""),
                    json.dumps(data, default=str),
                ),
            )
            self._conn.commit()
        return cred_id

    def store_chain_action(self, action: ChainAction) -> str:
        """Store a chain action."""
        action_id = str(uuid.uuid4())
        with self._lock:
            self._conn.execute(
                """INSERT INTO chain_actions
                   (id, chain_type, source_finding, source_framework,
                    target_framework, target_module, target, rationale,
                    auto_execute, triggered_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    action_id,
                    action.chain_type.value,
                    action.source_finding,
                    action.source_framework,
                    action.target_framework,
                    action.target_module,
                    action.target,
                    action.rationale,
                    1 if action.auto_execute else 0,
                    action.triggered_at,
                ),
            )
            self._conn.commit()
        return action_id

    def get_all_findings(self) -> list[dict[str, Any]]:
        """Get all findings across all frameworks."""
        with self._lock:
            cursor = self._conn.execute(
                "SELECT * FROM findings ORDER BY created_at DESC"
            )
            cols = [desc[0] for desc in cursor.description]
            rows = cursor.fetchall()
        return [self._row_to_dict(cols, row) for row in rows]

    def get_findings_by_framework(self, framework: str) -> list[dict[str, Any]]:
        """Get findings for a specific framework."""
        with self._lock:
            cursor = self._conn.execute(
                "SELECT * FROM findings WHERE framework=? ORDER BY created_at DESC",
                (framework,),
            )
            cols = [desc[0] for desc in cursor.description]
            rows = cursor.fetchall()
        return [self._row_to_dict(cols, row) for row in rows]

    def get_all_credentials(self) -> list[dict[str, Any]]:
        """Get all credentials across all frameworks."""
        with self._lock:
            cursor = self._conn.execute(
                "SELECT * FROM credentials ORDER BY created_at DESC"
            )
            cols = [desc[0] for desc in cursor.description]
            rows = cursor.fetchall()
        return [self._row_to_dict(cols, row) for row in rows]

    def get_chain_actions(self, executed: bool | None = None) -> list[dict[str, Any]]:
        """Get chain actions, optionally filtered by execution status."""
        with self._lock:
            if executed is None:
                cursor = self._conn.execute(
                    "SELECT * FROM chain_actions ORDER BY triggered_at DESC"
                )
            else:
                cursor = self._conn.execute(
                    "SELECT * FROM chain_actions WHERE executed=? ORDER BY triggered_at DESC",
                    (1 if executed else 0,),
                )
            cols = [desc[0] for desc in cursor.description]
            rows = cursor.fetchall()
        return [self._row_to_dict(cols, row) for row in rows]

    def count_findings(self) -> int:
        """Return total finding count."""
        with self._lock:
            cursor = self._conn.execute("SELECT COUNT(*) FROM findings")
            return cursor.fetchone()[0]

    def severity_counts(self) -> dict[str, int]:
        """Return findings grouped by severity."""
        with self._lock:
            cursor = self._conn.execute(
                "SELECT severity, COUNT(*) FROM findings GROUP BY severity"
            )
            return dict(cursor.fetchall())

    def close(self) -> None:
        """Close the database connection."""
        if self._conn:
            self._conn.close()
            self._conn = None

    @staticmethod
    def _row_to_dict(cols: list[str], row: tuple) -> dict[str, Any]:
        """Convert a sqlite row to dict, unpacking data_json."""
        d = dict(zip(cols, row))
        if "data_json" in d:
            try:
                extra = json.loads(d.pop("data_json"))
                d.update(extra)
            except (json.JSONDecodeError, TypeError):
                d.pop("data_json", None)
        return d


# ══════════════════════════════════════════════════════════════════════
# CHAIN DETECTION RULES
# ══════════════════════════════════════════════════════════════════════

def _detect_chains(framework: str, finding: dict[str, Any]) -> list[ChainAction]:
    """Detect cross-framework chain opportunities from a new finding.

    Returns a list of ChainActions that should be triggered.
    """
    chains: list[ChainAction] = []
    title = (finding.get("title") or "").lower()
    finding_id = finding.get("id", "unknown")
    target = finding.get("target", "")

    # ── WebForge SQLi → NetForge credential reuse (SMB/SSH/RDP) ──────
    if framework in ("webforge",) and ("sqli" in title or "sql injection" in title):
        chains.append(ChainAction(
            chain_type=ChainType.SQLI_TO_CRED_SPRAY,
            source_finding=finding_id,
            source_framework=framework,
            target_framework="netforge",
            target_module="credential_spray",
            target=target,
            rationale=(
                "SQLi credential extract → credential reuse across SMB/SSH/RDP. "
                "Extract DB creds via SQLi, then spray across network services."
            ),
        ))

    # ── WebForge XSS → session cookie hijack → account takeover ──────
    if framework in ("webforge",) and "xss" in title:
        chains.append(ChainAction(
            chain_type=ChainType.XSS_TO_SESSION_HIJACK,
            source_finding=finding_id,
            source_framework=framework,
            target_framework="webforge",
            target_module="session_hijack",
            target=target,
            rationale=(
                "XSS → steal session cookies → account takeover → priv esc. "
                "Inject XSS payload that exfiltrates session tokens."
            ),
        ))

    # ── NetForge SMB signing disabled/not enforced → ADForge NTLM relay ─
    if framework in ("netforge",) and (
        "smb signing" in title or "smb relay" in title
    ) and any(kw in title for kw in (
        "disabled", "not enforced", "not required", "not configured", "missing"
    )):
        chains.append(ChainAction(
            chain_type=ChainType.SMB_SIGNING_TO_RELAY,
            source_finding=finding_id,
            source_framework=framework,
            target_framework="adforge",
            target_module="ntlm_relay",
            target=target,
            rationale=(
                "SMB signing disabled → NTLM relay to capture domain credentials. "
                "Relay NTLM authentication to achieve domain user access."
            ),
        ))

    # ── NetForge host compromise → Forge C2 beacon deploy ────────────
    if framework in ("netforge", "webforge") and any(
        kw in title for kw in ("shell", "rce", "remote code execution", "command injection")
    ):
        chains.append(ChainAction(
            chain_type=ChainType.HOST_COMPROMISE_TO_C2,
            source_finding=finding_id,
            source_framework=framework,
            target_framework="forge_c2",
            target_module="beacon_deploy",
            target=target,
            rationale=(
                "Host compromised → deploy C2 beacon for persistent access. "
                "Use RCE to stage and execute beacon implant."
            ),
        ))

    # ── ADForge domain creds → NetForge lateral movement ─────────────
    if framework in ("adforge",) and any(
        kw in title for kw in ("credential", "password", "ntlm", "kerberoast",
                               "as-rep", "dcsync", "golden ticket")
    ):
        chains.append(ChainAction(
            chain_type=ChainType.DOMAIN_CREDS_TO_LATERAL,
            source_finding=finding_id,
            source_framework=framework,
            target_framework="netforge",
            target_module="lateral_smb",
            target=target,
            rationale=(
                "Domain credentials obtained → lateral movement via SMB/WMI/WinRM. "
                "Use captured domain creds to pivot across the network."
            ),
        ))

    # ── WebForge SSRF → NetForge internal network recon ──────────────
    if framework in ("webforge",) and "ssrf" in title:
        chains.append(ChainAction(
            chain_type=ChainType.SSRF_TO_INTERNAL_RECON,
            source_finding=finding_id,
            source_framework=framework,
            target_framework="netforge",
            target_module="port_scanner",
            target=target,
            rationale=(
                "SSRF confirmed → pivot to scan internal network via SSRF. "
                "Use SSRF as proxy to discover internal services."
            ),
            auto_execute=True,  # Recon is safe
        ))

    # ── WebForge file upload → web shell → C2 beacon ─────────────────
    if framework in ("webforge",) and ("file upload" in title or "upload bypass" in title):
        chains.append(ChainAction(
            chain_type=ChainType.UPLOAD_TO_WEBSHELL,
            source_finding=finding_id,
            source_framework=framework,
            target_framework="webforge",
            target_module="webshell_deploy",
            target=target,
            rationale=(
                "File upload vuln → deploy web shell → C2 beacon. "
                "Upload PHP/ASPX web shell for persistent RCE."
            ),
        ))

    # ── ADForge ADCS ESC → certificate forgery → domain admin ────────
    if framework in ("adforge",) and any(
        kw in title
        for kw in ("esc1", "esc2", "esc3", "esc4", "esc6", "esc7", "esc8",
                   "esc9", "esc10", "esc11", "esc13", "esc14",
                   "adcs", "certificate template", "certifried")
    ):
        chains.append(ChainAction(
            chain_type=ChainType.ADCS_ESC_TO_DOMAIN_ADMIN,
            source_finding=finding_id,
            source_framework=framework,
            target_framework="adforge",
            target_module="dcsync",
            target=target,
            rationale=(
                "ADCS misconfiguration → forge certificate as domain admin → DCSync. "
                "Request certificate with SAN for domain admin, authenticate, then dump credentials."
            ),
        ))

    # ── Zerologon → instant domain compromise ────────────────────────
    if framework in ("adforge", "netforge") and "zerologon" in title:
        chains.append(ChainAction(
            chain_type=ChainType.ZEROLOGON_TO_DOMAIN_COMPROMISE,
            source_finding=finding_id,
            source_framework=framework,
            target_framework="adforge",
            target_module="dcsync",
            target=target,
            rationale=(
                "Zerologon (CVE-2020-1472) detected → reset DC machine account password → "
                "DCSync all domain hashes. Instant full domain compromise."
            ),
        ))

    return chains


# ══════════════════════════════════════════════════════════════════════
# ENGAGEMENT BUS (SINGLETON)
# ══════════════════════════════════════════════════════════════════════

class EngagementBus:
    """Cross-framework finding exchange and chain orchestration.

    Singleton pattern: use EngagementBus.get_instance() to get the
    shared instance across all frameworks.

    Usage::

        bus = EngagementBus.get_instance()

        # Publish a finding from webforge
        await bus.publish("webforge", finding_dict)

        # Subscribe to all findings from any framework
        bus.subscribe(my_callback)

        # Get intel package for the planner
        intel = bus.get_intel()

        # Get all credentials found so far
        creds = bus.get_credentials()
    """

    _instance: EngagementBus | None = None
    _instance_lock = threading.Lock()

    def __init__(
        self,
        db_path: str | None = None,
        brain: Any | None = None,
        planner: Any | None = None,
        event_bus: Any | None = None,
        plan_trigger_threshold: int = 5,
    ) -> None:
        """Initialize the engagement bus.

        Args:
            db_path:    Path to SQLite database. Default: engagement.db
                        in current directory.
            brain:      ForgeBrain instance for auto-analysis.
            planner:    AttackPlanner instance for auto-planning.
            event_bus:  Dashboard EventBus for real-time push.
            plan_trigger_threshold: Trigger plan_next() after this many
                                    new findings since last plan.
        """
        self._db_path = db_path or os.environ.get(
            "FORGE_ENGAGEMENT_DB", "engagement.db"
        )
        self._store = _FindingStore(self._db_path)
        self._brain = brain
        self._planner = planner
        self._event_bus = event_bus
        self._plan_threshold = plan_trigger_threshold

        # Subscriber lists
        self._sync_subscribers: list[FindingSubscriber] = []
        self._async_subscribers: list[AsyncFindingSubscriber] = []
        self._lock = threading.Lock()

        # Counters
        self._findings_since_plan = 0
        self._total_published = 0
        self._total_chains_triggered = 0

        log.info(
            "EngagementBus initialized (db=%s, brain=%s, planner=%s, event_bus=%s)",
            self._db_path,
            "available" if brain and getattr(brain, "available", False) else "none",
            "yes" if planner else "none",
            "yes" if event_bus else "none",
        )

    @classmethod
    def get_instance(cls, **kwargs: Any) -> EngagementBus:
        """Get or create the singleton instance.

        Args:
            **kwargs: Passed to __init__ only on first creation.

        Returns:
            The shared EngagementBus instance.
        """
        with cls._instance_lock:
            if cls._instance is None:
                cls._instance = cls(**kwargs)
            return cls._instance

    @classmethod
    def reset_instance(cls) -> None:
        """Reset the singleton (for testing)."""
        with cls._instance_lock:
            if cls._instance is not None:
                cls._instance._store.close()
                cls._instance = None

    # ── Configuration ─────────────────────────────────────────────────

    def set_brain(self, brain: Any) -> None:
        """Set or replace the ForgeBrain instance."""
        self._brain = brain

    def set_planner(self, planner: Any) -> None:
        """Set or replace the AttackPlanner instance."""
        self._planner = planner

    def set_event_bus(self, event_bus: Any) -> None:
        """Set or replace the dashboard EventBus."""
        self._event_bus = event_bus

    # ── Publishing ────────────────────────────────────────────────────

    async def publish(self, framework: str, finding: dict[str, Any]) -> str:
        """Publish a finding from any framework.

        Stores in SQLite, notifies subscribers, detects chains,
        and optionally triggers brain analysis and planner.

        Args:
            framework: Source framework (netforge/webforge/adforge/aiforge).
            finding:   Finding dict (from Finding.to_dict() or raw dict).

        Returns:
            The finding ID.
        """
        # Store
        finding_id = self._store.store_finding(framework, finding)
        finding["id"] = finding_id

        with self._lock:
            self._total_published += 1
            self._findings_since_plan += 1
            sync_subs = list(self._sync_subscribers)
            async_subs = list(self._async_subscribers)

        log.debug(
            "Finding published: %s [%s] %s (%s)",
            finding_id, framework,
            finding.get("title", "?"), finding.get("severity", "?"),
        )

        # Emit to dashboard EventBus
        self._emit_event("finding_new", {
            "id": finding_id,
            "framework": framework,
            "title": finding.get("title", ""),
            "severity": finding.get("severity", ""),
            "target": finding.get("target", ""),
        })

        # Notify sync subscribers (lists already captured under lock above)

        for cb in sync_subs:
            try:
                cb(framework, finding)
            except Exception as exc:
                log.error("Sync subscriber error: %s", exc)

        for cb in async_subs:
            try:
                await cb(framework, finding)
            except Exception as exc:
                log.error("Async subscriber error: %s", exc)

        # Detect and trigger chains
        chains = _detect_chains(framework, finding)
        for chain in chains:
            self._store.store_chain_action(chain)
            self._total_chains_triggered += 1
            log.info(
                "Chain triggered: %s → %s/%s (from %s)",
                chain.chain_type.value,
                chain.target_framework, chain.target_module,
                finding_id,
            )
            self._emit_event("chain_action_new", {
                "chain_type": chain.chain_type.value,
                "source_finding": finding_id,
                "source_framework": framework,
                "target_framework": chain.target_framework,
                "target_module": chain.target_module,
                "rationale": chain.rationale,
            })

        # Brain analysis (async, fire-and-forget)
        if self._brain and getattr(self._brain, "available", False):
            asyncio.ensure_future(self._analyze_with_brain(finding_id, finding))

        # Auto-trigger planner after N findings
        if (
            self._planner
            and self._findings_since_plan >= self._plan_threshold
        ):
            asyncio.ensure_future(self._auto_plan())
            self._findings_since_plan = 0

        return finding_id

    async def publish_credential(
        self, framework: str, cred: dict[str, Any]
    ) -> str:
        """Publish a credential from any framework.

        Args:
            framework: Source framework.
            cred:      Credential dict (host, service, username, password/hash).

        Returns:
            The credential ID.
        """
        cred_id = self._store.store_credential(framework, cred)
        log.debug(
            "Credential published: %s [%s] %s@%s",
            cred_id, framework,
            cred.get("username", "?"), cred.get("host", "?"),
        )

        self._emit_event("credential_found", {
            "id": cred_id,
            "framework": framework,
            "host": cred.get("host", ""),
            "username": cred.get("username", ""),
            "service": cred.get("service", ""),
        })

        # Domain credential → trigger lateral movement chain
        if cred.get("domain"):
            chain = ChainAction(
                chain_type=ChainType.DOMAIN_CREDS_TO_LATERAL,
                source_finding=cred_id,
                source_framework=framework,
                target_framework="netforge",
                target_module="lateral_smb",
                target=cred.get("host", ""),
                rationale=(
                    f"Domain credential ({cred.get('username', '?')}@{cred.get('domain')}) "
                    "obtained → lateral movement via SMB/WMI/WinRM."
                ),
            )
            self._store.store_chain_action(chain)
            with self._lock:
                self._total_chains_triggered += 1
            log.info(
                "Chain triggered: %s (domain cred: %s@%s)",
                chain.chain_type.value,
                cred.get("username", "?"), cred.get("domain"),
            )
            self._emit_event("chain_action_new", {
                "chain_type": chain.chain_type.value,
                "source_finding": cred_id,
                "source_framework": framework,
                "target_framework": chain.target_framework,
                "target_module": chain.target_module,
                "rationale": chain.rationale,
            })

        return cred_id

    # ── Session Import ────────────────────────────────────────────────

    async def load_engagement_session(
        self,
        session: Path | dict[str, Any],
        *,
        engagement_name: str = "",
    ) -> dict[str, Any]:
        """Load a completed engagement session JSON into the forge brain.

        Accepts the nbc.json / edc.json export format. Publishes all
        findings and credentials via the normal pipeline (chain detection,
        brain analysis, event bus). Also seeds ForgeBrain.memory with
        lessons_learned, false_negatives, evasion techniques, payloads,
        error signatures, and attack chain summaries so future AI calls
        have full engagement context.

        Args:
            session:         Path to session JSON file, or a pre-loaded dict.
            engagement_name: Override for the target label (used if
                             export_metadata.target_summary is absent).

        Returns:
            Summary dict with keys: target, findings_loaded,
            credentials_loaded, brain_events_seeded.
        """
        if isinstance(session, Path):
            import json as _json
            data: dict[str, Any] = _json.loads(session.read_text())
        else:
            data = session

        meta = data.get("export_metadata", {})
        target_summary: str = meta.get("target_summary", "") or engagement_name or "imported session"

        findings_loaded = 0
        credentials_loaded = 0
        brain_events = 0

        # 1. Publish all findings through the normal pipeline
        for finding in data.get("findings", []):
            framework = finding.get("framework", "manual")
            await self.publish(framework, dict(finding))
            findings_loaded += 1

        # 2. Publish credentials (if any)
        for cred in data.get("credentials", []):
            framework = cred.get("framework", "manual")
            await self.publish_credential(framework, dict(cred))
            credentials_loaded += 1

        # 3. Seed ForgeBrain memory with rich engagement context
        if self._brain and hasattr(self._brain, "memory"):
            mem = self._brain.memory

            if tc := data.get("target_context"):
                mem.add("target_context", "import", {"target": target_summary, **tc})
                brain_events += 1

            for lesson in data.get("lessons_learned", []):
                applicable = lesson.get("applicable_to", ["manual"])
                mem.add("lesson", applicable[0] if applicable else "manual", lesson)
                brain_events += 1

            for fn in data.get("false_negatives_detected", []):
                mem.add("fn_hint", "import", fn)
                brain_events += 1

            for ev in data.get("evasion_techniques", []):
                mem.add("evasion", "import", ev)
                brain_events += 1

            for pl in data.get("payloads_library", []):
                mem.add("payload", "import", pl)
                brain_events += 1

            for es in data.get("error_signatures", []):
                mem.add("error_sig", "import", es)
                brain_events += 1

            for ac in data.get("attack_chains", []):
                mem.add("attack_chain", "import", {
                    "chain_type": ac.get("chain_type"),
                    "impact": ac.get("impact"),
                    "rationale": ac.get("rationale"),
                    "steps": len(ac.get("steps", [])),
                })
                brain_events += 1

        log.info(
            "Session loaded: %d findings, %d credentials, %d brain events (target=%s)",
            findings_loaded, credentials_loaded, brain_events, target_summary,
        )

        return {
            "target": target_summary,
            "findings_loaded": findings_loaded,
            "credentials_loaded": credentials_loaded,
            "brain_events_seeded": brain_events,
        }

    # ── Subscribing ───────────────────────────────────────────────────

    def subscribe(self, callback: FindingSubscriber) -> None:
        """Register a sync subscriber for all findings.

        Args:
            callback: Function(framework: str, finding: dict) called
                      on each new published finding.
        """
        with self._lock:
            self._sync_subscribers.append(callback)

    def async_subscribe(self, callback: AsyncFindingSubscriber) -> None:
        """Register an async subscriber for all findings.

        Args:
            callback: Async function(framework: str, finding: dict).
        """
        with self._lock:
            self._async_subscribers.append(callback)

    def unsubscribe(self, callback: FindingSubscriber) -> None:
        """Remove a sync subscriber."""
        with self._lock:
            if callback in self._sync_subscribers:
                self._sync_subscribers.remove(callback)

    def async_unsubscribe(self, callback: AsyncFindingSubscriber) -> None:
        """Remove an async subscriber."""
        with self._lock:
            if callback in self._async_subscribers:
                self._async_subscribers.remove(callback)

    # ── Querying ──────────────────────────────────────────────────────

    def get_all_findings(self) -> list[dict[str, Any]]:
        """Get all findings across all frameworks.

        Returns:
            List of finding dicts, newest first.
        """
        return self._store.get_all_findings()

    def get_findings_by_framework(self, framework: str) -> list[dict[str, Any]]:
        """Get findings for a specific framework."""
        return self._store.get_findings_by_framework(framework)

    def get_credentials(self) -> list[dict[str, Any]]:
        """Get all credentials found across all frameworks.

        Returns:
            List of credential dicts, newest first.
        """
        return self._store.get_all_credentials()

    def get_chain_actions(self, executed: bool | None = None) -> list[dict[str, Any]]:
        """Get cross-framework chain actions.

        Args:
            executed: Filter by execution status. None = all.
        """
        return self._store.get_chain_actions(executed)

    def get_intel(self) -> EngagementIntelligence:
        """Get full engagement intelligence for the planner.

        Aggregates all findings, credentials, and chain actions into
        a single EngagementIntelligence struct.

        Returns:
            EngagementIntelligence with all cross-framework data.
        """
        findings = self._store.get_all_findings()
        creds = self._store.get_all_credentials()
        chains = self._store.get_chain_actions()

        # Classify findings by type
        shells = [
            f for f in findings
            if any(kw in (f.get("title") or "").lower()
                   for kw in ("shell", "rce", "command execution"))
        ]
        persistence = [
            f for f in findings
            if any(kw in (f.get("title") or "").lower()
                   for kw in ("persistence", "backdoor", "cron", "scheduled task"))
        ]
        lateral = [
            f for f in findings
            if any(kw in (f.get("title") or "").lower()
                   for kw in ("lateral", "pivot", "pass-the-hash", "relay"))
        ]

        frameworks = list(set(f.get("framework", "") for f in findings) - {""})

        return EngagementIntelligence(
            findings=findings,
            credentials=creds,
            shells=shells,
            persistence=persistence,
            lateral_moves=lateral,
            chain_actions=chains,
            frameworks_active=sorted(frameworks),
            total_findings=len(findings),
            severity_counts=self._store.severity_counts(),
        )

    # ── Stats ─────────────────────────────────────────────────────────

    @property
    def stats(self) -> dict[str, Any]:
        """Runtime stats for the engagement bus."""
        return {
            "total_published": self._total_published,
            "total_chains_triggered": self._total_chains_triggered,
            "findings_in_store": self._store.count_findings(),
            "severity_counts": self._store.severity_counts(),
            "findings_since_plan": self._findings_since_plan,
            "sync_subscribers": len(self._sync_subscribers),
            "async_subscribers": len(self._async_subscribers),
            "brain_available": bool(
                self._brain and getattr(self._brain, "available", False)
            ),
            "planner_attached": self._planner is not None,
            "event_bus_attached": self._event_bus is not None,
        }

    # ── Internal Helpers ──────────────────────────────────────────────

    def _emit_event(self, event_type_str: str, data: dict[str, Any]) -> None:
        """Emit an event to the dashboard EventBus if attached."""
        if not self._event_bus:
            return
        try:
            from common.dashboard.event_bus import Event, EventType
            # Map string to EventType enum
            type_map = {
                "finding_new": EventType.FINDING_NEW,
                "credential_found": EventType.CREDENTIAL_FOUND,
            }
            etype = type_map.get(event_type_str)
            if etype:
                self._event_bus.emit(Event(
                    event_type=etype,
                    data=data,
                    source="engagement_bus",
                ))
            else:
                # For new event types (BRAIN_VERDICT, CHAIN_ACTION_NEW),
                # emit as data with state_snapshot until we add them to EventType
                self._event_bus.emit(Event(
                    event_type=EventType.STATE_SNAPSHOT,
                    data={"sub_type": event_type_str, **data},
                    source="engagement_bus",
                ))
        except Exception as exc:
            log.debug("EventBus emit failed (non-critical): %s", exc)

    async def _analyze_with_brain(
        self, finding_id: str, finding: dict[str, Any]
    ) -> None:
        """Analyze a finding with ForgeBrain and store the verdict."""
        try:
            result = await self._brain.analyze_finding(finding)
            self._store.update_brain_verdict(
                finding_id,
                result.verdict.value,
                result.confidence.value,
                result.reasoning,
            )
            log.debug(
                "Brain verdict for %s: %s (%s)",
                finding_id, result.verdict.value, result.confidence.value,
            )
            self._emit_event("brain_verdict", {
                "finding_id": finding_id,
                "verdict": result.verdict.value,
                "confidence": result.confidence.value,
                "reasoning": result.reasoning[:200],
            })
        except Exception as exc:
            log.warning("Brain analysis failed for %s: %s", finding_id, exc)

    async def _auto_plan(self) -> None:
        """Auto-trigger the planner after N new findings."""
        if not self._planner:
            return
        try:
            intel = self.get_intel()
            plan = await self._planner.plan_next(
                intel.to_dict(),
                target_context={},
            )
            for action in plan.actions:
                log.info(
                    "Planner suggests: [%s] %s/%s → %s",
                    action.phase, action.framework, action.module, action.target,
                )
                self._emit_event("chain_action_new", {
                    "phase": action.phase,
                    "framework": action.framework,
                    "module": action.module,
                    "target": action.target,
                    "rationale": action.rationale,
                    "auto_execute": action.auto_execute,
                })
        except Exception as exc:
            log.warning("Auto-plan failed: %s", exc)

    def close(self) -> None:
        """Close the engagement bus and its store."""
        self._store.close()


# ══════════════════════════════════════════════════════════════════════
# TESTS
# ══════════════════════════════════════════════════════════════════════

class TestEngagementBus:
    """Unit tests for EngagementBus."""

    @staticmethod
    def _make_bus(tmp_path: str = ":memory:") -> EngagementBus:
        """Create a test bus with in-memory DB."""
        EngagementBus.reset_instance()
        return EngagementBus(db_path=tmp_path)

    def test_store_and_retrieve_finding(self) -> None:
        bus = self._make_bus()
        store = bus._store
        fid = store.store_finding("webforge", {
            "id": "test-1",
            "title": "SQLi in login",
            "severity": "Critical",
            "target": "https://example.com",
            "module": "sqli_scanner",
        })
        assert fid == "test-1"
        findings = store.get_all_findings()
        assert len(findings) >= 1
        assert findings[0]["title"] == "SQLi in login"
        bus.close()

    def test_store_and_retrieve_credential(self) -> None:
        bus = self._make_bus()
        store = bus._store
        cid = store.store_credential("netforge", {
            "host": "10.0.0.1",
            "service": "ssh",
            "username": "admin",
            "password": "hunter2",
        })
        creds = store.get_all_credentials()
        assert len(creds) >= 1
        assert creds[0]["username"] == "admin"
        bus.close()

    def test_severity_counts(self) -> None:
        bus = self._make_bus()
        store = bus._store
        store.store_finding("webforge", {"title": "SQLi", "severity": "Critical"})
        store.store_finding("webforge", {"title": "XSS", "severity": "High"})
        store.store_finding("netforge", {"title": "Info", "severity": "Critical"})
        counts = store.severity_counts()
        assert counts.get("Critical", 0) == 2
        assert counts.get("High", 0) == 1
        bus.close()

    def test_chain_detection_sqli(self) -> None:
        finding = {"id": "f1", "title": "SQL Injection in login", "target": "https://app.com"}
        chains = _detect_chains("webforge", finding)
        types = [c.chain_type for c in chains]
        assert ChainType.SQLI_TO_CRED_SPRAY in types

    def test_chain_detection_xss(self) -> None:
        finding = {"id": "f2", "title": "Stored XSS in comments", "target": "https://app.com"}
        chains = _detect_chains("webforge", finding)
        types = [c.chain_type for c in chains]
        assert ChainType.XSS_TO_SESSION_HIJACK in types

    def test_chain_detection_smb(self) -> None:
        finding = {"id": "f3", "title": "SMB Signing Disabled on DC", "target": "10.0.0.1"}
        chains = _detect_chains("netforge", finding)
        types = [c.chain_type for c in chains]
        assert ChainType.SMB_SIGNING_TO_RELAY in types

    def test_chain_detection_rce(self) -> None:
        finding = {"id": "f4", "title": "Remote Code Execution via deserialization", "target": "10.0.0.5"}
        chains = _detect_chains("netforge", finding)
        types = [c.chain_type for c in chains]
        assert ChainType.HOST_COMPROMISE_TO_C2 in types

    def test_chain_detection_ssrf(self) -> None:
        finding = {"id": "f5", "title": "SSRF via image proxy", "target": "https://app.com/proxy"}
        chains = _detect_chains("webforge", finding)
        types = [c.chain_type for c in chains]
        assert ChainType.SSRF_TO_INTERNAL_RECON in types

    def test_chain_detection_upload(self) -> None:
        finding = {"id": "f6", "title": "Unrestricted file upload", "target": "https://app.com"}
        chains = _detect_chains("webforge", finding)
        types = [c.chain_type for c in chains]
        assert ChainType.UPLOAD_TO_WEBSHELL in types

    def test_chain_detection_ad_creds(self) -> None:
        finding = {"id": "f7", "title": "Kerberoastable service account", "target": "dc.corp.local"}
        chains = _detect_chains("adforge", finding)
        types = [c.chain_type for c in chains]
        assert ChainType.DOMAIN_CREDS_TO_LATERAL in types

    def test_chain_detection_smb_not_enforced(self) -> None:
        finding = {"id": "f3b", "title": "SMB Signing Not Enforced on 10.0.0.5", "target": "10.0.0.5"}
        chains = _detect_chains("netforge", finding)
        types = [c.chain_type for c in chains]
        assert ChainType.SMB_SIGNING_TO_RELAY in types

    def test_chain_detection_smb_not_required(self) -> None:
        finding = {"id": "f3c", "title": "SMB Signing Not Required — 10.0.0.10", "target": "10.0.0.10"}
        chains = _detect_chains("netforge", finding)
        types = [c.chain_type for c in chains]
        assert ChainType.SMB_SIGNING_TO_RELAY in types

    def test_chain_detection_adcs_esc(self) -> None:
        finding = {"id": "f8", "title": "ADCS ESC1 — Vulnerable Certificate Template", "target": "dc.corp.local"}
        chains = _detect_chains("adforge", finding)
        types = [c.chain_type for c in chains]
        assert ChainType.ADCS_ESC_TO_DOMAIN_ADMIN in types

    def test_chain_detection_zerologon(self) -> None:
        finding = {"id": "f9", "title": "Zerologon (CVE-2020-1472) — DC Vulnerable", "target": "10.0.0.5"}
        chains = _detect_chains("adforge", finding)
        types = [c.chain_type for c in chains]
        assert ChainType.ZEROLOGON_TO_DOMAIN_COMPROMISE in types

    def test_publish_credential_domain_triggers_chain(self) -> None:
        import asyncio
        bus = self._make_bus()
        cred = {
            "host": "dc.corp.local",
            "domain": "corp.local",
            "username": "svc_account",
            "password": "Password1!",
        }
        asyncio.run(bus.publish_credential("adforge", cred))
        chains = bus.get_chain_actions()
        chain_types = [c["chain_type"] for c in chains]
        assert ChainType.DOMAIN_CREDS_TO_LATERAL.value in chain_types
        bus.close()

    def test_publish_credential_no_domain_no_chain(self) -> None:
        import asyncio
        bus = self._make_bus()
        cred = {"host": "10.0.0.1", "username": "admin", "password": "pass123"}
        asyncio.run(bus.publish_credential("netforge", cred))
        chains = bus.get_chain_actions()
        assert len(chains) == 0
        bus.close()

    def test_async_unsubscribe(self) -> None:
        bus = self._make_bus()
        received: list = []

        async def cb(fw: str, f: dict) -> None:
            received.append(fw)

        bus.async_subscribe(cb)
        assert len(bus._async_subscribers) == 1
        bus.async_unsubscribe(cb)
        assert len(bus._async_subscribers) == 0
        bus.close()

    def test_no_chain_for_unrelated_finding(self) -> None:
        finding = {"id": "f99", "title": "Missing X-Frame-Options header", "target": "https://app.com"}
        chains = _detect_chains("webforge", finding)
        assert len(chains) == 0

    def test_publish_async(self) -> None:
        """Test that publish() works end-to-end."""
        import asyncio
        bus = self._make_bus()
        received: list[tuple[str, dict]] = []
        bus.subscribe(lambda fw, f: received.append((fw, f)))

        finding = {
            "title": "SQL Injection",
            "severity": "Critical",
            "target": "https://example.com",
        }
        fid = asyncio.run(bus.publish("webforge", finding))
        assert fid  # got an ID back
        assert len(received) == 1
        assert received[0][0] == "webforge"
        bus.close()

    def test_get_intel(self) -> None:
        bus = self._make_bus()
        store = bus._store
        store.store_finding("webforge", {
            "title": "SQL Injection", "severity": "Critical", "target": "https://app.com"
        })
        store.store_finding("netforge", {
            "title": "Shell access via RCE", "severity": "Critical", "target": "10.0.0.1"
        })
        store.store_credential("webforge", {
            "host": "db.local", "username": "admin", "password": "pass123"
        })

        intel = bus.get_intel()
        assert intel.total_findings == 2
        assert len(intel.credentials) == 1
        assert len(intel.shells) >= 1  # RCE finding classified as shell
        assert "webforge" in intel.frameworks_active
        bus.close()

    def test_stats(self) -> None:
        bus = self._make_bus()
        stats = bus.stats
        assert stats["total_published"] == 0
        assert stats["brain_available"] is False
        bus.close()

    def test_brain_verdict_storage(self) -> None:
        bus = self._make_bus()
        store = bus._store
        store.store_finding("webforge", {
            "id": "bv-1", "title": "XSS", "severity": "High"
        })
        store.update_brain_verdict("bv-1", "TRUE_POSITIVE", "HIGH", "Strong evidence")
        findings = store.get_all_findings()
        f = next(f for f in findings if f["id"] == "bv-1")
        assert f["brain_verdict"] == "TRUE_POSITIVE"
        assert f["brain_confidence"] == "HIGH"
        bus.close()

    def test_singleton_pattern(self) -> None:
        EngagementBus.reset_instance()
        b1 = EngagementBus.get_instance(db_path=":memory:")
        b2 = EngagementBus.get_instance()
        assert b1 is b2
        EngagementBus.reset_instance()

    def test_engagement_intelligence_to_dict(self) -> None:
        intel = EngagementIntelligence(
            findings=[{"title": "test"}],
            total_findings=1,
            severity_counts={"Critical": 1},
        )
        d = intel.to_dict()
        assert d["total_findings"] == 1
        assert d["severity_counts"]["Critical"] == 1
