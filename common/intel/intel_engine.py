"""Intelligence Pipeline — Main Coordinator.

The IntelEngine orchestrates all intelligence gathering: CVE databases,
exploit references, Nuclei detection templates, and MITRE ATT&CK technique
mappings. It delegates to specialized sync modules but owns the unified
search interface and lifecycle management.

Usage (CLI via forge.py):
    python3 forge.py intel sync --all
    python3 forge.py intel sync --cve --since 2025-01-01
    python3 forge.py intel search "Apache 2.4"
    python3 forge.py intel search --cve CVE-2024-1234
    python3 forge.py intel search --product "OpenSSH" --severity critical
    python3 forge.py intel status

Usage (programmatic):
    engine = IntelEngine()
    await engine.sync(sources=["cve", "exploits"])
    results = engine.search("Log4j", limit=10)
    print(engine.status())
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import sqlite3
import time
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any

log = logging.getLogger("forge.intel")


# ══════════════════════════════════════════════════════════════════════
# ENUMS & DATA CLASSES
# ══════════════════════════════════════════════════════════════════════

class IntelSource(str, Enum):
    """Available intelligence sources."""
    CVE        = "cve"
    EXPLOITS   = "exploits"
    NUCLEI     = "nuclei"
    TECHNIQUES = "techniques"

    @classmethod
    def all(cls) -> list["IntelSource"]:
        return list(cls)

    @classmethod
    def from_str(cls, name: str) -> "IntelSource":
        """Resolve a source name string to enum, case-insensitive."""
        name = name.strip().lower()
        for member in cls:
            if member.value == name:
                return member
        raise ValueError(f"Unknown intel source: '{name}'. Valid: {[s.value for s in cls]}")


class IntelSeverity(str, Enum):
    """Normalized severity levels for intel records."""
    CRITICAL = "critical"
    HIGH     = "high"
    MEDIUM   = "medium"
    LOW      = "low"
    INFO     = "info"
    UNKNOWN  = "unknown"


class SyncStatus(str, Enum):
    """State of a sync operation."""
    IDLE       = "idle"
    RUNNING    = "running"
    COMPLETED  = "completed"
    FAILED     = "failed"
    PARTIAL    = "partial"


@dataclass
class IntelRecord:
    """A single intelligence record — unified across all sources.

    This is the common format returned by search operations regardless
    of whether the underlying data is a CVE, an exploit, a Nuclei template,
    or an ATT&CK technique.
    """
    record_id:    str                          # Unique ID (CVE-2024-XXXX, EDB-XXXXX, etc.)
    source:       str                          # Which source this came from
    title:        str                          # Human-readable title
    description:  str           = ""           # Full description
    severity:     str           = "unknown"    # Normalized severity
    cvss_score:   float | None  = None         # CVSS score if applicable
    products:     list[str]     = field(default_factory=list)  # Affected products/CPEs
    references:   list[str]     = field(default_factory=list)  # External URLs
    tags:         list[str]     = field(default_factory=list)  # Classification tags
    exploit_available: bool     = False        # Has known exploit
    published_at: str           = ""           # ISO-8601 publish date
    updated_at:   str           = ""           # ISO-8601 last update
    raw_data:     dict[str, Any] = field(default_factory=dict)  # Original source data

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["raw_data"] = json.dumps(d["raw_data"])
        return d

    @classmethod
    def from_row(cls, row: dict[str, Any]) -> "IntelRecord":
        """Reconstruct from a SQLite row dict."""
        raw = row.get("raw_data", "{}")
        if isinstance(raw, str):
            try:
                raw = json.loads(raw)
            except (json.JSONDecodeError, TypeError):
                raw = {}
        products = row.get("products", "[]")
        if isinstance(products, str):
            try:
                products = json.loads(products)
            except (json.JSONDecodeError, TypeError):
                products = []
        references = row.get("references", "[]")
        if isinstance(references, str):
            try:
                references = json.loads(references)
            except (json.JSONDecodeError, TypeError):
                references = []
        tags = row.get("tags", "[]")
        if isinstance(tags, str):
            try:
                tags = json.loads(tags)
            except (json.JSONDecodeError, TypeError):
                tags = []
        return cls(
            record_id=row["record_id"],
            source=row["source"],
            title=row["title"],
            description=row.get("description", ""),
            severity=row.get("severity", "unknown"),
            cvss_score=row.get("cvss_score"),
            products=products,
            references=references,
            tags=tags,
            exploit_available=bool(row.get("exploit_available", False)),
            published_at=row.get("published_at", ""),
            updated_at=row.get("updated_at", ""),
            raw_data=raw,
        )

    def __str__(self) -> str:
        """CLI-friendly one-line summary."""
        sev = self.severity.upper()[:4].ljust(4)
        score = f"{self.cvss_score:.1f}" if self.cvss_score else "  - "
        exploit = "[!]" if self.exploit_available else "   "
        return f"  [{sev}] {score} {exploit} {self.record_id:20s}  {self.title[:80]}"


@dataclass
class SyncResult:
    """Outcome of a single source sync operation."""
    source:       str
    status:       SyncStatus     = SyncStatus.IDLE
    records_new:  int            = 0
    records_updated: int         = 0
    records_total: int           = 0
    duration:     float          = 0.0
    error:        str | None     = None
    started_at:   str            = ""
    completed_at: str            = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "status": self.status.value,
            "records_new": self.records_new,
            "records_updated": self.records_updated,
            "records_total": self.records_total,
            "duration": round(self.duration, 2),
            "error": self.error,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
        }


@dataclass
class SourceMeta:
    """Metadata about a registered intel source and its last sync."""
    source:          IntelSource
    last_sync:       str | None   = None      # ISO-8601
    record_count:    int          = 0
    sync_status:     SyncStatus   = SyncStatus.IDLE
    sync_module:     str | None   = None      # Module path for dynamic import
    description:     str          = ""


# ══════════════════════════════════════════════════════════════════════
# INTEL DATABASE — Local SQLite storage
# ══════════════════════════════════════════════════════════════════════

# Default DB location: common/intel/forge_intel.db
# Can be overridden via FORGE_INTEL_DB env var
DEFAULT_DB_PATH = Path(__file__).parent / "forge_intel.db"


def _get_db_path() -> Path:
    """Resolve the intel database path, respecting env override."""
    env_path = os.environ.get("FORGE_INTEL_DB")
    if env_path:
        return Path(env_path)
    return DEFAULT_DB_PATH


def _init_db(db_path: Path) -> sqlite3.Connection:
    """Initialize the intel SQLite database with schema.

    Creates the database file and all tables if they don't exist.
    Uses WAL mode for concurrent read access during scans.

    Returns:
        sqlite3.Connection with row_factory=sqlite3.Row
    """
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")

    # ── Intel records table ───────────────────────────────────────
    conn.execute("""
        CREATE TABLE IF NOT EXISTS intel_records (
            record_id         TEXT PRIMARY KEY,
            source            TEXT NOT NULL,
            title             TEXT NOT NULL,
            description       TEXT DEFAULT '',
            severity          TEXT DEFAULT 'unknown',
            cvss_score        REAL,
            products          TEXT DEFAULT '[]',
            references_json   TEXT DEFAULT '[]',
            tags              TEXT DEFAULT '[]',
            exploit_available INTEGER DEFAULT 0,
            published_at      TEXT DEFAULT '',
            updated_at        TEXT DEFAULT '',
            raw_data          TEXT DEFAULT '{}',
            indexed_at        TEXT DEFAULT (datetime('now'))
        )
    """)

    # ── Full-text search virtual table (standalone, no content sync) ─
    # Using a standalone FTS5 table instead of content-synced to avoid
    # "database disk image malformed" errors across SQLite versions.
    # We manually keep it in sync via rebuild_fts / _rebuild_fts_for_source.
    conn.execute("""
        CREATE VIRTUAL TABLE IF NOT EXISTS intel_fts USING fts5(
            record_id,
            title,
            description,
            products,
            tags
        )
    """)

    # ── Sync metadata table ───────────────────────────────────────
    conn.execute("""
        CREATE TABLE IF NOT EXISTS sync_meta (
            source        TEXT PRIMARY KEY,
            last_sync     TEXT,
            record_count  INTEGER DEFAULT 0,
            last_status   TEXT DEFAULT 'idle',
            last_error    TEXT,
            last_duration REAL DEFAULT 0.0
        )
    """)

    # ── Sync history / audit log ──────────────────────────────────
    conn.execute("""
        CREATE TABLE IF NOT EXISTS sync_history (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            source        TEXT NOT NULL,
            status        TEXT NOT NULL,
            records_new   INTEGER DEFAULT 0,
            records_updated INTEGER DEFAULT 0,
            records_total INTEGER DEFAULT 0,
            duration      REAL DEFAULT 0.0,
            error         TEXT,
            started_at    TEXT,
            completed_at  TEXT
        )
    """)

    # ── Indexes for common queries ────────────────────────────────
    conn.execute("CREATE INDEX IF NOT EXISTS idx_intel_source ON intel_records(source)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_intel_severity ON intel_records(severity)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_intel_cvss ON intel_records(cvss_score)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_intel_published ON intel_records(published_at)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_intel_exploit ON intel_records(exploit_available)")

    conn.commit()
    log.debug("Intel database initialized: %s", db_path)
    return conn


# ══════════════════════════════════════════════════════════════════════
# INTEL ENGINE — Main Coordinator
# ══════════════════════════════════════════════════════════════════════

class IntelEngine:
    """Central coordinator for the intelligence pipeline.

    Manages sync operations across all intelligence sources, provides
    unified search, and handles lifecycle/status reporting. Integrates
    with the EventBus to push intel events to the War Room dashboard.

    Attributes:
        db_path:    Path to the SQLite intel database.
        event_bus:  Optional EventBus for dashboard integration.
        offline:    If True, skip all network operations.
        sources:    Registry of available intel source modules.

    Usage::

        engine = IntelEngine()

        # Sync all sources
        results = await engine.sync_async(sources=["cve", "exploits"])

        # Synchronous wrapper (used by forge.py CLI)
        engine.sync(sources=["cve"], since="2025-01-01")

        # Search local database
        hits = engine.search("Apache httpd", limit=20)

        # Check sync status
        print(engine.status())
    """

    # Source registry — maps source name to (module_path, class_name, description)
    SOURCE_REGISTRY: dict[str, tuple[str, str, str]] = {
        "cve": (
            "common.intel.cve_sync",
            "CVESync",
            "NVD API v2 — Common Vulnerabilities & Exposures",
        ),
        "exploits": (
            "common.intel.exploit_db_sync",
            "ExploitDBSync",
            "Exploit-DB — Public exploit archive mirror",
        ),
        "nuclei": (
            "common.intel.nuclei_sync",
            "NucleiSync",
            "ProjectDiscovery Nuclei — Detection templates",
        ),
        "techniques": (
            "common.intel.technique_learner",
            "TechniqueLearner",
            "MITRE ATT&CK — Adversary tactics & techniques",
        ),
    }

    def __init__(
        self,
        db_path: Path | None = None,
        event_bus: Any = None,
        offline: bool = False,
    ) -> None:
        """Initialize the intel engine.

        Args:
            db_path:    Override path for the SQLite database.
            event_bus:  Optional EventBus for dashboard events.
            offline:    If True, all sync operations are skipped.
        """
        self.db_path = db_path or _get_db_path()
        self.event_bus = event_bus
        self.offline = offline
        self._conn: sqlite3.Connection | None = None
        self._sync_results: dict[str, SyncResult] = {}
        self._active_syncs: set[str] = set()

    @property
    def conn(self) -> sqlite3.Connection:
        """Lazy-initialize the database connection."""
        if self._conn is None:
            self._conn = _init_db(self.db_path)
        return self._conn

    def close(self) -> None:
        """Close the database connection."""
        if self._conn is not None:
            self._conn.close()
            self._conn = None

    # ── Sync orchestration ────────────────────────────────────────

    def sync(
        self,
        sources: list[str] | None = None,
        since: str | None = None,
    ) -> list[SyncResult]:
        """Synchronous wrapper for sync_async — used by forge.py CLI.

        Args:
            sources: List of source names to sync (e.g. ["cve", "exploits"]).
                     None or empty means sync all.
            since:   Only sync records published after this date (YYYY-MM-DD).

        Returns:
            List of SyncResult, one per source.
        """
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None

        if loop and loop.is_running():
            # Already inside an async context — schedule as task
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor() as pool:
                future = pool.submit(asyncio.run, self.sync_async(sources, since))
                return future.result()
        else:
            return asyncio.run(self.sync_async(sources, since))

    async def sync_async(
        self,
        sources: list[str] | None = None,
        since: str | None = None,
    ) -> list[SyncResult]:
        """Sync intelligence from specified sources.

        Delegates to individual sync modules (cve_sync, exploit_db_sync, etc.)
        and collects results. Each sync module must implement:
            async def sync(conn, since=None, event_bus=None) -> SyncResult

        Args:
            sources: Source names to sync. None = all sources.
            since:   ISO date filter for incremental sync.

        Returns:
            List of SyncResult objects.
        """
        if self.offline:
            log.info("Offline mode — skipping intel sync")
            print("  [*] Offline mode — using cached intelligence only")
            return []

        # Resolve source list
        if not sources:
            source_keys = list(self.SOURCE_REGISTRY.keys())
        else:
            source_keys = []
            for s in sources:
                try:
                    resolved = IntelSource.from_str(s)
                    source_keys.append(resolved.value)
                except ValueError as e:
                    log.warning(str(e))
                    print(f"  [!] {e}")

        if not source_keys:
            log.warning("No valid intel sources to sync")
            return []

        # The legacy source adapters use raw urllib/aiohttp endpoints and have
        # no update-specific consumed envelope, endpoint pin, or outbound
        # audit.  Keep the library entry point inert as well as the CLI path;
        # direct programmatic invocation must not become an implicit updater.
        log.warning(
            "Intel sync disabled until pinned update endpoints use the outbound policy"
        )
        return [
            SyncResult(
                source=key,
                status=SyncStatus.FAILED,
                error="outbound_policy_unsupported",
            )
            for key in source_keys
        ]

        # Emit sync start event
        self._emit("intel_sync_start", sources=source_keys)
        print(f"\n  ╔══════════════════════════════════════════════════════╗")
        print(f"  ║  FORGE INTEL PIPELINE — Sync Starting               ║")
        print(f"  ╠══════════════════════════════════════════════════════╣")
        print(f"  ║  Sources: {', '.join(source_keys):42s} ║")
        if since:
            print(f"  ║  Since:   {since:42s} ║")
        print(f"  ╚══════════════════════════════════════════════════════╝\n")

        results: list[SyncResult] = []
        total_start = time.monotonic()

        for key in source_keys:
            result = await self._sync_source(key, since)
            results.append(result)
            self._sync_results[key] = result

            # Print per-source result
            icon = "✅" if result.status == SyncStatus.COMPLETED else "❌"
            print(f"  {icon} {key:12s}  +{result.records_new:5d} new  "
                  f"~{result.records_updated:5d} updated  "
                  f"({result.duration:.1f}s)")
            if result.error:
                print(f"     └─ Error: {result.error}")

        total_elapsed = time.monotonic() - total_start

        # Summary
        total_new = sum(r.records_new for r in results)
        total_updated = sum(r.records_updated for r in results)
        succeeded = sum(1 for r in results if r.status == SyncStatus.COMPLETED)
        failed = sum(1 for r in results if r.status == SyncStatus.FAILED)

        print(f"\n  ── Sync Complete ──────────────────────────────────────")
        print(f"  Sources: {succeeded} succeeded, {failed} failed")
        print(f"  Records: +{total_new} new, ~{total_updated} updated")
        print(f"  Duration: {total_elapsed:.1f}s\n")

        # Emit sync complete event
        self._emit(
            "intel_sync_complete",
            sources=source_keys,
            records_new=total_new,
            records_updated=total_updated,
            duration=round(total_elapsed, 2),
        )

        return results

    async def _sync_source(self, source_key: str, since: str | None = None) -> SyncResult:
        """Sync a single intelligence source.

        Attempts to import and delegate to the source's sync module.
        Falls back gracefully if the module isn't built yet.

        Args:
            source_key: The source identifier (e.g. "cve").
            since:      Optional date filter.

        Returns:
            SyncResult with outcome.
        """
        result = SyncResult(
            source=source_key,
            started_at=datetime.now(timezone.utc).isoformat(),
        )
        self._active_syncs.add(source_key)

        try:
            if source_key not in self.SOURCE_REGISTRY:
                raise ValueError(f"Unknown intel source: {source_key}")

            module_path, class_name, description = self.SOURCE_REGISTRY[source_key]
            log.info("Syncing intel source: %s (%s)", source_key, description)

            # Dynamic import of the sync module
            try:
                import importlib
                mod = importlib.import_module(module_path)
                sync_class = getattr(mod, class_name)
            except (ImportError, AttributeError) as e:
                # Module not built yet — graceful degradation
                log.warning(
                    "Intel sync module not available: %s.%s — %s",
                    module_path, class_name, e,
                )
                result.status = SyncStatus.FAILED
                result.error = f"Module not yet built: {module_path}.{class_name}"
                self._record_sync_meta(result)
                return result

            # Instantiate and run the sync
            start = time.monotonic()
            result.status = SyncStatus.RUNNING

            syncer = sync_class()
            sync_outcome = await syncer.sync(
                conn=self.conn,
                since=since,
                event_bus=self.event_bus,
            )

            # Merge results from the sync module
            result.records_new = sync_outcome.get("records_new", 0)
            result.records_updated = sync_outcome.get("records_updated", 0)
            result.records_total = sync_outcome.get("records_total", 0)
            result.duration = time.monotonic() - start
            result.status = SyncStatus.COMPLETED

            # Update the FTS index for new records
            self._rebuild_fts_for_source(source_key)

        except Exception as exc:
            result.status = SyncStatus.FAILED
            result.error = str(exc)
            result.duration = time.monotonic() - time.monotonic()  # ~0
            log.error("Intel sync failed for %s: %s", source_key, exc, exc_info=True)

        finally:
            result.completed_at = datetime.now(timezone.utc).isoformat()
            self._active_syncs.discard(source_key)
            self._record_sync_meta(result)

        return result

    def _record_sync_meta(self, result: SyncResult) -> None:
        """Persist sync metadata and history to the database."""
        try:
            # Upsert sync_meta
            self.conn.execute("""
                INSERT INTO sync_meta (source, last_sync, record_count, last_status, last_error, last_duration)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(source) DO UPDATE SET
                    last_sync = excluded.last_sync,
                    record_count = excluded.record_count,
                    last_status = excluded.last_status,
                    last_error = excluded.last_error,
                    last_duration = excluded.last_duration
            """, (
                result.source,
                result.completed_at,
                result.records_total,
                result.status.value,
                result.error,
                result.duration,
            ))

            # Append to sync_history
            self.conn.execute("""
                INSERT INTO sync_history
                    (source, status, records_new, records_updated, records_total,
                     duration, error, started_at, completed_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                result.source,
                result.status.value,
                result.records_new,
                result.records_updated,
                result.records_total,
                result.duration,
                result.error,
                result.started_at,
                result.completed_at,
            ))

            self.conn.commit()
        except Exception as exc:
            log.debug("Failed to persist sync metadata: %s", exc)

    def _rebuild_fts_for_source(self, source: str) -> None:
        """Rebuild the FTS index for a specific source.

        Called after a sync to keep full-text search current.
        """
        try:
            # Delete existing FTS entries for this source
            self.conn.execute("""
                DELETE FROM intel_fts WHERE record_id IN (
                    SELECT record_id FROM intel_records WHERE source = ?
                )
            """, (source,))

            # Re-insert from intel_records
            self.conn.execute("""
                INSERT INTO intel_fts (record_id, title, description, products, tags)
                SELECT record_id, title, description, products, tags
                FROM intel_records WHERE source = ?
            """, (source,))

            self.conn.commit()
            log.debug("FTS index rebuilt for source: %s", source)
        except Exception as exc:
            log.debug("FTS rebuild failed for %s: %s", source, exc)

    # ── Record insertion (used by sync modules) ───────────────────

    def upsert_record(self, record: IntelRecord) -> bool:
        """Insert or update an intel record in the database.

        Used by sync modules to push their fetched data into the
        unified storage layer.

        Args:
            record: The IntelRecord to persist.

        Returns:
            True if the record was new (inserted), False if updated.
        """
        existing = self.conn.execute(
            "SELECT record_id FROM intel_records WHERE record_id = ?",
            (record.record_id,),
        ).fetchone()

        is_new = existing is None

        self.conn.execute("""
            INSERT INTO intel_records
                (record_id, source, title, description, severity, cvss_score,
                 products, references_json, tags, exploit_available,
                 published_at, updated_at, raw_data, indexed_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
            ON CONFLICT(record_id) DO UPDATE SET
                title = excluded.title,
                description = excluded.description,
                severity = excluded.severity,
                cvss_score = excluded.cvss_score,
                products = excluded.products,
                references_json = excluded.references_json,
                tags = excluded.tags,
                exploit_available = excluded.exploit_available,
                updated_at = excluded.updated_at,
                raw_data = excluded.raw_data,
                indexed_at = datetime('now')
        """, (
            record.record_id,
            record.source,
            record.title,
            record.description,
            record.severity,
            record.cvss_score,
            json.dumps(record.products),
            json.dumps(record.references),
            json.dumps(record.tags),
            1 if record.exploit_available else 0,
            record.published_at,
            record.updated_at,
            json.dumps(record.raw_data),
        ))
        self.conn.commit()

        # Emit event for new CVEs
        if is_new and record.source == IntelSource.CVE.value:
            self._emit(
                "intel_cve_new",
                cve_id=record.record_id,
                title=record.title,
                severity=record.severity,
                cvss=record.cvss_score,
            )

        return is_new

    def bulk_upsert(self, records: list[IntelRecord]) -> tuple[int, int]:
        """Batch insert/update records for performance.

        Args:
            records: List of IntelRecords to persist.

        Returns:
            Tuple of (new_count, updated_count).
        """
        new_count = 0
        updated_count = 0

        # Check existing IDs in one query
        if records:
            placeholders = ",".join("?" * len(records))
            ids = [r.record_id for r in records]
            existing_rows = self.conn.execute(
                f"SELECT record_id FROM intel_records WHERE record_id IN ({placeholders})",
                ids,
            ).fetchall()
            existing_ids = {row["record_id"] for row in existing_rows}
        else:
            existing_ids = set()

        for record in records:
            is_new = record.record_id not in existing_ids

            self.conn.execute("""
                INSERT INTO intel_records
                    (record_id, source, title, description, severity, cvss_score,
                     products, references_json, tags, exploit_available,
                     published_at, updated_at, raw_data, indexed_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
                ON CONFLICT(record_id) DO UPDATE SET
                    title = excluded.title,
                    description = excluded.description,
                    severity = excluded.severity,
                    cvss_score = excluded.cvss_score,
                    products = excluded.products,
                    references_json = excluded.references_json,
                    tags = excluded.tags,
                    exploit_available = excluded.exploit_available,
                    updated_at = excluded.updated_at,
                    raw_data = excluded.raw_data,
                    indexed_at = datetime('now')
            """, (
                record.record_id,
                record.source,
                record.title,
                record.description,
                record.severity,
                record.cvss_score,
                json.dumps(record.products),
                json.dumps(record.references),
                json.dumps(record.tags),
                1 if record.exploit_available else 0,
                record.published_at,
                record.updated_at,
                json.dumps(record.raw_data),
            ))

            if is_new:
                new_count += 1
            else:
                updated_count += 1

        self.conn.commit()
        return new_count, updated_count

    # ── Search ────────────────────────────────────────────────────

    def search(
        self,
        query: str | None = None,
        cve_id: str | None = None,
        product: str | None = None,
        severity: str | None = None,
        source: str | None = None,
        exploit_only: bool = False,
        since: str | None = None,
        limit: int = 20,
    ) -> list[IntelRecord]:
        """Search the local intelligence database.

        Supports full-text search, CVE ID lookup, product filtering,
        severity filtering, and source filtering. Results are ordered
        by relevance (FTS rank) then by CVSS score descending.

        Args:
            query:        Free-text search query (uses FTS5).
            cve_id:       Exact CVE ID lookup (e.g. "CVE-2024-1234").
            product:      Filter by affected product name.
            severity:     Filter by severity level.
            source:       Filter by intel source.
            exploit_only: Only return records with known exploits.
            since:        Only records published after this date.
            limit:        Maximum results to return.

        Returns:
            List of IntelRecord objects.
        """
        # Exact CVE lookup — fast path
        if cve_id:
            row = self.conn.execute(
                "SELECT * FROM intel_records WHERE record_id = ?",
                (cve_id.upper(),),
            ).fetchone()
            if row:
                return [self._row_to_record(dict(row))]
            return []

        # Full-text search via FTS5
        if query:
            return self._fts_search(query, severity, source, exploit_only, since, limit)

        # Filtered browse (no FTS)
        return self._filtered_search(product, severity, source, exploit_only, since, limit)

    def _fts_search(
        self,
        query: str,
        severity: str | None,
        source: str | None,
        exploit_only: bool,
        since: str | None,
        limit: int,
    ) -> list[IntelRecord]:
        """Full-text search using FTS5 index."""
        # Build the FTS query — escape special chars
        fts_query = query.replace('"', '""')

        sql = """
            SELECT r.*, fts.rank
            FROM intel_fts fts
            JOIN intel_records r ON r.record_id = fts.record_id
            WHERE intel_fts MATCH ?
        """
        params: list[Any] = [f'"{fts_query}"']

        if severity:
            sql += " AND r.severity = ?"
            params.append(severity.lower())
        if source:
            sql += " AND r.source = ?"
            params.append(source.lower())
        if exploit_only:
            sql += " AND r.exploit_available = 1"
        if since:
            sql += " AND r.published_at >= ?"
            params.append(since)

        sql += " ORDER BY fts.rank, r.cvss_score DESC LIMIT ?"
        params.append(limit)

        try:
            rows = self.conn.execute(sql, params).fetchall()
            return [self._row_to_record(dict(row)) for row in rows]
        except sqlite3.OperationalError as e:
            # FTS table might be empty or corrupt — fallback to LIKE
            log.debug("FTS search failed, falling back to LIKE: %s", e)
            return self._filtered_search(query, severity, source, exploit_only, since, limit)

    def _filtered_search(
        self,
        product_or_query: str | None,
        severity: str | None,
        source: str | None,
        exploit_only: bool,
        since: str | None,
        limit: int,
    ) -> list[IntelRecord]:
        """Filtered search using standard SQL LIKE."""
        sql = "SELECT * FROM intel_records WHERE 1=1"
        params: list[Any] = []

        if product_or_query:
            sql += " AND (title LIKE ? OR description LIKE ? OR products LIKE ?)"
            like = f"%{product_or_query}%"
            params.extend([like, like, like])
        if severity:
            sql += " AND severity = ?"
            params.append(severity.lower())
        if source:
            sql += " AND source = ?"
            params.append(source.lower())
        if exploit_only:
            sql += " AND exploit_available = 1"
        if since:
            sql += " AND published_at >= ?"
            params.append(since)

        sql += " ORDER BY cvss_score DESC, published_at DESC LIMIT ?"
        params.append(limit)

        rows = self.conn.execute(sql, params).fetchall()
        return [self._row_to_record(dict(row)) for row in rows]

    def _row_to_record(self, row: dict[str, Any]) -> IntelRecord:
        """Convert a database row dict to an IntelRecord.

        Handles the column name difference (references_json → references).
        """
        # Map DB column name to dataclass field name
        if "references_json" in row:
            row["references"] = row.pop("references_json")
        # Remove DB-only fields
        row.pop("indexed_at", None)
        row.pop("rank", None)
        return IntelRecord.from_row(row)

    # ── Status reporting ──────────────────────────────────────────

    def status(self) -> str:
        """Human-readable status report of the intel pipeline.

        Shows per-source record counts, last sync times, and database
        size. Used by `forge.py intel status`.

        Returns:
            Formatted multi-line status string.
        """
        lines = []
        lines.append("")
        lines.append("  ╔══════════════════════════════════════════════════════════════╗")
        lines.append("  ║             FORGE INTEL PIPELINE — Status                   ║")
        lines.append("  ╠══════════════════════════════════════════════════════════════╣")

        # Per-source status
        for source_key, (mod_path, cls_name, description) in self.SOURCE_REGISTRY.items():
            meta = self._get_source_meta(source_key)
            icon = "🟢" if meta["last_status"] == "completed" else "🔴" if meta["last_status"] == "failed" else "⚪"
            count = meta["record_count"]
            last = meta["last_sync"] or "never"
            if last != "never":
                # Truncate to just date + time
                last = last[:19].replace("T", " ")

            lines.append(f"  ║  {icon} {source_key:12s}  {count:>7,d} records  │  Last: {last:20s}║")

        lines.append("  ╠══════════════════════════════════════════════════════════════╣")

        # Totals
        total = self._get_total_records()
        db_size = self._get_db_size()
        lines.append(f"  ║  Total Records: {total:>10,d}                                  ║")
        lines.append(f"  ║  Database Size: {db_size:>10s}                                  ║")
        lines.append(f"  ║  Database Path: {str(self.db_path)[:42]:42s}  ║")
        lines.append("  ╚══════════════════════════════════════════════════════════════╝")
        lines.append("")

        return "\n".join(lines)

    def _get_source_meta(self, source: str) -> dict[str, Any]:
        """Get sync metadata for a specific source."""
        row = self.conn.execute(
            "SELECT * FROM sync_meta WHERE source = ?", (source,)
        ).fetchone()
        if row:
            return dict(row)
        return {
            "source": source,
            "last_sync": None,
            "record_count": 0,
            "last_status": "idle",
            "last_error": None,
            "last_duration": 0.0,
        }

    def _get_total_records(self) -> int:
        """Get total record count across all sources."""
        row = self.conn.execute("SELECT COUNT(*) as cnt FROM intel_records").fetchone()
        return row["cnt"] if row else 0

    def _get_db_size(self) -> str:
        """Get human-readable database file size."""
        if self.db_path.exists():
            size = float(self.db_path.stat().st_size)
            for unit in ("B", "KB", "MB", "GB"):
                if size < 1024:
                    return f"{size:.1f} {unit}"
                size /= 1024
            return f"{size:.1f} TB"
        return "0 B"

    def get_sync_history(self, source: str | None = None, limit: int = 10) -> list[dict[str, Any]]:
        """Get recent sync history entries.

        Args:
            source: Filter by source, or None for all.
            limit:  Max entries to return.

        Returns:
            List of sync history dicts, newest first.
        """
        if source:
            rows = self.conn.execute(
                "SELECT * FROM sync_history WHERE source = ? ORDER BY id DESC LIMIT ?",
                (source, limit),
            ).fetchall()
        else:
            rows = self.conn.execute(
                "SELECT * FROM sync_history ORDER BY id DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [dict(row) for row in rows]

    # ── Lookup helpers for scan-time enrichment ───────────────────

    def lookup_cve(self, cve_id: str) -> IntelRecord | None:
        """Quick CVE lookup by ID. Returns None if not found."""
        results = self.search(cve_id=cve_id)
        return results[0] if results else None

    def lookup_product_cves(
        self,
        product: str,
        version: str | None = None,
        severity_min: str | None = None,
    ) -> list[IntelRecord]:
        """Find CVEs affecting a specific product.

        Used by scanning modules to enrich findings with CVE context.

        Args:
            product:      Product name to search.
            version:      Optional version string to narrow results.
            severity_min: Minimum severity ("low", "medium", "high", "critical").

        Returns:
            List of matching IntelRecords.
        """
        query = product
        if version:
            query = f"{product} {version}"
        return self.search(query=query, severity=severity_min, source="cve", limit=50)

    def has_exploit(self, cve_id: str) -> bool:
        """Check if a CVE has a known public exploit.

        Args:
            cve_id: The CVE identifier.

        Returns:
            True if an exploit reference exists.
        """
        row = self.conn.execute(
            "SELECT exploit_available FROM intel_records WHERE record_id = ?",
            (cve_id.upper(),),
        ).fetchone()
        return bool(row and row["exploit_available"])

    def get_techniques_for_tactic(self, tactic: str) -> list[IntelRecord]:
        """Get ATT&CK techniques for a specific tactic.

        Args:
            tactic: MITRE ATT&CK tactic name (e.g. "initial-access").

        Returns:
            List of technique IntelRecords.
        """
        return self.search(
            query=tactic,
            source="techniques",
            limit=100,
        )

    # ── Statistics ────────────────────────────────────────────────

    def stats(self) -> dict[str, Any]:
        """Get comprehensive statistics about the intel database.

        Returns:
            Dict with counts, breakdowns, and timing info.
        """
        total = self._get_total_records()

        # Per-source counts
        source_counts = {}
        for src in self.SOURCE_REGISTRY:
            row = self.conn.execute(
                "SELECT COUNT(*) as cnt FROM intel_records WHERE source = ?",
                (src,),
            ).fetchone()
            source_counts[src] = row["cnt"] if row else 0

        # Severity distribution
        severity_dist = {}
        rows = self.conn.execute(
            "SELECT severity, COUNT(*) as cnt FROM intel_records GROUP BY severity"
        ).fetchall()
        for row in rows:
            severity_dist[row["severity"]] = row["cnt"]

        # Exploit coverage
        exploit_count = self.conn.execute(
            "SELECT COUNT(*) as cnt FROM intel_records WHERE exploit_available = 1"
        ).fetchone()

        # Date range
        oldest = self.conn.execute(
            "SELECT MIN(published_at) as oldest FROM intel_records WHERE published_at != ''"
        ).fetchone()
        newest = self.conn.execute(
            "SELECT MAX(published_at) as newest FROM intel_records WHERE published_at != ''"
        ).fetchone()

        return {
            "total_records": total,
            "by_source": source_counts,
            "by_severity": severity_dist,
            "with_exploit": exploit_count["cnt"] if exploit_count else 0,
            "oldest_record": oldest["oldest"] if oldest else None,
            "newest_record": newest["newest"] if newest else None,
            "db_path": str(self.db_path),
            "db_size": self._get_db_size(),
        }

    # ── EventBus integration ──────────────────────────────────────

    def _emit(self, event_type: str, **data: Any) -> None:
        """Emit an event to the dashboard EventBus.

        Follows the same lazy-import pattern as TargetManager and
        the framework orchestrators — never crash the main flow.
        """
        if not self.event_bus:
            return
        try:
            from common.dashboard.event_bus import Event, EventType
            et = EventType(event_type)
            self.event_bus.emit(Event(
                event_type=et,
                data=data,
                source="intel_engine",
            ))
        except (ValueError, ImportError):
            pass

    # ── Maintenance ───────────────────────────────────────────────

    def vacuum(self) -> None:
        """Compact the database file."""
        self.conn.execute("VACUUM")
        log.info("Intel database vacuumed: %s", self.db_path)

    def rebuild_fts(self) -> None:
        """Full rebuild of the FTS index from intel_records."""
        self.conn.execute("DELETE FROM intel_fts")
        self.conn.execute("""
            INSERT INTO intel_fts (record_id, title, description, products, tags)
            SELECT record_id, title, description, products, tags
            FROM intel_records
        """)
        self.conn.commit()
        log.info("FTS index fully rebuilt")

    def purge_source(self, source: str) -> int:
        """Delete all records for a specific source.

        Args:
            source: The source to purge.

        Returns:
            Number of records deleted.
        """
        cursor = self.conn.execute(
            "DELETE FROM intel_records WHERE source = ?", (source,)
        )
        self.conn.execute(
            "DELETE FROM sync_meta WHERE source = ?", (source,)
        )
        self.conn.commit()
        deleted = cursor.rowcount
        self._rebuild_fts_for_source(source)
        log.info("Purged %d records from source: %s", deleted, source)
        return deleted

    def __del__(self) -> None:
        """Ensure database connection is closed on cleanup."""
        self.close()


# ══════════════════════════════════════════════════════════════════════
# UNIT TESTS
# ══════════════════════════════════════════════════════════════════════

class TestIntelEngine:
    """Unit tests for the IntelEngine."""

    def _make_engine(self, tmp_path: Path) -> IntelEngine:
        db = tmp_path / "test_intel.db"
        return IntelEngine(db_path=db)

    def test_init_creates_db(self, tmp_path: Path) -> None:
        engine = self._make_engine(tmp_path)
        _ = engine.conn  # Trigger lazy init
        assert (tmp_path / "test_intel.db").exists()
        engine.close()

    def test_upsert_and_search(self, tmp_path: Path) -> None:
        engine = self._make_engine(tmp_path)
        record = IntelRecord(
            record_id="CVE-2024-9999",
            source="cve",
            title="Test Vulnerability in Apache httpd 2.4.51",
            description="A critical buffer overflow in Apache httpd allows RCE",
            severity="critical",
            cvss_score=9.8,
            products=["cpe:2.3:a:apache:http_server:2.4.51"],
            references=["https://nvd.nist.gov/vuln/detail/CVE-2024-9999"],
            tags=["rce", "buffer-overflow"],
            exploit_available=True,
            published_at="2024-03-15T00:00:00Z",
        )
        is_new = engine.upsert_record(record)
        assert is_new is True

        # Rebuild FTS for search
        engine.rebuild_fts()

        # Search by text
        results = engine.search(query="Apache httpd")
        assert len(results) >= 1
        assert results[0].record_id == "CVE-2024-9999"

        # Search by CVE ID
        results = engine.search(cve_id="CVE-2024-9999")
        assert len(results) == 1
        assert results[0].cvss_score == 9.8

        engine.close()

    def test_bulk_upsert(self, tmp_path: Path) -> None:
        engine = self._make_engine(tmp_path)
        records = [
            IntelRecord(
                record_id=f"CVE-2024-{i:04d}",
                source="cve",
                title=f"Test Vuln {i}",
                severity="high",
                cvss_score=7.5,
            )
            for i in range(10)
        ]
        new, updated = engine.bulk_upsert(records)
        assert new == 10
        assert updated == 0

        # Upsert same records — should all be updates
        new2, updated2 = engine.bulk_upsert(records)
        assert new2 == 0
        assert updated2 == 10
        engine.close()

    def test_stats(self, tmp_path: Path) -> None:
        engine = self._make_engine(tmp_path)
        engine.upsert_record(IntelRecord(
            record_id="CVE-2024-0001", source="cve",
            title="Test", severity="critical", cvss_score=9.0,
        ))
        engine.upsert_record(IntelRecord(
            record_id="EDB-12345", source="exploits",
            title="Test Exploit", severity="high",
        ))
        s = engine.stats()
        assert s["total_records"] == 2
        assert s["by_source"]["cve"] == 1
        assert s["by_source"]["exploits"] == 1
        engine.close()

    def test_status_output(self, tmp_path: Path) -> None:
        engine = self._make_engine(tmp_path)
        status = engine.status()
        assert "FORGE INTEL PIPELINE" in status
        assert "Total Records" in status
        engine.close()

    def test_offline_mode(self, tmp_path: Path) -> None:
        engine = IntelEngine(db_path=tmp_path / "offline.db", offline=True)
        # sync should return empty list in offline mode
        results = engine.sync(sources=["cve"])
        assert results == []
        engine.close()

    def test_lookup_cve(self, tmp_path: Path) -> None:
        engine = self._make_engine(tmp_path)
        engine.upsert_record(IntelRecord(
            record_id="CVE-2024-5555",
            source="cve",
            title="Known vuln",
            severity="high",
            cvss_score=8.1,
        ))
        result = engine.lookup_cve("CVE-2024-5555")
        assert result is not None
        assert result.cvss_score == 8.1

        missing = engine.lookup_cve("CVE-9999-0000")
        assert missing is None
        engine.close()

    def test_has_exploit(self, tmp_path: Path) -> None:
        engine = self._make_engine(tmp_path)
        engine.upsert_record(IntelRecord(
            record_id="CVE-2024-7777",
            source="cve",
            title="Exploitable vuln",
            exploit_available=True,
        ))
        assert engine.has_exploit("CVE-2024-7777") is True
        assert engine.has_exploit("CVE-2024-0000") is False
        engine.close()

    def test_purge_source(self, tmp_path: Path) -> None:
        engine = self._make_engine(tmp_path)
        for i in range(5):
            engine.upsert_record(IntelRecord(
                record_id=f"NUC-{i:04d}", source="nuclei",
                title=f"Template {i}",
            ))
        deleted = engine.purge_source("nuclei")
        assert deleted == 5
        assert engine._get_total_records() == 0
        engine.close()

    def test_severity_filter(self, tmp_path: Path) -> None:
        engine = self._make_engine(tmp_path)
        engine.upsert_record(IntelRecord(
            record_id="CVE-2024-A001", source="cve",
            title="Critical thing", severity="critical", cvss_score=9.5,
        ))
        engine.upsert_record(IntelRecord(
            record_id="CVE-2024-A002", source="cve",
            title="Low thing", severity="low", cvss_score=2.1,
        ))
        results = engine.search(severity="critical")
        assert len(results) == 1
        assert results[0].severity == "critical"
        engine.close()

    def test_record_str_repr(self) -> None:
        r = IntelRecord(
            record_id="CVE-2024-1234",
            source="cve",
            title="Buffer overflow in libpng",
            severity="high",
            cvss_score=8.5,
            exploit_available=True,
        )
        s = str(r)
        assert "CVE-2024-1234" in s
        assert "HIGH" in s or "high" in s.lower()
        assert "[!]" in s
