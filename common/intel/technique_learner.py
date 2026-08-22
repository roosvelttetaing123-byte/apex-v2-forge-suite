"""Technique Learner — MITRE ATT&CK Technique Database.

Fetches the MITRE ATT&CK Enterprise knowledge base and stores normalized
technique/tactic records in the local intel SQLite database. Provides
mappings between techniques, tactics, mitigations, and software used by
threat groups — essential for kill chain analysis and red team planning.

Data Source:
    MITRE ATT&CK STIX 2.1 JSON bundles (official distribution):
    https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json

    Alternative: ATT&CK API at https://attack.mitre.org (used for
    individual technique lookups when the full bundle is unavailable).

Features:
    - Full STIX 2.1 bundle parsing (attack-patterns, x-mitre-tactic,
      relationships, intrusion-sets, malware, tools)
    - Tactic → technique mapping via kill_chain_phases
    - Technique metadata: ID, name, description, platforms, permissions,
      data sources, detection, sub-techniques
    - Software/group cross-referencing (which APTs use which techniques)
    - Mitigation extraction for defensive enrichment
    - Incremental sync via bundle version comparison
    - Severity scoring heuristic based on technique prevalence + impact
    - Bulk upsert with progress tracking

Environment Variables:
    FORGE_ATTACK_BUNDLE_URL  — Override STIX bundle URL.
    FORGE_ATTACK_BUNDLE_PATH — Use a local STIX JSON file.
    FORGE_ATTACK_VERSION     — Force a specific ATT&CK version.

Usage:
    learner = TechniqueLearner()
    result = await learner.sync(conn=sqlite_conn, since="2025-01-01")
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import sqlite3
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from common.version import PRODUCT_USER_AGENT

log = logging.getLogger("forge.intel.techniques")

# MITRE ATT&CK STIX 2.1 bundle (Enterprise matrix)
DEFAULT_BUNDLE_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
    "master/enterprise-attack/enterprise-attack.json"
)

# ATT&CK tactic ordering (kill chain phases)
TACTIC_ORDER = [
    "reconnaissance",
    "resource-development",
    "initial-access",
    "execution",
    "persistence",
    "privilege-escalation",
    "defense-evasion",
    "credential-access",
    "discovery",
    "lateral-movement",
    "collection",
    "command-and-control",
    "exfiltration",
    "impact",
]

# Severity heuristic — tactics later in the kill chain are generally
# higher impact (post-exploitation vs. recon)
TACTIC_SEVERITY = {
    "reconnaissance":        "info",
    "resource-development":  "info",
    "initial-access":        "high",
    "execution":             "high",
    "persistence":           "medium",
    "privilege-escalation":  "high",
    "defense-evasion":       "medium",
    "credential-access":     "high",
    "discovery":             "low",
    "lateral-movement":      "high",
    "collection":            "medium",
    "command-and-control":   "medium",
    "exfiltration":          "high",
    "impact":                "critical",
}

# STIX object type filters
STIX_ATTACK_PATTERN = "attack-pattern"
STIX_TACTIC         = "x-mitre-tactic"
STIX_RELATIONSHIP   = "relationship"
STIX_INTRUSION_SET  = "intrusion-set"
STIX_MALWARE        = "malware"
STIX_TOOL           = "tool"
STIX_MITIGATION     = "course-of-action"

BATCH_SIZE = 500
TECHNIQUE_LEARNER_USER_AGENT = (
    f"{PRODUCT_USER_AGENT} IntelPipeline (TechniqueLearner)"
)


# ── HTTP helper ──────────────────────────────────────────────────

async def _fetch_bundle(url: str) -> dict[str, Any]:
    raise RuntimeError("outbound_policy_unsupported")
    """Download the STIX 2.1 JSON bundle.

    The enterprise-attack.json is ~30MB so we stream it in a thread
    executor. No external HTTP libs required.
    """
    import urllib.request
    import urllib.error

    headers = {
        "Accept": "application/json",
        "User-Agent": TECHNIQUE_LEARNER_USER_AGENT,
    }
    request = urllib.request.Request(url, headers=headers)

    loop = asyncio.get_event_loop()
    try:
        response = await loop.run_in_executor(
            None,
            lambda: urllib.request.urlopen(request, timeout=120),
        )
        # Read in chunks
        chunks: list[bytes] = []
        while True:
            chunk = await loop.run_in_executor(
                None, lambda: response.read(2 * 1024 * 1024)
            )
            if not chunk:
                break
            chunks.append(chunk)
        body = b"".join(chunks).decode("utf-8")
        return json.loads(body)
    except urllib.error.HTTPError as e:
        log.error("ATT&CK bundle download HTTP %d: %s", e.code, e.reason)
        raise
    except urllib.error.URLError as e:
        log.error("ATT&CK bundle download error: %s", e.reason)
        raise
    except json.JSONDecodeError as e:
        log.error("ATT&CK bundle invalid JSON: %s", e)
        raise


# ══════════════════════════════════════════════════════════════════════
# TECHNIQUE LEARNER — MITRE ATT&CK Database Engine
# ══════════════════════════════════════════════════════════════════════

class TechniqueLearner:
    """MITRE ATT&CK Enterprise technique database synchronizer.

    Downloads the STIX 2.1 bundle, parses attack-patterns (techniques),
    tactics, relationships, and software/group associations, then stores
    normalized IntelRecords in the shared SQLite database.

    The sync contract (called by IntelEngine._sync_source):
        async def sync(conn, since=None, event_bus=None) -> dict

    Returns:
        dict with keys: records_new, records_updated, records_total
    """

    def __init__(self) -> None:
        self.bundle_url: str = os.environ.get(
            "FORGE_ATTACK_BUNDLE_URL", DEFAULT_BUNDLE_URL
        )
        self.bundle_path: str | None = os.environ.get("FORGE_ATTACK_BUNDLE_PATH")
        self._tactic_map: dict[str, str] = {}       # stix_id → shortname
        self._tactic_names: dict[str, str] = {}      # shortname → display name
        self._relationships: dict[str, list[str]] = {}  # technique_stix_id → [software/group names]
        self._mitigations: dict[str, list[str]] = {}    # technique_stix_id → [mitigation names]
        self._stix_name_map: dict[str, str] = {}     # stix_id → name (for relationship resolution)

    async def sync(
        self,
        conn: sqlite3.Connection,
        since: str | None = None,
        event_bus: Any = None,
    ) -> dict[str, int]:
        """Execute ATT&CK technique database sync.

        Downloads the STIX bundle, parses all relevant objects, builds
        enriched technique records with tactic/software/mitigation
        associations, and bulk-upserts into the database.

        Args:
            conn:      SQLite connection (from IntelEngine).
            since:     ISO date string (used for filtering modified techniques).
            event_bus: Optional EventBus for dashboard events.

        Returns:
            Dict with records_new, records_updated, records_total counts.
        """
        raise RuntimeError("outbound_policy_unsupported")
        log.info("ATT&CK technique sync starting (since=%s)", since)
        from common.intel.intel_engine import IntelRecord

        # ── Step 1: Get the STIX bundle ───────────────────────────
        print("     ├─ Downloading MITRE ATT&CK STIX bundle...")
        bundle = await self._get_bundle()
        if not bundle:
            raise RuntimeError("Failed to retrieve ATT&CK STIX bundle")

        bundle_version = bundle.get("spec_version", "unknown")
        objects = bundle.get("objects", [])
        log.info("ATT&CK bundle loaded: %d STIX objects (spec %s)",
                 len(objects), bundle_version)
        print(f"     ├─ Loaded {len(objects):,d} STIX objects")

        # ── Step 2: Index tactics, relationships, software, mitigations
        print("     ├─ Indexing tactics, software, and relationships...")
        self._index_bundle(objects)

        # ── Step 3: Parse techniques into IntelRecords ────────────
        print("     ├─ Parsing attack techniques...")
        records = self._parse_techniques(objects, since)
        total_parsed = len(records)
        log.info("Parsed %d ATT&CK techniques", total_parsed)
        print(f"     ├─ Parsed {total_parsed:,d} techniques (incl. sub-techniques)")

        # Also parse tactics themselves as records
        tactic_records = self._parse_tactics(objects)
        records.extend(tactic_records)
        print(f"     ├─ Parsed {len(tactic_records)} tactics")

        if not records:
            row = conn.execute(
                "SELECT COUNT(*) as cnt FROM intel_records WHERE source = 'techniques'"
            ).fetchone()
            return {
                "records_new": 0,
                "records_updated": 0,
                "records_total": row["cnt"] if row else 0,
            }

        # ── Step 4: Bulk upsert ──────────────────────────────────
        print("     ├─ Upserting technique records...")
        total_new = 0
        total_updated = 0

        for i in range(0, len(records), BATCH_SIZE):
            batch = records[i:i + BATCH_SIZE]
            new, updated = self._bulk_upsert(conn, batch)
            total_new += new
            total_updated += updated

        # ── Step 5: Total count ──────────────────────────────────
        row = conn.execute(
            "SELECT COUNT(*) as cnt FROM intel_records WHERE source = 'techniques'"
        ).fetchone()
        records_total = row["cnt"] if row else len(records)

        log.info("ATT&CK sync complete: %d new, %d updated, %d total",
                 total_new, total_updated, records_total)

        return {
            "records_new": total_new,
            "records_updated": total_updated,
            "records_total": records_total,
        }

    # ── Bundle retrieval ──────────────────────────────────────────

    async def _get_bundle(self) -> dict[str, Any]:
        """Load the STIX bundle from local file or remote URL."""
        if self.bundle_path:
            local = Path(self.bundle_path)
            if local.exists():
                log.info("Using local ATT&CK bundle: %s", local)
                print(f"     │  ├─ Loading from local file: {local.name}")
                content = local.read_text(encoding="utf-8")
                return json.loads(content)
            else:
                log.warning("Local bundle not found: %s, falling back to URL",
                            local)

        return await _fetch_bundle(self.bundle_url)

    # ── Bundle indexing ───────────────────────────────────────────

    def _index_bundle(self, objects: list[dict[str, Any]]) -> None:
        """Pre-index tactics, relationships, software, and mitigations.

        Building lookup maps before parsing techniques allows us to
        enrich each technique with its associated tactics, software
        used by threat actors, and available mitigations.
        """
        # Reset indexes
        self._tactic_map.clear()
        self._tactic_names.clear()
        self._relationships.clear()
        self._mitigations.clear()
        self._stix_name_map.clear()

        # First pass: index names and tactics
        for obj in objects:
            obj_type = obj.get("type", "")
            stix_id = obj.get("id", "")
            name = obj.get("name", "")

            # Skip revoked/deprecated objects
            if obj.get("revoked", False) or obj.get("x_mitre_deprecated", False):
                continue

            self._stix_name_map[stix_id] = name

            if obj_type == STIX_TACTIC:
                # Map STIX ID to tactic shortname
                refs = obj.get("external_references", [])
                for ref in refs:
                    if ref.get("source_name") == "mitre-attack":
                        shortname = obj.get("x_mitre_shortname", "")
                        if shortname:
                            self._tactic_map[stix_id] = shortname
                            self._tactic_names[shortname] = name
                        break

        # Second pass: index relationships
        for obj in objects:
            if obj.get("type") != STIX_RELATIONSHIP:
                continue
            if obj.get("revoked", False) or obj.get("x_mitre_deprecated", False):
                continue

            rel_type = obj.get("relationship_type", "")
            source_ref = obj.get("source_ref", "")
            target_ref = obj.get("target_ref", "")

            if rel_type == "uses" and target_ref.startswith("attack-pattern--"):
                # Software/group uses technique
                source_name = self._stix_name_map.get(source_ref, "")
                if source_name:
                    self._relationships.setdefault(target_ref, []).append(source_name)

            elif rel_type == "mitigates" and target_ref.startswith("attack-pattern--"):
                # Mitigation for technique
                source_name = self._stix_name_map.get(source_ref, "")
                if source_name:
                    self._mitigations.setdefault(target_ref, []).append(source_name)

        log.debug("Indexed %d tactics, %d technique relationships, %d mitigations",
                  len(self._tactic_map), len(self._relationships),
                  len(self._mitigations))

    # ── Technique parsing ─────────────────────────────────────────

    def _parse_techniques(
        self,
        objects: list[dict[str, Any]],
        since: str | None = None,
    ) -> list[Any]:
        """Parse STIX attack-pattern objects into IntelRecords.

        Each technique becomes one IntelRecord with:
            - record_id: ATT&CK ID (e.g. T1059, T1059.001)
            - source: "techniques"
            - severity: based on tactic severity heuristic
            - tags: tactic names, platforms, permissions
            - raw_data: full metadata (sub-techniques, data sources,
              detection methods, associated software/groups)
        """
        from common.intel.intel_engine import IntelRecord

        records: list[IntelRecord] = []

        # Parse since date
        since_dt = None
        if since:
            try:
                since_dt = datetime.fromisoformat(since.replace("Z", "+00:00"))
                if since_dt.tzinfo is None:
                    since_dt = since_dt.replace(tzinfo=timezone.utc)
            except ValueError:
                try:
                    since_dt = datetime.strptime(since[:10], "%Y-%m-%d").replace(
                        tzinfo=timezone.utc
                    )
                except ValueError:
                    pass

        for obj in objects:
            if obj.get("type") != STIX_ATTACK_PATTERN:
                continue
            if obj.get("revoked", False) or obj.get("x_mitre_deprecated", False):
                continue

            record = self._parse_technique(obj, since_dt)
            if record:
                records.append(record)

        return records

    def _parse_technique(
        self,
        obj: dict[str, Any],
        since_dt: datetime | None,
    ) -> Any:
        """Parse a single STIX attack-pattern into an IntelRecord."""
        from common.intel.intel_engine import IntelRecord

        stix_id = obj.get("id", "")

        # Extract ATT&CK ID from external_references
        attack_id = ""
        attack_url = ""
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                attack_id = ref.get("external_id", "")
                attack_url = ref.get("url", "")
                break

        if not attack_id:
            return None

        # Date filtering
        modified = obj.get("modified", "")
        if since_dt and modified:
            try:
                mod_dt = datetime.fromisoformat(modified.replace("Z", "+00:00"))
                if mod_dt.tzinfo is None:
                    mod_dt = mod_dt.replace(tzinfo=timezone.utc)
                if mod_dt < since_dt:
                    return None
            except ValueError:
                pass

        # ── Basic metadata ────────────────────────────────────────
        name = obj.get("name", "")
        description = obj.get("description", "")
        # Strip markdown-style formatting for cleaner storage
        description = re.sub(r'\[([^\]]+)\]\([^)]+\)', r'\1', description)
        description = description[:1000]  # Cap description length

        created = obj.get("created", "")

        # ── Tactics (kill chain phases) ───────────────────────────
        tactics = []
        kill_chain = obj.get("kill_chain_phases", [])
        for phase in kill_chain:
            if phase.get("kill_chain_name") == "mitre-attack":
                phase_name = phase.get("phase_name", "")
                if phase_name:
                    tactics.append(phase_name)

        # ── Severity (based on highest-impact tactic) ─────────────
        severity = "info"
        for tactic in tactics:
            tactic_sev = TACTIC_SEVERITY.get(tactic, "medium")
            if _severity_rank(tactic_sev) > _severity_rank(severity):
                severity = tactic_sev

        # ── Platforms ─────────────────────────────────────────────
        platforms = obj.get("x_mitre_platforms", [])

        # ── Permissions required ──────────────────────────────────
        permissions = obj.get("x_mitre_permissions_required", [])

        # ── Data sources ──────────────────────────────────────────
        data_sources = obj.get("x_mitre_data_sources", [])

        # ── Detection ─────────────────────────────────────────────
        detection = obj.get("x_mitre_detection", "")
        if detection:
            detection = re.sub(r'\[([^\]]+)\]\([^)]+\)', r'\1', detection)
            detection = detection[:500]

        # ── Is sub-technique? ─────────────────────────────────────
        is_subtechnique = obj.get("x_mitre_is_subtechnique", False)

        # ── Associated software/groups ────────────────────────────
        used_by = self._relationships.get(stix_id, [])
        mitigations = self._mitigations.get(stix_id, [])

        # ── Tags ──────────────────────────────────────────────────
        tags = []
        tags.extend(tactics)
        tags.extend([p.lower() for p in platforms[:5]])
        if is_subtechnique:
            tags.append("sub-technique")
        if permissions:
            tags.extend([f"requires:{p.lower()}" for p in permissions[:3]])
        if len(used_by) > 3:
            tags.append("widely-used")

        # ── References ────────────────────────────────────────────
        references = []
        if attack_url:
            references.append(attack_url)
        for ref in obj.get("external_references", []):
            url = ref.get("url", "")
            if url and url != attack_url and url.startswith("http"):
                references.append(url)
                if len(references) >= 10:
                    break

        # ── Build record ──────────────────────────────────────────
        record_id = f"ATT&CK-{attack_id}"
        title = f"{attack_id}: {name}"

        return IntelRecord(
            record_id=record_id,
            source="techniques",
            title=title,
            description=description,
            severity=severity,
            cvss_score=None,
            products=[p.lower() for p in platforms],
            references=references,
            tags=tags[:25],
            exploit_available=False,
            published_at=created,
            updated_at=modified,
            raw_data={
                "attack_id": attack_id,
                "stix_id": stix_id,
                "name": name,
                "tactics": tactics,
                "platforms": platforms,
                "permissions_required": permissions,
                "data_sources": data_sources[:10],
                "detection": detection,
                "is_subtechnique": is_subtechnique,
                "used_by": used_by[:20],
                "mitigations": mitigations[:10],
                "x_mitre_version": obj.get("x_mitre_version", ""),
            },
        )

    # ── Tactic parsing ────────────────────────────────────────────

    def _parse_tactics(self, objects: list[dict[str, Any]]) -> list[Any]:
        """Parse STIX x-mitre-tactic objects into IntelRecords.

        Tactics are stored as separate records to enable tactic-based
        querying and kill chain visualization.
        """
        from common.intel.intel_engine import IntelRecord

        records: list[IntelRecord] = []

        for obj in objects:
            if obj.get("type") != STIX_TACTIC:
                continue
            if obj.get("revoked", False) or obj.get("x_mitre_deprecated", False):
                continue

            # Extract ATT&CK tactic ID
            tactic_id = ""
            tactic_url = ""
            for ref in obj.get("external_references", []):
                if ref.get("source_name") == "mitre-attack":
                    tactic_id = ref.get("external_id", "")
                    tactic_url = ref.get("url", "")
                    break

            if not tactic_id:
                continue

            shortname = obj.get("x_mitre_shortname", "")
            name = obj.get("name", "")
            description = obj.get("description", "")
            description = re.sub(r'\[([^\]]+)\]\([^)]+\)', r'\1', description)

            severity = TACTIC_SEVERITY.get(shortname, "medium")

            # Count techniques in this tactic
            technique_count = sum(
                1 for t_id, t_name in self._tactic_map.items()
                if t_name == shortname
            )

            record_id = f"ATT&CK-{tactic_id}"

            records.append(IntelRecord(
                record_id=record_id,
                source="techniques",
                title=f"{tactic_id}: {name}",
                description=description[:500],
                severity=severity,
                cvss_score=None,
                products=[],
                references=[tactic_url] if tactic_url else [],
                tags=["tactic", shortname],
                exploit_available=False,
                published_at=obj.get("created", ""),
                updated_at=obj.get("modified", ""),
                raw_data={
                    "tactic_id": tactic_id,
                    "shortname": shortname,
                    "name": name,
                    "stix_id": obj.get("id", ""),
                    "kill_chain_order": TACTIC_ORDER.index(shortname)
                        if shortname in TACTIC_ORDER else 99,
                },
            ))

        return records

    # ── Database operations ───────────────────────────────────────

    def _bulk_upsert(
        self,
        conn: sqlite3.Connection,
        records: list[Any],
    ) -> tuple[int, int]:
        """Batch upsert records into the intel_records table."""
        if not records:
            return 0, 0

        placeholders = ",".join("?" * len(records))
        ids = [r.record_id for r in records]
        existing_rows = conn.execute(
            f"SELECT record_id FROM intel_records WHERE record_id IN ({placeholders})",
            ids,
        ).fetchall()
        existing_ids = {row["record_id"] for row in existing_rows}

        new_count = 0
        updated_count = 0

        for record in records:
            is_new = record.record_id not in existing_ids

            conn.execute("""
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

        conn.commit()
        return new_count, updated_count


# ── Severity ranking helper ──────────────────────────────────────

_SEVERITY_RANKS = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
    "unknown": 0,
}


def _severity_rank(severity: str) -> int:
    """Convert severity string to numeric rank for comparison."""
    return _SEVERITY_RANKS.get(severity, 0)


# ══════════════════════════════════════════════════════════════════════
# UNIT TESTS
# ══════════════════════════════════════════════════════════════════════

class TestTechniqueLearner:
    """Unit tests for TechniqueLearner parsing and indexing."""

    def _make_stix_technique(
        self,
        attack_id: str = "T1059",
        name: str = "Command and Scripting Interpreter",
        tactics: list[str] | None = None,
        platforms: list[str] | None = None,
        is_sub: bool = False,
    ) -> dict[str, Any]:
        """Build a minimal STIX attack-pattern object for testing."""
        if tactics is None:
            tactics = ["execution"]
        if platforms is None:
            platforms = ["Windows", "Linux", "macOS"]

        return {
            "type": "attack-pattern",
            "id": f"attack-pattern--{attack_id.lower()}-0000-0000-0000-000000000001",
            "name": name,
            "description": f"Adversaries may abuse {name.lower()} to execute commands.",
            "created": "2020-01-01T00:00:00.000Z",
            "modified": "2025-06-01T00:00:00.000Z",
            "external_references": [
                {
                    "source_name": "mitre-attack",
                    "external_id": attack_id,
                    "url": f"https://attack.mitre.org/techniques/{attack_id.replace('.', '/')}/",
                }
            ],
            "kill_chain_phases": [
                {"kill_chain_name": "mitre-attack", "phase_name": t}
                for t in tactics
            ],
            "x_mitre_platforms": platforms,
            "x_mitre_permissions_required": ["User"],
            "x_mitre_data_sources": ["Process: Process Creation"],
            "x_mitre_detection": "Monitor for process creation events.",
            "x_mitre_is_subtechnique": is_sub,
            "x_mitre_version": "1.0",
        }

    def _make_stix_tactic(
        self,
        tactic_id: str = "TA0002",
        name: str = "Execution",
        shortname: str = "execution",
    ) -> dict[str, Any]:
        """Build a minimal STIX x-mitre-tactic object."""
        return {
            "type": "x-mitre-tactic",
            "id": f"x-mitre-tactic--{tactic_id.lower()}-0000-0000-0000-000000000001",
            "name": name,
            "description": f"The adversary is trying to run {name.lower()} code.",
            "x_mitre_shortname": shortname,
            "created": "2020-01-01T00:00:00.000Z",
            "modified": "2025-01-01T00:00:00.000Z",
            "external_references": [
                {
                    "source_name": "mitre-attack",
                    "external_id": tactic_id,
                    "url": f"https://attack.mitre.org/tactics/{tactic_id}/",
                }
            ],
        }

    def test_parse_technique(self) -> None:
        """Test parsing a single STIX technique."""
        learner = TechniqueLearner()
        obj = self._make_stix_technique()
        objects = [
            self._make_stix_tactic(),
            obj,
        ]
        learner._index_bundle(objects)
        records = learner._parse_techniques(objects)

        assert len(records) == 1
        r = records[0]
        assert r.record_id == "ATT&CK-T1059"
        assert r.source == "techniques"
        assert "execution" in r.tags
        assert r.severity == "high"  # execution tactic = high
        assert "windows" in r.products

    def test_subtechnique(self) -> None:
        """Test sub-technique flag in parsed record."""
        learner = TechniqueLearner()
        obj = self._make_stix_technique(
            attack_id="T1059.001",
            name="PowerShell",
            is_sub=True,
        )
        objects = [obj]
        learner._index_bundle(objects)
        records = learner._parse_techniques(objects)

        assert len(records) == 1
        assert "sub-technique" in records[0].tags
        assert records[0].raw_data["is_subtechnique"] is True

    def test_tactic_parsing(self) -> None:
        """Test parsing tactics as separate records."""
        learner = TechniqueLearner()
        objects = [self._make_stix_tactic()]
        learner._index_bundle(objects)
        records = learner._parse_tactics(objects)

        assert len(records) == 1
        r = records[0]
        assert r.record_id == "ATT&CK-TA0002"
        assert "tactic" in r.tags
        assert "execution" in r.tags

    def test_revoked_skipped(self) -> None:
        """Test that revoked techniques are skipped."""
        learner = TechniqueLearner()
        obj = self._make_stix_technique()
        obj["revoked"] = True
        objects = [obj]
        learner._index_bundle(objects)
        records = learner._parse_techniques(objects)
        assert len(records) == 0

    def test_deprecated_skipped(self) -> None:
        """Test that deprecated techniques are skipped."""
        learner = TechniqueLearner()
        obj = self._make_stix_technique()
        obj["x_mitre_deprecated"] = True
        objects = [obj]
        learner._index_bundle(objects)
        records = learner._parse_techniques(objects)
        assert len(records) == 0

    def test_severity_from_tactic(self) -> None:
        """Test severity assignment based on tactic."""
        learner = TechniqueLearner()

        # Impact tactic should give critical severity
        obj = self._make_stix_technique(
            attack_id="T1485",
            name="Data Destruction",
            tactics=["impact"],
        )
        objects = [obj]
        learner._index_bundle(objects)
        records = learner._parse_techniques(objects)
        assert records[0].severity == "critical"

        # Discovery tactic should give low severity
        obj2 = self._make_stix_technique(
            attack_id="T1082",
            name="System Information Discovery",
            tactics=["discovery"],
        )
        objects2 = [obj2]
        learner._index_bundle(objects2)
        records2 = learner._parse_techniques(objects2)
        assert records2[0].severity == "low"

    def test_multi_tactic_severity(self) -> None:
        """Test that multi-tactic techniques get highest severity."""
        learner = TechniqueLearner()
        obj = self._make_stix_technique(
            attack_id="T1055",
            name="Process Injection",
            tactics=["defense-evasion", "privilege-escalation"],
        )
        objects = [obj]
        learner._index_bundle(objects)
        records = learner._parse_techniques(objects)
        # privilege-escalation = high, defense-evasion = medium → picks high
        assert records[0].severity == "high"

    def test_relationship_indexing(self) -> None:
        """Test that software/group relationships are indexed."""
        learner = TechniqueLearner()
        technique = self._make_stix_technique()
        stix_id = technique["id"]

        software = {
            "type": "malware",
            "id": "malware--cobalt-strike",
            "name": "Cobalt Strike",
        }
        relationship = {
            "type": "relationship",
            "id": "relationship--test-001",
            "relationship_type": "uses",
            "source_ref": "malware--cobalt-strike",
            "target_ref": stix_id,
        }

        objects = [technique, software, relationship]
        learner._index_bundle(objects)

        assert stix_id in learner._relationships
        assert "Cobalt Strike" in learner._relationships[stix_id]

    def test_severity_rank(self) -> None:
        """Test severity ranking helper."""
        assert _severity_rank("critical") > _severity_rank("high")
        assert _severity_rank("high") > _severity_rank("medium")
        assert _severity_rank("medium") > _severity_rank("low")
        assert _severity_rank("low") > _severity_rank("info")
        assert _severity_rank("unknown") == _severity_rank("info")

    def test_since_filter(self) -> None:
        """Test date-based filtering of techniques."""
        learner = TechniqueLearner()
        obj = self._make_stix_technique()
        obj["modified"] = "2024-01-01T00:00:00.000Z"

        objects = [obj]
        learner._index_bundle(objects)

        # Should be filtered out (modified before since date)
        records = learner._parse_techniques(objects, since="2025-01-01")
        assert len(records) == 0

        # Should pass (no filter)
        records2 = learner._parse_techniques(objects, since=None)
        assert len(records2) == 1
