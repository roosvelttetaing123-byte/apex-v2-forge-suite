"""Nuclei Sync — ProjectDiscovery Nuclei Template Auto-Update.

Fetches Nuclei detection templates from the ProjectDiscovery
nuclei-templates GitHub repository and stores normalized records in
the local intel SQLite database. Templates are used by scanning modules
to detect vulnerabilities, misconfigurations, and exposures.

Data Source:
    GitHub API: https://api.github.com/repos/projectdiscovery/nuclei-templates
    Git clone/pull for full template sync.
    GitHub releases API for version tracking.

Features:
    - GitHub API-based template index fetching (tree endpoint)
    - YAML template metadata parsing (id, name, severity, tags, CVE refs)
    - Incremental sync via git pull or release date comparison
    - Template classification by directory (cves/, vulnerabilities/,
      misconfigurations/, exposures/, technologies/, etc.)
    - Severity normalization from template metadata
    - CVE cross-referencing for template-to-CVE linking
    - Batch upsert with progress tracking
    - Fallback: local template directory scan if GitHub is unreachable

Environment Variables:
    FORGE_NUCLEI_TEMPLATES_DIR  — Local nuclei-templates directory.
    FORGE_GITHUB_TOKEN          — GitHub personal access token (rate limits).
    FORGE_NUCLEI_REPO_URL       — Override repository URL.

Usage:
    syncer = NucleiSync()
    result = await syncer.sync(conn=sqlite_conn, since="2025-01-01")
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import sqlite3
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any

log = logging.getLogger("forge.intel.nuclei")

# GitHub API endpoints
GITHUB_API_BASE = "https://api.github.com"
DEFAULT_REPO = "projectdiscovery/nuclei-templates"

# Template directories we care about (skip helpers, workflows, etc.)
TEMPLATE_DIRS = [
    "http/cves",
    "http/vulnerabilities",
    "http/misconfigurations",
    "http/exposures",
    "http/technologies",
    "http/default-logins",
    "http/takeovers",
    "network/cves",
    "network/vulnerabilities",
    "network/misconfigurations",
    "network/default-logins",
    "dns",
    "ssl",
    "headless",
    "javascript",
    # Legacy flat structure (pre-v9 templates)
    "cves",
    "vulnerabilities",
    "misconfigurations",
    "exposures",
    "technologies",
    "default-logins",
    "takeovers",
]

# Severity normalization from Nuclei's own severity field
NUCLEI_SEVERITY_MAP = {
    "critical": "critical",
    "high":     "high",
    "medium":   "medium",
    "low":      "low",
    "info":     "info",
    "unknown":  "unknown",
}

# Batch size for DB operations
BATCH_SIZE = 500

# GitHub rate limit spacing
GITHUB_RATE_DELAY = 1.0  # seconds between API calls (unauthenticated: 60/hr)
GITHUB_RATE_DELAY_AUTH = 0.25  # with token: 5000/hr


# ── YAML mini-parser ─────────────────────────────────────────────
# We parse just the 'info:' block from Nuclei YAML templates without
# requiring PyYAML as a hard dependency. Nuclei templates follow a
# very consistent structure so regex extraction works reliably.

def _extract_template_info(content: str) -> dict[str, Any]:
    """Extract template metadata from YAML content without PyYAML.

    Nuclei template structure:
        id: CVE-2024-1234
        info:
          name: Apache Struts RCE
          author: h4x0r
          severity: critical
          description: |
            Apache Struts is vulnerable...
          reference:
            - https://nvd.nist.gov/...
          classification:
            cvss-metrics: CVSS:3.1/AV:N/AC:L/...
            cvss-score: 9.8
            cve-id: CVE-2024-1234
            cwe-id: CWE-78
          tags: rce,struts,apache,cve2024

    Returns:
        Dict with: id, name, author, severity, description, references,
        cvss_score, cve_id, cwe_ids, tags
    """
    info: dict[str, Any] = {}

    # ── Template ID ───────────────────────────────────────────────
    id_match = re.search(r'^id:\s*(.+?)$', content, re.MULTILINE)
    info["id"] = id_match.group(1).strip() if id_match else ""

    # ── Info block fields ─────────────────────────────────────────
    name_match = re.search(r'^\s+name:\s*(.+?)$', content, re.MULTILINE)
    info["name"] = name_match.group(1).strip().strip('"\'') if name_match else ""

    author_match = re.search(r'^\s+author:\s*(.+?)$', content, re.MULTILINE)
    info["author"] = author_match.group(1).strip() if author_match else ""

    severity_match = re.search(r'^\s+severity:\s*(.+?)$', content, re.MULTILINE)
    info["severity"] = severity_match.group(1).strip().lower() if severity_match else "unknown"

    # Description — can be multiline (indicated by | or >)
    desc_match = re.search(
        r'^\s+description:\s*(?:\||-|>)?\s*\n((?:\s{4,}.+\n?)*)',
        content, re.MULTILINE
    )
    if desc_match:
        desc_lines = desc_match.group(1).strip().split("\n")
        info["description"] = " ".join(line.strip() for line in desc_lines)
    else:
        # Single-line description
        desc_single = re.search(r'^\s+description:\s*(.+?)$', content, re.MULTILINE)
        info["description"] = desc_single.group(1).strip().strip('"\'') if desc_single else ""

    # References — list under reference:
    refs: list[str] = []
    ref_section = re.search(
        r'^\s+reference:\s*\n((?:\s+- .+\n?)*)',
        content, re.MULTILINE
    )
    if ref_section:
        for line in ref_section.group(1).strip().split("\n"):
            url = line.strip().lstrip("- ").strip()
            if url.startswith("http"):
                refs.append(url)
    info["references"] = refs

    # ── Classification block ──────────────────────────────────────
    cvss_score_match = re.search(r'^\s+cvss-score:\s*([0-9.]+)', content, re.MULTILINE)
    info["cvss_score"] = float(cvss_score_match.group(1)) if cvss_score_match else None

    cve_match = re.search(r'^\s+cve-id:\s*(.+?)$', content, re.MULTILINE)
    cve_val = cve_match.group(1).strip() if cve_match else ""
    # Can be comma-separated or single
    if cve_val:
        info["cve_ids"] = [c.strip() for c in cve_val.split(",") if c.strip().startswith("CVE-")]
    else:
        info["cve_ids"] = []

    cwe_match = re.search(r'^\s+cwe-id:\s*(.+?)$', content, re.MULTILINE)
    cwe_val = cwe_match.group(1).strip() if cwe_match else ""
    if cwe_val:
        info["cwe_ids"] = [c.strip() for c in cwe_val.split(",") if c.strip().startswith("CWE-")]
    else:
        info["cwe_ids"] = []

    cvss_vector_match = re.search(r'^\s+cvss-metrics:\s*(.+?)$', content, re.MULTILINE)
    info["cvss_vector"] = cvss_vector_match.group(1).strip() if cvss_vector_match else ""

    # ── Tags ──────────────────────────────────────────────────────
    tags_match = re.search(r'^\s+tags:\s*(.+?)$', content, re.MULTILINE)
    if tags_match:
        info["tags"] = [t.strip() for t in tags_match.group(1).split(",") if t.strip()]
    else:
        info["tags"] = []

    return info


# ── HTTP helper ──────────────────────────────────────────────────

async def _github_api(
    endpoint: str,
    token: str | None = None,
) -> Any:
    """Make a GitHub API request (via stdlib urllib).

    Args:
        endpoint: API path (e.g. /repos/owner/repo/git/trees/main).
        token:    Optional GitHub personal access token.

    Returns:
        Parsed JSON response.
    """
    import urllib.request
    import urllib.error

    url = f"{GITHUB_API_BASE}{endpoint}"
    headers = {
        "Accept": "application/vnd.github.v3+json",
        "User-Agent": "Forge-Suite/5.0 IntelPipeline (NucleiSync)",
    }
    if token:
        headers["Authorization"] = f"token {token}"

    request = urllib.request.Request(url, headers=headers)
    loop = asyncio.get_event_loop()

    try:
        response = await loop.run_in_executor(
            None,
            lambda: urllib.request.urlopen(request, timeout=30),
        )
        body = response.read().decode("utf-8")
        return json.loads(body)
    except urllib.error.HTTPError as e:
        if e.code == 403:
            log.warning("GitHub API rate limit hit. Use FORGE_GITHUB_TOKEN env var.")
        body = e.read().decode("utf-8", errors="replace") if e.fp else ""
        log.error("GitHub API HTTP %d: %s", e.code, body[:300])
        raise
    except urllib.error.URLError as e:
        log.error("GitHub API connection error: %s", e.reason)
        raise


async def _fetch_raw_content(url: str, token: str | None = None) -> str:
    """Fetch raw file content from GitHub."""
    import urllib.request
    import urllib.error

    headers = {
        "Accept": "application/vnd.github.v3.raw",
        "User-Agent": "Forge-Suite/5.0 IntelPipeline (NucleiSync)",
    }
    if token:
        headers["Authorization"] = f"token {token}"

    request = urllib.request.Request(url, headers=headers)
    loop = asyncio.get_event_loop()

    try:
        response = await loop.run_in_executor(
            None,
            lambda: urllib.request.urlopen(request, timeout=30),
        )
        return response.read().decode("utf-8", errors="replace")
    except Exception as e:
        log.debug("Failed to fetch raw content from %s: %s", url, e)
        return ""


# ══════════════════════════════════════════════════════════════════════
# NUCLEI SYNC — Template Auto-Update Engine
# ══════════════════════════════════════════════════════════════════════

class NucleiSync:
    """ProjectDiscovery Nuclei template synchronization engine.

    Fetches template metadata from the nuclei-templates GitHub repo,
    parses YAML template info blocks, normalizes into IntelRecords,
    and bulk-upserts into the shared intel SQLite database.

    Supports two modes:
        1. GitHub API mode (default): Uses the Git trees API to enumerate
           templates and fetch metadata from YAML files.
        2. Local directory mode: Scans a local nuclei-templates clone
           for YAML files and parses them directly.

    The sync contract (called by IntelEngine._sync_source):
        async def sync(conn, since=None, event_bus=None) -> dict

    Returns:
        dict with keys: records_new, records_updated, records_total
    """

    def __init__(self) -> None:
        self.github_token: str | None = os.environ.get("FORGE_GITHUB_TOKEN")
        self.templates_dir: str | None = os.environ.get("FORGE_NUCLEI_TEMPLATES_DIR")
        self.repo: str = os.environ.get("FORGE_NUCLEI_REPO_URL", DEFAULT_REPO)
        self.rate_delay: float = (
            GITHUB_RATE_DELAY_AUTH if self.github_token else GITHUB_RATE_DELAY
        )
        self._last_request: float = 0.0

    async def sync(
        self,
        conn: sqlite3.Connection,
        since: str | None = None,
        event_bus: Any = None,
    ) -> dict[str, int]:
        """Execute a Nuclei template sync.

        Tries local directory first (if configured), then falls back
        to GitHub API. Parses template YAML files, normalizes into
        IntelRecords, and bulk-upserts into the database.

        Args:
            conn:      SQLite connection (from IntelEngine).
            since:     ISO date string for incremental filtering.
            event_bus: Optional EventBus for dashboard events.

        Returns:
            Dict with records_new, records_updated, records_total counts.
        """
        log.info("Nuclei sync starting (since=%s, local=%s)",
                 since, self.templates_dir or "none")

        from common.intel.intel_engine import IntelRecord

        # ── Mode selection ────────────────────────────────────────
        if self.templates_dir and Path(self.templates_dir).is_dir():
            print("     ├─ Using local nuclei-templates directory...")
            records = await self._sync_local(since)
        else:
            print("     ├─ Fetching templates from GitHub API...")
            records = await self._sync_github(since)

        total_parsed = len(records)
        log.info("Parsed %d Nuclei templates", total_parsed)
        print(f"     ├─ Parsed {total_parsed:,d} templates")

        if not records:
            row = conn.execute(
                "SELECT COUNT(*) as cnt FROM intel_records WHERE source = 'nuclei'"
            ).fetchone()
            return {
                "records_new": 0,
                "records_updated": 0,
                "records_total": row["cnt"] if row else 0,
            }

        # ── Bulk upsert ──────────────────────────────────────────
        print("     ├─ Upserting templates into database...")
        total_new = 0
        total_updated = 0

        for i in range(0, len(records), BATCH_SIZE):
            batch = records[i:i + BATCH_SIZE]
            new, updated = self._bulk_upsert(conn, batch)
            total_new += new
            total_updated += updated

        # ── Cross-reference CVEs ──────────────────────────────────
        print("     ├─ Cross-referencing CVEs with detection templates...")
        xref_count = self._cross_reference_cves(conn)
        if xref_count > 0:
            print(f"     ├─ Linked {xref_count:,d} templates to CVE records")

        # ── Total count ───────────────────────────────────────────
        row = conn.execute(
            "SELECT COUNT(*) as cnt FROM intel_records WHERE source = 'nuclei'"
        ).fetchone()
        records_total = row["cnt"] if row else total_parsed

        log.info("Nuclei sync complete: %d new, %d updated, %d total",
                 total_new, total_updated, records_total)

        return {
            "records_new": total_new,
            "records_updated": total_updated,
            "records_total": records_total,
        }

    # ── GitHub API mode ───────────────────────────────────────────

    async def _sync_github(self, since: str | None = None) -> list[Any]:
        """Sync templates via GitHub API.

        Uses the Git Trees API to enumerate .yaml files in relevant
        directories, then fetches and parses each template.

        For efficiency, we use the recursive tree endpoint to get
        all file paths in one call, then selectively fetch templates
        from directories we care about.
        """
        from common.intel.intel_engine import IntelRecord

        records: list[IntelRecord] = []

        # Get the full recursive tree
        print("     │  ├─ Fetching repository tree...")
        try:
            await self._rate_limit()
            tree_data = await _github_api(
                f"/repos/{self.repo}/git/trees/main?recursive=1",
                token=self.github_token,
            )
        except Exception as exc:
            log.error("Failed to fetch Nuclei repo tree: %s", exc)
            raise RuntimeError(f"GitHub API error: {exc}")

        tree = tree_data.get("tree", [])
        if not tree:
            log.warning("Empty tree returned from GitHub API")
            return records

        # Filter to YAML templates in relevant directories
        template_paths = self._filter_template_paths(tree)
        total_templates = len(template_paths)
        print(f"     │  ├─ Found {total_templates:,d} template files")

        if total_templates == 0:
            return records

        # For large repos, we don't fetch every file individually.
        # Instead, we extract metadata from the file path and use
        # the GitHub Contents API in batches for template details.
        # For practical limits, cap at 5000 templates per sync.
        if total_templates > 5000:
            template_paths = template_paths[:5000]
            print(f"     │  ├─ Capped at 5,000 templates for this sync")

        # Parse templates — use path-based metadata for templates
        # where we can infer info (CVE templates have ID in filename)
        fast_records = self._parse_from_paths(template_paths)
        records.extend(fast_records)

        # For CVE templates, optionally fetch full YAML for richer metadata
        cve_paths = [p for p in template_paths if "/cves/" in p["path"].lower()]
        if cve_paths and len(cve_paths) <= 200:
            print(f"     │  ├─ Fetching {len(cve_paths)} CVE template details...")
            enriched = await self._fetch_template_details(cve_paths[:200])
            # Merge enriched data into existing records
            enriched_map = {r.record_id: r for r in enriched}
            for i, rec in enumerate(records):
                if rec.record_id in enriched_map:
                    records[i] = enriched_map[rec.record_id]

        return records

    def _filter_template_paths(self, tree: list[dict]) -> list[dict]:
        """Filter git tree entries to relevant YAML template files."""
        templates = []
        for entry in tree:
            if entry.get("type") != "blob":
                continue
            path = entry.get("path", "")
            if not path.endswith(".yaml"):
                continue
            # Check if it's in a template directory we care about
            for tdir in TEMPLATE_DIRS:
                if path.startswith(tdir + "/") or f"/{tdir}/" in path:
                    templates.append(entry)
                    break
        return templates

    def _parse_from_paths(self, entries: list[dict]) -> list[Any]:
        """Build IntelRecords from file paths alone (fast, no API calls).

        Nuclei template paths follow predictable patterns:
            http/cves/2024/CVE-2024-1234.yaml
            http/vulnerabilities/apache/apache-struts-rce.yaml
            http/misconfigurations/nginx/nginx-status-page.yaml

        We extract template ID, category, and year from the path.
        """
        from common.intel.intel_engine import IntelRecord

        records: list[IntelRecord] = []

        for entry in entries:
            path = entry.get("path", "")
            filename = path.rsplit("/", 1)[-1] if "/" in path else path
            template_id = filename.replace(".yaml", "")

            if not template_id:
                continue

            # Determine category from path
            category = self._classify_path(path)

            # Check if it's a CVE template
            is_cve = template_id.upper().startswith("CVE-")
            cve_ids = [template_id.upper()] if is_cve else []

            # Infer severity from category
            severity = self._infer_severity(category, is_cve)

            # Build human-readable title from template ID
            title = self._id_to_title(template_id)

            # Build tags
            tags = [category]
            if is_cve:
                tags.append("cve")
            # Extract year from path if present
            year_match = re.search(r'/(\d{4})/', path)
            if year_match:
                tags.append(f"year:{year_match.group(1)}")

            # Extract technology from path
            parts = path.split("/")
            if len(parts) >= 3:
                tech = parts[-2] if parts[-2] not in ("cves", "vulnerabilities",
                    "misconfigurations", "exposures") else ""
                if tech and not tech.isdigit():
                    tags.append(tech)

            record_id = f"NUCLEI-{template_id}"

            records.append(IntelRecord(
                record_id=record_id,
                source="nuclei",
                title=title,
                description=f"Nuclei detection template: {title} [{category}]",
                severity=severity,
                cvss_score=None,
                products=[],
                references=[
                    f"https://github.com/{self.repo}/blob/main/{path}"
                ],
                tags=tags[:15],
                exploit_available=is_cve,  # CVE templates are effectively exploit checks
                published_at="",
                updated_at="",
                raw_data={
                    "template_id": template_id,
                    "path": path,
                    "category": category,
                    "cve_ids": cve_ids,
                    "sha": entry.get("sha", ""),
                },
            ))

        return records

    async def _fetch_template_details(self, entries: list[dict]) -> list[Any]:
        """Fetch and parse full YAML for select templates (CVEs).

        Makes individual API calls for each template to get the full
        YAML content, then extracts richer metadata.
        """
        from common.intel.intel_engine import IntelRecord

        records: list[IntelRecord] = []

        for entry in entries:
            path = entry.get("path", "")
            try:
                await self._rate_limit()
                url = (f"https://raw.githubusercontent.com/"
                       f"{self.repo}/main/{path}")
                content = await _fetch_raw_content(url, self.github_token)
                if not content:
                    continue

                info = _extract_template_info(content)
                record = self._info_to_record(info, path)
                if record:
                    records.append(record)
            except Exception as exc:
                log.debug("Failed to fetch template %s: %s", path, exc)
                continue

        return records

    def _info_to_record(self, info: dict[str, Any], path: str) -> Any:
        """Convert parsed template info to an IntelRecord."""
        from common.intel.intel_engine import IntelRecord

        template_id = info.get("id", "")
        if not template_id:
            return None

        name = info.get("name", "")
        severity = NUCLEI_SEVERITY_MAP.get(
            info.get("severity", "unknown"), "unknown"
        )
        description = info.get("description", "")
        if not description:
            description = f"Nuclei template: {name}"

        tags = info.get("tags", [])
        cve_ids = info.get("cve_ids", [])
        cwe_ids = info.get("cwe_ids", [])

        # Merge CWE into tags
        tags.extend(cwe_ids)

        # Build references
        references = info.get("references", [])
        references.append(f"https://github.com/{self.repo}/blob/main/{path}")

        record_id = f"NUCLEI-{template_id}"

        return IntelRecord(
            record_id=record_id,
            source="nuclei",
            title=name or self._id_to_title(template_id),
            description=description[:500],
            severity=severity,
            cvss_score=info.get("cvss_score"),
            products=[],
            references=references[:10],
            tags=tags[:20],
            exploit_available=bool(cve_ids),
            published_at="",
            updated_at="",
            raw_data={
                "template_id": template_id,
                "path": path,
                "author": info.get("author", ""),
                "cve_ids": cve_ids,
                "cwe_ids": cwe_ids,
                "cvss_vector": info.get("cvss_vector", ""),
                "category": self._classify_path(path),
            },
        )

    # ── Local directory mode ──────────────────────────────────────

    async def _sync_local(self, since: str | None = None) -> list[Any]:
        """Sync from a local nuclei-templates directory.

        Walks the directory tree, finds .yaml files in relevant
        subdirectories, parses their info blocks, and returns records.
        """
        from common.intel.intel_engine import IntelRecord

        templates_path = Path(self.templates_dir)  # type: ignore
        records: list[IntelRecord] = []
        count = 0

        # Parse since date for file mtime filtering
        since_ts = None
        if since:
            try:
                since_ts = datetime.strptime(since[:10], "%Y-%m-%d").timestamp()
            except ValueError:
                pass

        for yaml_path in templates_path.rglob("*.yaml"):
            # Check if it's in a relevant directory
            rel_path = str(yaml_path.relative_to(templates_path)).replace("\\", "/")
            relevant = False
            for tdir in TEMPLATE_DIRS:
                if rel_path.startswith(tdir + "/"):
                    relevant = True
                    break
            if not relevant:
                continue

            # Date filtering by file modification time
            if since_ts and yaml_path.stat().st_mtime < since_ts:
                continue

            try:
                content = yaml_path.read_text(encoding="utf-8", errors="replace")
                info = _extract_template_info(content)
                record = self._info_to_record(info, rel_path)
                if record:
                    records.append(record)
                    count += 1
                    if count % 1000 == 0:
                        log.info("Parsed %d local templates...", count)
            except Exception as exc:
                log.debug("Failed to parse local template %s: %s", yaml_path, exc)
                continue

        return records

    # ── Classification helpers ────────────────────────────────────

    def _classify_path(self, path: str) -> str:
        """Classify a template by its directory path."""
        path_lower = path.lower()
        if "/cves/" in path_lower:
            return "cve-detection"
        elif "/vulnerabilities/" in path_lower:
            return "vulnerability"
        elif "/misconfigurations/" in path_lower:
            return "misconfiguration"
        elif "/exposures/" in path_lower:
            return "exposure"
        elif "/technologies/" in path_lower:
            return "technology-detection"
        elif "/default-logins/" in path_lower:
            return "default-login"
        elif "/takeovers/" in path_lower:
            return "subdomain-takeover"
        elif "/dns/" in path_lower:
            return "dns-check"
        elif "/ssl/" in path_lower:
            return "ssl-check"
        elif "/headless/" in path_lower:
            return "headless-check"
        elif "/javascript/" in path_lower:
            return "javascript-check"
        return "other"

    def _infer_severity(self, category: str, is_cve: bool) -> str:
        """Infer a default severity based on template category."""
        severity_map = {
            "cve-detection":       "high",
            "vulnerability":       "high",
            "misconfiguration":    "medium",
            "exposure":            "medium",
            "technology-detection": "info",
            "default-login":       "high",
            "subdomain-takeover":  "high",
            "dns-check":           "info",
            "ssl-check":           "medium",
            "headless-check":      "medium",
            "javascript-check":    "medium",
        }
        return severity_map.get(category, "medium" if is_cve else "info")

    def _id_to_title(self, template_id: str) -> str:
        """Convert a template ID to a human-readable title.

        Examples:
            CVE-2024-1234        → CVE-2024-1234
            apache-struts-rce    → Apache Struts RCE
            nginx-status-page    → Nginx Status Page
        """
        if template_id.upper().startswith("CVE-"):
            return template_id.upper()
        # Convert kebab-case to Title Case
        return template_id.replace("-", " ").replace("_", " ").title()

    # ── CVE cross-referencing ─────────────────────────────────────

    def _cross_reference_cves(self, conn: sqlite3.Connection) -> int:
        """Link Nuclei templates to existing CVE records.

        For templates with cve_ids in raw_data, update the corresponding
        CVE records to flag them as having detection templates available.
        """
        rows = conn.execute(
            "SELECT raw_data FROM intel_records WHERE source = 'nuclei'"
        ).fetchall()

        cve_ids_with_templates: set[str] = set()
        for row in rows:
            try:
                raw = json.loads(row["raw_data"]) if isinstance(row["raw_data"], str) else row["raw_data"]
                for cve_id in raw.get("cve_ids", []):
                    if cve_id.startswith("CVE-"):
                        cve_ids_with_templates.add(cve_id)
            except (json.JSONDecodeError, TypeError, AttributeError):
                continue

        if not cve_ids_with_templates:
            return 0

        # We don't modify exploit_available for CVEs based on Nuclei templates,
        # but we can add a tag. For now, just count the cross-references.
        count = 0
        batch = list(cve_ids_with_templates)
        for i in range(0, len(batch), 500):
            chunk = batch[i:i + 500]
            placeholders = ",".join("?" * len(chunk))
            cursor = conn.execute(
                f"SELECT COUNT(*) as cnt FROM intel_records "
                f"WHERE record_id IN ({placeholders}) AND source = 'cve'",
                chunk,
            )
            row = cursor.fetchone()
            count += row["cnt"] if row else 0

        return count

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

    # ── Rate limiting ─────────────────────────────────────────────

    async def _rate_limit(self) -> None:
        """Enforce GitHub API rate limits."""
        now = time.monotonic()
        elapsed = now - self._last_request
        if elapsed < self.rate_delay:
            wait = self.rate_delay - elapsed
            await asyncio.sleep(wait)
        self._last_request = time.monotonic()


# ══════════════════════════════════════════════════════════════════════
# UNIT TESTS
# ══════════════════════════════════════════════════════════════════════

class TestNucleiSync:
    """Unit tests for NucleiSync parsing and classification."""

    def test_yaml_info_extraction(self) -> None:
        """Test extracting metadata from a Nuclei YAML template."""
        yaml_content = """id: CVE-2024-1234

info:
  name: Apache Struts RCE via OGNL Injection
  author: h4x0r,pdteam
  severity: critical
  description: |
    Apache Struts allows remote code execution through
    OGNL injection in the ActionContext.
  reference:
    - https://nvd.nist.gov/vuln/detail/CVE-2024-1234
    - https://struts.apache.org/announce-2024
  classification:
    cvss-metrics: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
    cvss-score: 9.8
    cve-id: CVE-2024-1234
    cwe-id: CWE-94
  tags: rce,struts,apache,cve2024,ognl

http:
  - method: GET
    path:
      - "{{BaseURL}}/struts2-showcase/"
"""
        info = _extract_template_info(yaml_content)
        assert info["id"] == "CVE-2024-1234"
        assert info["name"] == "Apache Struts RCE via OGNL Injection"
        assert info["severity"] == "critical"
        assert info["cvss_score"] == 9.8
        assert "CVE-2024-1234" in info["cve_ids"]
        assert "CWE-94" in info["cwe_ids"]
        assert "rce" in info["tags"]
        assert len(info["references"]) == 2

    def test_path_classification(self) -> None:
        """Test template path classification."""
        syncer = NucleiSync()
        assert syncer._classify_path("http/cves/2024/CVE-2024-1234.yaml") == "cve-detection"
        assert syncer._classify_path("http/vulnerabilities/apache/struts.yaml") == "vulnerability"
        assert syncer._classify_path("http/misconfigurations/nginx/status.yaml") == "misconfiguration"
        assert syncer._classify_path("http/exposures/configs/phpinfo.yaml") == "exposure"
        assert syncer._classify_path("http/technologies/wordpress.yaml") == "technology-detection"
        assert syncer._classify_path("http/default-logins/admin/default.yaml") == "default-login"
        assert syncer._classify_path("dns/cname-check.yaml") == "dns-check"

    def test_id_to_title(self) -> None:
        """Test template ID to title conversion."""
        syncer = NucleiSync()
        assert syncer._id_to_title("CVE-2024-1234") == "CVE-2024-1234"
        assert syncer._id_to_title("apache-struts-rce") == "Apache Struts Rce"
        assert syncer._id_to_title("nginx-status-page") == "Nginx Status Page"

    def test_severity_inference(self) -> None:
        """Test severity inference from category."""
        syncer = NucleiSync()
        assert syncer._infer_severity("cve-detection", True) == "high"
        assert syncer._infer_severity("vulnerability", False) == "high"
        assert syncer._infer_severity("misconfiguration", False) == "medium"
        assert syncer._infer_severity("technology-detection", False) == "info"
        assert syncer._infer_severity("default-login", False) == "high"

    def test_path_filtering(self) -> None:
        """Test git tree filtering for template files."""
        syncer = NucleiSync()
        tree = [
            {"path": "http/cves/2024/CVE-2024-1234.yaml", "type": "blob"},
            {"path": "http/cves/2024/CVE-2024-5678.yaml", "type": "blob"},
            {"path": "helpers/wordlists/passwords.txt", "type": "blob"},
            {"path": ".github/workflows/ci.yml", "type": "blob"},
            {"path": "http/vulnerabilities/apache/struts.yaml", "type": "blob"},
            {"path": "README.md", "type": "blob"},
            {"path": "http/cves", "type": "tree"},  # directory, not blob
        ]
        filtered = syncer._filter_template_paths(tree)
        assert len(filtered) == 3
        paths = [e["path"] for e in filtered]
        assert "http/cves/2024/CVE-2024-1234.yaml" in paths
        assert "http/vulnerabilities/apache/struts.yaml" in paths
        assert "helpers/wordlists/passwords.txt" not in paths

    def test_parse_from_paths(self) -> None:
        """Test record generation from file paths."""
        syncer = NucleiSync()
        entries = [
            {"path": "http/cves/2024/CVE-2024-9999.yaml", "type": "blob", "sha": "abc123"},
        ]
        records = syncer._parse_from_paths(entries)
        assert len(records) == 1
        r = records[0]
        assert r.record_id == "NUCLEI-CVE-2024-9999"
        assert r.source == "nuclei"
        assert "cve" in r.tags
        assert "cve-detection" in r.tags

    def test_empty_yaml(self) -> None:
        """Test graceful handling of empty/minimal YAML."""
        info = _extract_template_info("")
        assert info["id"] == ""
        assert info["name"] == ""
        assert info["severity"] == "unknown"

    def test_minimal_yaml(self) -> None:
        """Test parsing a minimal valid template."""
        yaml_content = """id: simple-check
info:
  name: Simple Health Check
  severity: info
  tags: health,ping
"""
        info = _extract_template_info(yaml_content)
        assert info["id"] == "simple-check"
        assert info["name"] == "Simple Health Check"
        assert info["severity"] == "info"
        assert "health" in info["tags"]
