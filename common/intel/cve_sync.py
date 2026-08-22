"""CVE Sync — NVD API v2 CVE Synchronization.

Pulls CVE data from the NIST National Vulnerability Database (NVD) REST
API v2.0 and stores normalized records in the local intel SQLite database.

Features:
    - Paginated API traversal (2,000 results per page)
    - Incremental sync via lastModStartDate / pubStartDate
    - CVSS v3.1 / v3.0 / v2.0 score extraction with severity normalization
    - CPE product string parsing for affected-product tagging
    - Reference URL and tag extraction
    - Exploit-availability flagging from reference tags
    - Rate limiting (NVD public rate limit: 5 req/30s without API key,
      50 req/30s with key — configurable via FORGE_NVD_API_KEY env var)
    - Bulk upsert batching (500 records per commit)
    - EventBus integration for dashboard intel events

Environment Variables:
    FORGE_NVD_API_KEY   — Optional NVD API key for higher rate limits.
    FORGE_NVD_BASE_URL  — Override base URL (for testing / mirrors).

Usage:
    syncer = CVESync()
    result = await syncer.sync(conn=sqlite_conn, since="2025-01-01")
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import sqlite3
import time
from datetime import datetime, timezone, timedelta
from typing import Any
from urllib.parse import urlencode

log = logging.getLogger("forge.intel.cve")

# NVD API v2 endpoints
DEFAULT_NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Rate limits
PUBLIC_RATE_DELAY = 6.5    # seconds between requests (no API key)
KEYED_RATE_DELAY  = 0.65   # seconds between requests (with API key)

# Pagination
RESULTS_PER_PAGE = 2000
BATCH_SIZE       = 500     # records per DB commit

# ── Severity normalization ────────────────────────────────────────

CVSS_SEVERITY_MAP = {
    "CRITICAL": "critical",
    "HIGH":     "high",
    "MEDIUM":   "medium",
    "LOW":      "low",
    "NONE":     "info",
}

CVSS_SCORE_THRESHOLDS = [
    (9.0, "critical"),
    (7.0, "high"),
    (4.0, "medium"),
    (0.1, "low"),
    (0.0, "info"),
]


def _normalize_severity(cvss_score: float | None, cvss_severity: str | None) -> str:
    """Map a CVSS score + severity string to our normalized severity enum."""
    if cvss_severity:
        mapped = CVSS_SEVERITY_MAP.get(cvss_severity.upper())
        if mapped:
            return mapped
    if cvss_score is not None:
        for threshold, sev in CVSS_SCORE_THRESHOLDS:
            if cvss_score >= threshold:
                return sev
    return "unknown"


# ── HTTP helper (stdlib only — no external deps required) ─────────

async def _fetch_json(url: str, headers: dict[str, str] | None = None) -> dict[str, Any]:
    raise RuntimeError("outbound_policy_unsupported")
    """Async HTTP GET returning parsed JSON, using urllib (stdlib).

    We intentionally avoid requiring `aiohttp` or `httpx` as hard deps.
    The NVD API is slow enough that blocking in a thread executor is fine.
    """
    import urllib.request
    import urllib.error

    req_headers = {
        "Accept": "application/json",
        "User-Agent": "Forge-Suite/5.0 IntelPipeline (CVESync)",
    }
    if headers:
        req_headers.update(headers)

    request = urllib.request.Request(url, headers=req_headers)

    loop = asyncio.get_event_loop()
    try:
        response = await loop.run_in_executor(
            None,
            lambda: urllib.request.urlopen(request, timeout=60),
        )
        body = response.read().decode("utf-8")
        return json.loads(body)
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace") if e.fp else ""
        log.error("NVD API HTTP %d: %s — %s", e.code, e.reason, body[:200])
        raise
    except urllib.error.URLError as e:
        log.error("NVD API connection error: %s", e.reason)
        raise
    except json.JSONDecodeError as e:
        log.error("NVD API returned invalid JSON: %s", e)
        raise


# ══════════════════════════════════════════════════════════════════════
# CVE SYNC — NVD API v2 Client
# ══════════════════════════════════════════════════════════════════════

class CVESync:
    """NVD API v2 CVE synchronization engine.

    Fetches CVE records from the NVD, normalizes them into IntelRecords,
    and bulk-upserts them into the shared intel SQLite database.

    The sync contract (called by IntelEngine._sync_source):
        async def sync(conn, since=None, event_bus=None) -> dict

    Returns:
        dict with keys: records_new, records_updated, records_total
    """

    def __init__(self) -> None:
        self.api_key: str | None = os.environ.get("FORGE_NVD_API_KEY")
        self.base_url: str = os.environ.get("FORGE_NVD_BASE_URL", DEFAULT_NVD_BASE)
        self.rate_delay: float = KEYED_RATE_DELAY if self.api_key else PUBLIC_RATE_DELAY
        self._last_request: float = 0.0
        self._request_count: int = 0

    async def sync(
        self,
        conn: sqlite3.Connection,
        since: str | None = None,
        event_bus: Any = None,
    ) -> dict[str, int]:
        """Execute a full or incremental CVE sync from NVD.

        Args:
            conn:      SQLite connection (from IntelEngine).
            since:     ISO date string for incremental sync.
                       If None, syncs CVEs from the last 120 days.
            event_bus: Optional EventBus for dashboard events.

        Returns:
            Dict with records_new, records_updated, records_total counts.
        """
        raise RuntimeError("outbound_policy_unsupported")
        log.info("CVE sync starting (since=%s, api_key=%s)",
                 since, "yes" if self.api_key else "no")

        # Import IntelRecord for record construction
        from common.intel.intel_engine import IntelRecord

        # Build date range for the API query
        params = self._build_query_params(since)
        total_new = 0
        total_updated = 0
        total_fetched = 0
        start_index = 0
        total_results = None
        page = 0

        while True:
            # Rate limiting
            await self._rate_limit()

            # Build paginated URL
            page_params = {**params, "startIndex": start_index, "resultsPerPage": RESULTS_PER_PAGE}
            url = f"{self.base_url}?{urlencode(page_params)}"

            log.info("CVE sync page %d: startIndex=%d", page, start_index)
            print(f"     ├─ Fetching CVEs page {page + 1} (offset {start_index})...")

            try:
                headers = {}
                if self.api_key:
                    headers["apiKey"] = self.api_key
                data = await _fetch_json(url, headers=headers)
            except Exception as exc:
                log.error("CVE sync fetch failed at page %d: %s", page, exc)
                # Return what we have so far rather than crashing
                if total_fetched > 0:
                    break
                raise

            # Parse API response
            if total_results is None:
                total_results = data.get("totalResults", 0)
                log.info("NVD reports %d total CVEs matching query", total_results)
                print(f"     ├─ NVD reports {total_results:,d} total matching CVEs")

            vulnerabilities = data.get("vulnerabilities", [])
            if not vulnerabilities:
                break

            # Parse each CVE into an IntelRecord
            batch: list[IntelRecord] = []
            for item in vulnerabilities:
                cve_data = item.get("cve", {})
                record = self._parse_cve(cve_data)
                if record:
                    batch.append(record)

            # Bulk upsert this batch
            if batch:
                new, updated = self._bulk_upsert(conn, batch)
                total_new += new
                total_updated += updated
                total_fetched += len(batch)

                # Emit events for new critical/high CVEs
                if event_bus:
                    for rec in batch:
                        if rec.severity in ("critical", "high"):
                            self._emit_cve_event(event_bus, rec)

            log.info("CVE sync page %d: %d records (%d new, %d updated)",
                     page, len(batch), new if batch else 0, updated if batch else 0)

            # Check if we've fetched everything
            start_index += RESULTS_PER_PAGE
            page += 1
            if start_index >= (total_results or 0):
                break

        # Get total record count for this source
        row = conn.execute(
            "SELECT COUNT(*) as cnt FROM intel_records WHERE source = 'cve'"
        ).fetchone()
        records_total = row["cnt"] if row else total_fetched

        log.info("CVE sync complete: %d new, %d updated, %d total in DB",
                 total_new, total_updated, records_total)

        return {
            "records_new": total_new,
            "records_updated": total_updated,
            "records_total": records_total,
        }

    # ── Query parameter construction ──────────────────────────────

    def _build_query_params(self, since: str | None) -> dict[str, str]:
        """Build NVD API v2 query parameters.

        The NVD API v2 uses ISO-8601 datetime format for date filters.

        Args:
            since: Optional date string (YYYY-MM-DD or ISO-8601).

        Returns:
            Dict of query parameters.
        """
        params: dict[str, str] = {}

        if since:
            # Parse the since date and format for NVD API
            try:
                if "T" in since:
                    dt = datetime.fromisoformat(since.replace("Z", "+00:00"))
                else:
                    dt = datetime.strptime(since, "%Y-%m-%d").replace(tzinfo=timezone.utc)
            except ValueError:
                # Fallback: last 120 days
                dt = datetime.now(timezone.utc) - timedelta(days=120)
                log.warning("Invalid since date '%s', using 120-day window", since)

            # NVD API requires paired start/end dates
            params["lastModStartDate"] = dt.strftime("%Y-%m-%dT%H:%M:%S.000")
            params["lastModEndDate"] = datetime.now(timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%S.000"
            )
        else:
            # Default: last 120 days of modifications
            start = datetime.now(timezone.utc) - timedelta(days=120)
            params["lastModStartDate"] = start.strftime("%Y-%m-%dT%H:%M:%S.000")
            params["lastModEndDate"] = datetime.now(timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%S.000"
            )

        return params

    # ── CVE parsing ───────────────────────────────────────────────

    def _parse_cve(self, cve: dict[str, Any]) -> Any:
        """Parse a single NVD CVE v2 JSON object into an IntelRecord.

        Handles the nested NVD structure:
            cve.id, cve.descriptions[], cve.metrics.cvssMetricV31[],
            cve.references[], cve.configurations[], cve.weaknesses[]

        Args:
            cve: The 'cve' object from the NVD API response.

        Returns:
            IntelRecord or None if parsing fails.
        """
        from common.intel.intel_engine import IntelRecord

        try:
            cve_id = cve.get("id", "")
            if not cve_id:
                return None

            # ── Description ───────────────────────────────────────
            descriptions = cve.get("descriptions", [])
            description = ""
            for desc in descriptions:
                if desc.get("lang") == "en":
                    description = desc.get("value", "")
                    break
            if not description and descriptions:
                description = descriptions[0].get("value", "")

            # ── Title: first 120 chars of description ─────────────
            title = description[:120].rstrip(".")
            if len(description) > 120:
                title += "..."

            # ── CVSS Score & Severity ─────────────────────────────
            cvss_score, cvss_severity = self._extract_cvss(cve)
            severity = _normalize_severity(cvss_score, cvss_severity)

            # ── Products (CPE matches) ────────────────────────────
            products = self._extract_products(cve)

            # ── References ────────────────────────────────────────
            refs = cve.get("references", [])
            reference_urls = [r.get("url", "") for r in refs if r.get("url")]

            # ── Tags (CWE IDs + reference tags) ───────────────────
            tags = self._extract_tags(cve, refs)

            # ── Exploit availability ──────────────────────────────
            # Check reference tags for exploit indicators
            exploit_available = self._check_exploit_available(refs)

            # ── Dates ─────────────────────────────────────────────
            published = cve.get("published", "")
            last_modified = cve.get("lastModified", "")

            return IntelRecord(
                record_id=cve_id,
                source="cve",
                title=title,
                description=description,
                severity=severity,
                cvss_score=cvss_score,
                products=products,
                references=reference_urls[:20],  # Cap at 20 refs
                tags=tags,
                exploit_available=exploit_available,
                published_at=published,
                updated_at=last_modified,
                raw_data={
                    "vulnStatus": cve.get("vulnStatus", ""),
                    "cvss_vector": self._extract_cvss_vector(cve),
                    "cwe_ids": self._extract_cwes(cve),
                    "source_identifier": cve.get("sourceIdentifier", ""),
                },
            )

        except Exception as exc:
            log.debug("Failed to parse CVE %s: %s", cve.get("id", "?"), exc)
            return None

    def _extract_cvss(self, cve: dict[str, Any]) -> tuple[float | None, str | None]:
        """Extract the best available CVSS score and severity.

        Prioritizes: CVSS v3.1 > CVSS v3.0 > CVSS v2.0

        Returns:
            Tuple of (score, severity_string) or (None, None).
        """
        metrics = cve.get("metrics", {})

        # Try v3.1 first
        v31_list = metrics.get("cvssMetricV31", [])
        for metric in v31_list:
            cvss_data = metric.get("cvssData", {})
            score = cvss_data.get("baseScore")
            severity = cvss_data.get("baseSeverity")
            if score is not None:
                return float(score), severity

        # Try v3.0
        v30_list = metrics.get("cvssMetricV30", [])
        for metric in v30_list:
            cvss_data = metric.get("cvssData", {})
            score = cvss_data.get("baseScore")
            severity = cvss_data.get("baseSeverity")
            if score is not None:
                return float(score), severity

        # Fall back to v2.0
        v2_list = metrics.get("cvssMetricV2", [])
        for metric in v2_list:
            cvss_data = metric.get("cvssData", {})
            score = cvss_data.get("baseScore")
            severity = metric.get("baseSeverity")  # Note: severity at metric level for v2
            if score is not None:
                return float(score), severity

        return None, None

    def _extract_cvss_vector(self, cve: dict[str, Any]) -> str:
        """Extract the CVSS vector string (v3.1 > v3.0 > v2.0)."""
        metrics = cve.get("metrics", {})
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            metric_list = metrics.get(key, [])
            for metric in metric_list:
                vector = metric.get("cvssData", {}).get("vectorString")
                if vector:
                    return vector
        return ""

    def _extract_cwes(self, cve: dict[str, Any]) -> list[str]:
        """Extract CWE IDs from the weaknesses array."""
        cwes = []
        for weakness in cve.get("weaknesses", []):
            for desc in weakness.get("description", []):
                cwe_val = desc.get("value", "")
                if cwe_val.startswith("CWE-") and cwe_val != "CWE-noinfo":
                    cwes.append(cwe_val)
        return cwes

    def _extract_products(self, cve: dict[str, Any]) -> list[str]:
        """Extract affected product CPE strings from configurations.

        NVD v2 nests CPE matches inside configurations[].nodes[].cpeMatch[].
        We extract the CPE 2.3 URI strings.
        """
        products = []
        for config in cve.get("configurations", []):
            for node in config.get("nodes", []):
                for match in node.get("cpeMatch", []):
                    if match.get("vulnerable", False):
                        cpe = match.get("criteria", "")
                        if cpe:
                            products.append(cpe)
                # Handle nested children (AND/OR operators)
                for child in node.get("children", []):
                    for match in child.get("cpeMatch", []):
                        if match.get("vulnerable", False):
                            cpe = match.get("criteria", "")
                            if cpe:
                                products.append(cpe)
        # Deduplicate and cap
        seen = set()
        deduped = []
        for p in products:
            if p not in seen:
                seen.add(p)
                deduped.append(p)
            if len(deduped) >= 50:
                break
        return deduped

    def _extract_tags(self, cve: dict[str, Any], refs: list[dict]) -> list[str]:
        """Build tag list from CWEs and reference tags."""
        tags = []

        # CWE IDs
        tags.extend(self._extract_cwes(cve))

        # Unique reference tags (Exploit, Patch, Vendor Advisory, etc.)
        ref_tags: set[str] = set()
        for ref in refs:
            for tag in ref.get("tags", []):
                ref_tags.add(tag.lower().replace(" ", "-"))
        tags.extend(sorted(ref_tags))

        return tags[:30]  # Cap at 30 tags

    def _check_exploit_available(self, refs: list[dict]) -> bool:
        """Check if any reference indicates a known exploit.

        NVD reference tags that indicate exploit availability:
            - "Exploit"
            - "Third Party Advisory" with exploit-db.com URL
        """
        exploit_indicators = {"exploit", "third party advisory"}
        exploit_domains = {"exploit-db.com", "packetstormsecurity.com", "github.com/rapid7"}

        for ref in refs:
            ref_tags = {t.lower() for t in ref.get("tags", [])}
            if "exploit" in ref_tags:
                return True

            url = ref.get("url", "").lower()
            for domain in exploit_domains:
                if domain in url:
                    return True

        return False

    # ── Database operations ───────────────────────────────────────

    def _bulk_upsert(
        self,
        conn: sqlite3.Connection,
        records: list[Any],
    ) -> tuple[int, int]:
        """Batch upsert records into the intel_records table.

        Uses the same schema as IntelEngine.bulk_upsert but operates
        directly on the connection for performance.

        Args:
            conn:    SQLite connection.
            records: List of IntelRecord objects.

        Returns:
            Tuple of (new_count, updated_count).
        """
        if not records:
            return 0, 0

        # Check existing IDs in one query
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
        """Enforce NVD API rate limits.

        Public API: max 5 requests per 30 seconds (6.5s spacing).
        With API key: max 50 requests per 30 seconds (0.65s spacing).
        """
        now = time.monotonic()
        elapsed = now - self._last_request
        if elapsed < self.rate_delay:
            wait = self.rate_delay - elapsed
            log.debug("Rate limiting: sleeping %.1fs", wait)
            await asyncio.sleep(wait)
        self._last_request = time.monotonic()
        self._request_count += 1

    # ── EventBus integration ──────────────────────────────────────

    def _emit_cve_event(self, event_bus: Any, record: Any) -> None:
        """Emit a new-CVE event to the dashboard EventBus."""
        try:
            from common.dashboard.event_bus import Event, EventType
            event_bus.emit(Event(
                event_type=EventType("intel_cve_new"),
                data={
                    "cve_id": record.record_id,
                    "title": record.title,
                    "severity": record.severity,
                    "cvss": record.cvss_score,
                    "exploit_available": record.exploit_available,
                },
                source="cve_sync",
            ))
        except (ValueError, ImportError, AttributeError):
            pass


# ══════════════════════════════════════════════════════════════════════
# UNIT TESTS
# ══════════════════════════════════════════════════════════════════════

class TestCVESync:
    """Unit tests for CVESync parsing and normalization logic."""

    def test_severity_normalization(self) -> None:
        assert _normalize_severity(9.8, "CRITICAL") == "critical"
        assert _normalize_severity(7.5, "HIGH") == "high"
        assert _normalize_severity(5.0, "MEDIUM") == "medium"
        assert _normalize_severity(2.0, "LOW") == "low"
        assert _normalize_severity(0.0, None) == "info"
        assert _normalize_severity(None, None) == "unknown"
        # Score takes over when severity string is missing
        assert _normalize_severity(9.1, None) == "critical"
        assert _normalize_severity(7.0, None) == "high"
        assert _normalize_severity(4.0, None) == "medium"

    def test_parse_cve_basic(self) -> None:
        """Test parsing a minimal NVD CVE v2 structure."""
        syncer = CVESync()
        cve = {
            "id": "CVE-2024-1234",
            "descriptions": [
                {"lang": "en", "value": "A critical vulnerability in ExampleApp allows remote code execution via a crafted HTTP request."}
            ],
            "metrics": {
                "cvssMetricV31": [{
                    "cvssData": {
                        "baseScore": 9.8,
                        "baseSeverity": "CRITICAL",
                        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    }
                }]
            },
            "references": [
                {"url": "https://example.com/advisory", "tags": ["Vendor Advisory"]},
                {"url": "https://exploit-db.com/exploits/51234", "tags": ["Exploit"]},
            ],
            "weaknesses": [
                {"description": [{"value": "CWE-78"}]}
            ],
            "configurations": [
                {"nodes": [{"cpeMatch": [
                    {"vulnerable": True, "criteria": "cpe:2.3:a:example:exampleapp:1.0:*:*:*:*:*:*:*"}
                ]}]}
            ],
            "published": "2024-03-15T00:00:00.000",
            "lastModified": "2024-03-16T12:00:00.000",
            "vulnStatus": "Analyzed",
        }

        from common.intel.intel_engine import IntelRecord
        record = syncer._parse_cve(cve)
        assert record is not None
        assert record.record_id == "CVE-2024-1234"
        assert record.source == "cve"
        assert record.severity == "critical"
        assert record.cvss_score == 9.8
        assert record.exploit_available is True
        assert len(record.products) == 1
        assert "CWE-78" in record.tags

    def test_parse_cve_v2_fallback(self) -> None:
        """Test CVSS v2 fallback when v3.x is absent."""
        syncer = CVESync()
        cve = {
            "id": "CVE-2014-0001",
            "descriptions": [{"lang": "en", "value": "Old vulnerability with only CVSS v2 scoring."}],
            "metrics": {
                "cvssMetricV2": [{
                    "cvssData": {"baseScore": 7.5, "vectorString": "AV:N/AC:L/Au:N/C:P/I:P/A:P"},
                    "baseSeverity": "HIGH",
                }]
            },
            "references": [],
            "weaknesses": [],
            "configurations": [],
            "published": "2014-01-01T00:00:00.000",
        }
        record = syncer._parse_cve(cve)
        assert record is not None
        assert record.cvss_score == 7.5
        assert record.severity == "high"

    def test_exploit_detection(self) -> None:
        """Test exploit availability detection from references."""
        syncer = CVESync()
        # Explicit Exploit tag
        assert syncer._check_exploit_available([
            {"url": "https://example.com", "tags": ["Exploit"]}
        ]) is True
        # Exploit-DB domain
        assert syncer._check_exploit_available([
            {"url": "https://www.exploit-db.com/exploits/12345", "tags": []}
        ]) is True
        # No exploit
        assert syncer._check_exploit_available([
            {"url": "https://example.com/patch", "tags": ["Patch"]}
        ]) is False

    def test_empty_cve(self) -> None:
        """Test graceful handling of empty/malformed CVE data."""
        syncer = CVESync()
        assert syncer._parse_cve({}) is None
        assert syncer._parse_cve({"id": ""}) is None

    def test_query_params_with_since(self) -> None:
        """Test query parameter building with a since date."""
        syncer = CVESync()
        params = syncer._build_query_params("2025-01-01")
        assert "lastModStartDate" in params
        assert "lastModEndDate" in params
        assert params["lastModStartDate"].startswith("2025-01-01")

    def test_query_params_default(self) -> None:
        """Test default query parameters (no since date)."""
        syncer = CVESync()
        params = syncer._build_query_params(None)
        assert "lastModStartDate" in params
        assert "lastModEndDate" in params
