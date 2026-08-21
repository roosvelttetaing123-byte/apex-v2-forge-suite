"""CVE Database — NVD feed ingestion + CPE-based vulnerability lookup.

Downloads NVD CVE data (via NVD 2.0 API or pre-built JSON feeds),
stores in local SQLite, and provides CPE-based version matching to
correlate discovered services against 200,000+ known CVEs.

This is the Nessus-killer layer: version-based correlation at scale
without writing individual detection modules per CVE.

Usage:
    db = CVEDatabase()
    await db.update()                              # sync from NVD
    hits = db.lookup_by_cpe("cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*")
    hits = db.lookup_by_product("apache", "http_server", "2.4.49")
"""
from __future__ import annotations

import gzip
import json
import logging
import re
import sqlite3
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, NoReturn

from common.outbound_policy import OutboundDenied, OutboundReason

log = logging.getLogger("forge.cve_db")

# Default DB location — lives alongside other netforge data files
_DEFAULT_DB_PATH = Path(__file__).parent / "cve_cache.db"

# NVD 2.0 API base
NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
# NVD bulk JSON feed (legacy but faster for initial load)
NVD_FEED_BASE = "https://nvd.nist.gov/feeds/json/cve/1.1"
# CISA KEV catalog
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
# EPSS scores
EPSS_URL = "https://epss.cyentia.com/epss_scores-current.csv.gz"


def _deny_unmigrated_cve_update() -> NoReturn:
    """Keep remote CVE updates inert until their policy adapter exists."""
    raise OutboundDenied(OutboundReason.OUTBOUND_POLICY_UNSUPPORTED)


@dataclass
class CVEMatch:
    """A single CVE that matched a CPE/version query."""
    cve_id: str
    description: str = ""
    cvss31_score: float = 0.0
    cvss31_vector: str = ""
    cvss40_score: float = 0.0
    cvss40_vector: str = ""
    severity: str = "MEDIUM"
    published: str = ""
    modified: str = ""
    references: list[str] = field(default_factory=list)
    cpe_match: str = ""
    is_kev: bool = False
    epss_score: float = 0.0
    epss_percentile: float = 0.0
    weaknesses: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "cve_id": self.cve_id,
            "description": self.description,
            "cvss31_score": self.cvss31_score,
            "cvss31_vector": self.cvss31_vector,
            "cvss40_score": self.cvss40_score,
            "cvss40_vector": self.cvss40_vector,
            "severity": self.severity,
            "published": self.published,
            "references": self.references,
            "is_kev": self.is_kev,
            "epss_score": self.epss_score,
            "weaknesses": self.weaknesses,
        }


# ── SQLite Schema ────────────────────────────────────────────────────────

_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS cves (
    cve_id        TEXT PRIMARY KEY,
    description   TEXT,
    cvss31_score  REAL DEFAULT 0.0,
    cvss31_vector TEXT DEFAULT '',
    cvss40_score  REAL DEFAULT 0.0,
    cvss40_vector TEXT DEFAULT '',
    severity      TEXT DEFAULT 'MEDIUM',
    published     TEXT,
    modified      TEXT,
    references_json TEXT DEFAULT '[]',
    weaknesses_json TEXT DEFAULT '[]'
);

CREATE TABLE IF NOT EXISTS cpe_matches (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    cve_id          TEXT NOT NULL,
    cpe23           TEXT NOT NULL,
    vendor          TEXT DEFAULT '',
    product         TEXT DEFAULT '',
    version_start   TEXT DEFAULT '',
    version_start_type TEXT DEFAULT '',   -- 'including' or 'excluding'
    version_end     TEXT DEFAULT '',
    version_end_type TEXT DEFAULT '',     -- 'including' or 'excluding'
    exact_version   TEXT DEFAULT '',
    FOREIGN KEY (cve_id) REFERENCES cves(cve_id)
);

CREATE INDEX IF NOT EXISTS idx_cpe_vendor_product ON cpe_matches(vendor, product);
CREATE INDEX IF NOT EXISTS idx_cpe_cpe23 ON cpe_matches(cpe23);
CREATE INDEX IF NOT EXISTS idx_cpe_cve ON cpe_matches(cve_id);

CREATE TABLE IF NOT EXISTS kev (
    cve_id              TEXT PRIMARY KEY,
    vendor              TEXT,
    product             TEXT,
    vulnerability_name  TEXT,
    date_added          TEXT,
    due_date            TEXT,
    known_ransomware    TEXT DEFAULT 'Unknown'
);

CREATE TABLE IF NOT EXISTS epss (
    cve_id      TEXT PRIMARY KEY,
    score       REAL DEFAULT 0.0,
    percentile  REAL DEFAULT 0.0,
    date        TEXT
);

CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT
);
"""


class CVEDatabase:
    """Local CVE database backed by SQLite.

    Provides version-correlation vulnerability matching using CPE strings
    from the NVD. Think of this as our version of Nessus's plugin feed —
    except we pull from NVD directly and match at query time.
    """

    def __init__(self, db_path: Path | str | None = None) -> None:
        self.db_path = Path(db_path) if db_path else _DEFAULT_DB_PATH
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn: sqlite3.Connection | None = None
        self._ensure_schema()

    def _get_conn(self) -> sqlite3.Connection:
        if self._conn is None:
            self._conn = sqlite3.connect(str(self.db_path), timeout=30)
            self._conn.row_factory = sqlite3.Row
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA synchronous=NORMAL")
        return self._conn

    def _ensure_schema(self) -> None:
        conn = self._get_conn()
        conn.executescript(_SCHEMA_SQL)
        conn.commit()

    def close(self) -> None:
        if self._conn:
            self._conn.close()
            self._conn = None

    # ── Stats ────────────────────────────────────────────────────────────

    def stats(self) -> dict[str, Any]:
        """Return database statistics."""
        conn = self._get_conn()
        cve_count = conn.execute("SELECT COUNT(*) FROM cves").fetchone()[0]
        cpe_count = conn.execute("SELECT COUNT(*) FROM cpe_matches").fetchone()[0]
        kev_count = conn.execute("SELECT COUNT(*) FROM kev").fetchone()[0]
        epss_count = conn.execute("SELECT COUNT(*) FROM epss").fetchone()[0]
        last_update = conn.execute(
            "SELECT value FROM meta WHERE key='last_nvd_update'"
        ).fetchone()
        return {
            "cve_count": cve_count,
            "cpe_match_count": cpe_count,
            "kev_count": kev_count,
            "epss_count": epss_count,
            "last_update": last_update[0] if last_update else "never",
            "db_path": str(self.db_path),
            "db_size_mb": round(self.db_path.stat().st_size / 1024 / 1024, 2)
            if self.db_path.exists()
            else 0,
        }

    # ── NVD Feed Ingestion ───────────────────────────────────────────────

    async def update(self, api_key: str | None = None, years: list[int] | None = None) -> dict[str, int]:
        """Download and ingest NVD CVE data.

        Uses the NVD 2.0 API with pagination. If api_key is provided,
        uses higher rate limits (50 req/30s vs 5 req/30s).

        Returns dict with counts of ingested records.
        """
        _deny_unmigrated_cve_update()
        import aiohttp

        if years is None:
            # Default: last 10 years of CVEs (covers 95%+ of relevant vulns)
            current_year = time.gmtime().tm_year
            years = list(range(current_year - 10, current_year + 1))

        headers = {}
        if api_key:
            headers["apiKey"] = api_key

        total_cves = 0
        total_cpe_matches = 0

        # Rate limiting: 5 req/30s without key, 50 with key
        delay = 6.0 if not api_key else 0.6

        async with aiohttp.ClientSession(headers=headers) as session:
            for year in years:
                log.info("Fetching NVD CVEs for year %d...", year)
                start_index = 0
                results_per_page = 2000

                while True:
                    params = {
                        "pubStartDate": f"{year}-01-01T00:00:00.000",
                        "pubEndDate": f"{year}-12-31T23:59:59.999",
                        "startIndex": start_index,
                        "resultsPerPage": results_per_page,
                    }

                    try:
                        async with session.get(
                            NVD_API_BASE, params=params, timeout=aiohttp.ClientTimeout(total=60)
                        ) as resp:
                            if resp.status == 403:
                                log.warning("NVD API rate limited — waiting 30s")
                                import asyncio
                                await asyncio.sleep(30)
                                continue
                            if resp.status != 200:
                                log.error("NVD API returned %d for year %d", resp.status, year)
                                break

                            data = await resp.json()
                    except Exception as exc:
                        log.error("NVD API request failed: %s", exc)
                        break

                    vulnerabilities = data.get("vulnerabilities", [])
                    if not vulnerabilities:
                        break

                    cve_count, cpe_count = self._ingest_nvd_batch(vulnerabilities)
                    total_cves += cve_count
                    total_cpe_matches += cpe_count

                    total_results = data.get("totalResults", 0)
                    start_index += results_per_page

                    log.info(
                        "Year %d: ingested %d/%d CVEs (batch %d CPE matches)",
                        year, min(start_index, total_results), total_results, cpe_count,
                    )

                    if start_index >= total_results:
                        break

                    import asyncio
                    await asyncio.sleep(delay)

        # Record update timestamp
        conn = self._get_conn()
        conn.execute(
            "INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)",
            ("last_nvd_update", time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())),
        )
        conn.commit()

        log.info("NVD update complete: %d CVEs, %d CPE matches", total_cves, total_cpe_matches)
        return {"cves": total_cves, "cpe_matches": total_cpe_matches}

    def _ingest_nvd_batch(self, vulnerabilities: list[dict]) -> tuple[int, int]:
        """Ingest a batch of NVD vulnerability records into SQLite."""
        conn = self._get_conn()
        cve_count = 0
        cpe_count = 0

        for vuln_wrapper in vulnerabilities:
            cve_data = vuln_wrapper.get("cve", {})
            cve_id = cve_data.get("id", "")
            if not cve_id:
                continue

            # Extract description (English preferred)
            descriptions = cve_data.get("descriptions", [])
            description = ""
            for desc in descriptions:
                if desc.get("lang") == "en":
                    description = desc.get("value", "")
                    break
            if not description and descriptions:
                description = descriptions[0].get("value", "")

            # Extract CVSS scores
            metrics = cve_data.get("metrics", {})
            cvss31_score, cvss31_vector = self._extract_cvss31(metrics)
            cvss40_score, cvss40_vector = self._extract_cvss40(metrics)

            # Determine severity
            severity = self._determine_severity(cvss31_score, cvss40_score)

            # Extract references
            refs = [
                r.get("url", "")
                for r in cve_data.get("references", [])
                if r.get("url")
            ][:10]

            # Extract weaknesses (CWE IDs)
            weaknesses = []
            for w in cve_data.get("weaknesses", []):
                for desc in w.get("description", []):
                    val = desc.get("value", "")
                    if val.startswith("CWE-"):
                        weaknesses.append(val)

            # Dates
            published = cve_data.get("published", "")
            modified = cve_data.get("lastModified", "")

            # Upsert CVE
            conn.execute(
                """INSERT OR REPLACE INTO cves
                   (cve_id, description, cvss31_score, cvss31_vector,
                    cvss40_score, cvss40_vector, severity, published,
                    modified, references_json, weaknesses_json)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    cve_id, description[:5000], cvss31_score, cvss31_vector,
                    cvss40_score, cvss40_vector, severity, published,
                    modified, json.dumps(refs), json.dumps(weaknesses),
                ),
            )
            cve_count += 1

            # Extract and insert CPE matches
            configurations = cve_data.get("configurations", [])
            for config in configurations:
                for node in config.get("nodes", []):
                    cpe_count += self._process_cpe_node(conn, cve_id, node)

        conn.commit()
        return cve_count, cpe_count

    def _process_cpe_node(self, conn: sqlite3.Connection, cve_id: str, node: dict) -> int:
        """Process a CPE configuration node, returns count of matches inserted."""
        count = 0
        for match in node.get("cpeMatch", []):
            if not match.get("vulnerable", False):
                continue

            cpe23 = match.get("criteria", "")
            if not cpe23:
                continue

            # Parse CPE 2.3 string: cpe:2.3:part:vendor:product:version:...
            parts = cpe23.split(":")
            vendor = parts[3] if len(parts) > 3 else ""
            product = parts[4] if len(parts) > 4 else ""
            exact_version = parts[5] if len(parts) > 5 and parts[5] != "*" else ""

            version_start = match.get("versionStartIncluding", "") or match.get("versionStartExcluding", "")
            version_start_type = (
                "including" if match.get("versionStartIncluding") else
                "excluding" if match.get("versionStartExcluding") else ""
            )
            version_end = match.get("versionEndIncluding", "") or match.get("versionEndExcluding", "")
            version_end_type = (
                "including" if match.get("versionEndIncluding") else
                "excluding" if match.get("versionEndExcluding") else ""
            )

            conn.execute(
                """INSERT INTO cpe_matches
                   (cve_id, cpe23, vendor, product, version_start,
                    version_start_type, version_end, version_end_type, exact_version)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    cve_id, cpe23, vendor, product, version_start,
                    version_start_type, version_end, version_end_type,
                    exact_version,
                ),
            )
            count += 1

        # Recurse into child nodes
        for child in node.get("children", []):
            count += self._process_cpe_node(conn, cve_id, child)

        return count

    def _extract_cvss31(self, metrics: dict) -> tuple[float, str]:
        """Extract CVSS 3.1 score and vector from NVD metrics."""
        for entry in metrics.get("cvssMetricV31", []):
            data = entry.get("cvssData", {})
            return data.get("baseScore", 0.0), data.get("vectorString", "")
        # Fallback to CVSS 3.0
        for entry in metrics.get("cvssMetricV30", []):
            data = entry.get("cvssData", {})
            return data.get("baseScore", 0.0), data.get("vectorString", "")
        return 0.0, ""

    def _extract_cvss40(self, metrics: dict) -> tuple[float, str]:
        """Extract CVSS 4.0 score and vector from NVD metrics."""
        for entry in metrics.get("cvssMetricV40", []):
            data = entry.get("cvssData", {})
            return data.get("baseScore", 0.0), data.get("vectorString", "")
        return 0.0, ""

    def _determine_severity(self, cvss31: float, cvss40: float) -> str:
        """Map CVSS score to severity string."""
        score = cvss31 or cvss40
        if score >= 9.0:
            return "CRITICAL"
        if score >= 7.0:
            return "HIGH"
        if score >= 4.0:
            return "MEDIUM"
        if score > 0:
            return "LOW"
        return "MEDIUM"

    # ── Query Methods ────────────────────────────────────────────────────

    def lookup_by_cpe(
        self, cpe_string: str, min_cvss: float = 0.0
    ) -> list[CVEMatch]:
        """Find all CVEs matching a CPE 2.3 string.

        Matches exact CPE entries and version-range entries.
        """
        parts = cpe_string.split(":")
        if len(parts) < 6:
            return []

        vendor = parts[3] if parts[3] != "*" else ""
        product = parts[4] if parts[4] != "*" else ""
        version = parts[5] if len(parts) > 5 and parts[5] != "*" else ""

        return self.lookup_by_product(vendor, product, version, min_cvss=min_cvss)

    def lookup_by_product(
        self,
        vendor: str,
        product: str,
        version: str = "",
        min_cvss: float = 0.0,
    ) -> list[CVEMatch]:
        """Find all CVEs for a vendor:product:version combination.

        This is the main query method. It checks:
        1. Exact version matches in CPE entries
        2. Version range matches (versionStartIncluding/Excluding, versionEndIncluding/Excluding)
        3. Wildcard CPE entries (version = *)
        """
        conn = self._get_conn()

        # Query all CPE match rows for this vendor+product
        rows = conn.execute(
            """SELECT cm.cve_id, cm.cpe23, cm.version_start, cm.version_start_type,
                      cm.version_end, cm.version_end_type, cm.exact_version,
                      c.description, c.cvss31_score, c.cvss31_vector,
                      c.cvss40_score, c.cvss40_vector, c.severity,
                      c.published, c.modified, c.references_json, c.weaknesses_json
               FROM cpe_matches cm
               JOIN cves c ON cm.cve_id = c.cve_id
               WHERE cm.vendor = ? AND cm.product = ?
                 AND (c.cvss31_score >= ? OR c.cvss40_score >= ? OR ? = 0)
            """,
            (vendor.lower(), product.lower(), min_cvss, min_cvss, min_cvss),
        ).fetchall()

        results: dict[str, CVEMatch] = {}

        for row in rows:
            cve_id = row["cve_id"]
            if cve_id in results:
                continue

            # Check version match
            if version and not self._version_matches(
                version,
                exact=row["exact_version"],
                start=row["version_start"],
                start_type=row["version_start_type"],
                end=row["version_end"],
                end_type=row["version_end_type"],
            ):
                continue

            # Check KEV status
            kev_row = conn.execute(
                "SELECT 1 FROM kev WHERE cve_id = ?", (cve_id,)
            ).fetchone()

            # Check EPSS score
            epss_row = conn.execute(
                "SELECT score, percentile FROM epss WHERE cve_id = ?", (cve_id,)
            ).fetchone()

            refs = json.loads(row["references_json"]) if row["references_json"] else []
            weaknesses = json.loads(row["weaknesses_json"]) if row["weaknesses_json"] else []

            results[cve_id] = CVEMatch(
                cve_id=cve_id,
                description=row["description"] or "",
                cvss31_score=row["cvss31_score"] or 0.0,
                cvss31_vector=row["cvss31_vector"] or "",
                cvss40_score=row["cvss40_score"] or 0.0,
                cvss40_vector=row["cvss40_vector"] or "",
                severity=row["severity"] or "MEDIUM",
                published=row["published"] or "",
                modified=row["modified"] or "",
                references=refs,
                cpe_match=row["cpe23"],
                is_kev=kev_row is not None,
                epss_score=epss_row["score"] if epss_row else 0.0,
                epss_percentile=epss_row["percentile"] if epss_row else 0.0,
                weaknesses=weaknesses,
            )

        # Sort by CVSS score descending, KEV first
        return sorted(
            results.values(),
            key=lambda m: (m.is_kev, m.cvss31_score or m.cvss40_score),
            reverse=True,
        )

    def _version_matches(
        self,
        version: str,
        exact: str = "",
        start: str = "",
        start_type: str = "",
        end: str = "",
        end_type: str = "",
    ) -> bool:
        """Check if a version string falls within a CPE version range.

        Handles:
        - Exact match (exact_version field)
        - Range match (versionStart/End Including/Excluding)
        - Wildcard (no version constraints = matches all)
        """
        # No constraints = wildcard match
        if not exact and not start and not end:
            return True

        # Exact match
        if exact:
            return self._version_compare(version, exact) == 0

        # Range match
        v_parts = self._parse_version(version)

        if start:
            s_parts = self._parse_version(start)
            cmp = self._compare_parts(v_parts, s_parts)
            if start_type == "including" and cmp < 0:
                return False
            if start_type == "excluding" and cmp <= 0:
                return False

        if end:
            e_parts = self._parse_version(end)
            cmp = self._compare_parts(v_parts, e_parts)
            if end_type == "including" and cmp > 0:
                return False
            if end_type == "excluding" and cmp >= 0:
                return False

        return True

    @staticmethod
    def _parse_version(v: str) -> list[int | str]:
        """Parse version string into comparable parts.

        '2.4.49' -> [2, 4, 49]
        '8.0p1' -> [8, 0, 'p1']
        '1.3.5a' -> [1, 3, '5a']
        """
        parts: list[int | str] = []
        for segment in re.split(r"[.\-_]", v):
            # Try to extract leading number
            m = re.match(r"^(\d+)(.*)", segment)
            if m:
                parts.append(int(m.group(1)))
                if m.group(2):
                    parts.append(m.group(2))
            elif segment:
                parts.append(segment)
        return parts

    @staticmethod
    def _compare_parts(a: list[int | str], b: list[int | str]) -> int:
        """Compare two parsed version part lists."""
        for i in range(max(len(a), len(b))):
            pa = a[i] if i < len(a) else 0
            pb = b[i] if i < len(b) else 0

            # Both ints: numeric compare
            if isinstance(pa, int) and isinstance(pb, int):
                if pa != pb:
                    return 1 if pa > pb else -1
            # Mixed: int > str (release > pre-release)
            elif isinstance(pa, int) and isinstance(pb, str):
                return 1
            elif isinstance(pa, str) and isinstance(pb, int):
                return -1
            # Both str: lexicographic
            else:
                if pa != pb:
                    return 1 if str(pa) > str(pb) else -1
        return 0

    def _version_compare(self, a: str, b: str) -> int:
        """Compare two version strings. Returns -1, 0, or 1."""
        return self._compare_parts(self._parse_version(a), self._parse_version(b))

    # ── Bulk Ingestion Helpers ───────────────────────────────────────────

    def ingest_kev_catalog(self, catalog_data: dict) -> int:
        """Ingest CISA KEV catalog JSON."""
        conn = self._get_conn()
        count = 0
        for vuln in catalog_data.get("vulnerabilities", []):
            cve_id = vuln.get("cveID", "")
            if not cve_id:
                continue
            conn.execute(
                """INSERT OR REPLACE INTO kev
                   (cve_id, vendor, product, vulnerability_name, date_added,
                    due_date, known_ransomware)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (
                    cve_id,
                    vuln.get("vendorProject", ""),
                    vuln.get("product", ""),
                    vuln.get("vulnerabilityName", ""),
                    vuln.get("dateAdded", ""),
                    vuln.get("dueDate", ""),
                    vuln.get("knownRansomwareCampaignUse", "Unknown"),
                ),
            )
            count += 1
        conn.commit()
        log.info("Ingested %d CISA KEV entries", count)
        return count

    def ingest_epss_csv(self, csv_lines: list[str]) -> int:
        """Ingest EPSS CSV data (skip header, format: cve,epss,percentile)."""
        conn = self._get_conn()
        count = 0
        today = time.strftime("%Y-%m-%d")
        for line in csv_lines:
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("cve"):
                continue
            parts = line.split(",")
            if len(parts) < 3:
                continue
            cve_id = parts[0].strip()
            try:
                score = float(parts[1])
                percentile = float(parts[2])
            except ValueError:
                continue
            conn.execute(
                """INSERT OR REPLACE INTO epss (cve_id, score, percentile, date)
                   VALUES (?, ?, ?, ?)""",
                (cve_id, score, percentile, today),
            )
            count += 1
        conn.commit()
        log.info("Ingested %d EPSS scores", count)
        return count

    def is_kev(self, cve_id: str) -> bool:
        """Check if a CVE is in the CISA KEV catalog."""
        conn = self._get_conn()
        return conn.execute(
            "SELECT 1 FROM kev WHERE cve_id = ?", (cve_id,)
        ).fetchone() is not None

    def get_epss(self, cve_id: str) -> tuple[float, float]:
        """Get EPSS score and percentile for a CVE. Returns (0.0, 0.0) if not found."""
        conn = self._get_conn()
        row = conn.execute(
            "SELECT score, percentile FROM epss WHERE cve_id = ?", (cve_id,)
        ).fetchone()
        return (row["score"], row["percentile"]) if row else (0.0, 0.0)

    def search(self, query: str, limit: int = 50) -> list[CVEMatch]:
        """Full-text search across CVE IDs and descriptions."""
        conn = self._get_conn()
        rows = conn.execute(
            """SELECT cve_id, description, cvss31_score, cvss31_vector,
                      cvss40_score, cvss40_vector, severity, published,
                      modified, references_json, weaknesses_json
               FROM cves
               WHERE cve_id LIKE ? OR description LIKE ?
               ORDER BY cvss31_score DESC
               LIMIT ?""",
            (f"%{query}%", f"%{query}%", limit),
        ).fetchall()

        results = []
        for row in rows:
            refs = json.loads(row["references_json"]) if row["references_json"] else []
            weaknesses = json.loads(row["weaknesses_json"]) if row["weaknesses_json"] else []
            results.append(CVEMatch(
                cve_id=row["cve_id"],
                description=row["description"] or "",
                cvss31_score=row["cvss31_score"] or 0.0,
                cvss31_vector=row["cvss31_vector"] or "",
                severity=row["severity"] or "MEDIUM",
                published=row["published"] or "",
                references=refs,
                weaknesses=weaknesses,
            ))
        return results


# ── CLI Interface ────────────────────────────────────────────────────────

async def update_cve_db(
    api_key: str | None = None,
    db_path: str | None = None,
    years: list[int] | None = None,
) -> dict[str, Any]:
    """CLI-callable function to update the CVE database."""
    _deny_unmigrated_cve_update()
    import aiohttp

    db = CVEDatabase(db_path)

    results: dict[str, Any] = {}

    # 1. Update NVD CVEs
    log.info("Updating NVD CVE data...")
    nvd_result = await db.update(api_key=api_key, years=years)
    results["nvd"] = nvd_result

    # 2. Update CISA KEV
    log.info("Updating CISA KEV catalog...")
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(KEV_URL, timeout=aiohttp.ClientTimeout(total=30)) as resp:
                if resp.status == 200:
                    kev_data = await resp.json()
                    kev_count = db.ingest_kev_catalog(kev_data)
                    results["kev"] = kev_count
    except Exception as exc:
        log.error("KEV update failed: %s", exc)
        results["kev_error"] = str(exc)

    # 3. Update EPSS scores
    log.info("Updating EPSS scores...")
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(EPSS_URL, timeout=aiohttp.ClientTimeout(total=60)) as resp:
                if resp.status == 200:
                    raw = await resp.read()
                    decompressed = gzip.decompress(raw).decode("utf-8", errors="ignore")
                    lines = decompressed.strip().split("\n")
                    epss_count = db.ingest_epss_csv(lines)
                    results["epss"] = epss_count
    except Exception as exc:
        log.error("EPSS update failed: %s", exc)
        results["epss_error"] = str(exc)

    # Final stats
    results["stats"] = db.stats()
    db.close()
    return results


# ── Tests ────────────────────────────────────────────────────────────────

class TestCVEDatabase:
    """Unit tests for the CVE database."""

    def test_version_parsing(self) -> None:
        parts = CVEDatabase._parse_version("2.4.49")
        assert parts == [2, 4, 49]

    def test_version_compare(self) -> None:
        db = CVEDatabase.__new__(CVEDatabase)
        assert db._version_compare("2.4.49", "2.4.50") == -1
        assert db._version_compare("2.4.50", "2.4.49") == 1
        assert db._version_compare("2.4.49", "2.4.49") == 0
        assert db._version_compare("8.0", "7.9") == 1
        assert db._version_compare("1.0.0", "1.0") == 0

    def test_version_range(self) -> None:
        db = CVEDatabase.__new__(CVEDatabase)
        # In range: 2.0 <= 2.4.49 < 2.15.0
        assert db._version_matches(
            "2.4.49", start="2.0", start_type="including",
            end="2.15.0", end_type="excluding",
        ) is True
        # Out of range: 2.15.0 not < 2.15.0
        assert db._version_matches(
            "2.15.0", start="2.0", start_type="including",
            end="2.15.0", end_type="excluding",
        ) is False
        # Exact match
        assert db._version_matches("2.4.49", exact="2.4.49") is True
        assert db._version_matches("2.4.50", exact="2.4.49") is False

    def test_schema_creation(self, tmp_path) -> None:
        db = CVEDatabase(tmp_path / "test_cve.db")
        stats = db.stats()
        assert stats["cve_count"] == 0
        db.close()
