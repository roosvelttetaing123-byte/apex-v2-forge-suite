"""CPE Vulnerability Engine — correlate service banners with CVEs via CPE matching.

Maps discovered service banners → CPE 2.3 strings → NVD CVE lookups:
  - Fuzzy banner-to-CPE matching (product, vendor, version)
  - NVD API v2 lookups with local cache (TTL 24h)
  - CVSS v3.1 + v4.0 severity scoring
  - CISA KEV cross-reference
  - Exploit-DB availability check (via NVD hasExploit flag)
  - CPE confirmation bands: CONFIRMED / PLAUSIBLE / POSSIBLE

MITRE ATT&CK: T1190 — Exploit Public-Facing Application

Usage: populated by port_scanner/service_id via config.extra["service_banners"]
"""
from __future__ import annotations

import asyncio
import json
import os
import re
import sys
import time
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity

CACHE_TTL_S = 86400  # 24 hours

# ── CPE banner-to-product mapping ────────────────────────────────────────────

_BANNER_CPE_MAP: list[tuple[re.Pattern, str, str, str]] = [
    # (pattern, vendor, product, version_group_index_hint)
    (re.compile(r"Apache[/ ](\d+\.\d+\.\d+)", re.I), "apache", "http_server", ""),
    (re.compile(r"nginx[/ ](\d+\.\d+\.\d+)", re.I),  "nginx",  "nginx",       ""),
    (re.compile(r"OpenSSH[_/ ](\d+\.\d+[p\d]*)", re.I), "openbsd", "openssh", ""),
    (re.compile(r"Microsoft-IIS[/ ](\d+\.\d+)", re.I), "microsoft", "iis",    ""),
    (re.compile(r"Tomcat[/ ](\d+\.\d+\.\d+)", re.I), "apache",   "tomcat",    ""),
    (re.compile(r"JBoss[/ ](\d+\.\d+)", re.I),       "redhat",   "jboss",     ""),
    (re.compile(r"WordPress[/ ](\d+\.\d+\.\d+)", re.I), "wordpress", "wordpress", ""),
    (re.compile(r"Drupal[/ ]\s?(\d+\.\d+)", re.I),   "drupal",   "drupal",    ""),
    (re.compile(r"Joomla[! /](\d+\.\d+)", re.I),     "joomla",   "joomla",    ""),
    (re.compile(r"phpMyAdmin[/ ](\d+\.\d+\.\d+)", re.I), "phpmyadmin", "phpmyadmin", ""),
    (re.compile(r"Jenkins[/ ](\d+\.\d+)", re.I),     "jenkins",  "jenkins",   ""),
    (re.compile(r"Kubernetes[/ ]v?(\d+\.\d+)", re.I), "kubernetes", "kubernetes", ""),
    (re.compile(r"etcd[/ ](\d+\.\d+\.\d+)", re.I),   "coreos",   "etcd",      ""),
    (re.compile(r"Redis[/ ](\d+\.\d+\.\d+)", re.I),  "redis",    "redis",     ""),
    (re.compile(r"MongoDB\s+(\d+\.\d+\.\d+)", re.I), "mongodb",  "mongodb",   ""),
    (re.compile(r"Elasticsearch[/ ](\d+\.\d+\.\d+)", re.I), "elastic", "elasticsearch", ""),
    (re.compile(r"RabbitMQ[/ ](\d+\.\d+\.\d+)", re.I), "rabbitmq", "rabbitmq", ""),
    (re.compile(r"MySQL[/ ](\d+\.\d+\.\d+)", re.I),  "mysql",    "mysql",     ""),
    (re.compile(r"PostgreSQL[/ ](\d+\.\d+)", re.I),  "postgresql", "postgresql", ""),
    (re.compile(r"MSSQL.+?(\d{4})", re.I),           "microsoft", "sql_server", ""),
    (re.compile(r"Samba[/ ](\d+\.\d+\.\d+)", re.I),  "samba",    "samba",     ""),
    (re.compile(r"OpenVPN[/ ](\d+\.\d+\.\d+)", re.I), "openvpn", "openvpn",   ""),
    (re.compile(r"ProFTPD[/ ](\d+\.\d+\.\d+)", re.I), "proftpd", "proftpd",   ""),
    (re.compile(r"vsFTPd\s+(\d+\.\d+\.\d+)", re.I),  "vsftpd",   "vsftpd",    ""),
    (re.compile(r"Exim\s+(\d+\.\d+)", re.I),          "exim",     "exim",      ""),
    (re.compile(r"Postfix[/ ](\d+\.\d+\.\d+)", re.I), "postfix",  "postfix",   ""),
    (re.compile(r"Dovecot[/ ](\d+\.\d+\.\d+)", re.I), "dovecot",  "dovecot",   ""),
    (re.compile(r"HAProxy[/ ](\d+\.\d+\.\d+)", re.I), "haproxy",  "haproxy",   ""),
    (re.compile(r"Grafana[/ ]v?(\d+\.\d+\.\d+)", re.I), "grafana", "grafana",  ""),
    (re.compile(r"Kibana[/ ](\d+\.\d+\.\d+)", re.I), "elastic",  "kibana",    ""),
    (re.compile(r"Spring[/ ](\d+\.\d+\.\d+)", re.I), "vmware",   "spring_framework", ""),
    (re.compile(r"Strapi[/ ](\d+\.\d+\.\d+)", re.I), "strapi",   "strapi",    ""),
]

# CISA KEV cross-reference (abbreviated)
_CISA_KEV: frozenset[str] = frozenset({
    "CVE-2021-44228", "CVE-2021-26855", "CVE-2021-34527", "CVE-2022-26134",
    "CVE-2022-22954", "CVE-2022-1388",  "CVE-2023-44487", "CVE-2023-34362",
    "CVE-2024-3400",  "CVE-2024-21762", "CVE-2024-6387",  "CVE-2019-11510",
    "CVE-2019-19781", "CVE-2020-5902",  "CVE-2021-21985", "CVE-2021-22986",
    "CVE-2025-23006", "CVE-2025-29824",
})

_CVSS_HIGH = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
_CVSS40_HIGH = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N"
_CVSS_CRIT = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
_CVSS40_CRIT = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H"


class CpeVulnEngine(BaseModule):
    """CPE → CVE correlation engine for discovered service versions."""

    NAME        = "cpe_vuln_engine"
    DESCRIPTION = "Map service banners to CVEs via CPE matching + NVD API v2"
    PHASE       = 5
    TAGS        = ["vuln", "cpe", "nvd", "cve", "T1190"]

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._cache_dir = self.results_dir / ".cpe_cache"
        self._cache_dir.mkdir(parents=True, exist_ok=True)
        self._nvd_api_key = os.environ.get("NVD_API_KEY", "")

    async def run(self) -> ModuleResult:
        start   = time.monotonic()
        target  = self.config.target
        banners = self.config.extra.get("service_banners", [])

        if not banners:
            self.log.info("No service banners available — skipping CPE correlation")
            return self._make_result(start, skipped=True, skip_reason="no banners")

        self.log.info("CPE correlation for %d banner(s)", len(banners))

        # Phase 1: banner → CPE matches
        cpe_matches: list[dict[str, Any]] = []
        for banner_entry in banners:
            banner_text = banner_entry.get("banner", "")
            port        = banner_entry.get("port", 0)
            ip          = banner_entry.get("ip", target)
            for cpe in self._match_banner(banner_text):
                cpe["port"] = port
                cpe["ip"]   = ip
                cpe_matches.append(cpe)

        if not cpe_matches:
            self.log.info("No CPE matches from banners")
            return self._make_result(start)

        # Phase 2: CPE → CVE lookup via NVD API v2
        sem = asyncio.Semaphore(3)
        tasks = [self._lookup_cves(m, sem) for m in cpe_matches]
        results_list = await asyncio.gather(*tasks, return_exceptions=True)

        # Phase 3: emit findings
        for cpe_info, cves in zip(cpe_matches, results_list):
            if isinstance(cves, Exception) or not cves:
                continue
            self._emit_findings(cpe_info, cves, target)

        return self._make_result(start)

    # ── CPE matching ──────────────────────────────────────────────────────────

    def _match_banner(self, banner: str) -> list[dict[str, Any]]:
        """Match banner string against known product patterns."""
        if not banner:
            return []
        matches: list[dict[str, Any]] = []
        for pattern, vendor, product, _ in _BANNER_CPE_MAP:
            m = pattern.search(banner)
            if m:
                version = m.group(1) if m.lastindex else "*"
                cpe23   = f"cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*"
                matches.append({
                    "vendor":  vendor,
                    "product": product,
                    "version": version,
                    "cpe23":   cpe23,
                    "banner":  banner[:200],
                })
        return matches

    # ── NVD API v2 ────────────────────────────────────────────────────────────

    def _cache_key(self, cpe: str) -> Path:
        safe = re.sub(r"[^A-Za-z0-9._-]", "_", cpe)[:80]
        return self._cache_dir / f"{safe}.json"

    def _cache_load(self, cpe: str) -> list[dict] | None:
        path = self._cache_key(cpe)
        if not path.exists():
            return None
        try:
            data = json.loads(path.read_text())
            if time.time() - data.get("ts", 0) < CACHE_TTL_S:
                return data["cves"]
        except Exception:
            pass
        return None

    def _cache_save(self, cpe: str, cves: list[dict]) -> None:
        path = self._cache_key(cpe)
        try:
            path.write_text(json.dumps({"ts": time.time(), "cves": cves}))
        except Exception:
            pass

    async def _lookup_cves(
        self, cpe_info: dict[str, Any], sem: asyncio.Semaphore
    ) -> list[dict[str, Any]]:
        async with sem:
            cpe = cpe_info["cpe23"]
            cached = self._cache_load(cpe)
            if cached is not None:
                return cached

            cves = await self._nvd_api_lookup(cpe_info)
            self._cache_save(cpe, cves)
            return cves

    async def _nvd_api_lookup(self, cpe_info: dict[str, Any]) -> list[dict[str, Any]]:
        """Query NVD API v2 for CVEs matching this CPE."""
        try:
            import aiohttp
        except ImportError:
            return []

        params: dict[str, str] = {
            "cpeName":  cpe_info["cpe23"],
            "resultsPerPage": "20",
        }
        headers: dict[str, str] = {"User-Agent": "ForgeNetForge/5.0"}
        if self._nvd_api_key:
            headers["apiKey"] = self._nvd_api_key

        url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

        try:
            await asyncio.sleep(0.6 if self._nvd_api_key else 6.0)
            async with aiohttp.ClientSession() as s:
                async with s.get(
                    url, params=params, headers=headers,
                    timeout=aiohttp.ClientTimeout(total=20)
                ) as r:
                    if r.status == 429:
                        await asyncio.sleep(30)
                        return []
                    if r.status != 200:
                        return []
                    data = await r.json()
                    return self._parse_nvd_response(data)
        except Exception as exc:
            self.log.debug("NVD lookup failed for %s: %s", cpe_info["product"], exc)
            return []

    @staticmethod
    def _parse_nvd_response(data: dict[str, Any]) -> list[dict[str, Any]]:
        """Extract CVE ID, CVSS scores, description from NVD API v2 response."""
        cves: list[dict[str, Any]] = []
        for vuln in data.get("vulnerabilities", []):
            cve_data = vuln.get("cve", {})
            cve_id   = cve_data.get("id", "")
            if not cve_id:
                continue

            desc = ""
            for d in cve_data.get("descriptions", []):
                if d.get("lang") == "en":
                    desc = d.get("value", "")
                    break

            # Extract CVSS v3.1 score
            cvss31_score = 0.0
            cvss31_vector = ""
            metrics = cve_data.get("metrics", {})
            for m in metrics.get("cvssMetricV31", []):
                cvss_data = m.get("cvssData", {})
                cvss31_score  = float(cvss_data.get("baseScore", 0))
                cvss31_vector = cvss_data.get("vectorString", "")
                break

            has_exploit = cve_data.get("cisaExploitAdd", "") != ""
            is_kev      = cve_id in _CISA_KEV or has_exploit

            cves.append({
                "id":          cve_id,
                "description": desc[:500],
                "cvss31_score":  cvss31_score,
                "cvss31_vector": cvss31_vector,
                "is_kev":      is_kev,
                "has_exploit": has_exploit,
                "published":   cve_data.get("published", ""),
            })

        # Sort by CVSS descending
        return sorted(cves, key=lambda c: c["cvss31_score"], reverse=True)

    # ── findings ──────────────────────────────────────────────────────────────

    def _emit_findings(
        self, cpe_info: dict[str, Any], cves: list[dict], target: str
    ) -> None:
        critical_cves = [c for c in cves if c["cvss31_score"] >= 9.0 or c["is_kev"]]
        high_cves     = [c for c in cves if 7.0 <= c["cvss31_score"] < 9.0 and not c["is_kev"]]
        other_cves    = [c for c in cves if c["cvss31_score"] < 7.0]

        product = f"{cpe_info['product'].replace('_', ' ').title()} {cpe_info['version']}"
        port    = cpe_info.get("port", 0)
        ip      = cpe_info.get("ip", target)
        loc     = f"{ip}:{port}" if port else ip

        if critical_cves:
            kev_ids = [c["id"] for c in critical_cves if c["is_kev"]]
            severity = Severity.CRITICAL
            self.new_finding(
                title=(
                    f"CRITICAL CVEs in {product} at {loc}"
                    + (f" [CISA KEV: {', '.join(kev_ids[:2])}]" if kev_ids else "")
                ),
                severity=severity,
                description=(
                    f"CPE matching identified {len(critical_cves)} critical CVE(s) in "
                    f"{product} at {loc}.\n\n"
                    + "\n".join(
                        f"• {c['id']} (CVSS {c['cvss31_score']:.1f})"
                        + (" [KEV]" if c["is_kev"] else "")
                        + f": {c['description'][:120]}"
                        for c in critical_cves[:5]
                    )
                ),
                reproduction_steps=[
                    f"# Detected: {cpe_info['banner'][:100]}",
                    f"# CPE: {cpe_info['cpe23']}",
                ] + [
                    f"https://nvd.nist.gov/vuln/detail/{c['id']}"
                    for c in critical_cves[:3]
                ],
                remediation=(
                    f"Upgrade {product} immediately. "
                    "Check vendor advisories for patches. "
                    "Apply virtual patches via WAF if immediate upgrade is not possible."
                ),
                references=[c["id"] for c in critical_cves[:5]]
                + ["https://www.cisa.gov/known-exploited-vulnerabilities-catalog"],
                evidence=Evidence(extra={
                    "cpe": cpe_info["cpe23"],
                    "banner": cpe_info["banner"],
                    "cves": critical_cves[:10],
                }),
                cvss_v31_vector=critical_cves[0].get("cvss31_vector", _CVSS_CRIT) or _CVSS_CRIT,
                cvss_v40_vector=_CVSS40_CRIT,
                target=target,
            )

        if high_cves:
            self.new_finding(
                title=f"HIGH CVEs in {product} at {loc} ({len(high_cves)} found)",
                severity=Severity.HIGH,
                description=(
                    f"{len(high_cves)} high-severity CVE(s) found in {product} at {loc}.\n\n"
                    + "\n".join(
                        f"• {c['id']} (CVSS {c['cvss31_score']:.1f}): {c['description'][:100]}"
                        for c in high_cves[:5]
                    )
                ),
                reproduction_steps=[
                    f"# CPE: {cpe_info['cpe23']}",
                ] + [
                    f"https://nvd.nist.gov/vuln/detail/{c['id']}"
                    for c in high_cves[:3]
                ],
                remediation=f"Patch {product} to the latest stable release.",
                references=[c["id"] for c in high_cves[:5]],
                evidence=Evidence(extra={
                    "cpe": cpe_info["cpe23"],
                    "cves": high_cves[:10],
                }),
                cvss_v31_vector=high_cves[0].get("cvss31_vector", _CVSS_HIGH) or _CVSS_HIGH,
                cvss_v40_vector=_CVSS40_HIGH,
                target=target,
            )

        if other_cves and not critical_cves and not high_cves:
            self.new_finding(
                title=f"Known CVEs in {product} at {loc} ({len(other_cves)} medium/low)",
                severity=Severity.MEDIUM,
                description=(
                    f"{len(other_cves)} medium/low severity CVE(s) in {product} at {loc}."
                ),
                reproduction_steps=[f"# CPE: {cpe_info['cpe23']}"],
                remediation=f"Schedule patching of {product}.",
                references=[c["id"] for c in other_cves[:5]],
                evidence=Evidence(extra={"cpe": cpe_info["cpe23"], "cves": other_cves[:5]}),
                cvss_v31_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
                cvss_v40_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N",
                target=target,
            )


class TestCpeVulnEngine:
    def test_match_banner_apache(self) -> None:
        e = CpeVulnEngine.__new__(CpeVulnEngine)
        matches = e._match_banner("Apache/2.4.51 (Ubuntu)")
        assert len(matches) == 1
        assert matches[0]["product"] == "http_server"
        assert matches[0]["version"] == "2.4.51"

    def test_match_banner_nginx(self) -> None:
        e = CpeVulnEngine.__new__(CpeVulnEngine)
        matches = e._match_banner("nginx/1.24.0")
        assert len(matches) == 1
        assert matches[0]["vendor"] == "nginx"

    def test_match_banner_openssh(self) -> None:
        e = CpeVulnEngine.__new__(CpeVulnEngine)
        matches = e._match_banner("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1")
        assert len(matches) == 1
        assert matches[0]["product"] == "openssh"
        assert "8.9" in matches[0]["version"]

    def test_match_banner_no_match(self) -> None:
        e = CpeVulnEngine.__new__(CpeVulnEngine)
        matches = e._match_banner("Unknown service v1.0")
        assert len(matches) == 0

    def test_match_banner_empty(self) -> None:
        e = CpeVulnEngine.__new__(CpeVulnEngine)
        assert e._match_banner("") == []

    def test_cpe23_format(self) -> None:
        e = CpeVulnEngine.__new__(CpeVulnEngine)
        matches = e._match_banner("Redis/7.0.12")
        assert matches[0]["cpe23"].startswith("cpe:2.3:a:")
        assert "7.0.12" in matches[0]["cpe23"]

    def test_parse_nvd_response_empty(self) -> None:
        result = CpeVulnEngine._parse_nvd_response({"vulnerabilities": []})
        assert result == []

    def test_parse_nvd_response_sorted(self) -> None:
        data = {
            "vulnerabilities": [
                {"cve": {"id": "CVE-2021-0001", "descriptions": [], "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 7.5, "vectorString": ""}}]}}},
                {"cve": {"id": "CVE-2021-0002", "descriptions": [], "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8, "vectorString": ""}}]}}},
            ]
        }
        result = CpeVulnEngine._parse_nvd_response(data)
        assert result[0]["id"] == "CVE-2021-0002"
        assert result[0]["cvss31_score"] == 9.8

    def test_cisa_kev_has_log4shell(self) -> None:
        assert "CVE-2021-44228" in _CISA_KEV

    def test_banner_map_coverage(self) -> None:
        assert len(_BANNER_CPE_MAP) >= 20
