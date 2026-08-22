"""CPE Generator — convert service banners/fingerprints to CPE 2.3 strings.

The magic glue between service discovery and CVE lookup. When nmap/netforge
finds "Apache/2.4.49" on port 80, this module produces:
    cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*

That CPE string hits the CVE database and returns every matching CVE.
Without this, the CVE DB is just a pretty SQLite file collecting dust.

Usage:
    gen = CPEGenerator()
    cpes = gen.from_banner("Apache/2.4.49 (Ubuntu)")
    cpes = gen.from_service("http", "Apache", "2.4.49")
    cpes = gen.from_nmap_service({"name": "http", "product": "Apache httpd", "version": "2.4.49"})
"""
from __future__ import annotations

import re
import logging
from dataclasses import dataclass
from typing import Any

log = logging.getLogger("forge.cpe_gen")


@dataclass
class CPEEntry:
    """A generated CPE 2.3 string with metadata."""
    cpe23: str
    vendor: str
    product: str
    version: str
    confidence: float = 0.8  # 0.0-1.0, how confident we are in this mapping
    source: str = ""         # what generated this (banner, nmap, fingerprint)

    def __str__(self) -> str:
        return self.cpe23


# ── Product Mapping Dictionary ───────────────────────────────────────────
# Maps common service names/products to (vendor, product) CPE tuples.
# This is the heart of the translator — without it, we're guessing.
#
# Format: pattern -> (vendor, product, version_regex_for_banner)
# Pattern matching is case-insensitive.

_PRODUCT_MAP: dict[str, tuple[str, str, str]] = {
    # ── Web Servers ──────────────────────────────────────────────────
    "apache httpd":       ("apache", "http_server", r"(\d+\.\d+\.\d+)"),
    "apache http server": ("apache", "http_server", r"(\d+\.\d+\.\d+)"),
    "apache":             ("apache", "http_server", r"(\d+\.\d+[\.\d]*)"),
    "nginx":              ("f5", "nginx", r"(\d+\.\d+[\.\d]*)"),
    "openresty":          ("openresty", "openresty", r"(\d+\.\d+[\.\d]*)"),
    "iis":                ("microsoft", "internet_information_services", r"(\d+\.\d+)"),
    "microsoft-iis":      ("microsoft", "internet_information_services", r"(\d+\.\d+)"),
    "lighttpd":           ("lighttpd", "lighttpd", r"(\d+\.\d+[\.\d]*)"),
    "caddy":              ("caddyserver", "caddy", r"(\d+\.\d+[\.\d]*)"),
    "tomcat":             ("apache", "tomcat", r"(\d+\.\d+[\.\d]*)"),
    "apache tomcat":      ("apache", "tomcat", r"(\d+\.\d+[\.\d]*)"),
    "jetty":              ("eclipse", "jetty", r"(\d+\.\d+[\.\d]*)"),
    "gunicorn":           ("gunicorn", "gunicorn", r"(\d+\.\d+[\.\d]*)"),
    "uvicorn":            ("encode", "uvicorn", r"(\d+\.\d+[\.\d]*)"),
    "litespeed":          ("litespeedtech", "litespeed_web_server", r"(\d+\.\d+[\.\d]*)"),
    "cherokee":           ("cherokee-project", "cherokee", r"(\d+\.\d+[\.\d]*)"),

    # ── SSH ──────────────────────────────────────────────────────────
    "openssh":            ("openbsd", "openssh", r"(\d+\.\d+[p\d]*)"),
    "dropbear":           ("dropbear_ssh_project", "dropbear_ssh", r"(\d+\.\d+[\.\d]*)"),
    "libssh":             ("libssh", "libssh", r"(\d+\.\d+[\.\d]*)"),

    # ── FTP ──────────────────────────────────────────────────────────
    "proftpd":            ("proftpd", "proftpd", r"(\d+\.\d+[\.\d\w]*)"),
    "vsftpd":             ("vsftpd_project", "vsftpd", r"(\d+\.\d+[\.\d]*)"),
    "pure-ftpd":          ("pureftpd", "pure-ftpd", r"(\d+\.\d+[\.\d]*)"),
    "filezilla server":   ("filezilla-project", "filezilla_server", r"(\d+\.\d+[\.\d]*)"),

    # ── Mail ─────────────────────────────────────────────────────────
    "postfix":            ("postfix", "postfix", r"(\d+\.\d+[\.\d]*)"),
    "exim":               ("exim", "exim", r"(\d+\.\d+[\.\d]*)"),
    "sendmail":           ("sendmail", "sendmail", r"(\d+\.\d+[\.\d]*)"),
    "dovecot":            ("dovecot", "dovecot", r"(\d+\.\d+[\.\d]*)"),
    "courier":            ("courier-mta", "courier", r"(\d+\.\d+[\.\d]*)"),
    "microsoft exchange": ("microsoft", "exchange_server", r"(\d+\.\d+[\.\d]*)"),

    # ── Databases ────────────────────────────────────────────────────
    "mysql":              ("oracle", "mysql", r"(\d+\.\d+[\.\d]*)"),
    "mariadb":            ("mariadb", "mariadb", r"(\d+\.\d+[\.\d]*)"),
    "postgresql":         ("postgresql", "postgresql", r"(\d+\.\d+[\.\d]*)"),
    "postgres":           ("postgresql", "postgresql", r"(\d+\.\d+[\.\d]*)"),
    "microsoft sql server": ("microsoft", "sql_server", r"(\d+\.\d+[\.\d]*)"),
    "mssql":              ("microsoft", "sql_server", r"(\d+\.\d+[\.\d]*)"),
    "mongodb":            ("mongodb", "mongodb", r"(\d+\.\d+[\.\d]*)"),
    "redis":              ("redis", "redis", r"(\d+\.\d+[\.\d]*)"),
    "memcached":          ("memcached", "memcached", r"(\d+\.\d+[\.\d]*)"),
    "elasticsearch":      ("elastic", "elasticsearch", r"(\d+\.\d+[\.\d]*)"),
    "couchdb":            ("apache", "couchdb", r"(\d+\.\d+[\.\d]*)"),
    "cassandra":          ("apache", "cassandra", r"(\d+\.\d+[\.\d]*)"),
    "oracle database":    ("oracle", "database_server", r"(\d+[\.\d]*)"),
    "oracle":             ("oracle", "database_server", r"(\d+[\.\d]*)"),
    "influxdb":           ("influxdata", "influxdb", r"(\d+\.\d+[\.\d]*)"),
    "neo4j":              ("neo4j", "neo4j", r"(\d+\.\d+[\.\d]*)"),

    # ── SMB / Windows ────────────────────────────────────────────────
    "samba":              ("samba", "samba", r"(\d+\.\d+[\.\d]*)"),
    "windows server":     ("microsoft", "windows_server", r"(\d+)"),
    "windows 10":         ("microsoft", "windows_10", r""),
    "windows 11":         ("microsoft", "windows_11", r""),

    # ── DNS ──────────────────────────────────────────────────────────
    "bind":               ("isc", "bind", r"(\d+\.\d+[\.\d\w\-]*)"),
    "isc bind":           ("isc", "bind", r"(\d+\.\d+[\.\d\w\-]*)"),
    "dnsmasq":            ("thekelleys", "dnsmasq", r"(\d+\.\d+[\.\d]*)"),
    "powerdns":           ("powerdns", "authoritative_server", r"(\d+\.\d+[\.\d]*)"),
    "unbound":            ("nlnetlabs", "unbound", r"(\d+\.\d+[\.\d]*)"),
    "microsoft dns":      ("microsoft", "dns_server", r""),

    # ── Proxies / LB ────────────────────────────────────────────────
    "haproxy":            ("haproxy", "haproxy", r"(\d+\.\d+[\.\d]*)"),
    "squid":              ("squid-cache", "squid", r"(\d+\.\d+[\.\d]*)"),
    "varnish":            ("varnish-software", "varnish_cache", r"(\d+\.\d+[\.\d]*)"),
    "traefik":            ("traefik", "traefik", r"(\d+\.\d+[\.\d]*)"),
    "envoy":              ("envoyproxy", "envoy", r"(\d+\.\d+[\.\d]*)"),

    # ── Network Appliances ───────────────────────────────────────────
    "fortios":            ("fortinet", "fortios", r"(\d+\.\d+[\.\d]*)"),
    "fortigate":          ("fortinet", "fortios", r"(\d+\.\d+[\.\d]*)"),
    "panos":              ("paloaltonetworks", "pan-os", r"(\d+\.\d+[\.\d]*)"),
    "palo alto":          ("paloaltonetworks", "pan-os", r"(\d+\.\d+[\.\d]*)"),
    "cisco ios":          ("cisco", "ios", r"(\d+\.\d+[\.\d\w]*)"),
    "cisco ios xe":       ("cisco", "ios_xe", r"(\d+\.\d+[\.\d\w]*)"),
    "cisco asa":          ("cisco", "adaptive_security_appliance_software", r"(\d+\.\d+[\.\d]*)"),
    "junos":              ("juniper", "junos", r"(\d+\.\d+[\.\w\-]*)"),
    "netscaler":          ("citrix", "netscaler_application_delivery_controller", r"(\d+\.\d+[\.\d]*)"),
    "citrix adc":         ("citrix", "netscaler_application_delivery_controller", r"(\d+\.\d+[\.\d]*)"),
    "sonicwall":          ("sonicwall", "sonicos", r"(\d+\.\d+[\.\d]*)"),
    "mikrotik":           ("mikrotik", "routeros", r"(\d+\.\d+[\.\d]*)"),
    "routeros":           ("mikrotik", "routeros", r"(\d+\.\d+[\.\d]*)"),
    "ubiquiti":           ("ui", "unifi_network_application", r"(\d+\.\d+[\.\d]*)"),

    # ── Virtualization ───────────────────────────────────────────────
    "vmware esxi":        ("vmware", "esxi", r"(\d+\.\d+[\.\d]*)"),
    "vmware vcenter":     ("vmware", "vcenter_server", r"(\d+\.\d+[\.\d]*)"),
    "proxmox":            ("proxmox", "virtual_environment", r"(\d+\.\d+[\.\d]*)"),

    # ── CI/CD / DevOps ───────────────────────────────────────────────
    "jenkins":            ("jenkins", "jenkins", r"(\d+\.\d+[\.\d]*)"),
    "gitlab":             ("gitlab", "gitlab", r"(\d+\.\d+[\.\d]*)"),
    "gitea":              ("gitea", "gitea", r"(\d+\.\d+[\.\d]*)"),
    "sonarqube":          ("sonarsource", "sonarqube", r"(\d+\.\d+[\.\d]*)"),
    "nexus":              ("sonatype", "nexus_repository_manager", r"(\d+\.\d+[\.\d]*)"),
    "artifactory":        ("jfrog", "artifactory", r"(\d+\.\d+[\.\d]*)"),
    "teamcity":           ("jetbrains", "teamcity", r"(\d+\.\d+[\.\d]*)"),
    "bamboo":             ("atlassian", "bamboo", r"(\d+\.\d+[\.\d]*)"),
    "harbor":             ("goharbor", "harbor", r"(\d+\.\d+[\.\d]*)"),

    # ── Containers / Orchestration ───────────────────────────────────
    "docker":             ("docker", "docker", r"(\d+\.\d+[\.\d]*)"),
    "kubernetes":         ("kubernetes", "kubernetes", r"(\d+\.\d+[\.\d]*)"),
    "etcd":               ("etcd-io", "etcd", r"(\d+\.\d+[\.\d]*)"),
    "consul":             ("hashicorp", "consul", r"(\d+\.\d+[\.\d]*)"),
    "vault":              ("hashicorp", "vault", r"(\d+\.\d+[\.\d]*)"),
    "nomad":              ("hashicorp", "nomad", r"(\d+\.\d+[\.\d]*)"),

    # ── Message Queues ───────────────────────────────────────────────
    "rabbitmq":           ("pivotal_software", "rabbitmq", r"(\d+\.\d+[\.\d]*)"),
    "kafka":              ("apache", "kafka", r"(\d+\.\d+[\.\d]*)"),
    "activemq":           ("apache", "activemq", r"(\d+\.\d+[\.\d]*)"),
    "nats":               ("nats", "nats_server", r"(\d+\.\d+[\.\d]*)"),
    "mosquitto":          ("eclipse", "mosquitto", r"(\d+\.\d+[\.\d]*)"),

    # ── CMS / Frameworks ────────────────────────────────────────────
    "wordpress":          ("wordpress", "wordpress", r"(\d+\.\d+[\.\d]*)"),
    "drupal":             ("drupal", "drupal", r"(\d+\.\d+[\.\d]*)"),
    "joomla":             ("joomla", "joomla\\!", r"(\d+\.\d+[\.\d]*)"),
    "django":             ("djangoproject", "django", r"(\d+\.\d+[\.\d]*)"),
    "flask":              ("palletsprojects", "flask", r"(\d+\.\d+[\.\d]*)"),
    "spring boot":        ("vmware", "spring_boot", r"(\d+\.\d+[\.\d]*)"),
    "spring framework":   ("vmware", "spring_framework", r"(\d+\.\d+[\.\d]*)"),
    "rails":              ("rubyonrails", "rails", r"(\d+\.\d+[\.\d]*)"),
    "ruby on rails":      ("rubyonrails", "rails", r"(\d+\.\d+[\.\d]*)"),
    "laravel":            ("laravel", "laravel", r"(\d+\.\d+[\.\d]*)"),
    "express":            ("expressjs", "express", r"(\d+\.\d+[\.\d]*)"),
    "next.js":            ("vercel", "next.js", r"(\d+\.\d+[\.\d]*)"),
    "php":                ("php", "php", r"(\d+\.\d+[\.\d]*)"),

    # ── Monitoring ───────────────────────────────────────────────────
    "grafana":            ("grafana", "grafana", r"(\d+\.\d+[\.\d]*)"),
    "prometheus":         ("prometheus", "prometheus", r"(\d+\.\d+[\.\d]*)"),
    "zabbix":             ("zabbix", "zabbix", r"(\d+\.\d+[\.\d]*)"),
    "nagios":             ("nagios", "nagios", r"(\d+\.\d+[\.\d]*)"),
    "kibana":             ("elastic", "kibana", r"(\d+\.\d+[\.\d]*)"),

    # ── VPN ──────────────────────────────────────────────────────────
    "openvpn":            ("openvpn", "openvpn", r"(\d+\.\d+[\.\d]*)"),
    "wireguard":          ("wireguard", "wireguard", r"(\d+\.\d+[\.\d]*)"),
    "strongswan":         ("strongswan", "strongswan", r"(\d+\.\d+[\.\d]*)"),
    "openconnect":        ("infradead", "openconnect", r"(\d+\.\d+[\.\d]*)"),
    "pulse secure":       ("pulsesecure", "pulse_connect_secure", r"(\d+\.\d+[\.\d]*)"),
    "ivanti connect secure": ("ivanti", "connect_secure", r"(\d+\.\d+[\.\d]*)"),

    # ── File Transfer ────────────────────────────────────────────────
    "moveit":             ("progress", "moveit_transfer", r"(\d+\.\d+[\.\d]*)"),
    "moveit transfer":    ("progress", "moveit_transfer", r"(\d+\.\d+[\.\d]*)"),
    "goanywhere":         ("fortra", "goanywhere_managed_file_transfer", r"(\d+\.\d+[\.\d]*)"),
    "solarwinds serv-u":  ("solarwinds", "serv-u", r"(\d+\.\d+[\.\d]*)"),

    # ── SNMP ─────────────────────────────────────────────────────────
    "net-snmp":           ("net-snmp", "net-snmp", r"(\d+\.\d+[\.\d]*)"),

    # ── Remote Access ────────────────────────────────────────────────
    "rdp":                ("microsoft", "remote_desktop_protocol", r""),
    "vnc":                ("realvnc", "vnc_server", r"(\d+\.\d+[\.\d]*)"),
    "tightvnc":           ("tightvnc", "tightvnc", r"(\d+\.\d+[\.\d]*)"),
    "xrdp":               ("neutrinolabs", "xrdp", r"(\d+\.\d+[\.\d]*)"),

    # ── Printers ─────────────────────────────────────────────────────
    "cups":               ("apple", "cups", r"(\d+\.\d+[\.\d]*)"),

    # ── NTP ──────────────────────────────────────────────────────────
    "ntpd":               ("ntp", "ntp", r"(\d+\.\d+[\.\d\w]*)"),
    "chrony":             ("tuxfamily", "chrony", r"(\d+\.\d+[\.\d]*)"),

    # ── SSL/TLS ──────────────────────────────────────────────────────
    "openssl":            ("openssl", "openssl", r"(\d+\.\d+[\.\d\w]*)"),

    # ── Java / Runtime ───────────────────────────────────────────────
    "java":               ("oracle", "jdk", r"(\d+[\.\d_]*)"),
    "openjdk":            ("oracle", "openjdk", r"(\d+[\.\d_]*)"),
    "log4j":              ("apache", "log4j", r"(\d+\.\d+[\.\d]*)"),

    # ── IPMI ─────────────────────────────────────────────────────────
    "ipmi":               ("intel", "ipmi", r"(\d+\.\d+)"),
}

# Sorted by key length descending for longest-match-first
_SORTED_PRODUCT_KEYS = sorted(_PRODUCT_MAP.keys(), key=len, reverse=True)


class CPEGenerator:
    """Generate CPE 2.3 strings from service fingerprints.

    Translates the messy real-world output of service detection
    (nmap banners, HTTP headers, etc.) into standardized CPE strings
    that can query our CVE database.
    """

    def from_banner(self, banner: str) -> list[CPEEntry]:
        """Extract CPE entries from a raw service banner string.

        Tries longest-match-first against the product dictionary.
        Can return multiple CPEs if the banner contains multiple products.

        Examples:
            "Apache/2.4.49 (Ubuntu) OpenSSL/1.1.1l"
            -> [cpe:2.3:a:apache:http_server:2.4.49:..., cpe:2.3:a:openssl:openssl:1.1.1l:...]
        """
        if not banner:
            return []

        results: list[CPEEntry] = []
        banner_lower = banner.lower()

        for key in _SORTED_PRODUCT_KEYS:
            if key in banner_lower:
                vendor, product, ver_regex = _PRODUCT_MAP[key]
                version = ""

                if ver_regex:
                    # Search for version near the product name
                    # First try: product/version or product version pattern
                    idx = banner_lower.index(key)
                    search_region = banner[idx:idx + len(key) + 40]
                    m = re.search(ver_regex, search_region)
                    if m:
                        version = m.group(1)
                    else:
                        # Broader search in full banner
                        m = re.search(ver_regex, banner)
                        if m:
                            version = m.group(1)

                cpe = self._build_cpe(vendor, product, version)
                entry = CPEEntry(
                    cpe23=cpe, vendor=vendor, product=product,
                    version=version, confidence=0.7 if version else 0.4,
                    source="banner",
                )
                if entry.cpe23 not in {e.cpe23 for e in results}:
                    results.append(entry)

        return results

    def from_service(
        self, service_name: str, product: str = "", version: str = ""
    ) -> list[CPEEntry]:
        """Generate CPE from structured service info (e.g., from nmap -sV).

        Args:
            service_name: Service type (http, ssh, ftp, etc.)
            product: Product name (Apache httpd, OpenSSH, etc.)
            version: Version string
        """
        results: list[CPEEntry] = []

        # Try product name first (more specific)
        if product:
            product_lower = product.lower()
            for key in _SORTED_PRODUCT_KEYS:
                if key in product_lower:
                    vendor, prod, ver_regex = _PRODUCT_MAP[key]
                    ver = version
                    if not ver and ver_regex:
                        m = re.search(ver_regex, product)
                        if m:
                            ver = m.group(1)

                    cpe = self._build_cpe(vendor, prod, ver)
                    results.append(CPEEntry(
                        cpe23=cpe, vendor=vendor, product=prod,
                        version=ver, confidence=0.85 if ver else 0.5,
                        source="service",
                    ))
                    break

        # Fallback: try service name
        if not results and service_name:
            svc_lower = service_name.lower()
            for key in _SORTED_PRODUCT_KEYS:
                if key == svc_lower or svc_lower.startswith(key):
                    vendor, prod, _ = _PRODUCT_MAP[key]
                    cpe = self._build_cpe(vendor, prod, version)
                    results.append(CPEEntry(
                        cpe23=cpe, vendor=vendor, product=prod,
                        version=version, confidence=0.6 if version else 0.3,
                        source="service_name",
                    ))
                    break

        return results

    def from_nmap_service(self, svc: dict[str, Any]) -> list[CPEEntry]:
        """Generate CPE from an nmap service dict.

        Expected dict keys: name, product, version, extrainfo, cpe (if nmap provides one)
        """
        results: list[CPEEntry] = []

        # If nmap already provides a CPE, use it (highest confidence)
        nmap_cpe = svc.get("cpe", "")
        if nmap_cpe:
            parts = nmap_cpe.split(":")
            vendor = parts[3] if len(parts) > 3 else ""
            product = parts[4] if len(parts) > 4 else ""
            version = parts[5] if len(parts) > 5 and parts[5] != "*" else svc.get("version", "")
            results.append(CPEEntry(
                cpe23=self._normalize_cpe(nmap_cpe, version),
                vendor=vendor, product=product, version=version,
                confidence=0.95, source="nmap_cpe",
            ))

        # Also try our own mapping (may catch things nmap misses)
        product = svc.get("product", "")
        version = svc.get("version", "")
        service = svc.get("name", "")
        extra = svc.get("extrainfo", "")

        our_cpes = self.from_service(service, product, version)
        for entry in our_cpes:
            if entry.cpe23 not in {e.cpe23 for e in results}:
                results.append(entry)

        # Try banner/extrainfo too
        banner = f"{product} {version} {extra}".strip()
        if banner:
            banner_cpes = self.from_banner(banner)
            for entry in banner_cpes:
                if entry.cpe23 not in {e.cpe23 for e in results}:
                    entry.confidence *= 0.8  # slightly lower for banner extraction
                    results.append(entry)

        return results

    def from_http_headers(self, headers: dict[str, str]) -> list[CPEEntry]:
        """Extract CPEs from HTTP response headers.

        Checks Server, X-Powered-By, X-AspNet-Version, etc.
        """
        results: list[CPEEntry] = []

        server = headers.get("Server", headers.get("server", ""))
        if server:
            results.extend(self.from_banner(server))

        powered_by = headers.get("X-Powered-By", headers.get("x-powered-by", ""))
        if powered_by:
            results.extend(self.from_banner(powered_by))

        aspnet = headers.get("X-AspNet-Version", headers.get("x-aspnet-version", ""))
        if aspnet:
            cpe = self._build_cpe("microsoft", "asp.net", aspnet)
            results.append(CPEEntry(
                cpe23=cpe, vendor="microsoft", product="asp.net",
                version=aspnet, confidence=0.9, source="http_header",
            ))

        aspnetcore = headers.get("X-AspNetCore-Version", "")
        if aspnetcore:
            cpe = self._build_cpe("microsoft", "asp.net_core", aspnetcore)
            results.append(CPEEntry(
                cpe23=cpe, vendor="microsoft", product="asp.net_core",
                version=aspnetcore, confidence=0.9, source="http_header",
            ))

        # Dedup
        seen = set()
        deduped = []
        for entry in results:
            if entry.cpe23 not in seen:
                seen.add(entry.cpe23)
                deduped.append(entry)
        return deduped

    @staticmethod
    def _build_cpe(vendor: str, product: str, version: str = "") -> str:
        """Build a CPE 2.3 URI string."""
        v = version if version else "*"
        # CPE 2.3 format: cpe:2.3:part:vendor:product:version:update:edition:language:sw_edition:target_sw:target_hw:other
        return f"cpe:2.3:a:{vendor}:{product}:{v}:*:*:*:*:*:*:*"

    @staticmethod
    def _normalize_cpe(cpe: str, version: str = "") -> str:
        """Normalize a CPE string, optionally injecting version."""
        if not cpe.startswith("cpe:2.3:"):
            # Convert CPE 2.2 to 2.3
            cpe = cpe.replace("cpe:/", "cpe:2.3:")

        parts = cpe.split(":")
        # Pad to 13 fields
        while len(parts) < 13:
            parts.append("*")

        # Inject version if provided and current is wildcard
        if version and len(parts) > 5 and parts[5] == "*":
            parts[5] = version

        return ":".join(parts)

    @staticmethod
    def product_count() -> int:
        """Return the number of products in the mapping dictionary."""
        return len(_PRODUCT_MAP)


# ── Tests ────────────────────────────────────────────────────────────────

class TestCPEGenerator:
    def test_apache_banner(self) -> None:
        gen = CPEGenerator()
        cpes = gen.from_banner("Apache/2.4.49 (Ubuntu)")
        assert len(cpes) >= 1
        assert any("apache:http_server:2.4.49" in c.cpe23 for c in cpes)

    def test_nginx_banner(self) -> None:
        gen = CPEGenerator()
        cpes = gen.from_banner("nginx/1.18.0")
        assert len(cpes) >= 1
        assert any("nginx:1.18.0" in c.cpe23 for c in cpes)

    def test_openssh_banner(self) -> None:
        gen = CPEGenerator()
        cpes = gen.from_banner("OpenSSH_8.2p1 Ubuntu-4ubuntu0.5")
        assert len(cpes) >= 1
        assert any("openssh" in c.cpe23 for c in cpes)

    def test_multi_product_banner(self) -> None:
        gen = CPEGenerator()
        cpes = gen.from_banner("Apache/2.4.49 OpenSSL/1.1.1l")
        assert len(cpes) >= 2

    def test_from_service(self) -> None:
        gen = CPEGenerator()
        cpes = gen.from_service("ssh", "OpenSSH", "8.2p1")
        assert len(cpes) >= 1
        assert any("openssh" in c.cpe23 for c in cpes)

    def test_from_nmap_service(self) -> None:
        gen = CPEGenerator()
        cpes = gen.from_nmap_service({
            "name": "http",
            "product": "Apache httpd",
            "version": "2.4.49",
        })
        assert len(cpes) >= 1

    def test_product_count(self) -> None:
        assert CPEGenerator.product_count() > 100

    def test_http_headers(self) -> None:
        gen = CPEGenerator()
        cpes = gen.from_http_headers({"Server": "nginx/1.20.1", "X-Powered-By": "PHP/8.1.2"})
        assert len(cpes) >= 2
