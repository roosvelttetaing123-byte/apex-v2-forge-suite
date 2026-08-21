"""DNS Enum module — comprehensive DNS enumeration for AD infrastructure.

Covers:
- Standard record types (A, AAAA, MX, NS, TXT, SOA, SRV, CNAME)
- AD-specific SRV records (_ldap._tcp, _kerberos._tcp, _gc._tcp, ...)
- Zone transfer (AXFR) attempt against all discovered nameservers
- Subdomain brute-force with 80+ common names
- Wildcard DNS detection
- DNSSEC presence check
- RFC-1918 (internal) IP exposure detection

MITRE ATT&CK: T1018 (Remote System Discovery), T1590.002 (DNS)
"""
from __future__ import annotations

import subprocess
import sys
import time
import unittest
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity

# ---------------------------------------------------------------------------
# CVSS vectors
# ---------------------------------------------------------------------------
CVSS_ZONE_XFER_V31  = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
CVSS_ZONE_XFER_V40  = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N"
CVSS_INTERNAL_V31   = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
CVSS_INTERNAL_V40   = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N"
CVSS_WILDCARD_V31   = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"
CVSS_WILDCARD_V40   = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N"

# ---------------------------------------------------------------------------
# AD-specific SRV records
# ---------------------------------------------------------------------------
_AD_SRV_NAMES = [
    "_ldap._tcp",
    "_ldap._tcp.dc._msdcs",
    "_ldap._tcp.pdc._msdcs",
    "_ldap._tcp.gc._msdcs",
    "_kerberos._tcp",
    "_kerberos._udp",
    "_kerberos._tcp.dc._msdcs",
    "_kpasswd._tcp",
    "_kpasswd._udp",
    "_gc._tcp",
    "_gc._tcp.{domain}",
    "_ldap._tcp.{domain}",
    "_kerberos._tcp.{domain}",
    "_msrpc._tcp",
    "_certificates._tcp",
    "_adfs._tcp",
]

# Common subdomain wordlist for brute-force
_SUBDOMAINS = [
    "dc", "dc1", "dc2", "dc3", "dc01", "dc02", "dc03",
    "ad", "ads", "active-directory", "adfs", "sts", "sso", "mfa", "idp",
    "ldap", "kerberos", "krb", "pdc", "bdc",
    "mail", "smtp", "exchange", "ews", "autodiscover", "owa",
    "sharepoint", "sp", "spsite",
    "sccm", "sms", "wsus", "wds",
    "mgmt", "management", "scom", "mom", "opsmgr",
    "backup", "backups", "veeam", "commvault",
    "vpn", "vpn1", "vpn2", "remote", "sslvpn", "pulse",
    "citrix", "xenapp", "receiver", "rdg", "rdweb", "rds",
    "fs", "dfs", "file", "fileserver", "nas", "storage",
    "print", "printer",
    "proxy", "squid", "zscaler",
    "monitor", "monitoring", "zabbix", "nagios", "prometheus", "grafana",
    "splunk", "siem", "logstash", "elastic",
    "jenkins", "gitlab", "github", "gitea", "ci", "cd", "build",
    "dev", "devops", "staging", "test", "uat", "qa", "prod",
    "api", "api1", "api2", "app", "web", "www", "intranet", "portal",
    "jira", "confluence", "wiki", "docs",
    "helpdesk", "servicedesk", "itsm",
    "db", "sql", "mssql", "mysql", "oracle", "postgres", "mongodb",
    "ntp", "time", "dns", "ns", "ns1", "ns2",
    "gw", "gateway", "router", "fw", "firewall",
    "ansible", "puppet", "chef", "salt",
    "vault", "secrets", "pki", "ca", "ocsp",
]

# RFC-1918 prefixes for internal IP detection
_RFC1918_PREFIXES = ("10.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.",
                     "172.21.", "172.22.", "172.23.", "172.24.", "172.25.", "172.26.",
                     "172.27.", "172.28.", "172.29.", "172.30.", "172.31.", "192.168.")


class DnsEnum(BaseModule):
    """Comprehensive DNS enumeration for Active Directory environments."""

    NAME        = "dns_enum"
    DESCRIPTION = "DNS zone enumeration, zone transfer, subdomain brute-force, and AD SRV discovery"
    PHASE       = 1
    TAGS        = ["unauth", "dns", "recon", "cwe-200"]

    async def run(self) -> ModuleResult:
        start  = time.monotonic()
        target = self.config.target
        domain = self.config.extra.get("domain", "")

        if not self.check_scope(target):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        if not domain:
            # Fall back to treating the target as the domain if it looks like one
            if "." in target and not target[0].isdigit():
                domain = target
            else:
                self.log.info("dns_enum: no domain configured, skipping")
                return self._make_result(start, skipped=True, skip_reason="no domain provided")

        try:
            import dns.resolver  # noqa: F401
        except ImportError:
            self.log.warning("dnspython is not installed — skipping dns_enum module")
            return self._make_result(start, skipped=True, skip_reason="dnspython missing")

        records       = self._enum_standard_records(domain, target)
        nameservers   = records.get("NS", [])
        # Extract plain NS hostnames for zone transfer
        ns_hosts      = [ns.rstrip(".") for ns in nameservers]

        zone_data     = self._zone_transfer_attempt(domain, ns_hosts or [target])
        subdomains    = self._bruteforce_subdomains(domain, target)
        wildcard      = self._check_wildcard_dns(domain, target)
        dnssec        = self._detect_dnssec(domain, target)
        internal_ips  = self._find_internal_ips(records, subdomains)

        self._emit_findings(target, domain, records, zone_data, subdomains,
                            internal_ips, wildcard, dnssec)
        return self._make_result(start)

    # ------------------------------------------------------------------
    # Record enumeration
    # ------------------------------------------------------------------

    def _query_record(self, host: str, rtype: str, nameserver: str | None = None) -> list[str]:
        """Query *rtype* for *host*, fallback to dig subprocess."""
        try:
            import dns.resolver
            resolver = dns.resolver.Resolver()
            resolver.timeout  = 3
            resolver.lifetime = 5
            if nameserver:
                resolver.nameservers = [nameserver]
            answers = resolver.resolve(host, rtype)
            return [rdata.to_text() for rdata in answers]
        except Exception:
            pass
        # Fallback: dig
        try:
            result = subprocess.run(
                ["dig", "+short", rtype, host],
                capture_output=True, text=True, timeout=5,
            )
            lines = [ln.strip() for ln in result.stdout.splitlines() if ln.strip()]
            return lines
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            return []

    def _enum_standard_records(self, domain: str, nameserver: str | None = None) -> dict[str, list[str]]:
        """Enumerate standard DNS records and AD SRV names."""
        records: dict[str, list[str]] = {}

        for rtype in ("A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME"):
            results = self._query_record(domain, rtype, nameserver)
            if results:
                records[rtype] = results

        # AD-specific SRV records
        srv_results: list[str] = []
        for name_tmpl in _AD_SRV_NAMES:
            srv_name = name_tmpl.replace("{domain}", domain)
            full     = f"{srv_name}.{domain}" if not srv_name.endswith(domain) else srv_name
            results  = self._query_record(full, "SRV", nameserver)
            for r in results:
                srv_results.append(f"{full}: {r}")
        if srv_results:
            records["SRV"] = srv_results

        return records

    # ------------------------------------------------------------------
    # Zone transfer
    # ------------------------------------------------------------------

    def _zone_transfer_attempt(self, domain: str, nameservers: list[str]) -> list[str]:
        """Attempt AXFR against each nameserver; return records on success."""
        for ns in nameservers:
            transferred = self._axfr_dnspython(domain, ns)
            if transferred:
                self.log.warning("Zone transfer succeeded from %s for %s!", ns, domain)
                return transferred
            transferred = self._axfr_dig(domain, ns)
            if transferred:
                self.log.warning("Zone transfer succeeded (dig) from %s for %s!", ns, domain)
                return transferred
        return []

    def _axfr_dnspython(self, domain: str, ns: str) -> list[str]:
        try:
            import dns.zone
            import dns.query
            import dns.exception
            z = dns.zone.from_xfr(dns.query.xfr(ns, domain, timeout=8))
            records = []
            for name in z.nodes.keys():
                records.append(f"{name.to_text()} {z[name].to_text(name)}")
            return records
        except Exception:
            return []

    def _axfr_dig(self, domain: str, ns: str) -> list[str]:
        try:
            result = subprocess.run(
                ["dig", f"@{ns}", domain, "AXFR"],
                capture_output=True, text=True, timeout=10,
            )
            lines = [
                ln.strip()
                for ln in result.stdout.splitlines()
                if ln.strip() and not ln.startswith(";")
            ]
            # A successful zone transfer returns multiple resource records
            return lines if len(lines) > 5 else []
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            return []

    # ------------------------------------------------------------------
    # Subdomain brute-force
    # ------------------------------------------------------------------

    def _bruteforce_subdomains(self, domain: str, nameserver: str | None = None) -> list[str]:
        """Try all entries in _SUBDOMAINS; return those that resolve."""
        found: list[str] = []
        for sub in _SUBDOMAINS:
            fqdn = f"{sub}.{domain}"
            try:
                import dns.resolver
                resolver = dns.resolver.Resolver()
                resolver.timeout  = 1
                resolver.lifetime = 2
                if nameserver:
                    try:
                        resolver.nameservers = [nameserver]
                    except Exception:
                        pass
                answers = resolver.resolve(fqdn, "A")
                ips = [r.to_text() for r in answers]
                for ip in ips:
                    found.append(f"{fqdn} -> {ip}")
            except Exception:
                pass
        return found

    # ------------------------------------------------------------------
    # Wildcard / DNSSEC checks
    # ------------------------------------------------------------------

    def _check_wildcard_dns(self, domain: str, nameserver: str | None = None) -> bool:
        """Return True if a random nonexistent subdomain resolves (wildcard DNS)."""
        random_sub = f"forge-nonexistent-{uuid.uuid4().hex[:8]}.{domain}"
        results = self._query_record(random_sub, "A", nameserver)
        return bool(results)

    def _detect_dnssec(self, domain: str, nameserver: str | None = None) -> bool:
        """Return True if DNSKEY records are present (DNSSEC is configured)."""
        results = self._query_record(domain, "DNSKEY", nameserver)
        return bool(results)

    # ------------------------------------------------------------------
    # Internal IP extraction
    # ------------------------------------------------------------------

    def _find_internal_ips(self, records: dict[str, list[str]], subdomains: list[str]) -> list[str]:
        """Extract RFC-1918 addresses from all discovered records."""
        internal: list[str] = []
        all_text: list[str] = []
        for values in records.values():
            all_text.extend(values)
        all_text.extend(subdomains)

        for line in all_text:
            for token in line.split():
                if any(token.startswith(prefix) for prefix in _RFC1918_PREFIXES):
                    if token not in internal:
                        internal.append(token)
        return internal

    # ------------------------------------------------------------------
    # Findings emitter
    # ------------------------------------------------------------------

    def _emit_findings(
        self,
        target: str,
        domain: str,
        records: dict[str, list[str]],
        zone_transfer_data: list[str],
        subdomains: list[str],
        internal_ips: list[str],
        wildcard: bool,
        dnssec: bool,
    ) -> None:

        if zone_transfer_data:
            ev = Evidence(
                request_raw=f"dig AXFR @{target} {domain}",
                response_raw="\n".join(zone_transfer_data[:100])
                + ("\n...(truncated)" if len(zone_transfer_data) > 100 else ""),
                extra={"record_count": len(zone_transfer_data)},
            )
            self.new_finding(
                title=f"DNS Zone Transfer (AXFR) Allowed — {domain}",
                severity=Severity.CRITICAL,
                description=(
                    f"The DNS server for {domain} allows unauthorized zone transfers. "
                    f"{len(zone_transfer_data)} record(s) were retrieved, "
                    "revealing the complete internal network topology including "
                    "hostnames, IP addresses, and service locations."
                ),
                reproduction_steps=[
                    f"dig AXFR @{target} {domain}",
                    f"host -l {domain} {target}",
                ],
                remediation=(
                    "Restrict zone transfers to trusted secondary DNS servers only. "
                    "In BIND: add 'allow-transfer { <secondary>; }' in named.conf. "
                    "In Windows DNS: set Zone Transfer permission to named servers only."
                ),
                references=["CWE-200", "MITRE T1590.002"],
                evidence=ev,
                cvss_v31_vector=CVSS_ZONE_XFER_V31,
                cvss_v40_vector=CVSS_ZONE_XFER_V40,
                mitre_attack=["TA0043/T1590.002", "TA0007/T1018"],
                target=target,
            )

        if internal_ips:
            ev = Evidence(
                request_raw=f"DNS enumeration of {domain}",
                response_raw="Internal IPs: " + ", ".join(internal_ips),
                extra={"internal_ips": internal_ips},
            )
            self.new_finding(
                title=f"Internal IP Addresses Exposed in DNS — {domain}",
                severity=Severity.HIGH,
                description=(
                    f"DNS records for {domain} expose {len(internal_ips)} RFC-1918 "
                    f"(internal) IP address(es): {', '.join(internal_ips[:10])}. "
                    "These reveal internal network topology to any external observer."
                ),
                reproduction_steps=[
                    f"dig A {domain}",
                    f"dig ANY @{target} {domain}",
                ],
                remediation=(
                    "Use DNS split-horizon to serve different records internally and externally. "
                    "Ensure public DNS zones only contain public-facing IP addresses."
                ),
                references=["CWE-200", "MITRE T1018"],
                evidence=ev,
                cvss_v31_vector=CVSS_INTERNAL_V31,
                cvss_v40_vector=CVSS_INTERNAL_V40,
                mitre_attack=["TA0007/T1018", "TA0043/T1590.002"],
                target=target,
            )

        if wildcard:
            ev = Evidence(
                request_raw=f"DNS A query for random nonexistent subdomain of {domain}",
                response_raw="Wildcard DNS record resolved successfully",
            )
            self.new_finding(
                title=f"Wildcard DNS Configured — {domain}",
                severity=Severity.MEDIUM,
                description=(
                    f"The domain {domain} has a wildcard DNS record (*. A ...). "
                    "Any subdomain lookup resolves, which can assist attackers in "
                    "phishing (convincing-looking subdomains resolve) and bypasses "
                    "subdomain brute-force defences."
                ),
                reproduction_steps=[
                    f"dig A forge-test-random.{domain}",
                ],
                remediation=(
                    "Remove wildcard DNS records unless explicitly required. "
                    "Use explicit records for each required subdomain."
                ),
                references=["CWE-200"],
                evidence=ev,
                cvss_v31_vector=CVSS_WILDCARD_V31,
                cvss_v40_vector=CVSS_WILDCARD_V40,
                target=target,
            )

        if records:
            srv_count = len(records.get("SRV", []))
            ev = Evidence(
                request_raw=f"Full DNS enumeration of {domain}",
                response_raw="\n".join(
                    f"{rtype}: {v}"
                    for rtype, vals in records.items()
                    for v in vals[:10]
                ),
                extra={
                    "record_types": list(records.keys()),
                    "subdomain_count": len(subdomains),
                    "srv_count": srv_count,
                    "dnssec": dnssec,
                },
            )
            self.new_finding(
                title=f"DNS Enumeration Results — {domain}",
                severity=Severity.INFORMATIONAL,
                description=(
                    f"DNS enumeration of {domain} produced: "
                    f"{sum(len(v) for v in records.values())} records across "
                    f"{len(records)} types, {len(subdomains)} live subdomain(s), "
                    f"{srv_count} AD SRV record(s). "
                    f"DNSSEC: {'enabled' if dnssec else 'not detected'}."
                ),
                reproduction_steps=[
                    f"dig ANY @{target} {domain}",
                    f"for sub in dc ldap kerberos mail; do dig A $sub.{domain}; done",
                ],
                remediation="Review DNS records for unnecessary information disclosure.",
                references=["MITRE T1590.002"],
                evidence=ev,
                cvss_v31_vector=CVSS_WILDCARD_V31,
                cvss_v40_vector=CVSS_WILDCARD_V40,
                mitre_attack=["TA0043/T1590.002"],
                target=target,
            )


# ---------------------------------------------------------------------------
# Embedded tests
# ---------------------------------------------------------------------------

class TestDnsEnum(unittest.TestCase):

    def test_phase(self):
        assert DnsEnum.PHASE == 1

    def test_name(self):
        assert DnsEnum.NAME == "dns_enum"

    def test_tags(self):
        assert "dns" in DnsEnum.TAGS
        assert "recon" in DnsEnum.TAGS

    def test_cvss_zone_xfer_critical(self):
        assert "C:H" in CVSS_ZONE_XFER_V31
        assert "PR:N" in CVSS_ZONE_XFER_V31

    def test_subdomain_list_length(self):
        assert len(_SUBDOMAINS) >= 80

    def test_subdomain_list_contains_dc(self):
        assert "dc" in _SUBDOMAINS

    def test_subdomain_list_contains_adfs(self):
        assert "adfs" in _SUBDOMAINS

    def test_ad_srv_names_contains_kerberos(self):
        assert any("kerberos" in s for s in _AD_SRV_NAMES)

    def test_ad_srv_names_contains_ldap(self):
        assert any("ldap" in s for s in _AD_SRV_NAMES)

    def test_rfc1918_prefixes(self):
        assert "10." in _RFC1918_PREFIXES
        assert "192.168." in _RFC1918_PREFIXES
        assert "172.16." in _RFC1918_PREFIXES

    def test_find_internal_ips_extracts_correctly(self):
        mod = DnsEnum.__new__(DnsEnum)
        mod.log = type("L", (), {"debug": lambda *a, **k: None})()
        records = {"A": ["10.0.0.1", "8.8.8.8"]}
        ips = mod._find_internal_ips(records, [])
        assert "10.0.0.1" in ips
        assert "8.8.8.8" not in ips

    def test_find_internal_ips_from_subdomains(self):
        mod = DnsEnum.__new__(DnsEnum)
        mod.log = type("L", (), {"debug": lambda *a, **k: None})()
        ips = mod._find_internal_ips({}, ["dc.corp.local -> 192.168.1.10"])
        assert "192.168.1.10" in ips

    def test_check_wildcard_dns_no_server(self):
        """Returns False gracefully when DNS is unreachable."""
        mod = DnsEnum.__new__(DnsEnum)
        mod.log = type("L", (), {"debug": lambda *a, **k: None, "warning": lambda *a, **k: None})()
        result = mod._check_wildcard_dns("nonexistent.local", "127.0.0.1")
        assert result is False

    def test_detect_dnssec_no_server(self):
        """Returns False gracefully when DNS is unreachable."""
        mod = DnsEnum.__new__(DnsEnum)
        mod.log = type("L", (), {"debug": lambda *a, **k: None})()
        result = mod._detect_dnssec("nonexistent.local", "127.0.0.1")
        assert result is False


if __name__ == "__main__":
    unittest.main()
