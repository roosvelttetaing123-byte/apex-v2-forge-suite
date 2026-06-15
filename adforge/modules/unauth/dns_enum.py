"""DNS Enum module."""
from __future__ import annotations
import sys, time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))
from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity

CVSS_DNS_V31 = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
CVSS_DNS_V40 = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N"

class DnsEnum(BaseModule):
    """Enumerate DNS zones and records."""
    NAME = "dns_enum"
    DESCRIPTION = "Enumerate DNS zones and records"
    PHASE = 1
    TAGS = ["unauth", "dns", "recon"]
    
    async def run(self) -> ModuleResult:
        start = time.monotonic()
        target = self.config.target
        if not self.check_scope(target): return self._make_result(start, skipped=True)
        
        domain = self.config.extra.get("domain")
        if not domain:
            self.log.info("DNS Enum requires a domain. Skipping.")
            return self._make_result(start, skipped=True, skip_reason="No domain provided")

        try:
            import dns.resolver
            import dns.zone
            import dns.query
            import dns.exception

            # Try zone transfer (AXFR) first
            try:
                self.log.info("Attempting AXFR zone transfer for %s at %s", domain, target)
                z = dns.zone.from_xfr(dns.query.xfr(target, domain, timeout=5))
                records = [f"{n.to_text()} {z[n].to_text(n)}" for n in z.nodes.keys()]
                
                ev = Evidence(
                    request_raw=f"dig AXFR @{target} {domain}", 
                    response_raw="\n".join(records[:50]) + ("\n..." if len(records) > 50 else ""),
                    extra={"record_count": len(records)}
                )
                self.new_finding(
                    title="DNS Zone Transfer (AXFR) Allowed",
                    severity=Severity.HIGH,
                    description="The DNS server allows unauthorized zone transfers, revealing the entire internal network topology.",
                    reproduction_steps=[f"dig AXFR @{target} {domain}"],
                    remediation="Restrict zone transfers to trusted secondary DNS servers only.",
                    references=["CWE-200", "MITRE T1590.002"],
                    evidence=ev,
                    cvss_v31_vector=CVSS_DNS_V31, cvss_v40_vector=CVSS_DNS_V40, target=target
                )
            except Exception as e:
                self.log.debug("Zone transfer failed: %s", e)
                
            # If AXFR fails, attempt common record enumeration
            resolver = dns.resolver.Resolver()
            resolver.nameservers = [target]
            resolver.timeout = 2
            resolver.lifetime = 2
            
            interesting_records = []
            for qtype in ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SRV']:
                try:
                    if qtype == 'SRV':
                        # Look for common AD SRV records
                        queries = [f"_kerberos._tcp.{domain}", f"_ldap._tcp.{domain}", f"_gc._tcp.{domain}"]
                    else:
                        queries = [domain]
                        
                    for q in queries:
                        answers = resolver.resolve(q, qtype)
                        for rdata in answers:
                            interesting_records.append(f"{q} IN {qtype} {rdata.to_text()}")
                except Exception:
                    pass
            
            if interesting_records:
                self.log.info("Found %d interesting DNS records", len(interesting_records))

        except ImportError:
            self.log.error("dnspython is required for DNS Enum module")
            return self._make_result(start, skipped=True, skip_reason="dnspython missing")

        return self._make_result(start)

class TestDnsEnum:
    def test_phase(self): assert DnsEnum.PHASE == 1
