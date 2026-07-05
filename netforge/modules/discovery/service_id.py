"""Service Identification — fingerprint-db + banner + nmap version detection."""
from __future__ import annotations

import asyncio
import re
import shutil
import sys
import time
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity

_CVSS31_INFO = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
_CVSS40_INFO = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N"


class Confidence(str, Enum):
    HIGH   = "HIGH"
    MEDIUM = "MEDIUM"
    LOW    = "LOW"


@dataclass
class ServiceFingerprint:
    port:       int
    proto:      str
    service:    str
    product:    str
    version:    str
    cpe:        str
    confidence: Confidence


# 80+ fingerprints covering common + cloud/container ports
_FINGERPRINT_DB: list[ServiceFingerprint] = [
    # Core network services
    ServiceFingerprint(21,    "tcp", "ftp",        "vsftpd",         "",      "cpe:/a:beasts:vsftpd",               Confidence.MEDIUM),
    ServiceFingerprint(22,    "tcp", "ssh",        "OpenSSH",        "",      "cpe:/a:openssh:openssh",             Confidence.MEDIUM),
    ServiceFingerprint(23,    "tcp", "telnet",     "telnet",         "",      "cpe:/a:mit:telnet",                  Confidence.LOW),
    ServiceFingerprint(25,    "tcp", "smtp",       "Postfix",        "",      "cpe:/a:postfix:postfix",             Confidence.MEDIUM),
    ServiceFingerprint(53,    "tcp", "dns",        "BIND",           "",      "cpe:/a:isc:bind",                    Confidence.LOW),
    ServiceFingerprint(69,    "udp", "tftp",       "tftp",           "",      "cpe:/a:tftp:tftp",                   Confidence.LOW),
    ServiceFingerprint(79,    "tcp", "finger",     "finger",         "",      "cpe:/a:gnu:finger",                  Confidence.LOW),
    ServiceFingerprint(80,    "tcp", "http",       "nginx",          "",      "cpe:/a:nginx:nginx",                 Confidence.MEDIUM),
    ServiceFingerprint(88,    "tcp", "kerberos",   "MIT Kerberos",   "",      "cpe:/a:mit:kerberos_5",              Confidence.HIGH),
    ServiceFingerprint(110,   "tcp", "pop3",       "Dovecot",        "",      "cpe:/a:dovecot:dovecot",             Confidence.MEDIUM),
    ServiceFingerprint(111,   "tcp", "rpcbind",    "rpcbind",        "",      "cpe:/a:sun:rpcbind",                 Confidence.HIGH),
    ServiceFingerprint(119,   "tcp", "nntp",       "INN",            "",      "cpe:/a:isc:inn",                     Confidence.LOW),
    ServiceFingerprint(123,   "udp", "ntp",        "ntpd",           "",      "cpe:/a:ntp:ntp",                     Confidence.MEDIUM),
    ServiceFingerprint(135,   "tcp", "msrpc",      "Microsoft RPC",  "",      "cpe:/a:microsoft:windows",           Confidence.HIGH),
    ServiceFingerprint(137,   "udp", "netbios-ns", "NetBIOS",        "",      "cpe:/a:microsoft:windows",           Confidence.HIGH),
    ServiceFingerprint(139,   "tcp", "netbios-ssn","Samba",          "",      "cpe:/a:samba:samba",                 Confidence.MEDIUM),
    ServiceFingerprint(143,   "tcp", "imap",       "Dovecot",        "",      "cpe:/a:dovecot:dovecot",             Confidence.MEDIUM),
    ServiceFingerprint(161,   "udp", "snmp",       "Net-SNMP",       "",      "cpe:/a:net-snmp:net-snmp",           Confidence.MEDIUM),
    ServiceFingerprint(179,   "tcp", "bgp",        "Quagga",         "",      "cpe:/a:quagga:quagga",               Confidence.LOW),
    ServiceFingerprint(389,   "tcp", "ldap",       "OpenLDAP",       "",      "cpe:/a:openldap:openldap",           Confidence.MEDIUM),
    ServiceFingerprint(443,   "tcp", "https",      "nginx",          "",      "cpe:/a:nginx:nginx",                 Confidence.MEDIUM),
    ServiceFingerprint(445,   "tcp", "smb",        "Samba",          "",      "cpe:/a:samba:samba",                 Confidence.MEDIUM),
    ServiceFingerprint(464,   "tcp", "kpasswd",    "MIT Kerberos",   "",      "cpe:/a:mit:kerberos_5",              Confidence.HIGH),
    ServiceFingerprint(500,   "udp", "isakmp",     "strongSwan",     "",      "cpe:/a:strongswan:strongswan",       Confidence.MEDIUM),
    ServiceFingerprint(512,   "tcp", "rexec",      "rexec",          "",      "cpe:/a:openbsd:openssh",             Confidence.LOW),
    ServiceFingerprint(513,   "tcp", "rlogin",     "rlogin",         "",      "cpe:/a:mit:kerberos_5",              Confidence.LOW),
    ServiceFingerprint(514,   "tcp", "rsh",        "rsh",            "",      "cpe:/a:mit:kerberos_5",              Confidence.LOW),
    ServiceFingerprint(515,   "tcp", "lpd",        "CUPS",           "",      "cpe:/a:apple:cups",                  Confidence.LOW),
    ServiceFingerprint(587,   "tcp", "submission", "Postfix",        "",      "cpe:/a:postfix:postfix",             Confidence.MEDIUM),
    ServiceFingerprint(631,   "tcp", "ipp",        "CUPS",           "",      "cpe:/a:apple:cups",                  Confidence.MEDIUM),
    ServiceFingerprint(636,   "tcp", "ldaps",      "OpenLDAP",       "",      "cpe:/a:openldap:openldap",           Confidence.MEDIUM),
    ServiceFingerprint(873,   "tcp", "rsync",      "rsync",          "",      "cpe:/a:rsync:rsync",                 Confidence.HIGH),
    ServiceFingerprint(993,   "tcp", "imaps",      "Dovecot",        "",      "cpe:/a:dovecot:dovecot",             Confidence.MEDIUM),
    ServiceFingerprint(995,   "tcp", "pop3s",      "Dovecot",        "",      "cpe:/a:dovecot:dovecot",             Confidence.MEDIUM),
    # Windows / AD
    ServiceFingerprint(1433,  "tcp", "ms-sql-s",   "Microsoft SQL Server", "", "cpe:/a:microsoft:sql_server",      Confidence.HIGH),
    ServiceFingerprint(1521,  "tcp", "oracle",     "Oracle DB",      "",      "cpe:/a:oracle:database_server",      Confidence.HIGH),
    ServiceFingerprint(1723,  "tcp", "pptp",       "PPTP",           "",      "cpe:/a:microsoft:windows",           Confidence.MEDIUM),
    ServiceFingerprint(2049,  "tcp", "nfs",        "NFS",            "",      "cpe:/a:sun:nfs",                     Confidence.HIGH),
    ServiceFingerprint(3268,  "tcp", "globalcatalog", "AD GC",       "",      "cpe:/a:microsoft:active_directory",  Confidence.HIGH),
    ServiceFingerprint(3269,  "tcp", "globalcatalog-ssl","AD GC SSL","",      "cpe:/a:microsoft:active_directory",  Confidence.HIGH),
    ServiceFingerprint(3306,  "tcp", "mysql",      "MySQL",          "",      "cpe:/a:oracle:mysql",                Confidence.HIGH),
    ServiceFingerprint(3389,  "tcp", "ms-wbt-server","RDP",          "",      "cpe:/a:microsoft:remote_desktop",    Confidence.HIGH),
    ServiceFingerprint(3690,  "tcp", "svn",        "Subversion",     "",      "cpe:/a:apache:subversion",           Confidence.HIGH),
    ServiceFingerprint(5432,  "tcp", "postgresql", "PostgreSQL",     "",      "cpe:/a:postgresql:postgresql",       Confidence.HIGH),
    ServiceFingerprint(5900,  "tcp", "vnc",        "RealVNC",        "",      "cpe:/a:realvnc:realvnc",             Confidence.MEDIUM),
    ServiceFingerprint(5985,  "tcp", "wsman",      "WinRM HTTP",     "",      "cpe:/a:microsoft:windows",           Confidence.HIGH),
    ServiceFingerprint(5986,  "tcp", "wsmans",     "WinRM HTTPS",    "",      "cpe:/a:microsoft:windows",           Confidence.HIGH),
    # Messaging & streaming
    ServiceFingerprint(5671,  "tcp", "amqps",      "RabbitMQ",       "",      "cpe:/a:pivotal_software:rabbitmq",   Confidence.MEDIUM),
    ServiceFingerprint(5672,  "tcp", "amqp",       "RabbitMQ",       "",      "cpe:/a:pivotal_software:rabbitmq",   Confidence.MEDIUM),
    ServiceFingerprint(9092,  "tcp", "kafka",      "Apache Kafka",   "",      "cpe:/a:apache:kafka",                Confidence.HIGH),
    ServiceFingerprint(2181,  "tcp", "zookeeper",  "Apache ZooKeeper","",     "cpe:/a:apache:zookeeper",            Confidence.HIGH),
    ServiceFingerprint(61616, "tcp", "activemq",   "ActiveMQ",       "",      "cpe:/a:apache:activemq",             Confidence.HIGH),
    # NoSQL / caches
    ServiceFingerprint(6379,  "tcp", "redis",      "Redis",          "",      "cpe:/a:redislabs:redis",             Confidence.HIGH),
    ServiceFingerprint(9200,  "tcp", "elasticsearch","Elasticsearch","",      "cpe:/a:elastic:elasticsearch",       Confidence.HIGH),
    ServiceFingerprint(9300,  "tcp", "elasticsearch-cluster","Elasticsearch","","cpe:/a:elastic:elasticsearch",     Confidence.HIGH),
    ServiceFingerprint(11211, "tcp", "memcached",  "Memcached",      "",      "cpe:/a:memcached:memcached",         Confidence.HIGH),
    ServiceFingerprint(27017, "tcp", "mongodb",    "MongoDB",        "",      "cpe:/a:mongodb:mongodb",             Confidence.HIGH),
    # Container / Kubernetes
    ServiceFingerprint(2375,  "tcp", "docker",     "Docker Engine",  "",      "cpe:/a:docker:docker",               Confidence.HIGH),
    ServiceFingerprint(2376,  "tcp", "docker-tls", "Docker Engine TLS","",   "cpe:/a:docker:docker",               Confidence.HIGH),
    ServiceFingerprint(2379,  "tcp", "etcd-client","etcd",           "",      "cpe:/a:etcd:etcd",                   Confidence.HIGH),
    ServiceFingerprint(2380,  "tcp", "etcd-peer",  "etcd",           "",      "cpe:/a:etcd:etcd",                   Confidence.HIGH),
    ServiceFingerprint(6443,  "tcp", "kubernetes", "Kubernetes API", "",      "cpe:/a:kubernetes:kubernetes",       Confidence.HIGH),
    ServiceFingerprint(10250, "tcp", "kubelet",    "kubelet",        "",      "cpe:/a:kubernetes:kubernetes",       Confidence.HIGH),
    ServiceFingerprint(10255, "tcp", "kubelet-ro", "kubelet read-only","",    "cpe:/a:kubernetes:kubernetes",       Confidence.HIGH),
    # HashiCorp / service mesh
    ServiceFingerprint(8200,  "tcp", "vault",      "HashiCorp Vault","",      "cpe:/a:hashicorp:vault",             Confidence.HIGH),
    ServiceFingerprint(8300,  "tcp", "consul-rpc", "Consul",         "",      "cpe:/a:hashicorp:consul",            Confidence.HIGH),
    ServiceFingerprint(8301,  "tcp", "consul-gossip","Consul",       "",      "cpe:/a:hashicorp:consul",            Confidence.MEDIUM),
    ServiceFingerprint(8500,  "tcp", "consul-http","Consul HTTP",    "",      "cpe:/a:hashicorp:consul",            Confidence.HIGH),
    # Observability
    ServiceFingerprint(3000,  "tcp", "grafana",    "Grafana",        "",      "cpe:/a:grafana:grafana",             Confidence.HIGH),
    ServiceFingerprint(5601,  "tcp", "kibana",     "Kibana",         "",      "cpe:/a:elastic:kibana",              Confidence.HIGH),
    ServiceFingerprint(9090,  "tcp", "prometheus", "Prometheus",     "",      "cpe:/a:prometheus:prometheus",       Confidence.MEDIUM),
    ServiceFingerprint(9100,  "tcp", "node-exporter","node_exporter","",      "cpe:/a:prometheus:node_exporter",    Confidence.HIGH),
    # Web / App servers
    ServiceFingerprint(8080,  "tcp", "http-alt",   "Apache Tomcat",  "",      "cpe:/a:apache:tomcat",               Confidence.MEDIUM),
    ServiceFingerprint(7001,  "tcp", "weblogic",   "Oracle WebLogic","",      "cpe:/a:oracle:weblogic_server",      Confidence.HIGH),
    ServiceFingerprint(4848,  "tcp", "glassfish",  "GlassFish",      "",      "cpe:/a:oracle:glassfish_server",     Confidence.HIGH),
    ServiceFingerprint(8081,  "tcp", "nexus",      "Sonatype Nexus", "",      "cpe:/a:sonatype:nexus_repository_manager", Confidence.MEDIUM),
    ServiceFingerprint(8443,  "tcp", "https-alt",  "nginx",          "",      "cpe:/a:nginx:nginx",                 Confidence.MEDIUM),
    ServiceFingerprint(8888,  "tcp", "jupyter",    "Jupyter",        "",      "cpe:/a:project_jupyter:jupyter_notebook", Confidence.HIGH),
    ServiceFingerprint(9000,  "tcp", "sonarqube",  "SonarQube",      "",      "cpe:/a:sonarsource:sonarqube",       Confidence.MEDIUM),
    ServiceFingerprint(50000, "tcp", "jenkins-jnlp","Jenkins",       "",      "cpe:/a:jenkins:jenkins",             Confidence.HIGH),
    ServiceFingerprint(8500,  "tcp", "consul-http","Consul",         "",      "cpe:/a:hashicorp:consul",            Confidence.HIGH),
]

_PORT_TO_FP: dict[int, ServiceFingerprint] = {fp.port: fp for fp in _FINGERPRINT_DB}

_PROTOCOL_PROBES: dict[int, bytes] = {
    80:    b"HEAD / HTTP/1.0\r\nHost: forge\r\n\r\n",
    8080:  b"HEAD / HTTP/1.0\r\nHost: forge\r\n\r\n",
    8443:  b"HEAD / HTTP/1.0\r\nHost: forge\r\n\r\n",
    8000:  b"HEAD / HTTP/1.0\r\nHost: forge\r\n\r\n",
    8888:  b"GET / HTTP/1.0\r\nHost: forge\r\n\r\n",
    6379:  b"PING\r\n",
    11211: b"stats\r\n",
    9200:  b"GET / HTTP/1.0\r\nHost: forge\r\n\r\n",
    5601:  b"GET / HTTP/1.0\r\nHost: forge\r\n\r\n",
    3000:  b"GET / HTTP/1.0\r\nHost: forge\r\n\r\n",
    9090:  b"GET /metrics HTTP/1.0\r\nHost: forge\r\n\r\n",
    9100:  b"GET /metrics HTTP/1.0\r\nHost: forge\r\n\r\n",
    8200:  b"GET /v1/sys/health HTTP/1.0\r\nHost: forge\r\n\r\n",
    8500:  b"GET /v1/status/leader HTTP/1.0\r\nHost: forge\r\n\r\n",
    2379:  b"GET /health HTTP/1.0\r\nHost: forge\r\n\r\n",
}


class ServiceId(BaseModule):
    """Service identification: fingerprint DB + banner grabbing + nmap -sV."""

    NAME        = "service_id"
    DESCRIPTION = "Service identification: fingerprint DB, CPE generation, banner probes, nmap -sV"
    PHASE       = 2
    TAGS        = ["recon", "discovery", "service-id", "cwe-200"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        target = self.config.target

        if not self.check_scope(target):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        hosts = self.config.extra.get("live_hosts", [target])
        open_ports = self.config.extra.get("open_ports", {})

        services: dict[str, list[dict]] = {}
        sem = asyncio.Semaphore(30)

        for host in hosts[:50]:
            if not self.check_scope(host):
                continue
            port_entries = open_ports.get(host, [])
            ports_to_probe = [e["port"] if isinstance(e, dict) else e for e in port_entries]
            if not ports_to_probe:
                continue

            tasks = [self._identify_port(host, port, sem) for port in ports_to_probe[:100]]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            host_services = [r for r in results if isinstance(r, dict)]
            if host_services:
                services[host] = host_services

        for host in list(services.keys())[:5]:
            await self._nmap_version_detect(host, services)

        for host, svc_list in services.items():
            version_disclosures = [s for s in svc_list if s.get("version") or s.get("cpe")]
            if version_disclosures:
                ev = Evidence(
                    extra={
                        "host": host,
                        "services": svc_list[:30],
                        "version_disclosures": len(version_disclosures),
                    },
                )
                self.new_finding(
                    title=f"Service Version Disclosure — {host} ({len(svc_list)} services identified)",
                    severity=Severity.INFORMATIONAL,
                    description=(
                        f"Services identified on {host}:\n"
                        + "\n".join(
                            f"  Port {s['port']}/{s.get('proto','tcp')}: {s['service']}"
                            + (f" {s['product']}" if s.get("product") else "")
                            + (f" {s['version']}" if s.get("version") else "")
                            + (f" [{s['confidence']}]" if s.get("confidence") else "")
                            for s in svc_list[:20]
                        )
                    ),
                    reproduction_steps=[f"nmap -sV -p {','.join(str(s['port']) for s in svc_list[:20])} {host}"],
                    remediation="Suppress version banners where possible. Enable generic service headers.",
                    references=["CWE-200"],
                    evidence=ev,
                    cvss_v31_vector=_CVSS31_INFO,
                    cvss_v40_vector=_CVSS40_INFO,
                    target=host,
                )
            self.config.extra.setdefault("service_map", {})[host] = svc_list

        return self._make_result(start)

    async def _identify_port(self, host: str, port: int, sem: asyncio.Semaphore) -> dict | None:
        async with sem:
            await self.rate_limit()
            banner = await self._grab_banner(host, port)
            fp = _PORT_TO_FP.get(port)
            result = _identify_from_banner(port, banner or "")
            if fp and not result.get("product"):
                result["service"] = fp.service
                result["product"] = fp.product
                result["cpe"] = fp.cpe
                result["confidence"] = fp.confidence.value

            if banner and result.get("product") and result.get("version"):
                result["cpe"] = _cpe_from_banner(result["product"], result["version"])
                result["confidence"] = Confidence.HIGH.value
            elif banner and result.get("product"):
                result["confidence"] = Confidence.MEDIUM.value
            elif not result.get("confidence"):
                result["confidence"] = Confidence.LOW.value

            result["port"] = port
            result["proto"] = fp.proto if fp else "tcp"
            result["banner"] = (banner or "")[:300]
            return result

    async def _grab_banner(self, host: str, port: int) -> str | None:
        probe = _PROTOCOL_PROBES.get(port)
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=3.0
            )
            if probe:
                actual_probe = probe.replace(b"forge", host.encode())
                writer.write(actual_probe)
                await asyncio.wait_for(writer.drain(), timeout=2.0)
            data = await asyncio.wait_for(reader.read(1024), timeout=3.0)
            try:
                writer.close()
                await asyncio.wait_for(writer.wait_closed(), timeout=1.0)
            except Exception:
                pass
            return data.decode(errors="ignore").strip()[:500] if data else None
        except Exception:
            return None

    async def _nmap_version_detect(self, host: str, services: dict) -> None:
        nmap = shutil.which("nmap")
        if not nmap:
            return
        ports = [str(s["port"]) for s in services.get(host, [])]
        if not ports:
            return
        await self.rate_limit()
        try:
            proc = await asyncio.create_subprocess_exec(
                nmap, "-sV", "--version-light",
                "-p", ",".join(ports[:50]),
                "-n", "-Pn", host,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=60)
            output = stdout.decode(errors="ignore")
            for line in output.split("\n"):
                m = re.match(r"(\d+)/tcp\s+open\s+(\S+)\s*(.*)", line.strip())
                if m:
                    portnum = int(m.group(1))
                    svc_name = m.group(2)
                    version_str = m.group(3).strip()
                    for svc in services.get(host, []):
                        if svc["port"] == portnum:
                            if svc_name and svc_name != "unknown":
                                svc["service"] = svc_name
                            if version_str:
                                parts = version_str.split(" ")
                                if parts:
                                    svc["product"] = parts[0]
                                    svc["version"] = " ".join(parts[1:]) if len(parts) > 1 else ""
                                    svc["cpe"] = _cpe_from_banner(svc["product"], svc["version"])
                                    svc["confidence"] = Confidence.HIGH.value
        except Exception:
            pass


def _identify_from_banner(port: int, banner: str) -> dict:
    result: dict = {"service": "unknown", "product": "", "version": ""}
    if not banner:
        return result

    bl = banner.lower()

    m = re.search(r"SSH-([\d.]+)-(\S+)", banner)
    if m:
        result["service"] = "ssh"
        product_full = m.group(2)
        pm = re.match(r"([A-Za-z_]+)[_\-]?([\d.p]+.*)", product_full)
        if pm:
            result["product"] = pm.group(1)
            result["version"] = pm.group(2)
        else:
            result["product"] = product_full
        return result

    m = re.search(r"(?i)server:\s*([^\r\n]+)", banner)
    if "http/" in bl or m:
        result["service"] = "http"
        if m:
            srv = m.group(1).strip()
            parts = srv.split("/", 1)
            result["product"] = parts[0]
            result["version"] = parts[1].split(" ")[0] if len(parts) > 1 else ""
        return result

    if re.match(r"220\s", banner) and "ftp" in bl:
        result["service"] = "ftp"
        m2 = re.search(r"220[- ].*?(\S+)\s+FTP\s+server\s+.*?version\s+(\S+)", banner, re.IGNORECASE)
        if m2:
            result["product"] = m2.group(1)
            result["version"] = m2.group(2)
        return result

    if re.match(r"220\s", banner) and ("smtp" in bl or "mail" in bl or "esmtp" in bl or "postfix" in bl or "sendmail" in bl):
        result["service"] = "smtp"
        m2 = re.search(r"(?:Postfix|Sendmail|Exim|Dovecot)[/ ]?([\d.]+)", banner, re.IGNORECASE)
        if m2:
            result["product"] = m2.group(0).split("/")[0].split(" ")[0]
            result["version"] = m2.group(1)
        return result

    if "+PONG" in banner or ("redis" in bl and "-ERR" in banner) or "NOAUTH" in banner:
        result["service"] = "redis"
        result["product"] = "Redis"
        m2 = re.search(r"redis_version:(\S+)", bl)
        if m2:
            result["version"] = m2.group(1)
        return result

    if "memcached" in bl or "STAT pid" in banner or "STAT version" in banner:
        result["service"] = "memcached"
        result["product"] = "Memcached"
        m2 = re.search(r"STAT version\s+(\S+)", banner)
        if m2:
            result["version"] = m2.group(1)
        return result

    if "elasticsearch" in bl or '"cluster_name"' in bl:
        result["service"] = "elasticsearch"
        result["product"] = "Elasticsearch"
        m2 = re.search(r'"number"\s*:\s*"([^"]+)"', banner)
        if m2:
            result["version"] = m2.group(1)
        return result

    if "grafana" in bl:
        result["service"] = "grafana"
        result["product"] = "Grafana"
        m2 = re.search(r"grafana[/ ]([\d.]+)", bl)
        if m2:
            result["version"] = m2.group(1)
        return result

    if "vault" in bl and ("initialized" in bl or "sealed" in bl):
        result["service"] = "vault"
        result["product"] = "HashiCorp Vault"
        return result

    if "consul" in bl:
        result["service"] = "consul"
        result["product"] = "Consul"
        return result

    if "etcd" in bl or "health" in bl:
        result["service"] = "etcd"
        result["product"] = "etcd"
        return result

    if "prometheus" in bl or "HELP go_goroutines" in banner:
        result["service"] = "prometheus"
        result["product"] = "Prometheus"
        m2 = re.search(r"prometheus_build_info.*?version=\"([^\"]+)\"", banner)
        if m2:
            result["version"] = m2.group(1)
        return result

    if port == 3306 or "mysql" in bl or "mariadb" in bl:
        result["service"] = "mysql"
        result["product"] = "MariaDB" if "mariadb" in bl else "MySQL"
        m2 = re.search(r"([\d]+\.[\d]+\.[\d]+(?:-MariaDB)?)", banner)
        if m2:
            result["version"] = m2.group(1)
        return result

    if port == 5432 or "postgresql" in bl:
        result["service"] = "postgresql"
        result["product"] = "PostgreSQL"
        return result

    if port == 27017:
        result["service"] = "mongodb"
        result["product"] = "MongoDB"
        return result

    if port in (5985, 5986):
        result["service"] = "winrm"
        result["product"] = "WinRM"
        return result

    fp = _PORT_TO_FP.get(port)
    if fp:
        result["service"] = fp.service
        result["product"] = fp.product
        result["cpe"] = fp.cpe
    return result


def _cpe_from_banner(product: str, version: str) -> str:
    _PRODUCT_TO_VENDOR: dict[str, str] = {
        "openssh": "openssh",
        "nginx":   "nginx",
        "apache":  "apache",
        "iis":     "microsoft",
        "mysql":   "oracle",
        "mariadb": "mariadb",
        "postgresql": "postgresql",
        "mongodb": "mongodb",
        "redis":   "redislabs",
        "memcached": "memcached",
        "elasticsearch": "elastic",
        "vault":   "hashicorp",
        "consul":  "hashicorp",
        "grafana": "grafana",
        "kibana":  "elastic",
        "prometheus": "prometheus",
        "tomcat":  "apache",
        "weblogic":"oracle",
        "glassfish":"oracle",
        "jenkins": "jenkins",
        "postfix": "postfix",
        "dovecot": "dovecot",
        "samba":   "samba",
        "bind":    "isc",
        "vsftpd":  "beasts",
        "openssh": "openssh",
    }
    p_lower = product.lower()
    vendor = _PRODUCT_TO_VENDOR.get(p_lower, p_lower)
    clean_version = re.sub(r"[^\w.\-]", "", version) if version else ""
    cpe = f"cpe:/a:{vendor}:{p_lower}"
    if clean_version:
        cpe += f":{clean_version}"
    return cpe


class TestServiceId:
    def test_fingerprint_db_size(self) -> None:
        assert len(_FINGERPRINT_DB) >= 80

    def test_port_to_fp(self) -> None:
        assert 22 in _PORT_TO_FP
        assert _PORT_TO_FP[22].service == "ssh"
        assert 6379 in _PORT_TO_FP
        assert 10250 in _PORT_TO_FP
        assert 2379 in _PORT_TO_FP

    def test_identify_ssh(self) -> None:
        result = _identify_from_banner(22, "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3")
        assert result["service"] == "ssh"
        assert "OpenSSH" in result["product"]
        assert "8.9p1" in result["version"]

    def test_identify_http_nginx(self) -> None:
        result = _identify_from_banner(80, "HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\n")
        assert result["service"] == "http"
        assert result["product"] == "nginx"
        assert "1.24.0" in result["version"]

    def test_identify_redis_noauth(self) -> None:
        result = _identify_from_banner(6379, "+PONG\r\n")
        assert result["service"] == "redis"
        assert result["product"] == "Redis"

    def test_identify_redis_auth(self) -> None:
        result = _identify_from_banner(6379, "-NOAUTH Authentication required")
        assert result["service"] == "redis"

    def test_identify_smtp(self) -> None:
        result = _identify_from_banner(25, "220 mail.example.com ESMTP Postfix")
        assert result["service"] == "smtp"

    def test_cpe_from_banner(self) -> None:
        cpe = _cpe_from_banner("OpenSSH", "8.9p1")
        assert "openssh" in cpe
        assert "8.9p1" in cpe

    def test_cpe_from_banner_mysql(self) -> None:
        cpe = _cpe_from_banner("MySQL", "8.0.33")
        assert "oracle" in cpe or "mysql" in cpe

    def test_phase(self) -> None:
        assert ServiceId.PHASE == 2

    def test_confidence_enum(self) -> None:
        assert Confidence.HIGH == "HIGH"
        assert Confidence.MEDIUM == "MEDIUM"
        assert Confidence.LOW == "LOW"
