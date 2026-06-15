"""Forge Suite v5 APEX — Intelligence Pipeline.

Automated intelligence gathering for CVEs, exploits, attack techniques,
and detection templates. Keeps the offensive platform sharp with fresh
data from NVD, Exploit-DB, Nuclei, and MITRE ATT&CK.

Modules:
    intel_engine     — Main coordinator, search, sync orchestration
    cve_sync         — NVD API v2 CVE synchronization
    exploit_db_sync  — Exploit-DB mirror and search
    nuclei_sync      — Nuclei template auto-update
    technique_learner — MITRE ATT&CK technique database
    offline_db       — SQLite offline storage manager
"""
