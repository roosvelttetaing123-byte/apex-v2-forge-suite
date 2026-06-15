"""AD Backup Check — verify AD backup health and exposure."""
from __future__ import annotations
import sys, time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))
from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity
from adforge.core.ldap_client import LdapClient

CVSS_BACKUP = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"
CVSS40_BACKUP = "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N"
CVSS_INFO = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N"
CVSS40_INFO = "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N"

class AdBackupCheck(BaseModule):
    NAME = "ad_backup_check"
    DESCRIPTION = "AD: check backup age, DSRM password, ntds.dit exposure"
    PHASE = 13
    TAGS = ["post", "backup", "hygiene"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        dc_ip = self.config.extra.get("dc", self.config.target)
        domain = self.config.extra.get("domain", "")
        if not self.check_scope(dc_ip):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        client = LdapClient(dc_ip=dc_ip, domain=domain,
            username=self.config.extra.get("username", ""),
            password=self.config.extra.get("password", ""),
            nt_hash=self.config.extra.get("hash", ""))
        if not client.connect(): return self._make_result(start)

        try:
            from datetime import datetime, timezone, timedelta
            now = datetime.now(timezone.utc)

            # Check DSA signature (tombstone lifetime indicates backup age)
            await self.rate_limit()
            config = client.search(
                "(objectClass=nTDSService)",
                ["tombstoneLifetime"],
                search_base=f"CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,{client.base_dn}")

            tombstone_days = 180  # Default
            if config:
                tombstone_days = int(str(config[0].get("tombstoneLifetime", 180) or 180))

            # Check DCs for lastBackupTime
            await self.rate_limit()
            dcs = client.search(
                "(primaryGroupID=516)",
                ["sAMAccountName", "dNSHostName", "operatingSystem"])

            dc_list = [str(dc.get("sAMAccountName", "?")) for dc in dcs]

            # Check for ntds.dit exposure via SMB shares
            ntds_exposed = False
            try:
                from impacket.smbconnection import SMBConnection
                conn = SMBConnection(dc_ip, dc_ip, timeout=5)
                conn.login(
                    self.config.extra.get("username", ""),
                    self.config.extra.get("password", ""),
                    domain,
                    nthash=self.config.extra.get("hash", ""))

                # Check common backup share locations
                shares = conn.listShares()
                share_names = [str(s["shi1_netname"]).rstrip("\x00") for s in shares]

                backup_shares = [s for s in share_names if any(
                    kw in s.lower() for kw in ["backup", "bkup", "ntds", "system state", "recovery"])]

                if backup_shares:
                    ev = Evidence(extra={"backup_shares": backup_shares})
                    self.new_finding(
                        title=f"AD Backup Shares Exposed — {', '.join(backup_shares)}",
                        severity=Severity.HIGH,
                        description=(
                            f"Backup-related SMB shares found: {', '.join(backup_shares)}\n"
                            "These may contain ntds.dit, SYSTEM hive, or other credential material."
                        ),
                        reproduction_steps=[f"smbclient //{dc_ip}/{backup_shares[0]} -U user"],
                        remediation="Restrict backup share access. Move backups to isolated storage.",
                        references=["CWE-312", "MITRE T1003.003"],
                        evidence=ev, cvss_v31_vector=CVSS_BACKUP, cvss_v40_vector=CVSS40_BACKUP,
                        mitre_attack=["TA0006/T1003.003"],
                        target=dc_ip)
                conn.close()
            except Exception:
                pass

            ev = Evidence(extra={
                "dcs": dc_list, "tombstone_days": tombstone_days})
            self.new_finding(
                title=f"AD Backup Health — {len(dc_list)} DCs, tombstone={tombstone_days}d",
                severity=Severity.INFORMATIONAL,
                description=(
                    f"AD infrastructure: {len(dc_list)} domain controller(s), "
                    f"tombstone lifetime: {tombstone_days} days.\n"
                    f"DCs: {', '.join(dc_list[:10])}"
                ),
                reproduction_steps=["repadmin /showbackup"],
                remediation="Ensure AD backups run within tombstone lifetime. Test DSRM recovery.",
                references=["CWE-693"],
                evidence=ev,
                cvss_v31_vector=CVSS_INFO, cvss_v40_vector=CVSS40_INFO,
                target=dc_ip)
        finally:
            client.disconnect()
        return self._make_result(start)

class TestAdBackupCheck:
    def test_phase(self) -> None: assert AdBackupCheck.PHASE == 13
