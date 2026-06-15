"""BloodHound data exporter — run SharpHound/BloodHound.py collectors."""
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


class BloodhoundExport(BaseModule):
    """BloodHound data collection and export."""

    NAME        = "bloodhound_export"
    DESCRIPTION = "Collect BloodHound data using bloodhound-python or SharpHound"
    PHASE       = 14
    TAGS        = ["reporting", "bloodhound", "graph", "attack-path"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        domain = self.config.extra.get("domain", "")
        dc_ip  = self.config.extra.get("dc", self.config.target)

        if not self.config.extra.get("bloodhound_enabled", False):
            self.log.info("BloodHound export not enabled — use --bloodhound flag. Skipping.")
            return self._make_result(start, skipped=True, skip_reason="--bloodhound not set")

        if not self.check_scope(dc_ip):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        bh_dir = Path(self.config.extra.get("results_dir", "/tmp")) / "bloodhound"
        bh_dir.mkdir(parents=True, exist_ok=True)

        bh = shutil.which("bloodhound-python") or shutil.which("bloodhound")
        if not bh:
            self.log.warning("bloodhound-python not found. Install: pip install bloodhound")
            return self._make_result(start)

        username = self.config.extra.get("username", "")
        password = self.config.extra.get("password", "")
        nt_hash  = self.config.extra.get("hash", "")

        cmd = [
            bh,
            "-d", domain,
            "-dc", dc_ip,
            "-c", "All",
            "-o", str(bh_dir),
        ]
        if nt_hash:
            cmd += ["-u", f"{username}@{domain}", "--hashes", f":{nt_hash}"]
        elif username:
            cmd += ["-u", f"{username}@{domain}", "-p", password]

        self.log.info("Running BloodHound collection against %s", dc_ip)
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=300)
            output = stdout.decode() + stderr.decode()

            if proc.returncode == 0 or "Done" in output:
                json_files = list(bh_dir.glob("*.json"))
                zip_files  = list(bh_dir.glob("*.zip"))
                self.log.info(
                    "BloodHound collection complete: %d JSON + %d ZIP files",
                    len(json_files), len(zip_files)
                )
                ev = Evidence(
                    extra={
                        "output_dir": str(bh_dir),
                        "files":      [f.name for f in json_files[:5]] + [f.name for f in zip_files[:5]],
                    }
                )
                self.new_finding(
                    title="BloodHound Data Collected Successfully",
                    severity=Severity.INFORMATIONAL,
                    description=(
                        f"BloodHound collection completed for {domain}. "
                        f"Data saved to {bh_dir}. "
                        "Import into BloodHound GUI to visualize attack paths."
                    ),
                    reproduction_steps=[
                        "Start BloodHound GUI",
                        f"Import ZIP from {bh_dir}",
                        "Run pre-built queries: Shortest Path to Domain Admins",
                    ],
                    remediation="Use attack path analysis to prioritize remediation.",
                    references=["BloodHound CE", "MITRE ATT&CK"],
                    evidence=ev,
                    cvss_v31_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N",
                    target=dc_ip,
                )
            else:
                self.log.warning("BloodHound may have failed: %s", output[:200])

        except asyncio.TimeoutError:
            self.log.warning("BloodHound timed out after 300s")
        except Exception as exc:
            self.log.error("BloodHound export failed: %s", exc)

        return self._make_result(start)


class TestBloodhoundExport:
    def test_name(self) -> None:
        assert BloodhoundExport.NAME == "bloodhound_export"
