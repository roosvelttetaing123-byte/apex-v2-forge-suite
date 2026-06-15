"""GPO Path Check — SYSVOL share permissions for GPO hijacking."""
from __future__ import annotations
import asyncio, sys, time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))
from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity

CVSS = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
CVSS40 = "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"

class GpoPathCheck(BaseModule):
    NAME = "gpo_path_check"
    DESCRIPTION = "GPO: check SYSVOL share permissions for GPO hijacking via writable paths"
    PHASE = 10
    TAGS = ["gpo-abuse", "privesc", "cwe-284"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        dc_ip = self.config.extra.get("dc", self.config.target)
        domain = self.config.extra.get("domain", "")
        if not self.check_scope(dc_ip):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        gpo_data = self.config.extra.get("domain_gpos", [])
        writable_paths = []

        for gpo in gpo_data:
            sysvol = gpo.get("sysvol_path", "")
            if not sysvol:
                continue

            await self.rate_limit()
            # Try writing a test file to SYSVOL path via SMB
            try:
                from impacket.smbconnection import SMBConnection
                conn = SMBConnection(dc_ip, dc_ip, timeout=5)
                conn.login(
                    self.config.extra.get("username", ""),
                    self.config.extra.get("password", ""),
                    domain,
                    nthash=self.config.extra.get("hash", ""),
                )

                # Parse UNC path: \\server\SYSVOL\domain\Policies\{GUID}
                parts = sysvol.replace("\\\\", "").split("\\", 1)
                if len(parts) < 2:
                    continue
                share = parts[1].split("\\")[0]  # Usually "SYSVOL"
                subpath = "\\".join(parts[1].split("\\")[1:])

                try:
                    # Try to list the GPO directory
                    files = conn.listPath(share, f"{subpath}\\*")
                    gpo_files = [f.get_longname() for f in files if f.get_longname() not in (".", "..")]

                    # Try writing a test file
                    test_path = f"{subpath}\\__forge_test__.tmp"
                    try:
                        fid = conn.createFile(share, test_path)
                        conn.writeFile(share, fid, b"test")
                        conn.closeFile(share, fid)
                        conn.deleteFile(share, test_path)

                        writable_paths.append({
                            "gpo": gpo.get("name", "?"),
                            "path": sysvol,
                            "files": gpo_files[:5],
                        })
                    except Exception:
                        pass  # Not writable — expected
                except Exception:
                    pass

                conn.close()
            except ImportError:
                # No impacket — use smbclient if available
                import shutil
                smbclient = shutil.which("smbclient")
                if smbclient:
                    try:
                        proc = await asyncio.create_subprocess_exec(
                            smbclient, f"//{dc_ip}/SYSVOL",
                            "-U", f"{self.config.extra.get('username', '')}%{self.config.extra.get('password', '')}",
                            "-c", f"ls {domain}\\Policies\\",
                            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
                        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
                    except Exception:
                        pass
            except Exception:
                pass

        if writable_paths:
            if not self.confirm_action(
                action="Report writable GPO SYSVOL paths",
                target=dc_ip,
                risk="GPO hijacking allows code execution on all domain-joined machines"):
                return self._make_result(start, skipped=True, skip_reason="operator declined")

            ev = Evidence(extra={"writable_paths": writable_paths})
            self.new_finding(
                title=f"Writable GPO SYSVOL Paths — {len(writable_paths)} GPO(s) hijackable",
                severity=Severity.CRITICAL,
                description=(
                    f"{len(writable_paths)} GPO SYSVOL paths are writable by current user:\n"
                    + "\n".join(f"  {w['gpo']}: {w['path']}" for w in writable_paths[:5])
                    + "\n\nAn attacker can modify GPO files (scripts, settings) to execute "
                    "arbitrary code on ALL domain-joined machines that apply the GPO."
                ),
                reproduction_steps=[
                    "# Modify Scheduled Task in GPO:",
                    "# Edit ScheduledTasks.xml in SYSVOL\\Policies\\{GUID}\\Machine\\Preferences\\ScheduledTasks\\",
                    "# SharpGPOAbuse: SharpGPOAbuse.exe --AddComputerTask --TaskName 'Evil' --GPOName 'Default Domain Policy'",
                ],
                remediation="Fix SYSVOL permissions. Only Domain Admins should have write access to GPO paths.",
                references=["CWE-284", "MITRE T1484.001"],
                evidence=ev, cvss_v31_vector=CVSS, cvss_v40_vector=CVSS40,
                mitre_attack=["TA0005/T1484.001"],
                target=dc_ip)

        return self._make_result(start)

class TestGpoPathCheck:
    def test_phase(self) -> None: assert GpoPathCheck.PHASE == 10
