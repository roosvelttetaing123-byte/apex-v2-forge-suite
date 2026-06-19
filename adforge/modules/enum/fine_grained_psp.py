"""Fine-Grained Password Policy — enumerate PSOs and their targets."""
from __future__ import annotations
import sys, time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))
from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity
from adforge.core.ldap_client import LdapClient

CVSS_WEAK_PSO = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N"
CVSS40_WEAK_PSO = "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N"
CVSS_INFO = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N"
CVSS40_INFO = "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N"

PSO_ATTRS = [
    "cn", "msDS-PasswordSettingsPrecedence", "msDS-MinimumPasswordLength",
    "msDS-PasswordComplexityEnabled", "msDS-MinimumPasswordAge",
    "msDS-MaximumPasswordAge", "msDS-PasswordHistoryLength",
    "msDS-LockoutThreshold", "msDS-LockoutDuration",
    "msDS-PSOAppliesTo", "distinguishedName",
]

class FineGrainedPsp(BaseModule):
    NAME = "fine_grained_psp"
    DESCRIPTION = "Enumerate Fine-Grained Password Policies (PSOs) and their targets"
    PHASE = 2
    TAGS = ["enum", "password-policy", "ldap", "cwe-521"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        domain = self.config.extra.get("domain", "")
        dc_ip = self.config.extra.get("dc", self.config.target)
        if not self.check_scope(dc_ip):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        client = LdapClient(
            dc_ip=dc_ip, domain=domain,
            username=self.config.extra.get("username", ""),
            password=self.config.extra.get("password", ""),
            nt_hash=self.config.extra.get("hash", ""),
        )
        if not client.connect():
            return self._make_result(start)

        try:
            await self.rate_limit()
            psos = client.search(
                "(objectClass=msDS-PasswordSettings)", PSO_ATTRS,
                search_base=f"CN=Password Settings Container,CN=System,{client.base_dn}",
            )
            self.log.info("Found %d Fine-Grained Password Policy(ies)", len(psos))

            pso_data = []
            weak_psos = []

            for pso in psos:
                name = str(pso.get("cn", "?"))
                min_len = int(str(pso.get("msDS-MinimumPasswordLength", 0) or 0))
                complexity = str(pso.get("msDS-PasswordComplexityEnabled", "?"))
                lockout = int(str(pso.get("msDS-LockoutThreshold", 0) or 0))
                history = int(str(pso.get("msDS-PasswordHistoryLength", 0) or 0))
                precedence = int(str(pso.get("msDS-PasswordSettingsPrecedence", 0) or 0))
                applies_to = pso.get("msDS-PSOAppliesTo", [])
                if isinstance(applies_to, str):
                    applies_to = [applies_to]

                targets = [a.split(",")[0].replace("CN=", "") for a in applies_to[:10]]

                info = {
                    "name": name, "min_length": min_len, "complexity": complexity,
                    "lockout_threshold": lockout, "history": history,
                    "precedence": precedence, "targets": targets,
                }
                pso_data.append(info)

                if min_len < 12 or lockout == 0 or lockout > 10:
                    weak_psos.append(info)

            if pso_data:
                ev = Evidence(extra={"psos": pso_data[:20]})
                self.new_finding(
                    title=f"Fine-Grained Password Policies — {len(pso_data)} PSO(s)",
                    severity=Severity.INFORMATIONAL,
                    description=(
                        f"Password Settings Objects:\n"
                        + "\n".join(
                            f"  {p['name']}: minLen={p['min_length']}, lockout={p['lockout_threshold']}, "
                            f"targets={', '.join(p['targets'][:3])}"
                            for p in pso_data[:10]
                        )
                    ),
                    reproduction_steps=["Get-ADFineGrainedPasswordPolicy -Filter *"],
                    remediation="Review PSOs for adequate password requirements.",
                    references=["CWE-521"],
                    evidence=ev,
                    cvss_v31_vector=CVSS_INFO, cvss_v40_vector=CVSS40_INFO,
                    target=dc_ip,
                )

            if weak_psos:
                ev = Evidence(extra={"weak_psos": weak_psos})
                self.new_finding(
                    title=f"Weak Password Policies — {len(weak_psos)} PSO(s) below minimum standard",
                    severity=Severity.MEDIUM,
                    description=(
                        f"{len(weak_psos)} PSO(s) have weak settings (minLen<12 or no lockout):\n"
                        + "\n".join(
                            f"  {p['name']}: minLen={p['min_length']}, lockout={p['lockout_threshold']}"
                            for p in weak_psos[:10]
                        )
                    ),
                    reproduction_steps=["Get-ADFineGrainedPasswordPolicy -Filter {MinPasswordLength -lt 12}"],
                    remediation="Set minimum password length to 14+. Enable lockout (threshold 5-10).",
                    references=["CWE-521", "NIST SP 800-63B"],
                    evidence=ev,
                    cvss_v31_vector=CVSS_WEAK_PSO, cvss_v40_vector=CVSS40_WEAK_PSO,
                    target=dc_ip,
                )
        finally:
            client.disconnect()
        return self._make_result(start)

class TestFineGrainedPsp:
    def test_phase(self) -> None:
        assert FineGrainedPsp.PHASE == 2
