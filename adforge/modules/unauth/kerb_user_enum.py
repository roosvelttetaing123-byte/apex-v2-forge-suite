"""Kerberos user enumeration — validate usernames without credentials."""
from __future__ import annotations

import asyncio
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity

CVSS_KERB_ENUM = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
CVSS40_KERB_ENUM = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N"
class KerbUserEnum(BaseModule):
    """Kerberos-based user enumeration without credentials."""

    NAME        = "kerb_user_enum"
    DESCRIPTION = "Enumerate valid domain users via Kerberos pre-auth error codes"
    PHASE       = 1
    TAGS        = ["unauth", "kerberos", "user-enum", "cwe-204"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        domain = self.config.extra.get("domain", "")
        dc_ip  = self.config.extra.get("dc", self.config.target)

        if not self.check_scope(dc_ip):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        # Load username list
        usernames = self._load_usernames()
        if not usernames:
            self.log.info("No username list found")
            return self._make_result(start)

        self.log.info("Enumerating %d username(s) via Kerberos", len(usernames))
        valid_users = await self._enumerate(usernames, domain, dc_ip)

        if valid_users:
            self.config.extra["valid_domain_users"] = valid_users
            ev = Evidence(
                extra={
                    "valid_users":  valid_users,
                    "tested":       len(usernames),
                }
            )
            self.new_finding(
                title=f"Valid Kerberos Users Enumerated ({len(valid_users)} found)",
                severity=Severity.MEDIUM,
                description=(
                    f"{len(valid_users)} valid domain user(s) identified via Kerberos enumeration: "
                    f"{', '.join(valid_users[:10])}. "
                    "Kerberos returns distinct error codes for valid vs. invalid usernames."
                ),
                reproduction_steps=[
                    f"kerbrute userenum -d {domain} --dc {dc_ip} usernames.txt",
                ],
                remediation=(
                    "Enable 'Do not preauthenticate' protection. "
                    "Use honey account names to detect enumeration. "
                    "Monitor Event ID 4768 (TGT requests) for enumeration patterns."
                ),
                references=["CWE-204", "MITRE T1589.001"],
                evidence=ev,
                cvss_v31_vector=CVSS_KERB_ENUM,
                cvss_v40_vector=CVSS40_KERB_ENUM,
                mitre_attack=["TA0043/T1589.001"],
                target=dc_ip,
            )

        return self._make_result(start)

    async def _enumerate(
        self, usernames: list[str], domain: str, dc_ip: str
    ) -> list[str]:
        """Enumerate valid users via Kerberos AS-REQ."""
        valid: list[str] = []

        # Try kerbrute first
        import shutil
        kerbrute = shutil.which("kerbrute")
        if kerbrute:
            valid = await self._run_kerbrute(kerbrute, usernames, domain, dc_ip)
            if valid:
                return valid

        # Fallback: impacket AS-REQ
        for username in usernames[:100]:
            await self.rate_limit()
            result = await self._kerberos_probe(username, domain, dc_ip)
            if result == "valid":
                valid.append(username)
            elif result == "no_preauth":
                valid.append(username)
                self.config.extra.setdefault("asrep_accounts", []).append(username)

        return valid

    async def _run_kerbrute(
        self, kerbrute: str, usernames: list[str], domain: str, dc_ip: str
    ) -> list[str]:
        import tempfile, os
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("\n".join(usernames))
            userlist_path = f.name

        valid: list[str] = []
        try:
            proc = await asyncio.create_subprocess_exec(
                kerbrute, "userenum",
                "-d", domain, "--dc", dc_ip,
                "--output", "/dev/null",
                userlist_path,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=120)
            for line in stdout.decode().splitlines():
                if "VALID USERNAME" in line or "VALID" in line:
                    import re
                    m = re.search(r"(\S+@\S+|\S+)", line)
                    if m:
                        user = m.group(1).split("@")[0]
                        valid.append(user)
        except Exception:
            pass
        finally:
            try:
                os.unlink(userlist_path)
            except Exception:
                pass
        return valid

    async def _kerberos_probe(
        self, username: str, domain: str, dc_ip: str
    ) -> str:
        """Probe Kerberos and interpret error code."""
        try:
            from impacket.krb5.kerberosv5 import getKerberosTGT
            from impacket.krb5 import constants
            from impacket.krb5.types import Principal
            from impacket.krb5.kerberosv5 import SessionKeyDecryptionError
            from pyasn1.error import SubstrateUnderrunError

            user_principal = Principal(
                username, type=constants.PrincipalNameType.NT_PRINCIPAL.value
            )
            getKerberosTGT(user_principal, "INVALID_PASSWORD_FORGE_777", domain, "", "", "", dc_ip)
            return "valid"
        except Exception as exc:
            msg = str(exc).lower()
            if "client not found" in msg or "never existed" in msg:
                return "invalid"
            elif "preauthentication failed" in msg or "wrong password" in msg:
                return "valid"
            elif "no pre-auth" in msg or "notpreauthent" in msg:
                return "no_preauth"
            return "error"

    def _load_usernames(self) -> list[str]:
        wl_path = Path(__file__).parent.parent.parent / "data" / "wordlists" / "usernames.txt"
        if wl_path.exists():
            return [l.strip() for l in wl_path.read_text().splitlines()
                    if l.strip() and not l.startswith("#")]
        return [
            "administrator", "admin", "guest", "test", "service",
            "svc_sql", "svc_iis", "svc_exchange", "backup",
            "helpdesk", "support", "readonly",
        ]


class TestKerbUserEnum:
    def test_load_usernames_fallback(self) -> None:
        mod = KerbUserEnum.__new__(KerbUserEnum)
        mod.config = type("C", (), {"extra": {}})()
        users = mod._load_usernames()
        assert isinstance(users, list)
        assert len(users) > 0
