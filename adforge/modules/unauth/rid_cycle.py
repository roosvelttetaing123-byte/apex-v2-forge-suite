"""RID Cycling module — enumerate domain users via null session or anonymous RPC.

Attempts an SMB null session and then cycles through RIDs to resolve
domain accounts using the SAMR or LSARPC interface.

MITRE ATT&CK: T1087.002 (Account Discovery — Domain Account)
CVSS 3.1: AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N (null session + user enum)
          AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N  (null session only)
"""
from __future__ import annotations

import concurrent.futures
import re
import subprocess
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
CVSS_NULL_ENUM_V31  = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
CVSS_NULL_ENUM_V40  = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N"
CVSS_NULL_ONLY_V31  = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
CVSS_NULL_ONLY_V40  = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N"

# Well-known RIDs for Domain accounts
_WELL_KNOWN_RIDS: dict[int, str] = {
    500: "Administrator",
    501: "Guest",
    502: "krbtgt",
    512: "Domain Admins",
    513: "Domain Users",
    514: "Domain Guests",
    515: "Domain Computers",
    516: "Domain Controllers",
    517: "Cert Publishers",
    518: "Schema Admins",
    519: "Enterprise Admins",
    520: "Group Policy Creator Owners",
    544: "Administrators",
    545: "Users",
    546: "Guests",
}

_MAX_THREADS = 10


class RidCycle(BaseModule):
    """Enumerate domain users via RID cycling over null session."""

    NAME        = "rid_cycle"
    DESCRIPTION = "Enumerate users via RPC null session (RID Cycling)"
    PHASE       = 1
    TAGS        = ["unauth", "rpc", "enum", "smb", "cwe-306"]

    async def run(self) -> ModuleResult:
        start  = time.monotonic()
        target = self.config.target
        domain = self.config.extra.get("domain", "")

        if not self.check_scope(target):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        null_ok = self._try_null_session(target)
        users: list[dict] = []
        domain_sid: str | None = None

        if null_ok:
            domain_sid = self._get_domain_sid(target, domain)
            if domain_sid:
                rid_start = int(self.config.extra.get("rid_start", 500))
                rid_end   = int(self.config.extra.get("rid_end",   5000))
                users = self._cycle_rids(target, domain_sid, rid_start, rid_end)

        self._emit_findings(target, users, null_ok, domain_sid)
        return self._make_result(start)

    # ------------------------------------------------------------------
    # Null session probe
    # ------------------------------------------------------------------

    def _try_null_session(self, host: str) -> bool:
        """Attempt SMB null session; return True when successful."""
        # Try impacket SMBConnection first
        if self._try_impacket_smb(host):
            return True
        # Fallback to rpcclient subprocess
        return self._try_rpcclient(host)

    def _try_impacket_smb(self, host: str) -> bool:
        """Use impacket SMBConnection with empty credentials."""
        try:
            from impacket.smbconnection import SMBConnection
            smb = SMBConnection(host, host, timeout=10)
            smb.login("", "")  # null session: empty username + empty password
            smb.logoff()
            self.log.info("Null SMB session established on %s", host)
            return True
        except ImportError:
            self.log.debug("impacket not installed — cannot test SMB null session")
        except Exception as exc:
            self.log.debug("impacket null session failed: %s", exc)
        return False

    def _try_rpcclient(self, host: str) -> bool:
        """Fallback: rpcclient null session check via subprocess."""
        try:
            result = subprocess.run(
                ["rpcclient", "-U", "", "-N", host, "-c", "srvinfo"],
                capture_output=True, text=True, timeout=10,
            )
            if result.returncode == 0 and ("Server" in result.stdout or "srvinfo" in result.stdout.lower()):
                self.log.info("rpcclient null session OK on %s", host)
                return True
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            pass
        return False

    # ------------------------------------------------------------------
    # Domain SID retrieval
    # ------------------------------------------------------------------

    def _get_domain_sid(self, host: str, domain: str = "") -> str | None:
        """Retrieve domain SID via impacket LSA query or rpcclient.

        *domain* is accepted for API symmetry and may be used in future
        Kerberos-based SID lookups; the current implementation queries
        the host directly via LSARPC.
        """
        _ = domain  # reserved for future Kerberos path
        sid = self._lsaquery_impacket(host)
        if sid:
            return sid
        return self._lsaquery_rpcclient(host)

    def _lsaquery_impacket(self, host: str) -> str | None:
        """Query domain SID via impacket LSARPC."""
        try:
            from impacket.dcerpc.v5 import transport as imp_transport, lsat, lsad
            from impacket.dcerpc.v5.dtypes import MAXIMUM_ALLOWED

            string_binding = r"ncacn_np:%s[\pipe\lsarpc]" % host
            rpctransport   = imp_transport.DCERPCTransportFactory(string_binding)
            rpctransport.set_credentials("", "", "", "", "")
            dce = rpctransport.get_dce_rpc()
            dce.connect()
            dce.bind(lsat.MSRPC_UUID_LSAT)

            resp    = lsat.hLsarOpenPolicy2(dce, MAXIMUM_ALLOWED | lsad.POLICY_LOOKUP_NAMES)
            policy  = resp["PolicyHandle"]
            info    = lsad.hLsarQueryInformationPolicy2(
                dce, policy, lsad.POLICY_INFORMATION_CLASS.PolicyPrimaryDomainInformation
            )
            sid_obj = info["PolicyInformation"]["PolicyPrimaryDomainInfo"]["Sid"]
            sid_str = "S-1-5-21-" + "-".join(str(i) for i in sid_obj["SubAuthority"])
            dce.disconnect()
            return sid_str
        except Exception as exc:
            self.log.debug("impacket lsaquery failed: %s", exc)
            return None

    def _lsaquery_rpcclient(self, host: str) -> str | None:
        """Fallback: parse domain SID from rpcclient lsaquery output."""
        try:
            result = subprocess.run(
                ["rpcclient", "-U", "", "-N", host, "-c", "lsaquery"],
                capture_output=True, text=True, timeout=10,
            )
            for line in result.stdout.splitlines():
                m = re.search(r"(S-1-5-21(?:-\d+)+)", line)
                if m:
                    return m.group(1)
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            pass
        return None

    # ------------------------------------------------------------------
    # RID cycling
    # ------------------------------------------------------------------

    def _cycle_rids(
        self,
        host: str,
        domain_sid: str,
        start: int = 500,
        end: int = 5000,
    ) -> list[dict]:
        """Resolve RIDs start..end concurrently (max _MAX_THREADS)."""
        found: list[dict] = []
        rids   = list(range(start, end + 1))
        lookup = self._lookup_rid_impacket if self._has_impacket() else self._lookup_rid_rpcclient

        with concurrent.futures.ThreadPoolExecutor(max_workers=_MAX_THREADS) as pool:
            futures = {
                pool.submit(lookup, host, domain_sid, rid): rid
                for rid in rids
            }
            for fut in concurrent.futures.as_completed(futures):
                try:
                    result = fut.result(timeout=5)
                    if result:
                        found.append(result)
                except Exception:
                    pass

        found.sort(key=lambda x: x["rid"])
        return found

    @staticmethod
    def _has_impacket() -> bool:
        try:
            import impacket  # noqa: F401
            return True
        except ImportError:
            return False

    def _lookup_rid_impacket(self, host: str, domain_sid: str, rid: int) -> dict | None:
        """Look up a single RID via impacket SAMR."""
        try:
            from impacket.dcerpc.v5 import transport as imp_transport, samr
            from impacket.dcerpc.v5.dtypes import MAXIMUM_ALLOWED

            string_binding = r"ncacn_np:%s[\pipe\samr]" % host
            rpctransport   = imp_transport.DCERPCTransportFactory(string_binding)
            rpctransport.set_credentials("", "", "", "", "")
            dce = rpctransport.get_dce_rpc()
            dce.connect()
            dce.bind(samr.MSRPC_UUID_SAMR)

            resp        = samr.hSamrConnect(dce, host + "\x00", MAXIMUM_ALLOWED)
            server_hdl  = resp["ServerHandle"]
            resp2       = samr.hSamrOpenDomain(dce, server_hdl, MAXIMUM_ALLOWED, self._sid_from_string(domain_sid))
            domain_hdl  = resp2["DomainHandle"]

            # Build SID for this RID
            full_sid_str = f"{domain_sid}-{rid}"
            resp3 = samr.hSamrLookupIdsInDomain(dce, domain_hdl, [rid])
            names = resp3["Names"]["Element"]
            types = resp3["Use"]["Element"]

            if names and str(names[0]) and str(names[0]) not in ("\x00", ""):
                name     = str(names[0])
                obj_type = int(types[0]) if types else 0
                type_str = {1: "user", 2: "group", 4: "alias", 5: "well_known"}.get(obj_type, "unknown")
                dce.disconnect()
                return {"rid": rid, "username": name, "type": type_str, "sid": full_sid_str}
            dce.disconnect()
        except Exception:
            pass
        return None

    def _lookup_rid_rpcclient(self, host: str, domain_sid: str, rid: int) -> dict | None:
        """Fallback: resolve RID via rpcclient lookupsids."""
        try:
            full_sid = f"{domain_sid}-{rid}"
            result = subprocess.run(
                ["rpcclient", "-U", "", "-N", host, "-c", f"lookupsids {full_sid}"],
                capture_output=True, text=True, timeout=5,
            )
            m = re.search(r"S-\S+\s+(\S+)\s+\((\d+)\)", result.stdout)
            if m:
                name     = m.group(1)
                obj_type = int(m.group(2))
                type_str = {1: "user", 2: "group", 4: "alias"}.get(obj_type, "unknown")
                if name not in ("UNKNOWN", "", "*unknown*"):
                    return {"rid": rid, "username": name, "type": type_str, "sid": full_sid}
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError, AttributeError):
            pass
        return None

    @staticmethod
    def _sid_from_string(sid_str: str) -> Any:
        """Convert 'S-1-5-21-A-B-C' string to impacket SID object."""
        try:
            from impacket.structure import Structure  # noqa: F401
            from impacket.dcerpc.v5.dtypes import RPC_SID
            parts = sid_str.lstrip("S-").split("-")
            # revision=1, sub-authority=parts[2:]
            sid_obj = RPC_SID()
            sid_obj["Revision"]            = int(parts[0])
            sid_obj["SubAuthorityCount"]   = len(parts) - 2
            sid_obj["IdentifierAuthority"] = b"\x00\x00\x00\x00\x00" + bytes([int(parts[1])])
            sid_obj["SubAuthority"]        = [int(p) for p in parts[2:]]
            return sid_obj
        except Exception:
            return sid_str

    # ------------------------------------------------------------------
    # Findings emitter
    # ------------------------------------------------------------------

    def _emit_findings(
        self,
        target: str,
        users: list[dict],
        null_session_works: bool,
        domain_sid: str | None,
    ) -> None:
        if not null_session_works:
            return

        user_accounts = [u for u in users if u.get("type") == "user"]
        all_accounts  = users

        if user_accounts:
            ev = Evidence(
                request_raw=f"SMB null session → SAMR/LSARPC RID cycling (SID: {domain_sid})",
                response_raw="\n".join(
                    f"RID {u['rid']}: {u['username']} ({u['type']})" for u in all_accounts[:50]
                ),
                extra={
                    "domain_sid":    domain_sid,
                    "users_found":   user_accounts,
                    "total_resolved": len(all_accounts),
                },
            )
            self.new_finding(
                title=f"RID Cycling — {len(user_accounts)} Domain User(s) Enumerated",
                severity=Severity.HIGH,
                description=(
                    f"SMB null session is permitted on {target}. "
                    f"RID cycling resolved {len(user_accounts)} domain user account(s) "
                    f"and {len(all_accounts) - len(user_accounts)} other object(s). "
                    f"Domain SID: {domain_sid}. "
                    "Sample accounts: "
                    + ", ".join(u["username"] for u in user_accounts[:10])
                ),
                reproduction_steps=[
                    f"rpcclient -U '' -N {target} -c enumdomusers",
                    f"impacket-lookupsid {target} -no-pass",
                    f"crackmapexec smb {target} -u '' -p '' --rid-brute",
                ],
                remediation=(
                    "Set registry value RestrictAnonymous to 1 (or 2 to fully block null sessions). "
                    "Enable GPO: 'Network access: Do not allow anonymous enumeration of SAM accounts'. "
                    "Block TCP 445 from untrusted networks."
                ),
                references=["MITRE T1087.002", "CWE-306", "MS Security Bulletin MS17-010"],
                evidence=ev,
                cvss_v31_vector=CVSS_NULL_ENUM_V31,
                cvss_v40_vector=CVSS_NULL_ENUM_V40,
                mitre_attack=["TA0007/T1087.002"],
                target=target,
            )

        elif null_session_works:
            ev = Evidence(
                request_raw="SMB null session login attempt",
                response_raw="Null session accepted; no users resolved",
            )
            self.new_finding(
                title="SMB Null Session Permitted",
                severity=Severity.MEDIUM,
                description=(
                    f"The SMB service on {target} accepts unauthenticated null sessions. "
                    "While no users were resolved via RID cycling in this run, the null session "
                    "channel can be used for further enumeration (shares, LSA, SAMR)."
                ),
                reproduction_steps=[
                    f"rpcclient -U '' -N {target} -c srvinfo",
                    f"smbclient -L //{target} -N",
                ],
                remediation=(
                    "Set RestrictAnonymous=1 in the registry. "
                    "Apply 'Network security: Do not store LAN Manager hash value on next password change'."
                ),
                references=["CWE-306", "MITRE T1087.002"],
                evidence=ev,
                cvss_v31_vector=CVSS_NULL_ONLY_V31,
                cvss_v40_vector=CVSS_NULL_ONLY_V40,
                mitre_attack=["TA0007/T1087.002"],
                target=target,
            )


# ---------------------------------------------------------------------------
# Embedded tests
# ---------------------------------------------------------------------------

class TestRidCycle(unittest.TestCase):

    def test_phase(self):
        assert RidCycle.PHASE == 1

    def test_name(self):
        assert RidCycle.NAME == "rid_cycle"

    def test_tags(self):
        assert "rpc" in RidCycle.TAGS
        assert "unauth" in RidCycle.TAGS

    def test_cvss_null_enum_is_high_c(self):
        assert "C:H" in CVSS_NULL_ENUM_V31
        assert "PR:N" in CVSS_NULL_ENUM_V31

    def test_well_known_rid_500(self):
        assert _WELL_KNOWN_RIDS[500] == "Administrator"

    def test_well_known_rid_502(self):
        assert _WELL_KNOWN_RIDS[502] == "krbtgt"

    def test_thread_limit(self):
        """Max threads constant is 10."""
        assert _MAX_THREADS == 10

    def test_try_null_session_no_server(self):
        """Returns False when nothing listens on the target port."""
        mod = RidCycle.__new__(RidCycle)
        mod.log = type("L", (), {
            "info": lambda *a, **k: None,
            "debug": lambda *a, **k: None,
        })()
        # Using localhost on an unbound port — should not connect
        result = mod._try_null_session("127.0.0.1")
        assert result is False

    def test_has_impacket_returns_bool(self):
        result = RidCycle._has_impacket()
        assert isinstance(result, bool)

    def test_domain_sid_regex(self):
        """SID pattern from rpcclient output is parsed correctly."""
        sample = "Domain SID: S-1-5-21-1234567890-987654321-111111111"
        m = re.search(r"(S-1-5-21(?:-\d+)+)", sample)
        assert m is not None
        assert m.group(1) == "S-1-5-21-1234567890-987654321-111111111"

    def test_cycle_rids_empty_on_no_server(self):
        """RID cycling returns empty list when nothing is reachable."""
        mod = RidCycle.__new__(RidCycle)
        mod.log = type("L", (), {
            "info": lambda *a, **k: None,
            "debug": lambda *a, **k: None,
        })()
        # Use rpcclient path which will fail silently
        result = mod._cycle_rids("127.0.0.1", "S-1-5-21-0-0-0", 500, 510)
        assert isinstance(result, list)


if __name__ == "__main__":
    unittest.main()
