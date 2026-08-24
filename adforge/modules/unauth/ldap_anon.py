"""LDAP Anon module — anonymous LDAP enumeration.

Probes a target LDAP service for:
- Anonymous bind (unauthenticated access)
- rootDSE information disclosure
- Domain-object enumeration when anonymous bind permits it
- Null base-DN misconfiguration

MITRE ATT&CK: T1018 (Remote System Discovery)
CVSS 3.1: AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N (full enum)
          AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N (rootDSE only)
"""
from __future__ import annotations

import socket
import sys
import time
import unittest
from pathlib import Path
from typing import Any
from unittest import mock

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity

# ---------------------------------------------------------------------------
# CVSS vectors
# ---------------------------------------------------------------------------
CVSS_FULL_ENUM_V31  = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
CVSS_FULL_ENUM_V40  = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N"
CVSS_ROOTDSE_V31    = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
CVSS_ROOTDSE_V40    = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N"
CVSS_PORT_OPEN_V31  = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"
CVSS_PORT_OPEN_V40  = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N"

# rootDSE attributes that reveal sensitive environment details
_SENSITIVE_ROOTDSE_ATTRS = {
    "dnsHostName",
    "ldapServiceName",
    "serverName",
    "defaultNamingContext",
    "rootDomainNamingContext",
    "namingContexts",
    "supportedSASLMechanisms",
    "domainFunctionality",
    "forestFunctionality",
    "domainControllerFunctionality",
}


def _close_ldap_connection(connection: Any | None, logger: Any) -> None:
    """Idempotently close ldap3 state, including sockets retained after failed open."""

    if connection is None:
        return
    raw_socket = None
    try:
        raw_socket = getattr(connection, "socket", None)
    except Exception as exc:
        try:
            logger.debug("LDAP cleanup could not inspect the retained socket: %s", exc)
        except Exception:
            pass
    try:
        connection.unbind()
    except Exception as exc:
        try:
            logger.debug("LDAP unbind cleanup failed: %s", exc)
        except Exception:
            pass
    if raw_socket is not None:
        try:
            raw_socket.close()
        except Exception as exc:
            try:
                logger.debug("LDAP raw-socket cleanup failed: %s", exc)
            except Exception:
                pass


class LdapAnon(BaseModule):
    """Check for LDAP anonymous bind and enumerate available information."""

    NAME        = "ldap_anon"
    DESCRIPTION = "Anonymous LDAP bind, rootDSE enumeration, and domain object enumeration"
    PHASE       = 1
    TAGS        = ["unauth", "ldap", "recon", "cwe-284"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        target = self.config.target
        port   = int(self.config.extra.get("ldap_port", 389))

        if not self.check_scope(target):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        try:
            import ldap3
        except ImportError:
            self.log.warning("ldap3 is not installed — skipping ldap_anon module")
            return self._make_result(start, skipped=True, skip_reason="ldap3 missing")

        # Check port reachability first (fast fail)
        if not self._port_open(target, port):
            self.log.debug("LDAP port %d not open on %s", port, target)
            return self._make_result(start)

        anon_allowed = self._try_anonymous_bind(target, port)
        rootdse: dict[str, Any] = {}
        null_base = False
        users: list[dict] = []
        base_dn = ""

        if anon_allowed:
            rootdse = self._enum_rootdse(target, port)
            null_base = self._detect_null_base(target, port)
            base_dn = rootdse.get("defaultNamingContext", "")
            if base_dn:
                users = self._enum_domain_info(target, base_dn, port)

        self._emit_findings(target, rootdse, anon_allowed, users, null_base)
        return self._make_result(start)

    # ------------------------------------------------------------------
    # Core probes
    # ------------------------------------------------------------------

    def _port_open(self, host: str, port: int, timeout: float = 3.0) -> bool:
        """Return True when the TCP port is reachable."""
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return True
        except OSError:
            return False

    def _try_anonymous_bind(self, host: str, port: int = 389) -> bool:
        """Attempt an anonymous LDAP bind; return True if rootDSE is readable."""
        conn: Any | None = None
        try:
            import ldap3
            server = ldap3.Server(host, port=port, get_info=ldap3.NONE, connect_timeout=5)
            conn   = ldap3.Connection(
                server,
                authentication=ldap3.ANONYMOUS,
                raise_exceptions=False,
                receive_timeout=8,
            )
            if not conn.bind():
                return False
            # Verify we can actually read something
            conn.search(
                search_base="",
                search_filter="(objectclass=*)",
                search_scope=ldap3.BASE,
                attributes=["namingContexts"],
            )
            readable = bool(conn.entries or conn.result.get("description") == "success")
            return readable
        except Exception as exc:
            self.log.debug("Anonymous bind probe failed: %s", exc)
            return False
        finally:
            _close_ldap_connection(conn, self.log)

    def _enum_rootdse(self, host: str, port: int = 389) -> dict[str, Any]:
        """Extract key rootDSE attributes from an anonymously bound connection."""
        result: dict[str, Any] = {}
        conn: Any | None = None
        try:
            import ldap3
            attrs = list(_SENSITIVE_ROOTDSE_ATTRS) + [
                "supportedLDAPVersion",
                "currentTime",
                "highestCommittedUSN",
                "configurationNamingContext",
                "schemaNamingContext",
            ]
            server = ldap3.Server(host, port=port, get_info=ldap3.ALL, connect_timeout=5)
            conn   = ldap3.Connection(
                server,
                authentication=ldap3.ANONYMOUS,
                raise_exceptions=False,
                receive_timeout=8,
            )
            conn.bind()
            conn.search(
                search_base="",
                search_filter="(objectclass=*)",
                search_scope=ldap3.BASE,
                attributes=attrs,
            )
            if conn.entries:
                entry = conn.entries[0]
                for attr in attrs:
                    try:
                        val = entry[attr].value
                        if val:
                            result[attr] = val
                    except Exception:
                        pass
            # Also harvest from server.info if available
            if server.info:
                info = server.info
                for k in ("naming_contexts", "alt_servers", "supported_ldap_versions"):
                    try:
                        val = getattr(info, k, None)
                        if val:
                            result[k] = val
                    except Exception:
                        pass
        except Exception as exc:
            self.log.debug("rootDSE enumeration failed: %s", exc)
        finally:
            _close_ldap_connection(conn, self.log)
        return result

    def _enum_domain_info(
        self, host: str, base_dn: str, port: int = 389
    ) -> list[dict]:
        """Enumerate users, groups, and computers via anonymous bind if permitted."""
        found: list[dict] = []
        conn: Any | None = None
        try:
            import ldap3
            server = ldap3.Server(host, port=port, get_info=ldap3.NONE, connect_timeout=5)
            conn   = ldap3.Connection(
                server,
                authentication=ldap3.ANONYMOUS,
                raise_exceptions=False,
                receive_timeout=10,
            )
            if not conn.bind():
                return found

            queries = [
                ("(&(objectClass=user)(objectCategory=person))",
                 ["sAMAccountName", "displayName", "mail", "userAccountControl"],
                 "user"),
                ("(objectClass=group)",
                 ["sAMAccountName", "member", "description"],
                 "group"),
                ("(objectClass=computer)",
                 ["sAMAccountName", "dNSHostName", "operatingSystem"],
                 "computer"),
            ]

            for ldap_filter, attrs, obj_type in queries:
                try:
                    conn.search(
                        search_base=base_dn,
                        search_filter=ldap_filter,
                        search_scope=ldap3.SUBTREE,
                        attributes=attrs,
                        size_limit=200,
                    )
                    for entry in conn.entries:
                        obj: dict[str, Any] = {"type": obj_type}
                        for attr in attrs:
                            try:
                                obj[attr] = entry[attr].value
                            except Exception:
                                pass
                        found.append(obj)
                except Exception as exc:
                    self.log.debug("Anonymous enum (%s) failed: %s", obj_type, exc)
        except Exception as exc:
            self.log.debug("Domain info enumeration error: %s", exc)
        finally:
            _close_ldap_connection(conn, self.log)
        return found

    def _detect_null_base(self, host: str, port: int = 389) -> bool:
        """Check whether a null/empty base-DN search returns data (misconfiguration)."""
        conn: Any | None = None
        try:
            import ldap3
            server = ldap3.Server(host, port=port, get_info=ldap3.NONE, connect_timeout=5)
            conn   = ldap3.Connection(
                server,
                authentication=ldap3.ANONYMOUS,
                raise_exceptions=False,
                receive_timeout=5,
            )
            if not conn.bind():
                return False
            conn.search(
                search_base="",
                search_filter="(objectClass=*)",
                search_scope=ldap3.SUBTREE,
                size_limit=5,
            )
            result = len(conn.entries) > 0
            return result
        except Exception as exc:
            self.log.debug("Null-base probe failed: %s", exc)
            return False
        finally:
            _close_ldap_connection(conn, self.log)

    # ------------------------------------------------------------------
    # Findings emitter
    # ------------------------------------------------------------------

    def _emit_findings(
        self,
        target: str,
        rootdse: dict,
        anon_allowed: bool,
        users: list[dict],
        null_base: bool,
    ) -> None:
        user_count    = sum(1 for u in users if u.get("type") == "user")
        group_count   = sum(1 for u in users if u.get("type") == "group")
        computer_count = sum(1 for u in users if u.get("type") == "computer")
        dns_host      = rootdse.get("dnsHostName") or rootdse.get("serverName", "")
        domain_fn     = rootdse.get("domainFunctionality", "")
        naming_ctx    = rootdse.get("defaultNamingContext") or rootdse.get("naming_contexts", "")

        if anon_allowed and users:
            # CRITICAL: full enumeration of domain objects possible
            ev = Evidence(
                request_raw="Anonymous LDAP bind + SUBTREE search",
                response_raw=(
                    f"Users: {user_count}, Groups: {group_count}, "
                    f"Computers: {computer_count}\n"
                    f"Base DN: {naming_ctx}\n"
                    f"DC hostname: {dns_host}"
                ),
                extra={
                    "user_count":    user_count,
                    "group_count":   group_count,
                    "computer_count": computer_count,
                    "rootdse":       rootdse,
                },
            )
            self.new_finding(
                title="Anonymous LDAP Bind — Full Domain Object Enumeration",
                severity=Severity.CRITICAL,
                description=(
                    f"The LDAP service on {target} allows anonymous bind AND permits "
                    f"full SUBTREE enumeration of domain objects. "
                    f"Discovered: {user_count} user(s), {group_count} group(s), "
                    f"{computer_count} computer(s) without credentials.\n"
                    f"Domain functional level: {domain_fn}\n"
                    f"DC hostname: {dns_host}"
                ),
                reproduction_steps=[
                    f"ldapsearch -x -H ldap://{target} -b '{naming_ctx}' '(objectClass=user)'",
                    f"ldapsearch -x -H ldap://{target} -b '{naming_ctx}' '(objectClass=group)'",
                    f"ldapsearch -x -H ldap://{target} -b '{naming_ctx}' '(objectClass=computer)'",
                ],
                remediation=(
                    "Disable anonymous LDAP access via DSHeuristics (bit 2 of the 7th character). "
                    "Apply KB2000705. Restrict anonymous LDAP queries via Group Policy "
                    "'Network access: Do not allow anonymous enumeration of SAM accounts and shares'."
                ),
                references=["CWE-284", "MS KB2000705", "MITRE T1018"],
                evidence=ev,
                cvss_v31_vector=CVSS_FULL_ENUM_V31,
                cvss_v40_vector=CVSS_FULL_ENUM_V40,
                mitre_attack=["TA0007/T1018"],
                target=target,
            )

        elif anon_allowed and rootdse:
            # HIGH: anonymous bind works, rootDSE reveals sensitive info
            sensitive_keys = _SENSITIVE_ROOTDSE_ATTRS.intersection(rootdse.keys())
            ev = Evidence(
                request_raw="Anonymous LDAP bind + rootDSE BASE search",
                response_raw="\n".join(f"{k}: {rootdse[k]}" for k in sensitive_keys),
                extra={"rootdse": rootdse},
            )
            self.new_finding(
                title="Anonymous LDAP Bind — rootDSE Information Disclosure",
                severity=Severity.HIGH,
                description=(
                    f"Anonymous LDAP bind succeeds on {target}. "
                    f"The rootDSE exposes {len(sensitive_keys)} sensitive attribute(s): "
                    f"{', '.join(sensitive_keys)}. "
                    f"DC hostname: {dns_host or 'unknown'}"
                ),
                reproduction_steps=[
                    f"ldapsearch -x -H ldap://{target} -s base -b '' '*'",
                ],
                remediation=(
                    "Restrict anonymous LDAP queries via DSHeuristics. "
                    "Ensure dsHeuristics bit 2 is set to 2 (block anonymous search) "
                    "on the Directory Service configuration object."
                ),
                references=["CWE-284", "MITRE T1018"],
                evidence=ev,
                cvss_v31_vector=CVSS_ROOTDSE_V31,
                cvss_v40_vector=CVSS_ROOTDSE_V40,
                mitre_attack=["TA0007/T1018"],
                target=target,
            )

        elif anon_allowed:
            # MEDIUM: bind works but little info returned
            ev = Evidence(
                request_raw="Anonymous LDAP bind (BASE)",
                response_raw="Bind succeeded; limited attributes returned",
            )
            self.new_finding(
                title="Anonymous LDAP Bind Permitted",
                severity=Severity.MEDIUM,
                description=(
                    f"The LDAP service on {target} permits anonymous binding, "
                    "though limited information was returned. This indicates a "
                    "misconfiguration that may allow further enumeration with different queries."
                ),
                reproduction_steps=[
                    f"ldapsearch -x -H ldap://{target} -s base -b ''",
                ],
                remediation="Disable anonymous LDAP access. Configure RestrictAnonymous=1.",
                references=["CWE-284"],
                evidence=ev,
                cvss_v31_vector=CVSS_ROOTDSE_V31,
                cvss_v40_vector=CVSS_ROOTDSE_V40,
                mitre_attack=["TA0007/T1018"],
                target=target,
            )

        if null_base and anon_allowed:
            ev2 = Evidence(
                request_raw="Anonymous LDAP SUBTREE search with empty base DN",
                response_raw="Entries returned from null base search",
            )
            self.new_finding(
                title="LDAP Null Base DN Search Allowed",
                severity=Severity.HIGH,
                description=(
                    f"The LDAP service on {target} returns data when queried with "
                    "an empty base DN and SUBTREE scope. This is a misconfiguration "
                    "that may expose the entire directory tree to unauthenticated callers."
                ),
                reproduction_steps=[
                    f"ldapsearch -x -H ldap://{target} -b '' -s sub '(objectClass=*)'",
                ],
                remediation="Configure proper base-DN access restrictions on the LDAP service.",
                references=["CWE-284"],
                evidence=ev2,
                cvss_v31_vector=CVSS_ROOTDSE_V31,
                cvss_v40_vector=CVSS_ROOTDSE_V40,
                target=target,
            )


# ---------------------------------------------------------------------------
# Embedded tests
# ---------------------------------------------------------------------------

class TestLdapAnon(unittest.TestCase):

    @staticmethod
    def _connection_probe(*, bind_result: bool = False) -> mock.MagicMock:
        connection = mock.MagicMock()
        connection.bind.return_value = bind_result
        connection.socket = mock.MagicMock()
        return connection

    def test_phase(self):
        assert LdapAnon.PHASE == 1

    def test_name(self):
        assert LdapAnon.NAME == "ldap_anon"

    def test_tags_include_ldap(self):
        assert "ldap" in LdapAnon.TAGS

    def test_cvss_full_enum_is_critical_av_n(self):
        assert "AV:N" in CVSS_FULL_ENUM_V31
        assert "PR:N" in CVSS_FULL_ENUM_V31
        assert "C:H"  in CVSS_FULL_ENUM_V31

    def test_cvss_rootdse_is_lower(self):
        # rootDSE-only CVSS should have C:L not C:H
        assert "C:L" in CVSS_ROOTDSE_V31

    def test_sensitive_attrs_set(self):
        assert "dnsHostName" in _SENSITIVE_ROOTDSE_ATTRS
        assert "defaultNamingContext" in _SENSITIVE_ROOTDSE_ATTRS
        assert "supportedSASLMechanisms" in _SENSITIVE_ROOTDSE_ATTRS

    def test_port_open_unreachable(self):
        """Port probe returns False for a port that is not open."""
        mod = LdapAnon.__new__(LdapAnon)
        mod.log = type("L", (), {"debug": lambda *a, **k: None})()
        result = mod._port_open("127.0.0.1", 19999, timeout=0.2)
        assert result is False

    def test_try_anonymous_bind_no_server(self):
        """Returns False when the host is unreachable."""
        mod = LdapAnon.__new__(LdapAnon)
        mod.log = type("L", (), {"debug": lambda *a, **k: None})()
        assert mod._try_anonymous_bind("127.0.0.1", 19999) is False
        connection = self._connection_probe(bind_result=False)
        with mock.patch("ldap3.Connection", return_value=connection):
            assert mod._try_anonymous_bind("127.0.0.1", 19999) is False
        connection.unbind.assert_called_once_with()
        connection.socket.close.assert_called_once_with()

    def test_detect_null_base_no_server(self):
        """Returns False when the host is unreachable."""
        mod = LdapAnon.__new__(LdapAnon)
        mod.log = type("L", (), {"debug": lambda *a, **k: None})()
        assert mod._detect_null_base("127.0.0.1", 19999) is False
        connection = self._connection_probe()
        connection.bind.side_effect = RuntimeError("fixture bind failure")
        connection.unbind.side_effect = RuntimeError("fixture unbind failure")
        connection.socket.close.side_effect = RuntimeError("fixture close failure")
        with mock.patch("ldap3.Connection", return_value=connection):
            assert mod._detect_null_base("127.0.0.1", 19999) is False
        connection.unbind.assert_called_once_with()
        connection.socket.close.assert_called_once_with()

    def test_enum_domain_info_no_server(self):
        """Returns empty list when the host is unreachable."""
        mod = LdapAnon.__new__(LdapAnon)
        mod.log = type("L", (), {"debug": lambda *a, **k: None})()
        result = mod._enum_domain_info("127.0.0.1", "DC=test,DC=local", port=19999)
        assert isinstance(result, list)
        assert len(result) == 0
        connection = self._connection_probe(bind_result=False)
        with mock.patch("ldap3.Connection", return_value=connection):
            result = mod._enum_domain_info("127.0.0.1", "DC=test,DC=local", port=19999)
        assert result == []
        connection.unbind.assert_called_once_with()
        connection.socket.close.assert_called_once_with()

    def test_enum_rootdse_no_server(self):
        """Returns empty dict when the host is unreachable."""
        mod = LdapAnon.__new__(LdapAnon)
        mod.log = type("L", (), {"debug": lambda *a, **k: None})()
        result = mod._enum_rootdse("127.0.0.1", port=19999)
        assert isinstance(result, dict)
        connection = self._connection_probe(bind_result=True)
        connection.search.side_effect = RuntimeError("fixture search failure")
        with mock.patch("ldap3.Connection", return_value=connection):
            result = mod._enum_rootdse("127.0.0.1", port=19999)
        assert result == {}
        connection.unbind.assert_called_once_with()
        connection.socket.close.assert_called_once_with()


if __name__ == "__main__":
    unittest.main()
