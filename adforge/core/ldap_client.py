"""ADForge LDAP client — enterprise LDAP connection with NTLM/PtH/Kerberos auth."""
from __future__ import annotations

import logging
from typing import Any

log = logging.getLogger("forge.adforge.ldap_client")

# Active Directory UAC flag bits
_UAC_ACCOUNTDISABLE    = 0x0002      # 2
_UAC_DONT_REQUIRE_PREAUTH = 0x400000  # 4194304
_UAC_TRUSTED_FOR_DELEGATION = 0x080000  # 524288
_UAC_NOT_DELEGATED      = 0x100000  # 1048576

# OID for Simple Paged Results control
_PAGED_RESULTS_OID = "1.2.840.113556.1.4.319"


class LdapClient:
    """Enterprise-grade LDAP client for ADForge modules.

    Supports anonymous, NTLM (plaintext), Pass-the-Hash, Kerberos/GSSAPI,
    and LDAPS (port 636) auth modes with automatic paged result handling.

    Example::

        with LdapClient("10.0.0.1", "corp.local", "Administrator", "P@ss") as lc:
            users = lc.get_users()
            kerberoastable = lc.get_kerberoastable()
    """

    def __init__(
        self,
        dc_ip: str,
        domain: str,
        username: str = "",
        password: str = "",
        nt_hash: str = "",
        use_kerberos: bool = False,
        use_ssl: bool = False,
        timeout: int = 10,
    ):
        """Initialise the client.

        Args:
            dc_ip:        IP or hostname of the domain controller.
            domain:       FQDN of the target domain, e.g. ``corp.local``.
            username:     sAMAccountName or UPN for authentication.
            password:     Plaintext password (ignored when nt_hash or use_kerberos set).
            nt_hash:      NT hash for Pass-the-Hash (format: ``aabbcc…`` 32 hex chars).
            use_kerberos: Use Kerberos/GSSAPI (requires valid ccache on the host).
            use_ssl:      Connect to LDAPS on port 636 instead of plain LDAP 389.
            timeout:      TCP connect / receive timeout in seconds.
        """
        self.dc_ip        = dc_ip
        self.domain       = domain
        self.username     = username
        self.password     = password
        self.nt_hash      = nt_hash
        self.use_kerberos = use_kerberos
        self.use_ssl      = use_ssl
        self.timeout      = timeout
        self._conn        = None
        self._base_dn     = self._make_base_dn(domain)

    # ── Helpers ──────────────────────────────────────────────────────────────

    def _make_base_dn(self, domain: str) -> str:
        """Convert FQDN to LDAP base DN, e.g. ``corp.local`` → ``DC=corp,DC=local``."""
        return ",".join(f"DC={p}" for p in domain.split("."))

    def _extract_value(self, entry: Any, attr: str) -> Any:
        """Safely extract an attribute value from an ldap3 entry."""
        try:
            val = getattr(entry, attr, None)
            if val is None:
                return None
            if hasattr(val, "value"):
                return val.value
            return str(val)
        except Exception:
            return None

    def _entry_to_dict(self, entry: Any, attributes: list[str]) -> dict[str, Any]:
        """Convert an ldap3 entry to a plain dict."""
        row: dict[str, Any] = {"dn": str(entry.entry_dn)}
        for attr in attributes:
            val = self._extract_value(entry, attr)
            if val is not None:
                row[attr] = val
        return row

    # ── Connection ───────────────────────────────────────────────────────────

    def connect(self) -> bool:
        """Establish an LDAP(S) connection.

        Auth priority order:
        1. Kerberos/GSSAPI  (when ``use_kerberos=True``)
        2. Pass-the-Hash    (when ``nt_hash`` is non-empty)
        3. NTLM cleartext   (when ``username`` is set)
        4. Anonymous bind

        Returns:
            ``True`` if the bind succeeded, ``False`` otherwise.
        """
        try:
            from ldap3 import Server, Connection, NTLM, ALL, ANONYMOUS, SASL, GSSAPI
            port = 636 if self.use_ssl else 389
            server = Server(
                self.dc_ip,
                port=port,
                use_ssl=self.use_ssl,
                get_info=ALL,
                connect_timeout=self.timeout,
            )

            if self.use_kerberos:
                # Kerberos/GSSAPI — requires kinit or valid CCACHE env var
                conn = Connection(
                    server,
                    authentication=SASL,
                    sasl_mechanism=GSSAPI,
                    raise_exceptions=False,
                    receive_timeout=self.timeout,
                )

            elif self.nt_hash:
                # Pass-the-Hash: supply DOMAIN\user with LM:NT hash as password
                # ldap3 accepts NTLM hash in the format "<lm>:<nt>"
                short_domain = self.domain.split(".")[0].upper()
                user = f"{short_domain}\\{self.username}"
                # Use empty LM hash when only NT hash provided
                nt_creds = f"aad3b435b51404eeaad3b435b51404ee:{self.nt_hash}"
                conn = Connection(
                    server,
                    user=user,
                    password=nt_creds,
                    authentication=NTLM,
                    raise_exceptions=False,
                    receive_timeout=self.timeout,
                )

            elif self.username:
                # Standard NTLM with plaintext password
                upn = (
                    f"{self.username}@{self.domain}"
                    if "@" not in self.username
                    else self.username
                )
                conn = Connection(
                    server,
                    user=upn,
                    password=self.password,
                    authentication=NTLM,
                    raise_exceptions=False,
                    receive_timeout=self.timeout,
                )

            else:
                conn = Connection(server, authentication=ANONYMOUS, raise_exceptions=False)

            result = conn.bind()
            if result:
                self._conn = conn
                log.debug("LDAP bind succeeded (%s)", self.dc_ip)
                return True
            log.debug("LDAP bind failed: %s", getattr(conn, "result", {}))
            return False

        except Exception as exc:
            log.debug("LDAP connect error for %s: %s", self.dc_ip, exc)
            return False

    def disconnect(self) -> None:
        """Unbind and close the LDAP connection."""
        if self._conn:
            try:
                self._conn.unbind()
            except Exception:
                pass
            self._conn = None

    # ── Search ───────────────────────────────────────────────────────────────

    def search(
        self,
        search_filter: str,
        attributes: list[str],
        base_dn: str | None = None,
        search_scope: str = "SUBTREE",
        controls: list | None = None,
    ) -> list[dict[str, Any]]:
        """Execute a single (non-paged) LDAP search.

        Returns:
            List of result dicts, each with a ``dn`` key plus the requested attrs.
        """
        if not self._conn:
            return []
        try:
            from ldap3 import SUBTREE, BASE, LEVEL
            _scope_map = {"SUBTREE": SUBTREE, "BASE": BASE, "LEVEL": LEVEL}
            scope = _scope_map.get(search_scope.upper(), SUBTREE)
            self._conn.search(
                search_base=base_dn or self._base_dn,
                search_filter=search_filter,
                attributes=attributes,
                search_scope=scope,
                controls=controls,
            )
            return [self._entry_to_dict(e, attributes) for e in self._conn.entries]
        except Exception as exc:
            log.debug("LDAP search error: %s", exc)
            return []

    def search_paged(
        self,
        search_filter: str,
        attributes: list[str],
        base_dn: str | None = None,
        page_size: int = 1000,
    ) -> list[dict[str, Any]]:
        """Execute a paged LDAP search, transparently retrieving all result pages.

        Uses ldap3's built-in ``paged_size`` / ``paged_cookie`` parameters
        (RFC 2696 Simple Paged Results Control, OID 1.2.840.113556.1.4.319).

        Args:
            search_filter: Standard LDAP filter string.
            attributes:    List of attribute names to retrieve.
            base_dn:       Search base; defaults to domain root DN.
            page_size:     Number of entries per page (default 1000).

        Returns:
            Flat list of all result dicts across all pages.
        """
        if not self._conn:
            return []

        results: list[dict[str, Any]] = []
        cookie: bytes | None = None

        try:
            from ldap3 import SUBTREE
        except Exception as exc:
            log.debug("ldap3 import error: %s", exc)
            return []

        while True:
            try:
                self._conn.search(
                    search_base=base_dn or self._base_dn,
                    search_filter=search_filter,
                    search_scope=SUBTREE,
                    attributes=attributes,
                    paged_size=page_size,
                    paged_cookie=cookie,
                )
                for entry in self._conn.entries:
                    results.append(self._entry_to_dict(entry, attributes))

                # Extract cookie for next page
                cookie = self._extract_paging_cookie()
                if not cookie:
                    break

            except Exception as exc:
                log.debug("Paged search page error: %s", exc)
                break

        return results

    def _extract_paging_cookie(self) -> bytes | None:
        """Extract the Simple Paged Results cookie from the last search response."""
        try:
            if not self._conn or not self._conn.result:
                return None
            controls = self._conn.result.get("controls") or {}
            paged_ctrl = controls.get(_PAGED_RESULTS_OID, {})
            cookie = (paged_ctrl.get("value") or {}).get("cookie")
            if cookie:
                return cookie
        except Exception:
            pass
        return None

    # ── Security detection ───────────────────────────────────────────────────

    def detect_signing(self) -> dict[str, bool]:
        """Probe the target DC for LDAP signing and channel binding requirements.

        Performs an unauthenticated bind and inspects the server's error code
        and advertised capabilities to determine enforcement status.

        Returns:
            ``{"ldap_signing_required": bool, "ldap_channel_binding": bool}``
        """
        result: dict[str, bool] = {
            "ldap_signing_required": False,
            "ldap_channel_binding": False,
        }
        try:
            from ldap3 import Server, Connection, ANONYMOUS, ALL
            server = Server(self.dc_ip, get_info=ALL, connect_timeout=self.timeout)
            conn = Connection(server, authentication=ANONYMOUS, raise_exceptions=False)
            bound = conn.bind()

            if not bound:
                # Error code 8 → strongAuthRequired (signing enforced)
                res = conn.result or {}
                if isinstance(res, dict) and res.get("result") == 8:
                    result["ldap_signing_required"] = True

            # OID 1.2.840.113556.1.4.1791 → LDAP_CAP_ACTIVE_DIRECTORY_LDAP_INTEG_OID
            # Presence indicates channel binding is supported / required
            try:
                if server.info and server.info.other:
                    caps = server.info.other.get("supportedCapabilities", [])
                    if "1.2.840.113556.1.4.1791" in str(caps):
                        result["ldap_channel_binding"] = True
            except Exception:
                pass

            try:
                conn.unbind()
            except Exception:
                pass

        except Exception as exc:
            log.debug("Signing detection error: %s", exc)

        return result

    # ── Query helpers — all use search_paged internally ──────────────────────

    def get_users(self, enabled_only: bool = True) -> list[dict[str, Any]]:
        """Enumerate domain user accounts.

        Args:
            enabled_only: When ``True`` (default), skip accounts with ACCOUNTDISABLE set.

        Returns:
            List of user entry dicts with common AD attributes.
        """
        attrs = [
            "sAMAccountName", "distinguishedName", "userAccountControl",
            "adminCount", "pwdLastSet", "lastLogon", "memberOf",
            "servicePrincipalName", "description",
        ]
        if enabled_only:
            # Bit-AND filter: exclude bit 0x2 (ACCOUNTDISABLE)
            ldap_filter = (
                "(&(objectClass=user)"
                "(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
            )
        else:
            ldap_filter = "(objectClass=user)"
        return self.search_paged(ldap_filter, attrs)

    def get_computers(self) -> list[dict[str, Any]]:
        """Enumerate all computer accounts in the domain.

        Returns:
            List of computer entry dicts including OS and connectivity details.
        """
        attrs = [
            "name", "distinguishedName", "operatingSystem",
            "operatingSystemVersion", "dNSHostName",
            "userAccountControl", "lastLogon",
        ]
        return self.search_paged("(objectClass=computer)", attrs)

    def get_groups(self, privileged_only: bool = False) -> list[dict[str, Any]]:
        """Enumerate domain groups.

        Args:
            privileged_only: When ``True``, restrict to groups with ``adminCount=1``
                             (i.e., groups that have been granted privileged ACLs via
                             AdminSDHolder).

        Returns:
            List of group entry dicts.
        """
        attrs = [
            "sAMAccountName", "distinguishedName", "member",
            "memberOf", "adminCount", "description", "groupType",
        ]
        if privileged_only:
            ldap_filter = "(&(objectClass=group)(adminCount=1))"
        else:
            ldap_filter = "(objectClass=group)"
        return self.search_paged(ldap_filter, attrs)

    def get_kerberoastable(self) -> list[dict[str, Any]]:
        """Return user accounts that are Kerberoastable.

        A user is Kerberoastable when:
        - ``servicePrincipalName`` is populated (has at least one SPN), AND
        - ``ACCOUNTDISABLE`` is NOT set in ``userAccountControl``, AND
        - The account is a user (not a computer).

        Returns:
            List of Kerberoastable user entry dicts.
        """
        attrs = [
            "sAMAccountName", "servicePrincipalName", "distinguishedName",
            "userAccountControl", "pwdLastSet", "adminCount",
        ]
        # Server-side filter: users with SPNs who are not disabled
        ldap_filter = (
            "(&(objectClass=user)"
            "(servicePrincipalName=*)"
            "(!(userAccountControl:1.2.840.113556.1.4.803:=2))"
            "(!(objectClass=computer)))"
        )
        entries = self.search_paged(ldap_filter, attrs)
        # Secondary client-side filter to catch any stragglers
        return [
            e for e in entries
            if not (int(e.get("userAccountControl") or 0) & _UAC_ACCOUNTDISABLE)
        ]

    def get_asrep_candidates(self) -> list[dict[str, Any]]:
        """Return accounts vulnerable to AS-REP Roasting.

        Accounts with the ``DONT_REQUIRE_PREAUTH`` bit (0x400000 / 4194304) set
        in ``userAccountControl`` can be targeted for AS-REP Roasting without
        valid credentials.

        Returns:
            List of user entry dicts with the DONT_REQUIRE_PREAUTH flag.
        """
        attrs = [
            "sAMAccountName", "distinguishedName", "userAccountControl",
            "adminCount", "pwdLastSet", "lastLogon",
        ]
        # Bit-AND filter for DONT_REQUIRE_PREAUTH (4194304)
        ldap_filter = (
            "(&(objectClass=user)"
            "(userAccountControl:1.2.840.113556.1.4.803:=4194304))"
        )
        entries = self.search_paged(ldap_filter, attrs)
        # Client-side verification
        return [
            e for e in entries
            if int(e.get("userAccountControl") or 0) & _UAC_DONT_REQUIRE_PREAUTH
        ]

    def get_spns(self) -> list[dict[str, Any]]:
        """Return all user accounts that have registered SPNs.

        Returns:
            List of dicts with ``sAMAccountName`` and ``servicePrincipalName``.
        """
        attrs = ["sAMAccountName", "servicePrincipalName"]
        return self.search_paged("(&(objectClass=user)(servicePrincipalName=*))", attrs)

    def get_dacl_for(self, dn: str) -> bytes | None:
        """Retrieve the raw ``nTSecurityDescriptor`` (DACL blob) for a given DN.

        Requires the connection to be authenticated and the account to have
        read access to the security descriptor.

        Args:
            dn: Distinguished name of the target object.

        Returns:
            Raw bytes of the security descriptor, or ``None`` on failure.
        """
        if not self._conn:
            return None
        try:
            from ldap3 import BASE
            self._conn.search(
                search_base=dn,
                search_filter="(objectClass=*)",
                search_scope=BASE,
                attributes=["nTSecurityDescriptor"],
            )
            if self._conn.entries:
                entry = self._conn.entries[0]
                sd_attr = getattr(entry, "nTSecurityDescriptor", None)
                if sd_attr is not None and hasattr(sd_attr, "raw_values"):
                    raws = sd_attr.raw_values
                    if raws:
                        return raws[0]
        except Exception as exc:
            log.debug("DACL fetch error for %s: %s", dn, exc)
        return None

    def get_adcs_templates(self) -> list[dict[str, Any]]:
        """Enumerate ADCS certificate templates for ESC vulnerability analysis.

        Searches ``CN=Certificate Templates,CN=Public Key Services,
        CN=Services,CN=Configuration,<base_dn>``.

        Returns:
            List of certificate template dicts.  Key attributes include
            ``msPKI-Certificate-Name-Flag`` (ESC1 flag) and
            ``msPKI-Enrollment-Flag`` (manager approval bypass).
        """
        config_dn = (
            f"CN=Certificate Templates,CN=Public Key Services,"
            f"CN=Services,CN=Configuration,{self._base_dn}"
        )
        attrs = [
            "cn", "displayName",
            "msPKI-Certificate-Name-Flag",
            "msPKI-Enrollment-Flag",
            "msPKI-RA-Signature",
            "pkiExtendedKeyUsage",
            "nTSecurityDescriptor",
            "msPKI-Certificate-Application-Policy",
        ]
        return self.search_paged(
            "(objectClass=pKICertificateTemplate)", attrs, base_dn=config_dn
        )

    def get_domain_trusts(self) -> list[dict[str, Any]]:
        """Enumerate domain trusts for lateral-movement analysis.

        Returns:
            List of trust entry dicts.  ``trustType`` values:
            1=Win-NT, 2=AD, 3=MIT Kerberos.  ``trustDirection``
            values: 1=inbound, 2=outbound, 3=bidirectional.
        """
        attrs = [
            "cn", "trustType", "trustAttributes",
            "trustDirection", "flatName", "distinguishedName",
            "securityIdentifier",
        ]
        return self.search_paged("(objectClass=trustedDomain)", attrs)

    def get_password_policy(self) -> dict[str, Any]:
        """Retrieve the default domain password and lockout policy.

        Returns:
            Dict with policy attributes, or empty dict when not connected.
        """
        attrs = [
            "minPwdLength", "lockoutThreshold",
            "lockoutObservationWindow", "maxPwdAge",
            "ms-DS-MachineAccountQuota", "pwdHistoryLength",
            "minPwdAge", "lockoutDuration",
        ]
        entries = self.search_paged("(objectClass=domainDNS)", attrs)
        return entries[0] if entries else {}

    def get_domain_info(self) -> dict[str, Any]:
        """Retrieve basic domain information from the domain root object.

        Returns:
            Dict with domain-level attributes, or empty dict on failure.
        """
        entries = self.search(
            "(objectClass=domain)",
            [
                "name", "dc", "lockoutThreshold", "lockoutObservationWindow",
                "minPwdLength", "pwdHistoryLength", "maxPwdAge",
                "ms-DS-MachineAccountQuota",
            ],
        )
        return entries[0] if entries else {}

    # ── Context manager ──────────────────────────────────────────────────────

    def __enter__(self) -> "LdapClient":
        self.connect()
        return self

    def __exit__(self, *args: Any) -> None:
        self.disconnect()

    def __repr__(self) -> str:
        status = "connected" if self._conn else "disconnected"
        return (
            f"<LdapClient dc={self.dc_ip!r} domain={self.domain!r} "
            f"ssl={self.use_ssl} {status}>"
        )


# ── Embedded test suite ──────────────────────────────────────────────────────

class TestLdapClient:
    """Pytest-compatible tests for LdapClient.  Run with::

        python -m pytest adforge/core/ldap_client.py -q
    """

    # ── Base DN construction ──────────────────────────────────────────────

    def test_make_base_dn(self) -> None:
        client = LdapClient.__new__(LdapClient)
        dn = client._make_base_dn("corp.local")
        assert dn == "DC=corp,DC=local"

    def test_make_base_dn_three_levels(self) -> None:
        client = LdapClient.__new__(LdapClient)
        dn = client._make_base_dn("sub.corp.local")
        assert dn == "DC=sub,DC=corp,DC=local"

    def test_make_base_dn_single_label(self) -> None:
        client = LdapClient.__new__(LdapClient)
        assert client._make_base_dn("local") == "DC=local"

    # ── Query helpers return [] when _conn is None ────────────────────────

    def _unconnected(self) -> LdapClient:
        """Return a LdapClient with no active connection."""
        c = LdapClient.__new__(LdapClient)
        c._conn = None
        c._base_dn = "DC=corp,DC=local"
        c.domain = "corp.local"
        c.dc_ip = "127.0.0.2"
        c.timeout = 1
        c.log = log
        return c

    def test_search_empty_when_not_connected(self) -> None:
        c = self._unconnected()
        assert c.search("(objectClass=user)", ["sAMAccountName"]) == []

    def test_paged_search_empty_when_not_connected(self) -> None:
        c = self._unconnected()
        assert c.search_paged("(objectClass=user)", ["sAMAccountName"]) == []

    def test_get_users_empty_when_not_connected(self) -> None:
        assert self._unconnected().get_users() == []

    def test_get_computers_empty_when_not_connected(self) -> None:
        assert self._unconnected().get_computers() == []

    def test_get_groups_empty_when_not_connected(self) -> None:
        assert self._unconnected().get_groups() == []

    def test_get_kerberoastable_empty_when_not_connected(self) -> None:
        assert self._unconnected().get_kerberoastable() == []

    def test_get_asrep_candidates_empty_when_not_connected(self) -> None:
        assert self._unconnected().get_asrep_candidates() == []

    def test_get_spns_empty_when_not_connected(self) -> None:
        assert self._unconnected().get_spns() == []

    def test_get_password_policy_empty_when_not_connected(self) -> None:
        assert self._unconnected().get_password_policy() == {}

    # ── DACL lookup returns None when not connected ───────────────────────

    def test_dacl_lookup_returns_none_when_not_connected(self) -> None:
        c = self._unconnected()
        result = c.get_dacl_for("CN=Administrator,CN=Users,DC=corp,DC=local")
        assert result is None

    # ── Kerberoastable filtering logic ────────────────────────────────────

    def test_kerberoastable_excludes_disabled_accounts(self) -> None:
        from unittest.mock import patch

        disabled = {"sAMAccountName": "svc_off", "userAccountControl": 2, "dn": "CN=x"}
        enabled  = {"sAMAccountName": "svc_on",  "userAccountControl": 512, "dn": "CN=y"}

        c = self._unconnected()
        c._conn = object()  # pretend connected so search_paged is called

        with patch.object(c, "search_paged", return_value=[disabled, enabled]):
            result = c.get_kerberoastable()

        assert len(result) == 1
        assert result[0]["sAMAccountName"] == "svc_on"

    def test_kerberoastable_includes_account_with_uac_512(self) -> None:
        from unittest.mock import patch

        normal_svc = {"sAMAccountName": "svc_http", "userAccountControl": 512, "dn": "CN=z"}
        c = self._unconnected()
        c._conn = object()

        with patch.object(c, "search_paged", return_value=[normal_svc]):
            result = c.get_kerberoastable()

        assert result == [normal_svc]

    # ── AS-REP roasting flag detection ────────────────────────────────────

    def test_asrep_candidates_detects_4194304_flag(self) -> None:
        from unittest.mock import patch

        asrep   = {"sAMAccountName": "jdoe", "userAccountControl": 4194304, "dn": "CN=jdoe"}
        normal  = {"sAMAccountName": "jane", "userAccountControl": 512,     "dn": "CN=jane"}
        c = self._unconnected()
        c._conn = object()

        with patch.object(c, "search_paged", return_value=[asrep, normal]):
            result = c.get_asrep_candidates()

        assert len(result) == 1
        assert result[0]["sAMAccountName"] == "jdoe"

    def test_asrep_candidates_combined_uac_flag(self) -> None:
        from unittest.mock import patch

        # 4194304 + 512 = 4194816 — DONT_REQUIRE_PREAUTH plus NORMAL_ACCOUNT
        combined = {"sAMAccountName": "combo", "userAccountControl": 4194816, "dn": "CN=c"}
        c = self._unconnected()
        c._conn = object()

        with patch.object(c, "search_paged", return_value=[combined]):
            result = c.get_asrep_candidates()

        assert len(result) == 1

    # ── Paged search returns flat list ────────────────────────────────────

    def test_paged_search_returns_flat_list(self) -> None:
        from unittest.mock import MagicMock

        mock_entry = MagicMock()
        mock_entry.entry_dn = "CN=jdoe,DC=corp,DC=local"
        mock_entry.sAMAccountName.value = "jdoe"

        mock_conn = MagicMock()
        mock_conn.entries = [mock_entry]
        mock_conn.result = {}       # no cookie → single page
        mock_conn.response_controls = []

        c = self._unconnected()
        c._conn = mock_conn

        result = c.search_paged("(objectClass=user)", ["sAMAccountName"])

        assert isinstance(result, list)
        assert len(result) == 1
        assert result[0]["dn"] == "CN=jdoe,DC=corp,DC=local"

    # ── Signing detection returns dict with bool keys ─────────────────────

    def test_signing_detection_returns_dict_with_bool_keys(self) -> None:
        from unittest.mock import MagicMock, patch

        mock_server = MagicMock()
        mock_server.info.other = {}
        mock_conn   = MagicMock()
        mock_conn.bind.return_value = True
        mock_conn.result = {}

        mock_ldap3 = MagicMock()
        mock_ldap3.Server.return_value   = mock_server
        mock_ldap3.Connection.return_value = mock_conn
        mock_ldap3.ANONYMOUS = "ANONYMOUS"
        mock_ldap3.ALL       = "ALL"

        import sys
        with patch.dict(sys.modules, {"ldap3": mock_ldap3}):
            c = self._unconnected()
            result = c.detect_signing()

        assert isinstance(result, dict)
        assert "ldap_signing_required" in result
        assert "ldap_channel_binding" in result
        assert isinstance(result["ldap_signing_required"], bool)
        assert isinstance(result["ldap_channel_binding"], bool)

    def test_signing_detection_returns_defaults_on_failure(self) -> None:
        """detect_signing must never raise; defaults must be False on error."""
        from unittest.mock import patch, MagicMock
        import sys

        mock_ldap3 = MagicMock()
        mock_ldap3.Server.side_effect = RuntimeError("network error")

        with patch.dict(sys.modules, {"ldap3": mock_ldap3}):
            c = self._unconnected()
            result = c.detect_signing()

        assert result["ldap_signing_required"] is False
        assert result["ldap_channel_binding"]  is False

    # ── connect returns False on invalid host ─────────────────────────────

    def test_connect_returns_false_when_bind_fails(self) -> None:
        from unittest.mock import MagicMock, patch
        import sys

        mock_conn = MagicMock()
        mock_conn.bind.return_value = False
        mock_conn.result = {"result": 49}   # invalidCredentials

        mock_ldap3 = MagicMock()
        mock_ldap3.Server.return_value     = MagicMock()
        mock_ldap3.Connection.return_value = mock_conn
        mock_ldap3.NTLM      = "NTLM"
        mock_ldap3.ALL       = "ALL"
        mock_ldap3.ANONYMOUS = "ANONYMOUS"

        with patch.dict(sys.modules, {"ldap3": mock_ldap3}):
            c = LdapClient("127.0.0.2", "corp.local", timeout=1)
            assert c.connect() is False

    def test_connect_stores_conn_on_success(self) -> None:
        from unittest.mock import MagicMock, patch
        import sys

        mock_conn = MagicMock()
        mock_conn.bind.return_value = True

        mock_ldap3 = MagicMock()
        mock_ldap3.Server.return_value     = MagicMock()
        mock_ldap3.Connection.return_value = mock_conn
        mock_ldap3.NTLM      = "NTLM"
        mock_ldap3.ALL       = "ALL"
        mock_ldap3.ANONYMOUS = "ANONYMOUS"

        with patch.dict(sys.modules, {"ldap3": mock_ldap3}):
            c = LdapClient("10.0.0.1", "corp.local", timeout=1)
            result = c.connect()

        assert result is True
        assert c._conn is mock_conn

    # ── repr ──────────────────────────────────────────────────────────────

    def test_repr_disconnected(self) -> None:
        c = self._unconnected()
        r = repr(c)
        assert "disconnected" in r
        assert "corp.local" in r

    def test_repr_connected(self) -> None:
        c = self._unconnected()
        c._conn = object()
        r = repr(c)
        assert "connected" in r
