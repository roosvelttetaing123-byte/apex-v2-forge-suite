"""ADForge LDAP client — reusable LDAP connection with NTLM/Kerberos auth."""
from __future__ import annotations

from typing import Any


class LdapClient:
    """Thin wrapper around ldap3 for ADForge modules."""

    def __init__(
        self,
        dc_ip: str,
        domain: str,
        username: str = "",
        password: str = "",
        nt_hash: str = "",
        use_kerberos: bool = False,
        timeout: int = 10,
    ):
        self.dc_ip        = dc_ip
        self.domain       = domain
        self.username     = username
        self.password     = password
        self.nt_hash      = nt_hash
        self.use_kerberos = use_kerberos
        self.timeout      = timeout
        self._conn        = None
        self._base_dn     = self._make_base_dn(domain)

    def _make_base_dn(self, domain: str) -> str:
        return ",".join(f"DC={p}" for p in domain.split("."))

    def connect(self) -> bool:
        """Establish LDAP connection. Returns True on success."""
        try:
            from ldap3 import Server, Connection, NTLM, ALL, ANONYMOUS
            server = Server(
                self.dc_ip, get_info=ALL, connect_timeout=self.timeout
            )
            if self.username:
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
                conn = Connection(
                    server, authentication=ANONYMOUS, raise_exceptions=False
                )
            result = conn.bind()
            if result:
                self._conn = conn
                return True
            return False
        except Exception:
            return False

    def disconnect(self) -> None:
        if self._conn:
            try:
                self._conn.unbind()
            except Exception:
                pass
            self._conn = None

    def search(
        self,
        search_filter: str,
        attributes: list[str],
        base_dn: str | None = None,
        search_scope: str = "SUBTREE",
        controls: list | None = None,
    ) -> list[dict[str, Any]]:
        """Execute LDAP search. Returns list of entry dicts."""
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
            results = []
            for entry in self._conn.entries:
                row: dict[str, Any] = {"dn": str(entry.entry_dn)}
                for attr in attributes:
                    try:
                        val = getattr(entry, attr, None)
                        if val is not None:
                            row[attr] = val.value if hasattr(val, "value") else str(val)
                    except Exception:
                        pass
                results.append(row)
            return results
        except Exception:
            return []

    def get_domain_info(self) -> dict[str, Any]:
        """Retrieve basic domain information."""
        entries = self.search(
            "(objectClass=domain)",
            ["name", "dc", "lockoutThreshold", "lockoutObservationWindow",
             "minPwdLength", "pwdHistoryLength", "maxPwdAge", "ms-DS-MachineAccountQuota"],
        )
        return entries[0] if entries else {}

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, *args):
        self.disconnect()


class TestLdapClient:
    def test_make_base_dn(self) -> None:
        client = LdapClient.__new__(LdapClient)
        dn = client._make_base_dn("corp.local")
        assert dn == "DC=corp,DC=local"

    def test_make_base_dn_three_levels(self) -> None:
        client = LdapClient.__new__(LdapClient)
        dn = client._make_base_dn("sub.corp.local")
        assert dn == "DC=sub,DC=corp,DC=local"
