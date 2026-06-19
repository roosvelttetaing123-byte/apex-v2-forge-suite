"""SMB client wrapper using impacket."""
from __future__ import annotations

import logging

log = logging.getLogger("forge.adforge.smb")


class SmbClient:
    """Authenticated SMB connection via impacket."""

    def __init__(self, host: str, domain: str = "", username: str = "",
                 password: str = "", nt_hash: str = "") -> None:
        self.host     = host
        self.domain   = domain
        self.username = username
        self.password = password
        self.nt_hash  = nt_hash
        self._conn    = None

    def connect(self) -> bool:
        try:
            from impacket.smbconnection import SMBConnection
            self._conn = SMBConnection(self.host, self.host, sess_port=445)
            lm = ""
            nt = self.nt_hash or ""
            self._conn.login(self.username, self.password, self.domain, lm, nt)
            log.info("SMB connected: %s as %s\\%s", self.host, self.domain, self.username)
            return True
        except ImportError:
            log.warning("impacket not available")
            return False
        except Exception as exc:
            log.debug("SMB connect failed %s: %s", self.host, exc)
            return False

    def list_shares(self) -> list[dict]:
        if not self._conn:
            return []
        try:
            shares = self._conn.listShares()
            return [{"name": s["shi1_netname"][:-1], "comment": s["shi1_remark"][:-1]} for s in shares]
        except Exception as exc:
            log.debug("listShares failed: %s", exc)
            return []

    def read_file(self, share: str, path: str) -> bytes | None:
        if not self._conn:
            return None
        try:
            import io
            buf = io.BytesIO()
            self._conn.getFile(share, path, buf.write)
            return buf.getvalue()
        except Exception as exc:
            log.debug("read_file %s/%s failed: %s", share, path, exc)
            return None

    def exec_command(self, cmd: str, confirmed: bool = False) -> str | None:
        """Remote code execution via SMB exec — requires operator confirmation."""
        if not confirmed:
            log.warning("exec_command requires confirmed=True (operator gate)")
            return None
        try:
            import asyncio
            from impacket.examples.secretsdump import RemoteOperations
            log.info("SMB exec on %s: %s", self.host, cmd)
            # Actual exec via wmiexec/smbexec done by lateral modules
            return None
        except Exception as exc:
            log.debug("exec failed: %s", exc)
            return None

    def disconnect(self) -> None:
        if self._conn:
            try:
                self._conn.logoff()
            except Exception:
                pass
            self._conn = None
