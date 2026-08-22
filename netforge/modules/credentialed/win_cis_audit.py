"""Windows CIS Benchmark Audit — CIS Windows Server Benchmark Level 1 checks via WinRM.

Covers:
  - Account Policies: password history, age, length, complexity, lockout
  - User Rights Assignment: act as OS, elevated privileges
  - Security Options: administrator/guest account status, logon display,
    SMB signing, anonymous enumeration
  - Windows Firewall: domain, private, public profiles
  - Windows Defender / AV: real-time protection, behavior monitoring
  - PowerShell: script block logging
"""
from __future__ import annotations

import re
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity

# CVSS vectors
CVSS_CRITICAL   = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
CVSS_HIGH_AUTH  = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
CVSS_HIGH_LOCAL = "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
CVSS_MEDIUM     = "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N"
CVSS_LOW        = "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:L/I:N/A:N"


class WinCisAudit(BaseModule):
    """CIS Windows Server Benchmark Level 1 compliance checks via WinRM/PowerShell."""

    NAME        = "win_cis_audit"
    DESCRIPTION = (
        "WinRM credentialed CIS Windows Server Benchmark Level 1 checks: account policies, "
        "user rights, security options, firewall, Defender, PowerShell logging"
    )
    PHASE       = 5
    TAGS        = ["credentialed", "windows", "cis", "compliance", "benchmark"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        transport_mgr = self.config.extra.get("transport_manager")
        if not transport_mgr or not transport_mgr.has_creds("winrm"):
            return self._make_result(start, skipped=True, skip_reason="no WinRM credentials")

        hosts = self.config.extra.get("live_hosts", [self.config.target])
        for host in hosts[:20]:
            if not self.check_scope(host):
                continue
            await self.rate_limit()
            session = await transport_mgr.get_winrm_session(host)
            if not session:
                continue
            await self._audit_host(host, transport_mgr.winrm, session)

        return self._make_result(start)

    async def _audit_host(self, host: str, winrm, session) -> None:
        """Run all CIS Level 1 check groups against a single Windows host."""
        await self._check_account_policies(host, winrm, session)
        await self._check_user_rights(host, winrm, session)
        await self._check_security_options(host, winrm, session)
        await self._check_firewall(host, winrm, session)
        await self._check_defender(host, winrm, session)
        await self._check_powershell_logging(host, winrm, session)

    # -------------------------------------------------------------------------
    # CIS Section 1 — Account Policies
    # -------------------------------------------------------------------------

    async def _check_account_policies(self, host: str, winrm, session) -> None:
        """CIS 1.1.x / 1.2.x — password and lockout policy checks."""
        # Retrieve AD domain password policy; fall back to local policy
        policy_result = await winrm.execute(
            session,
            "try { "
            "  $p = Get-ADDefaultDomainPasswordPolicy -ErrorAction Stop; "
            "  [PSCustomObject]@{ "
            "    HistoryCount = $p.PasswordHistoryCount; "
            "    MaxAge       = $p.MaxPasswordAge.Days; "
            "    MinAge       = $p.MinPasswordAge.Days; "
            "    MinLength    = $p.MinPasswordLength; "
            "    Complexity   = $p.ComplexityEnabled; "
            "    Threshold    = $p.LockoutThreshold; "
            "    LockoutDur   = $p.LockoutDuration.Minutes "
            "  } | ConvertTo-Json "
            "} catch { "
            "  $n = net accounts; "
            "  $n | Out-String "
            "}"
        )
        raw = policy_result.stdout.strip() if policy_result.success else ""

        # Try JSON path first (AD available)
        parsed = {}
        try:
            import json
            parsed = json.loads(raw)
        except Exception:
            # Parse net accounts text output
            for line in raw.split("\n"):
                if "Minimum password length" in line:
                    m = re.search(r':\s*(\d+)', line)
                    if m:
                        parsed["MinLength"] = int(m.group(1))
                elif "Maximum password age" in line:
                    m = re.search(r':\s*(\d+)', line)
                    if m:
                        parsed["MaxAge"] = int(m.group(1))
                elif "Length of password history" in line:
                    m = re.search(r':\s*(\d+)', line)
                    if m:
                        parsed["HistoryCount"] = int(m.group(1))
                elif "Lockout threshold" in line:
                    m = re.search(r':\s*(\w+)', line)
                    if m:
                        val = m.group(1)
                        parsed["Threshold"] = 0 if val.lower() == "never" else int(val)
                elif "Lockout duration" in line:
                    m = re.search(r':\s*(\d+)', line)
                    if m:
                        parsed["LockoutDur"] = int(m.group(1))

        await self._eval_password_history(host, parsed, raw)
        await self._eval_password_max_age(host, parsed, raw)
        await self._eval_password_min_length(host, parsed, raw)
        await self._eval_password_complexity(host, winrm, session, parsed, raw)
        await self._eval_lockout_threshold(host, parsed, raw)
        await self._eval_lockout_duration(host, parsed, raw)

    async def _eval_password_history(self, host: str, parsed: dict, raw: str) -> None:
        """CIS 1.1.1 — Password history >= 24."""
        history = parsed.get("HistoryCount")
        if history is None or int(history) < 24:
            self.new_finding(
                title=f"CIS 1.1.1 — Password History < 24 — {host}",
                severity=Severity.HIGH,
                description=(
                    f"Password history is {'not configured' if history is None else history} "
                    f"on {host}. CIS requires >= 24 remembered passwords to prevent reuse. "
                    "Short history allows users to cycle back to previously compromised passwords."
                ),
                reproduction_steps=[
                    f"Enter-PSSession {host}",
                    "(Get-ADDefaultDomainPasswordPolicy).PasswordHistoryCount",
                ],
                remediation=(
                    "Set-ADDefaultDomainPasswordPolicy -Identity <domain> "
                    "-PasswordHistoryCount 24\n"
                    "Or via Group Policy: Computer Configuration -> Windows Settings -> "
                    "Security Settings -> Account Policies -> Password Policy -> "
                    "Enforce password history: 24"
                ),
                references=[
                    "CIS Windows Server Benchmark — Section 1.1.1",
                    "CWE-262",
                ],
                evidence=Evidence(extra={"host": host, "history_count": history, "raw": raw[:500]}),
                cvss_v31_vector=CVSS_HIGH_AUTH,
                mitre_attack=["TA0006/T1110"],
                target=host, service="winrm", confidence="HIGH",
            )

    async def _eval_password_max_age(self, host: str, parsed: dict, raw: str) -> None:
        """CIS 1.1.2 — Maximum password age <= 365 days."""
        max_age = parsed.get("MaxAge")
        if max_age is None or int(max_age) == 0 or int(max_age) > 365:
            self.new_finding(
                title=f"CIS 1.1.2 — Password Max Age Not Enforced — {host}",
                severity=Severity.HIGH,
                description=(
                    f"Password maximum age is "
                    f"{'not configured (never expires)' if max_age in (None, 0) else max_age} "
                    f"days on {host}. CIS requires <= 365 days. Long-lived passwords increase "
                    "the risk of undetected credential compromise."
                ),
                reproduction_steps=[
                    f"Enter-PSSession {host}",
                    "(Get-ADDefaultDomainPasswordPolicy).MaxPasswordAge",
                ],
                remediation=(
                    "Set-ADDefaultDomainPasswordPolicy -Identity <domain> "
                    "-MaxPasswordAge (New-TimeSpan -Days 90)\n"
                    "Or via Group Policy: Password Policy -> Maximum password age: 90"
                ),
                references=[
                    "CIS Windows Server Benchmark — Section 1.1.2",
                    "CWE-262",
                ],
                evidence=Evidence(extra={"host": host, "max_age_days": max_age, "raw": raw[:300]}),
                cvss_v31_vector=CVSS_HIGH_AUTH,
                mitre_attack=["TA0006/T1078"],
                target=host, service="winrm", confidence="HIGH",
            )

    async def _eval_password_min_length(self, host: str, parsed: dict, raw: str) -> None:
        """CIS 1.1.4 — Minimum password length >= 14."""
        min_len = parsed.get("MinLength")
        if min_len is None or int(min_len) < 14:
            self.new_finding(
                title=f"CIS 1.1.4 — Password Min Length < 14 — {host}",
                severity=Severity.HIGH,
                description=(
                    f"Password minimum length is "
                    f"{'not configured' if min_len is None else min_len} on {host}. "
                    "CIS requires >= 14 characters. Short passwords are trivially brute-forced "
                    "or cracked via NTLM hash extraction (Pass-the-Hash, cracking)."
                ),
                reproduction_steps=[
                    f"Enter-PSSession {host}",
                    "(Get-ADDefaultDomainPasswordPolicy).MinPasswordLength",
                    "net accounts",
                ],
                remediation=(
                    "Set-ADDefaultDomainPasswordPolicy -Identity <domain> "
                    "-MinPasswordLength 14\n"
                    "Or via Group Policy: Password Policy -> Minimum password length: 14"
                ),
                references=[
                    "CIS Windows Server Benchmark — Section 1.1.4",
                    "CWE-521",
                    "NIST SP 800-63B",
                ],
                evidence=Evidence(extra={"host": host, "min_length": min_len}),
                cvss_v31_vector=CVSS_HIGH_AUTH,
                mitre_attack=["TA0006/T1110", "TA0006/T1003.001"],
                target=host, service="winrm", confidence="HIGH",
            )

    async def _eval_password_complexity(self, host: str, winrm, session, parsed: dict, raw: str) -> None:
        """CIS 1.1.5 — Password complexity must be enabled."""
        complexity = parsed.get("Complexity")
        if complexity is None:
            # Query separately
            result = await winrm.execute(
                session,
                "try { (Get-ADDefaultDomainPasswordPolicy).ComplexityEnabled } "
                "catch { (Get-LocalUser Administrator | Select-Object *).PasswordRequired }"
            )
            val = result.stdout.strip().lower()
            complexity = val in ("true", "1", "yes")
        else:
            complexity = str(complexity).lower() in ("true", "1")

        if not complexity:
            self.new_finding(
                title=f"CIS 1.1.5 — Password Complexity Disabled — {host}",
                severity=Severity.HIGH,
                description=(
                    f"Password complexity requirements are disabled on {host}. "
                    "Without complexity, passwords of minimum length with no special characters "
                    "or mixed case are accepted, dramatically reducing the keyspace for "
                    "brute force attacks against captured NTLM hashes."
                ),
                reproduction_steps=[
                    f"Enter-PSSession {host}",
                    "(Get-ADDefaultDomainPasswordPolicy).ComplexityEnabled",
                ],
                remediation=(
                    "Set-ADDefaultDomainPasswordPolicy -Identity <domain> "
                    "-ComplexityEnabled $true\n"
                    "Or via Group Policy: Password Policy -> "
                    "Password must meet complexity requirements: Enabled"
                ),
                references=[
                    "CIS Windows Server Benchmark — Section 1.1.5",
                    "CWE-521",
                ],
                evidence=Evidence(extra={"host": host, "complexity_enabled": complexity}),
                cvss_v31_vector=CVSS_HIGH_AUTH,
                mitre_attack=["TA0006/T1110"],
                target=host, service="winrm", confidence="HIGH",
            )

    async def _eval_lockout_threshold(self, host: str, parsed: dict, raw: str) -> None:
        """CIS 1.2.1 — Account lockout threshold <= 5 attempts."""
        threshold = parsed.get("Threshold")
        if threshold is None or int(threshold) == 0 or int(threshold) > 5:
            self.new_finding(
                title=f"CIS 1.2.1 — Account Lockout Threshold Not Set or Too High — {host}",
                severity=Severity.HIGH,
                description=(
                    f"Account lockout threshold is "
                    f"{'disabled (never locks)' if threshold in (None, 0) else threshold} "
                    f"on {host}. CIS requires <= 5. Without a lockout, password spraying and "
                    "brute force attacks against Active Directory accounts are unconstrained."
                ),
                reproduction_steps=[
                    f"Enter-PSSession {host}",
                    "(Get-ADDefaultDomainPasswordPolicy).LockoutThreshold",
                    "net accounts",
                ],
                remediation=(
                    "Set-ADDefaultDomainPasswordPolicy -Identity <domain> "
                    "-LockoutThreshold 5\n"
                    "Or via Group Policy: Account Lockout Policy -> "
                    "Account lockout threshold: 5"
                ),
                references=[
                    "CIS Windows Server Benchmark — Section 1.2.1",
                    "CWE-307",
                ],
                evidence=Evidence(extra={"host": host, "lockout_threshold": threshold}),
                cvss_v31_vector=CVSS_HIGH_AUTH,
                mitre_attack=["TA0006/T1110.003"],
                target=host, service="winrm", confidence="HIGH",
            )

    async def _eval_lockout_duration(self, host: str, parsed: dict, raw: str) -> None:
        """CIS 1.2.2 — Account lockout duration >= 15 minutes."""
        duration = parsed.get("LockoutDur")
        if duration is not None and int(duration) < 15:
            self.new_finding(
                title=f"CIS 1.2.2 — Account Lockout Duration Too Short — {host}",
                severity=Severity.MEDIUM,
                description=(
                    f"Account lockout duration is {duration} minutes on {host}. "
                    "CIS requires >= 15 minutes. Short lockout duration allows rapid resumption "
                    "of brute force or password spray attacks."
                ),
                reproduction_steps=[
                    f"Enter-PSSession {host}",
                    "(Get-ADDefaultDomainPasswordPolicy).LockoutDuration",
                ],
                remediation=(
                    "Set-ADDefaultDomainPasswordPolicy -Identity <domain> "
                    "-LockoutDuration (New-TimeSpan -Minutes 15)\n"
                    "Or via Group Policy: Account lockout duration: 15"
                ),
                references=[
                    "CIS Windows Server Benchmark — Section 1.2.2",
                    "CWE-307",
                ],
                evidence=Evidence(extra={"host": host, "lockout_duration_min": duration}),
                cvss_v31_vector=CVSS_MEDIUM,
                target=host, service="winrm", confidence="HIGH",
            )

    # -------------------------------------------------------------------------
    # CIS Section 2.2 — User Rights Assignment
    # -------------------------------------------------------------------------

    async def _check_user_rights(self, host: str, winrm, session) -> None:
        """CIS 2.2.x — privilege assignment checks."""
        await self._check_act_as_os(host, winrm, session)
        await self._check_log_on_locally(host, winrm, session)

    async def _check_act_as_os(self, host: str, winrm, session) -> None:
        """CIS 2.2.4 — 'Act as part of the OS' (SeTcbPrivilege) should be empty."""
        result = await winrm.execute(
            session,
            "$tmpFile = 'C:\\Windows\\Temp\\secpol_cis.cfg'; "
            "secedit /export /cfg $tmpFile /quiet; "
            "$content = Get-Content $tmpFile -ErrorAction SilentlyContinue; "
            "Remove-Item $tmpFile -Force -ErrorAction SilentlyContinue; "
            "$content | Select-String 'SeTcbPrivilege' | Out-String"
        )
        if not result.success:
            return
        output = result.stdout.strip()
        # Compliant: line should not exist or value should be empty
        if output:
            m = re.search(r'SeTcbPrivilege\s*=\s*(.*)', output)
            if m:
                value = m.group(1).strip()
                if value and value not in ("", "*S-1-0-0"):  # S-1-0-0 = null SID
                    self.new_finding(
                        title=f"CIS 2.2.4 — SeTcbPrivilege Assigned — {host}",
                        severity=Severity.CRITICAL,
                        description=(
                            f"'Act as part of the operating system' privilege (SeTcbPrivilege) "
                            f"is assigned to: {value} on {host}. "
                            "This privilege grants near-complete OS control — the holder can "
                            "impersonate any user, bypass authentication, and read/write "
                            "any security context. Should be empty on all systems."
                        ),
                        reproduction_steps=[
                            f"Enter-PSSession {host}",
                            "secedit /export /cfg C:\\Windows\\Temp\\secpol.cfg",
                            "Select-String SeTcbPrivilege C:\\Windows\\Temp\\secpol.cfg",
                        ],
                        remediation=(
                            "Remove all accounts from 'Act as part of the operating system':\n"
                            "Computer Configuration -> Windows Settings -> Security Settings -> "
                            "Local Policies -> User Rights Assignment -> "
                            "Act as part of the operating system: (empty)"
                        ),
                        references=[
                            "CIS Windows Server Benchmark — Section 2.2.4",
                            "CWE-269",
                            "https://learn.microsoft.com/en-us/windows/security/threat-protection/"
                            "security-policy-settings/act-as-part-of-the-operating-system",
                        ],
                        evidence=Evidence(extra={"host": host, "setcbprivilege": value}),
                        cvss_v31_vector=CVSS_CRITICAL,
                        mitre_attack=["TA0004/T1134"],
                        target=host, service="winrm", confidence="HIGH",
                    )

    async def _check_log_on_locally(self, host: str, winrm, session) -> None:
        """CIS 2.2.26 — 'Allow log on locally' should be restricted."""
        result = await winrm.execute(
            session,
            "$tmpFile = 'C:\\Windows\\Temp\\secpol_logon.cfg'; "
            "secedit /export /cfg $tmpFile /quiet; "
            "$content = Get-Content $tmpFile -ErrorAction SilentlyContinue; "
            "Remove-Item $tmpFile -Force -ErrorAction SilentlyContinue; "
            "$content | Select-String 'SeInteractiveLogonRight' | Out-String"
        )
        if not result.success or not result.stdout.strip():
            return
        output = result.stdout.strip()
        m = re.search(r'SeInteractiveLogonRight\s*=\s*(.*)', output)
        if m:
            value = m.group(1).strip()
            accounts = [a.strip() for a in value.split(",") if a.strip()]
            # Flag if more than expected accounts (Administrators + Backup Operators)
            expected = {"*s-1-5-32-544", "*s-1-5-32-551"}  # Administrators, Backup Operators
            actual = set(a.lower() for a in accounts)
            unexpected = actual - expected
            if len(accounts) > 4 or unexpected:
                self.new_finding(
                    title=f"CIS 2.2.26 — Log On Locally Right Granted to Excessive Accounts — {host}",
                    severity=Severity.MEDIUM,
                    description=(
                        f"'Allow log on locally' is granted to {len(accounts)} accounts on {host}: "
                        f"{', '.join(accounts[:10])}. "
                        "This right should be restricted to Administrators and Backup Operators only. "
                        "Excessive grants increase the interactive attack surface."
                    ),
                    reproduction_steps=[
                        f"Enter-PSSession {host}",
                        "secedit /export /cfg C:\\Windows\\Temp\\secpol.cfg",
                        "Select-String SeInteractiveLogonRight C:\\Windows\\Temp\\secpol.cfg",
                    ],
                    remediation=(
                        "Restrict 'Allow log on locally' via Group Policy:\n"
                        "Computer Configuration -> Windows Settings -> Security Settings -> "
                        "Local Policies -> User Rights Assignment -> "
                        "Allow log on locally: Administrators, Backup Operators"
                    ),
                    references=[
                        "CIS Windows Server Benchmark — Section 2.2.26",
                        "CWE-250",
                    ],
                    evidence=Evidence(extra={"host": host, "accounts": accounts}),
                    cvss_v31_vector=CVSS_MEDIUM,
                    target=host, service="winrm", confidence="MEDIUM",
                )

    # -------------------------------------------------------------------------
    # CIS Section 2.3 — Security Options
    # -------------------------------------------------------------------------

    async def _check_security_options(self, host: str, winrm, session) -> None:
        """CIS 2.3.x — security options: accounts, logon, network, SMB."""
        await self._check_administrator_disabled(host, winrm, session)
        await self._check_guest_disabled(host, winrm, session)
        await self._check_dont_display_last_username(host, winrm, session)
        await self._check_smb_signing(host, winrm, session)
        await self._check_anonymous_sam_enumeration(host, winrm, session)
        await self._check_everyone_anonymous(host, winrm, session)

    async def _check_administrator_disabled(self, host: str, winrm, session) -> None:
        """CIS 2.3.1.1 — Built-in Administrator account should be disabled."""
        result = await winrm.execute(
            session,
            "try { "
            "  (Get-LocalUser | Where-Object { $_.SID -like '*-500' }).Enabled "
            "} catch { 'error' }"
        )
        val = result.stdout.strip().lower() if result.success else ""
        if val == "true":
            self.new_finding(
                title=f"CIS 2.3.1.1 — Built-in Administrator Account Enabled — {host}",
                severity=Severity.HIGH,
                description=(
                    f"The built-in Administrator account (RID 500) is enabled on {host}. "
                    "This well-known account is a prime target for credential attacks. "
                    "It cannot be locked out by default policy, making it vulnerable to "
                    "unlimited password spray attacks."
                ),
                reproduction_steps=[
                    f"Enter-PSSession {host}",
                    "Get-LocalUser | Where-Object { $_.SID -like '*-500' }",
                ],
                remediation=(
                    "Disable the built-in Administrator:\n"
                    "  Disable-LocalUser -SID (Get-LocalUser | "
                    "Where-Object {$_.SID -like '*-500'}).SID\n"
                    "Or via Group Policy: Security Options -> "
                    "Accounts: Administrator account status: Disabled"
                ),
                references=[
                    "CIS Windows Server Benchmark — Section 2.3.1.1",
                    "CWE-798",
                ],
                evidence=Evidence(extra={"host": host, "admin_enabled": True}),
                cvss_v31_vector=CVSS_HIGH_AUTH,
                mitre_attack=["TA0001/T1078.002"],
                target=host, service="winrm", confidence="HIGH",
            )

    async def _check_guest_disabled(self, host: str, winrm, session) -> None:
        """CIS 2.3.1.2 — Guest account should be disabled."""
        result = await winrm.execute(
            session,
            "try { (Get-LocalUser -Name 'Guest' -ErrorAction Stop).Enabled } catch { 'not_found' }"
        )
        val = result.stdout.strip().lower() if result.success else ""
        if val == "true":
            self.new_finding(
                title=f"CIS 2.3.1.2 — Guest Account Enabled — {host}",
                severity=Severity.HIGH,
                description=(
                    f"The built-in Guest account is enabled on {host}. "
                    "The Guest account provides unauthenticated or minimally authenticated "
                    "access to the system and is a common initial foothold for attackers."
                ),
                reproduction_steps=[
                    f"Enter-PSSession {host}",
                    "Get-LocalUser -Name 'Guest'",
                ],
                remediation=(
                    "Disable the Guest account:\n"
                    "  Disable-LocalUser -Name 'Guest'\n"
                    "Or via Group Policy: Security Options -> "
                    "Accounts: Guest account status: Disabled"
                ),
                references=[
                    "CIS Windows Server Benchmark — Section 2.3.1.2",
                    "CWE-284",
                ],
                evidence=Evidence(extra={"host": host, "guest_enabled": True}),
                cvss_v31_vector=CVSS_HIGH_AUTH,
                mitre_attack=["TA0001/T1078.003"],
                target=host, service="winrm", confidence="HIGH",
            )

    async def _check_dont_display_last_username(self, host: str, winrm, session) -> None:
        """CIS 2.3.7.3 — Interactive logon must not display last username."""
        result = await winrm.execute(
            session,
            "Get-ItemProperty -Path "
            "'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' "
            "-Name DontDisplayLastUserName -ErrorAction SilentlyContinue | "
            "Select-Object -ExpandProperty DontDisplayLastUserName"
        )
        val = result.stdout.strip() if result.success else ""
        if val != "1":
            self.new_finding(
                title=f"CIS 2.3.7.3 — Last Username Displayed at Logon — {host}",
                severity=Severity.MEDIUM,
                description=(
                    f"DontDisplayLastUserName is set to '{val}' on {host} (expected: 1). "
                    "Displaying the last logged-on username at the login screen leaks valid "
                    "usernames to an attacker with physical or RDP access to the console."
                ),
                reproduction_steps=[
                    f"Enter-PSSession {host}",
                    "Get-ItemProperty HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\"
                    "Policies\\System -Name DontDisplayLastUserName",
                ],
                remediation=(
                    "Set registry value:\n"
                    "  Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\"
                    "CurrentVersion\\Policies\\System' "
                    "-Name DontDisplayLastUserName -Value 1 -Type DWord\n"
                    "Or via Group Policy: Security Options -> "
                    "Interactive logon: Do not display last user name: Enabled"
                ),
                references=[
                    "CIS Windows Server Benchmark — Section 2.3.7.3",
                    "CWE-200",
                ],
                evidence=Evidence(extra={"host": host, "registry_value": val}),
                cvss_v31_vector=CVSS_MEDIUM,
                mitre_attack=["TA0007/T1087"],
                target=host, service="winrm", confidence="HIGH",
            )

    async def _check_smb_signing(self, host: str, winrm, session) -> None:
        """CIS 2.3.9.4 — SMB server must require security signature (signing)."""
        result = await winrm.execute(
            session,
            "Get-SmbServerConfiguration | "
            "Select-Object RequireSecuritySignature, EnableSecuritySignature | "
            "ConvertTo-Json -Compress"
        )
        if not result.success or not result.stdout.strip():
            return

        require_signing = None
        try:
            import json
            data = json.loads(result.stdout.strip())
            require_signing = data.get("RequireSecuritySignature")
        except Exception:
            m = re.search(r'RequireSecuritySignature["\s:]+(\w+)', result.stdout)
            if m:
                require_signing = m.group(1).lower() in ("true", "1")

        if require_signing is False or require_signing == "false":
            self.new_finding(
                title=f"CIS 2.3.9.4 — SMB Signing Not Required — {host}",
                severity=Severity.HIGH,
                description=(
                    f"RequireSecuritySignature is disabled on {host}. "
                    "Without mandatory SMB signing, an attacker with network access can perform "
                    "SMB relay attacks (NTLM relay) to authenticate as legitimate users, "
                    "enabling lateral movement without knowing credentials. "
                    "This is the primary enabler of Responder/ntlmrelayx attacks."
                ),
                reproduction_steps=[
                    f"Enter-PSSession {host}",
                    "Get-SmbServerConfiguration | Select-Object RequireSecuritySignature",
                    "# From attacker: responder -I eth0; ntlmrelayx.py -t smb://<host>",
                ],
                remediation=(
                    "Enable required SMB signing:\n"
                    "  Set-SmbServerConfiguration -RequireSecuritySignature $true "
                    "-EnableSecuritySignature $true -Force\n"
                    "Or via Group Policy: Security Options -> "
                    "Microsoft network server: Digitally sign communications (always): Enabled"
                ),
                references=[
                    "CIS Windows Server Benchmark — Section 2.3.9.4",
                    "CWE-300",
                    "https://attack.mitre.org/techniques/T1557/001/",
                ],
                evidence=Evidence(extra={"host": host, "require_signing": require_signing,
                                         "raw": result.stdout[:300]}),
                cvss_v31_vector=CVSS_HIGH_AUTH,
                mitre_attack=["TA0006/T1557.001"],
                target=host, service="winrm", confidence="HIGH",
            )

    async def _check_anonymous_sam_enumeration(self, host: str, winrm, session) -> None:
        """CIS 2.3.10.3 — Do not allow anonymous enumeration of SAM accounts."""
        result = await winrm.execute(
            session,
            "Get-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' "
            "-Name RestrictAnonymousSAM -ErrorAction SilentlyContinue | "
            "Select-Object -ExpandProperty RestrictAnonymousSAM"
        )
        val = result.stdout.strip() if result.success else ""
        if val != "1":
            self.new_finding(
                title=f"CIS 2.3.10.3 — Anonymous SAM Account Enumeration Allowed — {host}",
                severity=Severity.HIGH,
                description=(
                    f"RestrictAnonymousSAM is set to '{val}' on {host} (expected: 1). "
                    "Anonymous enumeration of SAM accounts allows unauthenticated users to "
                    "enumerate local user accounts via null session, leaking usernames for "
                    "targeted password attacks."
                ),
                reproduction_steps=[
                    f"Enter-PSSession {host}",
                    "reg query HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa "
                    "/v RestrictAnonymousSAM",
                    "# From attacker: enum4linux -a <host> or rpcclient -U '' <host>",
                ],
                remediation=(
                    "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' "
                    "-Name RestrictAnonymousSAM -Value 1 -Type DWord\n"
                    "Or via Group Policy: Security Options -> "
                    "Network access: Do not allow anonymous enumeration of SAM accounts: Enabled"
                ),
                references=[
                    "CIS Windows Server Benchmark — Section 2.3.10.3",
                    "CWE-287",
                ],
                evidence=Evidence(extra={"host": host, "restrict_anonymous_sam": val}),
                cvss_v31_vector=CVSS_HIGH_AUTH,
                mitre_attack=["TA0007/T1087.001"],
                target=host, service="winrm", confidence="HIGH",
            )

    async def _check_everyone_anonymous(self, host: str, winrm, session) -> None:
        """CIS 2.3.10.5 — Everyone permissions must not apply to anonymous users."""
        result = await winrm.execute(
            session,
            "Get-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' "
            "-Name EveryoneIncludesAnonymous -ErrorAction SilentlyContinue | "
            "Select-Object -ExpandProperty EveryoneIncludesAnonymous"
        )
        val = result.stdout.strip() if result.success else "0"
        if val == "1":
            self.new_finding(
                title=f"CIS 2.3.10.5 — Everyone Permissions Apply to Anonymous Users — {host}",
                severity=Severity.HIGH,
                description=(
                    f"EveryoneIncludesAnonymous is enabled on {host}. "
                    "This grants the Everyone group's ACL permissions to anonymous (null session) "
                    "connections, potentially exposing file shares, registry keys, and other "
                    "resources to unauthenticated access."
                ),
                reproduction_steps=[
                    f"Enter-PSSession {host}",
                    "reg query HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa "
                    "/v EveryoneIncludesAnonymous",
                ],
                remediation=(
                    "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' "
                    "-Name EveryoneIncludesAnonymous -Value 0 -Type DWord\n"
                    "Or via Group Policy: Security Options -> "
                    "Network access: Let Everyone permissions apply to anonymous users: Disabled"
                ),
                references=[
                    "CIS Windows Server Benchmark — Section 2.3.10.5",
                    "CWE-284",
                ],
                evidence=Evidence(extra={"host": host, "everyone_includes_anonymous": val}),
                cvss_v31_vector=CVSS_HIGH_AUTH,
                mitre_attack=["TA0007/T1135"],
                target=host, service="winrm", confidence="HIGH",
            )

    # -------------------------------------------------------------------------
    # CIS Section 9 — Windows Firewall
    # -------------------------------------------------------------------------

    async def _check_firewall(self, host: str, winrm, session) -> None:
        """CIS 9.x — Windows Firewall profile checks."""
        result = await winrm.execute(
            session,
            "Get-NetFirewallProfile -Profile Domain,Private,Public | "
            "Select-Object Name,Enabled | ConvertTo-Json -Compress"
        )
        if not result.success or not result.stdout.strip():
            return

        profiles = {}
        try:
            import json
            data = json.loads(result.stdout.strip())
            if isinstance(data, list):
                for entry in data:
                    profiles[entry.get("Name", "")] = entry.get("Enabled")
            elif isinstance(data, dict):
                profiles[data.get("Name", "")] = data.get("Enabled")
        except Exception:
            # Parse text fallback
            for line in result.stdout.split("\n"):
                for profile in ("Domain", "Private", "Public"):
                    if profile in line and ("True" in line or "False" in line):
                        profiles[profile] = "True" in line

        cis_map = {
            "Domain":  "9.1.1",
            "Private": "9.2.1",
            "Public":  "9.3.1",
        }
        for profile_name, cis_ref in cis_map.items():
            enabled = profiles.get(profile_name)
            if enabled is False or str(enabled).lower() in ("false", "0"):
                self.new_finding(
                    title=f"CIS {cis_ref} — {profile_name} Firewall Disabled — {host}",
                    severity=Severity.HIGH,
                    description=(
                        f"Windows Firewall is disabled for the {profile_name} profile on {host}. "
                        f"CIS {cis_ref} requires the {profile_name} profile to be enabled. "
                        "A disabled firewall allows unrestricted inbound connections, enabling "
                        "lateral movement, exploitation of listening services, and direct "
                        "access to admin shares."
                    ),
                    reproduction_steps=[
                        f"Enter-PSSession {host}",
                        f"Get-NetFirewallProfile -Profile {profile_name} | Select-Object Enabled",
                    ],
                    remediation=(
                        f"Enable the {profile_name} firewall profile:\n"
                        f"  Set-NetFirewallProfile -Profile {profile_name} -Enabled True\n"
                        "Or via Group Policy: Windows Defender Firewall with Advanced Security"
                    ),
                    references=[
                        f"CIS Windows Server Benchmark — Section {cis_ref}",
                        "CWE-1188",
                    ],
                    evidence=Evidence(extra={"host": host, "profile": profile_name, "enabled": enabled}),
                    cvss_v31_vector=CVSS_HIGH_AUTH,
                    mitre_attack=["TA0005/T1562.004"],
                    target=host, service="winrm", confidence="HIGH",
                )

    # -------------------------------------------------------------------------
    # CIS Section 18.9.45 — Windows Defender / AV
    # -------------------------------------------------------------------------

    async def _check_defender(self, host: str, winrm, session) -> None:
        """CIS 18.9.45/47 — Windows Defender real-time protection and behavior monitoring."""
        result = await winrm.execute(
            session,
            "try { "
            "  Get-MpPreference | "
            "  Select-Object DisableRealtimeMonitoring,DisableBehaviorMonitoring | "
            "  ConvertTo-Json -Compress "
            "} catch { Write-Output 'not_available' }"
        )
        if not result.success or "not_available" in result.stdout:
            return

        data = {}
        try:
            import json
            data = json.loads(result.stdout.strip())
        except Exception:
            # Parse fallback
            for line in result.stdout.split("\n"):
                if "DisableRealtimeMonitoring" in line:
                    data["DisableRealtimeMonitoring"] = "True" in line
                elif "DisableBehaviorMonitoring" in line:
                    data["DisableBehaviorMonitoring"] = "True" in line

        rt_disabled = data.get("DisableRealtimeMonitoring")
        bm_disabled = data.get("DisableBehaviorMonitoring")

        if rt_disabled is True or str(rt_disabled).lower() == "true":
            self.new_finding(
                title=f"CIS 18.9.45 — Windows Defender Real-Time Protection Disabled — {host}",
                severity=Severity.HIGH,
                description=(
                    f"Windows Defender real-time protection is disabled on {host}. "
                    "Without real-time monitoring, malicious files are not scanned on access, "
                    "allowing malware execution without any AV intervention. "
                    "This is a common attacker goal post-compromise (T1562.001)."
                ),
                reproduction_steps=[
                    f"Enter-PSSession {host}",
                    "Get-MpPreference | Select-Object DisableRealtimeMonitoring",
                ],
                remediation=(
                    "Enable real-time protection:\n"
                    "  Set-MpPreference -DisableRealtimeMonitoring $false\n"
                    "Or via Group Policy: Windows Defender Antivirus -> Real-time Protection -> "
                    "Turn off real-time protection: Disabled"
                ),
                references=[
                    "CIS Windows Server Benchmark — Section 18.9.45",
                    "CWE-693",
                ],
                evidence=Evidence(extra={"host": host, "rt_monitoring_disabled": rt_disabled}),
                cvss_v31_vector=CVSS_HIGH_LOCAL,
                mitre_attack=["TA0005/T1562.001"],
                target=host, service="winrm", confidence="HIGH",
            )

        if bm_disabled is True or str(bm_disabled).lower() == "true":
            self.new_finding(
                title=f"CIS 18.9.47 — Windows Defender Behavior Monitoring Disabled — {host}",
                severity=Severity.HIGH,
                description=(
                    f"Windows Defender behavior monitoring is disabled on {host}. "
                    "Behavior monitoring detects malicious patterns at runtime (process injection, "
                    "privilege escalation attempts, ransomware behavior). Disabling it leaves "
                    "the system vulnerable to fileless attacks and living-off-the-land techniques."
                ),
                reproduction_steps=[
                    f"Enter-PSSession {host}",
                    "Get-MpPreference | Select-Object DisableBehaviorMonitoring",
                ],
                remediation=(
                    "Enable behavior monitoring:\n"
                    "  Set-MpPreference -DisableBehaviorMonitoring $false\n"
                    "Or via Group Policy: Windows Defender Antivirus -> Real-time Protection -> "
                    "Turn on behavior monitoring: Enabled"
                ),
                references=[
                    "CIS Windows Server Benchmark — Section 18.9.47",
                    "CWE-693",
                ],
                evidence=Evidence(extra={"host": host, "behavior_monitoring_disabled": bm_disabled}),
                cvss_v31_vector=CVSS_HIGH_LOCAL,
                mitre_attack=["TA0005/T1562.001"],
                target=host, service="winrm", confidence="HIGH",
            )

    # -------------------------------------------------------------------------
    # CIS — PowerShell Script Block Logging
    # -------------------------------------------------------------------------

    async def _check_powershell_logging(self, host: str, winrm, session) -> None:
        """CIS — PowerShell script block logging should be enabled."""
        result = await winrm.execute(
            session,
            "Get-ItemProperty -Path "
            "'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging' "
            "-ErrorAction SilentlyContinue | "
            "Select-Object EnableScriptBlockLogging | ConvertTo-Json -Compress"
        )
        enabled = None
        if result.success and result.stdout.strip():
            try:
                import json
                data = json.loads(result.stdout.strip())
                enabled = data.get("EnableScriptBlockLogging")
            except Exception:
                m = re.search(r'EnableScriptBlockLogging["\s:]+(\d)', result.stdout)
                if m:
                    enabled = int(m.group(1))

        if enabled != 1 and str(enabled) != "1":
            self.new_finding(
                title=f"CIS — PowerShell Script Block Logging Disabled — {host}",
                severity=Severity.MEDIUM,
                description=(
                    f"PowerShell script block logging is not enabled on {host} "
                    f"(EnableScriptBlockLogging = {enabled}). "
                    "Script block logging records the content of all PowerShell scripts executed, "
                    "providing critical visibility into attacker activity using PowerShell for "
                    "lateral movement, C2 communication, and credential harvesting."
                ),
                reproduction_steps=[
                    f"Enter-PSSession {host}",
                    "Get-ItemProperty HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\"
                    "PowerShell\\ScriptBlockLogging",
                ],
                remediation=(
                    "Enable via Group Policy:\n"
                    "Computer Configuration -> Administrative Templates -> "
                    "Windows Components -> Windows PowerShell -> "
                    "Turn on PowerShell Script Block Logging: Enabled\n"
                    "Or via registry:\n"
                    "  New-Item -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\"
                    "PowerShell\\ScriptBlockLogging' -Force | "
                    "  New-ItemProperty -Name EnableScriptBlockLogging -Value 1 -Type DWord"
                ),
                references=[
                    "CIS Windows Server Benchmark — Script Block Logging",
                    "CWE-223",
                    "https://attack.mitre.org/techniques/T1059/001/",
                ],
                evidence=Evidence(extra={
                    "host": host,
                    "script_block_logging": enabled,
                    "raw": result.stdout[:300],
                }),
                cvss_v31_vector=CVSS_MEDIUM,
                mitre_attack=["TA0005/T1059.001"],
                target=host, service="winrm", confidence="HIGH",
            )
