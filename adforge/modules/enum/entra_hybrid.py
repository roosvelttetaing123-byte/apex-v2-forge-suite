"""Entra ID / Azure AD hybrid — detect AAD Connect accounts and hybrid attack surface."""
from __future__ import annotations

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity
from adforge.core.ldap_client import LdapClient

CVSS_MSOL    = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H"
CVSS40_MSOL  = "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H"
CVSS_HYBRID  = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"
CVSS40_HYBRID = "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N"
CVSS_PRT     = "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:N"
CVSS40_PRT   = "CVSS:4.0/AV:N/AC:H/AT:N/PR:L/UI:N/VC:H/VI:H/VA:N/SC:H/SI:H/SA:N"
# Microsoft Entra Connect (formerly Azure AD Connect) service account patterns
# v2.x renamed some accounts; both old and new naming patterns included
MSOL_PATTERNS = [
    "MSOL_",        # Entra Connect v1.x legacy account
    "AAD_",         # AAD Connect sync account
    "AZUREAD",      # generic
    "SYNC_",        # custom sync naming
    "AZURE_AD_CONNECT",
    "ENTRA_CONNECT", # Entra Connect v2.x naming
]
PTA_PATTERNS  = ["AZUREADSSOACC", "PTA", "PASSTHROUGH"]

# FOCI-capable client IDs (Family of Client IDs) — tokens from these can impersonate others
FOCI_CLIENT_IDS = [
    "1b730954-1685-4b74-9bfd-dac224a7b894",  # Azure PowerShell
    "04b07795-8ddb-461a-bbee-02f9e1bf7b46",  # Azure CLI
    "d3590ed6-52b3-4102-aeff-aad2292ab01c",  # Microsoft Office
    "00b41c95-dab0-4487-9791-b9d2c32c80f2",  # Office 365 Management
]


class EntraHybrid(BaseModule):
    """Detect Azure AD / Entra ID hybrid configuration and attack surface."""

    NAME        = "entra_hybrid"
    DESCRIPTION = "Detect AAD Connect (MSOL_*), PTA agent, PHS sync accounts, hybrid attack paths"
    PHASE       = 3
    TAGS        = ["enum", "entra", "azure-ad", "hybrid", "dcsync", "mitre-T1003.006"]

    async def run(self) -> ModuleResult:
        start  = time.monotonic()
        domain = self.config.extra.get("domain", "")
        dc_ip  = self.config.extra.get("dc", self.config.target)

        if not self.check_scope(dc_ip):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        client = LdapClient(
            dc_ip=dc_ip, domain=domain,
            username=self.config.extra.get("username", ""),
            password=self.config.extra.get("password", ""),
        )
        if not client.connect():
            return self._make_result(start)

        try:
            await self._check_hybrid(client, domain, dc_ip)
        finally:
            client.disconnect()

        return self._make_result(start)

    async def _check_hybrid(self, client: LdapClient, domain: str, dc_ip: str) -> None:
        # 1. Find MSOL_* / AAD Connect sync accounts (have DCSync rights by default)
        all_users = client.search(
            "(objectClass=user)",
            ["sAMAccountName", "description", "adminCount",
             "userAccountControl", "memberOf", "distinguishedName"],
        )

        msol_accounts: list[dict] = []
        pta_accounts:  list[dict] = []

        for user in all_users:
            name = str(user.get("sAMAccountName") or "").upper()
            desc = str(user.get("description") or "").lower()

            is_msol = (
                any(pat in name for pat in MSOL_PATTERNS) or
                "azure active directory connect" in desc or
                "aad connect" in desc or
                "dirsync" in desc
            )
            is_pta = any(pat in name for pat in PTA_PATTERNS)

            if is_msol:
                msol_accounts.append(user)
            elif is_pta:
                pta_accounts.append(user)

        # 2. Check for AdSyncAdmins group
        sync_admins = client.search(
            "(cn=ADSyncAdmins)",
            ["member", "distinguishedName"],
        )

        # 3. Check for AZUREADSSOACC$ (Kerberos Seamless SSO account)
        sso_accounts = client.search(
            "(sAMAccountName=AZUREADSSOACC$)",
            ["sAMAccountName", "userAccountControl", "msDS-SupportedEncryptionTypes"],
        )

        # 4. Check domain-level for sync indicators
        domain_info = client.get_domain_info()

        self.log.info(
            "Entra hybrid: MSOL accounts=%d, PTA accounts=%d, SSO accounts=%d",
            len(msol_accounts), len(pta_accounts), len(sso_accounts),
        )

        if msol_accounts:
            names = [str(a.get("sAMAccountName")) for a in msol_accounts]
            ev = Evidence(extra={
                "msol_accounts":     names,
                "adsynadmins_found": bool(sync_admins),
            })
            self.new_finding(
                title=f"Azure AD Connect (MSOL_*) Accounts Found — DCSync Rights",
                severity=Severity.CRITICAL,
                description=(
                    f"Found {len(msol_accounts)} Azure AD Connect / MSOL account(s): {names}.\n\n"
                    "These accounts are created by AAD Connect during installation and granted "
                    "DS-Replication-Get-Changes + DS-Replication-Get-Changes-All rights on the "
                    "domain — equivalent to DCSync access.\n\n"
                    "Attack chain (Password Hash Sync abuse):\n"
                    "1. Compromise the AAD Connect server (often an unmonitored server)\n"
                    "2. Extract MSOL account credentials from AAD Connect's encrypted config\n"
                    "3. Use MSOL credentials to perform DCSync → dump all hashes\n\n"
                    "Tool: AADInternals (Invoke-AADIntReconAsInsider)"
                ),
                reproduction_steps=[
                    "# Extract MSOL credentials from AAD Connect server (requires local admin):",
                    "Import-Module AADInternals",
                    "Get-AADIntSyncCredentials",
                    "# Then DCSync with extracted credentials:",
                    f"impacket-secretsdump {domain}/MSOL_XXXXXXXX:<password>@{dc_ip}",
                ],
                remediation=(
                    "Ensure AAD Connect server is in Tier 0 (same protection as DCs). "
                    "Enable Privileged Identity Management (PIM) for sync account. "
                    "Monitor for DCSync (Event 4662) from non-DC accounts. "
                    "Use Managed Identity or Federated Identity where possible instead of PHS."
                ),
                references=[
                    "MITRE T1003.006",
                    "AADInternals tool",
                    "https://o365blog.com/post/on-prem_admin/",
                ],
                evidence=ev,
                cvss_v31_vector=CVSS_MSOL,
                cvss_v40_vector=CVSS40_MSOL,
                mitre_attack=["TA0006/T1003.006"],
                target=dc_ip,
            )

        if sso_accounts:
            sso_name = str(sso_accounts[0].get("sAMAccountName") or "AZUREADSSOACC$")
            ev = Evidence(extra={
                "account": sso_name,
                "note":    "AES key used to forge Kerberos tickets for seamless SSO users",
            })
            self.new_finding(
                title=f"Azure AD Seamless SSO Account Found ({sso_name})",
                severity=Severity.HIGH,
                description=(
                    f"The Seamless SSO computer account '{sso_name}' was found. "
                    "Entra Seamless SSO uses a Kerberos ticket issued using this account's "
                    "AES key to authenticate cloud users without passwords.\n\n"
                    "If an attacker obtains this account's NTLM hash or AES key (via DCSync), "
                    "they can forge Kerberos tickets to impersonate ANY synchronized user "
                    "for Azure AD authentication."
                ),
                reproduction_steps=[
                    f"# Extract AZUREADSSOACC$ hash via DCSync:",
                    f"impacket-secretsdump {domain}/da_user@{dc_ip} -just-dc-user AZUREADSSOACC$",
                    "# Forge Silver ticket for AAD authentication:",
                    "Import-Module AADInternals",
                    "New-AADIntKerberosTicket -ADSSOKey <aes_key> -User victim@tenant.onmicrosoft.com",
                ],
                remediation=(
                    "Rotate the AZUREADSSOACC$ password from AAD Connect: "
                    "Update-MsolFederatedDomain -DomainName <domain> -SupportMultipleDomain\n"
                    "Rotate every 30 days or after any DC compromise. "
                    "Monitor for Kerberos tickets from AZUREADSSOACC$ to unexpected services."
                ),
                references=[
                    "MITRE T1558",
                    "https://docs.microsoft.com/azure/active-directory/hybrid/how-to-connect-sso-how-it-works",
                ],
                evidence=ev,
                cvss_v31_vector=CVSS_HYBRID,
                cvss_v40_vector=CVSS40_HYBRID,
                mitre_attack=["TA0006/T1558"],
                target=dc_ip,
            )

        if pta_accounts:
            names = [str(a.get("sAMAccountName")) for a in pta_accounts]
            self.new_finding(
                title=f"Pass-Through Authentication (PTA) Agent Account Found ({', '.join(names)})",
                severity=Severity.HIGH,
                description=(
                    f"PTA agent account(s) detected: {names}. "
                    "PTA forwards authentication requests to on-prem AD — an attacker who "
                    "compromises the PTA agent server can intercept cleartext credentials "
                    "of ALL cloud-only Entra ID users authenticating from that agent.\n\n"
                    "Tool: AADInternals (Invoke-AADIntPTABackdoor — installs rogue PTA DLL)"
                ),
                reproduction_steps=[
                    "# Install backdoor PTA DLL (requires local admin on PTA agent server):",
                    "Install-AADIntPTAAgent",
                    "Set-AADIntPTAEnabledForPasswordHash",
                    "# Captured credentials appear in AADInternals output",
                ],
                remediation=(
                    "Treat PTA agent servers as Tier 0 (same level as DCs). "
                    "Monitor PTA agent health in Entra ID portal. "
                    "Consider switching to PHS (Password Hash Sync) with MFA — "
                    "PHS is less susceptible to on-prem agent compromise for cloud auth."
                ),
                references=["MITRE T1556.007", "AADInternals PTA backdoor research"],
                evidence=Evidence(extra={"pta_accounts": names}),
                cvss_v31_vector=CVSS_MSOL,
                cvss_v40_vector=CVSS40_MSOL,
                mitre_attack=["TA0006/T1556.007"],
                target=dc_ip,
            )

        # Check for Hybrid Azure AD Joined devices (HAADJ) — PRT theft surface
        haadj_devices = client.search(
            "(&(objectClass=computer)(userCertificate=*))",
            ["sAMAccountName", "dNSHostName", "operatingSystem"],
        )
        if haadj_devices:
            self.log.info("Found %d HAADJ-candidate devices (have userCertificate)", len(haadj_devices))
            self.new_finding(
                title=f"Hybrid Azure AD Joined Devices Found ({len(haadj_devices)}) — PRT Theft Surface",
                severity=Severity.MEDIUM,
                description=(
                    f"{len(haadj_devices)} device(s) appear Hybrid Azure AD Joined "
                    "(have userCertificate). These devices hold Primary Refresh Tokens (PRT) "
                    "which provide seamless SSO to ALL Entra ID resources.\n\n"
                    "PRT theft attack chain:\n"
                    "1. Compromise any user session on a HAADJ device\n"
                    "2. Extract PRT using Mimikatz (sekurlsa::cloudap) or ROADtoken\n"
                    "3. Use PRT to mint access tokens for any cloud app without MFA\n\n"
                    "Device count: {len(haadj_devices)}"
                ),
                reproduction_steps=[
                    "# Extract PRT from LSASS (requires local admin):",
                    "mimikatz # sekurlsa::cloudap",
                    "# Or use ROADtoken (no LSASS required, user-space):",
                    "ROADtoken.exe",
                    "# Use stolen PRT to get tokens:",
                    "roadrecon auth --prt-cookie <prt_cookie> --prt-context <context>",
                ],
                remediation=(
                    "Enable Conditional Access policy requiring compliant device + MFA. "
                    "Deploy Microsoft Defender for Endpoint to detect LSASS access. "
                    "Enable Entra ID Sign-in Risk policies to detect anomalous PRT usage. "
                    "Consider Continuous Access Evaluation (CAE) to revoke tokens in real time."
                ),
                references=[
                    "MITRE T1528", "ROADtools research", "Mimikatz sekurlsa::cloudap",
                    "https://posts.specterops.io/death-from-above-lateral-movement-from-azure-to-on-prem-ad-d18cb3959d4d",
                ],
                evidence=Evidence(extra={"haadj_count": len(haadj_devices)}),
                cvss_v31_vector=CVSS_PRT,
                cvss_v40_vector=CVSS40_PRT,
                mitre_attack=["TA0006/T1528"],
                target=dc_ip,
            )

        if not msol_accounts and not sso_accounts and not pta_accounts:
            self.log.info("No Microsoft Entra / hybrid indicators found in domain")


class TestEntraHybrid:
    def test_msol_patterns(self) -> None:
        assert "MSOL_" in MSOL_PATTERNS
        assert "AAD_" in MSOL_PATTERNS

    def test_cvss(self) -> None:
        assert CVSS_MSOL.startswith("CVSS:3.1")
