# Red Team Operations Reference

## Engagement Planning

### Rules of Engagement (ROE) Essentials
- Defined target scope (IP ranges, domains, cloud accounts, physical locations)
- Out-of-scope systems (production databases, life-safety systems, specific subnets)
- Deconfliction process (emergency stop card, 24/7 contact)
- Data handling requirements (no exfiltration of real PII)
- Physical access scope (if any)
- Start/end dates and blackout windows

### Threat Profile Selection
Match adversary TTP set to client's actual threat model:
- **Financial sector**: FIN7, Scattered Spider, ransomware operators
- **Critical infrastructure**: Volt Typhoon, Sandworm (living-off-the-land focus)
- **Healthcare**: ALPHV/BlackCat, TA505
- **SaaS/Cloud-native**: Oktapus/Scattered Spider, credential-focused initial access

---

## Kill Chain (Unified)

### Phase 1: Initial Access (T1566, T1190, T1078)

**Phishing** — highest success rate for initial access:
```
Targets: IT helpdesk, finance, C-suite assistants, new employees
Lures: MFA fatigue, OneDrive share, invoice, IT ticket
Infrastructure: Lookalike domain + Evilginx2/Modlishka for AiTM credential capture
```

**External exploitation**:
```bash
# Asset discovery
subfinder -d target.com | httpx -silent | nuclei -t cves/

# VPN/Citrix/Exchange surface
nuclei -u https://vpn.target.com -t cves/ -severity critical,high
```

**Valid accounts** — purchased/stealed credentials, password spray:
```bash
# MSOLSpray / TREVORspray for M365
# Smart lockout: 1 attempt per 30 min per account max
```

### Phase 2: Execution (T1059)

- PowerShell (with AMSI bypass + ScriptBlock logging evasion)
- WMI (`wmic process call create`)
- LOLBins: `mshta`, `regsvr32`, `certutil`, `rundll32`, `msiexec`

### Phase 3: Persistence (T1053, T1543, T1547)

```
Scheduled task: schtasks /create /sc DAILY /tn "WindowsUpdate" /tr "C:\Windows\update.exe"
Service: sc create svc binpath= "C:\beacon.exe"
Registry run key: HKCU\Software\Microsoft\Windows\CurrentVersion\Run
WMI subscription: permanent event consumer (fileless)
```

### Phase 4: Privilege Escalation (T1068, T1134)

- Token impersonation (SeImpersonatePrivilege → Potato attacks)
- Unquoted service paths, weak service permissions
- AlwaysInstallElevated MSI
- ADCS ESC paths → domain admin via cert auth

### Phase 5: Defense Evasion (T1027, T1055, T1562)

See evasion-c2.md for full tradecraft.

Key: maintain low process/network footprint. Use built-in Windows tools where possible (T1218 LOLBins).

### Phase 6: Credential Access (T1003, T1558)

- LSASS dump: `procdump -ma lsass.exe` / `comsvcs.dll MiniDump` / `nanodump`
- SAM/SYSTEM registry hive dump
- DPAPI — browser credentials, credential manager
- Kerberoasting, AS-REP roasting
- ADCS shadow credentials

### Phase 7: Discovery (T1018, T1069, T1087, T1482)

```powershell
# Quiet enumeration (avoid net.exe — logged)
# Use LDAP queries via PowerView or ADModule
Get-DomainUser -Properties samaccountname,memberof | Export-Csv users.csv
Get-DomainComputer -Properties name,operatingsystem | Export-Csv hosts.csv
Get-DomainGroupMember "Domain Admins"
```

### Phase 8: Lateral Movement (T1550, T1021)

```bash
# Pass-the-Hash
impacket-psexec -hashes :NTLMHASH administrator@10.0.0.5

# Pass-the-Ticket
Rubeus.exe ptt /ticket:b64ticket
Invoke-Command -ComputerName DC01 -ScriptBlock { hostname }

# WMI lateral movement (quieter than PsExec)
wmiexec.py domain/user:pass@target
```

### Phase 9: Collection + Exfiltration (T1005, T1048)

```bash
# Targeted collection — avoid bulk file copy
# Focus: password stores, strategic docs, AD config, CI/CD secrets

# Exfil via HTTPS to redirector (blend with normal traffic)
# DNS exfil if egress filtered: dnscat2, iodine
```

---

## Infrastructure Setup

### Redirectors
- Nginx/Apache reverse proxy → C2 team server (never expose C2 directly)
- Cloudflare Worker → team server (CDN fronting, legitimate TLS cert)
- Multiple redirectors per protocol (HTTP, DNS, SMTP)

### Domain Selection
- Aged domain (2+ years) — new domains flagged by Umbrella/Zscaler
- Categorized (IT/Business) — uncategorized blocked by web proxies
- Valid MX record + SPF/DKIM/DMARC for phishing domains

### Operational Security
- Segregate infrastructure per phase (phishing ≠ C2 ≠ exfil)
- Use separate VPS per engagement
- Log all operator activity for debrief
- Timestamp all actions for timeline reconstruction

---

## Purple Team Integration

Purple team = red team + blue team operating together with full visibility.

Process:
1. Agree on ATT&CK techniques to exercise
2. Red executes one TTP at a time
3. Blue confirms detection/alert (or notes gap)
4. Iterate: tune detection rule → re-execute → verify
5. Output: ATT&CK coverage heatmap + detection rule improvements

Tooling: Atomic Red Team (individual technique execution), VECTR (tracking), Prelude Operator.

---

## OPSEC Notes
- Every lateral movement attempt creates authentication logs — work from one pivot, not many
- Cobalt Strike default named pipes (`msagent_*`, `postex_*`) are fingerprinted — rename in profile
- LSASS access (OpenProcess with PROCESS_VM_READ) generates Event 10 in Sysmon — use protected process bypasses
- Time operations to business hours (8am-6pm local) — anomaly detection models flag off-hours activity
