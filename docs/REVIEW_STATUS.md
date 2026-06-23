# forge-suite Code Review — Handoff Status
# All fixes applied so far are ALREADY IN THE FILES ON DISK.
# This document describes the 4 remaining bugs to fix.

---

## REMAINING BUGS TO FIX (4 items)

### Bug 1 — `adforge/modules/acl_abuse/acl_scanner.py`
**Problem:** `_analyze_security_descriptor()` calls `str(sd)` on an ldap3 binary blob,
then applies an SDDL regex on the bytes-repr string. It will NEVER match anything.
The `nTSecurityDescriptor` attribute from ldap3 is raw binary bytes, not SDDL text.

**Fix:** Parse with impacket's `SR_SECURITY_DESCRIPTOR`. Replace `_analyze_security_descriptor` with:

```python
def _analyze_security_descriptor(self, raw_sd: object, dn: str) -> list[dict]:
    issues: list[dict] = []
    try:
        from impacket.ldap import ldaptypes
        if isinstance(raw_sd, (bytes, bytearray)):
            sd_bytes = bytes(raw_sd)
        elif hasattr(raw_sd, "raw_values"):
            sd_bytes = raw_sd.raw_values[0]
        else:
            return issues

        sd = ldaptypes.SR_SECURITY_DESCRIPTOR()
        sd.fromString(sd_bytes)

        if not sd.get("Dacl"):
            return issues

        for ace in sd["Dacl"]["Data"]:
            if ace["TypeName"] not in ("ACCESS_ALLOWED_ACE", "ACCESS_ALLOWED_OBJECT_ACE"):
                continue
            mask = ace["Ace"]["Mask"]["Mask"]
            sid_obj = ace["Ace"]["Sid"]
            sid_str = sid_obj.formatCanonical()

            # Skip well-known admin SIDs
            SKIP_SIDS = {
                "S-1-5-18",       # SYSTEM
                "S-1-5-32-544",   # Administrators
                "S-1-5-32-512",   # Domain Admins (well-known)
            }
            if sid_str in SKIP_SIDS:
                continue

            RIGHT_MAP = {
                0xF01FF: "GenericAll",
                0x40000: "WriteDACL",
                0x80000: "WriteOwner",
                0x20000: "WriteProperty",
                0x10000: "DeleteChild",
            }
            for mask_val, right_name in RIGHT_MAP.items():
                if mask & mask_val == mask_val:
                    issues.append({"trustee": sid_str, "right": right_name})
                    break
            # AllExtendedRights
            if mask & 0x100:
                issues.append({"trustee": sid_str, "right": "AllExtendedRights"})
    except ImportError:
        pass
    except Exception as exc:
        self.log.debug("SD parse error on %s: %s", dn, exc)
    return issues
```

Also: the `client.search()` call must request `nTSecurityDescriptor` as a **control**
so ldap3 returns raw bytes. Update the search call to:
```python
entries = client.search(
    "(objectClass=domain)",
    ["distinguishedName", "nTSecurityDescriptor"],
)
# And pass controls=["1.2.840.113556.1.4.801"] to get raw SD bytes
```

Simplest fix: add `controls` parameter to `LdapClient.search()` and pass
`["1.2.840.113556.1.4.801:criticality=False:base64value=MAQCAQQ="]`
(SD_FLAGS_CONTROL requesting DACL only).

OR — simpler approach: use the ldap3 `SECURITY_DESCRIPTOR_CONTROL` in Connection
initialization:
```python
from ldap3 import SECURITY_DESCRIPTOR_CONTROL
# In LdapClient.search(), add controls parameter:
self._conn.search(..., controls=security_descriptor_control(sdflags=0x4))
```

---

### Bug 2 — `adforge/modules/attacks/asrep_roast.py`
**Two issues:**

**2a — Hash format bug (line 134):**
```python
# WRONG — base64 split at char 32 is not hashcat format:
hashes.append(f"$krb5asrep$23${username}@{domain.upper()}:{b64[:32]}${b64[32:]}")
```
Same bug as `kerberoast.py` which was already fixed. The correct hashcat `$krb5asrep$23$`
format uses hex-encoded cipher bytes. For AS-REP the TGT bytes from impacket need to be
split as: last 16 bytes = checksum (hex), rest = data (hex).

**Fix:**
```python
# Replace the hash formatting block with:
tgt_bytes = tgt  # raw bytes from impacket
if len(tgt_bytes) <= 16:
    checksum = tgt_bytes.hex()
    data = ""
else:
    checksum = tgt_bytes[-16:].hex()
    data = tgt_bytes[:-16].hex()
hashes.append(f"$krb5asrep$23${username}@{domain.upper()}:{checksum}${data}")
```

**2b — Targeting ALL users instead of pre-auth-disabled only (line 37):**
```python
# CURRENT — falls back to ALL 50 domain users:
asrep_accounts = self.config.extra.get("asrep_accounts", users[:50])
```
Most of those users HAVE pre-auth enabled, so their AS-REQs will fail (correctly),
but this creates noise and potential alerts for 50 failed requests.

**Fix:** Only roast accounts specifically identified as pre-auth-disabled by `user_enum`
or `asrep_enum`. Change line 37 to:
```python
# Use asrep_enum results (UAC_DONT_REQUIRE_PREAUTH flagged accounts only):
asrep_accounts = self.config.extra.get("asrep_accounts", [])
if not asrep_accounts:
    # Fall back to accounts user_enum flagged with no_preauth UAC bit
    asrep_accounts = self.config.extra.get("no_preauth_accounts", [])
```
Also update `user_enum.py` to store `config.extra["no_preauth_accounts"]` = the list
of account names with `UAC_DONT_REQUIRE_PREAUTH` set (it already builds `no_preauth`
list internally but doesn't store it to config.extra).

---

### Bug 3 — `netforge/modules/discovery/port_scanner.py`
**Two issues:**

**3a — WinRM (5985/5986) completely missing from TOP_PORTS.**
Critical for Windows networks — WinRM is the primary lateral movement protocol
via Evil-WinRM, CrackMapExec, etc.

**Fix:** Add to TOP_PORTS list:
```python
TOP_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139,
    143, 443, 445, 993, 995, 1433, 1521, 1723,
    2049, 2375, 3306, 3389, 4848, 5432, 5900, 5985, 5986,  # Added 1433,2049,5985,5986
    6379, 7001, 8080, 8443, 8888, 9000, 9090, 9200, 9300,
    11211, 27017, 50000,  # Memcached, MongoDB, SAP
]
```

Also add to BANNER_PORTS:
```python
5985:  "WinRM-HTTP",
5986:  "WinRM-HTTPS",
1433:  "MSSQL",
2049:  "NFS",
7001:  "WebLogic",
9300:  "Elasticsearch-Cluster",
```

**3b — 20-host cap too low for internal scans.**
Line 47: `for host in hosts[:20]` — for a /24 internal subnet with 254 hosts, this
misses 93% of targets.

**Fix:** Increase to 254 (full /24) or make it configurable:
```python
host_limit = self.config.extra.get("host_limit", 254)
for host in hosts[:host_limit]:
```

Also flag WinRM as a risky service:
```python
risky = [p for p in ports if p["port"] in [23, 21, 135, 445, 3389, 5900, 5985, 5986, 2375]]
```

---

### Bug 4 — `webforge/modules/injection/xss_scanner.py`
**Problem:** Only tests URL GET parameters. POST form bodies never tested.
(SQLi already got this fix — XSS needs the same treatment.)

**Fix:** After `_test_url_params`, add `_test_post_forms` method and call it from `run()`:

```python
async def run(self) -> ModuleResult:
    start = time.monotonic()
    target = self.config.target
    if not self.check_scope(target):
        return self._make_result(start, skipped=True, skip_reason="out of scope")

    from webforge.core.session import ForgeSession
    async with ForgeSession(
        rate=self.config.rate.requests_per_second,
        proxy=self.config.extra.get("proxy"),
    ) as session:
        await self._test_url_params(session, target)
        for form in self.config.extra.get("found_forms", [])[:15]:
            await self._test_post_form(session, form, target)
        await self._test_dom_xss(target)

    return self._make_result(start)


async def _test_post_form(self, session: Any, form: dict, target: str) -> None:
    action = form.get("action") or target
    inputs = form.get("inputs", [])
    if form.get("method", "GET").upper() != "POST" or not inputs:
        return

    for field_name in inputs:
        for payload in PAYLOADS_REFLECTED[:8]:
            await self.rate_limit()
            canary = f"{CANARY_PREFIX}{hashlib.md5(payload.encode()).hexdigest()[:8]}"
            tagged = payload.replace("alert(1)", f"alert('{canary}')")
            data   = {i: "test" for i in inputs}
            data[field_name] = tagged
            try:
                resp = await session.post(action, data=data)
                body = await resp.text()
                if tagged in body or canary in body:
                    ev = Evidence(
                        request_raw=f"POST {action} | {field_name}={tagged}",
                        response_raw=body[:2000],
                        extra={"field": field_name, "payload": tagged},
                    )
                    self.new_finding(
                        title=f"Reflected XSS (POST) — Field '{field_name}'",
                        severity=Severity.HIGH,
                        description=(
                            f"Reflected XSS in POST field '{field_name}' at {action}. "
                            f"Payload reflected without sanitisation."
                        ),
                        reproduction_steps=[
                            f"curl -X POST '{action}' -d '{field_name}={tagged}'",
                        ],
                        remediation=(
                            "Apply context-aware output encoding. "
                            "Use a templating engine with auto-escaping. "
                            "Implement a strict Content Security Policy."
                        ),
                        references=["CWE-79", "OWASP A03:2021"],
                        evidence=ev,
                        cvss_v31_vector=CVSS_XSS_REFLECTED,
                        mitre_attack=["TA0004/T1059.007"],
                        target=action,
                    )
                    return
            except Exception:
                pass
```

---

## WHAT WAS ALREADY FIXED (do not re-apply)

### Common infrastructure
- `finding.py` — removed duplicate Evidence class, moved `import math` to top
- `ldap_client.py` — `search_scope` parameter was silently ignored
- `password_spray.py` — missing `conn.unbind()` on locked path; `_get_password_policy` duplicated LDAP code
- `reporter.py` — inline imports inside loop; switched to Jinja2; `common/templates/report.html.j2` created
- `kerberos_client.py` — hardcoded `/tmp/spn_hashes.txt` → tempfile
- `kerberoast.py` — hardcoded `/tmp/tgs.txt` → tempfile; fixed `_format_tgs_hash` hex format
- `adforge.py` — no-op `replace("_","_")`; added ScanRunModel tracking; added `--autopilot`
- `user_enum.py` — malformed LDAP filter missing `&`
- `esc1_check.py` — PHASE = 12 → 11
- `netcheck.py` — broken monkeypatch test
- `ntlm_relay.py` — both branches added host regardless of signing status
- `laps_enum.py` — complete rewrite for Windows LAPS 2023+ (msLAPS-Password, msLAPS-EncryptedPassword)
- `golden_ticket.py` — RC4-only → added AES-256 + diamond ticket guidance
- `uncons_deleg.py` — fragile DC filtering → ADS_UF_SERVER_TRUST_ACCOUNT flag

### New modules created
- `adcs/esc9_check.py` — CT_FLAG_NO_SECURITY_EXTENSION
- `adcs/esc10_check.py` — weak DC certificate mapping
- `adcs/esc11_check.py` — missing IF_ENFORCEENCRYPTICERTREQUEST
- `adcs/esc13_check.py` — OID group link
- `adcs/esc14_check.py` — altSecurityIdentities explicit mapping
- `attacks/certifried.py` — CVE-2022-26923
- `attacks/shadowcoerce.py` — MS-FSRVP coercion
- `attacks/pre2000_computers.py` — default password machine accounts
- `enum/entra_hybrid.py` — MSOL_*/AAD Connect/AZUREADSSOACC$
- `enum/rc4_check.py` — msDS-SupportedEncryptionTypes audit
- `zerologon.py` — added `_check_enforcement_mode()` via remote registry
- `common/templates/report.html.j2` — Jinja2 HTML report template

### NetForge
- `cve_matcher.py` — 8 CVEs → 32 CVEs (MOVEit, Citrix Bleed, Ivanti, PAN-OS, Fortinet, F5, TeamCity, ConnectWise, Cisco IOS XE, VMware ESXi, runc, HTTP/2 rapid reset, etc.)
- `ssh_audit.py` — removed `ecdh-sha2-nistp256` false positive; added CVE-2024-6387 regreSSHion check; added CVE-2023-38408

### WebForge
- `jwt_audit.py` — added kid path traversal (7 payloads), jwk header injection, RS256/ES256→HS256 alg confusion
- `ssrf_scanner.py` — added IPv6/decimal/hex/octal IMDS bypasses, gopher/dict schemes, IMDSv2 headers, k8s API
- `advanced/cache_deception.py` — new module
- `sqli_scanner.py` — added POST body, JSON API, and HTTP header injection testing; fixed `Any` import

### ADForge post-exploitation
- `da_check.py` — fixed invalid LDAP wildcard; added DnsAdmins→SYSTEM and BackupOps→hashdump findings; populates graph_nodes/graph_edges for attack_path_svg

---

## SYNTAX STATUS
All files confirmed ALL OK with `python3 -m py_compile` after each batch.

## HOW TO VERIFY
```bash
cd forge-suite
find . -name "*.py" | xargs python3 -m py_compile && echo "ALL OK"
```
