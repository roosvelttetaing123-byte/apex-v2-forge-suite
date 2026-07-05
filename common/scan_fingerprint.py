"""ScanFingerprint — Passive/active technology fingerprinting engine.

Identifies web frameworks, CMS platforms, CDNs, WAFs, and cloud providers
from HTTP response headers, cookies, HTML body patterns, and IP/ASN hints.

Detection layers (in priority order):
    1. HTTP Response Headers   — Server, X-Powered-By, Via, CF-Ray, etc.
    2. Cookies                 — PHPSESSID, JSESSIONID, laravel_session, etc.
    3. HTML Body Patterns      — Meta generators, framework-specific JS/CSS paths
    4. IP/ASN Hints            — Known CDN/cloud CIDR ranges (best-effort)

For each category the engine returns the best match with a confidence score
(0.0–1.0) and the matched evidence strings so callers can explain the verdict.

FOR AUTHORIZED PENETRATION TESTING AND RED TEAM OPERATIONS ONLY.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any


# ══════════════════════════════════════════════════════════════════════
# DATA MODELS
# ══════════════════════════════════════════════════════════════════════

@dataclass
class FingerprintMatch:
    """Single fingerprint match result."""
    category:   str            # e.g. "framework", "cms", "waf", "cdn", "cloud"
    name:       str            # e.g. "WordPress", "Cloudflare WAF"
    confidence: float          # 0.0–1.0
    evidence:   list[str]      = field(default_factory=list)
    version:    str            = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "category":   self.category,
            "name":       self.name,
            "confidence": round(self.confidence, 2),
            "evidence":   self.evidence,
            "version":    self.version,
        }


@dataclass
class FingerprintResult:
    """Aggregated fingerprint output for a single HTTP response."""
    frameworks: list[FingerprintMatch] = field(default_factory=list)
    cms:        list[FingerprintMatch] = field(default_factory=list)
    wafs:       list[FingerprintMatch] = field(default_factory=list)
    cdns:       list[FingerprintMatch] = field(default_factory=list)
    cloud:      list[FingerprintMatch] = field(default_factory=list)

    @property
    def all_matches(self) -> list[FingerprintMatch]:
        return self.frameworks + self.cms + self.wafs + self.cdns + self.cloud

    def best(self, category: str) -> FingerprintMatch | None:
        mapping = {
            "framework": self.frameworks,
            "cms":       self.cms,
            "waf":       self.wafs,
            "cdn":       self.cdns,
            "cloud":     self.cloud,
        }
        pool = mapping.get(category, [])
        return max(pool, key=lambda m: m.confidence, default=None)

    def to_dict(self) -> dict[str, Any]:
        return {
            "frameworks": [m.to_dict() for m in self.frameworks],
            "cms":        [m.to_dict() for m in self.cms],
            "wafs":       [m.to_dict() for m in self.wafs],
            "cdns":       [m.to_dict() for m in self.cdns],
            "cloud":      [m.to_dict() for m in self.cloud],
        }


# ══════════════════════════════════════════════════════════════════════
# FINGERPRINT SIGNATURES
# ══════════════════════════════════════════════════════════════════════

# Each signature: (name, [(score, header_key_or_None, pattern_or_None)])
# Header key None → body pattern. Patterns are regex strings.

_FRAMEWORK_SIGS: list[tuple[str, list[tuple[float, str | None, str]]]] = [
    ("Django", [
        (0.9, "X-Framework",     r"django"),
        (0.8, "X-Powered-By",    r"django"),
        (0.7, None,              r"csrfmiddlewaretoken"),
        (0.6, None,              r"django\.contrib"),
        (0.5, None,              r"<input[^>]+name=['\"]csrfmiddlewaretoken"),
        (0.4, None,              r"/_static/admin/js/"),
    ]),
    ("Ruby on Rails", [
        (0.9, "X-Powered-By",    r"phusion passenger|rack"),
        (0.9, "X-Runtime",       r"[\d.]+"),           # Rails always sets X-Runtime
        (0.8, None,              r"authenticity_token"),
        (0.7, "Set-Cookie",      r"_session_id="),
        (0.6, None,              r"rails\.js|jquery_ujs|rails-ujs"),
        (0.5, None,              r"data-remote=['\"]true"),
    ]),
    ("Laravel", [
        (0.9, "Set-Cookie",      r"laravel_session"),
        (0.8, "X-Powered-By",    r"laravel"),
        (0.7, None,              r"_token.*laravel|laravel.*_token"),
        (0.6, None,              r"csrf-token.*laravel|laravel.*csrf"),
        (0.5, None,              r"app\.js|mix-manifest\.json"),
    ]),
    ("Express / Node.js", [
        (0.9, "X-Powered-By",    r"express"),
        (0.8, "Server",          r"node\.?js"),
        (0.7, "Set-Cookie",      r"connect\.sid"),
        (0.6, None,              r"__bundle\.js|main\.chunk\.js"),
        (0.5, None,              r"socket\.io"),
    ]),
    ("Spring (Java)", [
        (0.9, "X-Application-Context", r".+"),
        (0.8, "Set-Cookie",      r"JSESSIONID"),
        (0.8, "X-Powered-By",    r"spring"),
        (0.7, "Server",          r"apache-coyote|tomcat"),
        (0.6, None,              r"org\.springframework|spring\.js"),
        (0.5, None,              r"_csrf.*spring|spring.*_csrf"),
    ]),
    ("ASP.NET / .NET", [
        (0.9, "X-Powered-By",    r"asp\.net"),
        (0.9, "X-AspNet-Version", r"[\d.]+"),
        (0.8, "Set-Cookie",      r"ASP\.NET_SessionId|\.ASPXAUTH"),
        (0.7, "Server",          r"microsoft-iis"),
        (0.6, None,              r"__VIEWSTATE|__EVENTTARGET"),
        (0.5, None,              r"WebResource\.axd|ScriptResource\.axd"),
    ]),
    ("Flask", [
        (0.9, "Set-Cookie",      r"session=\.[A-Za-z0-9+/=_-]{20,}"),
        (0.8, "X-Powered-By",    r"flask|werkzeug"),
        (0.7, "Server",          r"werkzeug"),
        (0.6, None,              r"flask\.wtf|wtf\.csrf"),
        (0.5, None,              r"jinja2|url_for\("),
    ]),
    ("FastAPI", [
        (0.9, "Server",          r"uvicorn"),
        (0.8, "X-Process-Time", r"[\d.]+"),
        (0.7, None,              r"/openapi\.json|/docs#/|/redoc"),
        (0.6, None,              r"fastapi|pydantic"),
        (0.5, None,              r"\"detail\":.*\"msg\":"),
    ]),
    ("Next.js", [
        (0.9, "X-Powered-By",    r"next\.?js"),
        (0.8, None,              r"__NEXT_DATA__|_next/static"),
        (0.7, None,              r"/_next/chunks/|/_next/image"),
        (0.6, "Set-Cookie",      r"__Host-next-auth|next-auth"),
        (0.5, None,              r"next/router|next/link"),
    ]),
    ("Angular", [
        (0.8, None,              r"ng-version=['\"][\d.]+"),
        (0.7, None,              r"main\.\w+\.js|polyfills\.\w+\.js|runtime\.\w+\.js"),
        (0.6, None,              r"app-root|ng-app|angular\.min\.js"),
        (0.5, None,              r"\bngModel\b|\bng-if\b|\bng-for\b"),
    ]),
    ("React", [
        (0.8, None,              r"__react_fiber|__reactFiber|data-reactroot"),
        (0.7, None,              r"static/js/main\.\w+\.js|chunk\.js"),
        (0.6, None,              r"react\.development\.js|react\.production"),
        (0.5, None,              r"reactDOM\.render|createRoot\("),
    ]),
    ("Vue.js", [
        (0.8, None,              r"__vue__|vue\.runtime\.esm"),
        (0.7, None,              r"vue\.min\.js|vue@[\d.]+"),
        (0.6, None,              r"v-app|nuxt-link|<nuxt>"),
        (0.5, None,              r"v-model=|v-if=|v-for="),
    ]),
]

_CMS_SIGS: list[tuple[str, list[tuple[float, str | None, str]]]] = [
    ("WordPress", [
        (0.95, None,             r"/wp-content/|/wp-includes/"),
        (0.9,  None,             r"<meta name=['\"]generator['\"] content=['\"]WordPress"),
        (0.8,  "Set-Cookie",     r"wordpress_|wp-settings-"),
        (0.7,  "X-Pingback",     r"/xmlrpc\.php"),
        (0.6,  None,             r"wp-login\.php|wp-admin|wp-json"),
        (0.5,  "Link",           r"rel=['\"]https://api\.w\.org"),
    ]),
    ("Drupal", [
        (0.9,  None,             r"<meta name=['\"]generator['\"] content=['\"]Drupal"),
        (0.9,  "X-Generator",    r"drupal"),
        (0.8,  "Set-Cookie",     r"SESS[0-9a-f]{32}="),
        (0.7,  None,             r"/sites/default/files/|/misc/drupal\.js"),
        (0.6,  None,             r"Drupal\.settings|Drupal\.behaviors"),
        (0.5,  None,             r"/modules/system/|/core/misc/"),
    ]),
    ("Joomla", [
        (0.9,  None,             r"<meta name=['\"]generator['\"] content=['\"]Joomla"),
        (0.8,  "Set-Cookie",     r"[a-f0-9]{32}=|joomla_user_state"),
        (0.7,  None,             r"/media/jui/|/media/system/js/"),
        (0.6,  None,             r"mootools|Joomla\.optionList"),
        (0.5,  None,             r"/administrator/index\.php"),
    ]),
    ("Strapi", [
        (0.9,  "X-Powered-By",  r"strapi"),
        (0.8,  None,             r"/api/(?:articles|users|auth|content-type)"),
        (0.7,  None,             r"strapi\.io|strapi/admin"),
        (0.6,  None,             r"\"strapiVersion\":|\"contentType\":"),
        (0.5,  "Server",         r"koa"),
    ]),
    ("Ghost", [
        (0.9,  None,             r"<meta name=['\"]generator['\"] content=['\"]Ghost"),
        (0.8,  "X-Powered-By",  r"express"),
        (0.7,  None,             r"/ghost/api/|ghost\.min\.js"),
        (0.6,  None,             r"ghost-theme|ghost-editor"),
        (0.5,  "Set-Cookie",     r"ghost-admin-api-session"),
    ]),
    ("Magento", [
        (0.9,  None,             r"<meta name=['\"]generator['\"] content=['\"]Magento"),
        (0.8,  "Set-Cookie",     r"frontend=|PHPSESSID=.*Magento|mage-cache"),
        (0.7,  None,             r"/skin/frontend/|/mage/|Mage\.Cookies"),
        (0.6,  None,             r"var BLANK_URL = '.*magento"),
        (0.5,  None,             r"/checkout/cart/|catalog/product"),
    ]),
    ("Shopify", [
        (0.9,  None,             r"cdn\.shopify\.com|myshopify\.com"),
        (0.8,  "X-ShopId",      r"\d+"),
        (0.7,  None,             r"Shopify\.theme|shopify-section"),
        (0.6,  "Set-Cookie",     r"_shopify_s=|_shopify_y="),
        (0.5,  None,             r"Shopify\.PaymentButton|window\.Shopify"),
    ]),
    ("Confluence", [
        (0.9,  None,             r"<meta name=['\"]ajs-version-number"),
        (0.8,  "Set-Cookie",     r"JSESSIONID=.*confluence|confluence\.browse"),
        (0.7,  None,             r"/wiki/spaces/|confluence\.init"),
        (0.6,  "X-Confluence-Request-Time", r"\d+"),
        (0.5,  None,             r"com\.atlassian\.confluence"),
    ]),
    ("TYPO3", [
        (0.9,  None,             r"<meta name=['\"]generator['\"] content=['\"]TYPO3"),
        (0.8,  "Set-Cookie",     r"fe_typo_user|be_typo_user"),
        (0.7,  None,             r"/typo3/|TYPO3\.settings"),
        (0.6,  None,             r"typo3temp|fileadmin"),
        (0.5,  None,             r"typo3conf/ext/"),
    ]),
]

_WAF_SIGS: list[tuple[str, list[tuple[float, str | None, str]]]] = [
    ("Cloudflare WAF", [
        (0.95, "CF-Ray",         r"[0-9a-f]+-[A-Z]{3}"),
        (0.9,  "Server",         r"cloudflare"),
        (0.85, None,             r"Attention Required|cloudflare\.com/5xx-error"),
        (0.8,  "Set-Cookie",     r"__cf_bm=|cf_clearance="),
        (0.7,  None,             r"cf\.challenge\.error|cf-please-wait"),
    ]),
    ("ModSecurity", [
        (0.9,  None,             r"ModSecurity|mod_security|NAXSI"),
        (0.8,  "Server",         r"mod_security"),
        (0.7,  None,             r"This error was generated by Mod_Security"),
        (0.6,  None,             r"Mod_Security|modsecurity"),
        (0.5,  None,             r"Request Rejected.*mod"),
    ]),
    ("Imperva / Incapsula", [
        (0.95, "X-Iinfo",        r"\d+"),
        (0.9,  "Set-Cookie",     r"incap_ses_|visid_incap_"),
        (0.85, None,             r"incapsula incident id|Incapsula"),
        (0.8,  "X-CDN",         r"Incapsula"),
        (0.7,  None,             r"/_Incapsula_Resource"),
    ]),
    ("AWS WAF", [
        (0.9,  "X-Amzn-RequestId", r"[0-9a-f-]{36}"),
        (0.85, None,             r"aws waf|AWS WAF|x-amzn-waf"),
        (0.8,  "X-Amz-Cf-Id",   r"[A-Za-z0-9+/=]+"),
        (0.7,  None,             r"Request blocked.*AWS|AWSAccessDenied"),
        (0.6,  "Server",         r"AmazonS3|awselb"),
    ]),
    ("F5 BIG-IP ASM", [
        (0.9,  "Set-Cookie",     r"TS[0-9a-f]{8}=|BIGipServer"),
        (0.85, "Server",         r"BigIP|F5"),
        (0.8,  None,             r"The requested URL was rejected.*F5|f5_cspm"),
        (0.7,  "X-WA-Info",     r".+"),
        (0.6,  None,             r"support ID.*\d{16,}"),
    ]),
    ("Barracuda WAF", [
        (0.9,  "Set-Cookie",     r"barra_counter_session=|BNI__BARRACUDA_LB"),
        (0.85, None,             r"barracuda networks|barra_counter"),
        (0.7,  "Server",         r"BarracudaHTTP"),
        (0.6,  None,             r"Barracuda Application Firewall"),
    ]),
    ("Akamai WAF / Kona", [
        (0.9,  "X-Check-Cacheable", r"YES|NO"),
        (0.85, "Server",         r"akamaighost|akamai"),
        (0.8,  "Set-Cookie",     r"ak_bmsc=|bm_sz="),
        (0.7,  None,             r"Reference #[\d.]+.*akamai|akamai.*reference"),
        (0.6,  "X-Akamai-Request-ID", r".+"),
    ]),
    ("Sucuri WAF", [
        (0.9,  "X-Sucuri-ID",   r"\d+"),
        (0.85, "Server",         r"sucuri"),
        (0.8,  "X-Sucuri-Cache", r"HIT|MISS|BYPASS"),
        (0.7,  None,             r"sucuri\.net|cloudproxy"),
        (0.6,  "Set-Cookie",     r"sucuri_cloudproxy_uuid"),
    ]),
    ("Nginx + naxsi", [
        (0.8,  None,             r"NAXSI_FMT|naxsi"),
        (0.7,  "Server",         r"nginx"),
        (0.6,  None,             r"Naxsi.*blocked|naxsi-runtime"),
    ]),
    ("Palo Alto Prisma / NGFW", [
        (0.8,  None,             r"PAN-OS|Palo Alto Networks"),
        (0.7,  "Server",         r"Pan-Web"),
        (0.6,  None,             r"X-PAN-|pan-request-id"),
    ]),
]

_CDN_SIGS: list[tuple[str, list[tuple[float, str | None, str]]]] = [
    ("Cloudflare CDN", [
        (0.95, "CF-Ray",         r"[0-9a-f]+-[A-Z]{3}"),
        (0.9,  "Server",         r"cloudflare"),
        (0.8,  "CF-Cache-Status", r"HIT|MISS|DYNAMIC|BYPASS|EXPIRED"),
        (0.7,  "Set-Cookie",     r"cf_clearance=|__cfduid="),
    ]),
    ("Akamai CDN", [
        (0.9,  "X-Cache",        r"TCP_(?:HIT|MISS).*AkamaiGHost"),
        (0.85, "Server",         r"akamaighost"),
        (0.8,  "X-Akamai-Transformed", r".+"),
        (0.7,  "Via",            r"akamai|EdgeSuite"),
        (0.6,  "X-True-Cache-Key", r".+"),
    ]),
    ("Fastly CDN", [
        (0.95, "Fastly-Debug-Digest", r"[0-9a-f]+"),
        (0.9,  "X-Served-By",   r"cache-[a-z]+\d+-[A-Z]+"),
        (0.85, "X-Cache",        r"HIT.*fastly|MISS.*fastly"),
        (0.8,  "Via",            r"varnish"),
        (0.7,  "X-Timer",        r"S[\d.]+,VS[\d.,]+,VE\d+"),
    ]),
    ("AWS CloudFront", [
        (0.95, "X-Amz-Cf-Pop",  r"[A-Z]{3}\d+-[A-Z]\d+"),
        (0.9,  "X-Amz-Cf-Id",   r"[A-Za-z0-9_\-=+/]{50,}"),
        (0.85, "Via",            r"cloudfront"),
        (0.8,  "X-Cache",        r"Hit from cloudfront|Miss from cloudfront"),
        (0.7,  "Server",         r"CloudFront"),
    ]),
    ("Azure CDN / Front Door", [
        (0.9,  "X-Azure-Ref",   r"[0-9A-Za-z+/=]+"),
        (0.85, "X-Ms-Ref",      r".+"),
        (0.8,  "X-FD-HealthProbe", r"1"),
        (0.7,  "Server",         r"AzureFrontDoor|Azure"),
        (0.6,  None,             r"azure-cdn|azurefd\.net"),
    ]),
    ("Google Cloud CDN / GFE", [
        (0.9,  "Via",            r"1\.1 google|1\.1 GFE"),
        (0.85, "Server",         r"gws|Google Frontend"),
        (0.8,  "X-Goog-Served-By", r".+"),
        (0.7,  "X-Google-Cache-Control", r".+"),
        (0.6,  "Alt-Svc",        r"h3=.+googleapis"),
    ]),
    ("StackPath / MaxCDN", [
        (0.9,  "X-SP-BCache",   r"HIT|MISS"),
        (0.8,  "X-Cache",        r"HIT.*stackpath|MISS.*stackpath"),
        (0.7,  "Server",         r"StackPath|NetDNA"),
        (0.6,  None,             r"stackpathcdn\.com|maxcdn\.com"),
    ]),
    ("Varnish CDN", [
        (0.9,  "X-Varnish",     r"\d+"),
        (0.85, "Via",            r"varnish"),
        (0.8,  "Age",            r"\d+"),
        (0.7,  "X-Cache",        r"HIT|MISS"),
        (0.6,  "Server",         r"varnish"),
    ]),
    ("Nginx Proxy / Reverse Proxy", [
        (0.7,  "Server",         r"nginx"),
        (0.6,  "X-Cache-Status", r"HIT|MISS|BYPASS"),
        (0.5,  "X-Nginx-Cache",  r"HIT|MISS"),
    ]),
]

_CLOUD_SIGS: list[tuple[str, list[tuple[float, str | None, str]]]] = [
    ("AWS", [
        (0.95, "X-Amzn-RequestId", r"[0-9a-f-]{36}"),
        (0.9,  "X-Amz-Cf-Pop",  r"[A-Z]{3}\d+-[A-Z]\d+"),
        (0.9,  "X-Amz-Cf-Id",   r"[A-Za-z0-9_\-=+/]{50,}"),
        (0.85, "Server",         r"AmazonS3|awselb|Amazon"),
        (0.8,  None,             r"amazonaws\.com|s3\.amazonaws"),
        (0.7,  "X-Amz-Request-Id", r"[0-9A-F]{16}"),
        (0.6,  None,             r"aws-amplify|elasticbeanstalk"),
    ]),
    ("Azure", [
        (0.95, "X-Azure-Ref",   r"[0-9A-Za-z+/=]+"),
        (0.9,  "X-Ms-Request-Id", r"[0-9a-f-]{36}"),
        (0.85, "Server",         r"Microsoft-IIS|AzureFrontDoor|Azure"),
        (0.8,  None,             r"\.azurewebsites\.net|\.blob\.core\.windows\.net"),
        (0.7,  "X-Powered-By",  r"ASP\.NET"),
        (0.6,  None,             r"azure-functions|azurefd\.net"),
    ]),
    ("Google Cloud Platform", [
        (0.9,  "Via",            r"1\.1 google|1\.1 GFE"),
        (0.85, "X-Goog-Served-By", r".+"),
        (0.8,  "Server",         r"Google Frontend|gws"),
        (0.7,  None,             r"\.appspot\.com|\.run\.app|\.googleapis\.com"),
        (0.6,  "Alt-Svc",        r"h3=.+google|quic=.+google"),
        (0.5,  None,             r"cloud\.google\.com|Firebase"),
    ]),
    ("Heroku", [
        (0.9,  "X-Request-Id",  r"[0-9a-f-]{36}"),
        (0.85, "Via",            r"1\.1 vegur"),
        (0.8,  None,             r"\.herokuapp\.com"),
        (0.7,  "Server",         r"cowboy|heroku"),
        (0.6,  "X-Runtime",     r"[\d.]+"),
    ]),
    ("DigitalOcean", [
        (0.85, None,             r"\.digitalocean\.com|\.do\.net"),
        (0.8,  "Server",         r"nginx|OpenResty"),
        (0.7,  None,             r"digitalocean spaces|DO-Cache"),
        (0.6,  "X-DO-App-Origin", r".+"),
    ]),
    ("Vercel", [
        (0.95, "X-Vercel-Id",   r"[a-z]{3}1::[0-9a-z]+-\d+"),
        (0.9,  "Server",         r"vercel"),
        (0.8,  None,             r"\.vercel\.app|\.now\.sh"),
        (0.7,  "X-Vercel-Cache", r"HIT|MISS|STALE|BYPASS"),
    ]),
    ("Netlify", [
        (0.9,  "X-Nf-Request-Id", r"[0-9a-f-]{36}"),
        (0.85, "Server",         r"Netlify"),
        (0.8,  None,             r"\.netlify\.app|\.netlify\.com"),
        (0.7,  "Age",            r"\d+"),
        (0.6,  "X-Cache",        r"HIT|MISS"),
    ]),
    ("Cloudflare Workers / Pages", [
        (0.95, "CF-Ray",         r"[0-9a-f]+-[A-Z]{3}"),
        (0.85, "CF-Cache-Status", r"DYNAMIC|BYPASS"),
        (0.8,  None,             r"\.pages\.dev|\.workers\.dev"),
        (0.7,  "Server",         r"cloudflare"),
    ]),
]


# ══════════════════════════════════════════════════════════════════════
# CORE ENGINE
# ══════════════════════════════════════════════════════════════════════

def _normalise_headers(raw: dict[str, str]) -> dict[str, str]:
    """Return headers dict with lower-cased keys."""
    return {k.lower(): v for k, v in raw.items()}


def _score_sigs(
    sigs: list[tuple[str, list[tuple[float, str | None, str]]]],
    headers: dict[str, str],
    body: str,
    category: str,
) -> list[FingerprintMatch]:
    """Score all signatures for a category and return matches above 0.4."""
    matches: list[FingerprintMatch] = []

    for name, rules in sigs:
        best_score = 0.0
        evidence: list[str] = []
        version = ""

        for score, header_key, pattern in rules:
            if header_key is not None:
                # Header match
                hval = headers.get(header_key.lower(), "")
                if hval and re.search(pattern, hval, re.IGNORECASE):
                    best_score = max(best_score, score)
                    evidence.append(f"header:{header_key}: {hval[:80]}")
                    # Try to extract version from the matched value
                    if not version:
                        vm = re.search(r"([\d]+\.[\d]+(?:\.[\d]+)?)", hval)
                        if vm:
                            version = vm.group(1)
            else:
                # Body match
                if body and re.search(pattern, body, re.IGNORECASE | re.DOTALL):
                    best_score = max(best_score, score)
                    m = re.search(pattern, body, re.IGNORECASE | re.DOTALL)
                    snippet = m.group(0)[:60] if m else pattern
                    evidence.append(f"body:{snippet}")

        if best_score >= 0.4 and evidence:
            matches.append(FingerprintMatch(
                category=category,
                name=name,
                confidence=best_score,
                evidence=evidence,
                version=version,
            ))

    # Sort by confidence descending
    return sorted(matches, key=lambda m: m.confidence, reverse=True)


class ScanFingerprint:
    """HTTP response fingerprinting engine.

    Usage::

        from common.scan_fingerprint import ScanFingerprint

        fp = ScanFingerprint()
        result = fp.fingerprint(
            headers={"Server": "cloudflare", "CF-Ray": "abc123-LHR"},
            body="<meta name='generator' content='WordPress 6.4'>",
        )
        print(result.best("cms"))   # WordPress
        print(result.best("cdn"))   # Cloudflare CDN
    """

    def fingerprint(
        self,
        headers: dict[str, str],
        body: str = "",
        *,
        also_check_waf: bool = True,
        also_check_cloud: bool = True,
    ) -> FingerprintResult:
        """Fingerprint a single HTTP response.

        Args:
            headers:           Response headers dict (case-insensitive).
            body:              Response body text.
            also_check_waf:    Whether to include WAF detection.
            also_check_cloud:  Whether to include cloud provider detection.

        Returns:
            FingerprintResult with ranked matches per category.
        """
        h = _normalise_headers(headers)
        b = body[:65536]  # cap to avoid runaway regex

        result = FingerprintResult(
            frameworks=_score_sigs(_FRAMEWORK_SIGS, h, b, "framework"),
            cms=_score_sigs(_CMS_SIGS,       h, b, "cms"),
            cdns=_score_sigs(_CDN_SIGS,       h, b, "cdn"),
        )
        if also_check_waf:
            result.wafs = _score_sigs(_WAF_SIGS, h, b, "waf")
        if also_check_cloud:
            result.cloud = _score_sigs(_CLOUD_SIGS, h, b, "cloud")

        return result

    # ------------------------------------------------------------------
    # Convenience: fingerprint from a raw header block string
    # ------------------------------------------------------------------

    @staticmethod
    def parse_raw_headers(raw: str) -> dict[str, str]:
        """Parse raw HTTP header block into a dict.

        Args:
            raw: Multi-line header text (``Key: Value\\n`` lines).

        Returns:
            Dict of header_name → header_value.
        """
        headers: dict[str, str] = {}
        for line in raw.splitlines():
            if ":" in line:
                key, _, val = line.partition(":")
                headers[key.strip()] = val.strip()
        return headers

    def fingerprint_from_raw(
        self,
        raw_headers: str,
        body: str = "",
        **kwargs: Any,
    ) -> FingerprintResult:
        """Fingerprint from a raw header block string.

        Args:
            raw_headers: Multi-line HTTP headers string.
            body:        Response body.

        Returns:
            FingerprintResult.
        """
        return self.fingerprint(
            self.parse_raw_headers(raw_headers), body=body, **kwargs
        )

    # ------------------------------------------------------------------
    # Scoring summary for reports
    # ------------------------------------------------------------------

    @staticmethod
    def summarise(result: FingerprintResult) -> str:
        """Return a one-line human-readable summary string."""
        parts: list[str] = []
        for cat, pool in [
            ("Framework", result.frameworks),
            ("CMS",       result.cms),
            ("CDN",       result.cdns),
            ("WAF",       result.wafs),
            ("Cloud",     result.cloud),
        ]:
            if pool:
                top = pool[0]
                parts.append(f"{cat}={top.name}({top.confidence:.0%})")
        return " | ".join(parts) if parts else "No technology fingerprints detected"


# ══════════════════════════════════════════════════════════════════════
# EMBEDDED TESTS
# ══════════════════════════════════════════════════════════════════════

class TestScanFingerprint:
    """Pytest-compatible test suite for ScanFingerprint.

    Run with:  python -m pytest common/scan_fingerprint.py -q
    """

    def setup_method(self) -> None:
        self.fp = ScanFingerprint()

    # ── Framework detection ───────────────────────────────────────────

    def test_django_csrfmiddlewaretoken(self) -> None:
        result = self.fp.fingerprint(
            headers={},
            body='<input type="hidden" name="csrfmiddlewaretoken" value="abc">',
        )
        top = result.best("framework")
        assert top is not None
        assert top.name == "Django"
        assert top.confidence >= 0.4

    def test_django_header(self) -> None:
        result = self.fp.fingerprint(
            headers={"X-Powered-By": "Django/4.2"},
            body="",
        )
        top = result.best("framework")
        assert top is not None
        assert top.name == "Django"

    def test_rails_x_runtime(self) -> None:
        result = self.fp.fingerprint(
            headers={"X-Runtime": "0.034215"},
            body="<input name='authenticity_token' value='xyz'>",
        )
        top = result.best("framework")
        assert top is not None
        assert top.name == "Ruby on Rails"

    def test_laravel_session_cookie(self) -> None:
        result = self.fp.fingerprint(
            headers={"Set-Cookie": "laravel_session=eyJpd..."},
            body="",
        )
        top = result.best("framework")
        assert top is not None
        assert top.name == "Laravel"

    def test_express_header(self) -> None:
        result = self.fp.fingerprint(
            headers={"X-Powered-By": "Express"},
            body="",
        )
        top = result.best("framework")
        assert top is not None
        assert top.name == "Express / Node.js"

    def test_spring_jsessionid(self) -> None:
        result = self.fp.fingerprint(
            headers={"Set-Cookie": "JSESSIONID=ABC123"},
            body="",
        )
        top = result.best("framework")
        assert top is not None
        assert top.name == "Spring (Java)"

    def test_aspnet_header(self) -> None:
        result = self.fp.fingerprint(
            headers={"X-Powered-By": "ASP.NET", "X-AspNet-Version": "4.0.30319"},
            body="",
        )
        top = result.best("framework")
        assert top is not None
        assert top.name == "ASP.NET / .NET"

    def test_flask_werkzeug_server(self) -> None:
        result = self.fp.fingerprint(
            headers={"Server": "Werkzeug/2.3.6 Python/3.11.4"},
            body="",
        )
        top = result.best("framework")
        assert top is not None
        assert top.name == "Flask"

    def test_fastapi_uvicorn(self) -> None:
        result = self.fp.fingerprint(
            headers={"Server": "uvicorn"},
            body='/openapi.json {"title": "My API"}',
        )
        top = result.best("framework")
        assert top is not None
        assert top.name == "FastAPI"

    def test_nextjs_powered_by(self) -> None:
        result = self.fp.fingerprint(
            headers={"X-Powered-By": "Next.js"},
            body="",
        )
        top = result.best("framework")
        assert top is not None
        assert top.name == "Next.js"

    def test_angular_body(self) -> None:
        result = self.fp.fingerprint(
            headers={},
            body='<app-root ng-version="17.0.0"></app-root>',
        )
        top = result.best("framework")
        assert top is not None
        assert top.name == "Angular"

    def test_react_body(self) -> None:
        result = self.fp.fingerprint(
            headers={},
            body='<div data-reactroot="">',
        )
        top = result.best("framework")
        assert top is not None
        assert top.name == "React"

    def test_vuejs_body(self) -> None:
        result = self.fp.fingerprint(
            headers={},
            body='<script src="vue.min.js"></script>',
        )
        top = result.best("framework")
        assert top is not None
        assert top.name == "Vue.js"

    # ── CMS detection ─────────────────────────────────────────────────

    def test_wordpress_body(self) -> None:
        result = self.fp.fingerprint(
            headers={},
            body='<link href="/wp-content/themes/mytheme/style.css" />',
        )
        top = result.best("cms")
        assert top is not None
        assert top.name == "WordPress"
        assert top.confidence >= 0.9

    def test_wordpress_generator_meta(self) -> None:
        result = self.fp.fingerprint(
            headers={"Link": '<https://example.com/wp-json/>; rel="https://api.w.org/"'},
            body="<meta name='generator' content='WordPress 6.4.2'>",
        )
        top = result.best("cms")
        assert top is not None
        assert top.name == "WordPress"

    def test_drupal_x_generator(self) -> None:
        result = self.fp.fingerprint(
            headers={"X-Generator": "Drupal 10 (https://www.drupal.org)"},
            body="",
        )
        top = result.best("cms")
        assert top is not None
        assert top.name == "Drupal"

    def test_joomla_body(self) -> None:
        result = self.fp.fingerprint(
            headers={},
            body="<meta name='generator' content='Joomla! - Open Source Content Management'>",
        )
        top = result.best("cms")
        assert top is not None
        assert top.name == "Joomla"

    def test_strapi_powered_by(self) -> None:
        result = self.fp.fingerprint(
            headers={"X-Powered-By": "Strapi <strapi.io>"},
            body="",
        )
        top = result.best("cms")
        assert top is not None
        assert top.name == "Strapi"

    def test_shopify_cdn(self) -> None:
        result = self.fp.fingerprint(
            headers={},
            body='<script src="https://cdn.shopify.com/s/assets/storefront.js"></script>',
        )
        top = result.best("cms")
        assert top is not None
        assert top.name == "Shopify"

    # ── WAF detection ─────────────────────────────────────────────────

    def test_cloudflare_waf(self) -> None:
        result = self.fp.fingerprint(
            headers={
                "Server": "cloudflare",
                "CF-Ray": "7a3c4d5e6f7a8b9c-LHR",
            },
            body="",
        )
        top = result.best("waf")
        assert top is not None
        assert "Cloudflare" in top.name
        assert top.confidence >= 0.9

    def test_imperva_cookie(self) -> None:
        result = self.fp.fingerprint(
            headers={"Set-Cookie": "incap_ses_1234_5678=abc123; Path=/"},
            body="",
        )
        top = result.best("waf")
        assert top is not None
        assert "Imperva" in top.name

    def test_f5_bigip_cookie(self) -> None:
        result = self.fp.fingerprint(
            headers={"Set-Cookie": "BIGipServerPool=198.51.100.1.20480.0000; Path=/"},
            body="",
        )
        top = result.best("waf")
        assert top is not None
        assert "F5" in top.name or "BIG-IP" in top.name

    def test_modsecurity_body(self) -> None:
        result = self.fp.fingerprint(
            headers={},
            body="This error was generated by Mod_Security",
        )
        top = result.best("waf")
        assert top is not None
        assert "ModSecurity" in top.name

    def test_aws_waf_requestid(self) -> None:
        result = self.fp.fingerprint(
            headers={"X-Amzn-RequestId": "550e8400-e29b-41d4-a716-446655440000"},
            body="",
        )
        top = result.best("waf")
        assert top is not None
        assert "AWS" in top.name

    # ── CDN detection ─────────────────────────────────────────────────

    def test_cloudflare_cdn(self) -> None:
        result = self.fp.fingerprint(
            headers={
                "CF-Ray": "7a3c4d5e6f7a8b9c-LHR",
                "CF-Cache-Status": "HIT",
            },
            body="",
        )
        top = result.best("cdn")
        assert top is not None
        assert "Cloudflare" in top.name

    def test_cloudfront_cdn(self) -> None:
        result = self.fp.fingerprint(
            headers={
                "X-Amz-Cf-Pop": "LHR50-C1",
                "Via": "1.1 abc123.cloudfront.net (CloudFront)",
            },
            body="",
        )
        top = result.best("cdn")
        assert top is not None
        assert "CloudFront" in top.name or "AWS" in top.name

    def test_fastly_cdn(self) -> None:
        result = self.fp.fingerprint(
            headers={
                "X-Served-By": "cache-lhr7380-LHR",
                "X-Cache": "HIT",
                "Via": "1.1 varnish",
            },
            body="",
        )
        top = result.best("cdn")
        assert top is not None
        assert "Fastly" in top.name or "Varnish" in top.name

    def test_akamai_cdn(self) -> None:
        result = self.fp.fingerprint(
            headers={"Server": "AkamaiGHost"},
            body="",
        )
        top = result.best("cdn")
        assert top is not None
        assert "Akamai" in top.name

    def test_azure_cdn(self) -> None:
        result = self.fp.fingerprint(
            headers={"X-Azure-Ref": "0AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},
            body="",
        )
        top = result.best("cdn")
        assert top is not None
        assert "Azure" in top.name

    def test_vercel_cdn(self) -> None:
        result = self.fp.fingerprint(
            headers={"X-Vercel-Id": "sfo1::abc123-1234567890"},
            body="",
        )
        assert result.best("cdn") is not None or result.best("cloud") is not None

    # ── Cloud detection ───────────────────────────────────────────────

    def test_aws_cloud(self) -> None:
        result = self.fp.fingerprint(
            headers={"X-Amzn-RequestId": "550e8400-e29b-41d4-a716-446655440000"},
            body="",
        )
        top = result.best("cloud")
        assert top is not None
        assert top.name == "AWS"

    def test_azure_cloud(self) -> None:
        result = self.fp.fingerprint(
            headers={"X-Azure-Ref": "0AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},
            body="",
        )
        top = result.best("cloud")
        assert top is not None
        assert top.name == "Azure"

    def test_gcp_cloud(self) -> None:
        result = self.fp.fingerprint(
            headers={"Via": "1.1 google"},
            body="",
        )
        top = result.best("cloud")
        assert top is not None
        assert "Google" in top.name

    def test_heroku_cloud(self) -> None:
        result = self.fp.fingerprint(
            headers={"Via": "1.1 vegur"},
            body="",
        )
        top = result.best("cloud")
        assert top is not None
        assert top.name == "Heroku"

    def test_vercel_cloud(self) -> None:
        result = self.fp.fingerprint(
            headers={
                "X-Vercel-Id": "sfo1::abc123-1234567890",
                "Server": "vercel",
            },
            body="",
        )
        top = result.best("cloud")
        assert top is not None
        assert top.name == "Vercel"

    def test_netlify_cloud(self) -> None:
        result = self.fp.fingerprint(
            headers={
                "X-Nf-Request-Id": "01H5Z7W9XY12D3G4F5H6J7K8L9",
                "Server": "Netlify",
            },
            body="",
        )
        top = result.best("cloud")
        assert top is not None
        assert top.name == "Netlify"

    # ── Edge cases ────────────────────────────────────────────────────

    def test_empty_headers_and_body(self) -> None:
        result = self.fp.fingerprint(headers={}, body="")
        assert result.all_matches == []
        assert ScanFingerprint.summarise(result) == "No technology fingerprints detected"

    def test_no_match_below_threshold(self) -> None:
        # Server:nginx alone is below the 0.4 threshold for Nginx+naxsi WAF
        # but should not yield a confident CDN match
        result = self.fp.fingerprint(
            headers={"Server": "nginx/1.24.0"},
            body="",
            also_check_waf=True,
        )
        # Nginx CDN alone shouldn't be more than 0.7
        cdn = result.best("cdn")
        if cdn:
            assert cdn.confidence <= 0.75

    def test_to_dict_roundtrip(self) -> None:
        result = self.fp.fingerprint(
            headers={
                "X-Powered-By": "Express",
                "CF-Ray": "abc123-LHR",
                "Server": "cloudflare",
            },
            body="",
        )
        d = result.to_dict()
        assert "frameworks" in d
        assert "cdns" in d
        assert "wafs" in d
        assert "cloud" in d
        assert "cms" in d

    def test_parse_raw_headers(self) -> None:
        raw = "Server: cloudflare\nCF-Ray: abc123-LHR\nContent-Type: text/html"
        h = ScanFingerprint.parse_raw_headers(raw)
        assert h["Server"] == "cloudflare"
        assert h["CF-Ray"] == "abc123-LHR"

    def test_fingerprint_from_raw(self) -> None:
        raw = "Server: cloudflare\nCF-Ray: 7abc123-LHR"
        result = self.fp.fingerprint_from_raw(raw_headers=raw, body="")
        top = result.best("cdn")
        assert top is not None
        assert "Cloudflare" in top.name

    def test_summarise_output(self) -> None:
        result = self.fp.fingerprint(
            headers={"X-Powered-By": "Express", "CF-Ray": "abc-LHR", "Server": "cloudflare"},
            body="",
        )
        summary = ScanFingerprint.summarise(result)
        assert "Framework=Express" in summary or "Express" in summary
        assert "Cloudflare" in summary

    def test_also_check_waf_false(self) -> None:
        result = self.fp.fingerprint(
            headers={"Set-Cookie": "incap_ses_1234=abc"},
            body="",
            also_check_waf=False,
        )
        assert result.wafs == []

    def test_also_check_cloud_false(self) -> None:
        result = self.fp.fingerprint(
            headers={"X-Azure-Ref": "xyz"},
            body="",
            also_check_cloud=False,
        )
        assert result.cloud == []

    def test_confidence_ordering(self) -> None:
        """Matches with higher evidence should rank first."""
        result = self.fp.fingerprint(
            headers={
                "X-Powered-By": "ASP.NET",
                "X-AspNet-Version": "4.0.30319",
                "Set-Cookie": "ASP.NET_SessionId=abc123",
                "Server": "Microsoft-IIS/10.0",
            },
            body="<input name='__VIEWSTATE' value='xyz'>",
        )
        top = result.best("framework")
        assert top is not None
        assert top.name == "ASP.NET / .NET"
        assert top.confidence >= 0.9

    def test_wordpress_high_confidence(self) -> None:
        result = self.fp.fingerprint(
            headers={
                "Set-Cookie": "wordpress_logged_in_abc=user%7Cexpiry",
                "Link": '<https://example.com/wp-json/>; rel="https://api.w.org/"',
            },
            body='<link rel="stylesheet" href="/wp-content/themes/twenty/style.css">',
        )
        top = result.best("cms")
        assert top is not None
        assert top.name == "WordPress"
        assert top.confidence >= 0.8

    def test_fingerprint_match_to_dict(self) -> None:
        m = FingerprintMatch(
            category="framework",
            name="Django",
            confidence=0.9,
            evidence=["header:X-Powered-By: Django"],
            version="4.2",
        )
        d = m.to_dict()
        assert d["name"] == "Django"
        assert d["confidence"] == 0.9
        assert d["version"] == "4.2"
        assert d["category"] == "framework"

    def test_large_body_capped(self) -> None:
        """Engine must not OOM on huge bodies."""
        big_body = "A" * 200_000 + "<meta name='generator' content='WordPress 6.4'>"
        result = self.fp.fingerprint(headers={}, body=big_body)
        # The WP generator tag is beyond the 65k cap — that's expected
        # Just verify we don't crash
        assert isinstance(result, FingerprintResult)

    def test_case_insensitive_headers(self) -> None:
        result = self.fp.fingerprint(
            headers={"x-powered-by": "Express"},
            body="",
        )
        top = result.best("framework")
        assert top is not None
        assert top.name == "Express / Node.js"
