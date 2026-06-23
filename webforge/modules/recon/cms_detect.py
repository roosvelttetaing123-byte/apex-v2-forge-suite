"""CMS Detection — identify CMS platforms and versions for known vuln mapping."""
from __future__ import annotations
import re, sys, time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))
from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity
import aiohttp

CVSS_INFO = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
CVSS40_INFO = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N"
CVSS_OUTDATED = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
CVSS40_OUTDATED = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N"

CMS_SIGNATURES = {
    "WordPress": {
        "paths": ["/wp-login.php", "/wp-admin/", "/wp-content/", "/xmlrpc.php"],
        "headers": ["x-powered-by: WordPress"],
        "meta": [r'content="WordPress (\d+\.\d+[\.\d]*)"', r'wp-content/', r'wp-includes/'],
        "version_path": "/feed/",
        "version_regex": r'generator="WordPress/(\d+\.\d+[\.\d]*)"',
    },
    "Joomla": {
        "paths": ["/administrator/", "/media/jui/", "/templates/"],
        "meta": [r'content="Joomla!', r'/media/jui/'],
        "version_path": "/administrator/manifests/files/joomla.xml",
        "version_regex": r'<version>(\d+\.\d+[\.\d]*)</version>',
    },
    "Drupal": {
        "paths": ["/core/misc/drupal.js", "/misc/drupal.js", "/sites/default/"],
        "headers": ["x-drupal-cache", "x-generator: Drupal"],
        "meta": [r'Drupal', r'sites/default/files'],
        "version_path": "/CHANGELOG.txt",
        "version_regex": r'Drupal (\d+\.\d+[\.\d]*)',
    },
    "Magento": {
        "paths": ["/skin/frontend/", "/app/etc/local.xml", "/js/mage/"],
        "meta": [r'Magento', r'skin/frontend/'],
    },
    "Shopify": {
        "headers": ["x-shopify-stage"],
        "meta": [r'cdn\.shopify\.com'],
    },
}

SENSITIVE_FILES = [
    "/robots.txt", "/.env", "/.git/HEAD", "/wp-config.php.bak",
    "/web.config", "/server-info", "/server-status",
    "/.htaccess", "/phpinfo.php", "/info.php",
]

class CmsDetect(BaseModule):
    NAME = "cms_detect"
    DESCRIPTION = "CMS: detect platform (WordPress/Joomla/Drupal), version, sensitive files"
    PHASE = 1
    TAGS = ["recon", "cms", "fingerprint"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        target = self.config.target.rstrip("/")
        if not self.check_scope(target):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        detected_cms = None
        cms_version = None

        async with aiohttp.ClientSession(
            connector=aiohttp.TCPConnector(ssl=False),
            timeout=aiohttp.ClientTimeout(total=8),
        ) as session:
            # Fetch homepage
            await self.rate_limit()
            try:
                async with session.get(target) as resp:
                    body = await resp.text(errors="ignore")
                    headers = dict(resp.headers)
            except Exception:
                return self._make_result(start)

            # Check signatures
            for cms, sigs in CMS_SIGNATURES.items():
                # Check meta/body patterns
                for pattern in sigs.get("meta", []):
                    if re.search(pattern, body, re.I):
                        detected_cms = cms
                        # Try to extract version from homepage
                        for vp in sigs.get("meta", []):
                            m = re.search(vp, body)
                            if m and m.lastindex:
                                cms_version = m.group(1)
                        break

                # Check response headers
                for h in sigs.get("headers", []):
                    key, _, val = h.partition(": ")
                    if key.lower() in {k.lower(): k for k in headers}:
                        header_val = headers.get(key, headers.get(key.title(), ""))
                        if val.lower() in header_val.lower():
                            detected_cms = cms
                            break

                if detected_cms:
                    break

            # If CMS detected, try version-specific path
            if detected_cms and not cms_version:
                ver_path = CMS_SIGNATURES.get(detected_cms, {}).get("version_path")
                ver_regex = CMS_SIGNATURES.get(detected_cms, {}).get("version_regex")
                if ver_path and ver_regex:
                    await self.rate_limit()
                    try:
                        async with session.get(f"{target}{ver_path}") as resp:
                            ver_body = await resp.text(errors="ignore")
                            m = re.search(ver_regex, ver_body)
                            if m:
                                cms_version = m.group(1)
                    except Exception:
                        pass

            # Check CMS-specific paths
            if detected_cms:
                for path in CMS_SIGNATURES[detected_cms].get("paths", [])[:3]:
                    await self.rate_limit()
                    try:
                        async with session.get(f"{target}{path}") as resp:
                            if resp.status in (200, 301, 302, 403):
                                break
                    except Exception:
                        pass

            # Report CMS detection
            if detected_cms:
                version_str = f" v{cms_version}" if cms_version else ""
                ev = Evidence(
                    request_raw=f"GET {target}",
                    extra={"cms": detected_cms, "version": cms_version})
                self.new_finding(
                    title=f"CMS Detected: {detected_cms}{version_str}",
                    severity=Severity.INFORMATIONAL,
                    description=(
                        f"Content Management System: {detected_cms}{version_str}\n"
                        f"Target: {target}\n\n"
                        f"Known CMS platforms have well-documented attack surfaces."
                    ),
                    reproduction_steps=[f"# Confirm: curl -sI {target} | grep -i x-powered"],
                    remediation="Keep CMS updated. Remove version information from public pages.",
                    references=["CWE-200"],
                    evidence=ev,
                    cvss_v31_vector=CVSS_INFO, cvss_v40_vector=CVSS40_INFO,
                    target=target)

            # Detect SPA catch-all routing to avoid reporting the app shell
            # as sensitive files (Vercel/Next.js returns index.html for all paths).
            spa_fp = await self._spa_fingerprint(target)
            soft404_fps = await self._soft_404_fingerprints(target)

            # Check sensitive files
            exposed = []
            for path in SENSITIVE_FILES:
                await self.rate_limit()
                try:
                    async with session.get(f"{target}{path}") as resp:
                        if resp.status == 200:
                            body = await resp.text(errors="ignore")
                            if len(body) > 10 and "404" not in body[:100].lower():
                                # Skip if this is just the SPA shell, not a real file
                                if self._is_spa_body(body, spa_fp):
                                    continue
                                if self._is_waf_placeholder(body, resp.status, resp.headers):
                                    continue
                                if self._is_soft_404_body(body, resp.status, soft404_fps):
                                    continue
                                if not self._has_sensitive_file_content(path, body):
                                    continue
                                exposed.append({"path": path, "size": len(body)})
                except Exception:
                    pass

            if exposed:
                ev = Evidence(extra={"exposed_files": exposed})
                self.new_finding(
                    title=f"Sensitive Files Exposed — {len(exposed)} file(s)",
                    severity=Severity.MEDIUM,
                    description=(
                        f"Publicly accessible sensitive files:\n"
                        + "\n".join(f"  {target}{f['path']} ({f['size']} bytes)" for f in exposed[:10])
                    ),
                    reproduction_steps=[f"curl {target}{exposed[0]['path']}"],
                    remediation="Block access to sensitive files via web server configuration.",
                    references=["CWE-538"],
                    evidence=ev,
                    cvss_v31_vector=CVSS_OUTDATED, cvss_v40_vector=CVSS40_OUTDATED,
                    target=target)

        return self._make_result(start)

    def _has_sensitive_file_content(self, path: str, body: str) -> bool:
        """Require path-specific file evidence before reporting exposure."""
        lower_path = path.lower()
        sample = body[:12000]
        sample_lower = sample.lower()
        if ".env" in lower_path:
            return any(token in sample for token in ("APP_KEY=", "DB_PASSWORD=", "DATABASE_URL=", "AWS_SECRET_ACCESS_KEY="))
        if ".git/head" in lower_path:
            return "ref: refs/heads/" in sample_lower or sample.strip().startswith("ref:")
        if "wp-config" in lower_path:
            return "db_password" in sample_lower or "wp-config" in sample_lower
        if "web.config" in lower_path:
            return "<configuration" in sample_lower or "<system.webserver" in sample_lower
        if "server-status" in lower_path:
            return "apache server status" in sample_lower or "server uptime" in sample_lower
        if "server-info" in lower_path:
            return "apache server information" in sample_lower or "server settings" in sample_lower
        if lower_path.endswith((".htaccess", ".htpasswd")):
            return any(token in sample_lower for token in ("rewriteengine", "authuserfile", "authtype", "require valid-user"))
        if "phpinfo" in lower_path:
            return "php version" in sample_lower and "phpinfo()" in sample_lower
        return False

class TestCmsDetect:
    def test_signatures(self) -> None:
        assert "WordPress" in CMS_SIGNATURES
        assert "Drupal" in CMS_SIGNATURES
    def test_phase(self) -> None:
        assert CmsDetect.PHASE == 1
