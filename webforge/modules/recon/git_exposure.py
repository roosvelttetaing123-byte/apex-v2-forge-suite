"""Git exposure module — detect and exploit exposed .git directories."""
from __future__ import annotations

import asyncio
import re
import sys
import time
import zlib
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity

CVSS_GIT_EXPOSED  = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
CVSS40_GIT_EXPOSED = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N"
CVSS_GIT_SECRET   = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
CVSS40_GIT_SECRET  = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N"
CVSS_SOURCE_DUMP  = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
CVSS40_SOURCE_DUMP = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H"

GIT_PATHS = [
    ".git/HEAD",
    ".git/config",
    ".git/COMMIT_EDITMSG",
    ".git/description",
    ".git/packed-refs",
    ".git/refs/heads/master",
    ".git/refs/heads/main",
    ".git/refs/heads/develop",
    ".git/FETCH_HEAD",
    ".git/logs/HEAD",
    ".git/info/refs",
    ".git/info/exclude",
]

SECRET_PATTERNS: list[tuple[str, str, Severity]] = [
    (r"AKIA[0-9A-Z]{16}",                                              "AWS Access Key ID",               Severity.CRITICAL),
    (r"(?i)aws.{0,20}secret.{0,20}['\"][0-9A-Za-z/+=]{40}['\"]",      "AWS Secret Key",                  Severity.CRITICAL),
    (r"sk_(live|test)_[0-9a-zA-Z]{24,}",                               "Stripe API Key",                  Severity.CRITICAL),
    (r"ghp_[0-9a-zA-Z]{36}",                                            "GitHub Personal Access Token",    Severity.CRITICAL),
    (r"glpat-[A-Za-z0-9_\-]{20,}",                                     "GitLab Personal Access Token",    Severity.CRITICAL),
    (r"SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}",                   "SendGrid API Key",                Severity.CRITICAL),
    (r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",              "Private Key",                     Severity.CRITICAL),
    (r"(?i)(db|database)[_\-]?(password|passwd|pwd)\s*[=:]\s*['\"]([^'\"\s]{4,})['\"]", "DB Password",   Severity.CRITICAL),
    (r"url\s*=\s*https?://[^:@\s]+:[^@\s]+@",                          "Credential in Remote URL",        Severity.CRITICAL),
    (r"AIza[0-9A-Za-z\-_]{35}",                                         "Google API Key",                  Severity.HIGH),
    (r"(?i)(password|passwd|pwd)\s*[=:]\s*['\"]([^'\"\s]{8,})['\"]",   "Hardcoded Password",              Severity.HIGH),
    (r"(?i)(api[_\-]?key|apikey)\s*[=:]\s*['\"]([a-zA-Z0-9_\-]{20,})['\"]", "API Key",                  Severity.HIGH),
    (r"xox[baprs]-[0-9]{12}-[0-9]{12}-[a-zA-Z0-9]{24}",               "Slack Token",                     Severity.HIGH),
    (r"npm_[A-Za-z0-9]{36}",                                             "npm Access Token",                Severity.HIGH),
    (r"hf_[A-Za-z0-9]{37}",                                              "HuggingFace API Token",           Severity.HIGH),
    (r"pypi-[A-Za-z0-9_\-]{36,}",                                        "PyPI API Token",                  Severity.HIGH),
    (r"eyJ[a-zA-Z0-9_\-]+\.eyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+",      "JWT Token",                       Severity.MEDIUM),
]

CREDENTIAL_URL_RE = re.compile(r"url\s*=\s*(https?://[^:@\s]+:[^@\s]+@[^\s]+)", re.IGNORECASE)
REMOTE_URL_RE     = re.compile(r"url\s*=\s*(.+)",                                re.IGNORECASE)
COMMITTER_RE      = re.compile(r"^(?:author|committer)\s+(.+?)\s+<([^>]+)>",     re.MULTILINE)
SHA1_RE           = re.compile(r"^[0-9a-f]{40}$")

# Regex to extract cloud/internal hostname from committer email fields in git reflog.
# Matches hostnames in commit identity email fields that reveal deployment infrastructure:
#   root@ip-172-31-43-73.ap-southeast-1.compute.internal  → AWS region + private IP
#   deploy@prdsrv01.corp.internal                         → internal hostname
REFLOG_HOST_RE = re.compile(
    r"@([a-zA-Z0-9][a-zA-Z0-9.\-]*\."
    r"(?:internal|local|corp|lan|intranet|compute\.internal|compute\.amazonaws\.com))",
    re.IGNORECASE,
)
# AWS EC2 hostname pattern: ip-A-B-C-D.region.compute.internal → extract IP and region
AWS_HOST_RE = re.compile(
    r"ip-(\d+)-(\d+)-(\d+)-(\d+)\.([\w-]+-\d+)\.compute\.internal",
    re.IGNORECASE,
)
# Private IPv4 ranges embedded in hostnames (AWS style)
PRIVATE_IP_PREFIXES = ("10.", "172.", "192.168.")


class GitExposure(BaseModule):
    """Exposed .git directory detector and source code dumper."""

    NAME        = "git_exposure"
    DESCRIPTION = "Detect exposed .git directories; dump objects, extract secrets and committer intel"
    PHASE       = 1
    TAGS        = ["recon", "git", "disclosure", "cwe-538", "owasp-a05"]

    async def run(self) -> ModuleResult:
        start  = time.monotonic()
        target = self.config.target.rstrip("/")
        if not self.check_scope(target):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        import aiohttp
        async with aiohttp.ClientSession(
            connector=aiohttp.TCPConnector(ssl=False),
            headers={"User-Agent": "Mozilla/5.0"},
        ) as session:
            head_content = await self._fetch_text(session, f"{target}/.git/HEAD")
            if not head_content:
                return self._make_result(start)
            head_stripped = head_content.strip()
            if not (head_stripped.startswith("ref:") or SHA1_RE.match(head_stripped)):
                return self._make_result(start)

            self.log.warning("Exposed .git directory confirmed at %s", target)

            config_content = await self._fetch_text(session, f"{target}/.git/config")
            logs_head      = await self._fetch_text(session, f"{target}/.git/logs/HEAD")
            packed_refs    = await self._fetch_text(session, f"{target}/.git/packed-refs")
            commit_sha     = await self._resolve_head(session, target, head_stripped)

            exposed_paths: list[str] = []
            for git_path in GIT_PATHS:
                if await self._path_exists(session, f"{target}/{git_path}"):
                    exposed_paths.append(git_path)

            ev = Evidence(
                request_raw=f"GET {target}/.git/HEAD",
                response_raw=head_content[:500],
                extra={
                    "head":           head_stripped,
                    "commit_sha":     commit_sha,
                    "config_snippet": (config_content or "")[:200],
                    "exposed_paths":  exposed_paths,
                },
            )
            ev.screenshot_path = self.capture_screenshot(
                f"{target}/.git/HEAD", finding_id="git_head"
            )
            self.new_finding(
                title=f"Exposed .git Directory — Full Source Code Dump Possible ({target})",
                severity=Severity.CRITICAL,
                description=(
                    f"The .git directory is publicly accessible at {target}/.git/. "
                    "An attacker can reconstruct the full source code, extract secrets from "
                    "commit history, and enumerate internal infrastructure from remote URLs.\n\n"
                    f"HEAD: {head_stripped}\n"
                    f"Latest commit: {commit_sha or 'unknown'}\n"
                    f"Confirmed accessible paths: {len(exposed_paths)}"
                ),
                reproduction_steps=[
                    f"curl {target}/.git/HEAD",
                    f"python3 git-dumper.py {target}/.git /tmp/dump",
                    "cd /tmp/dump && git log --oneline",
                ],
                remediation=(
                    "Block HTTP access to .git in nginx/Apache:\n"
                    "  location ~ /\\.git { deny all; }\n"
                    "Rotate ALL secrets found anywhere in commit history — "
                    "git history retains them even after file deletion. "
                    "Use git-filter-repo to scrub history after rotation."
                ),
                references=["CWE-538", "OWASP A05:2021", "MITRE T1213"],
                evidence=ev,
                cvss_v31_vector=CVSS_SOURCE_DUMP,
                cvss_v40_vector=CVSS40_SOURCE_DUMP,
                mitre_attack=["TA0009/T1213", "TA0006/T1552.001"],
                target=target,
                url=f"{target}/.git/",
            )

            if config_content:
                await self._analyze_config(config_content, target)

            if logs_head:
                self._extract_committer_intel(logs_head, target)

            if commit_sha:
                dumped_blobs: dict[str, str] = {}
                await self._walk_commit(session, target, commit_sha, dumped_blobs, depth=0)
                if dumped_blobs:
                    self._scan_blobs_for_secrets(dumped_blobs, target)

            if packed_refs:
                await self._check_packed_refs(session, target, packed_refs)

        return self._make_result(start)

    # ── object graph traversal ──────────────────────────────────────────────

    async def _resolve_head(
        self, session: Any, target: str, head_content: str
    ) -> str | None:
        """Resolve HEAD ref chain to a concrete commit SHA."""
        if SHA1_RE.match(head_content):
            return head_content
        ref_path = head_content.removeprefix("ref: ").strip()
        sha = await self._fetch_text(session, f"{target}/.git/{ref_path}")
        if sha:
            sha = sha.strip()
            if SHA1_RE.match(sha):
                return sha
        packed = await self._fetch_text(session, f"{target}/.git/packed-refs")
        if packed:
            for line in packed.splitlines():
                parts = line.split()
                if len(parts) >= 2 and parts[1] == ref_path and SHA1_RE.match(parts[0]):
                    return parts[0]
        return None

    async def _walk_commit(
        self,
        session: Any,
        target: str,
        sha: str,
        blobs: dict[str, str],
        depth: int,
    ) -> None:
        """Walk commit → tree → blobs (max 2 commits deep)."""
        if depth > 2 or len(blobs) >= 50:
            return
        raw = await self._fetch_object(session, target, sha)
        if not raw:
            return
        obj_type, content_bytes = self._parse_object_raw(raw)
        if obj_type != "commit":
            return
        content_str = content_bytes.decode("utf-8", errors="ignore")
        tree_sha:   str | None = None
        parent_sha: str | None = None
        for line in content_str.splitlines():
            if line.startswith("tree "):
                tree_sha = line.split()[1]
            elif line.startswith("parent ") and depth == 0:
                parent_sha = line.split()[1]
        if tree_sha:
            await self._walk_tree(session, target, tree_sha, "", blobs)
        if parent_sha:
            await self._walk_commit(session, target, parent_sha, blobs, depth + 1)

    async def _walk_tree(
        self,
        session: Any,
        target: str,
        sha: str,
        prefix: str,
        blobs: dict[str, str],
    ) -> None:
        """Recursively walk a git tree object and collect interesting blobs."""
        if len(blobs) >= 50:
            return
        raw = await self._fetch_object(session, target, sha)
        if not raw:
            return
        obj_type, content_bytes = self._parse_object_raw(raw)
        if obj_type != "tree":
            return
        for mode, name, entry_sha in self._parse_tree_entries(content_bytes):
            if len(blobs) >= 50:
                break
            full_path = f"{prefix}/{name}" if prefix else name
            if mode.startswith("04"):
                await self._walk_tree(session, target, entry_sha, full_path, blobs)
            elif self._is_interesting_file(name):
                blob_raw = await self._fetch_object(session, target, entry_sha)
                if blob_raw:
                    _, blob_bytes = self._parse_object_raw(blob_raw)
                    if blob_bytes:
                        blobs[full_path] = blob_bytes.decode("utf-8", errors="ignore")

    def _parse_tree_entries(self, content_bytes: bytes) -> list[tuple[str, str, str]]:
        """Parse binary git tree content (post-header bytes) into (mode, name, sha_hex)."""
        entries: list[tuple[str, str, str]] = []
        i = 0
        data = content_bytes
        while i < len(data) - 21:
            try:
                sp  = data.index(b" ",  i)
                nul = data.index(b"\x00", sp)
                mode     = data[i:sp].decode("ascii", errors="ignore")
                name     = data[sp + 1:nul].decode("utf-8", errors="ignore")
                sha_hex  = data[nul + 1:nul + 21].hex()
                entries.append((mode, name, sha_hex))
                i = nul + 21
            except (ValueError, IndexError):
                break
        return entries

    # ── HTTP helpers ────────────────────────────────────────────────────────

    async def _fetch_object(self, session: Any, target: str, sha: str) -> bytes | None:
        """Download a compressed git object by SHA."""
        if not SHA1_RE.match(sha):
            return None
        import aiohttp
        url = f"{target}/.git/objects/{sha[:2]}/{sha[2:]}"
        try:
            await self.rate_limit()
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=8)) as resp:
                if resp.status == 200:
                    return await resp.read()
        except Exception:
            pass
        return None

    async def _fetch_text(self, session: Any, url: str) -> str | None:
        """GET a URL and return text, or None on non-200 / error."""
        import aiohttp
        try:
            await self.rate_limit()
            async with session.get(
                url,
                timeout=aiohttp.ClientTimeout(total=8),
                allow_redirects=False,
            ) as resp:
                if resp.status == 200:
                    return await resp.text(errors="ignore")
        except Exception:
            pass
        return None

    async def _path_exists(self, session: Any, url: str) -> bool:
        """Return True if the URL responds with HTTP 200."""
        import aiohttp
        try:
            await self.rate_limit()
            async with session.get(
                url,
                timeout=aiohttp.ClientTimeout(total=5),
                allow_redirects=False,
            ) as resp:
                return resp.status == 200
        except Exception:
            return False

    # ── intelligence extraction ─────────────────────────────────────────────

    async def _analyze_config(self, config_content: str, target: str) -> None:
        """Detect credentials embedded in git remote URLs."""
        cred_urls = CREDENTIAL_URL_RE.findall(config_content)
        if cred_urls:
            ev = Evidence(
                response_raw=config_content[:400],
                extra={"credential_urls": cred_urls},
            )
            self.new_finding(
                title=f"Git Config — Credentials in Remote URL ({target})",
                severity=Severity.CRITICAL,
                description=(
                    f".git/config at {target} contains credentials embedded "
                    "in a remote URL (user:password@host). "
                    "Any unauthenticated visitor can retrieve these."
                ),
                reproduction_steps=[
                    f"curl {target}/.git/config",
                    "grep -E 'url.*@' .git/config",
                ],
                remediation=(
                    "Remove credentials from git remote URLs. "
                    "Use SSH keys or a credential helper. "
                    "Rotate all exposed credentials immediately."
                ),
                references=["CWE-312", "CWE-798"],
                evidence=ev,
                cvss_v31_vector=CVSS_GIT_SECRET,
                cvss_v40_vector=CVSS40_GIT_SECRET,
                mitre_attack=["TA0006/T1552.001"],
                target=target,
                url=f"{target}/.git/config",
            )
        else:
            remote_urls = REMOTE_URL_RE.findall(config_content)
            if remote_urls:
                existing: list[str] = self.config.extra.get("git_remote_urls", [])
                existing.extend(u.strip() for u in remote_urls)
                self.config.extra["git_remote_urls"] = list(dict.fromkeys(existing))
                self.log.info("Git remote URLs found: %s", remote_urls[:3])

    def _extract_committer_intel(self, logs_head: str, target: str) -> None:
        """Extract committer identities and deployment infrastructure from git reflog.

        Parses both identity entries (author/committer lines) and reflog operation
        entries. Reflog entries use the format:
          <old-sha> <new-sha> Name <email> <timestamp> <tz>\t<action>
        When deployments are done manually on production servers the email field
        contains the server hostname, e.g.:
          root <root@ip-172-31-43-73.ap-southeast-1.compute.internal>
        This passively discloses cloud provider, region, VPC subnet, and privilege level.
        """
        committers: set[tuple[str, str]] = set()
        for m in COMMITTER_RE.finditer(logs_head):
            committers.add((m.group(1).strip(), m.group(2).strip()))

        if committers:
            committer_list = "\n".join(f"  • {n} <{e}>" for n, e in sorted(committers))
            ev = Evidence(
                response_raw=logs_head[:400],
                extra={"committers": [{"name": n, "email": e} for n, e in sorted(committers)]},
            )
            self.new_finding(
                title=f"Git History — Committer PII Exposed ({len(committers)} contributor(s))",
                severity=Severity.MEDIUM,
                description=(
                    f".git/logs/HEAD at {target} reveals contributor identities "
                    "enabling spear-phishing and developer targeting.\n\n"
                    f"{committer_list}"
                ),
                reproduction_steps=[
                    f"curl {target}/.git/logs/HEAD",
                    "grep -oE '(author|committer) .+ <[^>]+>' .git/logs/HEAD | sort -u",
                ],
                remediation="Block HTTP access to /.git/. Avoid personal email addresses in git commits.",
                references=["CWE-538", "OWASP A05:2021"],
                evidence=ev,
                cvss_v31_vector=CVSS_GIT_EXPOSED,
                cvss_v40_vector=CVSS40_GIT_EXPOSED,
                mitre_attack=["TA0043/T1589.002"],
                target=target,
                url=f"{target}/.git/logs/HEAD",
            )

        self._extract_infra_from_reflog(logs_head, target)

    def _extract_infra_from_reflog(self, logs_head: str, target: str) -> None:
        """Parse git reflog for server hostnames that reveal deployment infrastructure.

        When ops teams run 'git pull' or 'git clone' directly on production servers,
        the reflog records the committer identity as 'user@hostname'. Internal or
        cloud hostnames in these fields passively disclose the full deployment stack.
        """
        internal_hosts: set[str] = set()
        aws_regions:    set[str] = set()
        private_ips:    set[str] = set()
        root_deploys    = False

        all_emails: list[str] = []
        for line in logs_head.splitlines():
            # Reflog entry format: <sha> <sha> Name <email> <ts> <tz>\t<msg>
            bracket = line.find("<")
            end     = line.find(">", bracket) if bracket != -1 else -1
            if bracket != -1 and end != -1:
                all_emails.append(line[bracket + 1:end])

        for email in all_emails:
            if email.startswith("root@"):
                root_deploys = True

            m_aws = AWS_HOST_RE.search(email)
            if m_aws:
                ip  = f"{m_aws.group(1)}.{m_aws.group(2)}.{m_aws.group(3)}.{m_aws.group(4)}"
                region = m_aws.group(5)
                private_ips.add(ip)
                aws_regions.add(region)
                internal_hosts.add(email.split("@", 1)[1])
                continue

            m_host = REFLOG_HOST_RE.search(email)
            if m_host:
                internal_hosts.add(m_host.group(1))

        if not (internal_hosts or private_ips or aws_regions):
            return

        parts: list[str] = []
        if aws_regions:
            parts.append(f"Cloud provider: AWS — region(s): {', '.join(sorted(aws_regions))}")
        if private_ips:
            parts.append(f"Internal IPs discovered: {', '.join(sorted(private_ips))}")
        if internal_hosts:
            parts.append(f"Internal hostnames: {', '.join(sorted(internal_hosts))}")
        if root_deploys:
            parts.append("Deployments running as root (no privilege separation on production servers)")

        desc = (
            f".git/logs/HEAD at {target} contains server hostname(s) in committer "
            "identity fields, revealing deployment infrastructure:\n\n"
            + "\n".join(f"  • {p}" for p in parts)
            + "\n\nThis information is valuable for pivoting: internal IPs are candidates "
            "for SSRF targets; AWS regions confirm cloud provider and aid in attack surface mapping."
        )
        ev = Evidence(
            response_raw=logs_head[:500],
            extra={
                "internal_hosts": sorted(internal_hosts),
                "private_ips":    sorted(private_ips),
                "aws_regions":    sorted(aws_regions),
                "root_deploys":   root_deploys,
            },
        )
        self.new_finding(
            title=f"Git Reflog — Internal Infrastructure Disclosed via Committer Hostnames",
            severity=Severity.HIGH,
            description=desc,
            reproduction_steps=[
                f"curl {target}/.git/logs/HEAD",
                r"grep -oP '(?<=<)[^>]+(?=>)' .git/logs/HEAD | grep -E '\.(internal|local|corp)$'",
            ],
            remediation=(
                "Block HTTP access to /.git/ (see git exposure finding). "
                "Use CI/CD pipelines for deployments — never run git commands "
                "as root directly on production servers."
            ),
            references=["CWE-200", "OWASP A05:2021"],
            evidence=ev,
            cvss_v31_vector=CVSS_GIT_EXPOSED,
            cvss_v40_vector=CVSS40_GIT_EXPOSED,
            mitre_attack=["TA0043/T1592", "TA0007/T1016"],
            target=target,
            url=f"{target}/.git/logs/HEAD",
        )

    def _scan_blobs_for_secrets(self, blobs: dict[str, str], target: str) -> None:
        """Scan extracted source files for hardcoded secrets."""
        found_names: set[str] = set()
        for file_path, content in blobs.items():
            for pattern, name, severity in SECRET_PATTERNS:
                if name in found_names:
                    continue
                m = re.search(pattern, content)
                if not m:
                    continue
                found_names.add(name)
                snippet = content[max(0, m.start() - 30):m.end() + 30]
                ev = Evidence(
                    response_raw=snippet[:200],
                    extra={"file": file_path, "pattern": name, "match": m.group()[:80]},
                )
                self.new_finding(
                    title=f"Secret in Git Object Graph — {name} ({file_path})",
                    severity=severity,
                    description=(
                        f"A {name} was extracted from the git object graph "
                        f"(file '{file_path}'). "
                        "Secrets persist in git history even after file deletion."
                    ),
                    reproduction_steps=[
                        f"python3 git-dumper.py {target}/.git /tmp/dump",
                        f"grep -r '{pattern[:30]}' /tmp/dump/",
                    ],
                    remediation=(
                        "Rotate the credential immediately. "
                        "Rewrite git history with git-filter-repo. "
                        "Block /.git/ access on the server."
                    ),
                    references=["CWE-798", "CWE-312", "OWASP A02:2021"],
                    evidence=ev,
                    cvss_v31_vector=CVSS_GIT_SECRET,
                    cvss_v40_vector=CVSS40_GIT_SECRET,
                    mitre_attack=["TA0006/T1552.001"],
                    target=target,
                    url=f"{target}/.git/objects/",
                )

    async def _check_packed_refs(
        self, session: Any, target: str, packed_refs: str
    ) -> None:
        """Walk up to 2 additional branch tips from packed-refs."""
        tried = 0
        for line in packed_refs.splitlines():
            if line.startswith("#") or tried >= 2:
                continue
            parts = line.split()
            if len(parts) < 2 or not SHA1_RE.match(parts[0]):
                continue
            sha, ref = parts[0], parts[1]
            if "refs/heads/" in ref:
                tried += 1
                blobs: dict[str, str] = {}
                await self._walk_commit(session, target, sha, blobs, depth=0)
                if blobs:
                    self._scan_blobs_for_secrets(blobs, target)

    # ── static helpers ───────────────────────────────────────────────────────

    @staticmethod
    def _parse_object_raw(compressed: bytes) -> tuple[str, bytes]:
        """Decompress a git object and return (obj_type, content_bytes)."""
        try:
            data    = zlib.decompress(compressed)
            nul     = data.index(b"\x00")
            header  = data[:nul].decode("ascii", errors="ignore")
            return header.split()[0], data[nul + 1:]
        except Exception:
            return "unknown", b""

    @staticmethod
    def _is_interesting_file(name: str) -> bool:
        """Return True for files likely to contain secrets."""
        n = name.lower()
        interesting_names = {
            ".env", ".env.local", ".env.production", ".env.staging",
            "config.php", "wp-config.php", "configuration.php",
            "database.yml", "database.json", "secrets.yml", "secrets.json",
            "credentials.json", "settings.py", "config.py", "local_settings.py",
            "application.properties", "application.yml",
        }
        return (
            n in interesting_names
            or any(n.endswith(ext) for ext in (".env", ".cfg", ".conf", ".ini"))
            or any(kw in n for kw in ("config", "secret", "credential", "password"))
        )


class TestGitExposure:
    def test_sha1_pattern(self) -> None:
        assert SHA1_RE.match("a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2")
        assert not SHA1_RE.match("not-a-sha1")
        assert not SHA1_RE.match("a1b2c3")

    def test_is_interesting_file(self) -> None:
        assert GitExposure._is_interesting_file(".env")
        assert GitExposure._is_interesting_file("config.php")
        assert GitExposure._is_interesting_file("secrets.json")
        assert GitExposure._is_interesting_file("database.yml")
        assert not GitExposure._is_interesting_file("index.html")
        assert not GitExposure._is_interesting_file("app.js")

    def test_parse_object_raw_blob(self) -> None:
        import zlib
        raw = zlib.compress(b"blob 5\x00hello")
        obj_type, content = GitExposure._parse_object_raw(raw)
        assert obj_type == "blob"
        assert content == b"hello"

    def test_parse_object_raw_commit(self) -> None:
        import zlib
        body = b"tree abc123\nauthor Test <t@t.com>\n\ncommit msg"
        raw  = zlib.compress(b"commit " + str(len(body)).encode() + b"\x00" + body)
        obj_type, content = GitExposure._parse_object_raw(raw)
        assert obj_type == "commit"
        assert b"tree abc123" in content

    def test_credential_url_detection(self) -> None:
        config = '[remote "origin"]\n\turl = https://user:pass@github.com/org/repo.git\n'
        assert CREDENTIAL_URL_RE.search(config)

    def test_clean_remote_url_no_creds(self) -> None:
        config = '[remote "origin"]\n\turl = https://github.com/org/repo.git\n'
        assert not CREDENTIAL_URL_RE.search(config)

    def test_committer_pattern(self) -> None:
        log_line = "abc123 abc456 author Jane Doe <jane@example.com> 1700000000 +0000"
        # committer pattern matches start of line; test raw RE
        text = "author Jane Doe <jane@example.com>"
        m = COMMITTER_RE.search(text)
        assert m
        assert m.group(2) == "jane@example.com"

    def test_secret_patterns_coverage(self) -> None:
        names = [name for _, name, _ in SECRET_PATTERNS]
        assert "AWS Access Key ID" in names
        assert "GitLab Personal Access Token" in names
        assert "Stripe API Key" in names
        assert "Hardcoded Password" in names
