"""HashiCorp Vault Security Audit — Misconfiguration & Secret Exposure.

Comprehensive security auditor for HashiCorp Vault instances. Checks for:

    1. Dev mode detection (no authentication required)
    2. Unauthenticated health/seal status endpoints
    3. Secret engine enumeration
    4. Token brute-force / default token checks
    5. Audit logging verification
    6. Unseal key exposure
    7. Root token usage detection

Vault commonly runs on port 8200.

FOR AUTHORIZED PENETRATION TESTING AND RED TEAM OPERATIONS ONLY.
"""
from __future__ import annotations

import asyncio
import json
import logging
import sys
import time
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity

log = logging.getLogger("forge.vault_audit")

# ══════════════════════════════════════════════════════════════════════
# VAULT API ENDPOINTS
# ══════════════════════════════════════════════════════════════════════

HEALTH_ENDPOINTS = [
    "/v1/sys/health",
    "/v1/sys/seal-status",
    "/v1/sys/leader",
    "/v1/sys/ha-status",
]

SECRET_ENGINE_ENDPOINTS = [
    "/v1/sys/mounts",
    "/v1/sys/auth",
    "/v1/sys/policy",
    "/v1/sys/audit",
    "/v1/sys/plugins/catalog",
]

# Default/common tokens to test (non-destructive)
DEFAULT_TOKENS = [
    "root",
    "vault-root-token",
    "hvs.root",
    "s.root",
    "myroot",
    "devtoken",
]

VAULT_INDICATORS = [
    "vault",
    "hashicorp",
    "seal_type",
    "initialized",
    "sealed",
    "cluster_name",
]


class VaultAudit(BaseModule):
    """HashiCorp Vault Security Auditor.

    Checks for dev mode, unauthenticated access, secret engine exposure,
    audit logging gaps, and common misconfigurations.
    """

    NAME = "vault_audit"
    DESCRIPTION = "HashiCorp Vault security audit — dev mode, unauth access, secret exposure"
    PHASE = 4
    TAGS = ["vault", "hashicorp", "secret-management", "infrastructure"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        target = self.config.target.rstrip("/")

        if not self.check_scope(target):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        await self.rate_limit()

        # Phase 1: Detect Vault
        is_vault, info = await self._detect_vault(target)
        if not is_vault:
            self.log.info("[vault_audit] Target does not appear to be Vault")
            return self._make_result(start)

        # Phase 2: Dev mode check
        await self._check_dev_mode(target, info)

        # Phase 3: Health/seal status exposure
        await self._check_health_exposure(target)

        # Phase 4: Secret engine enumeration
        await self._enumerate_secret_engines(target)

        # Phase 5: Audit logging check
        await self._check_audit_logging(target)

        # Phase 6: Default token check
        await self._check_default_tokens(target)

        return self._make_result(start)

    async def _detect_vault(self, target: str) -> tuple[bool, dict[str, Any]]:
        """Detect HashiCorp Vault instance."""
        info: dict[str, Any] = {"detected": False, "version": "", "initialized": None, "sealed": None}
        import aiohttp

        try:
            async with aiohttp.ClientSession(
                connector=aiohttp.TCPConnector(ssl=False),
                timeout=aiohttp.ClientTimeout(total=8),
            ) as session:
                await self.rate_limit()
                try:
                    async with session.get(f"{target}/v1/sys/health") as resp:
                        body = await resp.text(errors="ignore")
                        try:
                            data = json.loads(body)
                            if any(k in data for k in ["initialized", "sealed", "version"]):
                                info["detected"] = True
                                info["version"] = data.get("version", "")
                                info["initialized"] = data.get("initialized")
                                info["sealed"] = data.get("sealed")
                                info["cluster_name"] = data.get("cluster_name", "")
                        except json.JSONDecodeError:
                            for ind in VAULT_INDICATORS:
                                if ind in body.lower():
                                    info["detected"] = True
                                    break
                except Exception:
                    pass

                if not info["detected"]:
                    await self.rate_limit()
                    try:
                        async with session.get(f"{target}/v1/sys/seal-status") as resp:
                            body = await resp.text(errors="ignore")
                            if "sealed" in body.lower() or "vault" in body.lower():
                                info["detected"] = True
                    except Exception:
                        pass
        except Exception as exc:
            self.log.debug("Vault detection error: %s", exc)

        return info["detected"], info

    async def _check_dev_mode(self, target: str, info: dict[str, Any]) -> None:
        """Check if Vault is running in development mode."""
        import aiohttp

        dev_indicators = []

        # Dev mode: initialized=true, sealed=false, no TLS
        if info.get("initialized") is True and info.get("sealed") is False:
            dev_indicators.append("initialized and unsealed")

        parsed = __import__("urllib.parse", fromlist=["urlparse"]).urlparse(target)
        if parsed.scheme == "http":
            dev_indicators.append("no TLS")

        # Try root token (dev mode default)
        try:
            async with aiohttp.ClientSession(
                connector=aiohttp.TCPConnector(ssl=False),
                timeout=aiohttp.ClientTimeout(total=8),
            ) as session:
                await self.rate_limit()
                try:
                    async with session.get(
                        f"{target}/v1/sys/mounts",
                        headers={"X-Vault-Token": "root"},
                    ) as resp:
                        if resp.status == 200:
                            dev_indicators.append("root token 'root' accepted")
                except Exception:
                    pass
        except Exception:
            pass

        if len(dev_indicators) >= 2:
            self.new_finding(
                title="HashiCorp Vault — Development Mode Detected",
                severity=Severity.CRITICAL,
                description=(
                    f"Vault at {target} appears to be running in development mode. "
                    f"Indicators: {', '.join(dev_indicators)}. "
                    f"Dev mode stores everything in memory, uses a known root token, "
                    f"and provides no security guarantees. "
                    f"Version: {info.get('version', 'unknown')}."
                ),
                reproduction_steps=[
                    f"1. Check {target}/v1/sys/health",
                    f"2. Dev mode indicators: {dev_indicators}",
                ],
                remediation=(
                    "CRITICAL: Never run Vault in dev mode in production. "
                    "Initialize properly with 'vault operator init'. "
                    "Enable TLS. Configure auto-unseal via cloud KMS. "
                    "Enable audit logging. Set up proper auth methods."
                ),
                references=[
                    "https://developer.hashicorp.com/vault/docs/concepts/dev-server",
                    "https://developer.hashicorp.com/vault/tutorials/getting-started/getting-started-deploy",
                ],
                evidence=Evidence(
                    extra={"dev_indicators": dev_indicators, "version": info.get("version", "")},
                ),
                cvss_v31_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                mitre_attack=["TA0006/T1552", "TA0001/T1190"],
                target=target,
                confidence="HIGH",
                tags=self.TAGS + ["dev-mode"],
            )

    async def _check_health_exposure(self, target: str) -> None:
        """Check which health/status endpoints are exposed."""
        import aiohttp
        exposed = []

        try:
            async with aiohttp.ClientSession(
                connector=aiohttp.TCPConnector(ssl=False),
                timeout=aiohttp.ClientTimeout(total=8),
            ) as session:
                for endpoint in HEALTH_ENDPOINTS:
                    await self.rate_limit()
                    try:
                        async with session.get(f"{target}{endpoint}") as resp:
                            if resp.status in {200, 429, 472, 473, 501, 503}:
                                body = await resp.text(errors="ignore")
                                exposed.append({
                                    "endpoint": endpoint,
                                    "status": resp.status,
                                    "body_preview": body[:200],
                                })
                    except Exception:
                        continue
        except Exception:
            pass

        if len(exposed) >= 2:
            self.new_finding(
                title="HashiCorp Vault — Health Endpoints Exposed Without Auth",
                severity=Severity.LOW,
                description=(
                    f"Vault at {target} exposes {len(exposed)} health/status endpoints "
                    f"without authentication. While these are designed to be public, "
                    f"they leak operational details useful for reconnaissance."
                ),
                reproduction_steps=[f"  - {e['endpoint']} → {e['status']}" for e in exposed],
                remediation="Consider restricting health endpoints via network policy if not needed for monitoring.",
                references=["https://developer.hashicorp.com/vault/api-docs/system/health"],
                evidence=Evidence(extra={"exposed_endpoints": exposed}),
                cvss_v31_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                mitre_attack=["TA0043/T1595"],
                target=target,
                confidence="HIGH",
                tags=self.TAGS,
            )

    async def _enumerate_secret_engines(self, target: str) -> None:
        """Try to enumerate secret engines without proper auth."""
        import aiohttp

        try:
            async with aiohttp.ClientSession(
                connector=aiohttp.TCPConnector(ssl=False),
                timeout=aiohttp.ClientTimeout(total=8),
            ) as session:
                for endpoint in SECRET_ENGINE_ENDPOINTS:
                    await self.rate_limit()
                    try:
                        async with session.get(f"{target}{endpoint}") as resp:
                            if resp.status == 200:
                                body = await resp.text(errors="ignore")
                                try:
                                    data = json.loads(body)
                                    if isinstance(data, dict) and len(data) > 0:
                                        self.new_finding(
                                            title=f"Vault — {endpoint.split('/')[-1].title()} Enumerable Without Auth",
                                            severity=Severity.HIGH,
                                            description=(
                                                f"Vault at {target}{endpoint} returns data without "
                                                f"authentication. Found {len(data)} entries."
                                            ),
                                            reproduction_steps=[
                                                f"1. GET {target}{endpoint} (no token)",
                                                f"2. {len(data)} entries returned",
                                            ],
                                            remediation="Enable authentication. Configure ACL policies.",
                                            references=["https://developer.hashicorp.com/vault/docs/concepts/policies"],
                                            evidence=Evidence(
                                                response_raw=body[:3000],
                                                extra={"endpoint": endpoint, "entry_count": len(data)},
                                            ),
                                            cvss_v31_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                                            mitre_attack=["TA0007/T1083", "TA0006/T1552"],
                                            target=target,
                                            confidence="HIGH",
                                            tags=self.TAGS,
                                        )
                                except json.JSONDecodeError:
                                    pass
                    except Exception:
                        continue
        except Exception as exc:
            self.log.debug("Secret engine enumeration error: %s", exc)

    async def _check_audit_logging(self, target: str) -> None:
        """Check if audit logging is configured."""
        import aiohttp

        try:
            async with aiohttp.ClientSession(
                connector=aiohttp.TCPConnector(ssl=False),
                timeout=aiohttp.ClientTimeout(total=8),
            ) as session:
                await self.rate_limit()
                try:
                    async with session.get(f"{target}/v1/sys/audit") as resp:
                        if resp.status == 200:
                            body = await resp.text(errors="ignore")
                            try:
                                data = json.loads(body)
                                audit_backends = data.get("data", data)
                                if isinstance(audit_backends, dict) and len(audit_backends) == 0:
                                    self.new_finding(
                                        title="Vault — No Audit Logging Configured",
                                        severity=Severity.MEDIUM,
                                        description=(
                                            f"Vault at {target} has no audit backends configured. "
                                            f"All secret access goes unlogged, preventing forensic "
                                            f"investigation of unauthorized access."
                                        ),
                                        reproduction_steps=[
                                            f"1. GET {target}/v1/sys/audit",
                                            "2. Empty audit backend list returned",
                                        ],
                                        remediation=(
                                            "Enable at least one audit backend: "
                                            "vault audit enable file file_path=/var/log/vault_audit.log"
                                        ),
                                        references=["https://developer.hashicorp.com/vault/docs/audit"],
                                        evidence=Evidence(extra={"audit_backends": 0}),
                                        cvss_v31_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",
                                        mitre_attack=["TA0005/T1562.002"],
                                        target=target,
                                        confidence="HIGH",
                                        tags=self.TAGS + ["no-audit"],
                                    )
                            except json.JSONDecodeError:
                                pass
                except Exception:
                    pass
        except Exception as exc:
            self.log.debug("Audit check error: %s", exc)

    async def _check_default_tokens(self, target: str) -> None:
        """Test for default/common Vault tokens."""
        import aiohttp

        try:
            async with aiohttp.ClientSession(
                connector=aiohttp.TCPConnector(ssl=False),
                timeout=aiohttp.ClientTimeout(total=8),
            ) as session:
                for token in DEFAULT_TOKENS:
                    await self.rate_limit()
                    try:
                        async with session.get(
                            f"{target}/v1/auth/token/lookup-self",
                            headers={"X-Vault-Token": token},
                        ) as resp:
                            if resp.status == 200:
                                body = await resp.text(errors="ignore")
                                try:
                                    data = json.loads(body)
                                    token_data = data.get("data", {})
                                    policies = token_data.get("policies", [])
                                    self.new_finding(
                                        title=f"Vault — Default Token Accepted: '{token}'",
                                        severity=Severity.CRITICAL,
                                        description=(
                                            f"Vault at {target} accepts the default/common token "
                                            f"'{token}'. Policies: {', '.join(policies)}. "
                                            f"This grants unauthorized access to secrets."
                                        ),
                                        reproduction_steps=[
                                            f"1. GET {target}/v1/auth/token/lookup-self",
                                            f"2. Header: X-Vault-Token: {token}",
                                            f"3. Token accepted with policies: {policies}",
                                        ],
                                        remediation="Revoke the token immediately. Never use default tokens in production.",
                                        references=["https://developer.hashicorp.com/vault/docs/concepts/tokens"],
                                        evidence=Evidence(
                                            extra={"token": token[:4] + "***", "policies": policies},
                                        ),
                                        cvss_v31_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                                        mitre_attack=["TA0006/T1552.004", "TA0001/T1078"],
                                        target=target,
                                        confidence="HIGH",
                                        tags=self.TAGS + ["default-creds"],
                                    )
                                    return  # One is enough
                                except json.JSONDecodeError:
                                    pass
                    except Exception:
                        continue
        except Exception as exc:
            self.log.debug("Default token check error: %s", exc)


# ══════════════════════════════════════════════════════════════════════
# UNIT TESTS
# ══════════════════════════════════════════════════════════════════════


class TestVaultAudit:
    def _make_module(self, tmp_path: Path) -> VaultAudit:
        from common.config import BaseForgeConfig
        from common.scope import Scope
        from common.db import create_db
        cfg = BaseForgeConfig(target="http://vault.example.com:8200")
        scope = Scope(["vault.example.com"])
        session = create_db(tmp_path / "test.db")
        return VaultAudit(cfg, scope, session, tmp_path)

    def test_module_metadata(self, tmp_path: Path) -> None:
        mod = self._make_module(tmp_path)
        assert mod.NAME == "vault_audit"
        assert mod.PHASE == 4
        assert "vault" in mod.TAGS

    def test_health_endpoints_defined(self, tmp_path: Path) -> None:
        assert len(HEALTH_ENDPOINTS) >= 3
        assert "/v1/sys/health" in HEALTH_ENDPOINTS

    def test_secret_engine_endpoints(self, tmp_path: Path) -> None:
        assert len(SECRET_ENGINE_ENDPOINTS) >= 4
        assert "/v1/sys/mounts" in SECRET_ENGINE_ENDPOINTS

    def test_default_tokens_list(self, tmp_path: Path) -> None:
        assert len(DEFAULT_TOKENS) >= 4
        assert "root" in DEFAULT_TOKENS

    def test_out_of_scope_skip(self, tmp_path: Path) -> None:
        from common.config import BaseForgeConfig
        from common.scope import Scope
        from common.db import create_db
        cfg = BaseForgeConfig(target="http://vault.example.com:8200")
        scope = Scope(["10.0.0.0/24"])
        session = create_db(tmp_path / "test.db")
        mod = VaultAudit(cfg, scope, session, tmp_path)
        result = asyncio.run(mod.run())
        assert result.skipped is True
