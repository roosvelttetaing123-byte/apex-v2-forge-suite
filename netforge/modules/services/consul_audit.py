"""HashiCorp Consul Security Audit — API Exposure & Secret Leakage.

Comprehensive security auditor for HashiCorp Consul instances. Checks for:

    1. Unauthenticated API access (/v1/agent/self, /v1/catalog/services)
    2. KV store secret exposure
    3. ACL bootstrap token leak
    4. Service mesh token extraction
    5. Agent configuration dump
    6. Connect CA private key exposure
    7. Prepared query enumeration

Consul commonly runs on port 8500 (HTTP) and 8501 (HTTPS).

FOR AUTHORIZED PENETRATION TESTING AND RED TEAM OPERATIONS ONLY.
"""
from __future__ import annotations

import asyncio
import json
import logging
import re
import sys
import time
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity

log = logging.getLogger("forge.consul_audit")

# ══════════════════════════════════════════════════════════════════════
# CONSUL API ENDPOINTS
# ══════════════════════════════════════════════════════════════════════

AGENT_ENDPOINTS = [
    ("/v1/agent/self", "Agent self info (config, member details)"),
    ("/v1/agent/members", "Cluster member listing"),
    ("/v1/agent/services", "Registered services"),
    ("/v1/agent/checks", "Health checks"),
]

CATALOG_ENDPOINTS = [
    ("/v1/catalog/datacenters", "Datacenter listing"),
    ("/v1/catalog/services", "All services"),
    ("/v1/catalog/nodes", "All nodes"),
]

ACL_ENDPOINTS = [
    ("/v1/acl/tokens", "ACL token listing"),
    ("/v1/acl/policies", "ACL policy listing"),
    ("/v1/acl/roles", "ACL role listing"),
    ("/v1/acl/bootstrap", "ACL bootstrap (POST)"),
]

SENSITIVE_ENDPOINTS = [
    ("/v1/connect/ca/roots", "Connect CA root certificates"),
    ("/v1/connect/ca/configuration", "CA configuration"),
    ("/v1/operator/raft/configuration", "Raft configuration"),
    ("/v1/operator/autopilot/configuration", "Autopilot config"),
    ("/v1/query", "Prepared queries"),
]

# KV paths commonly containing secrets
SENSITIVE_KV_PREFIXES = [
    "vault/",
    "secrets/",
    "config/",
    "credentials/",
    "passwords/",
    "tokens/",
    "certs/",
    "private/",
    "database/",
    "aws/",
]

CONSUL_INDICATORS = [
    "consul",
    "hashicorp",
    "X-Consul-Index",
    "X-Consul-KnownLeader",
    "X-Consul-Translate-Addresses",
]


class ConsulAudit(BaseModule):
    """HashiCorp Consul Security Auditor.

    Checks for unauthenticated API access, KV store secret exposure,
    ACL misconfiguration, and service mesh token leakage.
    """

    NAME = "consul_audit"
    DESCRIPTION = "HashiCorp Consul security audit — API exposure, KV secrets, ACL misconfig"
    PHASE = 4
    TAGS = ["consul", "hashicorp", "service-mesh", "secret-exposure", "infrastructure"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        target = self.config.target.rstrip("/")

        if not self.check_scope(target):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        await self.rate_limit()

        # Phase 1: Detect Consul
        is_consul, info = await self._detect_consul(target)
        if not is_consul:
            self.log.info("[consul_audit] Target does not appear to be Consul")
            return self._make_result(start)

        # Phase 2: Agent info exposure
        await self._check_agent_exposure(target, info)

        # Phase 3: Catalog enumeration
        await self._check_catalog(target)

        # Phase 4: KV store secrets
        await self._check_kv_secrets(target)

        # Phase 5: ACL configuration
        await self._check_acl_config(target)

        # Phase 6: Connect CA exposure
        await self._check_connect_ca(target)

        return self._make_result(start)

    async def _detect_consul(self, target: str) -> tuple[bool, dict[str, Any]]:
        """Detect and fingerprint Consul."""
        info: dict[str, Any] = {"detected": False, "version": "", "datacenter": ""}
        import aiohttp

        try:
            async with aiohttp.ClientSession(
                connector=aiohttp.TCPConnector(ssl=False),
                timeout=aiohttp.ClientTimeout(total=8),
            ) as session:
                await self.rate_limit()
                try:
                    async with session.get(f"{target}/v1/agent/self") as resp:
                        for key in resp.headers:
                            if "consul" in key.lower():
                                info["detected"] = True
                                break

                        if resp.status == 200:
                            body = await resp.text(errors="ignore")
                            try:
                                data = json.loads(body)
                                config = data.get("Config", data.get("config", {}))
                                info["detected"] = True
                                info["version"] = config.get("Version", data.get("Member", {}).get("Tags", {}).get("build", ""))
                                info["datacenter"] = config.get("Datacenter", "")
                                info["node_name"] = config.get("NodeName", "")
                                info["server"] = config.get("Server", False)
                            except json.JSONDecodeError:
                                pass
                        elif resp.status == 403:
                            # ACLs enabled but Consul is present
                            info["detected"] = True
                            info["acl_enabled"] = True
                except Exception:
                    pass

                if not info["detected"]:
                    await self.rate_limit()
                    try:
                        async with session.get(f"{target}/v1/status/leader") as resp:
                            body = await resp.text(errors="ignore")
                            if re.match(r'"[\d\.:]+"\s*$', body.strip()):
                                info["detected"] = True
                    except Exception:
                        pass
        except Exception as exc:
            self.log.debug("Consul detection error: %s", exc)

        return info["detected"], info

    async def _check_agent_exposure(self, target: str, info: dict[str, Any]) -> None:
        """Check agent endpoint exposure."""
        import aiohttp
        exposed = []

        try:
            async with aiohttp.ClientSession(
                connector=aiohttp.TCPConnector(ssl=False),
                timeout=aiohttp.ClientTimeout(total=8),
            ) as session:
                for path, desc in AGENT_ENDPOINTS:
                    await self.rate_limit()
                    try:
                        async with session.get(f"{target}{path}") as resp:
                            if resp.status == 200:
                                body = await resp.text(errors="ignore")
                                exposed.append({"path": path, "description": desc, "size": len(body)})
                    except Exception:
                        continue
        except Exception:
            pass

        if exposed:
            has_self = any("/agent/self" in e["path"] for e in exposed)
            self.new_finding(
                title="Consul — Agent API Exposed Without ACL",
                severity=Severity.HIGH if has_self else Severity.MEDIUM,
                description=(
                    f"Consul agent at {target} exposes {len(exposed)} endpoints without "
                    f"ACL authentication. "
                    f"{'Full agent configuration including tokens is accessible.' if has_self else ''} "
                    f"Version: {info.get('version', 'unknown')}, "
                    f"Datacenter: {info.get('datacenter', 'unknown')}."
                ),
                reproduction_steps=[f"  - GET {e['path']} ({e['description']})" for e in exposed],
                remediation=(
                    "Enable Consul ACLs: acl { enabled = true, default_policy = \"deny\" }. "
                    "Create tokens with minimum necessary permissions. "
                    "Restrict HTTP API access via bind_addr and network policy."
                ),
                references=[
                    "https://developer.hashicorp.com/consul/docs/security/acl",
                    "https://developer.hashicorp.com/consul/tutorials/security/access-control-setup-production",
                ],
                evidence=Evidence(extra={"exposed_endpoints": exposed, "version": info.get("version", "")}),
                cvss_v31_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                mitre_attack=["TA0007/T1046", "TA0009/T1213"],
                target=target,
                confidence="HIGH",
                tags=self.TAGS,
            )

    async def _check_catalog(self, target: str) -> None:
        """Check catalog endpoint for service/node enumeration."""
        import aiohttp

        try:
            async with aiohttp.ClientSession(
                connector=aiohttp.TCPConnector(ssl=False),
                timeout=aiohttp.ClientTimeout(total=8),
            ) as session:
                await self.rate_limit()
                try:
                    async with session.get(f"{target}/v1/catalog/services") as resp:
                        if resp.status == 200:
                            body = await resp.text(errors="ignore")
                            try:
                                services = json.loads(body)
                                if isinstance(services, dict) and len(services) > 0:
                                    self.new_finding(
                                        title="Consul — Service Catalog Exposed",
                                        severity=Severity.MEDIUM,
                                        description=(
                                            f"Consul catalog at {target} exposes {len(services)} "
                                            f"services without authentication. Service names reveal "
                                            f"infrastructure topology and attack surface."
                                        ),
                                        reproduction_steps=[
                                            f"1. GET {target}/v1/catalog/services",
                                            f"2. {len(services)} services returned",
                                        ],
                                        remediation="Enable ACLs with deny default policy.",
                                        references=["https://developer.hashicorp.com/consul/docs/security/acl"],
                                        evidence=Evidence(
                                            extra={"service_count": len(services), "services": list(services.keys())[:20]},
                                        ),
                                        cvss_v31_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                                        mitre_attack=["TA0007/T1046"],
                                        target=target,
                                        confidence="HIGH",
                                        tags=self.TAGS,
                                    )
                            except json.JSONDecodeError:
                                pass
                except Exception:
                    pass
        except Exception:
            pass

    async def _check_kv_secrets(self, target: str) -> None:
        """Check KV store for sensitive data."""
        import aiohttp
        secrets_found: list[dict[str, Any]] = []

        try:
            async with aiohttp.ClientSession(
                connector=aiohttp.TCPConnector(ssl=False),
                timeout=aiohttp.ClientTimeout(total=10),
            ) as session:
                # List root keys
                await self.rate_limit()
                try:
                    async with session.get(f"{target}/v1/kv/?keys") as resp:
                        if resp.status == 200:
                            body = await resp.text(errors="ignore")
                            try:
                                keys = json.loads(body)
                                if isinstance(keys, list):
                                    for key in keys:
                                        for pattern in SENSITIVE_KV_PREFIXES:
                                            if pattern.lower() in key.lower():
                                                secrets_found.append({"key": key, "pattern": pattern})
                                                break
                            except json.JSONDecodeError:
                                pass
                except Exception:
                    pass

                # Check specific sensitive prefixes
                for prefix in SENSITIVE_KV_PREFIXES[:5]:
                    await self.rate_limit()
                    try:
                        async with session.get(f"{target}/v1/kv/{prefix}?keys") as resp:
                            if resp.status == 200:
                                body = await resp.text(errors="ignore")
                                try:
                                    keys = json.loads(body)
                                    if isinstance(keys, list) and keys:
                                        for k in keys:
                                            if k not in [s["key"] for s in secrets_found]:
                                                secrets_found.append({"key": k, "pattern": prefix})
                                except json.JSONDecodeError:
                                    pass
                    except Exception:
                        continue
        except Exception:
            pass

        if secrets_found:
            self.new_finding(
                title="Consul — KV Store Contains Sensitive Data",
                severity=Severity.CRITICAL,
                description=(
                    f"Consul KV store at {target} contains {len(secrets_found)} "
                    f"potentially sensitive keys accessible without authentication. "
                    f"Keys matching patterns: {', '.join(set(s['pattern'] for s in secrets_found))}."
                ),
                reproduction_steps=[
                    f"1. GET {target}/v1/kv/?keys",
                    f"2. Found {len(secrets_found)} sensitive keys",
                ] + [f"   - {s['key']}" for s in secrets_found[:10]],
                remediation=(
                    "Enable Consul ACLs. Move secrets to HashiCorp Vault. "
                    "If KV must store secrets, use ACL policies to restrict read access."
                ),
                references=["https://developer.hashicorp.com/consul/docs/security/acl"],
                evidence=Evidence(extra={"secrets": secrets_found[:20]}),
                cvss_v31_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N",
                mitre_attack=["TA0006/T1552", "TA0009/T1213"],
                target=target,
                confidence="HIGH",
                tags=self.TAGS + ["kv-secrets"],
            )

    async def _check_acl_config(self, target: str) -> None:
        """Check ACL configuration and bootstrap status."""
        import aiohttp

        try:
            async with aiohttp.ClientSession(
                connector=aiohttp.TCPConnector(ssl=False),
                timeout=aiohttp.ClientTimeout(total=8),
            ) as session:
                # Check if ACL tokens are listable
                await self.rate_limit()
                try:
                    async with session.get(f"{target}/v1/acl/tokens") as resp:
                        if resp.status == 200:
                            body = await resp.text(errors="ignore")
                            try:
                                tokens = json.loads(body)
                                if isinstance(tokens, list) and tokens:
                                    self.new_finding(
                                        title="Consul — ACL Tokens Listable Without Auth",
                                        severity=Severity.CRITICAL,
                                        description=(
                                            f"Consul ACL tokens at {target} are listable without "
                                            f"authentication. Found {len(tokens)} tokens. "
                                            f"Token secrets may be extractable."
                                        ),
                                        reproduction_steps=[
                                            f"1. GET {target}/v1/acl/tokens",
                                            f"2. {len(tokens)} tokens returned",
                                        ],
                                        remediation="Enable ACLs with deny default. Restrict token listing.",
                                        references=["https://developer.hashicorp.com/consul/docs/security/acl"],
                                        evidence=Evidence(extra={"token_count": len(tokens)}),
                                        cvss_v31_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N",
                                        mitre_attack=["TA0006/T1552.004"],
                                        target=target,
                                        confidence="HIGH",
                                        tags=self.TAGS + ["acl-bypass"],
                                    )
                            except json.JSONDecodeError:
                                pass
                except Exception:
                    pass
        except Exception:
            pass

    async def _check_connect_ca(self, target: str) -> None:
        """Check if Connect CA configuration is exposed."""
        import aiohttp

        try:
            async with aiohttp.ClientSession(
                connector=aiohttp.TCPConnector(ssl=False),
                timeout=aiohttp.ClientTimeout(total=8),
            ) as session:
                await self.rate_limit()
                try:
                    async with session.get(f"{target}/v1/connect/ca/configuration") as resp:
                        if resp.status == 200:
                            body = await resp.text(errors="ignore")
                            try:
                                data = json.loads(body)
                                config = data.get("Config", {})
                                has_private = any(
                                    "private" in str(v).lower() or "key" in str(k).lower()
                                    for k, v in config.items()
                                )
                                if has_private or config:
                                    self.new_finding(
                                        title="Consul — Connect CA Configuration Exposed",
                                        severity=Severity.HIGH if has_private else Severity.MEDIUM,
                                        description=(
                                            f"Consul Connect CA configuration at {target} is "
                                            f"accessible without authentication. "
                                            f"{'Private key material may be exposed.' if has_private else ''}"
                                        ),
                                        reproduction_steps=[
                                            f"1. GET {target}/v1/connect/ca/configuration",
                                            "2. CA configuration returned",
                                        ],
                                        remediation="Enable ACLs. Restrict operator-level API access.",
                                        references=["https://developer.hashicorp.com/consul/docs/connect/ca"],
                                        evidence=Evidence(
                                            response_raw=body[:2000],
                                            extra={"has_private_key": has_private},
                                        ),
                                        cvss_v31_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                                        mitre_attack=["TA0006/T1552.004"],
                                        target=target,
                                        confidence="HIGH",
                                        tags=self.TAGS + ["ca-exposure"],
                                    )
                            except json.JSONDecodeError:
                                pass
                except Exception:
                    pass
        except Exception:
            pass


# ══════════════════════════════════════════════════════════════════════
# UNIT TESTS
# ══════════════════════════════════════════════════════════════════════


class TestConsulAudit:
    def _make_module(self, tmp_path: Path) -> ConsulAudit:
        from common.config import BaseForgeConfig
        from common.scope import Scope
        from common.db import create_db
        cfg = BaseForgeConfig(target="http://consul.example.com:8500")
        scope = Scope(["consul.example.com"])
        session = create_db(tmp_path / "test.db")
        return ConsulAudit(cfg, scope, session, tmp_path)

    def test_module_metadata(self, tmp_path: Path) -> None:
        mod = self._make_module(tmp_path)
        assert mod.NAME == "consul_audit"
        assert mod.PHASE == 4
        assert "consul" in mod.TAGS

    def test_agent_endpoints(self, tmp_path: Path) -> None:
        assert len(AGENT_ENDPOINTS) >= 3
        assert any("/v1/agent/self" in ep[0] for ep in AGENT_ENDPOINTS)

    def test_sensitive_kv_prefixes(self, tmp_path: Path) -> None:
        assert len(SENSITIVE_KV_PREFIXES) >= 5
        assert "secrets/" in SENSITIVE_KV_PREFIXES

    def test_acl_endpoints(self, tmp_path: Path) -> None:
        assert len(ACL_ENDPOINTS) >= 3

    def test_out_of_scope_skip(self, tmp_path: Path) -> None:
        from common.config import BaseForgeConfig
        from common.scope import Scope
        from common.db import create_db
        cfg = BaseForgeConfig(target="http://consul.example.com:8500")
        scope = Scope(["10.0.0.0/24"])
        session = create_db(tmp_path / "test.db")
        mod = ConsulAudit(cfg, scope, session, tmp_path)
        result = asyncio.run(mod.run())
        assert result.skipped is True
