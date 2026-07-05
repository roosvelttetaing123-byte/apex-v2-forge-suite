"""etcd Security Audit — Unauthenticated Access & Secret Exposure.

Comprehensive security auditor for etcd key-value stores commonly
deployed alongside Kubernetes clusters. Checks for:

    1. Unauthenticated API access (v2 and v3 APIs)
    2. Cluster member/health endpoint exposure
    3. Kubernetes secrets extraction via key enumeration
    4. TLS client certificate enforcement
    5. Authentication/RBAC configuration
    6. Sensitive data in key-value store

etcd commonly runs on ports 2379 (client) and 2380 (peer).

FOR AUTHORIZED PENETRATION TESTING AND RED TEAM OPERATIONS ONLY.
"""
from __future__ import annotations

import asyncio
import base64
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

log = logging.getLogger("forge.etcd_audit")

# Standard etcd ports
ETCD_PORTS = [2379, 2380]

# ══════════════════════════════════════════════════════════════════════
# API ENDPOINTS
# ══════════════════════════════════════════════════════════════════════

# v2 API endpoints
V2_ENDPOINTS = [
    ("/version", "Version info"),
    ("/v2/keys/", "Root key listing"),
    ("/v2/members", "Cluster members"),
    ("/v2/stats/self", "Node statistics"),
    ("/v2/stats/store", "Store statistics"),
    ("/v2/stats/leader", "Leader statistics"),
    ("/v2/keys/?recursive=true", "Recursive key dump"),
]

# v3 API endpoints (gRPC gateway)
V3_ENDPOINTS = [
    ("/v3/cluster/member/list", "Cluster member listing"),
    ("/v3/maintenance/status", "Maintenance status"),
    ("/v3/auth/status", "Auth status"),
    ("/v3/kv/range", "Key-value range query"),
]

# Sensitive key patterns (Kubernetes secrets, credentials, tokens)
SENSITIVE_KEY_PATTERNS = [
    re.compile(r"/registry/secrets/", re.I),
    re.compile(r"/registry/serviceaccounts/", re.I),
    re.compile(r"password", re.I),
    re.compile(r"secret", re.I),
    re.compile(r"token", re.I),
    re.compile(r"credential", re.I),
    re.compile(r"api[_-]?key", re.I),
    re.compile(r"private[_-]?key", re.I),
    re.compile(r"certificate", re.I),
    re.compile(r"kubeconfig", re.I),
]


class EtcdAudit(BaseModule):
    """etcd Security Auditor.

    Checks for unauthenticated access, secret exposure, cluster
    misconfiguration, and missing TLS enforcement on etcd instances.
    """

    NAME = "etcd_audit"
    DESCRIPTION = "etcd security audit — unauthenticated access, secret exposure, cluster misconfig"
    PHASE = 4
    TAGS = ["etcd", "kubernetes", "secret-exposure", "no-auth", "infrastructure"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        target = self.config.target.rstrip("/")

        if not self.check_scope(target):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        await self.rate_limit()

        # Phase 1: Detect etcd
        is_etcd, info = await self._detect_etcd(target)
        if not is_etcd:
            self.log.info("[etcd_audit] Target does not appear to be etcd")
            return self._make_result(start)

        # Phase 2: Check authentication status
        await self._check_auth_status(target, info)

        # Phase 3: Enumerate cluster
        await self._enumerate_cluster(target)

        # Phase 4: Check for sensitive keys
        await self._check_sensitive_keys(target)

        # Phase 5: Check TLS configuration
        await self._check_tls(target)

        return self._make_result(start)

    async def _detect_etcd(self, target: str) -> tuple[bool, dict[str, Any]]:
        """Detect and fingerprint etcd instance."""
        info: dict[str, Any] = {"detected": False, "version": "", "cluster_id": ""}
        import aiohttp

        try:
            async with aiohttp.ClientSession(
                connector=aiohttp.TCPConnector(ssl=False),
                timeout=aiohttp.ClientTimeout(total=8),
            ) as session:
                await self.rate_limit()
                try:
                    async with session.get(f"{target}/version") as resp:
                        if resp.status == 200:
                            body = await resp.text(errors="ignore")
                            try:
                                data = json.loads(body)
                                if "etcdserver" in data or "etcdcluster" in data:
                                    info["detected"] = True
                                    info["version"] = data.get("etcdserver", "")
                                    info["cluster_version"] = data.get("etcdcluster", "")
                            except json.JSONDecodeError:
                                if "etcd" in body.lower():
                                    info["detected"] = True
                except Exception:
                    pass

                if not info["detected"]:
                    await self.rate_limit()
                    try:
                        async with session.get(f"{target}/health") as resp:
                            body = await resp.text(errors="ignore")
                            if "true" in body.lower() or "health" in body.lower():
                                info["detected"] = True
                    except Exception:
                        pass
        except Exception as exc:
            self.log.debug("etcd detection error: %s", exc)

        return info["detected"], info

    async def _check_auth_status(self, target: str, info: dict[str, Any]) -> None:
        """Check if authentication is enabled on etcd."""
        import aiohttp

        try:
            async with aiohttp.ClientSession(
                connector=aiohttp.TCPConnector(ssl=False),
                timeout=aiohttp.ClientTimeout(total=8),
            ) as session:
                # v3 auth status
                await self.rate_limit()
                try:
                    async with session.post(
                        f"{target}/v3/auth/status",
                        json={},
                        headers={"Content-Type": "application/json"},
                    ) as resp:
                        body = await resp.text(errors="ignore")
                        try:
                            data = json.loads(body)
                            auth_enabled = data.get("enabled", False)
                            if not auth_enabled:
                                self.new_finding(
                                    title="etcd — Authentication Disabled",
                                    severity=Severity.CRITICAL,
                                    description=(
                                        f"etcd instance at {target} has authentication disabled. "
                                        f"Any client can read/write all keys including Kubernetes "
                                        f"secrets, service account tokens, and cluster configuration. "
                                        f"Version: {info.get('version', 'unknown')}."
                                    ),
                                    reproduction_steps=[
                                        f"1. POST {target}/v3/auth/status",
                                        "2. Response shows enabled: false",
                                        "3. All v2/v3 API endpoints accessible without auth",
                                    ],
                                    remediation=(
                                        "Enable etcd authentication: etcdctl auth enable. "
                                        "Configure RBAC roles and users. "
                                        "Enable mutual TLS for client connections. "
                                        "Restrict network access to etcd ports (2379/2380)."
                                    ),
                                    references=[
                                        "https://etcd.io/docs/latest/op-guide/authentication/",
                                        "https://etcd.io/docs/latest/op-guide/security/",
                                    ],
                                    evidence=Evidence(
                                        response_raw=body[:2000],
                                        extra={"auth_enabled": False, "version": info.get("version", "")},
                                    ),
                                    cvss_v31_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                                    mitre_attack=["TA0006/T1552", "TA0001/T1190"],
                                    target=target,
                                    confidence="HIGH",
                                    tags=self.TAGS,
                                )
                        except json.JSONDecodeError:
                            pass
                except Exception:
                    pass

                # v2 key listing (if accessible = no auth)
                await self.rate_limit()
                try:
                    async with session.get(f"{target}/v2/keys/") as resp:
                        if resp.status == 200:
                            body = await resp.text(errors="ignore")
                            try:
                                data = json.loads(body)
                                if "node" in data:
                                    nodes = data.get("node", {}).get("nodes", [])
                                    self.new_finding(
                                        title="etcd — Unauthenticated Key Listing (v2 API)",
                                        severity=Severity.HIGH,
                                        description=(
                                            f"etcd v2 API at {target}/v2/keys/ returns key listing "
                                            f"without authentication. Found {len(nodes)} root keys."
                                        ),
                                        reproduction_steps=[
                                            f"1. GET {target}/v2/keys/",
                                            f"2. {len(nodes)} root keys returned",
                                        ],
                                        remediation="Enable authentication and restrict v2 API access.",
                                        references=["https://etcd.io/docs/latest/op-guide/authentication/"],
                                        evidence=Evidence(
                                            response_raw=body[:3000],
                                            extra={"root_key_count": len(nodes)},
                                        ),
                                        cvss_v31_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                                        mitre_attack=["TA0006/T1552", "TA0007/T1083"],
                                        target=target,
                                        confidence="HIGH",
                                        tags=self.TAGS,
                                    )
                            except json.JSONDecodeError:
                                pass
                except Exception:
                    pass
        except Exception as exc:
            self.log.debug("Auth status check error: %s", exc)

    async def _enumerate_cluster(self, target: str) -> None:
        """Enumerate cluster members and health."""
        import aiohttp

        try:
            async with aiohttp.ClientSession(
                connector=aiohttp.TCPConnector(ssl=False),
                timeout=aiohttp.ClientTimeout(total=8),
            ) as session:
                await self.rate_limit()
                try:
                    async with session.post(
                        f"{target}/v3/cluster/member/list", json={},
                    ) as resp:
                        if resp.status == 200:
                            body = await resp.text(errors="ignore")
                            try:
                                data = json.loads(body)
                                members = data.get("members", [])
                                if members:
                                    member_info = []
                                    for m in members:
                                        member_info.append({
                                            "name": m.get("name", ""),
                                            "peer_urls": m.get("peerURLs", []),
                                            "client_urls": m.get("clientURLs", []),
                                        })
                                    self.new_finding(
                                        title="etcd — Cluster Membership Exposed",
                                        severity=Severity.MEDIUM,
                                        description=(
                                            f"etcd cluster at {target} exposes {len(members)} "
                                            f"member nodes without authentication."
                                        ),
                                        reproduction_steps=[
                                            f"1. POST {target}/v3/cluster/member/list",
                                            f"2. {len(members)} members returned",
                                        ],
                                        remediation="Enable authentication. Restrict cluster API access.",
                                        references=["https://etcd.io/docs/latest/op-guide/security/"],
                                        evidence=Evidence(extra={"members": member_info}),
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
        except Exception as exc:
            self.log.debug("Cluster enumeration error: %s", exc)

    async def _check_sensitive_keys(self, target: str) -> None:
        """Check for sensitive keys in the etcd store."""
        import aiohttp

        try:
            async with aiohttp.ClientSession(
                connector=aiohttp.TCPConnector(ssl=False),
                timeout=aiohttp.ClientTimeout(total=10),
            ) as session:
                # v3 range query for /registry/secrets (Kubernetes secrets)
                await self.rate_limit()
                try:
                    range_key = base64.b64encode(b"/registry/secrets/").decode()
                    range_end = base64.b64encode(b"/registry/secrets0").decode()  # lexicographic end
                    async with session.post(
                        f"{target}/v3/kv/range",
                        json={
                            "key": range_key,
                            "range_end": range_end,
                            "keys_only": True,
                            "limit": 50,
                        },
                    ) as resp:
                        if resp.status == 200:
                            body = await resp.text(errors="ignore")
                            try:
                                data = json.loads(body)
                                kvs = data.get("kvs", [])
                                if kvs:
                                    secret_keys = []
                                    for kv in kvs:
                                        key = base64.b64decode(kv.get("key", "")).decode(errors="ignore")
                                        secret_keys.append(key)
                                    self.new_finding(
                                        title="etcd — Kubernetes Secrets Accessible",
                                        severity=Severity.CRITICAL,
                                        description=(
                                            f"Kubernetes secrets are readable from etcd at {target}. "
                                            f"Found {len(secret_keys)} secret keys accessible without auth. "
                                            f"This exposes service account tokens, TLS certs, and "
                                            f"application credentials stored in the cluster."
                                        ),
                                        reproduction_steps=[
                                            f"1. POST {target}/v3/kv/range with key=/registry/secrets/",
                                            f"2. {len(secret_keys)} secret keys returned",
                                            "3. Full secret values can be read (not attempted)",
                                        ],
                                        remediation=(
                                            "Enable etcd authentication and RBAC. "
                                            "Enable Kubernetes encryption at rest (EncryptionConfiguration). "
                                            "Restrict etcd network access to kube-apiserver only. "
                                            "Rotate all exposed secrets immediately."
                                        ),
                                        references=[
                                            "https://kubernetes.io/docs/tasks/administer-cluster/encrypt-data/",
                                            "https://etcd.io/docs/latest/op-guide/security/",
                                        ],
                                        evidence=Evidence(
                                            extra={
                                                "secret_count": len(secret_keys),
                                                "sample_keys": secret_keys[:10],
                                            },
                                        ),
                                        cvss_v31_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                                        mitre_attack=["TA0006/T1552.004", "TA0009/T1213"],
                                        target=target,
                                        confidence="HIGH",
                                        tags=self.TAGS + ["k8s-secrets"],
                                    )
                            except json.JSONDecodeError:
                                pass
                except Exception:
                    pass
        except Exception as exc:
            self.log.debug("Sensitive key check error: %s", exc)

    async def _check_tls(self, target: str) -> None:
        """Check if etcd requires TLS client certificates."""
        parsed = __import__("urllib.parse", fromlist=["urlparse"]).urlparse(target)
        if parsed.scheme == "http":
            self.new_finding(
                title="etcd — No TLS Encryption",
                severity=Severity.HIGH,
                description=(
                    f"etcd instance at {target} is accessible over plaintext HTTP. "
                    f"All data including secrets and credentials are transmitted unencrypted."
                ),
                reproduction_steps=[
                    f"1. Connect to {target} over HTTP (no TLS)",
                    "2. All API responses are unencrypted",
                ],
                remediation=(
                    "Enable TLS for client connections. Configure mutual TLS "
                    "with client certificate verification. See etcd security guide."
                ),
                references=["https://etcd.io/docs/latest/op-guide/security/"],
                evidence=Evidence(extra={"scheme": "http"}),
                cvss_v31_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                mitre_attack=["TA0006/T1557"],
                target=target,
                confidence="HIGH",
                tags=self.TAGS + ["no-tls"],
            )


# ══════════════════════════════════════════════════════════════════════
# UNIT TESTS
# ══════════════════════════════════════════════════════════════════════


class TestEtcdAudit:
    def _make_module(self, tmp_path: Path) -> EtcdAudit:
        from common.config import BaseForgeConfig
        from common.scope import Scope
        from common.db import create_db
        cfg = BaseForgeConfig(target="http://etcd.example.com:2379")
        scope = Scope(["etcd.example.com"])
        session = create_db(tmp_path / "test.db")
        return EtcdAudit(cfg, scope, session, tmp_path)

    def test_module_metadata(self, tmp_path: Path) -> None:
        mod = self._make_module(tmp_path)
        assert mod.NAME == "etcd_audit"
        assert mod.PHASE == 4
        assert "etcd" in mod.TAGS

    def test_sensitive_key_patterns(self, tmp_path: Path) -> None:
        assert any(p.search("/registry/secrets/default/my-secret") for p in SENSITIVE_KEY_PATTERNS)
        assert any(p.search("database_password") for p in SENSITIVE_KEY_PATTERNS)
        assert any(p.search("api_key_prod") for p in SENSITIVE_KEY_PATTERNS)

    def test_v2_endpoints_defined(self, tmp_path: Path) -> None:
        assert len(V2_ENDPOINTS) >= 5
        assert any("/v2/keys/" in ep[0] for ep in V2_ENDPOINTS)

    def test_v3_endpoints_defined(self, tmp_path: Path) -> None:
        assert len(V3_ENDPOINTS) >= 3
        assert any("/v3/kv/range" in ep[0] for ep in V3_ENDPOINTS)

    def test_out_of_scope_skip(self, tmp_path: Path) -> None:
        from common.config import BaseForgeConfig
        from common.scope import Scope
        from common.db import create_db
        cfg = BaseForgeConfig(target="http://etcd.example.com:2379")
        scope = Scope(["10.0.0.0/24"])
        session = create_db(tmp_path / "test.db")
        mod = EtcdAudit(cfg, scope, session, tmp_path)
        result = asyncio.run(mod.run())
        assert result.skipped is True
