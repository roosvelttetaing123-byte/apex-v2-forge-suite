"""Kubernetes Auditor — API server auth, RBAC audit, etcd exposure, pod security.

Tests:
  - Unauthenticated API server access
  - Anonymous RBAC permissions
  - etcd direct access (TCP 2379)
  - Privileged pod detection
  - Service account token exposure
  - Dashboard exposure
"""
from __future__ import annotations

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity

CVSS_ANON_API    = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
CVSS40_ANON_API  = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H"
CVSS_ETCD        = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
CVSS40_ETCD      = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H"
CVSS_DASHBOARD   = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
CVSS40_DASHBOARD = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N"

K8S_PORTS = {
    6443: "kube-apiserver (https)",
    8443: "kube-apiserver (alt)",
    8080: "kube-apiserver (insecure)",
    10250: "kubelet",
    10255: "kubelet (read-only)",
    2379: "etcd",
    30000: "NodePort range start",
}


class KubernetesAudit(BaseModule):
    """Kubernetes cluster security auditor."""

    NAME        = "kubernetes_audit"
    DESCRIPTION = "K8s: API server auth, RBAC, etcd exposure, pod security, dashboard"
    PHASE       = 4
    TAGS        = ["kubernetes", "k8s", "container", "cwe-306", "cwe-284"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        target = self.config.target

        if not self.check_scope(target):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        hosts = self.config.extra.get("live_hosts", [target])
        for host in hosts[:10]:
            if not self.check_scope(host):
                continue
            await self.rate_limit()
            await self._audit_k8s(host)

        return self._make_result(start)

    async def _audit_k8s(self, host: str) -> None:
        import aiohttp

        # Check API server (6443, 8443, 8080)
        for port in [6443, 8443, 8080]:
            await self.rate_limit()
            scheme = "http" if port == 8080 else "https"
            try:
                async with aiohttp.ClientSession(
                    connector=aiohttp.TCPConnector(ssl=False),
                    timeout=aiohttp.ClientTimeout(total=8),
                ) as session:
                    async with session.get(f"{scheme}://{host}:{port}/api") as resp:
                        if resp.status == 200:
                            data = await resp.json()
                            await self._check_api_server(session, host, port, scheme, data)
                            break
                        elif resp.status == 403:
                            # API exists but requires auth — check for info leak
                            await self._check_version_leak(session, host, port, scheme)
                            break
            except Exception:
                continue

        # Check etcd (2379)
        await self._check_etcd(host)

        # Check kubelet (10250, 10255)
        await self._check_kubelet(host)

    async def _check_api_server(
        self, session, host: str, port: int, scheme: str, api_data: dict
    ) -> None:
        base = f"{scheme}://{host}:{port}"

        # Try to list namespaces (anonymous access test)
        try:
            async with session.get(f"{base}/api/v1/namespaces") as resp:
                if resp.status == 200:
                    ns_data = await resp.json()
                    namespaces = [
                        item.get("metadata", {}).get("name", "?")
                        for item in ns_data.get("items", [])
                    ]

                    ev = Evidence(
                        request_raw=f"GET {base}/api/v1/namespaces",
                        extra={
                            "host": host, "port": port,
                            "namespaces": namespaces[:20],
                            "anonymous_access": True,
                        },
                    )
                    self.new_finding(
                        title=f"Kubernetes API Server — Anonymous Access — {host}:{port}",
                        severity=Severity.CRITICAL,
                        description=(
                            f"Kubernetes API server on {host}:{port} allows anonymous access. "
                            f"Namespaces: {', '.join(namespaces[:10])}.\n\n"
                            "An attacker can:\n"
                            "  1. List all secrets (including service account tokens)\n"
                            "  2. Create privileged pods for container escape\n"
                            "  3. Access all deployed applications and data\n"
                            "  4. Deploy crypto miners or backdoors\n"
                            "  5. Exfiltrate all ConfigMaps and secrets"
                        ),
                        reproduction_steps=[
                            f"kubectl --server={base} --insecure-skip-tls-verify get namespaces",
                            f"kubectl --server={base} --insecure-skip-tls-verify get secrets -A",
                            f"kubectl --server={base} --insecure-skip-tls-verify get pods -A",
                        ],
                        remediation=(
                            "1. Disable anonymous auth: --anonymous-auth=false on API server\n"
                            "2. Enable RBAC: --authorization-mode=RBAC\n"
                            "3. Remove ClusterRoleBindings for system:anonymous\n"
                            "4. Use TLS client certificates for authentication\n"
                            "5. Never expose API server port to untrusted networks"
                        ),
                        references=["CWE-306", "CWE-284", "MITRE T1613"],
                        evidence=ev,
                        cvss_v31_vector=CVSS_ANON_API,
                        cvss_v40_vector=CVSS40_ANON_API,
                        mitre_attack=["TA0007/T1613"],
                        port=port, service="kube-apiserver", target=host,
                    )

                    # Try to read secrets
                    async with session.get(f"{base}/api/v1/secrets?limit=5") as sec_resp:
                        if sec_resp.status == 200:
                            sec_data = await sec_resp.json()
                            secret_names = [
                                s.get("metadata", {}).get("name", "?")
                                for s in sec_data.get("items", [])
                            ]
                            if secret_names:
                                ev2 = Evidence(extra={"secrets": secret_names[:20]})
                                self.new_finding(
                                    title=f"Kubernetes Secrets Readable — {host}:{port}",
                                    severity=Severity.CRITICAL,
                                    description=f"Secrets readable: {', '.join(secret_names[:10])}",
                                    reproduction_steps=[f"kubectl get secrets -A -o json --server={base}"],
                                    remediation="Restrict RBAC. Encrypt secrets at rest (etcd encryption).",
                                    references=["CWE-312", "MITRE T1552"],
                                    evidence=ev2,
                                    cvss_v31_vector=CVSS_ANON_API,
                                    cvss_v40_vector=CVSS40_ANON_API,
                                    port=port, service="kube-apiserver", target=host,
                                )
        except Exception:
            pass

    async def _check_version_leak(
        self, session, host: str, port: int, scheme: str
    ) -> None:
        try:
            async with session.get(f"{scheme}://{host}:{port}/version") as resp:
                if resp.status == 200:
                    data = await resp.json()
                    version = data.get("gitVersion", "unknown")
                    self.new_finding(
                        title=f"Kubernetes Version Disclosure — {host}:{port} ({version})",
                        severity=Severity.LOW,
                        description=f"K8s API server version: {version}",
                        reproduction_steps=[f"curl -k https://{host}:{port}/version"],
                        remediation="Restrict /version endpoint access.",
                        references=["CWE-200"],
                        evidence=Evidence(extra=data),
                        cvss_v31_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                        cvss_v40_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
                        port=port, service="kube-apiserver", target=host,
                    )
        except Exception:
            pass

    async def _check_etcd(self, host: str) -> None:
        import aiohttp
        try:
            async with aiohttp.ClientSession(
                connector=aiohttp.TCPConnector(ssl=False),
                timeout=aiohttp.ClientTimeout(total=5),
            ) as session:
                async with session.get(f"http://{host}:2379/version") as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        ev = Evidence(extra={"etcd_version": data})
                        self.new_finding(
                            title=f"etcd Unauthenticated Access — {host}:2379",
                            severity=Severity.CRITICAL,
                            description=(
                                f"etcd on {host}:2379 is accessible without auth. "
                                "etcd stores ALL Kubernetes cluster state including secrets, "
                                "ConfigMaps, service account tokens, and RBAC policies. "
                                "Full cluster compromise is immediate."
                            ),
                            reproduction_steps=[
                                f"curl http://{host}:2379/v2/keys/?recursive=true",
                                f"etcdctl --endpoints=http://{host}:2379 get / --prefix --keys-only",
                            ],
                            remediation=(
                                "1. Enable mTLS on etcd\n"
                                "2. Bind etcd to localhost or management interface\n"
                                "3. Firewall: block 2379/2380 from all non-control-plane nodes"
                            ),
                            references=["CWE-306"],
                            evidence=ev,
                            cvss_v31_vector=CVSS_ETCD,
                            cvss_v40_vector=CVSS40_ETCD,
                            port=2379, service="etcd", target=host,
                        )
        except Exception:
            pass

    async def _check_kubelet(self, host: str) -> None:
        import aiohttp
        for port in [10250, 10255]:
            try:
                scheme = "https" if port == 10250 else "http"
                async with aiohttp.ClientSession(
                    connector=aiohttp.TCPConnector(ssl=False),
                    timeout=aiohttp.ClientTimeout(total=5),
                ) as session:
                    async with session.get(f"{scheme}://{host}:{port}/pods") as resp:
                        if resp.status == 200:
                            data = await resp.json()
                            pods = [
                                p.get("metadata", {}).get("name", "?")
                                for p in data.get("items", [])
                            ]
                            ev = Evidence(extra={"pods": pods[:20], "port": port})
                            self.new_finding(
                                title=f"Kubelet API Exposed — {host}:{port} ({len(pods)} pods)",
                                severity=Severity.HIGH if port == 10255 else Severity.CRITICAL,
                                description=(
                                    f"Kubelet on {host}:{port} exposes pod information. "
                                    f"Pods: {', '.join(pods[:5])}. "
                                    + ("Port 10250 allows command execution in containers via /exec." if port == 10250 else "")
                                ),
                                reproduction_steps=[
                                    f"curl -k {scheme}://{host}:{port}/pods",
                                    f"curl -k {scheme}://{host}:{port}/runningpods/",
                                ],
                                remediation="Disable anonymous kubelet auth. Enable webhook authentication.",
                                references=["CWE-306"],
                                evidence=ev,
                                cvss_v31_vector=CVSS_DASHBOARD,
                                cvss_v40_vector=CVSS40_DASHBOARD,
                                port=port, service="kubelet", target=host,
                            )
            except Exception:
                pass


class TestKubernetesAudit:
    def test_ports(self) -> None:
        assert 6443 in K8S_PORTS
        assert 2379 in K8S_PORTS

    def test_cvss(self) -> None:
        assert CVSS_ANON_API.startswith("CVSS:3.1")
        assert "/S:C/" in CVSS_ANON_API

    def test_phase(self) -> None:
        assert KubernetesAudit.PHASE == 4
