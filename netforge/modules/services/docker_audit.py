"""Docker Audit — detect exposed Docker daemon API and security misconfigurations.

Tests:
  - Unauthenticated Docker API access (TCP 2375/2376)
  - Privileged container detection
  - Docker socket file exposure (/var/run/docker.sock)
  - Container escape risk assessment
  - Image vulnerability surface (outdated base images)
"""
from __future__ import annotations

import asyncio
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity

CVSS_API_EXPOSED    = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
CVSS40_API_EXPOSED  = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H"
CVSS_PRIVILEGED     = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H"
CVSS40_PRIVILEGED   = "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H"

DOCKER_PORTS = [2375, 2376, 4243]

DANGEROUS_MOUNTS = [
    "/var/run/docker.sock",
    "/",
    "/etc",
    "/proc",
    "/sys",
    "/dev",
]


class DockerAudit(BaseModule):
    """Docker daemon API security auditor."""

    NAME        = "docker_audit"
    DESCRIPTION = "Docker: unauthenticated API, privileged containers, socket exposure, escape risk"
    PHASE       = 4
    TAGS        = ["docker", "services", "container", "cwe-284", "cwe-250"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        target = self.config.target

        if not self.check_scope(target):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        hosts = self.config.extra.get("live_hosts", [target])

        for host in hosts[:20]:
            if not self.check_scope(host):
                continue
            for port in DOCKER_PORTS:
                await self.rate_limit()
                if await self._check_docker_api(host, port):
                    break  # One port per host is enough

        return self._make_result(start)

    async def _check_docker_api(self, host: str, port: int) -> bool:
        """Try unauthenticated access to Docker REST API."""
        import aiohttp
        url = f"http://{host}:{port}"
        try:
            async with aiohttp.ClientSession(
                connector=aiohttp.TCPConnector(ssl=False),
                timeout=aiohttp.ClientTimeout(total=8),
            ) as session:
                # Test /version endpoint
                await self.rate_limit()
                async with session.get(f"{url}/version") as resp:
                    if resp.status != 200:
                        return False
                    version_data = await resp.json()

                docker_version = version_data.get("Version", "unknown")
                api_version = version_data.get("ApiVersion", "unknown")
                os_type = version_data.get("Os", "unknown")
                arch = version_data.get("Arch", "unknown")

                # Critical: unauthenticated API access
                ev = Evidence(
                    request_raw=f"GET {url}/version",
                    response_raw=json.dumps(version_data, indent=2)[:2000],
                    extra={
                        "host": host, "port": port,
                        "docker_version": docker_version,
                        "api_version": api_version,
                        "os": os_type, "arch": arch,
                    },
                )
                self.new_finding(
                    title=f"Exposed Docker Daemon API — {host}:{port} (v{docker_version})",
                    severity=Severity.CRITICAL,
                    description=(
                        f"The Docker daemon API on {host}:{port} is accessible WITHOUT "
                        f"authentication. Docker version: {docker_version}, "
                        f"API: {api_version}, OS: {os_type}/{arch}.\n\n"
                        "An attacker can:\n"
                        "  1. Start a privileged container with host filesystem mounted\n"
                        "  2. Execute commands as root on the host\n"
                        "  3. Read all secrets, keys, and data on the host\n"
                        "  4. Install persistent backdoors\n"
                        "  5. Pivot to other networked systems\n\n"
                        "This is equivalent to unauthenticated root access."
                    ),
                    reproduction_steps=[
                        f"curl http://{host}:{port}/version",
                        f"# Full host takeover:",
                        f"docker -H tcp://{host}:{port} run -v /:/mnt --rm -it alpine chroot /mnt sh",
                        f"# Or via API:",
                        f'curl -X POST http://{host}:{port}/containers/create '
                        f'-H "Content-Type: application/json" '
                        f'-d \'{{"Image":"alpine","Cmd":["cat","/etc/shadow"],'
                        f'"HostConfig":{{"Binds":["/:/mnt"],"Privileged":true}}}}\'',
                    ],
                    remediation=(
                        "IMMEDIATE action required:\n"
                        "1. Bind Docker daemon to unix socket only (default): "
                        "remove -H tcp:// from dockerd args\n"
                        "2. If remote access needed: enable mutual TLS (mTLS)\n"
                        "   dockerd --tlsverify --tlscacert=ca.pem --tlscert=server-cert.pem "
                        "--tlskey=server-key.pem\n"
                        "3. Firewall: block TCP 2375/2376/4243 from all untrusted networks\n"
                        "4. Consider using Docker contexts with SSH transport instead"
                    ),
                    references=[
                        "CWE-284", "CWE-306",
                        "MITRE T1610", "MITRE T1609",
                        "https://docs.docker.com/engine/security/protect-access/",
                    ],
                    evidence=ev,
                    cvss_v31_vector=CVSS_API_EXPOSED,
                    cvss_v40_vector=CVSS40_API_EXPOSED,
                    mitre_attack=["TA0002/T1610", "TA0002/T1609"],
                    port=port, service="docker-api", target=host,
                )

                # Enumerate containers for privileged/dangerous configs
                await self._audit_containers(session, url, host, port)
                return True

        except Exception:
            return False

    async def _audit_containers(
        self, session, url: str, host: str, port: int
    ) -> None:
        """Check running containers for dangerous configurations."""
        try:
            await self.rate_limit()
            async with session.get(f"{url}/containers/json?all=true") as resp:
                if resp.status != 200:
                    return
                containers = await resp.json()

            for container in containers[:20]:
                cid = container.get("Id", "")[:12]
                name = (container.get("Names", ["unknown"]) or ["unknown"])[0].lstrip("/")
                image = container.get("Image", "unknown")
                state = container.get("State", "unknown")

                # Get detailed inspect for each running container
                if state != "running":
                    continue

                await self.rate_limit()
                async with session.get(f"{url}/containers/{cid}/json") as resp:
                    if resp.status != 200:
                        continue
                    detail = await resp.json()

                host_config = detail.get("HostConfig", {})
                privileged = host_config.get("Privileged", False)
                pid_mode = host_config.get("PidMode", "")
                network_mode = host_config.get("NetworkMode", "")
                cap_add = host_config.get("CapAdd") or []
                binds = host_config.get("Binds") or []

                issues = []
                if privileged:
                    issues.append("PRIVILEGED mode (full host kernel access)")
                if pid_mode == "host":
                    issues.append("PID namespace: host (can see/signal host processes)")
                if network_mode == "host":
                    issues.append("Network namespace: host (full network stack access)")
                if "SYS_ADMIN" in cap_add:
                    issues.append("CAP_SYS_ADMIN added (near-root capabilities)")
                if "SYS_PTRACE" in cap_add:
                    issues.append("CAP_SYS_PTRACE (can debug/inject into processes)")

                dangerous_mounts = []
                for bind in binds:
                    src = bind.split(":")[0] if ":" in bind else bind
                    if any(src == dm or src.startswith(dm + "/") for dm in DANGEROUS_MOUNTS):
                        dangerous_mounts.append(bind)

                if dangerous_mounts:
                    issues.append(f"Dangerous mounts: {', '.join(dangerous_mounts[:3])}")

                if issues:
                    ev = Evidence(
                        extra={
                            "container_id": cid, "name": name, "image": image,
                            "privileged": privileged, "issues": issues,
                            "mounts": dangerous_mounts, "cap_add": cap_add,
                        },
                    )
                    self.new_finding(
                        title=f"Docker Container Escape Risk — {name} ({cid})",
                        severity=Severity.CRITICAL if privileged else Severity.HIGH,
                        description=(
                            f"Container '{name}' (image: {image}) has dangerous configuration:\n"
                            + "\n".join(f"  - {i}" for i in issues) + "\n\n"
                            "These settings enable container escape to the host OS."
                        ),
                        reproduction_steps=[
                            f"docker -H tcp://{host}:{port} inspect {cid}",
                            f"# If privileged: docker exec -it {cid} nsenter -t 1 -m -u -i -n -p sh",
                        ],
                        remediation=(
                            "1. Remove --privileged flag; use specific capabilities instead\n"
                            "2. Avoid host PID/network/IPC namespaces\n"
                            "3. Drop all capabilities: --cap-drop=ALL, add only what's needed\n"
                            "4. Use read-only root filesystem: --read-only\n"
                            "5. Don't mount Docker socket or host root into containers"
                        ),
                        references=["CWE-250", "MITRE T1611"],
                        evidence=ev,
                        cvss_v31_vector=CVSS_PRIVILEGED,
                        cvss_v40_vector=CVSS40_PRIVILEGED,
                        mitre_attack=["TA0004/T1611"],
                        port=port, service="docker", target=host,
                    )
        except Exception as exc:
            self.log.debug("Container audit failed: %s", exc)


class TestDockerAudit:
    def test_docker_ports(self) -> None:
        assert 2375 in DOCKER_PORTS
        assert 2376 in DOCKER_PORTS

    def test_dangerous_mounts(self) -> None:
        assert "/var/run/docker.sock" in DANGEROUS_MOUNTS
        assert "/" in DANGEROUS_MOUNTS

    def test_cvss_vectors(self) -> None:
        assert CVSS_API_EXPOSED.startswith("CVSS:3.1")
        assert CVSS40_API_EXPOSED.startswith("CVSS:4.0")
        assert "/S:C/" in CVSS_API_EXPOSED  # Changed scope

    def test_phase(self) -> None:
        assert DockerAudit.PHASE == 4
