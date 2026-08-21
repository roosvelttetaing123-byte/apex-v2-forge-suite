"""Linux Docker Audit — container security checks via credentialed SSH."""
from __future__ import annotations

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity

CVSS_DOCKER_SOCK = "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H"
CVSS_PRIVILEGED  = "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H"
CVSS_HOST_MOUNT  = "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N"


class LinuxDockerAudit(BaseModule):
    NAME        = "linux_docker_audit"
    DESCRIPTION = "SSH credentialed: Docker socket, privileged containers, host mounts, outdated images"
    PHASE       = 5
    TAGS        = ["credentialed", "linux", "docker", "container", "cwe-250"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        transport_mgr = self.config.extra.get("transport_manager")
        if not transport_mgr or not transport_mgr.has_creds("ssh"):
            return self._make_result(start, skipped=True, skip_reason="no SSH credentials")

        hosts = self.config.extra.get("live_hosts", [self.config.target])
        for host in hosts[:30]:
            if not self.check_scope(host):
                continue
            await self.rate_limit()
            session = await transport_mgr.get_ssh_session(host)
            if not session:
                continue
            await self._audit_docker(host, transport_mgr.ssh, session)

        return self._make_result(start)

    async def _audit_docker(self, host: str, ssh, session) -> None:
        # Check if Docker is installed
        docker_check = await ssh.execute(session, "docker --version 2>/dev/null")
        if not docker_check.success:
            return

        # Docker socket permissions
        sock_result = await ssh.execute(session, "ls -la /var/run/docker.sock 2>/dev/null")
        if sock_result.success and "srw" in sock_result.stdout:
            perms = sock_result.stdout.strip().split()[0] if sock_result.stdout.split() else ""
            if len(perms) >= 8 and perms[7] == 'r':
                self.new_finding(
                    title=f"Docker Socket World-Accessible — {host}",
                    severity=Severity.CRITICAL,
                    description=(
                        f"Docker socket is world-readable/writable on {host}. "
                        "Any user can create privileged containers and escape to root."
                    ),
                    reproduction_steps=[f"ssh {host}", "ls -la /var/run/docker.sock"],
                    remediation="chmod 660 /var/run/docker.sock; restrict to docker group",
                    references=["CWE-250"],
                    evidence=Evidence(extra={"host": host, "perms": sock_result.stdout.strip()}),
                    cvss_v31_vector=CVSS_DOCKER_SOCK,
                    mitre_attack=["TA0004/T1611"],
                    target=host, service="ssh", confidence="HIGH",
                )

        # Docker group members (any member = root equivalent)
        group_result = await ssh.execute(session, "getent group docker 2>/dev/null")
        if group_result.success and ":" in group_result.stdout:
            members = group_result.stdout.strip().split(":")[-1].split(",")
            members = [m.strip() for m in members if m.strip()]
            if len(members) > 3:
                self.new_finding(
                    title=f"Excessive Docker Group Members ({len(members)}) — {host}",
                    severity=Severity.HIGH,
                    description=(
                        f"{len(members)} users in docker group (root equivalent): "
                        f"{', '.join(members[:10])}."
                    ),
                    reproduction_steps=[f"ssh {host}", "getent group docker"],
                    remediation="Remove unnecessary users from docker group.",
                    references=["CWE-250"],
                    evidence=Evidence(extra={"host": host, "members": members}),
                    target=host, service="ssh",
                )

        # Running containers — check for privileged and host mounts
        containers = await ssh.execute(session,
            "docker ps --format '{{.ID}} {{.Names}} {{.Image}}' 2>/dev/null")
        if not containers.success:
            return

        for line in containers.stdout.strip().split("\n"):
            parts = line.split()
            if len(parts) < 3:
                continue
            cid, name, image = parts[0], parts[1], parts[2]

            inspect = await ssh.execute(session,
                f"docker inspect {cid} --format "
                "'{{{{.HostConfig.Privileged}}}} {{{{.HostConfig.PidMode}}}} "
                "{{{{range .Mounts}}}}{{{{.Source}}}}:{{{{.Destination}}}} {{{{end}}}}' 2>/dev/null")

            if "true" in inspect.stdout.lower().split()[0:1]:
                self.new_finding(
                    title=f"Privileged Container Running — {name} — {host}",
                    severity=Severity.CRITICAL,
                    description=f"Container '{name}' ({image}) runs with --privileged on {host}.",
                    reproduction_steps=[f"ssh {host}", f"docker inspect {cid} | grep Privileged"],
                    remediation="Remove --privileged. Use specific capabilities instead.",
                    references=["CWE-250"],
                    evidence=Evidence(extra={"host": host, "container": name, "image": image}),
                    cvss_v31_vector=CVSS_PRIVILEGED,
                    mitre_attack=["TA0004/T1611"],
                    target=host, service="ssh", confidence="HIGH",
                )

            # Check for sensitive host mounts
            if inspect.success:
                mounts = inspect.stdout.strip()
                dangerous_mounts = ["/", "/etc", "/var/run/docker.sock", "/root", "/home"]
                for dm in dangerous_mounts:
                    if f"{dm}:" in mounts:
                        self.new_finding(
                            title=f"Container Mounts Host Path '{dm}' — {name} — {host}",
                            severity=Severity.HIGH,
                            description=f"Container '{name}' mounts sensitive host path {dm}.",
                            reproduction_steps=[f"ssh {host}", f"docker inspect {cid} | jq '.[].Mounts'"],
                            remediation=f"Remove host mount of {dm} from container.",
                            references=["CWE-250"],
                            evidence=Evidence(extra={"host": host, "container": name, "mount": dm}),
                            cvss_v31_vector=CVSS_HOST_MOUNT,
                            target=host, service="ssh",
                        )
                        break
