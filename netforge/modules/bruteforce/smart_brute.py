"""Smart brute forcer — credential testing on discovered services."""
from __future__ import annotations

import asyncio
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity

CVSS_BRUTE = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
CVSS40_BRUTE = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N"
DEFAULT_USERNAMES = ["admin", "root", "administrator", "user", "test", "guest",
                     "operator", "service", "backup"]
DEFAULT_PASSWORDS = ["admin", "password", "123456", "root", "admin123",
                     "default", "pass", "test", "guest", "service"]

SERVICE_BRUTE_MAP = {
    22:    "ssh",
    21:    "ftp",
    3306:  "mysql",
    5432:  "postgres",
    27017: "mongodb",
    6379:  "redis",
    3389:  "rdp",
}


class SmartBrute(BaseModule):
    """Service-aware credential brute forcer."""

    NAME        = "smart_brute"
    DESCRIPTION = "Test discovered services for default/weak credentials"
    PHASE       = 6
    TAGS        = ["bruteforce", "credentials", "default-creds", "cwe-521"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        target = self.config.target

        if not self.check_scope(target):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        confirmed = self.confirm_action(
            module=self.NAME,
            action="Test open services for default/weak credentials",
            target=target,
            risk="Lockout risk on SSH/RDP. Conservative wordlist used.",
        )
        if not confirmed:
            return self._make_result(start, skipped=True, skip_reason="operator declined")

        open_ports = self.config.extra.get("open_ports", {})

        for host, ports in open_ports.items():
            if not self.check_scope(host):
                continue
            for port_info in ports:
                port = port_info.get("port", 0)
                service = SERVICE_BRUTE_MAP.get(port)
                if service:
                    await self._brute_service(host, port, service)

        return self._make_result(start)

    async def _brute_service(self, host: str, port: int, service: str) -> None:
        """Test default credentials for a specific service."""
        self.log.info("Testing %s credentials on %s:%d", service, host, port)

        if service == "redis":
            await self._brute_redis(host, port)
        elif service == "ftp":
            await self._brute_ftp(host, port)
        elif service == "mongodb":
            await self._brute_mongodb(host, port)
        elif service in ("mysql", "postgres"):
            await self._brute_db(host, port, service)

    async def _brute_redis(self, host: str, port: int) -> None:
        """Check Redis for no-auth or password bypass."""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=3
            )
            writer.write(b"PING\r\n")
            await writer.drain()
            response = await asyncio.wait_for(reader.read(64), timeout=3)
            writer.close()

            if b"+PONG" in response:
                ev = Evidence(
                    extra={"host": host, "port": port, "auth": "none"}
                )
                self.new_finding(
                    title=f"Redis — No Authentication Required ({host}:{port})",
                    severity=Severity.CRITICAL,
                    description=(
                        f"Redis on {host}:{port} accepts commands without authentication. "
                        "Full data access and potential RCE via config rewrite."
                    ),
                    reproduction_steps=[
                        f"redis-cli -h {host} -p {port} PING",
                        f"redis-cli -h {host} -p {port} CONFIG SET dir /var/www/html",
                        f"redis-cli -h {host} -p {port} CONFIG SET dbfilename shell.php",
                    ],
                    remediation=(
                        "Set requirepass in redis.conf. "
                        "Bind Redis to 127.0.0.1 only. "
                        "Enable protected-mode yes."
                    ),
                    references=["CVE-2022-0543", "CWE-306"],
                    evidence=ev,
                    cvss_v31_vector=CVSS_BRUTE,
                    cvss_v40_vector=CVSS40_BRUTE,
                    mitre_attack=["TA0006/T1110"],
                    target=host,
                    port=port,
                    service="redis",
                    operator_confirmed=True,
                )
        except Exception:
            pass

    async def _brute_ftp(self, host: str, port: int) -> None:
        """Test FTP anonymous access."""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=5
            )
            banner = await asyncio.wait_for(reader.read(256), timeout=3)
            writer.write(b"USER anonymous\r\n")
            await writer.drain()
            resp = await asyncio.wait_for(reader.read(256), timeout=3)
            if b"331" in resp or b"230" in resp:
                writer.write(b"PASS anonymous@test.com\r\n")
                await writer.drain()
                resp2 = await asyncio.wait_for(reader.read(256), timeout=3)
                if b"230" in resp2:
                    ev = Evidence(
                        extra={"host": host, "port": port, "user": "anonymous"}
                    )
                    self.new_finding(
                        title=f"FTP Anonymous Login ({host}:{port})",
                        severity=Severity.HIGH,
                        description=(
                            f"FTP server {host}:{port} allows anonymous login. "
                            "An attacker can browse and potentially download/upload files."
                        ),
                        reproduction_steps=[f"ftp {host} {port}", "Username: anonymous"],
                        remediation="Disable anonymous FTP. Use SFTP instead.",
                        references=["CWE-306"],
                        evidence=ev,
                        cvss_v31_vector=CVSS_BRUTE,
                        cvss_v40_vector=CVSS40_BRUTE,
                        target=host,
                        port=port,
                        service="ftp",
                        operator_confirmed=True,
                    )
            writer.close()
        except Exception:
            pass

    async def _brute_mongodb(self, host: str, port: int) -> None:
        """Check MongoDB for unauthenticated access."""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=3
            )
            # Send isMaster command
            msg = (
                b"\x40\x00\x00\x00"  # message length
                b"\x00\x00\x00\x00"  # requestID
                b"\x00\x00\x00\x00"  # responseTo
                b"\xd4\x07\x00\x00"  # opCode OP_QUERY
                b"\x00\x00\x00\x00"  # flags
                b"admin.$cmd\x00"    # collection
                b"\x00\x00\x00\x00"  # numberToSkip
                b"\x01\x00\x00\x00"  # numberToReturn
                b"\x13\x00\x00\x00\x10isMaster\x00\x01\x00\x00\x00\x00"  # doc
            )
            writer.write(msg)
            await writer.drain()
            response = await asyncio.wait_for(reader.read(512), timeout=3)
            writer.close()

            if b"ismaster" in response.lower() or b"isWritablePrimary" in response:
                ev = Evidence(extra={"host": host, "port": port})
                self.new_finding(
                    title=f"MongoDB Accessible Without Authentication ({host}:{port})",
                    severity=Severity.CRITICAL,
                    description=(
                        f"MongoDB on {host}:{port} responds to unauthenticated queries. "
                        "May allow full database access."
                    ),
                    reproduction_steps=[
                        f"mongosh {host}:{port}",
                        "db.adminCommand({listDatabases: 1})",
                    ],
                    remediation="Enable MongoDB authentication. Bind to localhost or VPN.",
                    references=["CWE-306"],
                    evidence=ev,
                    cvss_v31_vector=CVSS_BRUTE,
                    cvss_v40_vector=CVSS40_BRUTE,
                    target=host,
                    port=port,
                    service="mongodb",
                    operator_confirmed=True,
                )
        except Exception:
            pass

    async def _brute_db(self, host: str, port: int, service: str) -> None:
        """Test database for empty/default passwords."""
        for username in ["root", "admin", service, "postgres", "sa"]:
            await self.rate_limit()
            try:
                if service == "mysql":
                    success = await self._try_mysql(host, port, username, "")
                elif service == "postgres":
                    success = await self._try_postgres(host, port, username, "")
                else:
                    success = False

                if success:
                    ev = Evidence(
                        extra={"host": host, "port": port, "service": service, "user": username}
                    )
                    self.new_finding(
                        title=f"{service.upper()} Empty Password — {username}@{host}:{port}",
                        severity=Severity.CRITICAL,
                        description=(
                            f"{service.upper()} login successful as '{username}' with empty password on "
                            f"{host}:{port}."
                        ),
                        reproduction_steps=[f"{service} -h {host} -P {port} -u {username}"],
                        remediation="Set strong password for all database accounts.",
                        references=["CWE-521"],
                        evidence=ev,
                        cvss_v31_vector=CVSS_BRUTE,
                        cvss_v40_vector=CVSS40_BRUTE,
                        target=host,
                        port=port,
                        service=service,
                        operator_confirmed=True,
                    )
                    break
            except Exception:
                pass

    async def _try_mysql(self, host: str, port: int, user: str, password: str) -> bool:
        try:
            loop = asyncio.get_event_loop()
            def _connect():
                import pymysql
                conn = pymysql.connect(host=host, port=port, user=user,
                                       password=password, connect_timeout=5)
                conn.close()
                return True
            return await loop.run_in_executor(None, _connect)
        except Exception:
            return False

    async def _try_postgres(self, host: str, port: int, user: str, password: str) -> bool:
        try:
            loop = asyncio.get_event_loop()
            def _connect():
                import psycopg2
                conn = psycopg2.connect(host=host, port=port, user=user,
                                        password=password, connect_timeout=5, dbname="postgres")
                conn.close()
                return True
            return await loop.run_in_executor(None, _connect)
        except Exception:
            return False


class TestSmartBrute:
    def test_service_map(self) -> None:
        assert SERVICE_BRUTE_MAP.get(22) == "ssh"
        assert SERVICE_BRUTE_MAP.get(6379) == "redis"
        assert SERVICE_BRUTE_MAP.get(27017) == "mongodb"
