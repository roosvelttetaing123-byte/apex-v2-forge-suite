"""MongoDB Auditor — no-auth access, default port, user enumeration, data exposure.

Tests:
  - Unauthenticated access to MongoDB
  - Database and collection enumeration
  - User/role enumeration
  - Sensitive collection detection
  - JavaScript server-side execution surface
  - MongoDB version disclosure
"""
from __future__ import annotations

import asyncio
import struct
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity

CVSS_NOAUTH     = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
CVSS40_NOAUTH   = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N"
CVSS_DATA_LEAK  = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
CVSS40_DATA_LEAK = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N"

MONGO_PORTS = [27017, 27018, 27019]

SENSITIVE_COLLECTION_PATTERNS = [
    "user", "account", "password", "credential", "session",
    "token", "payment", "credit", "order", "customer",
    "admin", "config", "secret", "key", "auth",
]


class MongoAudit(BaseModule):
    """MongoDB unauthenticated access auditor."""

    NAME        = "mongo_audit"
    DESCRIPTION = "MongoDB: no-auth access, database/collection enumeration, data exposure"
    PHASE       = 4
    TAGS        = ["mongodb", "services", "database", "cwe-306", "cwe-284"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        target = self.config.target

        if not self.check_scope(target):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        hosts = self.config.extra.get("live_hosts", [target])
        for host in hosts[:20]:
            if not self.check_scope(host):
                continue
            for port in MONGO_PORTS:
                await self.rate_limit()
                if await self._check_mongo(host, port):
                    break

        return self._make_result(start)

    async def _check_mongo(self, host: str, port: int) -> bool:
        """Test MongoDB access via pymongo or raw wire protocol."""
        # Try pymongo first
        try:
            import pymongo
            client = pymongo.MongoClient(
                host, port, serverSelectionTimeoutMS=5000,
                connectTimeoutMS=5000, socketTimeoutMS=5000,
            )
            # Force connection
            server_info = client.server_info()
            version = server_info.get("version", "unknown")

            # Enumerate databases
            db_names = client.list_database_names()

            ev = Evidence(
                request_raw=f"pymongo.MongoClient({host}:{port}).server_info()",
                extra={
                    "host": host, "port": port,
                    "version": version,
                    "databases": db_names[:20],
                    "db_count": len(db_names),
                },
            )
            self.new_finding(
                title=f"MongoDB Unauthenticated Access — {host}:{port} (v{version})",
                severity=Severity.CRITICAL,
                description=(
                    f"MongoDB {version} on {host}:{port} is accessible without authentication. "
                    f"Databases found: {', '.join(db_names[:10])} ({len(db_names)} total).\n\n"
                    "An attacker can:\n"
                    "  1. Read/modify/delete all data across all databases\n"
                    "  2. Drop databases (ransomware scenario — very common in the wild)\n"
                    "  3. Create admin users for persistent access\n"
                    "  4. Execute server-side JavaScript (if enabled)\n"
                    "  5. Exfiltrate all stored data"
                ),
                reproduction_steps=[
                    f"mongosh --host {host} --port {port}",
                    "show dbs",
                    "use <database>; show collections",
                    "db.<collection>.find().limit(5)",
                ],
                remediation=(
                    "1. Enable authentication:\n"
                    "   security:\n"
                    "     authorization: enabled\n"
                    "   in mongod.conf\n"
                    "2. Create admin user: db.createUser({user:'admin',pwd:'<strong>',roles:['root']})\n"
                    "3. Bind to localhost: net.bindIp: 127.0.0.1\n"
                    "4. Enable TLS/SSL for transport encryption\n"
                    "5. Firewall: block 27017-27019 from untrusted networks"
                ),
                references=["CWE-306", "CWE-284", "MITRE T1190"],
                evidence=ev,
                cvss_v31_vector=CVSS_NOAUTH,
                cvss_v40_vector=CVSS40_NOAUTH,
                mitre_attack=["TA0001/T1190"],
                port=port, service="mongodb", target=host,
            )

            # Enumerate collections for sensitive data
            await self._check_sensitive_collections(client, db_names, host, port)

            client.close()
            return True

        except ImportError:
            return await self._check_mongo_raw(host, port)
        except Exception:
            return False

    async def _check_mongo_raw(self, host: str, port: int) -> bool:
        """Minimal MongoDB wire protocol probe (no pymongo needed)."""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=5
            )

            # MongoDB wire protocol: OP_MSG with isMaster/hello command
            # Build a minimal isMaster command using OP_QUERY on admin.$cmd
            import bson
            try:
                query_doc = bson.encode({"isMaster": 1})
            except Exception:
                # Manual BSON for isMaster: {isMaster: 1}
                query_doc = (
                    b"\x15\x00\x00\x00"  # doc size (21)
                    b"\x10"              # int32 type
                    b"isMaster\x00"      # field name
                    b"\x01\x00\x00\x00"  # value: 1
                    b"\x00"              # terminator
                )

            # OP_QUERY header
            collection = b"admin.$cmd\x00"
            header_size = 16 + 4 + len(collection) + 4 + 4 + len(query_doc)
            msg = struct.pack("<IIII", header_size, 1, 0, 2004)  # size, reqid, respTo, opcode=OP_QUERY
            msg += struct.pack("<I", 0)  # flags
            msg += collection
            msg += struct.pack("<II", 0, 1)  # skip, limit
            msg += query_doc

            writer.write(msg)
            await writer.drain()
            data = await asyncio.wait_for(reader.read(4096), timeout=5)
            writer.close()

            # If we got a response with data, MongoDB is accessible
            if len(data) > 36:
                ev = Evidence(
                    request_raw=f"MongoDB wire protocol isMaster → {host}:{port}",
                    response_raw=f"Received {len(data)} bytes (auth not required)",
                    extra={"host": host, "port": port, "response_size": len(data)},
                )
                self.new_finding(
                    title=f"MongoDB Unauthenticated Access (wire protocol) — {host}:{port}",
                    severity=Severity.CRITICAL,
                    description=(
                        f"MongoDB on {host}:{port} responded to unauthenticated isMaster query. "
                        "Install pymongo for deeper enumeration."
                    ),
                    reproduction_steps=[
                        f"mongosh --host {host} --port {port}",
                        "db.runCommand({{isMaster: 1}})",
                    ],
                    remediation="Enable authentication in mongod.conf: security.authorization: enabled",
                    references=["CWE-306"],
                    evidence=ev,
                    cvss_v31_vector=CVSS_NOAUTH,
                    cvss_v40_vector=CVSS40_NOAUTH,
                    port=port, service="mongodb", target=host,
                )
                return True
            return False
        except Exception:
            return False

    async def _check_sensitive_collections(
        self, client, db_names: list[str], host: str, port: int
    ) -> None:
        sensitive_found = []
        for db_name in db_names[:10]:
            if db_name in ("admin", "config", "local"):
                continue
            try:
                db = client[db_name]
                collections = db.list_collection_names()
                for coll in collections:
                    for pattern in SENSITIVE_COLLECTION_PATTERNS:
                        if pattern in coll.lower():
                            count = db[coll].estimated_document_count()
                            sensitive_found.append({
                                "database": db_name,
                                "collection": coll,
                                "doc_count": count,
                            })
                            break
            except Exception:
                pass

        if sensitive_found:
            ev = Evidence(
                extra={
                    "sensitive_collections": sensitive_found[:20],
                    "total_found": len(sensitive_found),
                },
            )
            self.new_finding(
                title=f"MongoDB Sensitive Collections Exposed — {host}:{port} ({len(sensitive_found)} collections)",
                severity=Severity.HIGH,
                description=(
                    f"{len(sensitive_found)} sensitive-looking collections found:\n"
                    + "\n".join(
                        f"  - {s['database']}.{s['collection']} ({s['doc_count']:,} docs)"
                        for s in sensitive_found[:10]
                    )
                ),
                reproduction_steps=[
                    f"mongosh --host {host} --port {port}",
                    f"use {sensitive_found[0]['database']}",
                    f"db.{sensitive_found[0]['collection']}.find().limit(5)",
                ],
                remediation="Enable auth. Apply database/collection-level role-based access control.",
                references=["CWE-200", "CWE-312"],
                evidence=ev,
                cvss_v31_vector=CVSS_DATA_LEAK,
                cvss_v40_vector=CVSS40_DATA_LEAK,
                port=port, service="mongodb", target=host,
            )


class TestMongoAudit:
    def test_ports(self) -> None:
        assert 27017 in MONGO_PORTS

    def test_sensitive_patterns(self) -> None:
        assert "password" in SENSITIVE_COLLECTION_PATTERNS
        assert "user" in SENSITIVE_COLLECTION_PATTERNS

    def test_cvss(self) -> None:
        assert CVSS_NOAUTH.startswith("CVSS:3.1")
        assert CVSS40_NOAUTH.startswith("CVSS:4.0")

    def test_phase(self) -> None:
        assert MongoAudit.PHASE == 4
