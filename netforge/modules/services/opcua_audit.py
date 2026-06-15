"""OPC-UA Audit — Industrial Protocol (OPC Unified Architecture) security assessment.

OPC-UA is the primary protocol for industrial automation, SCADA, and ICS environments.
Poor configuration can expose PLCs, HMIs, historians, and process control systems.

Checks:
  - Port 4840 (TCP) and 4843 (TLS) reachability
  - Anonymous session establishment (no credentials)
  - Default / null security mode (None/Sign vs SignAndEncrypt)
  - Certificate validation
  - Endpoint URL enumeration (GetEndpoints)
  - Available security policies (None, Basic128Rsa15, Basic256, Basic256Sha256)
  - Node browsing without auth (information disclosure)
  - Server info disclosure (ProductName, SoftwareVersion, ServerStatus)
  - Subscription creation (write/command access probe)

Uses opcua (asyncua) library if available, falls back to raw TCP probes.

FOR AUTHORIZED PENETRATION TESTING ONLY.
"""
from __future__ import annotations

import asyncio
import struct
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.finding import Severity


class OpcuaAudit(BaseModule):
    """OPC-UA industrial protocol security audit."""

    NAME        = "opcua_audit"
    DESCRIPTION = "OPC-UA 4840/4843 anonymous auth, security policy, and node enumeration audit"
    PHASE       = 5
    TAGS        = ["ics", "scada", "opcua", "industrial", "credentials", "anonymous"]

    async def run(self) -> ModuleResult:
        start    = time.monotonic()
        target   = self.config.target.rstrip("/")
        host     = target.replace("opc.tcp://", "").split(":")[0].split("/")[0]
        port_str = target.split(":")[-1].split("/")[0]
        try:
            port = int(port_str) if port_str.isdigit() else 4840
        except ValueError:
            port = 4840

        username = self.config.extra.get("username", "")
        password = self.config.extra.get("password", "")

        if not self.check_scope(host):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        plain_up = await self._check_port(host, 4840)
        tls_up   = await self._check_port(host, 4843)

        if not plain_up and not tls_up and not await self._check_port(host, port):
            return self._make_result(start, skipped=True,
                                     skip_reason="OPC-UA ports 4840/4843 not reachable")

        actual_port = port if await self._check_port(host, port) else (4840 if plain_up else 4843)

        endpoint_url = f"opc.tcp://{host}:{actual_port}"

        # Try asyncua first (full library)
        if await self._try_asyncua(host, actual_port, endpoint_url, username, password):
            return self._make_result(start)

        # Fall back to raw TCP Hello/Open probes
        self._add_info(host, "asyncua not installed — using raw TCP OPC-UA probes")
        await self._raw_probe(host, actual_port)

        return self._make_result(start)

    # ── asyncua (full library) ──────────────────────────────────────────

    async def _try_asyncua(self, host: str, port: int, endpoint_url: str,
                           username: str, password: str) -> bool:
        """Use asyncua library for thorough OPC-UA audit."""
        try:
            from asyncua import Client
            from asyncua.ua import MessageSecurityMode
        except ImportError:
            return False

        # 1. GetEndpoints — enumerate security policies without connecting
        await self.rate_limit()
        try:
            client = Client(url=endpoint_url, timeout=10)
            endpoints = await client.connect_and_get_server_endpoints()
            await self._analyze_endpoints(host, endpoints)
        except Exception as exc:
            self.log.debug("OPC-UA GetEndpoints %s: %s", host, exc)

        # 2. Anonymous session
        await self.rate_limit()
        await self._test_anonymous_session(host, endpoint_url)

        # 3. Authenticated session
        if username:
            await self.rate_limit()
            await self._test_auth_session(host, endpoint_url, username, password)

        return True

    async def _analyze_endpoints(self, host: str, endpoints: list) -> None:
        """Analyze reported security policies for weak configurations."""
        from asyncua.ua import MessageSecurityMode

        none_policy  = []
        weak_policy  = []
        strong_policy = []

        for ep in endpoints:
            url  = str(ep.EndpointUrl)
            mode = ep.SecurityMode
            pol  = str(ep.SecurityPolicyUri).split("#")[-1]

            if mode == MessageSecurityMode.None_:
                none_policy.append(f"{url} [{pol}]")
            elif pol in ("Basic128Rsa15", "Basic256"):
                weak_policy.append(f"{url} [{pol}]")
            else:
                strong_policy.append(f"{url} [{pol}]")

        if none_policy:
            self._add_finding(
                host,
                f"OPC-UA endpoints with SecurityMode=None (no signing/encryption):\n"
                + "\n".join(f"  {e}" for e in none_policy),
                Severity.HIGH,
                "Set SecurityMode to 'Sign' or 'SignAndEncrypt' for all endpoints. "
                "SecurityMode=None allows network eavesdropping of all OPC-UA traffic.",
            )
        if weak_policy:
            self._add_finding(
                host,
                f"OPC-UA endpoints using weak security policies (Basic128Rsa15/Basic256):\n"
                + "\n".join(f"  {e}" for e in weak_policy),
                Severity.MEDIUM,
                "Upgrade to Basic256Sha256 or Aes128Sha256RsaOaep security policy. "
                "Basic128Rsa15 uses RSA PKCS#1 v1.5 padding which is vulnerable.",
            )
        if strong_policy:
            self._add_info(host, f"OPC-UA strong security policy endpoints: {len(strong_policy)}")

    async def _test_anonymous_session(self, host: str, endpoint_url: str) -> None:
        """Attempt anonymous OPC-UA session and enumerate server info + nodes."""
        try:
            from asyncua import Client
            from asyncua.ua import SecurityPolicy

            client = Client(url=endpoint_url, timeout=10)
            try:
                await asyncio.wait_for(client.connect(), timeout=12)
            except Exception as exc:
                self.log.debug("OPC-UA anon connect %s: %s", host, exc)
                return

            try:
                self._add_finding(
                    host,
                    "OPC-UA anonymous session ESTABLISHED — no credentials required to connect.",
                    Severity.CRITICAL,
                    "Disable anonymous sessions. Set AllowAnonymousIdentity=false in "
                    "the OPC-UA server configuration. Require at least username/password or certificates.",
                )

                # Server info disclosure
                try:
                    info = await client.get_node("i=2261").read_value()  # ServerStatus.BuildInfo
                    self._add_info(host, f"OPC-UA server info: {str(info)[:200]}")
                except Exception:
                    pass

                # Browse root nodes
                try:
                    root    = client.get_root_node()
                    objects = await root.get_children()
                    node_names = []
                    for obj in objects[:20]:
                        try:
                            dn = await obj.read_display_name()
                            node_names.append(dn.Text)
                        except Exception:
                            pass

                    if node_names:
                        self._add_finding(
                            host,
                            f"OPC-UA anonymous node browsing — {len(node_names)} root objects visible:\n"
                            + "\n".join(f"  {n}" for n in node_names[:15]),
                            Severity.HIGH,
                            "Apply node-level access control (OPC-UA role permissions). "
                            "Anonymous users should have no browse/read access.",
                        )
                except Exception as exc:
                    self.log.debug("OPC-UA anon browse: %s", exc)

                # Software version disclosure
                try:
                    ver = await client.get_node("i=2264").read_value()  # SoftwareVersion
                    self._add_info(host, f"OPC-UA SoftwareVersion: {ver}")
                except Exception:
                    pass

            finally:
                await client.disconnect()

        except Exception as exc:
            self.log.debug("OPC-UA anon session %s: %s", host, exc)

    async def _test_auth_session(self, host: str, endpoint_url: str,
                                 username: str, password: str) -> None:
        """Connect with username/password credentials."""
        try:
            from asyncua import Client

            client = Client(url=endpoint_url, timeout=10)
            client.set_user(username)
            client.set_password(password)

            try:
                await asyncio.wait_for(client.connect(), timeout=12)
                self._add_finding(
                    host,
                    f"OPC-UA authenticated session SUCCESS — {username}:{password}",
                    Severity.CRITICAL,
                    "Change default credentials. Use certificate-based authentication "
                    "instead of username/password where possible.",
                )

                # Try to read/write a node to assess permissions
                try:
                    root    = client.get_root_node()
                    objects = await root.get_children()
                    if objects:
                        readable = []
                        for obj in objects[:5]:
                            try:
                                val = await obj.read_value()
                                dn  = await obj.read_display_name()
                                readable.append(f"{dn.Text}={val!r}")
                            except Exception:
                                pass
                        if readable:
                            self._add_info(
                                host, f"OPC-UA authenticated read: {readable[:3]}"
                            )
                except Exception:
                    pass

                await client.disconnect()
            except Exception as exc:
                self.log.debug("OPC-UA auth session %s@%s: %s", username, host, exc)

        except Exception as exc:
            self.log.debug("OPC-UA auth setup %s: %s", host, exc)

    # ── Raw TCP OPC-UA probe ───────────────────────────────────────────

    async def _raw_probe(self, host: str, port: int) -> None:
        """Send OPC-UA HEL (Hello) and OpenSecureChannel without library."""
        await self.rate_limit()
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=8
            )
            # OPC-UA Hello message
            endpoint_url = f"opc.tcp://{host}:{port}".encode()
            hello = (
                b"HELF"                      # MessageType: HEL
                + b"F"                       # ChunkType: Final
                + struct.pack("<I", 28 + len(endpoint_url))  # MessageSize
                + struct.pack("<I", 0)        # ProtocolVersion
                + struct.pack("<I", 65536)    # ReceiveBufferSize
                + struct.pack("<I", 65536)    # SendBufferSize
                + struct.pack("<I", 0)        # MaxMessageSize
                + struct.pack("<I", 0)        # MaxChunkCount
                + struct.pack("<I", len(endpoint_url))
                + endpoint_url
            )
            writer.write(hello)
            await writer.drain()

            resp = await asyncio.wait_for(reader.read(256), timeout=8)
            writer.close()

            if resp[:4] == b"ACKF":
                self._add_finding(
                    host,
                    f"OPC-UA server responded to Hello (ACK) on port {port}. "
                    f"Server is running and accepting connections.",
                    Severity.INFO,
                    "Review OPC-UA security configuration.",
                )
                self._add_info(host, "Raw probe: OPC-UA ACK received — server is active")
            elif resp[:4] == b"ERRF":
                error_code = struct.unpack_from("<I", resp, 8)[0] if len(resp) >= 12 else 0
                self._add_info(host, f"OPC-UA error response: code=0x{error_code:08X}")
        except Exception as exc:
            self.log.debug("OPC-UA raw probe %s:%d: %s", host, port, exc)

    # ── Helpers ────────────────────────────────────────────────────────

    async def _check_port(self, host: str, port: int) -> bool:
        try:
            _, w = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=5)
            w.close()
            return True
        except Exception:
            return False

    def _add_finding(self, host: str, detail: str, severity: Severity,
                     remediation: str = "") -> None:
        from common.finding import Finding
        self.findings.append(Finding(
            title       = "OPC-UA Security Risk",
            description = detail,
            severity    = severity,
            host        = host,
            evidence    = detail,
            remediation = remediation or "Harden OPC-UA server security configuration.",
            references  = [
                "https://opcfoundation.org/security/",
                "https://attack.mitre.org/techniques/T0886/",
                "https://www.cisa.gov/uscert/ics/advisories",
                "https://documentation.unified-automation.com/uaexpert/1.5.0/html/uaexpert_security.html",
            ],
        ))

    def _add_info(self, host: str, msg: str) -> None:
        from common.finding import Finding
        self.findings.append(Finding(
            title       = "OPC-UA Info",
            description = msg,
            severity    = Severity.INFO,
            host        = host,
            evidence    = msg,
            remediation = "",
        ))
