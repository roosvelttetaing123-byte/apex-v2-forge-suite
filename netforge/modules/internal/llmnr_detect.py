"""LLMNR/NBT-NS detection — detect poisonable link-local name resolution."""
from __future__ import annotations

import asyncio
import socket
import struct
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity

CVSS_LLMNR = "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
CVSS40_LLMNR = "CVSS:4.0/AV:A/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N"
LLMNR_PORT = 5355
LLMNR_MCAST = "224.0.0.252"

NBTNS_PORT = 137
NBTNS_BCAST = "255.255.255.255"


class LlmnrDetect(BaseModule):
    """LLMNR and NBT-NS poisoning detection."""

    NAME        = "llmnr_detect"
    DESCRIPTION = "Detect LLMNR/NBT-NS protocols active on network — credential theft risk"
    PHASE       = 4
    TAGS        = ["internal", "llmnr", "nbns", "mitm", "cwe-923"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        target = self.config.target

        await asyncio.gather(
            self._check_llmnr(target),
            self._check_nbtns(target),
            self._check_nmap_llmnr(target),
        )
        return self._make_result(start)

    async def _check_llmnr(self, target: str) -> None:
        """Send an LLMNR query and listen for a response."""
        try:
            # Build LLMNR query for a non-existent name
            query_name = "FORGETEST_LLMNR_PROBE"
            query = self._build_llmnr_query(query_name)

            loop = asyncio.get_event_loop()
            response = await loop.run_in_executor(None, self._send_llmnr, query, target)

            if response:
                ev = Evidence(
                    extra={
                        "target":    target,
                        "response":  response.hex()[:40],
                        "protocol":  "LLMNR (UDP 5355)",
                    }
                )
                self.new_finding(
                    title=f"LLMNR Active on Network — {target}",
                    severity=Severity.HIGH,
                    description=(
                        f"LLMNR (Link-Local Multicast Name Resolution) is active on {target}. "
                        "LLMNR is vulnerable to poisoning attacks. An attacker can intercept "
                        "LLMNR queries and respond with their IP, causing authentication attempts "
                        "(NTLMv2 hashes) to be sent to the attacker. "
                        "Tools: Responder, Inveigh."
                    ),
                    reproduction_steps=[
                        "sudo responder -I eth0 -wrf",
                        "Or: sudo python3 Inveigh.py",
                        "Wait for LLMNR queries and captured NTLMv2 hashes",
                    ],
                    remediation=(
                        "Disable LLMNR via Group Policy: "
                        "Computer Configuration > Administrative Templates > Network > "
                        "DNS Client > Turn off multicast name resolution = Enabled\n"
                        "Registry: HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient\\EnableMulticast = 0"
                    ),
                    references=["CVE-2017-9951", "MITRE T1557.001", "CWE-923"],
                    evidence=ev,
                    cvss_v31_vector=CVSS_LLMNR,
                    cvss_v40_vector=CVSS40_LLMNR,
                    mitre_attack=["TA0006/T1557.001"],
                    target=target,
                )
        except Exception as exc:
            self.log.debug("LLMNR check failed: %s", exc)

    async def _check_nbtns(self, target: str) -> None:
        """Check if NBT-NS (NetBIOS Name Service) is responding."""
        try:
            loop = asyncio.get_event_loop()
            response = await loop.run_in_executor(None, self._send_nbtns, target)

            if response:
                ev = Evidence(
                    extra={
                        "target":   target,
                        "protocol": "NBT-NS (UDP 137)",
                    }
                )
                self.new_finding(
                    title=f"NBT-NS Active — {target}",
                    severity=Severity.MEDIUM,
                    description=(
                        f"NBT-NS (NetBIOS Name Service) is active on {target} port 137. "
                        "Similar to LLMNR, NBT-NS is vulnerable to poisoning attacks. "
                        "Responder can capture NTLMv2 hashes from NBT-NS queries."
                    ),
                    reproduction_steps=[
                        "sudo responder -I eth0",
                        "NBT-NS queries will be captured",
                    ],
                    remediation=(
                        "Disable NetBIOS over TCP/IP: "
                        "Network adapter settings > TCP/IP > Advanced > WINS > "
                        "Disable NetBIOS over TCP/IP"
                    ),
                    references=["MITRE T1557.001"],
                    evidence=ev,
                    cvss_v31_vector=CVSS_LLMNR,
                    cvss_v40_vector=CVSS40_LLMNR,
                    mitre_attack=["TA0006/T1557.001"],
                    target=target,
                )
        except Exception:
            pass

    async def _check_nmap_llmnr(self, target: str) -> None:
        """Use nmap to detect LLMNR if available."""
        import shutil
        nmap = shutil.which("nmap")
        if not nmap:
            return
        try:
            proc = await asyncio.create_subprocess_exec(
                nmap, "-sU", "-p", str(LLMNR_PORT), "--open", "-n", target,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=20)
            output = stdout.decode()
            if "open" in output and str(LLMNR_PORT) in output:
                ev = Evidence(
                    extra={"nmap_output": output[:500], "target": target}
                )
                self.new_finding(
                    title=f"LLMNR Port Open (UDP 5355) — {target}",
                    severity=Severity.HIGH,
                    description=f"LLMNR port 5355/udp is open on {target} (nmap scan).",
                    reproduction_steps=[f"nmap -sU -p 5355 {target}"],
                    remediation="Disable LLMNR via Group Policy (see remediation above).",
                    references=["MITRE T1557.001"],
                    evidence=ev,
                    cvss_v31_vector=CVSS_LLMNR,
                    cvss_v40_vector=CVSS40_LLMNR,
                    target=target,
                )
        except Exception:
            pass

    def _build_llmnr_query(self, name: str) -> bytes:
        """Build a simple LLMNR query packet."""
        transaction_id = b"\x00\x01"
        flags = b"\x00\x00"
        questions = b"\x00\x01"
        answer_rrs = b"\x00\x00"
        authority_rrs = b"\x00\x00"
        additional_rrs = b"\x00\x00"
        # Encode name
        encoded_name = b""
        for label in name.split("."):
            encoded_name += bytes([len(label)]) + label.encode()
        encoded_name += b"\x00"
        qtype = b"\x00\x01"  # A record
        qclass = b"\x00\x01"  # IN
        return (transaction_id + flags + questions + answer_rrs +
                authority_rrs + additional_rrs + encoded_name + qtype + qclass)

    def _send_llmnr(self, query: bytes, target: str) -> bytes | None:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(2.0)
            sock.sendto(query, (LLMNR_MCAST, LLMNR_PORT))
            data, _ = sock.recvfrom(512)
            sock.close()
            return data if data else None
        except Exception:
            return None

    def _send_nbtns(self, target: str) -> bytes | None:
        try:
            # NBT-NS name query for SAMBA
            query = (
                b"\x00\x01"  # TxID
                b"\x01\x10"  # Flags: query, recursion desired
                b"\x00\x01"  # Questions
                b"\x00\x00\x00\x00\x00\x00"
                b"\x20"      # Name length
                b"CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                b"\x00"
                b"\x00\x20"  # Type: NB
                b"\x00\x01"  # Class: IN
            )
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(2.0)
            sock.sendto(query, (target, NBTNS_PORT))
            data, _ = sock.recvfrom(512)
            sock.close()
            return data
        except Exception:
            return None


class TestLlmnrDetect:
    def test_build_llmnr_query(self) -> None:
        mod = LlmnrDetect.__new__(LlmnrDetect)
        query = mod._build_llmnr_query("TESTHOST")
        assert len(query) > 10
        assert b"\x00\x01" in query  # A record type

    def test_cvss_vector(self) -> None:
        assert CVSS_LLMNR.startswith("CVSS:3.1")
