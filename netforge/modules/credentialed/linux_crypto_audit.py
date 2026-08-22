"""Linux Crypto Audit — TLS/crypto policy, weak SSH host keys, expired certs."""
from __future__ import annotations

import re
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity

CVSS_WEAK_KEY = "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N"
CVSS_EXPIRED  = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N"


class LinuxCryptoAudit(BaseModule):
    NAME        = "linux_crypto_audit"
    DESCRIPTION = "SSH credentialed: crypto policy, weak host keys, expired certificates"
    PHASE       = 5
    TAGS        = ["credentialed", "linux", "crypto", "tls", "cwe-326"]

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
            await self._audit_crypto(host, transport_mgr.ssh, session)

        return self._make_result(start)

    async def _audit_crypto(self, host: str, ssh, session) -> None:
        # Check SSH host key sizes
        key_result = await ssh.execute(session,
            "for f in /etc/ssh/ssh_host_*_key.pub; do ssh-keygen -l -f $f 2>/dev/null; done")

        weak_keys = []
        for line in key_result.stdout.strip().split("\n"):
            parts = line.split()
            if len(parts) >= 4:
                bits = int(parts[0]) if parts[0].isdigit() else 0
                key_type = parts[-1].strip("()")
                if key_type == "RSA" and bits < 2048:
                    weak_keys.append(f"RSA-{bits}")
                elif key_type == "DSA":
                    weak_keys.append(f"DSA-{bits} (deprecated)")
                elif key_type == "ECDSA" and bits < 256:
                    weak_keys.append(f"ECDSA-{bits}")

        if weak_keys:
            self.new_finding(
                title=f"Weak SSH Host Keys — {host}",
                severity=Severity.HIGH,
                description=f"Weak SSH host keys on {host}: {', '.join(weak_keys)}.",
                reproduction_steps=[f"ssh {host}", "for f in /etc/ssh/ssh_host_*_key.pub; do ssh-keygen -l -f $f; done"],
                remediation="Regenerate host keys: ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key -N ''",
                references=["CWE-326"],
                evidence=Evidence(extra={"host": host, "weak_keys": weak_keys}),
                cvss_v31_vector=CVSS_WEAK_KEY,
                target=host, service="ssh", confidence="HIGH",
            )

        # Check for expired/self-signed certs
        cert_result = await ssh.execute(session,
            "find /etc/ssl /etc/pki -name '*.pem' -o -name '*.crt' 2>/dev/null | "
            "head -20 | while read f; do "
            "echo \"==$f==\"; openssl x509 -in $f -noout -dates -issuer 2>/dev/null; done")

        expired = []
        self_signed = []
        for block in cert_result.stdout.split("=="):
            block = block.strip()
            if not block:
                continue
            lines = block.split("\n")
            cert_file = lines[0].replace("==", "").strip() if lines else ""
            for line in lines:
                if "notAfter" in line:
                    # Simple expired check — compare date
                    try:
                        from datetime import datetime
                        date_str = line.split("=", 1)[1].strip()
                        expiry = datetime.strptime(date_str, "%b %d %H:%M:%S %Y %Z")
                        if expiry < datetime.utcnow():
                            expired.append(cert_file)
                    except Exception:
                        pass
                if "issuer" in line.lower() and "self" in line.lower():
                    self_signed.append(cert_file)

        if expired:
            self.new_finding(
                title=f"Expired SSL Certificates ({len(expired)}) — {host}",
                severity=Severity.MEDIUM,
                description=f"{len(expired)} expired certificates on {host}: {', '.join(expired[:5])}.",
                reproduction_steps=[f"ssh {host}", "openssl x509 -in <cert> -noout -dates"],
                remediation="Renew expired certificates.",
                references=["CWE-298"],
                evidence=Evidence(extra={"host": host, "expired": expired[:20]}),
                cvss_v31_vector=CVSS_EXPIRED,
                target=host, service="ssh",
            )
