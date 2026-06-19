"""Password quality auditor — analyze harvested password lists for weak patterns."""
from __future__ import annotations

import math
import re
import sys
import time
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity

CVSS_PASSWORD_QUALITY = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
CVSS40_PASSWORD_QUALITY = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N"
_COMMON_PATTERNS = [
    re.compile(r"^[a-zA-Z]+\d{1,4}$"),
    re.compile(r"^[A-Z][a-z]+\d{1,4}$"),
    re.compile(r"^\d+$"),
    re.compile(r"^(.)\1{3,}$"),
    re.compile(r"^(password|pass|admin|user|login|qwerty|abc|welcome)", re.I),
]


def _entropy(pw: str) -> float:
    if not pw:
        return 0.0
    charset = 0
    if re.search(r"[a-z]", pw):     charset += 26
    if re.search(r"[A-Z]", pw):     charset += 26
    if re.search(r"\d", pw):        charset += 10
    if re.search(r"[^a-zA-Z\d]", pw): charset += 32
    return len(pw) * math.log2(max(charset, 1))


def _is_weak_pattern(pw: str) -> bool:
    return any(p.search(pw) for p in _COMMON_PATTERNS)


def audit_password_file(path: Path) -> dict:
    passwords = [line.strip() for line in path.read_text(errors="ignore").splitlines() if line.strip()]
    total = len(passwords)
    if not total:
        return {}

    lengths = [len(p) for p in passwords]
    entropies = [_entropy(p) for p in passwords]
    weak_pattern_count = sum(1 for p in passwords if _is_weak_pattern(p))
    short_count = sum(1 for p in passwords if len(p) < 8)
    low_entropy = sum(1 for e in entropies if e < 30)
    top10 = Counter(passwords).most_common(10)
    avg_len = sum(lengths) / total
    avg_entropy = sum(entropies) / total
    length_dist = Counter(min(l, 20) for l in lengths)

    return {
        "total": total,
        "avg_length": round(avg_len, 1),
        "avg_entropy_bits": round(avg_entropy, 1),
        "short_passwords_pct": round(short_count / total * 100, 1),
        "weak_pattern_pct": round(weak_pattern_count / total * 100, 1),
        "low_entropy_pct": round(low_entropy / total * 100, 1),
        "top_10_passwords": [{"password": p, "count": c} for p, c in top10],
        "length_distribution": dict(sorted(length_dist.items())),
    }


class PasswordQuality(BaseModule):
    NAME        = "password_quality"
    DESCRIPTION = "Audit harvested passwords for entropy, patterns, and length"
    PHASE       = 7
    TAGS        = ["bruteforce", "password", "quality"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        pw_file = Path(self.config.extra.get("password_file", ""))
        if not pw_file.exists():
            return self._make_result(start, skipped=True, skip_reason="no password_file provided")

        stats = audit_password_file(pw_file)
        if not stats:
            return self._make_result(start, skipped=True, skip_reason="empty password file")

        sev = Severity.HIGH if stats["weak_pattern_pct"] > 30 else Severity.MEDIUM
        self.new_finding(
            title=f"Weak Password Quality Detected ({stats['weak_pattern_pct']}% weak patterns)",
            severity=sev,
            description=(
                f"Analysis of {stats['total']} passwords from {pw_file.name}: "
                f"avg length {stats['avg_length']} chars, avg entropy {stats['avg_entropy_bits']} bits. "
                f"{stats['short_passwords_pct']}% under 8 chars, {stats['weak_pattern_pct']}% match weak patterns."
            ),
            reproduction_steps=[
                f"Obtain password list (breach, NTDS dump): {pw_file}",
                "Analyze with: python3 -c \"from netforge.modules.bruteforce.password_quality import audit_password_file...\"",
            ],
            remediation=(
                "Enforce minimum 12-char passwords with complexity. "
                "Deploy password blacklisting against known-breached passwords. "
                "Require password manager use. Enable MFA."
            ),
            references=["NIST SP 800-63B", "MITRE T1110"],
            evidence=Evidence(extra=stats),
            cvss_v31_vector=CVSS_PASSWORD_QUALITY,
            cvss_v40_vector=CVSS40_PASSWORD_QUALITY,
            mitre_attack=["TA0006/T1110"],
        )
        return self._make_result(start)
