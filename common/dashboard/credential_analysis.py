"""Safe credential exposure analysis for dashboard uploads.

Parses operator-supplied files and produces redacted exposure findings,
attack-path simulations, and remediation guidance. This module never
authenticates with supplied credentials and never returns raw secrets.
"""
from __future__ import annotations

import base64
import csv
import hashlib
import io
import json
import re
import zipfile
from dataclasses import dataclass, field
from html import unescape
from pathlib import Path
from typing import Any
from xml.etree import ElementTree

MAX_UPLOAD_BYTES = 8 * 1024 * 1024
MAX_RECORDS = 2000

SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("AWS Access Key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("Google API Key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("GitHub Token", re.compile(r"\bgh[pousr]_[0-9A-Za-z_]{20,}\b")),
    ("Slack Token", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{20,}\b")),
    ("JWT", re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b")),
    ("NTLM Hash", re.compile(r"\b[a-fA-F0-9]{32}\b")),
    ("Private Key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")),
    ("Password Assignment", re.compile(r"(?i)\b(?:pass(?:word)?|pwd|secret|token|api[_ -]?key)\b\s*[:=]\s*([^\s,;]{4,})")),
)

EMAIL_RE = re.compile(r"\b[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}\b", re.IGNORECASE)
DOMAIN_USER_RE = re.compile(r"\b([A-Za-z0-9_.-]+\\[A-Za-z0-9_.-]+)\b")
URL_RE = re.compile(r"\bhttps?://[^\s,;)\]]+", re.IGNORECASE)

ADMIN_WORDS = {
    "admin", "administrator", "root", "domain admin", "enterprise admin",
    "svc-admin", "da-", "breakglass", "privileged",
}
SERVICE_WORDS = {"svc", "service", "app", "jenkins", "sql", "backup", "deploy", "ci", "automation"}
PROD_WORDS = {"prod", "production", "live", "dc", "domain controller", "vpn", "jump", "bastion"}
LOUD_ATTACK_WORDS = {
    "mimikatz", "psexec", "secretsdump", "dcsync", "golden ticket", "silver ticket",
    "pass-the-hash", "pass the hash", "lateral", "privilege escalation", "domain admin",
}


@dataclass
class CredentialExposure:
    kind: str
    account: str = ""
    secret_mask: str = ""
    secret_fingerprint: str = ""
    source: str = ""
    context: str = ""
    indicators: list[str] = field(default_factory=list)
    risk: str = "medium"
    score: int = 40

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "account": self.account,
            "secret_mask": self.secret_mask,
            "secret_fingerprint": self.secret_fingerprint,
            "source": self.source,
            "context": self.context,
            "indicators": self.indicators,
            "risk": self.risk,
            "score": self.score,
        }


def analyze_uploaded_credential_file(
    filename: str,
    content_base64: str,
    profile: str = "defensive",
) -> dict[str, Any]:
    """Decode, parse, and safely analyze an uploaded credential/source file."""
    raw = base64.b64decode(content_base64, validate=True)
    if len(raw) > MAX_UPLOAD_BYTES:
        raise ValueError(f"File too large; max size is {MAX_UPLOAD_BYTES // (1024 * 1024)} MB")

    rows, extraction_notes = extract_records(filename, raw)
    exposures = analyze_records(rows)
    chains = build_simulated_paths(exposures, profile=profile)
    summary = summarize(exposures, rows, filename)
    return {
        "filename": Path(filename).name,
        "profile": profile,
        "summary": summary,
        "exposures": [item.to_dict() for item in exposures[:MAX_RECORDS]],
        "paths": chains,
        "remediation": remediation_plan(exposures),
        "extraction_notes": extraction_notes,
        "safety": {
            "mode": "simulation_only",
            "raw_secrets_returned": False,
            "live_authentication_attempted": False,
            "attack_execution_attempted": False,
        },
    }


def extract_records(filename: str, raw: bytes) -> tuple[list[dict[str, str]], list[str]]:
    suffix = Path(filename).suffix.lower()
    notes: list[str] = []
    try:
        if suffix in {".csv", ".tsv"}:
            return _extract_delimited(raw, delimiter="\t" if suffix == ".tsv" else ","), notes
        if suffix in {".txt", ".md", ".log", ".note", ".notes"}:
            return _extract_text(raw), notes
        if suffix == ".json":
            return _extract_json(raw), notes
        if suffix == ".docx":
            return _extract_docx(raw), notes
        if suffix == ".xlsx":
            return _extract_xlsx(raw), notes
        if suffix in {".doc", ".xls"}:
            notes.append("Legacy binary Office files are scanned as best-effort text only; export to .docx/.xlsx for full structure.")
            return _extract_text(raw), notes
    except zipfile.BadZipFile:
        notes.append("Office container could not be opened; scanned as text fallback.")
    except Exception as exc:
        notes.append(f"Structured parse failed: {exc}; scanned as text fallback.")
    return _extract_text(raw), notes


def analyze_records(rows: list[dict[str, str]]) -> list[CredentialExposure]:
    exposures: list[CredentialExposure] = []
    seen: set[tuple[str, str, str]] = set()
    for row_index, row in enumerate(rows[:MAX_RECORDS], start=1):
        normalized = {str(k).strip().lower(): str(v).strip() for k, v in row.items()}
        joined = " ".join(v for v in normalized.values() if v)
        account = _first_account(joined, normalized)
        source = normalized.get("_source", f"row {row_index}")

        for label, pattern in SECRET_PATTERNS:
            for match in pattern.finditer(joined):
                secret = match.group(1) if match.lastindex else match.group(0)
                if _looks_false_positive(label, secret, joined):
                    continue
                exposure = _make_exposure(label, account, secret, source, joined, normalized)
                key = (exposure.kind, exposure.account, exposure.secret_fingerprint)
                if key not in seen:
                    seen.add(key)
                    exposures.append(exposure)

        paired_secret = _secret_from_columns(normalized)
        if paired_secret:
            exposure = _make_exposure("Credential Pair", account, paired_secret, source, joined, normalized)
            key = (exposure.kind, exposure.account, exposure.secret_fingerprint)
            if key not in seen:
                seen.add(key)
                exposures.append(exposure)

    exposures.sort(key=lambda item: item.score, reverse=True)
    return exposures


def build_simulated_paths(exposures: list[CredentialExposure], profile: str = "defensive") -> list[dict[str, Any]]:
    """Return non-executing attack-path simulations from exposure metadata."""
    paths: list[dict[str, Any]] = []
    for exposure in exposures[:50]:
        indicators = set(exposure.indicators)
        if {"privileged_account", "prod_context"} & indicators:
            paths.append({
                "type": "vertical_privilege_risk",
                "severity": exposure.risk,
                "source_account": exposure.account or "unknown account",
                "starting_material": exposure.kind,
                "simulation": [
                    "Use exposed credential only in an approved validation harness",
                    "Check effective group membership and privileged role assignments",
                    "Review admin surfaces reachable by this account",
                    "Confirm whether privilege boundaries allow elevation",
                ],
                "likely_controls_to_validate": [
                    "MFA enforcement", "least privilege", "privileged access management",
                    "conditional access", "admin role review",
                ],
            })
        if {"service_account", "host_or_url_context"} & indicators:
            paths.append({
                "type": "lateral_movement_risk",
                "severity": exposure.risk,
                "source_account": exposure.account or "unknown account",
                "starting_material": exposure.kind,
                "simulation": [
                    "Map systems referenced near the credential",
                    "Check where the account is permitted to log on without replaying the secret",
                    "Validate service account reuse and local-admin grants",
                    "Correlate with endpoint and identity logs for historical use",
                ],
                "likely_controls_to_validate": [
                    "service account tiering", "credential rotation",
                    "logon restrictions", "EDR alert coverage",
                ],
            })
        if exposure.kind in {"AWS Access Key", "Google API Key", "GitHub Token", "Slack Token", "JWT"}:
            paths.append({
                "type": "token_abuse_risk",
                "severity": exposure.risk,
                "source_account": exposure.account or "token principal unknown",
                "starting_material": exposure.kind,
                "simulation": [
                    "Identify token owner and scope from asset inventory or provider console",
                    "Check expiry, permissions, and recent use from provider audit logs",
                    "Rotate the token and search repositories/storage for duplicates",
                ],
                "likely_controls_to_validate": [
                    "token scoping", "secret scanning", "short token lifetime", "audit logging",
                ],
            })

    deduped: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    for path in paths:
        key = (path["type"], path["source_account"], path["starting_material"])
        if key not in seen:
            seen.add(key)
            deduped.append(path)
    return deduped[:25]


def summarize(exposures: list[CredentialExposure], rows: list[dict[str, str]], filename: str) -> dict[str, Any]:
    counts: dict[str, int] = {}
    risk_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for item in exposures:
        counts[item.kind] = counts.get(item.kind, 0) + 1
        risk_counts[item.risk] = risk_counts.get(item.risk, 0) + 1
    return {
        "records_scanned": len(rows),
        "exposures_found": len(exposures),
        "highest_risk": _highest_risk(exposures),
        "by_kind": counts,
        "by_risk": risk_counts,
        "file_sha256": hashlib.sha256(filename.encode()).hexdigest()[:16],
    }


def remediation_plan(exposures: list[CredentialExposure]) -> list[str]:
    if not exposures:
        return ["No credential-like material was detected. Continue scanning source and collaboration stores routinely."]
    steps = [
        "Quarantine the source file and restrict access while triage runs.",
        "Rotate or revoke every exposed credential; prioritize critical and high items first.",
        "Use identity/provider audit logs to determine whether exposed credentials were used unexpectedly.",
        "Enable or tune secret scanning in repositories, file shares, tickets, and chat exports.",
        "Replace long-lived shared credentials with vault-backed short-lived secrets.",
    ]
    if any("privileged_account" in item.indicators for item in exposures):
        steps.insert(2, "Review privileged group membership and force fresh MFA/session sign-in for affected accounts.")
    if any("service_account" in item.indicators for item in exposures):
        steps.insert(3, "Inventory service account dependencies before rotation, then apply logon restrictions and least privilege.")
    return steps


def _extract_text(raw: bytes) -> list[dict[str, str]]:
    text = raw.decode("utf-8", errors="ignore")
    rows = []
    for idx, line in enumerate(text.splitlines(), start=1):
        line = line.strip()
        if line:
            rows.append({"_source": f"line {idx}", "text": line})
    if not rows and text.strip():
        rows.append({"_source": "text", "text": text.strip()})
    return rows


def _extract_delimited(raw: bytes, delimiter: str) -> list[dict[str, str]]:
    text = raw.decode("utf-8-sig", errors="ignore")
    sample = text[:4096]
    try:
        dialect = csv.Sniffer().sniff(sample)
    except csv.Error:
        dialect = csv.excel_tab if delimiter == "\t" else csv.excel
    reader = csv.DictReader(io.StringIO(text), dialect=dialect)
    rows = []
    for idx, row in enumerate(reader, start=2):
        clean = {str(k or f"column_{i}"): str(v or "") for i, (k, v) in enumerate(row.items())}
        clean["_source"] = f"row {idx}"
        rows.append(clean)
    if rows:
        return rows
    return _extract_text(raw)


def _extract_json(raw: bytes) -> list[dict[str, str]]:
    data = json.loads(raw.decode("utf-8", errors="ignore"))
    rows: list[dict[str, str]] = []

    def walk(value: Any, path: str) -> None:
        if isinstance(value, dict):
            if any(_field_hint(k) for k in value):
                row = {str(k): _stringify(v) for k, v in value.items()}
                row["_source"] = path
                rows.append(row)
            for key, child in value.items():
                walk(child, f"{path}.{key}" if path else str(key))
        elif isinstance(value, list):
            for idx, child in enumerate(value):
                walk(child, f"{path}[{idx}]")
        elif isinstance(value, str):
            rows.append({"_source": path or "json", "text": value})

    walk(data, "")
    return rows


def _extract_docx(raw: bytes) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    with zipfile.ZipFile(io.BytesIO(raw)) as doc:
        xml = doc.read("word/document.xml")
    root = ElementTree.fromstring(xml)
    ns = {"w": "http://schemas.openxmlformats.org/wordprocessingml/2006/main"}
    for idx, para in enumerate(root.findall(".//w:p", ns), start=1):
        text = "".join(node.text or "" for node in para.findall(".//w:t", ns)).strip()
        if text:
            rows.append({"_source": f"paragraph {idx}", "text": unescape(text)})
    return rows


def _extract_xlsx(raw: bytes) -> list[dict[str, str]]:
    with zipfile.ZipFile(io.BytesIO(raw)) as book:
        shared_strings = _xlsx_shared_strings(book)
        workbook = ElementTree.fromstring(book.read("xl/workbook.xml"))
        rels = ElementTree.fromstring(book.read("xl/_rels/workbook.xml.rels"))
        rel_map = {
            rel.attrib["Id"]: rel.attrib["Target"]
            for rel in rels
            if rel.attrib.get("Id") and rel.attrib.get("Target")
        }
        ns = {
            "main": "http://schemas.openxmlformats.org/spreadsheetml/2006/main",
            "rel": "http://schemas.openxmlformats.org/officeDocument/2006/relationships",
        }
        rows: list[dict[str, str]] = []
        for sheet in workbook.findall(".//main:sheet", ns):
            name = sheet.attrib.get("name", "sheet")
            rel_id = sheet.attrib.get("{http://schemas.openxmlformats.org/officeDocument/2006/relationships}id", "")
            target = rel_map.get(rel_id, "")
            if not target:
                continue
            sheet_path = "xl/" + target.lstrip("/")
            sheet_xml = ElementTree.fromstring(book.read(sheet_path))
            for row in sheet_xml.findall(".//main:row", ns):
                cells = [_xlsx_cell_value(cell, shared_strings, ns) for cell in row.findall("main:c", ns)]
                if any(cells):
                    rows.append({
                        "_source": f"{name}!row {row.attrib.get('r', '?')}",
                        "text": " ".join(cell for cell in cells if cell),
                    })
        return rows


def _xlsx_shared_strings(book: zipfile.ZipFile) -> list[str]:
    try:
        xml = book.read("xl/sharedStrings.xml")
    except KeyError:
        return []
    root = ElementTree.fromstring(xml)
    ns = {"main": "http://schemas.openxmlformats.org/spreadsheetml/2006/main"}
    values: list[str] = []
    for si in root.findall(".//main:si", ns):
        values.append("".join(t.text or "" for t in si.findall(".//main:t", ns)))
    return values


def _xlsx_cell_value(cell: ElementTree.Element, shared_strings: list[str], ns: dict[str, str]) -> str:
    value = cell.find("main:v", ns)
    if value is None or value.text is None:
        return ""
    if cell.attrib.get("t") == "s":
        try:
            return shared_strings[int(value.text)]
        except (ValueError, IndexError):
            return ""
    return value.text


def _make_exposure(
    kind: str,
    account: str,
    secret: str,
    source: str,
    context: str,
    row: dict[str, str],
) -> CredentialExposure:
    indicators = _indicators(account, context, row, kind)
    score = _score(kind, secret, indicators)
    return CredentialExposure(
        kind=kind,
        account=account,
        secret_mask=mask_secret(secret),
        secret_fingerprint=hashlib.sha256(secret.encode()).hexdigest()[:12],
        source=source,
        context=_redact_context(context, secret),
        indicators=sorted(indicators),
        risk=_risk_label(score),
        score=score,
    )


def mask_secret(secret: str) -> str:
    secret = secret.strip()
    if not secret:
        return ""
    if len(secret) <= 4:
        return "*" * len(secret)
    if len(secret) <= 10:
        return secret[:1] + "*" * (len(secret) - 2) + secret[-1:]
    return secret[:4] + "*" * max(4, len(secret) - 8) + secret[-4:]


def _redact_context(context: str, secret: str) -> str:
    result = context[:500]
    if secret:
        result = result.replace(secret, mask_secret(secret))
    for _, pattern in SECRET_PATTERNS:
        result = pattern.sub(lambda m: m.group(0).replace(m.group(1), mask_secret(m.group(1))) if m.lastindex else mask_secret(m.group(0)), result)
    return result


def _first_account(text: str, row: dict[str, str]) -> str:
    for key in ("username", "user", "account", "login", "email", "upn"):
        if row.get(key):
            return row[key]
    email = EMAIL_RE.search(text)
    if email:
        return email.group(0)
    domain_user = DOMAIN_USER_RE.search(text)
    if domain_user:
        return domain_user.group(1)
    return ""


def _secret_from_columns(row: dict[str, str]) -> str:
    for key, value in row.items():
        if not value:
            continue
        if any(hint in key for hint in ("password", "passwd", "pwd", "secret", "token", "api_key", "apikey")):
            if len(value) >= 4 and value.lower() not in {"password", "secret", "token"}:
                return value
    return ""


def _field_hint(key: Any) -> bool:
    lowered = str(key).lower()
    return any(hint in lowered for hint in ("user", "account", "email", "password", "secret", "token", "key", "url", "host"))


def _stringify(value: Any) -> str:
    if isinstance(value, (dict, list)):
        return json.dumps(value, separators=(",", ":"))
    return "" if value is None else str(value)


def _indicators(account: str, context: str, row: dict[str, str], kind: str) -> set[str]:
    haystack = " ".join([account, context, " ".join(row.values())]).lower()
    indicators: set[str] = set()
    if any(word in haystack for word in ADMIN_WORDS):
        indicators.add("privileged_account")
    if any(word in haystack for word in SERVICE_WORDS):
        indicators.add("service_account")
    if any(word in haystack for word in PROD_WORDS):
        indicators.add("prod_context")
    if URL_RE.search(context) or re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", context):
        indicators.add("host_or_url_context")
    if any(word in haystack for word in LOUD_ATTACK_WORDS):
        indicators.add("attack_tooling_context")
    if kind in {"NTLM Hash", "Private Key", "JWT"}:
        indicators.add("replayable_material")
    if account:
        indicators.add("account_identified")
    return indicators


def _score(kind: str, secret: str, indicators: set[str]) -> int:
    base = {
        "Private Key": 82,
        "AWS Access Key": 80,
        "Google API Key": 75,
        "GitHub Token": 78,
        "Slack Token": 68,
        "JWT": 72,
        "NTLM Hash": 76,
        "Credential Pair": 70,
        "Password Assignment": 62,
    }.get(kind, 50)
    if len(secret) >= 24:
        base += 5
    if "privileged_account" in indicators:
        base += 15
    if "service_account" in indicators:
        base += 10
    if "prod_context" in indicators:
        base += 8
    if "host_or_url_context" in indicators:
        base += 5
    if "attack_tooling_context" in indicators:
        base += 4
    return min(base, 100)


def _risk_label(score: int) -> str:
    if score >= 85:
        return "critical"
    if score >= 70:
        return "high"
    if score >= 45:
        return "medium"
    return "low"


def _highest_risk(exposures: list[CredentialExposure]) -> str:
    if not exposures:
        return "none"
    return max(exposures, key=lambda item: item.score).risk


def _looks_false_positive(label: str, secret: str, context: str) -> bool:
    if label == "NTLM Hash":
        lowered = context.lower()
        if any(word in lowered for word in ("md5", "sha256", "sha1", "checksum", "etag")):
            return True
    return False
