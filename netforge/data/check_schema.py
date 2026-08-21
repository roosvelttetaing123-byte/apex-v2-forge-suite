"""Check Schema — Pydantic models for YAML vulnerability check definitions.

Defines the data format for our Nuclei-like-but-native check definitions.
Each YAML file describes a vulnerability check: what to probe, how to match,
and what to report when it hits.

Supports:
  - HTTP probes (GET/POST/PUT with headers, body, follow redirects)
  - Banner/TCP probes (connect, send, match response)
  - Version comparison (CPE + version range)
  - OOB callback detection (via ForgeCollab)
  - Multiple detection steps with AND/OR logic
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

import yaml


class CheckType(str, Enum):
    HTTP = "http"
    BANNER = "banner"
    TCP_PROBE = "tcp_probe"
    UDP_PROBE = "udp_probe"
    VERSION = "version"


class MatchType(str, Enum):
    STATUS_CODE = "status_code"
    BODY_CONTAINS = "body_contains"
    BODY_REGEX = "body_regex"
    HEADER_CONTAINS = "header_contains"
    HEADER_REGEX = "header_regex"
    BANNER_CONTAINS = "banner_contains"
    BANNER_REGEX = "banner_regex"
    OOB_CALLBACK = "oob_callback"
    NOT_CONTAINS = "not_contains"
    VERSION_RANGE = "version_range"
    RESPONSE_TIME = "response_time"


@dataclass
class MatchCondition:
    """A single match condition within a detection step."""
    type: MatchType
    value: Any = ""
    negate: bool = False

    @classmethod
    def from_dict(cls, data: dict) -> "MatchCondition":
        # Handle shorthand formats
        if "status_code" in data:
            return cls(type=MatchType.STATUS_CODE, value=data["status_code"])
        if "body_contains" in data:
            return cls(type=MatchType.BODY_CONTAINS, value=data["body_contains"])
        if "body_regex" in data:
            return cls(type=MatchType.BODY_REGEX, value=data["body_regex"])
        if "header_contains" in data:
            return cls(type=MatchType.HEADER_CONTAINS, value=data["header_contains"])
        if "header_regex" in data:
            return cls(type=MatchType.HEADER_REGEX, value=data["header_regex"])
        if "banner_contains" in data:
            return cls(type=MatchType.BANNER_CONTAINS, value=data["banner_contains"])
        if "banner_regex" in data:
            return cls(type=MatchType.BANNER_REGEX, value=data["banner_regex"])
        if "oob_callback" in data:
            return cls(type=MatchType.OOB_CALLBACK, value=data["oob_callback"])
        if "not_contains" in data:
            return cls(type=MatchType.NOT_CONTAINS, value=data["not_contains"], negate=True)
        if "version_range" in data:
            return cls(type=MatchType.VERSION_RANGE, value=data["version_range"])
        if "response_time" in data:
            return cls(type=MatchType.RESPONSE_TIME, value=data["response_time"])

        return cls(type=MatchType(data.get("type", "body_contains")), value=data.get("value", ""))


@dataclass
class DetectionStep:
    """A single detection step (probe + match)."""
    type: CheckType = CheckType.HTTP
    # HTTP options
    method: str = "GET"
    path: str = "/"
    paths: list[str] = field(default_factory=list)
    headers: dict[str, str] = field(default_factory=dict)
    body: str = ""
    follow_redirects: bool = True
    # TCP/Banner options
    port: int = 0
    ports: list[int] = field(default_factory=list)
    send: str = ""
    read_bytes: int = 4096
    timeout: float = 10.0
    # Version options
    cpe_vendor: str = ""
    cpe_product: str = ""
    version_range: str = ""
    # Match conditions
    match: list[MatchCondition] = field(default_factory=list)
    match_all: bool = True  # True = AND logic, False = OR logic
    # Extractors
    extract_regex: str = ""
    extract_name: str = ""

    @classmethod
    def from_dict(cls, data: dict) -> "DetectionStep":
        step = cls()
        step.type = CheckType(data.get("type", "http"))
        step.method = data.get("method", "GET")
        step.path = data.get("path", "/")
        step.paths = data.get("paths", [])
        step.headers = data.get("headers", {})
        step.body = data.get("body", "")
        step.follow_redirects = data.get("follow_redirects", True)
        step.port = data.get("port", 0)
        step.ports = data.get("ports", [])
        step.send = data.get("send", "")
        step.read_bytes = data.get("read_bytes", 4096)
        step.timeout = data.get("timeout", 10.0)
        step.cpe_vendor = data.get("cpe_vendor", "")
        step.cpe_product = data.get("cpe_product", "")
        step.version_range = data.get("version_range", "")
        step.match_all = data.get("match_all", True)
        step.extract_regex = data.get("extract_regex", "")
        step.extract_name = data.get("extract_name", "")

        # Parse match conditions
        match_data = data.get("match", {})
        if isinstance(match_data, dict):
            step.match = [MatchCondition.from_dict(match_data)]
        elif isinstance(match_data, list):
            step.match = [MatchCondition.from_dict(m) if isinstance(m, dict) else m for m in match_data]

        return step


@dataclass
class VulnCheck:
    """A complete vulnerability check definition loaded from YAML."""
    id: str = ""
    cve: str = ""
    cves: list[str] = field(default_factory=list)  # Multiple CVEs
    name: str = ""
    severity: str = "medium"
    cvss: str = ""
    cvss40: str = ""
    cpe: str = ""
    tags: list[str] = field(default_factory=list)
    description: str = ""
    remediation: str = ""
    references: list[str] = field(default_factory=list)
    detection: list[DetectionStep] = field(default_factory=list)
    # Targeting
    target_service: str = ""       # Only run if this service is detected
    target_port: int = 0           # Only run on this port
    target_ports: list[int] = field(default_factory=list)
    requires_auth: bool = False
    # Metadata
    author: str = "forge"
    maturity: str = "experimental"
    proof_type: str = "unknown"
    verification_state: str = "candidate"
    source_file: str = ""
    # Detection logic
    detection_all: bool = False    # True = ALL steps must match, False = ANY step

    @classmethod
    def from_dict(cls, data: dict, source_file: str = "") -> "VulnCheck":
        check = cls()
        check.id = data.get("id", "")
        check.cve = data.get("cve", "")
        check.cves = data.get("cves", [])
        if check.cve and check.cve not in check.cves:
            check.cves.insert(0, check.cve)
        check.name = data.get("name", check.id)
        check.severity = data.get("severity", "medium").lower()
        check.cvss = data.get("cvss", "")
        check.cvss40 = data.get("cvss40", "")
        check.cpe = data.get("cpe", "")
        check.tags = data.get("tags", [])
        check.description = data.get("description", "")
        check.remediation = data.get("remediation", "")
        check.references = data.get("references", [])
        check.target_service = data.get("target_service", "")
        check.target_port = data.get("target_port", 0)
        check.target_ports = data.get("target_ports", [])
        check.requires_auth = data.get("requires_auth", False)
        check.author = data.get("author", "forge")
        from common.verification_policy import normalise_maturity

        check.maturity = normalise_maturity(data.get("maturity")).value
        check.source_file = source_file
        check.detection_all = data.get("detection_all", False)

        # Parse detection steps
        for step_data in data.get("detection", []):
            check.detection.append(DetectionStep.from_dict(step_data))
        check.proof_type = check.infer_proof_type()
        check.verification_state = "simulation" if check.proof_type == "simulation" else "candidate"

        return check

    def infer_proof_type(self) -> str:
        """Classify the check signal without claiming that a match is verified."""
        match_types = {condition.type for step in self.detection for condition in step.match}
        step_types = {step.type for step in self.detection}
        if MatchType.OOB_CALLBACK in match_types:
            return "OOB"
        if CheckType.VERSION in step_types or MatchType.VERSION_RANGE in match_types:
            return "version_correlation"
        if step_types & {CheckType.BANNER}:
            return "passive"
        if step_types & {CheckType.HTTP, CheckType.TCP_PROBE, CheckType.UDP_PROBE}:
            return "active"
        return "unknown"

    @classmethod
    def from_yaml_file(cls, path: Path) -> "list[VulnCheck]":
        """Load one or more checks from a YAML file (supports multi-doc --- separators)."""
        with open(path, "r") as f:
            docs = list(yaml.safe_load_all(f))
        checks = []
        for data in docs:
            if data:
                checks.append(cls.from_dict(data, source_file=str(path)))
        return checks

    @classmethod
    def from_yaml_str(cls, content: str, source: str = "") -> "VulnCheck":
        """Load a check from a YAML string (single doc)."""
        data = yaml.safe_load(content)
        return cls.from_dict(data, source_file=source)

    def matches_service(self, service: str, port: int = 0) -> bool:
        """Check if this check should run for a given service/port."""
        if self.target_service:
            if self.target_service.lower() not in service.lower():
                return False
        if self.target_port and port:
            if self.target_port != port:
                return False
        if self.target_ports and port:
            if port not in self.target_ports:
                return False
        return True

    def validate(self) -> list[str]:
        """Validate the check definition. Returns list of error strings."""
        errors = []
        if not self.id:
            errors.append("Missing 'id' field")
        if not self.name:
            errors.append("Missing 'name' field")
        if not self.detection:
            errors.append("No detection steps defined")
        if self.severity not in {"critical", "high", "medium", "low", "info"}:
            errors.append(f"Invalid severity: {self.severity}")
        for i, step in enumerate(self.detection):
            if not step.match:
                errors.append(f"Detection step {i} has no match conditions")
        return errors


def load_checks_from_directory(checks_dir: Path) -> list[VulnCheck]:
    """Load all YAML check definitions from a directory (recursive).

    Returns validated checks, logs warnings for invalid ones.
    """
    import logging
    log = logging.getLogger("forge.check_schema")

    checks: list[VulnCheck] = []
    seen_ids: set[str] = set()

    if not checks_dir.exists():
        log.warning("Checks directory does not exist: %s", checks_dir)
        return checks

    for yaml_file in sorted(checks_dir.rglob("*.yaml")):
        try:
            file_checks = VulnCheck.from_yaml_file(yaml_file)
            for check in file_checks:
                errors = check.validate()
                if errors:
                    log.warning(
                        "Invalid check %s in %s: %s",
                        check.id or "?", yaml_file.name, "; ".join(errors),
                    )
                    continue
                if check.id in seen_ids:
                    raise ValueError(f"duplicate capability id: {check.id}")
                seen_ids.add(check.id)
                checks.append(check)
        except ValueError:
            raise
        except Exception as exc:
            log.warning("Failed to load check %s: %s", yaml_file.name, exc)

    log.info("Loaded %d vulnerability checks from %s", len(checks), checks_dir)
    return checks


# ── Multi-doc YAML support (multiple checks per file) ────────────────────

def load_checks_from_yaml_str(content: str, source: str = "") -> list[VulnCheck]:
    """Load checks from a multi-document YAML string."""
    checks = []
    for doc in yaml.safe_load_all(content):
        if doc:
            check = VulnCheck.from_dict(doc, source_file=source)
            errors = check.validate()
            if not errors:
                checks.append(check)
    return checks


# ── Tests ────────────────────────────────────────────────────────────────

class TestCheckSchema:
    def test_basic_http_check(self) -> None:
        yaml_str = """
id: CVE-2021-44228-log4shell
cve: CVE-2021-44228
name: "Apache Log4j RCE (Log4Shell)"
severity: critical
tags: [rce, java, cisa-kev]
detection:
  - type: http
    method: GET
    path: "/"
    headers:
      X-Api-Version: "${jndi:ldap://callback/test}"
    match:
      oob_callback: true
remediation: "Upgrade to Log4j 2.17.1+"
"""
        check = VulnCheck.from_yaml_str(yaml_str)
        assert check.id == "CVE-2021-44228-log4shell"
        assert check.cve == "CVE-2021-44228"
        assert check.severity == "critical"
        assert len(check.detection) == 1
        assert check.detection[0].type == CheckType.HTTP

    def test_banner_check(self) -> None:
        yaml_str = """
id: openssh-cve-2024-6387
cve: CVE-2024-6387
name: "OpenSSH regreSSHion"
severity: critical
detection:
  - type: banner
    port: 22
    match:
      banner_regex: 'OpenSSH_(8\\.[5-9]|9\\.[0-7])'
remediation: "Upgrade to OpenSSH 9.8+"
"""
        check = VulnCheck.from_yaml_str(yaml_str)
        assert check.detection[0].type == CheckType.BANNER
        assert check.detection[0].port == 22

    def test_validation(self) -> None:
        check = VulnCheck()
        errors = check.validate()
        assert len(errors) > 0  # Missing id, name, detection

    def test_service_matching(self) -> None:
        check = VulnCheck(target_service="http", target_ports=[80, 443, 8080])
        assert check.matches_service("http", 80) is True
        assert check.matches_service("http", 22) is False
        assert check.matches_service("ssh", 22) is False
