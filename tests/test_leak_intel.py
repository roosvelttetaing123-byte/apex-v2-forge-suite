"""Tests for leak_intel sprint 0 modules.

Validates:
  - All scanners follow BaseModule interface
  - Parsers produce correct output
  - DB models create and query correctly
  - Attack chains are registered
  - All modules import cleanly

FOR AUTHORIZED PENETRATION TESTING AND RED TEAM OPERATIONS ONLY.
"""
from __future__ import annotations

import asyncio
import os
import sqlite3
import stat
import time
import traceback
from contextlib import closing
from pathlib import Path
from typing import Any

import pytest


def _legacy_fixture_config(target: str):
    """Build an explicitly opted-in config for scanner-only fixture tests.

    Scanner unit tests exercise redaction and parsing directly, without the
    canonical run/tenant authorization graph used by production dispatch.  The
    explicit compatibility marker keeps those findings available in memory
    while leaving the production adapter's strict default unchanged.
    """
    from common.config import BaseForgeConfig

    config = BaseForgeConfig(target=target)
    config.extra["allow_legacy_compat"] = True
    return config


class TestLeakIntelImports:
    """Verify all leak_intel modules import without errors."""

    def test_import_scanners(self) -> None:
        from leak_intel.scanners.github_scanner import GitHubScanner
        from leak_intel.scanners.gitlab_scanner import GitLabScanner
        from leak_intel.scanners.bitbucket_scanner import BitbucketScanner
        from leak_intel.scanners.pastebin_scanner import PastebinScanner
        from leak_intel.scanners.crtsh_scanner import CrtshScanner
        from leak_intel.scanners.shodan_enricher import ShodanEnricher
        from leak_intel.scanners.dns_history import DnsHistoryScanner
        from leak_intel.scanners.cloud_asset_enum import CloudAssetEnumerator
        from leak_intel.scanners.npm_pypi_scanner import NpmPypiScanner
        from leak_intel.scanners.stackoverflow_scanner import StackOverflowScanner

        # All should be importable
        assert GitHubScanner.NAME == "github_scanner"
        assert GitLabScanner.NAME == "gitlab_scanner"
        assert BitbucketScanner.NAME == "bitbucket_scanner"
        assert PastebinScanner.NAME == "pastebin_scanner"
        assert CrtshScanner.NAME == "crtsh_scanner"
        assert ShodanEnricher.NAME == "shodan_enricher"
        assert DnsHistoryScanner.NAME == "dns_history"
        assert CloudAssetEnumerator.NAME == "cloud_asset_enum"
        assert NpmPypiScanner.NAME == "npm_pypi_scanner"
        assert StackOverflowScanner.NAME == "stackoverflow_scanner"

    def test_import_parsers(self) -> None:
        from leak_intel.parsers.env_parser import parse_env_content
        from leak_intel.parsers.aws_key_detector import detect_aws_keys
        from leak_intel.parsers.jwt_detector import detect_jwts
        from leak_intel.parsers.url_extractor import extract_urls
        from leak_intel.parsers.credential_tester import CredentialTester

        assert callable(parse_env_content)
        assert callable(detect_aws_keys)
        assert callable(detect_jwts)
        assert callable(extract_urls)
        assert CredentialTester.NAME == "credential_tester"

    def test_import_db(self) -> None:
        from leak_intel.db.leak_models import create_leak_db, save_leak_finding
        from leak_intel.db.enrichment_cache import EnrichmentCache

        assert callable(create_leak_db)
        assert callable(save_leak_finding)


class TestScannerBaseModuleInterface:
    """Verify all scanners follow the BaseModule interface."""

    def _make_scanner(self, scanner_class: type, tmp_path: Path) -> Any:
        from common.config import BaseForgeConfig
        from common.scope import Scope
        from common.db import create_db

        cfg = _legacy_fixture_config("https://example.com")
        scope = Scope(["example.com"])
        session = create_db(tmp_path / "test.db")
        return scanner_class(cfg, scope, session, tmp_path)

    @pytest.mark.parametrize("scanner_name,scanner_path", [
        ("GitHubScanner", "leak_intel.scanners.github_scanner"),
        ("GitLabScanner", "leak_intel.scanners.gitlab_scanner"),
        ("BitbucketScanner", "leak_intel.scanners.bitbucket_scanner"),
        ("PastebinScanner", "leak_intel.scanners.pastebin_scanner"),
        ("CrtshScanner", "leak_intel.scanners.crtsh_scanner"),
        ("ShodanEnricher", "leak_intel.scanners.shodan_enricher"),
        ("DnsHistoryScanner", "leak_intel.scanners.dns_history"),
        ("CloudAssetEnumerator", "leak_intel.scanners.cloud_asset_enum"),
        ("NpmPypiScanner", "leak_intel.scanners.npm_pypi_scanner"),
        ("StackOverflowScanner", "leak_intel.scanners.stackoverflow_scanner"),
    ])
    def test_scanner_has_required_attrs(self, scanner_name: str, scanner_path: str, tmp_path: Path) -> None:
        import importlib
        mod = importlib.import_module(scanner_path)
        cls = getattr(mod, scanner_name)

        # Check class attributes
        assert hasattr(cls, "NAME")
        assert hasattr(cls, "DESCRIPTION")
        assert hasattr(cls, "PHASE")
        assert hasattr(cls, "TAGS")
        assert cls.PHASE == 0

        # Check it's a BaseModule subclass
        from common.base_module import BaseModule
        assert issubclass(cls, BaseModule)

        # Instantiate and check interface
        instance = self._make_scanner(cls, tmp_path)
        assert hasattr(instance, "run")
        assert asyncio.iscoroutinefunction(instance.run)

    def test_credential_tester_interface(self, tmp_path: Path) -> None:
        from leak_intel.parsers.credential_tester import CredentialTester
        instance = self._make_scanner(CredentialTester, tmp_path)
        assert hasattr(instance, "run")
        assert hasattr(instance, "add_credential")


class TestEnvParser:
    """Tests for env_parser module."""

    def test_parse_basic(self) -> None:
        from leak_intel.parsers.env_parser import parse_env_content
        content = 'DB_PASSWORD="my_secret_123"\nAPI_KEY=abcdef1234567890abcdef\n'
        secrets = parse_env_content(content)
        assert len(secrets) >= 1
        keys = {s.key for s in secrets}
        assert "DB_PASSWORD" in keys

    def test_skip_comments(self) -> None:
        from leak_intel.parsers.env_parser import parse_env_content
        content = "# This is a comment\nDB_HOST=localhost\n"
        secrets = parse_env_content(content)
        keys = {s.key for s in secrets}
        assert "DB_HOST" in keys


class TestAWSKeyDetector:
    """Tests for aws_key_detector module."""

    def test_detect_akia(self) -> None:
        from leak_intel.parsers.aws_key_detector import detect_aws_keys
        content = "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"
        findings = detect_aws_keys(content)
        assert len(findings) == 1
        assert findings[0].access_key == "AKIAIOSFODNN7EXAMPLE"

    def test_no_false_positives(self) -> None:
        from leak_intel.parsers.aws_key_detector import detect_aws_keys
        content = "This is just normal text without any keys."
        findings = detect_aws_keys(content)
        assert len(findings) == 0

    def test_direct_validation_is_disabled_without_provider_or_network_calls(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        import sys
        import types

        from leak_intel.parsers.aws_key_detector import (
            AWSKeyFinding,
            validate_aws_key,
        )

        calls = 0

        class FakeClientSession:
            def __init__(self, *args: Any, **kwargs: Any) -> None:
                nonlocal calls
                calls += 1

        monkeypatch.setitem(
            sys.modules,
            "aiohttp",
            types.SimpleNamespace(ClientSession=FakeClientSession),
        )
        finding = AWSKeyFinding(
            access_key="AKIAIOSFODNN7EXAMPLE",
            secret_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        )

        with pytest.raises(PermissionError, match="authorized provider boundary"):
            asyncio.run(validate_aws_key(finding))

        assert calls == 0
        assert finding.is_valid is None

    def test_aws_key_repr_and_cleanup_do_not_disclose_secret_values(self) -> None:
        from leak_intel.parsers.aws_key_detector import AWSKeyFinding

        access_key = "AKIAIOSFODNN7EXAMPLE"
        secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        session_token = "CANARY_AWS_SESSION_TOKEN_007"
        finding = AWSKeyFinding(
            access_key=access_key,
            secret_key=secret_key,
            session_token=session_token,
        )

        rendered = repr(finding)
        assert access_key not in rendered
        assert secret_key not in rendered
        assert session_token not in rendered
        secret_fingerprint = finding.redacted_secret_key()
        assert secret_fingerprint.startswith("sha256:")
        assert secret_key[:4] not in secret_fingerprint
        assert secret_key[-4:] not in secret_fingerprint
        access_fingerprint = finding.redacted_access_key()
        assert access_fingerprint.startswith("sha256:")
        assert access_key[:8] not in access_fingerprint
        assert access_key[-4:] not in access_fingerprint

        finding.clear()
        assert finding.access_key == ""
        assert finding.secret_key is None
        assert finding.session_token is None

    def test_scanner_findings_never_retain_secret_derived_fragments(
        self,
        tmp_path: Path,
    ) -> None:
        import base64
        import json

        from common.config import BaseForgeConfig
        from common.db import create_db
        from common.scope import Scope
        from leak_intel.scanners.github_scanner import GitHubScanner
        from leak_intel.scanners.stackoverflow_scanner import StackOverflowScanner

        secret = "AKIA0123456789ABCDEF"
        cfg = _legacy_fixture_config("https://example.test")
        scope = Scope(["example.test"])
        stackoverflow = StackOverflowScanner(
            cfg,
            scope,
            create_db(tmp_path / "stackoverflow.db"),
            tmp_path / "stackoverflow-results",
        )
        stackoverflow._scan_content(
            secret,
            "fixture",
            "https://example.test/fixture",
            "answer",
        )

        class Response:
            status = 200

            async def __aenter__(self):
                return self

            async def __aexit__(self, *_args):
                return False

            async def json(self):
                return {
                    "encoding": "base64",
                    "content": base64.b64encode(secret.encode()).decode(),
                }

        class Session:
            def get(self, *_args, **_kwargs):
                return Response()

        github = GitHubScanner(
            cfg,
            scope,
            create_db(tmp_path / "github.db"),
            tmp_path / "github-results",
        )
        asyncio.run(
            github._scan_file_content(
                Session(),
                "raw-fixture",
                "https://example.test/fixture",
                "input.py",
                "fixture/repository",
            )
        )

        assert len(stackoverflow.findings) == 1
        assert len(github.findings) == 1
        for finding in (stackoverflow.findings[0], github.findings[0]):
            raw_finding = repr(finding)
            serialized = json.dumps(finding.to_dict(), sort_keys=True)
            for rendered in (raw_finding, serialized):
                assert secret not in rendered
                assert secret[:8] not in rendered
                assert secret[-4:] not in rendered
            assert "<redacted>" in finding.description

    def test_parser_reprs_and_cleanup_hide_secret_material(self) -> None:
        from leak_intel.parsers.env_parser import EnvSecret
        from leak_intel.parsers.jwt_detector import JWTFinding
        from leak_intel.parsers.url_extractor import ExtractedURL

        env_value = "CANARY_ENV_SECRET_TASK007"
        token = "CANARY.JWT.TOKEN_TASK007"
        weak_key = "CANARY_WEAK_KEY_TASK007"
        secret_url = "https://user:CANARY_URL_PASSWORD_TASK007@example.test/?token=CANARY_QUERY_TASK007"
        context = f"config={secret_url}"

        env_secret = EnvSecret(key="PASSWORD", value=env_value)
        jwt = JWTFinding(
            raw_token=token,
            header={"kid": "CANARY_HEADER_TASK007"},
            payload={"password": "CANARY_PAYLOAD_TASK007"},
            weak_key=weak_key,
        )
        extracted = ExtractedURL(url=secret_url, context=context)

        assert env_secret.redacted_value() == "<redacted>"
        assert jwt.redacted_token() == "<redacted>"
        for fragment in (
            env_value,
            env_value[:6],
            env_value[-6:],
            token,
            "CANARY",
            "TOKEN_TASK007",
        ):
            assert fragment not in env_secret.redacted_value()
            assert fragment not in jwt.redacted_token()

        malformed = "CANARY_MALFORMED_JWT_TASK007"
        malformed_redaction = JWTFinding(raw_token=malformed).redacted_token()
        assert malformed_redaction == "<redacted>"
        assert malformed not in malformed_redaction
        assert malformed[:10] not in malformed_redaction

        rendered = "\n".join([repr(env_secret), repr(jwt), repr(extracted)])
        for canary in (
            env_value,
            token,
            weak_key,
            "CANARY_HEADER_TASK007",
            "CANARY_PAYLOAD_TASK007",
            "CANARY_URL_PASSWORD_TASK007",
            "CANARY_QUERY_TASK007",
        ):
            assert canary not in rendered

        env_secret.clear()
        jwt.clear()
        extracted.clear()
        assert env_secret.value == ""
        assert jwt.raw_token == ""
        assert jwt.weak_key is None
        assert jwt.header == {}
        assert jwt.payload == {}
        assert extracted.url == ""
        assert extracted.context == ""

    def test_jwt_issue_text_does_not_embed_recovered_key_or_role_value(self) -> None:
        from leak_intel.parsers.jwt_detector import JWTFinding, _analyze_jwt, _test_weak_keys

        weak_key = "secret"
        header = "eyJhbGciOiJIUzI1NiJ9"
        payload = "eyJyb2xlIjoiQ0FOQVJZX0FETUlOX1JPTEVfVEFTSzAwNyJ9"
        import base64
        import hashlib
        import hmac

        signature = base64.urlsafe_b64encode(
            hmac.new(
                weak_key.encode(),
                f"{header}.{payload}".encode(),
                hashlib.sha256,
            ).digest()
        ).rstrip(b"=").decode()
        finding = JWTFinding(
            raw_token=f"{header}.{payload}.{signature}",
            header={"alg": "HS256"},
            payload={"role": "CANARY_ADMIN_ROLE_TASK007"},
            algorithm="HS256",
        )

        _analyze_jwt(finding)
        _test_weak_keys(finding, [header, payload, signature])

        assert finding.weak_key == weak_key
        issue_text = "\n".join(finding.issues)
        assert "CANARY_ADMIN_ROLE_TASK007" not in issue_text
        assert f"'{weak_key}'" not in issue_text

    @pytest.mark.parametrize(
        "scanner_path,scanner_name,environment",
        [
            ("leak_intel.scanners.github_scanner", "GitHubScanner", {"GITHUB_TOKEN": "CANARY_GITHUB_TOKEN_TASK007"}),
            ("leak_intel.scanners.gitlab_scanner", "GitLabScanner", {"GITLAB_TOKEN": "CANARY_GITLAB_TOKEN_TASK007", "GITLAB_API_URL": "https://evil.invalid/api/v4"}),
            ("leak_intel.scanners.bitbucket_scanner", "BitbucketScanner", {"BITBUCKET_USER": "CANARY_BITBUCKET_USER_TASK007", "BITBUCKET_APP_PASSWORD": "CANARY_BITBUCKET_PASSWORD_TASK007"}),
            ("leak_intel.scanners.pastebin_scanner", "PastebinScanner", {"PASTEBIN_API_KEY": "CANARY_PASTEBIN_KEY_TASK007"}),
            ("leak_intel.scanners.stackoverflow_scanner", "StackOverflowScanner", {"STACKOVERFLOW_API_KEY": "CANARY_STACKOVERFLOW_KEY_TASK007"}),
            ("leak_intel.scanners.shodan_enricher", "ShodanEnricher", {"SHODAN_API_KEY": "CANARY_SHODAN_KEY_TASK007"}),
            ("leak_intel.scanners.dns_history", "DnsHistoryScanner", {"SECURITYTRAILS_API_KEY": "CANARY_ST_KEY_TASK007", "PASSIVETOTAL_USER": "CANARY_PT_USER_TASK007", "PASSIVETOTAL_KEY": "CANARY_PT_KEY_TASK007"}),
        ],
    )
    def test_leak_scanners_ignore_plaintext_environment_credentials(
        self,
        scanner_path: str,
        scanner_name: str,
        environment: dict[str, str],
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        import importlib

        from common.config import BaseForgeConfig
        from common.db import create_db
        from common.scope import Scope

        for key, value in environment.items():
            monkeypatch.setenv(key, value)
        module = importlib.import_module(scanner_path)
        scanner_class = getattr(module, scanner_name)
        scanner = scanner_class(
            BaseForgeConfig(target="https://example.com"),
            Scope(["example.com"]),
            create_db(tmp_path / f"{scanner_name}.db"),
            tmp_path / scanner_name,
        )
        rendered = repr(vars(scanner))
        for value in environment.values():
            assert value not in rendered
        for field in (
            "_token",
            "_api_key",
            "_app_password",
            "_st_key",
            "_pt_key",
            "_pt_user",
            "_user",
        ):
            if hasattr(scanner, field):
                assert getattr(scanner, field) == ""
        if hasattr(scanner, "_api_base") and scanner_name == "GitLabScanner":
            assert scanner._api_base == "https://gitlab.com/api/v4"


class TestJWTDetector:
    """Tests for jwt_detector module."""

    def test_detect_jwt(self) -> None:
        from leak_intel.parsers.jwt_detector import detect_jwts
        token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        findings = detect_jwts(f"Authorization: Bearer {token}")
        assert len(findings) == 1
        assert findings[0].header.get("alg") == "HS256"


class TestURLExtractor:
    """Tests for url_extractor module."""

    def test_extract_internal_ip(self) -> None:
        from leak_intel.parsers.url_extractor import extract_urls
        content = 'url = "http://192.168.1.100:8080/api"'
        urls = extract_urls(content)
        assert len(urls) >= 1
        assert urls[0].category == "internal_ip"

    def test_extract_ci_cd(self) -> None:
        from leak_intel.parsers.url_extractor import extract_urls
        content = 'webhook = "https://jenkins.company.com/build"'
        urls = extract_urls(content)
        assert len(urls) >= 1
        assert urls[0].category == "ci_cd"


class TestLeakDB:
    """Tests for leak DB models."""

    def test_create_and_query(self, tmp_path: Path) -> None:
        from leak_intel.db.leak_models import create_leak_db, save_leak_finding, LeakFinding
        session = create_leak_db(tmp_path / "test.db")
        save_leak_finding(session, {
            "scanner": "github_scanner",
            "title": "Test finding",
            "severity": "High",
        })
        results = session.query(LeakFinding).all()
        assert len(results) == 1
        session.close()

    def test_sqlite_and_cache_redact_before_write_and_are_owner_only(
        self,
        tmp_path: Path,
    ) -> None:
        from leak_intel.db.enrichment_cache import EnrichmentCache
        from leak_intel.db.leak_models import (
            create_leak_db,
            log_audit,
            save_credential,
            save_leak_finding,
        )

        secret = "opaque31d92d3155074dfa0f9df3566d635c0"
        fragment = secret[:10]
        leak_path = tmp_path / "leak-private" / "leak.db"
        cache_path = tmp_path / "cache-private" / "cache.db"
        previous_umask = os.umask(0)
        try:
            session = create_leak_db(leak_path)
            save_leak_finding(
                session,
                {
                    "scanner": "fixture",
                    "title": f"Synthetic finding {fragment}",
                    "description": secret,
                    "raw_match": secret,
                    "source_url": f"https://example.test/{secret}",
                    "tags": [secret, fragment],
                    "severity": "High",
                },
            )
            save_credential(
                session,
                {
                    "finding_id": "finding-fixture",
                    "cred_type": "password",
                    "username": secret,
                    "redacted_value": secret,
                },
            )
            log_audit(
                session,
                {
                    "service": "fixture",
                    "detail": secret,
                    "source": secret,
                },
            )
            session.close()

            cache = EnrichmentCache(cache_path)
            cache.set(
                secret,
                secret,
                {
                    "response": secret,
                    "nested": [secret, fragment],
                    "note": f"detected-{fragment}",
                },
            )
            cached = cache.get(secret, secret)
        finally:
            os.umask(previous_umask)

        assert cached == {
            "response": "<redacted>",
            "nested": ["<redacted>", "<redacted>"],
            "note": "detected-<redacted>",
        }
        assert secret.encode() not in leak_path.read_bytes()
        assert secret.encode() not in cache_path.read_bytes()
        assert stat.S_IMODE(leak_path.stat().st_mode) == 0o600
        assert stat.S_IMODE(cache_path.stat().st_mode) == 0o600
        assert stat.S_IMODE(leak_path.parent.stat().st_mode) == 0o700
        assert stat.S_IMODE(cache_path.parent.stat().st_mode) == 0o700

        with closing(sqlite3.connect(leak_path)) as connection:
            stored = repr(
                connection.execute(
                    "SELECT description, raw_match, source_url, tags FROM leak_findings"
                ).fetchall()
                + connection.execute(
                    "SELECT username, redacted_value FROM leak_credentials"
                ).fetchall()
                + connection.execute(
                    "SELECT detail, source FROM leak_audit_log"
                ).fetchall()
            )
        assert secret not in stored
        assert fragment not in stored

    def test_existing_parent_permissions_are_preserved_for_db_and_cache(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from leak_intel.db.enrichment_cache import EnrichmentCache
        from leak_intel.db.leak_models import create_leak_db

        shared = tmp_path / "caller-owned"
        shared.mkdir(mode=0o755)
        shared.chmod(0o755)

        session = create_leak_db(shared / "leak.db")
        session.close()
        cache = EnrichmentCache(shared / "cache.db")
        cache.set("crtsh", "example.test", {"result": "fixture"})

        assert stat.S_IMODE(shared.stat().st_mode) == 0o755
        assert stat.S_IMODE((shared / "leak.db").stat().st_mode) == 0o600
        assert stat.S_IMODE((shared / "cache.db").stat().st_mode) == 0o600

        monkeypatch.chdir(shared)
        default_cache = EnrichmentCache()
        default_cache.set("crtsh", "default.example", {"result": "fixture"})
        assert stat.S_IMODE(shared.stat().st_mode) == 0o755
        assert stat.S_IMODE((shared / "enrichment_cache.db").stat().st_mode) == 0o600

    def test_db_and_cache_never_change_umask_and_create_nested_private_artifacts(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        import leak_intel.db.enrichment_cache as cache_module
        import leak_intel.db.leak_models as leak_module

        def reject_umask(*_args: object, **_kwargs: object) -> None:
            raise AssertionError("Leak Intel changed the process umask")

        monkeypatch.setattr(leak_module.os, "umask", reject_umask)
        monkeypatch.setattr(cache_module.os, "umask", reject_umask)
        leak_path = tmp_path / "leak-private" / "nested" / "leak.db"
        cache_path = tmp_path / "cache-private" / "nested" / "cache.db"

        session = leak_module.create_leak_db(leak_path)
        cache = cache_module.EnrichmentCache(cache_path)
        try:
            for directory in (
                leak_path.parent.parent,
                leak_path.parent,
                cache_path.parent.parent,
                cache_path.parent,
            ):
                assert stat.S_IMODE(directory.stat().st_mode) == 0o700
            for path in (
                leak_path,
                leak_path.with_suffix(".db.schema.lock"),
                Path(f"{leak_path}-wal"),
                Path(f"{leak_path}-shm"),
                cache_path,
                cache_path.with_suffix(".db.schema.lock"),
                Path(f"{cache_path}-wal"),
                Path(f"{cache_path}-shm"),
            ):
                assert path.is_file() and not path.is_symlink()
                assert stat.S_IMODE(path.stat().st_mode) == 0o600
        finally:
            bind = session.get_bind()
            session.close()
            bind.dispose()
            cache._engine.dispose()

    @pytest.mark.parametrize("artifact_kind", ["leak", "cache"])
    def test_db_and_cache_reject_intermediate_directory_symlink(
        self,
        tmp_path: Path,
        artifact_kind: str,
    ) -> None:
        from leak_intel.db.enrichment_cache import EnrichmentCache
        from leak_intel.db.leak_models import create_leak_db

        real_parent = tmp_path / "real-parent"
        nested_parent = real_parent / "nested"
        nested_parent.mkdir(parents=True)
        nested_parent.chmod(0o755)
        linked_parent = tmp_path / "linked-parent"
        linked_parent.symlink_to(real_parent, target_is_directory=True)
        destination = linked_parent / "nested" / f"{artifact_kind}.db"

        with pytest.raises(ValueError, match="artifact is unavailable or unsafe"):
            if artifact_kind == "leak":
                create_leak_db(destination)
            else:
                EnrichmentCache(destination)

        assert list(nested_parent.iterdir()) == []
        assert stat.S_IMODE(nested_parent.stat().st_mode) == 0o755

    @pytest.mark.parametrize("artifact_kind", ["leak", "cache"])
    @pytest.mark.parametrize("alias_kind", ["symlink", "hardlink"])
    def test_db_and_cache_reject_aliased_main_file_without_touching_victim(
        self,
        tmp_path: Path,
        artifact_kind: str,
        alias_kind: str,
    ) -> None:
        from leak_intel.db.enrichment_cache import EnrichmentCache
        from leak_intel.db.leak_models import create_leak_db

        victim = tmp_path / f"{artifact_kind}-{alias_kind}-victim.db"
        with closing(sqlite3.connect(victim)) as connection:
            connection.execute("CREATE TABLE victim_canary (value TEXT)")
        victim.chmod(0o644)
        original = victim.read_bytes()
        destination = tmp_path / f"{artifact_kind}.db"
        if alias_kind == "symlink":
            destination.symlink_to(victim)
        else:
            os.link(victim, destination)

        with pytest.raises(ValueError, match="artifact is unavailable or unsafe"):
            if artifact_kind == "leak":
                create_leak_db(destination)
            else:
                EnrichmentCache(destination)

        assert victim.read_bytes() == original
        assert stat.S_IMODE(victim.stat().st_mode) == 0o644
        assert victim.stat().st_nlink == (2 if alias_kind == "hardlink" else 1)

    @pytest.mark.parametrize("artifact_kind", ["leak", "cache"])
    @pytest.mark.parametrize("suffix", ["-journal", "-wal", "-shm"])
    @pytest.mark.parametrize("alias_kind", ["symlink", "hardlink"])
    def test_db_and_cache_reject_aliased_sidecar_without_touching_victim(
        self,
        tmp_path: Path,
        artifact_kind: str,
        suffix: str,
        alias_kind: str,
    ) -> None:
        from leak_intel.db.enrichment_cache import EnrichmentCache
        from leak_intel.db.leak_models import create_leak_db

        db_path = tmp_path / f"{artifact_kind}.db"
        with closing(sqlite3.connect(db_path)) as connection:
            connection.execute("CREATE TABLE existing (value TEXT)")
        victim = tmp_path / f"{artifact_kind}-{alias_kind}{suffix}-victim"
        victim.write_bytes(b"LEAK_INTEL_SIDECAR_CANARY_UNCHANGED")
        victim.chmod(0o644)
        original = victim.read_bytes()
        sidecar = Path(f"{db_path}{suffix}")
        if alias_kind == "symlink":
            sidecar.symlink_to(victim)
        else:
            os.link(victim, sidecar)

        with pytest.raises(ValueError, match="artifact is unavailable or unsafe"):
            if artifact_kind == "leak":
                create_leak_db(db_path)
            else:
                EnrichmentCache(db_path)

        assert victim.read_bytes() == original
        assert stat.S_IMODE(victim.stat().st_mode) == 0o644
        assert victim.stat().st_nlink == (2 if alias_kind == "hardlink" else 1)

    @pytest.mark.parametrize("artifact_kind", ["leak", "cache"])
    def test_db_and_cache_normalize_initialization_failures(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        artifact_kind: str,
    ) -> None:
        import leak_intel.db.enrichment_cache as cache_module
        import leak_intel.db.leak_models as leak_module

        failure_canary = "LEAK_INTEL_INITIALIZATION_DETAIL_MUST_NOT_ESCAPE"

        def fail_create_all(*_args: object, **_kwargs: object) -> None:
            raise RuntimeError(failure_canary)

        if artifact_kind == "leak":
            monkeypatch.setattr(leak_module.LeakBase.metadata, "create_all", fail_create_all)
            initializer = leak_module.create_leak_db
            error_type = leak_module.LeakDatabaseInitializationError
            expected = "leak database initialization failed"
        else:
            monkeypatch.setattr(cache_module.CacheBase.metadata, "create_all", fail_create_all)
            initializer = cache_module.EnrichmentCache
            error_type = cache_module.EnrichmentCacheInitializationError
            expected = "enrichment cache initialization failed"

        db_path = tmp_path / failure_canary / f"{artifact_kind}.db"
        with pytest.raises(error_type, match=expected) as exc_info:
            initializer(db_path)
        rendered = "".join(
            traceback.format_exception(
                type(exc_info.value),
                exc_info.value,
                exc_info.value.__traceback__,
            )
        )
        assert failure_canary not in rendered
        assert exc_info.value.__suppress_context__ is True
        descriptor_root = Path("/proc/self/fd")
        leaked_descriptors: list[str] = []
        if descriptor_root.is_dir():
            for descriptor in descriptor_root.iterdir():
                try:
                    target = os.readlink(descriptor)
                except OSError:
                    continue
                if os.fspath(db_path) in target:
                    leaked_descriptors.append(target)
        assert leaked_descriptors == []


class TestEnrichmentCache:
    """Tests for enrichment cache."""

    def test_set_and_get(self, tmp_path: Path) -> None:
        from leak_intel.db.enrichment_cache import EnrichmentCache
        cache = EnrichmentCache(tmp_path / "cache.db")
        cache.set("crtsh", "example.com", {"subs": ["a.example.com"]})
        result = cache.get("crtsh", "example.com")
        assert result is not None
        assert result["subs"] == ["a.example.com"]

    def test_cache_miss(self, tmp_path: Path) -> None:
        from leak_intel.db.enrichment_cache import EnrichmentCache
        cache = EnrichmentCache(tmp_path / "cache.db")
        assert cache.get("crtsh", "nope.com") is None

    def test_unlabelled_opaque_response_and_exception_are_not_persisted_or_logged(
        self,
        tmp_path: Path,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        import logging

        from leak_intel.db.enrichment_cache import CacheEntry, EnrichmentCache

        secret = "q7v9m2x4p8k6r3d1-secret-material"
        path = tmp_path / "cache.db"
        cache = EnrichmentCache(path)
        cache.set("shodan", "fixture.test", {"items": [secret], "status": "ok"})

        assert cache.get("shodan", "fixture.test") == {
            "items": ["<redacted>"],
            "status": "ok",
        }
        assert secret.encode() not in path.read_bytes()

        class RaisingQuery:
            def filter_by(self, **_kwargs: object) -> "RaisingQuery":
                return self

            def first(self) -> CacheEntry | None:
                raise RuntimeError(secret)

        class RaisingSession:
            def query(self, *_args: object, **_kwargs: object) -> RaisingQuery:
                return RaisingQuery()

            def close(self) -> None:
                return None

        cache._session_factory = RaisingSession  # type: ignore[assignment]
        with caplog.at_level(
            logging.DEBUG,
            logger="forge.leak_intel.enrichment_cache",
        ):
            assert cache.get("shodan", "fixture.test") is None
        assert secret not in caplog.text

    def test_cache_and_leak_sidecars_never_follow_symlinks(
        self,
        tmp_path: Path,
    ) -> None:
        from leak_intel.db.enrichment_cache import EnrichmentCache
        from leak_intel.db.leak_models import _secure_sqlite_paths

        victim = tmp_path / "cache-victim"
        victim.write_bytes(b"CACHE_VICTIM")
        victim.chmod(0o644)
        cache_path = tmp_path / "cache.db"
        cache_path.symlink_to(victim)

        with pytest.raises(ValueError, match="unavailable or unsafe"):
            EnrichmentCache(cache_path)
        assert victim.read_bytes() == b"CACHE_VICTIM"
        assert stat.S_IMODE(victim.stat().st_mode) == 0o644

        main = tmp_path / "leak.db"
        main.write_bytes(b"fixture")
        sidecar_victim = tmp_path / "sidecar-victim"
        sidecar_victim.write_bytes(b"SIDECAR_VICTIM")
        sidecar_victim.chmod(0o666)
        Path(f"{main}-wal").symlink_to(sidecar_victim)

        with pytest.raises(ValueError, match="unavailable or unsafe"):
            _secure_sqlite_paths(main)
        assert sidecar_victim.read_bytes() == b"SIDECAR_VICTIM"
        assert stat.S_IMODE(sidecar_victim.stat().st_mode) == 0o666


def test_detected_secret_fragments_are_removed_from_scanner_metadata(
    tmp_path: Path,
) -> None:
    import base64
    import json

    from common.config import BaseForgeConfig
    from common.db import create_db
    from common.scope import Scope
    from leak_intel.scanners.bitbucket_scanner import BitbucketScanner
    from leak_intel.parsers.aws_key_detector import detect_aws_keys
    from leak_intel.scanners.github_scanner import GitHubScanner
    from leak_intel.scanners.gitlab_scanner import GitLabScanner
    from leak_intel.scanners.pastebin_scanner import PastebinScanner
    from leak_intel.scanners.stackoverflow_scanner import StackOverflowScanner

    access_key = "AKIAABCDEFGHIJKLMNOP"
    access_prefix = access_key[:8]
    config = _legacy_fixture_config("https://example.test")
    scope = Scope(["example.test"])
    github = GitHubScanner(
        config,
        scope,
        create_db(tmp_path / "github.db"),
        tmp_path / "github-results",
    )

    class Response:
        status = 200

        async def __aenter__(self) -> "Response":
            return self

        async def __aexit__(self, *_args: object) -> bool:
            return False

        async def json(self) -> dict[str, str]:
            return {
                "encoding": "base64",
                "content": base64.b64encode(access_key.encode()).decode(),
            }

    class Session:
        def get(self, *_args: object, **_kwargs: object) -> Response:
            return Response()

    asyncio.run(
        github._scan_file_content(
            Session(),
            "fixture",
            f"https://example.test/{access_prefix}",
            f"{access_prefix}.txt",
            f"repo-{access_prefix}",
        )
    )
    github_rendered = repr(github.findings[0]) + json.dumps(
        github.findings[0].to_dict(),
        sort_keys=True,
    )

    stack_secret = "r8t4y2u6i0p9-secret-value"
    stack_prefix = stack_secret[:10]
    stack = StackOverflowScanner(
        config,
        scope,
        create_db(tmp_path / "stack.db"),
        tmp_path / "stack-results",
    )
    stack._scan_content(
        f"api_key={stack_secret}",
        "fixture",
        f"https://example.test/{stack_prefix}",
        "question",
    )
    stack_rendered = repr(stack.findings[0]) + json.dumps(
        stack.findings[0].to_dict(),
        sort_keys=True,
    )

    async def no_rate_limit(*_args: object, **_kwargs: object) -> None:
        return None

    class JSONResponse:
        status = 200

        def __init__(self, payload: object = None, text: str = "") -> None:
            self.payload = payload
            self.body = text

        async def __aenter__(self) -> "JSONResponse":
            return self

        async def __aexit__(self, *_args: object) -> bool:
            return False

        async def json(self) -> object:
            return self.payload

        async def text(self) -> str:
            return self.body

    gitlab = GitLabScanner(
        config,
        scope,
        create_db(tmp_path / "gitlab-fragments.db"),
        tmp_path / "gitlab-fragment-results",
    )
    gitlab.rate_limit = no_rate_limit  # type: ignore[method-assign]

    class GitLabSession:
        def get(self, *_args: object, **_kwargs: object) -> JSONResponse:
            return JSONResponse(
                [{
                    "data": access_key,
                    "filename": f"{access_prefix}.txt",
                    "ref": f"branch-{access_prefix}",
                }]
            )

    asyncio.run(
        gitlab._search_project_code(
            GitLabSession(),
            7,
            f"group/repo-{access_prefix}",
        )
    )

    bitbucket = BitbucketScanner(
        config,
        scope,
        create_db(tmp_path / "bitbucket-fragments.db"),
        tmp_path / "bitbucket-fragment-results",
    )
    bitbucket._workspace = f"workspace-{access_prefix}"

    class TextSession:
        def get(self, *_args: object, **_kwargs: object) -> JSONResponse:
            return JSONResponse(text=access_key)

    asyncio.run(
        bitbucket._scan_bitbucket_file(
            TextSession(),
            "https://fixture.test/raw",
            f"repo-{access_prefix}",
            f"config-{access_prefix}.txt",
        )
    )

    pastebin = PastebinScanner(
        config,
        scope,
        create_db(tmp_path / "pastebin-fragments.db"),
        tmp_path / "pastebin-fragment-results",
    )
    pastebin.rate_limit = no_rate_limit  # type: ignore[method-assign]
    pastebin._target_keywords.append(access_prefix)

    class PastebinSession:
        def get(self, url: str, **_kwargs: object) -> JSONResponse:
            if url.endswith("api_scraping.php"):
                return JSONResponse([{
                    "scrape_url": "https://fixture.test/raw",
                    "key": f"paste-{access_prefix}",
                    "title": f"title-{access_prefix}",
                }])
            return JSONResponse(text=f"example.test {access_key}")

    asyncio.run(pastebin._scrape_pastebin_pro(PastebinSession()))

    remaining_scanner_rendered = json.dumps(
        [
            finding.to_dict()
            for scanner in (gitlab, bitbucket, pastebin)
            for finding in scanner.findings
        ],
        sort_keys=True,
    )

    aws = detect_aws_keys(
        access_key,
        source_file=f"/fixture/{access_prefix}.txt",
    )[0]
    assert access_prefix not in github_rendered
    assert stack_prefix not in stack_rendered
    assert access_prefix not in remaining_scanner_rendered
    assert access_key not in remaining_scanner_rendered
    assert access_prefix not in repr(aws)


def test_remaining_scanner_exception_logs_omit_remote_exception_text(
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    import logging

    from common.config import BaseForgeConfig
    from common.db import create_db
    from common.scope import Scope
    from leak_intel.scanners.bitbucket_scanner import BitbucketScanner
    from leak_intel.scanners.dns_history import DnsHistoryScanner
    from leak_intel.scanners.gitlab_scanner import GitLabScanner
    from leak_intel.scanners.pastebin_scanner import PastebinScanner
    from leak_intel.scanners.shodan_enricher import ShodanEnricher

    exception_secret = "opaque-scanner-exception-f7b1bfe9"
    config = _legacy_fixture_config("https://example.test")
    scope = Scope(["example.test"])

    async def no_rate_limit(*_args: object, **_kwargs: object) -> None:
        return None

    class FailingSession:
        def get(self, *_args: object, **_kwargs: object) -> object:
            raise RuntimeError(exception_secret)

    gitlab = GitLabScanner(
        config,
        scope,
        create_db(tmp_path / "gitlab-exception.db"),
        tmp_path / "gitlab-exception-results",
    )
    bitbucket = BitbucketScanner(
        config,
        scope,
        create_db(tmp_path / "bitbucket-exception.db"),
        tmp_path / "bitbucket-exception-results",
    )
    pastebin = PastebinScanner(
        config,
        scope,
        create_db(tmp_path / "pastebin-exception.db"),
        tmp_path / "pastebin-exception-results",
    )
    shodan = ShodanEnricher(
        config,
        scope,
        create_db(tmp_path / "shodan-exception.db"),
        tmp_path / "shodan-exception-results",
    )
    dns_history = DnsHistoryScanner(
        config,
        scope,
        create_db(tmp_path / "dns-history-exception.db"),
        tmp_path / "dns-history-exception-results",
    )
    for scanner in (gitlab, bitbucket, pastebin, shodan, dns_history):
        scanner.rate_limit = no_rate_limit  # type: ignore[method-assign]

    caplog.set_level(logging.DEBUG)
    assert asyncio.run(gitlab._list_group_projects(FailingSession())) == []
    assert asyncio.run(bitbucket._list_repos(FailingSession())) == []
    asyncio.run(pastebin._scrape_pastebin_pro(FailingSession()))
    assert asyncio.run(shodan._resolve_domain(FailingSession(), "example.test")) == []
    asyncio.run(shodan._query_host(FailingSession(), "127.0.0.1", "example.test"))
    asyncio.run(shodan._search_domain(FailingSession(), "example.test"))
    asyncio.run(dns_history._query_securitytrails(FailingSession(), "example.test"))
    asyncio.run(dns_history._query_passivetotal(FailingSession(), "example.test"))

    assert exception_secret not in caplog.text
    assert caplog.text.count("RuntimeError") >= 8


def test_env_file_parse_failure_omits_path_and_exception_text(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    import logging

    from leak_intel.parsers.env_parser import parse_env_file

    exception_secret = "opaque-env-parser-exception-f5c9f8bd"
    source_secret = f"/fixture/{exception_secret}/.env"

    def fail_read(*_args: object, **_kwargs: object) -> str:
        raise RuntimeError(exception_secret)

    monkeypatch.setattr(Path, "read_text", fail_read)
    caplog.set_level(logging.ERROR, logger="forge.leak_intel.env_parser")

    assert parse_env_file(source_secret) == []
    assert exception_secret not in caplog.text
    assert source_secret not in caplog.text
    assert "RuntimeError" in caplog.text


class TestAttackChains:
    """Verify OSINT chains are registered."""

    def test_leak_intel_chains_exist(self) -> None:
        from common.attack_chains import _CHAIN_DEFINITIONS
        chain_ids = {c.chain_id for c in _CHAIN_DEFINITIONS}
        expected = {
            "git_leak_to_cred_to_webapp",
            "pastebin_leak_to_vpn",
            "crtsh_to_hidden_subdomain",
            "shodan_origin_to_cdn_bypass",
            "dns_history_to_stale_auth",
        }
        assert expected.issubset(chain_ids), f"Missing chains: {expected - chain_ids}"

    def test_chain_count_increased(self) -> None:
        from common.attack_chains import _CHAIN_DEFINITIONS
        # Original 10 + 5 new = 15
        assert len(_CHAIN_DEFINITIONS) >= 15
