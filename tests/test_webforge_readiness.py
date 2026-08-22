"""Focused tests for authenticated WebForge readiness plumbing."""
from __future__ import annotations

import json
from argparse import Namespace

from common.config import BaseForgeConfig
from common.outbound_policy import (
    evaluate_module_outbound_support,
    intrinsically_local_modules,
    module_requires_outbound_context,
    policy_supported_modules,
)
from webforge.core.auth_recorder import AuthRecorder, AuthReplayResult
from webforge.core.crawl_orchestrator import CrawlOrchestrator
from webforge.core.session_bridge import apply_session_to_forge
from webforge.modules.api.schema_import import APIEndpoint, SchemaImporter, SchemaImportResult
from webforge.modules.recon.link_crawler import LinkCrawler
from webforge.webforge import (
    _apply_auth_context,
    _apply_captured_session,
    _merge_auth_result,
    _merge_schema_result,
    prepare_api_schema_context,
    prepare_collab_context,
)


def _auth_args(**overrides) -> Namespace:
    defaults = {
        "auth_type": None,
        "header_name": "Authorization",
        "username": None,
        "password": None,
        "token": None,
        "cookie": None,
    }
    defaults.update(overrides)
    return Namespace(**defaults)


def test_whitebox_modules_are_supported_local_only_without_direct_bypass() -> None:
    supported = policy_supported_modules("webforge")

    assert {"secret_scan", "dep_audit"}.issubset(supported)
    for module_id in ("secret_scan", "dep_audit"):
        decision = evaluate_module_outbound_support(
            engine="webforge",
            module_id=module_id,
        )
        assert decision.supported is True
        assert decision.reason_code == "allowed"
        assert module_requires_outbound_context(
            engine="webforge",
            module_id=module_id,
        ) is False

    assert intrinsically_local_modules("webforge") == frozenset()
    for module_id in ("source_audit", "config_audit", "unknown_whitebox"):
        decision = evaluate_module_outbound_support(
            engine="webforge",
            module_id=module_id,
        )
        assert decision.supported is False
        assert decision.reason_code == "outbound_policy_unsupported"


def test_explicit_remote_schema_and_collab_requests_are_marked_unsupported() -> None:
    cfg = BaseForgeConfig(target="https://app.example.com")
    schema_args = Namespace(
        api_schema=None,
        graphql_schema_url="https://schema.example.com/graphql",
    )

    import asyncio

    asyncio.run(prepare_api_schema_context(cfg, schema_args))
    prepare_collab_context(cfg, Namespace(collab_domain="oob.example.com"))

    assert cfg.extra["schema_outbound_state"] == "outbound_policy_unsupported"
    assert cfg.extra["collab_outbound_state"] == "outbound_policy_unsupported"


def test_captured_sso_session_populates_headers_and_cookies() -> None:
    cfg = BaseForgeConfig(target="https://app.example.com")
    _apply_captured_session(
        cfg,
        {
            "cookies": [
                {
                    "name": "sessionid",
                    "value": "abc123",
                    "domain": "app.example.com",
                    "path": "/",
                    "secure": True,
                },
                {
                    "name": "theme",
                    "value": "dark",
                    "domain": "app.example.com",
                    "path": "/",
                    "secure": True,
                },
            ],
            "post_login_url": "https://app.example.com/dashboard",
            "detected_tokens": {
                "jwt": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig",
                "csrf": "csrf-token",
            },
        },
    )

    assert cfg.extra["session_cookies"]["sessionid"] == "abc123"
    assert "sessionid=abc123" in cfg.extra["session_headers"]["Cookie"]
    assert cfg.extra["session_headers"]["Authorization"].startswith("Bearer eyJ")
    assert cfg.extra["session_headers"]["X-CSRF-Token"] == "csrf-token"


def test_imported_storage_state_keeps_only_exact_app_origin_credentials(tmp_path) -> None:
    state = {
        "cookies": [
            {
                "name": "app_session",
                "value": "APP_COOKIE_CANARY",
                "domain": "app.example.com",
                "path": "/scan",
                "secure": True,
            },
            {
                "name": "idp_session",
                "value": "IDP_COOKIE_CANARY",
                "domain": "idp.example.com",
                "path": "/",
                "secure": True,
            },
            {
                "name": "wrong_path",
                "value": "WRONG_PATH_CANARY",
                "domain": "app.example.com",
                "path": "/admin",
                "secure": True,
            },
        ],
        "origins": [
            {
                "origin": "https://app.example.com",
                "localStorage": [
                    {"name": "access_token", "value": "APP_BEARER_CANARY"},
                    {"name": "csrf_token", "value": "APP_CSRF_CANARY"},
                ],
            },
            {
                "origin": "https://idp.example.com",
                "localStorage": [
                    {"name": "access_token", "value": "IDP_BEARER_CANARY"},
                    {"name": "csrf_token", "value": "IDP_CSRF_CANARY"},
                ],
            },
        ],
    }
    state_path = tmp_path / "storage-state.json"
    state_path.write_text(json.dumps(state), encoding="utf-8")
    target = "https://app.example.com/scan/start"
    auth = AuthRecorder(tmp_path).import_storage_state(state_path, target)
    cfg = BaseForgeConfig(target=target)

    _merge_auth_result(cfg, auth)

    assert auth.authenticated is True
    assert cfg.extra["session_cookies"] == {"app_session": "APP_COOKIE_CANARY"}
    assert cfg.extra["session_cookie_provenance"]["app_session"]["path"] == "/scan"
    assert cfg.extra["session_headers"]["Cookie"] == "app_session=APP_COOKIE_CANARY"
    assert cfg.extra["session_headers"]["Authorization"] == "Bearer APP_BEARER_CANARY"
    assert cfg.extra["session_headers"]["X-CSRF-Token"] == "APP_CSRF_CANARY"
    assert "IDP_" not in repr(cfg.extra)
    assert "WRONG_PATH_CANARY" not in repr(cfg.extra)


def test_path_scoped_cookie_values_are_not_promoted_to_origin_headers(tmp_path) -> None:
    state = {
        "cookies": [
            {
                "name": "sessionid",
                "value": "eyJcookie.payload.sig",
                "domain": "app.example.com",
                "path": "/admin",
                "secure": True,
            },
            {
                "name": "XSRF-TOKEN",
                "value": "CANARY_PATH_CSRF",
                "domain": "app.example.com",
                "path": "/admin",
                "secure": True,
            },
        ],
        "origins": [],
    }
    state_path = tmp_path / "path-scoped-state.json"
    state_path.write_text(json.dumps(state), encoding="utf-8")
    recorder = AuthRecorder(tmp_path)
    result = recorder.import_storage_state(
        state_path,
        "https://app.example.com/admin/start",
    )

    assert result.tokens == {}
    assert recorder.build_auth_headers(
        result,
        "https://app.example.com/public",
    ) == {}


def test_imported_cookie_secure_flag_is_strictly_typed(tmp_path) -> None:
    state = {
        "cookies": [
            {
                "name": "plain_default",
                "value": "PLAIN_DEFAULT_CANARY",
                "domain": "app.example.com",
                "path": "/",
            },
            {
                "name": "malformed_secure",
                "value": "MALFORMED_SECURE_CANARY",
                "domain": "app.example.com",
                "path": "/",
                "secure": "true",
            },
            {
                "name": "secure_cookie",
                "value": "SECURE_COOKIE_CANARY",
                "domain": "app.example.com",
                "path": "/",
                "secure": True,
            },
        ],
        "origins": [],
    }
    state_path = tmp_path / "strict-secure-state.json"
    state_path.write_text(json.dumps(state), encoding="utf-8")

    result = AuthRecorder(tmp_path).import_storage_state(
        state_path,
        "http://app.example.com/",
    )

    assert result.cookies == {"plain_default": "PLAIN_DEFAULT_CANARY"}
    assert "MALFORMED_SECURE_CANARY" not in repr(result.to_dict())
    assert "SECURE_COOKIE_CANARY" not in repr(result.to_dict())


def test_imported_storage_state_omits_conflicting_exact_origin_tokens(tmp_path) -> None:
    state = {
        "cookies": [],
        "origins": [
            {
                "origin": "https://app.example.com",
                "localStorage": [
                    {"name": "access_token", "value": "TOKEN_ONE_CANARY"},
                    {"name": "auth_token", "value": "TOKEN_TWO_CANARY"},
                ],
            },
        ],
    }
    state_path = tmp_path / "ambiguous-storage-state.json"
    state_path.write_text(json.dumps(state), encoding="utf-8")
    auth = AuthRecorder(tmp_path).import_storage_state(
        state_path,
        "https://app.example.com/",
    )
    cfg = BaseForgeConfig(target="https://app.example.com/")

    _merge_auth_result(cfg, auth)

    assert auth.tokens == {}
    assert "session_headers" not in cfg.extra
    assert "token" not in cfg.extra


def test_captured_session_rejects_idp_aggregate_tokens_and_foreign_cookies() -> None:
    cfg = BaseForgeConfig(target="https://app.example.com/")
    _apply_captured_session(
        cfg,
        {
            "post_login_url": "https://idp.example.com/continue",
            "cookies": [
                {
                    "name": "app_session",
                    "value": "APP_COOKIE_CANARY",
                    "domain": "app.example.com",
                    "path": "/",
                    "secure": True,
                },
                {
                    "name": "idp_session",
                    "value": "IDP_COOKIE_CANARY",
                    "domain": "idp.example.com",
                    "path": "/",
                    "secure": True,
                },
            ],
            "detected_tokens": {
                "bearer": "IDP_BEARER_CANARY",
                "csrf": "IDP_CSRF_CANARY",
            },
        },
    )

    assert cfg.extra["session_cookies"] == {"app_session": "APP_COOKIE_CANARY"}
    assert cfg.extra["session_headers"] == {"Cookie": "app_session=APP_COOKIE_CANARY"}
    assert "IDP_" not in repr(cfg.extra)
    assert "session_data" not in cfg.extra


def test_flattened_auth_result_without_per_credential_provenance_is_ignored() -> None:
    cfg = BaseForgeConfig(target="https://app.example.com/")
    auth = AuthReplayResult(
        authenticated=True,
        cookies={"session": "UNVERIFIED_COOKIE_CANARY"},
        tokens={"bearer": "UNVERIFIED_TOKEN_CANARY"},
        credential_origin="https://app.example.com:443",
    )

    _merge_auth_result(cfg, auth)

    assert "session_headers" not in cfg.extra
    assert "session_cookies" not in cfg.extra


def test_session_bridge_revalidates_capture_before_updating_client() -> None:
    class FakeSession:
        def __init__(self) -> None:
            self.cookies: dict[str, str] = {}
            self.cookie_provenance: dict[str, dict[str, object]] = {}
            self.headers: dict[str, str] = {}

        def update_cookies(
            self,
            cookies: dict[str, str],
            *,
            cookie_provenance: dict[str, dict[str, object]],
        ) -> None:
            self.cookies.update(cookies)
            self.cookie_provenance.update(cookie_provenance)

        def update_headers(self, headers: dict[str, str]) -> None:
            self.headers.update(headers)

    session = FakeSession()
    apply_session_to_forge(
        {
            "post_login_url": "https://idp.example.com/continue",
            "cookies": [
                {
                    "name": "app_session",
                    "value": "APP_COOKIE_CANARY",
                    "domain": "app.example.com",
                    "path": "/",
                    "secure": True,
                },
                {
                    "name": "idp_session",
                    "value": "IDP_COOKIE_CANARY",
                    "domain": "idp.example.com",
                    "path": "/",
                    "secure": True,
                },
            ],
            "detected_tokens": {"bearer": "IDP_BEARER_CANARY"},
        },
        session,
        target_url="https://app.example.com/",
    )

    assert session.cookies == {"app_session": "APP_COOKIE_CANARY"}
    assert session.cookie_provenance["app_session"]["path"] == "/"
    assert session.headers == {}


def test_resolved_bearer_auth_populates_custom_header_without_mutating_args() -> None:
    cfg = BaseForgeConfig(target="https://app.example.com")
    args = _auth_args(auth_type="bearer", header_name="X-Api-Key")

    _apply_auth_context(
        cfg,
        args,
        {
            "FORGE_AUTH_TYPE": "bearer",
        },
        credential_values={"token": "secret-token"},
    )

    assert cfg.extra["auth_type"] == "bearer"
    assert cfg.extra["token"] == "secret-token"
    assert cfg.extra["session_headers"] == {"X-Api-Key": "secret-token"}
    assert args.token is None


def test_resolved_cookie_auth_populates_header_and_cookie_jar_without_mutating_args() -> None:
    cfg = BaseForgeConfig(target="https://app.example.com")
    args = _auth_args(auth_type="cookie")

    _apply_auth_context(
        cfg,
        args,
        {
            "FORGE_AUTH_TYPE": "cookie",
        },
        credential_values={"cookie": "Cookie: session=abc123; Path=/; theme=dark"},
    )

    assert cfg.extra["auth_type"] == "cookie"
    assert cfg.extra["cookie"] == "session=abc123; Path=/; theme=dark"
    assert cfg.extra["session_headers"]["Cookie"] == "session=abc123; Path=/; theme=dark"
    assert cfg.extra["session_cookies"] == {"session": "abc123", "theme": "dark"}
    assert args.cookie is None


def test_resolved_form_auth_password_stays_out_of_args() -> None:
    cfg = BaseForgeConfig(target="https://app.example.com")
    args = _auth_args(auth_type="form", username="admin")

    _apply_auth_context(
        cfg,
        args,
        {
            "FORGE_AUTH_TYPE": "form",
        },
        credential_values={"password": "secret-password"},
    )

    assert cfg.extra["auth_type"] == "form"
    assert cfg.extra["username"] == "admin"
    assert cfg.extra["password"] == "secret-password"
    assert args.password is None


def test_plaintext_credential_environment_variables_are_ignored() -> None:
    cfg = BaseForgeConfig(target="https://app.example.com")
    args = _auth_args(auth_type="form", username="admin")

    _apply_auth_context(
        cfg,
        args,
        {
            "FORGE_AUTH_TYPE": "form",
            "FORGE_PASSWORD": "legacy-password-canary",
            "FORGE_TOKEN": "legacy-token-canary",
            "FORGE_COOKIE_JAR": "session=legacy-cookie-canary",
        },
    )

    rendered = repr(cfg.extra)
    assert "legacy-password-canary" not in rendered
    assert "legacy-token-canary" not in rendered
    assert "legacy-cookie-canary" not in rendered


def test_schema_import_merge_adds_api_endpoints_and_forms() -> None:
    cfg = BaseForgeConfig(target="https://app.example.com")
    spec = {
        "openapi": "3.0.0",
        "info": {"title": "Test API", "version": "1.0"},
        "servers": [{"url": "https://app.example.com"}],
        "paths": {
            "/users": {"get": {}},
            "/checkout": {
                "post": {
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "amount": {"type": "number"},
                                        "coupon": {"type": "string"},
                                    },
                                }
                            }
                        }
                    }
                }
            },
        },
    }
    result = SchemaImporter("https://app.example.com")._parse_openapi3(spec)

    _merge_schema_result(cfg, result)

    assert "https://app.example.com/users" in cfg.extra["api_endpoints"]
    assert "https://app.example.com/checkout" in cfg.extra["api_endpoints"]
    assert cfg.extra["found_forms"][0]["action"] == "https://app.example.com/checkout"
    assert "amount" in cfg.extra["found_forms"][0]["inputs"]


def test_schema_merge_omits_out_of_scope_endpoints_and_forms() -> None:
    cfg = BaseForgeConfig(target="https://app.example.com/")
    cfg.extra["allowed_scope"] = ["app.example.com"]
    result = SchemaImportResult(
        format="openapi3",
        endpoints=[
            APIEndpoint(
                method="POST",
                path="/submit",
                url="https://app.example.com/submit",
                parameters=[{"name": "value", "in": "body"}],
            ),
            APIEndpoint(
                method="POST",
                path="/steal",
                url="https://idp.example.com/steal",
                parameters=[{"name": "token", "in": "body"}],
            ),
            APIEndpoint(
                method="POST",
                path="/other-port",
                url="https://app.example.com:9443/other-port",
                parameters=[{"name": "token", "in": "body"}],
            ),
        ],
    )

    _merge_schema_result(cfg, result)

    rendered = repr(cfg.extra)
    assert "https://app.example.com/submit" in rendered
    assert "https://idp.example.com/steal" not in rendered
    assert "https://app.example.com:9443/other-port" not in rendered
    assert cfg.extra["api_schema"]["endpoint_count"] == 1


def test_discovered_links_and_forms_omit_cross_origin_children(tmp_path) -> None:
    html = """
        <a href="/inside">inside</a>
        <a href="https://idp.example.com/outside">outside</a>
        <form action="/submit"><input name="ok"></form>
        <form action="https://idp.example.com/steal"><input name="token"></form>
    """
    crawler = object.__new__(LinkCrawler)
    links = crawler._extract_links(
        html,
        "https://app.example.com/start",
        "https://app.example.com/",
        0,
    )
    orchestrator = CrawlOrchestrator(
        "https://app.example.com/",
        tmp_path,
        use_browser=False,
    )
    forms = orchestrator._extract_forms_html(
        html,
        "https://app.example.com/start",
    )

    rendered_links = repr(links)
    rendered_forms = repr(forms)
    assert "https://app.example.com/inside" in rendered_links
    assert "idp.example.com" not in rendered_links
    assert "https://app.example.com/submit" in rendered_forms
    assert "idp.example.com" not in rendered_forms
