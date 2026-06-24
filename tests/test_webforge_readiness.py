"""Focused tests for authenticated WebForge readiness plumbing."""
from __future__ import annotations

from common.config import BaseForgeConfig
from webforge.modules.api.schema_import import SchemaImporter
from webforge.webforge import _apply_captured_session, _merge_schema_result


def test_captured_sso_session_populates_headers_and_cookies() -> None:
    cfg = BaseForgeConfig(target="https://app.example.com")
    _apply_captured_session(
        cfg,
        {
            "cookies": [
                {"name": "sessionid", "value": "abc123"},
                {"name": "theme", "value": "dark"},
            ],
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
