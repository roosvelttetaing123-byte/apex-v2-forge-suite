"""API schema import — OpenAPI/Swagger, GraphQL introspection, Postman collection.

Parses API specifications into a normalised endpoint + parameter list that
WebForge injection modules can consume directly.

Supported formats:
    • OpenAPI 3.0 / Swagger 2.0 (JSON/YAML)
    • GraphQL introspection query
    • Postman Collection v2.1 (JSON)
"""
from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urljoin

log = logging.getLogger("webforge.schema_import")


@dataclass
class APIEndpoint:
    """Normalised API endpoint discovered from a schema."""
    method: str            # GET, POST, PUT, DELETE, QUERY, MUTATION
    path: str              # /api/v1/users/{id}
    url: str = ""          # Full URL (filled when base_url known)
    parameters: list[dict[str, Any]] = field(default_factory=list)
    # Each param: {"name": "id", "in": "path|query|body|header", "type": "string", "required": bool}
    content_type: str = "application/json"
    description: str = ""
    auth_required: bool = False
    tags: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "method": self.method,
            "path": self.path,
            "url": self.url,
            "parameters": self.parameters,
            "content_type": self.content_type,
            "description": self.description,
            "auth_required": self.auth_required,
            "tags": self.tags,
        }


@dataclass
class SchemaImportResult:
    """Result of parsing an API schema."""
    format: str               # "openapi3", "swagger2", "graphql", "postman"
    title: str = ""
    base_url: str = ""
    endpoints: list[APIEndpoint] = field(default_factory=list)
    auth_schemes: list[dict[str, Any]] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "format": self.format,
            "title": self.title,
            "base_url": self.base_url,
            "endpoint_count": len(self.endpoints),
            "endpoints": [e.to_dict() for e in self.endpoints],
            "auth_schemes": self.auth_schemes,
            "errors": self.errors,
        }

    @property
    def api_urls(self) -> list[str]:
        """Return flat list of full endpoint URLs for injection scanners."""
        return [e.url for e in self.endpoints if e.url]

    @property
    def forms(self) -> list[dict[str, Any]]:
        """Return endpoints as fake 'form' dicts that injection scanners expect."""
        result = []
        for ep in self.endpoints:
            if ep.method in ("POST", "PUT", "PATCH"):
                body_params = [p["name"] for p in ep.parameters if p.get("in") == "body"]
                if body_params:
                    result.append({
                        "action": ep.url or ep.path,
                        "method": ep.method,
                        "inputs": body_params,
                    })
        return result


class SchemaImporter:
    """Parse API specs into normalised WebForge endpoint lists."""

    def __init__(self, base_url: str = "") -> None:
        self.base_url = base_url.rstrip("/")

    def import_file(self, path: Path) -> SchemaImportResult:
        """Auto-detect format and parse."""
        text = path.read_text(encoding="utf-8")
        if path.suffix in (".yaml", ".yml"):
            return self._parse_openapi_yaml(text)

        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            return SchemaImportResult(format="unknown", errors=[f"Cannot parse {path}"])

        # Detect format from JSON structure
        if "openapi" in data:
            return self._parse_openapi3(data)
        if "swagger" in data:
            return self._parse_swagger2(data)
        if "info" in data and "item" in data:
            return self._parse_postman(data)
        if "data" in data and "__schema" in data.get("data", {}):
            return self._parse_graphql_introspection(data)

        return SchemaImportResult(format="unknown", errors=["Unknown schema format"])

    # ── OpenAPI 3.0 ───────────────────────────────────────────────────────────

    def _parse_openapi3(self, data: dict) -> SchemaImportResult:
        result = SchemaImportResult(format="openapi3")
        result.title = data.get("info", {}).get("title", "")

        # Determine base URL from servers[]
        servers = data.get("servers", [])
        if servers:
            result.base_url = servers[0].get("url", self.base_url)
        else:
            result.base_url = self.base_url

        # Parse security schemes
        components = data.get("components", {})
        for scheme_name, scheme_data in components.get("securitySchemes", {}).items():
            result.auth_schemes.append({
                "name": scheme_name,
                "type": scheme_data.get("type", ""),
                "scheme": scheme_data.get("scheme", ""),
                "in": scheme_data.get("in", ""),
            })

        # Parse paths
        for path, methods in data.get("paths", {}).items():
            for method, op_data in methods.items():
                if method in ("get", "post", "put", "delete", "patch", "options", "head"):
                    ep = self._parse_openapi3_operation(path, method.upper(), op_data, components)
                    ep.url = urljoin(result.base_url + "/", path.lstrip("/"))
                    result.endpoints.append(ep)

        return result

    def _parse_openapi3_operation(
        self, path: str, method: str, op: dict, components: dict
    ) -> APIEndpoint:
        params: list[dict[str, Any]] = []

        # Path/query/header parameters
        for p in op.get("parameters", []):
            resolved = self._resolve_ref(p, components)
            params.append({
                "name": resolved.get("name", ""),
                "in": resolved.get("in", "query"),
                "type": resolved.get("schema", {}).get("type", "string"),
                "required": resolved.get("required", False),
            })

        # Request body → body parameters
        body = op.get("requestBody", {})
        if body:
            content = body.get("content", {})
            for ct, ct_data in content.items():
                schema = ct_data.get("schema", {})
                resolved = self._resolve_ref(schema, components)
                for prop_name, prop_data in resolved.get("properties", {}).items():
                    params.append({
                        "name": prop_name,
                        "in": "body",
                        "type": prop_data.get("type", "string"),
                        "required": prop_name in resolved.get("required", []),
                    })
                break  # Take first content type

        # Check if auth required
        auth_required = bool(op.get("security"))

        return APIEndpoint(
            method=method,
            path=path,
            parameters=params,
            description=op.get("summary", op.get("description", ""))[:200],
            auth_required=auth_required,
            tags=op.get("tags", []),
        )

    # ── Swagger 2.0 ──────────────────────────────────────────────────────────

    def _parse_swagger2(self, data: dict) -> SchemaImportResult:
        result = SchemaImportResult(format="swagger2")
        result.title = data.get("info", {}).get("title", "")

        host = data.get("host", "")
        base_path = data.get("basePath", "")
        schemes = data.get("schemes", ["https"])
        result.base_url = self.base_url or f"{schemes[0]}://{host}{base_path}"

        for scheme_name, scheme_data in data.get("securityDefinitions", {}).items():
            result.auth_schemes.append({
                "name": scheme_name,
                "type": scheme_data.get("type", ""),
                "in": scheme_data.get("in", ""),
            })

        definitions = data.get("definitions", {})
        for path, methods in data.get("paths", {}).items():
            for method, op_data in methods.items():
                if method in ("get", "post", "put", "delete", "patch"):
                    ep = self._parse_swagger2_operation(path, method.upper(), op_data, definitions)
                    ep.url = urljoin(result.base_url + "/", path.lstrip("/"))
                    result.endpoints.append(ep)

        return result

    def _parse_swagger2_operation(
        self, path: str, method: str, op: dict, definitions: dict
    ) -> APIEndpoint:
        params: list[dict[str, Any]] = []
        for p in op.get("parameters", []):
            location = p.get("in", "query")
            if location == "body":
                schema = p.get("schema", {})
                resolved = self._resolve_swagger_def(schema, definitions)
                for prop_name in resolved.get("properties", {}):
                    params.append({
                        "name": prop_name, "in": "body",
                        "type": resolved["properties"][prop_name].get("type", "string"),
                        "required": prop_name in resolved.get("required", []),
                    })
            else:
                params.append({
                    "name": p.get("name", ""),
                    "in": location,
                    "type": p.get("type", "string"),
                    "required": p.get("required", False),
                })

        return APIEndpoint(
            method=method, path=path, parameters=params,
            description=op.get("summary", "")[:200],
            auth_required=bool(op.get("security")),
            tags=op.get("tags", []),
        )

    # ── GraphQL introspection ────────────────────────────────────────────────

    def _parse_graphql_introspection(self, data: dict) -> SchemaImportResult:
        result = SchemaImportResult(format="graphql", base_url=self.base_url)
        schema = data.get("data", {}).get("__schema", {})
        result.title = "GraphQL API"

        for type_key, method in [("queryType", "QUERY"), ("mutationType", "MUTATION")]:
            type_info = schema.get(type_key)
            if not type_info:
                continue
            type_name = type_info.get("name", "")
            # Find the actual type definition
            for t in schema.get("types", []):
                if t.get("name") == type_name:
                    for field_def in t.get("fields", []):
                        params = []
                        for arg in field_def.get("args", []):
                            params.append({
                                "name": arg.get("name", ""),
                                "in": "body",
                                "type": self._graphql_type_name(arg.get("type", {})),
                                "required": arg.get("type", {}).get("kind") == "NON_NULL",
                            })
                        result.endpoints.append(APIEndpoint(
                            method=method,
                            path=f"/{field_def['name']}",
                            url=self.base_url + "/graphql" if self.base_url else "/graphql",
                            parameters=params,
                            description=field_def.get("description", "")[:200],
                            tags=["graphql"],
                        ))
                    break

        return result

    def _graphql_type_name(self, type_def: dict) -> str:
        if type_def.get("kind") == "NON_NULL":
            return self._graphql_type_name(type_def.get("ofType", {})) + "!"
        if type_def.get("kind") == "LIST":
            return "[" + self._graphql_type_name(type_def.get("ofType", {})) + "]"
        return type_def.get("name", "Any")

    # ── Postman Collection v2.1 ──────────────────────────────────────────────

    def _parse_postman(self, data: dict) -> SchemaImportResult:
        result = SchemaImportResult(format="postman")
        result.title = data.get("info", {}).get("name", "Postman Collection")
        result.base_url = self.base_url

        self._walk_postman_items(data.get("item", []), result)
        return result

    def _walk_postman_items(self, items: list, result: SchemaImportResult) -> None:
        for item in items:
            if "item" in item:  # Folder
                self._walk_postman_items(item["item"], result)
            elif "request" in item:
                req = item["request"]
                method = req.get("method", "GET").upper()

                # URL handling
                url_data = req.get("url", {})
                if isinstance(url_data, str):
                    raw_url = url_data
                else:
                    raw_url = url_data.get("raw", "")

                # Parameters
                params: list[dict[str, Any]] = []
                if isinstance(url_data, dict):
                    for qp in url_data.get("query", []):
                        params.append({
                            "name": qp.get("key", ""),
                            "in": "query",
                            "type": "string",
                            "required": not qp.get("disabled", False),
                        })

                # Body parameters
                body = req.get("body", {})
                if body:
                    mode = body.get("mode", "")
                    if mode == "urlencoded":
                        for bp in body.get("urlencoded", []):
                            params.append({
                                "name": bp.get("key", ""),
                                "in": "body",
                                "type": "string",
                                "required": True,
                            })
                    elif mode == "raw":
                        raw = body.get("raw", "")
                        try:
                            json_body = json.loads(raw)
                            if isinstance(json_body, dict):
                                for key in json_body:
                                    params.append({
                                        "name": key, "in": "body",
                                        "type": type(json_body[key]).__name__,
                                        "required": True,
                                    })
                        except (json.JSONDecodeError, TypeError):
                            pass

                # Resolve URL
                full_url = raw_url
                if self.base_url and not raw_url.startswith("http"):
                    full_url = urljoin(self.base_url + "/", raw_url.lstrip("/"))

                result.endpoints.append(APIEndpoint(
                    method=method,
                    path=raw_url,
                    url=full_url,
                    parameters=params,
                    description=item.get("name", "")[:200],
                    tags=["postman"],
                ))

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _resolve_ref(self, obj: dict, components: dict) -> dict:
        ref = obj.get("$ref", "")
        if not ref:
            return obj
        # #/components/schemas/User → components.schemas.User
        parts = ref.lstrip("#/").split("/")
        resolved = components
        for part in parts[1:]:  # Skip 'components'
            resolved = resolved.get(part, {})
        return resolved if isinstance(resolved, dict) else obj

    def _resolve_swagger_def(self, schema: dict, definitions: dict) -> dict:
        ref = schema.get("$ref", "")
        if not ref:
            return schema
        def_name = ref.split("/")[-1]
        return definitions.get(def_name, schema)


# ── Async helpers for live introspection ──────────────────────────────────────

async def fetch_graphql_schema(
    url: str,
    headers: dict | None = None,
    outbound_policy: Any = None,
) -> SchemaImportResult:
    """Run a GraphQL introspection query against a live endpoint."""
    introspection_query = {
        "query": """
            query IntrospectionQuery {
                __schema {
                    queryType { name }
                    mutationType { name }
                    types {
                        name kind description
                        fields {
                            name description
                            args { name type { kind name ofType { kind name ofType { kind name } } } }
                        }
                    }
                }
            }
        """
    }
    if outbound_policy is None:
        return SchemaImportResult(
            format="graphql",
            errors=["outbound policy authorization is required for live schema fetch"],
        )
    try:
        from common.outbound_policy import PolicyHttpClient
        async with PolicyHttpClient(outbound_policy) as session:
            async with session.post(
                url, json=introspection_query,
                headers={**(headers or {}), "Content-Type": "application/json"},
                timeout=10,
            ) as resp:
                data = await resp.json()
                importer = SchemaImporter(base_url=url.rsplit("/", 1)[0])
                return importer._parse_graphql_introspection(data)
    except Exception as exc:
        return SchemaImportResult(format="graphql", errors=[str(exc)])


async def fetch_openapi_spec(
    url: str,
    headers: dict | None = None,
    outbound_policy: Any = None,
) -> SchemaImportResult:
    """Fetch and parse an OpenAPI/Swagger spec from a live URL."""
    if outbound_policy is None:
        return SchemaImportResult(
            format="openapi",
            errors=["outbound policy authorization is required for live schema fetch"],
        )
    try:
        from common.outbound_policy import PolicyHttpClient
        async with PolicyHttpClient(outbound_policy) as session:
            async with session.get(
                url, headers=headers or {},
                timeout=10,
            ) as resp:
                text = await resp.text()
                data = json.loads(text)
                base_url = url.rsplit("/", 1)[0]
                importer = SchemaImporter(base_url=base_url)
                if "openapi" in data:
                    return importer._parse_openapi3(data)
                elif "swagger" in data:
                    return importer._parse_swagger2(data)
                return SchemaImportResult(format="unknown", errors=["Not an OpenAPI/Swagger spec"])
    except Exception as exc:
        return SchemaImportResult(format="openapi", errors=[str(exc)])


# ── Tests ─────────────────────────────────────────────────────────────────────

class TestSchemaImporter:
    def test_openapi3_basic(self) -> None:
        spec = {
            "openapi": "3.0.0",
            "info": {"title": "Test API", "version": "1.0"},
            "servers": [{"url": "https://api.example.com"}],
            "paths": {
                "/users": {
                    "get": {"summary": "List users", "parameters": [
                        {"name": "limit", "in": "query", "schema": {"type": "integer"}}
                    ]},
                    "post": {"summary": "Create user", "requestBody": {
                        "content": {"application/json": {"schema": {
                            "type": "object",
                            "properties": {
                                "name": {"type": "string"},
                                "email": {"type": "string"},
                            },
                            "required": ["name"],
                        }}}
                    }},
                },
            },
        }
        imp = SchemaImporter("https://api.example.com")
        result = imp._parse_openapi3(spec)
        assert result.format == "openapi3"
        assert len(result.endpoints) == 2
        get_ep = [e for e in result.endpoints if e.method == "GET"][0]
        assert len(get_ep.parameters) == 1
        post_ep = [e for e in result.endpoints if e.method == "POST"][0]
        assert len(post_ep.parameters) == 2

    def test_swagger2_basic(self) -> None:
        spec = {
            "swagger": "2.0",
            "info": {"title": "Legacy API"},
            "host": "legacy.example.com",
            "basePath": "/v1",
            "paths": {
                "/items": {
                    "get": {"parameters": [
                        {"name": "q", "in": "query", "type": "string"}
                    ]},
                },
            },
        }
        imp = SchemaImporter()
        result = imp._parse_swagger2(spec)
        assert result.format == "swagger2"
        assert len(result.endpoints) == 1

    def test_postman_parse(self) -> None:
        collection = {
            "info": {"name": "My API"},
            "item": [
                {"name": "Get Users", "request": {
                    "method": "GET",
                    "url": {"raw": "https://api.test.com/users", "query": [
                        {"key": "page", "value": "1"},
                    ]},
                }},
            ],
        }
        imp = SchemaImporter("https://api.test.com")
        result = imp._parse_postman(collection)
        assert result.format == "postman"
        assert len(result.endpoints) == 1
        assert result.endpoints[0].parameters[0]["name"] == "page"

    def test_forms_property(self) -> None:
        spec = {
            "openapi": "3.0.0",
            "info": {"title": "T"},
            "paths": {
                "/login": {"post": {"requestBody": {"content": {
                    "application/json": {"schema": {
                        "type": "object",
                        "properties": {"username": {"type": "string"}, "password": {"type": "string"}},
                    }}
                }}}},
            },
        }
        imp = SchemaImporter("https://app.test.com")
        result = imp._parse_openapi3(spec)
        forms = result.forms
        assert len(forms) == 1
        assert "username" in forms[0]["inputs"]

    def test_api_urls_property(self) -> None:
        spec = {
            "openapi": "3.0.0",
            "info": {"title": "T"},
            "servers": [{"url": "https://api.test.com"}],
            "paths": {"/health": {"get": {}}},
        }
        imp = SchemaImporter("https://api.test.com")
        result = imp._parse_openapi3(spec)
        assert len(result.api_urls) == 1
