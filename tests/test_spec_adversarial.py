"""Hostile and degenerate specifications.

A specification is untrusted input. These tests check that AegisAPI either
parses it safely or refuses it clearly, and in particular that it never reaches
the network, never executes anything, and never spends unbounded time or memory.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from aegisapi.core.exceptions import InvalidSpecificationError, SpecificationError
from aegisapi.discovery.normalisation import MAX_OPERATIONS
from aegisapi.discovery.openapi import OpenApi3Parser
from aegisapi.discovery.references import ReferenceResolver
from aegisapi.discovery.schemas import (
    MAX_PROPERTIES_PER_SCHEMA,
    SchemaSummariser,
    WarningCollector,
)
from aegisapi.discovery.service import discover_from_specification
from aegisapi.models.discovery import ScopeClassification, WarningCode
from aegisapi.models.endpoint import MAX_SCHEMA_DEPTH, SchemaKind
from conftest import make_target
from specs import write_json, write_text, write_yaml


def parse(document: dict[str, Any]) -> tuple[Any, WarningCollector]:
    """Parse an OpenAPI 3 document, returning the result and warnings."""
    warnings = WarningCollector()
    return OpenApi3Parser(document, warnings).parse(), warnings


def codes(warnings: WarningCollector) -> set[WarningCode]:
    """Warning codes raised."""
    return {warning.code for warning in warnings.warnings}


class TestNoNetworkAccess:
    def test_discovery_does_not_open_a_socket(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Make any socket use fail loudly. If a $ref or server URL were ever
        # fetched, this test would catch it.
        import socket

        def forbidden(*args: object, **kwargs: object) -> None:
            raise AssertionError("discovery must not open a network connection")

        monkeypatch.setattr(socket, "socket", forbidden)
        monkeypatch.setattr(socket, "create_connection", forbidden)
        monkeypatch.setattr(socket, "getaddrinfo", forbidden)

        document = {
            "openapi": "3.0.0",
            "servers": [{"url": "https://attacker.test/v1"}],
            "paths": {
                "/x": {
                    "get": {
                        "parameters": [{"$ref": "https://attacker.test/p.json#/P"}],
                        "responses": {
                            "200": {
                                "description": "ok",
                                "content": {
                                    "application/json": {
                                        "schema": {"$ref": "http://169.254.169.254/meta"}
                                    }
                                },
                            }
                        },
                    }
                }
            },
            "components": {
                "securitySchemes": {
                    "oidc": {
                        "type": "openIdConnect",
                        "openIdConnectUrl": "https://attacker.test/.well-known/openid-configuration",
                    }
                }
            },
        }
        path = write_json(tmp_path / "spec.json", document)

        result = discover_from_specification(path, target=make_target())

        assert result.endpoint_count == 1
        assert WarningCode.EXTERNAL_REFERENCE in {w.code for w in result.warnings}

    def test_external_reference_shapes_are_all_reported(self, tmp_path: Path) -> None:
        resolver = ReferenceResolver({})
        for ref in (
            "https://evil.test/a.json#/X",
            "//evil.test/a.json#/X",
            "file:///etc/passwd",
            "spec2.yaml#/X",
        ):
            assert resolver.resolve(ref).value is None


class TestDegenerateDocuments:
    def test_path_with_no_operations(self) -> None:
        parsed, warnings = parse({"openapi": "3.0.0", "paths": {"/x": {}}})

        assert parsed.endpoints == []
        assert WarningCode.NO_OPERATIONS in codes(warnings)

    @pytest.mark.parametrize("value", [None, 7, "text", []])
    def test_path_item_of_the_wrong_type(self, value: object) -> None:
        parsed, warnings = parse({"openapi": "3.0.0", "paths": {"/x": value}})

        assert parsed.endpoints == []
        if value is not None:
            assert WarningCode.MALFORMED_SECTION in codes(warnings)

    @pytest.mark.parametrize("value", [7, "text", []])
    def test_operation_of_the_wrong_type(self, value: object) -> None:
        parsed, warnings = parse({"openapi": "3.0.0", "paths": {"/x": {"get": value}}})

        assert parsed.endpoints == []
        assert WarningCode.MALFORMED_SECTION in codes(warnings)

    def test_malformed_components_section(self) -> None:
        document = {
            "openapi": "3.0.0",
            "components": {"securitySchemes": "nope"},
            "paths": {},
        }
        parsed, warnings = parse(document)

        assert parsed.security_schemes == []
        assert WarningCode.MALFORMED_SECTION in codes(warnings)

    def test_malformed_servers_section(self) -> None:
        parsed, warnings = parse({"openapi": "3.0.0", "servers": "nope", "paths": {}})

        assert parsed.servers == []
        assert WarningCode.MALFORMED_SECTION in codes(warnings)

    def test_server_entry_without_a_url(self) -> None:
        parsed, warnings = parse(
            {"openapi": "3.0.0", "servers": [{"description": "no url"}], "paths": {}}
        )

        assert parsed.servers == []
        assert WarningCode.MALFORMED_SECTION in codes(warnings)

    def test_unusual_but_legal_paths_are_kept(self) -> None:
        document = {
            "openapi": "3.0.0",
            "paths": {
                "/": {"get": {"operationId": "root"}},
                "/a~b": {"get": {"operationId": "tilde"}},
                "/a/b/{c}/{d}": {"get": {"operationId": "nested"}},
            },
        }
        parsed, _ = parse(document)

        assert len(parsed.endpoints) == 3
        # The pointer escapes '/' and '~' per RFC 6901.
        pointers = {endpoint.source_pointer for endpoint in parsed.endpoints}
        assert "#/paths/~1a~0b/get" in pointers

    def test_duplicate_method_keys_cannot_occur_in_json(self, tmp_path: Path) -> None:
        # JSON objects with a repeated key keep the last value; the inventory
        # must still contain exactly one operation for that method and path.
        path = write_text(
            tmp_path / "spec.json",
            '{"openapi":"3.0.0","paths":{"/x":{"get":{"operationId":"a"},'
            '"get":{"operationId":"b"}}}}',
        )

        result = discover_from_specification(path, target=make_target())

        assert result.endpoint_count == 1
        assert result.endpoints[0].endpoint.operation_id == "b"

    def test_extremely_long_path_is_handled(self, tmp_path: Path) -> None:
        long_path = "/" + "/".join(f"segment{index}" for index in range(200))
        path = write_json(
            tmp_path / "spec.json",
            {"openapi": "3.0.0", "paths": {long_path: {"get": {"operationId": "deep"}}}},
        )

        result = discover_from_specification(path, target=make_target())

        assert result.endpoint_count == 1
        # Too long to form a usable URL, so it is unresolved rather than allowed.
        assert result.endpoints[0].classification in {
            ScopeClassification.IN_SCOPE,
            ScopeClassification.UNRESOLVED,
        }

    def test_many_operations_are_capped(self) -> None:
        paths = {
            f"/resource{index}": {"get": {"operationId": f"op{index}"}}
            for index in range(MAX_OPERATIONS + 10)
        }
        parsed, warnings = parse({"openapi": "3.0.0", "paths": paths})

        assert len(parsed.endpoints) <= MAX_OPERATIONS
        assert WarningCode.UNSUPPORTED_FEATURE in codes(warnings)


class TestSchemaBounds:
    def test_deeply_nested_schema_is_truncated_not_followed(self) -> None:
        node: dict[str, Any] = {"type": "string"}
        for _ in range(MAX_SCHEMA_DEPTH + 5):
            node = {"type": "object", "properties": {"child": node}}

        warnings = WarningCollector()
        summariser = SchemaSummariser(ReferenceResolver({}), warnings)
        summary = summariser.summarise(node, pointer="#/x")

        assert summary is not None
        depth = 0
        current = summary
        while current.properties.get("child") is not None:
            current = current.properties["child"]
            depth += 1
        assert depth <= MAX_SCHEMA_DEPTH
        assert WarningCode.SCHEMA_TRUNCATED in codes(warnings)

    def test_self_referential_schema_terminates(self) -> None:
        document = {"components": {"schemas": {"Node": {}}}}
        document["components"]["schemas"]["Node"] = {
            "type": "object",
            "properties": {"next": {"$ref": "#/components/schemas/Node"}},
        }
        warnings = WarningCollector()
        summariser = SchemaSummariser(ReferenceResolver(document), warnings)

        summary = summariser.summarise({"$ref": "#/components/schemas/Node"}, pointer="#/x")

        assert summary is not None
        assert summary.properties["next"].kind is SchemaKind.CIRCULAR
        assert WarningCode.CIRCULAR_REFERENCE in codes(warnings)

    def test_mutually_recursive_schemas_terminate(self) -> None:
        document = {
            "components": {
                "schemas": {
                    "A": {
                        "type": "object",
                        "properties": {"b": {"$ref": "#/components/schemas/B"}},
                    },
                    "B": {
                        "type": "object",
                        "properties": {"a": {"$ref": "#/components/schemas/A"}},
                    },
                }
            }
        }
        warnings = WarningCollector()
        summariser = SchemaSummariser(ReferenceResolver(document), warnings)

        summary = summariser.summarise({"$ref": "#/components/schemas/A"}, pointer="#/x")

        assert summary is not None
        assert summary.properties["b"].properties["a"].kind is SchemaKind.CIRCULAR

    def test_many_properties_are_capped(self) -> None:
        node = {
            "type": "object",
            "properties": {
                f"field{index}": {"type": "string"}
                for index in range(MAX_PROPERTIES_PER_SCHEMA + 50)
            },
        }
        warnings = WarningCollector()
        summariser = SchemaSummariser(ReferenceResolver({}), warnings)

        summary = summariser.summarise(node, pointer="#/x")

        assert summary is not None
        assert len(summary.properties) == MAX_PROPERTIES_PER_SCHEMA
        assert WarningCode.SCHEMA_TRUNCATED in codes(warnings)

    @pytest.mark.parametrize("node", [7, "text", ["a"]])
    def test_schema_of_the_wrong_type_is_reported(self, node: object) -> None:
        warnings = WarningCollector()
        summariser = SchemaSummariser(ReferenceResolver({}), warnings)

        summary = summariser.summarise(node, pointer="#/x")

        assert summary is not None
        assert summary.kind is SchemaKind.EMPTY
        assert WarningCode.MALFORMED_SECTION in codes(warnings)

    def test_boolean_schema_is_accepted(self) -> None:
        summariser = SchemaSummariser(ReferenceResolver({}), WarningCollector())

        assert summariser.summarise(True, pointer="#/x").kind is SchemaKind.EMPTY

    def test_absent_schema_stays_absent(self) -> None:
        summariser = SchemaSummariser(ReferenceResolver({}), WarningCollector())

        assert summariser.summarise(None, pointer="#/x") is None

    def test_composition_branches_are_summarised(self) -> None:
        node = {
            "allOf": [
                {"type": "object", "properties": {"a": {"type": "string"}}},
                {"type": "object", "required": ["b"]},
            ]
        }
        summariser = SchemaSummariser(ReferenceResolver({}), WarningCollector())

        summary = summariser.summarise(node, pointer="#/x")

        assert summary is not None
        assert summary.composition == "allOf"
        assert len(summary.composed_of) == 2

    def test_malformed_composition_is_reported(self) -> None:
        warnings = WarningCollector()
        summariser = SchemaSummariser(ReferenceResolver({}), warnings)

        summariser.summarise({"anyOf": "nope"}, pointer="#/x")

        assert WarningCode.MALFORMED_SECTION in codes(warnings)

    def test_enum_values_are_rendered_safely(self) -> None:
        summariser = SchemaSummariser(ReferenceResolver({}), WarningCollector())

        summary = summariser.summarise({"type": "string", "enum": ["a", 2, None]}, pointer="#/x")

        assert summary is not None
        assert summary.enum_values == ["a", "2", "None"]


class TestEndToEndRobustness:
    @pytest.mark.parametrize(
        "body",
        [
            "openapi: 3.0.0\npaths:\n  /x:\n    get:\n      responses: null\n",
            'openapi: "3.0.0"\npaths:\n  /x: null\n',
            "openapi: 3.1.0\npaths:\n  /x:\n    get:\n      security: {}\n",
        ],
    )
    def test_odd_but_parseable_documents_do_not_crash(self, tmp_path: Path, body: str) -> None:
        path = write_text(tmp_path / "spec.yaml", body)

        result = discover_from_specification(path, target=make_target())

        assert result.schema_version == 1

    def test_unicode_content_is_handled(self, tmp_path: Path) -> None:
        document = {
            "openapi": "3.0.0",
            "info": {"title": "Ünïcödé API 🌍", "version": "1.0"},
            "paths": {"/café": {"get": {"summary": "Grüße"}}},
        }
        path = write_yaml(tmp_path / "spec.yaml", document)

        result = discover_from_specification(path, target=make_target())

        assert result.specification.title == "Ünïcödé API 🌍"
        assert result.endpoint_count == 1

    def test_specification_errors_share_one_exit_code(self, tmp_path: Path) -> None:
        for body in ("{not json", "", '{"openapi": "9.9"}'):
            path = write_text(tmp_path / "spec.json", body)
            with pytest.raises(SpecificationError) as excinfo:
                discover_from_specification(path, target=make_target())
            assert excinfo.value.exit_code == 8

    def test_a_directory_is_not_parsed_as_a_specification(self, tmp_path: Path) -> None:
        directory = tmp_path / "spec.json"
        directory.mkdir()

        with pytest.raises(SpecificationError):
            discover_from_specification(directory, target=make_target())

    def test_binary_file_is_refused(self, tmp_path: Path) -> None:
        path = tmp_path / "spec.json"
        path.write_bytes(bytes(range(256)))

        with pytest.raises(InvalidSpecificationError):
            discover_from_specification(path, target=make_target())
