"""Normalising OpenAPI 3.x and Swagger 2.0 documents into an endpoint inventory."""

from __future__ import annotations

from typing import Any

import pytest

from aegisapi.discovery.normalisation import ParsedSpecification, deduplicate_endpoints
from aegisapi.discovery.openapi import OpenApi3Parser
from aegisapi.discovery.references import (
    ReferenceOutcome,
    ReferenceResolver,
    split_pointer,
    unescape_pointer_token,
)
from aegisapi.discovery.schemas import WarningCollector
from aegisapi.discovery.swagger import Swagger2Parser
from aegisapi.models.discovery import WarningCode
from aegisapi.models.endpoint import (
    Endpoint,
    HttpMethod,
    ParameterLocation,
    ParameterSource,
    SchemaKind,
    SecurityPosture,
    SecuritySchemeType,
)
from specs import FULL_OPENAPI_30, OPENAPI_31, SWAGGER_20, spec_copy


def parse_openapi(document: dict[str, Any]) -> tuple[ParsedSpecification, WarningCollector]:
    """Parse an OpenAPI 3 document, returning the result and its warnings."""
    warnings = WarningCollector()
    return OpenApi3Parser(document, warnings).parse(), warnings


def parse_swagger(document: dict[str, Any]) -> tuple[ParsedSpecification, WarningCollector]:
    """Parse a Swagger 2 document, returning the result and its warnings."""
    warnings = WarningCollector()
    return Swagger2Parser(document, warnings).parse(), warnings


def find(parsed: ParsedSpecification, key: str) -> Endpoint:
    """Fetch one endpoint by its ``METHOD /path`` key."""
    for endpoint in parsed.endpoints:
        if endpoint.key == key:
            return endpoint
    raise AssertionError(f"no endpoint {key!r} in {[e.key for e in parsed.endpoints]}")


def codes(warnings: WarningCollector) -> set[WarningCode]:
    """The set of warning codes raised."""
    return {warning.code for warning in warnings.warnings}


class TestOpenApiMetadata:
    def test_document_metadata_is_recorded(self) -> None:
        parsed, _ = parse_openapi(FULL_OPENAPI_30)

        assert parsed.title == "Acme Orders API"
        assert parsed.api_version == "2.1"
        assert parsed.description == "Order management."
        assert parsed.servers == ["https://api.acme.test/v1"]

    def test_all_operations_are_found(self) -> None:
        parsed, _ = parse_openapi(FULL_OPENAPI_30)

        assert sorted(endpoint.key for endpoint in parsed.endpoints) == [
            "DELETE /users/{userId}",
            "GET /admin/audit",
            "GET /health",
            "GET /users",
            "GET /users/{userId}",
            "GET /users/{userId}/orders",
            "POST /users",
        ]

    def test_operation_fields_are_recorded(self) -> None:
        parsed, _ = parse_openapi(FULL_OPENAPI_30)
        endpoint = find(parsed, "GET /users")

        assert endpoint.method is HttpMethod.GET
        assert endpoint.operation_id == "listUsers"
        assert endpoint.summary == "List users"
        assert endpoint.description == "Returns a page of users."
        assert endpoint.tags == ["users"]
        assert endpoint.deprecated is False
        assert endpoint.source_pointer == "#/paths/~1users/get"

    def test_absent_fields_stay_absent(self) -> None:
        parsed, _ = parse_openapi(FULL_OPENAPI_30)
        endpoint = find(parsed, "GET /admin/audit")

        # The document says nothing about these, so neither does the inventory.
        assert endpoint.summary is None
        assert endpoint.description is None
        assert endpoint.tags == []
        assert endpoint.deprecated is None
        assert endpoint.request_body is None

    def test_minimal_operation_invents_nothing(self) -> None:
        document = {
            "openapi": "3.0.0",
            "paths": {"/bare": {"get": {}}},
        }
        parsed, _ = parse_openapi(document)
        endpoint = find(parsed, "GET /bare")

        assert endpoint.operation_id is None
        assert endpoint.parameters == []
        assert endpoint.responses == []
        assert endpoint.declared_security.posture is SecurityPosture.NOT_DECLARED

    def test_31_type_list_is_preserved(self) -> None:
        parsed, _ = parse_openapi(OPENAPI_31)
        endpoint = find(parsed, "GET /items")
        cursor = endpoint.parameters[0]

        assert cursor.value_schema is not None
        assert cursor.value_schema.type == "string|null"


class TestParameterInheritance:
    def test_path_level_parameters_are_inherited(self) -> None:
        parsed, _ = parse_openapi(FULL_OPENAPI_30)
        endpoint = find(parsed, "GET /users")

        names = {parameter.name for parameter in endpoint.parameters}
        assert names == {"X-Request-Id", "limit"}

    def test_inherited_parameters_record_their_source(self) -> None:
        parsed, _ = parse_openapi(FULL_OPENAPI_30)
        endpoint = find(parsed, "GET /users")
        by_name = {parameter.name: parameter for parameter in endpoint.parameters}

        assert by_name["X-Request-Id"].source is ParameterSource.PATH_ITEM
        assert by_name["limit"].source is ParameterSource.OPERATION

    def test_operation_overrides_an_inherited_parameter(self) -> None:
        parsed, _ = parse_openapi(FULL_OPENAPI_30)
        endpoint = find(parsed, "GET /users/{userId}")
        by_name = {parameter.name: parameter for parameter in endpoint.parameters}

        # The path item declares X-Request-Id as optional; this operation
        # redeclares it as required, and the override wins.
        assert by_name["X-Request-Id"].required is True
        assert by_name["X-Request-Id"].source is ParameterSource.OPERATION
        assert by_name["X-Request-Id"].description == "Overridden to required"
        # The non-overridden inherited parameter survives.
        assert by_name["userId"].source is ParameterSource.PATH_ITEM
        assert len(endpoint.parameters) == 2

    def test_override_requires_the_same_location(self) -> None:
        document = {
            "openapi": "3.0.0",
            "paths": {
                "/x": {
                    "parameters": [{"name": "token", "in": "header"}],
                    "get": {"parameters": [{"name": "token", "in": "query"}]},
                }
            },
        }
        parsed, _ = parse_openapi(document)
        endpoint = find(parsed, "GET /x")

        # Same name, different location: two distinct parameters.
        assert len(endpoint.parameters) == 2
        assert {parameter.location for parameter in endpoint.parameters} == {
            ParameterLocation.HEADER,
            ParameterLocation.QUERY,
        }

    def test_duplicate_parameter_at_one_level_is_reported(self) -> None:
        document = {
            "openapi": "3.0.0",
            "paths": {
                "/x": {
                    "get": {
                        "parameters": [
                            {"name": "limit", "in": "query", "description": "first"},
                            {"name": "limit", "in": "query", "description": "second"},
                        ]
                    }
                }
            },
        }
        parsed, warnings = parse_openapi(document)
        endpoint = find(parsed, "GET /x")

        assert len(endpoint.parameters) == 1
        assert endpoint.parameters[0].description == "first"
        assert WarningCode.MALFORMED_SECTION in codes(warnings)

    def test_parameter_locations_are_normalised(self) -> None:
        document = {
            "openapi": "3.0.0",
            "paths": {
                "/x/{id}": {
                    "get": {
                        "parameters": [
                            {"name": "id", "in": "path", "required": True},
                            {"name": "q", "in": "query"},
                            {"name": "X-H", "in": "header"},
                            {"name": "session", "in": "cookie"},
                        ]
                    }
                }
            },
        }
        parsed, _ = parse_openapi(document)
        endpoint = find(parsed, "GET /x/{id}")

        assert {parameter.location for parameter in endpoint.parameters} == {
            ParameterLocation.PATH,
            ParameterLocation.QUERY,
            ParameterLocation.HEADER,
            ParameterLocation.COOKIE,
        }

    def test_unknown_parameter_location_is_skipped_and_reported(self) -> None:
        document = {
            "openapi": "3.0.0",
            "paths": {"/x": {"get": {"parameters": [{"name": "weird", "in": "body"}]}}},
        }
        parsed, warnings = parse_openapi(document)

        assert find(parsed, "GET /x").parameters == []
        assert WarningCode.MALFORMED_SECTION in codes(warnings)

    def test_parameter_without_name_or_location_is_skipped(self) -> None:
        document = {
            "openapi": "3.0.0",
            "paths": {"/x": {"get": {"parameters": [{"schema": {"type": "string"}}]}}},
        }
        parsed, warnings = parse_openapi(document)

        assert find(parsed, "GET /x").parameters == []
        assert WarningCode.MALFORMED_SECTION in codes(warnings)


class TestRequestAndResponseSchemas:
    def test_request_body_content_and_schema(self) -> None:
        parsed, _ = parse_openapi(FULL_OPENAPI_30)
        body = find(parsed, "POST /users").request_body

        assert body is not None
        assert body.required is True
        assert body.description == "The user to create"
        assert body.content_types == ("application/json",)
        schema = body.content[0].value_schema
        assert schema is not None
        assert schema.name == "User"
        assert set(schema.required) == {"id", "email"}
        assert "email" in schema.property_names()

    def test_response_status_codes_and_content(self) -> None:
        parsed, _ = parse_openapi(FULL_OPENAPI_30)
        endpoint = find(parsed, "GET /users")
        by_status = {response.status_code: response for response in endpoint.responses}

        assert set(by_status) == {"200", "default"}
        ok = by_status["200"]
        assert ok.description == "A page of users"
        assert ok.content_types == ("application/json",)
        assert ok.header_names == ["X-Total-Count"]

    def test_array_response_items_are_summarised(self) -> None:
        parsed, _ = parse_openapi(FULL_OPENAPI_30)
        endpoint = find(parsed, "GET /users")
        schema = endpoint.responses[0].content[0].value_schema

        assert schema is not None
        assert schema.type == "array"
        assert schema.items is not None
        assert schema.items.name == "User"

    def test_responses_are_not_invented(self) -> None:
        document = {"openapi": "3.0.0", "paths": {"/x": {"get": {"operationId": "x"}}}}
        parsed, _ = parse_openapi(document)

        assert find(parsed, "GET /x").responses == []

    def test_schema_names_collects_every_reference(self) -> None:
        parsed, _ = parse_openapi(FULL_OPENAPI_30)

        assert find(parsed, "GET /users/{userId}/orders").schema_names() == {"Order", "User"}

    def test_malformed_sections_are_reported_not_guessed(self) -> None:
        document = {
            "openapi": "3.0.0",
            "paths": {
                "/x": {
                    "get": {
                        "parameters": "not-a-list",
                        "responses": "not-an-object",
                        "requestBody": "not-an-object",
                    }
                }
            },
        }
        parsed, warnings = parse_openapi(document)
        endpoint = find(parsed, "GET /x")

        assert endpoint.parameters == []
        assert endpoint.responses == []
        assert endpoint.request_body is None
        assert WarningCode.MALFORMED_SECTION in codes(warnings)


class TestReferences:
    def test_local_reference_is_resolved(self) -> None:
        parsed, _ = parse_openapi(FULL_OPENAPI_30)
        schema = find(parsed, "POST /users").request_body.content[0].value_schema

        assert schema is not None
        assert schema.ref == "#/components/schemas/User"
        assert schema.kind is SchemaKind.RESOLVED

    def test_circular_reference_is_detected_not_followed(self) -> None:
        parsed, collected = parse_openapi(FULL_OPENAPI_30)
        warnings = collected
        schema = find(parsed, "GET /users/{userId}").responses[0].content[0].value_schema

        assert schema is not None
        manager = schema.properties["manager"]
        assert manager.kind is SchemaKind.CIRCULAR
        assert WarningCode.CIRCULAR_REFERENCE in codes(warnings)

    def test_external_reference_is_reported_and_never_fetched(self) -> None:
        document = {
            "openapi": "3.0.0",
            "paths": {
                "/x": {
                    "get": {
                        "responses": {
                            "200": {
                                "description": "ok",
                                "content": {
                                    "application/json": {
                                        "schema": {"$ref": "https://evil.test/schema.json#/User"}
                                    }
                                },
                            }
                        }
                    }
                }
            },
        }
        parsed, warnings = parse_openapi(document)
        schema = find(parsed, "GET /x").responses[0].content[0].value_schema

        assert schema is not None
        assert schema.kind is SchemaKind.UNRESOLVED_EXTERNAL
        assert WarningCode.EXTERNAL_REFERENCE in codes(warnings)

    @pytest.mark.parametrize(
        "ref",
        [
            "other.yaml#/components/schemas/User",
            "file:///etc/passwd",
            "http://169.254.169.254/latest/meta-data",
            "../shared/models.json#/User",
        ],
    )
    def test_every_external_reference_shape_is_refused(self, ref: str) -> None:
        resolver = ReferenceResolver({"components": {}})

        resolution = resolver.resolve(ref)

        assert resolution.outcome is ReferenceOutcome.EXTERNAL
        assert resolution.value is None

    def test_missing_local_reference_is_reported(self) -> None:
        document = {
            "openapi": "3.0.0",
            "paths": {
                "/x": {
                    "get": {
                        "responses": {
                            "200": {
                                "description": "ok",
                                "content": {
                                    "application/json": {
                                        "schema": {"$ref": "#/components/schemas/Absent"}
                                    }
                                },
                            }
                        }
                    }
                }
            },
        }
        parsed, warnings = parse_openapi(document)
        schema = find(parsed, "GET /x").responses[0].content[0].value_schema

        assert schema is not None
        assert schema.kind is SchemaKind.UNRESOLVED_MISSING
        assert WarningCode.MISSING_REFERENCE in codes(warnings)

    def test_path_item_reference_is_resolved(self) -> None:
        document = {
            "openapi": "3.0.0",
            "paths": {"/a": {"$ref": "#/components/pathItems/shared"}},
            "components": {
                "pathItems": {"shared": {"get": {"operationId": "shared", "responses": {}}}}
            },
        }
        parsed, _ = parse_openapi(document)

        assert find(parsed, "GET /a").operation_id == "shared"

    def test_parameter_reference_is_resolved(self) -> None:
        document = {
            "openapi": "3.0.0",
            "paths": {"/x": {"get": {"parameters": [{"$ref": "#/components/parameters/Limit"}]}}},
            "components": {
                "parameters": {
                    "Limit": {"name": "limit", "in": "query", "schema": {"type": "integer"}}
                }
            },
        }
        parsed, _ = parse_openapi(document)
        endpoint = find(parsed, "GET /x")

        assert [parameter.name for parameter in endpoint.parameters] == ["limit"]

    def test_response_reference_is_resolved(self) -> None:
        document = {
            "openapi": "3.0.0",
            "paths": {"/x": {"get": {"responses": {"404": {"$ref": "#/components/responses/NF"}}}}},
            "components": {"responses": {"NF": {"description": "Not found"}}},
        }
        parsed, _ = parse_openapi(document)

        assert find(parsed, "GET /x").responses[0].description == "Not found"

    def test_reference_chain_is_followed(self) -> None:
        resolver = ReferenceResolver(
            {
                "a": {"$ref": "#/b"},
                "b": {"$ref": "#/c"},
                "c": {"type": "string"},
            }
        )

        assert resolver.resolve("#/a").value == {"type": "string"}

    def test_mutually_circular_chain_is_caught(self) -> None:
        resolver = ReferenceResolver({"a": {"$ref": "#/b"}, "b": {"$ref": "#/a"}})

        assert resolver.resolve("#/a").outcome is ReferenceOutcome.CIRCULAR

    @pytest.mark.parametrize("ref", ["", "#invalid", "#not-a-pointer"])
    def test_malformed_references_are_refused(self, ref: str) -> None:
        resolver = ReferenceResolver({})

        assert resolver.resolve(ref).outcome in {
            ReferenceOutcome.MALFORMED,
            ReferenceOutcome.EXTERNAL,
        }

    def test_pointer_escaping_follows_rfc6901(self) -> None:
        assert unescape_pointer_token("a~1b") == "a/b"
        assert unescape_pointer_token("a~0b") == "a~b"
        # ~01 decodes to ~1, not to /
        assert unescape_pointer_token("a~01b") == "a~1b"
        assert split_pointer("#/paths/~1users/get") == ["paths", "/users", "get"]

    def test_list_index_in_a_pointer(self) -> None:
        resolver = ReferenceResolver({"items": [{"type": "string"}, {"type": "integer"}]})

        assert resolver.resolve("#/items/1").value == {"type": "integer"}
        assert resolver.resolve("#/items/9").outcome is ReferenceOutcome.MISSING
        assert resolver.resolve("#/items/x").outcome is ReferenceOutcome.MALFORMED


class TestDeclaredSecurity:
    def test_global_requirement_is_inherited(self) -> None:
        parsed, _ = parse_openapi(FULL_OPENAPI_30)
        declared = find(parsed, "GET /users").declared_security

        assert declared.posture is SecurityPosture.INHERITED_GLOBAL
        assert declared.scheme_names == ("bearerAuth",)
        assert declared.permits_anonymous is False

    def test_operation_override_replaces_the_global_requirement(self) -> None:
        parsed, _ = parse_openapi(FULL_OPENAPI_30)
        declared = find(parsed, "DELETE /users/{userId}").declared_security

        assert declared.posture is SecurityPosture.OPERATION_OVERRIDE
        # One alternative requiring both schemes: an AND, not two options.
        assert len(declared.alternatives) == 1
        assert set(declared.scheme_names) == {"bearerAuth", "adminKey"}

    def test_empty_operation_security_is_explicitly_optional(self) -> None:
        parsed, _ = parse_openapi(FULL_OPENAPI_30)
        declared = find(parsed, "GET /health").declared_security

        assert declared.posture is SecurityPosture.EXPLICITLY_OPTIONAL
        assert declared.permits_anonymous is True

    def test_silence_is_recorded_as_not_declared(self) -> None:
        document = {"openapi": "3.0.0", "paths": {"/x": {"get": {}}}}
        parsed, _ = parse_openapi(document)
        declared = find(parsed, "GET /x").declared_security

        assert declared.posture is SecurityPosture.NOT_DECLARED
        assert declared.has_usable_metadata is False
        # Absence of metadata is not a claim that the endpoint is unprotected.
        assert declared.permits_anonymous is False

    def test_alternatives_are_an_or_of_ands(self) -> None:
        document = {
            "openapi": "3.0.0",
            "components": {
                "securitySchemes": {
                    "a": {"type": "http", "scheme": "bearer"},
                    "b": {"type": "apiKey", "in": "header", "name": "X-B"},
                }
            },
            "paths": {"/x": {"get": {"security": [{"a": []}, {"b": []}]}}},
        }
        parsed, _ = parse_openapi(document)
        declared = find(parsed, "GET /x").declared_security

        assert len(declared.alternatives) == 2
        assert declared.posture is SecurityPosture.OPERATION_OVERRIDE

    def test_anonymous_alternative_among_others_permits_anonymous(self) -> None:
        document = {
            "openapi": "3.0.0",
            "components": {"securitySchemes": {"a": {"type": "http", "scheme": "bearer"}}},
            "paths": {"/x": {"get": {"security": [{"a": []}, {}]}}},
        }
        parsed, _ = parse_openapi(document)
        declared = find(parsed, "GET /x").declared_security

        assert declared.permits_anonymous is True
        assert declared.posture is SecurityPosture.OPERATION_OVERRIDE

    def test_undefined_scheme_is_recorded_as_insufficient_metadata(self) -> None:
        document = {
            "openapi": "3.0.0",
            "paths": {"/x": {"get": {"security": [{"ghostAuth": []}]}}},
        }
        parsed, warnings = parse_openapi(document)
        declared = find(parsed, "GET /x").declared_security

        assert declared.undefined_schemes == ["ghostAuth"]
        assert WarningCode.UNDEFINED_SECURITY_SCHEME in codes(warnings)

    def test_scopes_are_recorded(self) -> None:
        document = {
            "openapi": "3.0.0",
            "components": {"securitySchemes": {"oauth": {"type": "oauth2", "flows": {}}}},
            "paths": {"/x": {"get": {"security": [{"oauth": ["read", "write"]}]}}},
        }
        parsed, _ = parse_openapi(document)
        declared = find(parsed, "GET /x").declared_security

        assert declared.alternatives[0].schemes[0].scopes == ["read", "write"]

    def test_declared_schemes_are_extracted(self) -> None:
        parsed, _ = parse_openapi(FULL_OPENAPI_30)
        by_name = {scheme.name: scheme for scheme in parsed.security_schemes}

        assert by_name["bearerAuth"].type is SecuritySchemeType.HTTP
        assert by_name["bearerAuth"].scheme == "bearer"
        assert by_name["bearerAuth"].bearer_format == "JWT"
        assert by_name["adminKey"].type is SecuritySchemeType.API_KEY
        assert by_name["adminKey"].parameter_name == "X-Admin-Key"
        assert by_name["adminKey"].parameter_location == "header"
        assert by_name["oauth"].type is SecuritySchemeType.OAUTH2
        assert by_name["oauth"].flows == ["authorizationCode"]
        assert by_name["oauth"].scopes == {"read": "Read access", "write": "Write access"}

    def test_openid_connect_url_is_recorded_but_not_fetched(self) -> None:
        document = {
            "openapi": "3.0.0",
            "components": {
                "securitySchemes": {
                    "oidc": {
                        "type": "openIdConnect",
                        "openIdConnectUrl": "https://auth.test/.well-known/openid-configuration",
                    }
                }
            },
            "paths": {},
        }
        parsed, _ = parse_openapi(document)
        scheme = parsed.security_schemes[0]

        assert scheme.type is SecuritySchemeType.OPEN_ID_CONNECT
        assert scheme.open_id_connect_url is not None
        # Recorded verbatim; nothing contacted it.
        assert scheme.open_id_connect_url.startswith("https://auth.test")

    def test_unknown_scheme_type_is_reported(self) -> None:
        document = {
            "openapi": "3.0.0",
            "components": {"securitySchemes": {"odd": {"type": "magic"}}},
            "paths": {},
        }
        parsed, warnings = parse_openapi(document)

        assert parsed.security_schemes[0].type is SecuritySchemeType.UNKNOWN
        assert parsed.security_schemes[0].raw_type == "magic"
        assert WarningCode.UNKNOWN_SECURITY_SCHEME_TYPE in codes(warnings)

    def test_malformed_security_value_is_reported(self) -> None:
        document = {"openapi": "3.0.0", "paths": {"/x": {"get": {"security": "nope"}}}}
        parsed, warnings = parse_openapi(document)

        assert find(parsed, "GET /x").declared_security.posture is (SecurityPosture.NOT_DECLARED)
        assert WarningCode.MALFORMED_SECTION in codes(warnings)


class TestDuplicatesAndLimits:
    def test_path_item_reference_yields_an_endpoint_per_path(self) -> None:
        # Two path keys sharing one path item are two distinct operations, not
        # a duplicate: they are reachable at different URLs.
        document = {
            "openapi": "3.0.0",
            "paths": {
                "/a": {"get": {"operationId": "first"}},
                "/b": {"$ref": "#/paths/~1a"},
            },
        }
        parsed, _ = parse_openapi(document)

        assert sorted(endpoint.key for endpoint in parsed.endpoints) == ["GET /a", "GET /b"]

    def test_duplicate_operation_keeps_the_first_and_warns(self) -> None:
        parsed, _ = parse_openapi(
            {"openapi": "3.0.0", "paths": {"/a": {"get": {"operationId": "first"}}}}
        )
        collector = WarningCollector()

        unique = deduplicate_endpoints([*parsed.endpoints, *parsed.endpoints], warnings=collector)

        assert len(unique) == 1
        assert unique[0].operation_id == "first"
        assert WarningCode.DUPLICATE_OPERATION in codes(collector)

    def test_empty_paths_is_reported(self) -> None:
        parsed, warnings = parse_openapi({"openapi": "3.0.0", "paths": {}})

        assert parsed.endpoints == []
        assert WarningCode.NO_OPERATIONS in codes(warnings)

    def test_missing_paths_section_is_reported(self) -> None:
        parsed, warnings = parse_openapi({"openapi": "3.0.0"})

        assert parsed.endpoints == []
        assert WarningCode.NO_OPERATIONS in codes(warnings)

    def test_malformed_paths_section_is_reported(self) -> None:
        parsed, warnings = parse_openapi({"openapi": "3.0.0", "paths": ["/a"]})

        assert parsed.endpoints == []
        assert WarningCode.MALFORMED_SECTION in codes(warnings)

    def test_non_operation_keys_are_ignored(self) -> None:
        document = {
            "openapi": "3.0.0",
            "paths": {
                "/x": {
                    "summary": "a path summary",
                    "x-internal": True,
                    "get": {"operationId": "x"},
                }
            },
        }
        parsed, _ = parse_openapi(document)

        assert [endpoint.key for endpoint in parsed.endpoints] == ["GET /x"]

    def test_warning_collector_caps_and_deduplicates(self) -> None:
        collector = WarningCollector(limit=3)
        for index in range(10):
            collector.add(WarningCode.MALFORMED_SECTION, f"problem {index}")
        collector.add(WarningCode.MALFORMED_SECTION, "problem 0")

        assert len(collector.warnings) == 3
        assert collector.suppressed > 0


class TestSwagger:
    def test_metadata_and_server_are_built_from_parts(self) -> None:
        parsed, _ = parse_swagger(SWAGGER_20)

        assert parsed.title == "Legacy Acme API"
        # basePath belongs on the server, not on every path.
        assert parsed.servers == ["https://api.acme.test/v1"]

    def test_paths_are_recorded_as_declared(self) -> None:
        parsed, _ = parse_swagger(SWAGGER_20)

        assert sorted(endpoint.key for endpoint in parsed.endpoints) == [
            "GET /invoices",
            "GET /invoices/{invoiceId}",
            "POST /invoices",
            "POST /uploads",
        ]

    def test_multiple_schemes_produce_multiple_servers(self) -> None:
        document = spec_copy(SWAGGER_20)
        document["schemes"] = ["https", "http"]
        parsed, _ = parse_swagger(document)

        assert parsed.servers == [
            "https://api.acme.test/v1",
            "http://api.acme.test/v1",
        ]

    def test_missing_host_yields_a_relative_server(self) -> None:
        document = spec_copy(SWAGGER_20)
        document.pop("host")
        parsed, _ = parse_swagger(document)

        assert parsed.servers == ["/v1"]

    def test_missing_host_and_base_path_yields_no_server(self) -> None:
        document = spec_copy(SWAGGER_20)
        document.pop("host")
        document.pop("basePath")
        parsed, _ = parse_swagger(document)

        assert parsed.servers == []

    def test_scheme_less_host_is_recorded_without_inventing_one(self) -> None:
        document = spec_copy(SWAGGER_20)
        document.pop("schemes")
        parsed, _ = parse_swagger(document)

        assert parsed.servers == ["//api.acme.test/v1"]

    def test_body_parameter_becomes_a_request_body(self) -> None:
        parsed, _ = parse_swagger(SWAGGER_20)
        body = find(parsed, "POST /invoices").request_body

        assert body is not None
        assert body.required is True
        assert body.content_types == ("application/json",)
        assert body.content[0].value_schema is not None
        assert body.content[0].value_schema.name == "Invoice"
        # The body parameter is not also listed as an ordinary parameter.
        assert all(
            parameter.name != "body" for parameter in find(parsed, "POST /invoices").parameters
        )

    def test_form_data_becomes_a_request_body_object(self) -> None:
        parsed, _ = parse_swagger(SWAGGER_20)
        endpoint = find(parsed, "POST /uploads")

        assert endpoint.request_body is not None
        assert endpoint.request_body.content_types == ("multipart/form-data",)
        schema = endpoint.request_body.content[0].value_schema
        assert schema is not None
        assert set(schema.property_names()) == {"file", "note"}
        assert schema.required == ["file"]

    def test_form_data_parameters_are_still_listed(self) -> None:
        parsed, _ = parse_swagger(SWAGGER_20)
        endpoint = find(parsed, "POST /uploads")

        assert {parameter.location for parameter in endpoint.parameters} == {
            ParameterLocation.FORM_DATA
        }

    def test_parameter_type_is_lifted_into_a_schema(self) -> None:
        parsed, _ = parse_swagger(SWAGGER_20)
        endpoint = find(parsed, "GET /invoices")
        by_name = {parameter.name: parameter for parameter in endpoint.parameters}

        assert by_name["page"].value_schema is not None
        assert by_name["page"].value_schema.type == "integer"
        assert by_name["page"].value_schema.format == "int32"

    def test_path_level_inheritance_works(self) -> None:
        parsed, _ = parse_swagger(SWAGGER_20)
        endpoint = find(parsed, "GET /invoices")

        by_name = {parameter.name: parameter for parameter in endpoint.parameters}
        assert set(by_name) == {"X-Tenant", "page"}
        assert by_name["X-Tenant"].source is ParameterSource.PATH_ITEM
        assert by_name["X-Tenant"].required is True

    def test_produces_becomes_response_content_types(self) -> None:
        parsed, _ = parse_swagger(SWAGGER_20)
        response = find(parsed, "GET /invoices").responses[0]

        assert response.content_types == ("application/json",)
        assert response.header_names == ["X-Total-Count"]

    def test_definitions_reference_resolves(self) -> None:
        parsed, _ = parse_swagger(SWAGGER_20)
        schema = find(parsed, "GET /invoices/{invoiceId}").responses[0].content[0].value_schema

        assert schema is not None
        assert schema.name == "Invoice"
        assert schema.required == ["invoiceId"]

    def test_security_definitions_are_extracted(self) -> None:
        parsed, _ = parse_swagger(SWAGGER_20)
        by_name = {scheme.name: scheme for scheme in parsed.security_schemes}

        assert by_name["apiKeyHeader"].type is SecuritySchemeType.API_KEY
        assert by_name["apiKeyHeader"].parameter_name == "X-Api-Key"
        assert by_name["basicAuth"].type is SecuritySchemeType.BASIC
        assert by_name["basicAuth"].scheme == "basic"
        assert by_name["oauthLegacy"].type is SecuritySchemeType.OAUTH2
        assert by_name["oauthLegacy"].flows == ["implicit"]

    def test_global_and_operation_security(self) -> None:
        parsed, _ = parse_swagger(SWAGGER_20)

        assert find(parsed, "GET /invoices").declared_security.posture is (
            SecurityPosture.INHERITED_GLOBAL
        )
        assert find(parsed, "GET /invoices/{invoiceId}").declared_security.posture is (
            SecurityPosture.EXPLICITLY_OPTIONAL
        )

    def test_consumes_override_at_operation_level(self) -> None:
        parsed, _ = parse_swagger(SWAGGER_20)

        assert find(parsed, "POST /uploads").consumes == ["multipart/form-data"]
        assert find(parsed, "POST /invoices").consumes == ["application/json"]

    def test_second_body_parameter_is_reported(self) -> None:
        document = spec_copy(SWAGGER_20)
        document["paths"]["/invoices"]["post"]["parameters"].append(
            {"name": "other", "in": "body", "schema": {"type": "string"}}
        )
        parsed, warnings = parse_swagger(document)

        assert WarningCode.MALFORMED_SECTION in codes(warnings)
        body = find(parsed, "POST /invoices").request_body
        assert body is not None
        assert body.content[0].value_schema.name == "Invoice"

    def test_base_path_without_leading_slash_is_corrected(self) -> None:
        document = spec_copy(SWAGGER_20)
        document["basePath"] = "v2"
        parsed, warnings = parse_swagger(document)

        assert parsed.servers == ["https://api.acme.test/v2"]
        assert WarningCode.MALFORMED_SECTION in codes(warnings)

    def test_root_base_path_is_treated_as_empty(self) -> None:
        document = spec_copy(SWAGGER_20)
        document["basePath"] = "/"
        parsed, _ = parse_swagger(document)

        assert parsed.servers == ["https://api.acme.test"]
