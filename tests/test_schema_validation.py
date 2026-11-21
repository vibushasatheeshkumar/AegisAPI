"""Tests for M3 schema validation: schema_validator and the two checks.

Three groups:

1. :mod:`~aegisapi.testing.schema_validator` unit tests — pure function, no
   HTTP, covers every branch of validate_against_schema.
2. :class:`~aegisapi.testing.schema_validation.ResponseSchemaCheck` (SCHEMA-001)
   behavioural tests — fake transport, one request per case.
3. :class:`~aegisapi.testing.schema_validation.ResponseConformanceCheck` (SCHEMA-002)
   behavioural tests — same setup.
"""

from __future__ import annotations

import json

import pytest

from aegisapi.models.assessment import CheckCategory, CheckOutcome, FindingClass
from aegisapi.models.endpoint import MediaTypeSchema, ResponseSpec, SchemaSummary
from aegisapi.testing.schema_validation import (
    ResponseConformanceCheck,
    ResponseSchemaCheck,
    _bare_content_type,
    _find_response_spec,
    _has_response_schema,
    _is_json_content_type,
)
from aegisapi.testing.schema_validator import (
    MAX_VIOLATIONS,
    SchemaViolation,
    validate_against_schema,
)
from assessfix import (
    classified,
    discovery_result,
    make_client,
    make_config,
    operation,
    path_param,
    scoped_target,
)
from httpstub import FakeTransport, StubResponse


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def schema(**kwargs) -> SchemaSummary:
    """Build a SchemaSummary from keyword arguments."""
    return SchemaSummary(**kwargs)


def json_response(body: object, *, status: int = 200, truncated: bool = False) -> StubResponse:
    """A stub response that returns JSON."""
    encoded = json.dumps(body).encode()
    return StubResponse(
        status_code=status,
        headers=[("content-type", "application/json")],
        body=encoded,
        truncated=truncated,
    )


def run_check(check_id: str, endpoints, transport, *, auto_fixtures=None, budget=60):
    """Run a named check and return the assessment result."""
    target = scoped_target()
    config = make_config()
    client = make_client(target, config, transport)
    from aegisapi.testing import AssessmentEngine
    engine = AssessmentEngine(target=target, config=config)
    try:
        return engine.run(
            discovery=discovery_result([classified(ep) for ep in endpoints]),
            auto_fixtures=auto_fixtures or {},
            check_ids=[check_id],
            budget=budget,
            client=client,
        )
    finally:
        client.close()


def only(result, check_id: str):
    """Return the single result for one check, failing loudly if absent."""
    matches = [r for r in result.results if r.check_id == check_id]
    assert matches, f"no result for {check_id}"
    return matches[0]


def endpoint_with_response_schema(
    response_schema,
    *,
    method: str = "get",
    path: str = "/items",
    status_code: str = "200",
    content_type: str = "application/json",
):
    """An endpoint that declares a JSON response schema."""
    ep = operation(method, path)
    # Build responses with the given schema
    from aegisapi.models.endpoint import (
        DeclaredSecurity,
        Endpoint,
        HttpMethod,
        SecurityPosture,
    )
    return Endpoint(
        method=HttpMethod(method.lower()),
        path=path,
        operation_id=f"{method}{path}",
        responses=[
            ResponseSpec(
                status_code=status_code,
                content=[MediaTypeSchema(content_type=content_type, value_schema=response_schema)],
            )
        ],
        declared_security=DeclaredSecurity(posture=SecurityPosture.NOT_DECLARED),
        source_pointer=f"#/paths{path}/{method}",
    )


def endpoint_with_declared_responses(
    *,
    method: str = "get",
    path: str = "/items",
    status_codes: list[str] | None = None,
    content_type: str = "application/json",
):
    """An endpoint with declared response status codes but no body schema."""
    from aegisapi.models.endpoint import (
        DeclaredSecurity,
        Endpoint,
        HttpMethod,
        SecurityPosture,
    )
    codes = status_codes or ["200"]
    return Endpoint(
        method=HttpMethod(method.lower()),
        path=path,
        operation_id=f"{method}{path}",
        responses=[
            ResponseSpec(
                status_code=sc,
                content=[MediaTypeSchema(content_type=content_type)],
            )
            for sc in codes
        ],
        declared_security=DeclaredSecurity(posture=SecurityPosture.NOT_DECLARED),
        source_pointer=f"#/paths{path}/{method}",
    )


# ===========================================================================
# 1. schema_validator unit tests
# ===========================================================================

class TestValidateType:
    def test_string_matches_string(self) -> None:
        s = schema(type="string")
        assert validate_against_schema("hello", s) == []

    def test_integer_matches_integer(self) -> None:
        s = schema(type="integer")
        assert validate_against_schema(42, s) == []

    def test_number_matches_float(self) -> None:
        s = schema(type="number")
        assert validate_against_schema(3.14, s) == []

    def test_number_matches_integer(self) -> None:
        s = schema(type="number")
        assert validate_against_schema(5, s) == []

    def test_boolean_matches_boolean(self) -> None:
        s = schema(type="boolean")
        assert validate_against_schema(True, s) == []

    def test_object_matches_dict(self) -> None:
        s = schema(type="object")
        assert validate_against_schema({}, s) == []

    def test_array_matches_list(self) -> None:
        s = schema(type="array")
        assert validate_against_schema([], s) == []

    def test_null_matches_null(self) -> None:
        s = schema(type="null")
        assert validate_against_schema(None, s) == []

    def test_integer_rejects_string(self) -> None:
        s = schema(type="integer")
        violations = validate_against_schema("hello", s)
        assert len(violations) == 1
        assert violations[0].code == "wrong_type"
        assert violations[0].expected == "integer"
        assert violations[0].actual == "string"

    def test_string_rejects_integer(self) -> None:
        s = schema(type="string")
        violations = validate_against_schema(42, s)
        assert len(violations) == 1
        assert violations[0].code == "wrong_type"

    def test_integer_rejects_boolean(self) -> None:
        # bool is subclass of int in Python; must not be treated as integer.
        s = schema(type="integer")
        violations = validate_against_schema(True, s)
        assert len(violations) == 1
        assert violations[0].code == "wrong_type"
        assert violations[0].actual == "boolean"

    def test_number_rejects_boolean(self) -> None:
        s = schema(type="number")
        violations = validate_against_schema(False, s)
        assert len(violations) == 1
        assert violations[0].code == "wrong_type"
        assert violations[0].actual == "boolean"

    def test_unknown_type_passes(self) -> None:
        s = schema(type="binary")
        assert validate_against_schema("data", s) == []

    def test_no_type_passes_any_value(self) -> None:
        s = schema()
        assert validate_against_schema(42, s) == []
        assert validate_against_schema("x", s) == []
        assert validate_against_schema({}, s) == []


class TestNullHandling:
    def test_null_with_no_type_passes(self) -> None:
        s = schema()
        assert validate_against_schema(None, s) == []

    def test_null_with_null_type_passes(self) -> None:
        s = schema(type="null")
        assert validate_against_schema(None, s) == []

    def test_null_with_nullable_true_passes(self) -> None:
        s = schema(type="string", nullable=True)
        assert validate_against_schema(None, s) == []

    def test_null_with_typed_non_nullable_fails(self) -> None:
        s = schema(type="string")
        violations = validate_against_schema(None, s)
        assert len(violations) == 1
        assert violations[0].code == "wrong_type"
        assert violations[0].actual == "null"

    def test_null_with_nullable_false_fails(self) -> None:
        s = schema(type="integer", nullable=False)
        violations = validate_against_schema(None, s)
        assert len(violations) == 1
        assert violations[0].code == "wrong_type"


class TestEnumValidation:
    def test_value_in_enum_passes(self) -> None:
        s = schema(enum_values=["asc", "desc"])
        assert validate_against_schema("asc", s) == []

    def test_value_not_in_enum_fails(self) -> None:
        s = schema(enum_values=["asc", "desc"])
        violations = validate_against_schema("random", s)
        assert len(violations) == 1
        assert violations[0].code == "invalid_enum"

    def test_enum_with_integer_values(self) -> None:
        # enum_values are stored as strings per SchemaSummary
        s = schema(enum_values=["1", "2", "3"])
        assert validate_against_schema("1", s) == []

    def test_empty_enum_passes_anything(self) -> None:
        s = schema(enum_values=[])
        assert validate_against_schema("whatever", s) == []


class TestNumericConstraints:
    def test_above_minimum_passes(self) -> None:
        s = schema(type="integer", minimum=1)
        assert validate_against_schema(5, s) == []

    def test_at_minimum_passes(self) -> None:
        s = schema(type="integer", minimum=1)
        assert validate_against_schema(1, s) == []

    def test_below_minimum_fails(self) -> None:
        s = schema(type="integer", minimum=1)
        violations = validate_against_schema(0, s)
        assert len(violations) == 1
        assert violations[0].code == "below_minimum"

    def test_below_maximum_passes(self) -> None:
        s = schema(type="integer", maximum=100)
        assert validate_against_schema(50, s) == []

    def test_at_maximum_passes(self) -> None:
        s = schema(type="integer", maximum=100)
        assert validate_against_schema(100, s) == []

    def test_above_maximum_fails(self) -> None:
        s = schema(type="integer", maximum=100)
        violations = validate_against_schema(101, s)
        assert len(violations) == 1
        assert violations[0].code == "above_maximum"

    def test_minimum_and_maximum_in_range(self) -> None:
        s = schema(type="number", minimum=0.0, maximum=1.0)
        assert validate_against_schema(0.5, s) == []

    def test_boolean_not_checked_for_constraints(self) -> None:
        # Booleans fail type check first; constraints not reached.
        s = schema(type="integer", minimum=1)
        violations = validate_against_schema(True, s)
        assert violations[0].code == "wrong_type"


class TestStringConstraints:
    def test_string_at_min_length_passes(self) -> None:
        s = schema(type="string", min_length=3)
        assert validate_against_schema("abc", s) == []

    def test_string_above_min_length_passes(self) -> None:
        s = schema(type="string", min_length=3)
        assert validate_against_schema("abcdef", s) == []

    def test_string_below_min_length_fails(self) -> None:
        s = schema(type="string", min_length=5)
        violations = validate_against_schema("hi", s)
        assert len(violations) == 1
        assert violations[0].code == "below_min_length"
        assert "2" in violations[0].actual
        assert "5" in violations[0].expected

    def test_string_at_max_length_passes(self) -> None:
        s = schema(type="string", max_length=10)
        assert validate_against_schema("hello", s) == []

    def test_string_above_max_length_fails(self) -> None:
        s = schema(type="string", max_length=3)
        violations = validate_against_schema("toolong", s)
        assert len(violations) == 1
        assert violations[0].code == "above_max_length"

    def test_min_and_max_length_in_range(self) -> None:
        s = schema(type="string", min_length=2, max_length=5)
        assert validate_against_schema("abc", s) == []


class TestObjectValidation:
    def test_object_with_no_constraints_passes(self) -> None:
        s = schema(type="object")
        assert validate_against_schema({"a": 1}, s) == []

    def test_required_property_present_passes(self) -> None:
        s = schema(type="object", required=["id", "name"])
        assert validate_against_schema({"id": 1, "name": "Alice"}, s) == []

    def test_required_property_missing_fails(self) -> None:
        s = schema(type="object", required=["id"])
        violations = validate_against_schema({}, s)
        assert len(violations) == 1
        assert violations[0].code == "missing_required"
        assert "id" in violations[0].message

    def test_multiple_required_missing_all_reported(self) -> None:
        s = schema(type="object", required=["id", "name", "email"])
        violations = validate_against_schema({}, s)
        assert len(violations) == 3
        codes = [v.code for v in violations]
        assert all(c == "missing_required" for c in codes)

    def test_nested_property_validated(self) -> None:
        inner = schema(type="integer")
        outer = schema(type="object", properties={"count": inner})
        violations = validate_against_schema({"count": "wrong"}, outer)
        assert len(violations) == 1
        assert violations[0].code == "wrong_type"
        assert "$.count" in violations[0].path

    def test_extra_properties_not_flagged(self) -> None:
        # AegisAPI does not report additional properties as violations.
        s = schema(type="object", required=["id"])
        assert validate_against_schema({"id": 1, "extra": "ok"}, s) == []

    def test_non_dict_for_object_type_fails(self) -> None:
        s = schema(type="object")
        violations = validate_against_schema([1, 2], s)
        assert violations[0].code == "wrong_type"


class TestArrayValidation:
    def test_array_with_no_items_schema_passes(self) -> None:
        s = schema(type="array")
        assert validate_against_schema([1, 2, 3], s) == []

    def test_array_items_validated_against_schema(self) -> None:
        item_schema = schema(type="integer")
        s = schema(type="array", items=item_schema)
        assert validate_against_schema([1, 2, 3], s) == []

    def test_array_item_violation_reported(self) -> None:
        item_schema = schema(type="integer")
        s = schema(type="array", items=item_schema)
        violations = validate_against_schema([1, "bad", 3], s)
        assert len(violations) == 1
        assert violations[0].code == "wrong_type"
        assert "[1]" in violations[0].path

    def test_path_includes_index(self) -> None:
        item_schema = schema(type="string")
        s = schema(type="array", items=item_schema)
        violations = validate_against_schema([42], s)
        assert violations[0].path == "$[0]"


class TestComposition:
    def test_allof_all_branches_satisfied(self) -> None:
        s = schema(composition="allOf", composed_of=[
            SchemaSummary(type="object"),
            SchemaSummary(required=["id"]),
        ])
        assert validate_against_schema({"id": 1}, s) == []

    def test_allof_one_branch_fails(self) -> None:
        s = schema(composition="allOf", composed_of=[
            SchemaSummary(type="object"),
            SchemaSummary(required=["id"]),
        ])
        violations = validate_against_schema({}, s)
        assert any(v.code == "missing_required" for v in violations)

    def test_anyof_one_branch_satisfied(self) -> None:
        s = schema(composition="anyOf", composed_of=[
            SchemaSummary(type="string"),
            SchemaSummary(type="integer"),
        ])
        assert validate_against_schema(42, s) == []
        assert validate_against_schema("hello", s) == []

    def test_anyof_no_branch_satisfied(self) -> None:
        s = schema(composition="anyOf", composed_of=[
            SchemaSummary(type="string"),
            SchemaSummary(type="integer"),
        ])
        violations = validate_against_schema([], s)
        assert len(violations) == 1
        assert violations[0].code == "anyof_no_match"

    def test_oneof_exactly_one_branch(self) -> None:
        s = schema(composition="oneOf", composed_of=[
            SchemaSummary(type="string"),
            SchemaSummary(type="integer"),
        ])
        assert validate_against_schema(42, s) == []

    def test_oneof_no_branch(self) -> None:
        s = schema(composition="oneOf", composed_of=[
            SchemaSummary(type="string"),
            SchemaSummary(type="integer"),
        ])
        violations = validate_against_schema([], s)
        assert len(violations) == 1
        assert violations[0].code == "oneof_no_match"

    def test_oneof_multiple_branches_match(self) -> None:
        # Both branches match a number.
        s = schema(composition="oneOf", composed_of=[
            SchemaSummary(type="number"),
            SchemaSummary(type="integer"),
        ])
        violations = validate_against_schema(42, s)
        assert len(violations) == 1
        assert violations[0].code == "oneof_multiple_match"

    def test_empty_composition_passes(self) -> None:
        s = schema(composition="anyOf", composed_of=[])
        assert validate_against_schema("x", s) == []


class TestViolationCapping:
    def test_violations_capped_at_max(self) -> None:
        # Create a schema with 30 required properties; only MAX_VIOLATIONS returned.
        props = [f"prop{i}" for i in range(30)]
        s = schema(type="object", required=props)
        violations = validate_against_schema({}, s)
        assert len(violations) == MAX_VIOLATIONS

    def test_path_prefix_in_violations(self) -> None:
        inner = schema(type="integer")
        outer = schema(type="object", properties={"n": inner})
        violations = validate_against_schema({"n": "wrong"}, outer)
        assert violations[0].path == "$.n"

    def test_nested_path_accumulates(self) -> None:
        level3 = schema(type="integer")
        level2 = schema(type="object", properties={"val": level3})
        level1 = schema(type="object", properties={"child": level2})
        violations = validate_against_schema({"child": {"val": "oops"}}, level1)
        assert violations[0].path == "$.child.val"


class TestDepthCapping:
    def test_deep_recursion_stops_gracefully(self) -> None:
        # Build a deeply nested schema that would overflow without the depth cap.
        deep = schema(type="string")
        for _ in range(10):
            deep = schema(type="object", properties={"nested": deep})
        # Should not raise RecursionError; just returns violations (possibly empty after cap).
        result = validate_against_schema({"nested": {"nested": {"nested": "not-a-string"}}}, deep)
        assert isinstance(result, list)


# ===========================================================================
# 2. Helper function unit tests
# ===========================================================================

class TestHelpers:
    def test_bare_content_type_strips_charset(self) -> None:
        assert _bare_content_type("application/json; charset=utf-8") == "application/json"

    def test_bare_content_type_no_params(self) -> None:
        assert _bare_content_type("application/json") == "application/json"

    def test_bare_content_type_lowercases(self) -> None:
        assert _bare_content_type("Application/JSON") == "application/json"

    def test_is_json_content_type_exact(self) -> None:
        assert _is_json_content_type("application/json")

    def test_is_json_content_type_with_charset(self) -> None:
        assert _is_json_content_type("application/json; charset=utf-8")

    def test_is_json_content_type_plus_json(self) -> None:
        assert _is_json_content_type("application/vnd.api+json")

    def test_is_json_content_type_text_plain(self) -> None:
        assert not _is_json_content_type("text/plain")

    def test_find_response_spec_exact_match(self) -> None:
        from aegisapi.models.endpoint import DeclaredSecurity, Endpoint, HttpMethod, SecurityPosture
        ep = endpoint_with_declared_responses(status_codes=["200", "404"])
        spec = _find_response_spec(ep, 200)
        assert spec is not None
        assert spec.status_code == "200"

    def test_find_response_spec_wildcard(self) -> None:
        from aegisapi.models.endpoint import DeclaredSecurity, Endpoint, HttpMethod, SecurityPosture
        ep = endpoint_with_declared_responses(status_codes=["2XX"])
        spec = _find_response_spec(ep, 201)
        assert spec is not None
        assert spec.status_code == "2XX"

    def test_find_response_spec_default(self) -> None:
        ep = endpoint_with_declared_responses(status_codes=["default"])
        spec = _find_response_spec(ep, 500)
        assert spec is not None
        assert spec.status_code == "default"

    def test_find_response_spec_exact_beats_wildcard(self) -> None:
        ep = endpoint_with_declared_responses(status_codes=["200", "2XX"])
        spec = _find_response_spec(ep, 200)
        assert spec.status_code == "200"

    def test_find_response_spec_not_found(self) -> None:
        ep = endpoint_with_declared_responses(status_codes=["200"])
        assert _find_response_spec(ep, 500) is None

    def test_has_response_schema_true(self) -> None:
        ep = endpoint_with_response_schema(schema(type="object"))
        assert _has_response_schema(ep)

    def test_has_response_schema_no_schema(self) -> None:
        ep = endpoint_with_declared_responses()
        assert not _has_response_schema(ep)


# ===========================================================================
# 3. ResponseSchemaCheck (SCHEMA-001) behavioural tests
# ===========================================================================

class TestResponseSchemaCheck:
    def test_does_not_apply_to_endpoint_without_response_schema(self) -> None:
        ep = operation("get", "/items")
        result = run_check("SCHEMA-001", [ep], FakeTransport([json_response({"ok": True})]))
        # No SCHEMA-001 result means applies_to returned False → no result at all.
        matches = [r for r in result.results if r.check_id == "SCHEMA-001"]
        assert not matches

    def test_applies_to_endpoint_with_response_schema(self) -> None:
        ep = endpoint_with_response_schema(schema(type="object"))
        result = run_check("SCHEMA-001", [ep], FakeTransport([json_response({"ok": True})]))
        matches = [r for r in result.results if r.check_id == "SCHEMA-001"]
        assert matches

    def test_does_not_apply_to_post_without_write_opt_in(self) -> None:
        ep = endpoint_with_response_schema(schema(type="object"), method="post", path="/items")
        result = run_check("SCHEMA-001", [ep], FakeTransport([json_response({"ok": True})]))
        matches = [r for r in result.results if r.check_id == "SCHEMA-001"]
        assert not matches

    def test_pass_when_body_matches_schema(self) -> None:
        ep = endpoint_with_response_schema(schema(type="object", required=["id"]))
        result = run_check("SCHEMA-001", [ep], FakeTransport([json_response({"id": 1})]))
        item = only(result, "SCHEMA-001")
        assert item.outcome is CheckOutcome.PASS
        assert item.finding_class is FindingClass.NONE

    def test_fail_informational_when_body_violates_schema(self) -> None:
        ep = endpoint_with_response_schema(schema(type="object", required=["id", "name"]))
        result = run_check("SCHEMA-001", [ep], FakeTransport([json_response({})]))
        item = only(result, "SCHEMA-001")
        assert item.outcome is CheckOutcome.FAIL
        assert item.finding_class is FindingClass.INFORMATIONAL

    def test_fail_summary_mentions_violation_count(self) -> None:
        ep = endpoint_with_response_schema(schema(type="object", required=["id"]))
        result = run_check("SCHEMA-001", [ep], FakeTransport([json_response({})]))
        item = only(result, "SCHEMA-001")
        assert "1" in item.summary

    def test_fail_has_limitations(self) -> None:
        ep = endpoint_with_response_schema(schema(type="object", required=["id"]))
        result = run_check("SCHEMA-001", [ep], FakeTransport([json_response({})]))
        item = only(result, "SCHEMA-001")
        assert item.limitations

    def test_skipped_when_status_not_declared(self) -> None:
        # Schema declares 200 but API returns 404.
        ep = endpoint_with_response_schema(schema(type="object"))
        result = run_check(
            "SCHEMA-001", [ep],
            FakeTransport([StubResponse(
                status_code=404,
                headers=[("content-type", "application/json")],
                body=b'{"error": "not found"}',
            )])
        )
        item = only(result, "SCHEMA-001")
        assert item.outcome is CheckOutcome.SKIPPED

    def test_skipped_when_response_not_json(self) -> None:
        ep = endpoint_with_response_schema(schema(type="object"))
        result = run_check(
            "SCHEMA-001", [ep],
            FakeTransport([StubResponse(
                status_code=200,
                headers=[("content-type", "text/plain")],
                body=b"plain text",
            )])
        )
        item = only(result, "SCHEMA-001")
        assert item.outcome is CheckOutcome.SKIPPED

    def test_skipped_when_body_truncated(self) -> None:
        ep = endpoint_with_response_schema(schema(type="object", required=["id"]))
        result = run_check(
            "SCHEMA-001", [ep],
            FakeTransport([json_response({"id": 1}, truncated=True)])
        )
        item = only(result, "SCHEMA-001")
        assert item.outcome is CheckOutcome.SKIPPED

    def test_skipped_when_body_not_valid_json(self) -> None:
        ep = endpoint_with_response_schema(schema(type="object"))
        result = run_check(
            "SCHEMA-001", [ep],
            FakeTransport([StubResponse(
                status_code=200,
                headers=[("content-type", "application/json")],
                body=b"not{json}",
            )])
        )
        item = only(result, "SCHEMA-001")
        assert item.outcome is CheckOutcome.SKIPPED

    def test_skipped_when_no_json_schema_declared_for_response(self) -> None:
        # Endpoint has responses but only a text/plain schema.
        ep = endpoint_with_response_schema(
            schema(type="object"), content_type="text/plain"
        )
        result = run_check("SCHEMA-001", [ep], FakeTransport([json_response({"id": 1})]))
        # applies_to returns False because _has_response_schema is False for text/plain.
        matches = [r for r in result.results if r.check_id == "SCHEMA-001"]
        assert not matches

    def test_consumes_one_request(self) -> None:
        ep = endpoint_with_response_schema(schema(type="object"))
        transport = FakeTransport([json_response({"ok": True})])
        run_check("SCHEMA-001", [ep], transport)
        assert transport.call_count == 1

    def test_check_has_owasp_category(self) -> None:
        from aegisapi.testing.knowledge import knowledge_for
        k = knowledge_for("SCHEMA-001")
        assert k is not None
        assert k.owasp is not None

    def test_check_has_remediation(self) -> None:
        from aegisapi.testing.knowledge import knowledge_for
        k = knowledge_for("SCHEMA-001")
        assert k is not None
        assert k.remediation

    def test_check_category_is_schema_validation(self) -> None:
        check = ResponseSchemaCheck()
        assert check.category is CheckCategory.SCHEMA_VALIDATION

    def test_array_body_validated_against_items_schema(self) -> None:
        item_s = schema(type="integer")
        arr_s = schema(type="array", items=item_s)
        ep = endpoint_with_response_schema(arr_s)
        result = run_check("SCHEMA-001", [ep], FakeTransport([json_response([1, 2, 3])]))
        item = only(result, "SCHEMA-001")
        assert item.outcome is CheckOutcome.PASS

    def test_array_item_violation_causes_fail(self) -> None:
        item_s = schema(type="integer")
        arr_s = schema(type="array", items=item_s)
        ep = endpoint_with_response_schema(arr_s)
        result = run_check("SCHEMA-001", [ep], FakeTransport([json_response([1, "bad", 3])]))
        item = only(result, "SCHEMA-001")
        assert item.outcome is CheckOutcome.FAIL

    def test_wildcard_status_response_spec_matched(self) -> None:
        from aegisapi.models.endpoint import DeclaredSecurity, Endpoint, HttpMethod, SecurityPosture
        ep = Endpoint(
            method=HttpMethod("get"),
            path="/items",
            operation_id="getItems",
            responses=[
                ResponseSpec(
                    status_code="2XX",
                    content=[MediaTypeSchema(
                        content_type="application/json",
                        value_schema=schema(type="object", required=["id"]),
                    )],
                )
            ],
            declared_security=DeclaredSecurity(posture=SecurityPosture.NOT_DECLARED),
            source_pointer="#/paths/items/get",
        )
        result = run_check("SCHEMA-001", [ep], FakeTransport([json_response({"id": 1})]))
        item = only(result, "SCHEMA-001")
        assert item.outcome is CheckOutcome.PASS

    def test_skipped_when_budget_zero(self) -> None:
        ep = endpoint_with_response_schema(schema(type="object"))
        result = run_check("SCHEMA-001", [ep], FakeTransport([json_response({})]), budget=0)
        item = only(result, "SCHEMA-001")
        assert item.outcome is CheckOutcome.SKIPPED

    def test_requests_sent_is_one(self) -> None:
        ep = endpoint_with_response_schema(schema(type="object"))
        result = run_check("SCHEMA-001", [ep], FakeTransport([json_response({"ok": True})]))
        item = only(result, "SCHEMA-001")
        assert item.requests_sent == 1

    def test_nested_object_violation_path(self) -> None:
        inner = schema(type="integer")
        outer = schema(type="object", required=["count"], properties={"count": inner})
        ep = endpoint_with_response_schema(outer)
        result = run_check(
            "SCHEMA-001", [ep],
            FakeTransport([json_response({"count": "not-an-int"})])
        )
        item = only(result, "SCHEMA-001")
        assert item.outcome is CheckOutcome.FAIL


# ===========================================================================
# 4. ResponseConformanceCheck (SCHEMA-002) behavioural tests
# ===========================================================================

class TestResponseConformanceCheck:
    def test_does_not_apply_to_endpoint_without_responses(self) -> None:
        ep = operation("get", "/items")
        result = run_check("SCHEMA-002", [ep], FakeTransport([json_response({"ok": True})]))
        matches = [r for r in result.results if r.check_id == "SCHEMA-002"]
        assert not matches

    def test_applies_to_endpoint_with_declared_responses(self) -> None:
        ep = endpoint_with_declared_responses()
        result = run_check("SCHEMA-002", [ep], FakeTransport([json_response({"ok": True})]))
        matches = [r for r in result.results if r.check_id == "SCHEMA-002"]
        assert matches

    def test_pass_when_status_and_content_type_declared(self) -> None:
        ep = endpoint_with_declared_responses(status_codes=["200"], content_type="application/json")
        result = run_check("SCHEMA-002", [ep], FakeTransport([json_response({"ok": True})]))
        item = only(result, "SCHEMA-002")
        assert item.outcome is CheckOutcome.PASS
        assert item.finding_class is FindingClass.NONE

    def test_fail_informational_when_status_undeclared(self) -> None:
        # Declared 200 but API returns 201.
        ep = endpoint_with_declared_responses(status_codes=["200"])
        result = run_check(
            "SCHEMA-002", [ep],
            FakeTransport([StubResponse(
                status_code=201,
                headers=[("content-type", "application/json")],
                body=b'{"id": 1}',
            )])
        )
        item = only(result, "SCHEMA-002")
        assert item.outcome is CheckOutcome.FAIL
        assert item.finding_class is FindingClass.INFORMATIONAL

    def test_fail_mentions_undeclared_status(self) -> None:
        ep = endpoint_with_declared_responses(status_codes=["200"])
        result = run_check(
            "SCHEMA-002", [ep],
            FakeTransport([StubResponse(
                status_code=204,
                headers=[("content-type", "application/json")],
                body=b"",
            )])
        )
        item = only(result, "SCHEMA-002")
        assert "204" in item.summary

    def test_fail_informational_when_content_type_undeclared(self) -> None:
        # Declared application/json but API returns text/plain.
        ep = endpoint_with_declared_responses(status_codes=["200"], content_type="application/json")
        result = run_check(
            "SCHEMA-002", [ep],
            FakeTransport([StubResponse(
                status_code=200,
                headers=[("content-type", "text/plain")],
                body=b"hello",
            )])
        )
        item = only(result, "SCHEMA-002")
        assert item.outcome is CheckOutcome.FAIL
        assert item.finding_class is FindingClass.INFORMATIONAL

    def test_pass_with_wildcard_status_match(self) -> None:
        ep = endpoint_with_declared_responses(status_codes=["2XX"])
        result = run_check("SCHEMA-002", [ep], FakeTransport([json_response({"ok": True})]))
        item = only(result, "SCHEMA-002")
        assert item.outcome is CheckOutcome.PASS

    def test_check_has_owasp_category(self) -> None:
        from aegisapi.testing.knowledge import knowledge_for
        k = knowledge_for("SCHEMA-002")
        assert k is not None
        assert k.owasp is not None

    def test_check_category_is_schema_validation(self) -> None:
        check = ResponseConformanceCheck()
        assert check.category is CheckCategory.SCHEMA_VALIDATION

    def test_consumes_one_request(self) -> None:
        ep = endpoint_with_declared_responses()
        transport = FakeTransport([json_response({"ok": True})])
        run_check("SCHEMA-002", [ep], transport)
        assert transport.call_count == 1

    def test_pass_when_response_has_no_declared_content_types(self) -> None:
        # ResponseSpec with empty content means no content-type constraint.
        from aegisapi.models.endpoint import DeclaredSecurity, Endpoint, HttpMethod, SecurityPosture
        ep = Endpoint(
            method=HttpMethod("get"),
            path="/items",
            operation_id="getItems",
            responses=[ResponseSpec(status_code="200", content=[])],
            declared_security=DeclaredSecurity(posture=SecurityPosture.NOT_DECLARED),
            source_pointer="#/paths/items/get",
        )
        result = run_check("SCHEMA-002", [ep], FakeTransport([json_response({"ok": True})]))
        item = only(result, "SCHEMA-002")
        # Empty declared content means any content type is acceptable.
        assert item.outcome is CheckOutcome.PASS

    def test_has_limitations(self) -> None:
        ep = endpoint_with_declared_responses(status_codes=["200"])
        result = run_check(
            "SCHEMA-002", [ep],
            FakeTransport([StubResponse(status_code=404, body=b'{"e":"nf"}',
                                        headers=[("content-type", "application/json")])])
        )
        item = only(result, "SCHEMA-002")
        assert item.limitations

    def test_skipped_when_budget_zero(self) -> None:
        ep = endpoint_with_declared_responses()
        result = run_check("SCHEMA-002", [ep], FakeTransport([json_response({})]), budget=0)
        item = only(result, "SCHEMA-002")
        assert item.outcome is CheckOutcome.SKIPPED

    def test_requests_sent_is_one(self) -> None:
        ep = endpoint_with_declared_responses()
        result = run_check("SCHEMA-002", [ep], FakeTransport([json_response({"ok": True})]))
        item = only(result, "SCHEMA-002")
        assert item.requests_sent == 1


# ===========================================================================
# 5. Pipeline and engine integration tests
# ===========================================================================

class TestPipelineIntegration:
    def test_schema_val_stage_exists(self) -> None:
        from aegisapi.scan.pipeline import ScanStage
        assert ScanStage.SCHEMA_VAL

    def test_schema_val_stage_value(self) -> None:
        from aegisapi.scan.pipeline import ScanStage
        assert ScanStage.SCHEMA_VAL.value == "schema_val"

    def test_scan_result_has_schemas_validated_field(self) -> None:
        from aegisapi.scan.pipeline import ScanResult
        import inspect
        fields = {f.name for f in ScanResult.__dataclass_fields__.values()}
        assert "schemas_validated" in fields
        assert "schema_violations" in fields

    def test_check_category_schema_validation_exists(self) -> None:
        assert CheckCategory.SCHEMA_VALIDATION
        assert CheckCategory.SCHEMA_VALIDATION.value == "schema_validation"

    def test_schema_checks_registered_in_engine(self) -> None:
        from aegisapi.testing.engine import REGISTRY
        ids = {c.check_id for c in REGISTRY.all()}
        assert "SCHEMA-001" in ids
        assert "SCHEMA-002" in ids

    def test_schema_checks_have_correct_category(self) -> None:
        from aegisapi.testing.engine import REGISTRY
        for check_id in ("SCHEMA-001", "SCHEMA-002"):
            check = REGISTRY.get(check_id)
            assert check.category is CheckCategory.SCHEMA_VALIDATION

    def test_stage_labels_include_schema_val(self) -> None:
        from aegisapi.commands.scan import _STAGE_LABELS
        from aegisapi.scan.pipeline import ScanStage
        assert ScanStage.SCHEMA_VAL in _STAGE_LABELS
        assert _STAGE_LABELS[ScanStage.SCHEMA_VAL] == "schema-val"
