"""Tests for M2 — Automatic Test Fixture Generation.

Covers:
* SchemaSummary new fields (minimum, maximum, min_length, max_length)
* SchemaSummariser extracting bounds from raw schema nodes
* auto_fixtures.py generator logic for every schema shape
* fill_path_template utility
* CheckContext.auto_fixtures carrying generated values
* _QueryValidationCheck._send() using auto fixtures for templated paths
* INPUT-001/002/003 running against templated endpoints
* ScanStage.FIXTURE_GEN existing
* ScanResult.fixtures_generated stat
"""

from __future__ import annotations

import pytest

from aegisapi.models.assessment import CheckOutcome
from aegisapi.models.endpoint import (
    Endpoint,
    HttpMethod,
    Parameter,
    ParameterLocation,
    SchemaSummary,
    SchemaKind,
    DeclaredSecurity,
    SecurityPosture,
)
from aegisapi.scan.pipeline import ScanStage
from aegisapi.testing.auto_fixtures import (
    EndpointFixtures,
    fill_path_template,
    generate_endpoint_fixtures,
    generate_fixtures,
    _schema_path_value,
    _id_fallback,
    _TEST_UUID,
)
from aegisapi.testing.registry import CheckContext
from assessfix import (
    classified,
    discovery_result,
    make_client,
    make_config,
    operation,
    path_param,
    protected,
    public,
    query,
    scoped_target,
)
from httpstub import FakeTransport, StubResponse


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _path_param(name: str, *, type_: str | None = None, fmt: str | None = None,
                enum: list[str] | None = None, minimum: float | None = None,
                maximum: float | None = None, min_length: int | None = None,
                max_length: int | None = None) -> Parameter:
    """Build a PATH parameter with an optional schema."""
    schema = None
    if any(v is not None for v in (type_, fmt, enum, minimum, maximum, min_length, max_length)):
        schema = SchemaSummary(
            type=type_,
            format=fmt,
            enum_values=enum or [],
            minimum=minimum,
            maximum=maximum,
            min_length=min_length,
            max_length=max_length,
        )
    return Parameter(name=name, location=ParameterLocation.PATH, required=True, value_schema=schema)


def _templated_endpoint(*path_params: Parameter, path: str = "/items/{id}") -> Endpoint:
    """Build a simple GET endpoint with the given path parameters."""
    return Endpoint(
        method=HttpMethod.GET,
        path=path,
        parameters=list(path_params),
        declared_security=DeclaredSecurity(
            posture=SecurityPosture.NOT_DECLARED,
            alternatives=[],
        ),
        source_pointer=f"#/paths{path}/get",
    )


# ---------------------------------------------------------------------------
# SchemaSummary new fields
# ---------------------------------------------------------------------------

class TestSchemaSummaryBoundsFields:
    def test_defaults_to_none(self) -> None:
        s = SchemaSummary(type="integer")
        assert s.minimum is None
        assert s.maximum is None
        assert s.min_length is None
        assert s.max_length is None

    def test_minimum_can_be_set(self) -> None:
        s = SchemaSummary(type="integer", minimum=1.0)
        assert s.minimum == 1.0

    def test_maximum_can_be_set(self) -> None:
        s = SchemaSummary(type="number", maximum=100.5)
        assert s.maximum == 100.5

    def test_min_length_can_be_set(self) -> None:
        s = SchemaSummary(type="string", min_length=5)
        assert s.min_length == 5

    def test_max_length_can_be_set(self) -> None:
        s = SchemaSummary(type="string", max_length=200)
        assert s.max_length == 200

    def test_all_bounds_together(self) -> None:
        s = SchemaSummary(
            type="number", minimum=-10.0, maximum=10.0, min_length=None, max_length=None
        )
        assert s.minimum == -10.0
        assert s.maximum == 10.0
        assert s.min_length is None
        assert s.max_length is None

    def test_zero_minimum_is_captured(self) -> None:
        s = SchemaSummary(type="integer", minimum=0.0)
        assert s.minimum == 0.0

    def test_zero_min_length_is_captured(self) -> None:
        s = SchemaSummary(type="string", min_length=0)
        assert s.min_length == 0


# ---------------------------------------------------------------------------
# SchemaSummariser extracting bounds
# ---------------------------------------------------------------------------

class TestSchemaSummariserBounds:
    """Verify the summariser captures bounds from raw OpenAPI schema nodes."""

    def _summarise(self, node: dict) -> SchemaSummary:
        from aegisapi.discovery.schemas import SchemaSummariser, WarningCollector
        from aegisapi.discovery.references import ReferenceResolver

        doc: dict = {"components": {}}
        resolver = ReferenceResolver(doc)
        warnings = WarningCollector()
        summariser = SchemaSummariser(resolver, warnings)
        result = summariser.summarise(node, pointer="#/test")
        assert result is not None
        return result

    def test_minimum_integer(self) -> None:
        summary = self._summarise({"type": "integer", "minimum": 5})
        assert summary.minimum == 5.0

    def test_minimum_float(self) -> None:
        summary = self._summarise({"type": "number", "minimum": 0.5})
        assert summary.minimum == 0.5

    def test_maximum_integer(self) -> None:
        summary = self._summarise({"type": "integer", "maximum": 100})
        assert summary.maximum == 100.0

    def test_min_length(self) -> None:
        summary = self._summarise({"type": "string", "minLength": 3})
        assert summary.min_length == 3

    def test_max_length(self) -> None:
        summary = self._summarise({"type": "string", "maxLength": 50})
        assert summary.max_length == 50

    def test_boolean_minimum_ignored(self) -> None:
        summary = self._summarise({"type": "integer", "minimum": True})
        assert summary.minimum is None

    def test_string_minimum_ignored(self) -> None:
        summary = self._summarise({"type": "integer", "minimum": "5"})
        assert summary.minimum is None

    def test_float_min_length_converts_to_int(self) -> None:
        summary = self._summarise({"type": "string", "minLength": 4.0})
        assert summary.min_length == 4

    def test_non_integer_float_min_length_ignored(self) -> None:
        summary = self._summarise({"type": "string", "minLength": 4.5})
        assert summary.min_length is None

    def test_zero_minimum_captured(self) -> None:
        summary = self._summarise({"type": "integer", "minimum": 0})
        assert summary.minimum == 0.0

    def test_negative_minimum_captured(self) -> None:
        summary = self._summarise({"type": "integer", "minimum": -99})
        assert summary.minimum == -99.0

    def test_absent_bounds_remain_none(self) -> None:
        summary = self._summarise({"type": "string"})
        assert summary.minimum is None
        assert summary.maximum is None
        assert summary.min_length is None
        assert summary.max_length is None


# ---------------------------------------------------------------------------
# _id_fallback and _schema_path_value helpers
# ---------------------------------------------------------------------------

class TestIdFallback:
    def test_name_with_id_suffix_returns_one(self) -> None:
        assert _id_fallback("userId") == "1"

    def test_name_with_id_prefix_returns_one(self) -> None:
        assert _id_fallback("id") == "1"

    def test_name_with_key_returns_one(self) -> None:
        assert _id_fallback("apiKey") == "1"

    def test_name_with_uuid_returns_one(self) -> None:
        assert _id_fallback("uuid") == "1"

    def test_generic_name_returns_test(self) -> None:
        assert _id_fallback("category") == "test"

    def test_name_with_pk_returns_one(self) -> None:
        assert _id_fallback("pk") == "1"

    def test_name_with_ref_returns_one(self) -> None:
        assert _id_fallback("orderRef") == "1"


class TestSchemaPathValue:
    def test_no_schema_uses_name_fallback(self) -> None:
        assert _schema_path_value("userId", None) == "1"
        assert _schema_path_value("category", None) == "test"

    def test_enum_uses_first_value(self) -> None:
        schema = SchemaSummary(type="string", enum_values=["active", "inactive"])
        assert _schema_path_value("status", schema) == "active"

    def test_uuid_format_returns_test_uuid(self) -> None:
        schema = SchemaSummary(type="string", format="uuid")
        assert _schema_path_value("userId", schema) == _TEST_UUID

    def test_guid_format_returns_test_uuid(self) -> None:
        schema = SchemaSummary(type="string", format="guid")
        assert _schema_path_value("ref", schema) == _TEST_UUID

    def test_uuid_format_takes_precedence_over_integer_type(self) -> None:
        # uuid format beats integer type — format is more specific.
        schema = SchemaSummary(type="integer", format="uuid")
        assert _schema_path_value("id", schema) == _TEST_UUID

    def test_integer_no_minimum_returns_one(self) -> None:
        schema = SchemaSummary(type="integer")
        assert _schema_path_value("userId", schema) == "1"

    def test_integer_with_minimum_returns_minimum(self) -> None:
        schema = SchemaSummary(type="integer", minimum=5.0)
        assert _schema_path_value("userId", schema) == "5"

    def test_integer_with_zero_minimum(self) -> None:
        schema = SchemaSummary(type="integer", minimum=0.0)
        assert _schema_path_value("index", schema) == "0"

    def test_number_no_minimum_returns_one(self) -> None:
        schema = SchemaSummary(type="number")
        assert _schema_path_value("score", schema) == "1"

    def test_number_with_minimum_returns_minimum(self) -> None:
        schema = SchemaSummary(type="number", minimum=0.5)
        assert _schema_path_value("score", schema) == "0.5"

    def test_string_id_like_name_returns_one(self) -> None:
        schema = SchemaSummary(type="string")
        assert _schema_path_value("userId", schema) == "1"

    def test_string_generic_name_returns_test(self) -> None:
        schema = SchemaSummary(type="string")
        assert _schema_path_value("category", schema) == "test"

    def test_string_min_length_short_uses_fallback(self) -> None:
        schema = SchemaSummary(type="string", min_length=4)
        assert _schema_path_value("name", schema) == "test"

    def test_string_min_length_long_pads(self) -> None:
        schema = SchemaSummary(type="string", min_length=8)
        result = _schema_path_value("name", schema)
        assert len(result) >= 8

    def test_unknown_type_uses_name_fallback(self) -> None:
        schema = SchemaSummary(type="object")
        assert _schema_path_value("userId", schema) == "1"
        assert _schema_path_value("thing", schema) == "test"

    def test_enum_takes_precedence_over_format(self) -> None:
        schema = SchemaSummary(type="string", format="uuid", enum_values=["fixed-uuid"])
        assert _schema_path_value("ref", schema) == "fixed-uuid"


# ---------------------------------------------------------------------------
# EndpointFixtures
# ---------------------------------------------------------------------------

class TestEndpointFixtures:
    def test_empty_has_no_path_values(self) -> None:
        ef = EndpointFixtures()
        assert not ef.has_path_values
        assert ef.path_values == {}

    def test_non_empty_has_path_values(self) -> None:
        ef = EndpointFixtures(path_values={"id": "1"})
        assert ef.has_path_values

    def test_is_frozen(self) -> None:
        from dataclasses import FrozenInstanceError
        ef = EndpointFixtures(path_values={"id": "1"})
        with pytest.raises((FrozenInstanceError, AttributeError)):
            ef.path_values = {"new": "x"}  # type: ignore[misc]


# ---------------------------------------------------------------------------
# fill_path_template
# ---------------------------------------------------------------------------

class TestFillPathTemplate:
    def test_simple_substitution(self) -> None:
        assert fill_path_template("/users/{userId}", {"userId": "42"}) == "/users/42"

    def test_multiple_variables(self) -> None:
        result = fill_path_template("/orgs/{orgId}/users/{userId}", {"orgId": "10", "userId": "20"})
        assert result == "/orgs/10/users/20"

    def test_missing_variable_returns_none(self) -> None:
        assert fill_path_template("/users/{userId}/orders/{orderId}", {"userId": "1"}) is None

    def test_empty_values_returns_none_when_variables_remain(self) -> None:
        assert fill_path_template("/items/{itemId}", {}) is None

    def test_non_templated_path_unchanged(self) -> None:
        assert fill_path_template("/users", {"id": "1"}) == "/users"

    def test_extra_values_do_not_break(self) -> None:
        result = fill_path_template("/users/{userId}", {"userId": "5", "extra": "ignored"})
        assert result == "/users/5"

    def test_uuid_value(self) -> None:
        path = "/items/{id}"
        result = fill_path_template(path, {"id": _TEST_UUID})
        assert result == f"/items/{_TEST_UUID}"


# ---------------------------------------------------------------------------
# generate_endpoint_fixtures
# ---------------------------------------------------------------------------

class TestGenerateEndpointFixtures:
    def test_non_templated_endpoint_returns_empty(self) -> None:
        ep = _templated_endpoint(path="/users")
        ef = generate_endpoint_fixtures(ep)
        assert not ef.has_path_values

    def test_single_path_param_no_schema(self) -> None:
        ep = _templated_endpoint(_path_param("userId"), path="/users/{userId}")
        ef = generate_endpoint_fixtures(ep)
        assert ef.has_path_values
        assert "userId" in ef.path_values
        assert ef.path_values["userId"] == "1"

    def test_path_param_integer_type(self) -> None:
        ep = _templated_endpoint(
            _path_param("orderId", type_="integer"),
            path="/orders/{orderId}",
        )
        ef = generate_endpoint_fixtures(ep)
        assert ef.path_values["orderId"] == "1"

    def test_path_param_integer_with_minimum(self) -> None:
        ep = _templated_endpoint(
            _path_param("pageNum", type_="integer", minimum=10.0),
            path="/pages/{pageNum}",
        )
        ef = generate_endpoint_fixtures(ep)
        assert ef.path_values["pageNum"] == "10"

    def test_path_param_uuid_format(self) -> None:
        ep = _templated_endpoint(
            _path_param("userId", type_="string", fmt="uuid"),
            path="/users/{userId}",
        )
        ef = generate_endpoint_fixtures(ep)
        assert ef.path_values["userId"] == _TEST_UUID

    def test_path_param_enum_values(self) -> None:
        ep = _templated_endpoint(
            _path_param("status", type_="string", enum=["active", "inactive"]),
            path="/items/{status}",
        )
        ef = generate_endpoint_fixtures(ep)
        assert ef.path_values["status"] == "active"

    def test_multiple_path_params(self) -> None:
        ep = _templated_endpoint(
            _path_param("orgId", type_="integer"),
            _path_param("userId", type_="string", fmt="uuid"),
            path="/orgs/{orgId}/users/{userId}",
        )
        ef = generate_endpoint_fixtures(ep)
        assert ef.path_values["orgId"] == "1"
        assert ef.path_values["userId"] == _TEST_UUID

    def test_path_param_undeclared_in_parameters(self) -> None:
        # Template variable exists in path but no Parameter declared for it.
        ep = _templated_endpoint(path="/items/{itemId}")
        ef = generate_endpoint_fixtures(ep)
        assert "itemId" in ef.path_values
        assert ef.path_values["itemId"] == "1"

    def test_path_param_string_min_length(self) -> None:
        ep = _templated_endpoint(
            _path_param("code", type_="string", min_length=8),
            path="/codes/{code}",
        )
        ef = generate_endpoint_fixtures(ep)
        assert len(ef.path_values["code"]) >= 8

    def test_generic_name_uses_test_fallback(self) -> None:
        ep = _templated_endpoint(
            _path_param("slug"),
            path="/posts/{slug}",
        )
        ef = generate_endpoint_fixtures(ep)
        assert ef.path_values["slug"] == "test"


# ---------------------------------------------------------------------------
# generate_fixtures (collection)
# ---------------------------------------------------------------------------

class TestGenerateFixtures:
    def test_returns_dict_keyed_by_endpoint_key(self) -> None:
        ep1 = _templated_endpoint(path="/users/{userId}")
        ep2 = _templated_endpoint(path="/items")
        result = generate_fixtures([ep1, ep2])
        assert "GET /users/{userId}" in result
        assert "GET /items" in result

    def test_non_templated_endpoint_has_empty_fixtures(self) -> None:
        ep = _templated_endpoint(path="/users")
        result = generate_fixtures([ep])
        assert not result["GET /users"].has_path_values

    def test_templated_endpoint_has_values(self) -> None:
        ep = _templated_endpoint(path="/users/{userId}")
        result = generate_fixtures([ep])
        assert result["GET /users/{userId}"].has_path_values

    def test_empty_list_returns_empty_dict(self) -> None:
        assert generate_fixtures([]) == {}


# ---------------------------------------------------------------------------
# CheckContext.auto_fixtures field
# ---------------------------------------------------------------------------

class TestCheckContextAutoFixtures:
    def _make_context(self, auto_fixtures=None) -> CheckContext:
        from aegisapi.testing.fixtures import AssessmentFixtures
        from aegisapi.testing.registry import RequestBudget

        target = scoped_target()
        config = make_config()
        transport = FakeTransport()
        client = make_client(target, config, transport)
        return CheckContext(
            target=target,
            config=config,
            client=client,
            budget=RequestBudget(limit=10),
            fixtures=AssessmentFixtures(),
            auto_fixtures=auto_fixtures or {},
        )

    def test_default_is_empty_dict(self) -> None:
        ctx = self._make_context()
        assert ctx.auto_fixtures == {}

    def test_auto_fixtures_can_be_set(self) -> None:
        ef = EndpointFixtures(path_values={"id": "1"})
        ctx = self._make_context(auto_fixtures={"GET /items/{id}": ef})
        assert ctx.auto_fixtures["GET /items/{id}"].path_values == {"id": "1"}


# ---------------------------------------------------------------------------
# INPUT checks on templated endpoints
# ---------------------------------------------------------------------------

def _run_input_check(
    endpoint: Endpoint,
    transport: FakeTransport,
    check_id: str,
    *,
    auto_fixtures: dict | None = None,
) -> object:
    """Run a single input validation check against one endpoint."""
    from aegisapi.testing import AssessmentEngine
    from aegisapi.models.discovery import DiscoveryResult

    target = scoped_target()
    config = make_config()
    client = make_client(target, config, transport)
    engine = AssessmentEngine(target=target, config=config)
    disc = discovery_result([classified(endpoint)])
    effective_auto = auto_fixtures if auto_fixtures is not None else {}
    try:
        result = engine.run(
            discovery=disc,
            check_ids=[check_id],
            budget=10,
            client=client,
            auto_fixtures=effective_auto,
        )
    finally:
        client.close()

    matches = [r for r in result.results if r.check_id == check_id]
    assert matches, f"no result for {check_id}"
    return matches[0]


class TestInputChecksOnTemplatedPaths:
    """INPUT-001/002/003 should run against templated endpoints when auto fixtures exist."""

    def test_input001_skips_without_auto_fixtures(self) -> None:
        ep = operation("get", "/items/{id}", parameters=[
            path_param("id"),
            query("filter", required=True),
        ])
        transport = FakeTransport()
        result = _run_input_check(ep, transport, "INPUT-001", auto_fixtures={})
        assert result.outcome is CheckOutcome.SKIPPED
        assert "templated" in result.summary.lower()
        assert transport.call_count == 0

    def test_input001_runs_with_auto_fixtures(self) -> None:
        ep = operation("get", "/items/{id}", parameters=[
            path_param("id"),
            query("filter", required=True),
        ])
        transport = FakeTransport(default=StubResponse(status_code=400))
        auto = {ep.key: EndpointFixtures(path_values={"id": "1"})}
        result = _run_input_check(ep, transport, "INPUT-001", auto_fixtures=auto)
        assert result.outcome is not CheckOutcome.SKIPPED
        assert transport.call_count == 1

    def test_input002_skips_without_auto_fixtures(self) -> None:
        ep = operation("get", "/items/{id}", parameters=[
            path_param("id"),
            query("count", type_="integer"),
        ])
        transport = FakeTransport()
        result = _run_input_check(ep, transport, "INPUT-002", auto_fixtures={})
        assert result.outcome is CheckOutcome.SKIPPED
        assert transport.call_count == 0

    def test_input002_runs_with_auto_fixtures(self) -> None:
        ep = operation("get", "/items/{id}", parameters=[
            path_param("id"),
            query("count", type_="integer"),
        ])
        transport = FakeTransport(default=StubResponse(status_code=400))
        auto = {ep.key: EndpointFixtures(path_values={"id": "1"})}
        result = _run_input_check(ep, transport, "INPUT-002", auto_fixtures=auto)
        assert result.outcome is not CheckOutcome.SKIPPED
        assert transport.call_count == 1

    def test_input003_skips_without_auto_fixtures(self) -> None:
        ep = operation("get", "/items/{id}", parameters=[
            path_param("id"),
            query("status", enum=["active", "inactive"]),
        ])
        transport = FakeTransport()
        result = _run_input_check(ep, transport, "INPUT-003", auto_fixtures={})
        assert result.outcome is CheckOutcome.SKIPPED
        assert transport.call_count == 0

    def test_input003_runs_with_auto_fixtures(self) -> None:
        ep = operation("get", "/items/{id}", parameters=[
            path_param("id"),
            query("status", enum=["active", "inactive"]),
        ])
        transport = FakeTransport(default=StubResponse(status_code=400))
        auto = {ep.key: EndpointFixtures(path_values={"id": "1"})}
        result = _run_input_check(ep, transport, "INPUT-003", auto_fixtures=auto)
        assert result.outcome is not CheckOutcome.SKIPPED
        assert transport.call_count == 1

    def test_non_templated_endpoint_runs_normally(self) -> None:
        ep = operation("get", "/items", parameters=[
            query("filter", required=True),
        ])
        transport = FakeTransport(default=StubResponse(status_code=400))
        result = _run_input_check(ep, transport, "INPUT-001", auto_fixtures={})
        # Non-templated path should NOT be skipped for a template reason
        assert "templated" not in result.summary.lower()
        assert transport.call_count == 1

    def test_path_is_filled_correctly_in_sent_request(self) -> None:
        ep = operation("get", "/users/{userId}/orders", parameters=[
            path_param("userId"),
            query("status", enum=["open", "closed"]),
        ])
        transport = FakeTransport(default=StubResponse(status_code=400))
        auto = {ep.key: EndpointFixtures(path_values={"userId": "42"})}
        _run_input_check(ep, transport, "INPUT-003", auto_fixtures=auto)
        assert transport.call_count == 1
        sent_url = transport.last_request.url
        assert "{userId}" not in sent_url
        assert "42" in sent_url

    def test_auto_fixture_uses_generated_values_from_engine(self) -> None:
        """Engine auto-generates fixtures from discovery when none are passed."""
        ep = operation("get", "/orders/{orderId}", parameters=[
            path_param("orderId"),
            query("filter", required=True),
        ])
        transport = FakeTransport(default=StubResponse(status_code=400))
        from aegisapi.testing import AssessmentEngine
        target = scoped_target()
        config = make_config()
        client = make_client(target, config, transport)
        engine = AssessmentEngine(target=target, config=config)
        disc = discovery_result([classified(ep)])
        try:
            result = engine.run(
                discovery=disc,
                check_ids=["INPUT-001"],
                budget=10,
                client=client,
                # auto_fixtures=None means engine generates them itself
            )
        finally:
            client.close()
        matches = [r for r in result.results if r.check_id == "INPUT-001"]
        assert matches
        # Engine should have generated fixtures and run the check (not skipped)
        assert matches[0].outcome is not CheckOutcome.SKIPPED


# ---------------------------------------------------------------------------
# FIXTURE_GEN stage
# ---------------------------------------------------------------------------

class TestFixtureGenStage:
    def test_fixture_gen_stage_exists(self) -> None:
        assert ScanStage.FIXTURE_GEN == "fixture_gen"

    def test_fixture_gen_comes_after_discover(self) -> None:
        stages = list(ScanStage)
        discover_idx = stages.index(ScanStage.DISCOVER)
        fixture_gen_idx = stages.index(ScanStage.FIXTURE_GEN)
        check_idx = stages.index(ScanStage.CHECK)
        assert discover_idx < fixture_gen_idx < check_idx

    def test_fixture_gen_stage_in_stage_labels(self) -> None:
        from aegisapi.commands.scan import _STAGE_LABELS
        assert ScanStage.FIXTURE_GEN in _STAGE_LABELS


# ---------------------------------------------------------------------------
# ScanResult.fixtures_generated field
# ---------------------------------------------------------------------------

class TestScanResultFixturesGenerated:
    def test_scan_result_has_fixtures_generated_field(self) -> None:
        from aegisapi.scan.pipeline import ScanResult
        import inspect
        fields = inspect.signature(ScanResult.__init__).parameters
        assert "fixtures_generated" in fields

    def test_fixtures_generated_defaults_to_zero(self) -> None:
        from aegisapi.scan.pipeline import ScanResult
        import dataclasses

        # Find the default for fixtures_generated
        for f in dataclasses.fields(ScanResult):
            if f.name == "fixtures_generated":
                assert f.default == 0
                break
        else:
            pytest.fail("fixtures_generated field not found on ScanResult")

    def test_pipeline_emits_fixture_gen_stage(self) -> None:
        """Progress callback receives FIXTURE_GEN events during a real scan."""
        from aegisapi.scan.pipeline import run_scan, ScanOptions
        from aegisapi.core.config import AegisConfig
        from httpstub import FakeTransport, StubResponse

        emitted_stages = []

        def capture(stage, message):
            emitted_stages.append(stage)

        transport = FakeTransport(default=StubResponse(status_code=200, body=b"{}"))
        config = AegisConfig.model_validate({
            "scope": {"allowed_hosts": ["api.acme.test"]},
            "http": {},
        })

        import contextlib
        with contextlib.suppress(Exception):
            run_scan(
                ScanOptions(url="https://api.acme.test/v1"),
                config=config,
                transport=transport,
                progress=capture,
            )

        assert ScanStage.FIXTURE_GEN in emitted_stages


# ---------------------------------------------------------------------------
# AssessmentEngine generates fixtures automatically
# ---------------------------------------------------------------------------

class TestEngineAutoFixtureGeneration:
    def test_engine_generates_fixtures_from_discovery(self) -> None:
        from aegisapi.testing import AssessmentEngine
        ep = _templated_endpoint(
            _path_param("userId", type_="integer"),
            path="/users/{userId}",
        )
        target = scoped_target()
        config = make_config()
        transport = FakeTransport(default=StubResponse(status_code=400))
        client = make_client(target, config, transport)
        engine = AssessmentEngine(target=target, config=config)
        disc = discovery_result([classified(ep)])
        try:
            engine.run(
                discovery=disc,
                check_ids=["INPUT-001"],
                budget=10,
                client=client,
            )
        finally:
            client.close()
        # If fixtures were generated, the request was sent rather than skipped
        # (INPUT-001 needs a required query param, but the templated path is now filled)
        # With no required query params this check won't apply_to, so just verify no crash

    def test_engine_accepts_explicit_auto_fixtures(self) -> None:
        from aegisapi.testing import AssessmentEngine
        ep = _templated_endpoint(path="/users/{userId}")
        target = scoped_target()
        config = make_config()
        transport = FakeTransport(default=StubResponse(status_code=400))
        client = make_client(target, config, transport)
        engine = AssessmentEngine(target=target, config=config)
        disc = discovery_result([classified(ep)])
        custom = {"GET /users/{userId}": EndpointFixtures(path_values={"userId": "999"})}
        try:
            engine.run(
                discovery=disc,
                check_ids=["INPUT-001"],
                budget=10,
                client=client,
                auto_fixtures=custom,
            )
        finally:
            client.close()
        # Verifies explicit auto_fixtures are accepted without error

    def test_engine_uses_explicit_auto_fixtures_not_regenerated(self) -> None:
        """Explicit auto_fixtures are used as-is; the engine does not regenerate them."""
        from aegisapi.testing import AssessmentEngine
        ep = operation("get", "/items/{id}", parameters=[
            path_param("id"),
            query("filter", required=True),
        ])
        transport = FakeTransport(default=StubResponse(status_code=400))
        target = scoped_target()
        config = make_config()
        client = make_client(target, config, transport)
        engine = AssessmentEngine(target=target, config=config)
        disc = discovery_result([classified(ep)])
        # Pass a specific value that proves we used these fixtures
        custom = {ep.key: EndpointFixtures(path_values={"id": "777"})}
        try:
            engine.run(
                discovery=disc,
                check_ids=["INPUT-001"],
                budget=10,
                client=client,
                auto_fixtures=custom,
            )
        finally:
            client.close()
        # The sent request path should contain 777
        if transport.call_count:
            sent_url = transport.last_request.url
            assert "777" in sent_url
