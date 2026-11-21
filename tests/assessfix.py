"""Builders for assessment and intelligence tests.

Constructing a discovery result by hand is verbose, and every test needs a
slightly different one. These helpers keep the tests about the behaviour under
test rather than about model construction.
"""

from __future__ import annotations

from collections.abc import Sequence

from aegisapi.core.config import AegisConfig
from aegisapi.http import ScopedHttpClient
from aegisapi.http.throttle import RequestThrottle
from aegisapi.models.assessment import (
    AssessmentResult,
    CheckCategory,
    CheckOutcome,
    CheckResult,
    Evidence,
    FindingClass,
)
from aegisapi.models.common import Confidence, Severity
from aegisapi.models.discovery import (
    ClassifiedEndpoint,
    DiscoveryResult,
    RelationshipKind,
    RelationshipObservation,
    ScopeClassification,
    SpecificationFormat,
    SpecificationInfo,
    SpecificationVersion,
)
from aegisapi.models.endpoint import (
    DeclaredSecurity,
    Endpoint,
    HttpMethod,
    MediaTypeSchema,
    Parameter,
    ParameterLocation,
    ResponseSpec,
    SchemaSummary,
    SecurityAlternative,
    SecurityPosture,
    SecurityRequirement,
)
from aegisapi.models.target import ScopeRules, Target

TOKEN = "eyJhbGciOiJIUzI1NiJ9.super-secret-token-value"


def operation(
    method: str,
    path: str,
    *,
    posture: SecurityPosture = SecurityPosture.NOT_DECLARED,
    schemes: Sequence[str] = (),
    permits_anonymous: bool = False,
    undefined_schemes: Sequence[str] = (),
    parameters: Sequence[Parameter] = (),
    response_schema: SchemaSummary | None = None,
    response_content_type: str = "application/json",
    tags: Sequence[str] = (),
) -> Endpoint:
    """Build an endpoint with the declared security a test needs."""
    alternatives: list[SecurityAlternative] = []
    if permits_anonymous:
        alternatives.append(SecurityAlternative(schemes=[]))
    if schemes:
        alternatives.append(
            SecurityAlternative(schemes=[SecurityRequirement(scheme_name=name) for name in schemes])
        )

    responses: list[ResponseSpec] = []
    if response_schema is not None:
        responses.append(
            ResponseSpec(
                status_code="200",
                content=[
                    MediaTypeSchema(
                        content_type=response_content_type, value_schema=response_schema
                    )
                ],
            )
        )

    return Endpoint(
        method=HttpMethod(method.lower()),
        path=path,
        operation_id=f"{method.lower()}{path.replace('/', '_')}",
        tags=list(tags),
        parameters=list(parameters),
        responses=responses,
        declared_security=DeclaredSecurity(
            posture=posture,
            alternatives=alternatives,
            undefined_schemes=list(undefined_schemes),
        ),
        source_pointer=f"#/paths/{path}/{method.lower()}",
    )


def protected(method: str, path: str, **kwargs: object) -> Endpoint:
    """An operation that declares a bearer scheme."""
    return operation(
        method,
        path,
        posture=SecurityPosture.INHERITED_GLOBAL,
        schemes=("bearerAuth",),
        **kwargs,  # type: ignore[arg-type]
    )


def public(method: str, path: str, **kwargs: object) -> Endpoint:
    """An operation documented as callable without credentials."""
    return operation(
        method,
        path,
        posture=SecurityPosture.EXPLICITLY_OPTIONAL,
        permits_anonymous=True,
        **kwargs,  # type: ignore[arg-type]
    )


def query(
    name: str,
    *,
    required: bool | None = None,
    type_: str | None = None,
    enum: Sequence[str] = (),
) -> Parameter:
    """A query parameter with a declared schema."""
    schema = None
    if type_ is not None or enum:
        schema = SchemaSummary(type=type_, enum_values=list(enum))
    return Parameter(
        name=name,
        location=ParameterLocation.QUERY,
        required=required,
        value_schema=schema,
    )


def path_param(name: str) -> Parameter:
    """A path parameter."""
    return Parameter(name=name, location=ParameterLocation.PATH, required=True)


def classified(
    endpoint: Endpoint,
    *,
    classification: ScopeClassification = ScopeClassification.IN_SCOPE,
    base: str = "https://api.acme.test/v1",
) -> ClassifiedEndpoint:
    """Wrap an endpoint with a scope classification."""
    return ClassifiedEndpoint(
        endpoint=endpoint,
        classification=classification,
        reason=f"endpoint is {classification.value}",
        resolved_url=f"{base}{endpoint.path}",
    )


def discovery_result(
    endpoints: Sequence[ClassifiedEndpoint],
    *,
    target_name: str = "acme",
    base_url: str = "https://api.acme.test/v1",
    relationships: Sequence[RelationshipObservation] = (),
) -> DiscoveryResult:
    """Build a discovery result around the given endpoints."""
    return DiscoveryResult(
        target_name=target_name,
        target_base_url=base_url,
        specification=SpecificationInfo(
            version=SpecificationVersion.OPENAPI_30,
            raw_version="3.0.3",
            format=SpecificationFormat.JSON,
            source_path="memory://spec.json",
            source_sha256="a" * 64,
            byte_size=100,
        ),
        endpoints=list(endpoints),
        relationships=list(relationships),
        aegisapi_version="0.1.0",
    )


def shared_schema_observation(name: str, keys: Sequence[str]) -> RelationshipObservation:
    """A Phase 3 observation that several operations share a declared schema."""
    return RelationshipObservation(
        kind=RelationshipKind.SHARED_SCHEMA,
        subject=name,
        description=f"{len(keys)} operation(s) reference the '{name}' schema.",
        endpoint_keys=list(keys),
        detail={"schema": name, "operation_count": str(len(keys))},
    )


def parent_child_observation(parent: str, keys: Sequence[str]) -> RelationshipObservation:
    """A Phase 3 observation of a nested resource path."""
    return RelationshipObservation(
        kind=RelationshipKind.PARENT_CHILD,
        subject=parent,
        description=f"'{parent}' identifies a resource with nested paths.",
        endpoint_keys=list(keys),
        detail={"parent_path": parent, "child_paths": "", "identifier": "orderId"},
    )


def make_config(
    *,
    allowed_hosts: Sequence[str] = ("api.acme.test",),
    requests_per_second: float = 100.0,
) -> AegisConfig:
    """A configuration that permits the test host and does not throttle."""
    return AegisConfig.model_validate(
        {
            "scope": {"allowed_hosts": list(allowed_hosts)},
            "http": {"requests_per_second": requests_per_second},
        }
    )


def make_client(
    target: Target,
    config: AegisConfig,
    transport: object,
    *,
    env: dict[str, str] | None = None,
) -> ScopedHttpClient:
    """A scoped client over an injected transport, with no real throttling."""
    return ScopedHttpClient(
        target=target,
        settings=config.scope,
        limits=config.http,
        transport=transport,  # type: ignore[arg-type]
        throttle=RequestThrottle(requests_per_second=10000.0, max_concurrency=4),
        env=env,
    )


def scoped_target(**overrides: object) -> Target:
    """A target whose scope admits everything under /v1."""
    defaults: dict[str, object] = {
        "name": "acme",
        "base_url": "https://api.acme.test/v1",
        "scope": ScopeRules(include_paths=["/v1"]),
    }
    defaults.update(overrides)
    return Target.create(**defaults)  # type: ignore[arg-type]


def check_result(
    check_id: str,
    endpoint_key: str,
    *,
    outcome: CheckOutcome = CheckOutcome.FAIL,
    finding_class: FindingClass = FindingClass.CONFIRMED,
    severity: Severity | None = Severity.HIGH,
    confidence: Confidence = Confidence.HIGH,
    category: CheckCategory = CheckCategory.AUTHORIZATION,
    evidence_count: int = 1,
    summary: str = "something was observed",
    target_name: str = "acme",
) -> CheckResult:
    """Build a check result for intelligence tests."""
    evidence = [
        Evidence(
            evidence_id=Evidence.make_id(check_id, f"obs{index}", endpoint_key, 200),
            label=f"observation {index}",
            method=endpoint_key.split(" ", 1)[0],
            url=f"https://api.acme.test/v1{endpoint_key.split(' ', 1)[-1]}",
            status_code=200,
        )
        for index in range(evidence_count)
    ]
    return CheckResult(
        check_id=check_id,
        check_name=f"check {check_id}",
        category=category,
        target_name=target_name,
        endpoint_key=endpoint_key,
        outcome=outcome,
        finding_class=finding_class,
        severity=severity,
        confidence=confidence,
        summary=summary,
        explanation="explanation",
        limitations=["a stated limitation"],
        evidence=evidence,
        requests_sent=len(evidence),
    )


def assessment_result(
    results: Sequence[CheckResult],
    *,
    target_name: str = "acme",
    base_url: str = "https://api.acme.test/v1",
) -> AssessmentResult:
    """Build an assessment result around the given check results."""
    return AssessmentResult(
        target_name=target_name,
        target_base_url=base_url,
        results=list(results),
        checks_run=sorted({item.check_id for item in results}),
        endpoints_considered=len({item.endpoint_key for item in results}),
        endpoints_tested=len({item.endpoint_key for item in results}),
        requests_sent=sum(item.requests_sent for item in results),
        request_budget=100,
        specification_sha256="a" * 64,
        aegisapi_version="0.1.0",
    )


__all__ = [
    "TOKEN",
    "assessment_result",
    "check_result",
    "classified",
    "discovery_result",
    "make_client",
    "make_config",
    "operation",
    "parent_child_observation",
    "path_param",
    "protected",
    "public",
    "query",
    "scoped_target",
    "shared_schema_observation",
]
