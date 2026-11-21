"""Schema validation checks.

Two checks verify that an API's behaviour aligns with what its specification
declares, without classifying every mismatch as a security vulnerability.

:class:`ResponseSchemaCheck` (SCHEMA-001)
    Sends a baseline GET to each endpoint, attempts to parse the JSON
    response body, and validates it against the declared response schema.
    Reports structural violations as documentation-accuracy observations.

:class:`ResponseConformanceCheck` (SCHEMA-002)
    Checks that the HTTP status code and content type the API actually returns
    are declared in the endpoint's response specifications.  An undeclared
    status or content type is a specification drift, not a confirmed exploit.

Design constraints shared with the input validation checks:

* At most one request per endpoint per check, so budget cost is predictable.
* No sensitive values appear in violations or findings — types and paths only.
* Truncated or unparseable response bodies produce a SKIPPED result with a
  note, so a schema validation failure is never a false negative caused by an
  oversized API response.
* Write methods are skipped unless the operator opted in, because schema
  validation of a resource that does not yet exist is uninformative.
"""

from __future__ import annotations

import json

from aegisapi.core.exceptions import TransportError
from aegisapi.models.assessment import (
    CheckCategory,
    CheckOutcome,
    CheckResult,
    FindingClass,
)
from aegisapi.models.common import Confidence
from aegisapi.models.discovery import ClassifiedEndpoint
from aegisapi.models.endpoint import Endpoint, ResponseSpec, SchemaSummary
from aegisapi.models.http import HttpResponse
from aegisapi.testing import evidence as ev
from aegisapi.testing.auto_fixtures import fill_path_template
from aegisapi.testing.registry import (
    SAFE_METHODS,
    BaseCheck,
    CheckContext,
    _transport_method,
)
from aegisapi.testing.schema_validator import SchemaViolation, validate_against_schema

_JSON_CONTENT_TYPES: frozenset[str] = frozenset({"application/json"})
"""Content-type prefixes that indicate a JSON body."""


def _bare_content_type(content_type: str) -> str:
    """Strip parameters (``; charset=…``) from a content-type value."""
    return content_type.split(";")[0].strip().lower()


def _is_json_content_type(content_type: str) -> bool:
    """True when the content type indicates a JSON body."""
    bare = _bare_content_type(content_type)
    return bare in _JSON_CONTENT_TYPES or bare.endswith("+json")


def _find_response_spec(endpoint: Endpoint, status_code: int) -> ResponseSpec | None:
    """Return the ResponseSpec declared for *status_code*, or None.

    Matching order: exact status string, then wildcard class (``2XX``),
    then ``default``.
    """
    exact = str(status_code)
    wildcard = f"{status_code // 100}XX"
    fallback: ResponseSpec | None = None
    class_match: ResponseSpec | None = None

    for resp in endpoint.responses:
        sc = resp.status_code.strip()
        if sc == exact:
            return resp
        if sc.upper() == wildcard and class_match is None:
            class_match = resp
        if sc.lower() == "default" and fallback is None:
            fallback = resp

    return class_match or fallback


def _find_json_schema(resp_spec: ResponseSpec) -> SchemaSummary | None:
    """Return the declared JSON schema for a response, or None."""
    for media in resp_spec.content:
        if _is_json_content_type(media.content_type) and media.value_schema is not None:
            return media.value_schema
    return None


def _has_response_schema(endpoint: Endpoint) -> bool:
    """True when at least one declared response has a JSON schema."""
    for resp in endpoint.responses:
        if _find_json_schema(resp) is not None:
            return True
    return False


def _send_baseline(
    endpoint: ClassifiedEndpoint,
    context: CheckContext,
    *,
    check: BaseCheck,
    label: str,
    note: str,
) -> tuple[CheckResult | None, HttpResponse | None]:
    """Send a read-shaped request to the endpoint.

    Returns ``(error_result, None)`` when the request could not be sent
    (templated path with no fixture, budget exhausted, transport error), or
    ``(None, response)`` on success.
    """
    operation = endpoint.endpoint
    path = operation.path

    if operation.is_templated:
        ep_fixtures = context.auto_fixtures.get(operation.key)
        if ep_fixtures is None or not ep_fixtures.has_path_values:
            return (
                check.skipped(
                    endpoint,
                    context,
                    f"path {operation.path} is templated; no fixture value is available",
                ),
                None,
            )
        filled = fill_path_template(operation.path, ep_fixtures.path_values)
        if filled is None:
            return (
                check.skipped(
                    endpoint,
                    context,
                    f"path {operation.path} has template variables with no generated value",
                ),
                None,
            )
        path = filled

    if not context.budget.consume():
        return check.skipped(endpoint, context, "request budget exhausted"), None

    try:
        response = context.client.request(
            operation.method.value.upper(), path
        )
    except TransportError as exc:
        return (
            check.result(
                endpoint,
                context,
                outcome=CheckOutcome.ERROR,
                summary="The baseline request did not complete.",
                finding_class=FindingClass.INCONCLUSIVE,
                explanation=exc.message,
                limitations=["No schema validation conclusion can be drawn."],
                requests_sent=1,
            ),
            None,
        )

    return None, response


def _violations_summary(violations: list[SchemaViolation]) -> str:
    """One-line summary of violations, without leaking values."""
    if not violations:
        return "Response body matches the declared schema."
    codes: dict[str, int] = {}
    for v in violations:
        codes[v.code] = codes.get(v.code, 0) + 1
    parts = [f"{count} {code}" for code, count in sorted(codes.items())]
    noun = "violation" if len(violations) == 1 else "violations"
    return f"Response body has {len(violations)} schema {noun}: {', '.join(parts)}"


class ResponseSchemaCheck(BaseCheck):
    """Does the response body match the declared JSON schema?

    Sends one baseline GET request per endpoint, parses the JSON body, and
    validates it against the declared response schema. Schema violations are
    reported as documentation-accuracy observations — not as security findings —
    because a type mismatch does not by itself establish exploitability.

    A truncated response body, one that is not JSON, or an endpoint with no
    declared JSON schema produces a SKIPPED result.
    """

    check_id = "SCHEMA-001"
    name = "Response body matches declared schema"
    description = (
        "Validates the JSON response body against the declared response schema "
        "and reports structural violations."
    )
    category = CheckCategory.SCHEMA_VALIDATION
    requests_per_endpoint = 1

    def applies_to(self, endpoint: Endpoint, context: CheckContext) -> bool:
        method = _transport_method(endpoint)
        if method is None:
            return False
        if method not in SAFE_METHODS and not context.fixtures.allow_write_methods:
            return False
        return _has_response_schema(endpoint)

    def run(self, endpoint: ClassifiedEndpoint, context: CheckContext) -> list[CheckResult]:
        operation = endpoint.endpoint
        error, response = _send_baseline(
            endpoint, context, check=self,
            label="baseline request for schema validation",
            note="validating response body against declared schema",
        )
        if error is not None:
            return [error]

        assert response is not None
        evidence = ev.from_response(
            response,
            check_id=self.check_id,
            label="baseline response",
            note="response body validated against declared schema",
        )

        # Find the ResponseSpec matching the returned status code.
        spec = _find_response_spec(operation, response.status_code)
        if spec is None:
            return [self.result(
                endpoint, context,
                outcome=CheckOutcome.SKIPPED,
                summary=(
                    f"No declared response for status {response.status_code}; "
                    "schema validation skipped."
                ),
                explanation=(
                    "The declared response specifications do not cover the status "
                    "code returned by this request, so there is no schema to "
                    "validate against."
                ),
                evidence=[evidence],
                requests_sent=1,
            )]

        schema = _find_json_schema(spec)
        if schema is None:
            return [self.result(
                endpoint, context,
                outcome=CheckOutcome.SKIPPED,
                summary=(
                    f"No JSON schema declared for status {response.status_code}; "
                    "schema validation skipped."
                ),
                explanation=(
                    "The matching declared response has no JSON schema, so the "
                    "body cannot be validated against it."
                ),
                evidence=[evidence],
                requests_sent=1,
            )]

        # Check the response content type before attempting JSON parsing.
        actual_ct = response.content_type or ""
        if not _is_json_content_type(actual_ct):
            return [self.result(
                endpoint, context,
                outcome=CheckOutcome.SKIPPED,
                summary=(
                    f"Response content type '{actual_ct}' is not JSON; "
                    "body schema validation skipped."
                ),
                explanation=(
                    "Schema validation requires a JSON response body. The "
                    "response content type does not indicate JSON."
                ),
                evidence=[evidence],
                requests_sent=1,
            )]

        # Parse the body preview. A truncated body may not be valid JSON.
        if response.truncated or response.body_preview is None:
            return [self.result(
                endpoint, context,
                outcome=CheckOutcome.SKIPPED,
                summary="Response body was truncated; schema validation skipped.",
                explanation=(
                    "The response body exceeded the preview limit and was cut "
                    "short, so it cannot be parsed as JSON for schema validation."
                ),
                evidence=[evidence],
                requests_sent=1,
            )]

        try:
            parsed = json.loads(response.body_preview)
        except (json.JSONDecodeError, ValueError):
            return [self.result(
                endpoint, context,
                outcome=CheckOutcome.SKIPPED,
                summary="Response body is not valid JSON; schema validation skipped.",
                explanation="The response body could not be parsed as JSON.",
                evidence=[evidence],
                requests_sent=1,
            )]

        violations = validate_against_schema(parsed, schema)

        if not violations:
            return [self.result(
                endpoint, context,
                outcome=CheckOutcome.PASS,
                summary="Response body matches the declared schema.",
                explanation=(
                    "Every validated field conforms to its declared type, "
                    "constraints, and required-property list."
                ),
                confidence=Confidence.MEDIUM,
                evidence=[evidence],
                requests_sent=1,
            )]

        explanation_lines = [v.message for v in violations[:5]]
        if len(violations) > 5:
            explanation_lines.append(f"… and {len(violations) - 5} more violation(s).")
        explanation = "\n".join(explanation_lines)

        return [self.result(
            endpoint, context,
            outcome=CheckOutcome.FAIL,
            finding_class=FindingClass.INFORMATIONAL,
            confidence=Confidence.MEDIUM,
            summary=_violations_summary(violations),
            explanation=explanation,
            limitations=[
                "Schema violations indicate specification drift, not necessarily "
                "an exploitable flaw.",
                "Validation is based on one baseline response; other responses "
                "may conform.",
                "Only the top-level structure and declared properties were "
                "validated.",
            ],
            next_step=(
                "Review each violation path in the API source to determine "
                "whether the specification or the implementation should change."
            ),
            evidence=[evidence],
            requests_sent=1,
        )]


class ResponseConformanceCheck(BaseCheck):
    """Are the response status code and content type declared?

    Checks that what the API actually returns for a baseline request is listed
    in the endpoint's declared responses. An undeclared status code or content
    type is a specification accuracy issue — the API is behaving differently
    from what its documentation says — which may matter for client
    compatibility and API governance without being an exploitable vulnerability.
    """

    check_id = "SCHEMA-002"
    name = "Response status and content type are declared"
    description = (
        "Checks that the HTTP status code and content type returned by the API "
        "are declared in the endpoint's response specifications."
    )
    category = CheckCategory.SCHEMA_VALIDATION
    requests_per_endpoint = 1

    def applies_to(self, endpoint: Endpoint, context: CheckContext) -> bool:
        method = _transport_method(endpoint)
        if method is None:
            return False
        if method not in SAFE_METHODS and not context.fixtures.allow_write_methods:
            return False
        return bool(endpoint.responses)

    def run(self, endpoint: ClassifiedEndpoint, context: CheckContext) -> list[CheckResult]:
        operation = endpoint.endpoint
        error, response = _send_baseline(
            endpoint, context, check=self,
            label="baseline request for conformance check",
            note="checking status code and content type against declared responses",
        )
        if error is not None:
            return [error]

        assert response is not None
        evidence = ev.from_response(
            response,
            check_id=self.check_id,
            label="baseline response",
            note="status code and content type compared against declared responses",
        )

        status = response.status_code
        actual_ct = _bare_content_type(response.content_type or "")

        spec = _find_response_spec(operation, status)
        status_declared = spec is not None

        # Find declared content types for the matched response spec.
        ct_declared: bool
        if not status_declared or spec is None:
            ct_declared = False
        elif not actual_ct:
            ct_declared = True  # no content type to check; treat as conformant
        else:
            declared_bare = {_bare_content_type(c) for c in spec.content_types}
            ct_declared = not declared_bare or actual_ct in declared_bare

        if status_declared and ct_declared:
            return [self.result(
                endpoint, context,
                outcome=CheckOutcome.PASS,
                summary=(
                    f"Status {status} and content type {actual_ct!r} are "
                    "both declared in the response specification."
                ),
                confidence=Confidence.HIGH,
                evidence=[evidence],
                requests_sent=1,
            )]

        issues: list[str] = []
        if not status_declared:
            issues.append(f"status {status} is not declared in the response specifications")
        elif not ct_declared:
            issues.append(
                f"content type '{actual_ct}' is not declared for status {status}"
            )

        summary = f"Response conformance issue: {'; '.join(issues)}."

        return [self.result(
            endpoint, context,
            outcome=CheckOutcome.FAIL,
            finding_class=FindingClass.INFORMATIONAL,
            confidence=Confidence.MEDIUM,
            summary=summary,
            explanation=(
                "The API returned a status code or content type that its own "
                "specification does not declare. This is a documentation accuracy "
                "issue: clients that follow the spec strictly may not handle the "
                "undeclared response correctly."
            ),
            limitations=[
                "An undeclared status code or content type is not itself a "
                "vulnerability.",
                "Only one baseline request was checked.",
                "The specification may be incomplete rather than the API incorrect.",
            ],
            next_step=(
                "Add the observed status code and content type to the endpoint's "
                "response declarations, or investigate why the API diverges from "
                "its own specification."
            ),
            evidence=[evidence],
            requests_sent=1,
        )]


__all__ = [
    "ResponseConformanceCheck",
    "ResponseSchemaCheck",
]
