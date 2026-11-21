"""Schema-driven input validation checks.

These checks ask one narrow question: does the API reject input its own
specification says is invalid? They send a handful of benign, obviously
synthetic values derived from the declared schema.

What this module deliberately is not:

* **Not a fuzzer.** Each check sends at most one request per endpoint, with a
  value chosen from the schema rather than generated.
* **Not an exploit attempt.** No SQL, no shell metacharacters, no traversal, no
  SSRF targets, no oversized payloads. The values are things like
  ``aegisapi-invalid`` and ``-1``.
* **Not a conclusion from a 500.** A server error means the input was handled
  badly, which is worth reporting at low severity as an error-handling
  observation. It is not proof of an injection or a crash, and it is never
  reported as one.

Write methods are skipped unless the operator opted in, because an accepted
malformed body can still create or modify a record.
"""

from __future__ import annotations

from aegisapi.core.exceptions import TransportError
from aegisapi.models.assessment import (
    CheckCategory,
    CheckOutcome,
    CheckResult,
    FindingClass,
)
from aegisapi.models.common import Confidence, Severity
from aegisapi.models.discovery import ClassifiedEndpoint
from aegisapi.models.endpoint import Endpoint, Parameter, ParameterLocation, SchemaSummary
from aegisapi.testing import evidence as ev
from aegisapi.testing.auto_fixtures import fill_path_template
from aegisapi.testing.registry import (
    SAFE_METHODS,
    BaseCheck,
    CheckContext,
    _transport_method,
)

CLIENT_ERROR_RANGE = range(400, 500)
SERVER_ERROR_RANGE = range(500, 600)

NON_NUMERIC_VALUE = "aegisapi-not-a-number"
"""A value that cannot be an integer or a number.

Fixed and obviously synthetic, so it can never be mistaken for real data and
cannot carry a payload.
"""

INVALID_ENUM_VALUE = "aegisapi-invalid-enum"
"""A value no sensible enumeration contains."""

NUMERIC_TYPES = frozenset({"integer", "number"})


def _required_query_parameters(endpoint: Endpoint) -> list[Parameter]:
    """Query parameters the specification marks required."""
    return [
        item for item in endpoint.parameters_in(ParameterLocation.QUERY) if item.required is True
    ]


def _typed_query_parameters(
    endpoint: Endpoint, wanted: frozenset[str]
) -> list[tuple[Parameter, SchemaSummary]]:
    """Query parameters whose declared type is one of ``wanted``."""
    found: list[tuple[Parameter, SchemaSummary]] = []
    for item in endpoint.parameters_in(ParameterLocation.QUERY):
        schema = item.value_schema
        if schema is not None and schema.type in wanted:
            found.append((item, schema))
    return found


def _enum_query_parameters(endpoint: Endpoint) -> list[tuple[Parameter, SchemaSummary]]:
    """Query parameters that declare an enumeration."""
    found: list[tuple[Parameter, SchemaSummary]] = []
    for item in endpoint.parameters_in(ParameterLocation.QUERY):
        schema = item.value_schema
        if schema is not None and schema.enum_values:
            found.append((item, schema))
    return found


def _baseline_query(endpoint: Endpoint, *, omit: str | None = None) -> dict[str, str]:
    """Fill required query parameters with plausible values.

    Needed so a check isolates the one thing it is testing: sending a bad
    ``limit`` while omitting a required ``tenant`` would produce a 400 that
    proves nothing about ``limit``.
    """
    values: dict[str, str] = {}
    for item in _required_query_parameters(endpoint):
        if item.name == omit:
            continue
        schema = item.value_schema
        declared = schema.type if schema is not None else None
        if declared in NUMERIC_TYPES:
            values[item.name] = "1"
        elif declared == "boolean":
            values[item.name] = "true"
        elif schema is not None and schema.enum_values:
            values[item.name] = schema.enum_values[0]
        else:
            values[item.name] = "aegisapi"
    return values


class _QueryValidationCheck(BaseCheck):
    """Shared behaviour for the query-parameter validation checks."""

    category = CheckCategory.INPUT_VALIDATION
    requests_per_endpoint = 1

    def applies_to(self, endpoint: Endpoint, context: CheckContext) -> bool:
        """Read-shaped operations only, unless the operator opted into writes."""
        method = _transport_method(endpoint)
        if method is None:
            return False
        if method not in SAFE_METHODS and not context.fixtures.allow_write_methods:
            return False
        return self.has_subject(endpoint)

    def has_subject(self, endpoint: Endpoint) -> bool:  # pragma: no cover - overridden
        raise NotImplementedError

    def _send(
        self,
        endpoint: ClassifiedEndpoint,
        context: CheckContext,
        *,
        params: dict[str, str],
        label: str,
        note: str,
    ) -> tuple[CheckResult | None, object]:
        """Send one probe, returning an error result or the response."""
        operation = endpoint.endpoint
        path = operation.path
        if operation.is_templated:
            ep_fixtures = context.auto_fixtures.get(operation.key)
            if ep_fixtures is None or not ep_fixtures.has_path_values:
                return (
                    self.skipped(
                        endpoint,
                        context,
                        f"path {operation.path} is templated; no fixture value is declared",
                    ),
                    None,
                )
            filled = fill_path_template(operation.path, ep_fixtures.path_values)
            if filled is None:
                return (
                    self.skipped(
                        endpoint,
                        context,
                        f"path {operation.path} has template variables with no generated value",
                    ),
                    None,
                )
            path = filled
        if not context.budget.consume():
            return self.skipped(endpoint, context, "request budget exhausted"), None

        try:
            response = context.client.request(
                operation.method.value.upper(), path, params=params
            )
        except TransportError as exc:
            return (
                self.result(
                    endpoint,
                    context,
                    outcome=CheckOutcome.ERROR,
                    summary="The probe request did not complete.",
                    finding_class=FindingClass.INCONCLUSIVE,
                    explanation=exc.message,
                    limitations=["No conclusion about input validation can be drawn."],
                    requests_sent=1,
                ),
                None,
            )
        return None, ev.from_response(response, check_id=self.check_id, label=label, note=note)

    def _interpret(
        self,
        endpoint: ClassifiedEndpoint,
        context: CheckContext,
        *,
        status: int,
        observation: object,
        subject: str,
        expectation: str,
    ) -> CheckResult:
        """Turn a status into a result, conservatively.

        Three outcomes, and none of them claims an exploit:

        * a 4xx is the API doing its job;
        * a 5xx is an error-handling observation, not a crash or an injection;
        * a 2xx means the declared constraint is not enforced, which matters
          for the specification's accuracy more than for security.
        """
        evidence = [observation]  # type: ignore[list-item]

        if status in CLIENT_ERROR_RANGE:
            return self.result(
                endpoint,
                context,
                outcome=CheckOutcome.PASS,
                summary=f"{expectation} was rejected with {status}.",
                explanation="The API refused input its own specification calls invalid.",
                limitations=["Only this parameter and value were tested."],
                confidence=Confidence.HIGH,
                evidence=evidence,
                requests_sent=1,
            )

        if status in SERVER_ERROR_RANGE:
            return self.result(
                endpoint,
                context,
                outcome=CheckOutcome.FAIL,
                summary=f"{expectation} produced a server error ({status}).",
                finding_class=FindingClass.SUSPECTED,
                severity=Severity.LOW,
                confidence=Confidence.MEDIUM,
                explanation=(
                    f"The API returned {status} rather than rejecting the input. "
                    "Invalid input reaching an unhandled path is an error-handling "
                    "weakness; it is not evidence of injection, memory corruption, or "
                    "any other exploitable condition."
                ),
                limitations=[
                    "A server error alone does not establish an exploitable flaw.",
                    "No payload was sent; the value was a benign synthetic string.",
                    f"Only {subject} was tested.",
                ],
                next_step=(
                    "Check whether the error response leaks internal detail, and ask "
                    "whether this input path is validated server-side."
                ),
                evidence=evidence,
                requests_sent=1,
            )

        return self.result(
            endpoint,
            context,
            outcome=CheckOutcome.FAIL,
            summary=f"{expectation} was accepted ({status}).",
            finding_class=FindingClass.INFORMATIONAL,
            confidence=Confidence.MEDIUM,
            explanation=(
                "The API accepted input its specification declares invalid. That is a "
                "mismatch between documentation and behaviour; whether it has a "
                "security consequence depends on what the value is used for."
            ),
            limitations=[
                "Acceptance of invalid input is not itself a vulnerability.",
                "The effect of the value on the API's behaviour was not traced.",
            ],
            next_step=(
                f"Determine how {subject} is used server-side before treating this as "
                "a security issue."
            ),
            evidence=evidence,
            requests_sent=1,
        )


class MissingRequiredParameterCheck(_QueryValidationCheck):
    """Is a required query parameter actually required?"""

    check_id = "INPUT-001"
    name = "Required query parameter is enforced"
    description = "Omits one required query parameter and expects the API to reject the request."

    def has_subject(self, endpoint: Endpoint) -> bool:
        return bool(_required_query_parameters(endpoint))

    def run(self, endpoint: ClassifiedEndpoint, context: CheckContext) -> list[CheckResult]:
        operation = endpoint.endpoint
        required = _required_query_parameters(operation)
        if not required:
            return [self.skipped(endpoint, context, "no required query parameter declared")]
        omitted = required[0]

        error, observation = self._send(
            endpoint,
            context,
            params=_baseline_query(operation, omit=omitted.name),
            label=f"request omitting required parameter {omitted.name}",
            note=f"{omitted.name} is declared required",
        )
        if error is not None:
            return [error]

        return [
            self._interpret(
                endpoint,
                context,
                status=observation.status_code or 0,  # type: ignore[union-attr]
                observation=observation,
                subject=f"required parameter {omitted.name!r}",
                expectation=f"Omitting required parameter {omitted.name!r}",
            )
        ]


class WrongTypeParameterCheck(_QueryValidationCheck):
    """Is a declared primitive type enforced?"""

    check_id = "INPUT-002"
    name = "Declared parameter type is enforced"
    description = (
        "Sends a non-numeric value for a parameter declared as a number and expects "
        "the API to reject it."
    )

    def has_subject(self, endpoint: Endpoint) -> bool:
        return bool(_typed_query_parameters(endpoint, NUMERIC_TYPES))

    def run(self, endpoint: ClassifiedEndpoint, context: CheckContext) -> list[CheckResult]:
        operation = endpoint.endpoint
        numeric = _typed_query_parameters(operation, NUMERIC_TYPES)
        if not numeric:
            return [self.skipped(endpoint, context, "no numeric query parameter declared")]
        parameter, schema = numeric[0]

        params = _baseline_query(operation)
        params[parameter.name] = NON_NUMERIC_VALUE

        error, observation = self._send(
            endpoint,
            context,
            params=params,
            label=f"non-numeric value for {parameter.name}",
            note=f"{parameter.name} is declared as {schema.type}",
        )
        if error is not None:
            return [error]

        return [
            self._interpret(
                endpoint,
                context,
                status=observation.status_code or 0,  # type: ignore[union-attr]
                observation=observation,
                subject=f"parameter {parameter.name!r} declared as {schema.type}",
                expectation=f"A non-numeric value for {parameter.name!r}",
            )
        ]


class InvalidEnumValueCheck(_QueryValidationCheck):
    """Is a declared enumeration enforced?"""

    check_id = "INPUT-003"
    name = "Declared enumeration is enforced"
    description = "Sends a value outside a declared enumeration and expects the API to reject it."

    def has_subject(self, endpoint: Endpoint) -> bool:
        return bool(_enum_query_parameters(endpoint))

    def run(self, endpoint: ClassifiedEndpoint, context: CheckContext) -> list[CheckResult]:
        operation = endpoint.endpoint
        enums = _enum_query_parameters(operation)
        if not enums:
            return [self.skipped(endpoint, context, "no enumerated query parameter declared")]
        parameter, schema = enums[0]

        params = _baseline_query(operation)
        params[parameter.name] = INVALID_ENUM_VALUE
        declared = ", ".join(schema.enum_values[:5])

        error, observation = self._send(
            endpoint,
            context,
            params=params,
            label=f"out-of-enumeration value for {parameter.name}",
            note=f"{parameter.name} declares: {declared}",
        )
        if error is not None:
            return [error]

        return [
            self._interpret(
                endpoint,
                context,
                status=observation.status_code or 0,  # type: ignore[union-attr]
                observation=observation,
                subject=f"enumerated parameter {parameter.name!r}",
                expectation=f"A value outside the enumeration for {parameter.name!r}",
            )
        ]


__all__ = [
    "INVALID_ENUM_VALUE",
    "NON_NUMERIC_VALUE",
    "InvalidEnumValueCheck",
    "MissingRequiredParameterCheck",
    "WrongTypeParameterCheck",
]
