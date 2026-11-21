"""Object-level and function-level authorization checks.

Both checks here depend entirely on operator-declared fixtures, and both skip
when those are absent. That is not a limitation to work around; it is the
design:

* To know that reading an object was *wrong*, AegisAPI must be told who owns
  it. Without ownership it would be guessing identifiers and reading strangers'
  data, which this project will not do.
* To know that a role should not have reached an endpoint, AegisAPI must be
  told what that role may do. An endpoint named ``/admin`` is not evidence; the
  name of a path has never been an authorization model.

Writes are off unless the operator sets ``allow_write_methods``. A DELETE
during an assessment can destroy data that cannot be recovered.
"""

from __future__ import annotations

from aegisapi.core.exceptions import MissingCredentialError, TransportError
from aegisapi.core.scope import path_matches
from aegisapi.models.assessment import (
    CheckCategory,
    CheckOutcome,
    CheckResult,
    FindingClass,
)
from aegisapi.models.common import Confidence, Severity
from aegisapi.models.discovery import ClassifiedEndpoint
from aegisapi.models.endpoint import Endpoint
from aegisapi.models.http import HttpResponse
from aegisapi.testing import evidence as ev
from aegisapi.testing.fixtures import AccessExpectation, AssessmentIdentity, OwnedObject
from aegisapi.testing.registry import (
    SAFE_METHODS,
    BaseCheck,
    CheckContext,
    _transport_method,
)

DENYING_STATUSES = frozenset({401, 403, 404})
"""Statuses consistent with access being refused.

``404`` is included because hiding a resource from a caller who may not see it
is a legitimate and common authorization response.
"""


def _fill_path(path: str, parameter: str, value: str) -> str | None:
    """Substitute one path template variable, leaving the rest untouched.

    Returns ``None`` when the template still has unfilled variables afterwards:
    a request containing a literal ``{orgId}`` is meaningless, and inventing a
    value for it would be guessing at a resource nobody declared.
    """
    filled = path.replace(f"{{{parameter}}}", value)
    if "{" in filled or "}" in filled:
        return None
    return filled


def _method_allowed(endpoint: Endpoint, context: CheckContext) -> bool:
    """Whether this operation's method may be sent."""
    method = _transport_method(endpoint)
    if method is None:
        return False
    if method in SAFE_METHODS:
        return True
    return context.fixtures.allow_write_methods


class ObjectLevelAuthorizationCheck(BaseCheck):
    """Can one identity read another identity's object? (BOLA / IDOR)

    Runs only against identifiers the operator declared, with owners the
    operator stated. The comparison is between the owner's view and a
    non-owner's view of the *same* declared object - never a scan for
    identifiers that happen to exist.
    """

    check_id = "BOLA-001"
    name = "Object-level authorization between declared identities"
    description = (
        "Requests a declared object as its owner and as another declared identity, "
        "and compares the two responses. Requires fixtures with at least two "
        "identities and an owned object."
    )
    category = CheckCategory.AUTHORIZATION
    requests_per_endpoint = 2

    def applies_to(self, endpoint: Endpoint, context: CheckContext) -> bool:
        """Needs a declared object whose parameter this operation accepts."""
        if not _method_allowed(endpoint, context):
            return False
        if not context.fixtures.has_authorization_fixtures:
            return False
        names = set(endpoint.path_parameter_names)
        if not names:
            return False
        return any(item.parameter in names for item in context.fixtures.objects)

    def _candidates(
        self, endpoint: Endpoint, context: CheckContext
    ) -> tuple[OwnedObject, AssessmentIdentity, AssessmentIdentity] | None:
        """Pick an object, its owner, and one non-owner identity.

        Deterministic: the first declared object this operation accepts, its
        stated owner, and the first other identity in declaration order.
        """
        names = set(endpoint.path_parameter_names)
        for candidate in context.fixtures.objects:
            if candidate.parameter not in names:
                continue
            owner = context.fixtures.identity(candidate.owner)
            if owner is None:
                continue
            for other in context.fixtures.identities:
                if other.name != owner.name:
                    return candidate, owner, other
        return None

    def run(self, endpoint: ClassifiedEndpoint, context: CheckContext) -> list[CheckResult]:
        operation = endpoint.endpoint
        chosen = self._candidates(operation, context)
        if chosen is None:
            return [
                self.skipped(
                    endpoint,
                    context,
                    "no declared object with a known owner matches this operation",
                )
            ]
        obj, owner, other = chosen

        path = _fill_path(operation.path, obj.parameter, obj.value)
        if path is None:
            return [
                self.skipped(
                    endpoint,
                    context,
                    (
                        f"path {operation.path} needs values for parameters other than "
                        f"{obj.parameter!r}, which no fixture declares"
                    ),
                )
            ]

        method = operation.method.value.upper()
        if not context.budget.consume(2):
            return [self.skipped(endpoint, context, "request budget exhausted")]

        owner_view = self._fetch(context, owner, method, path)
        if isinstance(owner_view, str):
            return [self._unavailable(endpoint, context, owner, owner_view)]
        other_view = self._fetch(context, other, method, path)
        if isinstance(other_view, str):
            return [self._unavailable(endpoint, context, other, other_view)]

        owner_evidence = ev.from_response(
            owner_view,
            check_id=self.check_id,
            label=f"owner {owner.name} requests the object",
            note=f"{obj.parameter}={obj.value}, declared owner",
            identity=owner.name,
        )
        other_evidence = ev.from_response(
            other_view,
            check_id=self.check_id,
            label=f"non-owner {other.name} requests the same object",
            note=f"{obj.parameter}={obj.value}, not the declared owner",
            identity=other.name,
        )
        shared = [owner_evidence, other_evidence]

        if not owner_view.is_success:
            return [
                self.result(
                    endpoint,
                    context,
                    outcome=CheckOutcome.NEEDS_REVIEW,
                    summary=(
                        f"The declared owner could not read the object "
                        f"({owner_view.status_code}), so no baseline was established."
                    ),
                    finding_class=FindingClass.INCONCLUSIVE,
                    explanation=(
                        "Without a successful owner request there is nothing to compare "
                        "the non-owner's response against."
                    ),
                    limitations=[
                        "The fixture may name an object that no longer exists.",
                        f"The owner identity {owner.name!r} may lack a valid credential.",
                    ],
                    next_step="Confirm the fixture object and the owner's credential.",
                    confidence=Confidence.LOW,
                    evidence=shared,
                    requests_sent=2,
                    url=path,
                )
            ]

        if other_view.status_code in DENYING_STATUSES:
            return [
                self.result(
                    endpoint,
                    context,
                    outcome=CheckOutcome.PASS,
                    summary=(
                        f"A non-owner was refused with {other_view.status_code} while the "
                        "owner succeeded."
                    ),
                    explanation=(
                        f"Identity {other.name!r} could not read an object owned by "
                        f"{owner.name!r} through this operation."
                    ),
                    limitations=[
                        "Only one declared object and one identity pair were tested.",
                        "Other operations on the same resource may behave differently.",
                    ],
                    confidence=Confidence.HIGH,
                    evidence=shared,
                    requests_sent=2,
                    url=path,
                )
            ]

        if other_view.is_success and ev.bodies_match(owner_evidence, other_evidence):
            return [
                self.result(
                    endpoint,
                    context,
                    outcome=CheckOutcome.FAIL,
                    summary=(
                        f"Identity {other.name!r} received the same object as its owner "
                        f"{owner.name!r}."
                    ),
                    finding_class=FindingClass.CONFIRMED,
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    explanation=(
                        f"The operation returned an identical response body to the "
                        f"declared owner and to a different declared identity for "
                        f"{obj.parameter}={obj.value}. Object ownership is declared by "
                        "the operator, so the access was not permitted."
                    ),
                    limitations=[
                        "Only the bounded response excerpt was compared.",
                        "The sensitivity of the data returned was not assessed.",
                        "Only this identifier was tested; no others were tried.",
                    ],
                    next_step=(
                        "Verify by hand with both identities, then check whether other "
                        "methods on this resource are affected the same way."
                    ),
                    evidence=shared,
                    requests_sent=2,
                    url=path,
                )
            ]

        if other_view.is_success:
            return [
                self.result(
                    endpoint,
                    context,
                    outcome=CheckOutcome.FAIL,
                    summary=(
                        f"Identity {other.name!r} received {other_view.status_code} for an "
                        "object it does not own, with different content."
                    ),
                    finding_class=FindingClass.SUSPECTED,
                    severity=Severity.MEDIUM,
                    confidence=Confidence.MEDIUM,
                    explanation=(
                        "The non-owner was served rather than refused, but the body "
                        "differs from the owner's view. It may be a filtered or empty "
                        "representation rather than the owner's data."
                    ),
                    limitations=[
                        "The bodies differ, so leakage of the owner's data is not proven.",
                        "Only the bounded excerpt was compared.",
                    ],
                    next_step=(
                        "Inspect the non-owner response to see whether it contains any of "
                        "the owner's data."
                    ),
                    evidence=shared,
                    requests_sent=2,
                    url=path,
                )
            ]

        return [
            self.result(
                endpoint,
                context,
                outcome=CheckOutcome.NEEDS_REVIEW,
                summary=(
                    f"Non-owner request returned {other_view.status_code}, which is "
                    "neither access nor a clear refusal."
                ),
                finding_class=FindingClass.INCONCLUSIVE,
                explanation="The response does not establish whether access was granted.",
                limitations=["The status is ambiguous for an authorization decision."],
                confidence=Confidence.LOW,
                evidence=shared,
                requests_sent=2,
                url=path,
            )
        ]

    def _fetch(
        self, context: CheckContext, identity: AssessmentIdentity, method: str, path: str
    ) -> HttpResponse | str:
        """Request a path as one identity, or return a reason it failed."""
        try:
            return context.client_for(identity).request(method, path)
        except MissingCredentialError as exc:
            return exc.message
        except TransportError as exc:
            return exc.message

    def _unavailable(
        self,
        endpoint: ClassifiedEndpoint,
        context: CheckContext,
        identity: AssessmentIdentity,
        detail: str,
    ) -> CheckResult:
        """A result recording that one identity could not be used."""
        return self.result(
            endpoint,
            context,
            outcome=CheckOutcome.SKIPPED,
            summary=f"Identity {identity.name!r} could not be used for this comparison.",
            explanation=detail,
            limitations=["Authorization cannot be compared without both identities."],
            next_step=f"Check the credential and connectivity for {identity.name!r}.",
        )


class FunctionLevelAuthorizationCheck(BaseCheck):
    """Can an identity reach a function it was declared not to have? (BFLA)

    Driven by declared expectations only. Without an expectation for an
    identity and operation, there is nothing to compare observed behaviour
    against, and the check skips.
    """

    check_id = "BFLA-001"
    name = "Function-level authorization against declared expectations"
    description = (
        "Calls an operation as an identity the operator declared should not be "
        "permitted, and reports when it succeeds. Requires declared access "
        "expectations."
    )
    category = CheckCategory.AUTHORIZATION
    requests_per_endpoint = 1

    def _expectations(
        self, endpoint: Endpoint, context: CheckContext
    ) -> list[tuple[AccessExpectation, AssessmentIdentity]]:
        """Deny-expectations that apply to this operation, with their identities."""
        method = _transport_method(endpoint)
        matches: list[tuple[AccessExpectation, AssessmentIdentity]] = []
        for expectation in context.fixtures.expectations:
            if expectation.allowed:
                continue
            if expectation.method is not None and expectation.method is not method:
                continue
            # Reuse the project's one pattern matcher rather than a second one.
            if not path_matches(endpoint.path, expectation.path):
                continue
            identity = context.fixtures.identity(expectation.identity)
            if identity is not None:
                matches.append((expectation, identity))
        return matches

    def applies_to(self, endpoint: Endpoint, context: CheckContext) -> bool:
        """Needs at least one deny-expectation for this operation."""
        if not _method_allowed(endpoint, context):
            return False
        return bool(self._expectations(endpoint, context))

    def run(self, endpoint: ClassifiedEndpoint, context: CheckContext) -> list[CheckResult]:
        operation = endpoint.endpoint
        matches = self._expectations(operation, context)
        if not matches:
            return [
                self.skipped(
                    endpoint,
                    context,
                    "no declared access expectation forbids an identity here",
                )
            ]

        expectation, identity = matches[0]
        if operation.is_templated:
            return [
                self.skipped(
                    endpoint,
                    context,
                    (f"path {operation.path} is templated; declare a fixture object to test it"),
                )
            ]

        if not context.budget.consume():
            return [self.skipped(endpoint, context, "request budget exhausted")]

        method = operation.method.value.upper()
        try:
            response = context.client_for(identity).request(method, operation.path)
        except MissingCredentialError as exc:
            return [
                self.result(
                    endpoint,
                    context,
                    outcome=CheckOutcome.SKIPPED,
                    summary=f"Identity {identity.name!r} has no usable credential.",
                    explanation=exc.message,
                    limitations=["The expectation could not be tested."],
                    next_step=f"Set the credential variable for {identity.name!r}.",
                )
            ]
        except TransportError as exc:
            return [
                self.result(
                    endpoint,
                    context,
                    outcome=CheckOutcome.ERROR,
                    summary="The request did not complete.",
                    finding_class=FindingClass.INCONCLUSIVE,
                    explanation=exc.message,
                    limitations=["No authorization conclusion can be drawn."],
                    requests_sent=1,
                )
            ]

        observation = ev.from_response(
            response,
            check_id=self.check_id,
            label=f"{identity.name} calls an operation it should not reach",
            note=(
                f"operator declared {identity.name!r} (role "
                f"{identity.role or 'unspecified'}) not permitted on {expectation.path}"
            ),
            identity=identity.name,
        )

        if response.status_code in DENYING_STATUSES:
            return [
                self.result(
                    endpoint,
                    context,
                    outcome=CheckOutcome.PASS,
                    summary=(
                        f"Identity {identity.name!r} was refused with "
                        f"{response.status_code}, as declared."
                    ),
                    explanation=(
                        "The operation refused an identity the operator declared should "
                        "not be permitted."
                    ),
                    limitations=[
                        "Only this identity and operation were tested.",
                        "Refusal does not establish that permitted roles work correctly.",
                    ],
                    confidence=Confidence.HIGH,
                    evidence=[observation],
                    requests_sent=1,
                )
            ]

        if response.is_success:
            return [
                self.result(
                    endpoint,
                    context,
                    outcome=CheckOutcome.FAIL,
                    summary=(
                        f"Identity {identity.name!r} reached an operation it was declared "
                        f"not to have: {response.status_code}."
                    ),
                    finding_class=FindingClass.CONFIRMED,
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    explanation=(
                        f"The operator declared that {identity.name!r} (role "
                        f"{identity.role or 'unspecified'}) must not be permitted on "
                        f"{expectation.path}. The operation returned "
                        f"{response.status_code} for that identity, so the declared "
                        "restriction is not enforced."
                    ),
                    limitations=[
                        "The conclusion rests on the operator's declared expectation.",
                        "What the response contained was not assessed for sensitivity.",
                    ],
                    next_step=(
                        "Confirm the expectation is correct with the API owner, then "
                        "verify the call by hand."
                    ),
                    evidence=[observation],
                    requests_sent=1,
                )
            ]

        return [
            self.result(
                endpoint,
                context,
                outcome=CheckOutcome.NEEDS_REVIEW,
                summary=(
                    f"Identity {identity.name!r} received {response.status_code}, which is "
                    "neither access nor a clear refusal."
                ),
                finding_class=FindingClass.INCONCLUSIVE,
                explanation="The response does not establish whether the call was permitted.",
                limitations=["The status is ambiguous for an authorization decision."],
                confidence=Confidence.LOW,
                evidence=[observation],
                requests_sent=1,
            )
        ]


__all__ = [
    "DENYING_STATUSES",
    "FunctionLevelAuthorizationCheck",
    "ObjectLevelAuthorizationCheck",
]
