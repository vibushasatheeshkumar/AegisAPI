"""Authentication enforcement checks.

The discipline here is the difference between a useful tool and a noisy one.
Two rules shape every check in this module:

* **A status code alone proves nothing.** A 200 to an unauthenticated request
  might be a public endpoint, a cached error page, or a login form. Confirming
  that authentication is not enforced needs the *same resource* returned to
  both an authenticated and an unauthenticated caller, which is why
  :func:`~aegisapi.testing.evidence.bodies_match` exists.
* **Missing specification metadata is not a vulnerability.** An operation the
  document says nothing about is a documentation gap. It is reported as such,
  at informational level, and never as a bypass.
"""

from __future__ import annotations

from aegisapi.core.exceptions import MissingCredentialError, TransportError
from aegisapi.models.assessment import (
    CheckCategory,
    CheckOutcome,
    CheckResult,
    FindingClass,
)
from aegisapi.models.common import Confidence, Severity
from aegisapi.models.discovery import ClassifiedEndpoint
from aegisapi.models.endpoint import Endpoint, SecurityPosture
from aegisapi.models.target import AuthMethod
from aegisapi.testing import evidence as ev
from aegisapi.testing.registry import SAFE_METHODS, BaseCheck, CheckContext, _transport_method

REJECTING_STATUSES = frozenset({401, 403})
"""Statuses that demonstrate a request was refused."""

PROBE_TOKEN = "aegisapi-invalid-probe-token"
"""A deliberately invalid bearer token.

Not a guess at a real credential: a fixed, obviously synthetic string, so the
request cannot accidentally authenticate as anyone.
"""


def _declares_authentication(endpoint: Endpoint) -> bool:
    """``True`` when the specification says this operation needs credentials."""
    declared = endpoint.declared_security
    if declared.posture in {
        SecurityPosture.NOT_DECLARED,
        SecurityPosture.EXPLICITLY_OPTIONAL,
    }:
        return False
    return bool(declared.scheme_names) and not declared.permits_anonymous


class UnauthenticatedAccessCheck(BaseCheck):
    """Does an operation that declares authentication actually require it?"""

    check_id = "AUTH-001"
    name = "Declared authentication is enforced"
    description = (
        "Sends the operation without credentials and compares the result with an "
        "authenticated request. Only a matching response body confirms that "
        "authentication is not enforced."
    )
    category = CheckCategory.AUTHENTICATION
    requests_per_endpoint = 2

    def applies_to(self, endpoint: Endpoint, context: CheckContext) -> bool:
        """Needs a read-shaped operation that declares authentication."""
        if _transport_method(endpoint) not in SAFE_METHODS:
            return False
        if not _declares_authentication(endpoint):
            return False
        return context.target.auth.method is not AuthMethod.NONE

    def run(self, endpoint: ClassifiedEndpoint, context: CheckContext) -> list[CheckResult]:
        operation = endpoint.endpoint
        path = operation.path
        schemes = ", ".join(operation.declared_security.scheme_names) or "unnamed"

        if not context.budget.consume():
            return [self.skipped(endpoint, context, "request budget exhausted")]

        try:
            unauth = context.client.request(
                operation.method.value.upper(), path, authenticate=False
            )
        except TransportError as exc:
            return [
                self.result(
                    endpoint,
                    context,
                    outcome=CheckOutcome.ERROR,
                    summary="The unauthenticated request did not complete.",
                    finding_class=FindingClass.INCONCLUSIVE,
                    explanation=exc.message,
                    limitations=["No conclusion about authentication can be drawn."],
                    evidence=[
                        ev.from_failure(
                            check_id=self.check_id,
                            label="unauthenticated request failed",
                            method=operation.method.value.upper(),
                            url=endpoint.resolved_url or path,
                            note=exc.message,
                        )
                    ],
                    requests_sent=1,
                )
            ]

        unauth_evidence = ev.from_response(
            unauth,
            check_id=self.check_id,
            label="request without credentials",
            note=f"operation declares {schemes}",
        )

        if unauth.status_code in REJECTING_STATUSES:
            return [
                self.result(
                    endpoint,
                    context,
                    outcome=CheckOutcome.PASS,
                    summary=f"Unauthenticated request was refused with {unauth.status_code}.",
                    explanation=(
                        "The operation declares authentication and refused a request "
                        "that carried none."
                    ),
                    limitations=[
                        "Only this operation and method were tested.",
                        "Refusal does not establish that authorisation is correct.",
                    ],
                    confidence=Confidence.HIGH,
                    evidence=[unauth_evidence],
                    requests_sent=1,
                )
            ]

        if not unauth.is_success:
            return [
                self.result(
                    endpoint,
                    context,
                    outcome=CheckOutcome.NEEDS_REVIEW,
                    summary=(
                        f"Unauthenticated request returned {unauth.status_code}, which is "
                        "neither a refusal nor a success."
                    ),
                    finding_class=FindingClass.INCONCLUSIVE,
                    explanation=(
                        "The response does not show the operation being served, and does "
                        "not show it being refused for lack of credentials."
                    ),
                    limitations=["The response was not compared with an authenticated one."],
                    next_step="Send the request manually and compare the two responses.",
                    confidence=Confidence.LOW,
                    evidence=[unauth_evidence],
                    requests_sent=1,
                )
            ]

        # A 2xx without credentials. On its own that is not a bypass, so the
        # authenticated request decides.
        if not context.budget.consume():
            return [
                self.result(
                    endpoint,
                    context,
                    outcome=CheckOutcome.NEEDS_REVIEW,
                    summary="Unauthenticated request succeeded; no budget left to compare.",
                    finding_class=FindingClass.SUSPECTED,
                    severity=Severity.MEDIUM,
                    confidence=Confidence.LOW,
                    explanation=(
                        "The operation declares authentication but served a request "
                        "without credentials. The authenticated comparison was not made."
                    ),
                    limitations=[
                        "No authenticated response was obtained, so the bodies were not compared.",
                        "The response may be a public error or placeholder document.",
                    ],
                    next_step="Re-run with a larger budget to compare both responses.",
                    evidence=[unauth_evidence],
                    requests_sent=1,
                )
            ]

        try:
            authed = context.client.request(operation.method.value.upper(), path, authenticate=True)
        except MissingCredentialError as exc:
            return [
                self.result(
                    endpoint,
                    context,
                    outcome=CheckOutcome.NEEDS_REVIEW,
                    summary="Unauthenticated request succeeded; credentials unavailable.",
                    finding_class=FindingClass.SUSPECTED,
                    severity=Severity.MEDIUM,
                    confidence=Confidence.LOW,
                    explanation=(
                        "The operation declares authentication but served an "
                        "unauthenticated request. The comparison needs a working "
                        "credential."
                    ),
                    limitations=[exc.message, "The responses were not compared."],
                    next_step="Set the target's credential variable and re-run.",
                    evidence=[unauth_evidence],
                    requests_sent=1,
                )
            ]
        except TransportError as exc:
            return [
                self.result(
                    endpoint,
                    context,
                    outcome=CheckOutcome.NEEDS_REVIEW,
                    summary="Unauthenticated request succeeded; comparison failed.",
                    finding_class=FindingClass.SUSPECTED,
                    severity=Severity.MEDIUM,
                    confidence=Confidence.LOW,
                    explanation=exc.message,
                    limitations=["The authenticated comparison did not complete."],
                    evidence=[unauth_evidence],
                    requests_sent=2,
                )
            ]

        auth_evidence = ev.from_response(
            authed,
            check_id=self.check_id,
            label="request with credentials",
            note="comparison for the unauthenticated response",
        )

        if authed.is_success and ev.bodies_match(unauth_evidence, auth_evidence):
            return [
                self.result(
                    endpoint,
                    context,
                    outcome=CheckOutcome.FAIL,
                    summary=(
                        "The operation returned the same response with and without credentials."
                    ),
                    finding_class=FindingClass.CONFIRMED,
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    explanation=(
                        f"The specification declares {schemes} for this operation, but "
                        "an unauthenticated request received the same body as an "
                        "authenticated one. The credential made no difference to what "
                        "was served."
                    ),
                    limitations=[
                        "Only the response excerpt was compared, not the full body.",
                        "The data returned may itself be public; sensitivity was not assessed.",
                    ],
                    next_step=(
                        "Confirm by hand whether the returned data is meant to be public, "
                        "and check whether other operations on the same resource behave "
                        "the same way."
                    ),
                    evidence=[unauth_evidence, auth_evidence],
                    requests_sent=2,
                )
            ]

        if authed.is_success:
            return [
                self.result(
                    endpoint,
                    context,
                    outcome=CheckOutcome.FAIL,
                    summary=(
                        "The operation served an unauthenticated request, with different "
                        "content from the authenticated one."
                    ),
                    finding_class=FindingClass.SUSPECTED,
                    severity=Severity.MEDIUM,
                    confidence=Confidence.MEDIUM,
                    explanation=(
                        f"The specification declares {schemes}, yet the operation returned "
                        f"{unauth.status_code} without credentials. The two bodies differ, "
                        "so the unauthenticated response may be a reduced or public view "
                        "rather than the protected resource."
                    ),
                    limitations=[
                        "The bodies differ, so this is not proof that protected data was served.",
                        "Only the response excerpt was compared.",
                    ],
                    next_step=(
                        "Inspect the unauthenticated response to see whether it contains "
                        "data the declared scheme was meant to protect."
                    ),
                    evidence=[unauth_evidence, auth_evidence],
                    requests_sent=2,
                )
            ]

        return [
            self.result(
                endpoint,
                context,
                outcome=CheckOutcome.NEEDS_REVIEW,
                summary=(
                    f"Unauthenticated request returned {unauth.status_code} but the "
                    f"authenticated one returned {authed.status_code}."
                ),
                finding_class=FindingClass.INCONCLUSIVE,
                explanation=(
                    "The authenticated request did not succeed, so the two responses "
                    "cannot be compared meaningfully."
                ),
                limitations=["The configured credential may be invalid or expired."],
                next_step="Verify the credential, then re-run this check.",
                confidence=Confidence.LOW,
                evidence=[unauth_evidence, auth_evidence],
                requests_sent=2,
            )
        ]


class InvalidCredentialCheck(BaseCheck):
    """Is an obviously invalid credential rejected?"""

    check_id = "AUTH-002"
    name = "Invalid credentials are rejected"
    description = (
        "Sends a syntactically valid but deliberately invalid bearer token and "
        "expects the operation to refuse it."
    )
    category = CheckCategory.AUTHENTICATION
    requests_per_endpoint = 1

    def applies_to(self, endpoint: Endpoint, context: CheckContext) -> bool:
        """Needs a read-shaped operation that declares authentication."""
        del context
        return _transport_method(endpoint) in SAFE_METHODS and _declares_authentication(endpoint)

    def run(self, endpoint: ClassifiedEndpoint, context: CheckContext) -> list[CheckResult]:
        operation = endpoint.endpoint
        if not context.budget.consume():
            return [self.skipped(endpoint, context, "request budget exhausted")]

        try:
            response = context.client.request(
                operation.method.value.upper(),
                operation.path,
                headers={"Authorization": f"Bearer {PROBE_TOKEN}"},
                authenticate=False,
            )
        except TransportError as exc:
            return [
                self.result(
                    endpoint,
                    context,
                    outcome=CheckOutcome.ERROR,
                    summary="The request did not complete.",
                    finding_class=FindingClass.INCONCLUSIVE,
                    explanation=exc.message,
                    limitations=["No conclusion about credential validation can be drawn."],
                    requests_sent=1,
                )
            ]

        observation = ev.from_response(
            response,
            check_id=self.check_id,
            label="request with an invalid token",
            note="token is a fixed synthetic string, not a guess",
        )

        if response.status_code in REJECTING_STATUSES:
            return [
                self.result(
                    endpoint,
                    context,
                    outcome=CheckOutcome.PASS,
                    summary=f"An invalid token was refused with {response.status_code}.",
                    explanation="The operation rejected a credential it should not accept.",
                    limitations=["Token validation beyond rejection was not assessed."],
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
                        f"An invalid token was accepted: the operation returned "
                        f"{response.status_code}."
                    ),
                    finding_class=FindingClass.SUSPECTED,
                    severity=Severity.HIGH,
                    confidence=Confidence.MEDIUM,
                    explanation=(
                        "The operation declares authentication and served a request "
                        "carrying a token that cannot be valid. Either the token is not "
                        "validated, or the operation does not require one despite its "
                        "declaration."
                    ),
                    limitations=[
                        "Whether the response contains protected data was not assessed.",
                        "AUTH-001 distinguishes 'no validation' from 'no requirement'.",
                    ],
                    next_step=(
                        "Compare with AUTH-001 for this operation, and check whether the "
                        "response differs from an unauthenticated one."
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
                summary=f"An invalid token produced {response.status_code}.",
                finding_class=FindingClass.INCONCLUSIVE,
                explanation=(
                    "The response neither refused the credential nor served the operation."
                ),
                limitations=["The status does not indicate how the token was treated."],
                confidence=Confidence.LOW,
                evidence=[observation],
                requests_sent=1,
            )
        ]


class SecurityMetadataCheck(BaseCheck):
    """Does the specification say anything about authenticating this operation?"""

    check_id = "AUTH-003"
    name = "Declared security metadata is present"
    description = (
        "Reports operations whose specification declares no security requirement, or "
        "declares one it never defines. A documentation gap, not a vulnerability."
    )
    category = CheckCategory.AUTHENTICATION
    requests_per_endpoint = 0

    def applies_to(self, endpoint: Endpoint, context: CheckContext) -> bool:
        """Applies wherever the declaration is absent, optional, or incomplete."""
        del context
        declared = endpoint.declared_security
        return declared.posture in {
            SecurityPosture.NOT_DECLARED,
            SecurityPosture.EXPLICITLY_OPTIONAL,
        } or bool(declared.undefined_schemes)

    def run(self, endpoint: ClassifiedEndpoint, context: CheckContext) -> list[CheckResult]:
        """Report the gap without sending anything.

        This check makes no request at all. It is a reading of the
        specification, and treating it as evidence about the running API would
        be exactly the mistake the project warns against.
        """
        declared = endpoint.endpoint.declared_security

        if declared.undefined_schemes:
            names = ", ".join(declared.undefined_schemes)
            return [
                self.result(
                    endpoint,
                    context,
                    outcome=CheckOutcome.NEEDS_REVIEW,
                    summary=f"Operation requires undefined security scheme(s): {names}.",
                    finding_class=FindingClass.INFORMATIONAL,
                    confidence=Confidence.HIGH,
                    explanation=(
                        "The operation names a security scheme the document never "
                        "defines, so what it actually requires cannot be read from the "
                        "specification."
                    ),
                    limitations=[
                        "This is a specification defect, not an observation of the API.",
                        "No request was sent.",
                    ],
                    next_step="Ask the API owner what these scheme names refer to.",
                )
            ]

        if declared.posture is SecurityPosture.EXPLICITLY_OPTIONAL:
            return [
                self.result(
                    endpoint,
                    context,
                    outcome=CheckOutcome.PASS,
                    summary="Operation is documented as not requiring authentication.",
                    finding_class=FindingClass.INFORMATIONAL,
                    confidence=Confidence.HIGH,
                    explanation=(
                        "The specification states that this operation may be called "
                        "anonymously, so an unauthenticated success is expected rather "
                        "than a weakness."
                    ),
                    limitations=[
                        "Whether the operation should be public was not assessed.",
                        "No request was sent.",
                    ],
                )
            ]

        return [
            self.result(
                endpoint,
                context,
                outcome=CheckOutcome.NEEDS_REVIEW,
                summary="Specification declares no security requirement for this operation.",
                finding_class=FindingClass.INFORMATIONAL,
                confidence=Confidence.HIGH,
                explanation=(
                    "Neither the operation nor the document states whether credentials "
                    "are needed. That is a gap in the documentation; it is not evidence "
                    "that the operation is unprotected."
                ),
                limitations=[
                    "No request was sent, so the running API's behaviour is unknown.",
                    "A missing declaration is not a vulnerability.",
                ],
                next_step=(
                    "Determine the intended requirement with the API owner, then test "
                    "enforcement with AUTH-001."
                ),
            )
        ]


__all__ = [
    "PROBE_TOKEN",
    "REJECTING_STATUSES",
    "InvalidCredentialCheck",
    "SecurityMetadataCheck",
    "UnauthenticatedAccessCheck",
]
