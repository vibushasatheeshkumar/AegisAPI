"""Security misconfiguration checks, interpreted in context.

Header and CORS checks are where API scanners generate the most noise, so the
rules here are strict about what gets claimed:

* **A missing header is not a vulnerability.** ``Strict-Transport-Security``
  matters on an HTTPS browser-facing service and means nothing on a
  machine-to-machine JSON API over a private network. These are reported as
  informational observations with the context stated.
* **A permissive CORS policy is only interesting with credentials.**
  ``Access-Control-Allow-Origin: *`` without
  ``Access-Control-Allow-Credentials: true`` cannot be used to read an
  authenticated response. Reflecting an arbitrary origin *with* credentials
  can, and that distinction decides the severity.
* **Only safe methods are probed.** ``OPTIONS`` is sent to read what the server
  advertises. AegisAPI does not try ``DELETE`` on an endpoint to see what
  happens.
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
from aegisapi.models.endpoint import Endpoint, SecurityPosture
from aegisapi.models.http import HttpMethod
from aegisapi.testing import evidence as ev
from aegisapi.testing.registry import (
    SAFE_METHODS,
    BaseCheck,
    CheckContext,
    _transport_method,
)

PROBE_ORIGIN = "https://aegisapi-cors-probe.invalid"
"""An origin that cannot exist.

``.invalid`` is reserved by RFC 2606, so reflecting this proves the server
echoes arbitrary origins rather than matching an allow-list.
"""

API_RELEVANT_HEADERS: dict[str, str] = {
    "x-content-type-options": "stops a client sniffing a response into another type",
    "cache-control": "controls whether an authenticated response may be stored",
    "strict-transport-security": "only meaningful over HTTPS",
}
"""Headers worth commenting on for an API, with why they matter.

Deliberately short. ``X-Frame-Options`` and ``Content-Security-Policy`` govern
browser rendering and say little about a JSON API, so their absence is not
reported as an issue.
"""

INFORMATIVE_SERVER_HEADERS = ("server", "x-powered-by", "x-aspnet-version")


def _header(response_headers: dict[str, str], name: str) -> str | None:
    """Fetch a header case-insensitively."""
    wanted = name.lower()
    for key, value in response_headers.items():
        if key.lower() == wanted:
            return value
    return None


class SecurityHeaderCheck(BaseCheck):
    """Which response headers are present, and does their absence matter here?"""

    check_id = "CONF-001"
    name = "Security-relevant response headers"
    description = (
        "Records which security-relevant headers an operation returns, interpreted "
        "for an API rather than a browser page."
    )
    category = CheckCategory.CONFIGURATION
    requests_per_endpoint = 1

    def run(self, endpoint: ClassifiedEndpoint, context: CheckContext) -> list[CheckResult]:
        operation = endpoint.endpoint
        if operation.is_templated:
            return [self.skipped(endpoint, context, "path is templated; no value declared")]
        if not context.budget.consume():
            return [self.skipped(endpoint, context, "request budget exhausted")]

        try:
            response = context.client.request(operation.method.value.upper(), operation.path)
        except TransportError as exc:
            return [
                self.result(
                    endpoint,
                    context,
                    outcome=CheckOutcome.ERROR,
                    summary="The request did not complete.",
                    finding_class=FindingClass.INCONCLUSIVE,
                    explanation=exc.message,
                    limitations=["No header observation was possible."],
                    requests_sent=1,
                )
            ]

        observation = ev.from_response(response, check_id=self.check_id, label="header observation")
        is_https = (endpoint.resolved_url or "").startswith("https://")

        missing: list[str] = []
        for name, why in API_RELEVANT_HEADERS.items():
            if name == "strict-transport-security" and not is_https:
                continue
            if _header(response.headers, name) is None:
                missing.append(f"{name} ({why})")

        if not missing:
            return [
                self.result(
                    endpoint,
                    context,
                    outcome=CheckOutcome.PASS,
                    summary="The security-relevant headers AegisAPI checks are present.",
                    explanation="Nothing to report for this small, API-relevant header set.",
                    limitations=[
                        "Only a short list of API-relevant headers was considered.",
                        "Header values were not assessed for correctness.",
                    ],
                    confidence=Confidence.HIGH,
                    evidence=[observation],
                    requests_sent=1,
                )
            ]

        return [
            self.result(
                endpoint,
                context,
                outcome=CheckOutcome.NEEDS_REVIEW,
                summary=f"{len(missing)} security-relevant header(s) absent.",
                finding_class=FindingClass.INFORMATIONAL,
                confidence=Confidence.HIGH,
                explanation=(
                    "Absent: " + "; ".join(missing) + ". For a machine-to-machine API "
                    "these are hardening measures rather than vulnerabilities, and "
                    "their importance depends on whether browsers call this endpoint."
                ),
                limitations=[
                    "A missing header is not an exploitable weakness on its own.",
                    "Whether a browser ever calls this operation was not determined.",
                ],
                next_step=(
                    "Decide whether browser clients use this API; if none do, most of "
                    "these headers are not required."
                ),
                evidence=[observation],
                requests_sent=1,
            )
        ]


class CorsPolicyCheck(BaseCheck):
    """Does the API echo an arbitrary origin, and does it do so with credentials?"""

    check_id = "CONF-002"
    name = "CORS policy reflection"
    description = (
        "Sends an impossible Origin and reports how the response's CORS headers "
        "treat it. Reflection with credentials is the case that matters."
    )
    category = CheckCategory.CONFIGURATION
    requests_per_endpoint = 1

    def run(self, endpoint: ClassifiedEndpoint, context: CheckContext) -> list[CheckResult]:
        operation = endpoint.endpoint
        if operation.is_templated:
            return [self.skipped(endpoint, context, "path is templated; no value declared")]
        if not context.budget.consume():
            return [self.skipped(endpoint, context, "request budget exhausted")]

        try:
            response = context.client.request(
                operation.method.value.upper(),
                operation.path,
                headers={"Origin": PROBE_ORIGIN},
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
                    limitations=["No CORS observation was possible."],
                    requests_sent=1,
                )
            ]

        allow_origin = _header(response.headers, "access-control-allow-origin")
        allow_credentials = (
            _header(response.headers, "access-control-allow-credentials") or ""
        ).strip().lower() == "true"
        observation = ev.from_response(
            response,
            check_id=self.check_id,
            label="CORS probe with an impossible origin",
            note=f"Origin: {PROBE_ORIGIN}",
        )

        if allow_origin is None:
            return [
                self.result(
                    endpoint,
                    context,
                    outcome=CheckOutcome.PASS,
                    summary="No CORS headers were returned for an arbitrary origin.",
                    explanation=(
                        "The operation did not grant cross-origin access to an origin "
                        "that cannot exist."
                    ),
                    limitations=[
                        "A preflight request was not sent; only a simple request was made.",
                        "Other origins may be treated differently.",
                    ],
                    confidence=Confidence.HIGH,
                    evidence=[observation],
                    requests_sent=1,
                )
            ]

        reflected = allow_origin.strip() == PROBE_ORIGIN

        if reflected and allow_credentials:
            return [
                self.result(
                    endpoint,
                    context,
                    outcome=CheckOutcome.FAIL,
                    summary="An arbitrary origin was reflected together with credentials.",
                    finding_class=FindingClass.CONFIRMED,
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    explanation=(
                        f"The operation echoed {PROBE_ORIGIN} in "
                        "Access-Control-Allow-Origin and set "
                        "Access-Control-Allow-Credentials: true. That origin cannot "
                        "exist, so the server is reflecting whatever it is given rather "
                        "than matching an allow-list. A page on any origin could then "
                        "read authenticated responses from this endpoint in a victim's "
                        "browser."
                    ),
                    limitations=[
                        "Exploitability depends on browser clients using cookie or "
                        "header credentials against this API.",
                        "Only a simple request was sent, not a preflight.",
                    ],
                    next_step=(
                        "Confirm whether browser clients authenticate against this API, "
                        "then have the allow-list fixed rather than reflected."
                    ),
                    evidence=[observation],
                    requests_sent=1,
                )
            ]

        if reflected:
            return [
                self.result(
                    endpoint,
                    context,
                    outcome=CheckOutcome.NEEDS_REVIEW,
                    summary="An arbitrary origin was reflected, without credentials.",
                    finding_class=FindingClass.SUSPECTED,
                    severity=Severity.LOW,
                    confidence=Confidence.MEDIUM,
                    explanation=(
                        "The server echoed an impossible origin but did not allow "
                        "credentials, so a cross-origin page cannot read authenticated "
                        "responses. It can read whatever is public."
                    ),
                    limitations=[
                        "Without credentials this is not a path to authenticated data.",
                        "Only a simple request was sent, not a preflight.",
                    ],
                    next_step=(
                        "Check whether any related operation reflects origins *and* "
                        "allows credentials."
                    ),
                    evidence=[observation],
                    requests_sent=1,
                )
            ]

        if allow_origin.strip() == "*":
            return [
                self.result(
                    endpoint,
                    context,
                    outcome=CheckOutcome.NEEDS_REVIEW,
                    summary="CORS is open to all origins with a wildcard.",
                    finding_class=FindingClass.INFORMATIONAL,
                    confidence=Confidence.HIGH,
                    explanation=(
                        "Access-Control-Allow-Origin is '*'. Browsers refuse to send "
                        "credentials to a wildcard origin, so this exposes only data "
                        "the endpoint serves without authentication."
                    ),
                    limitations=[
                        "A wildcard cannot be combined with credentials by browsers.",
                        "Whether the data served is intended to be public was not assessed.",
                    ],
                    next_step="Confirm that everything this operation returns is public.",
                    evidence=[observation],
                    requests_sent=1,
                )
            ]

        return [
            self.result(
                endpoint,
                context,
                outcome=CheckOutcome.PASS,
                summary=f"CORS returned a fixed origin ({allow_origin}).",
                explanation=(
                    "The server returned a specific origin rather than echoing the one "
                    "sent, which is consistent with an allow-list."
                ),
                limitations=["The full allow-list was not enumerated."],
                confidence=Confidence.MEDIUM,
                evidence=[observation],
                requests_sent=1,
            )
        ]


class AdvertisedMethodsCheck(BaseCheck):
    """What methods does the server advertise, and do they match the specification?"""

    check_id = "CONF-003"
    name = "Advertised methods against the specification"
    description = (
        "Sends OPTIONS and compares the advertised Allow header with the methods the "
        "specification documents for that path. Only OPTIONS is sent."
    )
    category = CheckCategory.CONFIGURATION
    requests_per_endpoint = 1

    def applies_to(self, endpoint: Endpoint, context: CheckContext) -> bool:
        """Run once per path, on its GET operation, and only if not templated."""
        del context
        if endpoint.is_templated:
            return False
        return _transport_method(endpoint) is HttpMethod.GET

    def run(self, endpoint: ClassifiedEndpoint, context: CheckContext) -> list[CheckResult]:
        operation = endpoint.endpoint
        if not context.budget.consume():
            return [self.skipped(endpoint, context, "request budget exhausted")]

        try:
            response = context.client.request("OPTIONS", operation.path)
        except TransportError as exc:
            return [
                self.result(
                    endpoint,
                    context,
                    outcome=CheckOutcome.ERROR,
                    summary="The OPTIONS request did not complete.",
                    finding_class=FindingClass.INCONCLUSIVE,
                    explanation=exc.message,
                    limitations=["No method observation was possible."],
                    requests_sent=1,
                )
            ]

        observation = ev.from_response(response, check_id=self.check_id, label="OPTIONS probe")
        allow = _header(response.headers, "allow")
        if not allow:
            return [
                self.result(
                    endpoint,
                    context,
                    outcome=CheckOutcome.NEEDS_REVIEW,
                    summary="The server advertised no Allow header for OPTIONS.",
                    finding_class=FindingClass.INFORMATIONAL,
                    confidence=Confidence.MEDIUM,
                    explanation=(
                        "Without an Allow header the advertised methods cannot be "
                        "compared with the specification."
                    ),
                    limitations=[
                        "AegisAPI does not probe methods individually to find out.",
                    ],
                    evidence=[observation],
                    requests_sent=1,
                )
            ]

        advertised = {item.strip().upper() for item in allow.split(",") if item.strip()}
        documented = self._documented_methods(context, operation.path)
        extra = sorted(advertised - documented - {"OPTIONS", "HEAD"})

        if not extra:
            return [
                self.result(
                    endpoint,
                    context,
                    outcome=CheckOutcome.PASS,
                    summary="Advertised methods match the specification.",
                    explanation=f"The server advertises {allow}, all documented.",
                    limitations=["Advertisement is not proof of what is implemented."],
                    confidence=Confidence.MEDIUM,
                    evidence=[observation],
                    requests_sent=1,
                )
            ]

        return [
            self.result(
                endpoint,
                context,
                outcome=CheckOutcome.NEEDS_REVIEW,
                summary=f"Server advertises undocumented method(s): {', '.join(extra)}.",
                finding_class=FindingClass.INFORMATIONAL,
                confidence=Confidence.MEDIUM,
                explanation=(
                    f"The Allow header offers {', '.join(extra)} for {operation.path}, "
                    "which the specification does not document. The methods were not "
                    "called: AegisAPI does not send a write method to find out what it "
                    "does."
                ),
                limitations=[
                    "The undocumented methods were not invoked.",
                    "An Allow header can advertise methods the server does not implement.",
                ],
                next_step=(
                    "Decide with the API owner whether these methods should be reachable, "
                    "then test them deliberately in a safe environment."
                ),
                evidence=[observation],
                requests_sent=1,
            )
        ]

    @staticmethod
    def _documented_methods(context: CheckContext, path: str) -> set[str]:
        """Methods the specification documents for one path."""
        if context.discovery is None:
            return set()
        return {
            item.endpoint.method.value.upper()
            for item in context.discovery.endpoints
            if item.endpoint.path == path
        }


class InformationExposureCheck(BaseCheck):
    """Do responses advertise the software stack?"""

    check_id = "CONF-004"
    name = "Server software disclosure"
    description = (
        "Reports Server and X-Powered-By style headers, which narrow an attacker's "
        "search for known issues without being weaknesses themselves."
    )
    category = CheckCategory.CONFIGURATION
    requests_per_endpoint = 1

    def applies_to(self, endpoint: Endpoint, context: CheckContext) -> bool:
        """Run once per target, on the first read-shaped untemplated operation."""
        del context
        if endpoint.is_templated:
            return False
        return _transport_method(endpoint) in SAFE_METHODS

    def run(self, endpoint: ClassifiedEndpoint, context: CheckContext) -> list[CheckResult]:
        operation = endpoint.endpoint
        if not context.budget.consume():
            return [self.skipped(endpoint, context, "request budget exhausted")]

        try:
            response = context.client.request(operation.method.value.upper(), operation.path)
        except TransportError as exc:
            return [
                self.result(
                    endpoint,
                    context,
                    outcome=CheckOutcome.ERROR,
                    summary="The request did not complete.",
                    finding_class=FindingClass.INCONCLUSIVE,
                    explanation=exc.message,
                    limitations=["No header observation was possible."],
                    requests_sent=1,
                )
            ]

        observation = ev.from_response(
            response, check_id=self.check_id, label="software disclosure observation"
        )
        disclosed = {
            name: value
            for name in INFORMATIVE_SERVER_HEADERS
            if (value := _header(response.headers, name)) is not None
        }

        if not disclosed:
            return [
                self.result(
                    endpoint,
                    context,
                    outcome=CheckOutcome.PASS,
                    summary="No server software headers were returned.",
                    explanation="The response did not advertise the stack.",
                    limitations=["Other responses may differ."],
                    confidence=Confidence.MEDIUM,
                    evidence=[observation],
                    requests_sent=1,
                )
            ]

        described = ", ".join(f"{name}: {value}" for name, value in sorted(disclosed.items()))
        return [
            self.result(
                endpoint,
                context,
                outcome=CheckOutcome.NEEDS_REVIEW,
                summary="The response advertises server software.",
                finding_class=FindingClass.INFORMATIONAL,
                confidence=Confidence.HIGH,
                explanation=(
                    f"Observed {described}. Version disclosure narrows the search for "
                    "known issues in that software. It is not itself a weakness, and "
                    "removing it does not fix anything."
                ),
                limitations=[
                    "No attempt was made to determine whether the disclosed version "
                    "has known issues.",
                    "This is hardening information, not a vulnerability.",
                ],
                evidence=[observation],
                requests_sent=1,
            )
        ]


class ContentTypeDriftCheck(BaseCheck):
    """Does the response content type match what the specification promised?"""

    check_id = "CONF-005"
    name = "Response content type matches the specification"
    description = (
        "Compares the observed response content type with the one the specification "
        "documents for the operation."
    )
    category = CheckCategory.CONFIGURATION
    requests_per_endpoint = 1

    def applies_to(self, endpoint: Endpoint, context: CheckContext) -> bool:
        """Needs a documented response content type and an untemplated path."""
        del context
        if endpoint.is_templated or _transport_method(endpoint) not in SAFE_METHODS:
            return False
        return bool(self._documented_types(endpoint))

    @staticmethod
    def _documented_types(endpoint: Endpoint) -> set[str]:
        """Content types the specification declares for success responses."""
        declared: set[str] = set()
        for response in endpoint.responses:
            if response.status_code.startswith("2") or response.status_code == "default":
                declared.update(
                    item.split(";")[0].strip().lower() for item in response.content_types
                )
        return {item for item in declared if item}

    def run(self, endpoint: ClassifiedEndpoint, context: CheckContext) -> list[CheckResult]:
        operation = endpoint.endpoint
        documented = self._documented_types(operation)
        if not context.budget.consume():
            return [self.skipped(endpoint, context, "request budget exhausted")]

        try:
            response = context.client.request(operation.method.value.upper(), operation.path)
        except TransportError as exc:
            return [
                self.result(
                    endpoint,
                    context,
                    outcome=CheckOutcome.ERROR,
                    summary="The request did not complete.",
                    finding_class=FindingClass.INCONCLUSIVE,
                    explanation=exc.message,
                    limitations=["No content type observation was possible."],
                    requests_sent=1,
                )
            ]

        observation = ev.from_response(
            response, check_id=self.check_id, label="content type observation"
        )
        observed = (response.content_type or "").split(";")[0].strip().lower()

        if not observed:
            return [
                self.result(
                    endpoint,
                    context,
                    outcome=CheckOutcome.NEEDS_REVIEW,
                    summary="The response declared no content type.",
                    finding_class=FindingClass.INFORMATIONAL,
                    confidence=Confidence.MEDIUM,
                    explanation=(
                        "A response without a content type leaves interpretation to the "
                        "client, which is where sniffing problems start."
                    ),
                    limitations=["The response body may have been empty."],
                    evidence=[observation],
                    requests_sent=1,
                )
            ]

        if observed in documented:
            return [
                self.result(
                    endpoint,
                    context,
                    outcome=CheckOutcome.PASS,
                    summary=f"Response content type {observed} is as documented.",
                    explanation="Observed behaviour matches the specification.",
                    limitations=["Only one response was sampled."],
                    confidence=Confidence.MEDIUM,
                    evidence=[observation],
                    requests_sent=1,
                )
            ]

        if not response.is_success:
            # The documented types describe a *successful* response, so a 4xx or
            # 5xx is not drift. Reporting it as "as documented" would attach a
            # statement the evidence contradicts, which is worse than reporting
            # nothing: the specification here documents application/json and the
            # response was text/html.
            documented_list = ", ".join(sorted(documented))
            if response.status_code >= 500:
                return [
                    self.result(
                        endpoint,
                        context,
                        outcome=CheckOutcome.NEEDS_REVIEW,
                        summary=(
                            f"The operation returned {response.status_code} as "
                            f"{observed}, not the documented {documented_list}."
                        ),
                        finding_class=FindingClass.INFORMATIONAL,
                        confidence=Confidence.MEDIUM,
                        explanation=(
                            "A server error was returned, so no conclusion about content "
                            "type drift on a successful response is possible. The error "
                            "itself is worth a look: an API that documents "
                            f"{documented_list} and serves {observed} under failure is "
                            "usually returning a proxy or framework error page to "
                            "clients."
                        ),
                        limitations=[
                            "Content type drift was not assessed; the operation did not "
                            "return a successful response.",
                            "The cause of the server error was not investigated.",
                        ],
                        next_step=(
                            "Request this operation manually and check whether the error "
                            "page is intended to reach clients."
                        ),
                        evidence=[observation],
                        requests_sent=1,
                    )
                ]
            return [
                self.result(
                    endpoint,
                    context,
                    outcome=CheckOutcome.PASS,
                    summary=(
                        f"The operation returned {response.status_code}, so the "
                        f"documented {documented_list} does not apply."
                    ),
                    explanation=(
                        "The documented content types describe a successful response. "
                        "This request was refused, which is a normal answer and not "
                        "drift."
                    ),
                    limitations=[
                        "Content type drift was not assessed: no successful response "
                        "was obtained for this operation.",
                    ],
                    confidence=Confidence.MEDIUM,
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
                    f"Response content type {observed} is not documented "
                    f"({', '.join(sorted(documented))})."
                ),
                finding_class=FindingClass.INFORMATIONAL,
                confidence=Confidence.MEDIUM,
                explanation=(
                    "The specification and the running API disagree about what this "
                    "operation returns. That matters for clients, and it means the "
                    "specification is a less reliable basis for assessment."
                ),
                limitations=[
                    "Specification drift is not itself a security weakness.",
                    "Only one response was sampled.",
                ],
                next_step="Decide which of the two is correct before relying on the document.",
                evidence=[observation],
                requests_sent=1,
            )
        ]


def declares_authentication(endpoint: Endpoint) -> bool:
    """``True`` when the operation's specification requires credentials.

    Shared with the intelligence layer, which needs the same reading of a
    declaration without importing the authentication checks.
    """
    declared = endpoint.declared_security
    if declared.posture in {
        SecurityPosture.NOT_DECLARED,
        SecurityPosture.EXPLICITLY_OPTIONAL,
    }:
        return False
    return bool(declared.scheme_names) and not declared.permits_anonymous


__all__ = [
    "API_RELEVANT_HEADERS",
    "PROBE_ORIGIN",
    "AdvertisedMethodsCheck",
    "ContentTypeDriftCheck",
    "CorsPolicyCheck",
    "InformationExposureCheck",
    "SecurityHeaderCheck",
    "declares_authentication",
]
