"""Rate-limit observation, deliberately too gentle to be a load test.

The honest version of this check is unglamorous. It sends a small number of
identical read requests, stops the moment the API says to, and reports what it
saw - including "the sample was too small to conclude anything", which is the
usual answer.

What keeps it safe:

* **A small, configurable budget**, drawn from the same pool as every other
  check, with a hard default of :data:`DEFAULT_PROBE_REQUESTS`.
* **It stops on the first 429**, or on any ``Retry-After``. It does not wait out
  the delay and resume; a limiter that fires has already answered the question.
* **It inherits the configured rate limit**, because every request goes through
  the scoped client's throttle. The probe cannot send faster than the operator
  allowed, which also means it cannot prove the limit is *higher* than that.
* **Read-shaped methods only**, and never a retry.

The last point is a real limitation, stated in every result: AegisAPI throttles
itself to ``http.requests_per_second``, so if the API's limit is above that,
this check cannot reach it.
"""

from __future__ import annotations

from aegisapi.core.exceptions import TransportError
from aegisapi.models.assessment import (
    CheckCategory,
    CheckOutcome,
    CheckResult,
    Evidence,
    FindingClass,
)
from aegisapi.models.common import Confidence, Severity
from aegisapi.models.discovery import ClassifiedEndpoint
from aegisapi.models.endpoint import Endpoint
from aegisapi.testing import evidence as ev
from aegisapi.testing.registry import (
    SAFE_METHODS,
    BaseCheck,
    CheckContext,
    _transport_method,
)

DEFAULT_PROBE_REQUESTS = 5
"""How many requests the probe sends when the budget allows.

Five is enough to notice a limiter set to one or two per second and far too few
to be a load test. Raising it is the operator's decision, through the budget.
"""

MINIMUM_USEFUL_SAMPLE = 3
"""Below this many requests, the check refuses to draw a conclusion."""

RATE_LIMIT_HEADERS = (
    "retry-after",
    "ratelimit-limit",
    "ratelimit-remaining",
    "ratelimit-reset",
    "x-ratelimit-limit",
    "x-ratelimit-remaining",
    "x-ratelimit-reset",
)


def _rate_headers(headers: dict[str, str]) -> dict[str, str]:
    """Rate-limit headers present in a response."""
    lowered = {name.lower(): value for name, value in headers.items()}
    return {name: lowered[name] for name in RATE_LIMIT_HEADERS if name in lowered}


class RateLimitProbeCheck(BaseCheck):
    """Does the API limit repeated requests, and does it say so?"""

    check_id = "RATE-001"
    name = "Rate limiting on repeated requests"
    description = (
        "Sends a small number of identical read requests and reports whether a limit "
        "was reached or advertised. Stops immediately on 429."
    )
    category = CheckCategory.RATE_LIMITS
    requests_per_endpoint = DEFAULT_PROBE_REQUESTS

    def applies_to(self, endpoint: Endpoint, context: CheckContext) -> bool:
        """One untemplated read-shaped operation is enough to probe."""
        del context
        if endpoint.is_templated:
            return False
        return _transport_method(endpoint) in SAFE_METHODS

    def run(self, endpoint: ClassifiedEndpoint, context: CheckContext) -> list[CheckResult]:
        operation = endpoint.endpoint
        method = operation.method.value.upper()
        planned = min(DEFAULT_PROBE_REQUESTS, context.budget.remaining)

        if planned < MINIMUM_USEFUL_SAMPLE:
            return [
                self.skipped(
                    endpoint,
                    context,
                    (
                        f"only {planned} request(s) available, fewer than the "
                        f"{MINIMUM_USEFUL_SAMPLE} needed for a usable sample"
                    ),
                )
            ]

        observations: list[Evidence] = []
        sent = 0
        limited_at: int | None = None
        advertised: dict[str, str] = {}

        for attempt in range(1, planned + 1):
            if not context.budget.consume():
                break
            try:
                response = context.client.request(method, operation.path)
            except TransportError as exc:
                observations.append(
                    ev.from_failure(
                        check_id=self.check_id,
                        label=f"request {attempt} failed",
                        method=method,
                        url=endpoint.resolved_url or operation.path,
                        note=exc.message,
                    )
                )
                sent += 1
                break

            sent += 1
            headers = _rate_headers(response.headers)
            advertised.update(headers)

            # Keep only the first and the decisive observation: evidence is for
            # confirming a conclusion, not for archiving every repeat.
            if attempt == 1 or response.status_code == 429:
                observations.append(
                    ev.from_response(
                        response,
                        check_id=self.check_id,
                        label=f"request {attempt} of {planned}",
                        note=(
                            "rate-limit headers: "
                            + (", ".join(f"{k}={v}" for k, v in sorted(headers.items())) or "none")
                        ),
                    )
                )

            if response.status_code == 429:
                limited_at = attempt
                break

        throttle_note = (
            f"AegisAPI throttled itself to {context.config.http.requests_per_second:g} "
            "requests per second, so a limit above that rate cannot be detected."
        )

        if limited_at is not None:
            return [
                self.result(
                    endpoint,
                    context,
                    outcome=CheckOutcome.PASS,
                    summary=f"A rate limit was enforced after {limited_at} request(s).",
                    finding_class=FindingClass.INFORMATIONAL,
                    confidence=Confidence.HIGH,
                    explanation=(
                        f"The operation returned 429 on request {limited_at}. The probe "
                        "stopped immediately rather than waiting out the delay."
                    ),
                    limitations=[
                        f"Only {sent} request(s) were sent.",
                        throttle_note,
                        "The exact threshold and window were not determined.",
                    ],
                    evidence=observations[:3],
                    requests_sent=sent,
                )
            ]

        if sent < MINIMUM_USEFUL_SAMPLE:
            return [
                self.result(
                    endpoint,
                    context,
                    outcome=CheckOutcome.NEEDS_REVIEW,
                    summary=f"Only {sent} request(s) were sent; too few to conclude.",
                    finding_class=FindingClass.INCONCLUSIVE,
                    confidence=Confidence.LOW,
                    explanation="The sample is smaller than the minimum this check trusts.",
                    limitations=[
                        f"A sample of {sent} cannot distinguish a limiter from its absence.",
                        throttle_note,
                    ],
                    next_step="Re-run with a larger request budget.",
                    evidence=observations[:2],
                    requests_sent=sent,
                )
            ]

        if advertised:
            described = ", ".join(f"{name}={value}" for name, value in sorted(advertised.items()))
            return [
                self.result(
                    endpoint,
                    context,
                    outcome=CheckOutcome.PASS,
                    summary="A rate limit is advertised but was not reached.",
                    finding_class=FindingClass.INFORMATIONAL,
                    confidence=Confidence.MEDIUM,
                    explanation=(
                        f"The API advertised {described} without refusing any of the "
                        f"{sent} requests sent. A limit exists; this probe stayed inside it."
                    ),
                    limitations=[
                        f"Only {sent} request(s) were sent.",
                        throttle_note,
                    ],
                    evidence=observations[:2],
                    requests_sent=sent,
                )
            ]

        return [
            self.result(
                endpoint,
                context,
                outcome=CheckOutcome.NEEDS_REVIEW,
                summary=(f"No rate limit was observed or advertised across {sent} request(s)."),
                finding_class=FindingClass.INCONCLUSIVE,
                severity=Severity.LOW,
                confidence=Confidence.LOW,
                explanation=(
                    f"All {sent} requests were served, and no rate-limit headers were "
                    "returned. That is not evidence that no limit exists: the sample is "
                    "small by design and AegisAPI limits its own rate."
                ),
                limitations=[
                    f"A sample of {sent} request(s) cannot establish the absence of a limit.",
                    throttle_note,
                    "Only one operation was probed.",
                ],
                next_step=(
                    "If rate limiting matters for this engagement, test it deliberately "
                    "with the API owner's agreement rather than inferring it here."
                ),
                evidence=observations[:2],
                requests_sent=sent,
            )
        ]


__all__ = [
    "DEFAULT_PROBE_REQUESTS",
    "MINIMUM_USEFUL_SAMPLE",
    "RATE_LIMIT_HEADERS",
    "RateLimitProbeCheck",
]
