"""When a request may be retried, and how long to wait first.

The policy is deliberately narrow, because a retry is an extra request against
someone else's API:

* **Read-shaped methods only.** ``GET``, ``HEAD``, and ``OPTIONS``. A repeated
  ``POST`` can create a second resource; a repeated ``DELETE`` can remove
  something that came back. ``PUT`` and ``DELETE`` are idempotent on paper, but
  "idempotent on paper" is not a good enough reason to send a duplicate during
  an engagement.
* **Transient failures only.** A connection error, a timeout, a 429, or a
  503. Never a 401, 403, or 404: those are answers, and repeating the request
  will not change them.
* **Never a scope violation or a credential failure.** Those raise before
  anything is sent, so they never reach this policy at all.
* **None by default.** ``max_retries`` defaults to zero. Retrying is opt-in.

A retry is still subject to scope validation and the rate limit, because it
goes back through the same request boundary as the original.
"""

from __future__ import annotations

from dataclasses import dataclass
from email.utils import parsedate_to_datetime

from aegisapi.core.exceptions import (
    ConnectionFailedError,
    RequestTimeoutError,
    TransportError,
)
from aegisapi.models.http import MAX_RETRY_AFTER_SECONDS, HttpMethod

RETRYABLE_STATUS_CODES: frozenset[int] = frozenset({429, 503})
"""Statuses that mean "not now" rather than "no"."""

DEFAULT_BACKOFF_SECONDS = 0.5
"""Base delay, doubled per attempt, when the server suggests nothing."""

MAX_BACKOFF_SECONDS = 8.0
"""Ceiling on computed backoff, before any ``Retry-After`` is considered."""


@dataclass(frozen=True)
class RetryDecision:
    """Whether to retry, and why."""

    retry: bool
    delay_seconds: float = 0.0
    reason: str = ""

    @classmethod
    def stop(cls, reason: str) -> RetryDecision:
        """Do not retry."""
        return cls(retry=False, reason=reason)

    @classmethod
    def again(cls, delay_seconds: float, reason: str) -> RetryDecision:
        """Retry after waiting."""
        return cls(retry=True, delay_seconds=max(delay_seconds, 0.0), reason=reason)


def parse_retry_after(value: str | None, *, now: float | None = None) -> float | None:
    """Interpret a ``Retry-After`` header.

    Accepts both forms the specification allows: a number of seconds, and an
    HTTP date. The result is capped at :data:`MAX_RETRY_AFTER_SECONDS`, because
    a server can ask for a day and honouring that literally would hang an
    assessment.

    Returns:
        Seconds to wait, or ``None`` when the header is absent or unusable.
    """
    if value is None:
        return None
    text = value.strip()
    if not text:
        return None

    try:
        seconds = float(text)
    except ValueError:
        try:
            when = parsedate_to_datetime(text)
        except (TypeError, ValueError):
            return None
        if when is None:  # pragma: no cover - defensive
            return None
        reference = now if now is not None else when.timestamp()
        seconds = when.timestamp() - reference if now is not None else 0.0

    if seconds < 0:
        return 0.0
    return min(seconds, MAX_RETRY_AFTER_SECONDS)


def backoff_for(attempt: int) -> float:
    """Exponential backoff for ``attempt`` (1 for the first retry)."""
    delay = DEFAULT_BACKOFF_SECONDS * (2 ** max(attempt - 1, 0))
    return min(delay, MAX_BACKOFF_SECONDS)


def decide_for_status(
    status_code: int,
    *,
    method: HttpMethod,
    attempt: int,
    max_retries: int,
    retry_after: str | None = None,
) -> RetryDecision:
    """Decide whether an HTTP status warrants another attempt."""
    if max_retries <= 0:
        return RetryDecision.stop("retries are disabled")
    if not method.is_idempotent:
        return RetryDecision.stop(f"{method.value} is not retried automatically")
    if attempt > max_retries:
        return RetryDecision.stop(f"retry limit of {max_retries} reached")
    if status_code not in RETRYABLE_STATUS_CODES:
        return RetryDecision.stop(f"status {status_code} is not transient")

    suggested = parse_retry_after(retry_after)
    if suggested is not None:
        return RetryDecision.again(
            suggested, f"status {status_code} with Retry-After {suggested:g}s"
        )
    return RetryDecision.again(backoff_for(attempt), f"status {status_code}")


def decide_for_error(
    error: TransportError,
    *,
    method: HttpMethod,
    attempt: int,
    max_retries: int,
) -> RetryDecision:
    """Decide whether a transport failure warrants another attempt.

    Only connection failures and timeouts qualify. A TLS error is not retried:
    an untrusted certificate will be untrusted next time, and retrying would
    just repeat the connection against a host whose identity is unproven.
    """
    if max_retries <= 0:
        return RetryDecision.stop("retries are disabled")
    if not method.is_idempotent:
        return RetryDecision.stop(f"{method.value} is not retried automatically")
    if attempt > max_retries:
        return RetryDecision.stop(f"retry limit of {max_retries} reached")
    if not isinstance(error, (ConnectionFailedError, RequestTimeoutError)):
        return RetryDecision.stop(f"{type(error).__name__} is not transient")
    return RetryDecision.again(backoff_for(attempt), type(error).__name__)


__all__ = [
    "DEFAULT_BACKOFF_SECONDS",
    "MAX_BACKOFF_SECONDS",
    "RETRYABLE_STATUS_CODES",
    "RetryDecision",
    "backoff_for",
    "decide_for_error",
    "decide_for_status",
    "parse_retry_after",
]
