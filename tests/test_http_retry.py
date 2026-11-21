"""The retry policy: what may be repeated, and after how long."""

from __future__ import annotations

import pytest

from aegisapi.core.exceptions import (
    ConnectionFailedError,
    RequestTimeoutError,
    ResponseTooLargeError,
    TlsError,
    TransportError,
)
from aegisapi.http.retry import (
    MAX_BACKOFF_SECONDS,
    backoff_for,
    decide_for_error,
    decide_for_status,
    parse_retry_after,
)
from aegisapi.models.http import MAX_RETRY_AFTER_SECONDS, HttpMethod


class TestStatusDecisions:
    def test_retries_disabled_by_default(self) -> None:
        decision = decide_for_status(503, method=HttpMethod.GET, attempt=1, max_retries=0)

        assert decision.retry is False
        assert "disabled" in decision.reason

    @pytest.mark.parametrize("status", [429, 503])
    def test_transient_statuses_are_retried_for_read_methods(self, status: int) -> None:
        decision = decide_for_status(status, method=HttpMethod.GET, attempt=1, max_retries=2)

        assert decision.retry is True
        assert decision.delay_seconds > 0

    @pytest.mark.parametrize("status", [200, 301, 400, 401, 403, 404, 418, 500, 502])
    def test_other_statuses_are_answers_not_retries(self, status: int) -> None:
        decision = decide_for_status(status, method=HttpMethod.GET, attempt=1, max_retries=3)

        assert decision.retry is False

    @pytest.mark.parametrize(
        "method", [HttpMethod.POST, HttpMethod.PUT, HttpMethod.PATCH, HttpMethod.DELETE]
    )
    def test_non_idempotent_methods_are_never_retried(self, method: HttpMethod) -> None:
        decision = decide_for_status(503, method=method, attempt=1, max_retries=3)

        assert decision.retry is False
        assert "not retried automatically" in decision.reason

    def test_retry_limit_is_respected(self) -> None:
        decision = decide_for_status(503, method=HttpMethod.GET, attempt=4, max_retries=3)

        assert decision.retry is False
        assert "limit" in decision.reason

    def test_retry_after_is_honoured(self) -> None:
        decision = decide_for_status(
            429, method=HttpMethod.GET, attempt=1, max_retries=2, retry_after="3"
        )

        assert decision.retry is True
        assert decision.delay_seconds == pytest.approx(3.0)
        assert "Retry-After" in decision.reason

    def test_unusable_retry_after_falls_back_to_backoff(self) -> None:
        decision = decide_for_status(
            429, method=HttpMethod.GET, attempt=1, max_retries=2, retry_after="soon"
        )

        assert decision.retry is True
        assert decision.delay_seconds == pytest.approx(backoff_for(1))


class TestErrorDecisions:
    @pytest.mark.parametrize(
        "error", [ConnectionFailedError("reset"), RequestTimeoutError("timeout")]
    )
    def test_transient_failures_are_retried(self, error: TransportError) -> None:
        decision = decide_for_error(error, method=HttpMethod.GET, attempt=1, max_retries=1)

        assert decision.retry is True

    @pytest.mark.parametrize(
        "error",
        [
            TlsError("bad certificate"),
            ResponseTooLargeError("too big"),
            TransportError("generic"),
        ],
    )
    def test_permanent_failures_are_not_retried(self, error: TransportError) -> None:
        # A certificate that fails verification will fail again, and retrying
        # would re-connect to a host whose identity is unproven.
        decision = decide_for_error(error, method=HttpMethod.GET, attempt=1, max_retries=3)

        assert decision.retry is False

    def test_non_idempotent_methods_are_not_retried_on_failure(self) -> None:
        decision = decide_for_error(
            ConnectionFailedError("reset"),
            method=HttpMethod.POST,
            attempt=1,
            max_retries=3,
        )

        assert decision.retry is False

    def test_disabled_retries_win(self) -> None:
        decision = decide_for_error(
            RequestTimeoutError("t"), method=HttpMethod.GET, attempt=1, max_retries=0
        )

        assert decision.retry is False


class TestRetryAfterParsing:
    @pytest.mark.parametrize(
        ("value", "expected"),
        [("0", 0.0), ("5", 5.0), ("2.5", 2.5), ("  7  ", 7.0), ("-3", 0.0)],
    )
    def test_numeric_values(self, value: str, expected: float) -> None:
        assert parse_retry_after(value) == pytest.approx(expected)

    @pytest.mark.parametrize("value", [None, "", "   ", "later", "not-a-date"])
    def test_unusable_values_return_none(self, value: str | None) -> None:
        assert parse_retry_after(value) is None

    def test_http_date_is_accepted(self) -> None:
        assert parse_retry_after("Wed, 21 Oct 2026 07:28:00 GMT") is not None

    def test_absurd_delay_is_capped(self) -> None:
        # A server asking for a day must not hang an assessment.
        assert parse_retry_after("86400") == pytest.approx(MAX_RETRY_AFTER_SECONDS)


class TestBackoff:
    def test_backoff_grows_then_plateaus(self) -> None:
        delays = [backoff_for(attempt) for attempt in range(1, 8)]

        assert delays == sorted(delays)
        assert max(delays) <= MAX_BACKOFF_SECONDS
        assert delays[0] < delays[-1]
