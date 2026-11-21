"""Rate and concurrency limits, including under real threads."""

from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor

import pytest

from aegisapi.http.throttle import ConcurrencyLimiter, RateLimiter, RequestThrottle


class FakeClock:
    """A monotonic clock advanced only by sleeping, for deterministic tests."""

    def __init__(self) -> None:
        self.now = 0.0
        self.sleeps: list[float] = []
        self._lock = threading.Lock()

    def time(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        with self._lock:
            self.sleeps.append(seconds)
            self.now += seconds


class TestRateLimiter:
    def test_first_request_is_immediate(self) -> None:
        clock = FakeClock()
        limiter = RateLimiter(2.0, clock=clock.time, sleeper=clock.sleep)

        assert limiter.acquire() == 0.0
        assert clock.sleeps == []

    def test_second_request_waits_one_interval(self) -> None:
        clock = FakeClock()
        limiter = RateLimiter(2.0, clock=clock.time, sleeper=clock.sleep)

        limiter.acquire()
        waited = limiter.acquire()

        assert waited == pytest.approx(0.5)
        assert clock.sleeps == [pytest.approx(0.5)]

    def test_requests_are_spaced_by_the_configured_rate(self) -> None:
        clock = FakeClock()
        limiter = RateLimiter(4.0, clock=clock.time, sleeper=clock.sleep)

        for _ in range(4):
            limiter.acquire()

        assert limiter.interval_seconds == pytest.approx(0.25)
        assert clock.sleeps == [pytest.approx(0.25)] * 3

    def test_no_wait_once_enough_time_has_passed(self) -> None:
        clock = FakeClock()
        limiter = RateLimiter(10.0, clock=clock.time, sleeper=clock.sleep)

        limiter.acquire()
        clock.now += 5.0

        assert limiter.acquire() == 0.0

    def test_concurrent_callers_get_distinct_slots(self) -> None:
        # The point of the lock: ten threads must not all wake at once and
        # fire together, which would exceed the configured rate.
        clock = FakeClock()
        limiter = RateLimiter(5.0, clock=clock.time, sleeper=clock.sleep)

        with ThreadPoolExecutor(max_workers=10) as pool:
            list(pool.map(lambda _: limiter.acquire(), range(10)))

        assert len(clock.sleeps) == 9
        assert all(delay > 0 for delay in clock.sleeps)

    @pytest.mark.parametrize("rate", [0, -1.0])
    def test_non_positive_rate_is_rejected(self, rate: float) -> None:
        with pytest.raises(ValueError, match="positive"):
            RateLimiter(rate)


class TestConcurrencyLimiter:
    def test_peak_never_exceeds_the_ceiling(self) -> None:
        limiter = ConcurrencyLimiter(3)
        barrier_reached = threading.Event()

        def work(_: int) -> None:
            with limiter.slot():
                barrier_reached.set()
                # Hold the slot briefly so overlap is genuinely possible.
                threading.Event().wait(0.01)

        with ThreadPoolExecutor(max_workers=12) as pool:
            list(pool.map(work, range(24)))

        assert barrier_reached.is_set()
        assert limiter.peak_in_flight <= 3
        assert limiter.max_concurrency == 3

    def test_slot_is_released_after_an_exception(self) -> None:
        limiter = ConcurrencyLimiter(1)

        with pytest.raises(RuntimeError), limiter.slot():
            raise RuntimeError("boom")

        # If the slot leaked, this would block forever.
        with limiter.slot():
            pass

    def test_zero_concurrency_is_rejected(self) -> None:
        with pytest.raises(ValueError, match="at least 1"):
            ConcurrencyLimiter(0)


class TestRequestThrottle:
    def test_reserve_applies_both_limits(self) -> None:
        clock = FakeClock()
        throttle = RequestThrottle(
            requests_per_second=2.0,
            max_concurrency=2,
            clock=clock.time,
            sleeper=clock.sleep,
        )

        with throttle.reserve() as first:
            assert first == 0.0
        with throttle.reserve() as second:
            assert second == pytest.approx(0.5)

        assert throttle.concurrency.peak_in_flight == 1

    def test_concurrency_cannot_outrun_the_rate_limit(self) -> None:
        clock = FakeClock()
        throttle = RequestThrottle(
            requests_per_second=2.0,
            max_concurrency=8,
            clock=clock.time,
            sleeper=clock.sleep,
        )
        sent: list[int] = []
        lock = threading.Lock()

        def send(index: int) -> None:
            with throttle.reserve(), lock:
                sent.append(index)

        with ThreadPoolExecutor(max_workers=8) as pool:
            list(pool.map(send, range(8)))

        # Eight workers, but the rate gate still forced seven waits.
        assert len(sent) == 8
        assert len(clock.sleeps) == 7
        assert throttle.concurrency.peak_in_flight <= 8
