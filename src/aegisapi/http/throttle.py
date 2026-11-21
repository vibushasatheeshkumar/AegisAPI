"""Rate and concurrency limits.

Both are process-wide and thread-safe, because the guarantee that matters is
"AegisAPI will not exceed N requests per second against this API", not "each
worker will not". A per-worker limiter multiplied by the worker count is how
assessment tools accidentally become load tests.

The clock and the sleep function are injected. That is not ceremony: it makes
the limiter's behaviour assertable in milliseconds instead of waiting on real
time, so the tests that prove concurrency cannot outrun the rate limit are
fast and deterministic.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from types import TracebackType

Clock = Callable[[], float]
Sleeper = Callable[[float], None]


class RateLimiter:
    """Spaces requests so a configured rate is never exceeded.

    A simple interval gate rather than a token bucket: no burst allowance. An
    assessment has no reason to burst, and a smooth rate is both gentler on the
    API and easier to explain to whoever authorised the test.
    """

    def __init__(
        self,
        requests_per_second: float,
        *,
        clock: Clock | None = None,
        sleeper: Sleeper | None = None,
    ) -> None:
        if requests_per_second <= 0:
            raise ValueError("requests_per_second must be positive")
        self._interval = 1.0 / requests_per_second
        self._clock = clock or time.monotonic
        self._sleep = sleeper or time.sleep
        self._lock = threading.Lock()
        self._next_allowed: float | None = None

    @property
    def interval_seconds(self) -> float:
        """Minimum spacing between two requests."""
        return self._interval

    def acquire(self) -> float:
        """Block until the next request is allowed.

        Returns:
            How long this call waited, which the caller can report.

        The slot is reserved while the lock is held and the sleep happens
        outside it, so concurrent callers queue for distinct slots instead of
        all waking at the same instant and firing together.
        """
        with self._lock:
            now = self._clock()
            if self._next_allowed is None or now >= self._next_allowed:
                self._next_allowed = now + self._interval
                return 0.0
            wait_until = self._next_allowed
            self._next_allowed = wait_until + self._interval
            delay = wait_until - now

        if delay > 0:
            self._sleep(delay)
        return max(delay, 0.0)


class ConcurrencyLimiter:
    """Caps how many requests are in flight at once."""

    def __init__(self, max_concurrency: int) -> None:
        if max_concurrency < 1:
            raise ValueError("max_concurrency must be at least 1")
        self._max = max_concurrency
        self._semaphore = threading.BoundedSemaphore(max_concurrency)
        self._lock = threading.Lock()
        self._in_flight = 0
        self._peak = 0

    @property
    def max_concurrency(self) -> int:
        """Configured ceiling."""
        return self._max

    @property
    def peak_in_flight(self) -> int:
        """Highest number of simultaneous requests observed.

        Recorded so a test can prove the ceiling held, and so an operator can
        see whether concurrency was actually the bottleneck.
        """
        return self._peak

    @contextmanager
    def slot(self) -> Iterator[None]:
        """Hold one concurrency slot for the duration of the block."""
        self._semaphore.acquire()
        with self._lock:
            self._in_flight += 1
            self._peak = max(self._peak, self._in_flight)
        try:
            yield
        finally:
            with self._lock:
                self._in_flight -= 1
            self._semaphore.release()


class RequestThrottle:
    """Rate and concurrency limits applied together.

    The concurrency slot is taken first, then the rate gate. In that order a
    waiting request holds a slot while it waits, which keeps the number of
    threads actually talking to the API bounded by both limits at once.
    """

    def __init__(
        self,
        *,
        requests_per_second: float,
        max_concurrency: int,
        clock: Clock | None = None,
        sleeper: Sleeper | None = None,
    ) -> None:
        self.rate = RateLimiter(requests_per_second, clock=clock, sleeper=sleeper)
        self.concurrency = ConcurrencyLimiter(max_concurrency)

    @contextmanager
    def reserve(self) -> Iterator[float]:
        """Acquire both limits, yielding how long the rate gate waited."""
        with self.concurrency.slot():
            yield self.rate.acquire()

    def __enter__(self) -> RequestThrottle:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        return None


__all__ = ["ConcurrencyLimiter", "RateLimiter", "RequestThrottle"]
