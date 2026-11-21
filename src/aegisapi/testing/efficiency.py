"""Request deduplication and response caching for one assessment.

Design rules
------------
*  GET-only cache.  GET is idempotent; POST, PUT, DELETE are not. Caching a
   non-GET response and returning it for a second call of the same method could
   change what a check observes (e.g. the second POST should fail because the
   resource already exists, but the cache returns the first POST's 201).

*  Cross-check only.  When check A and check B both want ``GET /api/health``
   with the same auth context, B gets A's cached response.  When check A itself
   calls the same URL twice — intentionally, as RATE-001 does to trigger 429 —
   it still sends every request.  The rule: a cache hit is served only when the
   requesting check differs from the check that populated the entry.

*  Auth-context-aware.  The fingerprint includes an auth-context key (target
   name + auth method), so a response fetched with bearer credentials is never
   returned to a request that sends no credentials, and vice versa.

*  Bounded.  The GET cache is capped at ``max_entries`` entries to prevent
   unbounded memory growth on a large API.
"""

from __future__ import annotations

import hashlib
import threading
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from aegisapi.models.http import HttpResponse

_MAX_CACHE_ENTRIES = 1000
"""Hard cap on GET cache size.  Sized so a scan of a large API (hundreds of
endpoints × several checks each) stays well inside available memory."""


class EfficiencyTracker:
    """Thread-safe efficiency tracker for one assessment.

    One instance is created per scan and shared across all
    :class:`~aegisapi.http.ScopedHttpClient` instances created for that scan
    (the main client and each per-identity client).  Auth-context keys in the
    fingerprint ensure that a response fetched under one identity is never
    served to a request under a different one.

    The engine sets the *current check* via :meth:`set_current_check` before
    and after each check runs, so the cache can tell whether a lookup is
    within-check (let through) or cross-check (serve from cache).
    """

    def __init__(self, *, max_entries: int = _MAX_CACHE_ENTRIES) -> None:
        self._lock = threading.Lock()
        self._max = max_entries
        # GET response cache: fingerprint → (sender_check_id, HttpResponse)
        # First sender wins; subsequent inserts for the same fingerprint are ignored.
        self._get_cache: dict[str, tuple[str | None, "HttpResponse"]] = {}
        # M6: thread-local current check so parallel workers each track their own
        # check context independently.  _current_check is now per-thread.
        self._tls: threading.local = threading.local()
        # (check_id, endpoint_key) pairs that have already executed
        self._done_checks: set[tuple[str, str]] = set()
        # Public metrics (read by to_summary)
        self.cache_hits: int = 0
        self.requests_deduped: int = 0
        self.redundant_checks_skipped: int = 0
        self.endpoints_prioritized: int = 0

    # ------------------------------------------------------------------
    # Fingerprinting
    # ------------------------------------------------------------------

    @staticmethod
    def make_fingerprint(
        method: str,
        url: str,
        body: bytes | None,
        auth_context_key: str,
        authenticated: bool,
    ) -> str:
        """Build a request fingerprint for dedup/cache lookup.

        The fingerprint covers everything that determines whether two requests
        are semantically equivalent: method, full URL (with query string),
        body bytes, the target's auth context, and whether credentials were
        attached.  Custom headers are intentionally excluded; including them
        would prevent legitimate dedup where two checks happen to set different
        ``Accept`` or ``X-Request-ID`` headers.
        """
        h = hashlib.sha256(usedforsecurity=False)
        h.update(method.upper().encode())
        h.update(b"\x00")
        h.update(url.encode())
        h.update(b"\x00")
        h.update(body or b"")
        h.update(b"\x00")
        h.update(auth_context_key.encode())
        h.update(b"\x00")
        h.update(b"1" if authenticated else b"0")
        return h.hexdigest()

    # ------------------------------------------------------------------
    # Check context management
    # ------------------------------------------------------------------

    def set_current_check(self, check_id: str | None) -> None:
        """Register which check is currently executing for the **calling thread**.

        M6: stored in thread-local storage so parallel workers do not interfere
        with each other's within-check cache bypass (RATE-001 compatibility).
        """
        self._tls.check = check_id

    # ------------------------------------------------------------------
    # GET response cache
    # ------------------------------------------------------------------

    def lookup_get(self, fingerprint: str) -> "HttpResponse | None":
        """Return a cached GET response, or ``None`` if not available.

        A cached entry is returned only when the requesting check differs from
        the check that sent the original request.  Within-check repeats are
        allowed so that checks like RATE-001 that intentionally probe the same
        endpoint multiple times continue to function.

        M6: ``_current_check`` is now thread-local, so each parallel worker
        sees its own check identity independently.
        """
        current = getattr(self._tls, "check", None)
        with self._lock:
            entry = self._get_cache.get(fingerprint)
            if entry is None:
                return None
            sender, response = entry
            if sender == current and current is not None:
                # Same check sent this earlier — allow the repeat through
                return None
            # Different check (or no check context) → serve from cache
            self.cache_hits += 1
            self.requests_deduped += 1
            return response

    def record_get(self, fingerprint: str, response: "HttpResponse") -> None:
        """Store a GET response.  First write wins; later identical fingerprints ignored."""
        current = getattr(self._tls, "check", None)
        with self._lock:
            if fingerprint not in self._get_cache and len(self._get_cache) < self._max:
                self._get_cache[fingerprint] = (current, response)

    # ------------------------------------------------------------------
    # Redundant check elimination
    # ------------------------------------------------------------------

    def is_check_done(self, check_id: str, endpoint_key: str) -> bool:
        """``True`` if (check_id, endpoint_key) has already executed in this assessment."""
        with self._lock:
            return (check_id, endpoint_key) in self._done_checks

    def mark_check_done(self, check_id: str, endpoint_key: str) -> None:
        """Record that a (check_id, endpoint_key) pair has completed."""
        with self._lock:
            self._done_checks.add((check_id, endpoint_key))

    def record_redundant_check_skipped(self) -> None:
        """Increment the redundant-check-skipped counter."""
        with self._lock:
            self.redundant_checks_skipped += 1

    # ------------------------------------------------------------------
    # Summary
    # ------------------------------------------------------------------

    def to_summary(self) -> "EfficiencySummary":
        """Build an :class:`~aegisapi.models.efficiency.EfficiencySummary`."""
        from aegisapi.models.efficiency import EfficiencySummary

        with self._lock:
            return EfficiencySummary(
                requests_deduped=self.requests_deduped,
                cache_hits=self.cache_hits,
                redundant_checks_skipped=self.redundant_checks_skipped,
                endpoints_prioritized=self.endpoints_prioritized,
                total_requests_saved=self.requests_deduped,
            )


__all__ = ["EfficiencyTracker"]
