"""M8 scan event system: thread-safe events for real-time scan visibility.

Security notes
--------------
* Event payloads must never contain credentials, authorization headers, or
  request/response bodies. The dispatcher enforces no such constraint — callers
  are responsible for including only safe fields.
* Untrusted strings (endpoint paths, summaries derived from API responses) in
  payloads should be rendered through Rich :class:`~rich.text.Text` at the
  presentation layer to prevent ANSI escape-code injection from a hostile server.
* Handlers are called without any engine-internal lock held; a handler that
  tries to acquire an engine-internal lock would deadlock. Keep handlers short
  and lock-free.
"""

from __future__ import annotations

import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any


class ScanEventType(StrEnum):
    """The events a scan emits as it progresses, in rough chronological order."""

    SCAN_STARTED = "scan_started"
    """The scan pipeline has begun; URL and options are fixed."""

    TARGET_VALIDATED = "target_validated"
    """URL was validated and the scope was derived."""

    DISCOVERY_STARTED = "discovery_started"
    """The endpoint inventory phase has begun."""

    ENDPOINT_DISCOVERED = "endpoint_discovered"
    """One endpoint was found in the inventory."""

    TESTING_STARTED = "testing_started"
    """Security checks are about to begin."""

    CHECK_STARTED = "check_started"
    """One (check, endpoint) pair is about to run."""

    CHECK_COMPLETED = "check_completed"
    """One (check, endpoint) pair finished (whether pass, fail, skip, or error)."""

    FINDING_DETECTED = "finding_detected"
    """A check produced a CONFIRMED or SUSPECTED finding."""

    PROGRESS_UPDATED = "progress_updated"
    """Periodic counter update: checks completed, checks total."""

    SCAN_COMPLETED = "scan_completed"
    """The scan finished normally."""

    SCAN_FAILED = "scan_failed"
    """The scan raised an unhandled exception."""

    SCAN_CANCELLED = "scan_cancelled"
    """The scan was interrupted (KeyboardInterrupt)."""


@dataclass(frozen=True)
class ScanEvent:
    """An immutable event emitted by the scan pipeline.

    The *payload* dict holds serialisable, credential-free values. Keys and
    values depend on the event type; callers should handle missing keys
    gracefully with ``.get()``.
    """

    event_type: ScanEventType
    timestamp: datetime
    payload: dict[str, Any] = field(default_factory=dict)


EventHandler = Callable[[ScanEvent], None]
"""A callable that receives a :class:`ScanEvent`.  Must not raise."""


class EventDispatcher:
    """Thread-safe event dispatcher for the scan pipeline.

    Subscribers register handlers that are called each time an event is
    emitted. Handlers run synchronously from the emitting thread and in
    registration order. A handler that raises does not stop the scan or
    other handlers — the exception is silently swallowed.

    Usage::

        dispatcher = EventDispatcher()
        dispatcher.subscribe(my_handler)
        # pass dispatcher to run_scan(event_dispatcher=dispatcher)
    """

    def __init__(self) -> None:
        self._handlers: list[EventHandler] = []
        self._lock = threading.Lock()

    def subscribe(self, handler: EventHandler) -> None:
        """Register *handler* to receive all future events."""
        with self._lock:
            self._handlers.append(handler)

    def emit(self, event_type: ScanEventType | str, **payload: Any) -> None:
        """Emit an event to every registered handler.

        *event_type* may be a :class:`ScanEventType` member or a matching
        string literal, so engine code that avoids the import can call
        ``dispatcher.emit("finding_detected", ...)`` and the type is
        normalised before the event is built.
        """
        if not isinstance(event_type, ScanEventType):
            event_type = ScanEventType(event_type)
        event = ScanEvent(
            event_type=event_type,
            timestamp=datetime.now(UTC),
            payload=payload,
        )
        with self._lock:
            handlers = list(self._handlers)
        for handler in handlers:
            try:
                handler(event)
            except Exception:
                pass  # a broken handler never kills the scan

    def clear(self) -> None:
        """Remove all registered handlers."""
        with self._lock:
            self._handlers.clear()


__all__ = [
    "EventDispatcher",
    "EventHandler",
    "ScanEvent",
    "ScanEventType",
]
