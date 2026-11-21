"""Integration tests for M8 live scan event delivery.

Tests that:
- run_scan() delivers stage events (SCAN_STARTED, TARGET_VALIDATED, etc.)
- Findings produce FINDING_DETECTED events immediately
- Progress counters are updated correctly
- Security invariants are upheld (no credentials, no bodies in events)
- make_event_handler() prints findings and is silent in --no-progress mode
- --no-progress suppresses live output but final report is still produced
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from io import StringIO
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from aegisapi.core.config import AegisConfig
from aegisapi.scan.events import EventDispatcher, ScanEvent, ScanEventType
from aegisapi.scan.pipeline import ScanOptions, run_scan


# ---------------------------------------------------------------------------
# Minimal local HTTP server
# ---------------------------------------------------------------------------

_SPEC = {
    "openapi": "3.0.0",
    "info": {"title": "LiveScan Lab", "version": "1.0.0"},
    "paths": {
        "/api/items": {
            "get": {
                "operationId": "listItems",
                "security": [{"bearerAuth": []}],
                "responses": {"200": {"description": "ok"}},
            }
        },
        "/api/health": {
            "get": {
                "operationId": "health",
                "responses": {"200": {"description": "ok"}},
            }
        },
    },
    "components": {
        "securitySchemes": {
            "bearerAuth": {"type": "http", "scheme": "bearer"}
        }
    },
}


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        if self.path.startswith("/openapi.json"):
            body = json.dumps(_SPEC).encode()
            ct = "application/json"
        else:
            body = b'{"ok": true}'
            ct = "application/json"
        self.send_response(200)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args: Any) -> None:
        pass


def _start_server() -> tuple[HTTPServer, str]:
    server = HTTPServer(("127.0.0.1", 0), _Handler)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    port = server.server_address[1]
    return server, f"http://127.0.0.1:{port}"


@pytest.fixture(scope="module")
def lab_server() -> Any:
    server, url = _start_server()
    yield url
    server.shutdown()
    server.server_close()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _collect(dispatcher: EventDispatcher) -> list[ScanEvent]:
    seen: list[ScanEvent] = []
    dispatcher.subscribe(seen.append)
    return seen


def _events_of(events: list[ScanEvent], event_type: ScanEventType) -> list[ScanEvent]:
    return [e for e in events if e.event_type is event_type]


def _run(url: str, budget: int = 60) -> tuple[Any, list[ScanEvent]]:
    d = EventDispatcher()
    seen = _collect(d)
    config = AegisConfig()
    opts = ScanOptions(url=url, local_lab=True, budget=budget)
    result = run_scan(opts, config=config, event_dispatcher=d)
    return result, seen


# ---------------------------------------------------------------------------
# TestStageLevelEvents
# ---------------------------------------------------------------------------

class TestStageLevelEvents:
    def test_scan_started_emitted_first(self, lab_server: str) -> None:
        _, seen = _run(lab_server)
        assert seen[0].event_type is ScanEventType.SCAN_STARTED

    def test_scan_started_carries_url(self, lab_server: str) -> None:
        _, seen = _run(lab_server)
        started = _events_of(seen, ScanEventType.SCAN_STARTED)
        assert started[0].payload["url"] == lab_server

    def test_target_validated_emitted(self, lab_server: str) -> None:
        _, seen = _run(lab_server)
        assert any(e.event_type is ScanEventType.TARGET_VALIDATED for e in seen)

    def test_target_validated_carries_host(self, lab_server: str) -> None:
        _, seen = _run(lab_server)
        tv = _events_of(seen, ScanEventType.TARGET_VALIDATED)
        assert tv[0].payload.get("host") == "127.0.0.1"

    def test_discovery_started_emitted(self, lab_server: str) -> None:
        _, seen = _run(lab_server)
        assert any(e.event_type is ScanEventType.DISCOVERY_STARTED for e in seen)

    def test_endpoint_discovered_emitted_for_each_endpoint(self, lab_server: str) -> None:
        _, seen = _run(lab_server)
        discovered = _events_of(seen, ScanEventType.ENDPOINT_DISCOVERED)
        assert len(discovered) >= 1
        for ev in discovered:
            assert "endpoint_key" in ev.payload
            assert "classification" in ev.payload

    def test_testing_started_emitted(self, lab_server: str) -> None:
        _, seen = _run(lab_server)
        assert any(e.event_type is ScanEventType.TESTING_STARTED for e in seen)

    def test_scan_completed_emitted_last(self, lab_server: str) -> None:
        _, seen = _run(lab_server)
        completed = _events_of(seen, ScanEventType.SCAN_COMPLETED)
        assert len(completed) == 1
        # SCAN_COMPLETED should be the last event
        assert seen[-1].event_type is ScanEventType.SCAN_COMPLETED

    def test_scan_completed_carries_duration(self, lab_server: str) -> None:
        _, seen = _run(lab_server)
        completed = _events_of(seen, ScanEventType.SCAN_COMPLETED)
        assert "duration_seconds" in completed[0].payload
        assert completed[0].payload["duration_seconds"] >= 0.0

    def test_scan_failed_emitted_on_error(self) -> None:
        d = EventDispatcher()
        seen = _collect(d)
        config = AegisConfig()
        # Non-routable host to force a TransportError
        opts = ScanOptions(url="http://127.0.0.1:1", local_lab=True, budget=5)
        with pytest.raises(Exception):
            run_scan(opts, config=config, event_dispatcher=d)
        failed = _events_of(seen, ScanEventType.SCAN_FAILED)
        assert len(failed) == 1


# ---------------------------------------------------------------------------
# TestCheckLevelEvents
# ---------------------------------------------------------------------------

class TestCheckLevelEvents:
    def test_check_started_emitted_per_work_item(self, lab_server: str) -> None:
        _, seen = _run(lab_server)
        started = _events_of(seen, ScanEventType.CHECK_STARTED)
        assert len(started) >= 1
        for ev in started:
            assert "check_id" in ev.payload
            assert "endpoint_key" in ev.payload

    def test_check_completed_emitted_after_started(self, lab_server: str) -> None:
        _, seen = _run(lab_server)
        started = len(_events_of(seen, ScanEventType.CHECK_STARTED))
        completed = len(_events_of(seen, ScanEventType.CHECK_COMPLETED))
        assert started == completed

    def test_progress_updated_emitted(self, lab_server: str) -> None:
        _, seen = _run(lab_server)
        progress = _events_of(seen, ScanEventType.PROGRESS_UPDATED)
        assert len(progress) >= 1

    def test_progress_updated_checks_total_is_consistent(self, lab_server: str) -> None:
        _, seen = _run(lab_server)
        progress = _events_of(seen, ScanEventType.PROGRESS_UPDATED)
        if progress:
            # All events should report the same total
            totals = {ev.payload["checks_total"] for ev in progress}
            assert len(totals) == 1
            # Last event: completed == total
            last = progress[-1]
            assert last.payload["checks_completed"] == last.payload["checks_total"]

    def test_check_started_carries_expected_fields(self, lab_server: str) -> None:
        _, seen = _run(lab_server)
        for ev in _events_of(seen, ScanEventType.CHECK_STARTED):
            assert isinstance(ev.payload.get("check_id"), str)
            assert isinstance(ev.payload.get("endpoint_key"), str)

    def test_check_completed_carries_expected_fields(self, lab_server: str) -> None:
        _, seen = _run(lab_server)
        for ev in _events_of(seen, ScanEventType.CHECK_COMPLETED):
            assert isinstance(ev.payload.get("check_id"), str)
            assert isinstance(ev.payload.get("endpoint_key"), str)


# ---------------------------------------------------------------------------
# TestFindingDetectedEvents
# ---------------------------------------------------------------------------

class TestFindingDetectedEvents:
    def test_finding_detected_payload_has_no_body_excerpt(self, lab_server: str) -> None:
        _, seen = _run(lab_server)
        for ev in _events_of(seen, ScanEventType.FINDING_DETECTED):
            assert "body_excerpt" not in ev.payload
            assert "request_body" not in ev.payload
            assert "response_body" not in ev.payload

    def test_finding_detected_payload_has_no_auth_headers(self, lab_server: str) -> None:
        _, seen = _run(lab_server)
        for ev in _events_of(seen, ScanEventType.FINDING_DETECTED):
            assert "Authorization" not in str(ev.payload)
            assert "Authorization:" not in str(ev.payload)

    def test_finding_detected_carries_severity_and_check_id(self, lab_server: str) -> None:
        _, seen = _run(lab_server)
        for ev in _events_of(seen, ScanEventType.FINDING_DETECTED):
            assert "check_id" in ev.payload
            assert "severity" in ev.payload
            assert "endpoint_key" in ev.payload
            assert "summary" in ev.payload


# ---------------------------------------------------------------------------
# TestSecurityInvariants
# ---------------------------------------------------------------------------

class TestSecurityInvariants:
    def test_no_credentials_in_any_payload(self, lab_server: str) -> None:
        _, seen = _run(lab_server)
        forbidden_keys = {
            "authorization", "token", "password", "secret",
            "api_key", "credential", "bearer",
        }
        for event in seen:
            for key in event.payload:
                assert key.lower() not in forbidden_keys, (
                    f"Credential-like key {key!r} in {event.event_type} payload"
                )

    def test_no_body_data_in_any_payload(self, lab_server: str) -> None:
        _, seen = _run(lab_server)
        for event in seen:
            assert "body_excerpt" not in event.payload
            assert "response_body" not in event.payload
            assert "request_body" not in event.payload

    def test_all_events_have_utc_timestamps(self, lab_server: str) -> None:
        _, seen = _run(lab_server)
        for event in seen:
            assert event.timestamp.tzinfo is not None


# ---------------------------------------------------------------------------
# TestNoProgressMode
# ---------------------------------------------------------------------------

class TestNoProgressMode:
    def test_no_progress_handler_is_callable(self) -> None:
        from aegisapi.commands.scan import make_event_handler
        from rich.console import Console

        console = Console(file=StringIO(), force_terminal=False)
        handler = make_event_handler(console, no_progress=True)
        # Should not raise
        event = ScanEvent(
            event_type=ScanEventType.FINDING_DETECTED,
            timestamp=__import__("datetime").datetime.now(__import__("datetime").timezone.utc),
            payload={"check_id": "AUTH-001", "severity": "high"},
        )
        handler(event)

    def test_no_progress_handler_produces_no_output(self) -> None:
        from aegisapi.commands.scan import make_event_handler
        from rich.console import Console

        buf = StringIO()
        console = Console(file=buf, force_terminal=False)
        handler = make_event_handler(console, no_progress=True)
        event = ScanEvent(
            event_type=ScanEventType.FINDING_DETECTED,
            timestamp=__import__("datetime").datetime.now(__import__("datetime").timezone.utc),
            payload={"check_id": "AUTH-001", "severity": "high", "summary": "Test"},
        )
        handler(event)
        assert buf.getvalue() == ""

    def test_live_handler_prints_on_finding_detected(self) -> None:
        from aegisapi.commands.scan import make_event_handler
        from rich.console import Console
        import datetime as _dt

        buf = StringIO()
        console = Console(file=buf, force_terminal=False)
        handler = make_event_handler(console, no_progress=False)
        event = ScanEvent(
            event_type=ScanEventType.FINDING_DETECTED,
            timestamp=_dt.datetime.now(_dt.timezone.utc),
            payload={
                "check_id": "AUTH-001",
                "severity": "high",
                "endpoint_key": "GET /api/items",
                "summary": "Authentication not enforced",
            },
        )
        handler(event)
        output = buf.getvalue()
        assert "AUTH-001" in output
        assert "GET /api/items" in output

    def test_live_handler_ignores_non_finding_events(self) -> None:
        from aegisapi.commands.scan import make_event_handler
        from rich.console import Console
        import datetime as _dt

        buf = StringIO()
        console = Console(file=buf, force_terminal=False)
        handler = make_event_handler(console, no_progress=False)
        event = ScanEvent(
            event_type=ScanEventType.SCAN_STARTED,
            timestamp=_dt.datetime.now(_dt.timezone.utc),
            payload={"url": "http://example.com"},
        )
        handler(event)
        assert buf.getvalue() == ""

    def test_scan_without_dispatcher_still_runs(self, lab_server: str) -> None:
        config = AegisConfig()
        opts = ScanOptions(url=lab_server, local_lab=True, budget=60)
        result = run_scan(opts, config=config)  # no dispatcher
        assert result is not None

    def test_scan_with_none_dispatcher_does_not_raise(self, lab_server: str) -> None:
        config = AegisConfig()
        opts = ScanOptions(url=lab_server, local_lab=True, budget=60)
        result = run_scan(opts, config=config, event_dispatcher=None)
        assert result is not None


# ---------------------------------------------------------------------------
# TestParallelScanEvents
# ---------------------------------------------------------------------------

class TestParallelScanEvents:
    def test_parallel_scan_delivers_events(self, lab_server: str) -> None:
        d = EventDispatcher()
        seen = _collect(d)
        config = AegisConfig()
        opts = ScanOptions(url=lab_server, local_lab=True, budget=120, max_workers=4)
        run_scan(opts, config=config, event_dispatcher=d)
        assert any(e.event_type is ScanEventType.SCAN_STARTED for e in seen)
        assert any(e.event_type is ScanEventType.SCAN_COMPLETED for e in seen)

    def test_parallel_scan_no_duplicate_scan_started(self, lab_server: str) -> None:
        d = EventDispatcher()
        seen = _collect(d)
        config = AegisConfig()
        opts = ScanOptions(url=lab_server, local_lab=True, budget=120, max_workers=4)
        run_scan(opts, config=config, event_dispatcher=d)
        started = _events_of(seen, ScanEventType.SCAN_STARTED)
        assert len(started) == 1

    def test_parallel_scan_no_duplicate_scan_completed(self, lab_server: str) -> None:
        d = EventDispatcher()
        seen = _collect(d)
        config = AegisConfig()
        opts = ScanOptions(url=lab_server, local_lab=True, budget=120, max_workers=4)
        run_scan(opts, config=config, event_dispatcher=d)
        completed = _events_of(seen, ScanEventType.SCAN_COMPLETED)
        assert len(completed) == 1

    def test_parallel_started_equals_completed_counts(self, lab_server: str) -> None:
        d = EventDispatcher()
        seen = _collect(d)
        config = AegisConfig()
        opts = ScanOptions(url=lab_server, local_lab=True, budget=120, max_workers=4)
        run_scan(opts, config=config, event_dispatcher=d)
        started = len(_events_of(seen, ScanEventType.CHECK_STARTED))
        completed = len(_events_of(seen, ScanEventType.CHECK_COMPLETED))
        assert started == completed
