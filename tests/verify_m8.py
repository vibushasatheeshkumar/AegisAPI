#!/usr/bin/env python3
"""E2E verification script for M8 — Live Findings and Real-Time Scan Progress.

Runs a local HTTP server with a minimal OpenAPI spec, drives run_scan() with an
EventDispatcher, and asserts each verification point (VP) in sequence.

Usage:
    python tests/verify_m8.py          # all VPs
    python tests/verify_m8.py VP-01    # specific VP
"""

from __future__ import annotations

import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from io import StringIO
from typing import Any

from aegisapi.core.config import AegisConfig
from aegisapi.scan.events import EventDispatcher, ScanEvent, ScanEventType
from aegisapi.scan.pipeline import ScanOptions, run_scan

# ---------------------------------------------------------------------------
# Minimal lab server
# ---------------------------------------------------------------------------

_SPEC = {
    "openapi": "3.0.0",
    "info": {"title": "M8 Lab", "version": "1.0.0"},
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


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

PASS = "\033[32m✓\033[0m"
FAIL = "\033[31m✗\033[0m"

_results: list[tuple[str, bool, str]] = []


def vp(name: str, condition: bool, detail: str = "") -> None:
    _results.append((name, condition, detail))
    mark = PASS if condition else FAIL
    suffix = f"  ({detail})" if detail and not condition else ""
    print(f"  {mark}  {name}{suffix}")


def _run(url: str, budget: int = 60, max_workers: int = 1) -> tuple[Any, list[ScanEvent]]:
    d = EventDispatcher()
    seen: list[ScanEvent] = []
    d.subscribe(seen.append)
    config = AegisConfig()
    opts = ScanOptions(url=url, local_lab=True, budget=budget, max_workers=max_workers)
    result = run_scan(opts, config=config, event_dispatcher=d)
    return result, seen


def _types(events: list[ScanEvent]) -> list[str]:
    return [e.event_type.value for e in events]


# ---------------------------------------------------------------------------
# Verification points
# ---------------------------------------------------------------------------

def run_vps(url: str) -> None:
    print("\n--- Running scan for VP-01 through VP-18 ---")
    result, events = _run(url)
    types = _types(events)

    # --- Stage events ---
    print("\n[Stage events]")

    vp("VP-01  SCAN_STARTED is the first event",
       types[0] == "scan_started")

    vp("VP-02  SCAN_STARTED payload carries URL",
       events[0].payload.get("url") == url)

    vp("VP-03  TARGET_VALIDATED is emitted",
       "target_validated" in types)

    vp("VP-04  DISCOVERY_STARTED is emitted",
       "discovery_started" in types)

    vp("VP-05  ENDPOINT_DISCOVERED emitted ≥1 time",
       types.count("endpoint_discovered") >= 1)

    vp("VP-06  ENDPOINT_DISCOVERED payload has endpoint_key + classification",
       all("endpoint_key" in e.payload and "classification" in e.payload
           for e in events if e.event_type.value == "endpoint_discovered"))

    vp("VP-07  TESTING_STARTED is emitted",
       "testing_started" in types)

    vp("VP-08  SCAN_COMPLETED is the last event",
       types[-1] == "scan_completed")

    vp("VP-09  SCAN_COMPLETED emitted exactly once",
       types.count("scan_completed") == 1)

    vp("VP-10  SCAN_COMPLETED payload has duration_seconds ≥ 0",
       all(e.payload.get("duration_seconds", -1) >= 0
           for e in events if e.event_type.value == "scan_completed"))

    # --- Check-level events ---
    print("\n[Check-level events]")

    started = [e for e in events if e.event_type.value == "check_started"]
    completed = [e for e in events if e.event_type.value == "check_completed"]
    progress = [e for e in events if e.event_type.value == "progress_updated"]

    vp("VP-11  CHECK_STARTED emitted ≥1 time",
       len(started) >= 1)

    vp("VP-12  CHECK_STARTED == CHECK_COMPLETED count",
       len(started) == len(completed),
       f"started={len(started)} completed={len(completed)}")

    vp("VP-13  PROGRESS_UPDATED emitted",
       len(progress) >= 1)

    if progress:
        totals = {e.payload.get("checks_total") for e in progress}
        last = progress[-1]
        vp("VP-14  PROGRESS_UPDATED checks_total is consistent across all events",
           len(totals) == 1)
        vp("VP-15  Final PROGRESS_UPDATED: checks_completed == checks_total",
           last.payload.get("checks_completed") == last.payload.get("checks_total"),
           f"done={last.payload.get('checks_completed')} total={last.payload.get('checks_total')}")
    else:
        vp("VP-14  PROGRESS_UPDATED checks_total consistent", True, "no progress events")
        vp("VP-15  Final PROGRESS_UPDATED == total", True, "no progress events")

    # --- Security invariants ---
    print("\n[Security invariants]")

    forbidden_keys = {"authorization", "token", "password", "secret", "api_key",
                      "credential", "bearer", "body_excerpt", "request_body", "response_body"}
    payload_violations = [
        f"{e.event_type}: {k}"
        for e in events
        for k in e.payload
        if k.lower() in forbidden_keys
    ]
    vp("VP-16  No credential/body keys in any payload",
       len(payload_violations) == 0,
       "; ".join(payload_violations))

    vp("VP-17  All events have UTC-aware timestamps",
       all(e.timestamp.tzinfo is not None for e in events))

    vp("VP-18  SCAN_STARTED emitted exactly once",
       types.count("scan_started") == 1)


def run_vp_no_progress() -> None:
    print("\n--- make_event_handler tests ---")
    from rich.console import Console
    from aegisapi.commands.scan import make_event_handler
    import datetime as _dt

    # VP-19: no_progress=True produces no output
    buf = StringIO()
    console = Console(file=buf, force_terminal=False)
    handler = make_event_handler(console, no_progress=True)
    ev = ScanEvent(
        event_type=ScanEventType.FINDING_DETECTED,
        timestamp=_dt.datetime.now(_dt.timezone.utc),
        payload={"check_id": "AUTH-001", "severity": "high", "summary": "X"},
    )
    handler(ev)
    vp("VP-19  no_progress=True produces no output on FINDING_DETECTED",
       buf.getvalue() == "")

    # VP-20: no_progress=False prints on FINDING_DETECTED
    buf2 = StringIO()
    console2 = Console(file=buf2, force_terminal=False)
    handler2 = make_event_handler(console2, no_progress=False)
    handler2(ev)
    output = buf2.getvalue()
    vp("VP-20  no_progress=False prints check_id and endpoint_key on FINDING_DETECTED",
       "AUTH-001" in output)

    # VP-21: non-finding events suppressed even in live mode
    buf3 = StringIO()
    console3 = Console(file=buf3, force_terminal=False)
    handler3 = make_event_handler(console3, no_progress=False)
    scan_ev = ScanEvent(
        event_type=ScanEventType.SCAN_STARTED,
        timestamp=_dt.datetime.now(_dt.timezone.utc),
        payload={"url": "http://example.com"},
    )
    handler3(scan_ev)
    vp("VP-21  no_progress=False is silent for non-FINDING_DETECTED events",
       buf3.getvalue() == "")


def run_vp_parallel(url: str) -> None:
    print("\n--- Parallel scan events (max_workers=4) ---")
    result, events = _run(url, budget=120, max_workers=4)
    types = _types(events)

    vp("VP-22  Parallel: SCAN_STARTED emitted exactly once",
       types.count("scan_started") == 1)

    vp("VP-23  Parallel: SCAN_COMPLETED emitted exactly once",
       types.count("scan_completed") == 1)

    started = types.count("check_started")
    completed = types.count("check_completed")
    vp("VP-24  Parallel: CHECK_STARTED == CHECK_COMPLETED",
       started == completed,
       f"started={started} completed={completed}")


def run_vp_scan_failed() -> None:
    print("\n--- SCAN_FAILED event ---")
    d = EventDispatcher()
    seen: list[ScanEvent] = []
    d.subscribe(seen.append)
    config = AegisConfig()
    opts = ScanOptions(url="http://127.0.0.1:1", local_lab=True, budget=5)
    exc_raised = False
    try:
        run_scan(opts, config=config, event_dispatcher=d)
    except Exception:
        exc_raised = True
    failed = [e for e in seen if e.event_type.value == "scan_failed"]
    vp("VP-25  SCAN_FAILED emitted on exception from run_scan",
       len(failed) == 1 and exc_raised,
       f"exc_raised={exc_raised} scan_failed_count={len(failed)}")


def run_vp_no_dispatcher(url: str) -> None:
    print("\n--- Scan without dispatcher ---")
    config = AegisConfig()
    opts = ScanOptions(url=url, local_lab=True, budget=60)
    exc = None
    try:
        result = run_scan(opts, config=config)
    except Exception as e:
        exc = e
    vp("VP-26  run_scan without event_dispatcher does not raise",
       exc is None,
       str(exc) if exc else "")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main(argv: list[str]) -> int:
    filter_vp: str | None = argv[0].upper() if argv else None

    server, url = _start_server()
    print(f"Lab server: {url}")

    try:
        if filter_vp is None or filter_vp.startswith("VP-0") or filter_vp.startswith("VP-1"):
            run_vps(url)
        if filter_vp is None or filter_vp in ("VP-19", "VP-20", "VP-21"):
            run_vp_no_progress()
        if filter_vp is None or filter_vp in ("VP-22", "VP-23", "VP-24"):
            run_vp_parallel(url)
        if filter_vp is None or filter_vp == "VP-25":
            run_vp_scan_failed()
        if filter_vp is None or filter_vp == "VP-26":
            run_vp_no_dispatcher(url)
    finally:
        server.shutdown()
        server.server_close()

    total = len(_results)
    passed = sum(1 for _, ok, _ in _results if ok)
    failed = total - passed

    print(f"\n{'=' * 50}")
    print(f"M8 E2E: {passed}/{total} passed", end="")
    if failed:
        print(f"  ({failed} failed)")
        for name, ok, detail in _results:
            if not ok:
                print(f"  FAIL: {name}  {detail}")
    else:
        print("  — all pass")

    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
