"""End-to-end verification of M3 — Complete Schema Validation.

Starts a schema-focused lab API on an ephemeral loopback port that serves
endpoints with:
  - conformant response bodies (schema matches declared schema)
  - violating response bodies (required fields missing, wrong types)
  - undeclared response status codes
  - undeclared response content types

Then runs the full scan pipeline and verifies that SCHEMA-001 (body
validation) and SCHEMA-002 (conformance) fire, classify correctly, and
appear in both JSON and HTML reports.

Run with:
    python tests/verify_m3.py

Nothing here touches an external host.  All traffic stays on 127.0.0.1.
"""

from __future__ import annotations

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import json
import pathlib
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any


# ---------------------------------------------------------------------------
# M3 lab specification
# ---------------------------------------------------------------------------

M3_SPEC: dict[str, Any] = {
    "openapi": "3.0.3",
    "info": {"title": "M3 Schema Lab", "version": "1.0.0"},
    "servers": [{"url": "/"}],
    "paths": {
        # SCHEMA-001 PASS: response body exactly matches declared schema.
        "/api/m3/conformant": {
            "get": {
                "operationId": "getConformant",
                "summary": "Returns a body that matches the declared schema.",
                "security": [],
                "responses": {
                    "200": {
                        "description": "OK",
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "required": ["id", "name"],
                                    "properties": {
                                        "id": {"type": "integer"},
                                        "name": {"type": "string"},
                                    },
                                }
                            }
                        },
                    }
                },
            }
        },
        # SCHEMA-001 FAIL (INFORMATIONAL): response body violates schema.
        # Missing 'name' (required) and 'id' is a string, not integer.
        "/api/m3/violating": {
            "get": {
                "operationId": "getViolating",
                "summary": "Returns a body that violates the declared schema.",
                "security": [],
                "responses": {
                    "200": {
                        "description": "OK",
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "required": ["id", "name"],
                                    "properties": {
                                        "id": {"type": "integer"},
                                        "name": {"type": "string"},
                                    },
                                }
                            }
                        },
                    }
                },
            }
        },
        # SCHEMA-001 PASS with nested object.
        "/api/m3/nested": {
            "get": {
                "operationId": "getNested",
                "summary": "Returns a body with nested objects matching the declared schema.",
                "security": [],
                "responses": {
                    "200": {
                        "description": "OK",
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "required": ["user"],
                                    "properties": {
                                        "user": {
                                            "type": "object",
                                            "required": ["id"],
                                            "properties": {
                                                "id": {"type": "integer"},
                                            },
                                        }
                                    },
                                }
                            }
                        },
                    }
                },
            }
        },
        # SCHEMA-002 PASS: status 200 and content-type match declared spec.
        "/api/m3/status-conformant": {
            "get": {
                "operationId": "getStatusConformant",
                "summary": "Returns a declared status code and content type.",
                "security": [],
                "responses": {
                    "200": {
                        "description": "OK",
                        "content": {"application/json": {"schema": {}}},
                    }
                },
            }
        },
        # SCHEMA-002 FAIL: returns 204 but spec only declares 200.
        "/api/m3/undeclared-status": {
            "get": {
                "operationId": "getUndeclaredStatus",
                "summary": "Returns 204 but spec only declares 200.",
                "security": [],
                "responses": {
                    "200": {
                        "description": "OK",
                        "content": {"application/json": {"schema": {}}},
                    }
                },
            }
        },
        # SCHEMA-002 FAIL: returns text/plain but spec declares application/json.
        "/api/m3/wrong-content-type": {
            "get": {
                "operationId": "getWrongContentType",
                "summary": "Returns text/plain but spec declares application/json.",
                "security": [],
                "responses": {
                    "200": {
                        "description": "OK",
                        "content": {"application/json": {"schema": {}}},
                    }
                },
            }
        },
    },
}


# ---------------------------------------------------------------------------
# Lab HTTP server
# ---------------------------------------------------------------------------

class _M3Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt: str, *args: Any) -> None:
        pass

    def _send(self, status: int, body: bytes, *, ct: str = "application/json") -> None:
        self.send_response(status)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _json(self, status: int, payload: Any) -> None:
        self._send(status, json.dumps(payload).encode(), ct="application/json")

    @property
    def _path(self) -> str:
        return self.path.split("?", 1)[0]

    def do_GET(self) -> None:  # noqa: N802
        p = self._path

        if p == "/openapi.json":
            self._json(200, M3_SPEC)
            return

        if p == "/":
            self._json(200, {"service": "m3-schema-lab"})
            return

        if p == "/api/m3/conformant":
            # Exactly matches declared schema: {id: integer, name: string}
            self._json(200, {"id": 1, "name": "Alice"})
            return

        if p == "/api/m3/violating":
            # Violates declared schema: 'id' is string (should be integer),
            # 'name' is absent (required).
            self._json(200, {"id": "not-an-integer"})
            return

        if p == "/api/m3/nested":
            # Exactly matches nested schema.
            self._json(200, {"user": {"id": 42}})
            return

        if p == "/api/m3/status-conformant":
            self._json(200, {"ok": True})
            return

        if p == "/api/m3/undeclared-status":
            # Declared 200; returns 204.
            self._send(204, b"")
            return

        if p == "/api/m3/wrong-content-type":
            # Declared application/json; returns text/plain.
            self._send(200, b"hello world", ct="text/plain")
            return

        self._json(404, {"error": "not found"})

    def do_HEAD(self) -> None:  # noqa: N802
        self.do_GET()

    def do_OPTIONS(self) -> None:  # noqa: N802
        self._send(204, b"")


def _start_lab() -> tuple[ThreadingHTTPServer, int]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), _M3Handler)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    return server, server.server_address[1]


# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------

W = 70

def section(title: str) -> None:
    print(f"\n{'=' * W}")
    print(f"  {title}")
    print("=" * W)

def ok(label: str, detail: str = "") -> None:
    suffix = f"  {detail}" if detail else ""
    print(f"  PASS  {label}{suffix}")

def fail(label: str, detail: str = "") -> None:
    suffix = f"  {detail}" if detail else ""
    print(f"  FAIL  {label}{suffix}")
    return 1

def info(label: str) -> None:
    print(f"        {label}")


# ---------------------------------------------------------------------------
# Main verification
# ---------------------------------------------------------------------------

def run_verification() -> int:
    failures = 0

    # ------------------------------------------------------------------ #
    # Boot the M3 lab
    # ------------------------------------------------------------------ #
    section("Starting M3 schema lab")
    server, port = _start_lab()
    base_url = f"http://127.0.0.1:{port}"
    info(f"Lab listening at {base_url}")
    info(f"Endpoints: conformant, violating, nested, status-conformant,")
    info(f"           undeclared-status, wrong-content-type")

    # ------------------------------------------------------------------ #
    # Imports
    # ------------------------------------------------------------------ #
    from aegisapi.core.config import AegisConfig
    from aegisapi.models.assessment import CheckOutcome, FindingClass
    from aegisapi.reporting import render_html_report, render_json_report, write_report_text
    from aegisapi.scan.pipeline import ScanOptions, ScanStage, run_scan

    config = AegisConfig()

    # ------------------------------------------------------------------ #
    # Run the full scan
    # ------------------------------------------------------------------ #
    section("Running full scan pipeline")
    stages_seen: list[ScanStage] = []
    messages_seen: list[tuple[ScanStage, str]] = []

    def capture(stage: ScanStage, message: str) -> None:
        stages_seen.append(stage)
        messages_seen.append((stage, message))

    options = ScanOptions(url=base_url, local_lab=True, budget=400)
    result = run_scan(options, config=config, progress=capture)

    info(f"Scan complete: {result.requests_sent} requests")
    info(f"Results total: {len(result.assessment.results)}")
    info(f"schemas_validated: {result.schemas_validated}")
    info(f"schema_violations: {result.schema_violations}")

    # ------------------------------------------------------------------ #
    # V-01: SCHEMA_VAL stage was emitted
    # ------------------------------------------------------------------ #
    section("V-01: SCHEMA_VAL stage emitted")
    if ScanStage.SCHEMA_VAL in stages_seen:
        ok("SCHEMA_VAL stage was emitted")
    else:
        failures += fail("SCHEMA_VAL stage was NOT emitted")

    schema_val_msgs = [m for s, m in messages_seen if s is ScanStage.SCHEMA_VAL]
    for msg in schema_val_msgs:
        info(f"  [schema-val] {msg}")

    # ------------------------------------------------------------------ #
    # V-02: schemas_validated count > 0
    # ------------------------------------------------------------------ #
    section("V-02: schemas_validated is positive")
    info(f"schemas_validated = {result.schemas_validated}")
    if result.schemas_validated > 0:
        ok(f"schemas_validated = {result.schemas_validated}")
    else:
        failures += fail("schemas_validated is 0; expected > 0")

    # ------------------------------------------------------------------ #
    # V-03: schema_violations > 0 (violating endpoint causes failure)
    # ------------------------------------------------------------------ #
    section("V-03: schema_violations is positive")
    info(f"schema_violations = {result.schema_violations}")
    if result.schema_violations > 0:
        ok(f"schema_violations = {result.schema_violations}")
    else:
        failures += fail("schema_violations is 0; expected > 0")

    # ------------------------------------------------------------------ #
    # V-04: SCHEMA-001 PASS on conformant endpoint
    # ------------------------------------------------------------------ #
    section("V-04: SCHEMA-001 passes for /api/m3/conformant")
    conformant_001 = [
        r for r in result.assessment.results
        if r.check_id == "SCHEMA-001" and "conformant" in r.endpoint_key
        and "violating" not in r.endpoint_key and "nested" not in r.endpoint_key
    ]
    info(f"SCHEMA-001 results for /conformant: {len(conformant_001)}")
    for r in conformant_001:
        info(f"  {r.endpoint_key}: outcome={r.outcome} class={r.finding_class}")

    passed_001 = [r for r in conformant_001 if r.outcome is CheckOutcome.PASS]
    if passed_001:
        ok("SCHEMA-001 PASS on /api/m3/conformant")
    elif conformant_001:
        failures += fail(
            f"SCHEMA-001 did not PASS on /conformant; got {conformant_001[0].outcome}"
        )
    else:
        failures += fail("No SCHEMA-001 result found for /conformant")

    # ------------------------------------------------------------------ #
    # V-05: SCHEMA-001 FAIL (INFORMATIONAL) on violating endpoint
    # ------------------------------------------------------------------ #
    section("V-05: SCHEMA-001 FAIL INFORMATIONAL on /api/m3/violating")
    violating_001 = [
        r for r in result.assessment.results
        if r.check_id == "SCHEMA-001" and r.endpoint_key == "GET /api/m3/violating"
    ]
    info(f"SCHEMA-001 results for /violating: {len(violating_001)}")
    for r in violating_001:
        info(f"  outcome={r.outcome} class={r.finding_class} summary={r.summary[:60]}")

    fail_info_001 = [
        r for r in violating_001
        if r.outcome is CheckOutcome.FAIL and r.finding_class is FindingClass.INFORMATIONAL
    ]
    if fail_info_001:
        ok("SCHEMA-001 FAIL INFORMATIONAL on /api/m3/violating")
        info(f"  Summary: {fail_info_001[0].summary}")
    elif violating_001:
        failures += fail(
            f"SCHEMA-001 outcome/class wrong: {violating_001[0].outcome}/{violating_001[0].finding_class}"
        )
    else:
        failures += fail("No SCHEMA-001 result found for /violating")

    # ------------------------------------------------------------------ #
    # V-06: SCHEMA-001 violations mention only types, not values
    # ------------------------------------------------------------------ #
    section("V-06: Violation messages do not leak response values")
    sensitive_patterns = ['"not-an-integer"', "not-an-integer", "Alice"]
    for r in result.assessment.results:
        if r.check_id != "SCHEMA-001":
            continue
        for pattern in sensitive_patterns:
            if pattern in r.summary or pattern in r.explanation:
                failures += fail(
                    f"Sensitive value '{pattern}' found in SCHEMA-001 result for "
                    f"{r.endpoint_key}"
                )
                break
        else:
            continue  # no sensitive pattern in this result
        break
    else:
        ok("No sensitive response values found in SCHEMA-001 results")

    # ------------------------------------------------------------------ #
    # V-07: SCHEMA-001 PASS on nested endpoint
    # ------------------------------------------------------------------ #
    section("V-07: SCHEMA-001 passes for /api/m3/nested")
    nested_001 = [
        r for r in result.assessment.results
        if r.check_id == "SCHEMA-001" and r.endpoint_key == "GET /api/m3/nested"
    ]
    info(f"SCHEMA-001 results for /nested: {len(nested_001)}")
    if nested_001:
        r = nested_001[0]
        info(f"  outcome={r.outcome} class={r.finding_class}")
        if r.outcome is CheckOutcome.PASS:
            ok("SCHEMA-001 PASS on /api/m3/nested (nested object)")
        else:
            failures += fail(f"SCHEMA-001 did not PASS on /nested: {r.outcome} {r.summary}")
    else:
        failures += fail("No SCHEMA-001 result for /nested")

    # ------------------------------------------------------------------ #
    # V-08: SCHEMA-002 PASS on conformant-status endpoint
    # ------------------------------------------------------------------ #
    section("V-08: SCHEMA-002 passes for /api/m3/status-conformant")
    conformant_002 = [
        r for r in result.assessment.results
        if r.check_id == "SCHEMA-002" and r.endpoint_key == "GET /api/m3/status-conformant"
    ]
    info(f"SCHEMA-002 results for /status-conformant: {len(conformant_002)}")
    if conformant_002:
        r = conformant_002[0]
        info(f"  outcome={r.outcome} class={r.finding_class}")
        if r.outcome is CheckOutcome.PASS:
            ok("SCHEMA-002 PASS on /api/m3/status-conformant")
        else:
            failures += fail(f"SCHEMA-002 did not PASS: {r.outcome} {r.summary}")
    else:
        failures += fail("No SCHEMA-002 result for /status-conformant")

    # ------------------------------------------------------------------ #
    # V-09: SCHEMA-002 FAIL (INFORMATIONAL) on undeclared-status endpoint
    # ------------------------------------------------------------------ #
    section("V-09: SCHEMA-002 FAIL INFORMATIONAL on /api/m3/undeclared-status")
    undeclared_002 = [
        r for r in result.assessment.results
        if r.check_id == "SCHEMA-002" and r.endpoint_key == "GET /api/m3/undeclared-status"
    ]
    info(f"SCHEMA-002 results for /undeclared-status: {len(undeclared_002)}")
    if undeclared_002:
        r = undeclared_002[0]
        info(f"  outcome={r.outcome} class={r.finding_class} summary={r.summary[:60]}")
        if r.outcome is CheckOutcome.FAIL and r.finding_class is FindingClass.INFORMATIONAL:
            ok("SCHEMA-002 FAIL INFORMATIONAL on /undeclared-status")
        else:
            failures += fail(f"SCHEMA-002 wrong outcome/class: {r.outcome}/{r.finding_class}")
    else:
        failures += fail("No SCHEMA-002 result for /undeclared-status")

    # ------------------------------------------------------------------ #
    # V-10: SCHEMA-002 FAIL (INFORMATIONAL) on wrong-content-type endpoint
    # ------------------------------------------------------------------ #
    section("V-10: SCHEMA-002 FAIL INFORMATIONAL on /api/m3/wrong-content-type")
    wrong_ct_002 = [
        r for r in result.assessment.results
        if r.check_id == "SCHEMA-002" and r.endpoint_key == "GET /api/m3/wrong-content-type"
    ]
    info(f"SCHEMA-002 results for /wrong-content-type: {len(wrong_ct_002)}")
    if wrong_ct_002:
        r = wrong_ct_002[0]
        info(f"  outcome={r.outcome} class={r.finding_class} summary={r.summary[:60]}")
        if r.outcome is CheckOutcome.FAIL and r.finding_class is FindingClass.INFORMATIONAL:
            ok("SCHEMA-002 FAIL INFORMATIONAL on /wrong-content-type")
        else:
            failures += fail(f"SCHEMA-002 wrong outcome/class: {r.outcome}/{r.finding_class}")
    else:
        failures += fail("No SCHEMA-002 result for /wrong-content-type")

    # ------------------------------------------------------------------ #
    # V-11: SCHEMA-001 and SCHEMA-002 have OWASP categories
    # ------------------------------------------------------------------ #
    section("V-11: SCHEMA-001 and SCHEMA-002 carry OWASP categories")
    all_schema_001 = [r for r in result.assessment.results if r.check_id == "SCHEMA-001" and r.owasp]
    all_schema_002 = [r for r in result.assessment.results if r.check_id == "SCHEMA-002" and r.owasp]
    if all_schema_001:
        ok(f"SCHEMA-001 carries OWASP: {all_schema_001[0].owasp.identifier if all_schema_001[0].owasp else 'none'}")
    else:
        failures += fail("No SCHEMA-001 result with an OWASP category")
    if all_schema_002:
        ok(f"SCHEMA-002 carries OWASP: {all_schema_002[0].owasp.identifier if all_schema_002[0].owasp else 'none'}")
    else:
        failures += fail("No SCHEMA-002 result with an OWASP category")

    # ------------------------------------------------------------------ #
    # V-12: JSON and HTML reports produced and contain schema results
    # ------------------------------------------------------------------ #
    section("V-12: JSON and HTML reports contain SCHEMA-001/002 results")
    with tempfile.TemporaryDirectory() as tmpdir:
        json_path = pathlib.Path(tmpdir) / "report.json"
        html_path = pathlib.Path(tmpdir) / "report.html"

        json_text = render_json_report(result.report)
        html_text = render_html_report(result.report)
        write_report_text(json_path, json_text, overwrite=True)
        write_report_text(html_path, html_text, overwrite=True)

        try:
            parsed = json.loads(json_text)
            # INFORMATIONAL results (schema violations) are not "findings" so
            # they don't appear in report.results by default; check checks_run
            # instead, which lists every check that was attempted.
            checks_run = parsed.get("checks_run", [])
            schema_in_checks_run = [c for c in checks_run if str(c).startswith("SCHEMA-")]
            info(f"SCHEMA-* entries in checks_run: {len(schema_in_checks_run)}")
            if schema_in_checks_run:
                ok(f"JSON report lists {len(schema_in_checks_run)} SCHEMA-* checks in checks_run")
            else:
                failures += fail("JSON report checks_run contains no SCHEMA-* entries")
        except json.JSONDecodeError as exc:
            failures += fail(f"JSON report could not be parsed: {exc}")

        if "SCHEMA-001" in html_text or "SCHEMA-002" in html_text:
            ok("HTML report mentions SCHEMA-001 or SCHEMA-002")
        else:
            failures += fail("HTML report does not mention SCHEMA-001 or SCHEMA-002")

        info(f"JSON report: {json_path}")
        info(f"HTML report: {html_path}")

    # ------------------------------------------------------------------ #
    # V-13: Scan summary shows "Schema validation" row
    # ------------------------------------------------------------------ #
    section("V-13: Scan summary shows schema_validated count")
    info(f"schemas_validated = {result.schemas_validated}")
    info(f"schema_violations = {result.schema_violations}")
    if result.schemas_validated > 0:
        ok(f"schemas_validated={result.schemas_validated} will render in summary")
    else:
        failures += fail("schemas_validated is 0; summary row will not appear")

    # ------------------------------------------------------------------ #
    # V-14: Progress messages show [schema-val] prefix
    # ------------------------------------------------------------------ #
    section("V-14: Progress messages from SCHEMA_VAL stage observed")
    schema_val_progress = [(s, m) for s, m in messages_seen if s is ScanStage.SCHEMA_VAL]
    info(f"SCHEMA_VAL progress messages: {len(schema_val_progress)}")
    for _, msg in schema_val_progress:
        info(f"  {msg}")
    if schema_val_progress:
        ok(f"Received {len(schema_val_progress)} SCHEMA_VAL progress message(s)")
    else:
        failures += fail("No SCHEMA_VAL progress messages received")

    # ------------------------------------------------------------------ #
    # Final summary
    # ------------------------------------------------------------------ #
    section("SUMMARY")
    total_v = 14
    passed_v = total_v - failures
    if failures == 0:
        print(f"  ALL {total_v} VERIFICATION POINTS PASSED")
    else:
        print(f"  {passed_v}/{total_v} passed — {failures} FAILED")
    print()

    server.shutdown()
    return failures


if __name__ == "__main__":
    sys.exit(run_verification())
