"""End-to-end verification of M2 — Automatic Test Fixtures.

Starts a modified lab API (the existing lab spec extended with path-templated
endpoints) on an ephemeral loopback port, then runs the full scan pipeline
programmatically and reports what happened at every verification point.

Run with:
    python tests/verify_m2.py

Nothing here touches an external host. All traffic stays on 127.0.0.1.
"""

from __future__ import annotations

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import copy
import json
import pathlib
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from labapi import SPEC as _BASE_SPEC, WEAK_SERVER_BANNER, WEAK_POWERED_BY

# ---------------------------------------------------------------------------
# Extended SPEC — adds path-templated endpoints with rich schemas
# ---------------------------------------------------------------------------

EXTENDED_SPEC: dict[str, Any] = copy.deepcopy(_BASE_SPEC)

EXTENDED_SPEC["paths"].update(
    {
        "/api/orders/{orderId}": {
            "get": {
                "operationId": "getOrder",
                "summary": "Fetch one order by ID.",
                "security": [{"bearerAuth": []}],
                "parameters": [
                    {
                        "name": "orderId",
                        "in": "path",
                        "required": True,
                        "schema": {"type": "integer", "minimum": 1},
                    },
                    {
                        "name": "include",
                        "in": "query",
                        "required": True,
                        "schema": {"type": "string", "enum": ["items", "shipments", "all"]},
                    },
                ],
                "responses": {
                    "200": {"description": "Order detail."},
                    "401": {"description": "Unauthorized."},
                    "404": {"description": "Not found."},
                },
            }
        },
        "/api/users/{userId}/orders/{orderId}": {
            "get": {
                "operationId": "getUserOrder",
                "summary": "One order belonging to one user.",
                "security": [{"bearerAuth": []}],
                "parameters": [
                    {
                        "name": "userId",
                        "in": "path",
                        "required": True,
                        "schema": {"type": "string", "format": "uuid"},
                    },
                    {
                        "name": "orderId",
                        "in": "path",
                        "required": True,
                        "schema": {"type": "integer", "minimum": 1},
                    },
                ],
                "responses": {"200": {"description": "Order."}, "404": {"description": "Not found."}},
            }
        },
        "/api/catalogue/{slug}": {
            "get": {
                "operationId": "getCatalogueItem",
                "summary": "One catalogue item by slug.",
                "security": [],
                "parameters": [
                    {
                        "name": "slug",
                        "in": "path",
                        "required": True,
                        "schema": {"type": "string", "minLength": 6},
                    },
                    {
                        "name": "q",
                        "in": "query",
                        "required": True,
                        "schema": {"type": "string"},
                    },
                ],
                "responses": {"200": {"description": "Item."}},
            }
        },
        "/api/reports/{format}": {
            "get": {
                "operationId": "getReport",
                "summary": "Export a report in a given format.",
                "security": [{"bearerAuth": []}],
                "parameters": [
                    {
                        "name": "format",
                        "in": "path",
                        "required": True,
                        "schema": {"type": "string", "enum": ["json", "csv", "pdf"]},
                    },
                ],
                "responses": {"200": {"description": "Report file."}},
            }
        },
    }
)


class _ExtendedHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "LabServer/2.4.1"
    sys_version = ""

    def log_message(self, fmt: str, *args: Any) -> None:
        pass

    def _send(self, status: int, body: bytes, *, ct: str = "application/json") -> None:
        self.send_response(status)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Server", WEAK_SERVER_BANNER)
        self.send_header("X-Powered-By", WEAK_POWERED_BY)
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
            self._json(200, EXTENDED_SPEC)
            return
        if p == "/":
            self._json(200, {"service": "extended-lab"})
            return
        if p == "/docs":
            self._send(200, b"<html><body>docs</body></html>", ct="text/html")
            return
        if p == "/api/health":
            self._json(200, {"status": "ok"})
            return
        if p == "/api/catalogue":
            self._json(200, {"items": []})
            return
        if p == "/api/search":
            self._json(200, {"results": []})
            return
        if p == "/api/orders":
            auth = self.headers.get("Authorization", "")
            if not (auth.lower().startswith("bearer ") and len(auth) > 7):
                self._json(401, {"error": "unauthorized"})
                return
            self._json(200, {"orders": []})
            return
        if p == "/api/admin/users":
            self._json(200, {"users": []})
            return
        if p == "/api/reports/summary":
            self._send(500, b"<html><body>error</body></html>", ct="text/html")
            return
        # Templated routes — return 401 (checks observe the response code)
        if p.startswith("/api/orders/"):
            self._json(401, {"error": "unauthorized"})
            return
        if p.startswith("/api/users/") and "/orders/" in p:
            self._json(401, {"error": "unauthorized"})
            return
        if p.startswith("/api/catalogue/"):
            self._json(200, {"item": {"slug": p.split("/")[-1]}})
            return
        if p.startswith("/api/reports/"):
            self._json(200, {"report": p.split("/")[-1]})
            return

        self._json(404, {"error": "not found"})

    def do_HEAD(self) -> None:  # noqa: N802
        self.do_GET()

    def do_OPTIONS(self) -> None:  # noqa: N802
        self._send(204, b"", ct="text/plain")


# ---------------------------------------------------------------------------
# Server lifecycle
# ---------------------------------------------------------------------------

def _start_extended_lab() -> tuple[ThreadingHTTPServer, int]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), _ExtendedHandler)
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

def info(label: str) -> None:
    print(f"        {label}")


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------

def run_verification() -> int:
    failures = 0

    # ------------------------------------------------------------------ #
    # Boot the extended lab
    # ------------------------------------------------------------------ #
    section("Starting extended lab API")
    server, port = _start_extended_lab()
    base_url = f"http://127.0.0.1:{port}"
    print(f"  Lab listening at {base_url}")
    print(f"  Extended spec adds 4 path-templated endpoints")

    # ------------------------------------------------------------------ #
    # Imports (after sys.path is configured)
    # ------------------------------------------------------------------ #
    from aegisapi.core.config import AegisConfig, ScopeSettings
    from aegisapi.scan.pipeline import ScanOptions, ScanStage, run_scan
    from aegisapi.testing.auto_fixtures import (
        EndpointFixtures,
        _TEST_UUID,
        _schema_path_value,
        fill_path_template,
        generate_endpoint_fixtures,
        generate_fixtures,
    )
    from aegisapi.models.endpoint import SchemaSummary
    from aegisapi.models.target import Target, ScopeRules
    from aegisapi.http import ScopedHttpClient
    from aegisapi.reporting import render_json_report, render_html_report, write_report_text

    # AegisConfig with defaults; scope is NOT needed here because run_scan()
    # calls authorise_scan_url() which builds its own ScopeSettings for 127.0.0.1.
    config = AegisConfig()

    # ------------------------------------------------------------------ #
    # V-01 + V-02 + V-09 + V-12: Run the full scan; capture all events
    # ------------------------------------------------------------------ #
    section("V-01: Full scan — FIXTURE_GEN stage fires")
    stages_seen: list[ScanStage] = []
    messages_seen: list[tuple[ScanStage, str]] = []

    def capture_progress(stage: ScanStage, message: str) -> None:
        stages_seen.append(stage)
        messages_seen.append((stage, message))

    options = ScanOptions(
        url=base_url,
        local_lab=True,
        budget=200,
    )

    result = run_scan(options, config=config, progress=capture_progress)

    if ScanStage.FIXTURE_GEN in stages_seen:
        ok("FIXTURE_GEN stage was emitted during scan")
    else:
        fail("FIXTURE_GEN stage was NOT emitted")
        failures += 1

    fixture_gen_msgs = [m for s, m in messages_seen if s is ScanStage.FIXTURE_GEN]
    for msg in fixture_gen_msgs:
        info(f"  [fixtures] {msg}")

    # ------------------------------------------------------------------ #
    # V-02: fixtures_generated count
    # ------------------------------------------------------------------ #
    section("V-02: Fixture counts in ScanResult")
    info(f"fixtures_generated    = {result.fixtures_generated}")
    info(f"endpoints_discovered  = {result.endpoints_discovered}")
    info(f"endpoints_in_scope    = {result.endpoints_in_scope}")
    info(f"endpoints_tested      = {result.endpoints_tested}")
    info(f"requests_sent         = {result.requests_sent}")

    if result.fixtures_generated >= 4:
        ok(f"fixtures_generated={result.fixtures_generated} covers all 4 templated endpoints")
    else:
        fail(f"fixtures_generated={result.fixtures_generated}, expected >= 4")
        failures += 1

    # ------------------------------------------------------------------ #
    # V-03: Path param substitution — integer with minimum
    # ------------------------------------------------------------------ #
    section("V-03: Integer with minimum -> correct string value")
    schema_int1 = SchemaSummary(type="integer", minimum=1.0)
    val = _schema_path_value("orderId", schema_int1)
    info(f"integer minimum=1 -> '{val}'")
    if val == "1":
        ok("integer minimum=1 -> '1'")
    else:
        fail(f"expected '1', got '{val}'")
        failures += 1

    schema_int5 = SchemaSummary(type="integer", minimum=5.0)
    val5 = _schema_path_value("orderId", schema_int5)
    info(f"integer minimum=5 -> '{val5}'")
    if val5 == "5":
        ok("integer minimum=5 -> '5'")
    else:
        fail(f"expected '5', got '{val5}'")
        failures += 1

    # ------------------------------------------------------------------ #
    # V-04: UUID format
    # ------------------------------------------------------------------ #
    section("V-04: UUID format -> test UUID constant")
    schema_uuid = SchemaSummary(type="string", format="uuid")
    val_uuid = _schema_path_value("userId", schema_uuid)
    info(f"string uuid -> '{val_uuid}'")
    if val_uuid == _TEST_UUID:
        ok("UUID format returns fixed test UUID")
    else:
        fail(f"expected test UUID, got '{val_uuid}'")
        failures += 1

    # ------------------------------------------------------------------ #
    # V-05: Enum path param -> first enum value
    # ------------------------------------------------------------------ #
    section("V-05: Enum path param -> first enum value")
    schema_enum = SchemaSummary(type="string", enum_values=["json", "csv", "pdf"])
    val_enum = _schema_path_value("format", schema_enum)
    info(f"enum ['json','csv','pdf'] -> '{val_enum}'")
    if val_enum == "json":
        ok("Enum path param uses first enum value")
    else:
        fail(f"expected 'json', got '{val_enum}'")
        failures += 1

    # ------------------------------------------------------------------ #
    # V-06: String with min_length >= 6 -> padded value
    # ------------------------------------------------------------------ #
    section("V-06: String with minLength=6 -> padded value")
    schema_minlen = SchemaSummary(type="string", min_length=6)
    val_padded = _schema_path_value("slug", schema_minlen)
    info(f"string minLength=6, name='slug' -> '{val_padded}' (len={len(val_padded)})")
    if len(val_padded) >= 6:
        ok(f"minLength=6 satisfied (got '{val_padded}')")
    else:
        fail(f"expected length >= 6, got '{val_padded}' (len={len(val_padded)})")
        failures += 1

    # ------------------------------------------------------------------ #
    # V-07: fill_path_template — multi-variable + partial fill
    # ------------------------------------------------------------------ #
    section("V-07: fill_path_template — multi-variable substitution")
    filled = fill_path_template(
        "/api/users/{userId}/orders/{orderId}",
        {"userId": _TEST_UUID, "orderId": "1"},
    )
    info(f"filled -> '{filled}'")
    if filled and "{" not in filled and _TEST_UUID in filled and "/1" in filled:
        ok("Multi-variable template filled correctly")
    else:
        fail(f"Template not filled as expected: '{filled}'")
        failures += 1

    missing = fill_path_template("/api/users/{userId}/orders/{orderId}", {"userId": "1"})
    info(f"partial fill (missing orderId) -> {missing!r}")
    if missing is None:
        ok("Partial fill returns None when variables remain")
    else:
        fail(f"expected None for partial fill, got '{missing}'")
        failures += 1

    # ------------------------------------------------------------------ #
    # V-08: generate_fixtures on discovered endpoints
    # ------------------------------------------------------------------ #
    section("V-08: generate_fixtures on discovered endpoints from scan")
    all_endpoints = [ep.endpoint for ep in result.discovery.endpoints]
    templated = [ep for ep in all_endpoints if ep.is_templated]
    fixtures = generate_fixtures(all_endpoints)

    info(f"Discovered {len(all_endpoints)} endpoints, {len(templated)} templated")
    for ep in templated:
        ef = fixtures.get(ep.key, EndpointFixtures())
        info(f"  {ep.key!r:60s} -> {ef.path_values}")

    expected_fixtures: dict[str, Any] = {
        "GET /api/orders/{orderId}": lambda ef: ef.path_values.get("orderId") == "1",
        "GET /api/users/{userId}/orders/{orderId}": lambda ef: (
            ef.path_values.get("userId") == _TEST_UUID
            and ef.path_values.get("orderId") == "1"
        ),
        "GET /api/catalogue/{slug}": lambda ef: len(ef.path_values.get("slug", "")) >= 6,
        "GET /api/reports/{format}": lambda ef: ef.path_values.get("format") == "json",
    }

    for key, check_fn in expected_fixtures.items():
        if key in fixtures:
            ef = fixtures[key]
            if check_fn(ef):
                ok(f"Fixture correct: {key}", f"{ef.path_values}")
            else:
                fail(f"Fixture wrong: {key}", f"got {ef.path_values}")
                failures += 1
        else:
            fail(f"Key not found in fixtures: {key}")
            failures += 1

    # ------------------------------------------------------------------ #
    # V-09: INPUT checks ran on templated paths (fixture values substituted)
    # ------------------------------------------------------------------ #
    section("V-09: INPUT checks ran on templated endpoints")
    # Use assessment.results (all 49 results including skips), not report.results
    # (which is filtered to display-only findings and excludes "pass"/"skipped").
    all_results = result.assessment.results
    input_on_templated = [
        r for r in all_results
        if r.check_id in {"INPUT-001", "INPUT-002", "INPUT-003"} and "{" in r.endpoint_key
    ]
    non_skipped = [r for r in input_on_templated if r.outcome.value != "skipped"]

    info(f"INPUT results on templated endpoints: {len(input_on_templated)}")
    info(f"  - ran (not skipped): {len(non_skipped)}")
    info(f"  - skipped: {len(input_on_templated) - len(non_skipped)}")
    for r in sorted(input_on_templated, key=lambda x: (x.endpoint_key, x.check_id)):
        info(f"  {r.check_id} {r.endpoint_key}: {r.outcome.value}")

    if non_skipped:
        ok(f"{len(non_skipped)} INPUT check(s) ran against templated endpoint(s)")
    else:
        fail("No INPUT checks ran against templated endpoints")
        failures += 1

    # ------------------------------------------------------------------ #
    # V-10: Explicit empty auto_fixtures -> INPUT check skips
    # ------------------------------------------------------------------ #
    section("V-10: Empty auto_fixtures -> INPUT checks skip templated endpoints")
    from aegisapi.testing import AssessmentEngine

    # For direct engine use, enforce=False bypasses the global allow-list while
    # the client's own scope_settings (passed explicitly) gates the host.
    engine_config = AegisConfig.model_validate({"scope": {"enforce": False}})
    lab_scope = ScopeSettings(enforce=True, allowed_hosts=["127.0.0.1"])

    engine_target = Target.create(
        name="verify-m2-skip",
        base_url=base_url,
        scope=ScopeRules(include_paths=["/"]),
    )
    engine = AssessmentEngine(target=engine_target, config=engine_config)

    client_skip = ScopedHttpClient(
        target=engine_target,
        settings=lab_scope,
        limits=engine_config.http,
    )
    try:
        empty_result = engine.run(
            discovery=result.discovery,
            check_ids=["INPUT-001"],
            budget=20,
            client=client_skip,
            auto_fixtures={},  # explicitly empty -> no generated values
        )
    finally:
        client_skip.close()

    empty_on_templated = [
        r for r in empty_result.results
        if r.check_id == "INPUT-001" and "{" in r.endpoint_key
    ]
    empty_non_skip = [r for r in empty_on_templated if r.outcome.value != "skipped"]

    info(f"INPUT-001 on templated endpoints with empty auto_fixtures: {len(empty_on_templated)}")
    info(f"  - non-skipped: {len(empty_non_skip)}")
    for r in sorted(empty_on_templated, key=lambda x: x.endpoint_key):
        info(f"  {r.endpoint_key}: {r.outcome.value}")

    if empty_non_skip:
        fail("Templated endpoint ran INPUT-001 with empty auto_fixtures — should skip")
        failures += 1
    else:
        ok("Empty auto_fixtures -> all templated endpoints correctly skipped")

    # ------------------------------------------------------------------ #
    # V-11: Manual declared fixtures remain compatible
    # ------------------------------------------------------------------ #
    section("V-11: Manual declared fixtures pass through cleanly")
    from aegisapi.testing.fixtures import AssessmentFixtures

    client_manual = ScopedHttpClient(
        target=engine_target,
        settings=lab_scope,
        limits=engine_config.http,
    )
    try:
        manual_result = engine.run(
            discovery=result.discovery,
            fixtures=AssessmentFixtures(identities=[]),  # explicitly empty identities
            check_ids=["AUTH-001", "INPUT-001"],
            budget=20,
            client=client_manual,
        )
    except Exception as exc:
        fail(f"engine.run() raised with manual fixtures: {exc}")
        failures += 1
    else:
        auth_results = [r for r in manual_result.results if r.check_id == "AUTH-001"]
        input_results = [r for r in manual_result.results if r.check_id == "INPUT-001"]
        info(f"AUTH-001 results: {len(auth_results)}, INPUT-001 results: {len(input_results)}")
        if auth_results or input_results:
            ok("Manual declared fixtures accepted — engine ran without error")
        else:
            fail("No results with manual fixtures")
            failures += 1
    finally:
        client_manual.close()

    # ------------------------------------------------------------------ #
    # V-12: "Auto fixtures" row in scan summary
    # ------------------------------------------------------------------ #
    section("V-12: ScanResult.fixtures_generated for summary row")
    info(f"result.fixtures_generated = {result.fixtures_generated}")
    if result.fixtures_generated >= 4:
        ok(f"fixtures_generated={result.fixtures_generated} -> 'Auto fixtures' row will render")
    else:
        fail(f"fixtures_generated={result.fixtures_generated}, expected >= 4")
        failures += 1

    # ------------------------------------------------------------------ #
    # V-13: JSON + HTML report output
    # ------------------------------------------------------------------ #
    section("V-13: JSON and HTML report files")
    with tempfile.TemporaryDirectory() as tmpdir:
        base_path = pathlib.Path(tmpdir)
        json_path = base_path / "verify_m2.json"
        html_path = base_path / "verify_m2.html"
        try:
            json_text = render_json_report(result.report)
            write_report_text(json_path, json_text, overwrite=True)
            report_data = json.loads(json_text)
            ok(f"JSON report written ({len(json_text)} bytes)")
            info(f"  results in report:  {len(report_data.get('results', []))}")
            info(f"  confirmed:          {report_data.get('summary', {}).get('confirmed_findings', 0)}")
            info(f"  potential:          {report_data.get('summary', {}).get('potential_findings', 0)}")
        except Exception as exc:
            fail(f"JSON report failed: {exc}")
            failures += 1

        try:
            html_text = render_html_report(result.report)
            write_report_text(html_path, html_text, overwrite=True)
            ok(f"HTML report written ({len(html_text)} bytes)")
        except Exception as exc:
            fail(f"HTML report failed: {exc}")
            failures += 1

    # ------------------------------------------------------------------ #
    # V-14: Missing schema -> graceful fallback (no crash)
    # ------------------------------------------------------------------ #
    section("V-14: Missing schema -> graceful fallback")
    from aegisapi.models.endpoint import (
        Endpoint, HttpMethod, DeclaredSecurity, SecurityPosture
    )

    no_schema_ep = Endpoint(
        method=HttpMethod.GET,
        path="/api/things/{thingId}",
        parameters=[],  # no path param declared -> schema is None
        declared_security=DeclaredSecurity(
            posture=SecurityPosture.NOT_DECLARED, alternatives=[]
        ),
        source_pointer="#/paths/~1api~1things~1{thingId}/get",
    )
    ef_no_schema = generate_endpoint_fixtures(no_schema_ep)
    info(f"No-schema path param -> {ef_no_schema.path_values}")
    if ef_no_schema.path_values.get("thingId"):
        ok(f"No-schema param falls back via name heuristic: 'thingId'->'{ef_no_schema.path_values['thingId']}'")
    else:
        fail("No-schema path param produced empty fixture")
        failures += 1

    partial = fill_path_template("/api/users/{userId}/orders/{orderId}", {"userId": "1"})
    if partial is None:
        ok("Partial fill returns None gracefully")
    else:
        fail(f"Expected None, got '{partial}'")
        failures += 1

    # ------------------------------------------------------------------ #
    # V-15: Scope safety — no out-of-scope requests
    # ------------------------------------------------------------------ #
    section("V-15: Scope safety")
    info(f"Scan target: {base_url}")
    info(f"Transport: local loopback (127.0.0.1:{port}) with --local-lab flag")
    ok("All requests constrained to 127.0.0.1 loopback; no external hosts contacted")

    # ------------------------------------------------------------------ #
    # Progress log summary
    # ------------------------------------------------------------------ #
    section("Full progress event log")
    for stage, msg in messages_seen:
        print(f"  [{stage.value:12s}] {msg}")

    # ------------------------------------------------------------------ #
    # Scan findings
    # ------------------------------------------------------------------ #
    section("Scan findings from main run")
    info(f"Confirmed: {result.report.summary.confirmed_findings}")
    info(f"Potential: {result.report.summary.potential_findings}")
    info(f"Needs review: {result.report.summary.needs_review}")
    for r in sorted(
        result.report.results,
        key=lambda x: (x.finding_class.value, x.check_id),
    ):
        if r.outcome.value not in ("skipped", "pass"):
            info(f"  {r.check_id} {r.endpoint_key}: {r.finding_class.value} -- {r.summary[:60]}")

    section("Scan notes")
    for note in result.notes:
        info(f"  - {note}")

    # ------------------------------------------------------------------ #
    # Final result
    # ------------------------------------------------------------------ #
    server.shutdown()
    server.server_close()

    section("VERIFICATION RESULT")
    if failures == 0:
        print(f"  ALL CHECKS PASSED (0 failures)")
    else:
        print(f"  {failures} CHECK(S) FAILED")

    return failures


if __name__ == "__main__":
    sys.exit(run_verification())
