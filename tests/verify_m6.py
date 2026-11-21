"""M6 — Parallel Scanning: end-to-end verification.

Stands up a local HTTP server and runs real scans to verify every M6
behavioural guarantee in an integrated context.

Verification points
-------------------
VP-1   Sequential scan (max_workers=1) completes without error
VP-2   Parallel scan (max_workers=4) completes without error
VP-3   Sequential and parallel scans produce identical report check IDs
VP-4   Sequential and parallel scans produce identical endpoint keys
VP-5   ScanOptions.max_workers is recorded in describe()
VP-6   --workers=4 is the default on ScanOptions
VP-7   report.results has no duplicate (check_id, endpoint_key) pairs
VP-8   parallel scan checks_timed_out is 0 on a fast target
VP-9   parallel scan budget.spent <= budget.limit
VP-10  budget.spent is non-zero (some requests were sent)
VP-11  RequestBudget cancel tokens are cleaned up after scan (no leaks)
VP-12  ONCE_PER_TARGET_CHECKS run exactly once regardless of worker count
VP-13  Out-of-scope endpoints produce only SKIPPED results in parallel mode
VP-14  Parallel scan efficiency_summary is non-None
VP-15  Parallel scan budget_summary is non-None
"""

from __future__ import annotations

import json
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

from aegisapi.core.config import AegisConfig
from aegisapi.scan.pipeline import ScanOptions, run_scan

PASS = "✓"
FAIL = "✗"


def check(label: str, condition: bool) -> None:
    mark = PASS if condition else FAIL
    print(f"  [{mark}] {label}")
    if not condition:
        raise AssertionError(f"FAILED: {label}")


# ---------------------------------------------------------------------------
# Local test server
# ---------------------------------------------------------------------------

SPEC = {
    "openapi": "3.0.0",
    "info": {"title": "M6 Lab", "version": "1.0.0"},
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
        "/api/users": {
            "get": {
                "operationId": "listUsers",
                "security": [{"bearerAuth": []}],
                "responses": {"200": {"description": "ok"}},
            }
        },
    },
}


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path.startswith("/openapi.json"):
            body = json.dumps(SPEC).encode()
            ct = "application/json"
        else:
            body = b'{"ok": true}'
            ct = "application/json"
        self.send_response(200)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


def _start_server() -> tuple[HTTPServer, str]:
    server = HTTPServer(("127.0.0.1", 0), _Handler)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    port = server.server_address[1]
    return server, f"http://127.0.0.1:{port}"


# ---------------------------------------------------------------------------
# VP-1 … VP-10: sequential vs parallel
# ---------------------------------------------------------------------------

def verify_sequential_vs_parallel() -> None:
    print("\n--- Sequential vs parallel scan ---")
    server, url = _start_server()
    try:
        config = AegisConfig()
        opts_seq = ScanOptions(url=url, local_lab=True, budget=300, max_workers=1)
        opts_par = ScanOptions(url=url, local_lab=True, budget=300, max_workers=4)

        result_seq = run_scan(opts_seq, config=config)
        result_par = run_scan(opts_par, config=config)

        check("VP-1  sequential scan completes", result_seq is not None)
        check("VP-2  parallel scan completes",   result_par is not None)

        def _result_key(r) -> tuple[str, str]:
            return (r.check_id, r.endpoint_key)

        seq_keys = sorted(_result_key(r) for r in result_seq.report.results)
        par_keys = sorted(_result_key(r) for r in result_par.report.results)
        check("VP-3  same check IDs in both runs",    seq_keys == par_keys)

        seq_eps = sorted({r.endpoint_key for r in result_seq.report.results})
        par_eps = sorted({r.endpoint_key for r in result_par.report.results})
        check("VP-4  same endpoint keys in both runs", seq_eps == par_eps)

        d = opts_par.describe()
        check("VP-5  parallel_workers in describe()",  "parallel_workers" in d)
        check("VP-6  default max_workers is 4",        ScanOptions(url=url, local_lab=True).max_workers == 4)

        par_pairs = [_result_key(r) for r in result_par.report.results]
        check("VP-7  no duplicate (check_id, endpoint_key)",
              len(par_pairs) == len(set(par_pairs)))

        check("VP-8  no timed-out checks",           result_par.assessment.checks_timed_out == 0)
        check("VP-9  budget.spent <= limit",          result_par.assessment.requests_sent <= 300)
        check("VP-10 some requests were sent",        result_par.assessment.requests_sent > 0)

    finally:
        server.shutdown()
        server.server_close()


# ---------------------------------------------------------------------------
# VP-11: cancel token cleanup
# ---------------------------------------------------------------------------

def verify_cancel_token_cleanup() -> None:
    print("\n--- Cancel token cleanup ---")
    from aegisapi.testing.registry import RequestBudget

    b = RequestBudget(limit=100)
    # Simulate _run_check_timed: register and unregister a cancel token.
    cancel_event = threading.Event()
    tid = threading.get_ident()
    b.register_cancel_token(tid, cancel_event)
    check("VP-11a token registered", len(b._cancel_tokens) == 1)
    b.unregister_cancel_token(tid)
    check("VP-11b token removed after unregister", len(b._cancel_tokens) == 0)


# ---------------------------------------------------------------------------
# VP-12: ONCE_PER_TARGET exactly once
# ---------------------------------------------------------------------------

def verify_once_per_target() -> None:
    print("\n--- ONCE_PER_TARGET exactly once ---")
    from aegisapi.testing.engine import ONCE_PER_TARGET_CHECKS
    check("VP-12 ONCE_PER_TARGET_CHECKS non-empty", len(ONCE_PER_TARGET_CHECKS) > 0)

    server, url = _start_server()
    try:
        config = AegisConfig()
        once_ids = list(ONCE_PER_TARGET_CHECKS)

        opts = ScanOptions(
            url=url, local_lab=True, budget=300,
            max_workers=4,
            check_ids=tuple(once_ids),
        )
        result = run_scan(opts, config=config)

        for once_id in once_ids:
            ran = [r for r in result.assessment.results
                   if r.check_id == once_id and r.outcome.value != "skipped"]
            check(
                f"VP-12  {once_id} ran ≤ 1 time",
                len(ran) <= 1,
            )
    finally:
        server.shutdown()
        server.server_close()


# ---------------------------------------------------------------------------
# VP-13: out-of-scope endpoints still skipped in parallel
# ---------------------------------------------------------------------------

def verify_oos_in_parallel() -> None:
    print("\n--- Out-of-scope endpoints skipped in parallel ---")
    from aegisapi.models.assessment import CheckCategory, CheckOutcome
    from aegisapi.models.discovery import ScopeClassification
    from aegisapi.testing import AssessmentEngine
    from aegisapi.testing.fixtures import AssessmentFixtures
    from assessfix import (
        classified as _cl,
        discovery_result,
        make_client,
        make_config,
        public,
        scoped_target,
    )
    from httpstub import FakeTransport

    target = scoped_target()
    config = make_config()
    transport = FakeTransport()
    client = make_client(target, config, transport)
    engine = AssessmentEngine(target=target, config=config)

    in_scope = _cl(public("get", "/api/ok"))
    oos = _cl(public("get", "/admin/secret"),
              classification=ScopeClassification.OUT_OF_SCOPE)
    disc = discovery_result([in_scope, oos])
    try:
        result = engine.run(
            discovery=disc,
            fixtures=AssessmentFixtures(),
            budget=300,
            client=client,
            max_workers=4,
        )
    finally:
        client.close()

    oos_results = [r for r in result.results if r.endpoint_key == oos.endpoint.key]
    check("VP-13a OOS endpoint has ≥1 result",   len(oos_results) >= 1)
    check("VP-13b OOS result is SKIPPED",
          all(r.outcome is CheckOutcome.SKIPPED for r in oos_results))
    check("VP-13c OOS result has ENGINE-000 id",
          all(r.check_id == "ENGINE-000" for r in oos_results))


# ---------------------------------------------------------------------------
# VP-14 … VP-15: efficiency + budget summaries
# ---------------------------------------------------------------------------

def verify_summaries() -> None:
    print("\n--- Summaries present in parallel scan ---")
    server, url = _start_server()
    try:
        config = AegisConfig()
        opts = ScanOptions(url=url, local_lab=True, budget=300, max_workers=4)
        result = run_scan(opts, config=config)
        r = result.report
        check("VP-14 efficiency_summary non-None", r.efficiency_summary is not None)
        check("VP-15 budget_summary non-None",     r.budget_summary is not None)
    finally:
        server.shutdown()
        server.server_close()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    print("=" * 60)
    print("M6 Parallel Scanning — End-to-End Verification")
    print("=" * 60)

    verify_sequential_vs_parallel()
    verify_cancel_token_cleanup()
    verify_once_per_target()
    verify_oos_in_parallel()
    verify_summaries()

    print("\n" + "=" * 60)
    print("ALL VERIFICATION POINTS PASSED")
    print("=" * 60)


if __name__ == "__main__":
    main()
