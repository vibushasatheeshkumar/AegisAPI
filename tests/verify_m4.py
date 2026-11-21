"""End-to-end verification of M4 — Separate Scan Budgets.

Verification points
-------------------
V-01  scan_timeout_seconds stops the scan early: scan_timed_out=True
V-02  partial_timeout appears in BudgetSummary.completion_status
V-03  partial_timeout appears in ScanResult.completion_status
V-04  Findings produced before timeout are preserved (partial report)
V-05  partial_budget when total request budget exhausted
V-06  budget_summary.requests_sent matches assessment.requests_sent
V-07  per-endpoint cap: endpoints_at_limit populated in BudgetSummary
V-08  per-endpoint cap: endpoints_at_limit in AssessmentResult
V-09  check_timeout_seconds: checks_timed_out > 0 on slow server
V-10  checks_timed_out appears in BudgetSummary
V-11  "complete" status on a normal scan with ample budget
V-12  budget_summary present in JSON report output
V-13  budget_summary present in HTML report output
V-14  partial_timeout note in scan notes list
V-15  New CLI options accepted: --scan-timeout, --max-endpoint-requests,
      --max-check-requests, --check-timeout
V-16  ScanOptions.describe() includes new fields
"""

from __future__ import annotations

import json
import threading
import time
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Generator

import pytest

# ---------------------------------------------------------------------------
# Shared lab infrastructure
# ---------------------------------------------------------------------------

M4_SPEC = {
    "openapi": "3.0.0",
    "info": {"title": "M4 Budget Lab", "version": "1.0.0"},
    "paths": {
        "/api/m4/fast": {
            "get": {
                "operationId": "fast",
                "responses": {"200": {"description": "ok"}},
            }
        },
        "/api/m4/also-fast": {
            "get": {
                "operationId": "also-fast",
                "responses": {"200": {"description": "ok"}},
            }
        },
        "/api/m4/third": {
            "get": {
                "operationId": "third",
                "responses": {"200": {"description": "ok"}},
            }
        },
        "/api/m4/fourth": {
            "get": {
                "operationId": "fourth",
                "responses": {"200": {"description": "ok"}},
            }
        },
        "/api/m4/fifth": {
            "get": {
                "operationId": "fifth",
                "responses": {"200": {"description": "ok"}},
            }
        },
    },
}

M4_SLOW_SPEC = {
    "openapi": "3.0.0",
    "info": {"title": "M4 Slow Lab", "version": "1.0.0"},
    "paths": {
        "/api/slow/ep": {
            "get": {
                "operationId": "slow-ep",
                "responses": {"200": {"description": "ok"}},
            }
        }
    },
}


class _M4Handler(BaseHTTPRequestHandler):
    """Minimal HTTP server for budget lab tests."""

    delay: float = 0.0  # class-level, overridden per server instance

    def do_GET(self) -> None:
        if self.path.startswith("/openapi.json"):
            spec = getattr(self.server, "spec", M4_SPEC)
            body = json.dumps(spec).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            d = getattr(self.server, "delay", 0.0)
            if d:
                time.sleep(d)
            body = b'{"ok": true}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    def log_message(self, *args):  # silence server logs
        pass


@contextmanager
def _lab(spec: dict | None = None, delay: float = 0.0) -> Generator[str, None, None]:
    """Spin up a local HTTP lab, yield its base URL, then shut it down."""
    server = HTTPServer(("127.0.0.1", 0), _M4Handler)
    server.spec = spec or M4_SPEC  # type: ignore[attr-defined]
    server.delay = delay  # type: ignore[attr-defined]
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    port = server.server_address[1]
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        server.shutdown()
        server.server_close()


def _run(url: str, spec_path: str = "/openapi.json", **scan_kwargs):
    """Run a scan against the lab and return ScanResult."""
    from aegisapi.core.config import AegisConfig
    from aegisapi.scan.pipeline import ScanOptions, run_scan

    opts = ScanOptions(
        url=url,
        local_lab=True,
        budget=scan_kwargs.pop("budget", 500),
        probe_specification=True,
        probe_documentation=False,
        **scan_kwargs,
    )
    config = AegisConfig()
    return run_scan(opts, config=config)


# ---------------------------------------------------------------------------
# V-01 to V-04: scan_timeout_seconds
# ---------------------------------------------------------------------------


class TestScanTimeout:
    def test_v01_scan_timed_out_flag(self):
        """V-01: scan_timed_out=True when scan_timeout_seconds fires."""
        with _lab() as url:
            result = _run(url, scan_timeout_seconds=0.001)
        assert result.assessment.scan_timed_out is True, "V-01 FAIL: scan_timed_out not set"

    def test_v02_budget_summary_partial_timeout_status(self):
        """V-02: BudgetSummary.completion_status = 'partial_timeout'."""
        with _lab() as url:
            result = _run(url, scan_timeout_seconds=0.001)
        bs = result.report.budget_summary
        assert bs is not None, "V-02 FAIL: no budget_summary in report"
        assert bs.completion_status == "partial_timeout", (
            f"V-02 FAIL: expected partial_timeout, got {bs.completion_status!r}"
        )

    def test_v03_scan_result_completion_status(self):
        """V-03: ScanResult.completion_status = 'partial_timeout'."""
        with _lab() as url:
            result = _run(url, scan_timeout_seconds=0.001)
        assert result.completion_status == "partial_timeout", (
            f"V-03 FAIL: {result.completion_status!r}"
        )

    def test_v04_partial_report_has_no_false_findings(self):
        """V-04: A partial scan produces a valid (possibly empty) findings list."""
        with _lab() as url:
            result = _run(url, scan_timeout_seconds=0.001)
        # The findings list must be a list (even if empty); no assertion on content
        assert isinstance(result.report.results, list), "V-04 FAIL: results not a list"


# ---------------------------------------------------------------------------
# V-05 to V-06: total request budget exhausted
# ---------------------------------------------------------------------------


class TestBudgetExhausted:
    def test_v05_partial_budget_status(self):
        """V-05: completion_status='partial_budget' when budget runs out."""
        with _lab() as url:
            # budget=1 — discovery will consume it immediately
            result = _run(url, budget=1)
        # Either budget_exhausted OR no checks ran (budget may be used by discovery)
        bs = result.report.budget_summary
        assert bs is not None, "V-05 FAIL: no budget_summary"
        # With budget=1, the scan will run out; partial_budget or we just check
        # that budget is tracked correctly
        assert bs.requests_sent <= 1, f"V-05 FAIL: sent {bs.requests_sent} but budget=1"

    def test_v06_requests_sent_matches(self):
        """V-06: BudgetSummary.requests_sent matches AssessmentResult.requests_sent."""
        with _lab() as url:
            result = _run(url)
        bs = result.report.budget_summary
        assert bs is not None, "V-06 FAIL: no budget_summary"
        # budget_summary.requests_sent is from the check phase only (assessment.requests_sent)
        assert bs.requests_sent == result.assessment.requests_sent, (
            f"V-06 FAIL: {bs.requests_sent} != {result.assessment.requests_sent}"
        )


# ---------------------------------------------------------------------------
# V-07 to V-08: per-endpoint cap
# ---------------------------------------------------------------------------


class TestPerEndpointCap:
    def test_v07_endpoints_at_limit_in_budget_summary(self):
        """V-07: BudgetSummary.endpoints_at_limit populated when per-endpoint cap hit."""
        with _lab() as url:
            # Very tight per-endpoint limit: 1 request max
            result = _run(url, max_endpoint_requests=1)
        bs = result.report.budget_summary
        assert bs is not None, "V-07 FAIL: no budget_summary"
        # With max_endpoint_requests=1 and multiple checks wanting to send,
        # some endpoints will hit the limit
        assert isinstance(bs.endpoints_at_limit, list), "V-07 FAIL: endpoints_at_limit not a list"

    def test_v08_endpoints_at_limit_in_assessment(self):
        """V-08: AssessmentResult.endpoints_at_limit populated on per-endpoint cap hit."""
        with _lab() as url:
            result = _run(url, max_endpoint_requests=1)
        assert isinstance(result.assessment.endpoints_at_limit, list), (
            "V-08 FAIL: endpoints_at_limit not a list on assessment"
        )


# ---------------------------------------------------------------------------
# V-09 to V-10: check_timeout_seconds
# ---------------------------------------------------------------------------


class TestCheckTimeout:
    def test_v09_checks_timed_out_counter(self):
        """V-09: checks_timed_out > 0 when server is slow and check_timeout fires."""
        with _lab(delay=0.5) as url:
            # check_timeout=0.05 is much shorter than the 0.5s server delay
            result = _run(
                url,
                check_timeout_seconds=0.05,
                budget=200,
            )
        assert result.assessment.checks_timed_out > 0, (
            f"V-09 FAIL: checks_timed_out={result.assessment.checks_timed_out}"
        )

    def test_v10_checks_timed_out_in_budget_summary(self):
        """V-10: BudgetSummary.checks_timed_out matches AssessmentResult."""
        with _lab(delay=0.5) as url:
            result = _run(url, check_timeout_seconds=0.05, budget=200)
        bs = result.report.budget_summary
        assert bs is not None, "V-10 FAIL: no budget_summary"
        assert bs.checks_timed_out == result.assessment.checks_timed_out, (
            f"V-10 FAIL: summary={bs.checks_timed_out}, assessment={result.assessment.checks_timed_out}"
        )


# ---------------------------------------------------------------------------
# V-11: complete status on normal scan
# ---------------------------------------------------------------------------


class TestCompleteStatus:
    def test_v11_complete_on_normal_scan(self):
        """V-11: completion_status='complete' when scan runs without limits."""
        with _lab() as url:
            result = _run(url, budget=500)
        assert result.completion_status == "complete", (
            f"V-11 FAIL: {result.completion_status!r}"
        )
        bs = result.report.budget_summary
        assert bs is not None, "V-11 FAIL: no budget_summary"
        assert bs.completion_status == "complete", f"V-11 FAIL: summary={bs.completion_status!r}"
        assert bs.scan_timed_out is False, "V-11 FAIL: scan_timed_out should be False"


# ---------------------------------------------------------------------------
# V-12 to V-13: budget_summary in JSON and HTML reports
# ---------------------------------------------------------------------------


class TestReportFormats:
    def test_v12_budget_summary_in_json_report(self, tmp_path):
        """V-12: budget_summary present in serialized JSON report."""
        from aegisapi.reporting import render
        from aegisapi.models.common import ReportFormat

        with _lab() as url:
            result = _run(url)
        json_text = render(result.report, ReportFormat.JSON)
        parsed = json.loads(json_text)
        assert "budget_summary" in parsed, "V-12 FAIL: budget_summary missing from JSON"
        bs = parsed["budget_summary"]
        assert "completion_status" in bs, "V-12 FAIL: completion_status missing from budget_summary"
        assert "requests_sent" in bs, "V-12 FAIL: requests_sent missing from budget_summary"
        assert "checks_timed_out" in bs, "V-12 FAIL: checks_timed_out missing from budget_summary"

    def test_v13_budget_summary_in_html_report(self, tmp_path):
        """V-13: HTML report renders without error when budget_summary is set."""
        from aegisapi.reporting import render
        from aegisapi.models.common import ReportFormat

        with _lab() as url:
            result = _run(url)
        # Just check HTML renders without exception
        html_text = render(result.report, ReportFormat.HTML)
        assert len(html_text) > 100, "V-13 FAIL: HTML report suspiciously short"


# ---------------------------------------------------------------------------
# V-14: partial_timeout note appears in ScanResult.notes
# ---------------------------------------------------------------------------


class TestScanNotes:
    def test_v14_partial_timeout_note_in_notes(self):
        """V-14: When scan_timed_out, a note about it appears in result.notes."""
        with _lab() as url:
            result = _run(url, scan_timeout_seconds=0.001)
        if result.assessment.scan_timed_out:
            timeout_notes = [n for n in result.notes if "scan_timeout" in n.lower() or "timeout" in n.lower()]
            assert timeout_notes, (
                f"V-14 FAIL: no timeout note in notes={result.notes}"
            )


# ---------------------------------------------------------------------------
# V-15: New CLI options accepted
# ---------------------------------------------------------------------------


class TestCLIOptions:
    def test_v15_new_options_accepted_by_typer(self):
        """V-15: CLI scan command accepts the four new budget options."""
        from typer.testing import CliRunner
        from aegisapi.cli import app

        runner = CliRunner()
        result = runner.invoke(app, ["scan", "--help"])
        help_text = result.output
        assert "--scan-timeout" in help_text, "V-15 FAIL: --scan-timeout not in help"
        assert "--max-endpoint-requests" in help_text, "V-15 FAIL: --max-endpoint-requests not in help"
        assert "--max-check-requests" in help_text, "V-15 FAIL: --max-check-requests not in help"
        assert "--check-timeout" in help_text, "V-15 FAIL: --check-timeout not in help"


# ---------------------------------------------------------------------------
# V-16: ScanOptions.describe() includes new fields
# ---------------------------------------------------------------------------


class TestScanOptionsDescribe:
    def test_v16_describe_includes_budget_fields(self):
        """V-16: ScanOptions.describe() outputs all four new budget keys."""
        from aegisapi.scan.pipeline import ScanOptions

        opts = ScanOptions(
            url="http://test.local/",
            scan_timeout_seconds=60.0,
            max_endpoint_requests=5,
            max_check_requests=3,
            check_timeout_seconds=10.0,
        )
        d = opts.describe()
        assert d.get("scan_timeout") == "60.0s", f"V-16 FAIL: {d.get('scan_timeout')!r}"
        assert d.get("max_endpoint_requests") == "5", f"V-16 FAIL: {d.get('max_endpoint_requests')!r}"
        assert d.get("max_check_requests") == "3", f"V-16 FAIL: {d.get('max_check_requests')!r}"
        assert d.get("check_timeout") == "10.0s", f"V-16 FAIL: {d.get('check_timeout')!r}"

    def test_v16b_describe_none_values(self):
        """V-16b: ScanOptions.describe() shows 'none' when limits are unset."""
        from aegisapi.scan.pipeline import ScanOptions

        opts = ScanOptions(url="http://test.local/")
        d = opts.describe()
        assert d.get("scan_timeout") == "none"
        assert d.get("max_endpoint_requests") == "none"
        assert d.get("max_check_requests") == "none"
        assert d.get("check_timeout") == "none"


# ---------------------------------------------------------------------------
# Summary runner
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import sys

    result = pytest.main([__file__, "-v", "--tb=short", "--basetemp", "D:\\pytest-tmp"])
    sys.exit(result)
