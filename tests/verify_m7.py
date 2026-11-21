"""M7 — SARIF Reporting: end-to-end verification.

Stands up a local HTTP server, runs real scans, and verifies the SARIF output
at every level: schema structure, finding mapping, security invariants, CLI
integration, and GitHub Code Scanning compatibility.

Verification points
-------------------
VP-1   SARIF $schema URI is present and correct
VP-2   SARIF version is "2.1.0"
VP-3   runs[0].tool.driver.name is "AegisAPI"
VP-4   runs[0].tool.driver.version matches __version__
VP-5   ReportFormat.SARIF is in SUPPORTED_FORMATS
VP-6   suffix_for(ReportFormat.SARIF) returns "sarif"
VP-7   render(report, ReportFormat.SARIF) returns valid JSON
VP-8   ScanFormat.SARIF exists in the CLI enum
VP-9   _scan_report_paths with ScanFormat.SARIF yields one .sarif path
VP-10  SARIF output from a real scan contains no body excerpts
VP-11  SARIF output from a real scan contains no Authorization header strings
VP-12  SARIF output passes json.loads without error
VP-13  Every result in SARIF has a fingerprint under "aegisapi/v1"
VP-14  Every result fingerprint equals CheckResult.result_id for that result
VP-15  OWASP CWE mapping covers all 10 categories
VP-16  Render via formats.render() dispatcher produces the same output as direct call
VP-17  Empty report (no findings) produces valid SARIF with empty results array
VP-18  SARIF output from a scan with --format sarif writes a .sarif file on disk
"""

from __future__ import annotations

import json
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from aegisapi import __version__
from aegisapi.models.assessment import (
    CheckCategory,
    CheckOutcome,
    CheckResult,
    FindingClass,
    OwaspApiCategory,
)
from aegisapi.models.common import Confidence, ReportFormat, Severity
from aegisapi.models.report import Report
from aegisapi.reporting.formats import SUPPORTED_FORMATS, render, suffix_for
from aegisapi.reporting.sarif_report import _OWASP_CWE, render_sarif_report

PASS = "✓"
FAIL = "✗"

_SCHEMA_URI = "https://json.schemastore.org/sarif-2.1.0.json"


def check(label: str, condition: bool) -> None:
    mark = PASS if condition else FAIL
    print(f"  [{mark}] {label}")
    if not condition:
        raise AssertionError(f"FAILED: {label}")


# ---------------------------------------------------------------------------
# Minimal local HTTP server
# ---------------------------------------------------------------------------

SPEC = {
    "openapi": "3.0.0",
    "info": {"title": "M7 Lab", "version": "1.0.0"},
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
# Helpers to build report objects in-process
# ---------------------------------------------------------------------------

def _make_finding(
    *,
    check_id: str = "AUTH-001",
    endpoint_key: str = "GET /api/items",
    severity: Severity = Severity.HIGH,
    owasp: OwaspApiCategory | None = OwaspApiCategory.API2_BROKEN_AUTHENTICATION,
    finding_class: FindingClass = FindingClass.CONFIRMED,
) -> CheckResult:
    return CheckResult(
        check_id=check_id,
        check_name="Check " + check_id,
        category=CheckCategory.AUTHENTICATION,
        target_name="verify-target",
        endpoint_key=endpoint_key,
        url=f"http://127.0.0.1:9999{endpoint_key.split(' ', 1)[1]}",
        outcome=CheckOutcome.FAIL,
        finding_class=finding_class,
        severity=severity,
        confidence=Confidence.HIGH,
        owasp=owasp,
        summary="Authentication was not enforced.",
        explanation="A request without credentials received HTTP 200.",
    )


def _make_report(findings: list[CheckResult] | None = None) -> Report:
    return Report(
        aegisapi_version=__version__,
        target_name="verify-target",
        target_base_url="http://127.0.0.1:9999",
        source_assessment_schema=1,
        results=findings or [],
    )


# ---------------------------------------------------------------------------
# VP-1 … VP-9: schema + format integration
# ---------------------------------------------------------------------------

def verify_schema_and_format() -> None:
    print("\n--- Schema and format integration ---")

    report = _make_report([_make_finding()])
    text = render_sarif_report(report)
    doc = json.loads(text)
    run = doc["runs"][0]

    check("VP-1  $schema URI present and correct", doc.get("$schema") == _SCHEMA_URI)
    check("VP-2  version is 2.1.0",                doc.get("version") == "2.1.0")
    check("VP-3  driver.name is AegisAPI",          run["tool"]["driver"]["name"] == "AegisAPI")
    check("VP-4  driver.version matches __version__", run["tool"]["driver"]["version"] == __version__)
    check("VP-5  ReportFormat.SARIF in SUPPORTED_FORMATS", ReportFormat.SARIF in SUPPORTED_FORMATS)
    check("VP-6  suffix_for(SARIF) returns 'sarif'", suffix_for(ReportFormat.SARIF) == "sarif")
    check("VP-7  render() returns valid JSON",       json.loads(render(report, ReportFormat.SARIF)) is not None)

    from aegisapi.cli import ScanFormat
    check("VP-8  ScanFormat.SARIF exists",           ScanFormat.SARIF == "sarif")

    from aegisapi.cli import _scan_report_paths
    pairs = _scan_report_paths(Path("out/report"), ScanFormat.SARIF)
    check(
        "VP-9  _scan_report_paths(SARIF) → one .sarif path",
        len(pairs) == 1 and pairs[0][1] is ReportFormat.SARIF and pairs[0][0].suffix == ".sarif",
    )


# ---------------------------------------------------------------------------
# VP-10 … VP-12: security invariants from a real scan
# ---------------------------------------------------------------------------

def verify_security_invariants() -> None:
    print("\n--- Security invariants ---")

    from aegisapi.core.config import AegisConfig
    from aegisapi.scan.pipeline import ScanOptions, run_scan

    server, url = _start_server()
    try:
        config = AegisConfig()
        opts = ScanOptions(url=url, local_lab=True, budget=200)
        result = run_scan(opts, config=config)
        text = render_sarif_report(result.report)

        check("VP-10 no body_excerpt key in SARIF",    "body_excerpt" not in text)
        check("VP-11 no Authorization header string",  "Authorization:" not in text)
        check("VP-12 output is valid JSON",             json.loads(text) is not None)
    finally:
        server.shutdown()
        server.server_close()


# ---------------------------------------------------------------------------
# VP-13 … VP-14: fingerprints
# ---------------------------------------------------------------------------

def verify_fingerprints() -> None:
    print("\n--- Fingerprints ---")

    r1 = _make_finding(check_id="AUTH-001", endpoint_key="GET /api/items")
    r2 = _make_finding(check_id="AUTH-002", endpoint_key="GET /api/health")
    doc = json.loads(render_sarif_report(_make_report([r1, r2])))
    sarif_results = doc["runs"][0]["results"]

    check(
        "VP-13 every SARIF result has fingerprints.aegisapi/v1",
        all("aegisapi/v1" in sr["fingerprints"] for sr in sarif_results),
    )

    fp_map = {sr["ruleId"]: sr["fingerprints"]["aegisapi/v1"] for sr in sarif_results}
    check(
        "VP-14 fingerprints match CheckResult.result_id",
        fp_map["AUTH-001"] == r1.result_id and fp_map["AUTH-002"] == r2.result_id,
    )


# ---------------------------------------------------------------------------
# VP-15: OWASP CWE mapping
# ---------------------------------------------------------------------------

def verify_owasp_cwe() -> None:
    print("\n--- OWASP CWE mapping ---")
    all_covered = all(cat in _OWASP_CWE for cat in OwaspApiCategory)
    check("VP-15 all 10 OWASP categories have a CWE mapping", all_covered)


# ---------------------------------------------------------------------------
# VP-16: render() dispatcher
# ---------------------------------------------------------------------------

def verify_render_dispatcher() -> None:
    print("\n--- formats.render() dispatcher ---")

    report = _make_report([_make_finding()])
    direct = render_sarif_report(report)
    via_dispatcher = render(report, ReportFormat.SARIF)
    check("VP-16 dispatcher produces same output as direct call", direct == via_dispatcher)


# ---------------------------------------------------------------------------
# VP-17: empty report
# ---------------------------------------------------------------------------

def verify_empty_report() -> None:
    print("\n--- Empty report ---")

    doc = json.loads(render_sarif_report(_make_report([])))
    check("VP-17 empty findings → empty SARIF results array",
          doc["runs"][0]["results"] == [])


# ---------------------------------------------------------------------------
# VP-18: scan --format sarif writes .sarif on disk
# ---------------------------------------------------------------------------

def verify_scan_writes_sarif_file() -> None:
    print("\n--- Scan writes .sarif file ---")

    from aegisapi.core.config import AegisConfig
    from aegisapi.scan.pipeline import ScanOptions, run_scan

    server, url = _start_server()
    try:
        config = AegisConfig()
        opts = ScanOptions(url=url, local_lab=True, budget=200)
        result = run_scan(opts, config=config)

        with tempfile.TemporaryDirectory() as tmpdir:
            out = Path(tmpdir) / "scan_report"
            from aegisapi.cli import ScanFormat, _write_scan_reports
            _write_scan_reports(result, output=out, report_format=ScanFormat.SARIF, overwrite=True)
            sarif_path = out.with_suffix(".sarif")
            check("VP-18 .sarif file was written", sarif_path.exists())
            if sarif_path.exists():
                doc = json.loads(sarif_path.read_text())
                check("VP-18 .sarif file contains valid SARIF", doc.get("version") == "2.1.0")
    finally:
        server.shutdown()
        server.server_close()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    print("=" * 60)
    print("M7 SARIF Reporting — End-to-End Verification")
    print("=" * 60)

    verify_schema_and_format()
    verify_security_invariants()
    verify_fingerprints()
    verify_owasp_cwe()
    verify_render_dispatcher()
    verify_empty_report()
    verify_scan_writes_sarif_file()

    print("\n" + "=" * 60)
    print("ALL VERIFICATION POINTS PASSED")
    print("=" * 60)


if __name__ == "__main__":
    main()
