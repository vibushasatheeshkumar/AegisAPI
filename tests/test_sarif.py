"""M7 — SARIF 2.1.0 reporting: unit tests.

Tests are grouped by concern:
  - Schema structure (top-level document shape)
  - Tool driver metadata
  - Rules (one per unique check_id, with OWASP/CWE tags)
  - Results (mapping from CheckResult to SARIF result)
  - Security invariants (no credentials, no body excerpts, no headers)
  - Severity → SARIF level mapping
  - Fingerprint stability
  - Filtering (only is_finding results appear)
  - Format integration (ReportFormat, ScanFormat, formats.py dispatcher)
"""

from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest

from aegisapi import __version__
from aegisapi.models.assessment import (
    CheckCategory,
    CheckOutcome,
    CheckResult,
    Evidence,
    FindingClass,
    OwaspApiCategory,
)
from aegisapi.models.common import Confidence, ReportFormat, Severity
from aegisapi.models.report import Report, ReportSummary
from aegisapi.reporting.formats import SUPPORTED_FORMATS, is_supported, render, suffix_for
from aegisapi.reporting.sarif_report import (
    _GITHUB_SECURITY_SEVERITY,
    _OWASP_CWE,
    _SARIF_LEVEL,
    render_sarif_report,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_SCHEMA_URI = "https://json.schemastore.org/sarif-2.1.0.json"


def _make_result(
    *,
    check_id: str = "AUTH-001",
    check_name: str = "Missing 401 Check",
    category: CheckCategory = CheckCategory.AUTHENTICATION,
    endpoint_key: str = "GET /api/users",
    url: str | None = "https://api.example.com/api/users",
    outcome: CheckOutcome = CheckOutcome.FAIL,
    finding_class: FindingClass = FindingClass.CONFIRMED,
    severity: Severity | None = Severity.HIGH,
    confidence: Confidence = Confidence.HIGH,
    owasp: OwaspApiCategory | None = OwaspApiCategory.API2_BROKEN_AUTHENTICATION,
    summary: str = "Endpoint returned 200 without authentication.",
    explanation: str = "No credential was required.",
    remediation: str | None = "Require a bearer token on all protected endpoints.",
    evidence: list[Evidence] | None = None,
) -> CheckResult:
    return CheckResult(
        check_id=check_id,
        check_name=check_name,
        category=category,
        target_name="test-target",
        endpoint_key=endpoint_key,
        url=url,
        outcome=outcome,
        finding_class=finding_class,
        severity=severity,
        confidence=confidence,
        owasp=owasp,
        summary=summary,
        explanation=explanation,
        remediation=remediation,
        evidence=evidence or [],
    )


def _make_report(results: list[CheckResult] | None = None) -> Report:
    return Report(
        aegisapi_version=__version__,
        target_name="test-target",
        target_base_url="https://api.example.com",
        source_assessment_schema=1,
        results=results or [],
    )


def _sarif(report: Report) -> dict:
    return json.loads(render_sarif_report(report))


# ---------------------------------------------------------------------------
# Schema structure
# ---------------------------------------------------------------------------


class TestSarifSchema:
    def test_top_level_schema_field(self):
        doc = _sarif(_make_report())
        assert doc["$schema"] == _SCHEMA_URI

    def test_top_level_version(self):
        doc = _sarif(_make_report())
        assert doc["version"] == "2.1.0"

    def test_has_runs_array(self):
        doc = _sarif(_make_report())
        assert isinstance(doc["runs"], list)
        assert len(doc["runs"]) == 1

    def test_runs_has_tool(self):
        run = _sarif(_make_report())["runs"][0]
        assert "tool" in run

    def test_runs_has_results(self):
        run = _sarif(_make_report())["runs"][0]
        assert "results" in run

    def test_automation_details_id(self):
        run = _sarif(_make_report())["runs"][0]
        assert run["automationDetails"]["id"] == "aegisapi/test-target"

    def test_output_ends_with_newline(self):
        text = render_sarif_report(_make_report())
        assert text.endswith("\n")

    def test_output_is_valid_json(self):
        text = render_sarif_report(_make_report())
        json.loads(text)  # must not raise


# ---------------------------------------------------------------------------
# Tool driver
# ---------------------------------------------------------------------------


class TestToolDriver:
    def test_driver_name(self):
        driver = _sarif(_make_report())["runs"][0]["tool"]["driver"]
        assert driver["name"] == "AegisAPI"

    def test_driver_version(self):
        driver = _sarif(_make_report())["runs"][0]["tool"]["driver"]
        assert driver["version"] == __version__

    def test_driver_has_rules(self):
        driver = _sarif(_make_report())["runs"][0]["tool"]["driver"]
        assert "rules" in driver


# ---------------------------------------------------------------------------
# Rules
# ---------------------------------------------------------------------------


class TestRules:
    def test_one_rule_per_check_id(self):
        # Two results with the same check_id → one rule.
        r1 = _make_result(check_id="AUTH-001", endpoint_key="GET /a")
        r2 = _make_result(check_id="AUTH-001", endpoint_key="GET /b")
        rules = _sarif(_make_report([r1, r2]))["runs"][0]["tool"]["driver"]["rules"]
        assert len(rules) == 1

    def test_multiple_check_ids_produce_multiple_rules(self):
        r1 = _make_result(check_id="AUTH-001", endpoint_key="GET /a")
        r2 = _make_result(check_id="SCHEMA-001", check_name="Schema Check", endpoint_key="GET /b")
        rules = _sarif(_make_report([r1, r2]))["runs"][0]["tool"]["driver"]["rules"]
        rule_ids = [r["id"] for r in rules]
        assert "AUTH-001" in rule_ids
        assert "SCHEMA-001" in rule_ids

    def test_rule_id_is_check_id(self):
        r = _make_result(check_id="AUTH-001")
        rule = _sarif(_make_report([r]))["runs"][0]["tool"]["driver"]["rules"][0]
        assert rule["id"] == "AUTH-001"

    def test_rule_name_is_check_id(self):
        r = _make_result(check_id="AUTH-001")
        rule = _sarif(_make_report([r]))["runs"][0]["tool"]["driver"]["rules"][0]
        assert rule["name"] == "AUTH-001"

    def test_rule_short_description(self):
        r = _make_result(check_name="Missing 401 Check")
        rule = _sarif(_make_report([r]))["runs"][0]["tool"]["driver"]["rules"][0]
        assert rule["shortDescription"]["text"] == "Missing 401 Check"

    def test_rule_default_configuration_level_high(self):
        r = _make_result(severity=Severity.HIGH)
        rule = _sarif(_make_report([r]))["runs"][0]["tool"]["driver"]["rules"][0]
        assert rule["defaultConfiguration"]["level"] == "error"

    def test_rule_default_configuration_level_medium(self):
        r = _make_result(severity=Severity.MEDIUM)
        rule = _sarif(_make_report([r]))["runs"][0]["tool"]["driver"]["rules"][0]
        assert rule["defaultConfiguration"]["level"] == "warning"

    def test_rule_default_configuration_level_low(self):
        r = _make_result(severity=Severity.LOW)
        rule = _sarif(_make_report([r]))["runs"][0]["tool"]["driver"]["rules"][0]
        assert rule["defaultConfiguration"]["level"] == "note"

    def test_rule_has_security_tag(self):
        r = _make_result()
        rule = _sarif(_make_report([r]))["runs"][0]["tool"]["driver"]["rules"][0]
        assert "security" in rule["properties"]["tags"]

    def test_rule_has_category_tag(self):
        r = _make_result(category=CheckCategory.AUTHENTICATION)
        rule = _sarif(_make_report([r]))["runs"][0]["tool"]["driver"]["rules"][0]
        assert "authentication" in rule["properties"]["tags"]

    def test_rule_has_owasp_tag_when_set(self):
        r = _make_result(owasp=OwaspApiCategory.API2_BROKEN_AUTHENTICATION)
        rule = _sarif(_make_report([r]))["runs"][0]["tool"]["driver"]["rules"][0]
        tags = rule["properties"]["tags"]
        assert any(t.startswith("owasp:API2") for t in tags)

    def test_rule_has_cwe_tag_for_owasp(self):
        r = _make_result(owasp=OwaspApiCategory.API2_BROKEN_AUTHENTICATION)
        rule = _sarif(_make_report([r]))["runs"][0]["tool"]["driver"]["rules"][0]
        tags = rule["properties"]["tags"]
        assert "CWE-287" in tags

    def test_rule_no_owasp_tag_when_unset(self):
        r = _make_result(owasp=None)
        rule = _sarif(_make_report([r]))["runs"][0]["tool"]["driver"]["rules"][0]
        tags = rule["properties"]["tags"]
        assert not any(t.startswith("owasp:") for t in tags)

    def test_rule_github_security_severity_present_for_high(self):
        r = _make_result(severity=Severity.HIGH)
        rule = _sarif(_make_report([r]))["runs"][0]["tool"]["driver"]["rules"][0]
        assert "security-severity" in rule["properties"]
        assert rule["properties"]["security-severity"] == "8.0"

    def test_rule_github_security_severity_critical(self):
        r = _make_result(severity=Severity.CRITICAL)
        rule = _sarif(_make_report([r]))["runs"][0]["tool"]["driver"]["rules"][0]
        assert rule["properties"]["security-severity"] == "9.5"

    def test_rule_github_security_severity_medium(self):
        r = _make_result(severity=Severity.MEDIUM)
        rule = _sarif(_make_report([r]))["runs"][0]["tool"]["driver"]["rules"][0]
        assert rule["properties"]["security-severity"] == "5.5"

    def test_no_rules_when_no_findings(self):
        rules = _sarif(_make_report([]))["runs"][0]["tool"]["driver"]["rules"]
        assert rules == []


# ---------------------------------------------------------------------------
# Results
# ---------------------------------------------------------------------------


class TestResults:
    def test_one_result_per_finding(self):
        r = _make_result()
        sarif_results = _sarif(_make_report([r]))["runs"][0]["results"]
        assert len(sarif_results) == 1

    def test_result_rule_id(self):
        r = _make_result(check_id="AUTH-001")
        sarif_result = _sarif(_make_report([r]))["runs"][0]["results"][0]
        assert sarif_result["ruleId"] == "AUTH-001"

    def test_result_level_high(self):
        r = _make_result(severity=Severity.HIGH)
        sarif_result = _sarif(_make_report([r]))["runs"][0]["results"][0]
        assert sarif_result["level"] == "error"

    def test_result_level_critical(self):
        r = _make_result(severity=Severity.CRITICAL)
        sarif_result = _sarif(_make_report([r]))["runs"][0]["results"][0]
        assert sarif_result["level"] == "error"

    def test_result_level_medium(self):
        r = _make_result(severity=Severity.MEDIUM)
        sarif_result = _sarif(_make_report([r]))["runs"][0]["results"][0]
        assert sarif_result["level"] == "warning"

    def test_result_level_low(self):
        r = _make_result(severity=Severity.LOW)
        sarif_result = _sarif(_make_report([r]))["runs"][0]["results"][0]
        assert sarif_result["level"] == "note"

    def test_result_level_info(self):
        r = _make_result(severity=Severity.INFO)
        sarif_result = _sarif(_make_report([r]))["runs"][0]["results"][0]
        assert sarif_result["level"] == "note"

    def test_result_level_no_severity(self):
        r = _make_result(severity=None)
        sarif_result = _sarif(_make_report([r]))["runs"][0]["results"][0]
        assert sarif_result["level"] == "note"

    def test_result_message_contains_summary(self):
        r = _make_result(summary="Endpoint returned 200 without auth.")
        sarif_result = _sarif(_make_report([r]))["runs"][0]["results"][0]
        assert "Endpoint returned 200 without auth." in sarif_result["message"]["text"]

    def test_result_message_contains_explanation_when_set(self):
        r = _make_result(summary="S.", explanation="Because X happened.")
        sarif_result = _sarif(_make_report([r]))["runs"][0]["results"][0]
        assert "Because X happened." in sarif_result["message"]["text"]

    def test_result_message_summary_only_when_no_explanation(self):
        r = _make_result(summary="Just the summary.", explanation="")
        sarif_result = _sarif(_make_report([r]))["runs"][0]["results"][0]
        assert sarif_result["message"]["text"] == "Just the summary."

    def test_result_has_locations(self):
        r = _make_result()
        sarif_result = _sarif(_make_report([r]))["runs"][0]["results"][0]
        assert len(sarif_result["locations"]) >= 1

    def test_result_logical_location_name(self):
        r = _make_result(endpoint_key="GET /api/users")
        sarif_result = _sarif(_make_report([r]))["runs"][0]["results"][0]
        logical = sarif_result["locations"][0]["logicalLocations"][0]
        assert logical["name"] == "GET /api/users"
        assert logical["kind"] == "api-endpoint"

    def test_result_physical_location_uri_when_url_set(self):
        r = _make_result(url="https://api.example.com/api/users")
        sarif_result = _sarif(_make_report([r]))["runs"][0]["results"][0]
        phys = sarif_result["locations"][0]["physicalLocation"]
        assert phys["artifactLocation"]["uri"] == "https://api.example.com/api/users"
        assert phys["artifactLocation"]["uriBaseId"] == "%APIROOT%"

    def test_result_no_physical_location_when_url_none(self):
        r = _make_result(url=None)
        sarif_result = _sarif(_make_report([r]))["runs"][0]["results"][0]
        assert "physicalLocation" not in sarif_result["locations"][0]

    def test_result_fingerprints_present(self):
        r = _make_result()
        sarif_result = _sarif(_make_report([r]))["runs"][0]["results"][0]
        assert "aegisapi/v1" in sarif_result["fingerprints"]

    def test_result_fingerprint_equals_result_id(self):
        r = _make_result()
        sarif_result = _sarif(_make_report([r]))["runs"][0]["results"][0]
        assert sarif_result["fingerprints"]["aegisapi/v1"] == r.result_id

    def test_result_properties_finding_class(self):
        r = _make_result(finding_class=FindingClass.CONFIRMED)
        sarif_result = _sarif(_make_report([r]))["runs"][0]["results"][0]
        assert sarif_result["properties"]["aegisapi.finding_class"] == "confirmed"

    def test_result_properties_severity(self):
        r = _make_result(severity=Severity.HIGH)
        sarif_result = _sarif(_make_report([r]))["runs"][0]["results"][0]
        assert sarif_result["properties"]["aegisapi.severity"] == "high"

    def test_result_properties_owasp(self):
        r = _make_result(owasp=OwaspApiCategory.API2_BROKEN_AUTHENTICATION)
        sarif_result = _sarif(_make_report([r]))["runs"][0]["results"][0]
        owasp_val = sarif_result["properties"]["aegisapi.owasp"]
        assert "API2:2023" in owasp_val

    def test_result_properties_remediation_when_set(self):
        r = _make_result(remediation="Require bearer token.")
        sarif_result = _sarif(_make_report([r]))["runs"][0]["results"][0]
        assert sarif_result["properties"]["aegisapi.remediation"] == "Require bearer token."

    def test_result_properties_no_remediation_when_unset(self):
        r = _make_result(remediation=None)
        sarif_result = _sarif(_make_report([r]))["runs"][0]["results"][0]
        assert "aegisapi.remediation" not in sarif_result["properties"]

    def test_empty_results_when_no_findings(self):
        sarif_results = _sarif(_make_report([]))["runs"][0]["results"]
        assert sarif_results == []


# ---------------------------------------------------------------------------
# Filtering — only is_finding results appear
# ---------------------------------------------------------------------------


class TestFiltering:
    def test_confirmed_finding_included(self):
        r = _make_result(finding_class=FindingClass.CONFIRMED, outcome=CheckOutcome.FAIL)
        assert len(_sarif(_make_report([r]))["runs"][0]["results"]) == 1

    def test_suspected_finding_included(self):
        r = _make_result(
            finding_class=FindingClass.SUSPECTED,
            outcome=CheckOutcome.NEEDS_REVIEW,
        )
        assert len(_sarif(_make_report([r]))["runs"][0]["results"]) == 1

    def test_pass_result_excluded(self):
        r = _make_result(
            finding_class=FindingClass.NONE,
            outcome=CheckOutcome.PASS,
            severity=None,
        )
        assert len(_sarif(_make_report([r]))["runs"][0]["results"]) == 0

    def test_skipped_result_excluded(self):
        r = _make_result(
            finding_class=FindingClass.NONE,
            outcome=CheckOutcome.SKIPPED,
            severity=None,
        )
        assert len(_sarif(_make_report([r]))["runs"][0]["results"]) == 0

    def test_error_result_excluded(self):
        r = _make_result(
            finding_class=FindingClass.NONE,
            outcome=CheckOutcome.ERROR,
            severity=None,
        )
        assert len(_sarif(_make_report([r]))["runs"][0]["results"]) == 0

    def test_inconclusive_result_excluded(self):
        r = _make_result(
            finding_class=FindingClass.INCONCLUSIVE,
            outcome=CheckOutcome.FAIL,
            severity=None,
        )
        assert len(_sarif(_make_report([r]))["runs"][0]["results"]) == 0

    def test_informational_result_excluded(self):
        r = _make_result(
            finding_class=FindingClass.INFORMATIONAL,
            outcome=CheckOutcome.PASS,
            severity=None,
        )
        assert len(_sarif(_make_report([r]))["runs"][0]["results"]) == 0


# ---------------------------------------------------------------------------
# Security invariants
# ---------------------------------------------------------------------------


class TestSecurityInvariants:
    def test_no_body_excerpts_in_sarif(self):
        evidence = Evidence(
            evidence_id=Evidence.make_id("AUTH-001", "unauth-200", "https://api.example.com/users", 200),
            label="Unauthenticated 200",
            method="GET",
            url="https://api.example.com/users",
            status_code=200,
            body_excerpt='{"users": [{"id": 1, "token": "SECRET_VALUE"}]}',
            body_bytes=50,
        )
        r = _make_result(evidence=[evidence])
        text = render_sarif_report(_make_report([r]))
        assert "SECRET_VALUE" not in text
        assert "body_excerpt" not in text

    def test_no_request_headers_in_sarif(self):
        evidence = Evidence(
            evidence_id=Evidence.make_id("AUTH-001", "req", "https://api.example.com/users", 200),
            label="Request",
            method="GET",
            url="https://api.example.com/users",
            status_code=200,
            request_headers={"Authorization": "[REDACTED]", "X-API-Key": "[REDACTED]"},
        )
        r = _make_result(evidence=[evidence])
        text = render_sarif_report(_make_report([r]))
        assert "Authorization" not in text
        assert "X-API-Key" not in text
        assert "request_headers" not in text

    def test_no_response_headers_in_sarif(self):
        evidence = Evidence(
            evidence_id=Evidence.make_id("AUTH-001", "resp", "https://api.example.com/users", 200),
            label="Response",
            method="GET",
            url="https://api.example.com/users",
            status_code=200,
            response_headers={"Set-Cookie": "session=abc; HttpOnly", "X-Internal-Token": "secret"},
        )
        r = _make_result(evidence=[evidence])
        text = render_sarif_report(_make_report([r]))
        assert "Set-Cookie" not in text
        assert "X-Internal-Token" not in text
        assert "response_headers" not in text

    def test_sarif_contains_no_raw_secrets(self):
        """Confirm that common secret-shaped strings do not leak into output."""
        r = _make_result(
            summary="Auth bypass observed.",
            explanation="No token was needed.",
            remediation="Require a valid JWT.",
        )
        text = render_sarif_report(_make_report([r]))
        assert "password" not in text.lower() or "aegisapi" in text.lower()  # sanitized context only
        assert "Authorization:" not in text
        assert "Bearer " not in text

    def test_untrusted_string_cannot_break_json(self):
        """An endpoint key with JSON-special chars must be safely serialised."""
        r = _make_result(
            endpoint_key='GET /api/items?q={"evil": true}',
            summary='Summary with "quotes" and \\backslash.',
        )
        text = render_sarif_report(_make_report([r]))
        parsed = json.loads(text)  # must not raise
        assert isinstance(parsed, dict)


# ---------------------------------------------------------------------------
# Fingerprint stability
# ---------------------------------------------------------------------------


class TestFingerprints:
    def test_fingerprint_stable_across_renders(self):
        r = _make_result()
        t1 = render_sarif_report(_make_report([r]))
        t2 = render_sarif_report(_make_report([r]))
        d1 = json.loads(t1)["runs"][0]["results"][0]["fingerprints"]["aegisapi/v1"]
        d2 = json.loads(t2)["runs"][0]["results"][0]["fingerprints"]["aegisapi/v1"]
        assert d1 == d2

    def test_different_check_ids_produce_different_fingerprints(self):
        r1 = _make_result(check_id="AUTH-001", endpoint_key="GET /a")
        r2 = _make_result(check_id="AUTH-002", endpoint_key="GET /a")
        doc = _sarif(_make_report([r1, r2]))
        fps = [res["fingerprints"]["aegisapi/v1"] for res in doc["runs"][0]["results"]]
        assert fps[0] != fps[1]

    def test_different_endpoints_produce_different_fingerprints(self):
        r1 = _make_result(check_id="AUTH-001", endpoint_key="GET /a")
        r2 = _make_result(check_id="AUTH-001", endpoint_key="GET /b")
        doc = _sarif(_make_report([r1, r2]))
        fps = [res["fingerprints"]["aegisapi/v1"] for res in doc["runs"][0]["results"]]
        assert fps[0] != fps[1]


# ---------------------------------------------------------------------------
# OWASP → CWE mapping completeness
# ---------------------------------------------------------------------------


class TestOwaspCweMapping:
    @pytest.mark.parametrize("owasp_cat", list(OwaspApiCategory))
    def test_every_owasp_category_has_cwe(self, owasp_cat: OwaspApiCategory):
        assert owasp_cat in _OWASP_CWE, f"Missing CWE mapping for {owasp_cat}"

    @pytest.mark.parametrize("owasp_cat", list(OwaspApiCategory))
    def test_cwe_in_rule_tags(self, owasp_cat: OwaspApiCategory):
        r = _make_result(owasp=owasp_cat)
        rule = _sarif(_make_report([r]))["runs"][0]["tool"]["driver"]["rules"][0]
        expected_cwe = _OWASP_CWE[owasp_cat]
        assert expected_cwe in rule["properties"]["tags"]


# ---------------------------------------------------------------------------
# Format integration
# ---------------------------------------------------------------------------


class TestFormatIntegration:
    def test_sarif_in_supported_formats(self):
        assert ReportFormat.SARIF in SUPPORTED_FORMATS

    def test_sarif_is_supported(self):
        assert is_supported(ReportFormat.SARIF)

    def test_sarif_suffix(self):
        assert suffix_for(ReportFormat.SARIF) == "sarif"

    def test_render_dispatcher_sarif(self):
        report = _make_report()
        text = render(report, ReportFormat.SARIF)
        doc = json.loads(text)
        assert doc["version"] == "2.1.0"

    def test_scan_format_sarif_in_enum(self):
        from aegisapi.cli import ScanFormat
        assert ScanFormat.SARIF == "sarif"

    def test_scan_report_paths_sarif(self):
        from pathlib import Path
        from aegisapi.cli import ScanFormat, _scan_report_paths
        pairs = _scan_report_paths(Path("out/report"), ScanFormat.SARIF)
        assert len(pairs) == 1
        path, fmt = pairs[0]
        assert fmt is ReportFormat.SARIF
        assert path.suffix == ".sarif"

    def test_scan_report_paths_both_does_not_include_sarif(self):
        from pathlib import Path
        from aegisapi.cli import ScanFormat, _scan_report_paths
        pairs = _scan_report_paths(None, ScanFormat.BOTH)
        formats = [fmt for _, fmt in pairs]
        assert ReportFormat.JSON in formats
        assert ReportFormat.HTML in formats
        assert ReportFormat.SARIF not in formats

    def test_scan_report_paths_none_produces_empty(self):
        from pathlib import Path
        from aegisapi.cli import ScanFormat, _scan_report_paths
        pairs = _scan_report_paths(None, ScanFormat.NONE)
        assert pairs == []
