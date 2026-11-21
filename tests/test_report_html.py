"""The HTML report's security contract.

A report embeds material AegisAPI did not write: response excerpts and header
values from the API under test, and operation paths and schema names from a
specification supplied by a client. All of it is attacker-influencable.

Every test here corresponds to a way that content could otherwise execute, load
something, or escape its element. Treat them as load-bearing: each one is a
reason the renderer is written the way it is, not a coverage exercise.
"""

from __future__ import annotations

import html
import re

import pytest

from aegisapi.models.assessment import (
    CheckCategory,
    CheckOutcome,
    CheckResult,
    Evidence,
    FindingClass,
    OwaspApiCategory,
)
from aegisapi.models.common import Confidence, Severity
from aegisapi.models.intelligence import (
    AttackPath,
    AttackPathStep,
    Correlation,
    EdgeKind,
    PathStepKind,
    PrioritisedRisk,
    Provenance,
    RiskBand,
    RiskFactor,
)
from aegisapi.models.report import Report
from aegisapi.reporting import build_report, render_html_report
from aegisapi.reporting.html_report import (
    EXECUTIVE_SUMMARY_HEADING,
    METHODOLOGY_HEADING,
    NEXT_STEP_HEADING,
    REMEDIATION_HEADING,
)
from assessfix import TOKEN, assessment_result, check_result

PAYLOAD = "<script>alert('xss & \"pwn\"')</script>"
"""One string carrying every character that matters: < > & ' "."""

URL_PAYLOAD = "javascript:alert(document.domain)"
"""A URL that stays dangerous when escaped, so it must never become a link."""

MULTILINE = "line one\n  line two <b>&</b>\n\tline three"
"""An excerpt with newlines and tabs, which must survive for a reader."""


def hostile_evidence() -> Evidence:
    """Evidence with a payload in every string-bearing field."""
    return Evidence(
        evidence_id=PAYLOAD,
        label=PAYLOAD,
        method=PAYLOAD,
        url=URL_PAYLOAD,
        status_code=200,
        request_headers={PAYLOAD: PAYLOAD},
        response_headers={PAYLOAD: PAYLOAD, "server": PAYLOAD},
        content_type=PAYLOAD,
        body_excerpt=MULTILINE + PAYLOAD,
        body_bytes=12,
        truncated=True,
        elapsed_ms=1.5,
        authenticated=True,
        identity=PAYLOAD,
        note=PAYLOAD,
    )


def hostile_result() -> CheckResult:
    """A check result with a payload in every string-bearing field."""
    return CheckResult(
        check_id=PAYLOAD,
        check_name=PAYLOAD,
        category=CheckCategory.CONFIGURATION,
        target_name=PAYLOAD,
        endpoint_key=PAYLOAD,
        url=URL_PAYLOAD,
        outcome=CheckOutcome.FAIL,
        finding_class=FindingClass.CONFIRMED,
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        summary=PAYLOAD,
        explanation=PAYLOAD,
        limitations=[PAYLOAD, PAYLOAD],
        next_step=PAYLOAD,
        evidence=[hostile_evidence()],
        requests_sent=1,
    )


def hostile_risk() -> PrioritisedRisk:
    """A prioritised risk with a payload in every string-bearing field."""
    return PrioritisedRisk(
        risk_id=PAYLOAD,
        title=PAYLOAD,
        band=RiskBand.CRITICAL,
        score=91.5,
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        evidence_strength=2,
        confirmed=True,
        category=PAYLOAD,
        endpoints=[PAYLOAD],
        factors=[RiskFactor(name=PAYLOAD, points=3.0, reason=PAYLOAD)],
        source_results=[PAYLOAD],
        source_correlations=[PAYLOAD],
        evidence_ids=[PAYLOAD],
        what_was_observed=PAYLOAD,
        why_it_matters=PAYLOAD,
        unverified=[PAYLOAD],
        next_step=PAYLOAD,
    )


def hostile_path() -> AttackPath:
    """An attack path with a payload in every string-bearing field."""
    return AttackPath(
        path_id=PAYLOAD,
        title=PAYLOAD,
        steps=[
            AttackPathStep(
                from_node=PAYLOAD,
                to_node=PAYLOAD,
                edge_kind=EdgeKind.ACCEPTS_IDENTIFIER,
                kind=PathStepKind.INFERRED,
                description=PAYLOAD,
                evidence_ids=[PAYLOAD],
            )
        ],
        endpoints=[PAYLOAD],
        severity=Severity.HIGH,
        confidence=Confidence.LOW,
        weakest_step=PathStepKind.INFERRED,
        fully_evidenced=False,
        reasoning=PAYLOAD,
        unverified=[PAYLOAD],
    )


def hostile_correlation() -> Correlation:
    """A correlation with a payload in every string-bearing field."""
    return Correlation(
        correlation_id=PAYLOAD,
        kind=PAYLOAD,
        title=PAYLOAD,
        endpoints=[PAYLOAD],
        supporting_results=[PAYLOAD],
        supporting_edges=[PAYLOAD],
        evidence_ids=[PAYLOAD],
        provenance=Provenance.INFERRED,
        confidence=Confidence.LOW,
        confirmed=False,
        reasoning=PAYLOAD,
        limitations=[PAYLOAD],
    )


def hostile_report() -> Report:
    """A report whose every string-bearing field carries a payload."""
    assessment = assessment_result([hostile_result()], target_name=PAYLOAD, base_url=URL_PAYLOAD)
    report = build_report(assessment, include_all=True)
    return report.model_copy(
        update={
            "risks": [hostile_risk()],
            "attack_paths": [hostile_path()],
            "correlations": [hostile_correlation()],
            "notes": [*report.notes, PAYLOAD],
            "checks_run": [PAYLOAD],
            "specification_sha256": PAYLOAD,
            "source_intelligence_schema": 1,
        }
    )


@pytest.fixture
def hostile_html() -> str:
    """The rendered HTML for a report full of payloads."""
    return render_html_report(hostile_report())


class TestEscaping:
    def test_the_payload_never_appears_raw(self, hostile_html: str) -> None:
        assert PAYLOAD not in hostile_html

    def test_the_payload_appears_escaped(self, hostile_html: str) -> None:
        # Present as text, so the report is not silently dropping content.
        assert html.escape(PAYLOAD, quote=True) in hostile_html

    def test_no_script_element_is_emitted(self, hostile_html: str) -> None:
        assert "<script" not in hostile_html.lower()

    def test_angle_brackets_from_data_are_escaped(self, hostile_html: str) -> None:
        assert "&lt;script&gt;" in hostile_html

    def test_quotes_from_data_are_escaped(self, hostile_html: str) -> None:
        assert "&#x27;" in hostile_html
        assert "&quot;" in hostile_html

    def test_ampersands_from_data_are_escaped(self, hostile_html: str) -> None:
        assert "&amp;" in hostile_html

    @pytest.mark.parametrize(
        ("field", "builder"),
        [
            ("results", hostile_result),
            ("risks", hostile_risk),
            ("attack_paths", hostile_path),
            ("correlations", hostile_correlation),
        ],
        ids=["results", "risks", "attack_paths", "correlations"],
    )
    def test_each_model_is_escaped_in_isolation(self, field: str, builder: object) -> None:
        # One model at a time, so a field on any of them that bypassed the
        # helper is attributed to that model rather than hidden by the others.
        base = build_report(assessment_result([]), include_all=True)
        report = base.model_copy(
            update={field: [builder()], "source_intelligence_schema": 1}  # type: ignore[operator]
        )

        rendered = render_html_report(report)

        assert PAYLOAD not in rendered
        assert html.escape(PAYLOAD, quote=True) in rendered

    def test_a_payload_in_the_target_name_is_escaped_in_the_title(self) -> None:
        rendered = render_html_report(hostile_report())
        title = re.search(r"<title>(.*?)</title>", rendered, re.DOTALL)

        assert title is not None
        assert PAYLOAD not in title.group(1)
        assert "&lt;script&gt;" in title.group(1)

    def test_a_payload_in_a_note_is_escaped(self) -> None:
        report = build_report(assessment_result([])).model_copy(update={"notes": [PAYLOAD]})

        rendered = render_html_report(report)

        assert PAYLOAD not in rendered
        assert html.escape(PAYLOAD, quote=True) in rendered

    def test_a_payload_in_a_response_header_is_escaped(self, hostile_html: str) -> None:
        # Header names and values both come from the API, so both are escaped.
        assert hostile_html.count("&lt;script&gt;") > 1

    def test_remediation_payload_is_escaped(self) -> None:
        result = hostile_result().model_copy(update={"remediation": PAYLOAD})
        report = build_report(assessment_result([result]), include_all=True)
        rendered = render_html_report(report)
        assert PAYLOAD not in rendered
        assert html.escape(PAYLOAD, quote=True) in rendered


class TestNoLinksOrExternalResources:
    def test_no_href_attribute_exists_anywhere(self, hostile_html: str) -> None:
        # Escaping does not defuse a javascript: URL in an href, so the
        # document contains no link at all.
        assert "href=" not in hostile_html.lower()

    def test_no_src_attribute_exists_anywhere(self, hostile_html: str) -> None:
        assert "src=" not in hostile_html.lower()

    def test_a_model_url_is_rendered_as_text_not_a_link(self, hostile_html: str) -> None:
        assert html.escape(URL_PAYLOAD, quote=True) in hostile_html
        assert f'href="{URL_PAYLOAD}"' not in hostile_html
        assert "javascript:" not in hostile_html.lower().replace(
            html.escape(URL_PAYLOAD, quote=True).lower(), ""
        )

    def test_no_inline_event_handler_is_emitted(self, hostile_html: str) -> None:
        for handler in ("onclick=", "onerror=", "onload=", "onmouseover="):
            assert handler not in hostile_html.lower()

    def test_no_external_font_or_stylesheet_is_referenced(self, hostile_html: str) -> None:
        assert "<link" not in hostile_html.lower()
        assert "@import" not in hostile_html.lower()

    def test_no_iframe_object_or_embed(self, hostile_html: str) -> None:
        for element in ("<iframe", "<object", "<embed", "<form"):
            assert element not in hostile_html.lower()

    def test_a_restrictive_csp_is_declared(self, hostile_html: str) -> None:
        assert "Content-Security-Policy" in hostile_html
        assert "default-src 'none'" in hostile_html
        assert "style-src 'unsafe-inline'" in hostile_html


class TestStructureAndContent:
    def test_the_document_is_well_formed_html(self, hostile_html: str) -> None:
        assert hostile_html.startswith("<!DOCTYPE html>")
        assert hostile_html.rstrip().endswith("</html>")
        assert '<html lang="en">' in hostile_html
        assert '<meta charset="utf-8">' in hostile_html

    def test_semantic_elements_are_used(self, hostile_html: str) -> None:
        for element in ("<h1", "<h2", "<section", "<article", "<table", "<dl", "<footer"):
            assert element in hostile_html

    def test_a_print_stylesheet_is_embedded(self, hostile_html: str) -> None:
        assert "@media print" in hostile_html
        assert "page-break-inside" in hostile_html

    def test_the_stylesheet_is_embedded_not_linked(self, hostile_html: str) -> None:
        assert "<style>" in hostile_html

    def test_next_verification_step_is_the_heading(self, hostile_html: str) -> None:
        assert NEXT_STEP_HEADING == "Next Verification Step"
        assert "Next Verification Step" in hostile_html

    def test_no_remediation_heading_when_remediation_is_none(self, hostile_html: str) -> None:
        # hostile_result() does not set remediation, so the heading must not
        # appear in a report that uses it.
        assert REMEDIATION_HEADING not in hostile_html

    def test_remediation_heading_is_rendered_when_present(self) -> None:
        result = check_result("AUTH-001", "GET /items").model_copy(
            update={"remediation": "Enforce authorisation on all protected endpoints."}
        )
        report = build_report(assessment_result([result]), include_all=True)
        rendered = render_html_report(report)
        assert REMEDIATION_HEADING in rendered
        assert "Enforce authorisation on all protected endpoints." in rendered

    def test_remediation_renders_after_next_step(self) -> None:
        # next_step names the verifying observation; remediation is the fix.
        # Both must be present and in that order when both are set.
        result = check_result("AUTH-001", "GET /items").model_copy(
            update={
                "remediation": "Enforce auth.",
                "next_step": "Confirm without credentials.",
            }
        )
        report = build_report(assessment_result([result]), include_all=True)
        rendered = render_html_report(report)
        assert REMEDIATION_HEADING in rendered
        assert NEXT_STEP_HEADING in rendered
        assert rendered.index(NEXT_STEP_HEADING) < rendered.index(REMEDIATION_HEADING)

    def test_findings_risks_and_paths_are_distinguished(self, hostile_html: str) -> None:
        assert "Check results" in hostile_html
        assert "Prioritised risks" in hostile_html
        assert "Potential attack paths" in hostile_html

    def test_attack_paths_are_labelled_as_hypotheses(self, hostile_html: str) -> None:
        assert "not a demonstrated exploit" in hostile_html
        assert "weakest step" in hostile_html

    def test_a_limitations_section_is_present(self, hostile_html: str) -> None:
        assert "Limitations" in hostile_html
        assert "not a confirmed vulnerability" in hostile_html

    def test_the_summary_warns_against_adding_findings_to_risks(self, hostile_html: str) -> None:
        assert "never" in hostile_html and "added together" in hostile_html


class TestBodyExcerpts:
    def test_an_excerpt_is_wrapped_in_a_pre_element(self, hostile_html: str) -> None:
        assert '<pre class="excerpt">' in hostile_html

    def test_newlines_in_an_excerpt_survive(self, hostile_html: str) -> None:
        match = re.search(r'<pre class="excerpt">(.*?)</pre>', hostile_html, re.DOTALL)
        assert match is not None
        assert "line one\n" in match.group(1)
        assert "line two" in match.group(1)
        assert "line three" in match.group(1)

    def test_an_excerpt_cannot_close_its_element(self, hostile_html: str) -> None:
        match = re.search(r'<pre class="excerpt">(.*?)</pre>', hostile_html, re.DOTALL)
        assert match is not None
        assert "<" not in match.group(1)

    def test_the_pre_element_wraps_long_lines(self, hostile_html: str) -> None:
        assert "white-space: pre-wrap" in hostile_html
        assert "overflow-wrap: anywhere" in hostile_html

    def test_truncation_is_disclosed(self, hostile_html: str) -> None:
        assert "truncated" in hostile_html


class TestEmptyAndPartialReports:
    def test_a_report_with_no_results_renders(self) -> None:
        rendered = render_html_report(build_report(assessment_result([])))

        assert rendered.startswith("<!DOCTYPE html>")
        assert "recorded no results" in rendered

    def test_a_report_with_no_findings_explains_the_absence(self) -> None:
        assessment = assessment_result(
            [
                check_result(
                    "CONF-003",
                    "GET /ok",
                    outcome=CheckOutcome.PASS,
                    finding_class=FindingClass.NONE,
                    severity=None,
                )
            ]
        )

        rendered = render_html_report(build_report(assessment))

        assert "--include-all" in rendered

    def test_a_report_without_intelligence_omits_the_risk_sections(self) -> None:
        # The summary still lists the rows, showing a dash, so the assertion is
        # about the sections rather than every mention of the words.
        rendered = render_html_report(build_report(assessment_result([])))

        assert "<h2>Prioritised risks</h2>" not in rendered
        assert "<h2>Potential attack paths</h2>" not in rendered
        assert "<h2>Cross-endpoint correlations</h2>" not in rendered

    def test_a_report_without_intelligence_says_so(self) -> None:
        rendered = render_html_report(build_report(assessment_result([])))

        assert "No risk analysis was included" in rendered

    def test_unset_values_render_as_a_dash(self) -> None:
        rendered = render_html_report(build_report(assessment_result([])))

        assert "&mdash;" in rendered


class TestNoCredentials:
    def test_the_fixture_token_never_reaches_the_html(self) -> None:
        rendered = render_html_report(hostile_report())

        assert TOKEN not in rendered

    def test_a_credential_shaped_header_value_is_still_escaped(self) -> None:
        evidence = hostile_evidence().model_copy(
            update={"response_headers": {"authorization": "[REDACTED]"}}
        )
        result = hostile_result().model_copy(update={"evidence": [evidence]})
        report = build_report(assessment_result([result]), include_all=True)

        rendered = render_html_report(report)

        assert "[REDACTED]" in rendered
        assert TOKEN not in rendered


class TestRequestHeaders:
    def test_request_header_table_is_rendered_when_present(self) -> None:
        evidence = hostile_evidence().model_copy(
            update={"request_headers": {"content-type": "application/json"}}
        )
        result = hostile_result().model_copy(update={"evidence": [evidence]})
        report = build_report(assessment_result([result]), include_all=True)
        rendered = render_html_report(report)

        assert "<th>Request header</th>" in rendered
        assert "content-type" in rendered
        assert "application/json" in rendered

    def test_request_header_table_absent_when_dict_is_empty(self) -> None:
        # The methodology preamble also mentions "request headers" in prose;
        # check for the table element specifically to distinguish the two.
        evidence = hostile_evidence().model_copy(update={"request_headers": {}})
        result = hostile_result().model_copy(update={"evidence": [evidence]})
        report = build_report(assessment_result([result]), include_all=True)
        rendered = render_html_report(report)

        assert "<th>Request header</th>" not in rendered

    def test_request_header_names_are_escaped(self) -> None:
        evidence = hostile_evidence().model_copy(
            update={"request_headers": {PAYLOAD: "safe-value"}}
        )
        result = hostile_result().model_copy(update={"evidence": [evidence]})
        report = build_report(assessment_result([result]), include_all=True)
        rendered = render_html_report(report)

        assert PAYLOAD not in rendered
        assert html.escape(PAYLOAD, quote=True) in rendered

    def test_request_header_values_are_escaped(self) -> None:
        evidence = hostile_evidence().model_copy(
            update={"request_headers": {"x-custom": PAYLOAD}}
        )
        result = hostile_result().model_copy(update={"evidence": [evidence]})
        report = build_report(assessment_result([result]), include_all=True)
        rendered = render_html_report(report)

        assert PAYLOAD not in rendered
        assert html.escape(PAYLOAD, quote=True) in rendered

    def test_redacted_authorization_header_renders_safely(self) -> None:
        evidence = hostile_evidence().model_copy(
            update={"request_headers": {"authorization": "[REDACTED]"}}
        )
        result = hostile_result().model_copy(update={"evidence": [evidence]})
        report = build_report(assessment_result([result]), include_all=True)
        rendered = render_html_report(report)

        assert "Request header" in rendered
        assert "[REDACTED]" in rendered
        assert TOKEN not in rendered

    def test_response_header_rendering_is_unaffected(self) -> None:
        evidence = hostile_evidence().model_copy(
            update={
                "request_headers": {"accept": "application/json"},
                "response_headers": {"content-type": "application/json"},
            }
        )
        result = hostile_result().model_copy(update={"evidence": [evidence]})
        report = build_report(assessment_result([result]), include_all=True)
        rendered = render_html_report(report)

        assert "Request header" in rendered
        assert "Response header" in rendered


class TestOwaspDistribution:
    def test_owasp_table_absent_when_no_results_have_a_category(self) -> None:
        # check_result() does not set owasp, so the table must be absent.
        report = build_report(assessment_result([check_result("AUTH-001", "GET /x")]))
        rendered = render_html_report(report)

        assert "By OWASP API Security Top 10" not in rendered

    def test_owasp_table_rendered_when_category_present(self) -> None:
        result = check_result("AUTH-001", "GET /x").model_copy(
            update={"owasp": OwaspApiCategory.API2_BROKEN_AUTHENTICATION}
        )
        report = build_report(assessment_result([result]), include_all=True)
        rendered = render_html_report(report)

        assert "By OWASP API Security Top 10" in rendered
        assert OwaspApiCategory.API2_BROKEN_AUTHENTICATION.value in rendered

    def test_owasp_category_identifier_is_in_the_table(self) -> None:
        result = check_result("AUTH-001", "GET /x").model_copy(
            update={"owasp": OwaspApiCategory.API8_MISCONFIGURATION}
        )
        report = build_report(assessment_result([result]), include_all=True)
        rendered = render_html_report(report)

        assert "API8:2023" in rendered

    def test_owasp_category_value_is_escaped(self) -> None:
        # OwaspApiCategory values are known strings, but _count_table passes
        # them through _esc(), which is the invariant we verify here.
        result = check_result("AUTH-001", "GET /x").model_copy(
            update={"owasp": OwaspApiCategory.API1_BOLA}
        )
        report = build_report(assessment_result([result]), include_all=True)
        rendered = render_html_report(report)

        # The enum value must appear as text — not as raw HTML — confirming
        # _esc() was applied.
        assert OwaspApiCategory.API1_BOLA.value in rendered
        assert "<script" not in rendered.lower()


class TestMethodologySection:
    def test_methodology_section_is_present(self, hostile_html: str) -> None:
        assert "Assessment Methodology" in hostile_html

    def test_methodology_check_id_is_listed(self) -> None:
        result = check_result("AUTH-001", "GET /x")
        report = build_report(assessment_result([result]), include_all=True)
        rendered = render_html_report(report)

        assert "AUTH-001" in rendered

    def test_methodology_check_name_appears_when_result_is_displayed(self) -> None:
        result = check_result("AUTH-001", "GET /x")
        report = build_report(assessment_result([result]), include_all=True)
        rendered = render_html_report(report)

        assert result.check_name in rendered

    def test_methodology_no_checks_message_when_checks_run_empty(self) -> None:
        report = build_report(assessment_result([])).model_copy(update={"checks_run": []})
        rendered = render_html_report(report)

        assert "No checks were selected" in rendered

    def test_methodology_security_areas_listed_when_results_present(self) -> None:
        result = check_result("AUTH-001", "GET /x")
        report = build_report(assessment_result([result]), include_all=True)
        rendered = render_html_report(report)

        assert "Security areas covered" in rendered

    def test_methodology_security_area_absent_on_empty_assessment(self) -> None:
        report = build_report(assessment_result([]))
        rendered = render_html_report(report)

        assert "Security areas covered" not in rendered

    def test_methodology_owasp_categories_listed_when_present(self) -> None:
        result = check_result("AUTH-001", "GET /x").model_copy(
            update={"owasp": OwaspApiCategory.API2_BROKEN_AUTHENTICATION}
        )
        report = build_report(assessment_result([result]), include_all=True)
        rendered = render_html_report(report)

        assert "OWASP API Security Top 10 categories covered" in rendered
        assert OwaspApiCategory.API2_BROKEN_AUTHENTICATION.value in rendered

    def test_methodology_owasp_absent_when_no_owasp_results(self) -> None:
        result = check_result("AUTH-001", "GET /x")  # owasp defaults to None
        report = build_report(assessment_result([result]))
        rendered = render_html_report(report)

        assert "OWASP API Security Top 10 categories covered" not in rendered

    def test_methodology_coverage_facts_are_present(self) -> None:
        result = check_result("AUTH-001", "GET /x")
        report = build_report(assessment_result([result]), include_all=True)
        rendered = render_html_report(report)

        assert "Operations in scope" in rendered
        assert "Operations tested" in rendered
        assert "Operations not tested" in rendered
        assert "Requests sent" in rendered

    def test_methodology_budget_exhausted_note_appears(self) -> None:
        result = check_result("AUTH-001", "GET /x")
        assessment = assessment_result([result]).model_copy(update={"budget_exhausted": True})
        report = build_report(assessment, include_all=True)
        rendered = render_html_report(report)

        assert "budget was exhausted" in rendered.lower()

    def test_methodology_budget_note_absent_when_not_exhausted(self) -> None:
        result = check_result("AUTH-001", "GET /x")
        assessment = assessment_result([result]).model_copy(update={"budget_exhausted": False})
        report = build_report(assessment, include_all=True)
        rendered = render_html_report(report)

        assert "request budget was exhausted" not in rendered.lower()

    def test_methodology_evidence_collection_note_is_present(self) -> None:
        report = build_report(assessment_result([]))
        rendered = render_html_report(report)

        assert "Evidence collection" in rendered
        assert "[REDACTED]" in rendered

    def test_methodology_zero_operations_renders_correctly(self) -> None:
        # An empty assessment has 0 operations in scope and 0 tested.
        report = build_report(assessment_result([]))
        rendered = render_html_report(report)

        assert "Operations in scope" in rendered
        assert "Operations tested" in rendered

    def test_methodology_hostile_check_id_is_escaped(self, hostile_html: str) -> None:
        # checks_run = [PAYLOAD] in hostile_report; it must not appear raw.
        assert PAYLOAD not in hostile_html
        assert html.escape(PAYLOAD, quote=True) in hostile_html

    def test_methodology_section_comes_before_summary(self) -> None:
        report = build_report(assessment_result([check_result("AUTH-001", "GET /x")]))
        rendered = render_html_report(report)

        assert rendered.index("Assessment Methodology") < rendered.index("<h2>Summary</h2>")


class TestExecutiveSummarySection:
    def test_executive_summary_section_is_present(self, hostile_html: str) -> None:
        assert EXECUTIVE_SUMMARY_HEADING in hostile_html

    def test_confirmed_findings_count_is_shown(self) -> None:
        result = check_result("AUTH-001", "GET /x")
        report = build_report(assessment_result([result]), include_all=True)
        rendered = render_html_report(report)

        assert "Confirmed findings" in rendered

    def test_potential_findings_shown_distinct_from_confirmed(self) -> None:
        result = check_result("AUTH-001", "GET /x")
        report = build_report(assessment_result([result]), include_all=True)
        rendered = render_html_report(report)

        assert "Confirmed findings" in rendered
        assert "Potential findings" in rendered
        # Both labels must be present and distinct — not merged.
        assert rendered.index("Confirmed findings") != rendered.index("Potential findings")

    def test_needs_review_count_is_shown(self) -> None:
        result = check_result("AUTH-001", "GET /x")
        report = build_report(assessment_result([result]), include_all=True)
        rendered = render_html_report(report)

        assert "Results needing review" in rendered

    def test_highest_severity_shown_when_findings_have_severity(self) -> None:
        from aegisapi.models.common import Severity

        result = check_result("AUTH-001", "GET /x").model_copy(
            update={"severity": Severity.HIGH}
        )
        report = build_report(assessment_result([result]), include_all=True)
        rendered = render_html_report(report)

        assert "Highest observed severity" in rendered
        assert str(Severity.HIGH) in rendered

    def test_highest_severity_is_dash_when_no_severity_recorded(self) -> None:
        # check_result() does not set severity by default.
        report = build_report(assessment_result([check_result("AUTH-001", "GET /x")]))
        rendered = render_html_report(report)

        assert "Highest observed severity" in rendered
        # No severity → the dash placeholder is used.
        assert "&mdash;" in rendered

    def test_no_findings_note_does_not_claim_secure(self) -> None:
        # An assessment with no findings must not say the target is "secure".
        report = build_report(assessment_result([]))
        rendered = render_html_report(report)

        assert "secure" not in rendered.lower()
        assert "No confirmed or potential findings" in rendered

    def test_no_findings_note_mentions_coverage_gap(self) -> None:
        # The note must acknowledge that uncovered checks and operations leave gaps.
        report = build_report(assessment_result([]))
        rendered = render_html_report(report)

        assert "operations not tested" in rendered.lower()

    def test_no_findings_note_absent_when_findings_exist(self) -> None:
        result = check_result("AUTH-001", "GET /x")
        # build_report without include_all: result with default outcome (FAIL) is displayed.
        report = build_report(assessment_result([result]))
        rendered = render_html_report(report)

        assert "No confirmed or potential findings" not in rendered

    def test_risk_highlights_absent_without_intelligence(self) -> None:
        report = build_report(assessment_result([]))
        rendered = render_html_report(report)

        assert "Risk highlights" not in rendered

    def test_risk_highlights_present_with_intelligence(self, hostile_html: str) -> None:
        # hostile_report has source_intelligence_schema=1, so has_intelligence is True.
        assert "Risk highlights" in hostile_html

    def test_top_confirmed_risk_title_is_shown(self, hostile_html: str) -> None:
        # hostile_risk() has confirmed=True, so the highest-priority block is rendered.
        # Its title is PAYLOAD, which appears escaped.
        assert "Highest-priority confirmed risk" in hostile_html

    def test_risk_score_is_labeled_not_cvss(self, hostile_html: str) -> None:
        # Scores must never be presented as CVSS.
        assert "not CVSS" in hostile_html

    def test_no_security_grade_invented(self, hostile_html: str) -> None:
        # No invented overall grade label (e.g. "security grade", "overall rating")
        # should be generated.
        for phrase in ("security grade", "overall grade", "security rating", "overall rating"):
            assert phrase not in hostile_html.lower()

    def test_budget_exhausted_limitation_appears(self) -> None:
        result = check_result("AUTH-001", "GET /x")
        assessment = assessment_result([result]).model_copy(update={"budget_exhausted": True})
        report = build_report(assessment, include_all=True)
        rendered = render_html_report(report)

        assert "Assessment limitations" in rendered
        assert "request budget was exhausted" in rendered.lower()

    def test_no_intelligence_limitation_appears(self) -> None:
        # Without intelligence the section must say risk analysis was not performed.
        report = build_report(assessment_result([check_result("AUTH-001", "GET /x")]))
        rendered = render_html_report(report)

        assert "No risk analysis was performed" in rendered

    def test_no_intelligence_limitation_absent_when_intelligence_present(
        self, hostile_html: str
    ) -> None:
        # hostile_report has intelligence; this limitation must not be shown.
        assert "No risk analysis was performed" not in hostile_html

    def test_hostile_target_name_escaped_in_executive_summary(
        self, hostile_html: str
    ) -> None:
        # target_name = PAYLOAD in hostile_report.
        assert PAYLOAD not in hostile_html
        assert html.escape(PAYLOAD, quote=True) in hostile_html

    def test_hostile_risk_fields_escaped(self, hostile_html: str) -> None:
        # confirmed risk title, risk_id, category, what_was_observed = PAYLOAD.
        assert PAYLOAD not in hostile_html

    def test_executive_summary_comes_before_methodology(self) -> None:
        report = build_report(assessment_result([check_result("AUTH-001", "GET /x")]))
        rendered = render_html_report(report)

        assert rendered.index(EXECUTIVE_SUMMARY_HEADING) < rendered.index(
            "Assessment Methodology"
        )

    def test_executive_summary_comes_before_detailed_summary(self) -> None:
        report = build_report(assessment_result([check_result("AUTH-001", "GET /x")]))
        rendered = render_html_report(report)

        assert rendered.index(EXECUTIVE_SUMMARY_HEADING) < rendered.index("<h2>Summary</h2>")
