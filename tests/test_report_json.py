"""The JSON report: determinism, provenance, and no credentials.

A report is something a reader keeps and diffs against the next one, so stable
serialisation is a feature rather than a detail.
"""

from __future__ import annotations

import json

from aegisapi.intelligence import analyse
from aegisapi.models.assessment import (
    ASSESSMENT_SCHEMA_VERSION,
    CheckOutcome,
    FindingClass,
    OwaspApiCategory,
)
from aegisapi.models.common import Severity
from aegisapi.models.intelligence import INTELLIGENCE_SCHEMA_VERSION
from aegisapi.models.report import REPORT_SCHEMA_VERSION, Report
from aegisapi.reporting import build_report, render_json_report
from assessfix import TOKEN, assessment_result, check_result
from test_report_model import mixed_discovery, mixed_results


def rendered(include_all: bool = False) -> tuple[Report, str]:
    """Build and render a report over the shared fixture."""
    report = build_report(mixed_results(), include_all=include_all)
    return report, render_json_report(report)


class TestSerialisation:
    def test_the_output_is_valid_json(self) -> None:
        _, text = rendered()

        assert isinstance(json.loads(text), dict)

    def test_two_space_indentation_is_used(self) -> None:
        _, text = rendered()

        assert '\n  "' in text

    def test_keys_are_sorted(self) -> None:
        _, text = rendered()
        document = json.loads(text)

        assert list(document) == sorted(document)

    def test_unicode_is_not_escaped(self) -> None:
        assessment = assessment_result(
            [check_result("AUTH-001", "GET /ordres-café")],
        )

        text = render_json_report(build_report(assessment))

        assert "café" in text
        assert "\\u00e9" not in text

    def test_no_trailing_newline_is_added_by_the_renderer(self) -> None:
        # The writer owns the trailing newline, so the renderer must not add one.
        _, text = rendered()

        assert not text.endswith("\n")


class TestDeterminism:
    def test_the_same_report_renders_identically(self) -> None:
        report = build_report(mixed_results(), include_all=True)

        assert render_json_report(report) == render_json_report(report)

    def test_two_reports_with_the_same_timestamp_match_byte_for_byte(self) -> None:
        assessment = mixed_results()
        first = build_report(assessment, include_all=True)
        second = build_report(assessment, include_all=True).model_copy(
            update={"generated_at": first.generated_at}
        )

        assert render_json_report(first) == render_json_report(second)

    def test_only_the_timestamp_differs_between_rebuilds(self) -> None:
        assessment = mixed_results()
        first = json.loads(render_json_report(build_report(assessment, include_all=True)))
        second = json.loads(render_json_report(build_report(assessment, include_all=True)))

        first.pop("generated_at")
        second.pop("generated_at")
        assert first == second


class TestRecordedProvenance:
    def test_the_report_schema_version_is_serialised(self) -> None:
        _, text = rendered()

        assert json.loads(text)["schema_version"] == REPORT_SCHEMA_VERSION

    def test_the_source_assessment_version_is_serialised(self) -> None:
        _, text = rendered()

        assert json.loads(text)["source_assessment_schema"] == ASSESSMENT_SCHEMA_VERSION

    def test_the_intelligence_version_is_null_without_an_analysis(self) -> None:
        _, text = rendered()

        assert json.loads(text)["source_intelligence_schema"] is None

    def test_the_intelligence_version_is_serialised_when_present(self) -> None:
        assessment = mixed_results()
        report = build_report(assessment, analyse(mixed_discovery(), assessment))

        document = json.loads(render_json_report(report))

        assert document["source_intelligence_schema"] == INTELLIGENCE_SCHEMA_VERSION

    def test_the_aegisapi_version_is_recorded(self) -> None:
        report, text = rendered()

        assert json.loads(text)["aegisapi_version"] == report.aegisapi_version

    def test_enumerations_serialise_as_their_values(self) -> None:
        _, text = rendered(include_all=True)
        document = json.loads(text)

        assert document["summary"]["by_outcome"][CheckOutcome.FAIL.value] >= 1
        assert document["summary"]["by_finding_class"][FindingClass.CONFIRMED.value] >= 1
        assert document["summary"]["by_severity"][Severity.HIGH.value] == 1

    def test_timestamps_serialise_as_strings(self) -> None:
        _, text = rendered()
        document = json.loads(text)

        assert isinstance(document["generated_at"], str)
        assert isinstance(document["assessment_started_at"], str)


class TestContent:
    def test_filtered_and_full_reports_differ_in_results_only(self) -> None:
        assessment = mixed_results()
        filtered = json.loads(render_json_report(build_report(assessment)))
        everything = json.loads(render_json_report(build_report(assessment, include_all=True)))

        assert len(filtered["results"]) < len(everything["results"])
        assert filtered["summary"]["by_outcome"] == everything["summary"]["by_outcome"]

    def test_notes_are_serialised(self) -> None:
        _, text = rendered()

        assert json.loads(text)["notes"]

    def test_risks_and_paths_are_empty_lists_without_an_analysis(self) -> None:
        _, text = rendered()
        document = json.loads(text)

        assert document["risks"] == []
        assert document["attack_paths"] == []
        assert document["correlations"] == []

    def test_risks_and_paths_are_serialised_when_analysed(self) -> None:
        assessment = mixed_results()
        report = build_report(assessment, analyse(mixed_discovery(), assessment))

        document = json.loads(render_json_report(report))

        assert document["risks"]
        assert document["attack_paths"]
        assert "factors" in document["risks"][0]
        assert "steps" in document["attack_paths"][0]

    def test_an_empty_assessment_still_renders(self) -> None:
        text = render_json_report(build_report(assessment_result([])))
        document = json.loads(text)

        assert document["results"] == []
        assert document["summary"]["results_total"] == 0


class TestNoCredentials:
    def test_the_fixture_token_never_reaches_the_json(self) -> None:
        assessment = mixed_results()
        report = build_report(assessment, analyse(mixed_discovery(), assessment))

        assert TOKEN not in render_json_report(report)

    def test_a_token_in_an_excerpt_is_the_assessments_problem_not_the_reports(self) -> None:
        # The report copies evidence verbatim, so this asserts the boundary:
        # redaction happens in the HTTP layer, and the report neither adds to
        # nor removes from what it was given. If this ever fails, redaction
        # upstream has regressed.
        assessment = mixed_results()

        text = render_json_report(build_report(assessment, include_all=True))

        assert "Authorization" not in text or "[REDACTED]" in text


class TestOwaspDistributionJson:
    def test_by_owasp_is_absent_when_no_results_have_a_category(self) -> None:
        # check_result() does not set owasp; the field should be an empty dict.
        document = json.loads(render_json_report(build_report(mixed_results(), include_all=True)))

        assert document["summary"]["by_owasp"] == {}

    def test_by_owasp_serialises_category_values_as_keys(self) -> None:
        result = check_result("AUTH-001", "GET /x").model_copy(
            update={"owasp": OwaspApiCategory.API2_BROKEN_AUTHENTICATION}
        )
        document = json.loads(
            render_json_report(build_report(assessment_result([result]), include_all=True))
        )

        assert document["summary"]["by_owasp"] == {
            OwaspApiCategory.API2_BROKEN_AUTHENTICATION.value: 1
        }

    def test_by_owasp_accumulates_across_same_category(self) -> None:
        results = [
            check_result("AUTH-001", "GET /x").model_copy(
                update={"owasp": OwaspApiCategory.API1_BOLA}
            ),
            check_result("AUTH-002", "GET /y").model_copy(
                update={"owasp": OwaspApiCategory.API1_BOLA}
            ),
        ]
        document = json.loads(
            render_json_report(build_report(assessment_result(results), include_all=True))
        )

        assert document["summary"]["by_owasp"][OwaspApiCategory.API1_BOLA.value] == 2

    def test_by_owasp_keys_are_sorted_in_output(self) -> None:
        results = [
            check_result("AUTH-001", "GET /x").model_copy(
                update={"owasp": OwaspApiCategory.API8_MISCONFIGURATION}
            ),
            check_result("AUTH-002", "GET /y").model_copy(
                update={"owasp": OwaspApiCategory.API1_BOLA}
            ),
        ]
        document = json.loads(
            render_json_report(build_report(assessment_result(results), include_all=True))
        )
        owasp_keys = list(document["summary"]["by_owasp"])

        assert owasp_keys == sorted(owasp_keys)
