"""The report envelope and the builder that composes it.

These tests are about *counting discipline* as much as about structure. The
summary has to describe the whole assessment even when the body shows a subset,
and findings must never be added to risks as though the same observation had
been found twice.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from aegisapi.intelligence import analyse
from aegisapi.models.assessment import (
    ASSESSMENT_SCHEMA_VERSION,
    AssessmentResult,
    CheckCategory,
    CheckOutcome,
    FindingClass,
    OwaspApiCategory,
)
from aegisapi.models.common import Confidence, Severity
from aegisapi.models.discovery import DiscoveryResult
from aegisapi.models.intelligence import INTELLIGENCE_SCHEMA_VERSION, RiskBand
from aegisapi.models.report import REPORT_SCHEMA_VERSION, Report, ReportSummary
from aegisapi.reporting.build import (
    FILTERED_NOTE,
    NO_INTELLIGENCE_NOTE,
    NOT_A_VULNERABILITY_NOTE,
    build_report,
)
from assessfix import (
    assessment_result,
    check_result,
    classified,
    discovery_result,
    protected,
    public,
)

ENDPOINTS = ("/orders", "/health", "/public", "/ok", "/skipped", "/errored")


def mixed_discovery() -> DiscoveryResult:
    """A discovery result whose operations match :func:`mixed_results`."""
    return discovery_result(
        [classified(protected("get", "/orders"))]
        + [classified(public("get", path)) for path in ENDPOINTS[1:]]
    )


def mixed_results() -> AssessmentResult:
    """An assessment covering every outcome the filter has to reason about."""
    return assessment_result(
        [
            check_result(
                "AUTH-001",
                "GET /orders",
                outcome=CheckOutcome.FAIL,
                finding_class=FindingClass.CONFIRMED,
                severity=Severity.HIGH,
            ),
            check_result(
                "CONF-001",
                "GET /health",
                outcome=CheckOutcome.FAIL,
                finding_class=FindingClass.SUSPECTED,
                severity=Severity.LOW,
            ),
            check_result(
                "CONF-002",
                "GET /public",
                outcome=CheckOutcome.NEEDS_REVIEW,
                finding_class=FindingClass.INCONCLUSIVE,
                severity=None,
            ),
            check_result(
                "CONF-003",
                "GET /ok",
                outcome=CheckOutcome.PASS,
                finding_class=FindingClass.NONE,
                severity=None,
            ),
            check_result(
                "INPUT-001",
                "GET /skipped",
                outcome=CheckOutcome.SKIPPED,
                finding_class=FindingClass.NONE,
                severity=None,
            ),
            check_result(
                "RATE-001",
                "GET /errored",
                outcome=CheckOutcome.ERROR,
                finding_class=FindingClass.INCONCLUSIVE,
                severity=None,
            ),
        ]
    )


class TestSchemaVersions:
    def test_the_report_declares_its_own_version(self) -> None:
        report = build_report(assessment_result([check_result("AUTH-001", "GET /orders")]))

        assert report.schema_version == REPORT_SCHEMA_VERSION

    def test_the_source_assessment_version_is_recorded(self) -> None:
        report = build_report(assessment_result([check_result("AUTH-001", "GET /orders")]))

        assert report.source_assessment_schema == ASSESSMENT_SCHEMA_VERSION

    def test_the_intelligence_version_is_none_without_an_analysis(self) -> None:
        report = build_report(assessment_result([check_result("AUTH-001", "GET /orders")]))

        assert report.source_intelligence_schema is None
        assert report.has_intelligence is False

    def test_the_intelligence_version_is_recorded_when_analysed(self) -> None:
        assessment = mixed_results()
        intelligence = analyse(mixed_discovery(), assessment)

        report = build_report(assessment, intelligence)

        assert report.source_intelligence_schema == INTELLIGENCE_SCHEMA_VERSION
        assert report.has_intelligence is True

    def test_the_three_versions_are_independent_fields(self) -> None:
        # A report layout can change without the stored documents changing, so
        # bumping one number must not move the others.
        report = build_report(mixed_results())

        bumped = report.model_copy(update={"schema_version": 99})

        assert set(Report.model_fields) >= {
            "schema_version",
            "source_assessment_schema",
            "source_intelligence_schema",
        }
        assert bumped.schema_version == 99
        assert bumped.source_assessment_schema == report.source_assessment_schema
        assert bumped.source_intelligence_schema == report.source_intelligence_schema

    def test_a_report_rejects_unknown_fields(self) -> None:
        report = build_report(mixed_results())
        payload = report.model_dump(mode="json")
        payload["invented_field"] = True

        with pytest.raises(ValidationError):
            Report.model_validate(payload)

    def test_a_report_round_trips(self) -> None:
        report = build_report(mixed_results())

        restored = Report.model_validate(report.model_dump(mode="json"))

        assert restored.target_name == report.target_name
        assert restored.summary == report.summary
        assert len(restored.results) == len(report.results)


class TestSummaryUsesExistingAggregators:
    def test_distributions_match_the_assessment(self) -> None:
        assessment = mixed_results()

        summary = build_report(assessment, include_all=True).summary

        assert summary.by_outcome == assessment.by_outcome()
        assert summary.by_finding_class == assessment.by_finding_class()
        assert summary.by_category == assessment.by_category()

    def test_finding_counts_come_from_the_finding_class(self) -> None:
        assessment = mixed_results()
        by_class = assessment.by_finding_class()

        summary = build_report(assessment).summary

        assert summary.confirmed_findings == by_class[FindingClass.CONFIRMED]
        assert summary.potential_findings == by_class[FindingClass.SUSPECTED]
        assert summary.confirmed_findings + summary.potential_findings == len(assessment.findings())

    def test_needs_review_is_counted_by_outcome_not_finding_class(self) -> None:
        assessment = mixed_results()

        summary = build_report(assessment).summary

        assert summary.needs_review == assessment.by_outcome()[CheckOutcome.NEEDS_REVIEW]
        assert summary.needs_review == 1

    def test_severity_counts_skip_results_without_one(self) -> None:
        summary = build_report(mixed_results()).summary

        assert summary.by_severity == {Severity.HIGH: 1, Severity.LOW: 1}

    def test_run_statistics_are_carried_over(self) -> None:
        assessment = mixed_results()

        summary = build_report(assessment).summary

        assert summary.endpoints_considered == assessment.endpoints_considered
        assert summary.endpoints_tested == assessment.endpoints_tested
        assert summary.requests_sent == assessment.requests_sent
        assert summary.results_total == len(assessment.results)

    def test_risk_counts_come_from_the_intelligence_aggregators(self) -> None:
        assessment = mixed_results()
        intelligence = analyse(mixed_discovery(), assessment)

        summary = build_report(assessment, intelligence).summary

        assert summary.risks_total == len(intelligence.risks)
        assert summary.confirmed_risks == len(intelligence.confirmed_risks())
        assert summary.attack_paths_total == len(intelligence.attack_paths)
        assert summary.correlations_total == len(intelligence.correlations)
        for band, count in intelligence.band_counts().items():
            assert summary.risk_bands[band] == count

    def test_risk_counts_are_zero_without_an_analysis(self) -> None:
        summary = build_report(mixed_results()).summary

        assert summary.risks_total == 0
        assert summary.confirmed_risks == 0
        assert summary.attack_paths_total == 0
        assert summary.correlations_total == 0
        assert summary.risk_bands == {}

    def test_findings_and_risks_are_not_summed(self) -> None:
        # A risk is derived from check results, so adding the two would count
        # the same observation twice. They are separate fields and there is no
        # combined total anywhere on the summary.
        assessment = mixed_results()
        intelligence = analyse(mixed_discovery(), assessment)

        summary = build_report(assessment, intelligence).summary
        names = set(ReportSummary.model_fields)

        assert "confirmed_findings" in names
        assert "risks_total" in names
        assert not any("total_issues" in name or "all_findings" in name for name in names)
        assert summary.confirmed_findings != summary.confirmed_findings + summary.risks_total or (
            summary.risks_total == 0
        )

    def test_fully_evidenced_paths_are_counted_separately(self) -> None:
        assessment = mixed_results()
        intelligence = analyse(mixed_discovery(), assessment)

        summary = build_report(assessment, intelligence).summary

        expected = sum(1 for path in intelligence.attack_paths if path.fully_evidenced)
        assert summary.fully_evidenced_paths == expected
        assert summary.fully_evidenced_paths <= summary.attack_paths_total


class TestResultFiltering:
    def test_findings_and_reviews_are_shown_by_default(self) -> None:
        report = build_report(mixed_results())

        shown = {item.check_id for item in report.results}
        assert shown == {"AUTH-001", "CONF-001", "CONF-002"}

    def test_passed_skipped_and_errored_are_hidden_by_default(self) -> None:
        report = build_report(mixed_results())

        outcomes = {item.outcome for item in report.results}
        assert CheckOutcome.PASS not in outcomes
        assert CheckOutcome.SKIPPED not in outcomes
        assert CheckOutcome.ERROR not in outcomes

    def test_include_all_shows_every_result(self) -> None:
        assessment = mixed_results()

        report = build_report(assessment, include_all=True)

        assert len(report.results) == len(assessment.results)
        assert report.include_all is True

    def test_filtering_does_not_change_the_summary(self) -> None:
        assessment = mixed_results()

        filtered = build_report(assessment)
        everything = build_report(assessment, include_all=True)

        assert filtered.summary.results_total == everything.summary.results_total
        assert filtered.summary.by_outcome == everything.summary.by_outcome
        assert filtered.summary.results_displayed < everything.summary.results_displayed

    def test_a_filtered_report_says_so(self) -> None:
        report = build_report(mixed_results())

        assert FILTERED_NOTE in report.notes

    def test_an_unfiltered_report_does_not_claim_filtering(self) -> None:
        report = build_report(mixed_results(), include_all=True)

        assert FILTERED_NOTE not in report.notes

    def test_results_are_ordered_most_severe_first(self) -> None:
        report = build_report(mixed_results(), include_all=True)

        ranks = [item.severity.rank if item.severity is not None else -1 for item in report.results]
        assert ranks == sorted(ranks, reverse=True)

    def test_ordering_is_deterministic(self) -> None:
        assessment = mixed_results()

        first = build_report(assessment, include_all=True)
        second = build_report(assessment, include_all=True)

        assert [item.result_id for item in first.results] == [
            item.result_id for item in second.results
        ]


class TestEmptyAndAbsentInputs:
    def test_a_report_with_no_results_is_valid(self) -> None:
        report = build_report(assessment_result([]))

        assert report.results == []
        assert report.summary.results_total == 0
        assert report.has_findings is False

    def test_a_report_with_no_findings_shows_nothing_but_counts_everything(self) -> None:
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

        report = build_report(assessment)

        assert report.results == []
        assert report.summary.results_total == 1
        assert report.summary.by_outcome[CheckOutcome.PASS] == 1
        assert report.has_findings is False

    def test_an_assessment_only_report_records_the_omission(self) -> None:
        report = build_report(mixed_results())

        assert NO_INTELLIGENCE_NOTE in report.notes
        assert report.risks == []
        assert report.attack_paths == []
        assert report.correlations == []
        assert report.analysed_at is None

    def test_analysis_notes_are_carried_into_the_report(self) -> None:
        assessment = mixed_results()
        intelligence = analyse(mixed_discovery(), assessment)

        report = build_report(assessment, intelligence)

        for note in intelligence.notes:
            assert note in report.notes
        assert NO_INTELLIGENCE_NOTE not in report.notes

    def test_the_standing_caveat_is_always_present(self) -> None:
        assert NOT_A_VULNERABILITY_NOTE in build_report(assessment_result([])).notes
        assert NOT_A_VULNERABILITY_NOTE in build_report(mixed_results()).notes

    def test_an_exhausted_budget_is_disclosed(self) -> None:
        assessment = mixed_results()
        exhausted = assessment.model_copy(update={"budget_exhausted": True})

        report = build_report(exhausted)

        assert any("budget was exhausted" in note for note in report.notes)


class TestPurity:
    def test_building_does_not_mutate_the_assessment(self) -> None:
        assessment = mixed_results()
        before = assessment.model_dump(mode="json")

        build_report(assessment, include_all=True)

        assert assessment.model_dump(mode="json") == before

    def test_building_does_not_mutate_the_intelligence_report(self) -> None:
        assessment = mixed_results()
        intelligence = analyse(mixed_discovery(), assessment)
        before = intelligence.model_dump(mode="json")

        build_report(assessment, intelligence)

        assert intelligence.model_dump(mode="json") == before

    def test_appending_to_report_lists_does_not_reach_the_sources(self) -> None:
        assessment = mixed_results()
        intelligence = analyse(mixed_discovery(), assessment)
        report = build_report(assessment, intelligence)

        report.risks.clear()
        report.correlations.clear()
        report.attack_paths.clear()

        assert len(intelligence.risks) == len(analyse(mixed_discovery(), assessment).risks)


class TestIdentityFields:
    def test_target_identity_comes_from_the_assessment(self) -> None:
        assessment = assessment_result(
            [check_result("AUTH-001", "GET /orders")],
            target_name="acme",
            base_url="https://api.acme.test/v1",
        )

        report = build_report(assessment)

        assert report.target_name == "acme"
        assert report.target_base_url == "https://api.acme.test/v1"
        assert report.assessment_started_at == assessment.started_at

    def test_the_specification_digest_is_carried_when_present(self) -> None:
        assessment = mixed_results().model_copy(update={"specification_sha256": "a" * 64})

        assert build_report(assessment).specification_sha256 == "a" * 64

    def test_checks_run_are_listed(self) -> None:
        assessment = mixed_results()

        assert build_report(assessment).checks_run == assessment.checks_run

    def test_risk_bands_validate_as_the_enum(self) -> None:
        assessment = mixed_results()
        intelligence = analyse(mixed_discovery(), assessment)

        summary = build_report(assessment, intelligence).summary

        for key in summary.risk_bands:
            assert isinstance(key, RiskBand)

    def test_confidence_is_preserved_on_displayed_results(self) -> None:
        assessment = assessment_result(
            [check_result("AUTH-001", "GET /orders", confidence=Confidence.CONFIRMED)]
        )

        report = build_report(assessment)

        assert report.results[0].confidence is Confidence.CONFIRMED

    def test_categories_survive_into_the_report(self) -> None:
        assessment = assessment_result(
            [check_result("CONF-001", "GET /x", category=CheckCategory.CONFIGURATION)]
        )

        report = build_report(assessment)

        assert report.results[0].category is CheckCategory.CONFIGURATION


class TestOwaspDistribution:
    def test_empty_assessment_produces_empty_by_owasp(self) -> None:
        summary = build_report(assessment_result([])).summary

        assert summary.by_owasp == {}

    def test_results_without_owasp_are_excluded(self) -> None:
        # check_result() does not set owasp, so by_owasp must be empty even
        # though results exist.
        assessment = assessment_result([check_result("AUTH-001", "GET /x")])

        summary = build_report(assessment, include_all=True).summary

        assert summary.by_owasp == {}

    def test_single_result_with_owasp_is_counted(self) -> None:
        result = check_result("AUTH-001", "GET /x").model_copy(
            update={"owasp": OwaspApiCategory.API2_BROKEN_AUTHENTICATION}
        )
        assessment = assessment_result([result])

        summary = build_report(assessment, include_all=True).summary

        assert summary.by_owasp == {OwaspApiCategory.API2_BROKEN_AUTHENTICATION: 1}

    def test_multiple_results_sharing_a_category_accumulate(self) -> None:
        results = [
            check_result("AUTH-001", "GET /x").model_copy(
                update={"owasp": OwaspApiCategory.API1_BOLA}
            ),
            check_result("AUTH-002", "GET /y").model_copy(
                update={"owasp": OwaspApiCategory.API1_BOLA}
            ),
        ]
        assessment = assessment_result(results)

        summary = build_report(assessment, include_all=True).summary

        assert summary.by_owasp[OwaspApiCategory.API1_BOLA] == 2

    def test_results_across_different_categories_are_counted_separately(self) -> None:
        results = [
            check_result("AUTH-001", "GET /x").model_copy(
                update={"owasp": OwaspApiCategory.API1_BOLA}
            ),
            check_result("CONF-001", "GET /y").model_copy(
                update={"owasp": OwaspApiCategory.API8_MISCONFIGURATION}
            ),
        ]
        assessment = assessment_result(results)

        summary = build_report(assessment, include_all=True).summary

        assert summary.by_owasp[OwaspApiCategory.API1_BOLA] == 1
        assert summary.by_owasp[OwaspApiCategory.API8_MISCONFIGURATION] == 1
        assert len(summary.by_owasp) == 2

    def test_mixed_owasp_and_no_owasp_only_counts_mapped_results(self) -> None:
        results = [
            check_result("AUTH-001", "GET /x").model_copy(
                update={"owasp": OwaspApiCategory.API5_BFLA}
            ),
            check_result("AUTH-002", "GET /y"),  # no owasp
        ]
        assessment = assessment_result(results)

        summary = build_report(assessment, include_all=True).summary

        assert summary.by_owasp == {OwaspApiCategory.API5_BFLA: 1}

    def test_by_owasp_does_not_affect_existing_summary_fields(self) -> None:
        # Regression: adding by_owasp must not change any other count.
        assessment = assessment_result(
            [
                check_result("AUTH-001", "GET /x").model_copy(
                    update={"owasp": OwaspApiCategory.API2_BROKEN_AUTHENTICATION}
                )
            ]
        )
        report = build_report(assessment, include_all=True)

        assert report.summary.results_total == 1
        assert report.summary.confirmed_findings == 1
        assert report.summary.by_category != {}
        assert report.summary.by_owasp == {OwaspApiCategory.API2_BROKEN_AUTHENTICATION: 1}

    def test_by_owasp_keys_are_owasp_api_category_instances(self) -> None:
        result = check_result("AUTH-001", "GET /x").model_copy(
            update={"owasp": OwaspApiCategory.API7_SSRF}
        )
        summary = build_report(assessment_result([result]), include_all=True).summary

        for key in summary.by_owasp:
            assert isinstance(key, OwaspApiCategory)
