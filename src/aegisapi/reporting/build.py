"""Composing a report from documents that already exist.

:func:`build_report` is pure: it reads no file, opens no socket, runs no check,
and writes nothing back to the models it is given. Everything it produces is
derived from an assessment and, optionally, an intelligence report.

Two decisions are worth stating, because both are easy to get subtly wrong.

**Filtering changes what is shown, never what is counted.** By default a report
displays findings - confirmed or suspected - plus anything whose outcome is
``NEEDS_REVIEW``, because that outcome exists precisely to mark something a
human should look at. Passing ``include_all`` adds the rest. Either way
:class:`~aegisapi.models.report.ReportSummary` describes the whole assessment,
so a reader can always see how much was examined to produce what they are
looking at.

**Findings and risks are not added together.** A risk is derived *from* check
results, so a report that summed them would double-count the same observation
and overstate how much was found. Confirmed findings, potential findings, and
risks are counted separately and never combined, and attack paths are counted
apart from both because a path is an inference about reachability rather than
something that was observed.
"""

from __future__ import annotations

from aegisapi import __version__
from aegisapi.models.assessment import (
    AssessmentResult,
    CheckOutcome,
    CheckResult,
    FindingClass,
    OwaspApiCategory,
)
from aegisapi.models.common import Severity
from aegisapi.models.intelligence import IntelligenceReport, RiskBand
from aegisapi.models.efficiency import EfficiencySummary
from aegisapi.models.report import BudgetSummary, Report, ReportSummary
from aegisapi.testing.efficiency import EfficiencyTracker

NO_INTELLIGENCE_NOTE = (
    "No risk analysis was included, so this report contains check results only: "
    "no relationship graph, no prioritised risks, and no attack paths. "
    "Run 'aegisapi risk analyze <target> --save' and generate the report again."
)
"""Recorded when a report is built from an assessment alone."""

FILTERED_NOTE = (
    "This report shows findings and results needing review. Passed, skipped, and "
    "errored results were recorded by the assessment but are not displayed here; "
    "the summary counts cover all of them. Use --include-all to show every result."
)
"""Recorded when the displayed results are a subset of the assessment."""

NOT_A_VULNERABILITY_NOTE = (
    "A failed check is not a confirmed vulnerability, and an attack path is not an "
    "exploit. Read each result's finding class, confidence, and limitations before "
    "acting on it."
)
"""Always recorded. The discipline the whole tool is built around."""

_FINDING_CLASS_ORDER: dict[FindingClass, int] = {
    FindingClass.CONFIRMED: 0,
    FindingClass.SUSPECTED: 1,
    FindingClass.INFORMATIONAL: 2,
    FindingClass.INCONCLUSIVE: 3,
    FindingClass.NONE: 4,
}
"""Display order for finding classes: strongest claim first."""


def _is_displayed(result: CheckResult, *, include_all: bool) -> bool:
    """Whether a result appears in the report body.

    ``is_finding`` covers the confirmed and suspected classes;
    ``NEEDS_REVIEW`` is an *outcome*, so it is checked separately rather than
    assumed to imply a finding class.
    """
    if include_all:
        return True
    return result.is_finding or result.outcome is CheckOutcome.NEEDS_REVIEW


def _display_key(result: CheckResult) -> tuple[int, int, str, str]:
    """Sort key putting the most serious, best-supported results first.

    Severity descends, then the strength of the claim, then the check and
    operation identifiers so the order is total and a rebuild of the same
    inputs produces the same file.
    """
    severity_rank = result.severity.rank if result.severity is not None else -1
    return (
        -severity_rank,
        _FINDING_CLASS_ORDER[result.finding_class],
        result.check_id,
        result.endpoint_key,
    )


def _owasp_counts(assessment: AssessmentResult) -> dict[OwaspApiCategory, int]:
    """Count results that carry an OWASP API category, per category.

    Results without a mapping are excluded entirely; they do not inflate any
    category's count. Only categories that actually appear are returned, so an
    empty mapping means no result carried an OWASP tag rather than that
    counting failed.
    """
    counts: dict[OwaspApiCategory, int] = {}
    for result in assessment.results:
        if result.owasp is None:
            continue
        counts[result.owasp] = counts.get(result.owasp, 0) + 1
    return counts


def _severity_counts(assessment: AssessmentResult) -> dict[Severity, int]:
    """Count results carrying a severity, per level.

    Only levels that actually occur appear, so an empty mapping means no result
    justified a severity rather than that the counting failed.
    """
    counts: dict[Severity, int] = {}
    for result in assessment.results:
        if result.severity is None:
            continue
        counts[result.severity] = counts.get(result.severity, 0) + 1
    return counts


def _build_summary(
    assessment: AssessmentResult,
    intelligence: IntelligenceReport | None,
    *,
    displayed: int,
) -> ReportSummary:
    """Summarise the whole assessment, using the documents' own aggregators."""
    by_finding_class = assessment.by_finding_class()
    by_outcome = assessment.by_outcome()

    risk_bands: dict[RiskBand, int] = {}
    risks_total = 0
    confirmed_risks = 0
    attack_paths_total = 0
    fully_evidenced_paths = 0
    correlations_total = 0

    if intelligence is not None:
        risk_bands = intelligence.band_counts()
        risks_total = len(intelligence.risks)
        confirmed_risks = len(intelligence.confirmed_risks())
        attack_paths_total = len(intelligence.attack_paths)
        fully_evidenced_paths = sum(1 for path in intelligence.attack_paths if path.fully_evidenced)
        correlations_total = len(intelligence.correlations)

    return ReportSummary(
        confirmed_findings=by_finding_class[FindingClass.CONFIRMED],
        potential_findings=by_finding_class[FindingClass.SUSPECTED],
        needs_review=by_outcome[CheckOutcome.NEEDS_REVIEW],
        results_total=len(assessment.results),
        results_displayed=displayed,
        by_severity=_severity_counts(assessment),
        by_finding_class=by_finding_class,
        by_outcome=by_outcome,
        by_category=assessment.by_category(),
        by_owasp=_owasp_counts(assessment),
        risk_bands=risk_bands,
        risks_total=risks_total,
        confirmed_risks=confirmed_risks,
        attack_paths_total=attack_paths_total,
        fully_evidenced_paths=fully_evidenced_paths,
        correlations_total=correlations_total,
        endpoints_considered=assessment.endpoints_considered,
        endpoints_tested=assessment.endpoints_tested,
        requests_sent=assessment.requests_sent,
        request_budget=assessment.request_budget,
        budget_exhausted=assessment.budget_exhausted,
    )


def _build_notes(
    assessment: AssessmentResult,
    intelligence: IntelligenceReport | None,
    *,
    hidden: int,
) -> list[str]:
    """Collect the qualifications that belong on this report.

    The analysis's own notes come first, because they describe limits of the
    conclusions rather than of the report, and are then followed by whatever
    the report itself has to disclose.
    """
    notes: list[str] = [NOT_A_VULNERABILITY_NOTE]
    if intelligence is None:
        notes.append(NO_INTELLIGENCE_NOTE)
    else:
        notes.extend(intelligence.notes)
    if hidden:
        notes.append(FILTERED_NOTE)
    if assessment.budget_exhausted:
        notes.append(
            "The request budget was exhausted, so some checks did not run. "
            "Absence of a finding here is not evidence of its absence."
        )
    return notes


def _build_budget_summary(assessment: AssessmentResult) -> BudgetSummary:
    """Derive the budget summary from an assessment result."""
    scan_timed_out = getattr(assessment, "scan_timed_out", False)
    budget_exhausted = assessment.budget_exhausted

    if scan_timed_out:
        completion_status = "partial_timeout"
    elif budget_exhausted:
        completion_status = "partial_budget"
    else:
        completion_status = "complete"

    return BudgetSummary(
        requests_sent=assessment.requests_sent,
        request_budget=assessment.request_budget,
        scan_timed_out=scan_timed_out,
        endpoints_at_limit=list(getattr(assessment, "endpoints_at_limit", [])),
        checks_timed_out=getattr(assessment, "checks_timed_out", 0),
        completion_status=completion_status,
    )


def _build_efficiency_summary(tracker: EfficiencyTracker | None) -> EfficiencySummary | None:
    """Build an EfficiencySummary from a tracker, or None when tracking was disabled."""
    if tracker is None:
        return None
    return tracker.to_summary()


def build_report(
    assessment: AssessmentResult,
    intelligence: IntelligenceReport | None = None,
    *,
    include_all: bool = False,
    efficiency_tracker: EfficiencyTracker | None = None,
) -> Report:
    """Compose a report from an assessment and an optional analysis.

    Args:
        assessment: The check results to report on.
        intelligence: Risk analysis for the same target, when it exists.
            Without it the report carries results only, and says so in its
            notes rather than leaving the omission to be inferred.
        include_all: Show every result instead of findings and reviews only.
            The summary is unaffected; it always describes the whole
            assessment.

    Returns:
        A :class:`~aegisapi.models.report.Report`. Pure: the supplied documents
        are read and never modified.
    """
    displayed = sorted(
        (item for item in assessment.results if _is_displayed(item, include_all=include_all)),
        key=_display_key,
    )
    hidden = len(assessment.results) - len(displayed)

    return Report(
        aegisapi_version=__version__,
        target_name=assessment.target_name,
        target_base_url=assessment.target_base_url,
        specification_sha256=assessment.specification_sha256,
        assessment_started_at=assessment.started_at,
        analysed_at=intelligence.analysed_at if intelligence is not None else None,
        include_all=include_all,
        summary=_build_summary(assessment, intelligence, displayed=len(displayed)),
        budget_summary=_build_budget_summary(assessment),
        efficiency_summary=_build_efficiency_summary(efficiency_tracker),
        results=displayed,
        risks=list(intelligence.risks) if intelligence is not None else [],
        correlations=list(intelligence.correlations) if intelligence is not None else [],
        attack_paths=list(intelligence.attack_paths) if intelligence is not None else [],
        notes=_build_notes(assessment, intelligence, hidden=hidden),
        checks_run=list(assessment.checks_run),
        source_assessment_schema=assessment.schema_version,
        source_intelligence_schema=(
            intelligence.schema_version if intelligence is not None else None
        ),
    )


__all__ = [
    "FILTERED_NOTE",
    "NOT_A_VULNERABILITY_NOTE",
    "NO_INTELLIGENCE_NOTE",
    "build_report",
    "_build_budget_summary",
    "_build_efficiency_summary",
]
