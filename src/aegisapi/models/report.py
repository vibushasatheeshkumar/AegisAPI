"""Models for a generated report.

A report is a **view**, not a new source of truth. It embeds the existing
:class:`~aegisapi.models.assessment.CheckResult`,
:class:`~aegisapi.models.intelligence.PrioritisedRisk`,
:class:`~aegisapi.models.intelligence.Correlation`, and
:class:`~aegisapi.models.intelligence.AttackPath` models rather than copying
their fields, so there is exactly one definition of what a finding is and a
report cannot drift from the documents it was built from.

Three version numbers are kept, deliberately separate:

* :data:`REPORT_SCHEMA_VERSION` - the layout of this envelope.
* ``source_assessment_schema`` - the version of the assessment it was built
  from.
* ``source_intelligence_schema`` - the version of the intelligence document,
  or ``None`` when the report was produced without one.

The report layout can change without the stored documents changing, and a
consumer needs to know which input formats produced a given file. Collapsing
the three into one number would lose that.

**Counting discipline.** ``ReportSummary`` reports the whole assessment, even
when the report displays a filtered subset of results, and it never adds
findings to risks as though they were separate confirmed vulnerabilities: a
risk is derived *from* findings, so the two overlap by construction. Confirmed
and potential are counted apart, and attack paths are counted separately again
because a path is inference about reachability rather than an observation.
"""

from __future__ import annotations

from datetime import UTC, datetime

from pydantic import BaseModel, ConfigDict, Field, field_validator

from aegisapi.models.assessment import (
    CheckCategory,
    CheckOutcome,
    CheckResult,
    FindingClass,
    OwaspApiCategory,
)
from aegisapi.models.common import Severity
from aegisapi.models.efficiency import EfficiencySummary
from aegisapi.models.intelligence import (
    AttackPath,
    Correlation,
    PrioritisedRisk,
    RiskBand,
)

REPORT_SCHEMA_VERSION = 1
"""Format version of a generated report envelope."""

_VALID_COMPLETION_STATUSES = frozenset({"complete", "partial_timeout", "partial_budget"})


class BudgetSummary(BaseModel):
    """Budget usage and limit outcomes for one scan.

    Collected from :class:`~aegisapi.models.assessment.AssessmentResult` by the
    report builder and embedded in the report so consumers do not have to
    interpret raw counts themselves.
    """

    model_config = ConfigDict(extra="forbid")

    requests_sent: int = Field(default=0, ge=0, description="Requests the assessment transmitted.")
    request_budget: int = Field(default=0, ge=0, description="Total request budget for the run.")
    scan_timed_out: bool = Field(
        default=False, description="Whether the scan stopped because scan_timeout_seconds was hit."
    )
    endpoints_at_limit: list[str] = Field(
        default_factory=list,
        description="Endpoint keys that reached the per-endpoint request cap.",
    )
    checks_timed_out: int = Field(
        default=0, ge=0, description="Checks that exceeded check_timeout_seconds."
    )
    completion_status: str = Field(
        default="complete",
        description=(
            "One of 'complete', 'partial_timeout' (scan_timeout_seconds reached), "
            "or 'partial_budget' (total request budget exhausted)."
        ),
    )

    @field_validator("completion_status")
    @classmethod
    def _validate_status(cls, v: str) -> str:
        if v not in _VALID_COMPLETION_STATUSES:
            raise ValueError(
                f"completion_status must be one of {sorted(_VALID_COMPLETION_STATUSES)}, got {v!r}"
            )
        return v


class ReportSummary(BaseModel):
    """Headline counts for one report.

    Every count describes the **entire** assessment, not the subset of results
    the report chose to display, so a filtered report still states how much was
    examined. The distribution maps are produced by the source documents' own
    aggregators, so they cannot disagree with the documents.
    """

    model_config = ConfigDict(extra="forbid")

    confirmed_findings: int = Field(
        default=0,
        ge=0,
        description="Results whose finding class is 'confirmed'.",
    )
    potential_findings: int = Field(
        default=0,
        ge=0,
        description="Results whose finding class is 'suspected'.",
    )
    needs_review: int = Field(
        default=0,
        ge=0,
        description="Results with the 'needs_review' outcome, whatever their finding class.",
    )
    results_total: int = Field(
        default=0, ge=0, description="Every result the assessment recorded, including skips."
    )
    results_displayed: int = Field(
        default=0, ge=0, description="Results this report actually shows."
    )
    by_severity: dict[Severity, int] = Field(
        default_factory=dict,
        description=(
            "Results that carry a severity, counted per level. A check sets one only "
            "when a finding justifies it, so a result without one is not counted here."
        ),
    )
    by_finding_class: dict[FindingClass, int] = Field(
        default_factory=dict, description="All results per finding class."
    )
    by_outcome: dict[CheckOutcome, int] = Field(
        default_factory=dict, description="All results per outcome."
    )
    by_category: dict[CheckCategory, int] = Field(
        default_factory=dict, description="All results per security category."
    )
    by_owasp: dict[OwaspApiCategory, int] = Field(
        default_factory=dict,
        description=(
            "Results with an OWASP API Security Top 10 category, counted per category. "
            "Results without an OWASP mapping are not counted here."
        ),
    )
    risk_bands: dict[RiskBand, int] = Field(
        default_factory=dict, description="Prioritised risks per band. Empty without intelligence."
    )
    risks_total: int = Field(default=0, ge=0, description="Prioritised risks in the report.")
    confirmed_risks: int = Field(
        default=0,
        ge=0,
        description="Risks whose security claim direct evidence establishes.",
    )
    attack_paths_total: int = Field(
        default=0, ge=0, description="Potential attack paths. Inference, not observation."
    )
    fully_evidenced_paths: int = Field(
        default=0,
        ge=0,
        description="Paths whose every step is observed or documented. Still not exploits.",
    )
    correlations_total: int = Field(
        default=0, ge=0, description="Cross-endpoint correlations in the report."
    )
    endpoints_considered: int = Field(
        default=0, ge=0, description="Operations the engine looked at."
    )
    endpoints_tested: int = Field(
        default=0, ge=0, description="Operations that met at least one check's preconditions."
    )
    requests_sent: int = Field(default=0, ge=0, description="Requests the assessment transmitted.")
    request_budget: int = Field(default=0, ge=0, description="Budget the run was given.")
    budget_exhausted: bool = Field(
        default=False, description="Whether the run stopped because the budget ran out."
    )


class Report(BaseModel):
    """A rendered-ready view of one assessment, optionally with its analysis.

    Built by :func:`aegisapi.reporting.build.build_report` from documents that
    are already on disk. Nothing here is re-derived from an API: a report sends
    no requests and runs no checks.

    It cannot contain a credential, because every field it embeds comes from a
    model that structurally cannot hold one - evidence is built from an
    already-redacted response.
    """

    model_config = ConfigDict(extra="forbid")

    schema_version: int = Field(default=REPORT_SCHEMA_VERSION, ge=1)
    generated_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC), description="When the report was built (UTC)."
    )
    aegisapi_version: str = Field(description="AegisAPI version that produced the report.")
    target_name: str = Field(description="Target the report covers.")
    target_base_url: str = Field(description="Target base URL recorded by the assessment.")
    specification_sha256: str | None = Field(
        default=None,
        description="Digest of the specification the endpoints came from, when recorded.",
    )
    assessment_started_at: datetime | None = Field(
        default=None, description="When the assessment run started (UTC)."
    )
    analysed_at: datetime | None = Field(
        default=None, description="When risk analysis ran (UTC), when intelligence was supplied."
    )
    include_all: bool = Field(
        default=False,
        description="Whether every result is shown, rather than findings and reviews only.",
    )
    summary: ReportSummary = Field(
        default_factory=ReportSummary, description="Counts describing the whole assessment."
    )
    results: list[CheckResult] = Field(
        default_factory=list, description="The check results this report displays."
    )
    risks: list[PrioritisedRisk] = Field(
        default_factory=list, description="Prioritised risks, highest priority first."
    )
    correlations: list[Correlation] = Field(
        default_factory=list, description="Cross-endpoint conclusions."
    )
    attack_paths: list[AttackPath] = Field(
        default_factory=list, description="Potential multi-step relationships. Not exploits."
    )
    budget_summary: BudgetSummary | None = Field(
        default=None,
        description="Budget usage and limit outcomes for this scan.",
    )
    efficiency_summary: EfficiencySummary | None = Field(
        default=None,
        description="M5 efficiency metrics: requests saved, checks deduplicated, and prioritization.",
    )
    notes: list[str] = Field(
        default_factory=list,
        description="Limits that qualify this report, including any from the analysis.",
    )
    checks_run: list[str] = Field(
        default_factory=list, description="Check identifiers the assessment selected."
    )
    source_assessment_schema: int = Field(
        ge=1, description="Schema version of the assessment this was built from."
    )
    source_intelligence_schema: int | None = Field(
        default=None,
        description="Schema version of the intelligence document, or None if there was none.",
    )

    @property
    def has_intelligence(self) -> bool:
        """``True`` when the report was built with an intelligence document."""
        return self.source_intelligence_schema is not None

    @property
    def has_findings(self) -> bool:
        """``True`` when at least one confirmed or potential finding was recorded."""
        return bool(self.summary.confirmed_findings or self.summary.potential_findings)


__all__ = [
    "REPORT_SCHEMA_VERSION",
    "BudgetSummary",
    "EfficiencySummary",
    "Report",
    "ReportSummary",
]
