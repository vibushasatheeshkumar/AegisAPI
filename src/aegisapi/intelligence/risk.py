"""Deterministic, explainable risk prioritisation.

Scoring here is a published table, not a tuned formula. Every contribution is
a named :class:`~aegisapi.models.intelligence.RiskFactor` carrying its own
points and the reason it applied, so a score can be read back as an argument
and disagreed with.

Three rules the model will not break:

1. **Severity, confidence, and evidence strength stay separate.** A
   high-severity, low-confidence item scores below a confirmed medium one, but
   its severity is still reported as high. Collapsing them would hide which
   part is uncertain.
2. **Breadth never raises severity.** Affecting six operations instead of one
   adds a small, capped priority contribution - it says "look here first", not
   "this is worse". Severity comes from impact, not from counting.
3. **Unverified means unverified.** A suspected finding cannot reach the
   confirmed band, whatever else supports it, and an unverified attack path is
   never described as exploitable.
"""

from __future__ import annotations

from collections import defaultdict

from aegisapi.models.assessment import (
    AssessmentResult,
    CheckResult,
    FindingClass,
)
from aegisapi.models.common import Confidence, Severity
from aegisapi.models.intelligence import (
    Correlation,
    PrioritisedRisk,
    Provenance,
    RiskBand,
    RiskFactor,
)

SEVERITY_POINTS: dict[Severity, float] = {
    Severity.CRITICAL: 50.0,
    Severity.HIGH: 40.0,
    Severity.MEDIUM: 25.0,
    Severity.LOW: 12.0,
    Severity.INFO: 4.0,
}
"""Base points for impact if the finding is real.

The dominant term, because what matters most is how bad a problem would be.
"""

FINDING_CLASS_MULTIPLIER: dict[FindingClass, float] = {
    FindingClass.CONFIRMED: 1.0,
    FindingClass.SUSPECTED: 0.6,
    FindingClass.INFORMATIONAL: 0.25,
    FindingClass.INCONCLUSIVE: 0.1,
    FindingClass.NONE: 0.0,
}
"""How much of the base severity survives, given how well it is established.

A suspected finding keeps 60% of its impact score: enough to outrank a
confirmed trivial issue, not enough to outrank a confirmed serious one.
"""

CONFIDENCE_POINTS: dict[Confidence, float] = {
    Confidence.CONFIRMED: 12.0,
    Confidence.HIGH: 8.0,
    Confidence.MEDIUM: 4.0,
    Confidence.LOW: 0.0,
}
"""Points for how sure the check was of its own conclusion."""

EVIDENCE_POINTS_EACH = 3.0
MAX_EVIDENCE_POINTS = 9.0
"""Points per direct observation, capped.

Capped because a check that happened to record four responses is not three
times better supported than one that recorded two.
"""

BREADTH_POINTS_EACH = 1.5
MAX_BREADTH_POINTS = 6.0
"""Points per additional affected operation, capped hard.

Deliberately the smallest term in the model. Breadth changes where to look
first; it does not change how bad a problem is.
"""

UNAUTHENTICATED_REACHABLE_POINTS = 8.0
"""Points when the affected operation needs no credential to reach.

Something reachable without authentication has a larger population of
potential callers, which is a genuine exploitability difference rather than a
guess.
"""

CORRELATION_CONFIRMED_POINTS = 6.0
CORRELATION_SUPPORTING_POINTS = 2.0
"""Points for correlations, which add context rather than impact."""

BAND_THRESHOLDS: tuple[tuple[float, RiskBand], ...] = (
    (70.0, RiskBand.CRITICAL),
    (50.0, RiskBand.HIGH),
    (30.0, RiskBand.MEDIUM),
    (12.0, RiskBand.LOW),
    (0.0, RiskBand.INFORMATIONAL),
)
"""Score thresholds for each priority band, highest first."""

MAX_SCORE = 100.0


def band_for(score: float) -> RiskBand:
    """Map a score onto its priority band."""
    for threshold, band in BAND_THRESHOLDS:
        if score >= threshold:
            return band
    return RiskBand.INFORMATIONAL  # pragma: no cover - last threshold is 0


def _unauthenticated_reachable(result: CheckResult, anonymous_endpoints: set[str]) -> bool:
    """Whether the affected operation is documented as needing no credential."""
    return result.endpoint_key in anonymous_endpoints


def score_result(
    result: CheckResult,
    *,
    correlations: list[Correlation],
    anonymous_endpoints: set[str],
    related_endpoints: set[str],
) -> tuple[float, list[RiskFactor]]:
    """Score one finding, returning the score and every contribution.

    The factors are the output that matters. A score without them is a number
    nobody can argue with, which is worse than useless in a security report.
    """
    factors: list[RiskFactor] = []
    severity = result.severity or Severity.INFO

    base = SEVERITY_POINTS[severity]
    multiplier = FINDING_CLASS_MULTIPLIER[result.finding_class]
    impact = base * multiplier
    factors.append(
        RiskFactor(
            name="impact",
            points=round(impact, 2),
            reason=(
                f"severity {severity.value} is worth {base:g}, scaled by "
                f"{multiplier:g} because the finding is {result.finding_class.value}"
            ),
        )
    )

    confidence_points = CONFIDENCE_POINTS[result.confidence]
    if confidence_points:
        factors.append(
            RiskFactor(
                name="check_confidence",
                points=confidence_points,
                reason=f"the check reported {result.confidence.value} confidence",
            )
        )

    direct = len(result.evidence)
    if direct:
        points = min(direct * EVIDENCE_POINTS_EACH, MAX_EVIDENCE_POINTS)
        factors.append(
            RiskFactor(
                name="evidence_strength",
                points=points,
                reason=(
                    f"{direct} direct observation(s) recorded, worth "
                    f"{EVIDENCE_POINTS_EACH:g} each up to {MAX_EVIDENCE_POINTS:g}"
                ),
            )
        )

    if _unauthenticated_reachable(result, anonymous_endpoints):
        factors.append(
            RiskFactor(
                name="unauthenticated_reach",
                points=UNAUTHENTICATED_REACHABLE_POINTS,
                reason=(
                    "the affected operation is documented as callable without "
                    "credentials, so more callers can reach it"
                ),
            )
        )

    extra = max(len(related_endpoints) - 1, 0)
    if extra:
        points = min(extra * BREADTH_POINTS_EACH, MAX_BREADTH_POINTS)
        factors.append(
            RiskFactor(
                name="breadth",
                points=points,
                reason=(
                    f"{extra} related operation(s) share the affected resource, worth "
                    f"{BREADTH_POINTS_EACH:g} each up to {MAX_BREADTH_POINTS:g}; "
                    "breadth affects priority only, never severity"
                ),
            )
        )

    for correlation in correlations:
        points = (
            CORRELATION_CONFIRMED_POINTS if correlation.confirmed else CORRELATION_SUPPORTING_POINTS
        )
        factors.append(
            RiskFactor(
                name=f"correlation:{correlation.kind}",
                points=points,
                reason=(
                    f"{'confirmed' if correlation.confirmed else 'supporting'} correlation: "
                    f"{correlation.title}"
                ),
            )
        )

    total = min(sum(item.points for item in factors), MAX_SCORE)
    return round(max(total, 0.0), 2), factors


def _why_it_matters(result: CheckResult, related: set[str]) -> str:
    """State the consequence in terms of what was actually established."""
    if result.finding_class is FindingClass.CONFIRMED:
        lead = "This was established by direct observation, not inferred."
    elif result.finding_class is FindingClass.SUSPECTED:
        lead = "This is indicated but not established; the evidence is suggestive."
    else:
        lead = "This is context rather than a demonstrated weakness."

    breadth = ""
    if len(related) > 1:
        breadth = (
            f" {len(related) - 1} other operation(s) are documented as acting on the "
            "same resource and are the natural place to check next."
        )
    return f"{lead} {result.explanation}{breadth}".strip()


def build_risks(
    assessment: AssessmentResult,
    correlations: list[Correlation],
    *,
    anonymous_endpoints: set[str],
    resource_groups: dict[str, set[str]],
) -> list[PrioritisedRisk]:
    """Turn findings and correlations into a prioritised list.

    Sorted by score, then by severity, then by identifier, so the order is
    stable across runs over unchanged inputs.
    """
    by_endpoint: dict[str, set[str]] = defaultdict(set)
    for members in resource_groups.values():
        for key in members:
            by_endpoint[key] |= members

    correlations_by_endpoint: dict[str, list[Correlation]] = defaultdict(list)
    for correlation in correlations:
        for key in correlation.endpoints:
            correlations_by_endpoint[key].append(correlation)

    risks: list[PrioritisedRisk] = []
    for result in assessment.results:
        if result.finding_class in {FindingClass.NONE}:
            continue
        if result.finding_class is FindingClass.INCONCLUSIVE and result.severity is None:
            continue

        related = by_endpoint.get(result.endpoint_key, {result.endpoint_key})
        relevant = sorted(
            correlations_by_endpoint.get(result.endpoint_key, []),
            key=lambda item: item.correlation_id,
        )
        score, factors = score_result(
            result,
            correlations=relevant,
            anonymous_endpoints=anonymous_endpoints,
            related_endpoints=related,
        )

        unverified = list(result.limitations)
        if result.finding_class is FindingClass.SUSPECTED:
            unverified.insert(0, "The security claim itself is not established.")
        if len(related) > 1:
            unverified.append("Whether the related operations share the behaviour was not tested.")

        risks.append(
            PrioritisedRisk(
                risk_id=f"risk-{result.result_id.removeprefix('res-')}",
                title=result.summary,
                band=band_for(score),
                score=score,
                severity=result.severity or Severity.INFO,
                confidence=result.confidence,
                evidence_strength=len(result.evidence),
                confirmed=result.finding_class is FindingClass.CONFIRMED,
                category=result.category.value,
                endpoints=sorted(related) if len(related) > 1 else [result.endpoint_key],
                factors=factors,
                source_results=[result.result_id],
                source_correlations=[item.correlation_id for item in relevant],
                evidence_ids=list(result.evidence_ids),
                what_was_observed=result.summary,
                why_it_matters=_why_it_matters(result, related),
                unverified=unverified,
                next_step=(
                    result.next_step or "Reproduce the observation by hand before acting on it."
                ),
            )
        )

    risks.sort(
        key=lambda item: (
            -item.score,
            -SEVERITY_POINTS[item.severity],
            item.risk_id,
        )
    )
    return risks


def model_description() -> list[tuple[str, str]]:
    """The scoring table, for ``risk explain`` and the documentation.

    Published deliberately: an operator should be able to see the weights
    without reading the source, and disagree with them.
    """
    return [
        (
            "impact",
            "severity points "
            + ", ".join(f"{k.value}={v:g}" for k, v in SEVERITY_POINTS.items())
            + "; multiplied by finding class "
            + ", ".join(f"{k.value}={v:g}" for k, v in FINDING_CLASS_MULTIPLIER.items() if v),
        ),
        (
            "check_confidence",
            ", ".join(f"{k.value}={v:g}" for k, v in CONFIDENCE_POINTS.items()),
        ),
        (
            "evidence_strength",
            f"{EVIDENCE_POINTS_EACH:g} per direct observation, capped at {MAX_EVIDENCE_POINTS:g}",
        ),
        (
            "unauthenticated_reach",
            f"{UNAUTHENTICATED_REACHABLE_POINTS:g} when the operation is documented "
            "as needing no credential",
        ),
        (
            "breadth",
            f"{BREADTH_POINTS_EACH:g} per additional related operation, capped at "
            f"{MAX_BREADTH_POINTS:g}; priority only, never severity",
        ),
        (
            "correlation",
            f"{CORRELATION_CONFIRMED_POINTS:g} for a confirmed correlation, "
            f"{CORRELATION_SUPPORTING_POINTS:g} for a supporting one",
        ),
        (
            "bands",
            ", ".join(f"{band.value} at {threshold:g}+" for threshold, band in BAND_THRESHOLDS),
        ),
    ]


def provenance_summary(correlations: list[Correlation]) -> dict[Provenance, int]:
    """How many correlations rest on each kind of support."""
    counts: dict[Provenance, int] = dict.fromkeys(Provenance, 0)
    for correlation in correlations:
        counts[correlation.provenance] += 1
    return counts


__all__ = [
    "BAND_THRESHOLDS",
    "BREADTH_POINTS_EACH",
    "CONFIDENCE_POINTS",
    "CORRELATION_CONFIRMED_POINTS",
    "EVIDENCE_POINTS_EACH",
    "FINDING_CLASS_MULTIPLIER",
    "MAX_BREADTH_POINTS",
    "MAX_EVIDENCE_POINTS",
    "SEVERITY_POINTS",
    "UNAUTHENTICATED_REACHABLE_POINTS",
    "band_for",
    "build_risks",
    "model_description",
    "provenance_summary",
    "score_result",
]
