"""Presentation for the ``check`` and ``risk`` commands.

Display only. Two habits carried from the earlier phases:

* Everything that could contain untrusted text - a summary, an evidence
  excerpt, a header value - is rendered through Rich ``Text``, so a response
  cannot inject markup into the terminal.
* Outcomes and finding classes are shown as distinct columns, because the
  difference between "this check failed" and "this is a confirmed
  vulnerability" is the point of the whole engine.

Styling comes from :mod:`aegisapi.commands.theme`. Severity and risk band are
labelled in upper case because they are the two columns a reader scans first;
outcome and finding class stay lower case so they do not compete with them.
"""

from __future__ import annotations

from collections.abc import Sequence

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from aegisapi.commands import theme
from aegisapi.core.scope import AUTHORISATION_REMINDER
from aegisapi.intelligence.attack_paths import path_note
from aegisapi.intelligence.risk import model_description
from aegisapi.models.assessment import (
    AssessmentResult,
    CheckOutcome,
    CheckResult,
)
from aegisapi.models.intelligence import (
    AttackPath,
    IntelligenceReport,
    PathStepKind,
    PrioritisedRisk,
)
from aegisapi.testing.registry import SecurityCheck

NOT_A_VULNERABILITY_NOTE = (
    "A failed check is not a confirmed vulnerability. Read the finding class and "
    "the limitations before acting on anything here."
)


def render_check_catalogue(console: Console, checks: Sequence[SecurityCheck]) -> None:
    """List the available checks."""
    table = theme.data_table("Security checks")
    table.add_column("ID", style="aegis.label", no_wrap=True)
    table.add_column("Category", no_wrap=True)
    table.add_column("Name", overflow="fold")
    table.add_column("Reqs", justify="right", no_wrap=True)
    table.add_column("What it does", overflow="fold")

    for check in checks:
        table.add_row(
            check.check_id,
            check.category.value,
            Text(check.name),
            str(check.requests_per_endpoint),
            Text(check.description),
        )

    console.print(table)
    console.print()
    console.print(Text(f"{len(checks)} check(s).", style="aegis.muted"))
    console.print(Text(NOT_A_VULNERABILITY_NOTE, style="aegis.muted"))


def render_assessment(
    console: Console,
    assessment: AssessmentResult,
    *,
    show_skipped: bool = False,
    limit: int = 40,
) -> None:
    """Print the results of an assessment run."""
    summary = theme.kv_table("Assessment summary")
    summary.add_column("Item", style="aegis.label")
    summary.add_column("Value", overflow="fold")
    summary.add_row("Target", f"{assessment.target_name} ({assessment.target_base_url})")
    summary.add_row(
        "Operations",
        f"{assessment.endpoints_tested} tested of {assessment.endpoints_considered} considered",
    )
    summary.add_row(
        "Requests sent",
        f"{assessment.requests_sent} of a {assessment.request_budget} budget"
        + (" (exhausted)" if assessment.budget_exhausted else ""),
    )
    outcomes = {key.value: value for key, value in assessment.by_outcome().items() if value}
    summary.add_row("Outcomes", ", ".join(f"{k}: {v}" for k, v in outcomes.items()) or "none")
    classes = {key.value: value for key, value in assessment.by_finding_class().items() if value}
    summary.add_row("Finding classes", ", ".join(f"{k}: {v}" for k, v in classes.items()) or "none")
    console.print(summary)

    shown = [
        item
        for item in assessment.results
        if show_skipped or item.outcome is not CheckOutcome.SKIPPED
    ]
    if not shown:
        # Everything was skipped. Saying only "no results" would hide the one
        # fact that matters - why nothing ran - so the reasons are surfaced.
        console.print()
        console.print(Text("No checks produced a result. Reasons recorded:", style="status.warn"))
        for item in assessment.results[:10]:
            console.print(Text(f"  - {item.endpoint_key}: {item.summary}", style="status.warn"))
        if len(assessment.results) > 10:
            console.print(
                Text(f"  ... and {len(assessment.results) - 10} more.", style="aegis.muted")
            )
        return

    visible = shown if limit <= 0 else shown[:limit]
    table = theme.data_table("Check results")
    table.add_column("Check", style="aegis.label", no_wrap=True)
    table.add_column("Operation", overflow="fold")
    table.add_column("Outcome", no_wrap=True)
    table.add_column("Finding", no_wrap=True)
    table.add_column("Sev", no_wrap=True)
    table.add_column("Summary", overflow="fold")

    for item in visible:
        table.add_row(
            item.check_id,
            Text(item.endpoint_key),
            theme.outcome_label(item.outcome),
            theme.finding_label(item.finding_class),
            theme.severity_label(item.severity),
            Text(item.summary),
        )

    console.print()
    console.print(table)
    if len(visible) < len(shown):
        console.print(
            Text(f"Showing {len(visible)} of {len(shown)} result(s).", style="aegis.muted")
        )
    console.print()
    console.print(Text(NOT_A_VULNERABILITY_NOTE, style="status.notice"))
    console.print(Text(AUTHORISATION_REMINDER, style="status.notice"))


def render_result_detail(console: Console, result: CheckResult) -> None:
    """Print one check result in full, including its limitations."""
    header = Text()
    header.append(f"{result.check_id}  ", style="aegis.label")
    header.append(f"{result.check_name}\n")
    header.append(result.endpoint_key, style="aegis.accent")
    console.print(Panel(header, title="Check result", border_style="aegis.accent", expand=False))

    table = theme.kv_table()
    table.add_row("Outcome", theme.outcome_label(result.outcome))
    table.add_row(
        "Finding class",
        theme.finding_label(result.finding_class),
    )
    table.add_row("Severity", theme.severity_label(result.severity))
    table.add_row("Confidence", result.confidence.value)
    table.add_row("Summary", Text(result.summary))
    if result.explanation:
        table.add_row("Explanation", Text(result.explanation))
    if result.next_step:
        table.add_row("Next step", Text(result.next_step))
    console.print(table)

    if result.limitations:
        console.print()
        console.print(Text("What this does not establish:", style="status.notice"))
        for item in result.limitations:
            console.print(Text(f"  - {item}", style="status.warn"))

    if result.evidence:
        console.print()
        evidence = theme.data_table("Evidence")
        evidence.add_column("ID", no_wrap=True)
        evidence.add_column("Observation", overflow="fold")
        evidence.add_column("Status", no_wrap=True)
        evidence.add_column("Identity", no_wrap=True)
        for item in result.evidence:
            evidence.add_row(
                item.evidence_id,
                Text(item.label),
                str(item.status_code) if item.status_code else "-",
                item.identity or "-",
            )
        console.print(evidence)


def render_intelligence_summary(console: Console, report: IntelligenceReport) -> None:
    """Print the headline numbers from an analysis."""
    table = theme.kv_table("Risk intelligence")
    table.add_column("Item", style="aegis.label")
    table.add_column("Value", overflow="fold")
    table.add_row("Target", report.target_name)
    table.add_row("Graph", f"{len(report.nodes)} node(s), {len(report.edges)} edge(s)")
    provenance = {key.value: value for key, value in report.edges_by_provenance().items() if value}
    table.add_row(
        "Edge provenance", ", ".join(f"{k}: {v}" for k, v in provenance.items()) or "none"
    )
    table.add_row("Correlations", str(len(report.correlations)))
    bands = {key.value: value for key, value in report.band_counts().items() if value}
    table.add_row("Risk bands", ", ".join(f"{k}: {v}" for k, v in bands.items()) or "none")
    table.add_row("Confirmed risks", str(len(report.confirmed_risks())))
    table.add_row("Potential attack paths", str(len(report.attack_paths)))
    console.print(table)


def render_risks(console: Console, risks: Sequence[PrioritisedRisk], *, limit: int = 20) -> None:
    """Print prioritised risks, highest first."""
    if not risks:
        console.print()
        console.print(
            Text("No risks were derived. Run 'aegisapi check run' first.", style="status.warn")
        )
        return

    visible = risks if limit <= 0 else risks[:limit]
    table = theme.data_table("Prioritised risks")
    table.add_column("Risk", style="aegis.label", no_wrap=True)
    table.add_column("Band", no_wrap=True)
    table.add_column("Score", justify="right", no_wrap=True)
    table.add_column("Sev", no_wrap=True)
    table.add_column("Conf", no_wrap=True)
    table.add_column("Status", no_wrap=True)
    table.add_column("Title", overflow="fold")

    for risk in visible:
        table.add_row(
            risk.risk_id,
            theme.band_label(risk.band),
            f"{risk.score:.1f}",
            theme.severity_label(risk.severity),
            risk.confidence.value,
            Text("confirmed", style="status.error")
            if risk.confirmed
            else Text("unverified", style="status.warn"),
            Text(risk.title),
        )

    console.print()
    console.print(table)
    if len(visible) < len(risks):
        console.print(Text(f"Showing {len(visible)} of {len(risks)} risk(s).", style="aegis.muted"))
    console.print()
    console.print(
        Text(
            "Severity is impact if real; confidence is how sure AegisAPI is. They are "
            "separate on purpose.",
            style="aegis.muted",
        )
    )


def render_risk_explanation(console: Console, risk: PrioritisedRisk) -> None:
    """Explain one risk: what was seen, why it matters, what is unproven."""
    header = Text()
    header.append(f"{risk.risk_id}  ", style="aegis.label")
    header.append(risk.title)
    console.print(Panel(header, title="Risk", border_style="aegis.accent", expand=False))

    table = theme.kv_table()
    table.add_row("Band", theme.band_label(risk.band))
    table.add_row("Score", f"{risk.score:.1f} of 100")
    table.add_row("Severity", theme.severity_label(risk.severity) + Text(" (impact if real)"))
    table.add_row("Confidence", f"{risk.confidence.value} (how sure AegisAPI is)")
    table.add_row("Evidence strength", f"{risk.evidence_strength} direct observation(s)")
    table.add_row("Status", "confirmed" if risk.confirmed else "not verified")
    table.add_row("Operations", "\n".join(risk.endpoints) or "none")
    console.print(table)

    console.print()
    console.print(Text("What was observed", style="aegis.label"))
    console.print(Text(f"  {risk.what_was_observed}"))
    console.print()
    console.print(Text("Why it matters", style="aegis.label"))
    console.print(Text(f"  {risk.why_it_matters}"))

    console.print()
    console.print(Text("How the score was reached", style="aegis.label"))
    factors = Table(show_header=True, box=None, header_style="aegis.label")
    factors.add_column("Factor", style="aegis.label", no_wrap=True)
    factors.add_column("Points", justify="right", no_wrap=True)
    factors.add_column("Reason", overflow="fold")
    for factor in risk.factors:
        factors.add_row(factor.name, f"{factor.points:+.2f}", Text(factor.reason))
    console.print(factors)

    if risk.unverified:
        console.print()
        console.print(Text("What remains unverified", style="status.notice"))
        for item in risk.unverified:
            console.print(Text(f"  - {item}", style="status.warn"))

    console.print()
    console.print(Text("What to check next", style="aegis.label"))
    console.print(Text(f"  {risk.next_step}"))

    if risk.evidence_ids:
        console.print()
        console.print(Text(f"Evidence: {', '.join(risk.evidence_ids)}", style="aegis.muted"))


def render_graph(console: Console, report: IntelligenceReport, *, limit: int = 40) -> None:
    """Print the relationship edges with their provenance."""
    if not report.edges:
        console.print(Text("The graph has no edges.", style="status.warn"))
        return

    visible = report.edges if limit <= 0 else report.edges[:limit]
    table = theme.data_table("Endpoint relationships")
    table.add_column("From", overflow="fold")
    table.add_column("Relationship", no_wrap=True)
    table.add_column("To", overflow="fold")
    table.add_column("Provenance", no_wrap=True)
    table.add_column("Why", overflow="fold")

    for edge in visible:
        table.add_row(
            Text(edge.source),
            edge.kind.value,
            Text(edge.target),
            theme.provenance_label(edge.provenance),
            Text(edge.reason),
        )

    console.print(table)
    if len(visible) < len(report.edges):
        console.print(
            Text(f"Showing {len(visible)} of {len(report.edges)} edge(s).", style="aegis.muted")
        )
    console.print()
    console.print(
        Text(
            "Provenance: observed and fixture come from evidence, specification from the "
            "document, inferred from structure alone.",
            style="aegis.muted",
        )
    )


def render_correlations(console: Console, report: IntelligenceReport) -> None:
    """Print cross-endpoint correlations."""
    if not report.correlations:
        console.print(Text("No cross-endpoint correlations were found.", style="status.warn"))
        return

    table = theme.data_table("Cross-endpoint correlations")
    table.add_column("Kind", style="aegis.label", no_wrap=True)
    table.add_column("Status", no_wrap=True)
    table.add_column("Conf", no_wrap=True)
    table.add_column("Operations", justify="right", no_wrap=True)
    table.add_column("Finding", overflow="fold")

    for item in report.correlations:
        table.add_row(
            item.kind,
            Text("confirmed", style="status.error")
            if item.confirmed
            else Text("hypothesis", style="status.warn"),
            item.confidence.value,
            str(len(item.endpoints)),
            Text(item.title),
        )

    console.print(table)


def render_attack_paths(console: Console, paths: Sequence[AttackPath], *, limit: int = 10) -> None:
    """Print potential attack paths, with the weakest link named."""
    if not paths:
        console.print(Text("No potential attack paths were derived.", style="status.warn"))
        console.print(Text(path_note(), style="aegis.muted"))
        return

    visible = paths if limit <= 0 else paths[:limit]
    for path in visible:
        header = Text()
        header.append(path.title, style="aegis.label")
        console.print(Panel(header, border_style="aegis.accent", expand=False))
        for index, step in enumerate(path.steps, start=1):
            style = (
                "green"
                if step.kind is PathStepKind.OBSERVED
                else ("cyan" if step.kind is PathStepKind.DOCUMENTED else "yellow")
            )
            console.print(
                Text(f"  {index}. [{step.kind.value}] ", style=style),
                Text(f"{step.from_node} -> {step.to_node}: {step.description}"),
            )
        console.print(
            Text(
                f"  severity {path.severity.value}, confidence {path.confidence.value}, "
                f"weakest step {path.weakest_step.value}, "
                f"{'fully evidenced' if path.fully_evidenced else 'not fully evidenced'}",
                style="aegis.muted",
            )
        )
        for item in path.unverified:
            console.print(Text(f"  unverified: {item}", style="status.warn"))
        console.print()

    console.print(Text(path_note(), style="status.notice"))


def render_scoring_model(console: Console) -> None:
    """Print the published scoring weights."""
    table = theme.data_table("Risk scoring model")
    table.add_column("Factor", style="aegis.label", no_wrap=True)
    table.add_column("Weight", overflow="fold")
    for name, description in model_description():
        table.add_row(name, Text(description))
    console.print(table)
    console.print()
    console.print(
        Text(
            "Weights are fixed and published so a score can be argued with. Breadth "
            "contributes to priority only and never changes severity.",
            style="aegis.muted",
        )
    )


def render_notes(console: Console, notes: Sequence[str]) -> None:
    """Print the limits that qualify an analysis."""
    if not notes:
        return
    console.print()
    console.print(Text("Limits of this analysis", style="status.notice"))
    for note in notes:
        console.print(Text(f"  - {note}", style="status.warn"))


__all__ = [
    "NOT_A_VULNERABILITY_NOTE",
    "render_assessment",
    "render_attack_paths",
    "render_check_catalogue",
    "render_correlations",
    "render_graph",
    "render_intelligence_summary",
    "render_notes",
    "render_result_detail",
    "render_risk_explanation",
    "render_risks",
    "render_scoring_model",
]
