"""Presentation for the ``scan`` command.

Display only; the pipeline in :mod:`aegisapi.scan` has already decided
everything shown here. Three habits carried from the other command modules:

* Anything that could contain untrusted text - a summary, a URL, an evidence
  excerpt, a header value - is rendered through Rich :class:`~rich.text.Text`,
  so a response body cannot inject markup into the operator's terminal.
* Outcome and finding class stay separate columns. "This check failed" and
  "this is a confirmed vulnerability" are different statements, and collapsing
  them is how a scanner comes to overstate what it found.
* Progress lines go to stderr and results to stdout, so
  ``aegisapi scan ... > findings.txt`` captures the findings and leaves the
  progress on the terminal.
"""

from __future__ import annotations

from collections.abc import Callable

from rich.console import Console
from rich.text import Text

from aegisapi.commands import theme
from aegisapi.core.scope import AUTHORISATION_REMINDER
from aegisapi.models.assessment import CheckOutcome, CheckResult
from aegisapi.models.common import Severity
from aegisapi.scan.events import ScanEvent, ScanEventType
from aegisapi.scan.pipeline import ScanResult, ScanStage

NOT_A_VULNERABILITY_NOTE = (
    "A failed check is not a confirmed vulnerability. Read the finding class, the "
    "confidence, and the limitations before acting on anything here."
)

_STAGE_LABELS: dict[ScanStage, str] = {
    ScanStage.AUTHORISE: "scope",
    ScanStage.CONNECT: "connect",
    ScanStage.DISCOVER: "discover",
    ScanStage.FIXTURE_GEN: "fixtures",
    ScanStage.SCHEMA_VAL: "schema-val",
    ScanStage.CHECK: "check",
    ScanStage.ANALYSE: "analyse",
    ScanStage.REPORT: "report",
}

_SEVERITY_ORDER: dict[Severity, int] = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}


def make_progress_printer(console: Console, *, verbose: bool) -> object:
    """Build a progress callback that prints each stage as it happens.

    Quiet by default: one line per stage, so a scan of a large API does not
    bury its own findings in scrollback. ``--verbose`` prints every message the
    pipeline emits, which is what an operator wants when a scan is slow and
    they need to see which stage it is in.
    """
    seen: set[ScanStage] = set()

    def report(stage: ScanStage, message: str) -> None:
        if not verbose and stage in seen:
            return
        seen.add(stage)
        line = Text()
        line.append(f"[{_STAGE_LABELS.get(stage, stage.value)}] ", style="aegis.label")
        line.append(message)
        console.print(line)

    return report


def make_event_handler(
    console: Console,
    *,
    no_progress: bool,
) -> Callable[[ScanEvent], None]:
    """Build a handler that prints findings the moment they are detected.

    Live findings go to *console* immediately on :attr:`~aegisapi.scan.events.ScanEventType.FINDING_DETECTED`
    so the operator does not need to wait for the scan to finish. When
    *no_progress* is ``True`` (CI mode) all live output is suppressed so that
    only the final structured report is emitted.

    Security: untrusted strings from the payload (endpoint paths, summaries)
    are rendered through :class:`~rich.text.Text` to prevent ANSI injection
    from a hostile server.
    """
    if no_progress:
        return lambda _event: None

    def _handler(event: ScanEvent) -> None:
        if event.event_type is not ScanEventType.FINDING_DETECTED:
            return
        p = event.payload
        line = Text()
        line.append("[live] ", style="aegis.label")
        severity_str: str | None = p.get("severity")
        if severity_str:
            try:
                sev = Severity(severity_str)
                line.append(theme.severity_label(sev))
            except ValueError:
                line.append(Text(severity_str))
            line.append("  ")
        line.append(Text(str(p.get("check_id", "?"))))
        line.append("  ")
        line.append(Text(str(p.get("endpoint_key", ""))))
        line.append("  ")
        line.append(Text(str(p.get("summary", ""))))
        console.print(line)

    return _handler


def _display_order(result: CheckResult) -> tuple[int, int, str, str]:
    """Sort findings by seriousness, then deterministically.

    Confirmed before suspected before everything else, then by severity, so the
    first rows of the table are the ones worth reading first. The check id and
    endpoint key break ties, which keeps the order stable between runs - a
    table that reshuffles identical results makes two reports impossible to
    diff.
    """
    finding_rank = {
        "confirmed": 0,
        "suspected": 1,
        "informational": 2,
        "inconclusive": 3,
        "none": 4,
    }
    return (
        finding_rank.get(result.finding_class.value, 5),
        _SEVERITY_ORDER.get(result.severity, 5) if result.severity else 5,
        result.check_id,
        result.endpoint_key,
    )


def render_scan_summary(console: Console, result: ScanResult) -> None:
    """Print what the scan did, before what it found."""
    discovery = result.discovery
    table = theme.kv_table("Scan summary")
    if result.options.target is not None:
        target_cell = Text()
        target_cell.append(result.options.target.name, style="bold")
        target_cell.append(f"  {result.options.url}")
        table.add_row("Target", target_cell)
    else:
        table.add_row("Target", result.options.url)
    table.add_row(
        "Scope",
        f"host {result.authorisation.url.host}, path "
        f"{result.authorisation.target.scope.include_paths[0]}"
        + (" (local lab)" if result.options.local_lab else ""),
    )
    table.add_row("Started", result.started_at.isoformat(timespec="seconds"))
    table.add_row("Duration", f"{result.duration_seconds:.1f}s")
    table.add_row(
        "Mode",
        "active" if result.options.active else "passive (read-shaped requests only)",
    )
    table.add_row(
        "Inventory",
        (
            f"{discovery.specification.version.value} from {discovery.specification.source_path}"
            if result.live.from_specification
            else f"observed paths ({discovery.specification.source_path})"
        ),
    )
    table.add_row(
        "Endpoints",
        f"{result.endpoints_discovered} discovered, {result.endpoints_in_scope} in scope, "
        f"{result.endpoints_tested} tested",
    )
    if result.fixtures_generated:
        table.add_row(
            "Auto fixtures",
            f"{result.fixtures_generated} templated endpoint(s) equipped with generated path values",
        )
    if result.schemas_validated:
        violation_note = (
            f", {result.schema_violations} with violation(s)"
            if result.schema_violations
            else ", all conformant"
        )
        table.add_row(
            "Schema validation",
            f"{result.schemas_validated} endpoint(s) validated{violation_note}",
        )
    table.add_row(
        "Requests",
        f"{result.requests_sent} sent "
        f"({result.live.requests_sent} discovery, {result.assessment.requests_sent} checks) "
        f"of {result.options.budget} budgeted",
    )

    budget = result.report.budget_summary
    if budget is not None:
        status = result.completion_status
        if status != "complete":
            label = (
                "PARTIAL — scan_timeout reached"
                if status == "partial_timeout"
                else "PARTIAL — budget exhausted"
            )
            table.add_row("Completion", label)
        if budget.checks_timed_out:
            table.add_row("Checks timed out", str(budget.checks_timed_out))
        if budget.endpoints_at_limit:
            table.add_row(
                "Endpoints at limit",
                f"{len(budget.endpoints_at_limit)} endpoint(s) hit per-endpoint cap",
            )

    eff = result.report.efficiency_summary
    if eff is not None and (
        eff.total_requests_saved > 0
        or eff.redundant_checks_skipped > 0
        or eff.endpoints_prioritized > 0
    ):
        parts: list[str] = []
        if eff.total_requests_saved > 0:
            parts.append(f"{eff.total_requests_saved} request(s) saved via GET cache")
        if eff.redundant_checks_skipped > 0:
            parts.append(f"{eff.redundant_checks_skipped} redundant check(s) skipped")
        if eff.endpoints_prioritized > 0:
            parts.append(f"{eff.endpoints_prioritized} endpoint(s) prioritized")
        table.add_row("Efficiency", "; ".join(parts))

    console.print(table)


def render_findings(console: Console, result: ScanResult, *, limit: int = 40) -> None:
    """Print the findings table, most serious first."""
    results = sorted(result.report.results, key=_display_order)
    shown = results if limit <= 0 else results[:limit]

    theme.print_heading(console, "Findings")
    if not results:
        console.print(
            Text(
                "No finding or review item was produced. This is not a clean bill of "
                "health: read the notes for what did not run.",
                style="aegis.muted",
            )
        )
        return

    table = theme.data_table(None)
    table.add_column("Severity", no_wrap=True)
    table.add_column("Finding", no_wrap=True)
    table.add_column("Conf", no_wrap=True)
    table.add_column("Check", style="aegis.label", no_wrap=True)
    table.add_column("OWASP", no_wrap=True)
    table.add_column("Endpoint", overflow="fold")
    table.add_column("Observed", overflow="fold")

    for item in shown:
        table.add_row(
            theme.severity_label(item.severity),
            theme.finding_label(item.finding_class),
            Text(item.confidence.value),
            item.check_id,
            Text(item.owasp.identifier if item.owasp else "-"),
            Text(item.endpoint_key),
            Text(item.summary),
        )

    console.print(table)
    if limit > 0 and len(results) > limit:
        console.print(
            Text(
                f"{len(results) - limit} further row(s) not shown; pass --limit 0 for all.",
                style="aegis.muted",
            )
        )


def render_finding_detail(console: Console, item: CheckResult) -> None:
    """Print one finding in full: evidence, limits, remediation.

    This is the part of the output an operator pastes into a report, so every
    field a finding is required to carry appears here, including the ones that
    constrain it. A finding shown without its limitations reads as a stronger
    claim than the check made.
    """
    theme.print_heading(console, f"{item.check_id} - {item.check_name}")

    table = theme.kv_table(None)
    table.add_row("Endpoint", Text(item.endpoint_key))
    if item.url:
        table.add_row("URL", Text(item.url))
    table.add_row("Severity", theme.severity_label(item.severity))
    table.add_row("Finding class", theme.finding_label(item.finding_class))
    table.add_row("Confidence", Text(item.confidence.value))
    table.add_row("Outcome", theme.outcome_label(item.outcome))
    if item.owasp is not None:
        table.add_row("OWASP", Text(item.owasp.value))
    table.add_row("Observed", Text(item.summary))
    console.print(table)

    if item.explanation:
        console.print()
        console.print(Text("Why it matters", style="aegis.label"))
        console.print(Text(item.explanation))

    if item.evidence:
        console.print()
        console.print(Text("Evidence", style="aegis.label"))
        for piece in item.evidence:
            line = Text()
            line.append(f"{piece.method} {piece.url}")
            if piece.status_code is not None:
                line.append(f" -> {piece.status_code}")
            if piece.content_type:
                line.append(f" ({piece.content_type})")
            console.print(line)
            if piece.note:
                console.print(Text(f"  {piece.note}", style="aegis.muted"))
            if piece.body_excerpt:
                excerpt = piece.body_excerpt
                if len(excerpt) > 300:
                    excerpt = f"{excerpt[:300]}..."
                console.print(Text(f"  {excerpt}", style="aegis.muted"))

    if item.limitations:
        console.print()
        console.print(Text("What this does not establish", style="aegis.label"))
        for note in item.limitations:
            console.print(Text(f"- {note}"))

    if item.next_step:
        console.print()
        console.print(Text("How to confirm", style="aegis.label"))
        console.print(Text(item.next_step))

    if item.remediation:
        console.print()
        console.print(Text("Remediation", style="aegis.label"))
        console.print(Text(item.remediation))


def render_counts(console: Console, result: ScanResult) -> None:
    """Print the finding counts and the severity breakdown."""
    summary = result.report.summary
    table = theme.kv_table("Results")
    table.add_row("Confirmed findings", str(summary.confirmed_findings))
    table.add_row("Potential findings", str(summary.potential_findings))
    table.add_row("Needs review", str(summary.needs_review))
    table.add_row("Checks run", f"{len(result.assessment.checks_run)}")
    table.add_row("Results recorded", str(summary.results_total))

    severities = {
        severity: count for severity, count in summary.by_severity.items() if count
    }
    if severities:
        rendered = Text()
        for index, (severity, count) in enumerate(
            sorted(severities.items(), key=lambda pair: _SEVERITY_ORDER.get(pair[0], 5))
        ):
            if index:
                rendered.append("  ")
            rendered.append(theme.severity_label(severity))
            rendered.append(f" {count}")
        table.add_row("By severity", rendered)
    console.print(table)


def render_notes(console: Console, result: ScanResult) -> None:
    """Print what the scan did not do, and why.

    Printed every time, including on a scan that found nothing. The most
    misleading possible output is an empty findings table with no statement of
    which checks never ran, because it reads as "nothing is wrong" when it may
    mean "almost nothing was tested".
    """
    if not result.notes:
        return
    theme.print_heading(console, "Notes and limitations")
    for note in result.notes:
        console.print(Text(f"- {note}"))


def render_written(console: Console, paths: list[str]) -> None:
    """Report the report files that were written."""
    if not paths:
        return
    console.print()
    for path in paths:
        console.print(theme.status("ok", "Written", path))


def render_scan(
    console: Console,
    result: ScanResult,
    *,
    limit: int = 40,
    detail: bool = False,
) -> None:
    """Print a complete scan result."""
    render_scan_summary(console, result)
    console.print()
    render_counts(console, result)
    console.print()
    render_findings(console, result, limit=limit)

    if detail:
        for item in sorted(result.report.results, key=_display_order):
            if item.outcome in {CheckOutcome.PASS, CheckOutcome.SKIPPED}:
                continue
            console.print()
            render_finding_detail(console, item)

    console.print()
    render_notes(console, result)
    console.print()
    console.print(Text(NOT_A_VULNERABILITY_NOTE, style="aegis.muted"))
    theme.notice(console, AUTHORISATION_REMINDER)


__all__ = [
    "NOT_A_VULNERABILITY_NOTE",
    "make_event_handler",
    "make_progress_printer",
    "render_finding_detail",
    "render_findings",
    "render_notes",
    "render_scan",
    "render_scan_summary",
    "render_written",
]
