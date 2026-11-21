"""The ``aegisapi report`` command.

Building and rendering live in :mod:`aegisapi.reporting`; this module only
turns a :class:`~aegisapi.models.report.Report` and the path it was written to
into terminal output, so the reporting behaviour is testable without a console.

The summary printed here is deliberately the same set of counts the report
itself carries. A reader who runs the command and a reader who opens the file
should see the same numbers.
"""

from __future__ import annotations

from pathlib import Path

from rich.console import Console
from rich.table import Table
from rich.text import Text

from aegisapi.commands import theme
from aegisapi.models.common import ReportFormat
from aegisapi.models.report import Report

NO_INTELLIGENCE_WARNING = (
    "No saved risk analysis for this target; the report covers check results only. "
    "Run 'aegisapi risk analyze <target> --save' first for risks and attack paths."
)

AUTHORISATION_NOTICE = (
    "A report is evidence for a reader, not proof of a vulnerability. "
    "Check each item's finding class and limitations before acting on it."
)


def _summary_table(report: Report) -> Table:
    """Summarise what the generated report contains."""
    summary = report.summary
    table = theme.kv_table("Report contents")
    table.add_column("Item", style="aegis.label")
    table.add_column("Value", overflow="fold")

    table.add_row("Target", report.target_name)
    table.add_row("Confirmed findings", str(summary.confirmed_findings))
    table.add_row("Potential findings", str(summary.potential_findings))
    table.add_row("Needing review", str(summary.needs_review))
    if report.has_intelligence:
        table.add_row("Prioritised risks", str(summary.risks_total))
        table.add_row("Potential attack paths", str(summary.attack_paths_total))
    else:
        table.add_row("Risk analysis", "not included")
    table.add_row(
        "Results shown",
        f"{summary.results_displayed} of {summary.results_total}"
        + ("" if report.include_all else " (findings and reviews)"),
    )
    return table


def render_report_written(
    console: Console,
    report: Report,
    *,
    path: Path,
    report_format: ReportFormat,
) -> None:
    """Print the outcome of generating a report."""
    console.print(_summary_table(report))
    console.print()
    console.print(
        Text("Written", style="status.ok"),
        Text(f"{path} ({report_format.value})"),
    )
    console.print()
    console.print(Text(AUTHORISATION_NOTICE, style="status.notice"))


__all__ = [
    "AUTHORISATION_NOTICE",
    "NO_INTELLIGENCE_WARNING",
    "render_report_written",
]
