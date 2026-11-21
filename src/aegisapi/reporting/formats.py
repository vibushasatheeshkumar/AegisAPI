"""Which report formats this build can produce, and how a format is chosen.

Two rules, both of which exist to avoid handing someone a file that is not what
they asked for.

**No silent substitution.** :data:`ReportFormat` has included ``pdf`` since the
configuration vocabulary was first defined, and this build cannot produce it.
Asking for one therefore fails, with a message naming the alternative, rather
than quietly yielding JSON. A report in the wrong format is not a smaller
version of the right one; it is a different artefact that a reader may not
notice is wrong.

**The refusal names where the choice came from.** ``default_report_format``
validates ``"pdf"`` today, so a configuration file written before reporting
existed can select a format that has never been implemented. A failure that
only said "pdf is unsupported" would send the operator looking at their
command line when the setting is in a file. The two cases get different hints.
"""

from __future__ import annotations

from aegisapi.core.exceptions import ReportError
from aegisapi.models.common import ReportFormat
from aegisapi.models.report import Report
from aegisapi.reporting.html_report import render_html_report
from aegisapi.reporting.json_report import render_json_report
from aegisapi.reporting.sarif_report import render_sarif_report

SUPPORTED_FORMATS: tuple[ReportFormat, ...] = (
    ReportFormat.JSON,
    ReportFormat.HTML,
    ReportFormat.SARIF,
)
"""Formats this build renders. Order is the order shown to a user."""

_PDF_HINT = (
    "Native PDF generation is not implemented. Generate 'html' and use your "
    "browser's Print to PDF: the HTML report carries a print stylesheet for it."
)


def supported_names() -> str:
    """The supported formats as a comma-separated list, for messages."""
    return ", ".join(item.value for item in SUPPORTED_FORMATS)


def is_supported(report_format: ReportFormat) -> bool:
    """Whether this build can render ``report_format``."""
    return report_format in SUPPORTED_FORMATS


def resolve_format(
    explicit: ReportFormat | None,
    configured: ReportFormat,
) -> ReportFormat:
    """Choose the output format, or refuse to guess.

    Precedence is the project's usual order: an explicit ``--format`` wins,
    otherwise the configured default, which ``load_config`` has already
    resolved from the file and the ``AEGISAPI_*`` environment.

    Args:
        explicit: The value of ``--format``, or ``None`` when it was omitted.
        configured: ``AegisConfig.default_report_format``.

    Returns:
        A format this build can render.

    Raises:
        ReportError: If the chosen format is not supported. The message
            distinguishes a format asked for on the command line from one
            inherited from configuration.
    """
    chosen = explicit if explicit is not None else configured
    if is_supported(chosen):
        return chosen

    if explicit is not None:
        raise ReportError(
            f"{chosen.value} reports are not implemented in this build.",
            hint=f"{_PDF_HINT} Supported formats: {supported_names()}.",
        )
    raise ReportError(
        f"The configured default_report_format is {chosen.value!r}, "
        "which this build cannot produce.",
        hint=(
            f"Pass --format with one of: {supported_names()}, or change "
            f"default_report_format in config.toml. {_PDF_HINT}"
        ),
    )


def suffix_for(report_format: ReportFormat) -> str:
    """Filename extension for a format, without the dot."""
    return report_format.value


def render(report: Report, report_format: ReportFormat) -> str:
    """Render ``report`` in ``report_format``.

    Raises:
        ReportError: If the format is not supported. :func:`resolve_format`
            normally catches that first; this is the guard that keeps a new
            :class:`~aegisapi.models.common.ReportFormat` member from silently
            falling through to the wrong renderer.
    """
    if report_format is ReportFormat.JSON:
        return render_json_report(report)
    if report_format is ReportFormat.HTML:
        return render_html_report(report)
    if report_format is ReportFormat.SARIF:
        return render_sarif_report(report)
    raise ReportError(
        f"{report_format.value} reports are not implemented in this build.",
        hint=f"{_PDF_HINT} Supported formats: {supported_names()}.",
    )


__all__ = [
    "SUPPORTED_FORMATS",
    "is_supported",
    "render",
    "resolve_format",
    "suffix_for",
    "supported_names",
]
