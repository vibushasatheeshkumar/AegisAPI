"""Report generation: turning saved documents into something a person reads.

This package is **read-only with respect to the assessment**. It loads nothing
itself, sends no requests, and runs no checks; it takes an
:class:`~aegisapi.models.assessment.AssessmentResult` and, optionally, an
:class:`~aegisapi.models.intelligence.IntelligenceReport` that already exist,
and produces text. That boundary is what keeps reporting from becoming a second
assessment path.

Three stages, each in its own module and each independently testable:

* :mod:`aegisapi.reporting.build` - pure composition into a
  :class:`~aegisapi.models.report.Report`. No I/O at all.
* :mod:`aegisapi.reporting.json_report`, :mod:`aegisapi.reporting.html_report`,
  and :mod:`aegisapi.reporting.sarif_report` - rendering one report to text.
  Pure functions, so a test can assert on a string rather than a file.
* :mod:`aegisapi.reporting.writer` - putting rendered text on disk atomically.

:mod:`aegisapi.reporting.formats` sits across the two renderers: it owns which
formats this build supports, how one is chosen from a flag and configuration,
and the refusal when something asks for a format that does not exist here.

Rendering is separate from writing on purpose: every escaping guarantee the
HTML renderer makes is testable without touching the filesystem.
"""

from aegisapi.reporting.build import build_report
from aegisapi.reporting.formats import (
    SUPPORTED_FORMATS,
    is_supported,
    render,
    resolve_format,
    suffix_for,
    supported_names,
)
from aegisapi.reporting.html_report import render_html_report
from aegisapi.reporting.json_report import render_json_report
from aegisapi.reporting.sarif_report import render_sarif_report
from aegisapi.reporting.writer import write_report_text

__all__ = [
    "SUPPORTED_FORMATS",
    "build_report",
    "is_supported",
    "render",
    "render_html_report",
    "render_json_report",
    "render_sarif_report",
    "resolve_format",
    "suffix_for",
    "supported_names",
    "write_report_text",
]
