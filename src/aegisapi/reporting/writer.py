"""Putting a rendered report on disk, atomically.

This is a narrow, deliberate addition. The project already has two atomic
writers - :func:`aegisapi.testing.store.write_document` and
:func:`aegisapi.discovery.store.write_result_file` - but both take a *model*
and serialise it to JSON internally, so neither can accept the HTML this
package renders. Rather than widen a working writer on the request path's side
of the tree, reporting gets its own function for already-rendered text.

What this module owns is the report-specific part: refusing an existing file
unless asked, and translating a failure into :class:`ReportError` so the exit
code matches the rest of the ``report`` command. Putting the bytes down is
:func:`aegisapi.core.workspace.write_text_atomic`, shared with the other three
stores, so a reader sees either the previous report or the new one and never a
half-written document.
"""

from __future__ import annotations

from pathlib import Path

from aegisapi.core.exceptions import ReportError
from aegisapi.core.logging import get_logger
from aegisapi.core.workspace import write_text_atomic

_logger = get_logger(__name__)


def write_report_text(path: Path | str, text: str, *, overwrite: bool = False) -> Path:
    """Write ``text`` to ``path`` atomically.

    Args:
        path: Destination file. Parent directories are created as needed, so a
            workspace that predates the reports directory still works.
        text: The rendered report. A trailing newline is added if absent, so
            the file ends cleanly whatever the renderer produced.
        overwrite: Whether an existing file may be replaced.

    Returns:
        The path written.

    Raises:
        ReportError: If the destination is a directory, if it exists and
            ``overwrite`` is false, or if the write fails. The report-specific
            error type means a write failure exits with the reporting code
            rather than being reported as a discovery problem.
    """
    destination = Path(path).expanduser()

    if destination.is_dir():
        raise ReportError(
            f"Expected a file but found a directory: {destination}",
            hint="Pass a file path to --output.",
        )
    if destination.exists() and not overwrite:
        raise ReportError(
            f"A file already exists at {destination}.",
            hint="Pass --force to replace it, or choose another path with --output.",
        )

    payload = text if text.endswith("\n") else text + "\n"
    try:
        destination.parent.mkdir(parents=True, exist_ok=True)
        write_text_atomic(destination, payload)
    except OSError as exc:
        raise ReportError(
            f"The report could not be written: {destination}",
            hint=exc.strerror,
        ) from exc

    _logger.debug("Wrote %s", destination)
    return destination


__all__ = ["write_report_text"]
