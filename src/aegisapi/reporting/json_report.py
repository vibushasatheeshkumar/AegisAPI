"""Rendering a report as JSON.

Dependency-free: :mod:`json` is in the standard library, and Pydantic's
JSON-mode dump already converts the datetimes and string enumerations the
report embeds.

The serialisation settings match
:func:`aegisapi.testing.store.render_json` deliberately - two-space indent,
sorted keys, no ASCII escaping - so a report and the stored document it was
built from read the same way in a diff, and two runs over unchanged inputs
differ only where the inputs genuinely differ.

This module does **not** replace ``check run --export`` or
``risk analyze --export``. Those still write the stored documents' own schemas
through :mod:`aegisapi.testing.store`; this writes the report envelope defined
in :mod:`aegisapi.models.report`.
"""

from __future__ import annotations

import json

from aegisapi.models.report import Report


def render_json_report(report: Report) -> str:
    """Serialise ``report`` to stable, readable JSON.

    Keys are sorted, so two reports built from the same documents at the same
    timestamp serialise byte-for-byte identically regardless of field order.

    The result cannot contain a credential: every model the report embeds is
    built from already-redacted material, and none of them has a field that can
    hold a secret.

    Returns:
        The JSON text, without a trailing newline. The writer adds one.
    """
    return json.dumps(
        report.model_dump(mode="json"),
        indent=2,
        sort_keys=True,
        ensure_ascii=False,
    )


__all__ = ["render_json_report"]
