"""Persistence for assessment results.

One document per target, under ``<workspace>/assessments/``, written the same
way targets and discovery results are: temporary file, then atomic rename.

This is **plumbing, not history**. The intelligence engine reads an assessment
document rather than re-running every check, so the document has to exist
somewhere. Keeping several runs and comparing them over time is a later phase's
job, and nothing here does it: a second run replaces the first, and only when
the operator asks.
"""

from __future__ import annotations

import json
from pathlib import Path

from pydantic import ValidationError

from aegisapi.core.exceptions import DiscoveryError, format_validation_problems
from aegisapi.core.logging import get_logger
from aegisapi.core.paths import WorkspacePaths
from aegisapi.core.workspace import write_text_atomic
from aegisapi.models.assessment import ASSESSMENT_SCHEMA_VERSION, AssessmentResult
from aegisapi.models.intelligence import (
    INTELLIGENCE_SCHEMA_VERSION,
    IntelligenceReport,
)

_logger = get_logger(__name__)

MAX_DOCUMENT_BYTES = 64 * 1024 * 1024
"""Largest stored document AegisAPI will read back."""


def render_json(document: AssessmentResult | IntelligenceReport) -> str:
    """Serialise a document to stable, readable JSON.

    Keys sorted so two runs over unchanged inputs differ only in timestamps,
    which keeps a stored result diffable.

    Neither document type can contain a credential: assessment evidence is
    built from already-redacted responses, and intelligence references evidence
    by identifier rather than copying it.
    """
    return json.dumps(
        document.model_dump(mode="json"), indent=2, sort_keys=True, ensure_ascii=False
    )


def write_document(
    path: Path,
    document: AssessmentResult | IntelligenceReport,
    *,
    overwrite: bool,
) -> Path:
    """Write a document atomically.

    Raises:
        DiscoveryError: If the file exists and ``overwrite`` is false, the path
            is a directory, or the write fails. The shared error type keeps
            exit codes consistent across the stored-document commands.
    """
    destination = Path(path).expanduser()
    if destination.is_dir():
        raise DiscoveryError(
            f"Expected a file but found a directory: {destination}",
            hint="Choose a file path.",
        )
    if destination.exists() and not overwrite:
        raise DiscoveryError(
            f"A file already exists at {destination}.",
            hint="Pass --force to replace it, or choose another path.",
        )

    payload = render_json(document)
    try:
        destination.parent.mkdir(parents=True, exist_ok=True)
        write_text_atomic(destination, payload + "\n")
    except OSError as exc:
        raise DiscoveryError(
            f"The document could not be written: {destination}", hint=exc.strerror
        ) from exc

    _logger.debug("Wrote %s", destination)
    return destination


def _read_document(source: Path, *, kind: str) -> dict:
    """Read and parse a stored JSON document, reporting problems clearly."""
    if not source.exists():
        raise DiscoveryError(
            f"No {kind} is saved at {source}.",
            hint="Run the command that produces it first.",
        )
    if source.is_dir():
        raise DiscoveryError(f"Expected a file but found a directory: {source}")

    try:
        if source.stat().st_size > MAX_DOCUMENT_BYTES:
            raise DiscoveryError(
                f"The stored {kind} is larger than {MAX_DOCUMENT_BYTES} bytes: {source}"
            )
        raw = source.read_bytes()
    except OSError as exc:
        raise DiscoveryError(f"The {kind} could not be read: {source}", hint=exc.strerror) from exc

    try:
        document = json.loads(raw.decode("utf-8-sig"))
    except UnicodeDecodeError as exc:
        raise DiscoveryError(f"The {kind} is not valid UTF-8 text: {source}") from exc
    except json.JSONDecodeError as exc:
        raise DiscoveryError(
            f"The {kind} is not valid JSON: {source}",
            hint=f"{exc.msg} (line {exc.lineno}, column {exc.colno})",
        ) from exc

    if not isinstance(document, dict):
        raise DiscoveryError(
            f"The {kind} must be a JSON object: {source}",
            hint=f"Found {type(document).__name__}.",
        )
    return document


class AssessmentStore:
    """Reads and writes saved assessment results for one workspace."""

    def __init__(self, paths: WorkspacePaths) -> None:
        self._paths = paths

    @classmethod
    def for_workspace(cls, paths: WorkspacePaths) -> AssessmentStore:
        """Build a store for the given workspace."""
        return cls(paths)

    def path_for(self, target_name: str) -> Path:
        """Where the assessment for one target is stored."""
        return self._paths.assessments_dir / f"{target_name}.json"

    def exists(self, target_name: str) -> bool:
        """``True`` when an assessment is already saved."""
        return self.path_for(target_name).is_file()

    def save(self, result: AssessmentResult, *, overwrite: bool = False) -> Path:
        """Store an assessment for its target."""
        destination = self.path_for(result.target_name)
        if destination.exists() and not overwrite:
            raise DiscoveryError(
                f"An assessment is already saved for target '{result.target_name}': {destination}",
                hint="Pass --force to replace it.",
            )
        return write_document(destination, result, overwrite=True)

    def load(self, target_name: str) -> AssessmentResult:
        """Read back a saved assessment."""
        source = self.path_for(target_name)
        if not source.exists():
            raise DiscoveryError(
                f"No assessment is saved for target '{target_name}'.",
                hint=f"Run 'aegisapi check run {target_name} --save' first.",
            )
        document = _read_document(source, kind="assessment")

        version = document.get("schema_version", ASSESSMENT_SCHEMA_VERSION)
        if isinstance(version, int) and version > ASSESSMENT_SCHEMA_VERSION:
            raise DiscoveryError(
                f"The assessment uses schema version {version}, but this build "
                f"understands version {ASSESSMENT_SCHEMA_VERSION}: {source}",
                hint="Upgrade AegisAPI, or re-run the assessment.",
            )

        try:
            return AssessmentResult.model_validate(document)
        except ValidationError as exc:
            raise DiscoveryError(
                f"The stored assessment is not valid: {source}",
                hint=format_validation_problems(exc),
            ) from exc


class IntelligenceStore:
    """Reads and writes saved intelligence reports for one workspace."""

    def __init__(self, paths: WorkspacePaths) -> None:
        self._paths = paths

    @classmethod
    def for_workspace(cls, paths: WorkspacePaths) -> IntelligenceStore:
        """Build a store for the given workspace."""
        return cls(paths)

    def path_for(self, target_name: str) -> Path:
        """Where the intelligence report for one target is stored."""
        return self._paths.assessments_dir / f"{target_name}.intelligence.json"

    def exists(self, target_name: str) -> bool:
        """``True`` when a report is already saved."""
        return self.path_for(target_name).is_file()

    def save(self, report: IntelligenceReport, *, overwrite: bool = False) -> Path:
        """Store a report for its target."""
        destination = self.path_for(report.target_name)
        if destination.exists() and not overwrite:
            raise DiscoveryError(
                f"An intelligence report is already saved for target "
                f"'{report.target_name}': {destination}",
                hint="Pass --force to replace it.",
            )
        return write_document(destination, report, overwrite=True)

    def load(self, target_name: str) -> IntelligenceReport:
        """Read back a saved report."""
        source = self.path_for(target_name)
        if not source.exists():
            raise DiscoveryError(
                f"No intelligence report is saved for target '{target_name}'.",
                hint=f"Run 'aegisapi risk analyze {target_name} --save' first.",
            )
        document = _read_document(source, kind="intelligence report")

        version = document.get("schema_version", INTELLIGENCE_SCHEMA_VERSION)
        if isinstance(version, int) and version > INTELLIGENCE_SCHEMA_VERSION:
            raise DiscoveryError(
                f"The report uses schema version {version}, but this build understands "
                f"version {INTELLIGENCE_SCHEMA_VERSION}: {source}",
                hint="Upgrade AegisAPI, or re-run the analysis.",
            )

        try:
            return IntelligenceReport.model_validate(document)
        except ValidationError as exc:
            raise DiscoveryError(
                f"The stored report is not valid: {source}",
                hint=format_validation_problems(exc),
            ) from exc


__all__ = [
    "MAX_DOCUMENT_BYTES",
    "AssessmentStore",
    "IntelligenceStore",
    "render_json",
    "write_document",
]
