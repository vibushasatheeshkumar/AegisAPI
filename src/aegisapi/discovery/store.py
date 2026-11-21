"""Persistence for discovery results.

A saved inventory is one JSON document per target under
``<workspace>/discovery/``, written the same way targets are: to a temporary
file, then renamed into place. The reasoning is the same too - a half-written
inventory would misrepresent what an API exposes, and later phases are meant to
trust this file.

Overwriting is deliberate and explicit. Re-running discovery replaces a saved
result only when the caller passes ``overwrite``, because the previous result
may be the record of what an engagement was scoped against. A corrupt file is
reported, never silently replaced.

This is not assessment history. One result per target is kept; comparing runs
over time belongs to the planned persistence layer.
"""

from __future__ import annotations

import json
from pathlib import Path

from pydantic import ValidationError

from aegisapi.core.exceptions import (
    DiscoveryError,
    format_validation_problems,
)
from aegisapi.core.logging import get_logger
from aegisapi.core.paths import WorkspacePaths
from aegisapi.core.workspace import write_text_atomic
from aegisapi.models.discovery import DISCOVERY_SCHEMA_VERSION, DiscoveryResult

_logger = get_logger(__name__)

MAX_RESULT_BYTES = 64 * 1024 * 1024
"""Largest stored result AegisAPI will read back."""


def render_result_json(result: DiscoveryResult) -> str:
    """Serialise a discovery result to stable, readable JSON.

    Keys are sorted so two runs over an unchanged specification produce
    identical bytes apart from the timestamp, which keeps a stored result
    diffable.

    Nothing in a :class:`~aegisapi.models.discovery.DiscoveryResult` can hold a
    credential: the target is referenced by name, and security schemes are
    metadata. There is no authentication profile in this document to leak.
    """
    return json.dumps(result.model_dump(mode="json"), indent=2, sort_keys=True, ensure_ascii=False)


def write_result_file(path: Path, result: DiscoveryResult, *, overwrite: bool) -> Path:
    """Write a discovery result to ``path`` atomically.

    Args:
        path: Destination file.
        result: The result to serialise.
        overwrite: Whether an existing file may be replaced.

    Raises:
        DiscoveryError: If the file exists and ``overwrite`` is false, if the
            path is a directory, or if the write fails.
    """
    destination = Path(path).expanduser()
    if destination.is_dir():
        raise DiscoveryError(
            f"Expected a file but found a directory: {destination}",
            hint="Choose a file path for the export.",
        )
    if destination.exists() and not overwrite:
        raise DiscoveryError(
            f"A file already exists at {destination}.",
            hint="Pass --force to replace it, or choose another path.",
        )

    payload = render_result_json(result)
    try:
        destination.parent.mkdir(parents=True, exist_ok=True)
        write_text_atomic(destination, payload + "\n")
    except OSError as exc:
        raise DiscoveryError(
            f"The discovery result could not be written: {destination}",
            hint=exc.strerror,
        ) from exc

    _logger.debug("Wrote discovery result to %s", destination)
    return destination


class DiscoveryStore:
    """Reads and writes saved discovery results for one workspace."""

    def __init__(self, paths: WorkspacePaths) -> None:
        self._paths = paths

    @classmethod
    def for_workspace(cls, paths: WorkspacePaths) -> DiscoveryStore:
        """Build a store for the given workspace."""
        return cls(paths)

    def path_for(self, target_name: str) -> Path:
        """Where the result for one target is stored."""
        return self._paths.discovery_file(target_name)

    def exists(self, target_name: str) -> bool:
        """``True`` when a result is already saved for this target."""
        return self.path_for(target_name).is_file()

    def save(self, result: DiscoveryResult, *, overwrite: bool = False) -> Path:
        """Store a result for its target.

        Raises:
            DiscoveryError: If a result is already saved and ``overwrite`` is
                false, or if the write fails.
        """
        destination = self.path_for(result.target_name)
        if destination.exists() and not overwrite:
            raise DiscoveryError(
                f"A discovery result is already saved for target "
                f"'{result.target_name}': {destination}",
                hint="Pass --force to replace it.",
            )
        return write_result_file(destination, result, overwrite=True)

    def load(self, target_name: str) -> DiscoveryResult:
        """Read back a saved result.

        Raises:
            DiscoveryError: If no result is saved, or the stored file is
                unreadable, malformed, or written by a newer AegisAPI.
        """
        source = self.path_for(target_name)
        if not source.exists():
            raise DiscoveryError(
                f"No discovery result is saved for target '{target_name}'.",
                hint=f"Run 'aegisapi discover spec {target_name} --file <spec> --save' first.",
            )
        if source.is_dir():
            raise DiscoveryError(f"Expected a file but found a directory: {source}")

        try:
            if source.stat().st_size > MAX_RESULT_BYTES:
                raise DiscoveryError(
                    f"The stored discovery result is larger than {MAX_RESULT_BYTES} bytes: {source}"
                )
            raw = source.read_bytes()
        except OSError as exc:
            raise DiscoveryError(
                f"The discovery result could not be read: {source}",
                hint=exc.strerror,
            ) from exc

        try:
            document = json.loads(raw.decode("utf-8-sig"))
        except UnicodeDecodeError as exc:
            raise DiscoveryError(f"The discovery result is not valid UTF-8 text: {source}") from exc
        except json.JSONDecodeError as exc:
            raise DiscoveryError(
                f"The discovery result is not valid JSON: {source}",
                hint=f"{exc.msg} (line {exc.lineno}, column {exc.colno})",
            ) from exc

        if not isinstance(document, dict):
            raise DiscoveryError(
                f"The discovery result must be a JSON object: {source}",
                hint=f"Found {type(document).__name__}.",
            )

        version = document.get("schema_version", DISCOVERY_SCHEMA_VERSION)
        if isinstance(version, int) and version > DISCOVERY_SCHEMA_VERSION:
            raise DiscoveryError(
                f"The discovery result uses schema version {version}, but this build "
                f"understands version {DISCOVERY_SCHEMA_VERSION}: {source}",
                hint="Upgrade AegisAPI, or re-run discovery to regenerate it.",
            )

        try:
            return DiscoveryResult.model_validate(document)
        except ValidationError as exc:
            raise DiscoveryError(
                f"The stored discovery result is not valid: {source}",
                hint=format_validation_problems(exc),
            ) from exc


__all__ = ["MAX_RESULT_BYTES", "DiscoveryStore", "render_result_json", "write_result_file"]
