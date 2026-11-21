"""Persistence for registered targets.

Targets live in a single JSON document inside the workspace, written through a
temporary file and an atomic rename. That matters more than it sounds: a
half-written target file would silently narrow or widen a scope, and a scope
the operator cannot trust is worse than no scope at all.

Handling of a damaged file is deliberately conservative. AegisAPI reports the
problem and refuses to continue; it never discards or rewrites targets it could
not parse, because that file may be the only record of what an engagement was
authorised to touch.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from pydantic import ValidationError

from aegisapi.core.exceptions import (
    DuplicateTargetError,
    InvalidTargetError,
    TargetNotFoundError,
    TargetStoreError,
    format_validation_problems,
)
from aegisapi.core.logging import get_logger
from aegisapi.core.paths import WorkspacePaths
from aegisapi.core.workspace import write_text_atomic
from aegisapi.models.target import Target, TargetCollection, normalize_target_name

_logger = get_logger(__name__)

TARGETS_SCHEMA_VERSION = 1
"""Version written into new target documents.

A document declaring a higher version is refused rather than guessed at: a
newer AegisAPI may have added a scope field whose absence would silently widen
what this build considers authorised.
"""

_MAX_STORE_BYTES = 8 * 1024 * 1024
"""Refuse to parse an implausibly large target file."""


class TargetStore:
    """Reads and writes the target document for one workspace."""

    def __init__(self, path: Path) -> None:
        self._path = path

    @classmethod
    def for_workspace(cls, paths: WorkspacePaths) -> TargetStore:
        """Build a store for the given workspace."""
        return cls(paths.targets_file)

    @property
    def path(self) -> Path:
        """Location of the target document."""
        return self._path

    @property
    def exists(self) -> bool:
        """``True`` when the document is present on disk."""
        return self._path.is_file()

    def load(self) -> TargetCollection:
        """Read and validate the target document.

        A missing file is not an error; it means no targets are registered yet.

        Raises:
            TargetStoreError: If the file is unreadable, is not valid JSON, was
                written by a newer AegisAPI, or fails validation.
        """
        if not self._path.exists():
            return TargetCollection(schema_version=TARGETS_SCHEMA_VERSION)
        if self._path.is_dir():
            raise TargetStoreError(f"Expected the target file but found a directory: {self._path}")

        try:
            if self._path.stat().st_size > _MAX_STORE_BYTES:
                raise TargetStoreError(
                    f"The target file is larger than {_MAX_STORE_BYTES} bytes: {self._path}",
                    hint="This does not look like an AegisAPI target file.",
                )
            raw = self._path.read_bytes()
        except OSError as exc:
            raise TargetStoreError(
                f"The target file could not be read: {self._path}",
                hint=exc.strerror,
            ) from exc

        try:
            document = json.loads(raw.decode("utf-8-sig"))
        except UnicodeDecodeError as exc:
            raise TargetStoreError(
                f"The target file is not valid UTF-8 text: {self._path}"
            ) from exc
        except json.JSONDecodeError as exc:
            raise TargetStoreError(
                f"The target file is not valid JSON: {self._path}",
                hint=f"{exc.msg} (line {exc.lineno}, column {exc.colno})",
            ) from exc

        if not isinstance(document, dict):
            raise TargetStoreError(
                f"The target file must contain a JSON object: {self._path}",
                hint=f"Found {type(document).__name__}.",
            )

        version = document.get("schema_version", TARGETS_SCHEMA_VERSION)
        if isinstance(version, int) and version > TARGETS_SCHEMA_VERSION:
            raise TargetStoreError(
                f"The target file uses schema version {version}, "
                f"but this build understands version {TARGETS_SCHEMA_VERSION}: {self._path}",
                hint="Upgrade AegisAPI, or point --workspace at a different directory.",
            )

        try:
            return TargetCollection.model_validate(document)
        except ValidationError as exc:
            raise TargetStoreError(
                f"The target file contains an invalid target: {self._path}",
                hint=format_validation_problems(exc),
            ) from exc

    def save(self, collection: TargetCollection) -> None:
        """Write the document atomically.

        Serialisation happens here; putting the bytes down is
        :func:`aegisapi.core.workspace.write_text_atomic`, which renames a
        uniquely named temporary file over the original. A reader therefore
        sees either the old document or the new one, never a truncated mixture.

        Raises:
            TargetStoreError: If the directory or file cannot be written.
        """
        payload = json.dumps(
            collection.model_dump(mode="json"),
            indent=2,
            sort_keys=True,
            ensure_ascii=False,
        )
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            write_text_atomic(self._path, payload + "\n")
        except OSError as exc:
            raise TargetStoreError(
                f"The target file could not be written: {self._path}",
                hint=exc.strerror,
            ) from exc
        _logger.debug("Wrote %d target(s) to %s", len(collection.targets), self._path)

    def list_targets(self) -> list[Target]:
        """Every registered target, ordered by name."""
        return self.load().sorted_targets()

    def get(self, name: str) -> Target:
        """Look up one target by name.

        Raises:
            TargetNotFoundError: If no target is registered under that name.
            InvalidTargetError: If the name itself is not a valid target name.
        """
        return self._require(self.load(), self._normalise(name))

    def add(self, target: Target) -> Target:
        """Register a new target.

        Raises:
            DuplicateTargetError: If the name is already taken. Updating an
                existing target is a separate, explicit operation.
        """
        collection = self.load()
        if target.name in collection.targets:
            raise DuplicateTargetError(
                f"A target named '{target.name}' is already registered.",
                hint=f"Use 'aegisapi target update {target.name}', or choose another name.",
            )
        collection.targets[target.name] = target
        self.save(collection)
        _logger.debug("Registered target %s", target.name)
        return target

    def replace(self, target: Target) -> Target:
        """Overwrite an existing target and stamp ``updated_at``.

        Raises:
            TargetNotFoundError: If the target is not registered.
        """
        collection = self.load()
        existing = self._require(collection, target.name)
        updated = target.model_copy(
            update={"created_at": existing.created_at, "updated_at": datetime.now(UTC)}
        )
        collection.targets[updated.name] = updated
        self.save(collection)
        _logger.debug("Updated target %s", updated.name)
        return updated

    def remove(self, name: str) -> Target:
        """Delete a target and return what was removed.

        Raises:
            TargetNotFoundError: If the target is not registered.
        """
        collection = self.load()
        removed = self._require(collection, self._normalise(name))
        del collection.targets[removed.name]
        self.save(collection)
        _logger.debug("Removed target %s", removed.name)
        return removed

    @staticmethod
    def _normalise(name: str) -> str:
        """Canonicalise a user-supplied name, reporting a clear error."""
        try:
            return normalize_target_name(name)
        except ValueError as exc:
            raise InvalidTargetError(str(exc)) from exc

    @staticmethod
    def _require(collection: TargetCollection, name: str) -> Target:
        """Fetch a target or raise, listing what is available."""
        target = collection.targets.get(name)
        if target is not None:
            return target
        available = sorted(collection.targets)
        hint = (
            f"Registered targets: {', '.join(available)}."
            if available
            else "No targets are registered yet. Add one with 'aegisapi target add'."
        )
        raise TargetNotFoundError(f"No target named '{name}' is registered.", hint=hint)


def build_collection(targets: list[Target]) -> TargetCollection:
    """Assemble a collection from a list of targets, for tests and migrations.

    Raises:
        DuplicateTargetError: If two targets share a name.
    """
    mapping: dict[str, Target] = {}
    for target in targets:
        if target.name in mapping:
            raise DuplicateTargetError(f"Duplicate target name: '{target.name}'.")
        mapping[target.name] = target
    return TargetCollection(schema_version=TARGETS_SCHEMA_VERSION, targets=mapping)


__all__ = ["TARGETS_SCHEMA_VERSION", "TargetStore", "build_collection"]
