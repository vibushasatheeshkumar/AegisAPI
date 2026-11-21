"""Creation and inspection of the local AegisAPI workspace.

The workspace is a plain directory tree under the user's configuration
location. It holds the user-level ``config.toml`` plus directories that later
subsystems will write into (logs, assessment history, reports, evidence).

Initialisation is **idempotent and non-destructive**: directories are created
only if absent, and an existing ``config.toml`` is never rewritten unless the
caller explicitly asks for it. Nothing here touches files it did not create,
and no network access occurs.
"""

from __future__ import annotations

import os
import stat
import sys
import tempfile
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path

from aegisapi.core.config import render_sample_config
from aegisapi.core.exceptions import WorkspaceError
from aegisapi.core.logging import get_logger
from aegisapi.core.paths import WorkspacePaths

_logger = get_logger(__name__)

DIR_MODE = 0o700
"""POSIX mode for workspace directories: owner access only."""

FILE_MODE = 0o600
"""POSIX mode for workspace files: owner read and write only."""


@dataclass(frozen=True)
class InitResult:
    """What :func:`initialize_workspace` actually changed on disk."""

    paths: WorkspacePaths
    created_directories: tuple[Path, ...] = field(default_factory=tuple)
    created_files: tuple[Path, ...] = field(default_factory=tuple)
    overwritten_files: tuple[Path, ...] = field(default_factory=tuple)
    preserved_files: tuple[Path, ...] = field(default_factory=tuple)

    @property
    def root(self) -> Path:
        """Workspace root directory."""
        return self.paths.root

    @property
    def changed(self) -> bool:
        """``True`` when anything was created or rewritten."""
        return bool(self.created_directories or self.created_files or self.overwritten_files)


def restrict_permissions(path: Path, mode: int) -> None:
    """Tighten permissions on POSIX; rely on inherited ACLs on Windows.

    Windows does not honour POSIX mode bits in a meaningful way, and the
    per-user profile directory is already restricted, so AegisAPI does not
    attempt ACL surgery there.

    Shared with :mod:`aegisapi.core.targets`, so every file AegisAPI writes
    inside the workspace is created the same way.
    """
    if sys.platform == "win32":
        return
    try:
        path.chmod(mode)
    except OSError as exc:  # pragma: no cover - depends on filesystem
        _logger.debug("Could not set permissions on %s: %s", path, exc)


def _ensure_directory(path: Path) -> bool:
    """Create ``path`` if needed. Returns ``True`` when it was created."""
    if path.is_dir():
        return False
    if path.exists():
        raise WorkspaceError(
            f"Cannot create workspace directory because a file already exists there: {path}",
            hint="Move or remove that file, or choose another location with --path.",
        )
    try:
        path.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise WorkspaceError(
            f"Workspace directory could not be created: {path}",
            hint=exc.strerror,
        ) from exc
    restrict_permissions(path, DIR_MODE)
    return True


def write_text_atomic(destination: Path, payload: str) -> None:
    """Write ``payload`` to ``destination`` through a unique temporary file.

    Every document AegisAPI stores is written this way: to a temporary file
    beside the destination, flushed and fsynced, permission-restricted, then
    renamed into place. ``os.replace`` is atomic on Windows and POSIX alike, so
    a reader sees either the previous document or the new one, never a truncated
    mixture, and a failure before the rename leaves the previous document
    untouched.

    **The temporary name is unique per call.** Earlier versions derived it from
    the destination (``<name>.tmp``), which meant two writers aimed at the same
    document shared one scratch file and interleaved their bytes into it. The
    name now comes from :func:`tempfile.mkstemp`, which creates the file with
    ``O_CREAT | O_EXCL``, so each writer owns its own and cleanup can never
    remove another operation's work in progress.

    What this does **not** provide: serialisation between concurrent writers.
    Two writes aimed at one destination still race on the rename. The guarantee
    is only that whichever document arrives is individually intact and complete;
    which one arrives is undefined, and on Windows the losing rename may be
    refused outright with ``ERROR_ACCESS_DENIED`` rather than being quietly
    overwritten. That surfaces as an :exc:`OSError` the caller translates into
    its own error type, which is the right outcome - a failed save is reported
    rather than silently discarded - but it means a concurrent save can fail for
    a reason that has nothing to do with the document. Nothing here makes the
    pair of writers safe to run at once; it makes each one's output trustworthy.

    Args:
        destination: Final path. Its parent must already exist.
        payload: Exact text to write, including any trailing newline.

    Raises:
        OSError: If the temporary file cannot be created, written, or renamed.
            Deliberately not translated here: each caller raises the error type
            its own command contract documents.
    """
    handle_fd, temporary_name = tempfile.mkstemp(
        dir=destination.parent,
        prefix=f"{destination.name}.",
        suffix=".tmp",
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(handle_fd, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        restrict_permissions(temporary, FILE_MODE)
        temporary.replace(destination)
    except OSError:
        # Only ever our own temporary file, because the name is unique to this
        # call. Suppressed on failure so the original error is what propagates.
        try:
            temporary.unlink(missing_ok=True)
        except OSError as cleanup_error:  # pragma: no cover - filesystem dependent
            _logger.debug("Could not remove %s: %s", temporary, cleanup_error)
        raise


def _write_text_file(path: Path, content: str) -> None:
    """Write ``content`` to ``path`` with restrictive permissions."""
    try:
        path.write_text(content, encoding="utf-8", newline="\n")
    except OSError as exc:
        raise WorkspaceError(
            f"File could not be written: {path}",
            hint=exc.strerror,
        ) from exc
    restrict_permissions(path, FILE_MODE)


def initialize_workspace(
    root: str | os.PathLike[str] | None = None,
    *,
    force: bool = False,
    env: Mapping[str, str] | None = None,
) -> InitResult:
    """Create or repair the workspace at ``root``.

    Args:
        root: Workspace location. ``None`` selects the platform default.
        force: Overwrite an existing ``config.toml``. Without this the existing
            file is preserved and reported as such.
        env: Environment mapping used for default path resolution.

    Returns:
        An :class:`InitResult` describing exactly what changed.

    Raises:
        WorkspaceError: If a path is unusable or the filesystem refuses a write.
    """
    paths = WorkspacePaths.resolve(root, env=env)

    created_dirs = tuple(
        directory for directory in paths.directories if _ensure_directory(directory)
    )

    config_file = paths.config_file
    created_files: tuple[Path, ...] = ()
    overwritten_files: tuple[Path, ...] = ()
    preserved_files: tuple[Path, ...] = ()

    if config_file.is_dir():
        raise WorkspaceError(f"Expected a configuration file but found a directory: {config_file}")

    if not config_file.exists():
        _write_text_file(config_file, render_sample_config())
        created_files = (config_file,)
        _logger.debug("Created configuration file %s", config_file)
    elif force:
        _write_text_file(config_file, render_sample_config())
        overwritten_files = (config_file,)
        _logger.debug("Overwrote configuration file %s", config_file)
    else:
        preserved_files = (config_file,)
        _logger.debug("Preserved existing configuration file %s", config_file)

    return InitResult(
        paths=paths,
        created_directories=created_dirs,
        created_files=created_files,
        overwritten_files=overwritten_files,
        preserved_files=preserved_files,
    )


def describe_permissions(path: Path) -> str:
    """Return a short, human-readable permission summary for ``path``.

    On Windows this reports inherited ACLs rather than mode bits, because that
    is what actually governs access there.
    """
    if sys.platform == "win32":
        return "inherited from user profile ACLs"
    try:
        mode = stat.S_IMODE(path.stat().st_mode)
    except OSError:  # pragma: no cover - race with external deletion
        return "unknown"
    return format(mode, "04o")


__all__ = [
    "DIR_MODE",
    "FILE_MODE",
    "InitResult",
    "describe_permissions",
    "initialize_workspace",
    "restrict_permissions",
    "write_text_atomic",
]
