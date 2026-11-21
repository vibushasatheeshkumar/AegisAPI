r"""Platform-aware filesystem locations for the AegisAPI workspace.

Path resolution lives in its own module because several future subsystems
(persistence, evidence collection, reporting) need the same answers, and
because the rules are platform-specific enough to deserve focused tests.

Resolution order for the workspace root:

1. ``AEGISAPI_HOME`` environment variable, when set and non-empty.
2. ``%APPDATA%\AegisAPI`` on Windows.
3. ``$XDG_CONFIG_HOME/aegisapi`` or ``~/.config/aegisapi`` elsewhere.
"""

from __future__ import annotations

import os
import sys
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from aegisapi.core.exceptions import WorkspaceError

HOME_ENV_VAR = "AEGISAPI_HOME"
"""Environment variable that relocates the whole workspace."""

CONFIG_FILENAME = "config.toml"
"""Name of the user-level configuration file inside the workspace."""

TARGETS_FILENAME = "targets.json"
"""Name of the registered-target document inside the workspace."""

_WINDOWS_DIR_NAME = "AegisAPI"
_POSIX_DIR_NAME = "aegisapi"


def _environ(env: Mapping[str, str] | None) -> Mapping[str, str]:
    return os.environ if env is None else env


def validate_path_input(raw: str | os.PathLike[str], *, label: str = "path") -> Path:
    """Turn user-supplied text into an absolute :class:`~pathlib.Path`.

    Expands ``~`` and makes the result absolute so later code never depends on
    the process working directory. The path is *not* required to exist.

    Raises:
        WorkspaceError: If the value is empty or contains a NUL byte.
    """
    text = os.fspath(raw)
    if not text.strip():
        raise WorkspaceError(f"The {label} must not be empty.")
    if "\x00" in text:
        raise WorkspaceError(f"The {label} contains an invalid NUL character.")
    try:
        return Path(text).expanduser().resolve(strict=False)
    except OSError as exc:  # pragma: no cover - platform dependent
        raise WorkspaceError(f"The {label} {text!r} is not usable: {exc.strerror}") from exc


def default_workspace_root(env: Mapping[str, str] | None = None) -> Path:
    """Return the user-level workspace root for the current platform."""
    environ = _environ(env)

    override = environ.get(HOME_ENV_VAR, "").strip()
    if override:
        return validate_path_input(override, label=f"{HOME_ENV_VAR} directory")

    if sys.platform == "win32":
        appdata = environ.get("APPDATA", "").strip()
        base = Path(appdata) if appdata else Path.home() / "AppData" / "Roaming"
        return (base / _WINDOWS_DIR_NAME).expanduser().resolve(strict=False)

    xdg = environ.get("XDG_CONFIG_HOME", "").strip()
    base = Path(xdg) if xdg else Path.home() / ".config"
    return (base / _POSIX_DIR_NAME).expanduser().resolve(strict=False)


@dataclass(frozen=True)
class WorkspacePaths:
    """The set of directories and files that make up a workspace."""

    root: Path

    @classmethod
    def resolve(
        cls,
        root: str | os.PathLike[str] | None = None,
        *,
        env: Mapping[str, str] | None = None,
    ) -> WorkspacePaths:
        """Build paths for ``root``, falling back to the platform default."""
        if root is None:
            return cls(root=default_workspace_root(env))
        return cls(root=validate_path_input(root, label="workspace directory"))

    @property
    def config_file(self) -> Path:
        """User-level configuration file."""
        return self.root / CONFIG_FILENAME

    @property
    def targets_file(self) -> Path:
        """Registered targets.

        Created on demand by the first ``aegisapi target add`` rather than by
        ``aegisapi init``, so a fresh workspace can distinguish "no targets yet"
        from "an empty target list was deliberately saved".
        """
        return self.root / TARGETS_FILENAME

    @property
    def logs_dir(self) -> Path:
        """Destination for log files written with ``--log-file``."""
        return self.root / "logs"

    @property
    def discovery_dir(self) -> Path:
        """Saved endpoint inventories, one file per target."""
        return self.root / "discovery"

    def discovery_file(self, target_name: str) -> Path:
        """Saved inventory for one target.

        The caller passes an already-validated target name, which is a
        lowercase slug without dots or separators, so it cannot escape this
        directory.
        """
        return self.discovery_dir / f"{target_name}.json"

    @property
    def assessments_dir(self) -> Path:
        """Reserved for assessment history (planned persistence layer)."""
        return self.root / "assessments"

    @property
    def reports_dir(self) -> Path:
        """Generated reports, one file per target and format."""
        return self.root / "reports"

    def report_file(self, target_name: str, suffix: str) -> Path:
        """Default destination for one target's report in one format.

        The caller passes an already-validated target name, which is a
        lowercase slug without dots or separators, so it cannot escape this
        directory. ``suffix`` is a format extension such as ``json``, chosen by
        AegisAPI rather than supplied by a user.
        """
        return self.reports_dir / f"{target_name}.{suffix}"

    @property
    def evidence_dir(self) -> Path:
        """Reserved for collected evidence (planned evidence layer)."""
        return self.root / "evidence"

    @property
    def directories(self) -> tuple[Path, ...]:
        """Every directory that :func:`aegisapi.core.workspace.initialize_workspace` creates."""
        return (
            self.root,
            self.logs_dir,
            self.discovery_dir,
            self.assessments_dir,
            self.reports_dir,
            self.evidence_dir,
        )

    @property
    def exists(self) -> bool:
        """``True`` when the workspace root is present on disk."""
        return self.root.is_dir()


__all__ = [
    "CONFIG_FILENAME",
    "HOME_ENV_VAR",
    "TARGETS_FILENAME",
    "WorkspacePaths",
    "default_workspace_root",
    "validate_path_input",
]
