"""AegisAPI - a CLI-first API security assessment platform.

This module is the single authoritative source for the application's name,
version, and description. Packaging metadata in ``pyproject.toml`` reads the
version from here via setuptools' dynamic metadata, so the version string is
never duplicated.
"""

from __future__ import annotations

__version__ = "0.1.0"

APP_NAME = "AegisAPI"
APP_SLUG = "aegisapi"
APP_DESCRIPTION = (
    "CLI-first API security assessment platform for bug bounty hunters and penetration testers."
)

__all__ = ["APP_DESCRIPTION", "APP_NAME", "APP_SLUG", "__version__"]
