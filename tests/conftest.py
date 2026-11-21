"""Shared test fixtures.

Every test runs against a temporary workspace and a scrubbed environment, so
nothing in the suite reads or writes the developer's real AegisAPI workspace.
No test performs network access.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest
from typer.testing import CliRunner, Result

from aegisapi.core.config import CONFIG_ENV_VAR, ENV_PREFIX
from aegisapi.core.logging import reset_logging
from aegisapi.core.paths import HOME_ENV_VAR
from aegisapi.models.target import AuthProfile, ScopeRules, Target

MANAGED_ENV_VARS = (
    HOME_ENV_VAR,
    CONFIG_ENV_VAR,
    ENV_PREFIX + "LOG_LEVEL",
    ENV_PREFIX + "REQUEST_TIMEOUT",
    ENV_PREFIX + "MAX_CONCURRENCY",
    ENV_PREFIX + "REPORT_FORMAT",
    ENV_PREFIX + "ENFORCE_SCOPE",
    ENV_PREFIX + "ALLOWED_HOSTS",
)


def cli_text(result: Result) -> str:
    """Return a command's combined stdout and stderr.

    AegisAPI writes command output to stdout and diagnostics to stderr; tests
    that only care *that* a message reached the user read both together.
    """
    return result.output


def make_target(
    *,
    name: str = "acme",
    base_url: str = "https://api.acme.test/v1",
    scope: ScopeRules | None = None,
    auth: AuthProfile | None = None,
    enabled: bool = True,
    **extra: object,
) -> Target:
    """Build a target for tests, with scope defaults derived as in production.

    Goes through :meth:`Target.create`, so tests exercise the same derivation
    the ``target add`` command uses rather than a parallel shortcut.
    """
    return Target.create(
        name=name,
        base_url=base_url,
        scope=scope,
        auth=auth,
        enabled=enabled,
        **extra,  # type: ignore[arg-type]
    )


@pytest.fixture(autouse=True)
def isolated_environment(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Remove AegisAPI variables and pin the console width for stable output."""
    for variable in MANAGED_ENV_VARS:
        monkeypatch.delenv(variable, raising=False)
    monkeypatch.setenv("COLUMNS", "200")
    monkeypatch.setenv("TERM", "dumb")
    monkeypatch.delenv("NO_COLOR", raising=False)
    yield
    reset_logging()


@pytest.fixture
def workspace_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Point the default workspace at a temporary directory and return it."""
    root = tmp_path / "workspace"
    monkeypatch.setenv(HOME_ENV_VAR, str(root))
    return root


@pytest.fixture
def runner() -> CliRunner:
    """A Typer CLI runner."""
    return CliRunner()
