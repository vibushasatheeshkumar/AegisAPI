"""The ``aegisapi info`` command.

Reports what this installation *is* and what it can *currently do*. The
capability tables distinguish implemented functionality from planned
functionality, and no scan counts, finding totals, or other statistics are
shown, because this command reports capability rather than results: an
assessment's totals belong to ``check show`` and ``risk show``, which read a
specific saved document.
"""

from __future__ import annotations

from pathlib import Path

from rich.console import Console
from rich.table import Table

from aegisapi.commands import theme
from aegisapi.core.config import AegisConfig
from aegisapi.core.paths import WorkspacePaths
from aegisapi.models.common import AppMetadata
from aegisapi.reporting import supported_names

_SUPPORTED_REPORT_FORMATS = supported_names()
"""Report formats the renderer actually implements.

Read from :mod:`aegisapi.reporting` rather than written out here, so the
capability table cannot advertise a format that does not exist.
"""

AVAILABLE_CAPABILITIES: tuple[str, ...] = (
    "Command-line interface with help and version output",
    "Local workspace initialisation (aegisapi init)",
    "TOML configuration loading, validation, and precedence handling",
    "API target management: register, list, inspect, update, remove",
    "Scope configuration and local scope validation (no requests sent)",
    "Authentication profile configuration by environment-variable reference",
    "OpenAPI 3.0/3.1 and Swagger 2.0 specification parsing (local files only)",
    "Endpoint inventory with declared security and schema metadata",
    "Structural relationship observations over discovered operations",
    "Scope-gated HTTP requests with timeouts, size and rate limits",
    "Safe redirect policy and cross-origin credential withholding",
    "Evidence-driven security checks: auth, authorization, input, config, rate limits",
    "Context-aware risk intelligence: relationship graph, correlation, prioritisation",
    "Potential attack paths that separate evidence from inference",
    "Centralised logging with credential redaction",
    "Structured application error reporting",
    "Raw JSON export of saved inventories, check results, and risk reports",
    "One stored document per target for inventory, results, and risk report",
    f"Reader-oriented reports in {_SUPPORTED_REPORT_FORMATS} (aegisapi report generate)",
    "Self-contained HTML reports with a print stylesheet, no scripts, no external assets",
)
"""Functionality that exists today."""

PLANNED_CAPABILITIES: tuple[str, ...] = (
    "Live endpoint probing for undocumented operations",
    "Native PDF reporting, without a browser",
    "Assessment history and comparison between runs",
)
"""Functionality that is designed for but not implemented.

The report formats listed as available are taken from
:data:`aegisapi.reporting.SUPPORTED_FORMATS`, so this table cannot claim a
format the renderer does not implement. PDF stays planned: ``report generate
--format pdf`` refuses rather than substituting another format, and the
supported route to a PDF today is Print to PDF from the HTML report.
"""

AUTHORISATION_NOTICE = "Only assess APIs you own or have explicit written authorisation to test."


def _environment_table(
    metadata: AppMetadata,
    workspace: WorkspacePaths,
    config_path: Path | None,
) -> Table:
    """Build the runtime environment table."""
    table = theme.kv_table("Environment")

    table.add_row("Python version", metadata.python_version)
    table.add_row("Interpreter", metadata.python_executable)
    table.add_row("Platform", metadata.platform)

    workspace_state = "present" if workspace.exists else "not initialised"
    table.add_row("Workspace directory", f"{workspace.root} ({workspace_state})")

    if config_path is None:
        table.add_row(
            "Configuration file",
            "none found - built-in defaults in use (run 'aegisapi init')",
        )
    else:
        table.add_row("Configuration file", str(config_path))
    return table


def _settings_table(config: AegisConfig) -> Table:
    """Build the effective-settings table."""
    table = theme.kv_table("Effective settings")

    hosts = ", ".join(config.scope.allowed_hosts) if config.scope.allowed_hosts else "none"
    table.add_row("Log level", config.log_level.value)
    table.add_row("Request timeout", f"{config.request_timeout_seconds:g} s")
    table.add_row("Max concurrency", str(config.max_concurrency))
    table.add_row("Default report format", config.default_report_format.value)
    table.add_row("Scope enforcement", "enabled" if config.scope.enforce else "disabled")
    table.add_row("Allowed hosts", hosts)
    return table


def _capability_table() -> Table:
    """Build the available-versus-planned capability table.

    Each row keeps its status beside its capability on one line, so the table
    can be scanned for what this build will and will not do.
    """
    table = theme.data_table("Capabilities")
    table.add_column("Status", no_wrap=True)
    table.add_column("Capability", overflow="fold")

    for capability in AVAILABLE_CAPABILITIES:
        table.add_row(theme.status("ok", "Available"), capability)
    for capability in PLANNED_CAPABILITIES:
        table.add_row(theme.status("warn", "Planned"), capability)
    return table


def render_info(
    console: Console,
    *,
    config: AegisConfig,
    workspace: WorkspacePaths,
    config_path: Path | None = None,
) -> None:
    """Print the full information report to ``console``."""
    metadata = AppMetadata.current()

    console.print(theme.banner(version=metadata.version, description=metadata.description))
    console.print()
    console.print(_environment_table(metadata, workspace, config_path))
    console.print()
    console.print(_settings_table(config))
    console.print()
    console.print(_capability_table())
    console.print()
    theme.notice(console, AUTHORISATION_NOTICE)


__all__ = [
    "AUTHORISATION_NOTICE",
    "AVAILABLE_CAPABILITIES",
    "PLANNED_CAPABILITIES",
    "render_info",
]
