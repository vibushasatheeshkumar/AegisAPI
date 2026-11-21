"""The ``aegisapi init`` command.

The filesystem work lives in :mod:`aegisapi.core.workspace`; this module only
turns an :class:`~aegisapi.core.workspace.InitResult` into terminal output, so
that the behaviour can be tested without a console.
"""

from __future__ import annotations

from rich.console import Console
from rich.table import Table
from rich.text import Text

from aegisapi.commands import theme
from aegisapi.core.workspace import InitResult, describe_permissions

NEXT_STEPS = (
    "Review the configuration file and add the hosts you are authorised to assess.",
    "Run 'aegisapi info' to confirm the configuration AegisAPI will use.",
)


def _changes_table(result: InitResult) -> Table:
    """Summarise created, rewritten, and preserved paths."""
    table = theme.data_table("Workspace changes")
    table.add_column("Action", style="aegis.label", no_wrap=True)
    table.add_column("Path", overflow="fold")

    for directory in result.created_directories:
        table.add_row(Text("created", style="state.ok"), str(directory))
    for path in result.created_files:
        table.add_row(Text("created", style="state.ok"), str(path))
    for path in result.overwritten_files:
        table.add_row(Text("overwritten", style="status.warn"), str(path))
    for path in result.preserved_files:
        table.add_row(Text("preserved", style="aegis.accent"), str(path))

    if not result.changed and not result.preserved_files:  # pragma: no cover - defensive
        table.add_row(Text("unchanged", style="aegis.muted"), str(result.root))
    return table


def render_init_result(console: Console, result: InitResult) -> None:
    """Print the outcome of workspace initialisation to ``console``."""
    if result.changed:
        console.print(
            Text("Workspace ready", style="status.ok"),
            Text(f"at {result.root}"),
        )
    else:
        console.print(
            Text("Workspace already initialised", style="aegis.heading"),
            Text(f"at {result.root}"),
        )

    console.print()
    console.print(_changes_table(result))
    console.print()
    console.print(
        Text(
            f"Directory permissions: {describe_permissions(result.root)}",
            style="aegis.muted",
        )
    )

    if result.preserved_files:
        console.print(
            Text(
                "Existing configuration was left untouched. "
                "Pass --force to replace it with a fresh sample.",
                style="status.warn",
            )
        )

    console.print()
    console.print(Text("Next steps:", style="aegis.label"))
    for step in NEXT_STEPS:
        console.print(Text(f"  - {step}"))


__all__ = ["NEXT_STEPS", "render_init_result"]
