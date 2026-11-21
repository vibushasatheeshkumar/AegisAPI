"""Presentation for the ``aegisapi discover`` commands.

Display only; the pipeline lives in :mod:`aegisapi.discovery`.

Two things this module is careful about:

* It never prints a credential, because a
  :class:`~aegisapi.models.discovery.DiscoveryResult` cannot contain one. The
  security section shows *declared scheme metadata* - a scheme's name, type,
  and the header it would use - which is documentation, not a secret.
* It labels declarations as declarations. The security table says what the
  document claims; it does not say an endpoint is protected, and the
  relationship table says "observation", not "finding".
"""

from __future__ import annotations

from collections.abc import Sequence

from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from aegisapi.commands import theme
from aegisapi.core.scope import AUTHORISATION_REMINDER
from aegisapi.discovery.classification import server_matches_target
from aegisapi.models.discovery import (
    ClassifiedEndpoint,
    DiscoveryResult,
    ScopeClassification,
)
from aegisapi.models.endpoint import SecurityPosture
from aegisapi.models.target import Target

DEFAULT_ENDPOINT_LIMIT = 25
"""How many endpoints the table shows before summarising the rest."""

NO_REQUESTS_NOTE = (
    "No requests were sent. A specification was parsed locally; nothing was contacted."
)

DECLARATION_NOTE = (
    "Security columns show what the specification declares, not what the API enforces. "
    "Run 'aegisapi check run' to test enforcement against the live API."
)

_CLASSIFICATION_STYLES = {
    ScopeClassification.IN_SCOPE: ("in scope", "scope.in_scope"),
    ScopeClassification.OUT_OF_SCOPE: ("out of scope", "scope.out_of_scope"),
    ScopeClassification.UNRESOLVED: ("unresolved", "scope.unresolved"),
}
"""Label and theme style for each scope classification.

The labels stay here because they are discovery's own wording; only the colours
are shared, through :data:`aegisapi.commands.theme.AEGIS_THEME`.
"""

_POSTURE_LABELS = {
    SecurityPosture.OPERATION_OVERRIDE: "operation override",
    SecurityPosture.INHERITED_GLOBAL: "inherited global",
    SecurityPosture.EXPLICITLY_OPTIONAL: "explicitly optional",
    SecurityPosture.NOT_DECLARED: "not declared",
}


def _classification_text(classification: ScopeClassification) -> Text:
    """Render a classification with its colour."""
    label, style = _CLASSIFICATION_STYLES[classification]
    return Text(label, style=style)


def _security_text(item: ClassifiedEndpoint) -> Text:
    """Render an endpoint's declared security in one cell."""
    declared = item.endpoint.declared_security
    label = _POSTURE_LABELS[declared.posture]
    if declared.posture is SecurityPosture.NOT_DECLARED:
        return Text(label, style="status.warn")
    if declared.permits_anonymous:
        return Text(f"{label} (anonymous permitted)", style="status.warn")
    names = ", ".join(declared.scheme_names)
    return Text(f"{label}: {names}" if names else label, style="state.ok")


def render_specification_panel(console: Console, result: DiscoveryResult) -> None:
    """Print the parsed document's identity and provenance."""
    spec = result.specification
    body = Text()
    body.append(spec.title or "(untitled API)", style="aegis.label")
    if spec.api_version:
        body.append(f"  v{spec.api_version}", style="aegis.accent")
    body.append(f"\n{spec.version.value} ({spec.raw_version}), {spec.format.value}\n")
    body.append(f"{spec.source_path}\n", style="aegis.muted")
    body.append(f"sha256 {spec.source_sha256[:16]}...  {spec.byte_size} bytes", style="aegis.muted")
    console.print(Panel(body, title="Specification", border_style="aegis.accent", expand=False))


def render_summary(console: Console, result: DiscoveryResult, target: Target) -> None:
    """Print counts: endpoints, scope classifications, methods, postures."""
    table = theme.kv_table("Discovery summary")
    table.add_column("Item", style="aegis.label")
    table.add_column("Value", overflow="fold")

    counts = result.classification_counts()
    table.add_row("Target", f"{target.name} ({target.base_url})")
    table.add_row("Operations discovered", str(result.endpoint_count))
    table.add_row(
        "Scope classification",
        ", ".join(f"{_CLASSIFICATION_STYLES[key][0]}: {value}" for key, value in counts.items()),
    )
    methods = result.method_counts()
    table.add_row(
        "Methods", ", ".join(f"{name} {count}" for name, count in methods.items()) or "none"
    )
    table.add_row(
        "Declared servers",
        "\n".join(result.specification.servers) if result.specification.servers else "none",
    )

    postures = {
        _POSTURE_LABELS[key]: value for key, value in result.posture_counts().items() if value
    }
    table.add_row(
        "Declared security",
        ", ".join(f"{name}: {count}" for name, count in postures.items()) or "none",
    )
    anonymous = len(result.endpoints_permitting_anonymous())
    missing = len(result.endpoints_without_security_metadata())
    table.add_row(
        "Operations permitting anonymous access (declared)",
        str(anonymous),
    )
    table.add_row("Operations with no security metadata", str(missing))
    table.add_row("Structural observations", str(len(result.relationships)))
    table.add_row("Parse warnings", str(len(result.warnings)))

    console.print(table)


def render_server_mismatch_notice(
    console: Console, result: DiscoveryResult, target: Target
) -> None:
    """Warn when the document describes a different deployment to the target.

    This is the usual reason an entire inventory lands out of scope, and saying
    so directly saves an operator from assuming the scope rules are broken.
    """
    mismatched = [
        server
        for server in result.specification.servers
        if not server_matches_target(server, target)
    ]
    if not mismatched:
        return
    console.print()
    console.print(
        Text(
            f"Note: the specification declares server(s) {', '.join(mismatched)}, which do "
            f"not match the registered target host '{target.host}'. Endpoints were "
            "classified against the target you registered, so they may all be out of "
            "scope. AegisAPI does not widen a target's scope to match a specification.",
            style="status.warn",
        )
    )


def render_endpoints(
    console: Console,
    result: DiscoveryResult,
    *,
    limit: int = DEFAULT_ENDPOINT_LIMIT,
    only_in_scope: bool = False,
) -> None:
    """Print the endpoint inventory.

    Out-of-scope endpoints are shown by default. Hiding them would conceal what
    the specification declares beyond the engagement's boundary, which is
    exactly what a reviewer needs to see.
    """
    items = [item for item in result.endpoints if item.is_in_scope or not only_in_scope]
    if not items:
        console.print()
        console.print(Text("No operations to display.", style="status.warn"))
        return

    shown = items if limit <= 0 else items[:limit]
    table = theme.data_table("Endpoints")
    table.add_column("Method", style="aegis.label", no_wrap=True)
    table.add_column("Path", overflow="fold")
    table.add_column("Scope", no_wrap=True)
    table.add_column("Declared security", overflow="fold")
    table.add_column("Params", no_wrap=True)
    table.add_column("Tags", overflow="fold")

    for item in shown:
        endpoint = item.endpoint
        table.add_row(
            endpoint.method.value.upper(),
            endpoint.path,
            _classification_text(item.classification),
            _security_text(item),
            str(len(endpoint.parameters)),
            ", ".join(endpoint.tags) or "-",
        )

    console.print()
    console.print(table)
    if len(shown) < len(items):
        console.print(
            Text(
                f"Showing {len(shown)} of {len(items)} operation(s). "
                "Pass --limit 0 to show all, or --export to write the full inventory.",
                style="aegis.muted",
            )
        )


def render_security_schemes(console: Console, result: DiscoveryResult) -> None:
    """Print the declared security schemes.

    Scheme metadata only: a name, a type, and where a credential would travel.
    No credential value exists in a discovery result to print.
    """
    if not result.security_schemes:
        console.print()
        console.print(Text("The specification declares no security schemes.", style="status.warn"))
        return

    table = theme.data_table("Declared security schemes")
    table.add_column("Name", style="aegis.label", no_wrap=True)
    table.add_column("Type", no_wrap=True)
    table.add_column("Detail", overflow="fold")

    for scheme in result.security_schemes:
        details: list[str] = []
        if scheme.scheme:
            details.append(f"scheme: {scheme.scheme}")
        if scheme.bearer_format:
            details.append(f"format: {scheme.bearer_format}")
        if scheme.parameter_name:
            location = scheme.parameter_location or "unspecified"
            details.append(f"{location}: {scheme.parameter_name}")
        if scheme.flows:
            details.append(f"flows: {', '.join(scheme.flows)}")
        if scheme.scopes:
            details.append(f"{len(scheme.scopes)} scope(s)")
        if scheme.open_id_connect_url:
            details.append("discovery URL declared (not fetched)")
        table.add_row(scheme.name, scheme.type.value, "; ".join(details) or "-")

    console.print()
    console.print(table)


def render_relationships(console: Console, result: DiscoveryResult, *, limit: int = 15) -> None:
    """Print structural observations.

    Explicitly labelled as observations. None of these is a security finding,
    and the heading says so rather than leaving a reader to assume.
    """
    if not result.relationships:
        return

    table = theme.data_table("Structural observations (not security findings)")
    table.add_column("Kind", style="aegis.label", no_wrap=True)
    table.add_column("Subject", overflow="fold")
    table.add_column("Operations", no_wrap=True)
    table.add_column("Observation", overflow="fold")

    shown = result.relationships if limit <= 0 else result.relationships[:limit]
    for observation in shown:
        table.add_row(
            observation.kind.value,
            observation.subject,
            str(len(observation.endpoint_keys)),
            observation.description,
        )

    console.print()
    console.print(table)
    if len(shown) < len(result.relationships):
        console.print(
            Text(
                f"Showing {len(shown)} of {len(result.relationships)} observation(s).",
                style="aegis.muted",
            )
        )


def render_warnings(console: Console, result: DiscoveryResult, *, limit: int = 15) -> None:
    """Print parse warnings, grouped counts first."""
    if not result.warnings:
        return

    console.print()
    counts = result.warning_counts()
    console.print(
        Text(
            "Parse warnings: "
            + ", ".join(f"{code.value} ({count})" for code, count in counts.items()),
            style="status.warn",
        )
    )

    shown = result.warnings if limit <= 0 else result.warnings[:limit]
    for warning in shown:
        location = f" at {warning.pointer}" if warning.pointer else ""
        console.print(Text(f"  - {warning.message}{location}", style="aegis.muted"))
    if len(shown) < len(result.warnings):
        console.print(
            Text(f"  ... and {len(result.warnings) - len(shown)} more.", style="aegis.muted")
        )


def render_discovery_result(
    console: Console,
    result: DiscoveryResult,
    target: Target,
    *,
    limit: int = DEFAULT_ENDPOINT_LIMIT,
    only_in_scope: bool = False,
    show_relationships: bool = True,
) -> None:
    """Print the full discovery report."""
    render_specification_panel(console, result)
    console.print()
    render_summary(console, result, target)
    render_server_mismatch_notice(console, result, target)
    render_endpoints(console, result, limit=limit, only_in_scope=only_in_scope)
    render_security_schemes(console, result)
    if show_relationships:
        render_relationships(console, result)
    render_warnings(console, result)

    console.print()
    console.print(Text(NO_REQUESTS_NOTE, style="aegis.muted"))
    console.print(Text(DECLARATION_NOTE, style="aegis.muted"))
    console.print(Text(AUTHORISATION_REMINDER, style="status.notice"))


def render_saved(console: Console, paths: Sequence[str]) -> None:
    """Confirm where a result was written."""
    for path in paths:
        console.print(Text("Written", style="status.ok"), Text(path))


__all__ = [
    "DECLARATION_NOTE",
    "DEFAULT_ENDPOINT_LIMIT",
    "NO_REQUESTS_NOTE",
    "render_discovery_result",
    "render_endpoints",
    "render_relationships",
    "render_saved",
    "render_security_schemes",
    "render_server_mismatch_notice",
    "render_specification_panel",
    "render_summary",
    "render_warnings",
]
