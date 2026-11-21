"""Presentation for the ``aegisapi target`` commands.

Everything here is display only; the behaviour lives in
:mod:`aegisapi.core.targets` and :mod:`aegisapi.core.scope`.

No function in this module can print a credential, because no target model
holds one. What is shown is the *reference* - the name of an environment
variable - and whether that variable is currently set.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from aegisapi.commands import theme
from aegisapi.core.scope import AUTHORISATION_REMINDER, ScopeDecision
from aegisapi.models.target import AuthMethod, Target

NO_TARGETS_MESSAGE = "No targets are registered."
NO_TARGETS_HINT = "Register one with: aegisapi target add <name> <base-url>"

_CREDENTIAL_SET = "set"
_CREDENTIAL_MISSING = "not set"


def _credential_summary(target: Target, env: Mapping[str, str] | None = None) -> Text:
    """Summarise whether a target's credential references resolve."""
    if target.auth.method is AuthMethod.NONE:
        return Text("n/a", style="aegis.muted")
    status = target.auth.credential_status(dict(env) if env is not None else None)
    if not status:
        return Text("n/a", style="aegis.muted")
    if all(status.values()):
        return Text(_CREDENTIAL_SET, style="state.ok")
    if not any(status.values()):
        return Text(_CREDENTIAL_MISSING, style="state.bad")
    return Text("partial", style="status.warn")


def _enabled_text(target: Target) -> Text:
    """Render the enabled flag."""
    if target.enabled:
        return Text("enabled", style="state.ok")
    return Text("disabled", style="status.warn")


def render_target_table(
    console: Console,
    targets: Sequence[Target],
    *,
    env: Mapping[str, str] | None = None,
) -> None:
    """Print one row per target, with no credential values."""
    if not targets:
        console.print(Text(NO_TARGETS_MESSAGE, style="status.warn"))
        console.print(Text(NO_TARGETS_HINT, style="aegis.muted"))
        return

    table = theme.data_table("Registered targets")
    table.add_column("Name", style="aegis.label", no_wrap=True)
    table.add_column("Base URL", overflow="fold")
    table.add_column("State", no_wrap=True)
    table.add_column("Auth", no_wrap=True)
    table.add_column("Credentials", no_wrap=True)
    table.add_column("Scope", overflow="fold")

    for target in targets:
        table.add_row(
            target.name,
            target.base_url,
            _enabled_text(target),
            target.auth.method.value,
            _credential_summary(target, env),
            target.scope.summary(),
        )

    console.print(table)
    console.print()
    console.print(Text(f"{len(targets)} target(s).", style="aegis.muted"))


def render_target_detail(
    console: Console,
    target: Target,
    *,
    env: Mapping[str, str] | None = None,
) -> None:
    """Print the full configuration of one target."""
    header = Text()
    header.append(target.name, style="aegis.label")
    header.append(f"  {target.base_url}\n", style="aegis.accent")
    header.append(target.description or "(no description)")
    console.print(Panel(header, title="Target", border_style="aegis.accent", expand=False))
    console.print()

    identity = theme.kv_table("Identity")
    identity.add_column("Field", style="aegis.label")
    identity.add_column("Value", overflow="fold")
    identity.add_row("State", _enabled_text(target))
    identity.add_row("Scheme", target.scheme)
    identity.add_row("Host", target.host)
    identity.add_row("Port", str(target.port))
    identity.add_row("Base path", target.base_path)
    identity.add_row("Tags", ", ".join(target.tags) if target.tags else "none")
    identity.add_row("Created", target.created_at.isoformat(timespec="seconds"))
    identity.add_row("Updated", target.updated_at.isoformat(timespec="seconds"))
    console.print(identity)
    console.print()

    console.print(_scope_rules_table(target))
    console.print()
    console.print(_auth_table(target, env=env))
    console.print()
    console.print(Text(AUTHORISATION_REMINDER, style="status.notice"))


def _scope_rules_table(target: Target) -> Table:
    """Render the configured scope rules."""
    rules = target.scope
    table = theme.kv_table("Scope rules")
    table.add_column("Rule", style="aegis.label")
    table.add_column("Value", overflow="fold")

    if rules.include_paths:
        table.add_row("Include paths", "\n".join(rules.include_paths))
    else:
        table.add_row(
            "Include paths",
            Text("none - nothing is in scope", style="state.bad"),
        )
    table.add_row(
        "Exclude paths", "\n".join(rules.exclude_paths) if rules.exclude_paths else "none"
    )
    table.add_row("Extra hosts", "\n".join(rules.extra_hosts) if rules.extra_hosts else "none")
    table.add_row(
        "Extra ports",
        ", ".join(str(port) for port in rules.allowed_ports) if rules.allowed_ports else "none",
    )
    table.add_row("Subdomains", "allowed" if rules.allow_subdomains else "denied")
    return table


def _auth_table(target: Target, *, env: Mapping[str, str] | None = None) -> Table:
    """Render the authentication profile, references only."""
    auth = target.auth
    table = theme.kv_table("Authentication profile")
    table.add_column("Field", style="aegis.label")
    table.add_column("Value", overflow="fold")

    table.add_row("Method", auth.method.value)
    if auth.method is AuthMethod.NONE:
        table.add_row("Credentials", Text("none configured", style="aegis.muted"))
        return table

    if auth.method is AuthMethod.API_KEY:
        table.add_row("Key location", auth.api_key_location.value)
        table.add_row("Key name", auth.api_key_name)
    if auth.username is not None:
        table.add_row("Username", auth.username)

    status = auth.credential_status(dict(env) if env is not None else None)
    for field, ref in auth.references:
        available = status.get(field, False)
        state = (
            Text(_CREDENTIAL_SET, style="state.ok")
            if available
            else Text(_CREDENTIAL_MISSING, style="state.bad")
        )
        value = Text(f"{ref.describe()}  ")
        value.append(state)
        table.add_row(field.replace("_", " ").capitalize(), value)

    if not all(status.values()):
        table.add_row(
            "",
            Text(
                "Set the missing environment variable before an assessment phase uses it.",
                style="status.warn",
            ),
        )
    return table


def render_scope_rules(console: Console, target: Target) -> None:
    """Print only the scope rules for a target."""
    console.print(
        Text(f"Scope for target '{target.name}'", style="aegis.label"),
        Text(f"({target.base_url})", style="aegis.accent"),
    )
    console.print()
    console.print(_scope_rules_table(target))


def render_scope_checks(
    console: Console,
    checks: Sequence[tuple[str, ScopeDecision, ScopeDecision]],
) -> None:
    """Print the verdict for each checked URL.

    Args:
        checks: ``(url, target_decision, global_decision)`` triples. Both gates
            are shown separately so an operator can see which one denied a URL.
    """
    table = theme.data_table("Scope checks")
    table.add_column("URL", overflow="fold")
    table.add_column("Verdict", no_wrap=True)
    table.add_column("Target scope", overflow="fold")
    table.add_column("Global allow-list", overflow="fold")

    for url, target_decision, global_decision in checks:
        allowed = target_decision.allowed and global_decision.allowed
        verdict = (
            Text("in scope", style="state.ok")
            if allowed
            else Text("out of scope", style="state.bad")
        )
        table.add_row(
            url,
            verdict,
            _decision_text(target_decision),
            _decision_text(global_decision),
        )

    console.print(table)
    console.print()
    console.print(
        Text("No requests were sent; this is a local configuration check.", style="aegis.muted")
    )
    console.print(Text(AUTHORISATION_REMINDER, style="status.notice"))


def _decision_text(decision: ScopeDecision) -> Text:
    """Render one decision as a coloured reason."""
    style = "green" if decision.allowed else "red"
    return Text(decision.reason, style=style)


def render_target_saved(
    console: Console,
    target: Target,
    *,
    action: str,
    notes: Sequence[str] = (),
) -> None:
    """Confirm that a target was registered or updated.

    Args:
        action: Past-tense verb for the headline, such as ``"registered"``.
        notes: Consequences the operator should see, such as a scope that is
            now empty. Printed prominently rather than buried.
    """
    console.print(
        Text(f"Target {action}", style="status.ok"),
        Text(f"'{target.name}' -> {target.base_url}"),
    )
    console.print()
    for note in notes:
        console.print(Text(note, style="status.notice"))
    if notes:
        console.print()
    if not target.scope.include_paths:
        console.print(
            Text(
                "Warning: no include paths are configured, so nothing is in scope.",
                style="status.notice",
            )
        )
    else:
        console.print(
            Text(f"In scope: {', '.join(target.scope.include_paths)}", style="aegis.muted")
        )
    if target.auth.requires_credentials:
        missing = [
            field for field, available in target.auth.credential_status().items() if not available
        ]
        if missing:
            console.print(
                Text(
                    f"Credential reference(s) not yet resolvable: {', '.join(missing)}.",
                    style="status.warn",
                )
            )
    console.print(Text(AUTHORISATION_REMINDER, style="status.notice"))


def render_target_removed(console: Console, target: Target) -> None:
    """Confirm that a target was removed."""
    console.print(
        Text("Target removed", style="status.ok"),
        Text(f"'{target.name}' ({target.base_url})"),
    )


__all__ = [
    "NO_TARGETS_HINT",
    "NO_TARGETS_MESSAGE",
    "render_scope_checks",
    "render_scope_rules",
    "render_target_detail",
    "render_target_removed",
    "render_target_saved",
    "render_target_table",
]
