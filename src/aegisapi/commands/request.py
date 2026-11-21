"""Presentation for the ``aegisapi request`` command.

Display only. Two things this module is careful about:

* **No credential can be printed**, because an
  :class:`~aegisapi.models.http.HttpResponse` does not contain one. Headers and
  URLs are redacted before they reach the model, so there is nothing here to
  leak even by accident.
* **Response bodies are never rendered as markup.** Everything goes through
  Rich ``Text``, which displays its content literally. A response containing
  ``[bold red]`` or HTML is shown as those characters, not interpreted - an
  API under assessment is exactly the place to expect content crafted to
  exploit whatever renders it.
"""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from aegisapi.commands import theme
from aegisapi.models.http import HttpLimits, HttpResponse

NO_SECURITY_CONCLUSION = (
    "A response says what the API did, not whether it is secure. A 200 does not "
    "mean an endpoint is correctly authorised, and a 401 does not mean it is."
)

_STATUS_STYLES = {
    "2xx": "http.2xx",
    "3xx": "http.3xx",
    "4xx": "http.4xx",
    "5xx": "http.5xx",
}
"""Theme style for each response family. Colours live in the shared theme."""


def _status_text(response: HttpResponse) -> Text:
    """Render the status line with a colour for its family."""
    style = _STATUS_STYLES.get(response.status_class, "http.other")
    label = f"{response.status_code}"
    if response.reason_phrase:
        label = f"{label} {response.reason_phrase}"
    return Text(label, style=style)


def render_response(
    console: Console,
    response: HttpResponse,
    *,
    limits: HttpLimits,
    show_body: bool = True,
    show_headers: bool = True,
) -> None:
    """Print a normalised response."""
    header = Text()
    header.append(f"{response.request.method.value} ", style="aegis.label")
    header.append(f"{response.final_url}\n", style="aegis.accent")
    header.append(_status_text(response))
    header.append(f"  in {response.elapsed_seconds * 1000:.0f} ms")
    console.print(Panel(header, title="Response", border_style="aegis.accent", expand=False))
    console.print()

    summary = theme.kv_table()
    summary.add_column("Item", style="aegis.label")
    summary.add_column("Value", overflow="fold")

    summary.add_row("Status", _status_text(response))
    summary.add_row("Content type", response.content_type or "not declared")
    body_size = f"{response.body_bytes} bytes"
    if response.truncated:
        body_size = f"{body_size} (truncated at the {limits.max_response_bytes}-byte limit)"
    summary.add_row("Body received", body_size)
    summary.add_row(
        "Authentication",
        f"{response.request.auth_method} applied"
        if response.request.authenticated
        else (response.request.auth_method or "none") + " not applied",
    )
    if response.retries:
        summary.add_row("Retries used", str(response.retries))
    if response.redirect_chain:
        summary.add_row("Redirects followed", "\n".join(response.redirect_chain))
    summary.add_row("Scope decision", response.scope_reason)
    console.print(summary)

    if show_headers and response.headers:
        console.print()
        console.print(_headers_table(response))

    if show_body:
        console.print()
        _render_body(console, response)

    console.print()
    if not limits.verify_tls:
        console.print(
            Text(
                "TLS certificate verification was DISABLED. This response cannot be "
                "attributed to the intended host.",
                style="status.error",
            )
        )
    console.print(Text(NO_SECURITY_CONCLUSION, style="aegis.muted"))


def _headers_table(response: HttpResponse) -> Table:
    """Render response headers, already redacted."""
    table = theme.data_table("Response headers")
    table.add_column("Header", style="aegis.label", no_wrap=True)
    table.add_column("Value", overflow="fold")
    for name in sorted(response.headers):
        # Text(), so a header value cannot be interpreted as Rich markup.
        table.add_row(Text(name), Text(response.headers[name]))
    return table


def _render_body(console: Console, response: HttpResponse) -> None:
    """Print the bounded body preview as inert text."""
    if response.body_preview is None:
        if response.body_bytes:
            console.print(
                Text(
                    f"Body not shown: {response.content_type or 'unknown content type'} "
                    "is not previewed as text.",
                    style="aegis.muted",
                )
            )
        else:
            console.print(Text("Empty response body.", style="aegis.muted"))
        return

    console.print(Text("Body preview", style="aegis.label"))
    console.print(Panel(Text(response.body_preview), border_style="aegis.muted", expand=True))
    if response.truncated:
        console.print(Text("Body was truncated by the response size limit.", style="status.warn"))


def render_request_plan(
    console: Console,
    *,
    method: str,
    url: str,
    limits: HttpLimits,
) -> None:
    """Announce what is about to be sent, before sending it."""
    console.print(
        Text("Sending", style="aegis.label"),
        Text(f"{method} {url}", style="aegis.accent"),
    )
    console.print(
        Text(
            f"connect {limits.connect_timeout_seconds:g}s, read "
            f"{limits.read_timeout_seconds:g}s, max {limits.max_response_bytes} bytes, "
            f"{'following' if limits.follow_redirects else 'not following'} redirects",
            style="aegis.muted",
        )
    )


__all__ = [
    "NO_SECURITY_CONCLUSION",
    "render_request_plan",
    "render_response",
]
