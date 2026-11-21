"""The shared presentation layer: one place that decides how AegisAPI looks.

Before this module, every command module carried its own colour literals -
``style="yellow"`` thirty-two times, ``style="bold"`` forty times - and four
separate dictionaries mapped enumerations to colours. Nothing was wrong with any
one of them, but there was no way to change the product's appearance without
editing seven files, and no way to tell whether two commands agreed.

Everything here is **presentation only**. No function makes a decision about
severity, scope, or evidence; each one renders a decision another layer already
made. That boundary is why this module can be imported by every command without
risk: ``commands/`` is a leaf package, so a theme that imports ``rich`` and the
model enumerations creates no cycle.

Three rules shape the choices:

* **Semantic names, not colours.** Call sites ask for ``severity.high``, not
  ``red``. The mapping lives in :data:`AEGIS_THEME` alone, so the palette is one
  edit rather than a search.
* **Let Rich degrade.** Box characters come from :mod:`rich.box` presets and
  colour from the theme, so a terminal without Unicode gets ASCII borders and a
  terminal without colour gets plain text, automatically. Nothing here draws a
  box by hand or emits an escape sequence, because hand-drawn output cannot
  degrade. The one literal character used for a heading underline is ASCII
  ``-``, which is safe everywhere.
* **Restraint.** The 16 ANSI colours are used rather than fixed hex values, so
  the output adopts the reader's own palette instead of fighting it. No emoji,
  no animation, no colour carrying meaning on its own - a severity is always
  spelled out as well as coloured.
"""

from __future__ import annotations

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.theme import Theme

from aegisapi import APP_NAME, __version__
from aegisapi.models.assessment import CheckOutcome, FindingClass
from aegisapi.models.common import Severity
from aegisapi.models.intelligence import Provenance, RiskBand

TAGLINE = "API Security Intelligence"
"""What the product is, in three words, for the banner."""

AEGIS_THEME = Theme(
    {
        # Product identity and structure.
        "aegis.brand": "bold cyan",
        "aegis.version": "cyan",
        "aegis.tagline": "dim",
        "aegis.heading": "bold cyan",
        "aegis.accent": "cyan",
        "aegis.label": "bold",
        "aegis.strong": "bold",
        "aegis.muted": "dim",
        "aegis.border": "cyan",
        "aegis.rule": "dim cyan",
        # Status messages. One shape for every command.
        "status.ok": "bold green",
        "status.warn": "yellow",
        "status.error": "bold red",
        "status.info": "cyan",
        "status.notice": "bold yellow",
        # Binary states inside a table cell: present/absent, enabled/disabled,
        # in scope/out of scope. Unemphasised, because a table of them should
        # not shout.
        "state.ok": "green",
        "state.bad": "red",
        # Severity: impact if a finding is real.
        "severity.critical": "bold red",
        "severity.high": "red",
        "severity.medium": "yellow",
        "severity.low": "cyan",
        "severity.info": "dim",
        "severity.none": "dim",
        # Risk band: where a risk sits in the priority order.
        "band.critical": "bold red",
        "band.high": "red",
        "band.medium": "yellow",
        "band.low": "cyan",
        "band.informational": "dim",
        # What happened when a check ran.
        "outcome.pass": "green",
        "outcome.fail": "red",
        "outcome.needs_review": "yellow",
        "outcome.skipped": "dim",
        "outcome.error": "magenta",
        # How strongly the evidence supports a claim.
        "finding.confirmed": "bold red",
        "finding.suspected": "yellow",
        "finding.informational": "cyan",
        "finding.inconclusive": "dim",
        "finding.none": "dim",
        # Where a relationship came from.
        "provenance.observed": "green",
        "provenance.fixture": "green",
        "provenance.specification": "cyan",
        "provenance.inferred": "yellow",
        "provenance.hypothetical": "dim",
        # Scope classification of a discovered operation.
        "scope.in_scope": "green",
        "scope.out_of_scope": "red",
        "scope.unresolved": "yellow",
        # HTTP response families. Bold is part of the definition rather than
        # something a call site adds: Rich resolves a theme name only as a whole
        # token, so "bold http.2xx" silently renders unstyled.
        "http.2xx": "bold green",
        "http.3xx": "bold cyan",
        "http.4xx": "bold yellow",
        "http.5xx": "bold red",
        "http.other": "bold",
    }
)
"""The product palette. Every style name a call site may use is defined here.

**An undefined name fails silently.** Rich neither raises nor warns for a style
name it cannot resolve; it renders the text unstyled. The same is true of a
compound such as ``"bold severity.high"``, because a theme name resolves only as
a whole token. Either mistake would quietly strip the colour from the column a
reader scans first, so ``tests/test_theme.py`` scans the source for every style
name it uses and asserts that each one both exists here and actually emits an
escape sequence. That test is the guard; this docstring is not.
"""

DATA_BOX = box.SIMPLE_HEAD
"""Box for tables of rows: a rule under the header, no outer frame.

Chosen over Rich's default heavy frame because a frame around every table turns
a page of findings into a page of lines. Rich substitutes ASCII for the rule on
terminals that cannot draw it.
"""

PANEL_BOX = box.ROUNDED
"""Box for the few panels that frame a short, important block."""


def make_console(*, stderr: bool = False) -> Console:
    """Build a console that knows the product palette.

    The application keeps exactly two of these, both built in
    :mod:`aegisapi.cli` and passed down, so a renderer never creates its own and
    every command writes through the same configuration. Rich's own detection is
    left alone: colour, width, and box substitution follow the real terminal, so
    piping or redirecting behaves exactly as it did before this module existed.
    """
    return Console(stderr=stderr, theme=AEGIS_THEME)


def banner(*, version: str = __version__, description: str | None = None) -> Panel:
    """The product banner: name, version, and what the tool is.

    Shown by ``aegisapi info`` and by the no-argument overview, and nowhere
    else. A banner on every command would prepend three lines to the output of
    anything a script pipes, which is a cost paid by the people least likely to
    want it.
    """
    body = Text()
    body.append(APP_NAME, style="aegis.brand")
    body.append("  ")
    body.append(version, style="aegis.version")
    body.append("\n")
    body.append(TAGLINE, style="aegis.tagline")
    if description:
        body.append("\n")
        body.append(description, style="aegis.muted")
    return Panel(body, box=PANEL_BOX, border_style="aegis.border", expand=False)


def heading(title: str) -> Text:
    """A section heading with an ASCII underline.

    Used for blocks that are not a table, so the structure of a long run is
    visible without reading the content. ``-`` rather than a box-drawing
    character so it is identical on every terminal and in a redirected file.
    """
    text = Text(title, style="aegis.heading")
    text.append("\n")
    text.append("-" * len(title), style="aegis.rule")
    return text


def print_heading(console: Console, title: str, *, blank_before: bool = True) -> None:
    """Print a section heading, with the spacing commands use consistently."""
    if blank_before:
        console.print()
    console.print(heading(title))


def kv_table(title: str | None = None) -> Table:
    """A two-column label/value table, borderless.

    The form used for every "here are the facts about one thing" block. The two
    columns stay on one line per row: output is read by people scanning for a
    label, and asserted on by tests that look for a label and its value
    together, so a value must never be pushed onto its own line.
    """
    table = Table(
        title=Text(title, style="aegis.heading") if title else None,
        show_header=False,
        title_justify="left",
        box=None,
    )
    table.add_column("Item", style="aegis.label", no_wrap=True)
    table.add_column("Value", overflow="fold")
    return table


def data_table(title: str | None, *columns: str) -> Table:
    """A table of rows under a consistent header.

    Column behaviour is left to the caller, which adds its own columns when it
    needs widths or wrapping; passing names here covers the common case.
    """
    table = Table(
        title=Text(title, style="aegis.heading") if title else None,
        title_justify="left",
        box=DATA_BOX,
        header_style="aegis.label",
    )
    for name in columns:
        table.add_column(name)
    return table


def severity_label(severity: Severity | None) -> Text:
    """Render a severity as an upper-case label.

    Upper case because severity is what a reader scans for first, and a label
    reads as a label rather than as prose. ``None`` is rendered as ``-`` and
    never as ``INFO``: a check that declined to assign a severity has said
    something different from one that assigned the lowest.
    """
    if severity is None:
        return Text("-", style="severity.none")
    return Text(severity.value.upper(), style=f"severity.{severity.value}")


def band_label(band: RiskBand) -> Text:
    """Render a risk band as an upper-case label, matching severity."""
    return Text(band.value.upper(), style=f"band.{band.value}")


def outcome_label(outcome: CheckOutcome) -> Text:
    """Render what happened when a check ran.

    Lower case, unlike severity: an outcome is a state, not a grade, and
    ``NEEDS_REVIEW`` shouting in a table would compete with the severity column
    it sits beside.
    """
    return Text(outcome.value, style=f"outcome.{outcome.value}")


def finding_label(finding_class: FindingClass) -> Text:
    """Render how strongly the evidence supports a claim."""
    return Text(finding_class.value, style=f"finding.{finding_class.value}")


def provenance_label(provenance: Provenance) -> Text:
    """Render where a relationship came from."""
    return Text(provenance.value, style=f"provenance.{provenance.value}")


def status(kind: str, label: str, detail: str | None = None) -> Text:
    """Build a status message: a styled label, then optional plain detail.

    ``kind`` is one of ``ok``, ``warn``, ``error``, ``info``, or ``notice``.
    The detail is deliberately unstyled - it is usually a path or a name, often
    derived from input, and styling it would invite putting markup there.
    """
    # Built by appending rather than with a base style: a base style would also
    # colour the detail, which is the opposite of the intent above.
    text = Text()
    text.append(label, style=f"status.{kind}")
    if detail is not None:
        text.append(" ")
        text.append(detail)
    return text


def print_status(console: Console, kind: str, label: str, detail: str | None = None) -> None:
    """Print one status message."""
    console.print(status(kind, label, detail))


def notice(console: Console, message: str) -> None:
    """Print a standing reminder, such as the authorisation requirement.

    Separate from :func:`print_status` because these lines are not the outcome
    of anything the command did; they qualify the output every time, and they
    should look the same wherever they appear.
    """
    console.print(Text(message, style="status.notice"))


__all__ = [
    "AEGIS_THEME",
    "DATA_BOX",
    "PANEL_BOX",
    "TAGLINE",
    "band_label",
    "banner",
    "data_table",
    "finding_label",
    "heading",
    "kv_table",
    "make_console",
    "notice",
    "outcome_label",
    "print_heading",
    "print_status",
    "provenance_label",
    "severity_label",
    "status",
]
