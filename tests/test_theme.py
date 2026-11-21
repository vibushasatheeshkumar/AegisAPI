"""The shared presentation layer.

Two kinds of test here. The first pins the *contract* the command modules rely
on: a label spells out its meaning as well as colouring it, a key-value row
stays on one line, severity is never invented where none was assigned.

The second kind guards a trap found while building this module. Rich resolves a
theme name only as a whole token, so a compound style such as
``"bold http.2xx"`` raises nothing and renders **completely unstyled**. A typo
or a well-meaning ``f"bold {name}"`` would therefore silently remove the colour
from the one column a reader scans for. Those tests assert that every style name
the application uses both exists and actually emits an escape sequence.
"""

from __future__ import annotations

import io
import re
from pathlib import Path

import pytest
from rich.console import Console
from rich.text import Text

from aegisapi.commands import theme
from aegisapi.models.assessment import CheckOutcome, FindingClass
from aegisapi.models.common import Severity
from aegisapi.models.intelligence import Provenance, RiskBand

SOURCE_ROOT = Path(__file__).resolve().parents[1] / "src" / "aegisapi"

_STYLE_REFERENCE = re.compile(r'(?:style|border_style|header_style)=f?"([a-z]+\.[a-z0-9_]+)"')


def render(renderable: object, *, width: int = 100, color: bool = False) -> str:
    """Render through a themed console and return the text."""
    buffer = io.StringIO()
    console = Console(
        file=buffer,
        theme=theme.AEGIS_THEME,
        width=width,
        force_terminal=color,
        color_system="standard" if color else None,
        legacy_windows=False,
    )
    console.print(renderable)
    return buffer.getvalue()


def referenced_style_names() -> set[str]:
    """Every dotted style name the application asks a console for."""
    names: set[str] = set()
    for path in SOURCE_ROOT.rglob("*.py"):
        for match in _STYLE_REFERENCE.finditer(path.read_text(encoding="utf-8")):
            names.add(match.group(1))
    return names


class TestThemeCompleteness:
    def test_the_application_references_some_styles(self) -> None:
        # Guards the two tests below from passing because the scan found nothing.
        assert len(referenced_style_names()) >= 10

    def test_every_referenced_style_is_defined(self) -> None:
        undefined = sorted(referenced_style_names() - set(theme.AEGIS_THEME.styles))

        assert undefined == []

    @pytest.mark.parametrize("name", sorted(referenced_style_names()))
    def test_every_referenced_style_actually_renders(self, name: str) -> None:
        # Resolving is not enough: a style that resolves to nothing renders
        # plain text, which is how a severity column loses its colour without
        # anyone noticing.
        assert "\x1b" in render(Text("x", style=name), color=True), name

    def test_a_compound_theme_name_does_not_render(self) -> None:
        # The trap this module exists to avoid, pinned so nobody reintroduces
        # f"bold {name}" believing it works.
        assert "\x1b" not in render(Text("x", style="bold severity.high"), color=True)

    def test_an_undefined_style_name_fails_silently(self) -> None:
        # Measured, not assumed: Rich neither raises nor warns for a style name
        # it cannot resolve, it just renders plain text. That is precisely why
        # the source scan above exists rather than relying on a runtime error.
        assert "\x1b" not in render(Text("x", style="severity.nonexistent"), color=True)


class TestSeverityLabels:
    @pytest.mark.parametrize(
        ("severity", "expected"),
        [
            (Severity.CRITICAL, "CRITICAL"),
            (Severity.HIGH, "HIGH"),
            (Severity.MEDIUM, "MEDIUM"),
            (Severity.LOW, "LOW"),
            (Severity.INFO, "INFO"),
        ],
    )
    def test_each_severity_has_an_upper_case_label(self, severity: Severity, expected: str) -> None:
        assert theme.severity_label(severity).plain == expected

    def test_an_unassigned_severity_is_a_dash_not_info(self) -> None:
        # A check that declined to assign a severity has said something
        # different from one that assigned the lowest level.
        assert theme.severity_label(None).plain == "-"

    @pytest.mark.parametrize("severity", list(Severity))
    def test_each_severity_is_styled(self, severity: Severity) -> None:
        assert "\x1b" in render(theme.severity_label(severity), color=True)

    def test_critical_and_low_are_visually_distinct(self) -> None:
        critical = render(theme.severity_label(Severity.CRITICAL), color=True)
        low = render(theme.severity_label(Severity.LOW), color=True)

        assert critical != low

    def test_the_label_survives_without_colour(self) -> None:
        # Severity must be readable on a terminal that strips colour, so the
        # word carries the meaning and the colour only reinforces it.
        assert "CRITICAL" in render(theme.severity_label(Severity.CRITICAL))


class TestOtherLabels:
    @pytest.mark.parametrize("band", list(RiskBand))
    def test_band_labels_are_upper_case_and_styled(self, band: RiskBand) -> None:
        label = theme.band_label(band)

        assert label.plain == band.value.upper()
        assert "\x1b" in render(label, color=True)

    @pytest.mark.parametrize("outcome", list(CheckOutcome))
    def test_outcome_labels_keep_the_enum_wording(self, outcome: CheckOutcome) -> None:
        # Lower case on purpose: an outcome is a state, not a grade, and it sits
        # beside the severity column.
        assert theme.outcome_label(outcome).plain == outcome.value

    @pytest.mark.parametrize("finding_class", list(FindingClass))
    def test_finding_labels_keep_the_enum_wording(self, finding_class: FindingClass) -> None:
        assert theme.finding_label(finding_class).plain == finding_class.value

    @pytest.mark.parametrize("provenance", list(Provenance))
    def test_provenance_labels_keep_the_enum_wording(self, provenance: Provenance) -> None:
        assert theme.provenance_label(provenance).plain == provenance.value

    @pytest.mark.parametrize("outcome", list(CheckOutcome))
    def test_every_outcome_has_a_style(self, outcome: CheckOutcome) -> None:
        assert f"outcome.{outcome.value}" in theme.AEGIS_THEME.styles

    @pytest.mark.parametrize("finding_class", list(FindingClass))
    def test_every_finding_class_has_a_style(self, finding_class: FindingClass) -> None:
        assert f"finding.{finding_class.value}" in theme.AEGIS_THEME.styles

    @pytest.mark.parametrize("severity", list(Severity))
    def test_every_severity_has_a_style(self, severity: Severity) -> None:
        assert f"severity.{severity.value}" in theme.AEGIS_THEME.styles

    @pytest.mark.parametrize("band", list(RiskBand))
    def test_every_band_has_a_style(self, band: RiskBand) -> None:
        assert f"band.{band.value}" in theme.AEGIS_THEME.styles

    @pytest.mark.parametrize("provenance", list(Provenance))
    def test_every_provenance_has_a_style(self, provenance: Provenance) -> None:
        assert f"provenance.{provenance.value}" in theme.AEGIS_THEME.styles


class TestTables:
    def test_a_key_value_row_stays_on_one_line(self) -> None:
        # Load-bearing. Output is scanned for a label and its value together,
        # and the CLI tests assert on exactly that.
        table = theme.kv_table("Effective settings")
        table.add_row("Log level", "INFO")

        lines = [line for line in render(table).splitlines() if "Log level" in line]

        assert len(lines) == 1
        assert "INFO" in lines[0]

    def test_a_long_value_wraps_without_moving_the_label(self) -> None:
        table = theme.kv_table()
        table.add_row("Allowed hosts", ", ".join(f"host{index}.example.test" for index in range(8)))

        lines = render(table, width=60).splitlines()
        labelled = [line for line in lines if "Allowed hosts" in line]

        assert len(labelled) == 1
        assert "host0.example.test" in labelled[0]

    def test_a_key_value_table_has_no_header(self) -> None:
        table = theme.kv_table("Identity")
        table.add_row("Host", "api.acme.test")

        assert "Item" not in render(table)
        assert "Value" not in render(table)

    def test_a_titled_table_shows_its_title(self) -> None:
        assert "Effective settings" in render(theme.kv_table("Effective settings"))

    def test_an_untitled_table_shows_no_title(self) -> None:
        table = theme.kv_table()
        table.add_row("Host", "api.acme.test")

        assert render(table).splitlines()[0].strip().startswith("Host")

    def test_a_data_table_shows_its_columns(self) -> None:
        table = theme.data_table("Check results", "Check", "Outcome")
        table.add_row("AUTH-001", "fail")

        output = render(table)

        assert "Check results" in output
        assert "Outcome" in output
        assert "AUTH-001" in output

    def test_a_data_table_row_stays_on_one_line_when_it_fits(self) -> None:
        table = theme.data_table("Capabilities", "Status", "Capability")
        table.add_row("Available", "JSON and HTML reporting")

        lines = [line for line in render(table, width=120).splitlines() if "Available" in line]

        assert len(lines) == 1
        assert "JSON and HTML reporting" in lines[0]

    def test_a_data_table_has_no_outer_frame_on_a_capable_terminal(self) -> None:
        table = theme.data_table("Endpoints", "Operation")
        table.add_row("GET /orders")

        first = render(table).splitlines()[0]

        assert not first.strip().startswith(("+", "|", "┌", "╭"))


class TestBanner:
    def test_the_banner_names_the_product_and_tagline(self) -> None:
        output = render(theme.banner())

        assert "AegisAPI" in output
        assert theme.TAGLINE in output

    def test_the_banner_shows_the_version(self) -> None:
        assert "9.9.9" in render(theme.banner(version="9.9.9"))

    def test_the_banner_can_carry_a_description(self) -> None:
        assert "a description" in render(theme.banner(description="a description"))

    def test_the_banner_omits_the_description_by_default(self) -> None:
        assert len(render(theme.banner()).splitlines()) <= 5

    def test_the_banner_is_a_panel_rich_can_degrade(self) -> None:
        # Not hand-drawn, so Rich substitutes ASCII where Unicode is unavailable.
        assert theme.banner().box is theme.PANEL_BOX


class TestHeadings:
    def test_a_heading_underlines_with_ascii(self) -> None:
        # ASCII so it is identical on every terminal and in a redirected file.
        lines = render(theme.heading("Limitations")).splitlines()

        assert lines[0].strip() == "Limitations"
        assert lines[1].strip() == "-" * len("Limitations")

    def test_print_heading_leaves_a_blank_line_before(self) -> None:
        buffer = io.StringIO()
        console = Console(file=buffer, theme=theme.AEGIS_THEME, width=80)
        theme.print_heading(console, "Summary")

        assert buffer.getvalue().startswith("\n")

    def test_print_heading_can_omit_the_blank_line(self) -> None:
        buffer = io.StringIO()
        console = Console(file=buffer, theme=theme.AEGIS_THEME, width=80)
        theme.print_heading(console, "Summary", blank_before=False)

        assert not buffer.getvalue().startswith("\n")


class TestStatusMessages:
    @pytest.mark.parametrize("kind", ["ok", "warn", "error", "info", "notice"])
    def test_each_kind_is_defined_and_renders(self, kind: str) -> None:
        assert f"status.{kind}" in theme.AEGIS_THEME.styles
        assert "\x1b" in render(theme.status(kind, "Label"), color=True)

    def test_a_status_carries_its_label(self) -> None:
        assert "Written" in render(theme.status("ok", "Written"))

    def test_detail_follows_the_label_on_one_line(self) -> None:
        output = render(theme.status("ok", "Written", "reports/acme.html"))

        assert "Written reports/acme.html" in output

    def test_detail_is_left_unstyled(self) -> None:
        # Detail is usually a path or a name derived from input. Leaving it
        # unstyled keeps markup out of a value the operator supplied.
        text = theme.status("ok", "Written", "reports/acme.html")

        # One span covering the label only, and no base style that would spill
        # onto the detail.
        assert text.style == ""
        assert [(span.start, span.end, span.style) for span in text.spans] == [
            (0, len("Written"), "status.ok")
        ]

    def test_a_status_without_detail_has_no_trailing_space(self) -> None:
        assert theme.status("warn", "Planned").plain == "Planned"

    def test_print_status_writes_one_line(self) -> None:
        buffer = io.StringIO()
        console = Console(file=buffer, theme=theme.AEGIS_THEME, width=80)
        theme.print_status(console, "error", "Error:", "something failed")

        assert buffer.getvalue().count("\n") == 1

    def test_a_notice_is_rendered_as_a_standing_reminder(self) -> None:
        buffer = io.StringIO()
        console = Console(file=buffer, theme=theme.AEGIS_THEME, width=120)
        theme.notice(console, "Only assess APIs you are authorised to test.")

        assert "Only assess APIs you are authorised to test." in buffer.getvalue()


class TestConsoleConstruction:
    def test_the_console_knows_the_theme(self) -> None:
        console = theme.make_console()

        assert console.get_style("severity.critical") is not None

    def test_a_stderr_console_can_be_built(self) -> None:
        assert theme.make_console(stderr=True).stderr is True

    def test_the_console_does_not_force_colour(self) -> None:
        # Rich's own detection is left alone, so piping behaves as before.
        console = theme.make_console()

        assert console._force_terminal is None

    def test_the_console_does_not_force_box_characters(self) -> None:
        # safe_box stays on, which is what substitutes ASCII borders on a
        # terminal that cannot draw them.
        assert theme.make_console().safe_box is True
