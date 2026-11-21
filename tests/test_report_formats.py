"""Format selection, and the refusal to substitute one format for another.

The important behaviour here is negative: asking for a format this build cannot
produce must fail, and must fail differently depending on whether the choice
came from the command line or from configuration.
"""

from __future__ import annotations

import pytest

from aegisapi.core.exceptions import EXIT_REPORT_ERROR, ReportError
from aegisapi.models.common import ReportFormat
from aegisapi.reporting import (
    SUPPORTED_FORMATS,
    build_report,
    is_supported,
    render,
    render_html_report,
    render_json_report,
    resolve_format,
    suffix_for,
    supported_names,
)
from assessfix import assessment_result, check_result


def sample_report() -> object:
    """A minimal report to render."""
    return build_report(assessment_result([check_result("AUTH-001", "GET /orders")]))


class TestSupportedFormats:
    def test_json_and_html_and_sarif_are_supported(self) -> None:
        assert set(SUPPORTED_FORMATS) == {ReportFormat.JSON, ReportFormat.HTML, ReportFormat.SARIF}

    def test_pdf_is_not_supported(self) -> None:
        assert not is_supported(ReportFormat.PDF)
        assert ReportFormat.PDF not in SUPPORTED_FORMATS

    def test_pdf_remains_in_the_configuration_vocabulary(self) -> None:
        # The enum documents the roadmap; support is a separate question, and
        # removing the member would break an existing config.toml.
        assert ReportFormat.PDF in list(ReportFormat)

    def test_the_supported_names_read_as_a_list(self) -> None:
        assert supported_names() == "json, html, sarif"

    @pytest.mark.parametrize(
        ("report_format", "expected"),
        [(ReportFormat.JSON, "json"), (ReportFormat.HTML, "html")],
    )
    def test_the_suffix_is_the_format_name(
        self, report_format: ReportFormat, expected: str
    ) -> None:
        assert suffix_for(report_format) == expected


class TestPrecedence:
    def test_an_explicit_format_wins(self) -> None:
        assert resolve_format(ReportFormat.HTML, ReportFormat.JSON) is ReportFormat.HTML

    def test_the_configured_default_is_used_when_nothing_is_explicit(self) -> None:
        assert resolve_format(None, ReportFormat.HTML) is ReportFormat.HTML

    def test_a_supported_explicit_format_overrides_an_unsupported_default(self) -> None:
        assert resolve_format(ReportFormat.JSON, ReportFormat.PDF) is ReportFormat.JSON


class TestRefusals:
    def test_an_explicit_pdf_is_refused(self) -> None:
        with pytest.raises(ReportError) as excinfo:
            resolve_format(ReportFormat.PDF, ReportFormat.JSON)

        assert "not implemented" in excinfo.value.message
        assert "Print to PDF" in str(excinfo.value.hint)
        assert excinfo.value.exit_code == EXIT_REPORT_ERROR

    def test_a_configured_pdf_default_is_refused_with_a_different_message(self) -> None:
        with pytest.raises(ReportError) as excinfo:
            resolve_format(None, ReportFormat.PDF)

        # The operator needs to be sent to the file, not to their command line.
        assert "default_report_format" in excinfo.value.message
        assert "config.toml" in str(excinfo.value.hint)

    def test_the_two_refusals_differ(self) -> None:
        with pytest.raises(ReportError) as from_flag:
            resolve_format(ReportFormat.PDF, ReportFormat.JSON)
        with pytest.raises(ReportError) as from_config:
            resolve_format(None, ReportFormat.PDF)

        assert from_flag.value.message != from_config.value.message

    def test_both_refusals_name_the_supported_formats(self) -> None:
        with pytest.raises(ReportError) as from_flag:
            resolve_format(ReportFormat.PDF, ReportFormat.JSON)
        with pytest.raises(ReportError) as from_config:
            resolve_format(None, ReportFormat.PDF)

        assert "json, html" in str(from_flag.value.hint)
        assert "json, html" in str(from_config.value.hint)

    def test_rendering_an_unsupported_format_refuses_rather_than_substituting(self) -> None:
        # The guard behind resolve_format: a new ReportFormat member must not
        # fall through to whichever renderer happens to be last.
        with pytest.raises(ReportError, match="not implemented"):
            render(sample_report(), ReportFormat.PDF)  # type: ignore[arg-type]


class TestRenderDispatch:
    def test_json_dispatches_to_the_json_renderer(self) -> None:
        report = sample_report()

        assert render(report, ReportFormat.JSON) == render_json_report(report)  # type: ignore[arg-type]

    def test_html_dispatches_to_the_html_renderer(self) -> None:
        report = sample_report()

        assert render(report, ReportFormat.HTML) == render_html_report(report)  # type: ignore[arg-type]

    def test_the_two_formats_produce_different_text(self) -> None:
        report = sample_report()

        assert render(report, ReportFormat.JSON) != render(report, ReportFormat.HTML)  # type: ignore[arg-type]

    def test_every_supported_format_renders_without_error(self) -> None:
        report = sample_report()

        for report_format in SUPPORTED_FORMATS:
            assert render(report, report_format).strip()  # type: ignore[arg-type]
