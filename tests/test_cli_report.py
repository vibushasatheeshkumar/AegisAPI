"""The ``aegisapi report`` command group.

Reporting reads documents that are already on disk, so these tests seed the
stores directly rather than running an assessment. Nothing here starts a
server, and one test makes any socket use fail outright to prove the command
sends nothing.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from aegisapi.cli import app
from aegisapi.core.config import ENV_PREFIX
from aegisapi.core.exceptions import EXIT_OK, EXIT_REPORT_ERROR, EXIT_TARGET_ERROR
from aegisapi.core.paths import WorkspacePaths
from aegisapi.core.targets import TargetStore
from aegisapi.intelligence import analyse
from aegisapi.models.assessment import CheckOutcome, FindingClass
from aegisapi.models.common import Severity
from aegisapi.models.target import Target
from aegisapi.testing.store import AssessmentStore, IntelligenceStore
from assessfix import assessment_result
from conftest import cli_text
from test_report_model import mixed_discovery, mixed_results

EXIT_DISCOVERY_ERROR = 9
"""The code the assessment store raises with when a document is missing."""


def seed(
    workspace_root: Path,
    *,
    with_intelligence: bool = False,
    target_name: str = "acme",
) -> WorkspacePaths:
    """Create a workspace holding a target and a saved assessment."""
    paths = WorkspacePaths.resolve(workspace_root)
    for directory in paths.directories:
        directory.mkdir(parents=True, exist_ok=True)

    TargetStore.for_workspace(paths).add(
        Target.create(name=target_name, base_url="https://api.acme.test/v1")
    )
    assessment = mixed_results().model_copy(update={"target_name": target_name})
    AssessmentStore.for_workspace(paths).save(assessment, overwrite=True)

    if with_intelligence:
        report = analyse(mixed_discovery(), assessment).model_copy(
            update={"target_name": target_name}
        )
        IntelligenceStore.for_workspace(paths).save(report, overwrite=True)
    return paths


class TestHelp:
    def test_the_group_is_registered(self, runner: CliRunner) -> None:
        output = cli_text(runner.invoke(app, ["--help"]))

        assert "report" in output

    def test_the_group_help_names_the_formats(self, runner: CliRunner) -> None:
        result = runner.invoke(app, ["report", "--help"])
        output = cli_text(result)

        assert result.exit_code == EXIT_OK
        assert "JSON and HTML" in output
        assert "sends no requests" in output

    def test_generate_help_lists_the_options(self, runner: CliRunner) -> None:
        output = cli_text(runner.invoke(app, ["report", "generate", "--help"]))

        for option in ("--format", "--output", "--force", "--include-all"):
            assert option in output

    def test_no_arguments_shows_help(self, runner: CliRunner) -> None:
        output = cli_text(runner.invoke(app, ["report"]))

        assert "Usage" in output


class TestGeneration:
    def test_a_json_report_is_written_to_the_workspace(
        self, runner: CliRunner, workspace_root: Path
    ) -> None:
        paths = seed(workspace_root)

        result = runner.invoke(app, ["report", "generate", "acme", "--format", "json"])

        assert result.exit_code == EXIT_OK
        destination = paths.report_file("acme", "json")
        assert destination.is_file()
        assert json.loads(destination.read_text(encoding="utf-8"))["target_name"] == "acme"

    def test_an_html_report_is_written_to_the_workspace(
        self, runner: CliRunner, workspace_root: Path
    ) -> None:
        paths = seed(workspace_root)

        result = runner.invoke(app, ["report", "generate", "acme", "--format", "html"])

        assert result.exit_code == EXIT_OK
        text = paths.report_file("acme", "html").read_text(encoding="utf-8")
        assert text.startswith("<!DOCTYPE html>")
        assert "Content-Security-Policy" in text

    def test_the_written_path_is_reported(self, runner: CliRunner, workspace_root: Path) -> None:
        seed(workspace_root)

        output = cli_text(runner.invoke(app, ["report", "generate", "acme", "--format", "json"]))

        assert "Written" in output
        assert "acme.json" in output

    def test_the_summary_is_printed(self, runner: CliRunner, workspace_root: Path) -> None:
        seed(workspace_root)

        output = cli_text(runner.invoke(app, ["report", "generate", "acme", "--format", "json"]))

        assert "Confirmed findings" in output
        assert "Potential findings" in output

    def test_an_intelligence_report_is_included_when_saved(
        self, runner: CliRunner, workspace_root: Path
    ) -> None:
        paths = seed(workspace_root, with_intelligence=True)

        result = runner.invoke(app, ["report", "generate", "acme", "--format", "json"])

        assert result.exit_code == EXIT_OK
        document = json.loads(paths.report_file("acme", "json").read_text(encoding="utf-8"))
        assert document["source_intelligence_schema"] == 1
        assert document["risks"]

    def test_a_missing_analysis_is_warned_about_but_succeeds(
        self, runner: CliRunner, workspace_root: Path
    ) -> None:
        paths = seed(workspace_root, with_intelligence=False)

        result = runner.invoke(app, ["report", "generate", "acme", "--format", "json"])
        output = cli_text(result)

        assert result.exit_code == EXIT_OK
        assert "No saved risk analysis" in output
        document = json.loads(paths.report_file("acme", "json").read_text(encoding="utf-8"))
        assert document["source_intelligence_schema"] is None

    def test_include_all_shows_more_results(
        self, runner: CliRunner, workspace_root: Path, tmp_path: Path
    ) -> None:
        seed(workspace_root)
        filtered = tmp_path / "filtered.json"
        everything = tmp_path / "all.json"

        runner.invoke(
            app, ["report", "generate", "acme", "--format", "json", "--output", str(filtered)]
        )
        runner.invoke(
            app,
            [
                "report",
                "generate",
                "acme",
                "--format",
                "json",
                "--output",
                str(everything),
                "--include-all",
            ],
        )

        few = json.loads(filtered.read_text(encoding="utf-8"))
        many = json.loads(everything.read_text(encoding="utf-8"))
        assert len(few["results"]) < len(many["results"])
        assert few["summary"]["results_total"] == many["summary"]["results_total"]


class TestOutputPath:
    def test_output_writes_to_an_explicit_path(
        self, runner: CliRunner, workspace_root: Path, tmp_path: Path
    ) -> None:
        seed(workspace_root)
        destination = tmp_path / "custom" / "my-report.html"

        result = runner.invoke(
            app,
            ["report", "generate", "acme", "--format", "html", "--output", str(destination)],
        )

        assert result.exit_code == EXIT_OK
        assert destination.is_file()

    def test_output_does_not_write_the_default_path(
        self, runner: CliRunner, workspace_root: Path, tmp_path: Path
    ) -> None:
        paths = seed(workspace_root)
        destination = tmp_path / "my-report.json"

        runner.invoke(
            app,
            ["report", "generate", "acme", "--format", "json", "--output", str(destination)],
        )

        assert not paths.report_file("acme", "json").exists()

    def test_the_default_path_uses_the_format_suffix(
        self, runner: CliRunner, workspace_root: Path
    ) -> None:
        paths = seed(workspace_root)

        runner.invoke(app, ["report", "generate", "acme", "--format", "json"])
        runner.invoke(app, ["report", "generate", "acme", "--format", "html"])

        assert paths.report_file("acme", "json").is_file()
        assert paths.report_file("acme", "html").is_file()

    def test_a_directory_output_is_refused(
        self, runner: CliRunner, workspace_root: Path, tmp_path: Path
    ) -> None:
        seed(workspace_root)
        destination = tmp_path / "a-directory"
        destination.mkdir()

        result = runner.invoke(
            app,
            ["report", "generate", "acme", "--format", "json", "--output", str(destination)],
        )

        assert result.exit_code == EXIT_REPORT_ERROR
        assert "found a directory" in cli_text(result)


class TestOverwrite:
    def test_a_second_run_is_refused(self, runner: CliRunner, workspace_root: Path) -> None:
        paths = seed(workspace_root)
        runner.invoke(app, ["report", "generate", "acme", "--format", "json"])
        original = paths.report_file("acme", "json").read_text(encoding="utf-8")

        result = runner.invoke(app, ["report", "generate", "acme", "--format", "json"])

        assert result.exit_code == EXIT_REPORT_ERROR
        assert "already exists" in cli_text(result)
        assert paths.report_file("acme", "json").read_text(encoding="utf-8") == original

    def test_force_replaces_the_report(self, runner: CliRunner, workspace_root: Path) -> None:
        paths = seed(workspace_root)
        destination = paths.report_file("acme", "json")
        runner.invoke(app, ["report", "generate", "acme", "--format", "json"])
        destination.write_text("stale", encoding="utf-8")

        result = runner.invoke(app, ["report", "generate", "acme", "--format", "json", "--force"])

        assert result.exit_code == EXIT_OK
        assert destination.read_text(encoding="utf-8") != "stale"

    def test_the_refusal_mentions_force(self, runner: CliRunner, workspace_root: Path) -> None:
        seed(workspace_root)
        runner.invoke(app, ["report", "generate", "acme", "--format", "json"])

        output = cli_text(runner.invoke(app, ["report", "generate", "acme", "--format", "json"]))

        assert "--force" in output


class TestFormatPrecedence:
    def test_the_flag_wins_over_configuration(
        self, runner: CliRunner, workspace_root: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        paths = seed(workspace_root)
        monkeypatch.setenv(ENV_PREFIX + "REPORT_FORMAT", "json")

        runner.invoke(app, ["report", "generate", "acme", "--format", "html"])

        assert paths.report_file("acme", "html").is_file()
        assert not paths.report_file("acme", "json").exists()

    def test_the_environment_is_used_when_the_flag_is_absent(
        self, runner: CliRunner, workspace_root: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        paths = seed(workspace_root)
        monkeypatch.setenv(ENV_PREFIX + "REPORT_FORMAT", "html")

        result = runner.invoke(app, ["report", "generate", "acme"])

        assert result.exit_code == EXIT_OK
        assert paths.report_file("acme", "html").is_file()

    def test_a_config_file_is_used_when_the_flag_is_absent(
        self, runner: CliRunner, workspace_root: Path
    ) -> None:
        paths = seed(workspace_root)
        paths.config_file.write_text('default_report_format = "html"\n', encoding="utf-8")

        result = runner.invoke(app, ["report", "generate", "acme"])

        assert result.exit_code == EXIT_OK
        assert paths.report_file("acme", "html").is_file()

    def test_the_built_in_default_is_json(self, runner: CliRunner, workspace_root: Path) -> None:
        paths = seed(workspace_root)

        result = runner.invoke(app, ["report", "generate", "acme"])

        assert result.exit_code == EXIT_OK
        assert paths.report_file("acme", "json").is_file()

    def test_the_environment_wins_over_the_file(
        self, runner: CliRunner, workspace_root: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        paths = seed(workspace_root)
        paths.config_file.write_text('default_report_format = "json"\n', encoding="utf-8")
        monkeypatch.setenv(ENV_PREFIX + "REPORT_FORMAT", "html")

        runner.invoke(app, ["report", "generate", "acme"])

        assert paths.report_file("acme", "html").is_file()


class TestPdfRejection:
    def test_the_pdf_flag_is_refused(self, runner: CliRunner, workspace_root: Path) -> None:
        seed(workspace_root)

        result = runner.invoke(app, ["report", "generate", "acme", "--format", "pdf"])
        output = cli_text(result)

        assert result.exit_code == EXIT_REPORT_ERROR
        assert "not implemented" in output
        assert "Print to PDF" in output

    def test_no_file_is_written_when_pdf_is_refused(
        self, runner: CliRunner, workspace_root: Path
    ) -> None:
        paths = seed(workspace_root)

        runner.invoke(app, ["report", "generate", "acme", "--format", "pdf"])

        assert not paths.report_file("acme", "pdf").exists()
        assert not paths.report_file("acme", "json").exists()
        assert list(paths.reports_dir.iterdir()) == []

    def test_pdf_is_never_substituted_with_another_format(
        self, runner: CliRunner, workspace_root: Path, tmp_path: Path
    ) -> None:
        seed(workspace_root)
        destination = tmp_path / "out.pdf"

        result = runner.invoke(
            app,
            ["report", "generate", "acme", "--format", "pdf", "--output", str(destination)],
        )

        assert result.exit_code == EXIT_REPORT_ERROR
        assert not destination.exists()

    def test_a_configured_pdf_default_gives_a_helpful_error(
        self, runner: CliRunner, workspace_root: Path
    ) -> None:
        paths = seed(workspace_root)
        paths.config_file.write_text('default_report_format = "pdf"\n', encoding="utf-8")

        result = runner.invoke(app, ["report", "generate", "acme"])
        output = cli_text(result)

        assert result.exit_code == EXIT_REPORT_ERROR
        assert "default_report_format" in output
        assert "config.toml" in output
        assert "json, html" in output

    def test_a_configured_pdf_default_can_be_overridden_by_the_flag(
        self, runner: CliRunner, workspace_root: Path
    ) -> None:
        paths = seed(workspace_root)
        paths.config_file.write_text('default_report_format = "pdf"\n', encoding="utf-8")

        result = runner.invoke(app, ["report", "generate", "acme", "--format", "html"])

        assert result.exit_code == EXIT_OK
        assert paths.report_file("acme", "html").is_file()


class TestMissingInputs:
    def test_an_unknown_target_is_refused(self, runner: CliRunner, workspace_root: Path) -> None:
        seed(workspace_root)

        result = runner.invoke(app, ["report", "generate", "nope"])

        assert result.exit_code == EXIT_TARGET_ERROR
        assert "nope" in cli_text(result)

    def test_a_missing_assessment_is_refused(self, runner: CliRunner, workspace_root: Path) -> None:
        paths = WorkspacePaths.resolve(workspace_root)
        for directory in paths.directories:
            directory.mkdir(parents=True, exist_ok=True)
        TargetStore.for_workspace(paths).add(
            Target.create(name="acme", base_url="https://api.acme.test/v1")
        )

        result = runner.invoke(app, ["report", "generate", "acme"])
        output = cli_text(result)

        assert result.exit_code == EXIT_DISCOVERY_ERROR
        assert "No assessment is saved" in output
        assert "check run" in output

    def test_nothing_is_written_when_the_assessment_is_missing(
        self, runner: CliRunner, workspace_root: Path
    ) -> None:
        paths = WorkspacePaths.resolve(workspace_root)
        for directory in paths.directories:
            directory.mkdir(parents=True, exist_ok=True)
        TargetStore.for_workspace(paths).add(
            Target.create(name="acme", base_url="https://api.acme.test/v1")
        )

        runner.invoke(app, ["report", "generate", "acme"])

        assert list(paths.reports_dir.iterdir()) == []

    def test_an_empty_assessment_still_produces_a_report(
        self, runner: CliRunner, workspace_root: Path
    ) -> None:
        paths = WorkspacePaths.resolve(workspace_root)
        for directory in paths.directories:
            directory.mkdir(parents=True, exist_ok=True)
        TargetStore.for_workspace(paths).add(
            Target.create(name="acme", base_url="https://api.acme.test/v1")
        )
        AssessmentStore.for_workspace(paths).save(
            assessment_result([]).model_copy(update={"target_name": "acme"}), overwrite=True
        )

        result = runner.invoke(app, ["report", "generate", "acme", "--format", "html"])

        assert result.exit_code == EXIT_OK
        assert "recorded no results" in paths.report_file("acme", "html").read_text(
            encoding="utf-8"
        )


class TestNoNetworkAccess:
    def test_generating_a_report_does_not_open_a_socket(
        self, runner: CliRunner, workspace_root: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Reporting renders saved documents. If it ever reached the API - to
        # re-check something, or to resolve a URL - this would catch it.
        import socket

        paths = seed(workspace_root, with_intelligence=True)

        def forbidden(*args: object, **kwargs: object) -> None:
            raise AssertionError("report generation must not open a network connection")

        monkeypatch.setattr(socket, "socket", forbidden)
        monkeypatch.setattr(socket, "create_connection", forbidden)
        monkeypatch.setattr(socket, "getaddrinfo", forbidden)

        result = runner.invoke(app, ["report", "generate", "acme", "--format", "html"])

        assert result.exit_code == EXIT_OK
        assert paths.report_file("acme", "html").is_file()

    def test_a_disabled_target_can_still_be_reported_on(
        self, runner: CliRunner, workspace_root: Path
    ) -> None:
        # Nothing is contacted, so a disabled target is no obstacle to
        # reporting on results that were gathered while it was enabled.
        paths = seed(workspace_root)
        store = TargetStore.for_workspace(paths)
        store.replace(store.get("acme").model_copy(update={"enabled": False}))

        result = runner.invoke(app, ["report", "generate", "acme", "--format", "json"])

        assert result.exit_code == EXIT_OK
        assert paths.report_file("acme", "json").is_file()


class TestExistingCommandsUnaffected:
    def test_check_show_still_reads_the_saved_assessment(
        self, runner: CliRunner, workspace_root: Path
    ) -> None:
        seed(workspace_root)

        result = runner.invoke(app, ["check", "show", "acme"])

        assert result.exit_code == EXIT_OK

    def test_risk_show_still_reads_the_saved_analysis(
        self, runner: CliRunner, workspace_root: Path
    ) -> None:
        seed(workspace_root, with_intelligence=True)

        result = runner.invoke(app, ["risk", "show", "acme"])

        assert result.exit_code == EXIT_OK

    def test_the_raw_export_still_writes_the_stored_schema(
        self, runner: CliRunner, workspace_root: Path, tmp_path: Path
    ) -> None:
        # 'check run --export' is unchanged: it writes the assessment's own
        # schema, which has no report envelope around it.
        seed(workspace_root)
        destination = tmp_path / "raw.json"
        paths = WorkspacePaths.resolve(workspace_root)
        from aegisapi.testing.store import write_document

        saved = AssessmentStore.for_workspace(paths).load("acme")
        write_document(destination, saved, overwrite=True)

        document = json.loads(destination.read_text(encoding="utf-8"))
        assert "schema_version" in document
        assert "summary" not in document
        assert "source_assessment_schema" not in document

    def test_info_reports_only_implemented_formats(
        self, runner: CliRunner, workspace_root: Path
    ) -> None:
        output = cli_text(runner.invoke(app, ["info"]))

        assert "json, html" in output
        assert "Native PDF reporting" in output


class TestReportContent:
    def test_severities_appear_in_the_html(self, runner: CliRunner, workspace_root: Path) -> None:
        paths = seed(workspace_root)

        runner.invoke(app, ["report", "generate", "acme", "--format", "html"])

        text = paths.report_file("acme", "html").read_text(encoding="utf-8")
        assert Severity.HIGH.value in text
        assert FindingClass.CONFIRMED.value in text
        assert CheckOutcome.FAIL.value in text

    def test_the_html_names_the_target(self, runner: CliRunner, workspace_root: Path) -> None:
        paths = seed(workspace_root)

        runner.invoke(app, ["report", "generate", "acme", "--format", "html"])

        assert "acme" in paths.report_file("acme", "html").read_text(encoding="utf-8")

    def test_attack_paths_appear_when_analysed(
        self, runner: CliRunner, workspace_root: Path
    ) -> None:
        paths = seed(workspace_root, with_intelligence=True)

        runner.invoke(app, ["report", "generate", "acme", "--format", "html"])

        text = paths.report_file("acme", "html").read_text(encoding="utf-8")
        assert "Potential attack paths" in text
        assert "not a demonstrated exploit" in text
