"""End-to-end behaviour of the ``aegisapi`` command-line interface."""

from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from aegisapi import APP_NAME, __version__
from aegisapi.cli import app
from aegisapi.commands.info import AUTHORISATION_NOTICE
from aegisapi.core.exceptions import EXIT_CONFIG_ERROR, EXIT_OK
from aegisapi.core.paths import CONFIG_FILENAME
from conftest import cli_text


def line_containing(text: str, needle: str) -> str:
    """Return the first line of ``text`` that contains ``needle``."""
    for line in text.splitlines():
        if needle.lower() in line.lower():
            return line
    raise AssertionError(f"no line containing {needle!r} in:\n{text}")


class TestHelp:
    def test_help_describes_the_product_and_commands(self, runner: CliRunner) -> None:
        result = runner.invoke(app, ["--help"])
        output = cli_text(result)

        assert result.exit_code == EXIT_OK
        assert "Usage" in output
        assert "aegisapi" in output
        assert "API security assessment" in output
        assert "info" in output
        assert "init" in output

    def test_help_lists_the_global_options(self, runner: CliRunner) -> None:
        output = cli_text(runner.invoke(app, ["--help"]))

        for option in ("--version", "--config", "--workspace", "--debug", "--log-file"):
            assert option in output

    def test_help_states_the_authorisation_requirement(self, runner: CliRunner) -> None:
        output = cli_text(runner.invoke(app, ["--help"]))

        assert "authorisation" in output.lower()

    def test_command_help_is_available(self, runner: CliRunner) -> None:
        output = cli_text(runner.invoke(app, ["init", "--help"]))

        assert "--force" in output

    def test_no_arguments_shows_help(self, runner: CliRunner) -> None:
        output = cli_text(runner.invoke(app, []))

        assert "Usage" in output


class TestVersion:
    def test_version_flag_prints_the_single_source_version(self, runner: CliRunner) -> None:
        result = runner.invoke(app, ["--version"])
        output = cli_text(result)

        assert result.exit_code == EXIT_OK
        assert __version__ in output
        assert APP_NAME in output

    def test_version_is_available_as_a_short_flag(self, runner: CliRunner) -> None:
        assert __version__ in cli_text(runner.invoke(app, ["-V"]))

    def test_version_does_not_require_a_workspace(
        self, runner: CliRunner, workspace_root: Path
    ) -> None:
        result = runner.invoke(app, ["--version"])

        assert result.exit_code == EXIT_OK
        assert workspace_root.exists() is False


class TestInfo:
    def test_info_reports_product_and_interpreter_details(
        self, runner: CliRunner, workspace_root: Path
    ) -> None:
        import platform

        result = runner.invoke(app, ["info"])
        output = cli_text(result)

        assert result.exit_code == EXIT_OK
        assert APP_NAME in output
        assert __version__ in output
        assert platform.python_version() in output
        assert "API security assessment" in output

    def test_info_reports_an_uninitialised_workspace(
        self, runner: CliRunner, workspace_root: Path
    ) -> None:
        output = cli_text(runner.invoke(app, ["info"]))

        assert "not initialised" in line_containing(output, "Workspace directory")
        assert "built-in defaults" in line_containing(output, "Configuration file")

    def test_info_separates_available_from_planned_functionality(
        self, runner: CliRunner, workspace_root: Path
    ) -> None:
        output = cli_text(runner.invoke(app, ["info"]))

        assert "Available" in line_containing(output, "Local workspace initialisation")
        # Specification parsing landed in Phase 3, so it moved to Available.
        assert "Available" in line_containing(output, "specification parsing")
        assert "Available" in line_containing(output, "Endpoint inventory")
        # Scope-gated HTTP transport landed in Phase 4.
        assert "Available" in line_containing(output, "Scope-gated HTTP requests")
        # Checks and risk intelligence landed in Phases 5 and 6.
        assert "Available" in line_containing(output, "security checks")
        assert "Available" in line_containing(output, "risk intelligence")
        # Probing on its own initiative, and reporting, are still planned.
        assert "Planned" in line_containing(output, "Live endpoint probing")
        assert "Planned" in line_containing(output, "PDF reporting")
        assert "Planned" in line_containing(output, "Assessment history")

    def test_info_does_not_invent_assessment_statistics(
        self, runner: CliRunner, workspace_root: Path
    ) -> None:
        output = cli_text(runner.invoke(app, ["info"])).lower()

        for invented in ("scans completed", "findings found", "targets scanned", "last scan"):
            assert invented not in output

    def test_info_states_the_authorisation_requirement(
        self, runner: CliRunner, workspace_root: Path
    ) -> None:
        output = cli_text(runner.invoke(app, ["info"]))

        assert AUTHORISATION_NOTICE.split(".")[0] in output

    def test_info_reflects_the_workspace_configuration(
        self, runner: CliRunner, workspace_root: Path
    ) -> None:
        runner.invoke(app, ["init"])
        config_file = workspace_root / CONFIG_FILENAME
        config_file.write_text(
            'log_level = "WARNING"\nmax_concurrency = 9\n'
            '[scope]\nallowed_hosts = ["api.example.com"]\n',
            encoding="utf-8",
        )

        output = cli_text(runner.invoke(app, ["info"]))

        assert "WARNING" in line_containing(output, "Log level")
        assert "9" in line_containing(output, "Max concurrency")
        assert "api.example.com" in line_containing(output, "Allowed hosts")

    def test_info_honours_an_explicit_config_file(
        self, runner: CliRunner, workspace_root: Path, tmp_path: Path
    ) -> None:
        explicit = tmp_path / "engagement.toml"
        explicit.write_text('default_report_format = "html"\n', encoding="utf-8")

        output = cli_text(runner.invoke(app, ["--config", str(explicit), "info"]))

        assert "html" in line_containing(output, "Default report format")

    def test_info_honours_environment_overrides(
        self, runner: CliRunner, workspace_root: Path, monkeypatch
    ) -> None:
        monkeypatch.setenv("AEGISAPI_MAX_CONCURRENCY", "11")

        output = cli_text(runner.invoke(app, ["info"]))

        assert "11" in line_containing(output, "Max concurrency")


class TestInit:
    def test_init_creates_the_workspace(self, runner: CliRunner, workspace_root: Path) -> None:
        result = runner.invoke(app, ["init"])
        output = cli_text(result)

        assert result.exit_code == EXIT_OK
        assert (workspace_root / CONFIG_FILENAME).is_file()
        for subdirectory in ("logs", "assessments", "reports", "evidence"):
            assert (workspace_root / subdirectory).is_dir(), subdirectory
        assert "Workspace ready" in output

    def test_init_is_repeatable_and_preserves_edits(
        self, runner: CliRunner, workspace_root: Path
    ) -> None:
        runner.invoke(app, ["init"])
        config_file = workspace_root / CONFIG_FILENAME
        config_file.write_text('log_level = "ERROR"\n', encoding="utf-8")

        result = runner.invoke(app, ["init"])
        output = cli_text(result)

        assert result.exit_code == EXIT_OK
        assert config_file.read_text(encoding="utf-8") == 'log_level = "ERROR"\n'
        assert "already initialised" in output.lower()
        assert "--force" in output

    def test_init_force_replaces_the_config(self, runner: CliRunner, workspace_root: Path) -> None:
        runner.invoke(app, ["init"])
        config_file = workspace_root / CONFIG_FILENAME
        config_file.write_text('log_level = "ERROR"\n', encoding="utf-8")

        result = runner.invoke(app, ["init", "--force"])

        assert result.exit_code == EXIT_OK
        assert "AegisAPI configuration" in config_file.read_text(encoding="utf-8")

    def test_init_honours_an_explicit_workspace(
        self, runner: CliRunner, workspace_root: Path, tmp_path: Path
    ) -> None:
        elsewhere = tmp_path / "engagement-workspace"

        result = runner.invoke(app, ["--workspace", str(elsewhere), "init"])

        assert result.exit_code == EXIT_OK
        assert (elsewhere / CONFIG_FILENAME).is_file()
        assert workspace_root.exists() is False

    def test_init_does_not_disturb_unrelated_files(
        self, runner: CliRunner, workspace_root: Path
    ) -> None:
        workspace_root.mkdir(parents=True)
        unrelated = workspace_root / "notes.md"
        unrelated.write_text("engagement notes", encoding="utf-8")

        runner.invoke(app, ["init"])

        assert unrelated.read_text(encoding="utf-8") == "engagement notes"

    def test_init_repairs_a_partially_deleted_workspace(
        self, runner: CliRunner, workspace_root: Path
    ) -> None:
        runner.invoke(app, ["init"])
        (workspace_root / "reports").rmdir()

        result = runner.invoke(app, ["init"])

        assert result.exit_code == EXIT_OK
        assert (workspace_root / "reports").is_dir()


class TestErrorHandling:
    def test_missing_config_file_is_reported_without_a_traceback(
        self, runner: CliRunner, workspace_root: Path, tmp_path: Path
    ) -> None:
        result = runner.invoke(app, ["--config", str(tmp_path / "absent.toml"), "info"])
        output = cli_text(result)

        assert result.exit_code == EXIT_CONFIG_ERROR
        assert "Error:" in output
        assert "not found" in output
        assert "Traceback" not in output

    def test_malformed_config_is_reported_with_a_hint(
        self, runner: CliRunner, workspace_root: Path
    ) -> None:
        runner.invoke(app, ["init"])
        (workspace_root / CONFIG_FILENAME).write_text("log_level = \n", encoding="utf-8")

        result = runner.invoke(app, ["info"])
        output = cli_text(result)

        assert result.exit_code == EXIT_CONFIG_ERROR
        assert "not valid TOML" in output
        assert "Hint:" in output
        assert "Traceback" not in output

    def test_unknown_config_key_is_reported(self, runner: CliRunner, workspace_root: Path) -> None:
        runner.invoke(app, ["init"])
        (workspace_root / CONFIG_FILENAME).write_text('log_levl = "DEBUG"\n', encoding="utf-8")

        result = runner.invoke(app, ["info"])
        output = cli_text(result)

        assert result.exit_code == EXIT_CONFIG_ERROR
        assert "Invalid configuration" in output

    def test_unknown_command_is_a_usage_error(self, runner: CliRunner) -> None:
        result = runner.invoke(app, ["scan"])

        assert result.exit_code != EXIT_OK
        assert "Traceback" not in cli_text(result)

    def test_debug_flag_is_accepted(self, runner: CliRunner, workspace_root: Path) -> None:
        result = runner.invoke(app, ["--debug", "info"])

        assert result.exit_code == EXIT_OK

    def test_log_file_is_written_when_requested(
        self, runner: CliRunner, workspace_root: Path, tmp_path: Path
    ) -> None:
        log_file = tmp_path / "logs" / "run.log"

        result = runner.invoke(app, ["--debug", "--log-file", str(log_file), "init"])

        assert result.exit_code == EXIT_OK
        assert log_file.is_file()
        assert "config.toml" in log_file.read_text(encoding="utf-8")
