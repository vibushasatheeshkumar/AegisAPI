"""End-to-end behaviour of the ``aegisapi target`` commands."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from aegisapi.cli import app
from aegisapi.core.exceptions import (
    EXIT_OK,
    EXIT_SCOPE_ERROR,
    EXIT_TARGET_ERROR,
)
from aegisapi.core.paths import TARGETS_FILENAME
from conftest import cli_text
from test_cli import line_containing

TOKEN_VALUE = "eyJhbGciOiJIUzI1NiJ9.super-secret-token-value"


def add_acme(runner: CliRunner, *extra: str) -> None:
    """Register the standard test target, failing loudly if that does not work."""
    result = runner.invoke(app, ["target", "add", "acme", "https://api.acme.test/v1", *extra])
    assert result.exit_code == EXIT_OK, cli_text(result)


class TestHelp:
    def test_target_group_is_listed_in_the_root_help(self, runner: CliRunner) -> None:
        output = cli_text(runner.invoke(app, ["--help"]))

        assert "target" in output

    def test_group_help_lists_every_subcommand(self, runner: CliRunner) -> None:
        output = cli_text(runner.invoke(app, ["target", "--help"]))

        for command in ("add", "list", "show", "update", "remove", "scope"):
            assert command in output

    def test_group_help_states_that_no_requests_are_sent(self, runner: CliRunner) -> None:
        output = cli_text(runner.invoke(app, ["target", "--help"]))

        assert "never send a request" in output

    def test_add_help_documents_the_credential_convention(self, runner: CliRunner) -> None:
        output = cli_text(runner.invoke(app, ["target", "add", "--help"]))

        assert "--token-env" in output
        assert "NAME of the environment variable" in output

    def test_no_subcommand_shows_help(self, runner: CliRunner) -> None:
        output = cli_text(runner.invoke(app, ["target"]))

        assert "Usage" in output


class TestAdd:
    def test_add_registers_and_persists_the_target(
        self, runner: CliRunner, workspace_root: Path
    ) -> None:
        result = runner.invoke(app, ["target", "add", "acme", "https://api.acme.test/v1"])
        output = cli_text(result)

        assert result.exit_code == EXIT_OK
        assert "registered" in output
        document = json.loads((workspace_root / TARGETS_FILENAME).read_text(encoding="utf-8"))
        assert document["targets"]["acme"]["base_url"] == "https://api.acme.test/v1"

    def test_add_derives_scope_from_the_base_url(
        self, runner: CliRunner, workspace_root: Path
    ) -> None:
        output = cli_text(runner.invoke(app, ["target", "add", "acme", "https://api.acme.test/v1"]))

        assert "In scope: /v1" in output

    def test_add_accepts_full_scope_and_auth_options(
        self, runner: CliRunner, workspace_root: Path
    ) -> None:
        result = runner.invoke(
            app,
            [
                "target",
                "add",
                "acme",
                "https://api.acme.test/v1",
                "--description",
                "Acme API",
                "--tag",
                "prod",
                "--include-path",
                "/v1/**",
                "--exclude-path",
                "/v1/admin",
                "--extra-host",
                "cdn.acme.test",
                "--allowed-port",
                "8443",
                "--allow-subdomains",
                "--auth-method",
                "bearer",
                "--token-env",
                "ACME_TOKEN",
            ],
        )

        assert result.exit_code == EXIT_OK, cli_text(result)
        stored = json.loads((workspace_root / TARGETS_FILENAME).read_text(encoding="utf-8"))
        target = stored["targets"]["acme"]
        assert target["scope"]["include_paths"] == ["/v1/**"]
        assert target["scope"]["exclude_paths"] == ["/v1/admin"]
        assert target["scope"]["extra_hosts"] == ["cdn.acme.test"]
        assert target["scope"]["allowed_ports"] == [8443]
        assert target["scope"]["allow_subdomains"] is True
        assert target["auth"]["token"] == {"provider": "env", "variable": "ACME_TOKEN"}

    def test_add_never_writes_a_credential_value(
        self, runner: CliRunner, workspace_root: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("ACME_TOKEN", TOKEN_VALUE)

        add_acme(runner, "--auth-method", "bearer", "--token-env", "ACME_TOKEN")

        contents = (workspace_root / TARGETS_FILENAME).read_text(encoding="utf-8")
        assert "ACME_TOKEN" in contents
        assert TOKEN_VALUE not in contents

    def test_add_reports_a_credential_that_is_not_set(
        self, runner: CliRunner, workspace_root: Path
    ) -> None:
        result = runner.invoke(
            app,
            [
                "target",
                "add",
                "acme",
                "https://api.acme.test/v1",
                "--auth-method",
                "bearer",
                "--token-env",
                "ACME_TOKEN",
            ],
        )

        assert "not yet resolvable" in cli_text(result)

    def test_add_can_register_a_disabled_target(
        self, runner: CliRunner, workspace_root: Path
    ) -> None:
        add_acme(runner, "--disabled")

        output = cli_text(runner.invoke(app, ["target", "list"]))
        assert "disabled" in output

    def test_add_states_that_registration_is_not_authorisation(
        self, runner: CliRunner, workspace_root: Path
    ) -> None:
        output = cli_text(runner.invoke(app, ["target", "add", "acme", "https://api.acme.test/v1"]))

        assert "not" in output.lower()
        assert "authorisation" in output.lower()

    def test_duplicate_name_is_refused(self, runner: CliRunner, workspace_root: Path) -> None:
        add_acme(runner)

        result = runner.invoke(app, ["target", "add", "acme", "https://api.acme.test/v1"])
        output = cli_text(result)

        assert result.exit_code == EXIT_TARGET_ERROR
        assert "already registered" in output
        assert "Traceback" not in output

    @pytest.mark.parametrize(
        "base_url",
        [
            "ftp://api.acme.test",
            "api.acme.test",
            "https://api.acme.test@attacker.test",
            "https://api.acme.test/v1#frag",
        ],
    )
    def test_invalid_base_url_is_refused(
        self, runner: CliRunner, workspace_root: Path, base_url: str
    ) -> None:
        result = runner.invoke(app, ["target", "add", "acme", base_url])

        assert result.exit_code == EXIT_TARGET_ERROR
        assert "Error:" in cli_text(result)

    def test_invalid_name_is_refused(self, runner: CliRunner, workspace_root: Path) -> None:
        result = runner.invoke(app, ["target", "add", "not a name", "https://api.acme.test"])

        assert result.exit_code == EXIT_TARGET_ERROR
        assert "target name" in cli_text(result)

    def test_pasting_a_token_instead_of_a_variable_name_is_refused(
        self, runner: CliRunner, workspace_root: Path
    ) -> None:
        result = runner.invoke(
            app,
            [
                "target",
                "add",
                "acme",
                "https://api.acme.test",
                "--auth-method",
                "bearer",
                "--token-env",
                TOKEN_VALUE,
            ],
        )
        output = cli_text(result)

        assert result.exit_code == EXIT_TARGET_ERROR
        # The mistaken value must not be echoed back into the terminal.
        assert TOKEN_VALUE not in output
        assert "not a valid environment variable name" in output
        assert (workspace_root / TARGETS_FILENAME).exists() is False

    def test_auth_method_without_its_credential_is_refused(
        self, runner: CliRunner, workspace_root: Path
    ) -> None:
        result = runner.invoke(
            app, ["target", "add", "acme", "https://api.acme.test", "--auth-method", "bearer"]
        )

        assert result.exit_code == EXIT_TARGET_ERROR
        assert "requires token" in cli_text(result)


class TestList:
    def test_empty_store_explains_how_to_add_one(
        self, runner: CliRunner, workspace_root: Path
    ) -> None:
        result = runner.invoke(app, ["target", "list"])
        output = cli_text(result)

        assert result.exit_code == EXIT_OK
        assert "No targets are registered" in output
        assert "target add" in output

    def test_lists_registered_targets(self, runner: CliRunner, workspace_root: Path) -> None:
        add_acme(runner)

        result = runner.invoke(app, ["target", "list"])
        output = cli_text(result)

        assert result.exit_code == EXIT_OK
        assert "acme" in output
        assert "1 target(s)" in output

    def test_credential_values_are_never_listed(
        self, runner: CliRunner, workspace_root: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("ACME_TOKEN", TOKEN_VALUE)
        add_acme(runner, "--auth-method", "bearer", "--token-env", "ACME_TOKEN")

        output = cli_text(runner.invoke(app, ["target", "list"]))

        assert TOKEN_VALUE not in output
        assert "set" in line_containing(output, "acme")

    def test_enabled_only_filter(self, runner: CliRunner, workspace_root: Path) -> None:
        add_acme(runner, "--disabled")

        assert "acme" not in cli_text(runner.invoke(app, ["target", "list", "--enabled-only"]))

    def test_tag_filter(self, runner: CliRunner, workspace_root: Path) -> None:
        add_acme(runner, "--tag", "prod")
        result = runner.invoke(
            app, ["target", "add", "beta", "https://api.beta.test", "--tag", "staging"]
        )
        assert result.exit_code == EXIT_OK, cli_text(result)

        output = cli_text(runner.invoke(app, ["target", "list", "--tag", "prod"]))

        assert "acme" in output
        assert "beta" not in output


class TestShow:
    def test_shows_the_full_configuration(self, runner: CliRunner, workspace_root: Path) -> None:
        add_acme(runner, "--exclude-path", "/v1/admin", "--description", "Acme API")

        result = runner.invoke(app, ["target", "show", "acme"])
        output = cli_text(result)

        assert result.exit_code == EXIT_OK
        assert "Acme API" in output
        assert "api.acme.test" in line_containing(output, "Host")
        assert "/v1" in line_containing(output, "Include paths")
        assert "/v1/admin" in line_containing(output, "Exclude paths")
        assert "denied" in line_containing(output, "Subdomains")

    def test_shows_the_variable_name_but_not_the_credential(
        self, runner: CliRunner, workspace_root: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("ACME_TOKEN", TOKEN_VALUE)
        add_acme(runner, "--auth-method", "bearer", "--token-env", "ACME_TOKEN")

        output = cli_text(runner.invoke(app, ["target", "show", "acme"]))

        assert "env:ACME_TOKEN" in output
        assert TOKEN_VALUE not in output
        assert "set" in line_containing(output, "env:ACME_TOKEN")

    def test_reports_a_missing_credential_without_failing(
        self, runner: CliRunner, workspace_root: Path
    ) -> None:
        add_acme(runner, "--auth-method", "bearer", "--token-env", "ACME_TOKEN")

        result = runner.invoke(app, ["target", "show", "acme"])
        output = cli_text(result)

        assert result.exit_code == EXIT_OK
        assert "not set" in output

    def test_unknown_target_is_an_error(self, runner: CliRunner, workspace_root: Path) -> None:
        result = runner.invoke(app, ["target", "show", "ghost"])
        output = cli_text(result)

        assert result.exit_code == EXIT_TARGET_ERROR
        assert "No target named 'ghost'" in output
        assert "Traceback" not in output


class TestUpdate:
    def test_updates_only_what_was_passed(self, runner: CliRunner, workspace_root: Path) -> None:
        add_acme(runner, "--description", "original", "--tag", "prod")

        result = runner.invoke(app, ["target", "update", "acme", "--description", "changed"])
        assert result.exit_code == EXIT_OK, cli_text(result)

        output = cli_text(runner.invoke(app, ["target", "show", "acme"]))
        assert "changed" in output
        assert "prod" in line_containing(output, "Tags")

    def test_replaces_a_list_wholesale(self, runner: CliRunner, workspace_root: Path) -> None:
        add_acme(runner, "--exclude-path", "/v1/admin", "--exclude-path", "/v1/debug")

        runner.invoke(app, ["target", "update", "acme", "--exclude-path", "/v1/internal"])

        output = cli_text(runner.invoke(app, ["target", "show", "acme"]))
        assert "/v1/internal" in output
        assert "/v1/admin" not in output

    def test_disable_and_enable(self, runner: CliRunner, workspace_root: Path) -> None:
        add_acme(runner)

        runner.invoke(app, ["target", "update", "acme", "--disable"])
        assert "disabled" in cli_text(runner.invoke(app, ["target", "show", "acme"]))

        runner.invoke(app, ["target", "update", "acme", "--enable"])
        assert "enabled" in cli_text(runner.invoke(app, ["target", "show", "acme"]))

    def test_clear_empties_a_list(self, runner: CliRunner, workspace_root: Path) -> None:
        add_acme(runner, "--exclude-path", "/v1/admin", "--tag", "prod")

        result = runner.invoke(
            app, ["target", "update", "acme", "--clear", "exclude-paths", "--clear", "tags"]
        )
        assert result.exit_code == EXIT_OK, cli_text(result)

        output = cli_text(runner.invoke(app, ["target", "show", "acme"]))
        assert "none" in line_containing(output, "Exclude paths")
        assert "none" in line_containing(output, "Tags")

    def test_clearing_include_paths_warns_that_nothing_is_in_scope(
        self, runner: CliRunner, workspace_root: Path
    ) -> None:
        add_acme(runner)

        output = cli_text(
            runner.invoke(app, ["target", "update", "acme", "--clear", "include-paths"])
        )

        assert "nothing is in scope" in output

    def test_clearing_auth_removes_the_reference(
        self, runner: CliRunner, workspace_root: Path
    ) -> None:
        add_acme(runner, "--auth-method", "bearer", "--token-env", "ACME_TOKEN")

        result = runner.invoke(app, ["target", "update", "acme", "--clear", "auth"])
        assert result.exit_code == EXIT_OK, cli_text(result)

        output = cli_text(runner.invoke(app, ["target", "show", "acme"]))
        assert "ACME_TOKEN" not in output
        assert "none configured" in output

    def test_switching_auth_method_requires_the_new_credential(
        self, runner: CliRunner, workspace_root: Path
    ) -> None:
        add_acme(runner, "--auth-method", "bearer", "--token-env", "ACME_TOKEN")

        result = runner.invoke(app, ["target", "update", "acme", "--auth-method", "api_key"])

        assert result.exit_code == EXIT_TARGET_ERROR
        assert "requires api_key" in cli_text(result)

    def test_changing_only_the_token_variable_keeps_the_method(
        self, runner: CliRunner, workspace_root: Path
    ) -> None:
        add_acme(runner, "--auth-method", "bearer", "--token-env", "ACME_TOKEN")

        result = runner.invoke(app, ["target", "update", "acme", "--token-env", "NEW_TOKEN"])
        assert result.exit_code == EXIT_OK, cli_text(result)

        output = cli_text(runner.invoke(app, ["target", "show", "acme"]))
        assert "env:NEW_TOKEN" in output
        assert "bearer" in output

    def test_changing_the_base_url_warns_about_scope(
        self, runner: CliRunner, workspace_root: Path
    ) -> None:
        add_acme(runner)

        output = cli_text(
            runner.invoke(
                app, ["target", "update", "acme", "--base-url", "https://api.acme.test/v2"]
            )
        )

        assert "base URL changed" in output

    def test_unknown_target_is_an_error(self, runner: CliRunner, workspace_root: Path) -> None:
        result = runner.invoke(app, ["target", "update", "ghost", "--description", "x"])

        assert result.exit_code == EXIT_TARGET_ERROR

    def test_invalid_update_leaves_the_target_unchanged(
        self, runner: CliRunner, workspace_root: Path
    ) -> None:
        add_acme(runner)

        result = runner.invoke(app, ["target", "update", "acme", "--base-url", "ftp://a.test"])
        assert result.exit_code == EXIT_TARGET_ERROR

        output = cli_text(runner.invoke(app, ["target", "show", "acme"]))
        assert "https://api.acme.test/v1" in output


class TestRemove:
    def test_removes_with_explicit_consent(self, runner: CliRunner, workspace_root: Path) -> None:
        add_acme(runner)

        result = runner.invoke(app, ["target", "remove", "acme", "--yes"])
        output = cli_text(result)

        assert result.exit_code == EXIT_OK
        assert "removed" in output
        assert cli_text(runner.invoke(app, ["target", "list"])).count("acme") == 0

    def test_prompts_and_removes_when_confirmed(
        self, runner: CliRunner, workspace_root: Path
    ) -> None:
        add_acme(runner)

        result = runner.invoke(app, ["target", "remove", "acme"], input="y\n")

        assert result.exit_code == EXIT_OK
        assert "Remove target 'acme'" in cli_text(result)

    def test_declining_the_prompt_keeps_the_target(
        self, runner: CliRunner, workspace_root: Path
    ) -> None:
        add_acme(runner)

        result = runner.invoke(app, ["target", "remove", "acme"], input="n\n")

        assert result.exit_code != EXIT_OK
        assert "acme" in cli_text(runner.invoke(app, ["target", "list"]))

    def test_no_input_aborts_rather_than_assuming_consent(
        self, runner: CliRunner, workspace_root: Path
    ) -> None:
        add_acme(runner)

        result = runner.invoke(app, ["target", "remove", "acme"], input="")

        assert result.exit_code != EXIT_OK
        assert "acme" in cli_text(runner.invoke(app, ["target", "list"]))

    def test_unknown_target_fails_before_prompting(
        self, runner: CliRunner, workspace_root: Path
    ) -> None:
        result = runner.invoke(app, ["target", "remove", "ghost", "--yes"])
        output = cli_text(result)

        assert result.exit_code == EXIT_TARGET_ERROR
        assert "No target named 'ghost'" in output
        assert "Remove target" not in output


class TestScopeCommand:
    def test_shows_the_rules_when_no_url_is_given(
        self, runner: CliRunner, workspace_root: Path
    ) -> None:
        add_acme(runner, "--exclude-path", "/v1/admin")

        result = runner.invoke(app, ["target", "scope", "acme"])
        output = cli_text(result)

        assert result.exit_code == EXIT_OK
        assert "/v1" in line_containing(output, "Include paths")
        assert "/v1/admin" in line_containing(output, "Exclude paths")

    def test_in_scope_url_exits_zero(
        self, runner: CliRunner, workspace_root: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("AEGISAPI_ALLOWED_HOSTS", "api.acme.test")
        add_acme(runner)

        result = runner.invoke(app, ["target", "scope", "acme", "https://api.acme.test/v1/orders"])
        output = cli_text(result)

        assert result.exit_code == EXIT_OK
        assert "in scope" in output

    def test_out_of_scope_url_exits_with_the_scope_code(
        self, runner: CliRunner, workspace_root: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("AEGISAPI_ALLOWED_HOSTS", "api.acme.test")
        add_acme(runner)

        result = runner.invoke(
            app, ["target", "scope", "acme", "https://api.acme.test.attacker.test/v1"]
        )
        output = cli_text(result)

        assert result.exit_code == EXIT_SCOPE_ERROR
        assert "out of scope" in output

    def test_shows_both_gates_separately(self, runner: CliRunner, workspace_root: Path) -> None:
        add_acme(runner)

        # The target gate admits this URL; the empty global allow-list does not.
        result = runner.invoke(app, ["target", "scope", "acme", "https://api.acme.test/v1/orders"])
        output = cli_text(result)

        assert result.exit_code == EXIT_SCOPE_ERROR
        assert "matches include pattern" in output
        assert "allowed_hosts" in output

    def test_states_that_no_requests_were_sent(
        self, runner: CliRunner, workspace_root: Path
    ) -> None:
        add_acme(runner)

        output = cli_text(
            runner.invoke(app, ["target", "scope", "acme", "https://api.acme.test/v1"])
        )

        assert "No requests were sent" in output

    def test_malformed_url_is_reported_as_out_of_scope(
        self, runner: CliRunner, workspace_root: Path
    ) -> None:
        add_acme(runner)

        result = runner.invoke(app, ["target", "scope", "acme", "not a url"])
        output = cli_text(result)

        assert result.exit_code == EXIT_SCOPE_ERROR
        assert "out of scope" in output
        assert "Traceback" not in output

    def test_unknown_target_is_an_error(self, runner: CliRunner, workspace_root: Path) -> None:
        result = runner.invoke(app, ["target", "scope", "ghost"])

        assert result.exit_code == EXIT_TARGET_ERROR


class TestWorkspaceIsolation:
    def test_targets_live_in_the_selected_workspace(
        self, runner: CliRunner, workspace_root: Path, tmp_path: Path
    ) -> None:
        elsewhere = tmp_path / "other-workspace"

        result = runner.invoke(
            app,
            ["--workspace", str(elsewhere), "target", "add", "acme", "https://api.acme.test"],
        )
        assert result.exit_code == EXIT_OK, cli_text(result)

        assert (elsewhere / TARGETS_FILENAME).is_file()
        assert (workspace_root / TARGETS_FILENAME).exists() is False
        assert "No targets" in cli_text(runner.invoke(app, ["target", "list"]))

    def test_a_corrupt_target_file_is_reported_not_overwritten(
        self, runner: CliRunner, workspace_root: Path
    ) -> None:
        workspace_root.mkdir(parents=True, exist_ok=True)
        corrupt = workspace_root / TARGETS_FILENAME
        corrupt.write_text("{not json", encoding="utf-8")

        result = runner.invoke(app, ["target", "list"])
        output = cli_text(result)

        assert result.exit_code == EXIT_TARGET_ERROR
        assert "not valid JSON" in output
        assert corrupt.read_text(encoding="utf-8") == "{not json"
