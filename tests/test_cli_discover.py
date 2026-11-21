"""End-to-end behaviour of the ``aegisapi discover`` commands."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from aegisapi.cli import app
from aegisapi.core.exceptions import (
    EXIT_DISCOVERY_ERROR,
    EXIT_OK,
    EXIT_SPECIFICATION_ERROR,
    EXIT_TARGET_ERROR,
)
from aegisapi.core.paths import TARGETS_FILENAME
from conftest import cli_text
from specs import (
    FULL_OPENAPI_30,
    OPENAPI_31,
    SWAGGER_20,
    spec_copy,
    write_json,
    write_text,
    write_yaml,
)
from test_cli import line_containing

TOKEN_VALUE = "eyJhbGciOiJIUzI1NiJ9.super-secret-token-value"


def register_target(runner: CliRunner, *extra: str) -> None:
    """Register the standard test target."""
    result = runner.invoke(
        app,
        [
            "target",
            "add",
            "acme",
            "https://api.acme.test/v1",
            "--exclude-path",
            "/v1/admin",
            *extra,
        ],
    )
    assert result.exit_code == EXIT_OK, cli_text(result)


def discover(runner: CliRunner, path: Path, *extra: str):
    """Run ``discover spec`` against ``path``."""
    return runner.invoke(app, ["discover", "spec", "acme", "--file", str(path), *extra])


class TestHelp:
    def test_discover_group_is_listed_in_the_root_help(self, runner: CliRunner) -> None:
        assert "discover" in cli_text(runner.invoke(app, ["--help"]))

    def test_group_help_lists_subcommands(self, runner: CliRunner) -> None:
        output = cli_text(runner.invoke(app, ["discover", "--help"]))

        assert "spec" in output
        assert "show" in output

    def test_group_help_states_that_nothing_is_fetched(self, runner: CliRunner) -> None:
        output = cli_text(runner.invoke(app, ["discover", "--help"]))

        assert "No requests are sent" in output or "no requests are sent" in output.lower()

    def test_spec_help_documents_the_options(self, runner: CliRunner) -> None:
        output = cli_text(runner.invoke(app, ["discover", "spec", "--help"]))

        for option in ("--file", "--save", "--export", "--force", "--limit"):
            assert option in output

    def test_no_subcommand_shows_help(self, runner: CliRunner) -> None:
        assert "Usage" in cli_text(runner.invoke(app, ["discover"]))


class TestDiscoverSpec:
    def test_openapi_yaml_is_parsed_and_summarised(
        self, runner: CliRunner, workspace_root: Path, tmp_path: Path
    ) -> None:
        register_target(runner)
        path = write_yaml(tmp_path / "spec.yaml", FULL_OPENAPI_30)

        result = discover(runner, path)
        output = cli_text(result)

        assert result.exit_code == EXIT_OK
        assert "Acme Orders API" in output
        assert "7" in line_containing(output, "Operations discovered")
        assert "GET" in output
        assert "/users" in output

    def test_openapi_json_is_parsed(
        self, runner: CliRunner, workspace_root: Path, tmp_path: Path
    ) -> None:
        register_target(runner)
        path = write_json(tmp_path / "spec.json", OPENAPI_31)

        result = discover(runner, path)

        assert result.exit_code == EXIT_OK
        assert "openapi_3.1" in cli_text(result)

    def test_swagger_is_parsed(
        self, runner: CliRunner, workspace_root: Path, tmp_path: Path
    ) -> None:
        register_target(runner)
        path = write_json(tmp_path / "spec.json", SWAGGER_20)

        result = discover(runner, path)
        output = cli_text(result)

        assert result.exit_code == EXIT_OK
        assert "swagger_2.0" in output
        assert "/invoices" in output

    def test_scope_classification_is_displayed(
        self, runner: CliRunner, workspace_root: Path, tmp_path: Path
    ) -> None:
        register_target(runner)
        path = write_yaml(tmp_path / "spec.yaml", FULL_OPENAPI_30)

        output = cli_text(discover(runner, path))

        assert "in scope" in output
        assert "out of scope" in output
        assert "out of scope" in line_containing(output, "/admin/audit")

    def test_out_of_scope_endpoints_are_shown_by_default(
        self, runner: CliRunner, workspace_root: Path, tmp_path: Path
    ) -> None:
        register_target(runner)
        path = write_yaml(tmp_path / "spec.yaml", FULL_OPENAPI_30)

        output = cli_text(discover(runner, path, "--limit", "0"))

        assert "/admin/audit" in output

    def test_only_in_scope_hides_them_but_still_counts_them(
        self, runner: CliRunner, workspace_root: Path, tmp_path: Path
    ) -> None:
        register_target(runner)
        path = write_yaml(tmp_path / "spec.yaml", FULL_OPENAPI_30)

        output = cli_text(discover(runner, path, "--only-in-scope", "--limit", "0"))

        assert "out of scope: 1" in output
        rows = [line for line in output.splitlines() if "/admin/audit" in line]
        assert rows == []

    def test_declared_security_is_labelled_as_declared(
        self, runner: CliRunner, workspace_root: Path, tmp_path: Path
    ) -> None:
        register_target(runner)
        path = write_yaml(tmp_path / "spec.yaml", FULL_OPENAPI_30)

        output = cli_text(discover(runner, path))

        assert "Declared security" in output
        assert "not what the API enforces" in output

    def test_security_schemes_are_listed_without_secrets(
        self,
        runner: CliRunner,
        workspace_root: Path,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setenv("ACME_TOKEN", TOKEN_VALUE)
        register_target(runner, "--auth-method", "bearer", "--token-env", "ACME_TOKEN")
        path = write_yaml(tmp_path / "spec.yaml", FULL_OPENAPI_30)

        output = cli_text(discover(runner, path))

        assert "bearerAuth" in output
        assert "X-Admin-Key" in output
        assert TOKEN_VALUE not in output

    def test_structural_observations_are_labelled_not_findings(
        self, runner: CliRunner, workspace_root: Path, tmp_path: Path
    ) -> None:
        register_target(runner)
        path = write_yaml(tmp_path / "spec.yaml", FULL_OPENAPI_30)

        output = cli_text(discover(runner, path))

        assert "not security findings" in output
        assert "parent_child" in output

    def test_relationships_can_be_suppressed(
        self, runner: CliRunner, workspace_root: Path, tmp_path: Path
    ) -> None:
        register_target(runner)
        path = write_yaml(tmp_path / "spec.yaml", FULL_OPENAPI_30)

        output = cli_text(discover(runner, path, "--no-relationships"))

        assert "parent_child" not in output

    def test_warnings_are_surfaced(
        self, runner: CliRunner, workspace_root: Path, tmp_path: Path
    ) -> None:
        register_target(runner)
        path = write_yaml(tmp_path / "spec.yaml", FULL_OPENAPI_30)

        output = cli_text(discover(runner, path))

        assert "Parse warnings" in output
        assert "circular_reference" in output

    def test_output_states_that_nothing_was_contacted(
        self, runner: CliRunner, workspace_root: Path, tmp_path: Path
    ) -> None:
        register_target(runner)
        path = write_yaml(tmp_path / "spec.yaml", FULL_OPENAPI_30)

        output = cli_text(discover(runner, path))

        assert "No requests were sent" in output
        assert "authorisation" in output.lower()

    def test_limit_truncates_the_table(
        self, runner: CliRunner, workspace_root: Path, tmp_path: Path
    ) -> None:
        register_target(runner)
        path = write_yaml(tmp_path / "spec.yaml", FULL_OPENAPI_30)

        output = cli_text(discover(runner, path, "--limit", "2"))

        assert "Showing 2 of 7" in output

    def test_server_mismatch_is_explained(
        self, runner: CliRunner, workspace_root: Path, tmp_path: Path
    ) -> None:
        register_target(runner)
        document = spec_copy(FULL_OPENAPI_30)
        document["servers"] = [{"url": "https://production.acme.test/v1"}]
        path = write_yaml(tmp_path / "spec.yaml", document)

        output = cli_text(discover(runner, path))

        assert "do not match the registered target host" in output
        assert "does not widen a target's scope" in output

    def test_discovery_does_not_modify_the_target(
        self, runner: CliRunner, workspace_root: Path, tmp_path: Path
    ) -> None:
        register_target(runner)
        before = (workspace_root / TARGETS_FILENAME).read_text(encoding="utf-8")
        document = spec_copy(FULL_OPENAPI_30)
        document["servers"] = [{"url": "https://elsewhere.test/v9"}]
        path = write_yaml(tmp_path / "spec.yaml", document)

        discover(runner, path)

        assert (workspace_root / TARGETS_FILENAME).read_text(encoding="utf-8") == before


class TestFailurePaths:
    def test_unknown_target(self, runner: CliRunner, workspace_root: Path, tmp_path: Path) -> None:
        path = write_yaml(tmp_path / "spec.yaml", FULL_OPENAPI_30)

        result = runner.invoke(app, ["discover", "spec", "ghost", "--file", str(path)])
        output = cli_text(result)

        assert result.exit_code == EXIT_TARGET_ERROR
        assert "No target named 'ghost'" in output
        assert "Traceback" not in output

    def test_missing_specification_file(
        self, runner: CliRunner, workspace_root: Path, tmp_path: Path
    ) -> None:
        register_target(runner)

        result = discover(runner, tmp_path / "absent.yaml")
        output = cli_text(result)

        assert result.exit_code == EXIT_SPECIFICATION_ERROR
        assert "not found" in output
        assert "Traceback" not in output

    def test_malformed_specification(
        self, runner: CliRunner, workspace_root: Path, tmp_path: Path
    ) -> None:
        register_target(runner)
        path = write_text(tmp_path / "spec.yaml", "openapi: 3.0.0\npaths: [unclosed\n")

        result = discover(runner, path)
        output = cli_text(result)

        assert result.exit_code == EXIT_SPECIFICATION_ERROR
        assert "not valid YAML" in output
        assert "Hint:" in output

    def test_unsupported_version(
        self, runner: CliRunner, workspace_root: Path, tmp_path: Path
    ) -> None:
        register_target(runner)
        path = write_json(tmp_path / "spec.json", {"openapi": "4.0.0", "paths": {}})

        result = discover(runner, path)
        output = cli_text(result)

        assert result.exit_code == EXIT_SPECIFICATION_ERROR
        assert "not supported" in output
        assert "OpenAPI 3.1" in output

    def test_document_that_is_not_a_specification(
        self, runner: CliRunner, workspace_root: Path, tmp_path: Path
    ) -> None:
        register_target(runner)
        path = write_json(tmp_path / "spec.json", {"hello": "world"})

        result = discover(runner, path)

        assert result.exit_code == EXIT_SPECIFICATION_ERROR
        assert "does not declare" in cli_text(result)

    def test_empty_specification_file(
        self, runner: CliRunner, workspace_root: Path, tmp_path: Path
    ) -> None:
        register_target(runner)
        path = write_text(tmp_path / "spec.yaml", "")

        result = discover(runner, path)

        assert result.exit_code == EXIT_SPECIFICATION_ERROR
        assert "empty" in cli_text(result)

    def test_specification_with_no_operations_still_succeeds(
        self, runner: CliRunner, workspace_root: Path, tmp_path: Path
    ) -> None:
        register_target(runner)
        path = write_json(tmp_path / "spec.json", {"openapi": "3.0.0", "paths": {}})

        result = discover(runner, path)
        output = cli_text(result)

        assert result.exit_code == EXIT_OK
        assert "0" in line_containing(output, "Operations discovered")
        assert "no_operations" in output


class TestSaveAndExport:
    def test_save_stores_the_result(
        self, runner: CliRunner, workspace_root: Path, tmp_path: Path
    ) -> None:
        register_target(runner)
        path = write_yaml(tmp_path / "spec.yaml", FULL_OPENAPI_30)

        result = discover(runner, path, "--save")

        assert result.exit_code == EXIT_OK
        stored = workspace_root / "discovery" / "acme.json"
        assert stored.is_file()
        assert "Written" in cli_text(result)

    def test_resaving_without_force_is_refused(
        self, runner: CliRunner, workspace_root: Path, tmp_path: Path
    ) -> None:
        register_target(runner)
        path = write_yaml(tmp_path / "spec.yaml", FULL_OPENAPI_30)
        discover(runner, path, "--save")

        result = discover(runner, path, "--save")
        output = cli_text(result)

        assert result.exit_code == EXIT_DISCOVERY_ERROR
        assert "already saved" in output
        assert "--force" in output

    def test_force_allows_resaving(
        self, runner: CliRunner, workspace_root: Path, tmp_path: Path
    ) -> None:
        register_target(runner)
        path = write_yaml(tmp_path / "spec.yaml", FULL_OPENAPI_30)
        discover(runner, path, "--save")

        assert discover(runner, path, "--save", "--force").exit_code == EXIT_OK

    def test_export_writes_the_full_inventory(
        self, runner: CliRunner, workspace_root: Path, tmp_path: Path
    ) -> None:
        register_target(runner)
        path = write_yaml(tmp_path / "spec.yaml", FULL_OPENAPI_30)
        destination = tmp_path / "out" / "inventory.json"

        result = discover(runner, path, "--export", str(destination))

        assert result.exit_code == EXIT_OK
        document = json.loads(destination.read_text(encoding="utf-8"))
        assert document["target_name"] == "acme"
        assert len(document["endpoints"]) == 7
        assert document["schema_version"] == 1

    def test_export_does_not_overwrite_without_force(
        self, runner: CliRunner, workspace_root: Path, tmp_path: Path
    ) -> None:
        register_target(runner)
        path = write_yaml(tmp_path / "spec.yaml", FULL_OPENAPI_30)
        destination = tmp_path / "inventory.json"
        destination.write_text("important", encoding="utf-8")

        result = discover(runner, path, "--export", str(destination))

        assert result.exit_code == EXIT_DISCOVERY_ERROR
        assert destination.read_text(encoding="utf-8") == "important"

    def test_exported_file_contains_no_credential_value(
        self,
        runner: CliRunner,
        workspace_root: Path,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setenv("ACME_TOKEN", TOKEN_VALUE)
        register_target(runner, "--auth-method", "bearer", "--token-env", "ACME_TOKEN")
        path = write_yaml(tmp_path / "spec.yaml", FULL_OPENAPI_30)
        destination = tmp_path / "inventory.json"

        discover(runner, path, "--export", str(destination))

        body = destination.read_text(encoding="utf-8")
        assert TOKEN_VALUE not in body
        assert "ACME_TOKEN" not in body

    def test_exported_inventory_records_classifications(
        self, runner: CliRunner, workspace_root: Path, tmp_path: Path
    ) -> None:
        register_target(runner)
        path = write_yaml(tmp_path / "spec.yaml", FULL_OPENAPI_30)
        destination = tmp_path / "inventory.json"

        discover(runner, path, "--export", str(destination))
        document = json.loads(destination.read_text(encoding="utf-8"))
        classifications = {
            item["endpoint"]["path"]: item["classification"] for item in document["endpoints"]
        }

        assert classifications["/users"] == "in_scope"
        assert classifications["/admin/audit"] == "out_of_scope"


class TestDiscoverShow:
    def test_shows_a_saved_result(
        self, runner: CliRunner, workspace_root: Path, tmp_path: Path
    ) -> None:
        register_target(runner)
        path = write_yaml(tmp_path / "spec.yaml", FULL_OPENAPI_30)
        discover(runner, path, "--save")

        result = runner.invoke(app, ["discover", "show", "acme"])
        output = cli_text(result)

        assert result.exit_code == EXIT_OK
        assert "Acme Orders API" in output
        assert "7" in line_containing(output, "Operations discovered")

    def test_without_a_saved_result_it_explains_how_to_make_one(
        self, runner: CliRunner, workspace_root: Path
    ) -> None:
        register_target(runner)

        result = runner.invoke(app, ["discover", "show", "acme"])
        output = cli_text(result)

        assert result.exit_code == EXIT_DISCOVERY_ERROR
        assert "No discovery result" in output
        assert "--save" in output

    def test_unknown_target(self, runner: CliRunner, workspace_root: Path) -> None:
        result = runner.invoke(app, ["discover", "show", "ghost"])

        assert result.exit_code == EXIT_TARGET_ERROR

    def test_corrupt_saved_result_is_reported_not_replaced(
        self, runner: CliRunner, workspace_root: Path
    ) -> None:
        register_target(runner)
        stored = workspace_root / "discovery" / "acme.json"
        stored.parent.mkdir(parents=True, exist_ok=True)
        stored.write_text("{not json", encoding="utf-8")

        result = runner.invoke(app, ["discover", "show", "acme"])

        assert result.exit_code == EXIT_DISCOVERY_ERROR
        assert "not valid JSON" in cli_text(result)
        assert stored.read_text(encoding="utf-8") == "{not json"


class TestWorkspaceIsolation:
    def test_results_live_in_the_selected_workspace(
        self, runner: CliRunner, workspace_root: Path, tmp_path: Path
    ) -> None:
        elsewhere = tmp_path / "other-workspace"
        path = write_yaml(tmp_path / "spec.yaml", FULL_OPENAPI_30)
        add = runner.invoke(
            app,
            [
                "--workspace",
                str(elsewhere),
                "target",
                "add",
                "acme",
                "https://api.acme.test/v1",
            ],
        )
        assert add.exit_code == EXIT_OK, cli_text(add)

        result = runner.invoke(
            app,
            [
                "--workspace",
                str(elsewhere),
                "discover",
                "spec",
                "acme",
                "--file",
                str(path),
                "--save",
            ],
        )

        assert result.exit_code == EXIT_OK
        assert (elsewhere / "discovery" / "acme.json").is_file()
        assert (workspace_root / "discovery" / "acme.json").exists() is False

    def test_init_creates_the_discovery_directory(
        self, runner: CliRunner, workspace_root: Path
    ) -> None:
        assert runner.invoke(app, ["init"]).exit_code == EXIT_OK

        assert (workspace_root / "discovery").is_dir()
