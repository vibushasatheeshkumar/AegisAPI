"""End-to-end behaviour of the ``check`` and ``risk`` command groups.

Runs against a local HTTP server on 127.0.0.1. Denial cases assert the server
received nothing at all.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from aegisapi.cli import app
from aegisapi.core.exceptions import (
    EXIT_DISCOVERY_ERROR,
    EXIT_OK,
    EXIT_SCOPE_ERROR,
    EXIT_TARGET_ERROR,
)
from conftest import cli_text
from httpstub import StubHandler, StubServer, local_server

TOKEN = "eyJhbGciOiJIUzI1NiJ9.super-secret-token-value"

SPEC = {
    "openapi": "3.0.3",
    "info": {"title": "Local API", "version": "1.0"},
    "security": [{"bearerAuth": []}],
    "paths": {
        "/orders": {
            "get": {
                "operationId": "listOrders",
                "parameters": [
                    {
                        "name": "limit",
                        "in": "query",
                        "required": True,
                        "schema": {"type": "integer"},
                    }
                ],
                "responses": {
                    "200": {
                        "description": "ok",
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "array",
                                    "items": {"$ref": "#/components/schemas/Order"},
                                }
                            }
                        },
                    }
                },
            }
        },
        "/orders/{orderId}": {
            "get": {
                "operationId": "getOrder",
                "parameters": [
                    {
                        "name": "orderId",
                        "in": "path",
                        "required": True,
                        "schema": {"type": "string"},
                    }
                ],
                "responses": {
                    "200": {
                        "description": "ok",
                        "content": {
                            "application/json": {"schema": {"$ref": "#/components/schemas/Order"}}
                        },
                    }
                },
            }
        },
        "/health": {
            "get": {
                "operationId": "health",
                "security": [],
                "responses": {"200": {"description": "ok"}},
            }
        },
    },
    "components": {
        "securitySchemes": {"bearerAuth": {"type": "http", "scheme": "bearer"}},
        "schemas": {
            "Order": {
                "type": "object",
                "required": ["orderId"],
                "properties": {
                    "orderId": {"type": "string"},
                    "total": {"type": "number"},
                },
            }
        },
    },
}


def ok(handler: StubHandler) -> None:
    """A plain 200 with a JSON body."""
    handler.reply(200, b'{"orderId": "1001"}', {"content-type": "application/json"})


def routes() -> dict:
    """Routes covering the specification's paths."""
    return {"*": ok}


def prepare(
    runner: CliRunner,
    server: StubServer,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    extra_target: tuple[str, ...] = (),
) -> str:
    """Register a target, run discovery, and allow the loopback host."""
    host = server.server_address[0]
    spec = tmp_path / "spec.json"
    spec.write_text(json.dumps(SPEC), encoding="utf-8")

    added = runner.invoke(app, ["target", "add", "local", f"{server.base_url}/", *extra_target])
    assert added.exit_code == EXIT_OK, cli_text(added)

    monkeypatch.setenv("AEGISAPI_ALLOWED_HOSTS", host)
    discovered = runner.invoke(app, ["discover", "spec", "local", "--file", str(spec), "--save"])
    assert discovered.exit_code == EXIT_OK, cli_text(discovered)
    return host


class TestCheckList:
    def test_the_catalogue_is_listed(self, runner: CliRunner, workspace_root: Path) -> None:
        output = cli_text(runner.invoke(app, ["check", "list"]))

        assert "AUTH-001" in output
        assert "BOLA-001" in output
        assert "RATE-001" in output

    def test_the_catalogue_warns_against_over_reading_a_failure(
        self, runner: CliRunner, workspace_root: Path
    ) -> None:
        output = cli_text(runner.invoke(app, ["check", "list"]))

        assert "not a confirmed vulnerability" in output

    def test_category_filter(self, runner: CliRunner, workspace_root: Path) -> None:
        output = cli_text(runner.invoke(app, ["check", "list", "--category", "authorization"]))

        assert "BOLA-001" in output
        assert "RATE-001" not in output

    def test_groups_are_in_the_root_help(self, runner: CliRunner) -> None:
        output = cli_text(runner.invoke(app, ["--help"]))

        assert "check" in output
        assert "risk" in output


class TestCheckRun:
    def test_checks_run_against_discovered_endpoints(
        self,
        runner: CliRunner,
        workspace_root: Path,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        with local_server(routes()) as server:
            prepare(runner, server, tmp_path, monkeypatch)

            result = runner.invoke(
                app, ["check", "run", "local", "--category", "configuration", "--budget", "10"]
            )
            output = cli_text(result)

            assert result.exit_code == EXIT_OK, output
            assert server.received

        assert "Assessment summary" in output
        assert "Requests sent" in output

    def test_output_distinguishes_outcome_from_finding_class(
        self,
        runner: CliRunner,
        workspace_root: Path,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        with local_server(routes()) as server:
            prepare(runner, server, tmp_path, monkeypatch)
            output = cli_text(runner.invoke(app, ["check", "run", "local", "--budget", "20"]))

        assert "Outcome" in output
        assert "Finding" in output
        assert "not a confirmed vulnerability" in output

    def test_a_disabled_target_sends_nothing(
        self,
        runner: CliRunner,
        workspace_root: Path,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        with local_server(routes()) as server:
            prepare(runner, server, tmp_path, monkeypatch)
            runner.invoke(app, ["target", "update", "local", "--disable"])
            before = len(server.received)

            result = runner.invoke(app, ["check", "run", "local", "--budget", "20"])

            assert len(server.received) == before

        assert result.exit_code == EXIT_OK
        assert "disabled" in cli_text(result)

    def test_an_empty_global_allow_list_sends_nothing(
        self,
        runner: CliRunner,
        workspace_root: Path,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        with local_server(routes()) as server:
            prepare(runner, server, tmp_path, monkeypatch)
            monkeypatch.delenv("AEGISAPI_ALLOWED_HOSTS", raising=False)
            before = len(server.received)

            result = runner.invoke(app, ["check", "run", "local", "--budget", "20"])

            assert len(server.received) == before

        assert result.exit_code == EXIT_SCOPE_ERROR
        assert "--local-lab" in cli_text(result)

    def test_the_budget_is_respected(
        self,
        runner: CliRunner,
        workspace_root: Path,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        with local_server(routes()) as server:
            prepare(runner, server, tmp_path, monkeypatch)
            before = len(server.received)

            result = runner.invoke(app, ["check", "run", "local", "--budget", "3"])

            sent = len(server.received) - before
            assert sent <= 3

        assert result.exit_code == EXIT_OK

    def test_without_discovery_the_command_explains_what_to_do(
        self, runner: CliRunner, workspace_root: Path
    ) -> None:
        added = runner.invoke(app, ["target", "add", "local", "https://api.acme.test/v1"])
        assert added.exit_code == EXIT_OK, cli_text(added)

        result = runner.invoke(app, ["check", "run", "local"])

        assert result.exit_code == EXIT_DISCOVERY_ERROR
        assert "discover spec" in cli_text(result)

    def test_an_unknown_target_is_an_error(self, runner: CliRunner, workspace_root: Path) -> None:
        result = runner.invoke(app, ["check", "run", "ghost"])

        assert result.exit_code == EXIT_TARGET_ERROR

    def test_an_unknown_check_id_is_an_error(
        self,
        runner: CliRunner,
        workspace_root: Path,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        with local_server(routes()) as server:
            prepare(runner, server, tmp_path, monkeypatch)

            result = runner.invoke(app, ["check", "run", "local", "--check", "NOPE-1"])

        assert result.exit_code == EXIT_TARGET_ERROR
        assert "No security check" in cli_text(result)

    def test_save_and_show(
        self,
        runner: CliRunner,
        workspace_root: Path,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        with local_server(routes()) as server:
            prepare(runner, server, tmp_path, monkeypatch)
            saved = runner.invoke(app, ["check", "run", "local", "--budget", "10", "--save"])
            assert saved.exit_code == EXIT_OK, cli_text(saved)

            shown = runner.invoke(app, ["check", "show", "local"])

        assert (workspace_root / "assessments" / "local.json").is_file()
        assert shown.exit_code == EXIT_OK
        assert "Assessment summary" in cli_text(shown)

    def test_resaving_without_force_is_refused(
        self,
        runner: CliRunner,
        workspace_root: Path,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        with local_server(routes()) as server:
            prepare(runner, server, tmp_path, monkeypatch)
            runner.invoke(app, ["check", "run", "local", "--budget", "6", "--save"])

            again = runner.invoke(app, ["check", "run", "local", "--budget", "6", "--save"])

        assert again.exit_code == EXIT_DISCOVERY_ERROR
        assert "--force" in cli_text(again)

    def test_export_writes_json(
        self,
        runner: CliRunner,
        workspace_root: Path,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        destination = tmp_path / "assessment.json"
        with local_server(routes()) as server:
            prepare(runner, server, tmp_path, monkeypatch)

            result = runner.invoke(
                app,
                ["check", "run", "local", "--budget", "6", "--export", str(destination)],
            )

        assert result.exit_code == EXIT_OK, cli_text(result)
        document = json.loads(destination.read_text(encoding="utf-8"))
        assert document["target_name"] == "local"
        assert document["schema_version"] == 1

    def test_no_credential_appears_in_output_or_artifacts(
        self,
        runner: CliRunner,
        workspace_root: Path,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        destination = tmp_path / "assessment.json"
        with local_server(routes()) as server:
            prepare(
                runner,
                server,
                tmp_path,
                monkeypatch,
                extra_target=("--auth-method", "bearer", "--token-env", "LOCAL_TOKEN"),
            )
            monkeypatch.setenv("LOCAL_TOKEN", TOKEN)

            result = runner.invoke(
                app,
                [
                    "check",
                    "run",
                    "local",
                    "--budget",
                    "12",
                    "--save",
                    "--export",
                    str(destination),
                ],
            )
            output = cli_text(result)
            sent_auth = [
                headers.get("Authorization")
                for _, _, headers in server.received
                if "Authorization" in headers
            ]

        assert result.exit_code == EXIT_OK, output
        # The credential really was used...
        assert any(item == f"Bearer {TOKEN}" for item in sent_auth)
        # ...and appears nowhere it is recorded.
        assert TOKEN not in output
        assert TOKEN not in destination.read_text(encoding="utf-8")
        assert TOKEN not in (workspace_root / "assessments" / "local.json").read_text(
            encoding="utf-8"
        )

    def test_fixtures_are_loaded_and_validated(
        self,
        runner: CliRunner,
        workspace_root: Path,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        fixtures = tmp_path / "fixtures.json"
        fixtures.write_text(
            json.dumps(
                {
                    "identities": [
                        {
                            "name": "alice",
                            "role": "user",
                            "auth": {
                                "method": "bearer",
                                "token": {"variable": "ALICE_TOKEN"},
                            },
                        },
                        {
                            "name": "bob",
                            "role": "user",
                            "auth": {
                                "method": "bearer",
                                "token": {"variable": "BOB_TOKEN"},
                            },
                        },
                    ],
                    "objects": [{"owner": "alice", "parameter": "orderId", "value": "1001"}],
                }
            ),
            encoding="utf-8",
        )
        monkeypatch.setenv("ALICE_TOKEN", "alice-token")
        monkeypatch.setenv("BOB_TOKEN", "bob-token")

        with local_server(routes()) as server:
            prepare(runner, server, tmp_path, monkeypatch)

            result = runner.invoke(
                app,
                [
                    "check",
                    "run",
                    "local",
                    "--check",
                    "BOLA-001",
                    "--fixtures",
                    str(fixtures),
                    "--budget",
                    "10",
                ],
            )

        assert result.exit_code == EXIT_OK, cli_text(result)
        assert "BOLA-001" in cli_text(result)

    def test_a_malformed_fixtures_file_is_reported(
        self,
        runner: CliRunner,
        workspace_root: Path,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        fixtures = tmp_path / "fixtures.json"
        fixtures.write_text("{not json", encoding="utf-8")

        with local_server(routes()) as server:
            prepare(runner, server, tmp_path, monkeypatch)

            result = runner.invoke(app, ["check", "run", "local", "--fixtures", str(fixtures)])

        assert result.exit_code == EXIT_TARGET_ERROR
        assert "not valid JSON" in cli_text(result)

    def test_a_missing_fixtures_file_is_reported(
        self,
        runner: CliRunner,
        workspace_root: Path,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        with local_server(routes()) as server:
            prepare(runner, server, tmp_path, monkeypatch)

            result = runner.invoke(
                app, ["check", "run", "local", "--fixtures", str(tmp_path / "absent.json")]
            )

        assert result.exit_code == EXIT_TARGET_ERROR
        assert "not found" in cli_text(result)


class TestCheckShow:
    def test_one_result_can_be_shown_in_full(
        self,
        runner: CliRunner,
        workspace_root: Path,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        with local_server(routes()) as server:
            prepare(runner, server, tmp_path, monkeypatch)
            runner.invoke(app, ["check", "run", "local", "--budget", "12", "--save"])

            result = runner.invoke(app, ["check", "show", "local", "--check", "CONF-001"])
            output = cli_text(result)

        assert result.exit_code == EXIT_OK, output
        assert "CONF-001" in output
        assert "What this does not establish" in output or "Limitations" in output

    def test_an_unknown_saved_check_is_an_error(
        self,
        runner: CliRunner,
        workspace_root: Path,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        with local_server(routes()) as server:
            prepare(runner, server, tmp_path, monkeypatch)
            runner.invoke(app, ["check", "run", "local", "--budget", "6", "--save"])

            result = runner.invoke(app, ["check", "show", "local", "--check", "AUTH-999"])

        assert result.exit_code == EXIT_TARGET_ERROR

    def test_without_a_saved_assessment_the_command_explains(
        self,
        runner: CliRunner,
        workspace_root: Path,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        with local_server(routes()) as server:
            prepare(runner, server, tmp_path, monkeypatch)

            result = runner.invoke(app, ["check", "show", "local"])

        assert result.exit_code == EXIT_DISCOVERY_ERROR
        assert "check run" in cli_text(result)


class TestRiskCommands:
    def analyse(self, runner: CliRunner, server, tmp_path, monkeypatch):
        """Run discovery, checks, and analysis, saving each step."""
        prepare(runner, server, tmp_path, monkeypatch)
        ran = runner.invoke(app, ["check", "run", "local", "--budget", "20", "--save"])
        assert ran.exit_code == EXIT_OK, cli_text(ran)
        analysed = runner.invoke(app, ["risk", "analyze", "local", "--save"])
        assert analysed.exit_code == EXIT_OK, cli_text(analysed)
        return analysed

    def test_analysis_produces_risks_and_a_graph(
        self,
        runner: CliRunner,
        workspace_root: Path,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        with local_server(routes()) as server:
            output = cli_text(self.analyse(runner, server, tmp_path, monkeypatch))

        assert "Risk intelligence" in output
        assert "Graph" in output
        assert "Edge provenance" in output

    def test_analysis_sends_no_requests(
        self,
        runner: CliRunner,
        workspace_root: Path,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        with local_server(routes()) as server:
            prepare(runner, server, tmp_path, monkeypatch)
            runner.invoke(app, ["check", "run", "local", "--budget", "12", "--save"])
            before = len(server.received)

            result = runner.invoke(app, ["risk", "analyze", "local"])

            assert len(server.received) == before

        assert result.exit_code == EXIT_OK

    def test_analysis_without_an_assessment_says_so(
        self,
        runner: CliRunner,
        workspace_root: Path,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        with local_server(routes()) as server:
            prepare(runner, server, tmp_path, monkeypatch)

            result = runner.invoke(app, ["risk", "analyze", "local"])
            output = cli_text(result)

        assert result.exit_code == EXIT_OK
        assert "relationships only" in output

    def test_graph_shows_provenance(
        self,
        runner: CliRunner,
        workspace_root: Path,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        with local_server(routes()) as server:
            self.analyse(runner, server, tmp_path, monkeypatch)

            result = runner.invoke(app, ["risk", "graph", "local"])
            output = cli_text(result)

        assert result.exit_code == EXIT_OK, output
        assert "Provenance" in output
        assert "specification" in output

    def test_paths_carry_the_disclaimer(
        self,
        runner: CliRunner,
        workspace_root: Path,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        with local_server(routes()) as server:
            self.analyse(runner, server, tmp_path, monkeypatch)

            result = runner.invoke(app, ["risk", "paths", "local"])
            output = cli_text(result)

        assert result.exit_code == EXIT_OK, output
        assert "hypothesis about reachability" in output

    def test_explain_without_a_risk_prints_the_model(
        self, runner: CliRunner, workspace_root: Path
    ) -> None:
        output = cli_text(runner.invoke(app, ["risk", "explain", "local"]))

        assert "Risk scoring model" in output
        assert "never severity" in output

    def test_explain_a_named_risk(
        self,
        runner: CliRunner,
        workspace_root: Path,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        with local_server(routes()) as server:
            self.analyse(runner, server, tmp_path, monkeypatch)
            shown = runner.invoke(app, ["risk", "show", "local"])
            assert shown.exit_code == EXIT_OK, cli_text(shown)

            report = json.loads(
                (workspace_root / "assessments" / "local.intelligence.json").read_text(
                    encoding="utf-8"
                )
            )
            if not report["risks"]:
                pytest.skip("no risks were derived from this local API")
            risk_id = report["risks"][0]["risk_id"]

            result = runner.invoke(app, ["risk", "explain", "local", risk_id])
            output = cli_text(result)

        assert result.exit_code == EXIT_OK, output
        assert "How the score was reached" in output
        assert "What remains unverified" in output or "What to check next" in output

    def test_an_unknown_risk_id_is_an_error(
        self,
        runner: CliRunner,
        workspace_root: Path,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        with local_server(routes()) as server:
            self.analyse(runner, server, tmp_path, monkeypatch)

            result = runner.invoke(app, ["risk", "explain", "local", "risk-missing"])

        assert result.exit_code == EXIT_TARGET_ERROR

    def test_show_without_a_saved_report_explains(
        self,
        runner: CliRunner,
        workspace_root: Path,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        with local_server(routes()) as server:
            prepare(runner, server, tmp_path, monkeypatch)

            result = runner.invoke(app, ["risk", "show", "local"])

        assert result.exit_code == EXIT_DISCOVERY_ERROR
        assert "risk analyze" in cli_text(result)

    def test_export_writes_a_report(
        self,
        runner: CliRunner,
        workspace_root: Path,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        destination = tmp_path / "intel.json"
        with local_server(routes()) as server:
            prepare(runner, server, tmp_path, monkeypatch)
            runner.invoke(app, ["check", "run", "local", "--budget", "12", "--save"])

            result = runner.invoke(app, ["risk", "analyze", "local", "--export", str(destination)])

        assert result.exit_code == EXIT_OK, cli_text(result)
        document = json.loads(destination.read_text(encoding="utf-8"))
        assert document["target_name"] == "local"
        assert "edges" in document

    def test_no_credential_appears_in_an_intelligence_report(
        self,
        runner: CliRunner,
        workspace_root: Path,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        with local_server(routes()) as server:
            prepare(
                runner,
                server,
                tmp_path,
                monkeypatch,
                extra_target=("--auth-method", "bearer", "--token-env", "LOCAL_TOKEN"),
            )
            monkeypatch.setenv("LOCAL_TOKEN", TOKEN)
            runner.invoke(app, ["check", "run", "local", "--budget", "16", "--save"])

            result = runner.invoke(app, ["risk", "analyze", "local", "--save"])
            output = cli_text(result)

        assert result.exit_code == EXIT_OK, output
        assert TOKEN not in output
        assert TOKEN not in (workspace_root / "assessments" / "local.intelligence.json").read_text(
            encoding="utf-8"
        )


class TestCheckRunLocalLab:
    def test_local_lab_flag_allows_loopback_without_env_var(
        self,
        runner: CliRunner,
        workspace_root: Path,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """--local-lab bypasses the global allow-list for loopback targets."""
        with local_server(routes()) as server:
            prepare(runner, server, tmp_path, monkeypatch)
            monkeypatch.delenv("AEGISAPI_ALLOWED_HOSTS", raising=False)

            result = runner.invoke(
                app, ["check", "run", "local", "--local-lab", "--budget", "5"]
            )
            output = cli_text(result)

        assert result.exit_code == EXIT_OK, output
        assert "Assessment summary" in output

    def test_loopback_without_local_lab_and_no_env_var_is_denied(
        self,
        runner: CliRunner,
        workspace_root: Path,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Without --local-lab or AEGISAPI_ALLOWED_HOSTS, loopback is denied."""
        with local_server(routes()) as server:
            prepare(runner, server, tmp_path, monkeypatch)
            monkeypatch.delenv("AEGISAPI_ALLOWED_HOSTS", raising=False)
            before = len(server.received)

            result = runner.invoke(app, ["check", "run", "local", "--budget", "5"])

            assert len(server.received) == before

        assert result.exit_code == EXIT_SCOPE_ERROR
        assert "--local-lab" in cli_text(result)

    def test_local_lab_flag_appears_in_help(self, runner: CliRunner) -> None:
        output = cli_text(runner.invoke(app, ["check", "run", "--help"]))

        assert "--local-lab" in output


class TestRiskExplainNoArgs:
    def test_explain_with_no_arguments_prints_the_scoring_model(
        self, runner: CliRunner, workspace_root: Path
    ) -> None:
        result = runner.invoke(app, ["risk", "explain"])
        output = cli_text(result)

        assert result.exit_code == EXIT_OK, output
        assert "Risk scoring model" in output
        assert "never severity" in output

    def test_explain_with_no_name_still_shows_model_not_an_error(
        self, runner: CliRunner, workspace_root: Path
    ) -> None:
        result = runner.invoke(app, ["risk", "explain"])
        output = cli_text(result)

        assert result.exit_code == EXIT_OK, output
        assert "Risk scoring model" in output
