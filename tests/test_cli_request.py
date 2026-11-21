"""End-to-end behaviour of ``aegisapi request``.

The command talks to a real HTTP server on 127.0.0.1, so the whole path from
argument parsing through scope enforcement to response rendering is exercised.
Denial cases assert the server received nothing at all.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

from aegisapi.cli import app
from aegisapi.core.exceptions import (
    EXIT_OK,
    EXIT_SCOPE_ERROR,
    EXIT_TARGET_ERROR,
    EXIT_TRANSPORT_ERROR,
)
from conftest import cli_text
from httpstub import StubHandler, StubServer, closed_port_url, local_server

TOKEN = "eyJhbGciOiJIUzI1NiJ9.super-secret-token-value"


def ok(handler: StubHandler) -> None:
    """A plain 200 with a JSON body."""
    handler.reply(200, b'{"ok": true}', {"content-type": "application/json"})


def register(
    runner: CliRunner,
    server: StubServer,
    *extra: str,
    base_path: str = "/v1",
) -> str:
    """Register a target pointing at the loopback server. Returns its host."""
    host = server.server_address[0]
    result = runner.invoke(
        app,
        ["target", "add", "local", f"{server.base_url}{base_path}", *extra],
    )
    assert result.exit_code == EXIT_OK, cli_text(result)
    return host


def allow_host(monkeypatch: pytest.MonkeyPatch, host: str) -> None:
    """Satisfy the tool-wide allow-list for the loopback host."""
    monkeypatch.setenv("AEGISAPI_ALLOWED_HOSTS", host)


class TestHelp:
    def test_request_is_listed_in_the_root_help(self, runner: CliRunner) -> None:
        assert "request" in cli_text(runner.invoke(app, ["--help"]))

    def test_help_describes_the_command_as_a_smoke_test(self, runner: CliRunner) -> None:
        output = cli_text(runner.invoke(app, ["request", "--help"]))

        assert "not a scanner" in output
        assert "does not tell you the API is" in output

    def test_help_lists_the_safety_options(self, runner: CliRunner) -> None:
        output = cli_text(runner.invoke(app, ["request", "--help"]))

        for option in ("--no-auth", "--follow-redirects", "--max-bytes", "--timeout"):
            assert option in output


class TestSuccess:
    def test_a_request_in_scope_succeeds(
        self, runner: CliRunner, workspace_root: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        with local_server({"/v1/orders": ok}) as server:
            host = register(runner, server)
            allow_host(monkeypatch, host)

            result = runner.invoke(app, ["request", "local", "GET", "/orders"])
            output = cli_text(result)

            assert result.exit_code == EXIT_OK, output
            assert server.received[-1][1] == "/v1/orders"

        assert "200" in output
        assert "ok" in output

    def test_the_response_shows_timing_and_scope_reason(
        self, runner: CliRunner, workspace_root: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        with local_server({"/v1/orders": ok}) as server:
            allow_host(monkeypatch, register(runner, server))
            output = cli_text(runner.invoke(app, ["request", "local", "GET", "/orders"]))

        assert "ms" in output
        assert "Scope decision" in output
        assert "target scope" in output

    def test_query_parameters_and_headers_are_sent(
        self, runner: CliRunner, workspace_root: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        with local_server({"/v1/orders": ok}) as server:
            allow_host(monkeypatch, register(runner, server))

            result = runner.invoke(
                app,
                [
                    "request",
                    "local",
                    "GET",
                    "/orders",
                    "-q",
                    "limit=2",
                    "-H",
                    "Accept: application/json",
                ],
            )
            assert result.exit_code == EXIT_OK, cli_text(result)
            _, path, headers = server.received[-1]

        assert "limit=2" in path
        assert headers["Accept"] == "application/json"

    def test_a_body_is_sent(
        self, runner: CliRunner, workspace_root: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        with local_server({"/v1/orders": ok}) as server:
            allow_host(monkeypatch, register(runner, server))

            result = runner.invoke(
                app,
                [
                    "request",
                    "local",
                    "POST",
                    "/orders",
                    "-d",
                    '{"a":1}',
                    "--content-type",
                    "application/json",
                ],
            )
            assert result.exit_code == EXIT_OK, cli_text(result)

        assert server.received[-1][0] == "POST"

    def test_a_body_can_come_from_a_file(
        self,
        runner: CliRunner,
        workspace_root: Path,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        payload = tmp_path / "body.json"
        payload.write_text('{"from":"file"}', encoding="utf-8")

        with local_server({"/v1/orders": ok}) as server:
            allow_host(monkeypatch, register(runner, server))

            result = runner.invoke(
                app, ["request", "local", "POST", "/orders", "--data-file", str(payload)]
            )

        assert result.exit_code == EXIT_OK, cli_text(result)

    def test_error_statuses_are_displayed_not_treated_as_failures(
        self, runner: CliRunner, workspace_root: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def not_found(handler: StubHandler) -> None:
            handler.reply(404, b'{"error":"missing"}', {"content-type": "application/json"})

        with local_server({"/v1/gone": not_found}) as server:
            allow_host(monkeypatch, register(runner, server))

            result = runner.invoke(app, ["request", "local", "GET", "/gone"])
            output = cli_text(result)

        assert result.exit_code == EXIT_OK
        assert "404" in output

    def test_output_states_that_a_response_proves_nothing(
        self, runner: CliRunner, workspace_root: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        with local_server({"/v1/orders": ok}) as server:
            allow_host(monkeypatch, register(runner, server))
            output = cli_text(runner.invoke(app, ["request", "local", "GET", "/orders"]))

        assert "not whether it is secure" in output

    def test_no_body_and_no_headers_options(
        self, runner: CliRunner, workspace_root: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        with local_server({"/v1/orders": ok}) as server:
            allow_host(monkeypatch, register(runner, server))
            output = cli_text(
                runner.invoke(
                    app, ["request", "local", "GET", "/orders", "--no-body", "--no-headers"]
                )
            )

        assert "Response headers" not in output
        assert "Body preview" not in output


class TestDenials:
    def test_an_out_of_scope_path_sends_nothing(
        self, runner: CliRunner, workspace_root: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        with local_server({"/v1/orders": ok, "/v2/secret": ok}) as server:
            allow_host(monkeypatch, register(runner, server))

            result = runner.invoke(app, ["request", "local", "GET", f"{server.base_url}/v2/secret"])
            output = cli_text(result)

            assert server.received == []

        assert result.exit_code == EXIT_SCOPE_ERROR
        assert "out of scope" in output
        assert "No request was sent" in output
        assert "Traceback" not in output

    def test_an_excluded_path_sends_nothing(
        self, runner: CliRunner, workspace_root: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        with local_server({"/v1/admin": ok}) as server:
            allow_host(monkeypatch, register(runner, server, "--exclude-path", "/v1/admin"))

            result = runner.invoke(app, ["request", "local", "GET", "/admin"])

            assert server.received == []

        assert result.exit_code == EXIT_SCOPE_ERROR
        assert "excluded" in cli_text(result)

    def test_an_empty_global_allow_list_sends_nothing(
        self, runner: CliRunner, workspace_root: Path
    ) -> None:
        with local_server({"/v1/orders": ok}) as server:
            register(runner, server)

            result = runner.invoke(app, ["request", "local", "GET", "/orders"])
            output = cli_text(result)

            assert server.received == []

        assert result.exit_code == EXIT_SCOPE_ERROR
        assert "loopback" in output or "not explicitly authorised" in output
        assert "--local-lab" in output

    def test_a_disabled_target_sends_nothing(
        self, runner: CliRunner, workspace_root: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        with local_server({"/v1/orders": ok}) as server:
            allow_host(monkeypatch, register(runner, server, "--disabled"))

            result = runner.invoke(app, ["request", "local", "GET", "/orders"])
            output = cli_text(result)

            assert server.received == []

        assert result.exit_code == EXIT_TARGET_ERROR
        assert "disabled" in output
        assert "target update local --enable" in output

    def test_an_unknown_target_is_an_error(self, runner: CliRunner, workspace_root: Path) -> None:
        result = runner.invoke(app, ["request", "ghost", "GET", "/orders"])

        assert result.exit_code == EXIT_TARGET_ERROR
        assert "No target named 'ghost'" in cli_text(result)

    @pytest.mark.parametrize("path", ["//attacker.test/x", ""])
    def test_a_malformed_path_sends_nothing(
        self,
        runner: CliRunner,
        workspace_root: Path,
        monkeypatch: pytest.MonkeyPatch,
        path: str,
    ) -> None:
        with local_server({"/v1/orders": ok}) as server:
            allow_host(monkeypatch, register(runner, server))

            result = runner.invoke(app, ["request", "local", "GET", path])

            assert server.received == []

        assert result.exit_code != EXIT_OK
        assert "Traceback" not in cli_text(result)

    def test_setting_the_host_header_is_refused(
        self, runner: CliRunner, workspace_root: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        with local_server({"/v1/orders": ok}) as server:
            allow_host(monkeypatch, register(runner, server))

            result = runner.invoke(
                app, ["request", "local", "GET", "/orders", "-H", "Host: attacker.test"]
            )

            assert server.received == []

        assert result.exit_code != EXIT_OK
        assert "cannot be set" in cli_text(result)

    def test_an_unsupported_method_is_rejected_by_the_parser(
        self, runner: CliRunner, workspace_root: Path
    ) -> None:
        result = runner.invoke(app, ["request", "local", "TRACE", "/orders"])

        assert result.exit_code != EXIT_OK


class TestMalformedArguments:
    @pytest.mark.parametrize("header", ["no-colon", ": empty-name"])
    def test_a_malformed_header_option_is_reported(
        self, runner: CliRunner, workspace_root: Path, header: str
    ) -> None:
        result = runner.invoke(app, ["request", "local", "GET", "/orders", "-H", header])

        assert result.exit_code != EXIT_OK

    def test_a_malformed_query_option_is_reported(
        self, runner: CliRunner, workspace_root: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        with local_server({"/v1/orders": ok}) as server:
            allow_host(monkeypatch, register(runner, server))

            result = runner.invoke(app, ["request", "local", "GET", "/orders", "-q", "nokey"])

        assert result.exit_code == EXIT_TARGET_ERROR
        assert "key=value" in cli_text(result)

    def test_data_and_data_file_together_are_refused(
        self,
        runner: CliRunner,
        workspace_root: Path,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        payload = tmp_path / "body"
        payload.write_text("x", encoding="utf-8")

        with local_server({"/v1/orders": ok}) as server:
            allow_host(monkeypatch, register(runner, server))

            result = runner.invoke(
                app,
                [
                    "request",
                    "local",
                    "POST",
                    "/orders",
                    "-d",
                    "x",
                    "--data-file",
                    str(payload),
                ],
            )

        assert result.exit_code == EXIT_TARGET_ERROR
        assert "not both" in cli_text(result)

    def test_a_missing_body_file_is_reported(
        self, runner: CliRunner, workspace_root: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        with local_server({"/v1/orders": ok}) as server:
            allow_host(monkeypatch, register(runner, server))

            result = runner.invoke(
                app,
                ["request", "local", "POST", "/orders", "--data-file", "no-such-file"],
            )

        assert result.exit_code == EXIT_TARGET_ERROR
        assert "could not be read" in cli_text(result)


class TestTransportFailures:
    def test_a_connection_failure_is_reported_clearly(
        self, runner: CliRunner, workspace_root: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        dead = closed_port_url()
        add = runner.invoke(app, ["target", "add", "dead", f"{dead}/v1"])
        assert add.exit_code == EXIT_OK, cli_text(add)
        monkeypatch.setenv("AEGISAPI_ALLOWED_HOSTS", "127.0.0.1")

        result = runner.invoke(
            app, ["request", "dead", "GET", "/orders", "--connect-timeout", "0.5"]
        )
        output = cli_text(result)

        assert result.exit_code == EXIT_TRANSPORT_ERROR
        assert "Error:" in output
        assert "Traceback" not in output

    def test_a_read_timeout_is_reported_clearly(
        self, runner: CliRunner, workspace_root: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def slow(handler: StubHandler) -> None:
            handler.reply_stream(b"z" * 16, 50, delay=0.2)

        with local_server({"/v1/slow": slow}) as server:
            allow_host(monkeypatch, register(runner, server))

            result = runner.invoke(app, ["request", "local", "GET", "/slow", "--timeout", "0.15"])
            output = cli_text(result)

        assert result.exit_code == EXIT_TRANSPORT_ERROR
        assert "timed out" in output


class TestCredentialSafety:
    def test_a_configured_credential_is_sent_but_never_displayed(
        self, runner: CliRunner, workspace_root: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        with local_server({"/v1/orders": ok}) as server:
            host = register(runner, server, "--auth-method", "bearer", "--token-env", "ACME_TOKEN")
            allow_host(monkeypatch, host)
            monkeypatch.setenv("ACME_TOKEN", TOKEN)

            result = runner.invoke(app, ["request", "local", "GET", "/orders"])
            output = cli_text(result)
            sent_headers = server.received[-1][2]

        assert result.exit_code == EXIT_OK, output
        # It really was sent...
        assert sent_headers["Authorization"] == f"Bearer {TOKEN}"
        # ...and it appears nowhere in the output.
        assert TOKEN not in output
        assert "bearer applied" in output

    def test_no_auth_sends_no_credential(
        self, runner: CliRunner, workspace_root: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        with local_server({"/v1/orders": ok}) as server:
            host = register(runner, server, "--auth-method", "bearer", "--token-env", "ACME_TOKEN")
            allow_host(monkeypatch, host)
            monkeypatch.setenv("ACME_TOKEN", TOKEN)

            result = runner.invoke(app, ["request", "local", "GET", "/orders", "--no-auth"])
            sent_headers = server.received[-1][2]

        assert result.exit_code == EXIT_OK
        assert "Authorization" not in sent_headers

    def test_a_missing_credential_sends_nothing(
        self, runner: CliRunner, workspace_root: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        with local_server({"/v1/orders": ok}) as server:
            host = register(runner, server, "--auth-method", "bearer", "--token-env", "ACME_TOKEN")
            allow_host(monkeypatch, host)
            monkeypatch.delenv("ACME_TOKEN", raising=False)

            result = runner.invoke(app, ["request", "local", "GET", "/orders"])
            output = cli_text(result)

            assert server.received == []

        assert result.exit_code == 7
        assert "ACME_TOKEN" in output
        assert "is not set" in output

    def test_a_header_supplied_credential_is_redacted_in_output(
        self, runner: CliRunner, workspace_root: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        with local_server({"/v1/orders": ok}) as server:
            allow_host(monkeypatch, register(runner, server))

            result = runner.invoke(
                app,
                [
                    "request",
                    "local",
                    "GET",
                    "/orders",
                    "-H",
                    f"Authorization: Bearer {TOKEN}",
                ],
            )
            output = cli_text(result)

        assert result.exit_code == EXIT_OK, output
        assert TOKEN not in output

    def test_a_sensitive_query_parameter_is_redacted_in_output(
        self, runner: CliRunner, workspace_root: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        with local_server({"/v1/orders": ok}) as server:
            allow_host(monkeypatch, register(runner, server))

            result = runner.invoke(
                app, ["request", "local", "GET", "/orders", "-q", f"api_key={TOKEN}"]
            )
            output = cli_text(result)

        assert result.exit_code == EXIT_OK, output
        assert TOKEN not in output
        assert "[REDACTED]" in output

    def test_a_sensitive_response_header_is_redacted(
        self, runner: CliRunner, workspace_root: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def with_cookie(handler: StubHandler) -> None:
            handler.reply(
                200,
                b"{}",
                {"content-type": "application/json", "set-cookie": f"session={TOKEN}"},
            )

        with local_server({"/v1/orders": with_cookie}) as server:
            allow_host(monkeypatch, register(runner, server))

            output = cli_text(runner.invoke(app, ["request", "local", "GET", "/orders"]))

        assert TOKEN not in output
        assert "[REDACTED]" in output


class TestRedirectPolicy:
    def test_redirects_are_not_followed_by_default(
        self, runner: CliRunner, workspace_root: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def redirector(handler: StubHandler) -> None:
            handler.reply(302, b"", {"location": "/v1/elsewhere"})

        routes = {"/v1/start": redirector, "/v1/elsewhere": ok}
        with local_server(routes) as server:
            allow_host(monkeypatch, register(runner, server))

            result = runner.invoke(app, ["request", "local", "GET", "/start"])
            output = cli_text(result)
            paths = [entry[1] for entry in server.received]

        assert result.exit_code == EXIT_OK
        assert "302" in output
        assert paths == ["/v1/start"]

    def test_an_in_scope_redirect_is_followed_when_asked(
        self, runner: CliRunner, workspace_root: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def redirector(handler: StubHandler) -> None:
            handler.reply(302, b"", {"location": "/v1/elsewhere"})

        routes = {"/v1/start": redirector, "/v1/elsewhere": ok}
        with local_server(routes) as server:
            allow_host(monkeypatch, register(runner, server))

            result = runner.invoke(app, ["request", "local", "GET", "/start", "--follow-redirects"])
            output = cli_text(result)
            paths = [entry[1] for entry in server.received]

        assert result.exit_code == EXIT_OK, output
        assert paths == ["/v1/start", "/v1/elsewhere"]
        assert "Redirects followed" in output

    def test_an_out_of_scope_redirect_is_never_followed(
        self, runner: CliRunner, workspace_root: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def redirector(handler: StubHandler) -> None:
            handler.reply(302, b"", {"location": "/v2/secret"})

        routes = {"/v1/start": redirector, "/v2/secret": ok}
        with local_server(routes) as server:
            allow_host(monkeypatch, register(runner, server))

            result = runner.invoke(app, ["request", "local", "GET", "/start", "--follow-redirects"])
            output = cli_text(result)
            paths = [entry[1] for entry in server.received]

        assert result.exit_code == EXIT_SCOPE_ERROR
        # The first hop happened; the redirect target was never requested.
        assert paths == ["/v1/start"]
        assert "out of scope" in output

    def test_a_redirect_to_another_host_is_never_followed(
        self, runner: CliRunner, workspace_root: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def redirector(handler: StubHandler) -> None:
            handler.reply(302, b"", {"location": "https://attacker.test/steal"})

        with local_server({"/v1/start": redirector}) as server:
            allow_host(monkeypatch, register(runner, server))

            result = runner.invoke(app, ["request", "local", "GET", "/start", "--follow-redirects"])

        assert result.exit_code == EXIT_SCOPE_ERROR
        assert "out of scope" in cli_text(result)


class TestResponseLimits:
    def test_the_response_size_limit_is_applied(
        self, runner: CliRunner, workspace_root: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def big(handler: StubHandler) -> None:
            handler.reply_stream(b"x" * 1024, 100)

        with local_server({"/v1/big": big}) as server:
            allow_host(monkeypatch, register(runner, server))

            result = runner.invoke(app, ["request", "local", "GET", "/big", "--max-bytes", "2048"])
            output = cli_text(result)

        assert result.exit_code == EXIT_OK, output
        assert "truncated" in output

    def test_the_plan_line_states_the_limits_before_sending(
        self, runner: CliRunner, workspace_root: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        with local_server({"/v1/orders": ok}) as server:
            allow_host(monkeypatch, register(runner, server))
            output = cli_text(runner.invoke(app, ["request", "local", "GET", "/orders"]))

        assert "Sending" in output
        assert "not following redirects" in output


class TestLocalLab:
    def test_local_lab_flag_allows_loopback_without_env_var(
        self, runner: CliRunner, workspace_root: Path
    ) -> None:
        """--local-lab bypasses the global allow-list for loopback targets."""
        with local_server({"/v1/health": ok}) as server:
            register(runner, server)

            result = runner.invoke(app, ["request", "local", "GET", "/health", "--local-lab"])
            output = cli_text(result)

        assert result.exit_code == EXIT_OK, output
        assert "200" in output

    def test_loopback_without_local_lab_and_no_env_var_is_denied(
        self, runner: CliRunner, workspace_root: Path
    ) -> None:
        """Without --local-lab or AEGISAPI_ALLOWED_HOSTS, loopback is denied."""
        with local_server({"/v1/health": ok}) as server:
            register(runner, server)
            before = len(server.received)

            result = runner.invoke(app, ["request", "local", "GET", "/health"])

            assert len(server.received) == before

        assert result.exit_code == EXIT_SCOPE_ERROR

    def test_local_lab_flag_appears_in_help(self, runner: CliRunner) -> None:
        output = cli_text(runner.invoke(app, ["request", "--help"]))

        assert "--local-lab" in output
