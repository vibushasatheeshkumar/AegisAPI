"""Logging configuration, credential redaction, and exception behaviour."""

from __future__ import annotations

import io
import logging
from pathlib import Path

import pytest
import typer
from rich.console import Console

from aegisapi.cli import error_boundary
from aegisapi.core.exceptions import (
    EXIT_CONFIG_ERROR,
    EXIT_INTERNAL_ERROR,
    EXIT_WORKSPACE_ERROR,
    AegisAPIError,
    ConfigNotFoundError,
    InvalidConfigError,
    WorkspaceError,
)
from aegisapi.core.logging import (
    LOGGER_NAME,
    configure_logging,
    get_logger,
    is_configured,
    managed_handlers,
    reset_logging,
    set_log_level,
)
from aegisapi.models.common import LogLevel
from aegisapi.utils.redaction import REDACTED, is_sensitive_key, redact_mapping, redact_text

SECRET = "eyJhbGciOiJIUzI1NiJ9.super-secret-value"


def capture_console() -> tuple[Console, io.StringIO]:
    """Return a Rich console that writes into an in-memory buffer."""
    buffer = io.StringIO()
    return Console(file=buffer, width=200, no_color=True, highlight=False), buffer


class TestConfiguration:
    def test_configure_logging_installs_a_single_handler(self) -> None:
        console, _ = capture_console()

        logger = configure_logging(LogLevel.INFO, console=console)

        assert logger.name == LOGGER_NAME
        assert len(managed_handlers()) == 1
        assert is_configured() is True

    def test_repeated_configuration_replaces_handlers(self) -> None:
        console, _ = capture_console()

        configure_logging(LogLevel.INFO, console=console)
        configure_logging(LogLevel.WARNING, console=console)

        logger = logging.getLogger(LOGGER_NAME)
        assert len(managed_handlers()) == 1
        assert logger.level == logging.WARNING

    def test_requested_level_is_applied_to_logger_and_handlers(self) -> None:
        console, _ = capture_console()

        logger = configure_logging("warning", console=console)

        assert logger.level == logging.WARNING
        assert all(handler.level == logging.WARNING for handler in managed_handlers())

    def test_debug_flag_forces_debug_level(self) -> None:
        console, _ = capture_console()

        logger = configure_logging(LogLevel.CRITICAL, debug=True, console=console)

        assert logger.level == logging.DEBUG

    def test_configuring_aegisapi_does_not_touch_the_root_logger(self) -> None:
        console, _ = capture_console()
        root_handlers_before = list(logging.getLogger().handlers)

        logger = configure_logging(LogLevel.INFO, console=console)

        assert logger.propagate is False
        assert logging.getLogger().handlers == root_handlers_before

    def test_messages_below_the_level_are_not_emitted(self) -> None:
        console, buffer = capture_console()
        configure_logging(LogLevel.WARNING, console=console)

        get_logger("test").info("quiet message")
        get_logger("test").warning("loud message")

        output = buffer.getvalue()
        assert "quiet message" not in output
        assert "loud message" in output

    def test_set_log_level_updates_existing_handlers(self) -> None:
        console, _ = capture_console()
        logger = configure_logging(LogLevel.INFO, console=console)

        set_log_level(LogLevel.ERROR)

        assert logger.level == logging.ERROR
        assert all(handler.level == logging.ERROR for handler in managed_handlers())

    def test_reset_logging_removes_managed_handlers(self) -> None:
        console, _ = capture_console()
        configure_logging(LogLevel.INFO, console=console)
        foreign = logging.NullHandler()
        logging.getLogger(LOGGER_NAME).addHandler(foreign)

        reset_logging()

        assert is_configured() is False
        # A handler AegisAPI did not install is left in place.
        assert foreign in logging.getLogger(LOGGER_NAME).handlers
        logging.getLogger(LOGGER_NAME).removeHandler(foreign)

    def test_child_logger_names_are_namespaced(self) -> None:
        assert get_logger("core.config").name == f"{LOGGER_NAME}.core.config"
        assert get_logger(f"{LOGGER_NAME}.cli").name == f"{LOGGER_NAME}.cli"
        assert get_logger(None).name == LOGGER_NAME

    def test_log_file_receives_records(self, tmp_path: Path) -> None:
        console, _ = capture_console()
        log_file = tmp_path / "logs" / "aegisapi.log"

        configure_logging(LogLevel.INFO, console=console, log_file=log_file)
        get_logger("test").info("workspace initialised")
        reset_logging()

        assert "workspace initialised" in log_file.read_text(encoding="utf-8")

    def test_unwritable_log_file_raises_workspace_error(self, tmp_path: Path) -> None:
        console, _ = capture_console()
        blocker = tmp_path / "blocker"
        blocker.write_text("not a directory", encoding="utf-8")

        with pytest.raises(WorkspaceError):
            configure_logging(LogLevel.INFO, console=console, log_file=blocker / "aegisapi.log")


class TestRedaction:
    @pytest.mark.parametrize(
        "key",
        ["Authorization", "X-API-Key", "api_key", "apiKey", "Set-Cookie", "password", "token"],
    )
    def test_sensitive_keys_are_detected(self, key: str) -> None:
        assert is_sensitive_key(key) is True

    @pytest.mark.parametrize("key", ["host", "path", "status_code", "endpoint", ""])
    def test_ordinary_keys_are_not_sensitive(self, key: str) -> None:
        assert is_sensitive_key(key) is False

    def test_mapping_values_are_replaced(self) -> None:
        redacted = redact_mapping(
            {
                "Authorization": f"Bearer {SECRET}",
                "X-Request-Id": "abc-123",
                "nested": {"api_key": SECRET, "host": "api.example.com"},
            }
        )

        assert redacted["Authorization"] == REDACTED
        assert redacted["X-Request-Id"] == "abc-123"
        assert redacted["nested"]["api_key"] == REDACTED
        assert redacted["nested"]["host"] == "api.example.com"

    @pytest.mark.parametrize(
        "text",
        [
            "Authorization: Bearer " + SECRET,
            "api_key=" + SECRET,
            '"password": "' + SECRET + '"',
            "Cookie: session=" + SECRET,
        ],
    )
    def test_free_text_credentials_are_replaced(self, text: str) -> None:
        scrubbed = redact_text(text)

        assert SECRET not in scrubbed
        assert REDACTED in scrubbed

    def test_ordinary_text_is_untouched(self) -> None:
        message = "GET /v1/orders returned 200 in 31 ms"

        assert redact_text(message) == message

    def test_log_records_are_redacted_before_output(self) -> None:
        console, buffer = capture_console()
        configure_logging(LogLevel.INFO, console=console)

        get_logger("test").info("Authorization: Bearer %s", SECRET)
        get_logger("test").info("Captured header %s", f"api_key={SECRET}")

        output = buffer.getvalue()
        assert SECRET not in output
        assert REDACTED in output

    def test_formatting_arguments_still_interpolate(self) -> None:
        console, buffer = capture_console()
        configure_logging(LogLevel.INFO, console=console)

        get_logger("test").info("status %s for %s", 200, "api.example.com")

        output = buffer.getvalue()
        assert "status 200 for api.example.com" in output

    def test_credentials_passed_as_arguments_are_redacted(self) -> None:
        console, buffer = capture_console()
        configure_logging(LogLevel.INFO, console=console)

        # The format string alone reveals nothing, so the argument must be
        # scrubbed after interpolation rather than before.
        get_logger("test").info("Authorization: %s", f"Bearer {SECRET}")

        output = buffer.getvalue()
        assert SECRET not in output
        assert REDACTED in output

    def test_log_file_contents_are_redacted(self, tmp_path: Path) -> None:
        console, _ = capture_console()
        log_file = tmp_path / "aegisapi.log"

        configure_logging(LogLevel.INFO, console=console, log_file=log_file)
        get_logger("test").warning("Authorization: Bearer %s", SECRET)
        reset_logging()

        contents = log_file.read_text(encoding="utf-8")
        assert SECRET not in contents
        assert REDACTED in contents


class TestExceptions:
    def test_exit_codes_are_distinct_and_documented(self) -> None:
        assert AegisAPIError("x").exit_code == 1
        assert InvalidConfigError("x").exit_code == EXIT_CONFIG_ERROR
        assert ConfigNotFoundError("x").exit_code == EXIT_CONFIG_ERROR
        assert WorkspaceError("x").exit_code == EXIT_WORKSPACE_ERROR

    def test_message_and_hint_are_preserved(self) -> None:
        error = InvalidConfigError("bad config", hint="fix line 3")

        assert str(error) == "bad config"
        assert error.message == "bad config"
        assert error.hint == "fix line 3"

    def test_every_error_derives_from_the_base_class(self) -> None:
        for error in (InvalidConfigError("x"), ConfigNotFoundError("x"), WorkspaceError("x")):
            assert isinstance(error, AegisAPIError)

    def test_boundary_converts_application_error_to_exit_code(self) -> None:
        with pytest.raises(typer.Exit) as excinfo, error_boundary(debug=False):
            raise InvalidConfigError("bad config", hint="fix it")

        assert excinfo.value.exit_code == EXIT_CONFIG_ERROR

    def test_boundary_reports_unexpected_errors_as_internal(self) -> None:
        with pytest.raises(typer.Exit) as excinfo, error_boundary(debug=False):
            raise RuntimeError("defect")

        assert excinfo.value.exit_code == EXIT_INTERNAL_ERROR

    def test_boundary_does_not_swallow_exit_requests(self) -> None:
        with pytest.raises(typer.Exit) as excinfo, error_boundary(debug=False):
            raise typer.Exit(0)

        assert excinfo.value.exit_code == 0

    def test_boundary_passes_successful_blocks_through(self) -> None:
        marker = []

        with error_boundary(debug=False):
            marker.append("ran")

        assert marker == ["ran"]
