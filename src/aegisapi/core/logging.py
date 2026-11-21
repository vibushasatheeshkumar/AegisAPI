"""Centralised logging setup.

Two audiences are kept apart on purpose:

* **Operators** see short, actionable messages rendered by Rich. Internal
  tracebacks are suppressed unless debug mode is on.
* **Diagnostics** go to the ``aegisapi`` logger, optionally mirrored to a file
  with ``--log-file``.

Every record passes through :class:`SensitiveDataFilter`, so authorization
headers, API keys, tokens, and passwords are scrubbed before anything is
written. That filter is a safety net, not a licence to log secrets: call sites
should still avoid passing credentials to the logger.
"""

from __future__ import annotations

import logging
from pathlib import Path

from rich.console import Console
from rich.logging import RichHandler

from aegisapi import APP_SLUG
from aegisapi.core.exceptions import WorkspaceError
from aegisapi.models.common import LogLevel
from aegisapi.utils.redaction import redact_text

LOGGER_NAME = APP_SLUG
"""Root of the AegisAPI logger hierarchy."""

_HANDLER_MARKER = "_aegisapi_handler"


class SensitiveDataFilter(logging.Filter):
    """Redact credential-looking text from log records.

    The filter interpolates the record's arguments first and scrubs the
    resulting message, then clears the arguments. Scrubbing the raw format
    string instead would be unsafe and incorrect: a credential supplied as an
    argument to ``"Authorization: %s"`` would never be examined, and removing
    text around a placeholder breaks interpolation.

    Flattening the record loses the original arguments for downstream
    handlers. That is deliberate - no handler should ever receive an
    unredacted value.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            message = record.getMessage()
        except (TypeError, ValueError):  # pragma: no cover - malformed call site
            message = str(record.msg)

        record.msg = redact_text(message)
        record.args = ()
        return True


def get_logger(name: str | None = None) -> logging.Logger:
    """Return a logger inside the ``aegisapi`` hierarchy.

    Args:
        name: Dotted module name. ``aegisapi.core.config`` and ``core.config``
            both resolve to the same logger, so callers can pass ``__name__``.
    """
    if not name or name == LOGGER_NAME:
        return logging.getLogger(LOGGER_NAME)
    if name.startswith(LOGGER_NAME + "."):
        return logging.getLogger(name)
    return logging.getLogger(f"{LOGGER_NAME}.{name}")


def managed_handlers() -> list[logging.Handler]:
    """Return only the handlers that AegisAPI itself installed.

    Test frameworks and host applications legitimately attach their own
    handlers to the ``aegisapi`` logger. AegisAPI never removes or reconfigures
    those, so every operation here is scoped to its own handlers.
    """
    logger = logging.getLogger(LOGGER_NAME)
    return [handler for handler in logger.handlers if getattr(handler, _HANDLER_MARKER, False)]


def _remove_managed_handlers(logger: logging.Logger) -> None:
    """Drop handlers installed by a previous :func:`configure_logging` call."""
    for handler in list(logger.handlers):
        if getattr(handler, _HANDLER_MARKER, False):
            logger.removeHandler(handler)
            handler.close()


def _build_file_handler(log_file: Path, *, formatter: logging.Formatter) -> logging.Handler:
    """Create a UTF-8 file handler, creating the parent directory if needed."""
    try:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        handler = logging.FileHandler(log_file, encoding="utf-8", delay=True)
    except OSError as exc:
        raise WorkspaceError(
            f"Log file could not be opened: {log_file}",
            hint=exc.strerror,
        ) from exc
    handler.setFormatter(formatter)
    return handler


def configure_logging(
    level: LogLevel | str = LogLevel.INFO,
    *,
    debug: bool = False,
    console: Console | None = None,
    log_file: Path | None = None,
) -> logging.Logger:
    """Configure the ``aegisapi`` logger and return it.

    Calling this more than once is safe: handlers installed by earlier calls
    are replaced rather than stacked. Only the AegisAPI logger is touched, so
    importing AegisAPI never reconfigures the host application's root logger.

    Args:
        level: Minimum level to emit. Ignored when ``debug`` is set.
        debug: Force ``DEBUG`` level, show module paths, and enable Rich
            tracebacks for unexpected errors.
        console: Console to write to. Defaults to a stderr console so that log
            output never contaminates command output on stdout.
        log_file: Optional file to mirror records into.
    """
    effective = LogLevel.DEBUG if debug else LogLevel(str(level).upper())

    logger = logging.getLogger(LOGGER_NAME)
    logger.setLevel(effective.value)
    logger.propagate = False
    _remove_managed_handlers(logger)

    rich_handler = RichHandler(
        console=console or Console(stderr=True),
        show_time=debug,
        show_path=debug,
        rich_tracebacks=debug,
        markup=False,
        show_level=True,
    )
    rich_handler.setFormatter(logging.Formatter("%(message)s"))
    handlers: list[logging.Handler] = [rich_handler]

    if log_file is not None:
        handlers.append(
            _build_file_handler(
                log_file,
                formatter=logging.Formatter("%(asctime)s %(levelname)-8s %(name)s %(message)s"),
            )
        )

    redaction_filter = SensitiveDataFilter()
    for handler in handlers:
        handler.setLevel(effective.value)
        handler.addFilter(redaction_filter)
        setattr(handler, _HANDLER_MARKER, True)
        logger.addHandler(handler)

    return logger


def set_log_level(level: LogLevel | str) -> None:
    """Change the level of the configured logger and its managed handlers.

    Used after configuration is loaded, so the file's ``log_level`` takes
    effect without discarding handlers that are already installed.
    """
    effective = LogLevel(str(level).upper())
    logging.getLogger(LOGGER_NAME).setLevel(effective.value)
    for handler in managed_handlers():
        handler.setLevel(effective.value)


def is_configured() -> bool:
    """``True`` when :func:`configure_logging` has installed a handler."""
    return bool(managed_handlers())


def reset_logging() -> None:
    """Remove managed handlers. Intended for tests and repeated CLI invocations."""
    _remove_managed_handlers(logging.getLogger(LOGGER_NAME))


__all__ = [
    "LOGGER_NAME",
    "SensitiveDataFilter",
    "configure_logging",
    "get_logger",
    "is_configured",
    "managed_handlers",
    "reset_logging",
    "set_log_level",
]
