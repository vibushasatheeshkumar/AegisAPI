"""Configuration loading, validation, and defaults.

Format
------
Configuration is TOML, read with the standard library's :mod:`tomllib`, so no
third-party parser is required.

Precedence (lowest to highest)
------------------------------
1. Built-in defaults declared on :class:`AegisConfig`.
2. The user-level configuration file (``<workspace>/config.toml``), or the file
   named by ``--config`` / ``AEGISAPI_CONFIG``.
3. ``AEGISAPI_*`` environment variables.
4. Explicit overrides passed by the caller, which is how CLI flags win.

Unknown keys are rejected rather than ignored, so a typo surfaces immediately
instead of silently leaving a security-relevant setting at its default.
"""

from __future__ import annotations

import os
import tomllib
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    ValidationError,
    field_validator,
    model_validator,
)

from aegisapi.core.exceptions import (
    ConfigNotFoundError,
    InvalidConfigError,
    format_validation_problems,
)
from aegisapi.core.paths import WorkspacePaths
from aegisapi.models.common import LogLevel, ReportFormat
from aegisapi.models.http import HttpLimits

CONFIG_ENV_VAR = "AEGISAPI_CONFIG"
"""Environment variable naming an explicit configuration file."""

ENV_PREFIX = "AEGISAPI_"
"""Prefix for all configuration environment variables."""

DEFAULT_REQUEST_TIMEOUT_SECONDS = 10.0
DEFAULT_MAX_CONCURRENCY = 4

_TRUE_VALUES = frozenset({"1", "true", "yes", "on"})
_FALSE_VALUES = frozenset({"0", "false", "no", "off"})


class ScopeSettings(BaseModel):
    """Scope enforcement rules for future network-facing modules.

    Scope enforcement defaults to *enabled* with an *empty* allow-list, which
    means no host is authorised until the operator names one. That is the
    conservative choice for an assessment tool: a misconfiguration stops the
    run rather than probing an unintended target.
    """

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    enforce: bool = Field(
        default=True,
        description="Refuse to assess hosts that are not explicitly allowed.",
    )
    allowed_hosts: list[str] = Field(
        default_factory=list,
        description="Hostnames the operator is authorised to assess.",
    )

    @field_validator("allowed_hosts", mode="after")
    @classmethod
    def _normalise_hosts(cls, hosts: list[str]) -> list[str]:
        """Lowercase, de-duplicate, and reject anything that is not a hostname."""
        normalised: list[str] = []
        for raw in hosts:
            host = raw.strip().lower()
            if not host:
                continue
            if any(char.isspace() for char in host) or "/" in host or ":" in host:
                raise ValueError(
                    f"{raw!r} is not a bare hostname; omit the scheme, port, "
                    "and path (for example 'api.example.com')"
                )
            if host not in normalised:
                normalised.append(host)
        return normalised


class AegisConfig(BaseModel):
    """Validated AegisAPI settings."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    log_level: LogLevel = Field(
        default=LogLevel.INFO,
        description="Minimum level written to the console log.",
    )
    request_timeout_seconds: float = Field(
        default=DEFAULT_REQUEST_TIMEOUT_SECONDS,
        gt=0,
        le=600,
        description="Baseline per-request read timeout; seeds http.read_timeout_seconds.",
    )
    max_concurrency: int = Field(
        default=DEFAULT_MAX_CONCURRENCY,
        ge=1,
        le=64,
        description="Baseline concurrency ceiling; seeds http.max_concurrency.",
    )
    default_report_format: ReportFormat = Field(
        default=ReportFormat.JSON,
        description="Report format used when none is requested explicitly.",
    )
    scope: ScopeSettings = Field(
        default_factory=ScopeSettings,
        description="Scope enforcement rules.",
    )
    http: HttpLimits = Field(
        default_factory=HttpLimits,
        description="Bounds applied to every HTTP request AegisAPI sends.",
    )

    @model_validator(mode="before")
    @classmethod
    def _seed_http_limits(cls, data: Any) -> Any:
        """Let the two Phase 1 fields seed their ``[http]`` counterparts.

        ``request_timeout_seconds`` and ``max_concurrency`` predate the HTTP
        engine and describe the same quantities as ``http.read_timeout_seconds``
        and ``http.max_concurrency``. Rather than leaving two settings that
        silently disagree, the older ones act as defaults and anything written
        under ``[http]`` wins.

        Done in a "before" validator on the raw mapping so no field is assigned
        during validation.
        """
        if not isinstance(data, Mapping):
            return data

        http = data.get("http")
        if http is not None and not isinstance(http, Mapping):
            # Leave it alone; field validation will report the wrong type.
            return data

        seeded = dict(http) if isinstance(http, Mapping) else {}
        if "read_timeout_seconds" not in seeded and "request_timeout_seconds" in data:
            seeded["read_timeout_seconds"] = data["request_timeout_seconds"]
        if "max_concurrency" not in seeded and "max_concurrency" in data:
            seeded["max_concurrency"] = data["max_concurrency"]

        if not seeded:
            return data
        merged = dict(data)
        merged["http"] = seeded
        return merged

    @field_validator("log_level", mode="before")
    @classmethod
    def _upper_log_level(cls, value: Any) -> Any:
        """Accept ``debug`` as well as ``DEBUG``."""
        return value.upper() if isinstance(value, str) else value

    @field_validator("default_report_format", mode="before")
    @classmethod
    def _lower_report_format(cls, value: Any) -> Any:
        """Accept ``JSON`` as well as ``json``."""
        return value.lower() if isinstance(value, str) else value


def _environ(env: Mapping[str, str] | None) -> Mapping[str, str]:
    return os.environ if env is None else env


def _parse_bool(value: str, *, variable: str) -> bool:
    lowered = value.strip().lower()
    if lowered in _TRUE_VALUES:
        return True
    if lowered in _FALSE_VALUES:
        return False
    raise InvalidConfigError(
        f"{variable} must be a boolean value, got {value!r}.",
        hint="Use one of: true, false, 1, 0, yes, no, on, off.",
    )


def _parse_number(value: str, *, variable: str, cast: type[int] | type[float]) -> int | float:
    try:
        return cast(value.strip())
    except ValueError as exc:
        expected = "an integer" if cast is int else "a number"
        raise InvalidConfigError(f"{variable} must be {expected}, got {value!r}.") from exc


def read_config_file(path: Path) -> dict[str, Any]:
    """Parse a TOML configuration file.

    Raises:
        ConfigNotFoundError: If ``path`` does not exist.
        InvalidConfigError: If ``path`` is unreadable or not valid TOML.
    """
    try:
        raw = path.read_bytes()
    except FileNotFoundError as exc:
        raise ConfigNotFoundError(
            f"Configuration file not found: {path}",
            hint="Run 'aegisapi init' to create a workspace with a sample configuration.",
        ) from exc
    except IsADirectoryError as exc:
        raise InvalidConfigError(f"Configuration path is a directory, not a file: {path}") from exc
    except OSError as exc:
        raise InvalidConfigError(
            f"Configuration file could not be read: {path}",
            hint=exc.strerror,
        ) from exc

    try:
        # "utf-8-sig" discards a leading byte-order mark. Windows editors such
        # as Notepad and PowerShell's Set-Content add one, and tomllib rejects
        # it as an invalid statement, which is a baffling error to receive.
        return tomllib.loads(raw.decode("utf-8-sig"))
    except UnicodeDecodeError as exc:
        raise InvalidConfigError(f"Configuration file is not valid UTF-8 text: {path}") from exc
    except tomllib.TOMLDecodeError as exc:
        raise InvalidConfigError(
            f"Configuration file is not valid TOML: {path}",
            hint=str(exc),
        ) from exc


def config_overrides_from_env(env: Mapping[str, str] | None = None) -> dict[str, Any]:
    """Translate ``AEGISAPI_*`` variables into a nested override mapping.

    Empty variables are ignored so that an unset-but-present variable does not
    clobber a configured value.
    """
    environ = _environ(env)
    overrides: dict[str, Any] = {}
    scope: dict[str, Any] = {}

    def value_of(name: str) -> str | None:
        raw = environ.get(name)
        if raw is None or not raw.strip():
            return None
        return raw

    raw_level = value_of(ENV_PREFIX + "LOG_LEVEL")
    if raw_level is not None:
        overrides["log_level"] = raw_level.strip()

    raw_timeout = value_of(ENV_PREFIX + "REQUEST_TIMEOUT")
    if raw_timeout is not None:
        overrides["request_timeout_seconds"] = _parse_number(
            raw_timeout, variable=ENV_PREFIX + "REQUEST_TIMEOUT", cast=float
        )

    raw_concurrency = value_of(ENV_PREFIX + "MAX_CONCURRENCY")
    if raw_concurrency is not None:
        overrides["max_concurrency"] = _parse_number(
            raw_concurrency, variable=ENV_PREFIX + "MAX_CONCURRENCY", cast=int
        )

    raw_format = value_of(ENV_PREFIX + "REPORT_FORMAT")
    if raw_format is not None:
        overrides["default_report_format"] = raw_format.strip()

    raw_enforce = value_of(ENV_PREFIX + "ENFORCE_SCOPE")
    if raw_enforce is not None:
        scope["enforce"] = _parse_bool(raw_enforce, variable=ENV_PREFIX + "ENFORCE_SCOPE")

    raw_hosts = value_of(ENV_PREFIX + "ALLOWED_HOSTS")
    if raw_hosts is not None:
        scope["allowed_hosts"] = [part.strip() for part in raw_hosts.split(",") if part.strip()]

    http: dict[str, Any] = {}
    raw_connect = value_of(ENV_PREFIX + "CONNECT_TIMEOUT")
    if raw_connect is not None:
        http["connect_timeout_seconds"] = _parse_number(
            raw_connect, variable=ENV_PREFIX + "CONNECT_TIMEOUT", cast=float
        )
    raw_read = value_of(ENV_PREFIX + "READ_TIMEOUT")
    if raw_read is not None:
        http["read_timeout_seconds"] = _parse_number(
            raw_read, variable=ENV_PREFIX + "READ_TIMEOUT", cast=float
        )
    raw_max_bytes = value_of(ENV_PREFIX + "MAX_RESPONSE_BYTES")
    if raw_max_bytes is not None:
        http["max_response_bytes"] = _parse_number(
            raw_max_bytes, variable=ENV_PREFIX + "MAX_RESPONSE_BYTES", cast=int
        )
    raw_rps = value_of(ENV_PREFIX + "REQUESTS_PER_SECOND")
    if raw_rps is not None:
        http["requests_per_second"] = _parse_number(
            raw_rps, variable=ENV_PREFIX + "REQUESTS_PER_SECOND", cast=float
        )
    raw_retries = value_of(ENV_PREFIX + "MAX_RETRIES")
    if raw_retries is not None:
        http["max_retries"] = _parse_number(
            raw_retries, variable=ENV_PREFIX + "MAX_RETRIES", cast=int
        )
    raw_verify = value_of(ENV_PREFIX + "VERIFY_TLS")
    if raw_verify is not None:
        http["verify_tls"] = _parse_bool(raw_verify, variable=ENV_PREFIX + "VERIFY_TLS")

    if scope:
        overrides["scope"] = scope
    if http:
        overrides["http"] = http
    return overrides


def _deep_merge(base: Mapping[str, Any], updates: Mapping[str, Any]) -> dict[str, Any]:
    """Merge ``updates`` into ``base``, recursing into nested mappings."""
    merged: dict[str, Any] = dict(base)
    for key, value in updates.items():
        current = merged.get(key)
        if isinstance(current, Mapping) and isinstance(value, Mapping):
            merged[key] = _deep_merge(current, value)
        else:
            merged[key] = value
    return merged


def _as_config_error(error: ValidationError, source: str) -> InvalidConfigError:
    """Turn a Pydantic error into a short, user-facing configuration error."""
    return InvalidConfigError(
        f"Invalid configuration in {source}.",
        hint=format_validation_problems(error),
    )


def resolve_config_path(
    explicit: Path | None = None,
    *,
    workspace: WorkspacePaths | None = None,
    env: Mapping[str, str] | None = None,
) -> Path | None:
    """Decide which configuration file to load.

    Returns ``None`` when no configuration file is available, in which case
    defaults plus environment overrides apply.

    Raises:
        ConfigNotFoundError: If a file was requested explicitly but is missing.
    """
    environ = _environ(env)

    if explicit is None:
        from_env = environ.get(CONFIG_ENV_VAR, "").strip()
        if from_env:
            explicit = Path(from_env).expanduser()

    if explicit is not None:
        candidate = explicit.expanduser()
        if not candidate.is_file():
            raise ConfigNotFoundError(
                f"Configuration file not found: {candidate}",
                hint="Check the --config path, or run 'aegisapi init' to create one.",
            )
        return candidate

    paths = workspace or WorkspacePaths.resolve(env=env)
    return paths.config_file if paths.config_file.is_file() else None


def load_config(
    path: Path | None = None,
    *,
    env: Mapping[str, str] | None = None,
    overrides: Mapping[str, Any] | None = None,
) -> AegisConfig:
    """Load and validate configuration from ``path``, the environment, and ``overrides``.

    Args:
        path: Configuration file to read, or ``None`` to use defaults only.
        env: Environment mapping to read ``AEGISAPI_*`` variables from. Defaults
            to :data:`os.environ`.
        overrides: Highest-precedence values, typically derived from CLI flags.

    Raises:
        ConfigNotFoundError: If ``path`` is given but missing.
        InvalidConfigError: If any layer is malformed or fails validation.
    """
    data: dict[str, Any] = {}
    source = "built-in defaults"

    if path is not None:
        data = read_config_file(path)
        source = str(path)

    data = _deep_merge(data, config_overrides_from_env(env))
    if overrides:
        data = _deep_merge(data, overrides)

    try:
        return AegisConfig.model_validate(data)
    except ValidationError as exc:
        raise _as_config_error(exc, source) from exc


def render_sample_config() -> str:
    """Return the documented sample ``config.toml`` written by ``aegisapi init``.

    The sample deliberately contains no credentials. Authentication material
    for future assessment modules will be supplied per run, never stored here.
    """
    defaults = AegisConfig()
    follow_redirects = str(defaults.http.follow_redirects).lower()
    verify_tls = str(defaults.http.verify_tls).lower()
    return f"""\
# AegisAPI configuration
#
# Precedence, lowest to highest:
#   built-in defaults  ->  this file  ->  AEGISAPI_* environment variables
#   ->  command-line options
#
# Do not store API keys, tokens, or passwords in this file.

# Console log level: DEBUG, INFO, WARNING, ERROR, CRITICAL.
log_level = "{defaults.log_level.value}"

# Default per-request timeout, in seconds, for future HTTP modules.
request_timeout_seconds = {defaults.request_timeout_seconds}

# Default ceiling on concurrent requests for future HTTP modules.
max_concurrency = {defaults.max_concurrency}

# Default report format: json, html, or pdf.
default_report_format = "{defaults.default_report_format.value}"

[http]
# Bounds on every request AegisAPI sends. The defaults are deliberately
# conservative: an assessment tool that overloads an API is a liability
# regardless of what it finds.
connect_timeout_seconds = {defaults.http.connect_timeout_seconds}
read_timeout_seconds = {defaults.http.read_timeout_seconds}

# Largest response body accepted, in bytes. Enforced while receiving, not
# after the whole body has already been downloaded.
max_response_bytes = {defaults.http.max_response_bytes}

# Requests in flight at once, and the ceiling on request rate across all of
# them.
max_concurrency = {defaults.http.max_concurrency}
requests_per_second = {defaults.http.requests_per_second}

# Automatic retries, for read-shaped methods only. Zero means none.
max_retries = {defaults.http.max_retries}

# Redirects are not followed by default. When following is enabled, every hop
# is scope-checked independently and credentials are never carried to a
# different origin.
follow_redirects = {follow_redirects}
max_redirects = {defaults.http.max_redirects}

# HTTPS certificate verification. Turning this off is reported loudly on every
# request; AegisAPI will not disable it quietly.
verify_tls = {verify_tls}

# Response body kept for display, in bytes.
body_preview_bytes = {defaults.http.body_preview_bytes}

user_agent = "{defaults.http.user_agent}"

[scope]
# Only assess APIs you own or are explicitly authorised to test.
# With enforce = true, a host must appear in allowed_hosts before any future
# AegisAPI module will contact it.
enforce = {str(defaults.scope.enforce).lower()}

# Bare hostnames, without scheme, port, or path.
# Example: allowed_hosts = ["api.example.com", "staging-api.example.com"]
allowed_hosts = []
"""


__all__ = [
    "CONFIG_ENV_VAR",
    "DEFAULT_MAX_CONCURRENCY",
    "DEFAULT_REQUEST_TIMEOUT_SECONDS",
    "ENV_PREFIX",
    "AegisConfig",
    "HttpLimits",
    "ScopeSettings",
    "config_overrides_from_env",
    "load_config",
    "read_config_file",
    "render_sample_config",
    "resolve_config_path",
]
