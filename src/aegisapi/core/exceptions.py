"""Application exception hierarchy and process exit codes.

Every error that AegisAPI raises deliberately derives from
:class:`AegisAPIError`. The CLI layer catches that base class, prints the
``message`` (plus an optional ``hint``) and exits with ``exit_code``. Anything
that is *not* an :class:`AegisAPIError` is treated as an internal defect: it is
reported as such and logged, never silently swallowed.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pydantic import ValidationError

EXIT_OK = 0
"""Successful execution."""

EXIT_ERROR = 1
"""Generic, expected failure."""

EXIT_CONFIG_ERROR = 3
"""Configuration could not be found, parsed, or validated."""

EXIT_WORKSPACE_ERROR = 4
"""The local workspace could not be created or inspected."""

EXIT_SCOPE_ERROR = 5
"""A URL was rejected by scope enforcement."""

EXIT_TARGET_ERROR = 6
"""A target, or a URL supplied for one, could not be registered or found."""

EXIT_CREDENTIAL_ERROR = 7
"""A configured credential reference could not be resolved."""

EXIT_SPECIFICATION_ERROR = 8
"""An API specification could not be read, parsed, or supported."""

EXIT_DISCOVERY_ERROR = 9
"""A discovery result could not be stored, exported, or loaded."""

EXIT_TRANSPORT_ERROR = 10
"""An authorised request failed before a complete HTTP response arrived."""

EXIT_REPORT_ERROR = 11
"""A report could not be built or written."""

EXIT_FINDINGS_FOUND = 20
"""A scan completed and produced at least one finding at the requested severity threshold.

Only raised when the operator passed ``--fail-on``; a scan that completed its job
exits zero by default regardless of what it found.
"""

EXIT_INTERNAL_ERROR = 70
"""An unexpected exception escaped the application."""


class AegisAPIError(Exception):
    """Base class for all deliberate AegisAPI failures.

    Args:
        message: A short, user-facing description of what went wrong. It must
            never contain credentials or raw request/response bodies.
        hint: Optional actionable next step shown below the error message.
    """

    exit_code: int = EXIT_ERROR

    def __init__(self, message: str, *, hint: str | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.hint = hint

    def __str__(self) -> str:
        return self.message


class ConfigError(AegisAPIError):
    """Base class for configuration problems."""

    exit_code: int = EXIT_CONFIG_ERROR


class ConfigNotFoundError(ConfigError):
    """An explicitly requested configuration file does not exist."""


class InvalidConfigError(ConfigError):
    """A configuration file exists but is malformed or fails validation."""


class WorkspaceError(AegisAPIError):
    """The local AegisAPI workspace could not be created or read."""

    exit_code: int = EXIT_WORKSPACE_ERROR


class ScopeViolationError(AegisAPIError):
    """A URL falls outside the authorised assessment scope.

    Raised by :func:`aegisapi.core.scope.assert_in_scope`, which every future
    module that performs network activity must call before sending a request.
    """

    exit_code: int = EXIT_SCOPE_ERROR


class TargetError(AegisAPIError):
    """Base class for target management and target input problems."""

    exit_code: int = EXIT_TARGET_ERROR


class TargetNotFoundError(TargetError):
    """No target is registered under the requested name."""


class DuplicateTargetError(TargetError):
    """A target with the requested name is already registered."""


class InvalidTargetError(TargetError):
    """A target definition failed validation."""


class InvalidUrlError(TargetError):
    """A URL is malformed, or uses a form AegisAPI refuses to interpret.

    AegisAPI rejects ambiguous URLs rather than guessing, because a guess in a
    scope decision can mean contacting a host nobody authorised.
    """


class TargetStoreError(TargetError):
    """The target store file is missing, unreadable, or corrupt."""


class SpecificationError(AegisAPIError):
    """Base class for API specification problems."""

    exit_code: int = EXIT_SPECIFICATION_ERROR


class SpecificationNotFoundError(SpecificationError):
    """The specification file does not exist or is not a file."""


class InvalidSpecificationError(SpecificationError):
    """The specification file exists but is not valid JSON, YAML, or OpenAPI.

    An invalid specification is never treated as a valid one: a parser that
    guessed at a malformed document would produce an endpoint inventory the
    operator could not trust.
    """


class UnsupportedSpecificationError(SpecificationError):
    """The specification declares a version AegisAPI does not parse.

    Refused rather than approximated, because a format AegisAPI does not
    understand may place security requirements where it would not look.
    """


class DiscoveryError(AegisAPIError):
    """A discovery result could not be stored, exported, or loaded."""

    exit_code: int = EXIT_DISCOVERY_ERROR


class ReportError(AegisAPIError):
    """A report could not be built, rendered, or written.

    Distinct from :class:`DiscoveryError` so that a failure to produce output
    is not reported as a failure to read a stored document. A requested format
    that this build cannot produce raises this rather than falling back to one
    it can: a report in the wrong format is not the report that was asked for.
    """

    exit_code: int = EXIT_REPORT_ERROR


class TransportError(AegisAPIError):
    """An authorised request did not produce a complete HTTP response.

    Deliberately distinct from an HTTP error status: a 500 is an answer from
    the API, while a connection reset is the absence of one. Later phases must
    not read a transport failure as a finding about the API.
    """

    exit_code: int = EXIT_TRANSPORT_ERROR


class ConnectionFailedError(TransportError):
    """The host could not be reached, or refused or reset the connection."""


class RequestTimeoutError(TransportError):
    """A connect or read timeout elapsed before the response completed."""


class TlsError(TransportError):
    """TLS verification or negotiation failed.

    Never raised because AegisAPI skipped verification: certificate checking
    cannot be disabled silently, only by an explicit, warned-about option.
    """


class ResponseTooLargeError(TransportError):
    """The response exceeded the configured size limit while being received."""


class DestinationMismatchError(TransportError):
    """The transport sent a request somewhere other than the validated URL.

    This should be impossible. It exists because the whole scope guarantee
    rests on the bytes leaving the machine matching the URL that was checked,
    so the client verifies that rather than assuming it.
    """


class CredentialError(AegisAPIError):
    """Base class for credential resolution problems."""

    exit_code: int = EXIT_CREDENTIAL_ERROR


class MissingCredentialError(CredentialError):
    """A configured credential reference resolved to nothing.

    AegisAPI never substitutes an empty value for a missing credential: an
    unauthenticated request that was meant to be authenticated produces
    misleading assessment results.
    """


def format_validation_problems(error: ValidationError) -> str:
    """Summarise a Pydantic error as a short, user-facing list of problems.

    Produces ``"field.subfield: message; other: message"``. Pydantic's own
    representation includes input values, which could echo a credential back to
    the terminal, so only locations and messages are used.

    Pydantic's ``"Value error, "`` prefix is stripped, and a whole-model error
    is reported without a location, because ``"<root>: ..."`` tells an operator
    nothing they can act on.
    """
    problems = []
    for detail in error.errors():
        location = ".".join(str(part) for part in detail["loc"])
        message = detail["msg"]
        for prefix in ("Value error, ", "Assertion failed, "):
            message = message.removeprefix(prefix)
        problems.append(f"{location}: {message}" if location else message)
    return "; ".join(problems)


__all__ = [
    "EXIT_CONFIG_ERROR",
    "EXIT_CREDENTIAL_ERROR",
    "EXIT_DISCOVERY_ERROR",
    "EXIT_ERROR",
    "EXIT_FINDINGS_FOUND",
    "EXIT_INTERNAL_ERROR",
    "EXIT_OK",
    "EXIT_REPORT_ERROR",
    "EXIT_SCOPE_ERROR",
    "EXIT_SPECIFICATION_ERROR",
    "EXIT_TARGET_ERROR",
    "EXIT_TRANSPORT_ERROR",
    "EXIT_WORKSPACE_ERROR",
    "AegisAPIError",
    "ConfigError",
    "ConfigNotFoundError",
    "ConnectionFailedError",
    "CredentialError",
    "DestinationMismatchError",
    "DiscoveryError",
    "DuplicateTargetError",
    "InvalidConfigError",
    "InvalidSpecificationError",
    "InvalidTargetError",
    "InvalidUrlError",
    "MissingCredentialError",
    "ReportError",
    "RequestTimeoutError",
    "ResponseTooLargeError",
    "ScopeViolationError",
    "SpecificationError",
    "SpecificationNotFoundError",
    "TargetError",
    "TargetNotFoundError",
    "TargetStoreError",
    "TlsError",
    "TransportError",
    "UnsupportedSpecificationError",
    "WorkspaceError",
]
