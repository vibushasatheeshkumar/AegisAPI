"""Shared concepts used across the whole application.

Phase 1 intentionally defines only the vocabulary that the current foundation
needs: application metadata plus the three enumerations that later subsystems
(security checks, risk analysis, reporting, persistence) will all have to agree
on. The findings database, endpoint inventory, and relationship graph are
deliberately *not* modelled yet.
"""

from __future__ import annotations

import platform
import sys
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

from aegisapi import APP_DESCRIPTION, APP_NAME, __version__


class Severity(StrEnum):
    """Impact rating of a security finding.

    Values follow the familiar informational-to-critical scale so that reports
    and risk scoring can share one vocabulary. Use :attr:`rank` for ordering;
    the string values themselves sort alphabetically and are not meaningful.
    """

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        """Numeric ordering, higher meaning more severe."""
        return _SEVERITY_RANKS[self]


_SEVERITY_RANKS: dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


class Confidence(StrEnum):
    """How certain AegisAPI is that a finding is real.

    Severity answers "how bad is this?"; confidence answers "how sure are we?".
    Keeping them separate lets risk prioritisation weigh both, and lets reports
    distinguish a confirmed medium issue from a speculative critical one.
    """

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CONFIRMED = "confirmed"

    @property
    def rank(self) -> int:
        """Numeric ordering, higher meaning more certain."""
        return _CONFIDENCE_RANKS[self]


_CONFIDENCE_RANKS: dict[Confidence, int] = {
    Confidence.LOW: 0,
    Confidence.MEDIUM: 1,
    Confidence.HIGH: 2,
    Confidence.CONFIRMED: 3,
}


class AssessmentStatus(StrEnum):
    """Lifecycle state of a single assessment run."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"

    @property
    def is_terminal(self) -> bool:
        """``True`` when no further state transition is expected."""
        return self in _TERMINAL_STATUSES


_TERMINAL_STATUSES: frozenset[AssessmentStatus] = frozenset(
    {
        AssessmentStatus.COMPLETED,
        AssessmentStatus.FAILED,
        AssessmentStatus.CANCELLED,
    }
)


class ReportFormat(StrEnum):
    """Output formats planned for the reporting subsystem."""

    JSON = "json"
    HTML = "html"
    PDF = "pdf"
    SARIF = "sarif"


class LogLevel(StrEnum):
    """Logging levels accepted by configuration.

    The values match :mod:`logging` level names so they can be handed straight
    to the standard library.
    """

    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


class AppMetadata(BaseModel):
    """Static facts about this installation of AegisAPI."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str = Field(description="Product name.")
    version: str = Field(description="Installed AegisAPI version.")
    description: str = Field(description="Short product description.")
    python_version: str = Field(description="Interpreter version running AegisAPI.")
    python_executable: str = Field(description="Path to the active interpreter.")
    platform: str = Field(description="Host platform summary.")

    @classmethod
    def current(cls) -> AppMetadata:
        """Build metadata describing the running process."""
        return cls(
            name=APP_NAME,
            version=__version__,
            description=APP_DESCRIPTION,
            python_version=platform.python_version(),
            python_executable=sys.executable,
            platform=platform.platform(),
        )


__all__ = [
    "AppMetadata",
    "AssessmentStatus",
    "Confidence",
    "LogLevel",
    "ReportFormat",
    "Severity",
]
