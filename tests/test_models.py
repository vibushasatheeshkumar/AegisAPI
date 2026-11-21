"""Shared model and enumeration behaviour."""

from __future__ import annotations

import platform
import sys

import pytest
from pydantic import ValidationError

from aegisapi import APP_DESCRIPTION, APP_NAME, __version__
from aegisapi.models.common import (
    AppMetadata,
    AssessmentStatus,
    Confidence,
    LogLevel,
    ReportFormat,
    Severity,
)


class TestSeverity:
    def test_ranks_order_from_informational_to_critical(self) -> None:
        ordered = sorted(Severity, key=lambda severity: severity.rank)

        assert ordered == [
            Severity.INFO,
            Severity.LOW,
            Severity.MEDIUM,
            Severity.HIGH,
            Severity.CRITICAL,
        ]

    def test_values_are_lowercase_strings_usable_in_reports(self) -> None:
        assert Severity.HIGH == "high"
        assert f"{Severity.CRITICAL}" == "critical"


class TestConfidence:
    def test_confidence_is_independent_of_severity(self) -> None:
        assert Confidence.CONFIRMED.rank > Confidence.LOW.rank
        assert set(Confidence) & set(Severity) == {"low", "medium", "high"}

    def test_ranks_order_from_low_to_confirmed(self) -> None:
        ordered = sorted(Confidence, key=lambda confidence: confidence.rank)

        assert ordered[0] is Confidence.LOW
        assert ordered[-1] is Confidence.CONFIRMED


class TestAssessmentStatus:
    @pytest.mark.parametrize(
        "status",
        [AssessmentStatus.COMPLETED, AssessmentStatus.FAILED, AssessmentStatus.CANCELLED],
    )
    def test_finished_states_are_terminal(self, status: AssessmentStatus) -> None:
        assert status.is_terminal is True

    @pytest.mark.parametrize("status", [AssessmentStatus.PENDING, AssessmentStatus.RUNNING])
    def test_in_flight_states_are_not_terminal(self, status: AssessmentStatus) -> None:
        assert status.is_terminal is False


class TestEnumerationValues:
    def test_report_formats_match_the_planned_outputs(self) -> None:
        assert [fmt.value for fmt in ReportFormat] == ["json", "html", "pdf", "sarif"]

    def test_log_levels_match_standard_library_names(self) -> None:
        import logging

        for level in LogLevel:
            assert isinstance(logging.getLevelName(level.value), int)


class TestAppMetadata:
    def test_current_reports_the_running_environment(self) -> None:
        metadata = AppMetadata.current()

        assert metadata.name == APP_NAME
        assert metadata.version == __version__
        assert metadata.description == APP_DESCRIPTION
        assert metadata.python_version == platform.python_version()
        assert metadata.python_executable == sys.executable

    def test_metadata_is_immutable(self) -> None:
        metadata = AppMetadata.current()

        with pytest.raises(ValidationError):
            metadata.version = "9.9.9"

    def test_unknown_metadata_fields_are_rejected(self) -> None:
        with pytest.raises(ValidationError):
            AppMetadata(
                name=APP_NAME,
                version=__version__,
                description=APP_DESCRIPTION,
                python_version="3.11.9",
                python_executable=sys.executable,
                platform="test",
                scan_count=42,
            )
