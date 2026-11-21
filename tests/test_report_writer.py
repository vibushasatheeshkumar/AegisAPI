"""The report writer: atomic, permission-restricted, and non-destructive.

A report is often generated into a directory a person already has open, so a
half-written file or a silently clobbered previous report would both be real
problems. These tests cover the failure paths rather than only the happy one.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

from aegisapi.core.exceptions import EXIT_REPORT_ERROR, ReportError
from aegisapi.reporting import write_report_text


class TestWriting:
    def test_text_is_written(self, tmp_path: Path) -> None:
        destination = tmp_path / "report.html"

        written = write_report_text(destination, "<p>hello</p>")

        assert written == destination
        assert destination.read_text(encoding="utf-8") == "<p>hello</p>\n"

    def test_a_trailing_newline_is_added_when_missing(self, tmp_path: Path) -> None:
        destination = tmp_path / "report.json"

        write_report_text(destination, "{}")

        assert destination.read_text(encoding="utf-8") == "{}\n"

    def test_an_existing_trailing_newline_is_not_doubled(self, tmp_path: Path) -> None:
        destination = tmp_path / "report.json"

        write_report_text(destination, "{}\n")

        assert destination.read_text(encoding="utf-8") == "{}\n"

    def test_utf8_content_round_trips(self, tmp_path: Path) -> None:
        destination = tmp_path / "report.html"

        write_report_text(destination, "<p>café &mdash; ✓</p>")

        assert "café" in destination.read_text(encoding="utf-8")
        assert "✓" in destination.read_text(encoding="utf-8")

    def test_newlines_are_not_translated(self, tmp_path: Path) -> None:
        # Opened with newline="\n", so a report is byte-identical across
        # platforms and stays diffable.
        destination = tmp_path / "report.html"

        write_report_text(destination, "a\nb")

        assert destination.read_bytes() == b"a\nb\n"

    def test_parent_directories_are_created(self, tmp_path: Path) -> None:
        destination = tmp_path / "deep" / "nested" / "report.json"

        write_report_text(destination, "{}")

        assert destination.is_file()

    def test_no_temporary_file_is_left_behind(self, tmp_path: Path) -> None:
        destination = tmp_path / "report.json"

        write_report_text(destination, "{}")

        assert list(tmp_path.iterdir()) == [destination]

    def test_a_user_path_is_expanded(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("USERPROFILE", str(tmp_path))
        monkeypatch.setenv("HOME", str(tmp_path))

        written = write_report_text("~/report.json", "{}")

        assert written == tmp_path / "report.json"

    @pytest.mark.skipif(sys.platform == "win32", reason="POSIX mode bits")
    def test_posix_permissions_are_restrictive(self, tmp_path: Path) -> None:
        destination = tmp_path / "report.json"

        write_report_text(destination, "{}")

        assert destination.stat().st_mode & 0o777 == 0o600


class TestOverwriteProtection:
    def test_an_existing_file_is_refused(self, tmp_path: Path) -> None:
        destination = tmp_path / "report.json"
        destination.write_text("original", encoding="utf-8")

        with pytest.raises(ReportError, match="already exists"):
            write_report_text(destination, "replacement")

        assert destination.read_text(encoding="utf-8") == "original"

    def test_the_refusal_names_the_way_out(self, tmp_path: Path) -> None:
        destination = tmp_path / "report.json"
        destination.write_text("original", encoding="utf-8")

        with pytest.raises(ReportError) as excinfo:
            write_report_text(destination, "replacement")

        assert "--force" in str(excinfo.value.hint)
        assert excinfo.value.exit_code == EXIT_REPORT_ERROR

    def test_overwrite_replaces_the_file(self, tmp_path: Path) -> None:
        destination = tmp_path / "report.json"
        destination.write_text("original", encoding="utf-8")

        write_report_text(destination, "replacement", overwrite=True)

        assert destination.read_text(encoding="utf-8") == "replacement\n"

    def test_a_refused_write_leaves_no_temporary_file(self, tmp_path: Path) -> None:
        destination = tmp_path / "report.json"
        destination.write_text("original", encoding="utf-8")

        with pytest.raises(ReportError):
            write_report_text(destination, "replacement")

        assert list(tmp_path.iterdir()) == [destination]


class TestFailurePaths:
    def test_a_directory_destination_is_refused(self, tmp_path: Path) -> None:
        destination = tmp_path / "a-directory"
        destination.mkdir()

        with pytest.raises(ReportError, match="found a directory"):
            write_report_text(destination, "{}")

    def test_a_directory_destination_is_refused_even_with_overwrite(self, tmp_path: Path) -> None:
        destination = tmp_path / "a-directory"
        destination.mkdir()

        with pytest.raises(ReportError, match="found a directory"):
            write_report_text(destination, "{}", overwrite=True)

    def test_an_unusable_parent_raises_a_report_error(self, tmp_path: Path) -> None:
        blocker = tmp_path / "blocker"
        blocker.write_text("i am a file", encoding="utf-8")

        with pytest.raises(ReportError, match="could not be written"):
            write_report_text(blocker / "report.json", "{}")

    def test_a_failure_mid_write_removes_the_temporary_file(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        destination = tmp_path / "report.json"

        def exploding_fsync(_: int) -> None:
            raise OSError("disk went away")

        monkeypatch.setattr(os, "fsync", exploding_fsync)

        with pytest.raises(ReportError, match="could not be written"):
            write_report_text(destination, "{}")

        assert not destination.exists()
        assert list(tmp_path.iterdir()) == []

    def test_a_failure_mid_write_preserves_a_previous_report(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        destination = tmp_path / "report.json"
        destination.write_text("previous", encoding="utf-8")

        def exploding_fsync(_: int) -> None:
            raise OSError("disk went away")

        monkeypatch.setattr(os, "fsync", exploding_fsync)

        with pytest.raises(ReportError):
            write_report_text(destination, "replacement", overwrite=True)

        assert destination.read_text(encoding="utf-8") == "previous"
        assert list(tmp_path.iterdir()) == [destination]

    def test_the_error_carries_the_reporting_exit_code(self, tmp_path: Path) -> None:
        destination = tmp_path / "a-directory"
        destination.mkdir()

        with pytest.raises(ReportError) as excinfo:
            write_report_text(destination, "{}")

        assert excinfo.value.exit_code == EXIT_REPORT_ERROR == 11
