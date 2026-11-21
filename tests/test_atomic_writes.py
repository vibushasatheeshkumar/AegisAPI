"""The shared atomic-write primitive, and the race it was introduced to close.

Every document AegisAPI stores goes through
:func:`aegisapi.core.workspace.write_text_atomic`. Earlier versions of the four
writers each derived a temporary path from the destination - ``<name>.tmp`` -
which meant two writers aimed at the same document shared one scratch file and
interleaved their bytes into it, and either one's cleanup could delete the
other's work in progress.

The concurrency tests here do not rely on timing. A ``threading.Barrier``
installed through a controlled hook holds both writers at the moment their
temporary files exist on disk, so the assertion that two distinct files are
present is deterministic. Under the old fixed name there would have been one.
"""

from __future__ import annotations

import json
import os
import sys
import threading
from pathlib import Path

import pytest

from aegisapi.core import workspace as workspace_module
from aegisapi.core.exceptions import DiscoveryError, ReportError, TargetStoreError
from aegisapi.core.targets import TargetStore
from aegisapi.core.workspace import write_text_atomic
from aegisapi.discovery import store as discovery_store
from aegisapi.reporting import writer as report_writer
from aegisapi.testing import store as assessment_store
from assessfix import (
    assessment_result,
    check_result,
    classified,
    discovery_result,
    public,
)
from conftest import make_target

LEGACY_SUFFIX = ".tmp"
"""The suffix the superseded implementation derived from the destination."""


def temp_files(directory: Path, destination: Path) -> list[Path]:
    """Temporary files this primitive would have created for ``destination``."""
    return sorted(directory.glob(f"{destination.name}.*{LEGACY_SUFFIX}"))


def any_temp_files(directory: Path) -> list[Path]:
    """Every leftover temporary file in a directory."""
    return sorted(path for path in directory.iterdir() if path.name.endswith(LEGACY_SUFFIX))


class TestSuccessfulWrites:
    def test_the_payload_lands_at_the_destination(self, tmp_path: Path) -> None:
        destination = tmp_path / "doc.json"

        write_text_atomic(destination, '{"ok": true}\n')

        assert destination.read_text(encoding="utf-8") == '{"ok": true}\n'

    def test_an_existing_document_is_replaced(self, tmp_path: Path) -> None:
        destination = tmp_path / "doc.json"
        destination.write_text("previous", encoding="utf-8")

        write_text_atomic(destination, "current\n")

        assert destination.read_text(encoding="utf-8") == "current\n"

    def test_no_temporary_file_survives_a_success(self, tmp_path: Path) -> None:
        destination = tmp_path / "doc.json"

        write_text_atomic(destination, "payload\n")

        assert any_temp_files(tmp_path) == []
        assert list(tmp_path.iterdir()) == [destination]

    def test_newlines_are_not_translated(self, tmp_path: Path) -> None:
        destination = tmp_path / "doc.json"

        write_text_atomic(destination, "a\nb\n")

        assert destination.read_bytes() == b"a\nb\n"

    def test_utf8_round_trips(self, tmp_path: Path) -> None:
        destination = tmp_path / "doc.json"

        write_text_atomic(destination, "café ✓\n")

        assert destination.read_text(encoding="utf-8") == "café ✓\n"

    @pytest.mark.skipif(sys.platform == "win32", reason="POSIX mode bits")
    def test_posix_permissions_are_restrictive(self, tmp_path: Path) -> None:
        destination = tmp_path / "doc.json"

        write_text_atomic(destination, "payload\n")

        assert destination.stat().st_mode & 0o777 == 0o600


class TestUniqueTemporaryNames:
    def test_the_temporary_name_is_not_the_legacy_fixed_name(self, tmp_path: Path) -> None:
        destination = tmp_path / "doc.json"
        seen: list[str] = []

        def record(path: Path, mode: int) -> None:
            seen.append(path.name)

        with pytest.MonkeyPatch.context() as patch:
            patch.setattr("aegisapi.core.workspace.restrict_permissions", record)
            write_text_atomic(destination, "payload\n")

        assert seen
        assert seen[0] != destination.name + LEGACY_SUFFIX
        assert seen[0].startswith(destination.name + ".")
        assert seen[0].endswith(LEGACY_SUFFIX)

    def test_successive_writes_use_different_temporary_names(self, tmp_path: Path) -> None:
        destination = tmp_path / "doc.json"
        seen: list[str] = []

        def record(path: Path, mode: int) -> None:
            seen.append(path.name)

        with pytest.MonkeyPatch.context() as patch:
            patch.setattr("aegisapi.core.workspace.restrict_permissions", record)
            for index in range(5):
                write_text_atomic(destination, f"payload {index}\n")

        assert len(set(seen)) == 5

    def test_a_leftover_legacy_temporary_file_is_neither_used_nor_removed(
        self, tmp_path: Path
    ) -> None:
        # A file left behind by an older build must not be adopted as scratch
        # space, and a successful write must not quietly delete it.
        destination = tmp_path / "doc.json"
        legacy = tmp_path / (destination.name + LEGACY_SUFFIX)
        legacy.write_text("left behind by an older version", encoding="utf-8")

        write_text_atomic(destination, "payload\n")

        assert legacy.read_text(encoding="utf-8") == "left behind by an older version"
        assert destination.read_text(encoding="utf-8") == "payload\n"


class TestConcurrentWrites:
    def run_two_writers(
        self, destination: Path
    ) -> tuple[list[str], list[int], list[BaseException]]:
        """Hold two writers at the point their temporary files exist.

        The barrier makes the overlap deterministic: neither writer proceeds to
        the rename until both have a temporary file on disk.
        """
        barrier = threading.Barrier(2, timeout=30)
        names: list[str] = []
        observed: list[int] = []
        lock = threading.Lock()
        real = workspace_module.restrict_permissions

        def hooked(path: Path, mode: int) -> None:
            with lock:
                names.append(path.name)
            # First rendezvous: both temporary files now exist on disk.
            barrier.wait()
            with lock:
                observed.append(len(any_temp_files(destination.parent)))
            # Second rendezvous: neither writer may rename - which would consume
            # its temporary file - until both have finished counting. Without
            # this the count itself would be a race.
            barrier.wait()
            real(path, mode)

        errors: list[BaseException] = []

        def write(payload: str) -> None:
            try:
                write_text_atomic(destination, payload)
            except BaseException as exc:  # surfaced by the assertions below
                errors.append(exc)

        with pytest.MonkeyPatch.context() as patch:
            patch.setattr("aegisapi.core.workspace.restrict_permissions", hooked)
            threads = [
                threading.Thread(target=write, args=(f"{'x' * 2000}-{index}\n",))
                for index in range(2)
            ]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(timeout=30)

        return names, observed, errors

    def test_two_concurrent_writers_use_distinct_temporary_files(self, tmp_path: Path) -> None:
        destination = tmp_path / "doc.json"

        names, _, _ = self.run_two_writers(destination)

        assert len(names) == 2
        assert len(set(names)) == 2, "both writers shared one temporary file"

    def test_both_temporary_files_coexist_on_disk(self, tmp_path: Path) -> None:
        # The discriminating assertion. With the superseded fixed name there
        # would have been exactly one file here, whichever writer opened last.
        destination = tmp_path / "doc.json"

        _, observed, _ = self.run_two_writers(destination)

        assert observed == [2, 2]

    def test_the_destination_holds_one_complete_payload(self, tmp_path: Path) -> None:
        # The guarantee: whichever writer publishes, its document is intact.
        # The old shared temporary file could leave a mixture of both payloads.
        destination = tmp_path / "doc.json"

        self.run_two_writers(destination)

        content = destination.read_text(encoding="utf-8")
        assert content in {f"{'x' * 2000}-0\n", f"{'x' * 2000}-1\n"}

    def test_at_most_one_writer_fails_and_it_fails_as_an_os_error(self, tmp_path: Path) -> None:
        # On Windows a concurrent rename onto the same destination can be
        # refused with ERROR_ACCESS_DENIED, so one writer may lose rather than
        # simply being overwritten. Either way it surfaces as an OSError, which
        # each store translates into its own documented error type - never as a
        # silent partial write.
        destination = tmp_path / "doc.json"

        _, _, errors = self.run_two_writers(destination)

        assert len(errors) <= 1
        assert all(isinstance(error, OSError) for error in errors)
        assert destination.is_file()

    def test_no_temporary_file_is_left_after_concurrent_writes(self, tmp_path: Path) -> None:
        destination = tmp_path / "doc.json"

        self.run_two_writers(destination)

        assert any_temp_files(tmp_path) == []

    def test_concurrent_writes_to_different_destinations_both_succeed(self, tmp_path: Path) -> None:
        # The common case in practice: two commands saving two documents into
        # the same directory. Nothing contends, so both must complete intact.
        # This one would have passed before the fix too - the superseded name
        # was derived from the destination, so two destinations already meant
        # two temporary files. It is here to prove the unique naming introduced
        # no cross-talk between unrelated writes, not to demonstrate the bug.
        first = tmp_path / "one.json"
        second = tmp_path / "two.json"
        barrier = threading.Barrier(2, timeout=30)
        names: list[str] = []
        lock = threading.Lock()
        real = workspace_module.restrict_permissions

        def hooked(path: Path, mode: int) -> None:
            with lock:
                names.append(path.name)
            barrier.wait()
            real(path, mode)

        errors: list[BaseException] = []

        def write(destination: Path, payload: str) -> None:
            try:
                write_text_atomic(destination, payload)
            except BaseException as exc:  # surfaced by the assertions below
                errors.append(exc)

        with pytest.MonkeyPatch.context() as patch:
            patch.setattr("aegisapi.core.workspace.restrict_permissions", hooked)
            threads = [
                threading.Thread(target=write, args=(first, "first payload\n")),
                threading.Thread(target=write, args=(second, "second payload\n")),
            ]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(timeout=30)

        assert errors == []
        assert len(set(names)) == 2
        assert first.read_text(encoding="utf-8") == "first payload\n"
        assert second.read_text(encoding="utf-8") == "second payload\n"
        assert any_temp_files(tmp_path) == []


class TestFailureHandling:
    def failing_fsync(self) -> object:
        """A replacement for :func:`os.fsync` that always fails."""

        def explode(_: int) -> None:
            raise OSError("disk went away")

        return explode

    def test_a_write_failure_propagates_as_os_error(self, tmp_path: Path) -> None:
        destination = tmp_path / "doc.json"

        with pytest.MonkeyPatch.context() as patch:
            patch.setattr(os, "fsync", self.failing_fsync())
            with pytest.raises(OSError, match="disk went away"):
                write_text_atomic(destination, "payload\n")

    def test_an_existing_document_survives_a_failed_write(self, tmp_path: Path) -> None:
        destination = tmp_path / "doc.json"
        destination.write_text("previous", encoding="utf-8")

        with pytest.MonkeyPatch.context() as patch:
            patch.setattr(os, "fsync", self.failing_fsync())
            with pytest.raises(OSError):
                write_text_atomic(destination, "replacement\n")

        assert destination.read_text(encoding="utf-8") == "previous"

    def test_the_temporary_file_is_cleaned_up_after_a_failure(self, tmp_path: Path) -> None:
        destination = tmp_path / "doc.json"

        with pytest.MonkeyPatch.context() as patch:
            patch.setattr(os, "fsync", self.failing_fsync())
            with pytest.raises(OSError):
                write_text_atomic(destination, "payload\n")

        assert any_temp_files(tmp_path) == []
        assert not destination.exists()

    def test_a_failure_does_not_remove_another_operations_temporary_file(
        self, tmp_path: Path
    ) -> None:
        # Cleanup targets only the file this call created, which is why the
        # unique name matters as much for failure as for success.
        destination = tmp_path / "doc.json"
        foreign = tmp_path / f"{destination.name}.someoneelse{LEGACY_SUFFIX}"
        foreign.write_text("another writer's work in progress", encoding="utf-8")

        with pytest.MonkeyPatch.context() as patch:
            patch.setattr(os, "fsync", self.failing_fsync())
            with pytest.raises(OSError):
                write_text_atomic(destination, "payload\n")

        assert foreign.read_text(encoding="utf-8") == "another writer's work in progress"

    def failing_replace(self) -> object:
        """A replacement for :func:`os.replace` that always fails.

        The rename is the one step that is not retried or recovered, so a
        failure there is the case most likely to leave litter behind.
        """

        def explode(source: object, target: object) -> None:
            raise OSError("rename refused")

        return explode

    def test_a_replacement_failure_propagates_as_os_error(self, tmp_path: Path) -> None:
        destination = tmp_path / "doc.json"

        with pytest.MonkeyPatch.context() as patch:
            patch.setattr(os, "replace", self.failing_replace())
            with pytest.raises(OSError, match="rename refused"):
                write_text_atomic(destination, "payload\n")

    def test_a_replacement_failure_preserves_the_destination(self, tmp_path: Path) -> None:
        destination = tmp_path / "doc.json"
        destination.write_text("previous", encoding="utf-8")

        with pytest.MonkeyPatch.context() as patch:
            patch.setattr(os, "replace", self.failing_replace())
            with pytest.raises(OSError):
                write_text_atomic(destination, "replacement\n")

        assert destination.read_text(encoding="utf-8") == "previous"

    def test_a_replacement_failure_cleans_up_the_temporary_file(self, tmp_path: Path) -> None:
        destination = tmp_path / "doc.json"
        destination.write_text("previous", encoding="utf-8")

        with pytest.MonkeyPatch.context() as patch:
            patch.setattr(os, "replace", self.failing_replace())
            with pytest.raises(OSError):
                write_text_atomic(destination, "replacement\n")

        assert any_temp_files(tmp_path) == []
        assert list(tmp_path.iterdir()) == [destination]

    def test_a_replacement_failure_reaches_the_store_error_contract(self, tmp_path: Path) -> None:
        # The rename failing must surface through each store's own error type,
        # not as a bare OSError escaping the command boundary.
        destination = tmp_path / "assessment.json"

        with pytest.MonkeyPatch.context() as patch:
            patch.setattr(os, "replace", self.failing_replace())
            with pytest.raises(DiscoveryError, match="could not be written"):
                assessment_store.write_document(
                    destination,
                    assessment_result([check_result("AUTH-001", "GET /orders")]),
                    overwrite=False,
                )

        assert any_temp_files(tmp_path) == []

    def test_a_missing_parent_directory_raises(self, tmp_path: Path) -> None:
        # The primitive does not create directories; each caller does that, and
        # each translates the failure into its own error type.
        with pytest.raises(OSError):
            write_text_atomic(tmp_path / "absent" / "doc.json", "payload\n")


class TestAssessmentStoreRegression:
    def document(self) -> object:
        """An assessment document to store."""
        return assessment_result([check_result("AUTH-001", "GET /orders")])

    def test_a_document_is_written_as_valid_json(self, tmp_path: Path) -> None:
        destination = tmp_path / "assessment.json"

        assessment_store.write_document(destination, self.document(), overwrite=False)

        payload = json.loads(destination.read_text(encoding="utf-8"))
        assert payload["target_name"] == "acme"

    def test_no_temporary_file_survives(self, tmp_path: Path) -> None:
        destination = tmp_path / "assessment.json"

        assessment_store.write_document(destination, self.document(), overwrite=False)

        assert any_temp_files(tmp_path) == []

    def test_a_failed_write_keeps_the_previous_document(self, tmp_path: Path) -> None:
        destination = tmp_path / "assessment.json"
        assessment_store.write_document(destination, self.document(), overwrite=False)
        before = destination.read_text(encoding="utf-8")

        with pytest.MonkeyPatch.context() as patch:
            patch.setattr(os, "fsync", lambda _: (_ for _ in ()).throw(OSError("nope")))
            with pytest.raises(DiscoveryError, match="could not be written"):
                assessment_store.write_document(destination, self.document(), overwrite=True)

        assert destination.read_text(encoding="utf-8") == before
        assert any_temp_files(tmp_path) == []

    def test_a_serialisation_failure_touches_nothing(self, tmp_path: Path) -> None:
        destination = tmp_path / "assessment.json"
        assessment_store.write_document(destination, self.document(), overwrite=False)
        before = destination.read_text(encoding="utf-8")

        def explode(document: object) -> str:
            raise ValueError("cannot serialise")

        with pytest.MonkeyPatch.context() as patch:
            patch.setattr(assessment_store, "render_json", explode)
            with pytest.raises(ValueError, match="cannot serialise"):
                assessment_store.write_document(destination, self.document(), overwrite=True)

        assert destination.read_text(encoding="utf-8") == before
        assert any_temp_files(tmp_path) == []


class TestDiscoveryStoreRegression:
    def test_a_failed_write_keeps_the_previous_result(self, tmp_path: Path) -> None:
        result = discovery_result([classified(public("get", "/orders"))])

        destination = tmp_path / "discovery.json"
        discovery_store.write_result_file(destination, result, overwrite=False)
        before = destination.read_text(encoding="utf-8")

        with pytest.MonkeyPatch.context() as patch:
            patch.setattr(os, "fsync", lambda _: (_ for _ in ()).throw(OSError("nope")))
            with pytest.raises(DiscoveryError, match="could not be written"):
                discovery_store.write_result_file(destination, result, overwrite=True)

        assert destination.read_text(encoding="utf-8") == before
        assert any_temp_files(tmp_path) == []


class TestReportWriterRegression:
    def test_a_failed_write_keeps_the_previous_report(self, tmp_path: Path) -> None:
        destination = tmp_path / "report.html"
        report_writer.write_report_text(destination, "<p>first</p>")

        with pytest.MonkeyPatch.context() as patch:
            patch.setattr(os, "fsync", lambda _: (_ for _ in ()).throw(OSError("nope")))
            with pytest.raises(ReportError, match="could not be written"):
                report_writer.write_report_text(destination, "<p>second</p>", overwrite=True)

        assert destination.read_text(encoding="utf-8") == "<p>first</p>\n"
        assert any_temp_files(tmp_path) == []

    def test_overwrite_protection_is_unchanged(self, tmp_path: Path) -> None:
        destination = tmp_path / "report.html"
        report_writer.write_report_text(destination, "<p>first</p>")

        with pytest.raises(ReportError, match="already exists"):
            report_writer.write_report_text(destination, "<p>second</p>")


class TestTargetStoreRegression:
    def test_a_failed_write_keeps_the_previous_targets(self, tmp_path: Path) -> None:
        store = TargetStore(tmp_path / "targets.json")
        store.add(make_target())
        before = store.path.read_text(encoding="utf-8")

        with pytest.MonkeyPatch.context() as patch:
            patch.setattr(os, "fsync", lambda _: (_ for _ in ()).throw(OSError("nope")))
            with pytest.raises(TargetStoreError, match="could not be written"):
                store.add(make_target(name="other"))

        assert store.path.read_text(encoding="utf-8") == before
        assert any_temp_files(tmp_path) == []

    def test_targets_are_written_as_valid_json(self, tmp_path: Path) -> None:
        store = TargetStore(tmp_path / "targets.json")

        store.add(make_target())

        payload = json.loads(store.path.read_text(encoding="utf-8"))
        assert payload["targets"]["acme"]["name"] == "acme"
