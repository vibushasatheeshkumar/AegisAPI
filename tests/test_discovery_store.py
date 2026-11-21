"""Persisting and reloading discovery results."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from aegisapi.core.exceptions import DiscoveryError
from aegisapi.core.paths import WorkspacePaths
from aegisapi.discovery.service import discover_from_specification
from aegisapi.discovery.store import (
    DiscoveryStore,
    render_result_json,
    write_result_file,
)
from aegisapi.models.discovery import DISCOVERY_SCHEMA_VERSION, DiscoveryResult
from aegisapi.models.secrets import SecretRef
from aegisapi.models.target import AuthMethod, AuthProfile
from conftest import make_target
from specs import FULL_OPENAPI_30, write_yaml

TOKEN_VALUE = "eyJhbGciOiJIUzI1NiJ9.super-secret-token-value"


@pytest.fixture
def result(tmp_path: Path) -> DiscoveryResult:
    """A discovery result produced from the full OpenAPI fixture."""
    path = write_yaml(tmp_path / "spec.yaml", FULL_OPENAPI_30)
    return discover_from_specification(path, target=make_target())


@pytest.fixture
def store(tmp_path: Path) -> DiscoveryStore:
    """A store backed by a temporary workspace."""
    return DiscoveryStore.for_workspace(WorkspacePaths.resolve(tmp_path / "workspace"))


class TestSerialisation:
    def test_json_is_sorted_and_reloadable(self, result: DiscoveryResult) -> None:
        payload = render_result_json(result)
        document = json.loads(payload)

        assert document["schema_version"] == DISCOVERY_SCHEMA_VERSION
        assert DiscoveryResult.model_validate(document) == result

    def test_serialisation_is_stable_for_the_same_input(self, result: DiscoveryResult) -> None:
        first = json.loads(render_result_json(result))
        second = json.loads(render_result_json(result))
        first.pop("discovered_at")
        second.pop("discovered_at")

        assert first == second

    def test_no_credential_value_can_reach_the_output(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("ACME_TOKEN", TOKEN_VALUE)
        target = make_target(
            auth=AuthProfile(method=AuthMethod.BEARER, token=SecretRef(variable="ACME_TOKEN"))
        )
        path = write_yaml(tmp_path / "spec.yaml", FULL_OPENAPI_30)

        payload = render_result_json(discover_from_specification(path, target=target))

        # A discovery result references the target by name only; there is no
        # authentication profile in it to leak.
        assert TOKEN_VALUE not in payload
        assert "ACME_TOKEN" not in payload

    def test_declared_scheme_metadata_is_kept(self, result: DiscoveryResult) -> None:
        payload = json.loads(render_result_json(result))
        names = {scheme["name"] for scheme in payload["security_schemes"]}

        assert names == {"bearerAuth", "adminKey", "oauth"}


class TestStore:
    def test_save_then_load(self, store: DiscoveryStore, result: DiscoveryResult) -> None:
        store.save(result)

        assert store.load(result.target_name) == result

    def test_save_creates_the_directory(
        self, store: DiscoveryStore, result: DiscoveryResult
    ) -> None:
        assert store.exists(result.target_name) is False

        destination = store.save(result)

        assert destination.is_file()
        assert destination.parent.is_dir()
        assert destination.name == f"{result.target_name}.json"

    def test_resaving_without_overwrite_is_refused(
        self, store: DiscoveryStore, result: DiscoveryResult
    ) -> None:
        store.save(result)

        with pytest.raises(DiscoveryError) as excinfo:
            store.save(result)

        assert "already saved" in excinfo.value.message
        assert "--force" in str(excinfo.value.hint)
        assert excinfo.value.exit_code == 9

    def test_overwrite_replaces_the_result(
        self, store: DiscoveryStore, result: DiscoveryResult
    ) -> None:
        store.save(result)
        changed = result.model_copy(update={"endpoints": []})

        store.save(changed, overwrite=True)

        assert store.load(result.target_name).endpoint_count == 0

    def test_no_temporary_file_is_left_behind(
        self, store: DiscoveryStore, result: DiscoveryResult
    ) -> None:
        destination = store.save(result)

        assert list(destination.parent.glob("*.tmp")) == []

    def test_loading_without_a_saved_result_is_an_error(self, store: DiscoveryStore) -> None:
        with pytest.raises(DiscoveryError) as excinfo:
            store.load("acme")

        assert "No discovery result" in excinfo.value.message
        assert "discover spec acme" in str(excinfo.value.hint)

    @pytest.mark.skipif(sys.platform == "win32", reason="POSIX mode bits")
    def test_posix_permissions_are_restrictive(
        self, store: DiscoveryStore, result: DiscoveryResult
    ) -> None:
        destination = store.save(result)

        assert destination.stat().st_mode & 0o777 == 0o600


class TestCorruptedResults:
    def write(self, store: DiscoveryStore, text: str) -> Path:
        """Write raw text where a result would be stored."""
        path = store.path_for("acme")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        return path

    def test_malformed_json_is_reported(self, store: DiscoveryStore) -> None:
        path = self.write(store, "{not json")

        with pytest.raises(DiscoveryError) as excinfo:
            store.load("acme")

        assert "not valid JSON" in excinfo.value.message
        # The operator's file is left untouched for them to inspect.
        assert path.read_text(encoding="utf-8") == "{not json"

    @pytest.mark.parametrize("text", ["[]", '"x"', "7"])
    def test_non_object_document_is_reported(self, store: DiscoveryStore, text: str) -> None:
        self.write(store, text)

        with pytest.raises(DiscoveryError, match="must be a JSON object"):
            store.load("acme")

    def test_invalid_result_is_reported_with_detail(self, store: DiscoveryStore) -> None:
        self.write(store, json.dumps({"target_name": "acme"}))

        with pytest.raises(DiscoveryError) as excinfo:
            store.load("acme")

        assert "not valid" in excinfo.value.message
        assert "specification" in str(excinfo.value.hint)

    def test_future_schema_version_is_refused(
        self, store: DiscoveryStore, result: DiscoveryResult
    ) -> None:
        document = json.loads(render_result_json(result))
        document["schema_version"] = DISCOVERY_SCHEMA_VERSION + 1
        self.write(store, json.dumps(document))

        with pytest.raises(DiscoveryError) as excinfo:
            store.load("acme")

        assert "schema version" in excinfo.value.message

    def test_invalid_utf8_is_reported(self, store: DiscoveryStore) -> None:
        path = store.path_for("acme")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b'{"target_name": "\xff\xfe"}')

        with pytest.raises(DiscoveryError, match="not valid UTF-8"):
            store.load("acme")

    def test_byte_order_mark_is_tolerated(
        self, store: DiscoveryStore, result: DiscoveryResult
    ) -> None:
        destination = store.save(result)
        body = destination.read_bytes()
        destination.write_bytes(b"\xef\xbb\xbf" + body)

        assert store.load(result.target_name).target_name == result.target_name

    def test_directory_in_place_of_the_file(self, store: DiscoveryStore) -> None:
        path = store.path_for("acme")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.mkdir()

        with pytest.raises(DiscoveryError, match="found a directory"):
            store.load("acme")


class TestExportFile:
    def test_writes_json_to_an_arbitrary_path(
        self, tmp_path: Path, result: DiscoveryResult
    ) -> None:
        destination = tmp_path / "out" / "inventory.json"

        written = write_result_file(destination, result, overwrite=False)

        assert written == destination
        assert (
            DiscoveryResult.model_validate(json.loads(destination.read_text(encoding="utf-8")))
            == result
        )

    def test_existing_file_is_not_overwritten_silently(
        self, tmp_path: Path, result: DiscoveryResult
    ) -> None:
        destination = tmp_path / "inventory.json"
        destination.write_text("important", encoding="utf-8")

        with pytest.raises(DiscoveryError) as excinfo:
            write_result_file(destination, result, overwrite=False)

        assert "--force" in str(excinfo.value.hint)
        assert destination.read_text(encoding="utf-8") == "important"

    def test_overwrite_is_allowed_explicitly(self, tmp_path: Path, result: DiscoveryResult) -> None:
        destination = tmp_path / "inventory.json"
        destination.write_text("old", encoding="utf-8")

        write_result_file(destination, result, overwrite=True)

        assert destination.read_text(encoding="utf-8") != "old"

    def test_directory_destination_is_refused(
        self, tmp_path: Path, result: DiscoveryResult
    ) -> None:
        destination = tmp_path / "out"
        destination.mkdir()

        with pytest.raises(DiscoveryError, match="found a directory"):
            write_result_file(destination, result, overwrite=True)

    def test_unwritable_location_is_reported(self, tmp_path: Path, result: DiscoveryResult) -> None:
        blocker = tmp_path / "blocker"
        blocker.write_text("not a directory", encoding="utf-8")

        with pytest.raises(DiscoveryError, match="could not be written"):
            write_result_file(blocker / "out.json", result, overwrite=True)


class TestResultSummaries:
    def test_counts_match_the_inventory(self, result: DiscoveryResult) -> None:
        assert result.endpoint_count == 7
        assert sum(result.classification_counts().values()) == 7
        assert sum(result.method_counts().values()) == 7
        assert sum(result.posture_counts().values()) == 7

    def test_anonymous_and_missing_metadata_are_reported_separately(
        self, result: DiscoveryResult
    ) -> None:
        anonymous = {item.endpoint.key for item in result.endpoints_permitting_anonymous()}

        assert anonymous == {"GET /health"}
        # Everything else inherits a global requirement, so metadata exists.
        assert result.endpoints_without_security_metadata() == []

    def test_warning_counts_are_grouped(self, result: DiscoveryResult) -> None:
        counts = result.warning_counts()

        assert sum(counts.values()) == len(result.warnings)
