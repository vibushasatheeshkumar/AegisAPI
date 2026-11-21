"""Target persistence: reload, validation, corruption, and atomic writes."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from aegisapi.core.exceptions import (
    DuplicateTargetError,
    InvalidTargetError,
    TargetNotFoundError,
    TargetStoreError,
)
from aegisapi.core.paths import TARGETS_FILENAME, WorkspacePaths
from aegisapi.core.targets import TARGETS_SCHEMA_VERSION, TargetStore, build_collection
from aegisapi.models.secrets import SecretRef
from aegisapi.models.target import AuthMethod, AuthProfile, ScopeRules, Target
from conftest import make_target

TOKEN_VALUE = "eyJhbGciOiJIUzI1NiJ9.super-secret-token-value"


@pytest.fixture
def store(tmp_path: Path) -> TargetStore:
    """A store backed by a file inside a temporary workspace."""
    return TargetStore(tmp_path / "workspace" / TARGETS_FILENAME)


class TestCrud:
    def test_add_then_get(self, store: TargetStore) -> None:
        added = store.add(make_target())

        assert store.get("acme") == added

    def test_add_creates_the_file_and_parent_directory(self, store: TargetStore) -> None:
        assert store.exists is False

        store.add(make_target())

        assert store.exists is True
        assert store.path.parent.is_dir()

    def test_lookup_is_case_insensitive(self, store: TargetStore) -> None:
        store.add(make_target(name="acme"))

        assert store.get("ACME").name == "acme"

    def test_list_is_sorted_by_name(self, store: TargetStore) -> None:
        store.add(make_target(name="zeta", base_url="https://z.test"))
        store.add(make_target(name="alpha", base_url="https://a.test"))

        assert [target.name for target in store.list_targets()] == ["alpha", "zeta"]

    def test_empty_store_lists_nothing(self, store: TargetStore) -> None:
        assert store.list_targets() == []
        assert store.load().targets == {}

    def test_remove_returns_what_it_deleted(self, store: TargetStore) -> None:
        store.add(make_target())

        removed = store.remove("acme")

        assert removed.name == "acme"
        assert store.list_targets() == []

    def test_replace_overwrites_the_target(self, store: TargetStore) -> None:
        store.add(make_target())
        changed = make_target(base_url="https://api.acme.test/v2")

        updated = store.replace(changed)

        assert updated.base_url == "https://api.acme.test/v2"
        assert store.get("acme").base_url == "https://api.acme.test/v2"

    def test_replace_preserves_created_at_and_bumps_updated_at(self, store: TargetStore) -> None:
        original = store.add(make_target())

        updated = store.replace(make_target(base_url="https://api.acme.test/v2"))

        assert updated.created_at == original.created_at
        assert updated.updated_at >= original.updated_at

    def test_duplicate_name_is_refused(self, store: TargetStore) -> None:
        store.add(make_target())

        with pytest.raises(DuplicateTargetError) as excinfo:
            store.add(make_target())

        assert "already registered" in excinfo.value.message
        assert "target update acme" in str(excinfo.value.hint)
        assert excinfo.value.exit_code == 6

    def test_missing_target_lists_what_is_available(self, store: TargetStore) -> None:
        store.add(make_target(name="acme"))

        with pytest.raises(TargetNotFoundError) as excinfo:
            store.get("ghost")

        assert "ghost" in excinfo.value.message
        assert "acme" in str(excinfo.value.hint)

    def test_missing_target_in_an_empty_store_suggests_adding_one(self, store: TargetStore) -> None:
        with pytest.raises(TargetNotFoundError) as excinfo:
            store.get("ghost")

        assert "target add" in str(excinfo.value.hint)

    def test_removing_a_missing_target_is_an_error(self, store: TargetStore) -> None:
        with pytest.raises(TargetNotFoundError):
            store.remove("ghost")

    def test_replacing_a_missing_target_is_an_error(self, store: TargetStore) -> None:
        with pytest.raises(TargetNotFoundError):
            store.replace(make_target())

    def test_invalid_name_is_reported_clearly(self, store: TargetStore) -> None:
        with pytest.raises(InvalidTargetError, match="target name"):
            store.get("not a name")

    def test_for_workspace_uses_the_workspace_file(self, tmp_path: Path) -> None:
        paths = WorkspacePaths.resolve(tmp_path / "workspace")

        assert TargetStore.for_workspace(paths).path == paths.targets_file


class TestPersistence:
    def test_targets_survive_a_new_store_instance(self, tmp_path: Path) -> None:
        path = tmp_path / "workspace" / TARGETS_FILENAME
        TargetStore(path).add(
            make_target(
                scope=ScopeRules(
                    include_paths=["/v1/**"],
                    exclude_paths=["/v1/admin"],
                    extra_hosts=["cdn.acme.test"],
                    allowed_ports=[8443],
                    allow_subdomains=True,
                ),
                auth=AuthProfile(method=AuthMethod.BEARER, token=SecretRef(variable="ACME_TOKEN")),
            )
        )

        reloaded = TargetStore(path).get("acme")

        assert reloaded.scope.include_paths == ["/v1/**"]
        assert reloaded.scope.exclude_paths == ["/v1/admin"]
        assert reloaded.scope.extra_hosts == ["cdn.acme.test"]
        assert reloaded.scope.allowed_ports == [8443]
        assert reloaded.scope.allow_subdomains is True
        assert reloaded.auth.method is AuthMethod.BEARER
        assert reloaded.auth.token is not None
        assert reloaded.auth.token.variable == "ACME_TOKEN"

    def test_stored_file_contains_no_credential_value(
        self, store: TargetStore, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("ACME_TOKEN", TOKEN_VALUE)
        store.add(
            make_target(
                auth=AuthProfile(method=AuthMethod.BEARER, token=SecretRef(variable="ACME_TOKEN"))
            )
        )

        contents = store.path.read_text(encoding="utf-8")

        assert "ACME_TOKEN" in contents
        assert TOKEN_VALUE not in contents

    def test_document_is_written_with_a_schema_version(self, store: TargetStore) -> None:
        store.add(make_target())

        document = json.loads(store.path.read_text(encoding="utf-8"))

        assert document["schema_version"] == TARGETS_SCHEMA_VERSION

    def test_no_temporary_file_is_left_behind(self, store: TargetStore) -> None:
        store.add(make_target())

        leftovers = list(store.path.parent.glob("*.tmp"))

        assert leftovers == []

    def test_byte_order_mark_is_tolerated(self, store: TargetStore) -> None:
        store.add(make_target())
        body = store.path.read_bytes()
        store.path.write_bytes(b"\xef\xbb\xbf" + body)

        assert store.get("acme").name == "acme"

    def test_unrelated_files_are_untouched(self, store: TargetStore) -> None:
        store.path.parent.mkdir(parents=True, exist_ok=True)
        notes = store.path.parent / "notes.md"
        notes.write_text("engagement notes", encoding="utf-8")

        store.add(make_target())

        assert notes.read_text(encoding="utf-8") == "engagement notes"

    @pytest.mark.skipif(sys.platform == "win32", reason="POSIX mode bits")
    def test_posix_permissions_are_restrictive(self, store: TargetStore) -> None:
        store.add(make_target())

        assert store.path.stat().st_mode & 0o777 == 0o600


class TestCorruptedData:
    def write(self, store: TargetStore, text: str) -> None:
        """Write raw text to the store path."""
        store.path.parent.mkdir(parents=True, exist_ok=True)
        store.path.write_text(text, encoding="utf-8")

    def test_malformed_json_names_the_file(self, store: TargetStore) -> None:
        self.write(store, "{not json")

        with pytest.raises(TargetStoreError) as excinfo:
            store.load()

        assert str(store.path) in excinfo.value.message
        assert excinfo.value.hint
        assert excinfo.value.exit_code == 6

    @pytest.mark.parametrize("text", ["[]", '"a string"', "42", "null"])
    def test_non_object_document_is_rejected(self, store: TargetStore, text: str) -> None:
        self.write(store, text)

        with pytest.raises(TargetStoreError, match="must contain a JSON object"):
            store.load()

    def test_invalid_target_inside_the_file_is_reported(self, store: TargetStore) -> None:
        self.write(store, json.dumps({"targets": {"acme": {"name": "acme"}}}))

        with pytest.raises(TargetStoreError) as excinfo:
            store.load()

        assert "invalid target" in excinfo.value.message
        assert "base_url" in str(excinfo.value.hint)

    def test_plaintext_credential_field_is_refused(self, store: TargetStore) -> None:
        # Hand-editing a secret into the file must fail loudly, not be ignored.
        self.write(
            store,
            json.dumps(
                {
                    "targets": {
                        "acme": {
                            "name": "acme",
                            "base_url": "https://api.acme.test",
                            "auth": {"method": "bearer", "token_value": TOKEN_VALUE},
                        }
                    }
                }
            ),
        )

        with pytest.raises(TargetStoreError) as excinfo:
            store.load()

        assert "token_value" in str(excinfo.value.hint)

    def test_key_name_mismatch_is_rejected(self, store: TargetStore) -> None:
        self.write(
            store,
            json.dumps(
                {"targets": {"wrong": {"name": "acme", "base_url": "https://api.acme.test"}}}
            ),
        )

        with pytest.raises(TargetStoreError):
            store.load()

    def test_future_schema_version_is_refused(self, store: TargetStore) -> None:
        self.write(store, json.dumps({"schema_version": TARGETS_SCHEMA_VERSION + 1, "targets": {}}))

        with pytest.raises(TargetStoreError) as excinfo:
            store.load()

        assert "schema version" in excinfo.value.message
        assert "Upgrade AegisAPI" in str(excinfo.value.hint)

    def test_invalid_utf8_is_rejected(self, store: TargetStore) -> None:
        store.path.parent.mkdir(parents=True, exist_ok=True)
        store.path.write_bytes(b'{"targets": "\xff\xfe"}')

        with pytest.raises(TargetStoreError, match="not valid UTF-8"):
            store.load()

    def test_directory_in_place_of_the_file_is_reported(self, tmp_path: Path) -> None:
        path = tmp_path / TARGETS_FILENAME
        path.mkdir()

        with pytest.raises(TargetStoreError, match="found a directory"):
            TargetStore(path).load()

    def test_oversized_file_is_refused(self, store: TargetStore) -> None:
        self.write(store, '{"targets": {}, "padding": "' + "x" * (9 * 1024 * 1024) + '"}')

        with pytest.raises(TargetStoreError, match="larger than"):
            store.load()

    def test_a_corrupt_file_is_never_silently_replaced(self, store: TargetStore) -> None:
        self.write(store, "{not json")

        with pytest.raises(TargetStoreError):
            store.add(make_target())

        # The operator's file is still there, unmodified, for them to inspect.
        assert store.path.read_text(encoding="utf-8") == "{not json"

    def test_unwritable_location_is_reported(self, tmp_path: Path) -> None:
        blocker = tmp_path / "blocker"
        blocker.write_text("not a directory", encoding="utf-8")

        with pytest.raises(TargetStoreError, match="could not be written"):
            TargetStore(blocker / TARGETS_FILENAME).add(make_target())


class TestBuildCollection:
    def test_assembles_targets_by_name(self) -> None:
        collection = build_collection(
            [
                make_target(name="acme"),
                make_target(name="beta", base_url="https://b.test"),
            ]
        )

        assert sorted(collection.targets) == ["acme", "beta"]
        assert collection.schema_version == TARGETS_SCHEMA_VERSION

    def test_duplicate_names_are_refused(self) -> None:
        with pytest.raises(DuplicateTargetError, match="Duplicate target name"):
            build_collection([make_target(), make_target()])

    def test_round_trips_through_the_store(self, store: TargetStore) -> None:
        collection = build_collection(
            [make_target(), make_target(name="beta", base_url="https://b.test")]
        )

        store.save(collection)

        assert [target.name for target in store.list_targets()] == ["acme", "beta"]


class TestTargetModelIntegrationWithStore:
    def test_disabled_targets_persist_their_state(self, store: TargetStore) -> None:
        store.add(make_target(enabled=False))

        assert store.get("acme").enabled is False

    def test_stored_target_is_fully_validated_on_load(self, store: TargetStore) -> None:
        store.add(make_target())
        target = store.get("acme")

        # Validation on load means properties derived from the URL are usable.
        assert isinstance(target, Target)
        assert target.host == "api.acme.test"
        assert target.base_path == "/v1"
