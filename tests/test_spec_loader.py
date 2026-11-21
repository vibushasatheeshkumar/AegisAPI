"""Loading specification files, and the inputs AegisAPI refuses to load."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

import pytest

from aegisapi.core.exceptions import (
    InvalidSpecificationError,
    SpecificationNotFoundError,
    UnsupportedSpecificationError,
)
from aegisapi.discovery.loader import (
    MAX_SPECIFICATION_BYTES,
    MAX_YAML_ALIASES,
    detect_format,
    load_specification,
)
from aegisapi.discovery.versions import detect_version
from aegisapi.models.discovery import SpecificationFormat, SpecificationVersion
from specs import (
    FULL_OPENAPI_30,
    MINIMAL_OPENAPI_30,
    OPENAPI_31,
    SWAGGER_20,
    spec_copy,
    write_json,
    write_text,
    write_yaml,
)


class TestFormatDetection:
    def test_json_suffix_wins(self, tmp_path: Path) -> None:
        path = write_json(tmp_path / "spec.json", MINIMAL_OPENAPI_30)

        assert detect_format(path, path.read_text(encoding="utf-8")) is SpecificationFormat.JSON

    @pytest.mark.parametrize("suffix", [".yaml", ".yml"])
    def test_yaml_suffixes(self, tmp_path: Path, suffix: str) -> None:
        path = write_yaml(tmp_path / f"spec{suffix}", MINIMAL_OPENAPI_30)

        assert detect_format(path, path.read_text(encoding="utf-8")) is SpecificationFormat.YAML

    def test_unknown_suffix_sniffs_content(self, tmp_path: Path) -> None:
        json_path = write_json(tmp_path / "spec.txt", MINIMAL_OPENAPI_30)
        yaml_path = write_yaml(tmp_path / "other.txt", MINIMAL_OPENAPI_30)

        assert detect_format(json_path, json_path.read_text(encoding="utf-8")) is (
            SpecificationFormat.JSON
        )
        assert detect_format(yaml_path, yaml_path.read_text(encoding="utf-8")) is (
            SpecificationFormat.YAML
        )


class TestLoading:
    def test_loads_json(self, tmp_path: Path) -> None:
        path = write_json(tmp_path / "spec.json", MINIMAL_OPENAPI_30)

        loaded = load_specification(path)

        assert loaded.document["openapi"] == "3.0.3"
        assert loaded.format is SpecificationFormat.JSON
        assert loaded.source_path == path.resolve()

    def test_loads_yaml(self, tmp_path: Path) -> None:
        path = write_yaml(tmp_path / "spec.yaml", FULL_OPENAPI_30)

        loaded = load_specification(path)

        assert loaded.document["info"]["title"] == "Acme Orders API"
        assert loaded.format is SpecificationFormat.YAML

    def test_json_and_yaml_produce_the_same_document(self, tmp_path: Path) -> None:
        json_loaded = load_specification(write_json(tmp_path / "a.json", FULL_OPENAPI_30))
        yaml_loaded = load_specification(write_yaml(tmp_path / "a.yaml", FULL_OPENAPI_30))

        assert json_loaded.document == yaml_loaded.document

    def test_records_provenance(self, tmp_path: Path) -> None:
        path = write_json(tmp_path / "spec.json", MINIMAL_OPENAPI_30)
        raw = path.read_bytes()

        loaded = load_specification(path)

        assert loaded.source_sha256 == hashlib.sha256(raw).hexdigest()
        assert loaded.byte_size == len(raw)

    def test_byte_order_mark_is_tolerated(self, tmp_path: Path) -> None:
        path = tmp_path / "spec.json"
        path.write_bytes(b"\xef\xbb\xbf" + json.dumps(MINIMAL_OPENAPI_30).encode("utf-8"))

        assert load_specification(path).document["openapi"] == "3.0.3"

    def test_accepts_a_string_path(self, tmp_path: Path) -> None:
        path = write_json(tmp_path / "spec.json", MINIMAL_OPENAPI_30)

        assert load_specification(str(path)).document["openapi"] == "3.0.3"


class TestRejectedInput:
    def test_missing_file(self, tmp_path: Path) -> None:
        with pytest.raises(SpecificationNotFoundError, match="not found"):
            load_specification(tmp_path / "absent.yaml")

    def test_directory_instead_of_file(self, tmp_path: Path) -> None:
        directory = tmp_path / "spec.yaml"
        directory.mkdir()

        with pytest.raises(SpecificationNotFoundError, match="found a directory"):
            load_specification(directory)

    def test_malformed_json_reports_position(self, tmp_path: Path) -> None:
        path = write_text(tmp_path / "spec.json", '{"openapi": "3.0.0",}')

        with pytest.raises(InvalidSpecificationError) as excinfo:
            load_specification(path)

        assert "not valid JSON" in excinfo.value.message
        assert "line" in str(excinfo.value.hint)
        assert excinfo.value.exit_code == 8

    def test_malformed_yaml_reports_position(self, tmp_path: Path) -> None:
        path = write_text(tmp_path / "spec.yaml", "openapi: 3.0.0\npaths: [unclosed\n")

        with pytest.raises(InvalidSpecificationError) as excinfo:
            load_specification(path)

        assert "not valid YAML" in excinfo.value.message
        assert "line" in str(excinfo.value.hint)

    def test_empty_file(self, tmp_path: Path) -> None:
        path = write_text(tmp_path / "spec.yaml", "")

        with pytest.raises(InvalidSpecificationError, match="empty"):
            load_specification(path)

    @pytest.mark.parametrize("body", ["[1, 2, 3]", '"just a string"', "42"])
    def test_non_object_document(self, tmp_path: Path, body: str) -> None:
        path = write_text(tmp_path / "spec.json", body)

        with pytest.raises(InvalidSpecificationError, match="object at the top level"):
            load_specification(path)

    def test_invalid_utf8(self, tmp_path: Path) -> None:
        path = tmp_path / "spec.json"
        path.write_bytes(b'{"openapi": "\xff\xfe"}')

        with pytest.raises(InvalidSpecificationError, match="not valid UTF-8"):
            load_specification(path)

    def test_oversized_file(self, tmp_path: Path) -> None:
        path = tmp_path / "spec.json"
        path.write_bytes(b"{" + b" " * (MAX_SPECIFICATION_BYTES + 1))

        with pytest.raises(InvalidSpecificationError, match="larger than"):
            load_specification(path)

    def test_yaml_alias_bomb_is_refused(self, tmp_path: Path) -> None:
        # The "billion laughs" shape: a small file that expands enormously.
        lines = ["base: &anchor [a, b, c]", "expanded:"]
        lines.extend("  - [*anchor, *anchor]" for _ in range(MAX_YAML_ALIASES))
        path = write_text(tmp_path / "bomb.yaml", "\n".join(lines))

        with pytest.raises(InvalidSpecificationError, match="YAML aliases"):
            load_specification(path)

    def test_modest_alias_use_is_allowed(self, tmp_path: Path) -> None:
        document = (
            "openapi: 3.0.0\n"
            "info: &info\n  title: Aliased\n  version: '1'\n"
            "x-copy: *info\n"
            "paths: {}\n"
        )
        path = write_text(tmp_path / "spec.yaml", document)

        assert load_specification(path).document["x-copy"]["title"] == "Aliased"

    def test_yaml_object_tags_do_not_construct_python_objects(self, tmp_path: Path) -> None:
        # safe_load refuses a python object tag outright. An unsafe loader here
        # would turn reading a specification into executing it.
        path = write_text(
            tmp_path / "spec.yaml",
            "openapi: 3.0.0\nx-evil: !!python/object/apply:os.system ['echo pwned']\n",
        )

        with pytest.raises(InvalidSpecificationError, match="not valid YAML"):
            load_specification(path)


class TestVersionDetection:
    @pytest.mark.parametrize(
        ("declared", "expected"),
        [
            ("3.0.0", SpecificationVersion.OPENAPI_30),
            ("3.0.3", SpecificationVersion.OPENAPI_30),
            ("3.0", SpecificationVersion.OPENAPI_30),
            ("3.1.0", SpecificationVersion.OPENAPI_31),
            ("3.1", SpecificationVersion.OPENAPI_31),
        ],
    )
    def test_openapi_versions(self, declared: str, expected: SpecificationVersion) -> None:
        detected = detect_version({"openapi": declared, "paths": {}})

        assert detected.version is expected
        assert detected.raw == declared
        assert detected.is_openapi_3 is True

    def test_swagger_version(self) -> None:
        detected = detect_version({"swagger": "2.0", "paths": {}})

        assert detected.version is SpecificationVersion.SWAGGER_20
        assert detected.is_openapi_3 is False

    def test_unquoted_swagger_float_is_accepted(self) -> None:
        # YAML parses an unquoted 2.0 as a float; a common authoring mistake.
        assert detect_version({"swagger": 2.0}).version is SpecificationVersion.SWAGGER_20

    @pytest.mark.parametrize("declared", ["4.0.0", "2.0.0", "3.2.0", "1.0"])
    def test_unsupported_openapi_versions(self, declared: str) -> None:
        with pytest.raises(UnsupportedSpecificationError) as excinfo:
            detect_version({"openapi": declared})

        assert declared in excinfo.value.message
        assert "OpenAPI 3.1" in str(excinfo.value.hint)

    def test_unsupported_swagger_version(self) -> None:
        with pytest.raises(UnsupportedSpecificationError, match=re.escape("1.2")):
            detect_version({"swagger": "1.2"})

    def test_missing_version_field(self) -> None:
        with pytest.raises(InvalidSpecificationError, match="does not declare"):
            detect_version({"paths": {}})

    def test_both_version_fields(self) -> None:
        with pytest.raises(InvalidSpecificationError, match="both"):
            detect_version({"openapi": "3.0.0", "swagger": "2.0"})

    @pytest.mark.parametrize("value", [None, [], {}, True])
    def test_unusable_version_value(self, value: object) -> None:
        with pytest.raises(InvalidSpecificationError):
            detect_version({"openapi": value})

    def test_empty_version_value(self) -> None:
        with pytest.raises(InvalidSpecificationError, match="must not be empty"):
            detect_version({"openapi": "   "})

    def test_declared_version_is_believed_over_structure(self, tmp_path: Path) -> None:
        # A document claiming OpenAPI 3 but shaped like Swagger 2 is malformed.
        # It is parsed as what it claims, so the mismatch surfaces rather than
        # being papered over.
        document = spec_copy(SWAGGER_20)
        document.pop("swagger")
        document["openapi"] = "3.0.0"

        assert detect_version(document).version is SpecificationVersion.OPENAPI_30

    def test_fixtures_detect_as_expected(self) -> None:
        assert detect_version(OPENAPI_31).version is SpecificationVersion.OPENAPI_31
        assert detect_version(FULL_OPENAPI_30).version is SpecificationVersion.OPENAPI_30
        assert detect_version(SWAGGER_20).version is SpecificationVersion.SWAGGER_20
