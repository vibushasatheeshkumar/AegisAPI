"""Configuration defaults, precedence, validation, and error handling."""

from __future__ import annotations

from pathlib import Path

import pytest

from aegisapi.core.config import (
    CONFIG_ENV_VAR,
    DEFAULT_MAX_CONCURRENCY,
    DEFAULT_REQUEST_TIMEOUT_SECONDS,
    ENV_PREFIX,
    AegisConfig,
    config_overrides_from_env,
    load_config,
    render_sample_config,
    resolve_config_path,
)
from aegisapi.core.exceptions import ConfigNotFoundError, InvalidConfigError
from aegisapi.core.paths import WorkspacePaths
from aegisapi.models.common import LogLevel, ReportFormat

BOM = b"\xef\xbb\xbf"
"""UTF-8 byte-order mark, as written by Notepad and PowerShell's Set-Content."""


def write_config(path: Path, body: str) -> Path:
    """Write ``body`` to ``path`` and return the path."""
    path.write_text(body, encoding="utf-8")
    return path


class TestDefaults:
    def test_defaults_are_conservative(self) -> None:
        config = AegisConfig()

        assert config.log_level is LogLevel.INFO
        assert config.request_timeout_seconds == DEFAULT_REQUEST_TIMEOUT_SECONDS
        assert config.max_concurrency == DEFAULT_MAX_CONCURRENCY
        assert config.default_report_format is ReportFormat.JSON
        # Scope enforcement on, allow-list empty: nothing is authorised yet.
        assert config.scope.enforce is True
        assert config.scope.allowed_hosts == []

    def test_load_without_file_returns_defaults(self) -> None:
        assert load_config(None, env={}) == AegisConfig()

    def test_sample_config_round_trips_to_defaults(self, tmp_path: Path) -> None:
        path = write_config(tmp_path / "config.toml", render_sample_config())

        assert load_config(path, env={}) == AegisConfig()


class TestPrecedence:
    def test_file_overrides_defaults(self, tmp_path: Path) -> None:
        path = write_config(
            tmp_path / "config.toml",
            'log_level = "WARNING"\nmax_concurrency = 8\n',
        )

        config = load_config(path, env={})

        assert config.log_level is LogLevel.WARNING
        assert config.max_concurrency == 8
        assert config.request_timeout_seconds == DEFAULT_REQUEST_TIMEOUT_SECONDS

    def test_environment_overrides_file(self, tmp_path: Path) -> None:
        path = write_config(tmp_path / "config.toml", 'log_level = "WARNING"\n')

        config = load_config(path, env={ENV_PREFIX + "LOG_LEVEL": "error"})

        assert config.log_level is LogLevel.ERROR

    def test_explicit_overrides_beat_environment(self, tmp_path: Path) -> None:
        path = write_config(tmp_path / "config.toml", 'log_level = "WARNING"\n')

        config = load_config(
            path,
            env={ENV_PREFIX + "LOG_LEVEL": "ERROR"},
            overrides={"log_level": "DEBUG"},
        )

        assert config.log_level is LogLevel.DEBUG

    def test_nested_scope_values_merge_instead_of_replacing(self, tmp_path: Path) -> None:
        path = write_config(
            tmp_path / "config.toml",
            '[scope]\nenforce = true\nallowed_hosts = ["api.example.com"]\n',
        )

        config = load_config(path, env={ENV_PREFIX + "ENFORCE_SCOPE": "false"})

        assert config.scope.enforce is False
        # The host list from the file survives the environment override.
        assert config.scope.allowed_hosts == ["api.example.com"]

    def test_empty_environment_variable_is_ignored(self, tmp_path: Path) -> None:
        path = write_config(tmp_path / "config.toml", 'log_level = "WARNING"\n')

        config = load_config(path, env={ENV_PREFIX + "LOG_LEVEL": "   "})

        assert config.log_level is LogLevel.WARNING

    def test_environment_overrides_cover_every_setting(self) -> None:
        overrides = config_overrides_from_env(
            {
                ENV_PREFIX + "LOG_LEVEL": "debug",
                ENV_PREFIX + "REQUEST_TIMEOUT": "2.5",
                ENV_PREFIX + "MAX_CONCURRENCY": "16",
                ENV_PREFIX + "REPORT_FORMAT": "HTML",
                ENV_PREFIX + "ENFORCE_SCOPE": "no",
                ENV_PREFIX + "ALLOWED_HOSTS": "api.example.com, other.example.com",
            }
        )

        assert overrides == {
            "log_level": "debug",
            "request_timeout_seconds": 2.5,
            "max_concurrency": 16,
            "default_report_format": "HTML",
            "scope": {
                "enforce": False,
                "allowed_hosts": ["api.example.com", "other.example.com"],
            },
        }


class TestValidation:
    def test_log_level_and_report_format_are_case_insensitive(self) -> None:
        config = AegisConfig(log_level="debug", default_report_format="HTML")

        assert config.log_level is LogLevel.DEBUG
        assert config.default_report_format is ReportFormat.HTML

    def test_allowed_hosts_are_normalised_and_deduplicated(self) -> None:
        config = AegisConfig(scope={"allowed_hosts": [" API.Example.com ", "api.example.com", ""]})

        assert config.scope.allowed_hosts == ["api.example.com"]

    @pytest.mark.parametrize(
        "host",
        ["https://api.example.com", "api.example.com/v1", "api.example.com:8443", "two hosts"],
    )
    def test_allowed_hosts_reject_non_hostnames(self, host: str, tmp_path: Path) -> None:
        path = write_config(tmp_path / "config.toml", f'[scope]\nallowed_hosts = ["{host}"]\n')

        with pytest.raises(InvalidConfigError) as excinfo:
            load_config(path, env={})

        assert "allowed_hosts" in str(excinfo.value.hint)

    @pytest.mark.parametrize(
        "body",
        [
            "request_timeout_seconds = 0",
            "request_timeout_seconds = -1",
            "request_timeout_seconds = 601",
            "max_concurrency = 0",
            "max_concurrency = 1000",
            'log_level = "CHATTY"',
            'default_report_format = "docx"',
            "[scope]\nenforce = 7",
        ],
    )
    def test_out_of_range_values_are_rejected(self, body: str, tmp_path: Path) -> None:
        path = write_config(tmp_path / "config.toml", body + "\n")

        with pytest.raises(InvalidConfigError):
            load_config(path, env={})

    def test_unknown_keys_are_rejected_with_a_hint(self, tmp_path: Path) -> None:
        path = write_config(tmp_path / "config.toml", 'log_levl = "DEBUG"\n')

        with pytest.raises(InvalidConfigError) as excinfo:
            load_config(path, env={})

        assert str(path) in excinfo.value.message
        assert "log_levl" in str(excinfo.value.hint)

    def test_invalid_environment_number_is_reported(self) -> None:
        with pytest.raises(InvalidConfigError) as excinfo:
            load_config(None, env={ENV_PREFIX + "MAX_CONCURRENCY": "many"})

        assert ENV_PREFIX + "MAX_CONCURRENCY" in excinfo.value.message

    def test_invalid_environment_boolean_is_reported(self) -> None:
        with pytest.raises(InvalidConfigError) as excinfo:
            load_config(None, env={ENV_PREFIX + "ENFORCE_SCOPE": "maybe"})

        assert "boolean" in excinfo.value.message


class TestMalformedFiles:
    def test_malformed_toml_names_the_file(self, tmp_path: Path) -> None:
        path = write_config(tmp_path / "config.toml", "log_level = \n")

        with pytest.raises(InvalidConfigError) as excinfo:
            load_config(path, env={})

        assert str(path) in excinfo.value.message
        assert excinfo.value.exit_code == 3

    def test_directory_instead_of_file_is_rejected(self, tmp_path: Path) -> None:
        directory = tmp_path / "config.toml"
        directory.mkdir()

        with pytest.raises(InvalidConfigError):
            load_config(directory, env={})

    def test_utf8_byte_order_mark_is_tolerated(self, tmp_path: Path) -> None:
        # Notepad and PowerShell's Set-Content add a BOM on Windows.
        path = tmp_path / "config.toml"
        path.write_bytes(BOM + b'log_level = "WARNING"\n')

        assert load_config(path, env={}).log_level is LogLevel.WARNING

    def test_missing_file_raises_not_found(self, tmp_path: Path) -> None:
        with pytest.raises(ConfigNotFoundError):
            load_config(tmp_path / "absent.toml", env={})

    def test_non_utf8_file_is_rejected(self, tmp_path: Path) -> None:
        path = tmp_path / "config.toml"
        path.write_bytes(b'log_level = "\xff\xfe"\n')

        with pytest.raises(InvalidConfigError) as excinfo:
            load_config(path, env={})

        assert "UTF-8" in excinfo.value.message


class TestResolveConfigPath:
    def test_returns_none_when_workspace_has_no_config(self, tmp_path: Path) -> None:
        workspace = WorkspacePaths.resolve(tmp_path / "workspace")

        assert resolve_config_path(None, workspace=workspace, env={}) is None

    def test_returns_workspace_config_when_present(self, tmp_path: Path) -> None:
        workspace = WorkspacePaths.resolve(tmp_path / "workspace")
        workspace.root.mkdir(parents=True)
        write_config(workspace.config_file, render_sample_config())

        assert resolve_config_path(None, workspace=workspace, env={}) == workspace.config_file

    def test_explicit_path_wins_over_workspace(self, tmp_path: Path) -> None:
        workspace = WorkspacePaths.resolve(tmp_path / "workspace")
        workspace.root.mkdir(parents=True)
        write_config(workspace.config_file, render_sample_config())
        explicit = write_config(tmp_path / "other.toml", render_sample_config())

        assert resolve_config_path(explicit, workspace=workspace, env={}) == explicit

    def test_environment_variable_selects_the_file(self, tmp_path: Path) -> None:
        explicit = write_config(tmp_path / "from-env.toml", render_sample_config())
        workspace = WorkspacePaths.resolve(tmp_path / "workspace")

        resolved = resolve_config_path(
            None, workspace=workspace, env={CONFIG_ENV_VAR: str(explicit)}
        )

        assert resolved == explicit

    def test_missing_explicit_path_raises_not_found(self, tmp_path: Path) -> None:
        workspace = WorkspacePaths.resolve(tmp_path / "workspace")

        with pytest.raises(ConfigNotFoundError) as excinfo:
            resolve_config_path(tmp_path / "absent.toml", workspace=workspace, env={})

        assert "absent.toml" in excinfo.value.message


class TestSampleConfig:
    def test_sample_contains_no_credential_fields(self) -> None:
        sample = render_sample_config().lower()

        for forbidden in ("password", "api_key", "apikey", "token", "secret"):
            assert f"{forbidden} =" not in sample

    def test_sample_documents_precedence_and_authorisation(self) -> None:
        sample = render_sample_config()

        assert "Precedence" in sample
        assert "authorised" in sample


class TestShippedExamples:
    """The files under examples/ are documentation; they must stay loadable."""

    EXAMPLES_DIR = Path(__file__).resolve().parents[1] / "examples"

    def test_examples_directory_is_present(self) -> None:
        assert sorted(path.name for path in self.EXAMPLES_DIR.glob("*.toml"))

    def test_example_specification_parses(self) -> None:
        """The shipped example specification must stay loadable."""
        from aegisapi.discovery.service import discover_from_specification
        from conftest import make_target

        result = discover_from_specification(
            self.EXAMPLES_DIR / "petstore-openapi.yaml",
            target=make_target(base_url="https://api.example.test/v1"),
        )

        assert result.endpoint_count == 7

    def test_every_example_loads_and_validates(self) -> None:
        for path in sorted(self.EXAMPLES_DIR.glob("*.toml")):
            config = load_config(path, env={})
            assert config.scope.enforce is True, path.name

    def test_no_example_contains_a_credential(self) -> None:
        for path in sorted(self.EXAMPLES_DIR.glob("*.toml")):
            body = path.read_text(encoding="utf-8").lower()
            for forbidden in ("password =", "token =", "secret =", "api_key ="):
                assert forbidden not in body, f"{path.name} contains {forbidden!r}"
