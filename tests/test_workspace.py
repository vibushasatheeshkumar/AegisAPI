"""Workspace path resolution and safe initialisation."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from aegisapi.core.config import AegisConfig, load_config, render_sample_config
from aegisapi.core.exceptions import WorkspaceError
from aegisapi.core.paths import (
    CONFIG_FILENAME,
    HOME_ENV_VAR,
    WorkspacePaths,
    default_workspace_root,
    validate_path_input,
)
from aegisapi.core.workspace import initialize_workspace

SENTINEL = 'log_level = "ERROR"  # operator edit, must survive\n'


class TestPathResolution:
    def test_home_environment_variable_wins(self, tmp_path: Path) -> None:
        root = default_workspace_root({HOME_ENV_VAR: str(tmp_path / "custom")})

        assert root == (tmp_path / "custom").resolve()

    def test_blank_home_variable_falls_back_to_platform_default(self, tmp_path: Path) -> None:
        env = {
            HOME_ENV_VAR: "   ",
            "APPDATA": str(tmp_path / "AppData"),
            "XDG_CONFIG_HOME": str(tmp_path / "xdg"),
        }

        root = default_workspace_root(env)

        assert root.is_relative_to(tmp_path.resolve())
        assert root.name in {"AegisAPI", "aegisapi"}

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows path layout")
    def test_windows_default_is_under_appdata(self, tmp_path: Path) -> None:
        root = default_workspace_root({"APPDATA": str(tmp_path / "Roaming")})

        assert root == (tmp_path / "Roaming" / "AegisAPI").resolve()

    @pytest.mark.skipif(sys.platform == "win32", reason="POSIX path layout")
    def test_posix_default_is_under_xdg_config_home(self, tmp_path: Path) -> None:
        root = default_workspace_root({"XDG_CONFIG_HOME": str(tmp_path / "config")})

        assert root == (tmp_path / "config" / "aegisapi").resolve()

    def test_workspace_paths_are_derived_from_the_root(self, tmp_path: Path) -> None:
        paths = WorkspacePaths.resolve(tmp_path / "workspace")

        assert paths.config_file == paths.root / CONFIG_FILENAME
        assert paths.root in paths.directories
        assert paths.logs_dir in paths.directories
        assert paths.exists is False

    @pytest.mark.parametrize("value", ["", "   "])
    def test_empty_paths_are_rejected(self, value: str) -> None:
        with pytest.raises(WorkspaceError):
            validate_path_input(value, label="workspace directory")

    def test_relative_paths_become_absolute(self) -> None:
        resolved = validate_path_input("relative-dir")

        assert resolved.is_absolute()


class TestInitialisation:
    def test_creates_the_expected_directories_and_config(self, tmp_path: Path) -> None:
        root = tmp_path / "workspace"

        result = initialize_workspace(root)

        assert result.root == root.resolve()
        assert result.changed is True
        for directory in result.paths.directories:
            assert directory.is_dir(), directory
        assert result.paths.config_file.is_file()
        assert result.created_files == (result.paths.config_file,)
        assert result.preserved_files == ()

    def test_written_config_is_valid_and_matches_defaults(self, tmp_path: Path) -> None:
        result = initialize_workspace(tmp_path / "workspace")

        assert load_config(result.paths.config_file, env={}) == AegisConfig()
        assert result.paths.config_file.read_text(encoding="utf-8") == render_sample_config()

    def test_rerun_preserves_an_edited_config(self, tmp_path: Path) -> None:
        root = tmp_path / "workspace"
        initialize_workspace(root)
        config_file = (root / CONFIG_FILENAME).resolve()
        config_file.write_text(SENTINEL, encoding="utf-8")

        result = initialize_workspace(root)

        assert config_file.read_text(encoding="utf-8") == SENTINEL
        assert result.preserved_files == (config_file,)
        assert result.overwritten_files == ()
        assert result.created_files == ()
        assert result.changed is False

    def test_force_replaces_the_config(self, tmp_path: Path) -> None:
        root = tmp_path / "workspace"
        initialize_workspace(root)
        config_file = (root / CONFIG_FILENAME).resolve()
        config_file.write_text(SENTINEL, encoding="utf-8")

        result = initialize_workspace(root, force=True)

        assert config_file.read_text(encoding="utf-8") == render_sample_config()
        assert result.overwritten_files == (config_file,)
        assert result.preserved_files == ()

    def test_unrelated_files_in_the_workspace_are_left_alone(self, tmp_path: Path) -> None:
        root = tmp_path / "workspace"
        root.mkdir()
        unrelated = root / "operator-notes.md"
        unrelated.write_text("engagement notes", encoding="utf-8")

        initialize_workspace(root)

        assert unrelated.read_text(encoding="utf-8") == "engagement notes"

    def test_default_root_comes_from_the_environment(self, workspace_root: Path) -> None:
        result = initialize_workspace()

        assert result.root == workspace_root.resolve()
        assert result.paths.config_file.is_file()

    def test_file_in_place_of_the_workspace_root_is_an_error(self, tmp_path: Path) -> None:
        blocker = tmp_path / "workspace"
        blocker.write_text("not a directory", encoding="utf-8")

        with pytest.raises(WorkspaceError) as excinfo:
            initialize_workspace(blocker)

        assert "already exists" in excinfo.value.message

    def test_directory_in_place_of_the_config_file_is_an_error(self, tmp_path: Path) -> None:
        root = tmp_path / "workspace"
        (root / CONFIG_FILENAME).mkdir(parents=True)

        with pytest.raises(WorkspaceError) as excinfo:
            initialize_workspace(root)

        assert "directory" in excinfo.value.message

    @pytest.mark.skipif(sys.platform == "win32", reason="POSIX mode bits")
    def test_posix_permissions_are_restrictive(self, tmp_path: Path) -> None:
        result = initialize_workspace(tmp_path / "workspace")

        assert result.root.stat().st_mode & 0o777 == 0o700
        assert result.paths.config_file.stat().st_mode & 0o777 == 0o600
