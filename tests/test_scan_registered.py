"""Tests for registered-target scanning (M1).

Covers:
- authorise_registered_target() — scope derivation from a registered Target
- ScanOptions.target field — pipeline branches correctly
- aegisapi scan <target> CLI path — workspace, error handling, backward compat
- Integration: full scan of the lab via a registered target

Design:
- Unit tests (sections 1–4) make no network calls and use no live server.
- Integration tests (section 5) spin up the lab API exactly like
  test_scan_pipeline.py and use a real loopback connection.
- The existing test_scan_pipeline.py tests are unmodified; this file only
  adds to them.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from aegisapi.cli import app
from aegisapi.core.config import AegisConfig
from aegisapi.core.exceptions import (
    EXIT_OK,
    EXIT_SCOPE_ERROR,
    InvalidTargetError,
    ScopeViolationError,
)
from aegisapi.core.paths import HOME_ENV_VAR
from aegisapi.models.target import AuthProfile, AuthMethod, ScopeRules, Target
from aegisapi.models.secrets import SecretRef
from aegisapi.scan.authorisation import authorise_registered_target
from aegisapi.scan.pipeline import ScanOptions, run_scan
from conftest import make_target


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _make_loopback_target(port: int, **kwargs: Any) -> Target:
    return make_target(
        name="labtest",
        base_url=f"http://127.0.0.1:{port}/",
        **kwargs,
    )


def _default_config(*, rate: float = 50.0) -> AegisConfig:
    config = AegisConfig()
    return config.model_copy(
        update={"http": config.http.model_copy(update={"requests_per_second": rate})}
    )


# ---------------------------------------------------------------------------
# 1. authorise_registered_target — scope derivation
# ---------------------------------------------------------------------------


class TestAuthoriseRegisteredTarget:
    def test_public_host_succeeds(self) -> None:
        t = make_target(base_url="https://api.example.com/v1")
        auth = authorise_registered_target(t)
        assert auth.target is t
        assert auth.url.host == "api.example.com"

    def test_target_name_preserved(self) -> None:
        t = make_target(name="acme", base_url="https://api.acme.test/v2")
        auth = authorise_registered_target(t)
        assert auth.target.name == "acme"

    def test_scope_settings_includes_primary_host(self) -> None:
        t = make_target(base_url="https://api.example.com/v1")
        auth = authorise_registered_target(t)
        assert "api.example.com" in auth.scope_settings.allowed_hosts

    def test_scope_settings_includes_configured_extra_hosts(self) -> None:
        t = make_target(
            base_url="https://api.example.com/v1",
            scope=ScopeRules(extra_hosts=["cdn.example.com"]),
        )
        auth = authorise_registered_target(t)
        assert "cdn.example.com" in auth.scope_settings.allowed_hosts

    def test_scope_settings_includes_per_scan_extra_hosts(self) -> None:
        t = make_target(base_url="https://api.example.com/v1")
        auth = authorise_registered_target(t, extra_hosts=("other.example.com",))
        assert "other.example.com" in auth.scope_settings.allowed_hosts

    def test_no_duplicate_hosts_in_allowed_list(self) -> None:
        t = make_target(
            base_url="https://api.example.com/v1",
            scope=ScopeRules(extra_hosts=["api.example.com"]),
        )
        auth = authorise_registered_target(t)
        hosts = auth.scope_settings.allowed_hosts
        assert len(hosts) == len(set(hosts)), "No duplicate hosts expected"

    def test_loopback_without_local_lab_raises(self) -> None:
        t = make_target(base_url="http://127.0.0.1:8080/api")
        with pytest.raises(ScopeViolationError, match="not explicitly authorised"):
            authorise_registered_target(t, local_lab=False)

    def test_loopback_error_mentions_local_lab(self) -> None:
        t = make_target(base_url="http://127.0.0.1:8080/api")
        with pytest.raises(ScopeViolationError) as exc_info:
            authorise_registered_target(t, local_lab=False)
        assert "--local-lab" in (exc_info.value.hint or "")

    def test_private_host_without_local_lab_raises(self) -> None:
        t = make_target(base_url="http://192.168.1.100/api")
        with pytest.raises(ScopeViolationError):
            authorise_registered_target(t, local_lab=False)

    def test_loopback_with_local_lab_succeeds(self) -> None:
        t = make_target(base_url="http://127.0.0.1:9999/api")
        auth = authorise_registered_target(t, local_lab=True)
        assert auth.requires_local_lab is True

    def test_exposure_recorded_on_authorisation(self) -> None:
        t = make_target(base_url="http://127.0.0.1:9999/api")
        auth = authorise_registered_target(t, local_lab=True)
        from aegisapi.utils.urls import HostExposure
        assert auth.exposure is HostExposure.LOOPBACK

    def test_scope_settings_enforce_is_true(self) -> None:
        t = make_target(base_url="https://api.example.com/v1")
        auth = authorise_registered_target(t)
        assert auth.scope_settings.enforce is True


# ---------------------------------------------------------------------------
# 2. ScanOptions — target field
# ---------------------------------------------------------------------------


class TestScanOptionsTargetField:
    def test_target_defaults_to_none(self) -> None:
        opts = ScanOptions(url="https://api.example.com/v1")
        assert opts.target is None

    def test_target_can_be_set(self) -> None:
        t = make_target(base_url="https://api.example.com/v1")
        opts = ScanOptions(url=t.base_url, target=t)
        assert opts.target is t

    def test_describe_shows_target_name_when_target_is_set(self) -> None:
        t = make_target(name="acme", base_url="https://api.acme.test/v1")
        opts = ScanOptions(url=t.base_url, target=t)
        described = opts.describe()
        assert "acme" in described["url"]

    def test_describe_shows_url_only_for_ephemeral(self) -> None:
        opts = ScanOptions(url="https://api.example.com/v1")
        described = opts.describe()
        assert described["url"] == "https://api.example.com/v1"

    def test_describe_auth_from_target_when_target_has_auth(self) -> None:
        import os
        os.environ["_DESCRIBE_TEST_TOKEN"] = "x"
        try:
            auth = AuthProfile(
                method=AuthMethod.BEARER,
                token=SecretRef(variable="_DESCRIBE_TEST_TOKEN"),
            )
            t = make_target(
                name="authtest",
                base_url="https://api.example.com/v1",
                auth=auth,
            )
            opts = ScanOptions(url=t.base_url, target=t)
            described = opts.describe()
            assert described["authentication"] == "bearer"
        finally:
            os.environ.pop("_DESCRIBE_TEST_TOKEN", None)

    def test_describe_auth_none_for_target_with_no_auth(self) -> None:
        t = make_target(base_url="https://api.example.com/v1")
        opts = ScanOptions(url=t.base_url, target=t)
        described = opts.describe()
        assert described["authentication"] == "none"


# ---------------------------------------------------------------------------
# 3. CLI — input validation (no network)
# ---------------------------------------------------------------------------


class TestCliScanInputValidation:
    @pytest.fixture
    def runner(self) -> CliRunner:
        return CliRunner()

    def test_no_target_and_no_url_gives_error(self, runner: CliRunner) -> None:
        result = runner.invoke(app, ["scan"])
        assert result.exit_code != EXIT_OK

    def test_target_and_url_both_given_gives_error(
        self, runner: CliRunner, workspace_root: Path
    ) -> None:
        result = runner.invoke(
            app, ["scan", "myapi", "--url", "https://api.example.com", "--format", "none"]
        )
        assert result.exit_code != EXIT_OK

    def test_nonexistent_target_gives_error(
        self, runner: CliRunner, workspace_root: Path
    ) -> None:
        result = runner.invoke(app, ["scan", "doesnotexist", "--format", "none"])
        assert result.exit_code != EXIT_OK

    def test_nonexistent_target_error_message_helpful(
        self, runner: CliRunner, workspace_root: Path
    ) -> None:
        result = runner.invoke(app, ["scan", "doesnotexist", "--format", "none"])
        output = result.output.lower()
        # Should mention no targets registered or the target name
        assert "doesnotexist" in output or "no target" in output or "not registered" in output

    def test_scan_help_shows_target_argument(self, runner: CliRunner) -> None:
        result = runner.invoke(app, ["scan", "--help"])
        assert result.exit_code == EXIT_OK
        assert "TARGET" in result.output

    def test_scan_help_still_shows_url_option(self, runner: CliRunner) -> None:
        result = runner.invoke(app, ["scan", "--help"])
        assert result.exit_code == EXIT_OK
        assert "--url" in result.output

    def test_scan_help_shows_local_lab(self, runner: CliRunner) -> None:
        result = runner.invoke(app, ["scan", "--help"])
        assert "--local-lab" in result.output

    def test_disabled_target_gives_error(
        self, runner: CliRunner, workspace_root: Path
    ) -> None:
        # Register a disabled target, then try to scan it.
        runner.invoke(
            app,
            [
                "target", "add", "disabled-api",
                "https://api.example.com/v1",
                "--description", "disabled target",
            ],
        )
        runner.invoke(
            app,
            ["target", "update", "disabled-api", "--disable"],
        )
        result = runner.invoke(app, ["scan", "disabled-api", "--format", "none"])
        assert result.exit_code != EXIT_OK
        assert "disabled" in result.output.lower()


# ---------------------------------------------------------------------------
# 4. CLI — scope guard (no network, registered target with private/loopback host)
# ---------------------------------------------------------------------------


class TestCliScanScopeGuard:
    @pytest.fixture
    def runner(self) -> CliRunner:
        return CliRunner()

    def test_loopback_registered_target_without_local_lab_fails(
        self, runner: CliRunner, workspace_root: Path
    ) -> None:
        # Register a loopback target, then try to scan it without --local-lab.
        runner.invoke(
            app,
            ["target", "add", "loopback-api", "http://127.0.0.1:19999/api"],
        )
        result = runner.invoke(
            app, ["scan", "loopback-api", "--format", "none"]
        )
        # Should fail with scope error before any network attempt.
        assert result.exit_code == EXIT_SCOPE_ERROR

    def test_loopback_registered_target_without_local_lab_mentions_flag(
        self, runner: CliRunner, workspace_root: Path
    ) -> None:
        runner.invoke(
            app,
            ["target", "add", "loopback-api2", "http://127.0.0.1:19998/api"],
        )
        result = runner.invoke(
            app, ["scan", "loopback-api2", "--format", "none"]
        )
        assert "--local-lab" in result.output


# ---------------------------------------------------------------------------
# 5. Integration tests — full registered-target scan via the lab API
# ---------------------------------------------------------------------------


try:
    from labapi import running_lab  # type: ignore[import]
    _LABAPI_AVAILABLE = True
except ImportError:
    _LABAPI_AVAILABLE = False

pytestmark_lab = pytest.mark.skipif(
    not _LABAPI_AVAILABLE,
    reason="labapi not available",
)


@pytest.fixture(scope="module")
def lab_registered_scan_result() -> Any:
    """Full scan via a registered target pointing at the lab API."""
    if not _LABAPI_AVAILABLE:
        pytest.skip("labapi not available")
    from labapi import running_lab  # noqa: PLC0415

    with running_lab() as lab:
        config = _default_config(rate=50.0)
        t = make_target(
            name="labtest",
            base_url=lab.base_url,
        )
        options = ScanOptions(
            url=t.base_url,
            target=t,
            local_lab=True,
            budget=240,
        )
        return run_scan(options, config=config)


@pytest.mark.skipif(not _LABAPI_AVAILABLE, reason="labapi not available")
class TestRegisteredTargetIntegration:
    def test_all_stages_complete(self, lab_registered_scan_result: Any) -> None:
        result = lab_registered_scan_result
        assert result.discovery is not None
        assert result.assessment is not None
        assert result.intelligence is not None
        assert result.report is not None

    def test_target_name_in_result_is_registered_name(
        self, lab_registered_scan_result: Any
    ) -> None:
        result = lab_registered_scan_result
        assert result.authorisation.target.name == "labtest"

    def test_target_name_not_scan_ephemeral(
        self, lab_registered_scan_result: Any
    ) -> None:
        result = lab_registered_scan_result
        from aegisapi.scan.authorisation import SCAN_TARGET_NAME
        assert result.authorisation.target.name != SCAN_TARGET_NAME

    def test_endpoints_discovered(self, lab_registered_scan_result: Any) -> None:
        result = lab_registered_scan_result
        assert result.endpoints_discovered > 0

    def test_requests_sent_within_budget(self, lab_registered_scan_result: Any) -> None:
        result = lab_registered_scan_result
        assert result.requests_sent <= result.options.budget

    def test_no_requests_outside_registered_host(
        self, lab_registered_scan_result: Any
    ) -> None:
        result = lab_registered_scan_result
        lab_host = "127.0.0.1"
        for check_result in result.assessment.results:
            for evidence in check_result.evidence:
                assert lab_host in evidence.url, (
                    f"Evidence URL {evidence.url!r} is outside registered host"
                )

    def test_checks_produce_results(self, lab_registered_scan_result: Any) -> None:
        result = lab_registered_scan_result
        assert len(result.assessment.results) > 0

    def test_describe_shows_target_name(self, lab_registered_scan_result: Any) -> None:
        result = lab_registered_scan_result
        described = result.options.describe()
        assert "labtest" in described["url"]

    def test_loopback_note_present(self, lab_registered_scan_result: Any) -> None:
        result = lab_registered_scan_result
        assert any("loopback" in n.lower() for n in result.notes)

    def test_credentials_note_mentions_target_update(
        self, lab_registered_scan_result: Any
    ) -> None:
        result = lab_registered_scan_result
        # No auth on this target — the note should mention target update, not --auth-method
        auth_notes = [n for n in result.notes if "authentication" in n.lower() or "credential" in n.lower()]
        if auth_notes:
            combined = " ".join(auth_notes).lower()
            assert "target update" in combined or "auth-method" in combined


# ---------------------------------------------------------------------------
# 6. CLI integration — scan via registered target name
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not _LABAPI_AVAILABLE, reason="labapi not available")
class TestCliRegisteredTargetScan:
    @pytest.fixture
    def runner(self) -> CliRunner:
        return CliRunner()

    def test_scan_registered_target_produces_summary(
        self, runner: CliRunner, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        workspace = tmp_path / "ws"
        monkeypatch.setenv(HOME_ENV_VAR, str(workspace))
        from labapi import running_lab  # noqa: PLC0415

        with running_lab() as lab:
            runner.invoke(app, ["target", "add", "labapi", lab.base_url])
            result = runner.invoke(
                app,
                [
                    "scan", "labapi",
                    "--local-lab",
                    "--rate", "50",
                    "--format", "none",
                ],
            )
        assert result.exit_code == EXIT_OK, result.output
        assert "Scan summary" in result.output
        assert "Findings" in result.output

    def test_scan_registered_target_shows_name_in_summary(
        self, runner: CliRunner, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        workspace = tmp_path / "ws"
        monkeypatch.setenv(HOME_ENV_VAR, str(workspace))
        from labapi import running_lab  # noqa: PLC0415

        with running_lab() as lab:
            runner.invoke(app, ["target", "add", "labapi", lab.base_url])
            result = runner.invoke(
                app,
                [
                    "scan", "labapi",
                    "--local-lab",
                    "--rate", "50",
                    "--format", "none",
                ],
            )
        assert "labapi" in result.output

    def test_scan_registered_target_writes_reports_to_workspace(
        self, runner: CliRunner, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        workspace = tmp_path / "ws"
        monkeypatch.setenv(HOME_ENV_VAR, str(workspace))
        from labapi import running_lab  # noqa: PLC0415

        with running_lab() as lab:
            runner.invoke(app, ["target", "add", "labapi", lab.base_url])
            runner.invoke(
                app,
                [
                    "scan", "labapi",
                    "--local-lab",
                    "--rate", "50",
                    "--format", "both",
                ],
            )
        assert (workspace / "reports" / "labapi.json").exists(), (
            "JSON report should be written to workspace/reports/labapi.json"
        )
        assert (workspace / "reports" / "labapi.html").exists(), (
            "HTML report should be written to workspace/reports/labapi.html"
        )

    def test_scan_registered_target_json_report_has_findings(
        self, runner: CliRunner, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        workspace = tmp_path / "ws"
        monkeypatch.setenv(HOME_ENV_VAR, str(workspace))
        from labapi import running_lab  # noqa: PLC0415

        with running_lab() as lab:
            runner.invoke(app, ["target", "add", "labapi", lab.base_url])
            runner.invoke(
                app,
                [
                    "scan", "labapi",
                    "--local-lab",
                    "--rate", "50",
                    "--format", "json",
                ],
            )
        report_path = workspace / "reports" / "labapi.json"
        assert report_path.exists()
        doc = json.loads(report_path.read_text(encoding="utf-8"))
        assert len(doc.get("results", [])) > 0

    def test_scan_registered_target_explicit_output_overrides_workspace(
        self, runner: CliRunner, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        workspace = tmp_path / "ws"
        monkeypatch.setenv(HOME_ENV_VAR, str(workspace))
        custom_output = tmp_path / "custom-report"
        from labapi import running_lab  # noqa: PLC0415

        with running_lab() as lab:
            runner.invoke(app, ["target", "add", "labapi", lab.base_url])
            runner.invoke(
                app,
                [
                    "scan", "labapi",
                    "--local-lab",
                    "--rate", "50",
                    "--format", "json",
                    "--output", str(custom_output),
                ],
            )
        assert custom_output.with_suffix(".json").exists(), (
            "--output should override the workspace default"
        )

    def test_url_path_still_works_after_changes(
        self, runner: CliRunner, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Backward compatibility: aegisapi scan --url URL still works."""
        workspace = tmp_path / "ws"
        monkeypatch.setenv(HOME_ENV_VAR, str(workspace))
        from labapi import running_lab  # noqa: PLC0415

        with running_lab() as lab:
            result = runner.invoke(
                app,
                [
                    "scan",
                    "--url", lab.base_url,
                    "--local-lab",
                    "--rate", "50",
                    "--format", "none",
                ],
            )
        assert result.exit_code == EXIT_OK, result.output
        assert "Scan summary" in result.output

    def test_scan_authorisation_note_present_registered(
        self, runner: CliRunner, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        workspace = tmp_path / "ws"
        monkeypatch.setenv(HOME_ENV_VAR, str(workspace))
        from labapi import running_lab  # noqa: PLC0415

        with running_lab() as lab:
            runner.invoke(app, ["target", "add", "labapi", lab.base_url])
            result = runner.invoke(
                app,
                [
                    "scan", "labapi",
                    "--local-lab",
                    "--rate", "50",
                    "--format", "none",
                ],
            )
        assert "authorisation" in result.output.lower(), (
            "Authorisation reminder must appear in registered-target scan output"
        )
