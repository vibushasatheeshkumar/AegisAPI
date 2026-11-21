"""End-to-end tests for the scan pipeline, using the deliberate-weakness lab API.

``tests/labapi.py`` serves a real socket on an ephemeral loopback port.  Every
test here fires real HTTP requests against it, so this suite demonstrates that
the scan pipeline — URL validation, scope derivation, connectivity check,
endpoint discovery, security checks, finding generation, severity
classification, and report writing — works as a connected whole, not just that
each part compiles.

Design decisions:
* Tests assert *what kind of result* a check produces against a known endpoint,
  not the precise wording of a summary.  Wording is presentation; kind is
  behaviour.
* "Should trigger" means the check produces a non-PASS outcome (fail /
  needs_review / error) with a non-NONE finding class on that endpoint.
* "Should not trigger" means every result for that endpoint is PASS or SKIPPED.
* Clean-endpoint assertions use the two deliberately clean routes (/api/health
  and /api/catalogue) and confirm the scanner reports nothing on them.
* Tests that verify rejection (scope guard, loopback guard, out-of-scope
  redirect) do so without sending any traffic to a real host.
* Shared fixtures are module-level to avoid the pytest 9 class-scoped instance
  method deprecation that is promoted to an error by filterwarnings=["error"].
"""

from __future__ import annotations

import json
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from aegisapi.cli import app
from aegisapi.core.config import AegisConfig
from aegisapi.core.exceptions import (
    EXIT_FINDINGS_FOUND,
    EXIT_OK,
    EXIT_SCOPE_ERROR,
)
from aegisapi.models.assessment import CheckOutcome, FindingClass
from aegisapi.models.common import Severity
from aegisapi.scan.authorisation import authorise_scan_url
from aegisapi.scan.pipeline import ScanOptions, ScanResult, run_scan
from aegisapi.utils.urls import HostExposure, classify_host_exposure
from labapi import running_lab

# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _default_config(*, rate: float = 50.0) -> AegisConfig:
    config = AegisConfig()
    return config.model_copy(
        update={"http": config.http.model_copy(update={"requests_per_second": rate})}
    )


def _run(url: str, *, rate: float = 50.0, **kw: Any) -> ScanResult:
    """Run a scan against the lab and return the result."""
    config = _default_config(rate=rate)
    options = ScanOptions(url=url, local_lab=True, **kw)
    return run_scan(options, config=config)


def _results_for(result: ScanResult, check_id: str) -> list[Any]:
    return [r for r in result.assessment.results if r.check_id == check_id]


def _findings_for(result: ScanResult, check_id: str, endpoint_key: str) -> list[Any]:
    return [
        r
        for r in result.assessment.results
        if r.check_id == check_id and r.endpoint_key == endpoint_key
    ]


def _failed(r: Any) -> bool:
    """True when a result is fail or needs_review (i.e. worth reading)."""
    return r.outcome in {CheckOutcome.FAIL, CheckOutcome.NEEDS_REVIEW}


def _has_finding(r: Any) -> bool:
    """True when the result carries a non-none finding class."""
    return r.finding_class is not FindingClass.NONE


# ---------------------------------------------------------------------------
# Module-level shared fixtures.
#
# These are defined at module scope, not as methods inside test classes,
# to avoid the pytest 9 PytestRemovedIn10Warning for class-scoped instance
# method fixtures (which the project's filterwarnings=["error"] promotes to
# an error).
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def lab_scan() -> ScanResult:
    """A complete scan of the lab API, without credentials."""
    with running_lab() as lab:
        return _run(lab.base_url)


@pytest.fixture(scope="module")
def lab_scan_with_credentials() -> ScanResult:
    """A scan with a valid bearer token supplied.  AUTH-001 and AUTH-002 run."""
    os.environ["_TEST_SCAN_TOKEN"] = "fake-token-for-testing"
    try:
        from aegisapi.models.secrets import SecretRef
        from aegisapi.models.target import AuthMethod, AuthProfile

        auth = AuthProfile(
            method=AuthMethod.BEARER,
            token=SecretRef(variable="_TEST_SCAN_TOKEN"),
        )
        with running_lab() as lab:
            return _run(lab.base_url, auth=auth)
    finally:
        os.environ.pop("_TEST_SCAN_TOKEN", None)


@pytest.fixture(scope="module")
def lab_scan_with_garbage_token() -> ScanResult:
    """A scan with a deliberately-invalid bearer token to probe AUTH-002."""
    os.environ["_TEST_GARBAGE_TOKEN"] = "deliberate-garbage"
    try:
        from aegisapi.models.secrets import SecretRef
        from aegisapi.models.target import AuthMethod, AuthProfile

        auth = AuthProfile(
            method=AuthMethod.BEARER,
            token=SecretRef(variable="_TEST_GARBAGE_TOKEN"),
        )
        with running_lab() as lab:
            return _run(lab.base_url, auth=auth)
    finally:
        os.environ.pop("_TEST_GARBAGE_TOKEN", None)


# ---------------------------------------------------------------------------
# 1. URL validation and scope derivation
# ---------------------------------------------------------------------------


class TestUrlValidation:
    def test_non_http_scheme_is_rejected(self) -> None:
        from aegisapi.core.exceptions import InvalidUrlError

        with pytest.raises(InvalidUrlError):
            authorise_scan_url("ftp://example.com")

    def test_bare_hostname_without_scheme_is_rejected(self) -> None:
        from aegisapi.core.exceptions import InvalidUrlError

        with pytest.raises(InvalidUrlError):
            authorise_scan_url("example.com/api")

    def test_loopback_without_local_lab_is_rejected(self) -> None:
        from aegisapi.core.exceptions import ScopeViolationError

        with pytest.raises(ScopeViolationError, match="not explicitly authorised"):
            authorise_scan_url("http://127.0.0.1:5000", local_lab=False)

    def test_loopback_error_mentions_local_lab_flag(self) -> None:
        from aegisapi.core.exceptions import ScopeViolationError

        with pytest.raises(ScopeViolationError) as exc_info:
            authorise_scan_url("http://127.0.0.1:5000", local_lab=False)
        assert "--local-lab" in (exc_info.value.hint or "")

    def test_private_address_without_local_lab_is_rejected(self) -> None:
        from aegisapi.core.exceptions import ScopeViolationError

        with pytest.raises(ScopeViolationError):
            authorise_scan_url("http://192.168.1.1/api", local_lab=False)

    def test_public_host_does_not_need_local_lab(self) -> None:
        auth = authorise_scan_url("https://example.com")
        assert auth.url.host == "example.com"

    def test_loopback_with_local_lab_succeeds(self) -> None:
        auth = authorise_scan_url("http://127.0.0.1:9999", local_lab=True)
        assert auth.exposure is HostExposure.LOOPBACK
        assert auth.requires_local_lab is True

    def test_scope_is_derived_from_url_path(self) -> None:
        auth = authorise_scan_url("https://api.example.com/v2")
        assert "/v2" in auth.target.scope.include_paths

    def test_scope_admits_only_named_host(self) -> None:
        auth = authorise_scan_url("https://api.example.com/v2")
        assert auth.scope_settings.allowed_hosts == ["api.example.com"]

    def test_extra_host_added_to_scope(self) -> None:
        auth = authorise_scan_url(
            "https://api.example.com", extra_hosts=("cdn.example.com",)
        )
        assert "cdn.example.com" in auth.scope_settings.allowed_hosts


# ---------------------------------------------------------------------------
# 2. HostExposure classification
# ---------------------------------------------------------------------------


class TestHostExposureClassification:
    @pytest.mark.parametrize(
        "host",
        [
            "127.0.0.1",
            "127.1",          # legacy short form
            "::1",            # IPv6 loopback
            "localhost",
            "0x7f.0.0.1",     # hex octet
            "2130706433",     # decimal 127.0.0.1
            "0177.0.0.1",     # octal first octet
        ],
    )
    def test_loopback_addresses(self, host: str) -> None:
        assert classify_host_exposure(host) is HostExposure.LOOPBACK, (
            f"Expected {host!r} to be classified as LOOPBACK"
        )

    @pytest.mark.parametrize(
        "host",
        [
            "10.0.0.1",
            "10.1",           # legacy short form of 10.0.0.1
            "172.16.0.1",
            "192.168.1.100",
            "169.254.1.1",    # link-local
            "myserver.local",
            "app.internal",
        ],
    )
    def test_private_addresses(self, host: str) -> None:
        assert classify_host_exposure(host) is HostExposure.PRIVATE, (
            f"Expected {host!r} to be classified as PRIVATE"
        )

    @pytest.mark.parametrize(
        "host",
        [
            "example.com",
            "api.example.com",
            "8.8.8.8",
            "1.1.1.1",
        ],
    )
    def test_public_addresses(self, host: str) -> None:
        assert classify_host_exposure(host) is HostExposure.PUBLIC, (
            f"Expected {host!r} to be classified as PUBLIC"
        )


# ---------------------------------------------------------------------------
# 3. Connectivity and discovery
# ---------------------------------------------------------------------------


class TestConnectivityAndDiscovery:
    def test_connectivity_failure_raises_transport_error(self) -> None:
        from aegisapi.core.exceptions import TransportError

        with pytest.raises(TransportError):
            _run("http://127.0.0.1:1")

    def test_lab_serves_openapi_spec(self, lab_scan: ScanResult) -> None:
        assert lab_scan.live.from_specification is True

    def test_discovery_finds_all_lab_endpoints(self, lab_scan: ScanResult) -> None:
        endpoints = [e.endpoint.path for e in lab_scan.discovery.endpoints]
        for path in (
            "/api/health",
            "/api/orders",
            "/api/admin/users",
            "/api/reports/summary",
            "/api/search",
            "/api/catalogue",
        ):
            assert path in endpoints, f"{path} not discovered"

    def test_all_discovered_endpoints_are_in_scope(self, lab_scan: ScanResult) -> None:
        from aegisapi.models.discovery import ScopeClassification

        out_of_scope = [
            e for e in lab_scan.discovery.endpoints
            if e.classification is not ScopeClassification.IN_SCOPE
        ]
        assert out_of_scope == []

    def test_requests_sent_is_positive(self, lab_scan: ScanResult) -> None:
        assert lab_scan.requests_sent > 0

    def test_requests_sent_does_not_exceed_budget(self, lab_scan: ScanResult) -> None:
        assert lab_scan.requests_sent <= lab_scan.options.budget


# ---------------------------------------------------------------------------
# 4. Security check results — weaknesses that must trigger
# ---------------------------------------------------------------------------


class TestWeaknessesThatMustTrigger:
    """Every weakness planted in labapi.py must produce a non-PASS result."""

    def test_conf001_missing_headers_on_orders(self, lab_scan: ScanResult) -> None:
        rows = _findings_for(lab_scan, "CONF-001", "GET /api/orders")
        assert any(_failed(r) for r in rows), "CONF-001 should flag /api/orders"

    def test_conf001_missing_headers_on_admin_users(self, lab_scan: ScanResult) -> None:
        rows = _findings_for(lab_scan, "CONF-001", "GET /api/admin/users")
        assert any(_failed(r) for r in rows), "CONF-001 should flag /api/admin/users"

    def test_conf002_cors_reflection_on_orders(self, lab_scan: ScanResult) -> None:
        rows = _findings_for(lab_scan, "CONF-002", "GET /api/orders")
        assert any(_failed(r) for r in rows), "CONF-002 should flag /api/orders CORS"

    def test_conf002_is_confirmed_not_merely_suspected(
        self, lab_scan: ScanResult
    ) -> None:
        rows = _findings_for(lab_scan, "CONF-002", "GET /api/orders")
        assert any(
            r.finding_class is FindingClass.CONFIRMED for r in rows
        ), "CORS reflection with credentials should be CONFIRMED"

    def test_conf003_undocumented_methods_on_orders(self, lab_scan: ScanResult) -> None:
        rows = _findings_for(lab_scan, "CONF-003", "GET /api/orders")
        assert any(_failed(r) for r in rows), "CONF-003 should flag undocumented methods"

    def test_conf004_server_banner_disclosure(self, lab_scan: ScanResult) -> None:
        all_conf004 = _results_for(lab_scan, "CONF-004")
        assert any(_failed(r) for r in all_conf004), "CONF-004 should flag server banner"

    def test_conf005_content_type_mismatch_on_reports(
        self, lab_scan: ScanResult
    ) -> None:
        rows = _findings_for(lab_scan, "CONF-005", "GET /api/reports/summary")
        assert any(_failed(r) for r in rows), "CONF-005 should flag content-type mismatch"

    def test_conf005_does_not_say_content_type_is_as_documented(
        self, lab_scan: ScanResult
    ) -> None:
        # Regression: the old bug said "as documented" for a 500/HTML response
        # against an application/json spec.  Any PASS result claiming "as
        # documented" on /api/reports/summary is a false PASS.
        rows = _findings_for(lab_scan, "CONF-005", "GET /api/reports/summary")
        for r in rows:
            if r.outcome is CheckOutcome.PASS:
                assert "as documented" not in r.summary.lower(), (
                    "CONF-005 must not claim 500/HTML is as-documented"
                )

    def test_input001_required_param_not_enforced_on_search(
        self, lab_scan: ScanResult
    ) -> None:
        rows = _findings_for(lab_scan, "INPUT-001", "GET /api/search")
        assert any(_failed(r) for r in rows), "INPUT-001 should flag /api/search"

    def test_input002_integer_type_not_enforced_on_search(
        self, lab_scan: ScanResult
    ) -> None:
        rows = _findings_for(lab_scan, "INPUT-002", "GET /api/search")
        assert any(_failed(r) for r in rows), "INPUT-002 should flag /api/search"

    def test_input003_enum_not_enforced_on_search(self, lab_scan: ScanResult) -> None:
        rows = _findings_for(lab_scan, "INPUT-003", "GET /api/search")
        assert any(_failed(r) for r in rows), "INPUT-003 should flag /api/search"

    def test_conf004_information_exposure_on_lab(self, lab_scan: ScanResult) -> None:
        # The lab serves a stack trace with internal paths in the /api/reports/summary
        # 500 response body, and also exposes a detailed server banner.
        # CONF-004 (InformationExposureCheck) must fire somewhere.
        all_conf004 = _results_for(lab_scan, "CONF-004")
        assert any(_failed(r) for r in all_conf004), (
            "CONF-004 should flag information disclosure (server banner / stack trace)"
        )

    def test_rate001_no_rate_limit_observed(self, lab_scan: ScanResult) -> None:
        all_rate001 = _results_for(lab_scan, "RATE-001")
        assert any(_failed(r) for r in all_rate001), "RATE-001 should flag no rate-limit"


# ---------------------------------------------------------------------------
# 4b. AUTH-001 — requires credentials
# ---------------------------------------------------------------------------


class TestAuth001WithCredentials:
    """AUTH-001 needs an authenticated baseline to compare against."""

    def test_auth001_fires_on_admin_users(
        self, lab_scan_with_credentials: ScanResult
    ) -> None:
        rows = _findings_for(
            lab_scan_with_credentials, "AUTH-001", "GET /api/admin/users"
        )
        assert any(_failed(r) for r in rows), (
            "AUTH-001 must fire on /api/admin/users, which serves unauthenticated requests"
        )

    def test_auth001_severity_is_high(
        self, lab_scan_with_credentials: ScanResult
    ) -> None:
        rows = _findings_for(
            lab_scan_with_credentials, "AUTH-001", "GET /api/admin/users"
        )
        for r in rows:
            if _failed(r):
                assert r.severity is Severity.HIGH

    def test_auth001_does_not_fire_on_health(
        self, lab_scan_with_credentials: ScanResult
    ) -> None:
        # /api/health has security: [] — no auth required.  AUTH-001 must not
        # fire on an endpoint that is documented as public.
        rows = _findings_for(
            lab_scan_with_credentials, "AUTH-001", "GET /api/health"
        )
        assert all(
            r.outcome in {CheckOutcome.PASS, CheckOutcome.SKIPPED} for r in rows
        ), "AUTH-001 must not flag /api/health, which is declared public"

    def test_auth001_carrying_a_finding_class(
        self, lab_scan_with_credentials: ScanResult
    ) -> None:
        rows = _findings_for(
            lab_scan_with_credentials, "AUTH-001", "GET /api/admin/users"
        )
        for r in rows:
            if _failed(r):
                assert _has_finding(r), "A failed AUTH-001 must carry a finding class"
                assert r.finding_class is not FindingClass.NONE


# ---------------------------------------------------------------------------
# 5. AUTH-002 false-positive investigation
# ---------------------------------------------------------------------------


class TestAuth002FalsePositives:
    """AUTH-002 suspects token-verification weakness when an invalid token is accepted.

    This is a suspected (not confirmed) finding by design: the check cannot
    prove that the token format is wrong in a way that would only be accepted by
    a misconfigured verifier.  Confirm the finding class is SUSPECTED, not
    CONFIRMED, to ensure the tool is not overstating.
    """

    def test_auth002_fires_on_admin_users(
        self, lab_scan_with_garbage_token: ScanResult
    ) -> None:
        rows = _findings_for(
            lab_scan_with_garbage_token, "AUTH-002", "GET /api/admin/users"
        )
        assert any(_failed(r) for r in rows)

    def test_auth002_is_suspected_not_confirmed(
        self, lab_scan_with_garbage_token: ScanResult
    ) -> None:
        """AUTH-002 cannot confirm token-validation failure from one response."""
        rows = _findings_for(
            lab_scan_with_garbage_token, "AUTH-002", "GET /api/admin/users"
        )
        for r in rows:
            if _failed(r):
                assert r.finding_class is not FindingClass.CONFIRMED, (
                    "AUTH-002 should report SUSPECTED, not CONFIRMED: it cannot "
                    "prove the token format was invalid."
                )

    def test_auth002_does_not_fire_on_health(
        self, lab_scan_with_garbage_token: ScanResult
    ) -> None:
        # /api/health requires no auth at all, so an arbitrary token being
        # 'accepted' is not a weakness.
        rows = _findings_for(
            lab_scan_with_garbage_token, "AUTH-002", "GET /api/health"
        )
        assert all(
            r.outcome in {CheckOutcome.PASS, CheckOutcome.SKIPPED} for r in rows
        ), "AUTH-002 must not flag endpoints that declare no auth requirement"


# ---------------------------------------------------------------------------
# 6. Clean-endpoint negative tests
# ---------------------------------------------------------------------------


class TestCleanEndpoints:
    """The two clean routes must not produce confirmed or high-severity findings."""

    @pytest.mark.parametrize("path", ["/api/health", "/api/catalogue"])
    def test_no_confirmed_finding_on_clean_endpoint(
        self, path: str, lab_scan: ScanResult
    ) -> None:
        for check_id in (
            "CONF-001", "CONF-002", "CONF-003",
            "INPUT-001", "INPUT-002", "INPUT-003",
        ):
            endpoint_key = f"GET {path}"
            rows = _findings_for(lab_scan, check_id, endpoint_key)
            confirmed = [r for r in rows if r.finding_class is FindingClass.CONFIRMED]
            assert not confirmed, (
                f"{check_id} must not produce a CONFIRMED finding on clean {path}; "
                f"got: {[r.summary for r in confirmed]}"
            )

    @pytest.mark.parametrize("path", ["/api/health", "/api/catalogue"])
    def test_no_high_or_critical_finding_on_clean_endpoint(
        self, path: str, lab_scan: ScanResult
    ) -> None:
        endpoint_key = f"GET {path}"
        # CONF-004 fires globally (server banner on every response), so it is
        # excluded; it is a target-wide observation, not specific to a clean route.
        severe = [
            r
            for r in lab_scan.assessment.results
            if r.endpoint_key == endpoint_key
            and r.severity in {Severity.HIGH, Severity.CRITICAL}
            and r.check_id not in {"CONF-004"}
        ]
        assert not severe, (
            f"No HIGH/CRITICAL findings expected on clean {path} (excluding CONF-004); "
            f"got: {[(r.check_id, r.summary) for r in severe]}"
        )


# ---------------------------------------------------------------------------
# 7. Scope enforcement
# ---------------------------------------------------------------------------


class TestScopeEnforcement:
    def test_requests_stay_within_scope(self, lab_scan: ScanResult) -> None:
        """Every request the scan sends must be for 127.0.0.1 and nothing else."""
        lab_host = "127.0.0.1"
        for check_result in lab_scan.assessment.results:
            for evidence in check_result.evidence:
                assert lab_host in evidence.url, (
                    f"Evidence URL {evidence.url!r} is not on {lab_host}"
                )

    def test_out_of_scope_redirect_is_refused(self) -> None:
        """A redirect to a different host must be refused when follow_redirects=True."""
        from aegisapi.core.exceptions import ScopeViolationError
        from aegisapi.http import ScopedHttpClient
        from aegisapi.models.http import HttpLimits

        class _RedirectHandler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, fmt: str, *args: Any) -> None:
                del fmt, args

            def do_GET(self) -> None:
                self.send_response(302)
                self.send_header("Location", "http://evil.example.com/")
                self.send_header("Content-Length", "0")
                self.end_headers()

        server = ThreadingHTTPServer(("127.0.0.1", 0), _RedirectHandler)
        port = server.server_address[1]
        t = threading.Thread(target=server.serve_forever, daemon=True)
        t.start()
        try:
            from aegisapi.scan.authorisation import authorise_scan_url as _auth

            auth = _auth(f"http://127.0.0.1:{port}", local_lab=True)
            # Enable redirect following so the scope guard can intercept the hop.
            limits = HttpLimits(follow_redirects=True, requests_per_second=100.0)
            client = ScopedHttpClient(
                target=auth.target,
                settings=auth.scope_settings,
                limits=limits,
            )
            try:
                with pytest.raises(ScopeViolationError):
                    client.request("GET", f"http://127.0.0.1:{port}/")
            finally:
                client.close()
        finally:
            server.shutdown()
            server.server_close()


# ---------------------------------------------------------------------------
# 8. Request budget, rate limiting, and timeout
# ---------------------------------------------------------------------------


class TestBudgetAndLimits:
    def test_budget_note_appears_when_exhausted(self) -> None:
        with running_lab() as lab:
            result = _run(lab.base_url, budget=1)
        budget_notes = [n for n in result.notes if "budget" in n.lower()]
        assert budget_notes, "A note must explain when the budget was consumed"

    def test_scan_completes_within_reasonable_time(self) -> None:
        """With a high rate limit the lab scan should finish well under 30s."""
        import time

        with running_lab() as lab:
            t0 = time.monotonic()
            _run(lab.base_url, rate=50.0)
            elapsed = time.monotonic() - t0
        assert elapsed < 30.0, f"Scan took {elapsed:.1f}s, expected < 30s"

    def test_max_endpoints_limits_tested_count(self) -> None:
        with running_lab() as lab:
            result = _run(lab.base_url, max_endpoints=2)
        assert result.endpoints_tested <= 2


# ---------------------------------------------------------------------------
# 9. Exit codes
# ---------------------------------------------------------------------------


class TestExitCodes:
    @pytest.fixture
    def runner(self) -> CliRunner:
        return CliRunner()

    def test_exit_zero_when_no_fail_on_threshold(self, runner: CliRunner) -> None:
        with running_lab() as lab:
            result = runner.invoke(
                app,
                [
                    "scan",
                    "--url", lab.base_url,
                    "--local-lab",
                    "--rate", "50",
                    "--format", "none",
                    "--fail-on", "never",
                ],
            )
        assert result.exit_code == EXIT_OK, result.output

    def test_exit_findings_found_when_threshold_met(self, runner: CliRunner) -> None:
        with running_lab() as lab:
            result = runner.invoke(
                app,
                [
                    "scan",
                    "--url", lab.base_url,
                    "--local-lab",
                    "--rate", "50",
                    "--format", "none",
                    "--fail-on", "medium",
                ],
            )
        assert result.exit_code == EXIT_FINDINGS_FOUND, (
            f"Expected {EXIT_FINDINGS_FOUND}, got {result.exit_code}"
        )

    def test_exit_scope_error_without_local_lab(self, runner: CliRunner) -> None:
        with running_lab() as lab:
            result = runner.invoke(
                app,
                ["scan", "--url", lab.base_url, "--format", "none"],
            )
        assert result.exit_code == EXIT_SCOPE_ERROR

    def test_exit_zero_when_threshold_not_met(self, runner: CliRunner) -> None:
        with running_lab() as lab:
            result = runner.invoke(
                app,
                [
                    "scan",
                    "--url", lab.base_url,
                    "--local-lab",
                    "--rate", "50",
                    "--format", "none",
                    # Critical findings are not expected from the lab.
                    "--fail-on", "critical",
                ],
            )
        assert result.exit_code == EXIT_OK


# ---------------------------------------------------------------------------
# 10. Report generation
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def lab_reports(tmp_path_factory: pytest.TempPathFactory) -> dict[str, Path]:
    """Write JSON and HTML reports from a full lab scan and return their paths."""
    output = tmp_path_factory.mktemp("reports") / "scan"
    with running_lab() as lab:
        runner_obj = CliRunner()
        runner_obj.invoke(
            app,
            [
                "scan",
                "--url", lab.base_url,
                "--local-lab",
                "--rate", "50",
                "--output", str(output),
                "--format", "both",
            ],
        )
    return {
        "json": output.with_suffix(".json"),
        "html": output.with_suffix(".html"),
    }


class TestReportGeneration:

    def test_json_report_is_written(self, lab_reports: dict[str, Path]) -> None:
        assert lab_reports["json"].exists(), "JSON report file not written"

    def test_html_report_is_written(self, lab_reports: dict[str, Path]) -> None:
        assert lab_reports["html"].exists(), "HTML report file not written"

    def test_json_report_is_valid(self, lab_reports: dict[str, Path]) -> None:
        with lab_reports["json"].open() as f:
            doc = json.load(f)
        assert "results" in doc
        assert "summary" in doc

    def test_json_report_has_findings(self, lab_reports: dict[str, Path]) -> None:
        with lab_reports["json"].open() as f:
            doc = json.load(f)
        assert len(doc["results"]) > 0, "JSON report must contain at least one result"

    def test_html_report_contains_owasp_category(
        self, lab_reports: dict[str, Path]
    ) -> None:
        content = lab_reports["html"].read_text(encoding="utf-8")
        assert "OWASP API Security" in content, (
            "HTML report must include the OWASP API Security heading"
        )

    def test_html_report_contains_remediation(self, lab_reports: dict[str, Path]) -> None:
        content = lab_reports["html"].read_text(encoding="utf-8")
        assert "Recommended Remediation" in content, (
            "HTML report must include remediation guidance"
        )

    def test_html_report_does_not_say_no_remediation_guidance(
        self, lab_reports: dict[str, Path]
    ) -> None:
        content = lab_reports["html"].read_text(encoding="utf-8")
        assert "records no remediation guidance" not in content, (
            "Stale comment claiming no remediation guidance must not appear"
        )

    def test_html_report_is_valid_html(self, lab_reports: dict[str, Path]) -> None:
        content = lab_reports["html"].read_text(encoding="utf-8")
        assert content.startswith("<!DOCTYPE html"), "HTML report must have DOCTYPE"
        assert "</html>" in content

    def test_json_report_contains_owasp_on_findings(
        self, lab_reports: dict[str, Path]
    ) -> None:
        with lab_reports["json"].open() as f:
            doc = json.load(f)
        owasp_results = [r for r in doc["results"] if r.get("owasp")]
        assert len(owasp_results) > 0, "At least one result must carry an OWASP category"

    def test_json_report_target_base_url_matches(
        self, lab_reports: dict[str, Path]
    ) -> None:
        with lab_reports["json"].open() as f:
            doc = json.load(f)
        assert "127.0.0.1" in doc.get("target_base_url", ""), (
            "JSON report target_base_url must reference the scanned host"
        )

    def test_report_not_overwritten_without_force(
        self, tmp_path: Path, runner: CliRunner
    ) -> None:
        output = tmp_path / "scan"
        output.with_suffix(".json").write_text("{}", encoding="utf-8")
        with running_lab() as lab:
            runner.invoke(
                app,
                [
                    "scan",
                    "--url", lab.base_url,
                    "--local-lab",
                    "--rate", "50",
                    "--output", str(output),
                    "--format", "json",
                ],
            )
        # The original '{}' should not have been replaced.
        content = output.with_suffix(".json").read_text(encoding="utf-8")
        assert content == "{}", "Without --force the existing report must not be overwritten"

    @pytest.fixture
    def runner(self) -> CliRunner:
        return CliRunner()


# ---------------------------------------------------------------------------
# 11. Notes and limitations coverage
# ---------------------------------------------------------------------------


class TestScanNotes:
    def test_passive_mode_note_present(self, lab_scan: ScanResult) -> None:
        assert any("passive" in n.lower() for n in lab_scan.notes)

    def test_no_credentials_note_present(self, lab_scan: ScanResult) -> None:
        assert any("credential" in n.lower() for n in lab_scan.notes)

    def test_loopback_classification_note_present(
        self, lab_scan: ScanResult
    ) -> None:
        assert any("loopback" in n.lower() for n in lab_scan.notes)

    def test_silent_checks_note_names_check_ids(
        self, lab_scan: ScanResult
    ) -> None:
        silent_notes = [n for n in lab_scan.notes if "did not run" in n]
        if silent_notes:
            assert any(
                any(cid in n for cid in ("AUTH", "BOLA", "BFLA", "INPUT"))
                for n in silent_notes
            )


# ---------------------------------------------------------------------------
# 12. Full CLI round-trip
# ---------------------------------------------------------------------------


class TestCliRoundTrip:
    @pytest.fixture
    def runner(self) -> CliRunner:
        return CliRunner()

    def test_scan_help_renders(self, runner: CliRunner) -> None:
        result = runner.invoke(app, ["scan", "--help"])
        assert result.exit_code == EXIT_OK
        assert "--url" in result.output
        assert "--local-lab" in result.output
        assert "--fail-on" in result.output

    def test_scan_command_appears_in_top_level_help(self, runner: CliRunner) -> None:
        result = runner.invoke(app, ["--help"])
        assert "scan" in result.output

    def test_missing_url_gives_error(self, runner: CliRunner) -> None:
        result = runner.invoke(app, ["scan"])
        assert result.exit_code != EXIT_OK

    def test_full_scan_produces_summary(self, runner: CliRunner) -> None:
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
        output = result.output
        assert result.exit_code == EXIT_OK, output
        assert "Scan summary" in output
        assert "Findings" in output
        assert "Notes and limitations" in output

    def test_verbose_flag_prints_stage_messages(self, runner: CliRunner) -> None:
        with running_lab() as lab:
            result = runner.invoke(
                app,
                [
                    "scan",
                    "--url", lab.base_url,
                    "--local-lab",
                    "--rate", "50",
                    "--format", "none",
                    "--verbose",
                ],
                catch_exceptions=False,
            )
        assert "discover" in result.output.lower()
        assert "check" in result.output.lower()

    def test_detail_flag_prints_evidence_or_remediation(
        self, runner: CliRunner
    ) -> None:
        with running_lab() as lab:
            result = runner.invoke(
                app,
                [
                    "scan",
                    "--url", lab.base_url,
                    "--local-lab",
                    "--rate", "50",
                    "--format", "none",
                    "--detail",
                ],
            )
        assert "Evidence" in result.output or "Remediation" in result.output

    def test_scan_authorisation_note_always_present(
        self, runner: CliRunner
    ) -> None:
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
        assert "authorisation" in result.output.lower(), (
            "The authorisation reminder must always appear in scan output"
        )
