"""M4 budget unit tests: RequestBudget, BudgetSummary, engine integration."""

from __future__ import annotations

import threading
import time
from unittest.mock import MagicMock, patch

import pytest

from aegisapi.models.assessment import (
    AssessmentResult,
    CheckCategory,
    CheckOutcome,
    CheckResult,
    FindingClass,
)
from aegisapi.models.report import BudgetSummary, Report, ReportSummary
from aegisapi.reporting.build import _build_budget_summary, build_report
from aegisapi.testing.registry import CheckContext, RequestBudget


# ---------------------------------------------------------------------------
# RequestBudget — basic behaviour (unchanged from M1-M3)
# ---------------------------------------------------------------------------


class TestRequestBudgetBasic:
    def test_remaining_starts_at_limit(self):
        b = RequestBudget(limit=10)
        assert b.remaining == 10

    def test_consume_decrements_remaining(self):
        b = RequestBudget(limit=10)
        assert b.consume(3) is True
        assert b.remaining == 7
        assert b.spent == 3

    def test_consume_returns_false_when_empty(self):
        b = RequestBudget(limit=2)
        b.consume(2)
        assert b.exhausted is True
        assert b.consume(1) is False
        assert b.spent == 2  # unchanged

    def test_consume_partial_allowed(self):
        b = RequestBudget(limit=5)
        assert b.consume(3) is True
        assert b.consume(2) is True
        assert b.consume(1) is False

    def test_zero_limit_always_exhausted(self):
        b = RequestBudget(limit=0)
        assert b.exhausted is True
        assert b.consume(1) is False

    def test_consume_count_zero(self):
        b = RequestBudget(limit=5)
        assert b.consume(0) is True
        assert b.spent == 0


# ---------------------------------------------------------------------------
# RequestBudget — per-endpoint sub-limit
# ---------------------------------------------------------------------------


class TestRequestBudgetPerEndpoint:
    def test_per_endpoint_allows_up_to_limit(self):
        b = RequestBudget(limit=100, max_per_endpoint=3)
        b.set_context("GET /items", "CHECK-001")
        assert b.consume(1) is True
        assert b.consume(1) is True
        assert b.consume(1) is True
        assert b.consume(1) is False  # over limit

    def test_per_endpoint_tracks_separately_per_key(self):
        b = RequestBudget(limit=100, max_per_endpoint=2)
        b.set_context("GET /items", "CHECK-001")
        b.consume(2)
        b.clear_context()
        b.set_context("POST /items", "CHECK-001")
        # Fresh endpoint, limit resets
        assert b.consume(1) is True
        assert b.consume(1) is True
        assert b.consume(1) is False

    def test_endpoint_recorded_at_limit(self):
        b = RequestBudget(limit=100, max_per_endpoint=1)
        b.set_context("GET /ep", "CHECK-001")
        b.consume(1)
        b.consume(1)  # triggers at-limit
        assert "GET /ep" in b.endpoints_at_limit

    def test_endpoint_not_at_limit_when_not_exceeded(self):
        b = RequestBudget(limit=100, max_per_endpoint=5)
        b.set_context("GET /ep", "CHECK-001")
        b.consume(3)
        assert b.endpoints_at_limit == []

    def test_no_per_endpoint_limit_when_none(self):
        b = RequestBudget(limit=100, max_per_endpoint=None)
        b.set_context("GET /ep", "CHECK-001")
        for _ in range(50):
            assert b.consume(1) is True


# ---------------------------------------------------------------------------
# RequestBudget — per-check sub-limit
# ---------------------------------------------------------------------------


class TestRequestBudgetPerCheck:
    def test_per_check_allows_up_to_limit(self):
        b = RequestBudget(limit=100, max_per_check=2)
        b.set_context("GET /a", "CHECK-001")
        assert b.consume(1) is True
        assert b.consume(1) is True
        assert b.consume(1) is False  # over limit

    def test_per_check_accumulates_across_endpoints(self):
        b = RequestBudget(limit=100, max_per_check=3)
        b.set_context("GET /a", "CHECK-001")
        b.consume(2)
        b.clear_context()
        b.set_context("GET /b", "CHECK-001")
        # 1 left for this check
        assert b.consume(1) is True
        assert b.consume(1) is False

    def test_different_checks_track_independently(self):
        b = RequestBudget(limit=100, max_per_check=2)
        b.set_context("GET /a", "CHECK-001")
        b.consume(2)
        b.clear_context()
        b.set_context("GET /a", "CHECK-002")
        # Fresh check id
        assert b.consume(1) is True
        assert b.consume(1) is True
        assert b.consume(1) is False

    def test_no_per_check_limit_when_none(self):
        b = RequestBudget(limit=100, max_per_check=None)
        b.set_context("GET /ep", "CHECK-001")
        for _ in range(50):
            assert b.consume(1) is True


# ---------------------------------------------------------------------------
# RequestBudget — combined limits
# ---------------------------------------------------------------------------


class TestRequestBudgetCombined:
    def test_global_limit_enforced_before_per_endpoint(self):
        b = RequestBudget(limit=2, max_per_endpoint=10)
        b.set_context("GET /ep", "CHECK-001")
        b.consume(2)
        assert b.consume(1) is False  # global exhausted

    def test_per_endpoint_before_per_check(self):
        """When both limits are set, the more restrictive one wins first."""
        b = RequestBudget(limit=100, max_per_endpoint=1, max_per_check=5)
        b.set_context("GET /ep", "CHECK-001")
        b.consume(1)
        assert b.consume(1) is False  # per-endpoint hit

    def test_clear_context_allows_no_limits_on_next_consume(self):
        b = RequestBudget(limit=100, max_per_endpoint=1, max_per_check=1)
        b.set_context("GET /ep", "CHECK-001")
        b.consume(1)
        b.clear_context()
        # No context → neither sub-limit applies
        assert b.consume(50) is True


# ---------------------------------------------------------------------------
# RequestBudget — thread safety
# ---------------------------------------------------------------------------


class TestRequestBudgetThreadSafety:
    def test_concurrent_consume_respects_global_limit(self):
        b = RequestBudget(limit=100)
        results = []

        def consume_many():
            for _ in range(60):
                results.append(b.consume(1))

        t1 = threading.Thread(target=consume_many)
        t2 = threading.Thread(target=consume_many)
        t1.start()
        t2.start()
        t1.join()
        t2.join()

        successes = results.count(True)
        assert successes == 100
        assert b.spent == 100

    def test_set_context_is_thread_safe(self):
        b = RequestBudget(limit=1000)
        errors = []

        def worker(ep: str, ck: str):
            try:
                for _ in range(20):
                    b.set_context(ep, ck)
                    b.consume(1)
                    b.clear_context()
            except Exception as exc:
                errors.append(exc)

        threads = [
            threading.Thread(target=worker, args=(f"GET /ep{i}", f"CHECK-{i:03}"))
            for i in range(5)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors


# ---------------------------------------------------------------------------
# BudgetSummary model
# ---------------------------------------------------------------------------


class TestBudgetSummary:
    def test_complete_status(self):
        s = BudgetSummary(requests_sent=10, request_budget=100, completion_status="complete")
        assert s.completion_status == "complete"
        assert s.scan_timed_out is False
        assert s.checks_timed_out == 0

    def test_partial_timeout_status(self):
        s = BudgetSummary(
            requests_sent=50,
            request_budget=100,
            scan_timed_out=True,
            completion_status="partial_timeout",
        )
        assert s.completion_status == "partial_timeout"

    def test_partial_budget_status(self):
        s = BudgetSummary(
            requests_sent=100,
            request_budget=100,
            completion_status="partial_budget",
        )
        assert s.completion_status == "partial_budget"

    def test_invalid_status_raises(self):
        with pytest.raises(Exception):
            BudgetSummary(requests_sent=0, request_budget=0, completion_status="bogus")

    def test_endpoints_at_limit_stored(self):
        s = BudgetSummary(
            requests_sent=10,
            request_budget=100,
            endpoints_at_limit=["GET /a", "POST /b"],
            completion_status="complete",
        )
        assert "GET /a" in s.endpoints_at_limit

    def test_extra_fields_forbidden(self):
        with pytest.raises(Exception):
            BudgetSummary(requests_sent=0, request_budget=0, unknown_field="x")


# ---------------------------------------------------------------------------
# _build_budget_summary helper
# ---------------------------------------------------------------------------


def _make_assessment(**kwargs) -> AssessmentResult:
    defaults = dict(
        target_name="test",
        target_base_url="http://test.local",
        requests_sent=0,
        request_budget=100,
        budget_exhausted=False,
        scan_timed_out=False,
        endpoints_at_limit=[],
        checks_timed_out=0,
        aegisapi_version="0.0.0",
    )
    defaults.update(kwargs)
    return AssessmentResult(**defaults)


class TestBuildBudgetSummary:
    def test_complete_scan(self):
        a = _make_assessment(requests_sent=50)
        bs = _build_budget_summary(a)
        assert bs.completion_status == "complete"
        assert bs.requests_sent == 50
        assert bs.scan_timed_out is False
        assert bs.checks_timed_out == 0

    def test_scan_timed_out(self):
        a = _make_assessment(scan_timed_out=True, requests_sent=30)
        bs = _build_budget_summary(a)
        assert bs.completion_status == "partial_timeout"
        assert bs.scan_timed_out is True

    def test_budget_exhausted(self):
        a = _make_assessment(budget_exhausted=True, requests_sent=100)
        bs = _build_budget_summary(a)
        assert bs.completion_status == "partial_budget"

    def test_timeout_takes_precedence_over_budget_exhausted(self):
        a = _make_assessment(scan_timed_out=True, budget_exhausted=True)
        bs = _build_budget_summary(a)
        assert bs.completion_status == "partial_timeout"

    def test_endpoints_at_limit_propagated(self):
        a = _make_assessment(endpoints_at_limit=["GET /items"])
        bs = _build_budget_summary(a)
        assert "GET /items" in bs.endpoints_at_limit

    def test_checks_timed_out_propagated(self):
        a = _make_assessment(checks_timed_out=3)
        bs = _build_budget_summary(a)
        assert bs.checks_timed_out == 3


# ---------------------------------------------------------------------------
# build_report passes budget_summary through
# ---------------------------------------------------------------------------


class TestBuildReportBudgetSummary:
    def test_budget_summary_in_report(self):
        a = _make_assessment(requests_sent=20)
        report = build_report(a)
        assert report.budget_summary is not None
        assert report.budget_summary.requests_sent == 20
        assert report.budget_summary.completion_status == "complete"

    def test_partial_timeout_in_report(self):
        a = _make_assessment(scan_timed_out=True, requests_sent=15)
        report = build_report(a)
        assert report.budget_summary is not None
        assert report.budget_summary.completion_status == "partial_timeout"

    def test_partial_budget_in_report(self):
        a = _make_assessment(budget_exhausted=True, requests_sent=100)
        report = build_report(a)
        assert report.budget_summary is not None
        assert report.budget_summary.completion_status == "partial_budget"


# ---------------------------------------------------------------------------
# ScanOptions new fields
# ---------------------------------------------------------------------------


class TestScanOptionsNewFields:
    def test_defaults_are_none(self):
        from aegisapi.scan.pipeline import ScanOptions

        opts = ScanOptions(url="http://test.local/")
        assert opts.scan_timeout_seconds is None
        assert opts.max_endpoint_requests is None
        assert opts.max_check_requests is None
        assert opts.check_timeout_seconds is None

    def test_describe_includes_new_fields(self):
        from aegisapi.scan.pipeline import ScanOptions

        opts = ScanOptions(
            url="http://test.local/",
            scan_timeout_seconds=120.0,
            max_endpoint_requests=5,
            max_check_requests=10,
            check_timeout_seconds=30.0,
        )
        d = opts.describe()
        assert d["scan_timeout"] == "120.0s"
        assert d["max_endpoint_requests"] == "5"
        assert d["max_check_requests"] == "10"
        assert d["check_timeout"] == "30.0s"

    def test_describe_none_fields(self):
        from aegisapi.scan.pipeline import ScanOptions

        opts = ScanOptions(url="http://test.local/")
        d = opts.describe()
        assert d["scan_timeout"] == "none"
        assert d["max_endpoint_requests"] == "none"


# ---------------------------------------------------------------------------
# ScanResult.completion_status property
# ---------------------------------------------------------------------------


class TestScanResultCompletionStatus:
    def _make_scan_result(self, **assessment_kwargs):
        from datetime import UTC, datetime

        from aegisapi.scan.pipeline import ScanResult

        # Minimal mocks for unused fields
        opts = MagicMock()
        opts.budget = 100
        auth = MagicMock()
        auth.url.host = "test.local"
        auth.target.scope.include_paths = ["/"]
        auth.exposure.value = "public"
        auth.requires_local_lab = False

        a = _make_assessment(**assessment_kwargs)
        # Build a minimal report
        report = build_report(a)
        discovery = MagicMock()
        discovery.endpoints = []
        discovery.specification.source_path = "none"
        discovery.specification.version.value = "openapi3"
        live = MagicMock()
        live.requests_sent = 0
        live.from_specification = False

        return ScanResult(
            options=opts,
            authorisation=auth,
            started_at=datetime.now(UTC),
            finished_at=datetime.now(UTC),
            discovery=discovery,
            live=live,
            assessment=a,
            intelligence=None,
            report=report,
        )

    def test_complete(self):
        sr = self._make_scan_result()
        assert sr.completion_status == "complete"

    def test_partial_timeout(self):
        sr = self._make_scan_result(scan_timed_out=True)
        assert sr.completion_status == "partial_timeout"

    def test_partial_budget(self):
        sr = self._make_scan_result(budget_exhausted=True, requests_sent=100)
        assert sr.completion_status == "partial_budget"


# ---------------------------------------------------------------------------
# AssessmentEngine — scan deadline (unit-level, no real HTTP)
# ---------------------------------------------------------------------------


class TestEngineScanDeadline:
    def test_deadline_in_past_stops_before_first_endpoint(self):
        """With an already-expired deadline, no endpoints should be tested."""
        from aegisapi.testing.engine import AssessmentEngine
        from aegisapi.models.discovery import ScopeClassification
        from aegisapi.models.target import Target, ScopeRules
        from aegisapi.core.config import AegisConfig

        target = Target(
            name="deadline-test",
            base_url="http://test.local/",
            scope=ScopeRules(include_paths=["/"]),
        )
        config = AegisConfig()
        engine = AssessmentEngine(target=target, config=config)

        ep = MagicMock()
        ep.endpoint.key = "GET /items"
        ep.endpoint.is_templated = False
        ep.endpoint.parameters = []
        ep.endpoint.responses = {}
        ep.classification = ScopeClassification.IN_SCOPE
        ep.resolved_url = "http://test.local/items"
        ep.reason = "in scope"

        discovery = MagicMock()
        discovery.endpoints = [ep]
        discovery.specification.source_sha256 = None

        # Deadline already in the past
        past_deadline = time.monotonic() - 1.0

        client = MagicMock()
        client.transport_for_reuse = None
        client.throttle = None

        result = engine.run(
            discovery=discovery,
            budget=100,
            client=client,
            scan_deadline=past_deadline,
        )

        assert result.scan_timed_out is True
        assert result.endpoints_tested == 0


# ---------------------------------------------------------------------------
# AssessmentEngine — checks_timed_out counter
# ---------------------------------------------------------------------------


class TestEngineCheckTimeout:
    def test_timed_out_check_produces_skipped_result(self):
        """A check that runs longer than check_timeout_seconds becomes SKIPPED."""
        from aegisapi.testing.engine import AssessmentEngine
        from aegisapi.models.discovery import ScopeClassification
        from aegisapi.models.target import Target, ScopeRules
        from aegisapi.core.config import AegisConfig
        from aegisapi.testing.registry import CheckRegistry, BaseCheck

        class SlowCheck(BaseCheck):
            check_id = "SLOW-001"
            name = "Slow check"
            category = CheckCategory.CONFIGURATION
            requests_per_endpoint = 1

            def applies_to(self, endpoint, context):
                return True

            def run(self, endpoint, context):
                time.sleep(5.0)  # Will be interrupted by check_timeout
                return []

        target = Target(
            name="timeout-test",
            base_url="http://test.local/",
            scope=ScopeRules(include_paths=["/"]),
        )
        config = AegisConfig()
        registry = CheckRegistry()
        registry.register(SlowCheck())
        engine = AssessmentEngine(target=target, config=config, registry=registry)

        ep = MagicMock()
        ep.endpoint.key = "GET /slow"
        ep.endpoint.is_templated = False
        ep.endpoint.parameters = []
        ep.endpoint.responses = {}
        ep.classification = ScopeClassification.IN_SCOPE
        ep.resolved_url = "http://test.local/slow"
        ep.reason = "in scope"

        discovery = MagicMock()
        discovery.endpoints = [ep]
        discovery.specification.source_sha256 = None

        client = MagicMock()
        client.transport_for_reuse = None
        client.throttle = None

        result = engine.run(
            discovery=discovery,
            budget=100,
            client=client,
            check_timeout_seconds=0.1,  # very short timeout
        )

        assert result.checks_timed_out == 1
        # Should have exactly 1 result — the SKIPPED one
        assert len(result.results) == 1
        assert result.results[0].outcome == CheckOutcome.SKIPPED


# ---------------------------------------------------------------------------
# RequestBudget.endpoints_at_limit — engine integration
# ---------------------------------------------------------------------------


class TestEnginePerEndpointLimit:
    def test_per_endpoint_limit_records_at_limit_endpoints(self):
        """Engine should record endpoints_at_limit on the AssessmentResult."""
        from aegisapi.testing.engine import AssessmentEngine
        from aegisapi.models.discovery import ScopeClassification
        from aegisapi.models.target import Target, ScopeRules
        from aegisapi.core.config import AegisConfig
        from aegisapi.testing.registry import CheckRegistry, BaseCheck

        consumed = []

        class ThirstyCheck(BaseCheck):
            check_id = "THIRSTY-001"
            name = "Thirsty check"
            category = CheckCategory.CONFIGURATION
            requests_per_endpoint = 5

            def applies_to(self, endpoint, context):
                return True

            def run(self, endpoint, context):
                for _ in range(5):
                    ok = context.budget.consume(1)
                    consumed.append(ok)
                return []

        target = Target(
            name="perlimit-test",
            base_url="http://test.local/",
            scope=ScopeRules(include_paths=["/"]),
        )
        config = AegisConfig()
        registry = CheckRegistry()
        registry.register(ThirstyCheck())
        engine = AssessmentEngine(target=target, config=config, registry=registry)

        ep = MagicMock()
        ep.endpoint.key = "GET /thirsty"
        ep.endpoint.is_templated = False
        ep.endpoint.parameters = []
        ep.endpoint.responses = {}
        ep.classification = ScopeClassification.IN_SCOPE
        ep.resolved_url = "http://test.local/thirsty"
        ep.reason = "in scope"

        discovery = MagicMock()
        discovery.endpoints = [ep]
        discovery.specification.source_sha256 = None

        client = MagicMock()
        client.transport_for_reuse = None
        client.throttle = None

        result = engine.run(
            discovery=discovery,
            budget=100,
            client=client,
            max_per_endpoint=2,  # only 2 requests per endpoint
        )

        # The check tried to consume 5, but only 2 were allowed
        assert consumed.count(True) == 2
        assert consumed.count(False) == 3
        assert "GET /thirsty" in result.endpoints_at_limit
