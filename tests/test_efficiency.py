"""Comprehensive tests for M5 — Scanning Efficiency.

Six test categories
-------------------
1. EfficiencyTracker — fingerprinting, GET cache, within-check / cross-check rules
2. RequestBudget cancellation (M4 audit fix) — cancel_current_check / clear_context
3. Endpoint prioritization — _endpoint_priority_key sort order and moved-count
4. Redundant check skipping — is_check_done / mark_check_done
5. EfficiencySummary model — Pydantic validation and to_summary
6. build_report / pipeline integration — efficiency_tracker flows through correctly
"""

from __future__ import annotations

import threading
import time
from unittest.mock import MagicMock, patch

import pytest

from aegisapi.models.efficiency import EfficiencySummary
from aegisapi.testing.efficiency import EfficiencyTracker


# ---------------------------------------------------------------------------
# 1. EfficiencyTracker — core cache behaviour
# ---------------------------------------------------------------------------


class TestFingerprint:
    def test_same_inputs_same_fingerprint(self):
        fp1 = EfficiencyTracker.make_fingerprint("GET", "http://t.test/a", None, "t:none", True)
        fp2 = EfficiencyTracker.make_fingerprint("GET", "http://t.test/a", None, "t:none", True)
        assert fp1 == fp2

    def test_different_method_different_fingerprint(self):
        fp1 = EfficiencyTracker.make_fingerprint("GET", "http://t.test/a", None, "t:none", True)
        fp2 = EfficiencyTracker.make_fingerprint("POST", "http://t.test/a", None, "t:none", True)
        assert fp1 != fp2

    def test_different_url_different_fingerprint(self):
        fp1 = EfficiencyTracker.make_fingerprint("GET", "http://t.test/a", None, "t:none", True)
        fp2 = EfficiencyTracker.make_fingerprint("GET", "http://t.test/b", None, "t:none", True)
        assert fp1 != fp2

    def test_different_body_different_fingerprint(self):
        fp1 = EfficiencyTracker.make_fingerprint("POST", "http://t.test/", b"a", "t:none", True)
        fp2 = EfficiencyTracker.make_fingerprint("POST", "http://t.test/", b"b", "t:none", True)
        assert fp1 != fp2

    def test_different_auth_context_different_fingerprint(self):
        fp1 = EfficiencyTracker.make_fingerprint("GET", "http://t.test/", None, "t:bearer", True)
        fp2 = EfficiencyTracker.make_fingerprint("GET", "http://t.test/", None, "t:none", True)
        assert fp1 != fp2

    def test_authenticated_flag_affects_fingerprint(self):
        fp1 = EfficiencyTracker.make_fingerprint("GET", "http://t.test/", None, "t:none", True)
        fp2 = EfficiencyTracker.make_fingerprint("GET", "http://t.test/", None, "t:none", False)
        assert fp1 != fp2

    def test_method_case_insensitive(self):
        fp1 = EfficiencyTracker.make_fingerprint("get", "http://t.test/", None, "t:none", True)
        fp2 = EfficiencyTracker.make_fingerprint("GET", "http://t.test/", None, "t:none", True)
        assert fp1 == fp2


class TestGetCache:
    def test_no_cache_hit_on_first_request(self):
        tracker = EfficiencyTracker()
        fp = EfficiencyTracker.make_fingerprint("GET", "http://t.test/h", None, "t:none", True)
        assert tracker.lookup_get(fp) is None

    def test_cache_hit_from_different_check(self):
        tracker = EfficiencyTracker()
        fp = EfficiencyTracker.make_fingerprint("GET", "http://t.test/h", None, "t:none", True)
        fake_response = MagicMock()

        tracker.set_current_check("CHECK-A")
        tracker.record_get(fp, fake_response)

        tracker.set_current_check("CHECK-B")
        result = tracker.lookup_get(fp)
        assert result is fake_response
        assert tracker.cache_hits == 1
        assert tracker.requests_deduped == 1

    def test_no_cache_hit_within_same_check(self):
        """Within-check repeats (e.g. RATE-001) must not be cached."""
        tracker = EfficiencyTracker()
        fp = EfficiencyTracker.make_fingerprint("GET", "http://t.test/h", None, "t:none", True)
        fake_response = MagicMock()

        tracker.set_current_check("RATE-001")
        tracker.record_get(fp, fake_response)
        result = tracker.lookup_get(fp)  # same check
        assert result is None
        assert tracker.cache_hits == 0

    def test_cache_hit_when_no_check_context(self):
        """When set_current_check(None), any fingerprint can be served from cache."""
        tracker = EfficiencyTracker()
        fp = EfficiencyTracker.make_fingerprint("GET", "http://t.test/h", None, "t:none", True)
        fake_response = MagicMock()

        tracker.set_current_check("CHECK-A")
        tracker.record_get(fp, fake_response)

        tracker.set_current_check(None)
        result = tracker.lookup_get(fp)
        assert result is fake_response

    def test_first_sender_wins(self):
        """Second record_get for same fingerprint is ignored."""
        tracker = EfficiencyTracker()
        fp = EfficiencyTracker.make_fingerprint("GET", "http://t.test/h", None, "t:none", True)
        resp1 = MagicMock(name="resp1")
        resp2 = MagicMock(name="resp2")

        tracker.set_current_check("CHECK-A")
        tracker.record_get(fp, resp1)
        tracker.set_current_check("CHECK-B")
        tracker.record_get(fp, resp2)  # should be ignored

        tracker.set_current_check("CHECK-C")
        result = tracker.lookup_get(fp)
        assert result is resp1  # first sender wins

    def test_cache_bounded_at_max_entries(self):
        tracker = EfficiencyTracker(max_entries=3)
        tracker.set_current_check("CHECK-A")
        for i in range(5):
            fp = EfficiencyTracker.make_fingerprint(
                "GET", f"http://t.test/e{i}", None, "t:none", True
            )
            tracker.record_get(fp, MagicMock())
        assert len(tracker._get_cache) == 3

    def test_cross_auth_context_no_reuse(self):
        """Different auth context keys produce different fingerprints."""
        tracker = EfficiencyTracker()
        fp_bearer = EfficiencyTracker.make_fingerprint(
            "GET", "http://t.test/h", None, "t:bearer", True
        )
        fp_none = EfficiencyTracker.make_fingerprint(
            "GET", "http://t.test/h", None, "t:none", True
        )
        resp = MagicMock()
        tracker.set_current_check("CHECK-A")
        tracker.record_get(fp_bearer, resp)

        tracker.set_current_check("CHECK-B")
        # fp_none is a different fingerprint — no cache hit
        assert tracker.lookup_get(fp_none) is None

    def test_multiple_different_checks_all_hit_cache(self):
        tracker = EfficiencyTracker()
        fp = EfficiencyTracker.make_fingerprint("GET", "http://t.test/h", None, "t:none", True)
        resp = MagicMock()

        tracker.set_current_check("CHECK-A")
        tracker.record_get(fp, resp)

        for other in ("CHECK-B", "CHECK-C", "CHECK-D"):
            tracker.set_current_check(other)
            assert tracker.lookup_get(fp) is resp
        assert tracker.cache_hits == 3


# ---------------------------------------------------------------------------
# 2. RequestBudget cancellation (M4 audit fix)
# ---------------------------------------------------------------------------


class TestBudgetCancellation:
    def _make_budget(self, limit: int = 100) -> object:
        from aegisapi.testing.registry import RequestBudget
        return RequestBudget(limit=limit)

    def test_consume_normally(self):
        budget = self._make_budget()
        assert budget.consume(1) is True

    def test_cancel_blocks_consume(self):
        budget = self._make_budget()
        budget.set_context("ep", "CHK")
        budget.cancel_current_check()
        assert budget.consume(1) is False

    def test_clear_context_clears_cancel(self):
        budget = self._make_budget()
        budget.set_context("ep", "CHK")
        budget.cancel_current_check()
        budget.clear_context()
        assert budget.consume(1) is True  # cancel cleared

    def test_cancel_then_clear_then_new_check(self):
        """The cancel flag must not bleed into the next check."""
        budget = self._make_budget()
        budget.set_context("ep", "SLOW-CHECK")
        budget.cancel_current_check()
        budget.clear_context()

        budget.set_context("ep", "NEXT-CHECK")
        assert budget.consume(1) is True
        budget.clear_context()

    def test_cancel_does_not_affect_global_spent(self):
        """Calling cancel_current_check does not change spent count."""
        budget = self._make_budget()
        budget.set_context("ep", "CHK")
        before = budget.spent
        budget.cancel_current_check()
        assert budget.spent == before

    def test_cancel_is_thread_safe(self):
        """M6: cancel_current_check is per-thread (TLS).

        Cancelling in one thread blocks only that thread's consume; other
        threads with their own TLS context are unaffected.
        """
        from aegisapi.testing.registry import RequestBudget
        budget = RequestBudget(limit=1000)

        # Cancel main-thread context — only this thread should be blocked.
        budget.set_context("ep", "CHK-MAIN")
        budget.cancel_current_check()
        assert budget.consume(1) is False, "cancelled thread must return False"

        # Worker threads each set their own context → not cancelled → True.
        worker_results = []
        lock = threading.Lock()

        def worker():
            budget.set_context("ep", "CHK-WORKER")
            result = budget.consume(1)
            with lock:
                worker_results.append(result)
            budget.clear_context()

        threads = [threading.Thread(target=worker) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(worker_results) == 10
        assert all(r is True for r in worker_results), (
            "other threads must not be affected by a different thread's cancellation"
        )


# ---------------------------------------------------------------------------
# 3. Endpoint prioritization
# ---------------------------------------------------------------------------


class TestEndpointPrioritization:
    """Tests for _endpoint_priority_key and the sort in engine.run()."""

    def _make_classified(
        self,
        path: str,
        posture: str = "not_declared",
        in_scope: bool = True,
    ):
        from unittest.mock import MagicMock
        from aegisapi.models.discovery import ScopeClassification
        from aegisapi.models.endpoint import SecurityPosture

        posture_map = {
            "operation_override": SecurityPosture.OPERATION_OVERRIDE,
            "inherited_global": SecurityPosture.INHERITED_GLOBAL,
            "not_declared": SecurityPosture.NOT_DECLARED,
            "explicitly_optional": SecurityPosture.EXPLICITLY_OPTIONAL,
        }

        ep = MagicMock()
        ep.path = path
        ep.key = f"GET {path}"
        sec = MagicMock()
        sec.posture = posture_map[posture]
        ep.declared_security = sec
        classified = MagicMock()
        classified.endpoint = ep
        classified.classification = (
            ScopeClassification.IN_SCOPE if in_scope else ScopeClassification.OUT_OF_SCOPE
        )
        return classified

    def test_in_scope_before_out_of_scope(self):
        from aegisapi.testing.engine import _endpoint_priority_key
        a = self._make_classified("/a", in_scope=False)
        b = self._make_classified("/b", in_scope=True)
        assert _endpoint_priority_key(b) < _endpoint_priority_key(a)

    def test_secured_before_unsecured(self):
        from aegisapi.testing.engine import _endpoint_priority_key
        secured = self._make_classified("/a", posture="operation_override")
        unsecured = self._make_classified("/b", posture="not_declared")
        assert _endpoint_priority_key(secured) < _endpoint_priority_key(unsecured)

    def test_shorter_path_before_longer(self):
        from aegisapi.testing.engine import _endpoint_priority_key
        short = self._make_classified("/users")
        long_ = self._make_classified("/users/profile/settings")
        assert _endpoint_priority_key(short) < _endpoint_priority_key(long_)

    def test_alphabetical_tiebreaker(self):
        from aegisapi.testing.engine import _endpoint_priority_key
        a = self._make_classified("/a")
        b = self._make_classified("/b")
        assert _endpoint_priority_key(a) < _endpoint_priority_key(b)

    def test_sort_is_deterministic(self):
        from aegisapi.testing.engine import _endpoint_priority_key
        endpoints = [
            self._make_classified("/z", posture="not_declared"),
            self._make_classified("/a", posture="operation_override"),
            self._make_classified("/b", posture="not_declared", in_scope=False),
        ]
        sorted1 = sorted(endpoints, key=_endpoint_priority_key)
        sorted2 = sorted(endpoints, key=_endpoint_priority_key)
        assert [ep.endpoint.path for ep in sorted1] == [ep.endpoint.path for ep in sorted2]


# ---------------------------------------------------------------------------
# 4. Redundant check skipping
# ---------------------------------------------------------------------------


class TestRedundantCheckSkipping:
    def test_not_done_initially(self):
        tracker = EfficiencyTracker()
        assert not tracker.is_check_done("CHECK-A", "GET /users")

    def test_done_after_mark(self):
        tracker = EfficiencyTracker()
        tracker.mark_check_done("CHECK-A", "GET /users")
        assert tracker.is_check_done("CHECK-A", "GET /users")

    def test_different_check_id_not_done(self):
        tracker = EfficiencyTracker()
        tracker.mark_check_done("CHECK-A", "GET /users")
        assert not tracker.is_check_done("CHECK-B", "GET /users")

    def test_different_endpoint_not_done(self):
        tracker = EfficiencyTracker()
        tracker.mark_check_done("CHECK-A", "GET /users")
        assert not tracker.is_check_done("CHECK-A", "GET /items")

    def test_redundant_check_counter(self):
        tracker = EfficiencyTracker()
        tracker.record_redundant_check_skipped()
        tracker.record_redundant_check_skipped()
        assert tracker.redundant_checks_skipped == 2

    def test_thread_safe_mark_done(self):
        tracker = EfficiencyTracker()
        pairs = [(f"CHK-{i}", f"GET /ep{i}") for i in range(50)]
        threads = [
            threading.Thread(target=tracker.mark_check_done, args=pair)
            for pair in pairs
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        for pair in pairs:
            assert tracker.is_check_done(*pair)


# ---------------------------------------------------------------------------
# 5. EfficiencySummary model
# ---------------------------------------------------------------------------


class TestEfficiencySummaryModel:
    def test_defaults(self):
        s = EfficiencySummary()
        assert s.requests_deduped == 0
        assert s.cache_hits == 0
        assert s.redundant_checks_skipped == 0
        assert s.endpoints_prioritized == 0
        assert s.total_requests_saved == 0

    def test_all_fields(self):
        s = EfficiencySummary(
            requests_deduped=5,
            cache_hits=5,
            redundant_checks_skipped=2,
            endpoints_prioritized=3,
            total_requests_saved=5,
        )
        assert s.requests_deduped == 5
        assert s.cache_hits == 5
        assert s.redundant_checks_skipped == 2
        assert s.endpoints_prioritized == 3
        assert s.total_requests_saved == 5

    def test_negative_values_rejected(self):
        with pytest.raises(Exception):
            EfficiencySummary(requests_deduped=-1)

    def test_extra_fields_rejected(self):
        with pytest.raises(Exception):
            EfficiencySummary(unknown_field=1)

    def test_to_summary_from_tracker(self):
        tracker = EfficiencyTracker()
        fp = EfficiencyTracker.make_fingerprint("GET", "http://t.test/h", None, "t:none", True)
        resp = MagicMock()

        tracker.set_current_check("CHECK-A")
        tracker.record_get(fp, resp)
        tracker.set_current_check("CHECK-B")
        tracker.lookup_get(fp)
        tracker.record_redundant_check_skipped()
        tracker.endpoints_prioritized = 4

        s = tracker.to_summary()
        assert s.cache_hits == 1
        assert s.requests_deduped == 1
        assert s.redundant_checks_skipped == 1
        assert s.endpoints_prioritized == 4
        assert s.total_requests_saved == 1

    def test_serializes_to_json(self):
        s = EfficiencySummary(requests_deduped=2, cache_hits=2, total_requests_saved=2)
        d = s.model_dump()
        assert d["requests_deduped"] == 2
        assert d["cache_hits"] == 2


# ---------------------------------------------------------------------------
# 6. build_report / pipeline integration
# ---------------------------------------------------------------------------


class TestBuildReportEfficiency:
    def _make_assessment(self, **kwargs):
        from aegisapi.models.assessment import AssessmentResult

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

    def test_build_report_no_tracker_has_no_efficiency_summary(self):
        from aegisapi.reporting.build import build_report

        a = self._make_assessment()
        r = build_report(a)
        assert r.efficiency_summary is None

    def test_build_report_with_tracker_has_efficiency_summary(self):
        from aegisapi.reporting.build import build_report

        a = self._make_assessment()
        tracker = EfficiencyTracker()
        tracker.endpoints_prioritized = 5
        r = build_report(a, efficiency_tracker=tracker)
        assert r.efficiency_summary is not None
        assert r.efficiency_summary.endpoints_prioritized == 5

    def test_efficiency_summary_in_json_serialization(self):
        import json
        from aegisapi.models.common import ReportFormat
        from aegisapi.reporting import render
        from aegisapi.reporting.build import build_report

        a = self._make_assessment()
        tracker = EfficiencyTracker()
        fp = EfficiencyTracker.make_fingerprint("GET", "http://t.test/h", None, "t:none", True)
        tracker.set_current_check("C1")
        tracker.record_get(fp, MagicMock())
        tracker.set_current_check("C2")
        tracker.lookup_get(fp)

        r = build_report(a, efficiency_tracker=tracker)
        json_str = render(r, ReportFormat.JSON)
        parsed = json.loads(json_str)
        assert "efficiency_summary" in parsed
        assert parsed["efficiency_summary"]["cache_hits"] == 1

    def test_efficiency_summary_in_html(self):
        from aegisapi.models.common import ReportFormat
        from aegisapi.reporting import render
        from aegisapi.reporting.build import build_report

        a = self._make_assessment()
        tracker = EfficiencyTracker()
        r = build_report(a, efficiency_tracker=tracker)
        html = render(r, ReportFormat.HTML)
        assert len(html) > 100  # just ensure it renders without error

    def test_report_budget_summary_still_present(self):
        """Efficiency summary must not displace budget_summary."""
        from aegisapi.reporting.build import build_report

        a = self._make_assessment()
        tracker = EfficiencyTracker()
        r = build_report(a, efficiency_tracker=tracker)
        assert r.budget_summary is not None
        assert r.efficiency_summary is not None


class TestTrackerThreadSafety:
    """Stress test: concurrent lookups and records must not corrupt state."""

    def test_concurrent_record_and_lookup(self):
        tracker = EfficiencyTracker(max_entries=50)
        resp = MagicMock()

        def writer(i: int) -> None:
            fp = EfficiencyTracker.make_fingerprint(
                "GET", f"http://t.test/ep{i}", None, "t:none", True
            )
            tracker.set_current_check(f"WRITER-{i}")
            tracker.record_get(fp, resp)

        def reader(i: int) -> None:
            fp = EfficiencyTracker.make_fingerprint(
                "GET", f"http://t.test/ep{i % 10}", None, "t:none", True
            )
            tracker.set_current_check(f"READER-{i}")
            tracker.lookup_get(fp)  # may or may not hit cache

        threads = [threading.Thread(target=writer, args=(i,)) for i in range(30)]
        threads += [threading.Thread(target=reader, args=(i,)) for i in range(30)]

        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # Cache bounded at 50
        assert len(tracker._get_cache) <= 50
        # Metrics are non-negative
        assert tracker.cache_hits >= 0
        assert tracker.requests_deduped >= 0


# ---------------------------------------------------------------------------
# Integration smoke test: scan pipeline with tracker
# ---------------------------------------------------------------------------


class TestScanPipelineEfficiencyIntegration:
    """Light integration test verifying tracker flows from pipeline to report."""

    def test_scan_result_report_has_efficiency_summary(self, tmp_path):
        """Running run_scan() produces a report with an efficiency_summary field."""
        import json
        import threading
        from contextlib import contextmanager
        from http.server import BaseHTTPRequestHandler, HTTPServer

        from aegisapi.core.config import AegisConfig
        from aegisapi.scan.pipeline import ScanOptions, run_scan

        SPEC = {
            "openapi": "3.0.0",
            "info": {"title": "Eff Lab", "version": "1.0.0"},
            "paths": {
                "/api/health": {"get": {"operationId": "health", "responses": {"200": {"description": "ok"}}}},
            },
        }

        class _Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                spec_bytes = json.dumps(SPEC).encode()
                body = b'{"ok": true}'
                resp = spec_bytes if self.path.startswith("/openapi.json") else body
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(resp)))
                self.end_headers()
                self.wfile.write(resp)

            def log_message(self, *a):
                pass

        server = HTTPServer(("127.0.0.1", 0), _Handler)
        t = threading.Thread(target=server.serve_forever, daemon=True)
        t.start()
        port = server.server_address[1]
        url = f"http://127.0.0.1:{port}"
        try:
            opts = ScanOptions(url=url, local_lab=True, budget=200)
            result = run_scan(opts, config=AegisConfig())
            # efficiency_summary should be present
            assert result.report.efficiency_summary is not None
            s = result.report.efficiency_summary
            assert s.requests_deduped >= 0
            assert s.cache_hits >= 0
            assert s.redundant_checks_skipped >= 0
            assert s.total_requests_saved >= 0
        finally:
            server.shutdown()
            server.server_close()


if __name__ == "__main__":
    import sys
    result = pytest.main([__file__, "-v", "--tb=short", "--basetemp", "D:\\pytest-tmp"])
    sys.exit(result)
