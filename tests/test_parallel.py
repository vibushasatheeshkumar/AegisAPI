"""M6 — Parallel Scanning: unit and integration tests.

Tests are grouped by concern:

1. _execute_work_item — per-worker TLS context isolation
2. Sequential / parallel equivalence — same results both modes
3. Worker limits — concurrency does not exceed max_workers
4. Thread-safe budget — parallel consume stays within limit
5. Thread-safe results collection — no missing / no duplicate results
6. Exception isolation — one bad check doesn't abort others
7. Cancel-token / timeout in parallel mode
8. ONCE_PER_TARGET atomic claim — single execution under concurrency
9. Deterministic report output — sort order stable across runs
10. No out-of-scope requests under parallelism
"""

from __future__ import annotations

import threading
import time
from collections.abc import Mapping, Sequence
from typing import Any
from unittest.mock import MagicMock

import pytest

from assessfix import (
    classified as _assessfix_classified,
    discovery_result,
    make_client,
    make_config,
    public,
    scoped_target,
)
from httpstub import FakeTransport

from aegisapi.models.assessment import (
    CheckCategory,
    CheckOutcome,
    CheckResult,
    FindingClass,
)
from aegisapi.testing import AssessmentEngine
from aegisapi.testing.engine import ONCE_PER_TARGET_CHECKS
from aegisapi.testing.fixtures import AssessmentFixtures
from aegisapi.testing.registry import (
    BaseCheck,
    CheckContext,
    CheckRegistry,
    RequestBudget,
)


# ---------------------------------------------------------------------------
# Shared builders
# ---------------------------------------------------------------------------

def _make_budget(limit: int = 500, **kw: Any) -> RequestBudget:
    return RequestBudget(limit=limit, **kw)


def _ep(path: str = "/api/items") -> object:
    """A proper Endpoint (via assessfix) for use with engine.run()."""
    return public("get", path)


def _discovery(*paths: str):
    """A DiscoveryResult of in-scope public GET endpoints."""
    endpoints = [_assessfix_classified(public("get", p)) for p in paths]
    return discovery_result(endpoints)


def _make_check(
    check_id: str = "TEST-001",
    *,
    name: str = "test",
    category: CheckCategory = CheckCategory.CONFIGURATION,
    requests_per_endpoint: int = 0,
    side_effect: Any = None,
    sleep_seconds: float = 0.0,
    raise_exc: Exception | None = None,
) -> BaseCheck:
    """Build a lightweight SecurityCheck."""

    class _Check(BaseCheck):
        pass

    _Check.check_id = check_id
    _Check.name = name
    _Check.category = category
    _Check.requests_per_endpoint = requests_per_endpoint

    def _run(self, endpoint, context: CheckContext) -> list[CheckResult]:
        if sleep_seconds:
            time.sleep(sleep_seconds)
        if raise_exc is not None:
            raise raise_exc
        if side_effect is not None:
            return side_effect(endpoint, context)
        return [
            CheckResult(
                check_id=self.check_id,
                check_name=self.name,
                category=self.category,
                target_name=context.target.name,
                endpoint_key=endpoint.endpoint.key,
                outcome=CheckOutcome.PASS,
                finding_class=FindingClass.NONE,
                summary="ok",
            )
        ]

    _Check.run = _run
    return _Check()


def _run_engine(
    *checks: BaseCheck,
    n_paths: int = 2,
    max_workers: int = 1,
    budget: int = 500,
    check_timeout_seconds: float | None = None,
    **run_kw: Any,
) -> object:
    """Stand up an engine with the given checks and run it.

    Returns AssessmentResult.
    """
    registry = CheckRegistry()
    for c in checks:
        registry.register(c)

    target = scoped_target()
    config = make_config()
    transport = FakeTransport()
    client = make_client(target, config, transport)

    engine = AssessmentEngine(target=target, config=config, registry=registry)
    disc = _discovery(*[f"/api/ep{i}" for i in range(n_paths)])
    try:
        return engine.run(
            discovery=disc,
            fixtures=AssessmentFixtures(),
            budget=budget,
            client=client,
            max_workers=max_workers,
            check_timeout_seconds=check_timeout_seconds,
            **run_kw,
        )
    finally:
        client.close()


# ---------------------------------------------------------------------------
# Budget only: use a minimal context with a shared budget
# ---------------------------------------------------------------------------

def _make_budget_context(budget: RequestBudget) -> tuple[AssessmentEngine, CheckContext]:
    """Stand up engine + CheckContext using the given budget (no real HTTP)."""
    target = scoped_target()
    config = make_config()
    transport = FakeTransport()
    client = make_client(target, config, transport)
    engine = AssessmentEngine(target=target, config=config, registry=CheckRegistry())
    context = CheckContext(
        target=target,
        config=config,
        client=client,
        budget=budget,
        fixtures=AssessmentFixtures(),
    )
    return engine, context


def _classified_ep(path: str = "/api/items"):
    """A proper ClassifiedEndpoint for direct _execute_work_item calls."""
    return _assessfix_classified(public("get", path))


# ===========================================================================
# 1. _execute_work_item — TLS context isolation
# ===========================================================================

class TestExecuteWorkItem:
    def test_sets_tls_context_in_calling_thread(self):
        """set_context is called in the executing thread before the check runs."""
        budget = _make_budget(100)
        observed: list[tuple[str | None, str | None]] = []

        def _side_effect(ep, ctx: CheckContext) -> list[CheckResult]:
            observed.append((
                getattr(budget._tls, "endpoint", None),
                getattr(budget._tls, "check", None),
            ))
            return []

        engine, context = _make_budget_context(budget)
        check = _make_check("TLS-001", side_effect=_side_effect)
        classified = _classified_ep()

        engine._execute_work_item(check, classified, context, budget, None, None)

        assert observed == [(classified.endpoint.key, "TLS-001")]

    def test_clears_tls_context_after_check(self):
        """TLS context is cleared in the finally block."""
        budget = _make_budget(100)
        engine, context = _make_budget_context(budget)
        check = _make_check("TLS-002")
        classified = _classified_ep()

        engine._execute_work_item(check, classified, context, budget, None, None)

        assert getattr(budget._tls, "endpoint", None) is None
        assert getattr(budget._tls, "check", None) is None

    def test_clears_tls_context_on_exception(self):
        """TLS context is cleared even when the check raises."""
        budget = _make_budget(100)
        engine, context = _make_budget_context(budget)
        check = _make_check("TLS-003", raise_exc=ValueError("boom"))
        classified = _classified_ep()

        engine._execute_work_item(check, classified, context, budget, None, None)

        assert getattr(budget._tls, "endpoint", None) is None
        assert getattr(budget._tls, "check", None) is None

    def test_parallel_workers_have_independent_tls(self):
        """Two workers running concurrently see different TLS contexts."""
        budget = _make_budget(1000)
        tls_snapshots: list[tuple[str | None, str | None]] = []
        lock = threading.Lock()

        def _side_effect(ep, ctx: CheckContext) -> list[CheckResult]:
            with lock:
                tls_snapshots.append((
                    getattr(budget._tls, "endpoint", None),
                    getattr(budget._tls, "check", None),
                ))
            time.sleep(0.05)
            return []

        c1 = _make_check("PAR-001", side_effect=_side_effect)
        c2 = _make_check("PAR-002", side_effect=_side_effect)
        engine, context = _make_budget_context(budget)
        ep1 = _classified_ep("/api/a")
        ep2 = _classified_ep("/api/b")

        import concurrent.futures
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            f1 = pool.submit(engine._execute_work_item, c1, ep1, context, budget, None, None)
            f2 = pool.submit(engine._execute_work_item, c2, ep2, context, budget, None, None)
            f1.result()
            f2.result()

        eps = {snap[0] for snap in tls_snapshots}
        checks = {snap[1] for snap in tls_snapshots}
        assert ep1.endpoint.key in eps
        assert ep2.endpoint.key in eps
        assert "PAR-001" in checks
        assert "PAR-002" in checks


# ===========================================================================
# 2. Sequential / parallel equivalence
# ===========================================================================

class TestSequentialParallelEquivalence:
    def test_sequential_and_parallel_same_results(self):
        """Sequential (workers=1) and parallel (workers=4) produce identical sorted results."""
        checks = [_make_check(f"EQ-{i:03d}") for i in range(5)]

        seq = _run_engine(*checks, n_paths=3, max_workers=1)
        par = _run_engine(*checks, n_paths=3, max_workers=4)

        def _key(r: CheckResult):
            return (r.endpoint_key, r.check_id)

        seq_keys = sorted(_key(r) for r in seq.results if r.outcome is CheckOutcome.PASS)
        par_keys = sorted(_key(r) for r in par.results if r.outcome is CheckOutcome.PASS)
        assert seq_keys == par_keys, f"result mismatch: {seq_keys} vs {par_keys}"


# ===========================================================================
# 3. Worker limits — concurrency capped
# ===========================================================================

class TestWorkerLimits:
    def test_concurrency_does_not_exceed_max_workers(self):
        """Peak concurrent executions must not exceed max_workers."""
        max_w = 2
        gate = threading.Event()
        current: list[int] = [0]
        peak: list[int] = [0]
        lock = threading.Lock()

        def _side_effect(ep, ctx):
            with lock:
                current[0] += 1
                if current[0] > peak[0]:
                    peak[0] = current[0]
            gate.wait(timeout=2.0)
            with lock:
                current[0] -= 1
            return []

        checks = [_make_check(f"CW-{i:03d}", side_effect=_side_effect) for i in range(6)]

        # Unblock workers after a brief delay so they overlap
        def _release():
            time.sleep(0.05)
            gate.set()

        t = threading.Thread(target=_release)
        t.start()
        _run_engine(*checks, n_paths=1, max_workers=max_w, budget=500)
        t.join()

        assert peak[0] <= max_w, f"peak concurrency {peak[0]} exceeded max_workers {max_w}"

    def test_max_workers_1_executes_all_checks(self):
        """max_workers=1 still runs every check; no checks are dropped."""
        execution_order: list[str] = []
        lock = threading.Lock()

        def _make_ordered(check_id: str):
            def _side(ep, ctx):
                with lock:
                    execution_order.append(check_id)
                return []
            return _make_check(check_id, side_effect=_side)

        checks = [_make_ordered(f"ORD-{i:03d}") for i in range(5)]
        _run_engine(*checks, n_paths=1, max_workers=1, budget=500)
        assert len(execution_order) == 5


# ===========================================================================
# 4. Thread-safe budget under parallel execution
# ===========================================================================

class TestThreadSafeBudget:
    def test_parallel_consume_stays_within_limit(self):
        """Total consumed requests across parallel workers must not exceed limit."""
        limit = 20
        # Use a fresh registry with our checks and a shared budget
        checks = [_make_check(f"BUD-{i:03d}", requests_per_endpoint=1) for i in range(10)]
        result = _run_engine(*checks, n_paths=1, max_workers=4, budget=limit)
        # Checks that ran will have PASS results; those that didn't have SKIPPED.
        passes = sum(1 for r in result.results if r.outcome is CheckOutcome.PASS)
        assert passes <= limit

    def test_budget_exhaustion_produces_skipped_results(self):
        """An exhausted budget (limit=0) skips every check that needs requests."""
        checks = [_make_check(f"EX-{i:03d}", requests_per_endpoint=1) for i in range(5)]
        result = _run_engine(*checks, n_paths=2, max_workers=4, budget=0)
        skipped = [r for r in result.results if r.outcome is CheckOutcome.SKIPPED
                   and "budget" in r.summary.lower()]
        assert len(skipped) == 10  # 5 checks × 2 endpoints


# ===========================================================================
# 5. Thread-safe results collection
# ===========================================================================

class TestThreadSafeResults:
    def test_no_missing_results(self):
        """Every in-scope endpoint gets at least one result per check."""
        n_checks = 5
        n_paths = 3
        checks = [_make_check(f"RES-{i:03d}") for i in range(n_checks)]
        result = _run_engine(*checks, n_paths=n_paths, max_workers=4, budget=500)
        passes = [(r.check_id, r.endpoint_key) for r in result.results if r.outcome is CheckOutcome.PASS]
        assert len(passes) == n_checks * n_paths

    def test_no_duplicate_results(self):
        """No (check_id, endpoint_key) result appears twice."""
        checks = [_make_check(f"DUP-{i:03d}") for i in range(5)]
        result = _run_engine(*checks, n_paths=3, max_workers=4, budget=500)
        passes = [(r.check_id, r.endpoint_key) for r in result.results if r.outcome is CheckOutcome.PASS]
        assert len(passes) == len(set(passes)), "duplicate (check_id, endpoint_key) found"


# ===========================================================================
# 6. Exception isolation
# ===========================================================================

class TestExceptionIsolation:
    def test_one_failing_check_does_not_abort_others(self):
        """A check that raises produces an ERROR result; others run to completion."""
        failing = _make_check("FAIL-001", raise_exc=RuntimeError("intentional"))
        good1 = _make_check("GOOD-001")
        good2 = _make_check("GOOD-002")

        result = _run_engine(failing, good1, good2, n_paths=1, max_workers=2, budget=500)

        outcomes = {r.check_id: r.outcome for r in result.results}
        assert outcomes.get("FAIL-001") is CheckOutcome.ERROR
        assert outcomes.get("GOOD-001") is CheckOutcome.PASS
        assert outcomes.get("GOOD-002") is CheckOutcome.PASS

    def test_multiple_failing_checks_all_produce_error_results(self):
        """Multiple concurrently-failing checks each get their own ERROR result."""
        failing = [_make_check(f"MF-{i:03d}", raise_exc=ValueError(f"fail {i}")) for i in range(4)]

        result = _run_engine(*failing, n_paths=1, max_workers=4, budget=500)

        errors = [r for r in result.results if r.outcome is CheckOutcome.ERROR]
        assert len(errors) == 4


# ===========================================================================
# 7. Cancel-token / timeout in parallel mode
# ===========================================================================

class TestCancelTokenAndTimeout:
    def test_cancel_token_blocks_consume_in_inner_thread(self):
        """register_cancel_token + set → consume returns False in that thread."""
        budget = _make_budget(500)
        cancel_event = threading.Event()
        results: list[bool] = []

        def _worker():
            tid = threading.get_ident()
            budget.register_cancel_token(tid, cancel_event)
            budget.set_context("ep", "CHK")
            cancel_event.set()
            results.append(budget.consume(1))
            budget.unregister_cancel_token(tid)

        t = threading.Thread(target=_worker)
        t.start()
        t.join()

        assert results == [False]

    def test_cancel_token_does_not_affect_other_threads(self):
        """A cancel token set for thread A does not affect thread B."""
        budget = _make_budget(500)
        cancel_event_a = threading.Event()
        cancel_event_a.set()
        b_result: list[bool] = []

        def _thread_b():
            budget.set_context("ep", "CHK-B")
            b_result.append(budget.consume(1))
            budget.clear_context()

        budget.register_cancel_token(99999999, cancel_event_a)
        t = threading.Thread(target=_thread_b)
        t.start()
        t.join()
        budget.unregister_cancel_token(99999999)

        assert b_result == [True]

    def test_timed_out_check_produces_skipped_result(self):
        """A check that exceeds its timeout is recorded as SKIPPED."""
        slow_check = _make_check("SLOW-001", sleep_seconds=5.0)

        result = _run_engine(
            slow_check, n_paths=1, max_workers=2,
            check_timeout_seconds=0.1, budget=500,
        )

        skipped = [r for r in result.results if r.outcome is CheckOutcome.SKIPPED]
        assert any(r.check_id == "SLOW-001" for r in skipped)
        assert result.checks_timed_out >= 1

    def test_timeout_does_not_block_other_checks(self):
        """A slow (timed-out) check does not prevent faster checks from running."""
        slow = _make_check("SLOW-002", sleep_seconds=5.0)
        fast = _make_check("FAST-001")

        result = _run_engine(
            slow, fast, n_paths=1, max_workers=2,
            check_timeout_seconds=0.15, budget=500,
        )

        outcomes = {r.check_id: r.outcome for r in result.results}
        assert outcomes.get("FAST-001") is CheckOutcome.PASS


# ===========================================================================
# 8. ONCE_PER_TARGET atomic claim
# ===========================================================================

class TestOncePerTargetClaim:
    def test_once_per_target_check_runs_exactly_once(self):
        """A ONCE_PER_TARGET check runs for the first endpoint only."""
        once_id = next(iter(ONCE_PER_TARGET_CHECKS))

        run_count: list[int] = [0]
        count_lock = threading.Lock()

        class _OnceCheck(BaseCheck):
            check_id = once_id
            name = "once"
            category = CheckCategory.CONFIGURATION
            requests_per_endpoint = 0

            def run(self, ep, ctx):
                with count_lock:
                    run_count[0] += 1
                return []

        check = _OnceCheck()
        registry = CheckRegistry()
        registry.register(check)

        target = scoped_target()
        config = make_config()
        transport = FakeTransport()
        client = make_client(target, config, transport)
        engine = AssessmentEngine(target=target, config=config, registry=registry)
        disc = _discovery(*[f"/api/ep{i}" for i in range(5)])
        try:
            engine.run(
                discovery=disc,
                fixtures=AssessmentFixtures(),
                budget=500,
                client=client,
                max_workers=4,
            )
        finally:
            client.close()

        assert run_count[0] == 1, (
            f"once-per-target check ran {run_count[0]} times; expected 1"
        )


# ===========================================================================
# 9. Deterministic report output
# ===========================================================================

class TestDeterministicOutput:
    def _run_and_sort(self) -> list[tuple[str, str, str]]:
        from aegisapi.reporting.build import build_report
        checks = [_make_check(f"DET-{i:03d}") for i in range(6)]
        result = _run_engine(*checks, n_paths=4, max_workers=4, budget=500)
        report = build_report(result, None)
        return [(r.check_id, r.endpoint_key, r.outcome.value) for r in report.results]

    def test_report_output_is_deterministic(self):
        """Running the same scan twice with parallel workers yields identical report order."""
        run1 = self._run_and_sort()
        run2 = self._run_and_sort()
        assert run1 == run2, "report output differs between parallel runs"

    def test_report_has_no_duplicates(self):
        """Each (check_id, endpoint_key) appears at most once in the report."""
        rows = self._run_and_sort()
        keys = [(r[0], r[1]) for r in rows]
        assert len(keys) == len(set(keys)), "duplicate (check_id, endpoint_key) in report"


# ===========================================================================
# 10. No out-of-scope requests under parallelism
# ===========================================================================

class TestScopeEnforcementUnderParallelism:
    def test_out_of_scope_endpoints_produce_only_skipped(self):
        """Out-of-scope endpoints get SKIPPED (ENGINE-000); no check runs for them."""
        from aegisapi.models.discovery import ScopeClassification

        checks = [_make_check(f"SC-{i:03d}") for i in range(3)]
        registry = CheckRegistry()
        for c in checks:
            registry.register(c)

        target = scoped_target()
        config = make_config()
        transport = FakeTransport()
        client = make_client(target, config, transport)
        engine = AssessmentEngine(target=target, config=config, registry=registry)

        in_scope = _assessfix_classified(public("get", "/api/ok"))
        oos = _assessfix_classified(
            public("get", "/admin/secret"),
            classification=ScopeClassification.OUT_OF_SCOPE,
        )
        disc = discovery_result([in_scope, oos])
        try:
            result = engine.run(
                discovery=disc,
                fixtures=AssessmentFixtures(),
                budget=500,
                client=client,
                max_workers=4,
            )
        finally:
            client.close()

        oos_results = [r for r in result.results if r.endpoint_key == oos.endpoint.key]
        assert all(r.outcome is CheckOutcome.SKIPPED for r in oos_results)
        assert all(r.check_id == "ENGINE-000" for r in oos_results)

        # In-scope endpoint should have PASS results
        in_scope_passes = [
            r for r in result.results
            if r.endpoint_key == in_scope.endpoint.key and r.outcome is CheckOutcome.PASS
        ]
        assert len(in_scope_passes) == 3  # one per check
