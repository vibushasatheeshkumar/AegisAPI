"""The assessment engine: selects endpoints and checks, and runs them safely.

The engine owns everything a check should not have to think about:

* **Endpoint selection.** Only endpoints discovery classified as in scope are
  tested. An out-of-scope or unresolved endpoint produces a ``SKIPPED`` result
  and no request, so the record shows it was considered and declined.
* **The request budget.** Shared across every check, so one talkative check
  cannot consume the run and the total traffic is bounded before it starts.
* **Failure containment.** A check that raises becomes an ``ERROR`` result. One
  broken check does not abandon the assessment, and an exception is never
  mistaken for a finding.
* **One client.** Built once, from the target and the loaded configuration, and
  handed to every check. Checks have no other route to the network.

Checks are registered here rather than by import side effect, so the set of
available checks is a list in one place instead of a function of import order.
"""

from __future__ import annotations

import concurrent.futures
import threading
import time
from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

if TYPE_CHECKING:
    from aegisapi.testing.efficiency import EfficiencyTracker

from aegisapi import __version__
from aegisapi.core.config import AegisConfig
from aegisapi.core.exceptions import AegisAPIError, ScopeViolationError
from aegisapi.core.logging import get_logger
from aegisapi.http import ScopedHttpClient
from aegisapi.models.assessment import (
    AssessmentResult,
    CheckCategory,
    CheckOutcome,
    CheckResult,
    FindingClass,
)
from aegisapi.models.common import Confidence
from aegisapi.models.discovery import (
    ClassifiedEndpoint,
    DiscoveryResult,
    ScopeClassification,
)
from aegisapi.models.target import Target
from aegisapi.testing.authentication import (
    InvalidCredentialCheck,
    SecurityMetadataCheck,
    UnauthenticatedAccessCheck,
)
from aegisapi.testing.authorization import (
    FunctionLevelAuthorizationCheck,
    ObjectLevelAuthorizationCheck,
)
from aegisapi.testing.configuration import (
    AdvertisedMethodsCheck,
    ContentTypeDriftCheck,
    CorsPolicyCheck,
    InformationExposureCheck,
    SecurityHeaderCheck,
)
from aegisapi.testing.auto_fixtures import EndpointFixtures, generate_fixtures
from aegisapi.testing.fixtures import AssessmentFixtures
from aegisapi.testing.input_validation import (
    InvalidEnumValueCheck,
    MissingRequiredParameterCheck,
    WrongTypeParameterCheck,
)
from aegisapi.testing.rate_limits import RateLimitProbeCheck
from aegisapi.testing.schema_validation import (
    ResponseConformanceCheck,
    ResponseSchemaCheck,
)
from aegisapi.testing.registry import REGISTRY, CheckContext, CheckRegistry, RequestBudget
from aegisapi.models.endpoint import SecurityPosture

_logger = get_logger(__name__)


@runtime_checkable
class _EventEmitter(Protocol):
    """Minimal interface the engine uses to emit scan events.

    Accepts the same signature as :meth:`~aegisapi.scan.events.EventDispatcher.emit`
    so that an ``EventDispatcher`` satisfies the protocol without an import.
    """

    def emit(self, event_type: str, **payload: Any) -> None:  # pragma: no cover
        ...


DEFAULT_REQUEST_BUDGET = 60
"""Requests an assessment may send unless the operator raises it.

Sized so a default run against a small API finishes in seconds and could not be
mistaken for a stress test.
"""

ONCE_PER_TARGET_CHECKS: frozenset[str] = frozenset({"CONF-004", "RATE-001"})
"""Checks that answer a question about the deployment, not the operation.

Server software disclosure and rate limiting are properties of the service.
Running them against forty endpoints would send forty times the traffic to
learn the same thing once.
"""


def register_builtin_checks(registry: CheckRegistry) -> CheckRegistry:
    """Register every check AegisAPI ships with.

    Idempotent per registry: registering twice raises, which is what catches a
    duplicate identifier at import time rather than in a report.
    """
    for check in (
        UnauthenticatedAccessCheck(),
        InvalidCredentialCheck(),
        SecurityMetadataCheck(),
        ObjectLevelAuthorizationCheck(),
        FunctionLevelAuthorizationCheck(),
        MissingRequiredParameterCheck(),
        WrongTypeParameterCheck(),
        InvalidEnumValueCheck(),
        SecurityHeaderCheck(),
        CorsPolicyCheck(),
        AdvertisedMethodsCheck(),
        InformationExposureCheck(),
        ContentTypeDriftCheck(),
        RateLimitProbeCheck(),
        ResponseSchemaCheck(),
        ResponseConformanceCheck(),
    ):
        registry.register(check)
    return registry


if not REGISTRY.all():  # pragma: no branch - module-level registration
    register_builtin_checks(REGISTRY)


def _endpoint_priority_key(classified: ClassifiedEndpoint) -> tuple[int, int, int, str]:
    """Sort key for endpoint prioritization.

    Lower values sort first (higher priority). The ordering is:

    1. In-scope before out-of-scope (skipped endpoints at the end).
    2. Endpoints with declared authentication requirements before those without
       (they are more likely to have auth-bypass bugs worth finding first).
    3. Shorter path depth (more fundamental/root-level endpoints).
    4. Alphabetical by endpoint key (deterministic tiebreaker).
    """
    ep = classified.endpoint
    scope_rank = 0 if classified.classification is ScopeClassification.IN_SCOPE else 1
    # Endpoints with an actual security requirement (OPERATION_OVERRIDE or
    # INHERITED_GLOBAL) are higher priority than those with no requirement or
    # explicitly-optional security (which may hide auth-bypass bugs).
    security_rank = (
        0
        if ep.declared_security.posture
        in (SecurityPosture.OPERATION_OVERRIDE, SecurityPosture.INHERITED_GLOBAL)
        else 1
    )
    path_depth = len(ep.path.strip("/").split("/")) if ep.path and ep.path != "/" else 0
    return (scope_rank, security_rank, path_depth, ep.key)


def _skipped_out_of_scope(endpoint: ClassifiedEndpoint, target: Target, reason: str) -> CheckResult:
    """Record that an endpoint was considered and not tested.

    Kept in the results rather than filtered out: a reviewer needs to see that
    an operation the specification declares was left alone, and why.
    """
    return CheckResult(
        check_id="ENGINE-000",
        check_name="Endpoint selection",
        category=CheckCategory.CONFIGURATION,
        target_name=target.name,
        endpoint_key=endpoint.endpoint.key,
        url=endpoint.resolved_url,
        outcome=CheckOutcome.SKIPPED,
        finding_class=FindingClass.NONE,
        summary=reason,
        explanation="No request was sent to this endpoint.",
        limitations=["This operation was not assessed."],
    )


class AssessmentEngine:
    """Runs selected checks against a target's in-scope endpoints."""

    def __init__(
        self,
        *,
        target: Target,
        config: AegisConfig,
        registry: CheckRegistry | None = None,
    ) -> None:
        self._target = target
        self._config = config
        self._registry = registry or REGISTRY

    @property
    def registry(self) -> CheckRegistry:
        """The registry this engine selects from."""
        return self._registry

    def run(
        self,
        *,
        discovery: DiscoveryResult,
        fixtures: AssessmentFixtures | None = None,
        auto_fixtures: dict[str, EndpointFixtures] | None = None,
        categories: Sequence[CheckCategory] | None = None,
        check_ids: Sequence[str] | None = None,
        budget: int = DEFAULT_REQUEST_BUDGET,
        client: ScopedHttpClient | None = None,
        env: Mapping[str, str] | None = None,
        max_endpoints: int | None = None,
        scan_deadline: float | None = None,
        check_timeout_seconds: float | None = None,
        max_per_endpoint: int | None = None,
        max_per_check: int | None = None,
        efficiency_tracker: EfficiencyTracker | None = None,
        max_workers: int = 1,
        event_dispatcher: _EventEmitter | None = None,
    ) -> AssessmentResult:
        """Assess a target using a discovery result.

        Args:
            discovery: The endpoint inventory to work from. Required: AegisAPI
                tests what a specification declares, not paths it guessed.
            fixtures: Operator-declared identities, objects, and expectations.
                Authorization checks skip without them.
            auto_fixtures: Auto-generated path parameter values keyed by
                endpoint key. When provided, templated endpoints that would
                otherwise be skipped by input validation checks can be tested.
                If ``None``, fixtures are generated from ``discovery`` automatically.
            categories: Restrict to these categories.
            check_ids: Restrict to these checks exactly.
            budget: Total requests the run may send.
            client: An injected scoped client, for tests. Production code lets
                the engine build one so limits and scope come from configuration.
            env: Environment mapping for credential resolution.
            max_endpoints: Cap on endpoints considered, for a quick pass.

        Returns:
            An :class:`AssessmentResult` holding every result, including the
            skips.
        """
        declared = fixtures or AssessmentFixtures()
        effective_auto = auto_fixtures if auto_fixtures is not None else generate_fixtures(
            [ep.endpoint for ep in discovery.endpoints]
        )
        selected = self._registry.select(categories=categories, check_ids=check_ids)
        request_budget = RequestBudget(
            limit=max(budget, 0),
            max_per_endpoint=max_per_endpoint,
            max_per_check=max_per_check,
        )

        owns_client = client is None
        active = client or ScopedHttpClient(
            target=self._target,
            settings=self._config.scope,
            limits=self._config.http,
            env=env,
            efficiency_tracker=efficiency_tracker,
        )

        context = CheckContext(
            target=self._target,
            config=self._config,
            client=active,
            budget=request_budget,
            fixtures=declared,
            discovery=discovery,
            env=env,
            auto_fixtures=effective_auto,
            scan_deadline=scan_deadline,
            check_timeout_seconds=check_timeout_seconds,
            efficiency_tracker=efficiency_tracker,
        )

        results: list[CheckResult] = []
        tested_endpoints: set[str] = set()
        # ONCE_PER_TARGET_CHECKS: atomic claim set — a check is added when first
        # claimed so a second worker never starts the same once-per-target check.
        done_once: set[str] = set()
        done_once_lock = threading.Lock()
        checks_timed_out = 0
        scan_timed_out = False
        # M8: progress counters for event dispatch
        checks_completed_count = 0
        progress_lock = threading.Lock()
        total_checks = 0  # set after work_items is built

        # M5: Prioritize endpoints by security impact before the main loop.
        raw_endpoints = list(discovery.endpoints)
        if max_endpoints is not None:
            raw_endpoints = raw_endpoints[:max_endpoints]
        endpoints = sorted(raw_endpoints, key=_endpoint_priority_key)
        if efficiency_tracker is not None:
            moved = sum(
                1
                for i, ep in enumerate(endpoints)
                if ep is not raw_endpoints[i]
                and ep.classification is ScopeClassification.IN_SCOPE
            )
            efficiency_tracker.endpoints_prioritized = moved

        # Thread-safe mutable state for parallel collection
        results_lock = threading.Lock()
        tested_lock = threading.Lock()

        def _collect(
            produced: list[CheckResult],
            check_obj: object,
            classified_ep: ClassifiedEndpoint,
            timed_out: bool,
        ) -> None:
            nonlocal checks_timed_out, checks_completed_count
            with results_lock:
                results.extend(produced)
            if any(item.requests_sent for item in produced):
                with tested_lock:
                    tested_endpoints.add(classified_ep.endpoint.key)
            if timed_out:
                with results_lock:
                    checks_timed_out += 1
            check_id = getattr(check_obj, "check_id", "")
            if check_id in ONCE_PER_TARGET_CHECKS and any(
                item.outcome is not CheckOutcome.SKIPPED for item in produced
            ):
                # Mark done after execution (sequential semantics — no need for
                # lock here because we already claimed it atomically before running)
                pass
            if efficiency_tracker is not None:
                efficiency_tracker.mark_check_done(check_id, classified_ep.endpoint.key)
            # M8: emit events outside all engine locks so handlers cannot deadlock.
            if event_dispatcher is not None:
                for r in produced:
                    if r.is_finding:
                        event_dispatcher.emit(
                            "finding_detected",
                            check_id=r.check_id,
                            check_name=r.check_name,
                            severity=r.severity.value if r.severity else None,
                            finding_class=r.finding_class.value,
                            endpoint_key=r.endpoint_key,
                            url=r.url,
                            summary=r.summary,
                            owasp=r.owasp.identifier if r.owasp else None,
                        )
                with progress_lock:
                    checks_completed_count += 1
                    done = checks_completed_count
                event_dispatcher.emit(
                    "check_completed",
                    check_id=check_id,
                    endpoint_key=classified_ep.endpoint.key,
                    timed_out=timed_out,
                )
                event_dispatcher.emit(
                    "progress_updated",
                    checks_completed=done,
                    checks_total=total_checks,
                )

        def _budget_skip(check_obj: object, ep: ClassifiedEndpoint) -> CheckResult:
            return CheckResult(
                check_id=getattr(check_obj, "check_id", "UNKNOWN"),
                check_name=getattr(check_obj, "name", "unknown"),
                category=getattr(check_obj, "category", CheckCategory.CONFIGURATION),
                target_name=self._target.name,
                endpoint_key=ep.endpoint.key,
                url=ep.resolved_url,
                outcome=CheckOutcome.SKIPPED,
                finding_class=FindingClass.NONE,
                summary="Request budget exhausted before this check ran.",
                explanation="No request was sent.",
                limitations=["Raise --budget to cover more checks."],
            )

        try:
            if not self._target.enabled:
                results.append(
                    CheckResult(
                        check_id="ENGINE-001",
                        check_name="Target state",
                        category=CheckCategory.CONFIGURATION,
                        target_name=self._target.name,
                        endpoint_key="(target)",
                        outcome=CheckOutcome.SKIPPED,
                        finding_class=FindingClass.NONE,
                        summary=f"Target '{self._target.name}' is disabled.",
                        explanation="No requests were sent. Enable the target to assess it.",
                        limitations=["Nothing about this API was assessed."],
                        next_step=(f"aegisapi target update {self._target.name} --enable"),
                    )
                )
                return self._assemble(
                    discovery, selected, results, endpoints, 0, request_budget,
                    scan_timed_out=False, checks_timed_out=0,
                )

            # ── Build the flat work list ────────────────────────────────────
            # Collect (endpoint, check) pairs to execute; handle prefilter results
            # (scope skips, error from applies_to, budget skips) inline here so
            # workers only see items that are ready to run.
            WorkItem = tuple[ClassifiedEndpoint, object]
            work_items: list[WorkItem] = []

            for classified in endpoints:
                if scan_deadline is not None and time.monotonic() > scan_deadline:
                    scan_timed_out = True
                    break

                if classified.classification is not ScopeClassification.IN_SCOPE:
                    with results_lock:
                        results.append(
                            _skipped_out_of_scope(
                                classified,
                                self._target,
                                f"endpoint is {classified.classification.value}: {classified.reason}",
                            )
                        )
                    continue

                for check in selected:
                    # Atomic claim for ONCE_PER_TARGET checks.
                    if check.check_id in ONCE_PER_TARGET_CHECKS:
                        with done_once_lock:
                            if check.check_id in done_once:
                                continue
                            done_once.add(check.check_id)

                    # M5 redundant-check elimination.
                    if efficiency_tracker is not None and efficiency_tracker.is_check_done(
                        check.check_id, classified.endpoint.key
                    ):
                        efficiency_tracker.record_redundant_check_skipped()
                        continue

                    try:
                        applies = check.applies_to(classified.endpoint, context)
                    except Exception as exc:
                        with results_lock:
                            results.append(self._error_result(check, classified, exc))
                        continue
                    if not applies:
                        continue

                    if request_budget.exhausted and check.requests_per_endpoint > 0:
                        with results_lock:
                            results.append(_budget_skip(check, classified))
                        continue

                    work_items.append((classified, check))

            # ── Execute work items (parallel or sequential) ─────────────────
            total_checks = len(work_items)  # M8: used in progress_updated events
            workers = max(max_workers, 1)
            if workers == 1:
                # Sequential path — no thread pool overhead.
                for classified, check in work_items:
                    produced, timed_out = self._execute_work_item(
                        check, classified, context, request_budget,
                        efficiency_tracker, check_timeout_seconds, event_dispatcher,
                    )
                    _collect(produced, check, classified, timed_out)
            else:
                # Parallel path.
                with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
                    fut_map: dict[
                        concurrent.futures.Future[tuple[list[CheckResult], bool]],
                        tuple[ClassifiedEndpoint, object],
                    ] = {}
                    for classified, check in work_items:
                        fut = pool.submit(
                            self._execute_work_item,
                            check, classified, context, request_budget,
                            efficiency_tracker, check_timeout_seconds, event_dispatcher,
                        )
                        fut_map[fut] = (classified, check)

                    for fut in concurrent.futures.as_completed(fut_map):
                        classified, check = fut_map[fut]
                        try:
                            produced, timed_out = fut.result()
                        except Exception as exc:
                            produced = [self._error_result(check, classified, exc)]
                            timed_out = False
                        _collect(produced, check, classified, timed_out)

        finally:
            if owns_client:
                active.close()
            for sibling in context.identity_clients.values():
                if sibling is not active:
                    sibling.close()

        return self._assemble(
            discovery, selected, results, endpoints, len(tested_endpoints), request_budget,
            scan_timed_out=scan_timed_out, checks_timed_out=checks_timed_out,
        )

    def _execute_work_item(
        self,
        check: object,
        classified: ClassifiedEndpoint,
        context: CheckContext,
        budget: RequestBudget,
        efficiency_tracker: EfficiencyTracker | None,
        check_timeout_seconds: float | None,
        event_dispatcher: _EventEmitter | None = None,
    ) -> tuple[list[CheckResult], bool]:
        """Run one (check, endpoint) pair from the **calling thread**.

        Sets TLS context (budget + efficiency tracker) in this thread before the
        check runs, so parallel workers each carry independent context and do not
        clobber each other's per-endpoint / per-check sub-limits.

        Returns ``(results, timed_out)``.
        """
        ep_key = classified.endpoint.key
        check_id = getattr(check, "check_id", "")
        budget.set_context(ep_key, check_id)
        if efficiency_tracker is not None:
            efficiency_tracker.set_current_check(check_id)
        # M8: emit CHECK_STARTED from the worker thread, before the check runs.
        if event_dispatcher is not None:
            event_dispatcher.emit(
                "check_started",
                check_id=check_id,
                endpoint_key=ep_key,
            )
        try:
            if check_timeout_seconds is not None:
                return self._run_check_timed(
                    check, classified, context, budget,
                    check_timeout_seconds, efficiency_tracker,
                )
            return self._run_check(check, classified, context), False
        finally:
            budget.clear_context()
            if efficiency_tracker is not None:
                efficiency_tracker.set_current_check(None)

    def _run_check_timed(
        self,
        check: object,
        classified: ClassifiedEndpoint,
        context: CheckContext,
        budget: RequestBudget,
        timeout_seconds: float,
        efficiency_tracker: EfficiencyTracker | None = None,
    ) -> tuple[list[CheckResult], bool]:
        """Run a check with a wall-clock timeout.

        Returns ``(results, timed_out)``. When the check exceeds
        ``timeout_seconds``, a SKIPPED result is returned and ``timed_out`` is
        ``True``.

        M6: the inner thread registers its own cancel token and sets its own TLS
        context, so cross-thread cancellation works correctly when parallel
        workers each have independent TLS.  On timeout the outer thread sets the
        cancel event; the inner thread's :meth:`~RequestBudget.consume` sees it
        via the cancel-tokens dict and stops sending requests.
        """
        cancel_event = threading.Event()
        ep_key = classified.endpoint.key
        check_id = getattr(check, "check_id", "")

        def _inner() -> list[CheckResult]:
            tid = threading.get_ident()
            # Register cancel token BEFORE setting context so a race where the
            # outer thread times out immediately still signals correctly.
            budget.register_cancel_token(tid, cancel_event)
            budget.set_context(ep_key, check_id)
            if efficiency_tracker is not None:
                efficiency_tracker.set_current_check(check_id)
            try:
                return self._run_check(check, classified, context)
            finally:
                budget.unregister_cancel_token(tid)
                budget.clear_context()
                if efficiency_tracker is not None:
                    efficiency_tracker.set_current_check(None)

        executor = concurrent.futures.ThreadPoolExecutor(max_workers=1)
        future = executor.submit(_inner)
        try:
            produced = future.result(timeout=timeout_seconds)
            return produced, False
        except concurrent.futures.TimeoutError:
            cancel_event.set()
            skipped = CheckResult(
                check_id=check_id or "UNKNOWN",
                check_name=getattr(check, "name", "unknown check"),
                category=getattr(check, "category", CheckCategory.CONFIGURATION),
                target_name=self._target.name,
                endpoint_key=classified.endpoint.key,
                url=classified.resolved_url,
                outcome=CheckOutcome.SKIPPED,
                finding_class=FindingClass.NONE,
                summary="Check exceeded the per-check time limit and was skipped.",
                explanation="No conclusion can be drawn from a check that timed out.",
                limitations=["This operation was not fully assessed; raise --check-timeout to test it."],
            )
            return [skipped], True
        finally:
            executor.shutdown(wait=False)

    def _run_check(
        self,
        check: object,
        classified: ClassifiedEndpoint,
        context: CheckContext,
    ) -> list[CheckResult]:
        """Run one check, converting any failure into an ERROR result."""
        try:
            return list(check.run(classified, context))  # type: ignore[attr-defined]
        except ScopeViolationError as exc:
            # A check tried to reach something out of scope. The request was
            # refused before transmission; the result records the attempt so the
            # check can be fixed.
            _logger.warning(
                "Check %s attempted an out-of-scope request: %s",
                getattr(check, "check_id", "?"),
                exc.message,
            )
            return [self._error_result(check, classified, exc, scope_violation=True)]
        except AegisAPIError as exc:
            return [self._error_result(check, classified, exc)]
        except Exception as exc:  # one broken check must not end the run
            _logger.error(
                "Check %s raised an unexpected error",
                getattr(check, "check_id", "?"),
                exc_info=True,
            )
            return [self._error_result(check, classified, exc)]

    def _error_result(
        self,
        check: object,
        classified: ClassifiedEndpoint,
        exc: BaseException,
        *,
        scope_violation: bool = False,
    ) -> CheckResult:
        """Build an ERROR result for a check that failed."""
        message = getattr(exc, "message", None) or f"{type(exc).__name__}: {exc}"
        return CheckResult(
            check_id=getattr(check, "check_id", "UNKNOWN"),
            check_name=getattr(check, "name", "unknown check"),
            category=getattr(check, "category", CheckCategory.CONFIGURATION),
            target_name=self._target.name,
            endpoint_key=classified.endpoint.key,
            url=classified.resolved_url,
            outcome=CheckOutcome.ERROR,
            finding_class=FindingClass.INCONCLUSIVE,
            confidence=Confidence.LOW,
            summary=(
                "The check attempted an out-of-scope request and was refused."
                if scope_violation
                else "The check did not complete."
            ),
            explanation=message,
            limitations=[
                "This result says nothing about the API's security.",
                "No conclusion should be drawn from a check that errored.",
            ],
        )

    def _assemble(
        self,
        discovery: DiscoveryResult,
        selected: Sequence[object],
        results: list[CheckResult],
        endpoints: Sequence[ClassifiedEndpoint],
        tested: int,
        budget: RequestBudget,
        *,
        scan_timed_out: bool = False,
        checks_timed_out: int = 0,
    ) -> AssessmentResult:
        """Build the assessment document."""
        return AssessmentResult(
            target_name=self._target.name,
            target_base_url=self._target.base_url,
            results=results,
            checks_run=[getattr(item, "check_id", "?") for item in selected],
            endpoints_considered=len(endpoints),
            endpoints_tested=tested,
            requests_sent=budget.spent,
            request_budget=budget.limit,
            budget_exhausted=budget.exhausted and budget.limit > 0,
            specification_sha256=discovery.specification.source_sha256,
            aegisapi_version=__version__,
            scan_timed_out=scan_timed_out,
            endpoints_at_limit=budget.endpoints_at_limit,
            checks_timed_out=checks_timed_out,
        )


__all__ = [
    "DEFAULT_REQUEST_BUDGET",
    "ONCE_PER_TARGET_CHECKS",
    "AssessmentEngine",
    "register_builtin_checks",
]
