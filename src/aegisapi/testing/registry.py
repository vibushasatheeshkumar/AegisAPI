"""What a security check is, and how checks are selected.

A check is a small object with a declared contract: an identifier, a category,
the endpoint metadata it needs, and a ``run`` method that returns results. The
engine owns the request budget, the client, and error handling, so a check
contains only its own reasoning.

The important rule is in :class:`CheckContext`: a check receives a
:class:`~aegisapi.http.ScopedHttpClient` and has no other way to reach the
network. It cannot build a transport, cannot widen scope, and cannot skip the
pre-transmission checks, because it is never handed anything that would let it.
"""

from __future__ import annotations

import threading
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from aegisapi.testing.efficiency import EfficiencyTracker

from aegisapi.core.config import AegisConfig
from aegisapi.core.exceptions import InvalidTargetError
from aegisapi.http import ScopedHttpClient
from aegisapi.models.assessment import (
    CheckCategory,
    CheckOutcome,
    CheckResult,
    Evidence,
    FindingClass,
)
from aegisapi.models.common import Confidence, Severity
from aegisapi.models.discovery import ClassifiedEndpoint, DiscoveryResult
from aegisapi.models.endpoint import Endpoint
from aegisapi.models.http import HttpMethod
from aegisapi.models.target import Target
from aegisapi.testing.auto_fixtures import EndpointFixtures
from aegisapi.testing.fixtures import AssessmentFixtures, AssessmentIdentity
from aegisapi.testing.knowledge import knowledge_for

SAFE_METHODS: frozenset[HttpMethod] = frozenset(
    {HttpMethod.GET, HttpMethod.HEAD, HttpMethod.OPTIONS}
)
"""Methods a check may send without an explicit opt-in.

Read-shaped only. A POST during an assessment can create a record, a DELETE can
remove one, and neither belongs in a default run.
"""


@dataclass
class RequestBudget:
    """A hard ceiling on how many requests an assessment may send.

    Shared by every check, so no single check can consume the run. A budget is
    the difference between an assessment and a load test.

    Optional per-endpoint and per-check sub-limits are enforced after the global
    limit: ``set_context`` registers which endpoint and check is currently
    running so ``consume`` can apply the right cap. Thread-safe: the per-check
    timeout in the engine runs checks in background threads.
    """

    limit: int
    spent: int = 0
    max_per_endpoint: int | None = None
    max_per_check: int | None = None

    def __post_init__(self) -> None:
        self._per_endpoint: dict[str, int] = {}
        self._per_check: dict[str, int] = {}
        self._endpoints_at_limit: set[str] = set()
        self._lock: threading.Lock = threading.Lock()
        # M6: thread-local context so parallel workers do not clobber each other.
        # Each worker thread stores its own (endpoint, check, cancelled) state here.
        self._tls: threading.local = threading.local()
        # Per-thread cancel tokens registered by _run_check_timed for cross-thread
        # cancellation.  Keyed by thread id; value is a threading.Event.
        self._cancel_tokens: dict[int, threading.Event] = {}
        self._cancel_tokens_lock: threading.Lock = threading.Lock()

    @property
    def remaining(self) -> int:
        """Requests still available."""
        return max(self.limit - self.spent, 0)

    @property
    def exhausted(self) -> bool:
        """``True`` when nothing further may be sent."""
        return self.remaining <= 0

    @property
    def endpoints_at_limit(self) -> list[str]:
        """Endpoint keys that have reached their per-endpoint cap."""
        with self._lock:
            return sorted(self._endpoints_at_limit)

    def set_context(self, endpoint_key: str, check_id: str) -> None:
        """Register the endpoint and check for the **calling thread**.

        M6: thread-local so parallel workers each track their own context
        independently.  Must be called from the thread that will subsequently
        call :meth:`consume` (i.e. the check-runner thread, not the dispatcher).
        """
        self._tls.endpoint = endpoint_key
        self._tls.check = check_id
        self._tls.cancelled = False

    def cancel_current_check(self) -> None:
        """Signal that the **calling thread's** current check should stop.

        In sequential mode this is called from the same thread that runs the
        check, so the TLS flag is enough.  In M6 parallel mode,
        :meth:`_run_check_timed` registers a cross-thread
        :class:`~threading.Event` via :meth:`register_cancel_token` and uses
        that directly instead of calling this method.  This method therefore
        doubles as a fallback for callers that do not use the cancel-token API.
        """
        tid = threading.get_ident()
        with self._cancel_tokens_lock:
            token = self._cancel_tokens.get(tid)
        if token is not None:
            token.set()
        else:
            self._tls.cancelled = True

    def clear_context(self) -> None:
        """Clear this thread's endpoint/check context after a check finishes."""
        self._tls.endpoint = None
        self._tls.check = None
        self._tls.cancelled = False

    def register_cancel_token(self, thread_id: int, event: threading.Event) -> None:
        """Register a cross-thread cancel signal for *thread_id*.

        Called by :meth:`~aegisapi.testing.engine.AssessmentEngine._run_check_timed`
        for the inner worker thread so that a timeout can be signalled from the
        outer thread without touching TLS.
        """
        with self._cancel_tokens_lock:
            self._cancel_tokens[thread_id] = event

    def unregister_cancel_token(self, thread_id: int) -> None:
        """Remove the cancel token for *thread_id* when the check finishes."""
        with self._cancel_tokens_lock:
            self._cancel_tokens.pop(thread_id, None)

    def consume(self, count: int = 1) -> bool:
        """Reserve ``count`` requests, returning whether they were available.

        Checks the per-thread TLS cancellation flags and registered cancel
        tokens first (fast path, no lock), then the global limit, then
        per-endpoint and per-check sub-limits read from thread-local context.
        If a per-endpoint cap is reached, the endpoint key is recorded in
        ``endpoints_at_limit``.
        """
        # Fast per-thread cancellation checks (no lock needed).
        if getattr(self._tls, "cancelled", False):
            return False
        tid = threading.get_ident()
        with self._cancel_tokens_lock:
            token = self._cancel_tokens.get(tid)
        if token is not None and token.is_set():
            return False

        with self._lock:
            if self.remaining < count:
                return False

            # Read sub-limit context from TLS (each thread has its own).
            ep: str | None = getattr(self._tls, "endpoint", None)
            ck: str | None = getattr(self._tls, "check", None)

            if ep is not None and self.max_per_endpoint is not None:
                ep_spent = self._per_endpoint.get(ep, 0)
                if ep_spent + count > self.max_per_endpoint:
                    self._endpoints_at_limit.add(ep)
                    return False

            if ck is not None and self.max_per_check is not None:
                ck_spent = self._per_check.get(ck, 0)
                if ck_spent + count > self.max_per_check:
                    return False

            self.spent += count
            if ep is not None:
                self._per_endpoint[ep] = self._per_endpoint.get(ep, 0) + count
            if ck is not None:
                self._per_check[ck] = self._per_check.get(ck, 0) + count
            return True


@dataclass
class CheckContext:
    """Everything a check is allowed to use.

    The client is the only route to the network. ``fixtures`` carries whatever
    ground truth the operator declared, and checks that need some and do not
    find it must skip rather than guess.
    """

    target: Target
    config: AegisConfig
    client: ScopedHttpClient
    budget: RequestBudget
    fixtures: AssessmentFixtures
    discovery: DiscoveryResult | None = None
    env: Mapping[str, str] | None = None
    identity_clients: dict[str, ScopedHttpClient] = field(default_factory=dict)
    auto_fixtures: dict[str, EndpointFixtures] = field(default_factory=dict)
    scan_deadline: float | None = None
    check_timeout_seconds: float | None = None
    efficiency_tracker: EfficiencyTracker | None = None

    def client_for(self, identity: AssessmentIdentity) -> ScopedHttpClient:
        """A scoped client that authenticates as one declared identity.

        Built by swapping the target's authentication profile, which keeps every
        other guarantee - scope gates, limits, redaction - exactly as
        configured. Credentials still resolve through the identity's
        environment references at the moment of use.
        """
        existing = self.identity_clients.get(identity.name)
        if existing is not None:
            return existing

        try:
            as_identity = self.target.model_copy(update={"auth": identity.auth})
        except Exception as exc:  # pragma: no cover - defensive
            raise InvalidTargetError(
                f"Identity {identity.name!r} could not be applied to the target.",
                hint=str(exc),
            ) from exc

        client = ScopedHttpClient(
            target=as_identity,
            settings=self.config.scope,
            limits=self.config.http,
            transport=self.client.transport_for_reuse,
            throttle=self.client.throttle,
            env=self.env,
            efficiency_tracker=self.efficiency_tracker,
        )
        self.identity_clients[identity.name] = client
        return client


class SecurityCheck(Protocol):
    """The contract every check implements."""

    check_id: str
    name: str
    description: str
    category: CheckCategory
    requests_per_endpoint: int

    def applies_to(self, endpoint: Endpoint, context: CheckContext) -> bool:
        """Whether this check has what it needs for this operation."""
        ...

    def run(self, endpoint: ClassifiedEndpoint, context: CheckContext) -> list[CheckResult]:
        """Execute the check and return its results."""
        ...


class BaseCheck:
    """Shared plumbing for checks: identity, and result construction.

    Not an abstraction for its own sake - every check needs to build results
    with the same fields, and doing it in one place is what keeps limitations
    from being forgotten on a finding.
    """

    check_id: str = "BASE-000"
    name: str = "base"
    description: str = ""
    category: CheckCategory = CheckCategory.CONFIGURATION
    requests_per_endpoint: int = 1

    def applies_to(self, endpoint: Endpoint, context: CheckContext) -> bool:
        """Default: applies to read-shaped operations only."""
        del context
        return _transport_method(endpoint) in SAFE_METHODS

    def run(
        self, endpoint: ClassifiedEndpoint, context: CheckContext
    ) -> list[CheckResult]:  # pragma: no cover - overridden
        raise NotImplementedError

    def result(
        self,
        endpoint: ClassifiedEndpoint,
        context: CheckContext,
        *,
        outcome: CheckOutcome,
        summary: str,
        finding_class: FindingClass = FindingClass.NONE,
        severity: Severity | None = None,
        confidence: Confidence = Confidence.LOW,
        explanation: str = "",
        limitations: Sequence[str] = (),
        next_step: str | None = None,
        evidence: Sequence[Evidence] = (),
        requests_sent: int = 0,
        url: str | None = None,
    ) -> CheckResult:
        """Build a result for this check.

        A finding without limitations is almost always overstated, so the
        caller is expected to supply them; this method does not invent any.

        The OWASP category and remediation come from
        :mod:`aegisapi.testing.knowledge`, looked up by check identifier. They
        are attached here rather than passed by each check because they describe
        the weakness class and are the same for every endpoint a check visits -
        and because a check cannot then forget them on one branch and set them
        on another. A check with no entry in that table gets neither field.
        """
        knowledge = knowledge_for(self.check_id)
        return CheckResult(
            check_id=self.check_id,
            check_name=self.name,
            category=self.category,
            target_name=context.target.name,
            endpoint_key=endpoint.endpoint.key,
            url=url or endpoint.resolved_url,
            outcome=outcome,
            finding_class=finding_class,
            severity=severity,
            confidence=confidence,
            owasp=knowledge.owasp if knowledge is not None else None,
            remediation=knowledge.remediation if knowledge is not None else None,
            summary=summary,
            explanation=explanation,
            limitations=list(limitations),
            next_step=next_step,
            evidence=list(evidence),
            requests_sent=requests_sent,
        )

    def skipped(
        self,
        endpoint: ClassifiedEndpoint,
        context: CheckContext,
        reason: str,
    ) -> CheckResult:
        """A result recording that nothing was sent, and why."""
        return self.result(
            endpoint,
            context,
            outcome=CheckOutcome.SKIPPED,
            summary=reason,
            explanation="No request was sent for this check.",
        )


def _transport_method(endpoint: Endpoint) -> HttpMethod | None:
    """Map a specification method onto a transport method.

    The two enumerations differ deliberately: a specification may declare
    ``TRACE``, which the transport refuses to send. An unmappable method means
    the operation is not testable rather than that it should be forced through.
    """
    try:
        return HttpMethod(endpoint.method.value.upper())
    except ValueError:
        return None


class CheckRegistry:
    """The set of available checks, selectable by identifier or category."""

    def __init__(self) -> None:
        self._checks: dict[str, SecurityCheck] = {}

    def register(self, check: SecurityCheck) -> SecurityCheck:
        """Add a check, refusing a duplicate identifier.

        Identifiers appear in results and in reports, so two checks sharing one
        would make a result ambiguous.
        """
        if check.check_id in self._checks:
            raise ValueError(f"check id {check.check_id!r} is already registered")
        self._checks[check.check_id] = check
        return check

    def all(self) -> list[SecurityCheck]:
        """Every registered check, ordered by identifier."""
        return [self._checks[key] for key in sorted(self._checks)]

    def get(self, check_id: str) -> SecurityCheck:
        """One check by identifier.

        Raises:
            InvalidTargetError: If no such check exists, listing what does.
        """
        check = self._checks.get(check_id.strip().upper())
        if check is None:
            raise InvalidTargetError(
                f"No security check with id {check_id!r}.",
                hint=f"Available: {', '.join(sorted(self._checks))}",
            )
        return check

    def select(
        self,
        *,
        categories: Sequence[CheckCategory] | None = None,
        check_ids: Sequence[str] | None = None,
    ) -> list[SecurityCheck]:
        """Choose checks by category, by identifier, or all of them.

        Raises:
            InvalidTargetError: If an explicit identifier does not exist. A
                silent empty selection would look like "nothing to test".
        """
        if check_ids:
            return [self.get(item) for item in check_ids]
        if categories:
            wanted = set(categories)
            return [item for item in self.all() if item.category in wanted]
        return self.all()

    def categories(self) -> list[CheckCategory]:
        """Categories that have at least one registered check."""
        return sorted({item.category for item in self.all()})


REGISTRY = CheckRegistry()
"""The process-wide registry.

Populated by :mod:`aegisapi.testing.engine` importing the check modules, which
keeps registration in one place instead of relying on import side effects
happening in the right order.
"""


__all__ = [
    "REGISTRY",
    "SAFE_METHODS",
    "BaseCheck",
    "CheckContext",
    "CheckRegistry",
    "RequestBudget",
    "SecurityCheck",
    "EndpointFixtures",
    "register_cancel_token",
    "unregister_cancel_token",
]
