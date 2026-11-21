"""The end-to-end scan: one URL in, findings and reports out.

This is the module ``aegisapi scan`` is. It owns the order of the stages and
nothing else - every stage delegates to the component that already does that
job, so a scan and the equivalent sequence of individual commands produce the
same results through the same code:

======================  =====================================================
Stage                   Delegates to
======================  =====================================================
URL and scope           :mod:`aegisapi.scan.authorisation`
Connectivity            :func:`aegisapi.discovery.probe.verify_connectivity`
Discovery               :func:`aegisapi.discovery.live.discover_live`
Security checks         :class:`aegisapi.testing.AssessmentEngine`
Risk analysis           :func:`aegisapi.intelligence.analyse`
Report                  :func:`aegisapi.reporting.build_report`
======================  =====================================================

Two properties are worth stating because they are what make the stage list
trustworthy rather than decorative:

**Nothing is simulated.** Every number in a scan result comes from a request
that was sent or a document that was parsed. A stage that cannot run says so
and the report records it; none of them has a fallback that invents a plausible
result.

**The request budget spans the whole scan.** Discovery and the checks draw from
one ceiling, so the traffic a scan produces is bounded by an argument the
operator passed rather than by the sum of whatever each stage felt like
sending.
"""

from __future__ import annotations

import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum

from aegisapi import __version__
from aegisapi.core.config import AegisConfig
from aegisapi.core.exceptions import AegisAPIError, TransportError
from aegisapi.core.logging import get_logger
from aegisapi.discovery.live import LiveDiscovery, LiveDiscoveryPlan, discover_live
from aegisapi.discovery.probe import MAX_SUPPLIED_PATHS, MAX_WORDLIST_PATHS
from aegisapi.http import ScopedHttpClient, Transport
from aegisapi.intelligence import analyse
from aegisapi.models.assessment import AssessmentResult, CheckCategory
from aegisapi.models.discovery import DiscoveryResult, ScopeClassification
from aegisapi.models.http import HttpLimits
from aegisapi.models.intelligence import IntelligenceReport
from aegisapi.models.report import Report
from aegisapi.models.target import AuthMethod, AuthProfile, Target
from aegisapi.reporting import build_report
from aegisapi.scan.authorisation import (
    ScanAuthorisation,
    authorise_registered_target,
    authorise_scan_url,
)
from aegisapi.scan.events import EventDispatcher, ScanEventType
from aegisapi.testing import AssessmentEngine
from aegisapi.testing.auto_fixtures import generate_fixtures
from aegisapi.testing.efficiency import EfficiencyTracker
from aegisapi.testing.fixtures import AssessmentFixtures

_logger = get_logger(__name__)

DEFAULT_SCAN_BUDGET = 240
"""Requests a scan may send in total unless the operator changes it.

Larger than a bare ``check run`` default because a scan pays for discovery as
well, and still small enough that a default scan of a small API is seconds of
traffic rather than a load test.
"""


class ScanStage(StrEnum):
    """The stages of a scan, in the order they run.

    Reported through the progress callback so a caller can show what is
    happening without this module knowing anything about terminals.
    """

    AUTHORISE = "authorise"
    """Validate the URL and derive the scope that admits only it."""

    CONNECT = "connect"
    """Confirm the target answers at all."""

    DISCOVER = "discover"
    """Build the endpoint inventory."""

    FIXTURE_GEN = "fixture_gen"
    """Generate automatic test fixtures from discovered schemas."""

    SCHEMA_VAL = "schema_val"
    """Validate response bodies and status codes against declared schemas."""

    CHECK = "check"
    """Run the security checks."""

    ANALYSE = "analyse"
    """Correlate and prioritise what the checks found."""

    REPORT = "report"
    """Compose the report document."""


ProgressCallback = Callable[[ScanStage, str], None]
"""Called as each stage starts and finishes. Presentation is the caller's job."""


@dataclass(frozen=True)
class ScanOptions:
    """Everything the operator chose for one scan.

    Recorded verbatim onto the result so a report states the configuration that
    produced it. A report whose numbers cannot be tied to the settings that
    produced them is not reproducible.
    """

    url: str
    """The target URL as given.

    For a registered-target scan this is set to the target's configured
    ``base_url`` by the CLI so that every downstream consumer that reads this
    field (reports, notes, the terminal summary) sees the correct address.
    """

    target: Target | None = None
    """Registered workspace target.

    When set the scan uses this target directly instead of deriving an
    ephemeral one from :attr:`url`. Scope, authentication, and the tool-wide
    allow-list are built from the target's own configuration; the
    ``authorise_scan_url`` code path is skipped entirely.

    ``None`` for ``aegisapi scan --url URL`` (ephemeral) scans.
    """

    local_lab: bool = False
    """The operator's acknowledgement for a loopback or private destination."""

    active: bool = False
    """Run checks that send more than read-shaped requests.

    Off by default. The checks AegisAPI ships are read-shaped regardless; this
    flag exists so that a check which needs more is impossible to trigger by
    accident, and so the report records which mode produced it.
    """

    budget: int = DEFAULT_SCAN_BUDGET
    """Total requests the whole scan may send, discovery included."""

    categories: tuple[CheckCategory, ...] = ()
    """Restrict the checks to these categories. Empty means all of them."""

    check_ids: tuple[str, ...] = ()
    """Run exactly these checks. Empty means the category selection applies."""

    supplied_paths: tuple[str, ...] = ()
    """Endpoint paths the operator named explicitly."""

    wordlist_paths: tuple[str, ...] = ()
    """Endpoint paths read from a wordlist the operator chose."""

    probe_specification: bool = True
    """Try the conventional specification locations."""

    probe_documentation: bool = True
    """Try the conventional documentation UI locations."""

    max_endpoints: int | None = None
    """Only assess the first N in-scope operations."""

    extra_hosts: tuple[str, ...] = ()
    """Additional hosts the operator authorised."""

    auth: AuthProfile | None = None
    """How to authenticate, as environment-variable references.

    Worth supplying: several checks need a credential to say anything. Whether
    declared authentication is actually enforced (AUTH-001) is established by
    comparing an authenticated response with an unauthenticated one, and with
    no credential there is no baseline to compare against, so the check does
    not run rather than guess from one response.
    """

    scan_timeout_seconds: float | None = None
    """Wall-clock deadline for the whole scan.

    When set, the engine stops accepting new endpoints once this many seconds
    have elapsed since the scan started. Running checks are allowed to finish.
    """

    max_endpoint_requests: int | None = None
    """Per-endpoint request cap.

    When set, an individual endpoint that would cause this many requests to be
    consumed is skipped for the remainder of the scan. Discovery requests are
    not counted against this limit.
    """

    max_check_requests: int | None = None
    """Per-check-id request cap.

    When set, a check that would consume this many requests globally across all
    endpoints it runs against is skipped for subsequent endpoints.
    """

    check_timeout_seconds: float | None = None
    """Per-check execution time limit.

    When set, a check that runs for longer than this many seconds is abandoned
    and recorded as SKIPPED. The background thread continues to its own HTTP
    timeout; its result is discarded.
    """

    max_workers: int = 4
    """Maximum parallel worker threads for security checks.

    Defaults to 4 so independent checks overlap without saturating the target.
    Set to 1 to disable parallelism (sequential, same semantics as pre-M6).
    The engine clamps values below 1 to 1.
    """

    def describe(self) -> dict[str, str]:
        """The configuration as displayable strings, for the report."""
        # For registered-target scans auth lives in the target, not in options.auth.
        if self.target is not None:
            auth_display = (
                self.target.auth.method.value if self.target.auth is not None else "none"
            )
            target_display = f"{self.target.name} ({self.url})"
        else:
            auth_display = self.auth.method.value if self.auth is not None else "none"
            target_display = self.url
        return {
            "url": target_display,
            "mode": "active" if self.active else "passive (read-shaped requests only)",
            "local_lab": "yes" if self.local_lab else "no",
            "request_budget": str(self.budget),
            "scan_timeout": "none" if self.scan_timeout_seconds is None else f"{self.scan_timeout_seconds}s",
            "max_endpoint_requests": "none" if self.max_endpoint_requests is None else str(self.max_endpoint_requests),
            "max_check_requests": "none" if self.max_check_requests is None else str(self.max_check_requests),
            "check_timeout": "none" if self.check_timeout_seconds is None else f"{self.check_timeout_seconds}s",
            "checks": ", ".join(self.check_ids) if self.check_ids else "all",
            "categories": (
                ", ".join(item.value for item in self.categories) if self.categories else "all"
            ),
            "specification_probing": "on" if self.probe_specification else "off",
            "documentation_probing": "on" if self.probe_documentation else "off",
            "supplied_paths": str(len(self.supplied_paths)),
            "wordlist_paths": str(len(self.wordlist_paths)),
            "max_endpoints": "unlimited" if self.max_endpoints is None else str(self.max_endpoints),
            "authentication": auth_display,
            "parallel_workers": str(self.max_workers),
        }


@dataclass
class ScanResult:
    """Everything one scan produced.

    Holds the real documents rather than a summary of them, so the caller can
    render the terminal view, write JSON, and write HTML from one run without
    anything being recomputed or diverging between outputs.
    """

    options: ScanOptions
    """The configuration that produced this scan."""

    authorisation: ScanAuthorisation
    """The ephemeral target and derived scope the scan ran against."""

    started_at: datetime
    """When the scan began (UTC)."""

    finished_at: datetime
    """When it ended (UTC)."""

    discovery: DiscoveryResult
    """The endpoint inventory."""

    live: LiveDiscovery
    """How the inventory was obtained, with the observations behind it."""

    assessment: AssessmentResult
    """The check results."""

    intelligence: IntelligenceReport | None
    """Risk analysis, when it could be produced."""

    report: Report
    """The composed report, the source of both output formats."""

    notes: list[str] = field(default_factory=list)
    """Operator-facing notes about what was and was not done."""

    fixtures_generated: int = 0
    """Number of templated endpoints that received auto-generated path fixtures."""

    schemas_validated: int = 0
    """Number of endpoints whose response bodies were validated against declared schemas."""

    schema_violations: int = 0
    """Number of endpoints where the response body schema validation found violations."""

    aegisapi_version: str = __version__
    """The version that produced this scan."""

    @property
    def duration_seconds(self) -> float:
        """Wall-clock duration of the scan."""
        return max((self.finished_at - self.started_at).total_seconds(), 0.0)

    @property
    def endpoints_discovered(self) -> int:
        """Operations the inventory contains, in scope or not."""
        return len(self.discovery.endpoints)

    @property
    def endpoints_in_scope(self) -> int:
        """Operations the derived scope admits for testing."""
        return sum(
            1
            for item in self.discovery.endpoints
            if item.classification is ScopeClassification.IN_SCOPE
        )

    @property
    def endpoints_tested(self) -> int:
        """Operations at least one check actually sent a request for."""
        return self.assessment.endpoints_tested

    @property
    def requests_sent(self) -> int:
        """Requests the whole scan transmitted, discovery included."""
        return self.live.requests_sent + self.assessment.requests_sent

    @property
    def findings(self) -> list[object]:
        """Results the report displays, most serious first."""
        return list(self.report.results)

    @property
    def completion_status(self) -> str:
        """Whether the scan completed or stopped early.

        Returns one of ``"complete"``, ``"partial_timeout"`` (scan_timeout_seconds
        reached before all endpoints were visited), or ``"partial_budget"``
        (total request budget exhausted).
        """
        if self.assessment.scan_timed_out:
            return "partial_timeout"
        if self.assessment.budget_exhausted:
            return "partial_budget"
        return "complete"

    @property
    def has_findings(self) -> bool:
        """``True`` when at least one confirmed or suspected finding exists."""
        return bool(
            self.report.summary.confirmed_findings or self.report.summary.potential_findings
        )


def _noop(stage: ScanStage, message: str) -> None:
    """Default progress callback: report nothing."""
    del stage, message


def run_scan(
    options: ScanOptions,
    *,
    config: AegisConfig,
    transport: Transport | None = None,
    progress: ProgressCallback | None = None,
    fixtures: AssessmentFixtures | None = None,
    event_dispatcher: EventDispatcher | None = None,
) -> ScanResult:
    """Run the full assessment pipeline against one URL.

    Args:
        options: What the operator asked for.
        config: Loaded configuration. Supplies the HTTP limits - timeouts, rate,
            size cap, TLS verification - that every request in the scan obeys.
            The scope settings on it are *not* used: a scan derives its own
            allow-list from the URL, which is narrower than whatever the
            workspace happens to permit.
        transport: Injected transport, for tests. Production leaves it unset.
        progress: Called as each stage begins and ends.
        fixtures: Declared identities and owned objects. Without them the
            authorisation checks skip rather than guess, which is why a scan
            reports configuration weaknesses well and object-level
            authorisation not at all.

    Returns:
        A :class:`ScanResult` holding every document the scan produced.

    Raises:
        InvalidUrlError: If the URL cannot be parsed.
        ScopeViolationError: If the destination was refused, including a
            loopback or private host without ``local_lab``.
        TransportError: If the target did not answer the connectivity check.
            Raised rather than reported as a finding: a scan of a host that
            never responded has nothing to report, and an empty report would
            read as a clean result.
    """
    if event_dispatcher is not None:
        event_dispatcher.emit(ScanEventType.SCAN_STARTED, url=options.url)
    try:
        return _run_scan_body(
            options,
            config=config,
            transport=transport,
            progress=progress,
            fixtures=fixtures,
            event_dispatcher=event_dispatcher,
        )
    except KeyboardInterrupt:
        if event_dispatcher is not None:
            try:
                event_dispatcher.emit(ScanEventType.SCAN_CANCELLED)
            except Exception:
                pass
        raise
    except Exception:
        if event_dispatcher is not None:
            try:
                event_dispatcher.emit(ScanEventType.SCAN_FAILED)
            except Exception:
                pass
        raise


def _run_scan_body(
    options: ScanOptions,
    *,
    config: AegisConfig,
    transport: Transport | None,
    progress: ProgressCallback | None,
    fixtures: AssessmentFixtures | None,
    event_dispatcher: EventDispatcher | None,
) -> ScanResult:
    """The pipeline body, extracted so the outer function can wrap it cleanly."""
    emit = progress or _noop
    notes: list[str] = []
    started_at = datetime.now(UTC)
    fixtures_generated = 0
    schemas_validated = 0
    schema_violations = 0
    scan_deadline: float | None = (
        time.monotonic() + options.scan_timeout_seconds
        if options.scan_timeout_seconds is not None
        else None
    )

    if options.target is not None:
        emit(ScanStage.AUTHORISE, f"Using registered target {options.target.name!r}")
        authorisation = authorise_registered_target(
            options.target,
            local_lab=options.local_lab,
            extra_hosts=options.extra_hosts,
        )
    else:
        emit(ScanStage.AUTHORISE, f"Validating {options.url}")
        authorisation = authorise_scan_url(
            options.url,
            local_lab=options.local_lab,
            extra_hosts=options.extra_hosts,
            auth=options.auth,
        )
    target = authorisation.target
    if authorisation.requires_local_lab:
        notes.append(
            f"{authorisation.url.host} was classified as "
            f"{authorisation.exposure.value} and assessed under --local-lab."
        )
    emit(
        ScanStage.AUTHORISE,
        f"Scope: host {authorisation.url.host}, path {target.scope.include_paths[0]}",
    )
    if event_dispatcher is not None:
        event_dispatcher.emit(
            ScanEventType.TARGET_VALIDATED,
            target_name=target.name,
            host=authorisation.url.host,
        )

    # M5: One efficiency tracker for the whole assessment.  Created before the
    # client so that the tracker reference is always available when build_report
    # is called, even if the scan raises early.
    efficiency_tracker = EfficiencyTracker()

    # One client for the whole scan: discovery and every check share its
    # throttle and its connection pool, so the configured rate limit is a
    # property of the scan rather than of each stage separately.
    limits = _scan_limits(config.http, options)
    client = ScopedHttpClient(
        target=target,
        settings=authorisation.scope_settings,
        limits=limits,
        transport=transport,
    )

    try:
        emit(ScanStage.CONNECT, f"Contacting {authorisation.url.origin}")
        plan = LiveDiscoveryPlan(
            probe_specification_locations=options.probe_specification,
            probe_documentation_locations=options.probe_documentation,
            supplied_paths=options.supplied_paths,
            wordlist_paths=options.wordlist_paths,
            budget=options.budget,
        )

        emit(ScanStage.DISCOVER, "Discovering endpoints")
        if event_dispatcher is not None:
            event_dispatcher.emit(ScanEventType.DISCOVERY_STARTED)
        try:
            live = discover_live(client, target=target, plan=plan)
        except TransportError as exc:
            raise TransportError(
                f"{authorisation.url.origin} did not respond, so there is nothing to "
                f"assess. {exc.message}",
                hint=exc.hint or "Check the host, the port, and that the service is running.",
            ) from exc

        notes.extend(live.notes)
        discovery = live.result
        emit(
            ScanStage.DISCOVER,
            f"{len(discovery.endpoints)} operation(s) from "
            f"{'specification' if live.from_specification else 'observed paths'}"
            f" in {live.requests_sent} request(s)",
        )
        if event_dispatcher is not None:
            for ep in discovery.endpoints:
                event_dispatcher.emit(
                    ScanEventType.ENDPOINT_DISCOVERED,
                    endpoint_key=ep.endpoint.key,
                    classification=ep.classification.value,
                )

        check_budget = max(options.budget - live.requests_sent, 0)
        if check_budget == 0:
            notes.append(
                "The request budget was consumed by discovery, so no check ran. "
                "Raise --budget to assess the endpoints that were found."
            )

        emit(ScanStage.FIXTURE_GEN, "Generating test fixtures from schemas")
        all_endpoints = [ep.endpoint for ep in discovery.endpoints]
        auto_fixtures = generate_fixtures(all_endpoints)
        templated_count = sum(1 for ep in all_endpoints if ep.is_templated)
        fixtures_generated = sum(
            1 for ep_fix in auto_fixtures.values() if ep_fix.has_path_values
        )
        emit(
            ScanStage.FIXTURE_GEN,
            f"{fixtures_generated} of {templated_count} templated endpoint(s) equipped "
            "with generated path values",
        )

        schema_eligible = sum(
            1
            for ep in all_endpoints
            if ep.responses
        )
        emit(
            ScanStage.SCHEMA_VAL,
            f"{schema_eligible} endpoint(s) have declared responses for schema validation",
        )

        emit(ScanStage.CHECK, "Running security checks")
        if event_dispatcher is not None:
            event_dispatcher.emit(
                ScanEventType.TESTING_STARTED,
                endpoints_in_scope=sum(
                    1 for ep in discovery.endpoints
                    if ep.classification.value == "in_scope"
                ),
            )
        engine = AssessmentEngine(target=target, config=config)
        assessment = engine.run(
            discovery=discovery,
            fixtures=fixtures,
            auto_fixtures=auto_fixtures,
            categories=list(options.categories) or None,
            check_ids=list(options.check_ids) or None,
            budget=check_budget,
            client=client,
            max_endpoints=options.max_endpoints,
            scan_deadline=scan_deadline,
            check_timeout_seconds=options.check_timeout_seconds,
            max_per_endpoint=options.max_endpoint_requests,
            max_per_check=options.max_check_requests,
            efficiency_tracker=efficiency_tracker,
            max_workers=options.max_workers,
            event_dispatcher=event_dispatcher,
        )
        emit(
            ScanStage.CHECK,
            f"{len(assessment.results)} result(s) over {assessment.endpoints_tested} "
            f"endpoint(s) in {assessment.requests_sent} request(s)",
        )
        if assessment.scan_timed_out:
            notes.append(
                "The scan stopped early because scan_timeout_seconds was reached. "
                "Not all endpoints were assessed; absence of a finding is not evidence of safety."
            )
        if assessment.checks_timed_out:
            notes.append(
                f"{assessment.checks_timed_out} check(s) exceeded check_timeout_seconds and "
                "were skipped. Raise --check-timeout or investigate those endpoints manually."
            )
        if assessment.endpoints_at_limit:
            notes.append(
                f"{len(assessment.endpoints_at_limit)} endpoint(s) reached the per-endpoint "
                "request limit and were partially assessed: "
                + ", ".join(sorted(assessment.endpoints_at_limit))
                + "."
            )

        # Count schema validation outcomes from SCHEMA-001 results.
        schemas_validated = sum(
            1
            for r in assessment.results
            if r.check_id == "SCHEMA-001"
            and r.outcome not in {"skipped", "error"}
        )
        schema_violations = sum(
            1
            for r in assessment.results
            if r.check_id == "SCHEMA-001"
            and r.outcome == "fail"
        )
    finally:
        client.close()

    emit(ScanStage.ANALYSE, "Correlating and prioritising")
    intelligence: IntelligenceReport | None
    try:
        intelligence = analyse(discovery, assessment, fixtures)
    except AegisAPIError as exc:
        # Analysis is interpretation of results that already exist. Losing it
        # degrades the report; it must not discard the assessment that was paid
        # for in real traffic.
        intelligence = None
        notes.append(f"Risk analysis did not complete: {exc.message}")
        _logger.warning("Risk analysis failed: %s", exc.message)

    emit(ScanStage.REPORT, "Composing report")
    report = build_report(assessment, intelligence, efficiency_tracker=efficiency_tracker)

    if not options.active:
        notes.append(
            "Passive mode: only read-shaped requests were sent. No state-changing "
            "or exploitation request was made."
        )
    if fixtures is None:
        notes.append(
            "No fixtures were supplied, so the object- and function-level "
            "authorisation checks skipped. They need declared identities and "
            "owned objects to test against, and will not guess."
        )
    _auth_absent = target.auth is None or target.auth.method is AuthMethod.NONE
    if _auth_absent:
        if options.target is not None:
            notes.append(
                f"No authentication is configured on target '{target.name}'. "
                "Authentication-dependent checks did not run. "
                f"Use 'aegisapi target update {target.name} --auth-method ...' "
                "to add credentials."
            )
        else:
            notes.append(
                "No credentials were supplied. Checks that need an authenticated "
                "baseline to compare against - whether declared authentication is "
                "actually enforced, above all - did not run. Pass --auth-method and "
                "the matching credential option to include them."
            )

    # A check that applied to no endpoint produces no result at all, so without
    # this the operator cannot tell "ran and found nothing" from "never ran".
    # The distinction is the difference between a clean result and an untested
    # one, and a report that blurs it is misleading in the direction of
    # reassurance.
    produced = {item.check_id for item in assessment.results}
    silent = [check_id for check_id in assessment.checks_run if check_id not in produced]
    if silent:
        notes.append(
            f"{len(silent)} selected check(s) produced no result because no "
            f"discovered operation met their preconditions: {', '.join(sorted(silent))}. "
            "They did not run; this is not a pass."
        )

    finished_at = datetime.now(UTC)
    if event_dispatcher is not None:
        event_dispatcher.emit(
            ScanEventType.SCAN_COMPLETED,
            duration_seconds=(finished_at - started_at).total_seconds(),
            endpoints_tested=assessment.endpoints_tested,
            findings_count=sum(1 for r in report.results if r.is_finding),
        )
    return ScanResult(
        options=options,
        authorisation=authorisation,
        started_at=started_at,
        finished_at=finished_at,
        discovery=discovery,
        live=live,
        assessment=assessment,
        intelligence=intelligence,
        report=report,
        notes=notes,
        fixtures_generated=fixtures_generated,
        schemas_validated=schemas_validated,
        schema_violations=schema_violations,
    )


def _scan_limits(limits: HttpLimits, options: ScanOptions) -> HttpLimits:
    """Derive the HTTP limits a scan runs under.

    Redirect following stays as configured. It is off by default, and a scan
    does not turn it on: following one means re-validating a destination the
    operator did not name, and the client's per-hop gate is a safety net rather
    than a reason to invite the situation.
    """
    del options
    return limits


def read_wordlist(lines: Sequence[str], *, limit: int = MAX_WORDLIST_PATHS) -> list[str]:
    """Take wordlist lines as read, leaving validation to the probe.

    A thin seam so the CLI does not have to know the cap, and so a future
    source of candidate paths has one place to arrive through.
    """
    del limit
    return [line for line in lines if line.strip()]


__all__ = [
    "DEFAULT_SCAN_BUDGET",
    "MAX_SUPPLIED_PATHS",
    "MAX_WORDLIST_PATHS",
    "ProgressCallback",
    "ScanOptions",
    "ScanResult",
    "ScanStage",
    "read_wordlist",
    "run_scan",
]
