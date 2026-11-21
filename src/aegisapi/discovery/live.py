"""Building an endpoint inventory from a live target.

:func:`aegisapi.discovery.discover_from_specification` covers the case where the
operator has a specification file. This module covers the case where they have a
URL, and produces the same :class:`~aegisapi.models.discovery.DiscoveryResult`
so that everything downstream - classification, the checks, risk analysis,
reporting - is unchanged by where the inventory came from.

There are two ways an inventory is assembled, and the difference matters to
every conclusion drawn later:

* **From a specification the target serves.** The full document is parsed, so
  operations arrive with their declared methods, parameters, request bodies,
  and security requirements. Checks that need that metadata can run.
* **From observed paths.** When no specification is available, an inventory is
  assembled from the paths the operator supplied or that answered a probe. Each
  one yields a bare ``GET`` operation with no declared parameters and no
  declared security, because nothing declared them. Checks that require
  metadata will skip, and they should: there is nothing to check against.

The second mode is honest about being weaker rather than filling the gap with
assumptions. An operation marked :attr:`~aegisapi.models.endpoint.
DiscoverySource.PROBED` carries exactly one fact - this path answered - and
every result derived from it is traceable to that.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field

from aegisapi import __version__
from aegisapi.core.logging import get_logger
from aegisapi.discovery.classification import classify_endpoints
from aegisapi.discovery.probe import (
    MAX_SUPPLIED_PATHS,
    MAX_WORDLIST_PATHS,
    ProbeObservation,
    SpecificationCandidate,
    normalise_probe_paths,
    probe_documentation,
    probe_paths,
    probe_specification,
    verify_connectivity,
)
from aegisapi.discovery.relationships import observe_relationships
from aegisapi.discovery.schemas import WarningCollector
from aegisapi.discovery.service import parse_specification
from aegisapi.discovery.versions import detect_version
from aegisapi.http import ScopedHttpClient
from aegisapi.models.discovery import (
    DISCOVERY_SCHEMA_VERSION,
    DiscoveryResult,
    SpecificationFormat,
    SpecificationInfo,
    SpecificationVersion,
)
from aegisapi.models.endpoint import (
    DeclaredSecurity,
    DiscoverySource,
    Endpoint,
    HttpMethod,
    SecurityPosture,
)
from aegisapi.models.target import Target

_logger = get_logger(__name__)

OBSERVED_SPECIFICATION_TITLE = "Observed endpoints (no specification)"
"""Title recorded when the inventory was assembled from observed paths.

Named rather than left blank so a report never looks as though it parsed a
document that does not exist.
"""


@dataclass
class LiveDiscoveryPlan:
    """What a live discovery pass is permitted to do.

    Every field is an input the operator controls. Nothing here is derived from
    a response, so the maximum traffic a pass can produce is knowable before it
    starts.
    """

    probe_specification_locations: bool = True
    """Try the conventional specification locations."""

    probe_documentation_locations: bool = True
    """Try the conventional documentation UI locations."""

    supplied_paths: Sequence[str] = ()
    """Paths the operator named explicitly."""

    wordlist_paths: Sequence[str] = ()
    """Paths read from a wordlist the operator chose."""

    budget: int | None = None
    """Ceiling on requests for the whole discovery pass. ``None`` is unbounded."""


@dataclass
class LiveDiscovery:
    """The outcome of a live discovery pass."""

    result: DiscoveryResult
    """The inventory, in the same shape a parsed specification produces."""

    specification: SpecificationCandidate | None = None
    """The specification retrieved from the target, if there was one."""

    documentation: list[ProbeObservation] = field(default_factory=list)
    """Documentation UIs found exposed."""

    probe_observations: list[ProbeObservation] = field(default_factory=list)
    """Every path observation made, including misses."""

    requests_sent: int = 0
    """Requests this pass transmitted."""

    notes: list[str] = field(default_factory=list)
    """Operator-facing notes about what was and was not attempted."""

    @property
    def from_specification(self) -> bool:
        """``True`` when the inventory came from a parsed specification."""
        return self.specification is not None


def _observed_endpoint(path: str, *, source: DiscoverySource, detail: str | None) -> Endpoint:
    """Build a bare operation for a path that was observed rather than declared.

    Everything optional is left empty, which is the accurate record: no
    parameters were declared because nothing declared any, and the security
    posture is :attr:`SecurityPosture.NOT_DECLARED` because no document stated
    one. A check reading this endpoint sees an absence of metadata and skips,
    rather than reading a default that was invented here and treating it as the
    API's declared contract.
    """
    return Endpoint(
        method=HttpMethod.GET,
        path=path,
        summary=None,
        declared_security=DeclaredSecurity(posture=SecurityPosture.NOT_DECLARED),
        source_pointer=f"#/observed{path}",
        source=source,
        source_detail=detail,
    )


def _specification_result(
    candidate: SpecificationCandidate,
    *,
    target: Target,
) -> DiscoveryResult:
    """Parse a retrieved specification into a discovery result.

    Shares the parsers, the warning collector, the classifier, and the
    relationship observer with the local-file path, so a specification fetched
    from the target is processed by exactly the same code as one read off disk.
    The only difference recorded is the provenance.
    """
    loaded = candidate.loaded
    detected = detect_version(loaded.document)
    warnings = WarningCollector()

    parsed = parse_specification(loaded, detected, warnings)
    endpoints = [
        endpoint.model_copy(
            update={
                "source": DiscoverySource.SPECIFICATION,
                "source_detail": loaded.source_label,
            }
        )
        for endpoint in parsed.endpoints
    ]

    classified = classify_endpoints(
        endpoints,
        target=target,
        specification_servers=parsed.servers,
        warnings=warnings,
    )

    return DiscoveryResult(
        schema_version=DISCOVERY_SCHEMA_VERSION,
        target_name=target.name,
        target_base_url=target.base_url,
        specification=SpecificationInfo(
            version=detected.version,
            raw_version=detected.raw,
            format=loaded.format,
            source_path=loaded.source_label,
            source_sha256=loaded.source_sha256,
            byte_size=loaded.byte_size,
            title=parsed.title,
            api_version=parsed.api_version,
            description=parsed.description,
            servers=parsed.servers,
        ),
        endpoints=classified,
        security_schemes=parsed.security_schemes,
        global_security=parsed.global_security,
        relationships=observe_relationships(endpoints),
        warnings=warnings.warnings,
        aegisapi_version=__version__,
    )


def _observed_result(
    endpoints: Sequence[Endpoint],
    *,
    target: Target,
) -> DiscoveryResult:
    """Assemble a discovery result from observed paths alone."""
    warnings = WarningCollector()
    classified = classify_endpoints(
        list(endpoints),
        target=target,
        specification_servers=[target.base_url],
        warnings=warnings,
    )

    return DiscoveryResult(
        schema_version=DISCOVERY_SCHEMA_VERSION,
        target_name=target.name,
        target_base_url=target.base_url,
        specification=SpecificationInfo(
            version=SpecificationVersion.NONE,
            raw_version="none",
            format=SpecificationFormat.JSON,
            source_path=target.base_url,
            source_sha256="",
            byte_size=0,
            title=OBSERVED_SPECIFICATION_TITLE,
            api_version=None,
            description=(
                "No specification was available. This inventory was assembled from "
                "paths the operator supplied or that responded to a bounded probe. "
                "No parameters, request bodies, or security requirements are "
                "declared for these operations, because nothing declared them."
            ),
            servers=[target.base_url],
        ),
        endpoints=classified,
        security_schemes=[],
        global_security=[],
        relationships=observe_relationships(list(endpoints)),
        warnings=warnings.warnings,
        aegisapi_version=__version__,
    )


def discover_live(
    client: ScopedHttpClient,
    *,
    target: Target,
    plan: LiveDiscoveryPlan | None = None,
) -> LiveDiscovery:
    """Build an inventory for a live target.

    The order is deliberate: a specification is looked for first, because
    finding one makes everything else unnecessary and produces a far better
    inventory than probing can. Documentation locations are probed next, since
    an exposed UI is inventory information worth reporting whether or not the
    specification was found. Supplied and wordlist paths are probed last, and
    only contribute operations when no specification was retrieved - a
    specification already declares the API's routes, and re-adding a guessed
    path as a second bare operation would duplicate a well-described endpoint
    with a worse copy of itself.

    Args:
        client: A scope-gated client bound to ``target``. The only route to the
            network, and the reason this function cannot reach anything the
            target's scope does not admit.
        target: The target being assessed.
        plan: What the pass may do. Defaults to probing the conventional
            specification and documentation locations and nothing else.

    Returns:
        A :class:`LiveDiscovery` holding the inventory and how it was obtained.

    Raises:
        TransportError: If the target did not answer the connectivity check.
        ScopeViolationError: If the target's own base URL is out of scope.
    """
    settings = plan or LiveDiscoveryPlan()
    notes: list[str] = []
    observations: list[ProbeObservation] = []
    requests_sent = 0

    reachability = verify_connectivity(client)
    requests_sent += 1
    observations.append(reachability)

    def remaining() -> int | None:
        if settings.budget is None:
            return None
        return max(settings.budget - requests_sent, 0)

    candidate: SpecificationCandidate | None = None
    if settings.probe_specification_locations:
        candidate, found, attempts, probe_notes = probe_specification(
            client, budget=remaining()
        )
        requests_sent += attempts
        observations.extend(found)
        notes.extend(probe_notes)

    documentation: list[ProbeObservation] = []
    if settings.probe_documentation_locations:
        documentation, attempts, probe_notes = probe_documentation(client, budget=remaining())
        requests_sent += attempts
        observations.extend(documentation)
        notes.extend(probe_notes)

    supplied, supplied_notes = normalise_probe_paths(
        settings.supplied_paths, limit=MAX_SUPPLIED_PATHS
    )
    notes.extend(supplied_notes)
    wordlist, wordlist_notes = normalise_probe_paths(
        settings.wordlist_paths, limit=MAX_WORDLIST_PATHS
    )
    notes.extend(wordlist_notes)

    # Supplied paths first, then wordlist entries, de-duplicated across both:
    # a path named explicitly and also present in the wordlist is one path, and
    # probing it twice would spend budget to learn the same fact.
    responding: list[ProbeObservation] = []
    ordered: list[str] = []
    seen: set[str] = set()
    for path in (*supplied, *wordlist):
        if path not in seen:
            seen.add(path)
            ordered.append(path)

    if ordered:
        responding, attempts, probe_notes = probe_paths(client, ordered, budget=remaining())
        requests_sent += attempts
        observations.extend(responding)
        notes.extend(probe_notes)

    if candidate is not None:
        result = _specification_result(candidate, target=target)
        if ordered:
            notes.append(
                f"{len(ordered)} supplied or wordlist path(s) were probed, but the "
                "inventory comes from the specification the target served; a probed "
                "path is not added as a second, undeclared operation."
            )
    else:
        supplied_set = set(supplied)
        endpoints = [
            _observed_endpoint(
                item.path,
                source=(
                    DiscoverySource.SUPPLIED
                    if item.path in supplied_set
                    else DiscoverySource.PROBED
                ),
                detail=f"HTTP {item.status_code} from {item.url}",
            )
            for item in responding
        ]
        if not endpoints:
            notes.append(
                "No specification was found and no supplied or probed path responded, "
                "so the only operation in the inventory is the base path itself."
            )
            endpoints = [
                _observed_endpoint(
                    target.base_path or "/",
                    source=DiscoverySource.PROBED,
                    detail=f"HTTP {reachability.status_code} from {reachability.url}",
                )
            ]
        result = _observed_result(endpoints, target=target)

    _logger.debug(
        "Live discovery produced %d operation(s) in %d request(s)",
        len(result.endpoints),
        requests_sent,
    )

    return LiveDiscovery(
        result=result,
        specification=candidate,
        documentation=documentation,
        probe_observations=observations,
        requests_sent=requests_sent,
        notes=notes,
    )


__all__ = [
    "OBSERVED_SPECIFICATION_TITLE",
    "LiveDiscovery",
    "LiveDiscoveryPlan",
    "discover_live",
]
