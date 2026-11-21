"""Cross-endpoint correlation.

A correlation is a statement about *more than one* operation that neither
operation's own result makes. The useful ones look like:

* one operation refuses a caller while a related one serves them;
* a confirmed authorization weakness reaches several operations that the
  specification says share a resource;
* operations on one resource declare inconsistent authentication.

The discipline is in :attr:`Correlation.confirmed`. It is set only when direct
evidence establishes the correlated claim itself - not when several weak
observations happen to point the same way. Three informational results do not
become a confirmed vulnerability by being counted together; they become a
reason for someone to look.
"""

from __future__ import annotations

from collections import defaultdict

from aegisapi.models.assessment import (
    AssessmentResult,
    CheckOutcome,
    CheckResult,
    FindingClass,
)
from aegisapi.models.common import Confidence
from aegisapi.models.discovery import DiscoveryResult, ScopeClassification
from aegisapi.models.intelligence import (
    Correlation,
    EdgeKind,
    GraphEdge,
    Provenance,
)

MIN_WEAK_OBSERVATIONS = 3
"""How many low-grade observations on one resource justify a review prompt."""

MAX_CORRELATIONS = 100
"""Cap on correlations produced, so a large API cannot flood the output."""


def _edge_index(edges: list[GraphEdge]) -> dict[tuple[str, EdgeKind], list[GraphEdge]]:
    """Index edges by source node and kind."""
    index: dict[tuple[str, EdgeKind], list[GraphEdge]] = defaultdict(list)
    for edge in edges:
        index[(edge.source, edge.kind)].append(edge)
    return index


def _resource_members(edges: list[GraphEdge]) -> dict[str, list[str]]:
    """Group endpoint nodes by the resource node they are linked to."""
    members: dict[str, list[str]] = defaultdict(list)
    for edge in edges:
        if edge.kind in {EdgeKind.SHARES_SCHEMA, EdgeKind.SHARES_RESOURCE}:
            members[edge.target].append(edge.source)
    return {key: sorted(set(value)) for key, value in sorted(members.items())}


def _endpoint_key(node_id: str) -> str:
    """Recover an operation key from its node identifier."""
    return node_id.removeprefix("endpoint:")


def correlate(
    discovery: DiscoveryResult,
    assessment: AssessmentResult | None,
    edges: list[GraphEdge],
) -> list[Correlation]:
    """Produce every correlation supported by the inputs.

    Deterministic: inputs are sorted before grouping, so the same discovery and
    assessment always yield the same correlations in the same order.
    """
    correlations: list[Correlation] = []
    correlations.extend(_inconsistent_authentication(discovery, edges))
    if assessment is not None:
        correlations.extend(_shared_resource_findings(assessment, edges))
        correlations.extend(_inconsistent_enforcement(assessment, edges))
        correlations.extend(_accumulated_weak_observations(assessment, edges))
    return correlations[:MAX_CORRELATIONS]


def _inconsistent_authentication(
    discovery: DiscoveryResult, edges: list[GraphEdge]
) -> list[Correlation]:
    """Related operations whose declared authentication disagrees.

    Specification-backed, so it stands without any requests having been sent -
    but for the same reason it is never ``confirmed``: the document saying two
    operations differ is not evidence that the running API does.
    """
    found: list[Correlation] = []
    for edge in edges:
        if edge.kind is not EdgeKind.AUTH_DIFFERS:
            continue
        anonymous = _endpoint_key(edge.source)
        protected = _endpoint_key(edge.target)
        pair = sorted([anonymous, protected])
        found.append(
            Correlation(
                correlation_id=Correlation.make_id("inconsistent_authentication", pair),
                kind="inconsistent_authentication",
                title=(
                    f"Operations on one resource declare different authentication: "
                    f"{anonymous} is documented as anonymous, {protected} is not"
                ),
                endpoints=pair,
                supporting_edges=[edge.edge_id],
                provenance=Provenance.SPECIFICATION,
                confidence=Confidence.MEDIUM,
                confirmed=False,
                reasoning=(
                    f"{edge.reason}. Where one route to a resource is documented as "
                    "requiring no credentials and another requires a scheme, the "
                    "anonymous route is worth reading carefully: it may expose through "
                    "one method what the other protects."
                ),
                limitations=[
                    "This comes from the specification; the running API was not compared.",
                    "A documented anonymous route may be intentionally public.",
                    "No data was retrieved through either operation by this correlation.",
                ],
            )
        )
    discovery_unused = discovery  # kept for signature symmetry with other builders
    del discovery_unused
    return found


def _shared_resource_findings(
    assessment: AssessmentResult, edges: list[GraphEdge]
) -> list[Correlation]:
    """A finding on one operation, where siblings share the same resource.

    This is the correlation that changes a reviewer's priorities: a confirmed
    object-level weakness on ``GET /orders/{id}`` matters more when four other
    operations are documented as acting on the same ``Order`` schema, because
    the same identifier may reach all of them.
    """
    members = _resource_members(edges)
    by_endpoint: dict[str, list[CheckResult]] = defaultdict(list)
    for result in assessment.results:
        if result.is_finding:
            by_endpoint[result.endpoint_key].append(result)

    found: list[Correlation] = []
    for resource, endpoint_nodes in members.items():
        keys = [_endpoint_key(node) for node in endpoint_nodes]
        if len(keys) < 2:
            continue
        affected = sorted(key for key in keys if key in by_endpoint)
        if not affected:
            continue

        results = [item for key in affected for item in by_endpoint[key]]
        confirmed = [item for item in results if item.finding_class is FindingClass.CONFIRMED]
        resource_label = resource.removeprefix("resource:")
        siblings = sorted(set(keys) - set(affected))
        if not siblings:
            continue

        supporting = [
            edge.edge_id
            for edge in edges
            if edge.target == resource and _endpoint_key(edge.source) in keys
        ]
        provenance = (
            Provenance.OBSERVED
            if confirmed and any(item.evidence for item in confirmed)
            else Provenance.SPECIFICATION
        )
        found.append(
            Correlation(
                correlation_id=Correlation.make_id(
                    "finding_on_shared_resource", [resource_label, *affected]
                ),
                kind="finding_on_shared_resource",
                title=(
                    f"{len(results)} finding(s) on the '{resource_label}' resource, which "
                    f"{len(siblings)} other operation(s) also act on"
                ),
                endpoints=sorted(keys),
                supporting_results=sorted({item.result_id for item in results}),
                supporting_edges=sorted(supporting),
                evidence_ids=sorted({ref for item in results for ref in item.evidence_ids}),
                provenance=provenance,
                confidence=(Confidence.HIGH if confirmed else Confidence.MEDIUM),
                confirmed=bool(confirmed),
                reasoning=(
                    f"The specification links these operations to '{resource_label}'. "
                    f"{len(results)} finding(s) were recorded on {', '.join(affected)}. "
                    f"The other operations on the same resource ({', '.join(siblings)}) "
                    "were not shown to share the weakness, but they are the first place "
                    "to look for it."
                ),
                limitations=[
                    "The siblings were not themselves found to be affected.",
                    "Sharing a declared schema does not prove a shared implementation.",
                    "Breadth here indicates where to look next, not greater severity.",
                ],
            )
        )
    return found


def _inconsistent_enforcement(
    assessment: AssessmentResult, edges: list[GraphEdge]
) -> list[Correlation]:
    """One resource where a check passes on one operation and fails on another.

    Direct evidence on both sides, which is why this one can be confirmed: the
    inconsistency itself was observed, whatever it implies about exploitability.
    """
    by_resource: dict[str, dict[str, list[CheckResult]]] = defaultdict(lambda: defaultdict(list))
    members = _resource_members(edges)
    endpoint_to_resources: dict[str, list[str]] = defaultdict(list)
    for resource, nodes in members.items():
        for node in nodes:
            endpoint_to_resources[_endpoint_key(node)].append(resource)

    for result in assessment.results:
        if result.outcome not in {CheckOutcome.PASS, CheckOutcome.FAIL}:
            continue
        for resource in endpoint_to_resources.get(result.endpoint_key, []):
            by_resource[resource][result.check_id].append(result)

    found: list[Correlation] = []
    for resource, per_check in sorted(by_resource.items()):
        for check_id, results in sorted(per_check.items()):
            passed = sorted(
                {item.endpoint_key for item in results if item.outcome is CheckOutcome.PASS}
            )
            failed = sorted(
                {item.endpoint_key for item in results if item.outcome is CheckOutcome.FAIL}
            )
            if not passed or not failed:
                continue
            resource_label = resource.removeprefix("resource:")
            involved = sorted(set(passed) | set(failed))
            found.append(
                Correlation(
                    correlation_id=Correlation.make_id(
                        f"inconsistent_enforcement:{check_id}", involved
                    ),
                    kind="inconsistent_enforcement",
                    title=(
                        f"{check_id} passes on some '{resource_label}' operations and "
                        "fails on others"
                    ),
                    endpoints=involved,
                    supporting_results=sorted({item.result_id for item in results}),
                    supporting_edges=sorted(
                        edge.edge_id
                        for edge in edges
                        if edge.target == resource and _endpoint_key(edge.source) in involved
                    ),
                    evidence_ids=sorted({ref for item in results for ref in item.evidence_ids}),
                    provenance=Provenance.OBSERVED,
                    confidence=Confidence.HIGH,
                    confirmed=True,
                    reasoning=(
                        f"{check_id} was refused on {', '.join(passed)} and not refused on "
                        f"{', '.join(failed)}, all documented as acting on "
                        f"'{resource_label}'. The control exists but is applied unevenly, "
                        "which was observed directly on both sides."
                    ),
                    limitations=[
                        "The inconsistency is confirmed; its exploitability is not.",
                        "The operations may be intended to behave differently.",
                    ],
                )
            )
    return found


def _accumulated_weak_observations(
    assessment: AssessmentResult, edges: list[GraphEdge]
) -> list[Correlation]:
    """Several low-grade observations on one resource.

    Explicitly **not** confirmed and explicitly not escalated in severity. The
    output of this correlation is "a human should look at this resource", which
    is a different claim from "this resource is vulnerable".
    """
    members = _resource_members(edges)
    informational: dict[str, list[CheckResult]] = defaultdict(list)
    for result in assessment.results:
        if result.finding_class is FindingClass.INFORMATIONAL:
            informational[result.endpoint_key].append(result)

    found: list[Correlation] = []
    for resource, nodes in members.items():
        keys = [_endpoint_key(node) for node in nodes]
        gathered = [item for key in sorted(keys) for item in informational.get(key, [])]
        if len(gathered) < MIN_WEAK_OBSERVATIONS:
            continue
        resource_label = resource.removeprefix("resource:")
        categories = sorted({item.category.value for item in gathered})
        found.append(
            Correlation(
                correlation_id=Correlation.make_id("accumulated_observations", [resource_label]),
                kind="accumulated_observations",
                title=(
                    f"{len(gathered)} informational observations across the "
                    f"'{resource_label}' resource"
                ),
                endpoints=sorted({item.endpoint_key for item in gathered}),
                supporting_results=sorted({item.result_id for item in gathered}),
                evidence_ids=sorted({ref for item in gathered for ref in item.evidence_ids}),
                provenance=Provenance.OBSERVED,
                confidence=Confidence.LOW,
                confirmed=False,
                reasoning=(
                    f"Observations in {', '.join(categories)} accumulated on this "
                    "resource. Individually none is a weakness. Together they suggest "
                    "the resource is worth a manual pass, because a cluster of loose "
                    "ends often shares one cause."
                ),
                limitations=[
                    "Counting observations does not create a vulnerability.",
                    "This does not raise the severity of any individual observation.",
                    "No exploitable condition has been demonstrated.",
                ],
            )
        )
    return found


def correlations_for_endpoint(
    correlations: list[Correlation], endpoint_key: str
) -> list[Correlation]:
    """Correlations that involve one operation."""
    return [item for item in correlations if endpoint_key in item.endpoints]


def scope_note(discovery: DiscoveryResult) -> str | None:
    """Note how many discovered operations were never assessed.

    Worth stating in the report: correlations drawn from a partly tested surface
    are correspondingly partial.
    """
    skipped = [
        item
        for item in discovery.endpoints
        if item.classification is not ScopeClassification.IN_SCOPE
    ]
    if not skipped:
        return None
    return (
        f"{len(skipped)} of {len(discovery.endpoints)} discovered operation(s) were out "
        "of scope or unresolved and were never requested, so no correlation covers them."
    )


__all__ = [
    "MAX_CORRELATIONS",
    "MIN_WEAK_OBSERVATIONS",
    "correlate",
    "correlations_for_endpoint",
    "scope_note",
]
