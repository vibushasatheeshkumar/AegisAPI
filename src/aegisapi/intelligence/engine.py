"""Running the analysis: graph, correlations, risks, paths.

A thin orchestrator. Each stage lives in its own module; this one wires them
together, collects the notes that qualify the result, and produces an
:class:`~aegisapi.models.intelligence.IntelligenceReport`.

The analysis is **local and deterministic**. It sends no requests, needs no
service, and running it twice over the same discovery and assessment produces
the same report apart from the timestamp.
"""

from __future__ import annotations

from collections import defaultdict

from aegisapi import __version__
from aegisapi.intelligence.attack_paths import find_attack_paths, path_note
from aegisapi.intelligence.correlation import correlate, scope_note
from aegisapi.intelligence.graph import build_graph
from aegisapi.intelligence.risk import build_risks
from aegisapi.models.assessment import AssessmentResult
from aegisapi.models.discovery import DiscoveryResult, ScopeClassification
from aegisapi.models.intelligence import EdgeKind, GraphEdge, IntelligenceReport
from aegisapi.testing.fixtures import AssessmentFixtures


def _anonymous_endpoints(discovery: DiscoveryResult) -> set[str]:
    """Operations the specification documents as callable without credentials."""
    return {
        item.endpoint.key
        for item in discovery.endpoints
        if item.endpoint.declared_security.permits_anonymous
    }


def _resource_groups(edges: list[GraphEdge]) -> dict[str, set[str]]:
    """Operations grouped by the resource node they are linked to."""
    groups: dict[str, set[str]] = defaultdict(set)
    for edge in edges:
        if edge.kind in {EdgeKind.SHARES_SCHEMA, EdgeKind.SHARES_RESOURCE}:
            groups[edge.target].add(edge.source.removeprefix("endpoint:"))
    return {key: value for key, value in groups.items() if len(value) > 1}


def analyse(
    discovery: DiscoveryResult,
    assessment: AssessmentResult | None = None,
    fixtures: AssessmentFixtures | None = None,
) -> IntelligenceReport:
    """Produce contextual risk intelligence for one target.

    Args:
        discovery: The endpoint inventory. Required; the graph is built from it.
        assessment: Check results. Without them the report contains the graph
            and specification-backed correlations but no risks, because a risk
            needs a finding.
        fixtures: Operator-declared identities, used for provenance on
            identity-linked edges.

    Returns:
        A report whose every conclusion carries its provenance and its limits.
    """
    nodes, edges, truncated = build_graph(discovery, assessment, fixtures)
    correlations = correlate(discovery, assessment, edges)
    groups = _resource_groups(edges)

    risks = (
        build_risks(
            assessment,
            correlations,
            anonymous_endpoints=_anonymous_endpoints(discovery),
            resource_groups=groups,
        )
        if assessment is not None
        else []
    )
    paths = find_attack_paths(nodes, edges, assessment)

    notes: list[str] = [path_note()]
    if assessment is None:
        notes.append(
            "No assessment was supplied, so this report contains relationships only. "
            "Run 'aegisapi check run' to add evidence-backed findings."
        )
    skipped = scope_note(discovery)
    if skipped:
        notes.append(skipped)
    if truncated:
        notes.append("The graph hit its size cap, so some relationships were not recorded.")
    untested = _untested_note(discovery, assessment)
    if untested:
        notes.append(untested)

    return IntelligenceReport(
        target_name=discovery.target_name,
        nodes=nodes,
        edges=edges,
        correlations=correlations,
        risks=risks,
        attack_paths=paths,
        notes=notes,
        aegisapi_version=__version__,
    )


def _untested_note(discovery: DiscoveryResult, assessment: AssessmentResult | None) -> str | None:
    """Say how much of the in-scope surface produced no evidence."""
    if assessment is None:
        return None
    in_scope = {
        item.endpoint.key
        for item in discovery.endpoints
        if item.classification is ScopeClassification.IN_SCOPE
    }
    if not in_scope:
        return "No discovered operation was in scope, so nothing was assessed."
    exercised = {result.endpoint_key for result in assessment.results if result.requests_sent > 0}
    missing = in_scope - exercised
    if not missing:
        return None
    return (
        f"{len(missing)} of {len(in_scope)} in-scope operation(s) produced no requests, "
        "so conclusions about them rest on the specification alone."
    )


__all__ = ["analyse"]
