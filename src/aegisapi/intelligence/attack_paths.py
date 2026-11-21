"""Potential multi-step relationships between operations.

The canonical shape is::

    collection endpoint -> exposes identifier -> detail endpoint -> finding

Each arrow is labelled with how well it is supported. The first two come from
the specification; the last comes from a recorded check result. A path is a
**hypothesis about reachability**, never a demonstrated exploit, and
:attr:`AttackPath.weakest_step` names the transition a researcher should verify
first.

Two guards keep this honest and bounded:

* A path that contains a hypothetical step is never called fully evidenced,
  and the word "exploitable" appears nowhere in what this module produces.
* Traversal is capped by depth, by branching, and by result count, so a dense
  graph cannot produce unbounded work.

Identifiers come from :meth:`AttackPath.make_id`, a digest of the route itself,
so the same graph yields the same ``path_id`` in any process. That is what makes
the final sort below total rather than arbitrary, and it is a precondition for
comparing one stored analysis against another: an identifier that changed every
run could not be matched across records.
"""

from __future__ import annotations

from collections import defaultdict

from aegisapi.models.assessment import AssessmentResult, CheckResult, FindingClass
from aegisapi.models.common import Confidence, Severity
from aegisapi.models.intelligence import (
    AttackPath,
    AttackPathStep,
    EdgeKind,
    GraphEdge,
    GraphNode,
    PathStepKind,
    Provenance,
)

MAX_DEPTH = 4
"""Longest path, in transitions. Beyond this, relevance decays faster than cost."""

MAX_PATHS = 25
"""Most paths reported."""

MAX_BRANCHING = 12
"""Most successors explored from any one node."""

_PROVENANCE_TO_STEP: dict[Provenance, PathStepKind] = {
    Provenance.OBSERVED: PathStepKind.OBSERVED,
    Provenance.FIXTURE: PathStepKind.OBSERVED,
    Provenance.SPECIFICATION: PathStepKind.DOCUMENTED,
    Provenance.INFERRED: PathStepKind.INFERRED,
    Provenance.HYPOTHETICAL: PathStepKind.HYPOTHETICAL,
}

_STEP_RANK: dict[PathStepKind, int] = {
    PathStepKind.OBSERVED: 0,
    PathStepKind.DOCUMENTED: 1,
    PathStepKind.INFERRED: 2,
    PathStepKind.HYPOTHETICAL: 3,
}

_SEVERITY_RANK: dict[Severity, int] = {
    Severity.CRITICAL: 4,
    Severity.HIGH: 3,
    Severity.MEDIUM: 2,
    Severity.LOW: 1,
    Severity.INFO: 0,
}

TRAVERSABLE_EDGES: frozenset[EdgeKind] = frozenset(
    {
        EdgeKind.EXPOSES_IDENTIFIER,
        EdgeKind.ACCEPTED_BY,
        EdgeKind.PARENT_OF,
        EdgeKind.SHARES_SCHEMA,
        EdgeKind.AFFECTED_BY,
    }
)
"""Edge kinds a path may traverse.

``SHARES_RESOURCE`` is excluded on purpose: a shared path prefix is inferred
structure, and chaining through it would manufacture paths out of naming.
``ACCEPTS_IDENTIFIER`` is excluded because it points from an operation to an
identifier; ``ACCEPTED_BY`` carries the direction a chain needs.
"""


def _endpoint_key(node_id: str) -> str:
    """Recover an operation key from its node identifier."""
    return node_id.removeprefix("endpoint:")


def _weakest(steps: list[AttackPathStep]) -> PathStepKind:
    """The least supported transition in a path."""
    return max((step.kind for step in steps), key=lambda kind: _STEP_RANK[kind])


def _confidence_for(steps: list[AttackPathStep], finding: CheckResult) -> Confidence:
    """Path confidence: never better than its weakest link or its finding.

    A chain of documented relationships ending in a suspected finding is a
    suspected path. Taking the maximum anywhere would let a strong step carry a
    weak one.
    """
    weakest = _weakest(steps)
    ceiling = {
        PathStepKind.OBSERVED: Confidence.HIGH,
        PathStepKind.DOCUMENTED: Confidence.MEDIUM,
        PathStepKind.INFERRED: Confidence.LOW,
        PathStepKind.HYPOTHETICAL: Confidence.LOW,
    }[weakest]
    order = [Confidence.LOW, Confidence.MEDIUM, Confidence.HIGH, Confidence.CONFIRMED]
    return min(ceiling, finding.confidence, key=order.index)


def find_attack_paths(
    nodes: list[GraphNode],
    edges: list[GraphEdge],
    assessment: AssessmentResult | None,
) -> list[AttackPath]:
    """Find paths from a reachable operation to one carrying a finding.

    Only paths that *end* at a finding are reported. A walk through the graph
    that reaches nothing of concern is not an attack path, it is a sitemap.
    """
    if assessment is None:
        return []

    findings = {result.result_id: result for result in assessment.results if result.is_finding}
    if not findings:
        return []

    outgoing: dict[str, list[GraphEdge]] = defaultdict(list)
    for edge in edges:
        if edge.kind in TRAVERSABLE_EDGES:
            outgoing[edge.source].append(edge)
    for key in outgoing:
        outgoing[key] = sorted(outgoing[key], key=lambda item: item.edge_id)[:MAX_BRANCHING]

    finding_nodes = {node.node_id: node for node in nodes if node.node_id.startswith("finding:")}
    starts = sorted(
        node.node_id
        for node in nodes
        if node.kind.value == "endpoint" and node.attributes.get("permits_anonymous") == "true"
    )
    if not starts:
        # No documented anonymous entry point. Start from every operation that
        # exposes an identifier, which is the other way a chain begins.
        starts = sorted({edge.source for edge in edges if edge.kind is EdgeKind.EXPOSES_IDENTIFIER})

    paths: list[AttackPath] = []
    seen: set[tuple[str, ...]] = set()

    for start in starts:
        for route in _walk(start, outgoing, MAX_DEPTH):
            terminal = route[-1].target
            if terminal not in finding_nodes:
                continue
            signature = (route[0].source, *(edge.target for edge in route))
            if signature in seen:
                continue
            seen.add(signature)

            node = finding_nodes[terminal]
            result = findings.get(node.node_id.removeprefix("finding:"))
            if result is None:
                continue

            built = _build_path(route, result, nodes)
            if built is not None:
                paths.append(built)
            if len(paths) >= MAX_PATHS * 2:
                break
        if len(paths) >= MAX_PATHS * 2:
            break

    paths.sort(
        key=lambda item: (
            -_SEVERITY_RANK[item.severity],
            _STEP_RANK[item.weakest_step],
            -item.length,
            item.path_id,
        )
    )
    return paths[:MAX_PATHS]


def _walk(
    start: str,
    outgoing: dict[str, list[GraphEdge]],
    depth: int,
) -> list[list[GraphEdge]]:
    """Enumerate bounded routes from one node.

    Depth-limited and cycle-free. Returns the edge sequences themselves so the
    caller can label each transition with its provenance.
    """
    routes: list[list[GraphEdge]] = []
    stack: list[tuple[str, list[GraphEdge], set[str]]] = [(start, [], {start})]

    while stack:
        current, route, visited = stack.pop()
        if len(route) >= depth:
            continue
        for edge in outgoing.get(current, []):
            if edge.target in visited:
                continue
            extended = [*route, edge]
            routes.append(extended)
            if len(extended) < depth:
                stack.append((edge.target, extended, visited | {edge.target}))
        if len(routes) > MAX_PATHS * 10:
            break
    return routes


def _build_path(
    route: list[GraphEdge],
    finding: CheckResult,
    nodes: list[GraphNode],
) -> AttackPath | None:
    """Turn an edge sequence into a described path."""
    labels = {node.node_id: node.label for node in nodes}
    steps: list[AttackPathStep] = []
    for edge in route:
        steps.append(
            AttackPathStep(
                from_node=edge.source,
                to_node=edge.target,
                edge_kind=edge.kind,
                kind=_PROVENANCE_TO_STEP[edge.provenance],
                description=edge.reason,
                evidence_ids=list(edge.evidence_ids),
            )
        )
    if not steps:
        return None

    endpoints = [
        _endpoint_key(node)
        for node in [route[0].source, *(edge.target for edge in route)]
        if node.startswith("endpoint:")
    ]
    weakest = _weakest(steps)
    fully_evidenced = weakest in {PathStepKind.OBSERVED, PathStepKind.DOCUMENTED}
    entry = labels.get(route[0].source, route[0].source)

    return AttackPath(
        path_id=AttackPath.make_id(steps),
        title=(
            f"{entry} leads to {finding.check_id} on {finding.endpoint_key}"
            if endpoints
            else f"Route to {finding.check_id}"
        ),
        steps=steps,
        endpoints=sorted(set(endpoints)),
        severity=finding.severity or Severity.INFO,
        confidence=_confidence_for(steps, finding),
        weakest_step=weakest,
        fully_evidenced=fully_evidenced and finding.finding_class is FindingClass.CONFIRMED,
        reasoning=(
            "Each step is supported by the relationship named in its description: "
            + "; ".join(f"{step.kind.value} - {step.description}" for step in steps[:4])
            + f". The route ends at {finding.check_id}, recorded as "
            f"{finding.finding_class.value}."
        ),
        unverified=[
            "The steps were not chained together in a single live request sequence.",
            (
                "Whether an identifier obtained from one operation is accepted by "
                "another was not tested."
            ),
            *(
                ["The terminal finding is suspected rather than confirmed."]
                if finding.finding_class is not FindingClass.CONFIRMED
                else []
            ),
            *(
                [f"At least one step is {weakest.value} rather than observed."]
                if weakest is not PathStepKind.OBSERVED
                else []
            ),
        ],
    )


def path_note() -> str:
    """The sentence every attack-path listing carries."""
    return (
        "An attack path is a hypothesis about reachability built from documented "
        "relationships and recorded findings. None of these has been executed as a "
        "chain, and none should be described as exploitable without verification."
    )


__all__ = [
    "MAX_BRANCHING",
    "MAX_DEPTH",
    "MAX_PATHS",
    "TRAVERSABLE_EDGES",
    "find_attack_paths",
    "path_note",
]
