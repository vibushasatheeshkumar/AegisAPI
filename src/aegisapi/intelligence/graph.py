"""Building the endpoint relationship graph.

Every edge records **what supports it**. That is the whole point of the
:class:`~aegisapi.models.intelligence.Provenance` field: a reader can tell the
difference between "the specification says these two operations return the same
schema" and "these two paths start with the same word".

Edges are created only from:

* **Specification metadata** - declared schemas, path nesting, parameters,
  security requirements.
* **Phase 3 structural observations** - reused rather than recomputed, so there
  is one implementation of "these paths are related".
* **Recorded evidence** - a check result linking a finding to an operation.
* **Operator fixtures** - a declared identity used against an operation.

Nothing is inferred from similar names alone. Two paths called ``/orders`` and
``/orderings`` get no edge, because nothing states they are related.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence

from aegisapi.discovery.relationships import looks_like_identifier
from aegisapi.models.assessment import AssessmentResult, CheckResult, FindingClass
from aegisapi.models.common import Confidence
from aegisapi.models.discovery import (
    ClassifiedEndpoint,
    DiscoveryResult,
    RelationshipKind,
    ScopeClassification,
)
from aegisapi.models.endpoint import Endpoint, SchemaSummary
from aegisapi.models.intelligence import EdgeKind, GraphEdge, GraphNode, NodeKind, Provenance
from aegisapi.testing.fixtures import AssessmentFixtures

MAX_NODES = 2000
"""Cap on graph size, so a large specification cannot produce unbounded work."""

MAX_EDGES = 6000
"""Cap on edge count."""


def endpoint_node_id(key: str) -> str:
    """Node identifier for an operation."""
    return f"endpoint:{key}"


def identifier_node_id(name: str) -> str:
    """Node identifier for a resource identifier."""
    return f"identifier:{name}"


def resource_node_id(name: str) -> str:
    """Node identifier for a resource or schema."""
    return f"resource:{name}"


def scheme_node_id(name: str) -> str:
    """Node identifier for a declared security scheme."""
    return f"scheme:{name}"


def identity_node_id(name: str) -> str:
    """Node identifier for a configured test identity."""
    return f"identity:{name}"


def finding_node_id(result: CheckResult) -> str:
    """Node identifier for a recorded finding."""
    return f"finding:{result.result_id}"


def _exposed_identifiers(schema: SchemaSummary | None, depth: int = 0) -> set[str]:
    """Identifier-shaped property names a declared schema contains.

    This is what links a collection operation to a detail operation: the list
    response declares an ``orderId``, and another operation accepts one. Both
    halves come from the document, so the edge is specification-backed rather
    than guessed.
    """
    if schema is None or depth > 3:
        return set()
    found: set[str] = set()
    for name, child in schema.properties.items():
        if looks_like_identifier(name):
            found.add(name)
        found |= _exposed_identifiers(child, depth + 1)
    found |= _exposed_identifiers(schema.items, depth + 1)
    for branch in schema.composed_of:
        found |= _exposed_identifiers(branch, depth + 1)
    return found


def _response_identifiers(endpoint: Endpoint) -> set[str]:
    """Identifiers the operation's declared success responses contain."""
    found: set[str] = set()
    for response in endpoint.responses:
        if not (response.status_code.startswith("2") or response.status_code == "default"):
            continue
        for media in response.content:
            found |= _exposed_identifiers(media.value_schema)
    return found


class GraphBuilder:
    """Assembles nodes and edges, de-duplicating and respecting the caps."""

    def __init__(self) -> None:
        self._nodes: dict[str, GraphNode] = {}
        self._edges: dict[str, GraphEdge] = {}
        self.truncated = False

    def add_node(self, node: GraphNode) -> str:
        """Add a node, keeping the first definition of an identifier."""
        if node.node_id not in self._nodes:
            if len(self._nodes) >= MAX_NODES:
                self.truncated = True
                return node.node_id
            self._nodes[node.node_id] = node
        return node.node_id

    def add_edge(self, edge: GraphEdge) -> None:
        """Add an edge, keeping the strongest provenance for a duplicate.

        When two sources justify the same relationship, the better-supported
        one wins. An edge never degrades from specification-backed to inferred
        because a weaker source mentioned it later.
        """
        if edge.source == edge.target:
            return
        if edge.source not in self._nodes or edge.target not in self._nodes:
            return
        existing = self._edges.get(edge.edge_id)
        if existing is None:
            if len(self._edges) >= MAX_EDGES:
                self.truncated = True
                return
            self._edges[edge.edge_id] = edge
            return
        order = list(Provenance)
        if order.index(edge.provenance) < order.index(existing.provenance):
            self._edges[edge.edge_id] = edge

    @property
    def nodes(self) -> list[GraphNode]:
        """Nodes, ordered by identifier for determinism."""
        return [self._nodes[key] for key in sorted(self._nodes)]

    @property
    def edges(self) -> list[GraphEdge]:
        """Edges, ordered by identifier for determinism."""
        return [self._edges[key] for key in sorted(self._edges)]

    def has_node(self, node_id: str) -> bool:
        """``True`` when the node exists."""
        return node_id in self._nodes

    def edges_from(self, node_id: str) -> list[GraphEdge]:
        """Outgoing edges from one node, in deterministic order."""
        return [edge for edge in self.edges if edge.source == node_id]


def build_graph(
    discovery: DiscoveryResult,
    assessment: AssessmentResult | None = None,
    fixtures: AssessmentFixtures | None = None,
) -> tuple[list[GraphNode], list[GraphEdge], bool]:
    """Build the relationship graph for one target.

    Args:
        discovery: The endpoint inventory. Supplies specification-backed edges.
        assessment: Check results, if any. Supplies evidence-backed edges.
        fixtures: Operator-declared identities, for ``TESTED_AS`` edges.

    Returns:
        Nodes, edges, and whether a cap truncated the graph.
    """
    builder = GraphBuilder()
    in_scope = [
        item for item in discovery.endpoints if item.classification is ScopeClassification.IN_SCOPE
    ]

    _add_endpoint_nodes(builder, discovery.endpoints)
    _add_scheme_edges(builder, in_scope)
    _add_identifier_edges(builder, in_scope)
    _add_structural_edges(builder, discovery)
    _add_auth_difference_edges(builder, discovery)
    if assessment is not None:
        _add_finding_edges(builder, assessment)
    if fixtures is not None and assessment is not None:
        _add_identity_edges(builder, assessment, fixtures)

    return builder.nodes, builder.edges, builder.truncated


def _add_endpoint_nodes(builder: GraphBuilder, endpoints: Sequence[ClassifiedEndpoint]) -> None:
    """Add one node per discovered operation."""
    for classified in endpoints:
        operation = classified.endpoint
        declared = operation.declared_security
        builder.add_node(
            GraphNode(
                node_id=endpoint_node_id(operation.key),
                kind=NodeKind.ENDPOINT,
                label=operation.key,
                attributes={
                    "method": operation.method.value.upper(),
                    "path": operation.path,
                    "classification": classified.classification.value,
                    "security_posture": declared.posture.value,
                    "declared_schemes": ", ".join(declared.scheme_names) or "none",
                    "permits_anonymous": str(declared.permits_anonymous).lower(),
                    "tags": ", ".join(operation.tags) or "none",
                    "templated": str(operation.is_templated).lower(),
                },
            )
        )


def _add_scheme_edges(builder: GraphBuilder, endpoints: Sequence[ClassifiedEndpoint]) -> None:
    """Link operations to the security schemes they declare."""
    for classified in endpoints:
        operation = classified.endpoint
        for scheme in operation.declared_security.scheme_names:
            builder.add_node(
                GraphNode(
                    node_id=scheme_node_id(scheme),
                    kind=NodeKind.SECURITY_SCHEME,
                    label=scheme,
                )
            )
            builder.add_edge(
                GraphEdge(
                    source=endpoint_node_id(operation.key),
                    target=scheme_node_id(scheme),
                    kind=EdgeKind.REQUIRES_SCHEME,
                    provenance=Provenance.SPECIFICATION,
                    confidence=Confidence.HIGH,
                    reason=f"the specification declares {scheme} for this operation",
                )
            )


def _add_identifier_edges(builder: GraphBuilder, endpoints: Sequence[ClassifiedEndpoint]) -> None:
    """Link operations to the identifiers they accept and expose.

    The pairing of these two edge kinds is what makes a traversal possible: one
    operation hands out an identifier, another accepts it.
    """
    for classified in endpoints:
        operation = classified.endpoint

        for name in operation.path_parameter_names:
            if not looks_like_identifier(name):
                continue
            builder.add_node(
                GraphNode(
                    node_id=identifier_node_id(name),
                    kind=NodeKind.IDENTIFIER,
                    label=name,
                )
            )
            builder.add_edge(
                GraphEdge(
                    source=endpoint_node_id(operation.key),
                    target=identifier_node_id(name),
                    kind=EdgeKind.ACCEPTS_IDENTIFIER,
                    provenance=Provenance.SPECIFICATION,
                    confidence=Confidence.HIGH,
                    reason=f"declared path parameter {name}",
                )
            )
            # The reverse direction, so a chain can run from an operation that
            # hands out an identifier to one that takes it.
            builder.add_edge(
                GraphEdge(
                    source=identifier_node_id(name),
                    target=endpoint_node_id(operation.key),
                    kind=EdgeKind.ACCEPTED_BY,
                    provenance=Provenance.SPECIFICATION,
                    confidence=Confidence.HIGH,
                    reason=f"{name} is accepted as a path parameter here",
                )
            )

        for name in sorted(_response_identifiers(operation)):
            builder.add_node(
                GraphNode(
                    node_id=identifier_node_id(name),
                    kind=NodeKind.IDENTIFIER,
                    label=name,
                )
            )
            builder.add_edge(
                GraphEdge(
                    source=endpoint_node_id(operation.key),
                    target=identifier_node_id(name),
                    kind=EdgeKind.EXPOSES_IDENTIFIER,
                    provenance=Provenance.SPECIFICATION,
                    confidence=Confidence.MEDIUM,
                    reason=f"declared response schema contains {name}",
                )
            )


def _add_structural_edges(builder: GraphBuilder, discovery: DiscoveryResult) -> None:
    """Convert Phase 3 structural observations into graph edges.

    Reused rather than recomputed. The provenance differs by kind: nested paths
    and shared schemas are statements in the document, while a shared path
    prefix is structure AegisAPI noticed.
    """
    for observation in discovery.relationships:
        keys = [key for key in observation.endpoint_keys if builder.has_node(endpoint_node_id(key))]
        if len(keys) < 2:
            continue

        if observation.kind is RelationshipKind.PARENT_CHILD:
            parent_path = observation.detail.get("parent_path", observation.subject)
            parents = [key for key in keys if key.endswith(f" {parent_path}")]
            children = [key for key in keys if key not in parents]
            for parent in parents:
                for child in children:
                    builder.add_edge(
                        GraphEdge(
                            source=endpoint_node_id(parent),
                            target=endpoint_node_id(child),
                            kind=EdgeKind.PARENT_OF,
                            provenance=Provenance.SPECIFICATION,
                            confidence=Confidence.HIGH,
                            reason=(
                                f"{child.split(' ', 1)[-1]} is nested beneath the identified "
                                f"resource {parent_path}"
                            ),
                        )
                    )
            continue

        if observation.kind is RelationshipKind.SHARED_SCHEMA:
            resource = resource_node_id(observation.subject)
            builder.add_node(
                GraphNode(
                    node_id=resource,
                    kind=NodeKind.RESOURCE,
                    label=observation.subject,
                    attributes={"source": "declared schema"},
                )
            )
            for key in keys:
                builder.add_edge(
                    GraphEdge(
                        source=endpoint_node_id(key),
                        target=resource,
                        kind=EdgeKind.SHARES_SCHEMA,
                        provenance=Provenance.SPECIFICATION,
                        confidence=Confidence.HIGH,
                        reason=f"operation references the declared {observation.subject} schema",
                    )
                )
            continue

        if observation.kind in {RelationshipKind.SHARED_PREFIX, RelationshipKind.CRUD_SET}:
            resource = resource_node_id(observation.subject)
            builder.add_node(
                GraphNode(
                    node_id=resource,
                    kind=NodeKind.RESOURCE,
                    label=observation.subject,
                    attributes={"source": "path structure"},
                )
            )
            for key in keys:
                builder.add_edge(
                    GraphEdge(
                        source=endpoint_node_id(key),
                        target=resource,
                        kind=EdgeKind.SHARES_RESOURCE,
                        provenance=Provenance.INFERRED,
                        confidence=Confidence.MEDIUM,
                        reason=(
                            f"operation acts under the {observation.subject} path, which is "
                            "structure rather than a documented statement"
                        ),
                    )
                )


def _add_auth_difference_edges(builder: GraphBuilder, discovery: DiscoveryResult) -> None:
    """Link operations on one resource that declare different authentication.

    Worth a graph edge because inconsistent requirements across one resource is
    exactly the shape that hides an unprotected route behind a protected one.
    """
    by_resource: dict[str, list[ClassifiedEndpoint]] = {}
    for classified in discovery.endpoints:
        if classified.classification is not ScopeClassification.IN_SCOPE:
            continue
        segments = classified.endpoint.path_segments
        root = f"/{segments[0]}" if segments else "/"
        by_resource.setdefault(root, []).append(classified)

    for root, group in sorted(by_resource.items()):
        if len(group) < 2:
            continue
        anonymous = [item for item in group if item.endpoint.declared_security.permits_anonymous]
        protected = [
            item
            for item in group
            if item.endpoint.declared_security.scheme_names
            and not item.endpoint.declared_security.permits_anonymous
        ]
        for open_endpoint in anonymous:
            for closed_endpoint in protected:
                builder.add_edge(
                    GraphEdge(
                        source=endpoint_node_id(open_endpoint.endpoint.key),
                        target=endpoint_node_id(closed_endpoint.endpoint.key),
                        kind=EdgeKind.AUTH_DIFFERS,
                        provenance=Provenance.SPECIFICATION,
                        confidence=Confidence.HIGH,
                        reason=(
                            f"both act under {root}, but one is documented as anonymous "
                            "and the other requires a declared scheme"
                        ),
                    )
                )


def _add_finding_edges(builder: GraphBuilder, assessment: AssessmentResult) -> None:
    """Link operations to findings recorded against them."""
    for result in assessment.results:
        if result.finding_class in {FindingClass.NONE, FindingClass.INCONCLUSIVE}:
            continue
        endpoint = endpoint_node_id(result.endpoint_key)
        if not builder.has_node(endpoint):
            continue
        node = finding_node_id(result)
        builder.add_node(
            GraphNode(
                node_id=node,
                kind=NodeKind.FINDING,
                label=f"{result.check_id}: {result.summary}"[:120],
                attributes={
                    "check_id": result.check_id,
                    "category": result.category.value,
                    "finding_class": result.finding_class.value,
                    "outcome": result.outcome.value,
                    "severity": result.severity.value if result.severity else "none",
                    "confidence": result.confidence.value,
                },
            )
        )
        builder.add_edge(
            GraphEdge(
                source=endpoint,
                target=node,
                kind=EdgeKind.AFFECTED_BY,
                provenance=(Provenance.OBSERVED if result.evidence else Provenance.SPECIFICATION),
                confidence=result.confidence,
                reason=f"{result.check_id} recorded {result.finding_class.value} here",
                evidence_ids=list(result.evidence_ids),
            )
        )


def _add_identity_edges(
    builder: GraphBuilder,
    assessment: AssessmentResult,
    fixtures: AssessmentFixtures,
) -> None:
    """Link operations to the declared identities they were exercised with."""
    declared = {item.name for item in fixtures.identities}
    for result in assessment.results:
        endpoint = endpoint_node_id(result.endpoint_key)
        if not builder.has_node(endpoint):
            continue
        for item in result.evidence:
            if item.identity is None or item.identity not in declared:
                continue
            node = identity_node_id(item.identity)
            identity = fixtures.identity(item.identity)
            builder.add_node(
                GraphNode(
                    node_id=node,
                    kind=NodeKind.IDENTITY,
                    label=item.identity,
                    attributes={"role": (identity.role if identity else None) or "unspecified"},
                )
            )
            builder.add_edge(
                GraphEdge(
                    source=endpoint,
                    target=node,
                    kind=EdgeKind.TESTED_AS,
                    provenance=Provenance.FIXTURE,
                    confidence=Confidence.HIGH,
                    reason=f"exercised with the declared identity {item.identity}",
                    evidence_ids=[item.evidence_id],
                )
            )


def endpoints_by_key(discovery: DiscoveryResult) -> dict[str, ClassifiedEndpoint]:
    """Index discovered endpoints by their ``METHOD /path`` key."""
    return {item.endpoint.key: item for item in discovery.endpoints}


def results_by_endpoint(
    assessment: AssessmentResult | None,
) -> dict[str, list[CheckResult]]:
    """Group check results by the operation they ran against."""
    grouped: dict[str, list[CheckResult]] = {}
    if assessment is None:
        return grouped
    for result in assessment.results:
        grouped.setdefault(result.endpoint_key, []).append(result)
    return grouped


def filter_edges(
    edges: Iterable[GraphEdge], *, kinds: Sequence[EdgeKind] | None = None
) -> list[GraphEdge]:
    """Select edges of particular kinds, preserving order."""
    if kinds is None:
        return list(edges)
    wanted = set(kinds)
    return [edge for edge in edges if edge.kind in wanted]


__all__ = [
    "MAX_EDGES",
    "MAX_NODES",
    "GraphBuilder",
    "build_graph",
    "endpoint_node_id",
    "endpoints_by_key",
    "filter_edges",
    "finding_node_id",
    "identifier_node_id",
    "identity_node_id",
    "resource_node_id",
    "results_by_endpoint",
    "scheme_node_id",
]
