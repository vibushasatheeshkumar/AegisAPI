"""Models for the relationship graph, correlations, risks, and attack paths.

The distinction this module exists to preserve is **what is known versus what
is inferred**. Every edge, correlation, and path step carries a
:class:`Provenance`, so a reader can always tell whether AegisAPI observed
something, read it in a specification, or guessed at it.

Risk is modelled with three separate quantities, never collapsed into one:

* **Severity** - how bad it would be if real.
* **Confidence** - how sure AegisAPI is that it is real.
* **Evidence strength** - how much direct observation backs it.

A high-severity, low-confidence item is a lead to verify, not a vulnerability
to report, and the model makes that difference expressible.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from collections.abc import Sequence
from datetime import UTC, datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

from aegisapi.models.common import Confidence, Severity

INTELLIGENCE_SCHEMA_VERSION = 1
"""Format version of a persisted intelligence document."""


class Provenance(StrEnum):
    """Where a relationship or conclusion came from.

    Ordered from strongest to weakest. Nothing in AegisAPI may upgrade a
    weaker provenance into a stronger one.
    """

    OBSERVED = "observed"
    """AegisAPI sent a request and saw this behaviour."""

    FIXTURE = "fixture"
    """The operator declared it: a test identity, an owned object, a policy."""

    SPECIFICATION = "specification"
    """The API's own document states it."""

    INFERRED = "inferred"
    """Derived from structure, such as a shared path prefix. Not stated anywhere."""

    HYPOTHETICAL = "hypothetical"
    """A transition that would be possible if an assumption held. Never evidence."""

    @property
    def is_evidence(self) -> bool:
        """``True`` for provenances backed by something concrete."""
        return self in {Provenance.OBSERVED, Provenance.FIXTURE, Provenance.SPECIFICATION}


class NodeKind(StrEnum):
    """What a graph node represents."""

    ENDPOINT = "endpoint"
    RESOURCE = "resource"
    IDENTIFIER = "identifier"
    SECURITY_SCHEME = "security_scheme"
    IDENTITY = "identity"
    FINDING = "finding"


class EdgeKind(StrEnum):
    """What a graph edge asserts."""

    SHARES_RESOURCE = "shares_resource"
    """Two operations act on the same documented resource."""

    PARENT_OF = "parent_of"
    """One resource path is nested beneath an identified parent."""

    ACCEPTS_IDENTIFIER = "accepts_identifier"
    """An operation takes this identifier as input."""

    ACCEPTED_BY = "accepted_by"
    """This identifier is accepted as input by that operation.

    The reverse of :attr:`ACCEPTS_IDENTIFIER`, recorded explicitly rather than
    traversed backwards. A chain reads "A exposes an identifier, which B
    accepts", and a traversal that silently reversed an edge would be far
    harder to audit than one that follows a stated relationship.
    """

    EXPOSES_IDENTIFIER = "exposes_identifier"
    """An operation's declared response contains this identifier."""

    SHARES_SCHEMA = "shares_schema"
    """Two operations reference the same declared schema."""

    REQUIRES_SCHEME = "requires_scheme"
    """An operation declares this security scheme."""

    AUTH_DIFFERS = "auth_differs"
    """Two related operations declare different authentication requirements."""

    AFFECTED_BY = "affected_by"
    """An operation is affected by a recorded finding."""

    TESTED_AS = "tested_as"
    """An operation was exercised with this configured identity."""


class GraphNode(BaseModel):
    """One entity in the relationship graph."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    node_id: str = Field(description="Stable identifier, such as 'endpoint:GET /users/{id}'.")
    kind: NodeKind = Field(description="What this node represents.")
    label: str = Field(description="Human-readable name.")
    attributes: dict[str, str] = Field(
        default_factory=dict, description="Extra facts, as text, for display and reasoning."
    )


class GraphEdge(BaseModel):
    """A relationship between two nodes, with its provenance.

    An edge is only created when something supports it: a specification
    statement, operator-declared fixture, or recorded evidence. Similar names
    are not a reason.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    source: str = Field(description="Identifier of the source node.")
    target: str = Field(description="Identifier of the target node.")
    kind: EdgeKind = Field(description="What the edge asserts.")
    provenance: Provenance = Field(description="What supports it.")
    confidence: Confidence = Field(
        default=Confidence.MEDIUM, description="How sure AegisAPI is of the relationship."
    )
    reason: str = Field(description="Why this edge exists, in one line.")
    evidence_ids: list[str] = Field(
        default_factory=list, description="Evidence supporting it, by identifier."
    )

    @property
    def edge_id(self) -> str:
        """Stable identifier for this edge."""
        return f"{self.source}--{self.kind.value}->{self.target}"


class Correlation(BaseModel):
    """A conclusion drawn from more than one endpoint or result.

    ``confirmed`` is deliberately conservative: several weak observations never
    add up to a confirmed issue. They add up to a reason for a human to look.
    """

    model_config = ConfigDict(extra="forbid")

    correlation_id: str = Field(description="Stable identifier.")
    kind: str = Field(description="Short machine-readable category.")
    title: str = Field(description="One line naming the pattern.")
    endpoints: list[str] = Field(
        default_factory=list, description="Operations involved, as 'METHOD /path'."
    )
    supporting_results: list[str] = Field(
        default_factory=list, description="Check results involved, by result identifier."
    )
    supporting_edges: list[str] = Field(
        default_factory=list, description="Graph edges that justify the link."
    )
    evidence_ids: list[str] = Field(
        default_factory=list, description="Evidence referenced, never duplicated."
    )
    provenance: Provenance = Field(description="Strongest support behind the correlation.")
    confidence: Confidence = Field(description="How sure AegisAPI is.")
    confirmed: bool = Field(
        default=False,
        description="True only when direct evidence establishes the correlation itself.",
    )
    reasoning: str = Field(description="How the conclusion follows from the inputs.")
    limitations: list[str] = Field(
        default_factory=list, description="What this correlation does not establish."
    )

    @staticmethod
    def make_id(kind: str, endpoints: list[str]) -> str:
        """Build a stable correlation identifier from its inputs."""
        digest = hashlib.sha256(f"{kind}|{'|'.join(sorted(endpoints))}".encode()).hexdigest()
        return f"cor-{digest[:16]}"


class RiskFactor(BaseModel):
    """One documented contribution to a risk score.

    Every factor states its own weight and why it applied, so a score can be
    read back as an argument rather than taken on trust.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str = Field(description="Factor identifier, such as 'confirmed_finding'.")
    points: float = Field(description="Points contributed. May be negative.")
    reason: str = Field(description="Why the factor applied.")


class RiskBand(StrEnum):
    """Priority band a risk falls into."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class PrioritisedRisk(BaseModel):
    """A risk with its score, its reasoning, and what remains unverified."""

    model_config = ConfigDict(extra="forbid")

    risk_id: str = Field(description="Stable identifier, usable with 'risk explain'.")
    title: str = Field(description="One line naming the risk.")
    band: RiskBand = Field(description="Priority band.")
    score: float = Field(ge=0, le=100, description="Deterministic priority score.")
    severity: Severity = Field(description="Impact if the risk is real.")
    confidence: Confidence = Field(description="How sure AegisAPI is that it is real.")
    evidence_strength: int = Field(ge=0, description="Count of direct observations behind it.")
    confirmed: bool = Field(
        default=False, description="Whether direct evidence establishes the security claim."
    )
    category: str = Field(description="Security area the risk belongs to.")
    endpoints: list[str] = Field(default_factory=list, description="Operations involved.")
    factors: list[RiskFactor] = Field(
        default_factory=list, description="Every scoring contribution, with its reason."
    )
    source_results: list[str] = Field(
        default_factory=list, description="Check results behind the risk."
    )
    source_correlations: list[str] = Field(
        default_factory=list, description="Correlations behind the risk."
    )
    evidence_ids: list[str] = Field(default_factory=list, description="Evidence referenced.")
    what_was_observed: str = Field(description="What AegisAPI actually saw.")
    why_it_matters: str = Field(description="Why the observation is worth attention.")
    unverified: list[str] = Field(
        default_factory=list, description="What has not been established."
    )
    next_step: str = Field(description="The next verification a researcher should perform.")


class PathStepKind(StrEnum):
    """What kind of transition a path step represents."""

    OBSERVED = "observed"
    DOCUMENTED = "documented"
    INFERRED = "inferred"
    HYPOTHETICAL = "hypothetical"


class AttackPathStep(BaseModel):
    """One transition in a potential attack path."""

    model_config = ConfigDict(extra="forbid")

    from_node: str = Field(description="Node the step starts at.")
    to_node: str = Field(description="Node the step reaches.")
    edge_kind: EdgeKind = Field(description="Relationship traversed.")
    kind: PathStepKind = Field(description="How well supported this transition is.")
    description: str = Field(description="What the step means, in one line.")
    evidence_ids: list[str] = Field(default_factory=list, description="Evidence for the step.")


PATH_ID_PATTERN = re.compile(r"^path-[0-9a-f]{16}$")
"""Shape of an identifier produced by :meth:`AttackPath.make_id`."""

LEGACY_PATH_ID_PATTERN = re.compile(r"^path-\d{12}$")
"""Shape of an identifier produced by the superseded algorithm.

Earlier builds derived ``path_id`` from Python's built-in :func:`hash`, which is
randomised per process, so those identifiers are **not** reproducible - not even
by re-running the same analysis over the same inputs. They are recognisable by
shape, twelve decimal digits rather than sixteen hexadecimal characters, which
is what lets a consumer tell "this identifier cannot be matched" apart from
"this path is absent".

Saved documents containing them remain readable and are never rewritten. A
comparison between records must not match on ``path_id`` when either side is
legacy; see :func:`is_legacy_path_id`.
"""


def is_legacy_path_id(value: str) -> bool:
    """``True`` when ``value`` came from the superseded, non-reproducible scheme.

    A consumer comparing two stored analyses uses this to decide whether
    ``path_id`` carries any meaning across the pair. A legacy identifier is not
    wrong, it is simply unrepeatable, so a comparison should fall back to
    comparing the route itself or report attack paths as not comparable rather
    than inventing a difference.
    """
    return bool(LEGACY_PATH_ID_PATTERN.match(value))


class AttackPath(BaseModel):
    """A multi-step relationship that may be worth investigating.

    A path is a **hypothesis about reachability**, not a demonstrated exploit.
    ``weakest_step`` names the least supported transition, which is where a
    researcher should start, and a path containing a hypothetical step is never
    described as exploitable.
    """

    model_config = ConfigDict(extra="forbid")

    path_id: str = Field(description="Stable identifier.")
    title: str = Field(description="One line naming the path.")
    steps: list[AttackPathStep] = Field(default_factory=list, description="Ordered transitions.")
    endpoints: list[str] = Field(default_factory=list, description="Operations traversed.")
    severity: Severity = Field(description="Impact if the whole path held.")
    confidence: Confidence = Field(description="How sure AegisAPI is of the path.")
    weakest_step: PathStepKind = Field(
        description="Least supported transition in the path; the place to verify first."
    )
    fully_evidenced: bool = Field(
        default=False, description="True only when every step is observed or documented."
    )
    reasoning: str = Field(description="How the steps connect.")
    unverified: list[str] = Field(
        default_factory=list, description="What would have to be proven to realise the path."
    )

    @property
    def length(self) -> int:
        """How many transitions the path contains."""
        return len(self.steps)

    @staticmethod
    def make_id(steps: Sequence[AttackPathStep]) -> str:
        """Build a stable identifier from the route a path takes.

        The identity of a path is **where it goes**: for every step, the node it
        starts from, the relationship it traverses, and the node it reaches.
        Those three are what make one path a different path from another.

        Deliberately excluded, because each can change while the path stays the
        same one:

        * ``kind`` - how well a step is supported. A transition upgraded from
          inferred to observed is better evidence for the same route, so folding
          it into the identity would make a path vanish and a new one appear.
        * ``description`` - prose that may be reworded.
        * ``severity``, ``confidence``, ``fully_evidenced``, ``unverified`` -
          judgements about the path, not the path itself. Severity in particular
          must not drive identity, or a re-rated finding would break matching.
        * Timestamps, and the position of the path in any list.

        The route is serialised as JSON before hashing so that a node name
        containing a separator character cannot be confused with the boundary
        between fields. ``hashlib.sha256`` replaces the built-in :func:`hash`
        used by earlier builds, which was randomised per process and therefore
        produced a different identifier on every run; see
        :data:`LEGACY_PATH_ID_PATTERN`.

        Args:
            steps: The path's transitions, in order.

        Returns:
            An identifier matching :data:`PATH_ID_PATTERN`, reproducible in any
            process on any machine for the same route.
        """
        route: list[str] = []
        for step in steps:
            route.extend((step.from_node, step.edge_kind.value, step.to_node))
        canonical = json.dumps(route, ensure_ascii=True, separators=(",", ":"))
        digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        return f"path-{digest[:16]}"


class IntelligenceReport(BaseModel):
    """The output of contextual risk analysis for one target.

    Derived entirely from a discovery result and an assessment result, both of
    which it references rather than duplicating. Running it twice over the same
    inputs produces the same document.
    """

    model_config = ConfigDict(extra="forbid")

    schema_version: int = Field(default=INTELLIGENCE_SCHEMA_VERSION, ge=1)
    target_name: str = Field(description="Target analysed.")
    nodes: list[GraphNode] = Field(default_factory=list, description="Graph nodes.")
    edges: list[GraphEdge] = Field(default_factory=list, description="Graph edges.")
    correlations: list[Correlation] = Field(
        default_factory=list, description="Cross-endpoint conclusions."
    )
    risks: list[PrioritisedRisk] = Field(
        default_factory=list, description="Risks, highest priority first."
    )
    attack_paths: list[AttackPath] = Field(
        default_factory=list, description="Potential multi-step relationships."
    )
    notes: list[str] = Field(
        default_factory=list, description="Limits of this analysis, stated plainly."
    )
    analysed_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC), description="When analysis ran (UTC)."
    )
    aegisapi_version: str = Field(description="AegisAPI version that produced it.")

    def risk(self, risk_id: str) -> PrioritisedRisk | None:
        """Look up one risk by identifier."""
        for item in self.risks:
            if item.risk_id == risk_id:
                return item
        return None

    def band_counts(self) -> dict[RiskBand, int]:
        """How many risks fall into each band."""
        counts = Counter(item.band for item in self.risks)
        return {value: counts.get(value, 0) for value in RiskBand}

    def edges_by_provenance(self) -> dict[Provenance, int]:
        """How many edges came from each kind of support."""
        counts = Counter(item.provenance for item in self.edges)
        return {value: counts.get(value, 0) for value in Provenance}

    def confirmed_risks(self) -> list[PrioritisedRisk]:
        """Risks whose security claim is established by direct evidence."""
        return [item for item in self.risks if item.confirmed]


__all__ = [
    "INTELLIGENCE_SCHEMA_VERSION",
    "LEGACY_PATH_ID_PATTERN",
    "PATH_ID_PATTERN",
    "AttackPath",
    "AttackPathStep",
    "Correlation",
    "EdgeKind",
    "GraphEdge",
    "GraphNode",
    "IntelligenceReport",
    "NodeKind",
    "PathStepKind",
    "PrioritisedRisk",
    "Provenance",
    "RiskBand",
    "RiskFactor",
    "is_legacy_path_id",
]
