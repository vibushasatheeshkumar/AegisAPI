"""The intelligence engine: graph, correlation, risk, and attack paths.

The recurring assertions are about epistemic honesty: every edge carries
provenance, counting weak observations never produces a confirmed finding, and
an unverified path is never described as exploitable.
"""

from __future__ import annotations

import pytest

from aegisapi.intelligence import analyse
from aegisapi.intelligence.attack_paths import MAX_DEPTH, MAX_PATHS, find_attack_paths
from aegisapi.intelligence.correlation import correlate
from aegisapi.intelligence.graph import MAX_NODES, build_graph
from aegisapi.intelligence.risk import (
    MAX_BREADTH_POINTS,
    SEVERITY_POINTS,
    band_for,
    build_risks,
    model_description,
    score_result,
)
from aegisapi.models.assessment import CheckCategory, CheckOutcome, FindingClass
from aegisapi.models.common import Confidence, Severity
from aegisapi.models.discovery import ScopeClassification
from aegisapi.models.endpoint import SchemaSummary
from aegisapi.models.intelligence import EdgeKind, PathStepKind, Provenance, RiskBand
from aegisapi.models.secrets import SecretRef
from aegisapi.models.target import AuthMethod, AuthProfile
from aegisapi.testing.fixtures import AssessmentFixtures, AssessmentIdentity
from assessfix import (
    assessment_result,
    check_result,
    classified,
    discovery_result,
    parent_child_observation,
    path_param,
    protected,
    public,
    shared_schema_observation,
)


def order_schema() -> SchemaSummary:
    """A schema declaring an identifier-shaped property."""
    return SchemaSummary(
        type="object",
        required=["orderId"],
        properties={
            "orderId": SchemaSummary(type="string"),
            "total": SchemaSummary(type="number"),
        },
    )


def two_endpoint_discovery():
    """A collection and a detail operation sharing the Order schema."""
    collection = public(
        "get",
        "/orders",
        response_schema=SchemaSummary(type="array", items=order_schema()),
        tags=("orders",),
    )
    detail = protected(
        "get",
        "/orders/{orderId}",
        parameters=[path_param("orderId")],
        response_schema=order_schema(),
        tags=("orders",),
    )
    return discovery_result(
        [classified(collection), classified(detail)],
        relationships=[
            shared_schema_observation("Order", ["GET /orders", "GET /orders/{orderId}"]),
        ],
    )


class TestGraphConstruction:
    def test_every_operation_becomes_a_node(self) -> None:
        nodes, _, _ = build_graph(two_endpoint_discovery())

        endpoints = [node for node in nodes if node.node_id.startswith("endpoint:")]
        assert len(endpoints) == 2

    def test_every_edge_records_its_provenance(self) -> None:
        _, edges, _ = build_graph(two_endpoint_discovery())

        assert edges
        assert all(isinstance(edge.provenance, Provenance) for edge in edges)
        assert all(edge.reason for edge in edges)

    def test_declared_schemes_become_specification_edges(self) -> None:
        _, edges, _ = build_graph(two_endpoint_discovery())

        scheme = [edge for edge in edges if edge.kind is EdgeKind.REQUIRES_SCHEME]
        assert scheme
        assert all(edge.provenance is Provenance.SPECIFICATION for edge in scheme)

    def test_identifier_edges_link_exposure_to_acceptance(self) -> None:
        _, edges, _ = build_graph(two_endpoint_discovery())

        exposes = [edge for edge in edges if edge.kind is EdgeKind.EXPOSES_IDENTIFIER]
        accepts = [edge for edge in edges if edge.kind is EdgeKind.ACCEPTS_IDENTIFIER]

        assert any(edge.target == "identifier:orderId" for edge in exposes)
        assert any(edge.target == "identifier:orderId" for edge in accepts)

    def test_shared_schema_is_specification_backed(self) -> None:
        _, edges, _ = build_graph(two_endpoint_discovery())

        shared = [edge for edge in edges if edge.kind is EdgeKind.SHARES_SCHEMA]
        assert shared
        assert all(edge.provenance is Provenance.SPECIFICATION for edge in shared)

    def test_a_shared_path_prefix_is_only_inferred(self) -> None:
        from aegisapi.models.discovery import RelationshipKind, RelationshipObservation

        discovery = discovery_result(
            [classified(public("get", "/orders")), classified(public("post", "/orders"))],
            relationships=[
                RelationshipObservation(
                    kind=RelationshipKind.SHARED_PREFIX,
                    subject="/orders",
                    description="shared prefix",
                    endpoint_keys=["GET /orders", "POST /orders"],
                )
            ],
        )

        _, built, _ = build_graph(discovery)
        shared = [edge for edge in built if edge.kind is EdgeKind.SHARES_RESOURCE]

        # Structure, not a documented statement.
        assert shared
        assert all(edge.provenance is Provenance.INFERRED for edge in shared)

    def test_similar_names_alone_create_no_edge(self) -> None:
        discovery = discovery_result(
            [classified(public("get", "/orders")), classified(public("get", "/orderings"))]
        )

        _, edges, _ = build_graph(discovery)

        assert not [edge for edge in edges if edge.kind is EdgeKind.SHARES_RESOURCE]

    def test_parent_child_becomes_a_specification_edge(self) -> None:
        discovery = discovery_result(
            [
                classified(
                    protected("get", "/orders/{orderId}", parameters=[path_param("orderId")])
                ),
                classified(
                    protected("get", "/orders/{orderId}/items", parameters=[path_param("orderId")])
                ),
            ],
            relationships=[
                parent_child_observation(
                    "/orders/{orderId}",
                    ["GET /orders/{orderId}", "GET /orders/{orderId}/items"],
                )
            ],
        )

        _, edges, _ = build_graph(discovery)
        parent = next(edge for edge in edges if edge.kind is EdgeKind.PARENT_OF)

        assert parent.provenance is Provenance.SPECIFICATION

    def test_inconsistent_authentication_creates_an_edge(self) -> None:
        _, edges, _ = build_graph(two_endpoint_discovery())

        differs = [edge for edge in edges if edge.kind is EdgeKind.AUTH_DIFFERS]
        assert differs
        assert differs[0].provenance is Provenance.SPECIFICATION

    def test_findings_become_observed_edges(self) -> None:
        assessment = assessment_result([check_result("BOLA-001", "GET /orders/{orderId}")])

        _, edges, _ = build_graph(two_endpoint_discovery(), assessment)
        affected = [edge for edge in edges if edge.kind is EdgeKind.AFFECTED_BY]

        assert affected
        assert affected[0].provenance is Provenance.OBSERVED
        assert affected[0].evidence_ids

    def test_identity_edges_are_fixture_backed(self) -> None:
        result = check_result("BOLA-001", "GET /orders/{orderId}")
        result = result.model_copy(
            update={"evidence": [result.evidence[0].model_copy(update={"identity": "alice"})]}
        )
        fixtures = AssessmentFixtures(
            identities=[
                AssessmentIdentity(
                    name="alice",
                    role="user",
                    auth=AuthProfile(
                        method=AuthMethod.BEARER, token=SecretRef(variable="ALICE_TOKEN")
                    ),
                )
            ]
        )

        _, edges, _ = build_graph(two_endpoint_discovery(), assessment_result([result]), fixtures)
        tested = [edge for edge in edges if edge.kind is EdgeKind.TESTED_AS]

        assert tested
        assert tested[0].provenance is Provenance.FIXTURE

    def test_edges_never_dangle(self) -> None:
        nodes, edges, _ = build_graph(two_endpoint_discovery())
        ids = {node.node_id for node in nodes}

        for edge in edges:
            assert edge.source in ids
            assert edge.target in ids

    def test_graph_is_bounded(self) -> None:
        many = [classified(public("get", f"/r{index}")) for index in range(50)]
        nodes, _, truncated = build_graph(discovery_result(many))

        assert len(nodes) <= MAX_NODES
        assert truncated is False

    def test_graph_is_deterministic(self) -> None:
        first = build_graph(two_endpoint_discovery())
        second = build_graph(two_endpoint_discovery())

        assert [node.node_id for node in first[0]] == [node.node_id for node in second[0]]
        assert [edge.edge_id for edge in first[1]] == [edge.edge_id for edge in second[1]]


class TestCorrelation:
    def test_inconsistent_authentication_is_never_confirmed(self) -> None:
        discovery = two_endpoint_discovery()
        _, edges, _ = build_graph(discovery)

        found = correlate(discovery, None, edges)
        auth = [item for item in found if item.kind == "inconsistent_authentication"]

        assert auth
        assert auth[0].confirmed is False
        assert auth[0].provenance is Provenance.SPECIFICATION
        assert auth[0].limitations

    def test_a_finding_on_a_shared_resource_is_correlated(self) -> None:
        discovery = two_endpoint_discovery()
        assessment = assessment_result([check_result("BOLA-001", "GET /orders/{orderId}")])
        _, edges, _ = build_graph(discovery, assessment)

        found = correlate(discovery, assessment, edges)
        shared = [item for item in found if item.kind == "finding_on_shared_resource"]

        assert shared
        assert "GET /orders" in shared[0].endpoints
        assert shared[0].supporting_edges
        assert shared[0].evidence_ids

    def test_breadth_correlation_states_it_does_not_raise_severity(self) -> None:
        discovery = two_endpoint_discovery()
        assessment = assessment_result([check_result("BOLA-001", "GET /orders/{orderId}")])
        _, edges, _ = build_graph(discovery, assessment)

        shared = next(
            item
            for item in correlate(discovery, assessment, edges)
            if item.kind == "finding_on_shared_resource"
        )

        assert any("not greater severity" in item for item in shared.limitations)

    def test_inconsistent_enforcement_is_confirmed_by_both_sides(self) -> None:
        discovery = two_endpoint_discovery()
        assessment = assessment_result(
            [
                check_result(
                    "AUTH-001",
                    "GET /orders",
                    outcome=CheckOutcome.PASS,
                    finding_class=FindingClass.NONE,
                    severity=None,
                ),
                check_result(
                    "AUTH-001",
                    "GET /orders/{orderId}",
                    outcome=CheckOutcome.FAIL,
                    finding_class=FindingClass.CONFIRMED,
                ),
            ]
        )
        _, edges, _ = build_graph(discovery, assessment)

        found = [
            item
            for item in correlate(discovery, assessment, edges)
            if item.kind == "inconsistent_enforcement"
        ]

        assert found
        assert found[0].confirmed is True
        assert found[0].provenance is Provenance.OBSERVED

    def test_weak_observations_never_become_confirmed(self) -> None:
        discovery = two_endpoint_discovery()
        assessment = assessment_result(
            [
                check_result(
                    f"CONF-00{index}",
                    "GET /orders",
                    outcome=CheckOutcome.NEEDS_REVIEW,
                    finding_class=FindingClass.INFORMATIONAL,
                    severity=None,
                    category=CheckCategory.CONFIGURATION,
                )
                for index in range(1, 5)
            ]
        )
        _, edges, _ = build_graph(discovery, assessment)

        accumulated = [
            item
            for item in correlate(discovery, assessment, edges)
            if item.kind == "accumulated_observations"
        ]

        assert accumulated
        assert accumulated[0].confirmed is False
        assert accumulated[0].confidence is Confidence.LOW
        assert any("does not create a vulnerability" in item for item in accumulated[0].limitations)

    def test_correlations_are_deterministic(self) -> None:
        discovery = two_endpoint_discovery()
        assessment = assessment_result([check_result("BOLA-001", "GET /orders/{orderId}")])
        _, edges, _ = build_graph(discovery, assessment)

        first = [item.correlation_id for item in correlate(discovery, assessment, edges)]
        second = [item.correlation_id for item in correlate(discovery, assessment, edges)]

        assert first == second


class TestRiskScoring:
    def test_a_confirmed_high_finding_outranks_a_suspected_one(self) -> None:
        confirmed = check_result("A-1", "GET /a")
        suspected = check_result(
            "A-2", "GET /b", finding_class=FindingClass.SUSPECTED, confidence=Confidence.MEDIUM
        )

        high, _ = score_result(
            confirmed, correlations=[], anonymous_endpoints=set(), related_endpoints={"GET /a"}
        )
        low, _ = score_result(
            suspected, correlations=[], anonymous_endpoints=set(), related_endpoints={"GET /b"}
        )

        assert high > low

    def test_severity_and_confidence_stay_separate(self) -> None:
        result = check_result(
            "A-1",
            "GET /a",
            severity=Severity.HIGH,
            finding_class=FindingClass.SUSPECTED,
            confidence=Confidence.LOW,
        )

        risks = build_risks(
            assessment_result([result]), [], anonymous_endpoints=set(), resource_groups={}
        )

        # Severity is still high; the band is lower because confidence is low.
        assert risks[0].severity is Severity.HIGH
        assert risks[0].confidence is Confidence.LOW
        assert risks[0].band is not RiskBand.CRITICAL
        assert risks[0].confirmed is False

    def test_every_factor_states_its_reason(self) -> None:
        _, factors = score_result(
            check_result("A-1", "GET /a"),
            correlations=[],
            anonymous_endpoints={"GET /a"},
            related_endpoints={"GET /a", "GET /b"},
        )

        assert factors
        assert all(item.reason for item in factors)
        assert all(item.name for item in factors)

    def test_breadth_is_capped_and_cannot_dominate(self) -> None:
        many = {f"GET /r{index}" for index in range(50)} | {"GET /a"}

        _, factors = score_result(
            check_result("A-1", "GET /a", severity=Severity.LOW),
            correlations=[],
            anonymous_endpoints=set(),
            related_endpoints=many,
        )
        breadth = next(item for item in factors if item.name == "breadth")

        assert breadth.points <= MAX_BREADTH_POINTS

    def test_endpoint_count_alone_does_not_inflate_severity(self) -> None:
        narrow = check_result("A-1", "GET /a", severity=Severity.LOW)
        groups = {"resource:Order": {f"GET /r{index}" for index in range(30)} | {"GET /a"}}

        risks = build_risks(
            assessment_result([narrow]), [], anonymous_endpoints=set(), resource_groups=groups
        )

        assert risks[0].severity is Severity.LOW

    def test_unauthenticated_reach_contributes(self) -> None:
        result = check_result("A-1", "GET /a")

        with_reach, _ = score_result(
            result, correlations=[], anonymous_endpoints={"GET /a"}, related_endpoints={"GET /a"}
        )
        without, _ = score_result(
            result, correlations=[], anonymous_endpoints=set(), related_endpoints={"GET /a"}
        )

        assert with_reach > without

    def test_scores_are_bounded(self) -> None:
        score, _ = score_result(
            check_result("A-1", "GET /a", severity=Severity.CRITICAL, evidence_count=6),
            correlations=[],
            anonymous_endpoints={"GET /a"},
            related_endpoints={f"GET /r{index}" for index in range(40)},
        )

        assert 0 <= score <= 100

    @pytest.mark.parametrize(
        ("score", "band"),
        [
            (95.0, RiskBand.CRITICAL),
            (70.0, RiskBand.CRITICAL),
            (55.0, RiskBand.HIGH),
            (35.0, RiskBand.MEDIUM),
            (15.0, RiskBand.LOW),
            (2.0, RiskBand.INFORMATIONAL),
        ],
    )
    def test_band_thresholds(self, score: float, band: RiskBand) -> None:
        assert band_for(score) is band

    def test_risks_are_sorted_highest_first(self) -> None:
        results = [
            check_result(
                "A-1", "GET /a", severity=Severity.LOW, finding_class=FindingClass.INFORMATIONAL
            ),
            check_result("A-2", "GET /b", severity=Severity.HIGH),
            check_result(
                "A-3", "GET /c", severity=Severity.MEDIUM, finding_class=FindingClass.SUSPECTED
            ),
        ]

        risks = build_risks(
            assessment_result(results), [], anonymous_endpoints=set(), resource_groups={}
        )

        assert [item.score for item in risks] == sorted(
            (item.score for item in risks), reverse=True
        )

    def test_every_risk_explains_itself(self) -> None:
        risks = build_risks(
            assessment_result([check_result("A-1", "GET /a")]),
            [],
            anonymous_endpoints=set(),
            resource_groups={},
        )
        risk = risks[0]

        assert risk.what_was_observed
        assert risk.why_it_matters
        assert risk.next_step
        assert risk.unverified

    def test_a_suspected_risk_says_the_claim_is_unestablished(self) -> None:
        risks = build_risks(
            assessment_result(
                [check_result("A-1", "GET /a", finding_class=FindingClass.SUSPECTED)]
            ),
            [],
            anonymous_endpoints=set(),
            resource_groups={},
        )

        assert "not established" in " ".join(risks[0].unverified)

    def test_results_with_nothing_to_report_produce_no_risk(self) -> None:
        risks = build_risks(
            assessment_result(
                [
                    check_result(
                        "A-1",
                        "GET /a",
                        outcome=CheckOutcome.PASS,
                        finding_class=FindingClass.NONE,
                        severity=None,
                    )
                ]
            ),
            [],
            anonymous_endpoints=set(),
            resource_groups={},
        )

        assert risks == []

    def test_the_model_is_published(self) -> None:
        described = dict(model_description())

        assert "impact" in described
        assert "breadth" in described
        assert "never severity" in described["breadth"]
        assert all(severity.value in described["impact"] for severity in SEVERITY_POINTS)


class TestAttackPaths:
    def test_a_path_requires_a_finding_to_end_at(self) -> None:
        nodes, edges, _ = build_graph(two_endpoint_discovery())

        assert find_attack_paths(nodes, edges, None) == []

    def test_a_path_is_found_from_a_public_entry_to_a_finding(self) -> None:
        discovery = two_endpoint_discovery()
        assessment = assessment_result([check_result("BOLA-001", "GET /orders/{orderId}")])
        nodes, edges, _ = build_graph(discovery, assessment)

        paths = find_attack_paths(nodes, edges, assessment)

        assert paths
        assert any("BOLA-001" in path.title for path in paths)

    def test_every_step_is_labelled_with_its_support(self) -> None:
        discovery = two_endpoint_discovery()
        assessment = assessment_result([check_result("BOLA-001", "GET /orders/{orderId}")])
        nodes, edges, _ = build_graph(discovery, assessment)

        for path in find_attack_paths(nodes, edges, assessment):
            assert path.steps
            assert all(isinstance(step.kind, PathStepKind) for step in path.steps)
            assert all(step.description for step in path.steps)

    def test_the_weakest_step_is_identified(self) -> None:
        discovery = two_endpoint_discovery()
        assessment = assessment_result([check_result("BOLA-001", "GET /orders/{orderId}")])
        nodes, edges, _ = build_graph(discovery, assessment)

        for path in find_attack_paths(nodes, edges, assessment):
            ranks = {
                PathStepKind.OBSERVED: 0,
                PathStepKind.DOCUMENTED: 1,
                PathStepKind.INFERRED: 2,
                PathStepKind.HYPOTHETICAL: 3,
            }
            assert ranks[path.weakest_step] == max(ranks[step.kind] for step in path.steps)

    def test_a_suspected_finding_never_yields_a_fully_evidenced_path(self) -> None:
        discovery = two_endpoint_discovery()
        assessment = assessment_result(
            [
                check_result(
                    "BOLA-001",
                    "GET /orders/{orderId}",
                    finding_class=FindingClass.SUSPECTED,
                    confidence=Confidence.MEDIUM,
                )
            ]
        )
        nodes, edges, _ = build_graph(discovery, assessment)

        for path in find_attack_paths(nodes, edges, assessment):
            assert path.fully_evidenced is False
            assert any("suspected" in item for item in path.unverified)

    def test_every_path_states_what_is_unverified(self) -> None:
        discovery = two_endpoint_discovery()
        assessment = assessment_result([check_result("BOLA-001", "GET /orders/{orderId}")])
        nodes, edges, _ = build_graph(discovery, assessment)

        for path in find_attack_paths(nodes, edges, assessment):
            assert path.unverified
            assert "not chained together" in " ".join(path.unverified)

    def test_no_path_claims_to_be_exploitable(self) -> None:
        discovery = two_endpoint_discovery()
        assessment = assessment_result([check_result("BOLA-001", "GET /orders/{orderId}")])
        nodes, edges, _ = build_graph(discovery, assessment)

        for path in find_attack_paths(nodes, edges, assessment):
            assert "exploitable" not in path.reasoning.lower()
            assert "exploitable" not in path.title.lower()

    def test_path_confidence_is_capped_by_the_weakest_link(self) -> None:
        discovery = two_endpoint_discovery()
        assessment = assessment_result(
            [check_result("BOLA-001", "GET /orders/{orderId}", confidence=Confidence.CONFIRMED)]
        )
        nodes, edges, _ = build_graph(discovery, assessment)

        for path in find_attack_paths(nodes, edges, assessment):
            if path.weakest_step is PathStepKind.DOCUMENTED:
                assert path.confidence is Confidence.MEDIUM

    def test_traversal_is_bounded(self) -> None:
        chain = [
            classified(
                protected(
                    "get",
                    f"/level{index}/{{id{index}}}",
                    parameters=[path_param(f"id{index}")],
                    response_schema=SchemaSummary(
                        type="object",
                        properties={f"id{index + 1}": SchemaSummary(type="string")},
                    ),
                )
            )
            for index in range(12)
        ]
        discovery = discovery_result(chain)
        assessment = assessment_result(
            [check_result("BOLA-001", item.endpoint.key) for item in chain]
        )
        nodes, edges, _ = build_graph(discovery, assessment)

        paths = find_attack_paths(nodes, edges, assessment)

        assert len(paths) <= MAX_PATHS
        assert all(path.length <= MAX_DEPTH for path in paths)

    def test_paths_are_deterministic(self) -> None:
        discovery = two_endpoint_discovery()
        assessment = assessment_result([check_result("BOLA-001", "GET /orders/{orderId}")])
        nodes, edges, _ = build_graph(discovery, assessment)

        first = [path.path_id for path in find_attack_paths(nodes, edges, assessment)]
        second = [path.path_id for path in find_attack_paths(nodes, edges, assessment)]

        assert first == second


class TestAnalysis:
    def test_a_full_report_is_produced(self) -> None:
        discovery = two_endpoint_discovery()
        assessment = assessment_result([check_result("BOLA-001", "GET /orders/{orderId}")])

        report = analyse(discovery, assessment)

        assert report.nodes
        assert report.edges
        assert report.risks
        assert report.notes
        assert report.target_name == "acme"

    def test_without_an_assessment_there_are_no_risks(self) -> None:
        report = analyse(two_endpoint_discovery())

        assert report.risks == []
        assert report.attack_paths == []
        assert report.edges
        assert any("No assessment" in note for note in report.notes)

    def test_out_of_scope_endpoints_are_noted(self) -> None:
        discovery = discovery_result(
            [
                classified(public("get", "/health")),
                classified(
                    protected("get", "/admin"),
                    classification=ScopeClassification.OUT_OF_SCOPE,
                ),
            ]
        )

        report = analyse(discovery)

        assert any("out of scope" in note for note in report.notes)

    def test_untested_in_scope_endpoints_are_noted(self) -> None:
        discovery = two_endpoint_discovery()
        assessment = assessment_result([check_result("BOLA-001", "GET /orders/{orderId}")])

        report = analyse(discovery, assessment)

        assert any("produced no requests" in note for note in report.notes)

    def test_the_path_disclaimer_is_always_present(self) -> None:
        report = analyse(two_endpoint_discovery())

        assert any("hypothesis about reachability" in note for note in report.notes)

    def test_analysis_is_deterministic(self) -> None:
        discovery = two_endpoint_discovery()
        assessment = assessment_result([check_result("BOLA-001", "GET /orders/{orderId}")])

        first = analyse(discovery, assessment).model_dump(mode="json")
        second = analyse(discovery, assessment).model_dump(mode="json")
        first.pop("analysed_at")
        second.pop("analysed_at")

        assert first == second

    def test_the_report_references_evidence_without_copying_it(self) -> None:
        discovery = two_endpoint_discovery()
        assessment = assessment_result([check_result("BOLA-001", "GET /orders/{orderId}")])

        report = analyse(discovery, assessment)
        risk = report.risks[0]

        assert risk.evidence_ids
        # The report holds identifiers, not response bodies.
        assert "body_excerpt" not in report.model_dump_json()

    def test_risks_are_addressable_by_id(self) -> None:
        discovery = two_endpoint_discovery()
        assessment = assessment_result([check_result("BOLA-001", "GET /orders/{orderId}")])

        report = analyse(discovery, assessment)

        assert report.risk(report.risks[0].risk_id) is not None
        assert report.risk("risk-missing") is None

    def test_band_and_provenance_counts_are_consistent(self) -> None:
        discovery = two_endpoint_discovery()
        assessment = assessment_result([check_result("BOLA-001", "GET /orders/{orderId}")])

        report = analyse(discovery, assessment)

        assert sum(report.band_counts().values()) == len(report.risks)
        assert sum(report.edges_by_provenance().values()) == len(report.edges)

    def test_an_empty_discovery_produces_an_empty_report(self) -> None:
        report = analyse(discovery_result([]))

        assert report.nodes == []
        assert report.edges == []
        assert report.risks == []

    def test_no_credential_can_appear_in_a_report(self) -> None:
        from assessfix import TOKEN

        discovery = two_endpoint_discovery()
        assessment = assessment_result([check_result("BOLA-001", "GET /orders/{orderId}")])

        report = analyse(discovery, assessment)

        assert TOKEN not in report.model_dump_json()
