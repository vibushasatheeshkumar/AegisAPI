"""Attack-path identity: reproducible in any process, and only route-dependent.

Earlier builds derived ``path_id`` from Python's built-in :func:`hash`, which is
randomised per interpreter process. The identifier therefore changed on every
run, which meant two analyses of the same graph could not be matched against
each other and a stored report could not be re-derived. Comparison between saved
assessments depends on that not being true.

The tests below are split in two. The in-process ones pin *what* the identity is
made of. The subprocess ones pin that it survives leaving the process at all -
the property the old implementation silently lacked, and the one an in-process
test cannot observe, because ``hash`` is stable within a single interpreter.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys

import pytest

from aegisapi.intelligence.attack_paths import find_attack_paths
from aegisapi.intelligence.graph import build_graph
from aegisapi.models.intelligence import (
    LEGACY_PATH_ID_PATTERN,
    PATH_ID_PATTERN,
    AttackPath,
    AttackPathStep,
    EdgeKind,
    PathStepKind,
    is_legacy_path_id,
)
from assessfix import assessment_result, check_result
from test_intelligence import two_endpoint_discovery


def step(
    from_node: str,
    to_node: str,
    *,
    edge_kind: EdgeKind = EdgeKind.EXPOSES_IDENTIFIER,
    kind: PathStepKind = PathStepKind.DOCUMENTED,
    description: str = "declared relationship",
) -> AttackPathStep:
    """One transition, with everything but the route defaulted."""
    return AttackPathStep(
        from_node=from_node,
        to_node=to_node,
        edge_kind=edge_kind,
        kind=kind,
        description=description,
    )


def two_step_route() -> list[AttackPathStep]:
    """The canonical collection -> identifier -> detail route."""
    return [
        step("endpoint:GET /orders", "identifier:orderId"),
        step(
            "identifier:orderId",
            "endpoint:GET /orders/{orderId}",
            edge_kind=EdgeKind.ACCEPTED_BY,
        ),
    ]


# Run in a fresh interpreter so PYTHONHASHSEED actually takes effect. The probe
# also reports a built-in hash of the same strings, which is the control: if that
# value did not move between runs, the seed was not applied and the determinism
# assertion below would be vacuous.
_PROBE = """
import json
from aegisapi.models.intelligence import AttackPath, AttackPathStep, EdgeKind, PathStepKind

steps = [
    AttackPathStep(
        from_node="endpoint:GET /orders",
        to_node="identifier:orderId",
        edge_kind=EdgeKind.EXPOSES_IDENTIFIER,
        kind=PathStepKind.DOCUMENTED,
        description="declared relationship",
    ),
    AttackPathStep(
        from_node="identifier:orderId",
        to_node="endpoint:GET /orders/{orderId}",
        edge_kind=EdgeKind.ACCEPTED_BY,
        kind=PathStepKind.DOCUMENTED,
        description="declared relationship",
    ),
]
print(json.dumps({
    "path_id": AttackPath.make_id(steps),
    "builtin_hash": hash(("endpoint:GET /orders", "identifier:orderId")),
}))
"""


def probe(hash_seed: str) -> dict[str, object]:
    """Run the probe in a new interpreter with a given ``PYTHONHASHSEED``."""
    environment = dict(os.environ)
    environment["PYTHONHASHSEED"] = hash_seed
    completed = subprocess.run(
        [sys.executable, "-c", _PROBE],
        capture_output=True,
        text=True,
        check=True,
        env=environment,
        timeout=120,
    )
    return json.loads(completed.stdout)


class TestCrossProcessDeterminism:
    """The property the old implementation lacked."""

    def test_separate_processes_agree_on_the_identifier(self) -> None:
        first = probe("0")
        second = probe("1")

        assert first["path_id"] == second["path_id"]

    def test_the_hash_seed_really_differs_between_those_processes(self) -> None:
        # Guards the test above from passing vacuously. If PYTHONHASHSEED were
        # ignored, the built-in hash would match and the determinism assertion
        # would prove nothing, because `hash` is stable inside one interpreter.
        first = probe("0")
        second = probe("1")

        assert first["builtin_hash"] != second["builtin_hash"]

    def test_a_random_seed_still_produces_the_same_identifier(self) -> None:
        expected = AttackPath.make_id(two_step_route())

        assert probe("random")["path_id"] == expected
        assert probe("random")["path_id"] == expected

    def test_the_subprocess_agrees_with_this_process(self) -> None:
        assert probe("0")["path_id"] == AttackPath.make_id(two_step_route())

    def test_the_whole_analysis_is_reproducible_across_processes(self) -> None:
        # End to end: the identifiers a real analysis produces, not just the
        # helper's, have to survive a process boundary.
        script = (
            "import json, sys\n"
            "sys.path.insert(0, 'tests')\n"
            "from aegisapi.intelligence.attack_paths import find_attack_paths\n"
            "from aegisapi.intelligence.graph import build_graph\n"
            "from assessfix import assessment_result, check_result\n"
            "from test_intelligence import two_endpoint_discovery\n"
            "discovery = two_endpoint_discovery()\n"
            "assessment = assessment_result("
            "[check_result('BOLA-001', 'GET /orders/{orderId}')])\n"
            "nodes, edges, _ = build_graph(discovery, assessment)\n"
            "paths = find_attack_paths(nodes, edges, assessment)\n"
            "print(json.dumps([path.path_id for path in paths]))\n"
        )
        runs = []
        for seed in ("0", "1"):
            environment = dict(os.environ)
            environment["PYTHONHASHSEED"] = seed
            completed = subprocess.run(
                [sys.executable, "-c", script],
                capture_output=True,
                text=True,
                check=True,
                env=environment,
                timeout=120,
            )
            runs.append(json.loads(completed.stdout))

        assert runs[0] == runs[1]
        assert runs[0], "the fixture must produce at least one path for this to mean anything"


class TestIdentityIsTheRoute:
    def test_the_same_route_gives_the_same_identifier(self) -> None:
        assert AttackPath.make_id(two_step_route()) == AttackPath.make_id(two_step_route())

    def test_a_different_destination_gives_a_different_identifier(self) -> None:
        other = [
            step("endpoint:GET /orders", "identifier:orderId"),
            step("identifier:orderId", "endpoint:DELETE /orders/{orderId}"),
        ]

        assert AttackPath.make_id(two_step_route()) != AttackPath.make_id(other)

    def test_a_different_start_gives_a_different_identifier(self) -> None:
        # The superseded implementation hashed only the nodes a path *reached*,
        # so two routes that converged on the same chain from different entry
        # points collided while being kept as separate paths.
        shared_tail = step("identifier:orderId", "endpoint:GET /orders/{orderId}")
        from_orders = [step("endpoint:GET /orders", "identifier:orderId"), shared_tail]
        from_search = [step("endpoint:GET /search", "identifier:orderId"), shared_tail]

        assert AttackPath.make_id(from_orders) != AttackPath.make_id(from_search)

    def test_a_different_relationship_gives_a_different_identifier(self) -> None:
        via_exposure = [step("endpoint:GET /a", "endpoint:GET /b")]
        via_parent = [step("endpoint:GET /a", "endpoint:GET /b", edge_kind=EdgeKind.PARENT_OF)]

        assert AttackPath.make_id(via_exposure) != AttackPath.make_id(via_parent)

    def test_step_order_matters(self) -> None:
        forward = [step("endpoint:GET /a", "endpoint:GET /b")]
        backward = [step("endpoint:GET /b", "endpoint:GET /a")]

        assert AttackPath.make_id(forward) != AttackPath.make_id(backward)

    def test_a_longer_route_gives_a_different_identifier(self) -> None:
        short = two_step_route()
        longer = [*short, step("endpoint:GET /orders/{orderId}", "finding:res-abcdef0123456789")]

        assert AttackPath.make_id(short) != AttackPath.make_id(longer)

    def test_an_empty_route_is_handled(self) -> None:
        assert PATH_ID_PATTERN.match(AttackPath.make_id([]))


class TestIdentityIgnoresJudgements:
    """Strength and prose describe a path; they do not make it a different one."""

    def test_support_strength_does_not_change_the_identifier(self) -> None:
        inferred = [step("endpoint:GET /a", "endpoint:GET /b", kind=PathStepKind.INFERRED)]
        observed = [step("endpoint:GET /a", "endpoint:GET /b", kind=PathStepKind.OBSERVED)]

        assert AttackPath.make_id(inferred) == AttackPath.make_id(observed)

    def test_rewording_a_description_does_not_change_the_identifier(self) -> None:
        first = [step("endpoint:GET /a", "endpoint:GET /b", description="one wording")]
        second = [step("endpoint:GET /a", "endpoint:GET /b", description="quite another")]

        assert AttackPath.make_id(first) == AttackPath.make_id(second)

    def test_evidence_ids_do_not_change_the_identifier(self) -> None:
        bare = step("endpoint:GET /a", "endpoint:GET /b")
        cited = bare.model_copy(update={"evidence_ids": ["ev-0123456789abcdef"]})

        assert AttackPath.make_id([bare]) == AttackPath.make_id([cited])

    def test_a_separator_in_a_node_name_cannot_forge_another_route(self) -> None:
        # JSON encoding keeps field boundaries unambiguous, so a crafted node
        # name cannot be read as two fields.
        forged = 'endpoint:GET /a","exposes_identifier","endpoint:GET /b'
        crafted = [step(forged, "endpoint:GET /c")]
        genuine = [
            step("endpoint:GET /a", "endpoint:GET /b"),
            step("endpoint:GET /b", "endpoint:GET /c"),
        ]

        assert AttackPath.make_id(crafted) != AttackPath.make_id(genuine)


class TestIdentifierFormat:
    def test_the_identifier_matches_the_published_shape(self) -> None:
        assert PATH_ID_PATTERN.match(AttackPath.make_id(two_step_route()))

    def test_the_identifier_follows_the_projects_prefix_convention(self) -> None:
        identifier = AttackPath.make_id(two_step_route())

        assert identifier.startswith("path-")
        assert len(identifier) == len("path-") + 16

    def test_a_new_identifier_is_not_mistaken_for_a_legacy_one(self) -> None:
        assert is_legacy_path_id(AttackPath.make_id(two_step_route())) is False

    @pytest.mark.parametrize("legacy", ["path-582910203575", "path-000000000000"])
    def test_a_legacy_identifier_is_recognised(self, legacy: str) -> None:
        assert is_legacy_path_id(legacy) is True
        assert LEGACY_PATH_ID_PATTERN.match(legacy)
        assert not PATH_ID_PATTERN.match(legacy)

    @pytest.mark.parametrize(
        "value", ["path-58291020357", "path-5829102035751", "path-abcdef0123456789", "", "path-"]
    )
    def test_other_shapes_are_not_treated_as_legacy(self, value: str) -> None:
        assert is_legacy_path_id(value) is False


class TestAnalysisBehaviourIsPreserved:
    def paths(self) -> list[AttackPath]:
        """Paths from the shared two-endpoint fixture."""
        discovery = two_endpoint_discovery()
        assessment = assessment_result([check_result("BOLA-001", "GET /orders/{orderId}")])
        nodes, edges, _ = build_graph(discovery, assessment)
        return find_attack_paths(nodes, edges, assessment)

    def test_paths_are_still_found(self) -> None:
        assert self.paths()

    def test_every_identifier_has_the_new_shape(self) -> None:
        for path in self.paths():
            assert PATH_ID_PATTERN.match(path.path_id), path.path_id

    def test_identifiers_are_unique_within_one_analysis(self) -> None:
        identifiers = [path.path_id for path in self.paths()]

        assert len(identifiers) == len(set(identifiers))

    def test_each_identifier_matches_its_own_steps(self) -> None:
        # The stored identifier is recomputable from the path's own content,
        # which is what lets a consumer verify a record rather than trust it.
        for path in self.paths():
            assert path.path_id == AttackPath.make_id(path.steps)

    def test_the_other_path_fields_are_unaffected(self) -> None:
        for path in self.paths():
            assert path.title
            assert path.reasoning
            assert path.steps
            assert path.unverified
            assert path.weakest_step in set(PathStepKind)
