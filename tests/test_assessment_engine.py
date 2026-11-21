"""The assessment engine: selection, budgets, containment, and scope safety.

The security tests here use :class:`RefusingTransport`, which fails if asked to
send anything, so "no request was transmitted" is proven rather than counted.
"""

from __future__ import annotations

import pytest

from aegisapi.core.exceptions import InvalidTargetError, ScopeViolationError
from aegisapi.models.assessment import (
    AssessmentResult,
    CheckCategory,
    CheckOutcome,
    FindingClass,
)
from aegisapi.models.discovery import ScopeClassification
from aegisapi.models.secrets import SecretRef
from aegisapi.models.target import AuthMethod, AuthProfile
from aegisapi.testing import AssessmentEngine, AssessmentFixtures
from aegisapi.testing.engine import ONCE_PER_TARGET_CHECKS, register_builtin_checks
from aegisapi.testing.registry import (
    REGISTRY,
    BaseCheck,
    CheckContext,
    CheckRegistry,
    RequestBudget,
)
from assessfix import (
    TOKEN,
    classified,
    discovery_result,
    make_client,
    make_config,
    protected,
    public,
    scoped_target,
)
from httpstub import FakeTransport, RefusingTransport, StubResponse


def run_engine(
    *,
    endpoints,
    transport,
    target=None,
    config=None,
    fixtures=None,
    budget=60,
    categories=None,
    check_ids=None,
    env=None,
) -> AssessmentResult:
    """Run the engine over a built discovery result."""
    active_target = target or scoped_target()
    active_config = config or make_config()
    client = make_client(active_target, active_config, transport, env=env)
    engine = AssessmentEngine(target=active_target, config=active_config)
    try:
        return engine.run(
            discovery=discovery_result([classified(item) for item in endpoints]),
            fixtures=fixtures,
            categories=categories,
            check_ids=check_ids,
            budget=budget,
            client=client,
            env=env,
        )
    finally:
        client.close()


class TestRegistry:
    def test_builtin_checks_are_registered(self) -> None:
        assert len(REGISTRY.all()) >= 14

    def test_every_check_has_a_unique_id_and_category(self) -> None:
        ids = [item.check_id for item in REGISTRY.all()]

        assert len(ids) == len(set(ids))
        assert all(isinstance(item.category, CheckCategory) for item in REGISTRY.all())

    def test_checks_are_ordered_deterministically(self) -> None:
        first = [item.check_id for item in REGISTRY.all()]
        second = [item.check_id for item in REGISTRY.all()]

        assert first == second == sorted(first)

    def test_duplicate_registration_is_refused(self) -> None:
        registry = CheckRegistry()
        register_builtin_checks(registry)

        with pytest.raises(ValueError, match="already registered"):
            register_builtin_checks(registry)

    def test_selection_by_category(self) -> None:
        selected = REGISTRY.select(categories=[CheckCategory.AUTHENTICATION])

        assert selected
        assert all(item.category is CheckCategory.AUTHENTICATION for item in selected)

    def test_selection_by_id(self) -> None:
        selected = REGISTRY.select(check_ids=["AUTH-001"])

        assert [item.check_id for item in selected] == ["AUTH-001"]

    def test_unknown_check_id_is_an_error_not_an_empty_selection(self) -> None:
        with pytest.raises(InvalidTargetError, match="No security check"):
            REGISTRY.select(check_ids=["NOPE-999"])

    def test_categories_are_listed(self) -> None:
        assert CheckCategory.AUTHORIZATION in REGISTRY.categories()


class TestRequestBudget:
    def test_consuming_within_the_limit(self) -> None:
        budget = RequestBudget(limit=3)

        assert budget.consume() is True
        assert budget.remaining == 2
        assert budget.exhausted is False

    def test_consuming_beyond_the_limit_is_refused(self) -> None:
        budget = RequestBudget(limit=1)

        assert budget.consume(2) is False
        assert budget.spent == 0

    def test_exhaustion(self) -> None:
        budget = RequestBudget(limit=1)
        budget.consume()

        assert budget.exhausted is True
        assert budget.consume() is False


class TestScopeSafety:
    def test_out_of_scope_endpoints_are_never_requested(self) -> None:
        transport = RefusingTransport()
        target = scoped_target()
        config = make_config()
        client = make_client(target, config, transport)
        engine = AssessmentEngine(target=target, config=config)

        result = engine.run(
            discovery=discovery_result(
                [
                    classified(
                        protected("get", "/admin"),
                        classification=ScopeClassification.OUT_OF_SCOPE,
                    ),
                    classified(
                        protected("get", "/unknown"),
                        classification=ScopeClassification.UNRESOLVED,
                    ),
                ]
            ),
            budget=60,
            client=client,
        )
        client.close()

        assert result.requests_sent == 0
        assert all(item.outcome is CheckOutcome.SKIPPED for item in result.results)
        assert len(result.results) == 2

    def test_out_of_scope_endpoints_are_recorded_not_dropped(self) -> None:
        transport = RefusingTransport()
        target = scoped_target()
        config = make_config()
        client = make_client(target, config, transport)
        engine = AssessmentEngine(target=target, config=config)

        result = engine.run(
            discovery=discovery_result(
                [
                    classified(
                        protected("get", "/admin"),
                        classification=ScopeClassification.OUT_OF_SCOPE,
                    )
                ]
            ),
            budget=60,
            client=client,
        )
        client.close()

        assert "out_of_scope" in result.results[0].summary

    def test_a_disabled_target_sends_nothing(self) -> None:
        transport = RefusingTransport()
        target = scoped_target(enabled=False)
        config = make_config()
        client = make_client(target, config, transport)
        engine = AssessmentEngine(target=target, config=config)

        result = engine.run(
            discovery=discovery_result([classified(protected("get", "/orders"))]),
            budget=60,
            client=client,
        )
        client.close()

        assert result.requests_sent == 0
        assert result.results[0].check_id == "ENGINE-001"
        assert "disabled" in result.results[0].summary

    def test_an_empty_global_allow_list_blocks_every_check(self) -> None:
        # The client refuses each request; the engine turns that into ERROR
        # results rather than findings, and nothing is transmitted.
        transport = RefusingTransport()
        target = scoped_target()
        config = make_config(allowed_hosts=())
        client = make_client(target, config, transport)
        engine = AssessmentEngine(target=target, config=config)

        result = engine.run(
            discovery=discovery_result([classified(public("get", "/health"))]),
            budget=60,
            client=client,
        )
        client.close()

        errored = [item for item in result.results if item.outcome is CheckOutcome.ERROR]
        assert errored
        assert all(item.finding_class is FindingClass.INCONCLUSIVE for item in errored)

    def test_checks_use_the_injected_scoped_client(self) -> None:
        transport = FakeTransport()

        result = run_engine(
            endpoints=[public("get", "/health")],
            transport=transport,
            check_ids=["CONF-001"],
        )

        assert transport.call_count >= 1
        assert result.requests_sent >= 1
        assert transport.last_request.url.startswith("https://api.acme.test/v1")


class TestBudgetAndSelection:
    def test_the_budget_caps_total_requests(self) -> None:
        transport = FakeTransport(default=StubResponse())

        result = run_engine(
            endpoints=[public("get", f"/r{index}") for index in range(10)],
            transport=transport,
            budget=4,
        )

        assert result.requests_sent <= 4
        assert transport.call_count <= 4
        assert result.budget_exhausted is True

    def test_a_zero_budget_sends_nothing(self) -> None:
        transport = RefusingTransport()

        result = run_engine(endpoints=[public("get", "/health")], transport=transport, budget=0)

        assert result.requests_sent == 0

    def test_category_selection_limits_the_checks_run(self) -> None:
        transport = FakeTransport(default=StubResponse())

        result = run_engine(
            endpoints=[protected("get", "/orders")],
            transport=transport,
            categories=[CheckCategory.AUTHENTICATION],
        )

        assert {item.category for item in result.results} <= {CheckCategory.AUTHENTICATION}

    def test_once_per_target_checks_do_not_repeat(self) -> None:
        transport = FakeTransport(default=StubResponse())

        result = run_engine(
            endpoints=[public("get", "/a"), public("get", "/b"), public("get", "/c")],
            transport=transport,
            check_ids=["CONF-004"],
        )

        ran = [
            item
            for item in result.results
            if item.check_id in ONCE_PER_TARGET_CHECKS and item.outcome is not CheckOutcome.SKIPPED
        ]
        assert len(ran) == 1

    def test_max_endpoints_limits_consideration(self) -> None:
        transport = FakeTransport(default=StubResponse())
        target = scoped_target()
        config = make_config()
        client = make_client(target, config, transport)
        engine = AssessmentEngine(target=target, config=config)

        result = engine.run(
            discovery=discovery_result(
                [classified(public("get", f"/r{index}")) for index in range(5)]
            ),
            budget=60,
            client=client,
            max_endpoints=2,
        )
        client.close()

        assert result.endpoints_considered == 2


class TestPreconditions:
    def test_a_check_without_its_precondition_does_not_run(self) -> None:
        transport = FakeTransport(default=StubResponse())

        # BOLA needs declared fixtures; none are supplied.
        result = run_engine(
            endpoints=[protected("get", "/orders/{orderId}")],
            transport=transport,
            check_ids=["BOLA-001"],
        )

        assert result.requests_sent == 0
        assert transport.call_count == 0

    def test_authorization_checks_skip_without_fixtures(self) -> None:
        transport = RefusingTransport()

        result = run_engine(
            endpoints=[protected("get", "/orders/{orderId}")],
            transport=transport,
            check_ids=["BOLA-001", "BFLA-001"],
            fixtures=AssessmentFixtures(),
        )

        assert result.requests_sent == 0

    def test_metadata_check_sends_no_request(self) -> None:
        transport = RefusingTransport()

        result = run_engine(
            endpoints=[classified_free_operation()],
            transport=transport,
            check_ids=["AUTH-003"],
        )

        assert result.requests_sent == 0
        assert result.results[0].finding_class is FindingClass.INFORMATIONAL


def classified_free_operation():
    """An operation with no declared security, for AUTH-003."""
    return protected("get", "/orders").model_copy(
        update={
            "declared_security": protected("get", "/orders").declared_security.model_copy(
                update={"posture": "not_declared", "alternatives": []}
            )
        }
    )


class TestErrorContainment:
    def test_a_check_that_raises_becomes_an_error_result(self) -> None:
        class Exploding(BaseCheck):
            check_id = "TEST-999"
            name = "always raises"
            category = CheckCategory.CONFIGURATION
            requests_per_endpoint = 0

            def applies_to(self, endpoint, context) -> bool:
                return True

            def run(self, endpoint, context):
                raise RuntimeError("boom")

        registry = CheckRegistry()
        registry.register(Exploding())
        target = scoped_target()
        config = make_config()
        client = make_client(target, config, RefusingTransport())
        engine = AssessmentEngine(target=target, config=config, registry=registry)

        result = engine.run(
            discovery=discovery_result([classified(public("get", "/health"))]),
            budget=10,
            client=client,
        )
        client.close()

        assert result.results[0].outcome is CheckOutcome.ERROR
        assert result.results[0].finding_class is FindingClass.INCONCLUSIVE
        assert "boom" in result.results[0].explanation

    def test_a_check_reaching_out_of_scope_is_contained(self) -> None:
        class Wanderer(BaseCheck):
            check_id = "TEST-998"
            name = "requests another host"
            category = CheckCategory.CONFIGURATION
            requests_per_endpoint = 1

            def applies_to(self, endpoint, context) -> bool:
                return True

            def run(self, endpoint, context):
                context.client.request("GET", "https://attacker.test/steal")
                raise AssertionError("the client should have refused")

        registry = CheckRegistry()
        registry.register(Wanderer())
        target = scoped_target()
        config = make_config()
        transport = RefusingTransport()
        client = make_client(target, config, transport)
        engine = AssessmentEngine(target=target, config=config, registry=registry)

        result = engine.run(
            discovery=discovery_result([classified(public("get", "/health"))]),
            budget=10,
            client=client,
        )
        client.close()

        assert result.results[0].outcome is CheckOutcome.ERROR
        assert "out-of-scope" in result.results[0].summary

    def test_one_broken_check_does_not_stop_the_others(self) -> None:
        class Exploding(BaseCheck):
            check_id = "TEST-997"
            name = "always raises"
            category = CheckCategory.CONFIGURATION
            requests_per_endpoint = 0

            def applies_to(self, endpoint, context) -> bool:
                return True

            def run(self, endpoint, context):
                raise RuntimeError("boom")

        registry = CheckRegistry()
        register_builtin_checks(registry)
        registry.register(Exploding())
        target = scoped_target()
        config = make_config()
        client = make_client(target, config, FakeTransport(default=StubResponse()))
        engine = AssessmentEngine(target=target, config=config, registry=registry)

        result = engine.run(
            discovery=discovery_result([classified(public("get", "/health"))]),
            budget=30,
            client=client,
        )
        client.close()

        outcomes = {item.outcome for item in result.results}
        assert CheckOutcome.ERROR in outcomes
        assert len(result.results) > 1


class TestSecretSafety:
    def test_no_credential_reaches_the_assessment_document(self) -> None:
        transport = FakeTransport(default=StubResponse())
        target = scoped_target(
            auth=AuthProfile(method=AuthMethod.BEARER, token=SecretRef(variable="ACME_TOKEN"))
        )

        result = run_engine(
            endpoints=[protected("get", "/orders")],
            transport=transport,
            target=target,
            env={"ACME_TOKEN": TOKEN},
        )

        # The credential really was sent...
        assert any(
            value == f"Bearer {TOKEN}"
            for request in transport.requests
            for key, value in request.headers.items()
            if key.lower() == "authorization"
        )
        # ...and appears nowhere in the record.
        assert TOKEN not in result.model_dump_json()

    def test_evidence_redacts_request_headers(self) -> None:
        transport = FakeTransport(default=StubResponse())
        target = scoped_target(
            auth=AuthProfile(method=AuthMethod.BEARER, token=SecretRef(variable="ACME_TOKEN"))
        )

        result = run_engine(
            endpoints=[protected("get", "/orders")],
            transport=transport,
            target=target,
            check_ids=["AUTH-001"],
            env={"ACME_TOKEN": TOKEN},
        )

        headers = [
            value
            for item in result.results
            for piece in item.evidence
            for value in piece.request_headers.values()
        ]
        assert TOKEN not in " ".join(headers)

    def test_evidence_excerpts_are_bounded(self) -> None:
        big = b'{"data": "' + b"x" * 50_000 + b'"}'
        transport = FakeTransport(
            default=StubResponse(body=big, headers=[("content-type", "application/json")])
        )

        result = run_engine(
            endpoints=[public("get", "/health")],
            transport=transport,
            check_ids=["CONF-001"],
        )

        for item in result.results:
            for piece in item.evidence:
                if piece.body_excerpt is not None:
                    assert len(piece.body_excerpt) <= 1024


class TestResultShape:
    def test_results_carry_target_and_endpoint_references(self) -> None:
        result = run_engine(
            endpoints=[public("get", "/health")],
            transport=FakeTransport(default=StubResponse()),
            check_ids=["CONF-001"],
        )

        first = result.results[0]
        assert first.target_name == "acme"
        assert first.endpoint_key == "GET /health"
        assert first.recorded_at.tzinfo is not None

    def test_findings_always_state_their_limitations(self) -> None:
        transport = FakeTransport(default=StubResponse())
        target = scoped_target(
            auth=AuthProfile(method=AuthMethod.BEARER, token=SecretRef(variable="ACME_TOKEN"))
        )

        result = run_engine(
            endpoints=[protected("get", "/orders")],
            transport=transport,
            target=target,
            env={"ACME_TOKEN": TOKEN},
        )

        for item in result.findings():
            assert item.limitations, f"{item.check_id} reported a finding with no limitations"

    def test_summary_counts_are_consistent(self) -> None:
        result = run_engine(
            endpoints=[public("get", "/health"), public("get", "/status")],
            transport=FakeTransport(default=StubResponse()),
        )

        assert sum(result.by_outcome().values()) == len(result.results)
        assert sum(result.by_finding_class().values()) == len(result.results)

    def test_evidence_index_is_addressable(self) -> None:
        result = run_engine(
            endpoints=[public("get", "/health")],
            transport=FakeTransport(default=StubResponse()),
            check_ids=["CONF-001"],
        )

        index = result.evidence_index()
        for item in result.results:
            for reference in item.evidence_ids:
                assert reference in index


class AssessmentIdentityClients:
    def test_identity_clients_share_the_transport_and_throttle(self) -> None:
        from aegisapi.testing.fixtures import AssessmentIdentity

        transport = FakeTransport(default=StubResponse())
        target = scoped_target()
        config = make_config()
        client = make_client(target, config, transport)
        context = CheckContext(
            target=target,
            config=config,
            client=client,
            budget=RequestBudget(limit=5),
            fixtures=AssessmentFixtures(),
        )
        identity = AssessmentIdentity(
            name="alice",
            auth=AuthProfile(method=AuthMethod.BEARER, token=SecretRef(variable="ALICE_TOKEN")),
        )

        first = context.client_for(identity)
        second = context.client_for(identity)

        assert first is second
        assert first.throttle is client.throttle
        client.close()

    def test_an_identity_client_still_enforces_scope(self) -> None:
        from aegisapi.testing.fixtures import AssessmentIdentity

        target = scoped_target()
        config = make_config()
        client = make_client(target, config, RefusingTransport())
        context = CheckContext(
            target=target,
            config=config,
            client=client,
            budget=RequestBudget(limit=5),
            fixtures=AssessmentFixtures(),
        )
        identity = AssessmentIdentity(name="bob", auth=AuthProfile())

        with pytest.raises(ScopeViolationError):
            context.client_for(identity).request("GET", "https://attacker.test/x")
        client.close()

    def test_scope_settings_come_from_configuration_not_the_identity(self) -> None:
        from aegisapi.testing.fixtures import AssessmentIdentity

        target = scoped_target()
        config = make_config(allowed_hosts=())
        client = make_client(target, config, RefusingTransport())
        context = CheckContext(
            target=target,
            config=config,
            client=client,
            budget=RequestBudget(limit=5),
            fixtures=AssessmentFixtures(),
        )

        sibling = context.client_for(AssessmentIdentity(name="carol", auth=AuthProfile()))

        with pytest.raises(ScopeViolationError, match="not globally authorised"):
            sibling.request("GET", "/orders")
        client.close()
