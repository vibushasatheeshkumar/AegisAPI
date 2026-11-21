"""Behaviour of the individual security checks.

The recurring assertion is the project's central discipline: a check may FAIL
without the finding being ``CONFIRMED``. Each test states which of the two it
is exercising.
"""

from __future__ import annotations

import pytest

from aegisapi.models.assessment import CheckOutcome, FindingClass
from aegisapi.models.common import Confidence, Severity
from aegisapi.models.secrets import SecretRef
from aegisapi.models.target import ApiKeyLocation, AuthMethod, AuthProfile
from aegisapi.testing import AssessmentEngine, AssessmentFixtures
from aegisapi.testing.fixtures import AccessExpectation, AssessmentIdentity, OwnedObject
from assessfix import (
    TOKEN,
    classified,
    discovery_result,
    make_client,
    make_config,
    operation,
    path_param,
    protected,
    public,
    query,
    scoped_target,
)
from httpstub import FakeTransport, RefusingTransport, StubResponse


def run(
    endpoints,
    transport,
    *,
    check_ids,
    target=None,
    fixtures=None,
    auto_fixtures=None,
    env=None,
    budget=60,
):
    """Run named checks over the given endpoints."""
    active = target or scoped_target()
    config = make_config()
    client = make_client(active, config, transport, env=env)
    engine = AssessmentEngine(target=active, config=config)
    try:
        return engine.run(
            discovery=discovery_result([classified(item) for item in endpoints]),
            fixtures=fixtures,
            auto_fixtures=auto_fixtures,
            check_ids=check_ids,
            budget=budget,
            client=client,
            env=env,
        )
    finally:
        client.close()


def only(result, check_id: str):
    """The single result for one check."""
    matches = [item for item in result.results if item.check_id == check_id]
    assert matches, f"no result for {check_id}"
    return matches[0]


def bearer_target():
    """A target authenticating with a bearer token."""
    return scoped_target(
        auth=AuthProfile(method=AuthMethod.BEARER, token=SecretRef(variable="ACME_TOKEN"))
    )


class TestAuthenticationChecks:
    def test_refused_unauthenticated_request_passes(self) -> None:
        transport = FakeTransport([StubResponse(status_code=401, body=b'{"error":"unauthorized"}')])

        result = run(
            [protected("get", "/orders")],
            transport,
            check_ids=["AUTH-001"],
            target=bearer_target(),
            env={"ACME_TOKEN": TOKEN},
        )
        item = only(result, "AUTH-001")

        assert item.outcome is CheckOutcome.PASS
        assert item.finding_class is FindingClass.NONE

    def test_identical_bodies_confirm_authentication_is_not_enforced(self) -> None:
        same = StubResponse(status_code=200, body=b'{"orders":[1,2,3]}')
        transport = FakeTransport([same, same])

        result = run(
            [protected("get", "/orders")],
            transport,
            check_ids=["AUTH-001"],
            target=bearer_target(),
            env={"ACME_TOKEN": TOKEN},
        )
        item = only(result, "AUTH-001")

        assert item.outcome is CheckOutcome.FAIL
        assert item.finding_class is FindingClass.CONFIRMED
        assert item.severity is Severity.HIGH
        assert len(item.evidence) == 2
        assert item.limitations

    def test_differing_bodies_are_only_suspected(self) -> None:
        # A 200 without credentials is not proof: the content differs, so the
        # unauthenticated view may be a public subset.
        transport = FakeTransport(
            [
                StubResponse(status_code=200, body=b'{"orders":[]}'),
                StubResponse(status_code=200, body=b'{"orders":[1,2,3]}'),
            ]
        )

        result = run(
            [protected("get", "/orders")],
            transport,
            check_ids=["AUTH-001"],
            target=bearer_target(),
            env={"ACME_TOKEN": TOKEN},
        )
        item = only(result, "AUTH-001")

        assert item.outcome is CheckOutcome.FAIL
        assert item.finding_class is FindingClass.SUSPECTED
        assert item.severity is Severity.MEDIUM

    def test_a_status_code_alone_never_confirms(self) -> None:
        transport = FakeTransport(
            [
                StubResponse(status_code=200, body=b""),
                StubResponse(status_code=200, body=b""),
            ]
        )

        result = run(
            [protected("get", "/orders")],
            transport,
            check_ids=["AUTH-001"],
            target=bearer_target(),
            env={"ACME_TOKEN": TOKEN},
        )
        item = only(result, "AUTH-001")

        # Empty bodies are not compared as matching content.
        assert item.finding_class is not FindingClass.CONFIRMED

    def test_an_invalid_token_that_is_rejected_passes(self) -> None:
        transport = FakeTransport([StubResponse(status_code=403)])

        result = run(
            [protected("get", "/orders")],
            transport,
            check_ids=["AUTH-002"],
            target=bearer_target(),
            env={"ACME_TOKEN": TOKEN},
        )

        assert only(result, "AUTH-002").outcome is CheckOutcome.PASS

    def test_an_accepted_invalid_token_is_suspected_not_confirmed(self) -> None:
        transport = FakeTransport([StubResponse(status_code=200)])

        result = run(
            [protected("get", "/orders")],
            transport,
            check_ids=["AUTH-002"],
            target=bearer_target(),
            env={"ACME_TOKEN": TOKEN},
        )
        item = only(result, "AUTH-002")

        assert item.outcome is CheckOutcome.FAIL
        assert item.finding_class is FindingClass.SUSPECTED

    def test_the_probe_token_is_synthetic_not_a_guess(self) -> None:
        from aegisapi.testing.authentication import PROBE_TOKEN

        transport = FakeTransport([StubResponse(status_code=401)])
        run(
            [protected("get", "/orders")],
            transport,
            check_ids=["AUTH-002"],
            target=bearer_target(),
            env={"ACME_TOKEN": TOKEN},
        )

        sent = transport.header_of("authorization")
        assert sent == f"Bearer {PROBE_TOKEN}"
        assert TOKEN not in (sent or "")

    def test_missing_metadata_is_informational_not_a_finding(self) -> None:
        result = run(
            [operation("get", "/mystery")],
            RefusingTransport(),
            check_ids=["AUTH-003"],
        )
        item = only(result, "AUTH-003")

        assert item.finding_class is FindingClass.INFORMATIONAL
        assert item.severity is None
        assert item.requests_sent == 0
        assert "not a vulnerability" in " ".join(item.limitations)

    def test_a_documented_public_endpoint_passes(self) -> None:
        result = run([public("get", "/health")], RefusingTransport(), check_ids=["AUTH-003"])
        item = only(result, "AUTH-003")

        assert item.outcome is CheckOutcome.PASS
        assert item.finding_class is FindingClass.INFORMATIONAL

    def test_an_undefined_scheme_is_reported(self) -> None:
        endpoint = operation(
            "get",
            "/orders",
            posture="operation_override",
            schemes=("ghostAuth",),
            undefined_schemes=("ghostAuth",),
        )

        result = run([endpoint], RefusingTransport(), check_ids=["AUTH-003"])

        assert "undefined" in only(result, "AUTH-003").summary


class TestObjectLevelAuthorization:
    def fixtures(self, **overrides: object) -> AssessmentFixtures:
        """Two identities and one owned object."""
        defaults: dict[str, object] = {
            "identities": [
                AssessmentIdentity(
                    name="alice",
                    role="user",
                    auth=AuthProfile(
                        method=AuthMethod.BEARER, token=SecretRef(variable="ALICE_TOKEN")
                    ),
                ),
                AssessmentIdentity(
                    name="bob",
                    role="user",
                    auth=AuthProfile(
                        method=AuthMethod.BEARER, token=SecretRef(variable="BOB_TOKEN")
                    ),
                ),
            ],
            "objects": [OwnedObject(owner="alice", parameter="orderId", value="1001")],
        }
        defaults.update(overrides)
        return AssessmentFixtures.model_validate(defaults)

    def endpoint(self):
        return protected("get", "/orders/{orderId}", parameters=[path_param("orderId")])

    def env(self) -> dict[str, str]:
        return {"ALICE_TOKEN": "alice-token", "BOB_TOKEN": "bob-token"}

    def test_a_refused_non_owner_passes(self) -> None:
        transport = FakeTransport(
            [
                StubResponse(status_code=200, body=b'{"id":"1001"}'),
                StubResponse(status_code=403, body=b'{"error":"forbidden"}'),
            ]
        )

        result = run(
            [self.endpoint()],
            transport,
            check_ids=["BOLA-001"],
            fixtures=self.fixtures(),
            env=self.env(),
        )
        item = only(result, "BOLA-001")

        assert item.outcome is CheckOutcome.PASS
        assert transport.call_count == 2

    def test_identical_bodies_confirm_the_weakness(self) -> None:
        same = StubResponse(status_code=200, body=b'{"id":"1001","owner":"alice"}')
        transport = FakeTransport([same, same])

        result = run(
            [self.endpoint()],
            transport,
            check_ids=["BOLA-001"],
            fixtures=self.fixtures(),
            env=self.env(),
        )
        item = only(result, "BOLA-001")

        assert item.outcome is CheckOutcome.FAIL
        assert item.finding_class is FindingClass.CONFIRMED
        assert item.severity is Severity.HIGH
        assert item.confidence is Confidence.HIGH
        assert {piece.identity for piece in item.evidence} == {"alice", "bob"}

    def test_differing_bodies_are_only_suspected(self) -> None:
        transport = FakeTransport(
            [
                StubResponse(status_code=200, body=b'{"id":"1001","owner":"alice"}'),
                StubResponse(status_code=200, body=b'{"id":"1001"}'),
            ]
        )

        result = run(
            [self.endpoint()],
            transport,
            check_ids=["BOLA-001"],
            fixtures=self.fixtures(),
            env=self.env(),
        )

        assert only(result, "BOLA-001").finding_class is FindingClass.SUSPECTED

    def test_no_baseline_means_inconclusive(self) -> None:
        transport = FakeTransport([StubResponse(status_code=404), StubResponse(status_code=404)])

        result = run(
            [self.endpoint()],
            transport,
            check_ids=["BOLA-001"],
            fixtures=self.fixtures(),
            env=self.env(),
        )
        item = only(result, "BOLA-001")

        assert item.outcome is CheckOutcome.NEEDS_REVIEW
        assert item.finding_class is FindingClass.INCONCLUSIVE

    def test_a_single_identity_is_not_enough(self) -> None:
        fixtures = self.fixtures(
            identities=[
                AssessmentIdentity(
                    name="alice",
                    auth=AuthProfile(
                        method=AuthMethod.BEARER, token=SecretRef(variable="ALICE_TOKEN")
                    ),
                )
            ]
        )

        result = run(
            [self.endpoint()],
            RefusingTransport(),
            check_ids=["BOLA-001"],
            fixtures=fixtures,
            env=self.env(),
        )

        assert result.requests_sent == 0

    def test_a_missing_credential_skips_rather_than_guessing(self) -> None:
        transport = FakeTransport(default=StubResponse())

        result = run(
            [self.endpoint()],
            transport,
            check_ids=["BOLA-001"],
            fixtures=self.fixtures(),
            env={},
        )

        assert only(result, "BOLA-001").outcome is CheckOutcome.SKIPPED

    def test_write_methods_are_skipped_by_default(self) -> None:
        endpoint = protected("delete", "/orders/{orderId}", parameters=[path_param("orderId")])

        result = run(
            [endpoint],
            RefusingTransport(),
            check_ids=["BOLA-001"],
            fixtures=self.fixtures(),
            env=self.env(),
        )

        assert result.requests_sent == 0

    def test_write_methods_run_only_when_explicitly_permitted(self) -> None:
        endpoint = protected("delete", "/orders/{orderId}", parameters=[path_param("orderId")])
        transport = FakeTransport([StubResponse(status_code=204), StubResponse(status_code=403)])

        result = run(
            [endpoint],
            transport,
            check_ids=["BOLA-001"],
            fixtures=self.fixtures(allow_write_methods=True),
            env=self.env(),
        )

        assert transport.call_count == 2
        assert only(result, "BOLA-001").outcome is CheckOutcome.PASS

    def test_an_unfillable_template_is_skipped(self) -> None:
        endpoint = protected(
            "get",
            "/orgs/{orgId}/orders/{orderId}",
            parameters=[path_param("orgId"), path_param("orderId")],
        )

        result = run(
            [endpoint],
            RefusingTransport(),
            check_ids=["BOLA-001"],
            fixtures=self.fixtures(),
            env=self.env(),
        )

        assert only(result, "BOLA-001").outcome is CheckOutcome.SKIPPED


class TestFunctionLevelAuthorization:
    def fixtures(self, *, allowed: bool = False) -> AssessmentFixtures:
        return AssessmentFixtures(
            identities=[
                AssessmentIdentity(
                    name="bob",
                    role="user",
                    auth=AuthProfile(
                        method=AuthMethod.BEARER, token=SecretRef(variable="BOB_TOKEN")
                    ),
                )
            ],
            expectations=[AccessExpectation(identity="bob", path="/admin/**", allowed=allowed)],
        )

    def test_a_refused_identity_passes(self) -> None:
        transport = FakeTransport([StubResponse(status_code=403)])

        result = run(
            [protected("get", "/admin/users")],
            transport,
            check_ids=["BFLA-001"],
            fixtures=self.fixtures(),
            env={"BOB_TOKEN": "bob-token"},
        )

        assert only(result, "BFLA-001").outcome is CheckOutcome.PASS

    def test_reaching_a_forbidden_function_is_confirmed(self) -> None:
        transport = FakeTransport([StubResponse(status_code=200, body=b'{"users":[]}')])

        result = run(
            [protected("get", "/admin/users")],
            transport,
            check_ids=["BFLA-001"],
            fixtures=self.fixtures(),
            env={"BOB_TOKEN": "bob-token"},
        )
        item = only(result, "BFLA-001")

        assert item.outcome is CheckOutcome.FAIL
        assert item.finding_class is FindingClass.CONFIRMED
        assert "declared" in item.explanation

    def test_an_admin_sounding_path_alone_is_not_tested(self) -> None:
        # No declared expectation: nothing to compare against, so nothing runs.
        result = run(
            [protected("get", "/admin/users")],
            RefusingTransport(),
            check_ids=["BFLA-001"],
            fixtures=AssessmentFixtures(),
        )

        assert result.requests_sent == 0

    def test_an_allow_expectation_is_not_tested_as_a_denial(self) -> None:
        result = run(
            [protected("get", "/admin/users")],
            RefusingTransport(),
            check_ids=["BFLA-001"],
            fixtures=self.fixtures(allowed=True),
            env={"BOB_TOKEN": "bob-token"},
        )

        assert result.requests_sent == 0


class TestInputValidation:
    def test_a_rejected_missing_parameter_passes(self) -> None:
        transport = FakeTransport([StubResponse(status_code=400)])
        endpoint = public("get", "/orders", parameters=[query("limit", required=True)])

        result = run([endpoint], transport, check_ids=["INPUT-001"])

        assert only(result, "INPUT-001").outcome is CheckOutcome.PASS

    def test_an_accepted_missing_parameter_is_informational(self) -> None:
        transport = FakeTransport([StubResponse(status_code=200)])
        endpoint = public("get", "/orders", parameters=[query("limit", required=True)])

        result = run([endpoint], transport, check_ids=["INPUT-001"])
        item = only(result, "INPUT-001")

        assert item.outcome is CheckOutcome.FAIL
        assert item.finding_class is FindingClass.INFORMATIONAL
        assert item.severity is None

    def test_a_server_error_is_low_severity_and_not_an_exploit_claim(self) -> None:
        transport = FakeTransport([StubResponse(status_code=500)])
        endpoint = public(
            "get", "/orders", parameters=[query("limit", required=True, type_="integer")]
        )

        result = run([endpoint], transport, check_ids=["INPUT-002"])
        item = only(result, "INPUT-002")

        assert item.finding_class is FindingClass.SUSPECTED
        assert item.severity is Severity.LOW
        assert "not evidence of injection" in item.explanation

    def test_the_probe_value_is_benign(self) -> None:
        from aegisapi.testing.input_validation import NON_NUMERIC_VALUE

        transport = FakeTransport([StubResponse(status_code=400)])
        endpoint = public("get", "/orders", parameters=[query("limit", type_="integer")])

        run([endpoint], transport, check_ids=["INPUT-002"])

        assert NON_NUMERIC_VALUE in transport.last_request.url
        for forbidden in ("'", ";", "../", "<script", "UNION", "$("):
            assert forbidden not in transport.last_request.url

    def test_an_invalid_enum_value_is_probed(self) -> None:
        transport = FakeTransport([StubResponse(status_code=400)])
        endpoint = public("get", "/orders", parameters=[query("status", enum=("open", "closed"))])

        result = run([endpoint], transport, check_ids=["INPUT-003"])

        assert only(result, "INPUT-003").outcome is CheckOutcome.PASS

    def test_each_check_sends_at_most_one_request(self) -> None:
        transport = FakeTransport(default=StubResponse(status_code=400))
        endpoint = public(
            "get",
            "/orders",
            parameters=[
                query("limit", required=True, type_="integer"),
                query("status", enum=("open", "closed")),
            ],
        )

        result = run([endpoint], transport, check_ids=["INPUT-001", "INPUT-002", "INPUT-003"])

        assert transport.call_count == 3
        assert result.requests_sent == 3

    def test_templated_paths_send_request_with_auto_fixtures(self) -> None:
        # M2: auto fixtures are generated from the schema, so templated paths
        # are no longer unconditionally skipped.
        endpoint = public(
            "get",
            "/orders/{orderId}",
            parameters=[path_param("orderId"), query("limit", required=True)],
        )
        transport = FakeTransport(default=StubResponse(status_code=400))

        result = run([endpoint], transport, check_ids=["INPUT-001"])

        assert result.requests_sent == 1

    def test_templated_paths_skipped_when_no_auto_fixtures_provided(self) -> None:
        # When an empty auto_fixtures dict is passed explicitly, the check
        # falls back to skipping — no guessing without declared or generated values.
        endpoint = public(
            "get",
            "/orders/{orderId}",
            parameters=[path_param("orderId"), query("limit", required=True)],
        )

        result = run(
            [endpoint],
            RefusingTransport(),
            check_ids=["INPUT-001"],
            auto_fixtures={},
        )

        assert result.requests_sent == 0

    def test_write_methods_are_skipped_by_default(self) -> None:
        endpoint = public("post", "/orders", parameters=[query("limit", required=True)])

        result = run([endpoint], RefusingTransport(), check_ids=["INPUT-001"])

        assert result.requests_sent == 0


class TestConfigurationChecks:
    def test_present_headers_pass(self) -> None:
        transport = FakeTransport(
            [
                StubResponse(
                    headers=[
                        ("content-type", "application/json"),
                        ("x-content-type-options", "nosniff"),
                        ("cache-control", "no-store"),
                        ("strict-transport-security", "max-age=31536000"),
                    ]
                )
            ]
        )

        result = run([public("get", "/health")], transport, check_ids=["CONF-001"])

        assert only(result, "CONF-001").outcome is CheckOutcome.PASS

    def test_missing_headers_are_informational_not_vulnerabilities(self) -> None:
        transport = FakeTransport([StubResponse(headers=[("content-type", "application/json")])])

        result = run([public("get", "/health")], transport, check_ids=["CONF-001"])
        item = only(result, "CONF-001")

        assert item.finding_class is FindingClass.INFORMATIONAL
        assert item.severity is None
        assert "not an exploitable weakness" in " ".join(item.limitations)

    def test_hsts_is_not_expected_over_plain_http(self) -> None:
        transport = FakeTransport(
            [
                StubResponse(
                    headers=[
                        ("content-type", "application/json"),
                        ("x-content-type-options", "nosniff"),
                        ("cache-control", "no-store"),
                    ]
                )
            ]
        )
        target = scoped_target(base_url="http://api.acme.test/v1")
        config = make_config()
        client = make_client(target, config, transport)
        engine = AssessmentEngine(target=target, config=config)
        result = engine.run(
            discovery=discovery_result(
                [classified(public("get", "/health"), base="http://api.acme.test/v1")]
            ),
            check_ids=["CONF-001"],
            budget=10,
            client=client,
        )
        client.close()

        assert only(result, "CONF-001").outcome is CheckOutcome.PASS

    def test_reflected_origin_with_credentials_is_confirmed(self) -> None:
        from aegisapi.testing.configuration import PROBE_ORIGIN

        transport = FakeTransport(
            [
                StubResponse(
                    headers=[
                        ("content-type", "application/json"),
                        ("access-control-allow-origin", PROBE_ORIGIN),
                        ("access-control-allow-credentials", "true"),
                    ]
                )
            ]
        )

        result = run([public("get", "/health")], transport, check_ids=["CONF-002"])
        item = only(result, "CONF-002")

        assert item.finding_class is FindingClass.CONFIRMED
        assert item.severity is Severity.HIGH

    def test_reflected_origin_without_credentials_is_lower(self) -> None:
        from aegisapi.testing.configuration import PROBE_ORIGIN

        transport = FakeTransport(
            [
                StubResponse(
                    headers=[
                        ("content-type", "application/json"),
                        ("access-control-allow-origin", PROBE_ORIGIN),
                    ]
                )
            ]
        )

        result = run([public("get", "/health")], transport, check_ids=["CONF-002"])
        item = only(result, "CONF-002")

        assert item.finding_class is FindingClass.SUSPECTED
        assert item.severity is Severity.LOW

    def test_a_wildcard_is_informational(self) -> None:
        transport = FakeTransport(
            [
                StubResponse(
                    headers=[
                        ("content-type", "application/json"),
                        ("access-control-allow-origin", "*"),
                    ]
                )
            ]
        )

        result = run([public("get", "/health")], transport, check_ids=["CONF-002"])

        assert only(result, "CONF-002").finding_class is FindingClass.INFORMATIONAL

    def test_a_fixed_origin_passes(self) -> None:
        transport = FakeTransport(
            [
                StubResponse(
                    headers=[
                        ("content-type", "application/json"),
                        ("access-control-allow-origin", "https://app.acme.test"),
                    ]
                )
            ]
        )

        result = run([public("get", "/health")], transport, check_ids=["CONF-002"])

        assert only(result, "CONF-002").outcome is CheckOutcome.PASS

    def test_undocumented_methods_are_reported_without_being_called(self) -> None:
        transport = FakeTransport([StubResponse(headers=[("allow", "GET, POST, DELETE, OPTIONS")])])

        result = run([public("get", "/health")], transport, check_ids=["CONF-003"])
        item = only(result, "CONF-003")

        assert "DELETE" in item.summary
        assert transport.call_count == 1
        assert transport.last_request.method.value == "OPTIONS"

    def test_server_header_disclosure_is_informational(self) -> None:
        transport = FakeTransport(
            [StubResponse(headers=[("content-type", "application/json"), ("server", "nginx/1.2")])]
        )

        result = run([public("get", "/health")], transport, check_ids=["CONF-004"])
        item = only(result, "CONF-004")

        assert item.finding_class is FindingClass.INFORMATIONAL
        assert "not itself a weakness" in item.explanation

    def test_content_type_drift_is_reported(self) -> None:
        from aegisapi.models.endpoint import SchemaSummary

        endpoint = public(
            "get",
            "/health",
            response_schema=SchemaSummary(type="object"),
            response_content_type="application/json",
        )
        transport = FakeTransport([StubResponse(headers=[("content-type", "text/html")])])

        result = run([endpoint], transport, check_ids=["CONF-005"])

        assert "not documented" in only(result, "CONF-005").summary


class TestRateLimitProbe:
    def test_a_429_stops_the_probe_immediately(self) -> None:
        transport = FakeTransport(
            [
                StubResponse(status_code=200),
                StubResponse(status_code=429, headers=[("retry-after", "30")]),
                StubResponse(status_code=200),
            ]
        )

        result = run([public("get", "/health")], transport, check_ids=["RATE-001"])
        item = only(result, "RATE-001")

        assert transport.call_count == 2
        assert item.outcome is CheckOutcome.PASS
        assert "after 2 request(s)" in item.summary

    def test_no_limit_observed_is_inconclusive_not_a_finding(self) -> None:
        transport = FakeTransport(default=StubResponse(status_code=200))

        result = run([public("get", "/health")], transport, check_ids=["RATE-001"])
        item = only(result, "RATE-001")

        assert item.finding_class is FindingClass.INCONCLUSIVE
        assert "cannot establish the absence" in " ".join(item.limitations)

    def test_the_probe_respects_the_budget(self) -> None:
        transport = FakeTransport(default=StubResponse(status_code=200))

        run([public("get", "/health")], transport, check_ids=["RATE-001"], budget=3)

        assert transport.call_count <= 3

    def test_too_small_a_sample_is_skipped(self) -> None:
        transport = RefusingTransport()

        result = run([public("get", "/health")], transport, check_ids=["RATE-001"], budget=2)

        assert only(result, "RATE-001").outcome is CheckOutcome.SKIPPED

    def test_advertised_limits_are_reported(self) -> None:
        transport = FakeTransport(
            default=StubResponse(
                status_code=200,
                headers=[("content-type", "application/json"), ("x-ratelimit-limit", "100")],
            )
        )

        result = run([public("get", "/health")], transport, check_ids=["RATE-001"])
        item = only(result, "RATE-001")

        assert item.outcome is CheckOutcome.PASS
        assert "advertised" in item.summary

    def test_evidence_is_bounded_to_a_few_observations(self) -> None:
        transport = FakeTransport(default=StubResponse(status_code=200))

        result = run([public("get", "/health")], transport, check_ids=["RATE-001"])

        assert len(only(result, "RATE-001").evidence) <= 3


class TestEvidenceSafety:
    def test_only_allow_listed_response_headers_are_recorded(self) -> None:
        transport = FakeTransport(
            [
                StubResponse(
                    headers=[
                        ("content-type", "application/json"),
                        ("set-cookie", f"session={TOKEN}"),
                        ("x-internal-debug", "stack trace here"),
                    ]
                )
            ]
        )

        result = run([public("get", "/health")], transport, check_ids=["CONF-001"])
        recorded = only(result, "CONF-001").evidence[0].response_headers

        assert "content-type" in recorded
        assert "set-cookie" not in recorded
        assert "x-internal-debug" not in recorded

    def test_evidence_ids_are_stable_across_runs(self) -> None:
        def ids():
            transport = FakeTransport(default=StubResponse())
            result = run([public("get", "/health")], transport, check_ids=["CONF-001"])
            return only(result, "CONF-001").evidence_ids

        assert ids() == ids()

    @pytest.mark.parametrize("check_id", ["CONF-001", "CONF-002", "AUTH-002"])
    def test_no_check_records_a_credential(self, check_id: str) -> None:
        transport = FakeTransport(default=StubResponse())
        target = bearer_target()

        result = run(
            [protected("get", "/orders")],
            transport,
            check_ids=[check_id],
            target=target,
            env={"ACME_TOKEN": TOKEN},
        )

        assert TOKEN not in result.model_dump_json()


class TestApiKeyIdentity:
    def test_an_api_key_identity_is_applied_and_redacted(self) -> None:
        transport = FakeTransport(default=StubResponse())
        target = scoped_target(
            auth=AuthProfile(
                method=AuthMethod.API_KEY,
                api_key=SecretRef(variable="ACME_KEY"),
                api_key_name="X-Acme-Key",
                api_key_location=ApiKeyLocation.HEADER,
            )
        )

        result = run(
            [protected("get", "/orders")],
            transport,
            check_ids=["CONF-001"],
            target=target,
            env={"ACME_KEY": TOKEN},
        )

        assert transport.header_of("x-acme-key") == TOKEN
        assert TOKEN not in result.model_dump_json()
