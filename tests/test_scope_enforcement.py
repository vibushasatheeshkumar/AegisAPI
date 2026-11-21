"""One gate, used by the thing that actually sends.

:mod:`tests.test_scope` is the contract for what the scope policy decides, and
:mod:`tests.test_http_client` is the contract for the request boundary. This
module covers the seam between them: that
:func:`aegisapi.core.scope.assert_in_scope` is the function the production
request path calls, for the first request and for every redirect hop, and that
a direct call to it and a call through :class:`ScopedHttpClient` cannot
disagree.

The duplication these tests guard against is not hypothetical. The client used
to assemble the two-gate sequence itself - parse, check the target, check the
allow-list, raise - which meant the policy existed twice and a correction to
one copy would silently miss the path that sends bytes. A second copy would
make the parity tests below fail.
"""

from __future__ import annotations

from typing import ClassVar

import pytest

import aegisapi.core.scope as scope_module
import aegisapi.http.client as client_module
from aegisapi.core.config import ScopeSettings
from aegisapi.core.exceptions import AegisAPIError, ScopeViolationError
from aegisapi.core.scope import assert_in_scope
from aegisapi.http import ScopedHttpClient
from aegisapi.http.client import resolve_request_url
from aegisapi.http.throttle import RequestThrottle
from aegisapi.models.http import HttpLimits
from aegisapi.models.secrets import SecretRef
from aegisapi.models.target import AuthMethod, AuthProfile, ScopeRules, Target
from conftest import make_target
from httpstub import FakeTransport, RefusingTransport, StubResponse

TOKEN = "eyJhbGciOiJIUzI1NiJ9.super-secret-token-value"
ALLOWED = ScopeSettings(allowed_hosts=["api.acme.test"])

REDIRECT_LIMITS = HttpLimits(follow_redirects=True, requests_per_second=100.0)


def client(
    *,
    target: Target | None = None,
    settings: ScopeSettings | None = None,
    transport: object | None = None,
    limits: HttpLimits | None = None,
    env: dict[str, str] | None = None,
) -> ScopedHttpClient:
    """Build a client with deterministic throttling and no real transport."""
    return ScopedHttpClient(
        target=target or make_target(),
        settings=settings if settings is not None else ALLOWED,
        limits=limits or HttpLimits(requests_per_second=100.0),
        transport=transport or FakeTransport(),  # type: ignore[arg-type]
        throttle=RequestThrottle(requests_per_second=1000.0, max_concurrency=4),
        env=env,
        sleeper=lambda _: None,
    )


def record_gate_calls(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Spy on the gate as the client sees it, returning the URLs it was given.

    The real function still runs, so behaviour is unchanged and the recorded
    list is proof of delegation rather than a substitute for it.
    """
    calls: list[str] = []
    real = scope_module.assert_in_scope

    def recording(
        url: object,
        *,
        target: Target,
        settings: ScopeSettings | None = None,
    ) -> scope_module.ScopeAuthorisation:
        calls.append(str(url))
        return real(url, target=target, settings=settings)  # type: ignore[arg-type]

    monkeypatch.setattr(client_module, "assert_in_scope", recording)
    return calls


class TestTheClientUsesTheAuthoritativeGate:
    def test_the_client_imports_the_one_gate(self) -> None:
        assert client_module.assert_in_scope is scope_module.assert_in_scope

    def test_the_client_holds_no_second_copy_of_the_policy(self) -> None:
        # The client must reach the policy only through the gate. Importing the
        # raw decision functions here is how the duplicate arose before, so it
        # is what this test watches for.
        assert not hasattr(client_module, "ScopeValidator")
        assert not hasattr(client_module, "check_global_allow_list")

    def test_an_allowed_request_goes_through_the_gate(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        calls = record_gate_calls(monkeypatch)

        client().request("GET", "/orders")

        assert calls == ["https://api.acme.test/v1/orders"]

    def test_a_refusal_comes_from_the_gate_before_transmission(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        calls = record_gate_calls(monkeypatch)

        with pytest.raises(ScopeViolationError):
            client(transport=RefusingTransport()).request("GET", "https://attacker.test/v1/orders")

        # Consulted once, and RefusingTransport proves nothing was sent.
        assert calls == ["https://attacker.test/v1/orders"]

    def test_every_redirect_hop_passes_through_the_gate(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        calls = record_gate_calls(monkeypatch)
        transport = FakeTransport(
            [
                StubResponse(status_code=302, headers=[("location", "/v1/hop-one")]),
                StubResponse(status_code=302, headers=[("location", "/v1/hop-two")]),
                StubResponse(status_code=200),
            ]
        )

        response = client(transport=transport, limits=REDIRECT_LIMITS).request("GET", "/orders")

        assert response.status_code == 200
        assert calls == [
            "https://api.acme.test/v1/orders",
            "https://api.acme.test/v1/hop-one",
            "https://api.acme.test/v1/hop-two",
        ]

    def test_a_denied_hop_is_gated_and_the_chain_stops(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        calls = record_gate_calls(monkeypatch)
        transport = FakeTransport(
            [StubResponse(status_code=302, headers=[("location", "https://attacker.test/steal")])]
        )

        with pytest.raises(ScopeViolationError, match="out of scope"):
            client(transport=transport, limits=REDIRECT_LIMITS).request("GET", "/orders")

        # The first hop was answered; the second was judged and never sent.
        assert transport.call_count == 1
        assert calls == [
            "https://api.acme.test/v1/orders",
            "https://attacker.test/steal",
        ]


class TestDirectAndClientEnforcementAgree:
    """A URL judged by the gate and by the client must come out the same way."""

    CASES: ClassVar[list[str]] = [
        "https://api.acme.test/v1/orders",
        "https://api.acme.test/v1",
        "https://api.acme.test/v1/orders/42",
        "https://api.acme.test/v2/orders",
        "https://api.acme.test/v1beta/orders",
        "https://attacker.test/v1/orders",
        "https://api.acme.test.attacker.test/v1/orders",
        "https://sub.api.acme.test/v1/orders",
        "http://api.acme.test/v1/orders",
        "https://api.acme.test:8443/v1/orders",
    ]

    def gate_outcome(self, url: str, *, target: Target, settings: ScopeSettings) -> tuple[str, str]:
        """What a direct call to the gate decides."""
        try:
            return "allowed", assert_in_scope(url, target=target, settings=settings).reason
        except AegisAPIError as exc:
            return "refused", exc.message

    def client_outcome(
        self, url: str, *, target: Target, settings: ScopeSettings
    ) -> tuple[str, str]:
        """What the same URL does when sent through the client."""
        try:
            response = client(target=target, settings=settings, transport=FakeTransport()).request(
                "GET", url
            )
        except AegisAPIError as exc:
            return "refused", exc.message
        return "allowed", response.scope_reason

    @pytest.mark.parametrize("url", CASES)
    def test_the_verdict_and_its_reason_match(self, url: str) -> None:
        target = make_target()

        assert self.client_outcome(url, target=target, settings=ALLOWED) == self.gate_outcome(
            url, target=target, settings=ALLOWED
        )

    @pytest.mark.parametrize("url", CASES)
    def test_they_match_with_an_empty_global_allow_list(self, url: str) -> None:
        target = make_target()
        empty = ScopeSettings()

        assert self.client_outcome(url, target=target, settings=empty) == self.gate_outcome(
            url, target=target, settings=empty
        )

    @pytest.mark.parametrize(
        "rules",
        [
            ScopeRules(include_paths=["/v1"], exclude_paths=["/v1/admin"]),
            ScopeRules(include_paths=["/v1/**"]),
            ScopeRules(include_paths=["/v1/*/orders"]),
            ScopeRules(include_paths=["/"], extra_hosts=["cdn.acme.test"]),
            ScopeRules(include_paths=["/v1"], allow_subdomains=True),
            ScopeRules(include_paths=["/v1"], allowed_ports=[8443]),
        ],
    )
    def test_they_match_across_scope_shapes(self, rules: ScopeRules) -> None:
        target = make_target(scope=rules)
        settings = ScopeSettings(allowed_hosts=["api.acme.test", "cdn.acme.test"])
        urls = [
            *self.CASES,
            "https://api.acme.test/v1/admin",
            "https://api.acme.test/v1/eu/orders",
            "https://cdn.acme.test/assets",
        ]

        for url in urls:
            assert self.client_outcome(url, target=target, settings=settings) == self.gate_outcome(
                url, target=target, settings=settings
            )

    def test_a_disabled_target_is_refused_identically(self) -> None:
        target = make_target(enabled=False)
        url = "https://api.acme.test/v1/orders"

        assert self.client_outcome(url, target=target, settings=ALLOWED) == self.gate_outcome(
            url, target=target, settings=ALLOWED
        )

    def test_a_relative_reference_is_gated_as_its_resolved_url(self) -> None:
        target = make_target()
        resolved = resolve_request_url(target, "/orders")

        response = client().request("GET", "/orders")

        assert (
            response.scope_reason
            == assert_in_scope(resolved, target=target, settings=ALLOWED).reason
        )

    def test_the_recorded_reason_is_the_gate_reason_verbatim(self) -> None:
        target = make_target()
        url = "https://api.acme.test/v1/orders"

        response = client(target=target).request("GET", url)

        assert response.scope_reason == assert_in_scope(url, target=target, settings=ALLOWED).reason


class TestPreservedRedirectBehaviour:
    """Behaviour that had to survive the consolidation, not new behaviour."""

    def bearer_target(self, **overrides: object) -> Target:
        """A target authenticating with a bearer token."""
        return make_target(
            auth=AuthProfile(method=AuthMethod.BEARER, token=SecretRef(variable="ACME_TOKEN")),
            **overrides,  # type: ignore[arg-type]
        )

    def test_a_cross_origin_hop_is_gated_and_loses_the_credential(self) -> None:
        target = self.bearer_target(
            scope=ScopeRules(include_paths=["/"], extra_hosts=["cdn.acme.test"])
        )
        transport = FakeTransport(
            [
                StubResponse(
                    status_code=302, headers=[("location", "https://cdn.acme.test/assets")]
                ),
                StubResponse(status_code=200),
            ]
        )

        client(
            target=target,
            settings=ScopeSettings(allowed_hosts=["api.acme.test", "cdn.acme.test"]),
            transport=transport,
            limits=REDIRECT_LIMITS,
            env={"ACME_TOKEN": TOKEN},
        ).request("GET", "/orders")

        # Both hops were authorised, and only the target's own origin saw the token.
        assert transport.call_count == 2
        assert transport.header_of("authorization", 0) == f"Bearer {TOKEN}"
        assert transport.header_of("authorization", 1) is None

    def test_a_hop_allowed_by_the_target_but_not_globally_is_refused(self) -> None:
        # The second gate has to apply to a redirect as well as to a first
        # request, which is only true if every hop goes through both.
        target = make_target(scope=ScopeRules(include_paths=["/"], extra_hosts=["cdn.acme.test"]))
        transport = FakeTransport(
            [StubResponse(status_code=302, headers=[("location", "https://cdn.acme.test/assets")])]
        )

        with pytest.raises(ScopeViolationError, match="not globally authorised"):
            client(
                target=target,
                settings=ALLOWED,
                transport=transport,
                limits=REDIRECT_LIMITS,
            ).request("GET", "/orders")

        assert transport.call_count == 1

    def test_a_refusal_mid_chain_never_echoes_a_credential(self) -> None:
        transport = FakeTransport(
            [
                StubResponse(
                    status_code=302,
                    headers=[("location", f"https://attacker.test/steal?api_key={TOKEN}")],
                )
            ]
        )

        with pytest.raises(ScopeViolationError) as excinfo:
            client(transport=transport, limits=REDIRECT_LIMITS).request("GET", "/orders")

        assert TOKEN not in excinfo.value.message
        assert transport.call_count == 1
