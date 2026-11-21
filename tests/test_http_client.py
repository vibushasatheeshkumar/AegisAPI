"""The request boundary.

Every test here is about a way bytes could reach somewhere nobody authorised.
The denial cases use :class:`RefusingTransport`, which fails the test if it is
asked to send anything, so "no request was transmitted" is proven rather than
inferred from a counter.
"""

from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor

import pytest

from aegisapi.core.config import ScopeSettings
from aegisapi.core.exceptions import (
    ConnectionFailedError,
    DestinationMismatchError,
    InvalidUrlError,
    MissingCredentialError,
    RequestTimeoutError,
    ScopeViolationError,
    TlsError,
    TransportError,
)
from aegisapi.http import ScopedHttpClient
from aegisapi.http.client import FORBIDDEN_REQUEST_HEADERS, resolve_request_url
from aegisapi.http.throttle import RequestThrottle
from aegisapi.models.http import HttpLimits, HttpMethod
from aegisapi.models.secrets import SecretRef
from aegisapi.models.target import AuthMethod, AuthProfile, ScopeRules, Target
from conftest import make_target
from httpstub import FakeTransport, RefusingTransport, StubResponse

TOKEN = "eyJhbGciOiJIUzI1NiJ9.super-secret-token-value"
ALLOWED = ScopeSettings(allowed_hosts=["api.acme.test"])


def client(
    *,
    target: Target | None = None,
    settings: ScopeSettings | None = None,
    transport: object | None = None,
    limits: HttpLimits | None = None,
    env: dict[str, str] | None = None,
) -> ScopedHttpClient:
    """Build a client with deterministic throttling."""
    return ScopedHttpClient(
        target=target or make_target(),
        settings=settings if settings is not None else ALLOWED,
        limits=limits or HttpLimits(requests_per_second=100.0),
        transport=transport or FakeTransport(),  # type: ignore[arg-type]
        throttle=RequestThrottle(requests_per_second=1000.0, max_concurrency=4),
        env=env,
        sleeper=lambda _: None,
    )


class TestUrlResolution:
    @pytest.mark.parametrize(
        ("reference", "expected"),
        [
            ("/orders", "https://api.acme.test/v1/orders"),
            ("orders", "https://api.acme.test/v1/orders"),
            ("/orders/42", "https://api.acme.test/v1/orders/42"),
            ("/", "https://api.acme.test/v1"),
            ("/orders?limit=2", "https://api.acme.test/v1/orders?limit=2"),
        ],
    )
    def test_paths_resolve_against_the_base_url(self, reference: str, expected: str) -> None:
        assert resolve_request_url(make_target(), reference) == expected

    def test_absolute_urls_are_taken_as_given(self) -> None:
        assert (
            resolve_request_url(make_target(), "https://api.acme.test/v1/x")
            == "https://api.acme.test/v1/x"
        )

    @pytest.mark.parametrize(
        "reference", ["//attacker.test/x", "//attacker.test", "  //attacker.test/x  "]
    )
    def test_a_protocol_relative_path_cannot_change_the_origin(self, reference: str) -> None:
        # urljoin would turn this into a request to attacker.test.
        with pytest.raises(InvalidUrlError, match="protocol-relative"):
            resolve_request_url(make_target(), reference)

    @pytest.mark.parametrize("reference", ["", "   "])
    def test_empty_reference_is_refused(self, reference: str) -> None:
        with pytest.raises(InvalidUrlError, match="must not be empty"):
            resolve_request_url(make_target(), reference)

    @pytest.mark.parametrize(
        "reference",
        [
            "/orders%2f..%2fadmin",
            "/orders\\admin",
            "ftp://api.acme.test/v1",
            "/orders#fragment",
        ],
    )
    def test_ambiguous_and_malformed_references_are_refused(self, reference: str) -> None:
        with pytest.raises(InvalidUrlError):
            resolve_request_url(make_target(), reference)

    @pytest.mark.parametrize(
        ("reference", "expected"),
        [
            # Resolved unambiguously here, then judged by the one scope gate
            # rather than refused twice. An encoded dot segment decodes to '..'
            # with only one meaning, so normalising it is safe; an encoded
            # *separator* has more than one meaning and is refused above.
            ("/orders/../admin", "https://api.acme.test/v1/admin"),
            ("/orders/%2e%2e/admin", "https://api.acme.test/v1/admin"),
            ("/orders/../../etc", "https://api.acme.test/etc"),
        ],
    )
    def test_traversal_is_normalised_before_the_scope_decision(
        self, reference: str, expected: str
    ) -> None:
        assert resolve_request_url(make_target(), reference) == expected

    @pytest.mark.parametrize(
        "reference", ["/orders/../admin", "/orders/%2e%2e/admin", "/orders/../../etc"]
    )
    def test_normalised_traversal_is_then_denied_by_scope(self, reference: str) -> None:
        # Normalising first is what lets one exclusion catch every spelling,
        # and escaping the base path leaves the include list behind.
        target = make_target(scope=ScopeRules(include_paths=["/v1"], exclude_paths=["/v1/admin"]))

        with pytest.raises(ScopeViolationError):
            client(target=target, transport=RefusingTransport()).request("GET", reference)


class TestAllowedRequests:
    def test_a_request_in_scope_is_sent(self) -> None:
        transport = FakeTransport()
        response = client(transport=transport).request("GET", "/orders")

        assert response.status_code == 200
        assert transport.call_count == 1
        assert transport.last_request.url == "https://api.acme.test/v1/orders"
        assert transport.last_request.method is HttpMethod.GET

    def test_the_scope_decision_is_recorded_on_the_response(self) -> None:
        response = client().request("GET", "/orders")

        assert "target scope" in response.scope_reason
        assert "global" in response.scope_reason

    def test_query_parameters_are_merged(self) -> None:
        transport = FakeTransport()
        client(transport=transport).request("GET", "/orders", params={"limit": "2"})

        assert "limit=2" in transport.last_request.url

    def test_a_body_and_content_type_are_sent(self) -> None:
        transport = FakeTransport()
        response = client(transport=transport).request(
            "POST", "/orders", body='{"a":1}', content_type="application/json"
        )

        assert transport.last_request.body == b'{"a":1}'
        assert transport.header_of("content-type") == "application/json"
        assert response.request.body_bytes == 7

    def test_a_user_agent_is_always_sent(self) -> None:
        transport = FakeTransport()
        client(transport=transport).request("GET", "/orders")

        assert transport.header_of("user-agent") == "AegisAPI"

    def test_error_statuses_are_returned_not_raised(self) -> None:
        for status in (400, 401, 403, 404, 500, 503):
            transport = FakeTransport([StubResponse(status_code=status)])
            response = client(transport=transport).request("GET", "/orders")

            assert response.status_code == status
            assert response.is_success is False

    def test_limits_are_passed_to_the_transport(self) -> None:
        transport = FakeTransport()
        limits = HttpLimits(max_response_bytes=4096, requests_per_second=100.0)
        client(transport=transport, limits=limits).request("GET", "/orders")

        assert transport.limits_seen[0].max_response_bytes == 4096


class TestScopeDenials:
    """Each of these must produce zero transmissions."""

    @pytest.mark.parametrize(
        "reference",
        [
            "https://attacker.test/v1/orders",
            "https://api.acme.test.attacker.test/v1/orders",
            "https://notapi.acme.test/v1/orders",
            "http://api.acme.test/v1/orders",
            "https://api.acme.test:8443/v1/orders",
        ],
    )
    def test_out_of_scope_destinations_never_reach_the_network(self, reference: str) -> None:
        with pytest.raises(ScopeViolationError) as excinfo:
            client(transport=RefusingTransport()).request("GET", reference)

        assert "out of scope" in excinfo.value.message
        assert excinfo.value.exit_code == 5
        assert "No request was sent" in str(excinfo.value.hint)

    def test_an_excluded_path_is_refused(self) -> None:
        target = make_target(scope=ScopeRules(include_paths=["/v1"], exclude_paths=["/v1/admin"]))

        with pytest.raises(ScopeViolationError, match="excluded"):
            client(target=target, transport=RefusingTransport()).request("GET", "/admin")

    def test_traversal_cannot_reach_an_excluded_path(self) -> None:
        target = make_target(scope=ScopeRules(include_paths=["/v1"], exclude_paths=["/v1/admin"]))

        with pytest.raises(ScopeViolationError):
            client(target=target, transport=RefusingTransport()).request("GET", "/orders/../admin")

    def test_case_variation_cannot_reach_an_excluded_path(self) -> None:
        target = make_target(scope=ScopeRules(include_paths=["/v1"], exclude_paths=["/v1/admin"]))

        with pytest.raises(ScopeViolationError):
            client(target=target, transport=RefusingTransport()).request("GET", "/Admin")

    def test_a_path_outside_the_include_list_is_refused(self) -> None:
        target = make_target(base_url="https://api.acme.test/v1")

        with pytest.raises(ScopeViolationError):
            client(target=target, transport=RefusingTransport()).request(
                "GET", "https://api.acme.test/v2/orders"
            )

    def test_an_empty_global_allow_list_denies_everything(self) -> None:
        with pytest.raises(ScopeViolationError) as excinfo:
            client(settings=ScopeSettings(), transport=RefusingTransport()).request(
                "GET", "/orders"
            )

        assert "not globally authorised" in excinfo.value.message
        assert "allowed_hosts" in excinfo.value.message

    def test_a_host_missing_from_the_global_list_is_denied(self) -> None:
        target = make_target(scope=ScopeRules(include_paths=["/"], extra_hosts=["cdn.acme.test"]))

        with pytest.raises(ScopeViolationError, match="not globally authorised"):
            client(
                target=target,
                settings=ScopeSettings(allowed_hosts=["api.acme.test"]),
                transport=RefusingTransport(),
            ).request("GET", "https://cdn.acme.test/assets")

    def test_a_disabled_target_sends_nothing(self) -> None:
        target = make_target(enabled=False)

        with pytest.raises(ScopeViolationError, match="disabled"):
            client(target=target, transport=RefusingTransport()).request("GET", "/orders")

    def test_a_target_with_no_include_paths_sends_nothing(self) -> None:
        target = Target(name="acme", base_url="https://api.acme.test/v1")

        with pytest.raises(ScopeViolationError, match="no include patterns"):
            client(target=target, transport=RefusingTransport()).request("GET", "/orders")

    @pytest.mark.parametrize(
        "reference", ["//attacker.test/x", "", "/orders%2f..%2fadmin", "ftp://api.acme.test/"]
    )
    def test_malformed_references_send_nothing(self, reference: str) -> None:
        with pytest.raises(InvalidUrlError):
            client(transport=RefusingTransport()).request("GET", reference)

    def test_a_denial_is_logged_without_leaking_the_query(self) -> None:
        target = make_target(scope=ScopeRules(include_paths=["/v1"], exclude_paths=["/v1/admin"]))

        with pytest.raises(ScopeViolationError) as excinfo:
            client(target=target, transport=RefusingTransport()).request(
                "GET", "/admin?api_key=" + TOKEN
            )

        assert TOKEN not in excinfo.value.message


class TestForbiddenHeaders:
    @pytest.mark.parametrize("name", sorted(FORBIDDEN_REQUEST_HEADERS))
    def test_headers_that_could_redirect_the_request_are_refused(self, name: str) -> None:
        # Overriding Host would send the request to one address while claiming
        # another name, making the scope decision describe a different place.
        with pytest.raises(InvalidUrlError, match="cannot be set"):
            client(transport=RefusingTransport()).request(
                "GET", "/orders", headers={name: "evil.test"}
            )

    @pytest.mark.parametrize(
        "headers",
        [
            {"X-Test": "a\r\nInjected: b"},
            {"X-Test": "a\nInjected: b"},
            {"Bad: Name": "x"},
        ],
    )
    def test_header_injection_attempts_are_refused(self, headers: dict[str, str]) -> None:
        with pytest.raises(InvalidUrlError):
            client(transport=RefusingTransport()).request("GET", "/orders", headers=headers)

    def test_ordinary_headers_pass_through(self) -> None:
        transport = FakeTransport()
        client(transport=transport).request(
            "GET", "/orders", headers={"Accept": "application/json"}
        )

        assert transport.header_of("accept") == "application/json"


class TestRedirects:
    def test_redirects_are_not_followed_by_default(self) -> None:
        transport = FakeTransport(
            [StubResponse(status_code=302, headers=[("location", "/v1/elsewhere")])]
        )

        response = client(transport=transport).request("GET", "/orders")

        assert response.status_code == 302
        assert transport.call_count == 1
        assert response.redirect_chain == []

    def test_an_in_scope_redirect_is_followed_when_enabled(self) -> None:
        transport = FakeTransport(
            [
                StubResponse(status_code=302, headers=[("location", "/v1/elsewhere")]),
                StubResponse(status_code=200),
            ]
        )
        limits = HttpLimits(follow_redirects=True, requests_per_second=100.0)

        response = client(transport=transport, limits=limits).request("GET", "/orders")

        assert response.status_code == 200
        assert transport.call_count == 2
        assert transport.requests[1].url == "https://api.acme.test/v1/elsewhere"
        assert len(response.redirect_chain) == 1

    @pytest.mark.parametrize(
        "location",
        [
            "https://attacker.test/steal",
            "http://api.acme.test/v1/downgrade",
            "https://api.acme.test.attacker.test/v1/x",
            "https://api.acme.test:8443/v1/x",
            "/v2/outside-include",
        ],
    )
    def test_an_unauthorised_redirect_is_never_followed(self, location: str) -> None:
        transport = FakeTransport([StubResponse(status_code=302, headers=[("location", location)])])
        limits = HttpLimits(follow_redirects=True, requests_per_second=100.0)

        with pytest.raises(ScopeViolationError):
            client(transport=transport, limits=limits).request("GET", "/orders")

        # The redirect was answered but never acted on.
        assert transport.call_count == 1

    def test_a_malformed_redirect_target_is_refused(self) -> None:
        transport = FakeTransport(
            [StubResponse(status_code=302, headers=[("location", "ftp://api.acme.test/x")])]
        )
        limits = HttpLimits(follow_redirects=True, requests_per_second=100.0)

        with pytest.raises(ScopeViolationError, match="will not follow"):
            client(transport=transport, limits=limits).request("GET", "/orders")

        assert transport.call_count == 1

    def test_a_redirect_loop_is_detected(self) -> None:
        transport = FakeTransport(
            [
                StubResponse(status_code=302, headers=[("location", "/v1/b")]),
                StubResponse(status_code=302, headers=[("location", "/v1/orders")]),
                StubResponse(status_code=302, headers=[("location", "/v1/b")]),
            ]
        )
        limits = HttpLimits(follow_redirects=True, requests_per_second=100.0)

        with pytest.raises(TransportError, match="loop"):
            client(transport=transport, limits=limits).request("GET", "/orders")

    def test_the_redirect_limit_stops_the_chain(self) -> None:
        transport = FakeTransport(
            [
                StubResponse(status_code=302, headers=[("location", f"/v1/hop{index}")])
                for index in range(10)
            ]
        )
        limits = HttpLimits(follow_redirects=True, max_redirects=2, requests_per_second=100.0)

        response = client(transport=transport, limits=limits).request("GET", "/orders")

        assert transport.call_count == 3
        assert response.status_code == 302
        assert "redirect limit" in response.scope_reason

    def test_a_redirect_without_a_location_ends_the_chain(self) -> None:
        transport = FakeTransport([StubResponse(status_code=302, headers=[])])
        limits = HttpLimits(follow_redirects=True, requests_per_second=100.0)

        response = client(transport=transport, limits=limits).request("GET", "/orders")

        assert response.status_code == 302
        assert transport.call_count == 1

    @pytest.mark.parametrize("status", [301, 302, 303])
    def test_a_redirect_turns_a_post_into_a_get(self, status: int) -> None:
        transport = FakeTransport(
            [
                StubResponse(status_code=status, headers=[("location", "/v1/moved")]),
                StubResponse(status_code=200),
            ]
        )
        limits = HttpLimits(follow_redirects=True, requests_per_second=100.0)

        client(transport=transport, limits=limits).request("POST", "/orders", body="payload")

        assert transport.requests[1].method is HttpMethod.GET
        assert transport.requests[1].body is None


class TestCredentialHandling:
    def bearer_target(self, **overrides: object) -> Target:
        """A target authenticating with a bearer token."""
        return make_target(
            auth=AuthProfile(method=AuthMethod.BEARER, token=SecretRef(variable="ACME_TOKEN")),
            **overrides,  # type: ignore[arg-type]
        )

    def test_a_credential_is_attached_to_the_target_origin(self) -> None:
        transport = FakeTransport()
        response = client(
            target=self.bearer_target(), transport=transport, env={"ACME_TOKEN": TOKEN}
        ).request("GET", "/orders")

        assert transport.header_of("authorization") == f"Bearer {TOKEN}"
        assert response.request.authenticated is True
        assert response.request.auth_method == "bearer"

    def test_the_recorded_request_never_holds_the_credential(self) -> None:
        transport = FakeTransport()
        response = client(
            target=self.bearer_target(), transport=transport, env={"ACME_TOKEN": TOKEN}
        ).request("GET", "/orders")

        serialised = response.model_dump_json()
        assert TOKEN not in serialised
        assert response.request.headers["Authorization"] == "[REDACTED]"

    def test_no_auth_sends_the_request_without_credentials(self) -> None:
        transport = FakeTransport()
        response = client(
            target=self.bearer_target(), transport=transport, env={"ACME_TOKEN": TOKEN}
        ).request("GET", "/orders", authenticate=False)

        assert transport.header_of("authorization") is None
        assert response.request.authenticated is False

    def test_a_missing_credential_raises_and_sends_nothing(self) -> None:
        with pytest.raises(MissingCredentialError, match="is not set"):
            client(target=self.bearer_target(), transport=RefusingTransport(), env={}).request(
                "GET", "/orders"
            )

    def test_an_empty_credential_raises_and_sends_nothing(self) -> None:
        with pytest.raises(MissingCredentialError, match="set but empty"):
            client(
                target=self.bearer_target(),
                transport=RefusingTransport(),
                env={"ACME_TOKEN": "   "},
            ).request("GET", "/orders")

    def test_credentials_are_not_carried_across_a_redirect(self) -> None:
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
        limits = HttpLimits(follow_redirects=True, requests_per_second=100.0)

        client(
            target=target,
            settings=ScopeSettings(allowed_hosts=["api.acme.test", "cdn.acme.test"]),
            transport=transport,
            limits=limits,
            env={"ACME_TOKEN": TOKEN},
        ).request("GET", "/orders")

        assert transport.call_count == 2
        assert transport.header_of("authorization", index=0) == f"Bearer {TOKEN}"
        # The second hop is a different origin: no credential.
        assert transport.header_of("authorization", index=1) is None

    def test_a_caller_supplied_credential_header_is_stripped_across_origins(self) -> None:
        target = make_target(scope=ScopeRules(include_paths=["/"], extra_hosts=["cdn.acme.test"]))
        transport = FakeTransport(
            [
                StubResponse(
                    status_code=302, headers=[("location", "https://cdn.acme.test/assets")]
                ),
                StubResponse(status_code=200),
            ]
        )
        limits = HttpLimits(follow_redirects=True, requests_per_second=100.0)

        client(
            target=target,
            settings=ScopeSettings(allowed_hosts=["api.acme.test", "cdn.acme.test"]),
            transport=transport,
            limits=limits,
        ).request("GET", "/orders", headers={"Authorization": f"Bearer {TOKEN}"})

        assert transport.header_of("authorization", index=1) is None

    def test_an_api_key_in_the_query_is_redacted_in_the_record(self) -> None:
        target = make_target(
            auth=AuthProfile(
                method=AuthMethod.API_KEY,
                api_key=SecretRef(variable="ACME_KEY"),
                api_key_name="api_key",
                api_key_location="query",
            )
        )
        transport = FakeTransport()

        response = client(target=target, transport=transport, env={"ACME_KEY": TOKEN}).request(
            "GET", "/orders"
        )

        # The real request carries it; the record does not.
        assert TOKEN in transport.last_request.url
        assert TOKEN not in response.model_dump_json()
        assert "api_key=[REDACTED]" in response.final_url


class TestResponseNormalisation:
    def test_sensitive_response_headers_are_redacted(self) -> None:
        transport = FakeTransport(
            [
                StubResponse(
                    headers=[
                        ("content-type", "application/json"),
                        ("set-cookie", f"session={TOKEN}"),
                        ("authorization", TOKEN),
                    ]
                )
            ]
        )

        response = client(transport=transport).request("GET", "/orders")

        assert TOKEN not in response.model_dump_json()
        assert response.headers["set-cookie"] == "[REDACTED]"
        assert response.headers["content-type"] == "application/json"

    def test_a_body_preview_is_bounded_and_inert(self) -> None:
        body = b'{"markup": "[bold red]x[/] <script>alert(1)</script>"}'
        transport = FakeTransport([StubResponse(body=body)])

        response = client(transport=transport).request("GET", "/orders")

        assert response.body_preview is not None
        # Kept verbatim as text; rendering is the CLI's job and uses Text().
        assert "<script>" in response.body_preview
        assert response.body_bytes == len(body)

    def test_control_characters_are_stripped_from_a_preview(self) -> None:
        transport = FakeTransport([StubResponse(body=b"ok\x1b[31mred\x00")])

        response = client(transport=transport).request("GET", "/orders")

        assert response.body_preview is not None
        assert "\x1b" not in response.body_preview
        assert "\x00" not in response.body_preview

    def test_binary_content_is_not_previewed(self) -> None:
        transport = FakeTransport(
            [
                StubResponse(
                    headers=[("content-type", "application/octet-stream")],
                    body=b"\x00\x01\x02",
                )
            ]
        )

        response = client(transport=transport).request("GET", "/orders")

        assert response.body_preview is None
        assert response.body_bytes == 3

    def test_truncation_is_reported(self) -> None:
        transport = FakeTransport([StubResponse(body=b"x" * 100, truncated=True)])

        response = client(transport=transport).request("GET", "/orders")

        assert response.truncated is True

    def test_elapsed_time_is_recorded(self) -> None:
        response = client().request("GET", "/orders")

        assert response.elapsed_seconds >= 0.0


class TestDestinationVerification:
    def test_a_transport_that_changes_the_host_is_refused(self) -> None:
        transport = FakeTransport([StubResponse(final_url="https://attacker.test/v1/orders")])

        with pytest.raises(DestinationMismatchError, match="origin"):
            client(transport=transport).request("GET", "/orders")

    def test_a_transport_that_changes_the_path_is_refused(self) -> None:
        transport = FakeTransport(
            [StubResponse(final_url="https://api.acme.test/v1/somewhere-else")]
        )

        with pytest.raises(DestinationMismatchError, match="path"):
            client(transport=transport).request("GET", "/orders")

    def test_a_matching_destination_passes(self) -> None:
        transport = FakeTransport([StubResponse(final_url="https://api.acme.test/v1/orders")])

        assert client(transport=transport).request("GET", "/orders").status_code == 200


class TestTransportFailures:
    @pytest.mark.parametrize(
        "error",
        [
            ConnectionFailedError("refused"),
            RequestTimeoutError("timed out"),
            TlsError("bad certificate"),
        ],
    )
    def test_failures_propagate_as_transport_errors(self, error: TransportError) -> None:
        transport = FakeTransport([error])

        with pytest.raises(TransportError) as excinfo:
            client(transport=transport).request("GET", "/orders")

        assert excinfo.value.exit_code == 10

    def test_a_transport_failure_is_not_an_http_status(self) -> None:
        transport = FakeTransport([ConnectionFailedError("refused")])

        with pytest.raises(ConnectionFailedError):
            client(transport=transport).request("GET", "/orders")


class TestRetries:
    def test_nothing_is_retried_by_default(self) -> None:
        transport = FakeTransport([StubResponse(status_code=503), StubResponse()])

        response = client(transport=transport).request("GET", "/orders")

        assert response.status_code == 503
        assert transport.call_count == 1
        assert response.retries == 0

    def test_a_transient_status_is_retried_when_enabled(self) -> None:
        transport = FakeTransport([StubResponse(status_code=503), StubResponse()])
        limits = HttpLimits(max_retries=2, requests_per_second=100.0)

        response = client(transport=transport, limits=limits).request("GET", "/orders")

        assert response.status_code == 200
        assert transport.call_count == 2
        assert response.retries == 1

    def test_a_transient_failure_is_retried_when_enabled(self) -> None:
        transport = FakeTransport([ConnectionFailedError("reset"), StubResponse()])
        limits = HttpLimits(max_retries=1, requests_per_second=100.0)

        response = client(transport=transport, limits=limits).request("GET", "/orders")

        assert response.status_code == 200
        assert transport.call_count == 2

    def test_a_post_is_never_retried(self) -> None:
        transport = FakeTransport([StubResponse(status_code=503), StubResponse()])
        limits = HttpLimits(max_retries=3, requests_per_second=100.0)

        response = client(transport=transport, limits=limits).request("POST", "/orders")

        assert response.status_code == 503
        assert transport.call_count == 1

    @pytest.mark.parametrize("status", [401, 403, 404, 500])
    def test_permanent_statuses_are_not_retried(self, status: int) -> None:
        transport = FakeTransport([StubResponse(status_code=status), StubResponse()])
        limits = HttpLimits(max_retries=3, requests_per_second=100.0)

        client(transport=transport, limits=limits).request("GET", "/orders")

        assert transport.call_count == 1

    def test_a_tls_failure_is_not_retried(self) -> None:
        transport = FakeTransport([TlsError("bad certificate"), StubResponse()])
        limits = HttpLimits(max_retries=3, requests_per_second=100.0)

        with pytest.raises(TlsError):
            client(transport=transport, limits=limits).request("GET", "/orders")

        assert transport.call_count == 1

    def test_the_retry_limit_is_respected(self) -> None:
        transport = FakeTransport(
            [StubResponse(status_code=503) for _ in range(10)],
            default=StubResponse(status_code=503),
        )
        limits = HttpLimits(max_retries=2, requests_per_second=100.0)

        response = client(transport=transport, limits=limits).request("GET", "/orders")

        assert transport.call_count == 3
        assert response.retries == 2

    def test_retries_still_pass_through_the_throttle(self) -> None:
        transport = FakeTransport([StubResponse(status_code=503), StubResponse()])
        limits = HttpLimits(max_retries=1, requests_per_second=100.0)
        instance = client(transport=transport, limits=limits)

        instance.request("GET", "/orders")

        # Two sends means two reservations; the throttle saw both.
        assert transport.call_count == 2
        assert instance.throttle.concurrency.peak_in_flight >= 1


class TestConcurrency:
    def test_concurrent_requests_stay_within_the_concurrency_limit(self) -> None:
        transport = FakeTransport(default=StubResponse())
        instance = ScopedHttpClient(
            target=make_target(),
            settings=ALLOWED,
            limits=HttpLimits(requests_per_second=100.0, max_concurrency=2),
            transport=transport,  # type: ignore[arg-type]
            throttle=RequestThrottle(requests_per_second=1000.0, max_concurrency=2),
        )
        lock = threading.Lock()
        statuses: list[int] = []

        def send(_: int) -> None:
            response = instance.request("GET", "/orders")
            with lock:
                statuses.append(response.status_code)

        with ThreadPoolExecutor(max_workers=8) as pool:
            list(pool.map(send, range(16)))

        assert len(statuses) == 16
        assert instance.throttle.concurrency.peak_in_flight <= 2

    def test_concurrent_out_of_scope_requests_all_fail_closed(self) -> None:
        instance = ScopedHttpClient(
            target=make_target(),
            settings=ALLOWED,
            limits=HttpLimits(requests_per_second=100.0),
            transport=RefusingTransport(),  # type: ignore[arg-type]
            throttle=RequestThrottle(requests_per_second=1000.0, max_concurrency=4),
        )

        def send(_: int) -> bool:
            try:
                instance.request("GET", "https://attacker.test/x")
            except ScopeViolationError:
                return True
            return False

        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(send, range(16)))

        assert all(results)


class TestLifecycle:
    def test_the_client_closes_an_injected_transport_only_when_it_owns_it(self) -> None:
        transport = FakeTransport()
        with client(transport=transport) as instance:
            instance.request("GET", "/orders")

        # The caller supplied it, so the caller still owns it.
        assert transport.closed is False

    def test_the_target_and_limits_are_exposed(self) -> None:
        instance = client()

        assert instance.target.name == "acme"
        assert instance.limits.verify_tls is True
