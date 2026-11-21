"""The httpx transport, against a real HTTP server on the loopback interface.

These tests use genuine sockets, because the behaviours they cover - streaming
size limits, timeouts, connection refusal - are properties of the transport and
a fake would only prove the fake works. Every server binds to 127.0.0.1 on an
ephemeral port and is shut down with its context manager; nothing external is
contacted.
"""

from __future__ import annotations

import httpx
import pytest

from aegisapi.core.config import ScopeSettings
from aegisapi.core.exceptions import (
    ConnectionFailedError,
    RequestTimeoutError,
    TlsError,
    TransportError,
)
from aegisapi.http import ScopedHttpClient
from aegisapi.http.throttle import RequestThrottle
from aegisapi.http.transport import HttpxTransport, TransportRequest
from aegisapi.models.http import HttpLimits, HttpMethod
from aegisapi.models.target import ScopeRules, Target
from httpstub import StubHandler, closed_port_url, local_server

FAST = HttpLimits(
    connect_timeout_seconds=2.0,
    read_timeout_seconds=2.0,
    requests_per_second=100.0,
)


def send(request: TransportRequest, limits: HttpLimits = FAST):
    """Send one request through a real transport, closing it afterwards."""
    with HttpxTransport(limits=limits) as transport:
        return transport.send(request, limits=limits)


def ok(handler: StubHandler) -> None:
    """A plain 200 with a JSON body."""
    handler.reply(200, b'{"ok": true}', {"content-type": "application/json"})


class TestRealRequests:
    def test_a_successful_get(self) -> None:
        with local_server({"/v1/orders": ok}) as server:
            response = send(
                TransportRequest(method=HttpMethod.GET, url=f"{server.base_url}/v1/orders")
            )

        assert response.status_code == 200
        assert response.body == b'{"ok": true}'
        assert response.header("content-type") == "application/json"
        assert response.truncated is False

    def test_headers_and_body_are_transmitted(self) -> None:
        with local_server({"/v1/orders": ok}) as server:
            send(
                TransportRequest(
                    method=HttpMethod.POST,
                    url=f"{server.base_url}/v1/orders",
                    headers={"X-Test": "value", "Content-Type": "application/json"},
                    body=b'{"a":1}',
                )
            )
            method, path, headers = server.received[-1]

        assert method == "POST"
        assert path == "/v1/orders"
        assert headers["X-Test"] == "value"

    def test_query_strings_are_transmitted(self) -> None:
        with local_server({"/v1/orders": ok}) as server:
            send(
                TransportRequest(method=HttpMethod.GET, url=f"{server.base_url}/v1/orders?limit=2")
            )

        assert server.received[-1][1] == "/v1/orders?limit=2"

    @pytest.mark.parametrize("status", [201, 204, 400, 401, 403, 404, 500, 503])
    def test_error_statuses_are_returned_not_raised(self, status: int) -> None:
        def handler(handler: StubHandler) -> None:
            handler.reply(status, b"")

        with local_server({"/v1/x": handler}) as server:
            response = send(TransportRequest(method=HttpMethod.GET, url=f"{server.base_url}/v1/x"))

        assert response.status_code == status

    @pytest.mark.parametrize(
        "method", [HttpMethod.GET, HttpMethod.HEAD, HttpMethod.PUT, HttpMethod.DELETE]
    )
    def test_common_methods_are_supported(self, method: HttpMethod) -> None:
        with local_server({"/v1/x": ok}) as server:
            response = send(TransportRequest(method=method, url=f"{server.base_url}/v1/x"))

        assert response.status_code == 200
        assert server.received[-1][0] == method.value

    def test_redirects_are_not_followed_by_the_library(self) -> None:
        def redirector(handler: StubHandler) -> None:
            handler.reply(302, b"", {"location": "/v1/elsewhere"})

        with local_server({"/v1/start": redirector, "/v1/elsewhere": ok}) as server:
            response = send(
                TransportRequest(method=HttpMethod.GET, url=f"{server.base_url}/v1/start")
            )
            paths = [entry[1] for entry in server.received]

        assert response.status_code == 302
        assert paths == ["/v1/start"]


class TestResponseSizeLimit:
    def test_the_limit_is_enforced_while_receiving(self) -> None:
        # 200 chunks of 1 KiB, capped at 4 KiB: the transfer is abandoned
        # mid-stream rather than downloaded in full and measured afterwards.
        def streamer(handler: StubHandler) -> None:
            handler.reply_stream(b"x" * 1024, 200)

        limits = HttpLimits(
            max_response_bytes=4096, read_timeout_seconds=5.0, requests_per_second=100.0
        )
        with local_server({"/v1/big": streamer}) as server:
            response = send(
                TransportRequest(method=HttpMethod.GET, url=f"{server.base_url}/v1/big"),
                limits,
            )

        assert response.truncated is True
        assert len(response.body) == 4096

    def test_a_body_within_the_limit_is_not_truncated(self) -> None:
        def small(handler: StubHandler) -> None:
            handler.reply(200, b"y" * 100, {"content-type": "text/plain"})

        limits = HttpLimits(max_response_bytes=4096, requests_per_second=100.0)
        with local_server({"/v1/small": small}) as server:
            response = send(
                TransportRequest(method=HttpMethod.GET, url=f"{server.base_url}/v1/small"),
                limits,
            )

        assert response.truncated is False
        assert len(response.body) == 100

    def test_a_one_byte_limit_still_returns_the_status(self) -> None:
        def small(handler: StubHandler) -> None:
            handler.reply(200, b"abcdef", {"content-type": "text/plain"})

        limits = HttpLimits(max_response_bytes=1, requests_per_second=100.0)
        with local_server({"/v1/small": small}) as server:
            response = send(
                TransportRequest(method=HttpMethod.GET, url=f"{server.base_url}/v1/small"),
                limits,
            )

        assert response.status_code == 200
        assert response.truncated is True
        assert len(response.body) == 1


class TestFailures:
    def test_a_refused_connection_is_reported(self) -> None:
        # Windows answers a closed port by retrying the SYN rather than
        # refusing, so this surfaces as a connect timeout there and a refusal
        # on POSIX. Either is correct; what matters is that it is a transport
        # failure with its own exit code, not an HTTP response.
        limits = HttpLimits(connect_timeout_seconds=0.5, requests_per_second=100.0)

        with pytest.raises((ConnectionFailedError, RequestTimeoutError)) as excinfo:
            send(
                TransportRequest(method=HttpMethod.GET, url=f"{closed_port_url()}/v1/x"),
                limits,
            )

        assert excinfo.value.exit_code == 10

    def test_a_read_timeout_is_reported(self) -> None:
        def slow(handler: StubHandler) -> None:
            handler.reply_stream(b"z" * 16, 50, delay=0.2)

        limits = HttpLimits(
            connect_timeout_seconds=2.0,
            read_timeout_seconds=0.15,
            max_response_bytes=1024 * 1024,
            requests_per_second=100.0,
        )
        with local_server({"/v1/slow": slow}) as server, pytest.raises(RequestTimeoutError):
            send(
                TransportRequest(method=HttpMethod.GET, url=f"{server.base_url}/v1/slow"),
                limits,
            )

    def test_an_unresolvable_host_is_reported(self) -> None:
        with pytest.raises(TransportError):
            send(
                TransportRequest(
                    method=HttpMethod.GET,
                    url="http://this-host-does-not-exist.invalid/v1/x",
                )
            )

    def test_a_failure_message_carries_no_request_headers(self) -> None:
        token = "eyJhbGciOiJIUzI1NiJ9.super-secret-token-value"
        limits = HttpLimits(connect_timeout_seconds=0.5, requests_per_second=100.0)

        with pytest.raises(TransportError) as excinfo:
            send(
                TransportRequest(
                    method=HttpMethod.GET,
                    url=f"{closed_port_url()}/v1/x",
                    headers={"Authorization": f"Bearer {token}"},
                ),
                limits,
            )

        assert token not in str(excinfo.value)
        assert token not in str(excinfo.value.hint)


class TestTlsConfiguration:
    def test_verification_is_on_by_default(self) -> None:
        assert HttpLimits().verify_tls is True

    def test_a_certificate_failure_is_reported_as_a_tls_error(self) -> None:
        # Driven through a mock transport: a real bad-certificate server would
        # need a throwaway CA, and the behaviour under test is the mapping from
        # an SSL-caused ConnectError to TlsError.
        import ssl

        def handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError(
                "certificate verify failed",
                request=request,
            ) from ssl.SSLCertVerificationError("certificate verify failed")

        client = httpx.Client(transport=httpx.MockTransport(handler))
        transport = HttpxTransport(limits=FAST, client=client)

        with pytest.raises(TlsError) as excinfo:
            transport.send(
                TransportRequest(method=HttpMethod.GET, url="https://api.acme.test/v1"),
                limits=FAST,
            )

        assert "certificate" in excinfo.value.message
        assert "verify_tls" in str(excinfo.value.hint)
        client.close()

    def test_disabling_verification_is_recorded_on_the_limits(self) -> None:
        limits = HttpLimits(verify_tls=False)

        # Nothing silently flips this; it can only come from configuration.
        assert limits.verify_tls is False

    def test_disabling_verification_warns_on_the_client(self, caplog) -> None:
        import logging

        from aegisapi.core.logging import LOGGER_NAME

        with caplog.at_level(logging.WARNING, logger=LOGGER_NAME):
            ScopedHttpClient(
                target=Target.create(name="acme", base_url="https://api.acme.test/v1"),
                settings=ScopeSettings(allowed_hosts=["api.acme.test"]),
                limits=HttpLimits(verify_tls=False),
                transport=_NullTransport(),  # type: ignore[arg-type]
            )

        assert any("DISABLED" in record.getMessage() for record in caplog.records)


class _NullTransport:
    """A transport that is never sent through, for construction-only tests."""

    def send(self, request: TransportRequest, *, limits: HttpLimits):
        raise AssertionError("not expected to send")

    def close(self) -> None:
        return None


class TestClientAgainstRealServer:
    def build(self, server, **kwargs):
        """A client bound to the loopback server, with scope allowing it."""
        host = server.server_address[0]
        port = server.server_address[1]
        target = Target.create(
            name="local",
            base_url=f"http://{host}:{port}/v1",
            scope=ScopeRules(include_paths=["/v1"]),
            **kwargs,
        )
        return ScopedHttpClient(
            target=target,
            settings=ScopeSettings(allowed_hosts=[host]),
            limits=HttpLimits(
                connect_timeout_seconds=2.0,
                read_timeout_seconds=2.0,
                requests_per_second=100.0,
            ),
            throttle=RequestThrottle(requests_per_second=1000.0, max_concurrency=2),
        )

    def test_a_real_round_trip(self) -> None:
        with local_server({"/v1/orders": ok}) as server, self.build(server) as client:
            response = client.request("GET", "/orders")

        assert response.status_code == 200
        assert response.body_preview is not None
        assert '"ok"' in response.body_preview
        assert response.elapsed_seconds > 0

    def test_an_out_of_scope_path_reaches_no_real_server(self) -> None:
        from aegisapi.core.exceptions import ScopeViolationError

        with local_server({"/v2/secret": ok}) as server:
            with self.build(server) as client, pytest.raises(ScopeViolationError):
                client.request("GET", f"{client.target.url.origin}/v2/secret")
            assert server.received == []

    def test_the_destination_check_passes_for_a_real_request(self) -> None:
        with local_server({"/v1/orders": ok}) as server, self.build(server) as client:
            response = client.request("GET", "/orders")

        assert response.final_url.endswith("/v1/orders")
