"""Test doubles and a local HTTP server for the transport tests.

Two kinds of double, for two kinds of question:

* :class:`FakeTransport` answers "what did the client decide to send, and did
  it send anything at all?". It records every request and never touches a
  socket, which is how the tests prove a denied request produces no traffic.
* :func:`local_server` answers "does the real transport work?". It runs a
  genuine HTTP server on the loopback interface, so streaming, size limits,
  timeouts, and connection failures are exercised against a real socket
  without any external dependency.

Nothing here reaches the internet, and every server shuts down with its
context manager.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from aegisapi.core.exceptions import TransportError
from aegisapi.http.transport import TransportRequest, TransportResponse
from aegisapi.models.http import HttpLimits


@dataclass
class StubResponse:
    """A scripted response for :class:`FakeTransport`."""

    status_code: int = 200
    headers: Sequence[tuple[str, str]] = field(
        default_factory=lambda: [("content-type", "application/json")]
    )
    body: bytes = b'{"ok": true}'
    reason_phrase: str = "OK"
    truncated: bool = False
    final_url: str | None = None


class FakeTransport:
    """Records requests and returns scripted responses.

    Scripted outcomes are consumed in order. Each may be a
    :class:`StubResponse` or an exception instance to raise, which is how retry
    and transport-error behaviour is driven deterministically.
    """

    def __init__(
        self,
        outcomes: Sequence[StubResponse | Exception] | None = None,
        *,
        default: StubResponse | None = None,
    ) -> None:
        self.outcomes: list[StubResponse | Exception] = list(outcomes or [])
        self.default = default if default is not None else StubResponse()
        self.requests: list[TransportRequest] = []
        self.limits_seen: list[HttpLimits] = []
        self.closed = False

    @property
    def call_count(self) -> int:
        """How many requests reached the transport."""
        return len(self.requests)

    @property
    def last_request(self) -> TransportRequest:
        """The most recent request, failing loudly if none was sent."""
        if not self.requests:
            raise AssertionError("no request reached the transport")
        return self.requests[-1]

    def header_of(self, name: str, index: int = -1) -> str | None:
        """A header from a recorded request, matched case-insensitively."""
        wanted = name.lower()
        for key, value in self.requests[index].headers.items():
            if key.lower() == wanted:
                return value
        return None

    def send(self, request: TransportRequest, *, limits: HttpLimits) -> TransportResponse:
        """Record the request and return or raise the next scripted outcome."""
        self.requests.append(request)
        self.limits_seen.append(limits)
        outcome = self.outcomes.pop(0) if self.outcomes else self.default
        if isinstance(outcome, Exception):
            raise outcome
        return TransportResponse(
            status_code=outcome.status_code,
            reason_phrase=outcome.reason_phrase,
            headers=tuple(outcome.headers),
            body=outcome.body,
            truncated=outcome.truncated,
            final_url=outcome.final_url or request.url,
        )

    def close(self) -> None:
        """Mark the transport closed."""
        self.closed = True


class RefusingTransport:
    """A transport that fails the test if it is ever asked to send.

    Used wherever the point is that *no* request happens: a scope denial, a
    disabled target, a malformed URL. A recorded call count of zero can be an
    accident; this cannot.
    """

    def __init__(self) -> None:
        self.closed = False

    def send(self, request: TransportRequest, *, limits: HttpLimits) -> TransportResponse:
        raise AssertionError(f"a request was transmitted when none should have been: {request.url}")

    def close(self) -> None:
        self.closed = True


def transport_error(message: str = "connection reset") -> TransportError:
    """A generic transport failure, for scripting."""
    return TransportError(message)


Route = Callable[["StubHandler"], None]


class StubHandler(BaseHTTPRequestHandler):
    """Request handler that dispatches to routes registered on the server."""

    protocol_version = "HTTP/1.1"

    def log_message(self, fmt: str, *args: object) -> None:
        """Silence the default stderr logging."""

    def _dispatch(self) -> None:
        routes: Mapping[str, Route] = self.server.routes  # type: ignore[attr-defined]
        path = self.path.split("?", 1)[0]
        handler = routes.get(path) or routes.get("*")
        self.server.received.append(  # type: ignore[attr-defined]
            (self.command, self.path, dict(self.headers))
        )
        if handler is None:
            self.send_response(404)
            self.send_header("content-length", "0")
            self.end_headers()
            return
        handler(self)

    do_GET = _dispatch
    do_HEAD = _dispatch
    do_POST = _dispatch
    do_PUT = _dispatch
    do_PATCH = _dispatch
    do_DELETE = _dispatch
    do_OPTIONS = _dispatch

    def reply(
        self,
        status: int = 200,
        body: bytes = b"",
        headers: Mapping[str, str] | None = None,
    ) -> None:
        """Send a complete response."""
        self.send_response(status)
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        if body and self.command != "HEAD":
            self.wfile.write(body)

    def reply_stream(self, chunk: bytes, repeat: int, *, delay: float = 0.0) -> None:
        """Send a body in chunks, so a size limit can bite mid-transfer."""
        self.send_response(200)
        self.send_header("content-type", "application/octet-stream")
        self.send_header("transfer-encoding", "chunked")
        self.end_headers()
        try:
            for _ in range(repeat):
                self.wfile.write(f"{len(chunk):x}\r\n".encode("ascii"))
                self.wfile.write(chunk + b"\r\n")
                self.wfile.flush()
                if delay:
                    time.sleep(delay)
            self.wfile.write(b"0\r\n\r\n")
        except (BrokenPipeError, ConnectionResetError, OSError):
            # The client hit its size limit and hung up. That is the behaviour
            # under test, not a failure.
            pass


class StubServer(ThreadingHTTPServer):
    """Threading HTTP server carrying its routes and a request log."""

    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, routes: Mapping[str, Route]) -> None:
        super().__init__(("127.0.0.1", 0), StubHandler)
        self.routes: Mapping[str, Route] = routes
        self.received: list[tuple[str, str, dict[str, str]]] = []

    @property
    def base_url(self) -> str:
        """Origin this server is listening on."""
        host, port = self.server_address[:2]
        return f"http://{host}:{port}"


@contextmanager
def local_server(routes: Mapping[str, Route]) -> Iterator[StubServer]:
    """Run a local HTTP server for the duration of the block.

    Binds to port 0 on the loopback interface, so tests never collide and
    nothing is reachable from outside the machine. The server is always shut
    down and its thread joined, so a failing test cannot leak one.
    """
    server = StubServer(routes)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def closed_port_url() -> str:
    """A loopback URL with nothing listening, for connection-failure tests."""
    import socket

    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    return f"http://127.0.0.1:{port}"


__all__ = [
    "FakeTransport",
    "RefusingTransport",
    "StubHandler",
    "StubResponse",
    "StubServer",
    "closed_port_url",
    "local_server",
    "transport_error",
]
