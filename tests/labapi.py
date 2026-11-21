"""A deliberately weak local API, for testing AegisAPI end to end.

The test suite needs a real HTTP server: a stubbed transport proves the request
path is wired up, but it cannot prove that a scan started from a URL finds a
specification, parses it, tests the operations in it, and produces a report
whose findings match what the service actually does. Only a socket proves that.

**Built on the standard library** - ``http.server`` - rather than on Flask or
FastAPI. The tool's own dependencies are four packages, and the test suite must
run on a clean checkout on Windows, Linux, and Kali without an extra install
step. Adding a web framework to make a 200-line fixture more idiomatic is not
worth either cost. Nothing here needs routing decorators or dependency
injection; it needs to return exact headers and exact bodies, which is easier
to do precisely at this level.

**Every weakness in here is intentional**, and each is marked ``WEAKNESS`` with
the check it is there to exercise. Two endpoints are deliberately *clean*, so
the suite can show that AegisAPI reports nothing on them - a scanner that finds
a finding everywhere is as useless as one that finds none.

This module is in ``tests/`` and is not part of the installed package. It binds
to 127.0.0.1 on an ephemeral port and serves only while a test is running.
"""

from __future__ import annotations

import json
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

API_TITLE = "Lab Orders API"
API_VERSION = "1.4.2"

# The weak server banner the InformationExposureCheck (CONF-004) looks for.
WEAK_SERVER_BANNER = "LabServer/2.4.1 (Ubuntu) OpenSSL/1.1.1f"
WEAK_POWERED_BY = "LabFramework/3.11.2"

SPEC: dict[str, Any] = {
    "openapi": "3.0.3",
    "info": {"title": API_TITLE, "version": API_VERSION},
    "servers": [{"url": "/"}],
    "components": {
        "securitySchemes": {
            "bearerAuth": {"type": "http", "scheme": "bearer"},
        }
    },
    "paths": {
        # Clean: requires auth, returns correct headers, validates input.
        "/api/health": {
            "get": {
                "operationId": "health",
                "summary": "Liveness probe.",
                "security": [],
                "responses": {"200": {"description": "Service is up."}},
            }
        },
        # WEAKNESS (CONF-002): reflects any Origin with credentials allowed.
        # WEAKNESS (CONF-001): no security headers.
        "/api/orders": {
            "get": {
                "operationId": "listOrders",
                "summary": "List orders for the caller.",
                "security": [{"bearerAuth": []}],
                "parameters": [
                    {
                        "name": "limit",
                        "in": "query",
                        "required": True,
                        "schema": {"type": "integer"},
                    },
                    {
                        "name": "status",
                        "in": "query",
                        "required": False,
                        "schema": {"type": "string", "enum": ["open", "closed"]},
                    },
                ],
                "responses": {"200": {"description": "Orders."}},
            }
        },
        # WEAKNESS (AUTH-001): declares bearerAuth, serves anonymously.
        "/api/admin/users": {
            "get": {
                "operationId": "listUsers",
                "summary": "Administrative user list.",
                "security": [{"bearerAuth": []}],
                "responses": {"200": {"description": "Users."}},
            }
        },
        # WEAKNESS (CONF-005): declares JSON, returns an HTML error page.
        "/api/reports/summary": {
            "get": {
                "operationId": "reportSummary",
                "summary": "Summary report.",
                "security": [{"bearerAuth": []}],
                "responses": {
                    "200": {
                        "description": "Summary.",
                        "content": {"application/json": {"schema": {"type": "object"}}},
                    }
                },
            }
        },
        # WEAKNESS (INPUT-001/002/003): declares a required parameter, an
        # integer, and an enumeration, and enforces none of them. Public by
        # design, so no 401 masks the validation behaviour the way it does on
        # /api/orders.
        "/api/search": {
            "get": {
                "operationId": "search",
                "summary": "Search the catalogue.",
                "security": [],
                "parameters": [
                    {
                        "name": "q",
                        "in": "query",
                        "required": True,
                        "schema": {"type": "string"},
                    },
                    {
                        "name": "page",
                        "in": "query",
                        "required": False,
                        "schema": {"type": "integer"},
                    },
                    {
                        "name": "sort",
                        "in": "query",
                        "required": False,
                        "schema": {"type": "string", "enum": ["relevance", "price"]},
                    },
                ],
                "responses": {
                    "200": {
                        "description": "Results.",
                        "content": {"application/json": {"schema": {"type": "object"}}},
                    }
                },
            }
        },
        # Clean: a correctly configured operation, for the negative case.
        "/api/catalogue": {
            "get": {
                "operationId": "catalogue",
                "summary": "Public product catalogue.",
                "security": [],
                "responses": {"200": {"description": "Catalogue."}},
            }
        },
    },
}

_SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
    "Cache-Control": "no-store",
}
"""The headers a correctly configured endpoint in this lab returns."""

_HTML_ERROR = (
    "<!doctype html><html><head><title>Internal Server Error</title></head>"
    "<body><h1>500 Internal Server Error</h1>"
    "<pre>Traceback (most recent call last):\n"
    '  File "/srv/labapi/reports.py", line 88, in summary\n'
    "    total = sum(row.amount for row in rows)\n"
    "TypeError: unsupported operand type(s) for +: 'int' and 'NoneType'\n"
    "SQL: SELECT amount FROM orders WHERE tenant_id = 42</pre>"
    "</body></html>"
)
"""An HTML error page with a stack trace, for CONF-005 and CONF-004.

Includes a traceback, an internal filesystem path, and SQL text, because those
are what the information-exposure check reads a body for.
"""


class _Handler(BaseHTTPRequestHandler):
    """Routes for the lab API. One method per behaviour, no framework."""

    protocol_version = "HTTP/1.1"
    server_version = "LabServer/2.4.1"
    sys_version = ""

    # -- plumbing ---------------------------------------------------------

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        """Silence the default stderr access log, which would spam pytest."""

    def _send(
        self,
        status: int,
        body: bytes,
        *,
        content_type: str = "application/json",
        headers: dict[str, str] | None = None,
        secure_headers: bool = False,
    ) -> None:
        """Send one response with exactly the headers asked for."""
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        # WEAKNESS (CONF-004): the stack advertises its own software and
        # version on every response.
        self.send_header("Server", WEAK_SERVER_BANNER)
        self.send_header("X-Powered-By", WEAK_POWERED_BY)
        if secure_headers:
            for name, value in _SECURITY_HEADERS.items():
                self.send_header(name, value)
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _json(
        self,
        status: int,
        payload: Any,
        *,
        headers: dict[str, str] | None = None,
        secure_headers: bool = False,
    ) -> None:
        """Send a JSON response."""
        self._send(
            status,
            json.dumps(payload).encode("utf-8"),
            headers=headers,
            secure_headers=secure_headers,
        )

    @property
    def _path(self) -> str:
        """The request path without its query string."""
        return self.path.split("?", 1)[0]

    @property
    def _query(self) -> dict[str, str]:
        """The query string as a flat mapping. Last value of a repeat wins."""
        _, _, raw = self.path.partition("?")
        pairs: dict[str, str] = {}
        for item in raw.split("&"):
            if not item:
                continue
            key, _, value = item.partition("=")
            pairs[key] = value
        return pairs

    def _is_authenticated(self) -> bool:
        """Whether the request carries any bearer token at all.

        Deliberately shallow - the token is not verified - because the lab needs
        to distinguish "sent a credential" from "sent none", not to be a real
        authentication system.
        """
        header = self.headers.get("Authorization", "")
        return header.lower().startswith("bearer ") and len(header) > len("bearer ")

    def _cors_headers(self) -> dict[str, str]:
        """WEAKNESS (CONF-002): reflect any Origin, and allow credentials.

        Reflecting the caller's origin while allowing credentials lets any site
        a victim visits read authenticated responses from this API. This is the
        misconfiguration the CORS check is looking for.
        """
        origin = self.headers.get("Origin")
        if not origin:
            return {}
        return {
            "Access-Control-Allow-Origin": origin,
            "Access-Control-Allow-Credentials": "true",
            "Vary": "Origin",
        }

    # -- routes -----------------------------------------------------------

    def do_GET(self) -> None:  # noqa: N802 - http.server's required name
        """Serve the lab's read endpoints."""
        path = self._path

        if path in {"/openapi.json", "/"}:
            # WEAKNESS (DISC-001): the full specification is served to anyone.
            if path == "/":
                self._json(200, {"service": API_TITLE, "spec": "/openapi.json"})
                return
            self._json(200, SPEC)
            return

        if path == "/docs":
            # WEAKNESS (DISC-001): a documentation UI is publicly exposed.
            self._send(
                200,
                b"<!doctype html><html><title>Lab API docs</title>"
                b"<body>Swagger UI</body></html>",
                content_type="text/html; charset=utf-8",
            )
            return

        if path == "/api/health":
            # Clean: correct headers, no CORS reflection, no auth needed.
            self._json(200, {"status": "ok"}, secure_headers=True)
            return

        if path == "/api/catalogue":
            # Clean: correct headers, public by design and declared as such.
            self._json(
                200,
                {"items": [{"sku": "A-1", "name": "Widget"}]},
                secure_headers=True,
            )
            return

        if path == "/api/search":
            # WEAKNESS (INPUT-001): the required 'q' is not enforced.
            # WEAKNESS (INPUT-002): 'page' is declared an integer and any
            # string is accepted.
            # WEAKNESS (INPUT-003): 'sort' is declared an enumeration and any
            # value is accepted.
            query = self._query
            self._json(
                200,
                {
                    "results": [],
                    "query": query.get("q", ""),
                    "page": query.get("page", "1"),
                    "sort": query.get("sort", "relevance"),
                },
                secure_headers=True,
            )
            return

        if path == "/api/orders":
            # WEAKNESS (CONF-001): no security headers on this route.
            # WEAKNESS (CONF-002): CORS reflects the request origin.
            # WEAKNESS (INPUT-001/002/003): declared validation is not enforced.
            if not self._is_authenticated():
                self._json(401, {"error": "unauthorized"}, headers=self._cors_headers())
                return
            query = self._query
            self._json(
                200,
                {
                    "orders": [{"id": 1, "total": 99}],
                    "echo": {"limit": query.get("limit"), "status": query.get("status")},
                },
                headers=self._cors_headers(),
            )
            return

        if path == "/api/admin/users":
            # WEAKNESS (AUTH-001): the specification declares bearerAuth for
            # this operation, and the service serves it to anyone who asks.
            self._json(
                200,
                {
                    "users": [
                        {"id": 1, "email": "root@lab.test", "role": "admin"},
                        {"id": 2, "email": "ops@lab.test", "role": "operator"},
                    ]
                },
            )
            return

        if path == "/api/reports/summary":
            # WEAKNESS (CONF-005): declared application/json, answers HTML.
            # WEAKNESS (CONF-004): the body carries a traceback, an internal
            # path, and SQL text.
            self._send(
                500,
                _HTML_ERROR.encode("utf-8"),
                content_type="text/html; charset=utf-8",
            )
            return

        self._json(404, {"error": "not found"})

    def do_OPTIONS(self) -> None:  # noqa: N802 - http.server's required name
        """Answer preflight, advertising more methods than exist.

        WEAKNESS (CONF-003): ``/api/orders`` is a read-only operation in the
        specification, and the Allow header advertises write methods and TRACE.
        """
        path = self._path
        if path == "/api/orders":
            self._send(
                204,
                b"",
                content_type="text/plain",
                headers={
                    "Allow": "GET, POST, PUT, DELETE, PATCH, OPTIONS, TRACE",
                    "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, PATCH",
                    **self._cors_headers(),
                },
            )
            return
        self._send(
            204,
            b"",
            content_type="text/plain",
            headers={"Allow": "GET, HEAD, OPTIONS"},
            secure_headers=True,
        )

    def do_HEAD(self) -> None:  # noqa: N802 - http.server's required name
        """Mirror GET without a body."""
        self.do_GET()


class LabServer:
    """A running lab API, bound to an ephemeral loopback port."""

    def __init__(self, host: str = "127.0.0.1") -> None:
        self._server = ThreadingHTTPServer((host, 0), _Handler)
        self._thread = threading.Thread(
            target=self._server.serve_forever,
            name="labapi",
            daemon=True,
        )

    @property
    def port(self) -> int:
        """The port the server actually bound to."""
        return int(self._server.server_address[1])

    @property
    def base_url(self) -> str:
        """The URL to point a scan at."""
        return f"http://127.0.0.1:{self.port}"

    def start(self) -> None:
        """Begin serving in a background thread."""
        self._thread.start()

    def stop(self) -> None:
        """Stop serving and release the port."""
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=5)


@contextmanager
def running_lab() -> Iterator[LabServer]:
    """Run the lab API for the duration of a test."""
    server = LabServer()
    server.start()
    try:
        yield server
    finally:
        server.stop()


def main() -> None:
    """Serve the lab API on a fixed port, for a manual demonstration.

    ``python tests/labapi.py`` serves on 127.0.0.1:5000 so the documented
    ``aegisapi scan --url http://127.0.0.1:5000 --local-lab`` can be run by
    hand. Tests use :func:`running_lab` and an ephemeral port instead, so a
    test run never collides with a port something else is using.
    """
    server = ThreadingHTTPServer(("127.0.0.1", 5000), _Handler)
    print("Lab API on http://127.0.0.1:5000 (deliberately weak). Ctrl-C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
