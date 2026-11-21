"""The pluggable transport: the one place bytes actually move.

Why an abstraction rather than calling ``httpx`` from the client:

* **Testability.** Every behaviour that matters - size limits, retries,
  redirect handling, credential stripping - can be driven deterministically
  through a fake transport, with no network and no sleeping on real sockets.
* **Containment.** ``httpx`` types stay behind this module. The client, the
  CLI, and later phases work with AegisAPI's own request and response types, so
  swapping the HTTP library would not ripple outward.
* **No global state.** A transport owns its own connection pool and is closed
  explicitly. There is no module-level client that a stray import could
  reconfigure.

Two deliberate choices in the ``httpx`` implementation:

* **Redirects are off at the library level.** The client follows them itself,
  re-validating each hop, because ``httpx`` following a ``Location`` header
  would move the request to a destination nothing checked.
* **Bodies are streamed.** The size limit is applied while receiving, so an
  oversized or endless response is abandoned rather than downloaded in full and
  measured afterwards.
"""

from __future__ import annotations

import ssl
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Protocol

import httpx

from aegisapi.core.exceptions import (
    ConnectionFailedError,
    RequestTimeoutError,
    TlsError,
    TransportError,
)
from aegisapi.models.http import HttpLimits, HttpMethod


@dataclass(frozen=True)
class TransportRequest:
    """Everything the transport needs to send one request.

    ``headers`` may contain a resolved credential, which is why this object is
    never logged, stored, or serialised. The client builds it, hands it
    straight to the transport, and records a redacted copy separately.
    """

    method: HttpMethod
    url: str
    headers: Mapping[str, str] = field(default_factory=dict)
    body: bytes | None = None


@dataclass(frozen=True)
class TransportResponse:
    """A raw response, already bounded by the size limit."""

    status_code: int
    reason_phrase: str
    headers: tuple[tuple[str, str], ...]
    body: bytes
    truncated: bool
    final_url: str

    def header(self, name: str) -> str | None:
        """First value of a header, matched case-insensitively."""
        wanted = name.lower()
        for key, value in self.headers:
            if key.lower() == wanted:
                return value
        return None


class Transport(Protocol):
    """What the client needs from a transport."""

    def send(self, request: TransportRequest, *, limits: HttpLimits) -> TransportResponse:
        """Send one request and return the bounded response.

        Raises:
            TransportError: For any failure to obtain a complete response. An
                HTTP error status is *not* a failure and must be returned.
        """
        ...

    def close(self) -> None:
        """Release connections held by this transport."""
        ...


class HttpxTransport:
    """Transport backed by ``httpx``."""

    def __init__(
        self,
        *,
        limits: HttpLimits,
        client: httpx.Client | None = None,
    ) -> None:
        """Build a transport.

        Args:
            limits: Timeouts, size cap, concurrency, and TLS verification. The
                connection pool is sized from ``max_concurrency``.
            client: An existing client, for tests that want to supply
                ``httpx.MockTransport``. When given, AegisAPI does not own it
                and :meth:`close` leaves it open.
        """
        self._limits = limits
        self._owns_client = client is None
        self._client = client if client is not None else self._build_client(limits)

    @staticmethod
    def _build_client(limits: HttpLimits) -> httpx.Client:
        """Create an ``httpx`` client configured from the limits."""
        return httpx.Client(
            timeout=httpx.Timeout(
                connect=limits.connect_timeout_seconds,
                read=limits.read_timeout_seconds,
                write=limits.read_timeout_seconds,
                pool=limits.connect_timeout_seconds,
            ),
            # The client never follows redirects. ScopedHttpClient does, one
            # scope-checked hop at a time.
            follow_redirects=False,
            verify=limits.verify_tls,
            limits=httpx.Limits(
                max_connections=limits.max_concurrency,
                max_keepalive_connections=limits.max_concurrency,
            ),
            trust_env=False,
        )

    def send(self, request: TransportRequest, *, limits: HttpLimits) -> TransportResponse:
        """Send one request, bounding the response while it arrives."""
        try:
            built = self._client.build_request(
                request.method.value,
                request.url,
                headers=dict(request.headers),
                content=request.body,
            )
        except (httpx.InvalidURL, httpx.UnsupportedProtocol, ValueError) as exc:
            raise ConnectionFailedError(
                "The request could not be prepared for the given URL.",
                hint=str(exc),
            ) from exc

        with self._error_boundary():
            response = self._client.send(built, stream=True)
            try:
                body, truncated = _read_bounded(response, limits.max_response_bytes)
                return TransportResponse(
                    status_code=response.status_code,
                    reason_phrase=response.reason_phrase or "",
                    headers=tuple((name, value) for name, value in response.headers.multi_items()),
                    body=body,
                    truncated=truncated,
                    final_url=str(response.url),
                )
            finally:
                response.close()
                # No cookie jar: a credential or session must never be carried
                # implicitly from one request to the next.
                self._client.cookies.clear()

    @contextmanager
    def _error_boundary(self) -> Iterator[None]:
        """Translate ``httpx`` failures into AegisAPI transport errors.

        Ordering matters: ``httpx.ConnectError`` wraps TLS problems, so the
        certificate case is recognised before the generic connection case, and
        the operator is told which one happened.
        """
        try:
            yield
        except TransportError:
            raise
        except httpx.TimeoutException as exc:
            raise RequestTimeoutError(
                "The request timed out before a complete response arrived.",
                hint="Raise http.connect_timeout_seconds or http.read_timeout_seconds.",
            ) from exc
        except httpx.ConnectError as exc:
            if _is_tls_failure(exc):
                raise TlsError(
                    "The HTTPS certificate could not be verified.",
                    hint=(
                        "AegisAPI verifies certificates by default. Fix the trust chain, "
                        "or set http.verify_tls = false to accept the risk explicitly."
                    ),
                ) from exc
            raise ConnectionFailedError(
                "The host could not be reached.",
                hint=_safe_detail(exc),
            ) from exc
        except httpx.ProtocolError as exc:
            raise ConnectionFailedError(
                "The server sent a malformed HTTP response.",
                hint=_safe_detail(exc),
            ) from exc
        except httpx.HTTPError as exc:
            raise ConnectionFailedError(
                "The request failed before a complete response arrived.",
                hint=_safe_detail(exc),
            ) from exc
        except ssl.SSLError as exc:  # pragma: no cover - normally wrapped by httpx
            raise TlsError("TLS negotiation failed.", hint=_safe_detail(exc)) from exc

    def close(self) -> None:
        """Close the connection pool, if this transport owns it."""
        if self._owns_client:
            self._client.close()

    def __enter__(self) -> HttpxTransport:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()


def _read_bounded(response: httpx.Response, limit: int) -> tuple[bytes, bool]:
    """Read at most ``limit`` bytes from a streaming response.

    The cap is applied **as data arrives**. Reading the whole body and then
    checking its length would mean a hostile or misconfigured endpoint could
    exhaust memory before the check ran.

    Truncation is reported rather than raised: a truncated response is still
    evidence that the endpoint answered, and discarding it would lose that.
    ``ResponseTooLargeError`` exists for callers that need oversize to be fatal.

    Returns:
        The body and whether it was cut short.
    """
    chunks: list[bytes] = []
    total = 0
    truncated = False
    for chunk in response.iter_raw():
        remaining = limit - total
        if remaining <= 0:
            truncated = True
            break
        if len(chunk) > remaining:
            chunks.append(chunk[:remaining])
            total += remaining
            truncated = True
            break
        chunks.append(chunk)
        total += len(chunk)
    return b"".join(chunks), truncated


def _is_tls_failure(exc: Exception) -> bool:
    """``True`` when a connection error was really a certificate problem."""
    cause: BaseException | None = exc
    seen = 0
    while cause is not None and seen < 10:
        if isinstance(cause, ssl.SSLError):
            return True
        if "certificate" in str(cause).lower() or "ssl" in type(cause).__name__.lower():
            return True
        cause = cause.__cause__ or cause.__context__
        seen += 1
    return False


def _safe_detail(exc: Exception) -> str:
    """Summarise an exception for an operator without leaking request data.

    Only the exception type and its message are used. A credential cannot
    appear here: a resolved secret lives in a header value, which ``httpx``
    does not put into these messages, and AegisAPI never interpolates request
    headers into an error.
    """
    message = str(exc).strip()
    return f"{type(exc).__name__}: {message}" if message else type(exc).__name__


__all__ = [
    "HttpxTransport",
    "Transport",
    "TransportRequest",
    "TransportResponse",
]
