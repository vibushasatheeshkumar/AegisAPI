"""HTTP communication, gated by scope enforcement.

**This package is the only place in AegisAPI that opens a network connection.**
Everything above it - discovery, and the checks and analysis of later phases -
goes through :class:`~aegisapi.http.client.ScopedHttpClient`, which validates
the destination before any bytes leave the machine. A module that opened its
own socket would bypass the control the whole tool rests on.

Layout, one concern per module:

* :mod:`aegisapi.http.transport` - the pluggable transport. The real one wraps
  ``httpx``; tests inject a fake, so the request path is exercised without a
  network.
* :mod:`aegisapi.http.auth` - turns an authentication profile into request
  headers, resolving a credential at the moment of use and never storing it.
* :mod:`aegisapi.http.throttle` - rate and concurrency limits, shared across
  threads so concurrency cannot outrun the configured rate.
* :mod:`aegisapi.http.retry` - which failures may be retried, and how long to
  wait. Conservative: read-shaped methods only, and none by default.
* :mod:`aegisapi.http.client` - the request boundary: resolve, validate,
  authenticate, throttle, send, normalise.

**An HTTP response proves nothing about security.** A 200 does not mean an
endpoint is correctly authorised and a 401 does not mean it is. This phase
moves bytes and records what happened; interpreting it is a later phase's job.
"""

from aegisapi.http.client import FetchedDocument, ScopedHttpClient, resolve_request_url
from aegisapi.http.transport import HttpxTransport, Transport, TransportRequest

__all__ = [
    "FetchedDocument",
    "HttpxTransport",
    "ScopedHttpClient",
    "Transport",
    "TransportRequest",
    "resolve_request_url",
]
