"""Finding out what a live API exposes, without crawling it.

:mod:`aegisapi.discovery.service` parses a specification the operator already
has. This module covers the case where they have only a URL, and works by
asking a short, fixed list of questions:

1. Does the target serve a machine-readable specification at one of the
   locations frameworks conventionally use?
2. Does it serve a documentation UI at one of the locations that conventionally
   accompany them?
3. Do the paths the operator supplied, or a wordlist they supplied, respond?

What this module deliberately does **not** do:

* **It does not crawl.** No response body is scanned for links, and no
  discovered path leads to further requests. The set of requests a probe will
  send is a function of its configuration alone, which means an operator can
  know the upper bound before starting and a hostile response cannot enlarge
  it.
* **It does not brute-force.** Wordlist probing happens only when the operator
  passes a wordlist, and is capped by :data:`MAX_WORDLIST_PATHS` on top of
  whatever budget the caller sets.
* **It does not open its own connections.** Every request goes through the
  :class:`~aegisapi.http.ScopedHttpClient` it is handed, so the scope gates,
  the rate limit, the timeouts, and the size cap all apply, and a probe cannot
  reach a host the client would not.
* **It sends read-shaped requests only.** GET and OPTIONS. Nothing here can
  create, modify, or delete anything.

A path that responds is recorded as an observation, never as a finding. "This
URL returned 200" is a fact about routing; the checks decide whether any of it
matters.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field

from aegisapi.core.exceptions import (
    AegisAPIError,
    InvalidSpecificationError,
    ScopeViolationError,
    TransportError,
)
from aegisapi.core.logging import get_logger
from aegisapi.discovery.loader import LoadedSpecification, load_specification_bytes
from aegisapi.discovery.versions import looks_like_specification
from aegisapi.http import ScopedHttpClient
from aegisapi.models.assessment import Evidence
from aegisapi.models.http import HttpMethod, HttpResponse
from aegisapi.testing import evidence as ev

_logger = get_logger(__name__)

SPECIFICATION_LOCATIONS: tuple[str, ...] = (
    "/openapi.json",
    "/openapi.yaml",
    "/swagger.json",
    "/swagger.yaml",
    "/v3/api-docs",
    "/api-docs",
    "/api/openapi.json",
    "/api/swagger.json",
    "/api/v1/openapi.json",
    "/docs/openapi.json",
    "/swagger/v1/swagger.json",
    "/.well-known/openapi.json",
)
"""Paths at which a framework conventionally serves its own specification.

Fixed and short on purpose. FastAPI publishes ``/openapi.json``, springdoc
publishes ``/v3/api-docs``, ASP.NET publishes ``/swagger/v1/swagger.json``, and
the rest are the handful of variants that recur. This is a list of
*conventions*, not a dictionary to grind through: probing it costs a bounded
dozen requests and either finds the inventory or does not.
"""

DOCUMENTATION_LOCATIONS: tuple[str, ...] = (
    "/docs",
    "/redoc",
    "/swagger",
    "/swagger-ui.html",
    "/swagger-ui/index.html",
    "/api/docs",
    "/api-docs/index.html",
    "/graphiql",
)
"""Paths at which a human-facing API documentation UI conventionally lives.

Finding one is inventory information: it says the route list, parameter names,
and schema of the API are published to anyone who asks. Whether that is
intended is a question for the operator, which is why it is reported as an
observation and not as a vulnerability.
"""

MAX_WORDLIST_PATHS = 200
"""Most wordlist entries a single run will probe.

A second ceiling, independent of the request budget, so that passing a
500 000-line wordlist produces a refusal to try rather than hours of traffic
against someone's API.
"""

MAX_SUPPLIED_PATHS = 500
"""Most paths an operator may name explicitly in one run."""

_PROBE_METHOD = HttpMethod.GET
_NOT_ROUTED = frozenset({404, 410})
"""Statuses taken as "there is nothing here".

A 404 is the clearest signal a path is not routed. Everything else - including
401, 403, and 500 - means something is listening, which is the interesting
case: an endpoint that refuses you still exists.
"""


@dataclass(frozen=True)
class ProbeObservation:
    """One path that was probed, and what came back."""

    path: str
    """The path as probed, relative to the target's base URL."""

    url: str
    """The redacted absolute URL that was contacted."""

    status_code: int
    """The status the target returned."""

    content_type: str | None
    """The declared response content type, if any."""

    body_bytes: int
    """Size of the response body received."""

    evidence: Evidence
    """The recorded exchange, for attaching to a finding or a report."""

    @property
    def is_routed(self) -> bool:
        """``True`` when something is listening at this path."""
        return self.status_code not in _NOT_ROUTED


@dataclass(frozen=True)
class SpecificationCandidate:
    """A specification the target served, already parsed."""

    loaded: LoadedSpecification
    """The parsed document and its provenance."""

    observation: ProbeObservation
    """The exchange that retrieved it."""


@dataclass
class ProbeResult:
    """Everything a live discovery pass learned, and what it cost."""

    specification: SpecificationCandidate | None = None
    """The first parsable specification found, if any."""

    documentation: list[ProbeObservation] = field(default_factory=list)
    """Documentation UIs that responded."""

    responding_paths: list[ProbeObservation] = field(default_factory=list)
    """Supplied or wordlist paths that are routed."""

    attempts: int = 0
    """Requests this pass actually sent."""

    notes: list[str] = field(default_factory=list)
    """Why something was not attempted or did not work. Shown to the operator."""

    @property
    def found_specification(self) -> bool:
        """``True`` when an inventory was retrieved from the target."""
        return self.specification is not None


def _probe_once(
    client: ScopedHttpClient,
    path: str,
    *,
    label: str,
    notes: list[str],
) -> tuple[ProbeObservation | None, bytes, bool]:
    """Send one read-shaped request, returning what came back.

    The third element reports whether a request was actually transmitted, which
    is what the caller charges against its budget: a refusal by the scope gate
    costs nothing because nothing was sent.

    A scope refusal and a transport failure are both recorded as notes and
    neither aborts the pass. A probe list is a list of guesses, and one guess
    pointing somewhere out of scope - or at a path the server drops - is an
    ordinary outcome, not a reason to abandon discovery.
    """
    try:
        fetched = client.fetch_document(path, method=_PROBE_METHOD)
    except ScopeViolationError as exc:
        notes.append(f"{path}: out of scope, not probed ({exc.message})")
        return None, b"", False
    except TransportError as exc:
        notes.append(f"{path}: no response ({exc.message})")
        return None, b"", True
    except AegisAPIError as exc:
        notes.append(f"{path}: not probed ({exc.message})")
        return None, b"", False

    response: HttpResponse = fetched.response
    observation = ProbeObservation(
        path=path,
        url=response.final_url,
        status_code=response.status_code,
        content_type=response.content_type,
        body_bytes=response.body_bytes,
        evidence=ev.from_response(response, check_id="DISC-001", label=label),
    )
    return observation, fetched.body, True


def verify_connectivity(client: ScopedHttpClient) -> ProbeObservation:
    """Confirm the target answers before an assessment starts.

    Worth a dedicated step because the failure it catches is the one most
    likely to waste an operator's time: a wrong port, a service that is not
    running, or a host that does not resolve. Finding that out from one request
    gives a clear error, where discovering it across forty checks gives forty
    transport errors and an empty report.

    Any status counts as reachable. A 401 or a 404 at the base path is a
    perfectly normal way for an API to answer, and treating either as "down"
    would refuse to assess a correctly configured service.

    Raises:
        TransportError: If no response arrived at all.
        ScopeViolationError: If the base URL is not in scope - which would mean
            the scope was built wrongly, since it was derived from this URL.
    """
    # "/" rather than "": a reference is joined onto the base URL, so this
    # requests the base path itself, and an empty reference is refused as a
    # malformed path before it reaches the scope gate.
    fetched = client.fetch_document("/", method=_PROBE_METHOD)
    response = fetched.response
    return ProbeObservation(
        path=client.target.base_path,
        url=response.final_url,
        status_code=response.status_code,
        content_type=response.content_type,
        body_bytes=response.body_bytes,
        evidence=ev.from_response(
            response, check_id="DISC-001", label="connectivity verification"
        ),
    )


def probe_specification(
    client: ScopedHttpClient,
    *,
    locations: Sequence[str] = SPECIFICATION_LOCATIONS,
    budget: int | None = None,
) -> tuple[SpecificationCandidate | None, list[ProbeObservation], int, list[str]]:
    """Look for a specification the target serves, stopping at the first one.

    A response is only accepted as a specification when it parses *and*
    declares an OpenAPI or Swagger version. Both conditions matter: a
    single-page application returns 200 and valid JSON for almost any path, so
    "it parsed" alone would hand the inventory step a document with no
    operations in it and report success.

    Returns the candidate, every observation made along the way, the number of
    requests sent, and any notes.
    """
    observations: list[ProbeObservation] = []
    notes: list[str] = []
    attempts = 0

    for path in locations:
        if budget is not None and attempts >= budget:
            notes.append("specification probing stopped: request budget reached")
            break

        observation, body, sent = _probe_once(
            client, path, label="specification probe", notes=notes
        )
        if sent:
            attempts += 1
        if observation is None:
            continue
        observations.append(observation)

        if not observation.is_routed or not body:
            continue

        try:
            loaded = load_specification_bytes(
                body,
                source_url=observation.url,
                content_type=observation.content_type,
            )
        except InvalidSpecificationError:
            # Very common: the path exists but serves an HTML page or an error
            # document. Not worth a note on every miss.
            _logger.debug("%s did not parse as a specification", path)
            continue

        if not looks_like_specification(loaded.document):
            notes.append(f"{path}: parsed, but declares no OpenAPI or Swagger version")
            continue

        _logger.debug("Specification retrieved from %s", path)
        return (
            SpecificationCandidate(loaded=loaded, observation=observation),
            observations,
            attempts,
            notes,
        )

    return None, observations, attempts, notes


def probe_documentation(
    client: ScopedHttpClient,
    *,
    locations: Sequence[str] = DOCUMENTATION_LOCATIONS,
    budget: int | None = None,
) -> tuple[list[ProbeObservation], int, list[str]]:
    """Look for exposed API documentation UIs.

    Returns the ones that are routed, the number of requests sent, and notes.
    """
    found: list[ProbeObservation] = []
    notes: list[str] = []
    attempts = 0

    for path in locations:
        if budget is not None and attempts >= budget:
            notes.append("documentation probing stopped: request budget reached")
            break

        observation, _, sent = _probe_once(
            client, path, label="documentation probe", notes=notes
        )
        if sent:
            attempts += 1
        if observation is not None and observation.is_routed:
            found.append(observation)

    return found, attempts, notes


def normalise_probe_paths(paths: Iterable[str], *, limit: int) -> tuple[list[str], list[str]]:
    """Clean, de-duplicate, and cap a list of paths to probe.

    Returns the accepted paths and notes about what was dropped. Entries are
    accepted leniently - a wordlist usually has blank lines, comments, and
    entries with no leading slash - but the cap is applied strictly, because
    the whole point of a cap is that a longer input does not quietly produce
    more traffic.
    """
    accepted: list[str] = []
    notes: list[str] = []
    seen: set[str] = set()
    oversized = 0

    for raw in paths:
        candidate = raw.strip()
        if not candidate or candidate.startswith("#"):
            continue
        if "://" in candidate or candidate.startswith("//"):
            notes.append(f"{candidate!r} skipped: give a path, not a URL")
            continue
        if not candidate.startswith("/"):
            candidate = f"/{candidate}"
        if candidate in seen:
            continue
        if len(accepted) >= limit:
            oversized += 1
            continue
        seen.add(candidate)
        accepted.append(candidate)

    if oversized:
        notes.append(
            f"{oversized} further path(s) ignored: at most {limit} may be probed in one run"
        )
    return accepted, notes


def probe_paths(
    client: ScopedHttpClient,
    paths: Sequence[str],
    *,
    budget: int | None = None,
    label: str = "path probe",
) -> tuple[list[ProbeObservation], int, list[str]]:
    """Probe a list of paths and report which are routed.

    The paths come from the operator, either named individually or read from a
    wordlist they chose. Nothing here generates candidates, so the traffic this
    produces is bounded by an input the operator can read.
    """
    found: list[ProbeObservation] = []
    notes: list[str] = []
    attempts = 0

    for path in paths:
        if budget is not None and attempts >= budget:
            notes.append("path probing stopped: request budget reached")
            break

        observation, _, sent = _probe_once(client, path, label=label, notes=notes)
        if sent:
            attempts += 1
        if observation is not None and observation.is_routed:
            found.append(observation)

    return found, attempts, notes


__all__ = [
    "DOCUMENTATION_LOCATIONS",
    "MAX_SUPPLIED_PATHS",
    "MAX_WORDLIST_PATHS",
    "SPECIFICATION_LOCATIONS",
    "ProbeObservation",
    "ProbeResult",
    "SpecificationCandidate",
    "normalise_probe_paths",
    "probe_documentation",
    "probe_paths",
    "probe_specification",
    "verify_connectivity",
]
