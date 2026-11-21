"""Mapping discovered endpoints onto a target's configured scope.

Classification answers "does the engagement cover this?", and it answers it
with the **existing** scope validator from Phase 2 rather than a second
implementation. One gate, one set of rules, one place to audit.

What classification is not
--------------------------
A path appearing in a specification is not authorisation to request it, and a
classification of ``IN_SCOPE`` is not permission - it means the operator's own
configuration admits the URL. Nothing here widens a target's scope: the target
is read, never written.

Limits worth knowing
--------------------
* **A specification's server may not be the registered target.** A document
  shipped by a vendor often declares a production host while the engagement
  covers staging. Those endpoints classify as ``OUT_OF_SCOPE`` against the
  registered target, which is correct but can look surprising. They are kept,
  not dropped, so the mismatch is visible, and the reason names the server that
  was used.
* **Templated servers cannot be resolved.** ``https://{region}.example.com``
  has no concrete host, so those endpoints are ``UNRESOLVED`` rather than
  guessed at.
* **Paths are templates, not URLs.** ``/users/{userId}`` is classified as the
  literal template. A concrete request later may resolve a variable into a
  segment an exclusion would have caught, so classification is advisory: the
  authoritative check is
  :func:`aegisapi.core.scope.assert_in_scope` on the real URL at request time.
"""

from __future__ import annotations

import re

from aegisapi.core.exceptions import InvalidUrlError
from aegisapi.core.scope import ScopeValidator
from aegisapi.discovery.schemas import WarningCollector
from aegisapi.models.discovery import (
    ClassifiedEndpoint,
    ScopeClassification,
    WarningCode,
)
from aegisapi.models.endpoint import Endpoint
from aegisapi.models.target import Target
from aegisapi.utils.urls import normalize_url

_SERVER_TEMPLATE = re.compile(r"\{[^}]*\}")

TEMPLATED_PATH_NOTE = (
    "the path is a template, so concrete URLs are re-checked against scope at request time"
)


def _is_templated_server(url: str) -> bool:
    """``True`` when a server URL contains a variable placeholder."""
    return bool(_SERVER_TEMPLATE.search(url))


def _join(base: str, path: str) -> str:
    """Join a base URL or base path with a specification path."""
    if not path or path == "/":
        return base or "/"
    if not base or base == "/":
        return path
    return f"{base.rstrip('/')}/{path.lstrip('/')}"


def resolve_candidate_url(
    endpoint: Endpoint,
    *,
    target: Target,
    specification_servers: list[str],
) -> tuple[str | None, str | None, str | None]:
    """Work out which concrete URL an operation would be requested at.

    Precedence follows the specification: an operation or path-level server
    overrides the document's servers, which override nothing - when a document
    declares no server, the registered target's base URL is used, because that
    is the only host the operator told AegisAPI about.

    Returns:
        ``(url, server_url, unresolved_reason)``. Exactly one of ``url`` and
        ``unresolved_reason`` is set.
    """
    servers = endpoint.servers or specification_servers
    target_url = target.url

    if not servers:
        # No server declared anywhere. Treat the registered base URL as the
        # origin and keep its path prefix, which is what a client reading this
        # document against this target would do.
        return _join(target.base_url, endpoint.path), None, None

    server = servers[0]
    if _is_templated_server(server):
        return (
            None,
            server,
            f"server URL {server!r} contains a variable, so no concrete URL could be built",
        )

    if server.startswith("//"):
        # Swagger 2.0 with a host but no declared scheme. The document does not
        # say http or https, so the target's scheme is the only sane choice.
        return _join(f"{target_url.scheme}:{server}", endpoint.path), server, None

    if server.startswith("/"):
        # A relative server, meaning "this path prefix on whatever host serves
        # the document". Resolve it against the registered target.
        return _join(f"{target_url.origin}{server}", endpoint.path), server, None

    if "://" not in server:
        return (
            None,
            server,
            f"server URL {server!r} is not an absolute URL or an absolute path",
        )

    return _join(server, endpoint.path), server, None


def classify_endpoint(
    endpoint: Endpoint,
    *,
    target: Target,
    validator: ScopeValidator,
    specification_servers: list[str],
    warnings: WarningCollector | None = None,
) -> ClassifiedEndpoint:
    """Classify one endpoint against the target's configured scope."""
    url, server, unresolved = resolve_candidate_url(
        endpoint, target=target, specification_servers=specification_servers
    )

    if unresolved is not None:
        if warnings is not None and server is not None and _is_templated_server(server):
            warnings.add(
                WarningCode.TEMPLATED_SERVER,
                f"server URL {server!r} contains a variable and was not resolved",
                endpoint.source_pointer,
            )
        return ClassifiedEndpoint(
            endpoint=endpoint,
            classification=ScopeClassification.UNRESOLVED,
            reason=unresolved,
            server_url=server,
        )

    assert url is not None  # guaranteed by resolve_candidate_url's contract
    try:
        normalize_url(url)
    except InvalidUrlError as exc:
        # The specification produced something AegisAPI will not interpret. That
        # is not a scope decision, so it is recorded as unresolved rather than
        # silently denied or allowed.
        return ClassifiedEndpoint(
            endpoint=endpoint,
            classification=ScopeClassification.UNRESOLVED,
            reason=f"no usable URL could be built: {exc.message}",
            resolved_url=url,
            server_url=server,
        )

    decision = validator.check(url)
    reason = decision.reason
    if endpoint.is_templated:
        reason = f"{reason}; {TEMPLATED_PATH_NOTE}"

    return ClassifiedEndpoint(
        endpoint=endpoint,
        classification=(
            ScopeClassification.IN_SCOPE if decision.allowed else ScopeClassification.OUT_OF_SCOPE
        ),
        reason=reason,
        rule=decision.rule,
        resolved_url=url,
        server_url=server,
    )


def classify_endpoints(
    endpoints: list[Endpoint],
    *,
    target: Target,
    specification_servers: list[str],
    warnings: WarningCollector | None = None,
) -> list[ClassifiedEndpoint]:
    """Classify every endpoint, keeping out-of-scope ones for review.

    Out-of-scope endpoints are retained deliberately. What a specification
    declares beyond the engagement boundary is what a reviewer needs in order
    to judge whether the scope, or the authorisation behind it, is right.
    """
    validator = ScopeValidator(target)
    return [
        classify_endpoint(
            endpoint,
            target=target,
            validator=validator,
            specification_servers=specification_servers,
            warnings=warnings,
        )
        for endpoint in endpoints
    ]


def server_matches_target(server: str, target: Target) -> bool:
    """``True`` when a declared server points at the registered target's host.

    Used to tell the operator that a document describes a different deployment,
    which is the usual reason a whole inventory lands out of scope.
    """
    if _is_templated_server(server) or server.startswith("/"):
        return True
    candidate = f"{target.url.scheme}:{server}" if server.startswith("//") else server
    try:
        return normalize_url(candidate).host == target.host
    except InvalidUrlError:
        return False


__all__ = [
    "TEMPLATED_PATH_NOTE",
    "classify_endpoint",
    "classify_endpoints",
    "resolve_candidate_url",
    "server_matches_target",
]
