"""Turning responses into bounded, referenceable evidence.

Evidence has one job: let a reviewer confirm a conclusion without re-running
the assessment. It is not an archive of the API's responses, so excerpts are
bounded and only headers worth keeping are kept.

Everything here starts from an :class:`~aegisapi.models.http.HttpResponse`,
which the HTTP layer already redacted. That is the reason this module cannot
leak a credential: it never sees one.
"""

from __future__ import annotations

from aegisapi.models.assessment import MAX_EVIDENCE_EXCERPT, Evidence
from aegisapi.models.http import HttpResponse

INTERESTING_RESPONSE_HEADERS: frozenset[str] = frozenset(
    {
        "access-control-allow-credentials",
        "access-control-allow-headers",
        "access-control-allow-methods",
        "access-control-allow-origin",
        "allow",
        "cache-control",
        "content-security-policy",
        "content-type",
        "location",
        "ratelimit-limit",
        "ratelimit-remaining",
        "ratelimit-reset",
        "referrer-policy",
        "retry-after",
        "server",
        "strict-transport-security",
        "www-authenticate",
        "x-content-type-options",
        "x-frame-options",
        "x-powered-by",
        "x-ratelimit-limit",
        "x-ratelimit-remaining",
    }
)
"""Response headers worth recording.

A deliberate allow-list rather than "everything except secrets". Keeping only
headers a check reasons about keeps evidence small and makes it obvious that a
new header must be considered before it is stored.
"""


def _excerpt(response: HttpResponse, limit: int = MAX_EVIDENCE_EXCERPT) -> tuple[str | None, bool]:
    """Bound a response's body preview.

    The preview arriving here is already sanitised of control characters by the
    HTTP layer, so this only shortens it.
    """
    if response.body_preview is None:
        return None, response.truncated
    text = response.body_preview
    if len(text) <= limit:
        return text, response.truncated
    return text[:limit], True


def _selected_headers(headers: dict[str, str]) -> dict[str, str]:
    """Keep the response headers checks reason about."""
    return {
        name: value
        for name, value in sorted(headers.items())
        if name.lower() in INTERESTING_RESPONSE_HEADERS
    }


def from_response(
    response: HttpResponse,
    *,
    check_id: str,
    label: str,
    note: str | None = None,
    identity: str | None = None,
) -> Evidence:
    """Record one response as evidence.

    Args:
        response: An already-redacted response from the scoped client.
        check_id: The check recording it, used for a stable identifier.
        label: Short description of what this observation is.
        note: Why it matters.
        identity: Configured test identity used, by name only. Never a credential.
    """
    excerpt, truncated = _excerpt(response)
    return Evidence(
        evidence_id=Evidence.make_id(check_id, label, response.final_url, response.status_code),
        label=label,
        method=response.request.method.value,
        url=response.final_url,
        status_code=response.status_code,
        request_headers=dict(sorted(response.request.headers.items())),
        response_headers=_selected_headers(response.headers),
        content_type=response.content_type,
        body_excerpt=excerpt,
        body_bytes=response.body_bytes,
        truncated=truncated,
        elapsed_ms=round(response.elapsed_seconds * 1000, 2),
        authenticated=response.request.authenticated,
        identity=identity,
        note=note,
    )


def from_failure(
    *,
    check_id: str,
    label: str,
    method: str,
    url: str,
    note: str,
    identity: str | None = None,
) -> Evidence:
    """Record an attempt that produced no response.

    A transport failure is evidence of nothing about the API's security, but it
    is worth recording so a reviewer can see why a check reached no conclusion.
    """
    return Evidence(
        evidence_id=Evidence.make_id(check_id, label, url, None),
        label=label,
        method=method,
        url=url,
        status_code=None,
        note=note,
        identity=identity,
    )


def bodies_match(left: Evidence, right: Evidence) -> bool:
    """``True`` when two observations returned the same body excerpt.

    Used to tell "the endpoint answered both callers identically", which is
    direct evidence that a credential made no difference, apart from "both
    returned 2xx", which is not.
    """
    if left.body_excerpt is None or right.body_excerpt is None:
        return False
    return left.body_excerpt == right.body_excerpt


__all__ = [
    "INTERESTING_RESPONSE_HEADERS",
    "bodies_match",
    "from_failure",
    "from_response",
]
