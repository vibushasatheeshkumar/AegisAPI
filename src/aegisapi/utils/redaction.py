"""Credential redaction helpers.

AegisAPI will eventually handle authorization headers, API keys, and session
cookies. Those values must never reach a log file, a console message, or a
stored assessment record. The helpers here are the single place where that
scrubbing is implemented so every subsystem behaves identically.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

REDACTED = "[REDACTED]"
"""Replacement token written in place of a sensitive value."""

SENSITIVE_KEY_HINTS: frozenset[str] = frozenset(
    {
        "apikey",
        "api_key",
        "access_token",
        "authorization",
        "bearer",
        "client_secret",
        "cookie",
        "credential",
        "id_token",
        "passwd",
        "password",
        "private_key",
        "proxy_authorization",
        "refresh_token",
        "secret",
        "session",
        "set_cookie",
        "token",
    }
)
"""Substrings that mark a key as holding a secret."""

_NORMALISE_KEY = re.compile(r"[^a-z0-9]+")

# ``Authorization: Bearer abc`` / ``api-key=abc`` / ``"password": "abc"``.
#
# The value alternation matches an authentication scheme together with the
# token that follows it. Without that, ``Authorization: Bearer abc`` would
# redact only the word ``Bearer`` and leave the credential in place.
_SENSITIVE_ASSIGNMENT = re.compile(
    r"""(?ix)
    (?P<key>
        authorization | proxy-authorization | set-cookie | cookie
      | api[_-]?key | x-api-key | access[_-]?token | refresh[_-]?token | id[_-]?token
      | client[_-]?secret | private[_-]?key | passwd | password | secret | token
    )
    (?P<sep>["']?\s*[:=]\s*["']?)
    (?P<value>
        (?: bearer | basic | digest | negotiate | token | apikey ) \s+ [^\s,;&"']+
      | [^\s,;&"']+
    )
    """
)

_BEARER = re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._\-=+/]+")


def _normalise_key(key: str) -> str:
    """Reduce a key to lowercase alphanumerics joined by underscores."""
    return _NORMALISE_KEY.sub("_", key.strip().lower()).strip("_")


def is_sensitive_key(key: str) -> bool:
    """Return ``True`` when ``key`` names a value that must not be recorded.

    Matching is case-insensitive and ignores separators, so ``X-API-Key``,
    ``x_api_key``, and ``apiKey`` are all treated as sensitive.
    """
    normalised = _normalise_key(key)
    if not normalised:
        return False
    return any(hint in normalised for hint in SENSITIVE_KEY_HINTS)


def redact_mapping(mapping: Mapping[str, Any]) -> dict[str, Any]:
    """Return a copy of ``mapping`` with sensitive values replaced.

    Nested mappings are redacted recursively. Non-sensitive values are returned
    unchanged; string values are additionally passed through :func:`redact_text`
    so an embedded credential is removed as well.
    """
    redacted: dict[str, Any] = {}
    for key, value in mapping.items():
        if is_sensitive_key(str(key)):
            redacted[str(key)] = REDACTED
        elif isinstance(value, Mapping):
            redacted[str(key)] = redact_mapping(value)
        elif isinstance(value, str):
            redacted[str(key)] = redact_text(value)
        else:
            redacted[str(key)] = value
    return redacted


def redact_text(text: str) -> str:
    """Replace credential-looking assignments inside ``text``.

    This is a best-effort defence for free-form strings such as log messages.
    Structured data should be scrubbed with :func:`redact_mapping` instead,
    which is exact rather than heuristic.

    Named assignments are handled first, then any remaining bare ``Bearer``
    token, so a credential cannot survive by sitting just past a key that was
    already matched.
    """
    if not text:
        return text

    def _replace(match: re.Match[str]) -> str:
        return f"{match.group('key')}{match.group('sep')}{REDACTED}"

    scrubbed = _SENSITIVE_ASSIGNMENT.sub(_replace, text)
    return _BEARER.sub(f"Bearer {REDACTED}", scrubbed)


POLICY_HEADERS: frozenset[str] = frozenset(
    {
        "access-control-allow-credentials",
        "access-control-allow-headers",
        "access-control-allow-methods",
        "access-control-allow-origin",
        "access-control-expose-headers",
        "www-authenticate",
    }
)
"""Headers whose names look credential-bearing but whose values are policy.

``Access-Control-Allow-Credentials: true`` carries no secret - it states a
policy, and that policy is exactly what a CORS check needs to read.
``WWW-Authenticate`` names the scheme a server wants, not a credential.
Redacting these would destroy evidence while protecting nothing.
"""


def redact_headers(headers: Mapping[str, Any]) -> dict[str, str]:
    """Return header names with sensitive values replaced.

    Header *names* are kept, because knowing that a request carried an
    ``Authorization`` header is useful evidence and the name is not a secret.
    The value is what must never be recorded.

    :data:`POLICY_HEADERS` are exempt: their names contain words such as
    "credentials" but their values describe policy rather than carrying one.
    """
    redacted: dict[str, str] = {}
    for name, value in headers.items():
        key = str(name)
        if key.lower() in POLICY_HEADERS:
            redacted[key] = redact_text(str(value))
            continue
        redacted[key] = REDACTED if is_sensitive_key(key) else redact_text(str(value))
    return redacted


def redact_query(query: str) -> str:
    """Replace sensitive values in a URL query string.

    An API key placed in the query string travels in the URL, which means it
    reaches access logs, referrer headers, and anything that records a request
    line. Redacting it here keeps it out of AegisAPI's own records too.

    Parameter order and names are preserved so the URL stays recognisable.
    """
    if not query:
        return query
    parts: list[str] = []
    for fragment in query.split("&"):
        if not fragment:
            continue
        name, separator, _ = fragment.partition("=")
        if separator and is_sensitive_key(name):
            parts.append(f"{name}={REDACTED}")
        else:
            parts.append(fragment)
    return "&".join(parts)


def redact_url(url: str) -> str:
    """Return ``url`` with sensitive query values replaced.

    Also strips userinfo, which should never be present - AegisAPI refuses such
    URLs - but which would carry a credential if it ever were.
    """
    head, separator, query = url.partition("?")
    if "@" in head:
        scheme, _, remainder = head.partition("://")
        _, _, host_and_path = remainder.rpartition("@")
        head = f"{scheme}://{REDACTED}@{host_and_path}" if scheme else head
    if not separator:
        return head
    return f"{head}?{redact_query(query)}"


__all__ = [
    "POLICY_HEADERS",
    "REDACTED",
    "SENSITIVE_KEY_HINTS",
    "is_sensitive_key",
    "redact_headers",
    "redact_mapping",
    "redact_query",
    "redact_text",
    "redact_url",
]
