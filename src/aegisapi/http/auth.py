"""Attaching credentials to a request, as late and as narrowly as possible.

Four rules govern this module, and each exists because of a specific way
credentials leak in practice:

* **Resolve at the point of use.** A credential is read from the environment
  only once a request has already passed scope enforcement, and the resolved
  value is handed straight to the transport. It is never returned up the
  stack, stored on a model, or cached.
* **Never cross an origin.** Credentials are attached only when the destination
  matches the target's own origin. A redirect to another host gets no
  ``Authorization`` header, which is the difference between following a
  redirect and handing a token to whoever controls it.
* **Fail loudly.** A missing or empty environment variable raises. Sending the
  request unauthenticated instead would produce a 401 that looks like a
  finding.
* **Record names, never values.** What AegisAPI keeps is "a bearer token was
  attached", not the token.

Limits of environment-variable credentials are documented on
:mod:`aegisapi.models.secrets`: they are readable by any process running as the
same user and often land in shell history. This module does not improve that;
it only ensures AegisAPI itself does not widen the exposure.
"""

from __future__ import annotations

import base64
from collections.abc import Mapping
from dataclasses import dataclass, field

from aegisapi.models.target import ApiKeyLocation, AuthMethod, AuthProfile
from aegisapi.utils.urls import NormalizedUrl

SENSITIVE_REQUEST_HEADERS: frozenset[str] = frozenset(
    {"authorization", "proxy-authorization", "cookie", "x-api-key"}
)
"""Headers stripped when a request crosses to a different origin.

Lowercase for case-insensitive comparison. ``x-api-key`` is included because it
is the most common custom credential header; a profile's configured API key
header name is stripped as well, whatever it is called.
"""


@dataclass(frozen=True)
class PreparedAuth:
    """The result of applying an authentication profile to a request."""

    headers: dict[str, str] = field(default_factory=dict)
    """Headers to add. May contain a credential, so this is never recorded."""

    params: dict[str, str] = field(default_factory=dict)
    """Query parameters to add. May contain a credential."""

    method: AuthMethod = AuthMethod.NONE
    """Which method was applied, for the record."""

    applied: bool = False
    """Whether a credential was actually attached."""

    reason: str = "no authentication configured"
    """Why it was or was not applied, safe to display."""


def same_origin(left: NormalizedUrl, right: NormalizedUrl) -> bool:
    """``True`` when two URLs share scheme, host, and port.

    Origin equality, not host equality: a credential scoped to
    ``https://api.example.com`` must not travel to ``http://api.example.com``
    where it would cross the network in clear text, nor to port 8443 where a
    different service may be listening.
    """
    return (left.scheme, left.host, left.port) == (right.scheme, right.host, right.port)


def strip_credential_headers(
    headers: Mapping[str, str], *, extra_names: frozenset[str] = frozenset()
) -> dict[str, str]:
    """Remove credential-bearing headers from a mapping.

    Used when a redirect leads to a different origin: whatever the caller
    supplied, and whatever a previous hop attached, must not continue.
    """
    forbidden = SENSITIVE_REQUEST_HEADERS | {name.lower() for name in extra_names}
    return {name: value for name, value in headers.items() if name.lower() not in forbidden}


def prepare_authentication(
    profile: AuthProfile,
    *,
    destination: NormalizedUrl,
    target_origin: NormalizedUrl,
    env: Mapping[str, str] | None = None,
    enabled: bool = True,
) -> PreparedAuth:
    """Build the credential headers for one request.

    Args:
        profile: The target's configured authentication profile.
        destination: Where this particular request is going. For a redirect
            hop, this is the redirect target, not the original URL.
        target_origin: The target's own base URL.
        env: Environment mapping to resolve references from.
        enabled: ``False`` to send the request unauthenticated on purpose, as
            ``--no-auth`` does.

    Returns:
        A :class:`PreparedAuth`. When nothing is attached, the ``reason``
        explains why, so an unexpected 401 is easy to diagnose.

    Raises:
        MissingCredentialError: If a configured reference does not resolve.
            AegisAPI does not downgrade to an unauthenticated request.
    """
    if profile.method is AuthMethod.NONE:
        return PreparedAuth(reason="target has no authentication configured")
    if not enabled:
        return PreparedAuth(
            method=profile.method, reason="authentication disabled for this request"
        )
    if not same_origin(destination, target_origin):
        return PreparedAuth(
            method=profile.method,
            reason=(
                f"credentials withheld: {destination.origin} is not the target origin "
                f"{target_origin.origin}"
            ),
        )

    # Resolution happens here and nowhere earlier: the request is authorised,
    # in scope, and bound for the target's own origin.
    secrets = profile.resolve_credentials(dict(env) if env is not None else None)

    if profile.method is AuthMethod.BEARER:
        token = secrets["token"].reveal()
        return PreparedAuth(
            headers={"Authorization": f"Bearer {token}"},
            method=profile.method,
            applied=True,
            reason="bearer token attached",
        )

    if profile.method is AuthMethod.API_KEY:
        key = secrets["api_key"].reveal()
        if profile.api_key_location is ApiKeyLocation.QUERY:
            return PreparedAuth(
                params={profile.api_key_name: key},
                method=profile.method,
                applied=True,
                reason=f"API key attached as query parameter {profile.api_key_name}",
            )
        return PreparedAuth(
            headers={profile.api_key_name: key},
            method=profile.method,
            applied=True,
            reason=f"API key attached as header {profile.api_key_name}",
        )

    if profile.method is AuthMethod.BASIC:
        username = profile.username or ""
        password = secrets["password"].reveal()
        encoded = base64.b64encode(f"{username}:{password}".encode()).decode("ascii")
        return PreparedAuth(
            headers={"Authorization": f"Basic {encoded}"},
            method=profile.method,
            applied=True,
            reason="basic credentials attached",
        )

    # Unreachable while AuthMethod has four members; a new method must opt in
    # here rather than silently sending nothing.
    raise NotImplementedError(f"authentication method {profile.method!r} is not supported")


def credential_header_names(profile: AuthProfile) -> frozenset[str]:
    """Header names this profile would use, for stripping across origins."""
    names: set[str] = set()
    if profile.method is AuthMethod.API_KEY and profile.api_key_name:
        names.add(profile.api_key_name)
    if profile.method in (AuthMethod.BEARER, AuthMethod.BASIC):
        names.add("Authorization")
    return frozenset(names)


__all__ = [
    "SENSITIVE_REQUEST_HEADERS",
    "PreparedAuth",
    "credential_header_names",
    "prepare_authentication",
    "same_origin",
    "strip_credential_headers",
]
