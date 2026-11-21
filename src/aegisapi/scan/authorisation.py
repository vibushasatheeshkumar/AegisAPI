"""Turning a URL into an authorised target, or refusing to.

``aegisapi scan --url ...`` is a convenience: it skips the deliberate
``target add`` step and derives everything from one argument. That convenience
is where an assessment tool becomes dangerous, so the derivation is explicit
about what it is granting.

Two gates are applied before a scan target exists:

* **The allow-list is derived from the URL and nothing else.** The host in the
  URL is authorised; no subdomain, no sibling host, no other port. The scope's
  include pattern is the URL's own path, so scanning
  ``https://api.example.com/v2`` authorises ``/v2`` and below rather than the
  whole host. Both gates of :func:`aegisapi.core.scope.assert_in_scope` are
  still applied to every request, against this derived target.

* **Loopback and private hosts need a second argument.** Deriving scope from
  the URL means a typo can point a scanner at the machine it runs on or at the
  network it runs inside. Those destinations are the ones an operator is least
  likely to have authorisation for in writing and most likely to reach by
  accident, so ``--local-lab`` must say so out loud.

What this module cannot do is establish that the operator is authorised to
assess a public host. Nothing can: that is a fact about a contract, not about a
URL. It makes the boundary explicit and narrow so that whatever authorisation
exists is not accidentally exceeded.
"""

from __future__ import annotations

from dataclasses import dataclass

from aegisapi.core.config import ScopeSettings
from aegisapi.core.exceptions import ScopeViolationError
from aegisapi.models.target import AuthProfile, ScopeRules, Target
from aegisapi.utils.urls import (
    HostExposure,
    NormalizedUrl,
    classify_host_exposure,
    normalize_url,
)

SCAN_TARGET_NAME = "scan"
"""Name given to the ephemeral target a scan builds.

A scan target is never written to the workspace, so the name only has to be
valid and recognisable in output. Using a fixed one keeps a scan's results
distinguishable from those of a registered target an operator reviewed.
"""

LOCAL_LAB_HINT = (
    "Pass --local-lab to confirm you are assessing your own local test API. "
    "AegisAPI will not derive authorisation for a loopback or private host from "
    "a URL alone."
)


@dataclass(frozen=True)
class ScanAuthorisation:
    """An ephemeral target, and the settings that admit only it."""

    target: Target
    """The target every request in the scan is validated against."""

    scope_settings: ScopeSettings
    """A tool-wide allow-list containing exactly this one host."""

    url: NormalizedUrl
    """The parsed URL the scan was asked for."""

    exposure: HostExposure
    """How the host was classified, recorded for the report."""

    @property
    def requires_local_lab(self) -> bool:
        """``True`` when this destination needed the local-lab acknowledgement."""
        return self.exposure is not HostExposure.PUBLIC


def authorise_scan_url(
    raw_url: str,
    *,
    local_lab: bool = False,
    extra_hosts: tuple[str, ...] = (),
    auth: AuthProfile | None = None,
) -> ScanAuthorisation:
    """Validate a scan URL and derive the narrowest scope that admits it.

    Args:
        raw_url: The URL as the operator typed it.
        local_lab: The operator's explicit acknowledgement that a loopback or
            private destination is their own test environment.
        extra_hosts: Additional hosts to authorise. Each is added to both the
            target's scope and the tool-wide allow-list, because a host admitted
            by only one of them would be refused by the other.
        auth: How to authenticate. Credentials are environment-variable
            references, never values, so nothing secret reaches this call and
            nothing secret can be serialised out of the target it builds.

    Returns:
        A :class:`ScanAuthorisation` holding the ephemeral target and the
        allow-list that admits only it.

    Raises:
        InvalidUrlError: If the URL is not a parsable ``http``/``https`` URL.
        ScopeViolationError: If the destination is loopback or private and
            ``local_lab`` was not given.
    """
    url = normalize_url(raw_url, label="target URL", allow_query=False)
    exposure = classify_host_exposure(url.host)

    if exposure is not HostExposure.PUBLIC and not local_lab:
        kind = "the machine AegisAPI is running on" if exposure is HostExposure.LOOPBACK else (
            "a private or internal address"
        )
        raise ScopeViolationError(
            f"{url.host} is {kind}, and was not explicitly authorised.",
            hint=LOCAL_LAB_HINT,
        )

    hosts = [url.host, *(host.strip().lower() for host in extra_hosts if host.strip())]
    deduplicated: list[str] = []
    for host in hosts:
        if host not in deduplicated:
            deduplicated.append(host)

    target = Target.create(
        name=SCAN_TARGET_NAME,
        base_url=url.to_string(include_query=False),
        description=f"Ephemeral target for a scan of {url.origin}.",
        scope=ScopeRules(extra_hosts=list(deduplicated[1:])),
        auth=auth,
    )

    return ScanAuthorisation(
        target=target,
        # The second gate is derived from the same single source as the first.
        # It is not redundant: every sender applies both, so a later code path
        # that built a target by some other route is still capped here.
        scope_settings=ScopeSettings(enforce=True, allowed_hosts=deduplicated),
        url=url,
        exposure=exposure,
    )


def authorise_registered_target(
    target: Target,
    *,
    local_lab: bool = False,
    extra_hosts: tuple[str, ...] = (),
) -> ScanAuthorisation:
    """Build a :class:`ScanAuthorisation` from a registered workspace target.

    Mirrors :func:`authorise_scan_url` but starts from a :class:`Target` that
    was registered with ``aegisapi target add`` rather than from a raw URL.
    The target's configured scope and authentication profile are used directly;
    the same two gates are still applied to every request the scan sends.

    Args:
        target: A registered target loaded from the workspace.
        local_lab: Explicit acknowledgement that a loopback or private
            destination is the operator's own test environment.
        extra_hosts: Additional hosts to authorise for this scan only,
            added to the target's already-configured list.

    Returns:
        A :class:`ScanAuthorisation` holding the registered target and the
        tool-wide allow-list derived from its configured hosts.

    Raises:
        ScopeViolationError: If the target's host is loopback or private
            and ``local_lab`` was not given.
    """
    url = normalize_url(target.base_url, label="base URL", allow_query=False)
    exposure = classify_host_exposure(url.host)

    if exposure is not HostExposure.PUBLIC and not local_lab:
        kind = (
            "the machine AegisAPI is running on"
            if exposure is HostExposure.LOOPBACK
            else "a private or internal address"
        )
        raise ScopeViolationError(
            f"{url.host} is {kind}, and was not explicitly authorised.",
            hint=LOCAL_LAB_HINT,
        )

    # Build allowed_hosts: primary host first, then the target's configured
    # extra_hosts, then any per-scan extras, deduplicating throughout.
    allowed_hosts: list[str] = [url.host]
    for h in (*target.scope.extra_hosts, *extra_hosts):
        normalized = h.strip().lower()
        if normalized and normalized not in allowed_hosts:
            allowed_hosts.append(normalized)

    return ScanAuthorisation(
        target=target,
        scope_settings=ScopeSettings(enforce=True, allowed_hosts=allowed_hosts),
        url=url,
        exposure=exposure,
    )


__all__ = [
    "LOCAL_LAB_HINT",
    "SCAN_TARGET_NAME",
    "ScanAuthorisation",
    "authorise_registered_target",
    "authorise_scan_url",
]
