"""Scope enforcement: deciding whether a URL may be contacted.

**This is a technical control, not permission.** A passing scope check means the
URL matches what the operator configured. It says nothing about whether the
API's owner authorised the assessment. Only written authorisation from the
owner does that, and no amount of configuration substitutes for it.

Every module that performs network activity must call :func:`assert_in_scope`
before sending a request. Routing all outbound traffic through one gate is what
makes the guarantee auditable; a check module that opens its own socket bypasses
the control entirely.

This module offers three things, and the difference between them matters:

* :func:`assert_in_scope` is **the authoritative gate for outbound requests.**
  It parses the URL once, applies both gates, redacts and logs a refusal, and
  returns a :class:`ScopeAuthorisation` recording why the destination was
  admitted. :class:`~aegisapi.http.ScopedHttpClient` calls it for every request
  and every redirect hop, and it is what a future live-probing module must call
  too. There is deliberately no second implementation of this sequence.
* :meth:`ScopeValidator.check` and :func:`check_global_allow_list` return a
  :class:`ScopeDecision` without raising. They are the policy itself, and they
  exist separately so that **presentation and classification** code - ``target
  scope``, which displays verdicts, and
  :mod:`aegisapi.discovery.classification`, which labels a specification's
  operations - can report a verdict without pretending to send anything.
* :meth:`ScopeValidator.assert_allowed` applies the target gate alone and
  raises. It is a convenience for local reasoning, not the outbound gate; it
  shares its refusal path with :func:`assert_in_scope` so a denial is reported
  identically wherever it is raised.

Design rules, all of them fail-closed:

* **Default deny.** A URL is out of scope unless a rule admits it. An empty
  include list admits nothing.
* **Unparseable is never admitted.** :meth:`ScopeValidator.check` never raises
  for a malformed URL; it denies it, so a caller reporting a verdict cannot
  treat an error as "probably fine". :func:`assert_in_scope` instead lets
  :class:`~aegisapi.core.exceptions.InvalidUrlError` out, because a sender has
  to be stopped by something, and checking one spelling of a URL while sending
  another would be worse than refusing both. Either way nothing is contacted.
* **Exclusions win.** An excluded path is denied even when an include pattern
  matches it, and exclusions are matched case-insensitively so ``/Admin`` cannot
  slip past an exclusion written as ``/admin``.
* **Segment boundaries are respected.** An include or exclude of ``/admin``
  covers ``/admin`` and ``/admin/users``, but not ``/administrator``.
* **Two independent gates.** A target's own scope, and the tool-wide allow-list
  in ``config.toml``. Both must admit a host before a request may be sent.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from functools import lru_cache
from typing import NoReturn

from aegisapi.core.config import ScopeSettings
from aegisapi.core.exceptions import InvalidUrlError, ScopeViolationError
from aegisapi.core.logging import get_logger
from aegisapi.models.target import Target
from aegisapi.utils.redaction import redact_url
from aegisapi.utils.urls import NormalizedUrl, is_subdomain_of, normalize_url

_logger = get_logger(__name__)

AUTHORISATION_REMINDER = (
    "A scope check confirms a URL matches your configuration. It is not "
    "authorisation: obtain explicit written permission from the API owner."
)

TARGET_REFUSAL_HINT = (
    "No request was sent. Adjust the target's scope if the URL is inside your "
    f"engagement. {AUTHORISATION_REMINDER}"
)
"""Hint shown when a target's own scope rejects a destination."""

GLOBAL_REFUSAL_HINT = (
    "No request was sent. Add the host to scope.allowed_hosts in config.toml "
    "once you have written authorisation."
)
"""Hint shown when the tool-wide allow-list rejects a destination."""


@dataclass(frozen=True)
class ScopeDecision:
    """The outcome of a scope check, with the reason it came out that way."""

    allowed: bool
    reason: str
    rule: str | None = None

    @classmethod
    def allow(cls, reason: str, rule: str | None = None) -> ScopeDecision:
        """Build an allowing decision."""
        return cls(allowed=True, reason=reason, rule=rule)

    @classmethod
    def deny(cls, reason: str, rule: str | None = None) -> ScopeDecision:
        """Build a denying decision."""
        return cls(allowed=False, reason=reason, rule=rule)

    @property
    def verdict(self) -> str:
        """``"in scope"`` or ``"out of scope"``, for display."""
        return "in scope" if self.allowed else "out of scope"

    def __bool__(self) -> bool:
        return self.allowed


def combine_decisions(*decisions: ScopeDecision) -> ScopeDecision:
    """Reduce several decisions to one. The first denial wins.

    Raises:
        ValueError: If no decisions are supplied, since an empty conjunction
            would have to default to "allowed".
    """
    if not decisions:
        raise ValueError("at least one decision is required")
    for decision in decisions:
        if not decision.allowed:
            return decision
    return decisions[-1]


def _deny_target(
    url: str | NormalizedUrl, *, target_name: str, decision: ScopeDecision
) -> NoReturn:
    """Refuse a destination the target's own scope rejected.

    The URL is redacted before it reaches the message or the log. A rejected
    request can still carry an API key in its query string, and a refusal is
    both printed to the operator's terminal and written to the log file, so the
    redaction has to happen here rather than at either call site.
    """
    safe = redact_url(str(url))
    _logger.warning("Request to %s refused for target %s: %s", safe, target_name, decision.reason)
    raise ScopeViolationError(
        f"{safe} is out of scope for target '{target_name}': {decision.reason}",
        hint=TARGET_REFUSAL_HINT,
    )


def _deny_global(url: NormalizedUrl, *, decision: ScopeDecision) -> NoReturn:
    """Refuse a destination the tool-wide allow-list rejected."""
    safe = redact_url(url.to_string())
    _logger.warning("Request to %s refused by the global allow-list: %s", safe, decision.reason)
    raise ScopeViolationError(
        f"{safe} is not globally authorised: {decision.reason}",
        hint=GLOBAL_REFUSAL_HINT,
    )


@lru_cache(maxsize=512)
def _compile_pattern(pattern: str, *, case_sensitive: bool) -> re.Pattern[str]:
    """Translate a scope path pattern into an anchored regular expression.

    ``*`` matches within a single segment, ``**`` matches across segments, and a
    trailing ``/**`` also matches the prefix itself, so ``/v1/**`` covers
    ``/v1``. A pattern without wildcards matches its own path plus anything
    below it, stopping at a segment boundary.
    """
    flags = 0 if case_sensitive else re.IGNORECASE

    if "*" not in pattern:
        if pattern == "/":
            return re.compile(r".*", flags)
        return re.compile(re.escape(pattern) + r"(?:/.*)?$", flags)

    if pattern.endswith("/**"):
        head = pattern[: -len("/**")] or "/"
        return re.compile(_translate(head) + r"(?:/.*)?$", flags)
    return re.compile(_translate(pattern) + r"$", flags)


def _translate(pattern: str) -> str:
    """Convert wildcards to regex fragments, escaping everything else."""
    fragments: list[str] = []
    index = 0
    while index < len(pattern):
        if pattern.startswith("**", index):
            fragments.append(".*")
            index += 2
        elif pattern[index] == "*":
            fragments.append("[^/]*")
            index += 1
        else:
            fragments.append(re.escape(pattern[index]))
            index += 1
    return "".join(fragments)


def path_matches(path: str, pattern: str, *, case_sensitive: bool = True) -> bool:
    """``True`` when ``path`` falls under ``pattern``."""
    return _compile_pattern(pattern, case_sensitive=case_sensitive).match(path) is not None


class ScopeValidator:
    """Evaluates URLs against one target's configured scope.

    The validator is cheap to build and holds no state beyond the target, so a
    caller may construct one per request without concern.
    """

    def __init__(self, target: Target) -> None:
        self._target = target

    @property
    def target(self) -> Target:
        """The target whose scope this validator enforces."""
        return self._target

    def check(self, url: str | NormalizedUrl) -> ScopeDecision:
        """Decide whether ``url`` is inside the target's scope.

        Never raises for a bad URL: a URL that cannot be parsed unambiguously
        is denied, with the parser's reason attached.
        """
        target = self._target

        if not target.enabled:
            return ScopeDecision.deny(f"target '{target.name}' is disabled", rule="target.enabled")

        if isinstance(url, NormalizedUrl):
            parsed = url
        else:
            try:
                parsed = normalize_url(url)
            except InvalidUrlError as exc:
                return ScopeDecision.deny(f"URL was rejected: {exc.message}", rule="url.parse")

        return combine_decisions(
            self._check_scheme(parsed),
            self._check_host(parsed),
            self._check_port(parsed),
            self._check_path(parsed),
        )

    def assert_allowed(self, url: str | NormalizedUrl) -> NormalizedUrl:
        """Return the parsed URL, or raise if the target's scope rejects it.

        The target gate alone. **This is not the outbound-request gate:** a
        caller about to send something must use :func:`assert_in_scope`, which
        also applies the tool-wide allow-list. Refusal is delegated to the same
        helper that gate uses, so a denial reads identically either way.

        Raises:
            ScopeViolationError: If the URL is denied for any reason, including
                being unparseable.
        """
        decision = self.check(url)
        if not decision.allowed:
            _deny_target(url, target_name=self._target.name, decision=decision)
        return url if isinstance(url, NormalizedUrl) else normalize_url(url)

    def _check_scheme(self, url: NormalizedUrl) -> ScopeDecision:
        """A target's scope is pinned to the scheme of its base URL."""
        expected = self._target.scheme
        if url.scheme != expected:
            return ScopeDecision.deny(
                f"scheme '{url.scheme}' does not match the target scheme '{expected}'",
                rule="base_url.scheme",
            )
        return ScopeDecision.allow(
            f"scheme '{url.scheme}' matches the target", rule="base_url.scheme"
        )

    def _check_host(self, url: NormalizedUrl) -> ScopeDecision:
        """Match the host exactly, or against an explicit allowance."""
        target = self._target
        host = url.host
        if host == target.host:
            return ScopeDecision.allow(f"host '{host}' is the target host", rule="base_url.host")
        if host in target.scope.extra_hosts:
            return ScopeDecision.allow(
                f"host '{host}' is listed in scope.extra_hosts", rule="scope.extra_hosts"
            )
        if target.scope.allow_subdomains and is_subdomain_of(host, target.host):
            return ScopeDecision.allow(
                f"host '{host}' is a subdomain of '{target.host}'", rule="scope.allow_subdomains"
            )
        return ScopeDecision.deny(
            f"host '{host}' is not the target host '{target.host}' and is not explicitly allowed",
            rule="base_url.host",
        )

    def _check_port(self, url: NormalizedUrl) -> ScopeDecision:
        """Match the target's port, or an explicitly allowed one."""
        target = self._target
        if url.port == target.port:
            return ScopeDecision.allow(f"port {url.port} matches the target", rule="base_url.port")
        if url.port in target.scope.allowed_ports:
            return ScopeDecision.allow(
                f"port {url.port} is listed in scope.allowed_ports", rule="scope.allowed_ports"
            )
        return ScopeDecision.deny(
            f"port {url.port} is not the target port {target.port} and is not explicitly allowed",
            rule="base_url.port",
        )

    def _check_path(self, url: NormalizedUrl) -> ScopeDecision:
        """Exclusions are evaluated first, then include patterns."""
        rules = self._target.scope

        for pattern in rules.exclude_paths:
            if path_matches(url.path, pattern, case_sensitive=False):
                return ScopeDecision.deny(
                    f"path '{url.path}' is excluded by '{pattern}'", rule="scope.exclude_paths"
                )

        if not rules.include_paths:
            return ScopeDecision.deny(
                "no include patterns are configured, so no path is in scope",
                rule="scope.include_paths",
            )

        for pattern in rules.include_paths:
            if path_matches(url.path, pattern):
                return ScopeDecision.allow(
                    f"path '{url.path}' matches include pattern '{pattern}'",
                    rule="scope.include_paths",
                )

        return ScopeDecision.deny(
            f"path '{url.path}' does not match any include pattern",
            rule="scope.include_paths",
        )


def check_global_allow_list(host: str, settings: ScopeSettings) -> ScopeDecision:
    """Check a host against the tool-wide allow-list in ``config.toml``.

    This is the second, independent gate. It exists so that an operator can cap
    everything AegisAPI may contact in one place, regardless of how many
    targets are registered. Hosts are matched exactly; subdomains are not
    implied.
    """
    if not settings.enforce:
        return ScopeDecision.allow(
            "global scope enforcement is disabled in configuration", rule="scope.enforce"
        )
    if not settings.allowed_hosts:
        return ScopeDecision.deny(
            "scope.allowed_hosts is empty, so no host is authorised globally",
            rule="scope.allowed_hosts",
        )
    if host in settings.allowed_hosts:
        return ScopeDecision.allow(
            f"host '{host}' is listed in scope.allowed_hosts", rule="scope.allowed_hosts"
        )
    return ScopeDecision.deny(
        f"host '{host}' is not listed in scope.allowed_hosts", rule="scope.allowed_hosts"
    )


@dataclass(frozen=True)
class ScopeAuthorisation:
    """Proof that one destination passed every gate that applies to it.

    Returned by :func:`assert_in_scope` so a caller can record *why* a request
    was permitted without re-running the checks. Carrying both decisions is
    what lets the HTTP layer put the full reason on the response it stores as
    evidence, instead of reaching for the validator a second time.
    """

    url: NormalizedUrl
    """The parsed destination. Exactly what was checked, and what to contact."""

    target_decision: ScopeDecision
    """Why the target's own scope admitted it."""

    global_decision: ScopeDecision | None = None
    """Why the tool-wide allow-list admitted it, when that gate was applied."""

    @property
    def reason(self) -> str:
        """A safe, displayable account of why this destination was admitted."""
        if self.global_decision is None:
            return f"target scope: {self.target_decision.reason}"
        return f"target scope: {self.target_decision.reason}; global: {self.global_decision.reason}"


def assert_in_scope(
    url: str | NormalizedUrl,
    *,
    target: Target,
    settings: ScopeSettings | None = None,
) -> ScopeAuthorisation:
    """Gate a destination through every applicable scope check, or raise.

    **This is the authoritative gate for outbound requests.** Every module that
    sends a request goes through it, and none sends without it:
    :class:`~aegisapi.http.ScopedHttpClient` calls it for the initial request
    and again for each redirect hop, before any bytes leave the machine. A new
    sender - live probing is the next one - calls this rather than assembling
    the sequence itself, because a second assembly is a second policy.

    The URL is parsed once, and the parsed form is both what the gates judge
    and what the caller is handed back, so the destination that was authorised
    is exactly the destination that gets contacted.

    Args:
        url: The destination. A string is normalised; an already-parsed
            :class:`~aegisapi.utils.urls.NormalizedUrl` is used as given.
        target: The target whose scope applies.
        settings: Passing them applies the tool-wide allow-list as well, which
            every request-sending caller must do. Omitting them checks the
            target's scope alone, which is appropriate only for local reasoning
            that sends nothing.

    Returns:
        A :class:`ScopeAuthorisation` holding the parsed URL and each decision
        that admitted it.

    Raises:
        InvalidUrlError: If the URL cannot be parsed unambiguously. Raised
            rather than denied, because a malformed destination is bad input
            and not a scope decision - and because the alternative would be to
            check one spelling of a URL and send another.
        ScopeViolationError: If either gate denies the URL. Raised **before**
            anything is sent.
    """
    parsed = url if isinstance(url, NormalizedUrl) else normalize_url(url, label="request URL")

    target_decision = ScopeValidator(target).check(parsed)
    if not target_decision.allowed:
        _deny_target(parsed, target_name=target.name, decision=target_decision)

    global_decision: ScopeDecision | None = None
    if settings is not None:
        global_decision = check_global_allow_list(parsed.host, settings)
        if not global_decision.allowed:
            _deny_global(parsed, decision=global_decision)

    authorisation = ScopeAuthorisation(
        url=parsed,
        target_decision=target_decision,
        global_decision=global_decision,
    )
    _logger.debug(
        "Request to %s authorised (%s)",
        redact_url(parsed.to_string()),
        authorisation.reason,
    )
    return authorisation


__all__ = [
    "AUTHORISATION_REMINDER",
    "GLOBAL_REFUSAL_HINT",
    "TARGET_REFUSAL_HINT",
    "ScopeAuthorisation",
    "ScopeDecision",
    "ScopeValidator",
    "assert_in_scope",
    "check_global_allow_list",
    "combine_decisions",
    "path_matches",
]
