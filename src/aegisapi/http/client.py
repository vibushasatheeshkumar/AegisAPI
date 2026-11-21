"""The request boundary: nothing leaves the machine except through here.

Every request follows the same sequence, and the order is the security
property:

1. **Resolve** the destination from a path or an absolute URL, never allowing a
   path to change the origin.
2. **Normalise and validate** it with the project's existing URL utilities,
   which refuse ambiguous forms rather than guessing.
3. **Gate** it through :func:`aegisapi.core.scope.assert_in_scope`, which
   checks the target is enabled, applies the target's own scope, and applies
   the tool-wide allow-list. This is the Phase 2 validator, not a second copy.
4. **Authenticate**, resolving a credential only now, and only for the
   target's own origin.
5. **Throttle**, so concurrency cannot outrun the configured rate.
6. **Send**, then confirm the transport went where it was told.
7. **Normalise and redact** the response.

Callers cannot skip a step. There is no public method that sends without
validating, and the transport is private to the client.

Default deny is the rule throughout. If the destination cannot be resolved, if
the URL cannot be parsed unambiguously, or if a scope decision cannot be
established, the request is refused - never attempted "just to see".
"""

from __future__ import annotations

import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from types import TracebackType
from typing import TYPE_CHECKING
from urllib.parse import urlencode, urljoin

if TYPE_CHECKING:
    from aegisapi.testing.efficiency import EfficiencyTracker

from aegisapi.core.config import AegisConfig, ScopeSettings
from aegisapi.core.exceptions import (
    DestinationMismatchError,
    InvalidUrlError,
    ScopeViolationError,
    TransportError,
)
from aegisapi.core.logging import get_logger
from aegisapi.core.scope import assert_in_scope
from aegisapi.http import retry as retry_policy
from aegisapi.http.auth import (
    PreparedAuth,
    credential_header_names,
    prepare_authentication,
    same_origin,
    strip_credential_headers,
)
from aegisapi.http.throttle import RequestThrottle
from aegisapi.http.transport import (
    HttpxTransport,
    Transport,
    TransportRequest,
    TransportResponse,
)
from aegisapi.models.http import HttpLimits, HttpMethod, HttpResponse, RequestRecord
from aegisapi.models.target import Target
from aegisapi.utils.redaction import redact_headers, redact_url
from aegisapi.utils.urls import NormalizedUrl, normalize_url

_logger = get_logger(__name__)

FORBIDDEN_REQUEST_HEADERS: frozenset[str] = frozenset(
    {"host", "content-length", "transfer-encoding"}
)
"""Headers a caller may not set.

``Host`` is the important one: overriding it sends a request to one address
while claiming another name, which would make the scope decision describe a
destination different from the one actually addressed. The other two are owned
by the transport, and a mismatched value is a request-smuggling primitive.
"""

MAX_BODY_PREVIEW_LINE_LENGTH = 2000
_CONTROL_CHARACTERS = {chr(code) for code in range(0x20)} - {"\n", "\t"}


def resolve_request_url(target: Target, reference: str) -> str:
    """Work out the absolute URL a request reference means.

    A **path** (``/users``, ``users``, ``/users?limit=1``) is appended to the
    target's base URL. A path can never change the origin: anything that looks
    like a scheme or a protocol-relative authority is refused rather than
    joined, because ``urljoin`` would happily turn ``//evil.test/x`` into a
    request to ``evil.test``.

    An **absolute URL** is taken as given. It is not thereby trusted: it still
    passes the full scope gate, which is what decides whether an off-target
    host is permitted.

    Raises:
        InvalidUrlError: If the reference is empty, protocol-relative, or not a
            usable URL.
    """
    text = reference.strip()
    if not text:
        raise InvalidUrlError(
            "The request path must not be empty.",
            hint="Pass a path such as '/v1/orders', or a full URL.",
        )

    if text.startswith("//"):
        raise InvalidUrlError(
            f"The request path must not be protocol-relative: {text!r}",
            hint="Write a path starting with '/', or a full URL including the scheme.",
        )

    if "://" in text:
        # Absolute URL. Normalised here so a malformed one is refused before
        # anything else happens; scope still decides whether it is permitted.
        return normalize_url(text, label="request URL").to_string()

    path = text if text.startswith("/") else f"/{text}"
    base = target.base_url.rstrip("/")
    return normalize_url(f"{base}{path}", label="request URL").to_string()


@dataclass(frozen=True)
class FetchedDocument:
    """A response together with the raw body that produced it.

    Returned only by :meth:`ScopedHttpClient.fetch_document`. The body is held
    here, in a value the caller owns, rather than on the
    :class:`~aegisapi.models.http.HttpResponse` - which is serialised into
    assessments and reports, and has no business carrying response bodies.
    """

    response: HttpResponse
    """The normalised, redacted response. Safe to store as evidence."""

    body: bytes
    """The response body as received, already bounded by the size limit."""

    @property
    def content_type(self) -> str | None:
        """The declared response content type, if the server sent one."""
        return self.response.content_type


class ScopedHttpClient:
    """Sends HTTP requests that have passed scope enforcement.

    Not reusable across targets: one client is bound to one target and one set
    of scope settings, so a request cannot accidentally be validated against
    the wrong policy.
    """

    def __init__(
        self,
        *,
        target: Target,
        settings: ScopeSettings,
        limits: HttpLimits | None = None,
        transport: Transport | None = None,
        throttle: RequestThrottle | None = None,
        env: Mapping[str, str] | None = None,
        sleeper: Callable[[float], None] | None = None,
        efficiency_tracker: EfficiencyTracker | None = None,
    ) -> None:
        """Build a client.

        Args:
            target: The target every request is validated against.
            settings: The tool-wide allow-list. Required, not optional: a
                request that skipped the global gate would not be authorised.
            limits: Timeouts, size cap, rate, retries. Defaults are conservative.
            transport: Injected transport. Tests supply a fake; production code
                leaves it unset and gets an ``httpx`` transport the client owns.
            throttle: Injected throttle, for deterministic tests.
            env: Environment mapping used to resolve credential references.
            sleeper: Sleep function used between retries, injectable for tests.
            efficiency_tracker: Optional M5 efficiency tracker. When set, GET
                responses are cached for cross-check reuse and dedup metrics
                are collected. ``None`` disables all efficiency tracking.
        """
        self._target = target
        self._settings = settings
        self._limits = limits or HttpLimits()
        self._env = env
        self._sleep = sleeper or time.sleep
        self._owns_transport = transport is None
        self._transport = transport or HttpxTransport(limits=self._limits)
        self._throttle = throttle or RequestThrottle(
            requests_per_second=self._limits.requests_per_second,
            max_concurrency=self._limits.max_concurrency,
        )
        self._target_origin = target.url
        self._efficiency_tracker = efficiency_tracker

        if not self._limits.verify_tls:
            # Verification can be turned off, but never quietly.
            _logger.warning(
                "TLS certificate verification is DISABLED for target %s. "
                "Responses cannot be attributed to the intended host.",
                target.name,
            )

    @classmethod
    def from_config(
        cls,
        *,
        target: Target,
        config: AegisConfig,
        transport: Transport | None = None,
        **kwargs: object,
    ) -> ScopedHttpClient:
        """Build a client from a loaded configuration."""
        return cls(
            target=target,
            settings=config.scope,
            limits=config.http,
            transport=transport,
            **kwargs,  # type: ignore[arg-type]
        )

    @property
    def target(self) -> Target:
        """The target this client is bound to."""
        return self._target

    @property
    def limits(self) -> HttpLimits:
        """The limits in force."""
        return self._limits

    @property
    def throttle(self) -> RequestThrottle:
        """The throttle in force, exposed for assertions and diagnostics."""
        return self._throttle

    @property
    def _auth_context_key(self) -> str:
        """An opaque key identifying this client's authentication context.

        Used as part of the efficiency fingerprint to ensure a cached response
        from one auth profile is never served to a request under a different
        profile.  Does not expose credential values.
        """
        if self._target.auth is None:
            return f"{self._target.name}:none"
        return f"{self._target.name}:{self._target.auth.method.value}"

    @property
    def transport_for_reuse(self) -> Transport:
        """The transport, for building a sibling client over the same pool.

        Used when one assessment needs several clients that differ only in the
        authentication profile - one per configured test identity - so they
        share a connection pool and, importantly, one throttle.

        This does not widen anything: a transport on its own cannot send,
        because the URL it is given comes from a client that validated it. Pass
        it to another :class:`ScopedHttpClient`, never anywhere else.
        """
        return self._transport

    def request(
        self,
        method: HttpMethod | str,
        reference: str,
        *,
        params: Mapping[str, str] | None = None,
        headers: Mapping[str, str] | None = None,
        body: bytes | str | None = None,
        content_type: str | None = None,
        authenticate: bool = True,
    ) -> HttpResponse:
        """Send one request, after validating its destination.

        Args:
            method: HTTP method.
            reference: A path relative to the target's base URL, or an
                absolute URL.
            params: Query parameters to add.
            headers: Extra request headers. ``Host``, ``Content-Length``, and
                ``Transfer-Encoding`` are refused.
            body: Request body.
            content_type: Content type for the body.
            authenticate: ``False`` to send without credentials deliberately.

        Returns:
            A normalised :class:`~aegisapi.models.http.HttpResponse`, for any
            status code the API returned.

        Raises:
            InvalidUrlError: The destination could not be resolved or parsed.
            ScopeViolationError: Scope enforcement refused the destination.
                Raised **before** anything is sent.
            MissingCredentialError: A configured credential did not resolve.
            TransportError: No complete response arrived.
        """
        verb = HttpMethod(method.upper()) if isinstance(method, str) else method
        caller_headers = _validate_headers(headers)
        payload = _encode_body(body)

        url = resolve_request_url(self._target, reference)
        if params:
            url = _merge_query(url, params)

        # M5: Check GET response cache before hitting the wire.
        # Only GET responses are cached (idempotent). The fingerprint includes
        # the auth context key so cross-auth reuse cannot occur.
        if self._efficiency_tracker is not None and verb is HttpMethod.GET:
            from aegisapi.testing.efficiency import EfficiencyTracker
            fp = EfficiencyTracker.make_fingerprint(
                verb.value, url, payload, self._auth_context_key, authenticate
            )
            cached = self._efficiency_tracker.lookup_get(fp)
            if cached is not None:
                return cached

        destination, scope_reason = self._authorise(url)
        response = self._execute(
            verb,
            destination,
            scope_reason=scope_reason,
            caller_headers=caller_headers,
            body=payload,
            content_type=content_type,
            authenticate=authenticate,
        )

        # M5: Store GET response in cache after a successful send.
        if self._efficiency_tracker is not None and verb is HttpMethod.GET:
            self._efficiency_tracker.record_get(fp, response)  # type: ignore[possibly-undefined]

        return response

    def fetch_document(
        self,
        reference: str,
        *,
        method: HttpMethod | str = HttpMethod.GET,
        headers: Mapping[str, str] | None = None,
        authenticate: bool = True,
    ) -> FetchedDocument:
        """Send one request and return the normalised response *and* its body.

        :meth:`request` deliberately discards the response body, keeping only a
        short sanitised preview, because an :class:`HttpResponse` is stored as
        evidence and a saved assessment should not carry whole response bodies.
        Discovery needs the opposite: to parse a specification the target
        serves, it needs every byte of it.

        This method is the narrow exception. The bytes are returned to the
        caller and never placed on the response model, so nothing a report
        serialises changes. Everything else is identical to :meth:`request` -
        the same scope gate before anything is sent, the same per-hop redirect
        re-validation, the same size cap enforced while receiving, the same
        throttle.

        Args:
            reference: A path relative to the target's base URL, or an
                absolute URL.
            method: HTTP method. Read-shaped by default.
            headers: Extra request headers.
            authenticate: ``False`` to send without credentials deliberately.

        Returns:
            A :class:`FetchedDocument` holding the response and its raw body.

        Raises:
            InvalidUrlError: The destination could not be resolved or parsed.
            ScopeViolationError: Scope enforcement refused the destination.
            MissingCredentialError: A configured credential did not resolve.
            TransportError: No complete response arrived.
        """
        verb = HttpMethod(method.upper()) if isinstance(method, str) else method
        caller_headers = _validate_headers(headers)
        url = resolve_request_url(self._target, reference)
        destination, scope_reason = self._authorise(url)

        captured: list[bytes] = []
        response = self._execute(
            verb,
            destination,
            scope_reason=scope_reason,
            caller_headers=caller_headers,
            body=None,
            content_type=None,
            authenticate=authenticate,
            capture=captured,
        )
        return FetchedDocument(
            response=response,
            body=captured[-1] if captured else b"",
        )

    def _authorise(self, url: str) -> tuple[NormalizedUrl, str]:
        """Run the authoritative scope gate, or refuse.

        Delegates to :func:`aegisapi.core.scope.assert_in_scope`, which holds
        the only implementation of the policy: parse once, apply the target's
        scope, then apply the tool-wide allow-list, and refuse before anything
        is sent. The refusal message, its redaction, and the warning log live
        there too, so this client and any future sender report a denial
        identically.

        Returns the parsed destination and a safe explanation of why it was
        allowed, which is recorded on the response so every exchange carries
        the reason it was permitted.
        """
        authorisation = assert_in_scope(url, target=self._target, settings=self._settings)
        return authorisation.url, authorisation.reason

    def _execute(
        self,
        method: HttpMethod,
        destination: NormalizedUrl,
        *,
        scope_reason: str,
        caller_headers: dict[str, str],
        body: bytes | None,
        content_type: str | None,
        authenticate: bool,
        capture: list[bytes] | None = None,
    ) -> HttpResponse:
        """Send an authorised request, handling retries and redirects.

        ``capture``, when given, receives the raw body of the response that is
        finally returned. Only :meth:`fetch_document` passes it.
        """
        started = time.perf_counter()
        chain: list[str] = []
        visited: set[str] = set()
        current = destination
        current_reason = scope_reason
        current_headers = dict(caller_headers)
        retries_used = 0

        while True:
            response, used, prepared = self._send_with_retries(
                method,
                current,
                caller_headers=current_headers,
                body=body,
                content_type=content_type,
                authenticate=authenticate,
            )
            retries_used += used

            redirect_target = self._next_redirect(response, current)
            if redirect_target is None:
                elapsed = time.perf_counter() - started
                return self._build_response(
                    response,
                    method=method,
                    destination=current,
                    scope_reason=current_reason,
                    caller_headers=current_headers,
                    body=body,
                    authenticate=authenticate,
                    elapsed=elapsed,
                    chain=chain,
                    retries=retries_used,
                    prepared=prepared,
                    capture=capture,
                )

            if len(chain) >= self._limits.max_redirects:
                _logger.debug("Redirect limit reached at %s", redact_url(str(current)))
                elapsed = time.perf_counter() - started
                return self._build_response(
                    response,
                    method=method,
                    destination=current,
                    scope_reason=current_reason,
                    caller_headers=current_headers,
                    body=body,
                    authenticate=authenticate,
                    elapsed=elapsed,
                    chain=chain,
                    retries=retries_used,
                    prepared=prepared,
                    note=f"redirect limit of {self._limits.max_redirects} reached",
                    capture=capture,
                )

            next_url = redirect_target.to_string()
            if next_url in visited:
                raise TransportError(
                    f"Redirect loop detected at {redact_url(next_url)}.",
                    hint="The server redirected back to a URL already visited.",
                )
            visited.add(str(current))
            chain.append(redact_url(str(current)))

            # Every hop is validated independently, with both gates, before the
            # next request is built. A redirect is not permission to go there.
            current, current_reason = self._authorise(next_url)
            if not same_origin(current, self._target_origin):
                current_headers = strip_credential_headers(
                    current_headers,
                    extra_names=credential_header_names(self._target.auth),
                )
            method = HttpMethod.GET if response.status_code in (301, 302, 303) else method
            if method is HttpMethod.GET:
                body = None

    def _next_redirect(
        self, response: TransportResponse, current: NormalizedUrl
    ) -> NormalizedUrl | None:
        """Resolve a redirect target, or ``None`` when not following one."""
        if not self._limits.follow_redirects:
            return None
        if not 300 <= response.status_code < 400:
            return None
        location = response.header("location")
        if not location or not location.strip():
            return None

        joined = urljoin(current.to_string(), location.strip())
        try:
            return normalize_url(joined, label="redirect URL")
        except InvalidUrlError as exc:
            raise ScopeViolationError(
                f"The server redirected to a URL AegisAPI will not follow: {exc.message}",
                hint="No further request was sent.",
            ) from exc

    def _send_with_retries(
        self,
        method: HttpMethod,
        destination: NormalizedUrl,
        *,
        caller_headers: dict[str, str],
        body: bytes | None,
        content_type: str | None,
        authenticate: bool,
    ) -> tuple[TransportResponse, int, PreparedAuth]:
        """Send one hop, retrying only where the policy allows.

        Returns the response, how many retries were used, and the
        authentication that was applied. The prepared auth is returned rather
        than stashed on the client: two threads sharing one client would
        otherwise overwrite each other's record of what was attached.
        """
        attempt = 0
        while True:
            request, prepared = self._build_request(
                method,
                destination,
                caller_headers=caller_headers,
                body=body,
                content_type=content_type,
                authenticate=authenticate,
            )
            try:
                with self._throttle.reserve():
                    response = self._transport.send(request, limits=self._limits)
            except TransportError as exc:
                attempt += 1
                decision = retry_policy.decide_for_error(
                    exc,
                    method=method,
                    attempt=attempt,
                    max_retries=self._limits.max_retries,
                )
                if not decision.retry:
                    raise
                _logger.debug(
                    "Retrying %s %s after %s (%s)",
                    method.value,
                    redact_url(destination.to_string()),
                    type(exc).__name__,
                    decision.reason,
                )
                self._sleep(decision.delay_seconds)
                continue

            self._verify_destination(request, response, destination)

            attempt += 1
            decision = retry_policy.decide_for_status(
                response.status_code,
                method=method,
                attempt=attempt,
                max_retries=self._limits.max_retries,
                retry_after=response.header("retry-after"),
            )
            if not decision.retry:
                return response, attempt - 1, prepared
            _logger.debug(
                "Retrying %s %s (%s)",
                method.value,
                redact_url(destination.to_string()),
                decision.reason,
            )
            self._sleep(decision.delay_seconds)

    def _build_request(
        self,
        method: HttpMethod,
        destination: NormalizedUrl,
        *,
        caller_headers: dict[str, str],
        body: bytes | None,
        content_type: str | None,
        authenticate: bool,
    ) -> tuple[TransportRequest, PreparedAuth]:
        """Assemble the request, attaching credentials where permitted."""
        prepared = prepare_authentication(
            self._target.auth,
            destination=destination,
            target_origin=self._target_origin,
            env=self._env,
            enabled=authenticate,
        )

        headers: dict[str, str] = {"User-Agent": self._limits.user_agent}
        if content_type and body is not None:
            headers["Content-Type"] = content_type
        headers.update(caller_headers)
        headers.update(prepared.headers)

        url = destination.to_string()
        if prepared.params:
            url = _merge_query(url, prepared.params)

        return (
            TransportRequest(method=method, url=url, headers=headers, body=body),
            prepared,
        )

    def _verify_destination(
        self,
        request: TransportRequest,
        response: TransportResponse,
        destination: NormalizedUrl,
    ) -> None:
        """Confirm the transport went where the scope decision said.

        The guarantee this whole module provides is that the bytes leaving the
        machine match the URL that was validated. Checking it rather than
        assuming it costs one comparison and catches a transport that rewrote a
        URL, followed a redirect on its own, or silently normalised a host.
        """
        for label, candidate in (("request", request.url), ("response", response.final_url)):
            try:
                actual = normalize_url(candidate, label=f"{label} URL")
            except InvalidUrlError as exc:  # pragma: no cover - defensive
                raise DestinationMismatchError(
                    f"The transport reported an unusable {label} URL.",
                    hint=exc.message,
                ) from exc
            if (actual.scheme, actual.host, actual.port) != (
                destination.scheme,
                destination.host,
                destination.port,
            ):
                raise DestinationMismatchError(
                    f"The {label} origin {actual.origin} does not match the validated "
                    f"destination {destination.origin}.",
                    hint="The request was abandoned; the scope decision no longer applies.",
                )
            if actual.path != destination.path:
                raise DestinationMismatchError(
                    f"The {label} path {actual.path!r} does not match the validated "
                    f"path {destination.path!r}.",
                    hint="The request was abandoned; the scope decision no longer applies.",
                )

    def _build_response(
        self,
        response: TransportResponse,
        *,
        method: HttpMethod,
        destination: NormalizedUrl,
        scope_reason: str,
        caller_headers: Mapping[str, str],
        body: bytes | None,
        authenticate: bool,
        elapsed: float,
        chain: Sequence[str],
        retries: int,
        prepared: PreparedAuth,
        note: str | None = None,
        capture: list[bytes] | None = None,
    ) -> HttpResponse:
        """Normalise and redact a raw response.

        The recorded request headers are rebuilt from the caller's headers plus
        the *names* of whatever authentication added, then redacted. The live
        headers that carried the credential are not reachable from here.
        """
        if capture is not None:
            capture.append(response.body)

        recorded_headers = dict(caller_headers)
        # Record that a credential header was present, never its value. The
        # placeholder is replaced by the redaction marker below.
        for name in prepared.headers:
            recorded_headers[name] = ""
        redacted_request_headers = redact_headers(recorded_headers)

        record = RequestRecord(
            method=method,
            url=redact_url(destination.to_string()),
            headers=redacted_request_headers,
            body_bytes=len(body) if body else 0,
            auth_method=(prepared.method.value if prepared.method.value != "none" else None),
            authenticated=prepared.applied,
        )

        content_type = response.header("content-type")
        reason = f"{scope_reason}; {note}" if note else scope_reason
        if authenticate is False:
            reason = f"{reason}; sent without credentials by request"

        return HttpResponse(
            status_code=response.status_code,
            reason_phrase=response.reason_phrase,
            request=record,
            final_url=redact_url(response.final_url or destination.to_string()),
            headers=redact_headers(dict(response.headers)),
            content_type=content_type,
            body_bytes=len(response.body),
            body_preview=_body_preview(
                response.body, content_type, self._limits.body_preview_limit
            ),
            truncated=response.truncated,
            elapsed_seconds=max(elapsed, 0.0),
            redirect_chain=list(chain),
            scope_reason=reason,
            retries=retries,
        )

    def close(self) -> None:
        """Release the transport, if this client owns it."""
        if self._owns_transport:
            self._transport.close()

    def __enter__(self) -> ScopedHttpClient:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()


def _validate_headers(headers: Mapping[str, str] | None) -> dict[str, str]:
    """Reject headers a caller must not control.

    Raises:
        InvalidUrlError: Reused deliberately rather than inventing an error
            type: this is malformed request input, reported the same way a
            malformed URL is.
    """
    if not headers:
        return {}
    cleaned: dict[str, str] = {}
    for name, value in headers.items():
        key = str(name).strip()
        if not key:
            raise InvalidUrlError("A request header name must not be empty.")
        if key.lower() in FORBIDDEN_REQUEST_HEADERS:
            raise InvalidUrlError(
                f"The {key} header cannot be set by a caller.",
                hint=(
                    "Overriding it would make the request reach a destination "
                    "different from the one scope enforcement validated."
                ),
            )
        text = str(value)
        if any(char in text for char in ("\r", "\n")) or any(
            char in key for char in ("\r", "\n", ":", " ")
        ):
            raise InvalidUrlError(
                f"The {key} header contains characters that would split the request.",
            )
        cleaned[key] = text
    return cleaned


def _encode_body(body: bytes | str | None) -> bytes | None:
    """Encode a request body to bytes."""
    if body is None:
        return None
    return body if isinstance(body, bytes) else body.encode("utf-8")


def _merge_query(url: str, params: Mapping[str, str]) -> str:
    """Append query parameters to a URL, preserving any already present."""
    if not params:
        return url
    encoded = urlencode({str(key): str(value) for key, value in params.items()})
    separator = "&" if "?" in url else "?"
    return f"{url}{separator}{encoded}"


def _body_preview(body: bytes, content_type: str | None, limit: int) -> str | None:
    """Produce a bounded, inert preview of a response body.

    Three things happen here, all deliberate:

    * The body is decoded with replacement, so invalid bytes cannot raise.
    * Control characters are stripped, so a response cannot move the cursor,
      clear the screen, or inject an escape sequence into a terminal.
    * The result is plain text. Callers render it through Rich ``Text``, never
      as markup, so untrusted HTML or Rich tags are displayed rather than
      interpreted.
    """
    if limit <= 0 or not body:
        return None
    if content_type and not _is_textual(content_type):
        return None

    text = body[:limit].decode("utf-8", errors="replace")
    text = "".join(" " if char in _CONTROL_CHARACTERS else char for char in text)
    lines = [line[:MAX_BODY_PREVIEW_LINE_LENGTH] for line in text.splitlines()]
    return "\n".join(lines) if lines else text


def _is_textual(content_type: str) -> bool:
    """``True`` for content types worth previewing as text."""
    base = content_type.split(";", 1)[0].strip().lower()
    if base.startswith("text/"):
        return True
    return base in {
        "application/json",
        "application/problem+json",
        "application/xml",
        "application/xhtml+xml",
        "application/javascript",
        "application/x-www-form-urlencoded",
        "application/graphql",
    } or base.endswith("+json")


__all__ = [
    "FORBIDDEN_REQUEST_HEADERS",
    "FetchedDocument",
    "ScopedHttpClient",
    "resolve_request_url",
]
