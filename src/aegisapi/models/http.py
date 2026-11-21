"""Models for HTTP limits, requests, and responses.

Three groups live here:

* :class:`HttpLimits` - the configured bounds on a request. Every one of them
  has a conservative default, because an assessment tool that hammers a
  production API is a liability regardless of what it finds.
* :class:`RequestRecord` - what AegisAPI records about a request it sent. It
  holds *redacted* headers and a *redacted* URL, and it cannot hold a
  credential: resolved secrets never reach this model.
* :class:`HttpResponse` - a normalised response, with a bounded body preview
  and redacted metadata.

An important distinction is encoded in the types: an :class:`HttpResponse`
means the API answered, whatever the status code. A failure to get an answer is
a :class:`~aegisapi.core.exceptions.TransportError`, not a response with a
synthetic status. Later phases must not be able to confuse the two.

**A response proves nothing about security.** A 200 does not mean an endpoint
is correctly authorised, and a 401 does not mean it is. This phase moves bytes
and records what happened.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, field_validator

DEFAULT_CONNECT_TIMEOUT = 5.0
DEFAULT_READ_TIMEOUT = 10.0
DEFAULT_MAX_RESPONSE_BYTES = 1024 * 1024
DEFAULT_MAX_CONCURRENCY = 4
DEFAULT_REQUESTS_PER_SECOND = 2.0
DEFAULT_MAX_RETRIES = 0
DEFAULT_MAX_REDIRECTS = 5
DEFAULT_BODY_PREVIEW_BYTES = 2048

MAX_RETRY_AFTER_SECONDS = 60.0
"""Longest ``Retry-After`` delay AegisAPI will honour.

A hostile or broken server can send ``Retry-After: 86400``. Honouring it
literally would hang an assessment, so the delay is capped and the cap is
reported rather than silently applied.
"""


class HttpMethod(StrEnum):
    """HTTP methods the transport will send.

    Deliberately a closed set. An arbitrary method string is a way to reach
    behaviour nobody reviewed, and nothing in an API assessment needs one.
    """

    GET = "GET"
    HEAD = "HEAD"
    POST = "POST"
    PUT = "PUT"
    PATCH = "PATCH"
    DELETE = "DELETE"
    OPTIONS = "OPTIONS"

    @property
    def is_idempotent(self) -> bool:
        """``True`` for methods AegisAPI is willing to retry automatically.

        ``PUT`` and ``DELETE`` are idempotent by specification, but a repeated
        delete during an assessment is the kind of surprise that ends an
        engagement, so they are excluded. Only genuinely read-shaped methods
        are retried.
        """
        return self in _RETRYABLE_METHODS


_RETRYABLE_METHODS: frozenset[HttpMethod] = frozenset(
    {HttpMethod.GET, HttpMethod.HEAD, HttpMethod.OPTIONS}
)


class HttpLimits(BaseModel):
    """Bounds applied to every request AegisAPI sends."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    connect_timeout_seconds: float = Field(
        default=DEFAULT_CONNECT_TIMEOUT,
        gt=0,
        le=300,
        description="How long to wait for a connection to be established.",
    )
    read_timeout_seconds: float = Field(
        default=DEFAULT_READ_TIMEOUT,
        gt=0,
        le=600,
        description="How long to wait for response data once connected.",
    )
    max_response_bytes: int = Field(
        default=DEFAULT_MAX_RESPONSE_BYTES,
        ge=1,
        le=64 * 1024 * 1024,
        description="Largest response body to accept. Enforced while receiving.",
    )
    max_concurrency: int = Field(
        default=DEFAULT_MAX_CONCURRENCY,
        ge=1,
        le=64,
        description="Most requests in flight at once.",
    )
    requests_per_second: float = Field(
        default=DEFAULT_REQUESTS_PER_SECOND,
        gt=0,
        le=100,
        description="Ceiling on request rate, applied across all workers.",
    )
    max_retries: int = Field(
        default=DEFAULT_MAX_RETRIES,
        ge=0,
        le=5,
        description="Automatic retries for idempotent requests. Zero by default.",
    )
    max_redirects: int = Field(
        default=DEFAULT_MAX_REDIRECTS,
        ge=0,
        le=20,
        description="Redirect hops to follow when following is enabled.",
    )
    follow_redirects: bool = Field(
        default=False,
        description="Whether to follow redirects. Off by default; each hop is re-checked.",
    )
    verify_tls: bool = Field(
        default=True,
        description="Verify HTTPS certificates. Disabling it is loudly reported.",
    )
    body_preview_bytes: int = Field(
        default=DEFAULT_BODY_PREVIEW_BYTES,
        ge=0,
        le=64 * 1024,
        description="How much response body to keep for display.",
    )
    user_agent: str = Field(
        default="AegisAPI",
        min_length=1,
        max_length=200,
        description="User-Agent sent with every request.",
    )

    @field_validator("user_agent")
    @classmethod
    def _validate_user_agent(cls, value: str) -> str:
        """Keep the User-Agent free of characters that would split a header."""
        agent = value.strip()
        if not agent:
            raise ValueError("user_agent must not be empty")
        if any(ord(char) < 0x20 or ord(char) == 0x7F for char in agent):
            raise ValueError("user_agent must not contain control characters")
        return agent

    @property
    def body_preview_limit(self) -> int:
        """Preview size, never larger than the response limit itself."""
        return min(self.body_preview_bytes, self.max_response_bytes)


class RequestRecord(BaseModel):
    """What AegisAPI records about a request it sent.

    Contains no credential. ``headers`` is redacted before it reaches this
    model, and the resolved secret is passed straight to the transport without
    ever being stored.
    """

    model_config = ConfigDict(extra="forbid")

    method: HttpMethod = Field(description="Method that was sent.")
    url: str = Field(description="Destination URL, with sensitive query values redacted.")
    headers: dict[str, str] = Field(
        default_factory=dict, description="Request headers, values redacted where sensitive."
    )
    body_bytes: int = Field(default=0, ge=0, description="Size of the request body sent.")
    auth_method: str | None = Field(
        default=None, description="Authentication method applied, by name only."
    )
    authenticated: bool = Field(
        default=False, description="Whether a credential was attached to this request."
    )


class HttpResponse(BaseModel):
    """A normalised HTTP response.

    Its existence means the API answered. A 4xx or 5xx is an answer; a
    connection failure is not, and raises instead.
    """

    model_config = ConfigDict(extra="forbid")

    status_code: int = Field(ge=100, le=599, description="HTTP status code.")
    reason_phrase: str = Field(default="", description="Status text, where the server sent one.")
    request: RequestRecord = Field(description="The request that produced this response.")
    final_url: str = Field(description="URL that produced this response, redacted.")
    headers: dict[str, str] = Field(
        default_factory=dict, description="Response headers, values redacted where sensitive."
    )
    content_type: str | None = Field(default=None, description="Declared content type.")
    body_bytes: int = Field(default=0, ge=0, description="Bytes of body received.")
    body_preview: str | None = Field(
        default=None,
        description="Bounded, sanitised body text for display. Never rendered as markup.",
    )
    truncated: bool = Field(
        default=False, description="Whether the body was cut short by the size limit."
    )
    elapsed_seconds: float = Field(ge=0, description="Wall-clock time for the exchange.")
    redirect_chain: list[str] = Field(
        default_factory=list, description="Redacted URLs visited before the final response."
    )
    scope_reason: str = Field(description="Why scope enforcement admitted this destination.")
    retries: int = Field(default=0, ge=0, description="Automatic retries that were used.")
    sent_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC), description="When the request was sent (UTC)."
    )

    @property
    def is_success(self) -> bool:
        """``True`` for a 2xx status. Says nothing about security."""
        return 200 <= self.status_code < 300

    @property
    def is_redirect(self) -> bool:
        """``True`` for a 3xx status."""
        return 300 <= self.status_code < 400

    @property
    def status_class(self) -> str:
        """Status family, such as ``"2xx"``."""
        return f"{self.status_code // 100}xx"


__all__ = [
    "DEFAULT_BODY_PREVIEW_BYTES",
    "DEFAULT_CONNECT_TIMEOUT",
    "DEFAULT_MAX_CONCURRENCY",
    "DEFAULT_MAX_REDIRECTS",
    "DEFAULT_MAX_RESPONSE_BYTES",
    "DEFAULT_MAX_RETRIES",
    "DEFAULT_READ_TIMEOUT",
    "DEFAULT_REQUESTS_PER_SECOND",
    "MAX_RETRY_AFTER_SECONDS",
    "HttpLimits",
    "HttpMethod",
    "HttpResponse",
    "RequestRecord",
]
