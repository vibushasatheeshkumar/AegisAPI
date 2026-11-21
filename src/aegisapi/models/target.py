"""The target data model: what AegisAPI knows about an API it may assess.

A target bundles three things that belong together: where the API lives, which
parts of it the operator is authorised to touch, and how a request to it would
be authenticated. Keeping them in one validated document means a later phase
cannot send a request without also having the scope rules in hand.

Every model here forbids unknown fields. A hand-edited target file with a typo,
or with a field such as ``token_value`` that AegisAPI deliberately does not
support, fails loudly instead of being silently ignored.

Phase 2 note: nothing in this module performs network access. It describes and
validates configuration only.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from aegisapi.models.secrets import SecretRef
from aegisapi.utils.urls import (
    NormalizedUrl,
    normalize_host,
    normalize_path_pattern,
    normalize_url,
)

TARGET_NAME_PATTERN = re.compile(r"^[a-z0-9][a-z0-9_-]{0,47}$")
"""Target names are lowercase slugs.

Names are normalised to lowercase so ``Acme`` and ``acme`` cannot become two
targets for the same API, and the character set excludes path separators and
dots so a name stays safe to use in a filename or a report heading later.
"""

MAX_DESCRIPTION_LENGTH = 500
MAX_TAGS = 20
MAX_SCOPE_RULES = 200


def normalize_target_name(raw: str) -> str:
    """Return ``raw`` as a canonical target name.

    Raises:
        ValueError: If the name is empty or uses unsupported characters. The
            caller converts this into an :class:`~aegisapi.core.exceptions.
            InvalidTargetError`.
    """
    name = raw.strip().lower()
    if not name:
        raise ValueError("a target name must not be empty")
    if not TARGET_NAME_PATTERN.match(name):
        raise ValueError(
            f"{raw!r} is not a valid target name; use 1-48 characters from "
            "a-z, 0-9, '-', and '_', starting with a letter or digit"
        )
    return name


class AuthMethod(StrEnum):
    """How a request to the target would prove who it is."""

    NONE = "none"
    BEARER = "bearer"
    API_KEY = "api_key"
    BASIC = "basic"


class ApiKeyLocation(StrEnum):
    """Where an API key would be placed on a request."""

    HEADER = "header"
    QUERY = "query"


class AuthProfile(BaseModel):
    """How AegisAPI would authenticate to a target.

    There is deliberately no field anywhere in this model that can hold a
    credential. Every secret is a :class:`~aegisapi.models.secrets.SecretRef`,
    which stores only the name of an environment variable, so serialising a
    target cannot leak one. ``username`` is kept as plain text because it is an
    identifier rather than a credential.

    Phase 2 validates and reports this configuration. It does not build
    authenticated requests, because no HTTP layer exists yet.
    """

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    method: AuthMethod = Field(
        default=AuthMethod.NONE,
        description="Authentication method to use for this target.",
    )
    token: SecretRef | None = Field(
        default=None,
        description="Bearer token reference, required when method is 'bearer'.",
    )
    api_key: SecretRef | None = Field(
        default=None,
        description="API key reference, required when method is 'api_key'.",
    )
    api_key_name: str = Field(
        default="X-API-Key",
        min_length=1,
        max_length=128,
        description="Header or query parameter that would carry the API key.",
    )
    api_key_location: ApiKeyLocation = Field(
        default=ApiKeyLocation.HEADER,
        description="Whether the API key goes in a header or the query string.",
    )
    username: str | None = Field(
        default=None,
        max_length=256,
        description="Basic authentication user name. Not a credential.",
    )
    password: SecretRef | None = Field(
        default=None,
        description="Basic authentication password reference.",
    )

    @field_validator("api_key_name")
    @classmethod
    def _validate_api_key_name(cls, value: str) -> str:
        """Reject names that could not be sent as a header or query key."""
        name = value.strip()
        if not name:
            raise ValueError("api_key_name must not be empty")
        if any(char.isspace() or ord(char) < 0x20 for char in name):
            raise ValueError("api_key_name must not contain whitespace or control characters")
        if any(char in name for char in ':\r\n="'):
            raise ValueError("api_key_name must not contain ':', '=', '\"', or a line break")
        return name

    @field_validator("username")
    @classmethod
    def _validate_username(cls, value: str | None) -> str | None:
        """Keep a user name free of characters that break a header."""
        if value is None:
            return None
        username = value.strip()
        if not username:
            raise ValueError("username must not be empty when supplied")
        if any(ord(char) < 0x20 for char in username):
            raise ValueError("username must not contain control characters")
        return username

    @model_validator(mode="after")
    def _check_method_requirements(self) -> Self:
        """Require exactly the references the chosen method needs.

        An over-specified profile is as much a configuration bug as an
        under-specified one: it hides which credential would actually be used.
        """
        supplied = {
            "token": self.token is not None,
            "api_key": self.api_key is not None,
            "password": self.password is not None,
            "username": self.username is not None,
        }
        required: dict[AuthMethod, set[str]] = {
            AuthMethod.NONE: set(),
            AuthMethod.BEARER: {"token"},
            AuthMethod.API_KEY: {"api_key"},
            AuthMethod.BASIC: {"username", "password"},
        }
        needed = required[self.method]

        missing = sorted(field for field in needed if not supplied[field])
        if missing:
            raise ValueError(f"auth method '{self.method.value}' requires {', '.join(missing)}")
        extra = sorted(
            field for field, present in supplied.items() if present and field not in needed
        )
        if extra:
            raise ValueError(
                f"auth method '{self.method.value}' must not define {', '.join(extra)}"
            )
        return self

    @property
    def references(self) -> tuple[tuple[str, SecretRef], ...]:
        """The credential references this profile needs, as ``(field, ref)``."""
        pairs = (("token", self.token), ("api_key", self.api_key), ("password", self.password))
        return tuple((field, ref) for field, ref in pairs if ref is not None)

    @property
    def requires_credentials(self) -> bool:
        """``True`` when at least one credential must be resolvable."""
        return bool(self.references)

    def credential_status(self, env: dict[str, str] | None = None) -> dict[str, bool]:
        """Report which references currently resolve, without reading values.

        Returns a mapping of field name to availability. Safe to display: it
        says *whether* a credential is present, never what it is.
        """
        return {field: ref.is_available(env) for field, ref in self.references}

    def resolve_credentials(self, env: dict[str, str] | None = None) -> dict[str, Any]:
        """Resolve every reference, or raise.

        Returns:
            A mapping of field name to :class:`~aegisapi.utils.secrets.Secret`.
            Nothing is cached, and the result must not be stored.

        Raises:
            MissingCredentialError: If any reference is unset or empty. No
                partial result is returned, so a caller cannot accidentally
                send a half-authenticated request.
        """
        return {field: ref.resolve(env) for field, ref in self.references}

    def describe(self) -> tuple[str, ...]:
        """Render the profile as display lines that contain no credentials."""
        if self.method is AuthMethod.NONE:
            return ("no authentication configured",)
        lines = [f"method: {self.method.value}"]
        if self.method is AuthMethod.API_KEY:
            lines.append(f"{self.api_key_location.value}: {self.api_key_name}")
        if self.username is not None:
            lines.append(f"username: {self.username}")
        lines.extend(f"{field} from {ref.describe()}" for field, ref in self.references)
        return tuple(lines)


class ScopeRules(BaseModel):
    """What part of a target the operator is authorised to assess.

    The rules are evaluated by :class:`aegisapi.core.scope.ScopeValidator`, and
    every rule here is an *allowance*, not a restriction: a URL is out of scope
    unless something in this model admits it.

    An empty ``include_paths`` therefore means "no path is in scope". That is
    deliberate. A target file that lost its include list denies everything
    rather than quietly widening to the whole host.
    """

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    include_paths: list[str] = Field(
        default_factory=list,
        max_length=MAX_SCOPE_RULES,
        description="Path patterns in scope. Empty means nothing is in scope.",
    )
    exclude_paths: list[str] = Field(
        default_factory=list,
        max_length=MAX_SCOPE_RULES,
        description="Path patterns that are never in scope, even if included.",
    )
    extra_hosts: list[str] = Field(
        default_factory=list,
        max_length=MAX_SCOPE_RULES,
        description="Additional authorised hosts, matched exactly.",
    )
    allowed_ports: list[int] = Field(
        default_factory=list,
        max_length=64,
        description="Additional authorised ports beyond the base URL's port.",
    )
    allow_subdomains: bool = Field(
        default=False,
        description="Whether subdomains of the base URL host are in scope.",
    )

    @field_validator("include_paths", "exclude_paths")
    @classmethod
    def _normalise_patterns(cls, patterns: list[str]) -> list[str]:
        """Canonicalise each pattern and drop duplicates, preserving order."""
        normalised: list[str] = []
        for raw in patterns:
            pattern = normalize_path_pattern(raw)
            if pattern not in normalised:
                normalised.append(pattern)
        return normalised

    @field_validator("extra_hosts")
    @classmethod
    def _normalise_hosts(cls, hosts: list[str]) -> list[str]:
        """Canonicalise each host and drop duplicates, preserving order."""
        normalised: list[str] = []
        for raw in hosts:
            host = normalize_host(raw, label="scope host")
            if host not in normalised:
                normalised.append(host)
        return normalised

    @field_validator("allowed_ports")
    @classmethod
    def _validate_ports(cls, ports: list[int]) -> list[int]:
        """Keep ports inside the valid range and drop duplicates."""
        seen: list[int] = []
        for port in ports:
            if not 1 <= port <= 65535:
                raise ValueError(f"{port} is not a valid port; use 1-65535")
            if port not in seen:
                seen.append(port)
        return seen

    def summary(self) -> str:
        """One-line description for table output."""
        includes = len(self.include_paths)
        excludes = len(self.exclude_paths)
        parts = [f"{includes} include", f"{excludes} exclude"]
        if self.extra_hosts:
            parts.append(f"{len(self.extra_hosts)} extra host(s)")
        if self.allowed_ports:
            parts.append(f"{len(self.allowed_ports)} extra port(s)")
        if self.allow_subdomains:
            parts.append("subdomains")
        return ", ".join(parts)


class Target(BaseModel):
    """A registered API target.

    Registering a target records a technical scope. It is **not** authorisation:
    only the API's owner can give that, in writing. AegisAPI enforces what is
    configured here so a mistake cannot reach an unintended host, but it cannot
    know whether the configuration itself was permitted.
    """

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    name: str = Field(description="Unique lowercase identifier for the target.")
    base_url: str = Field(description="Canonical http(s) base URL of the API.")
    description: str = Field(
        default="",
        max_length=MAX_DESCRIPTION_LENGTH,
        description="Free-text note about the engagement or API.",
    )
    tags: list[str] = Field(
        default_factory=list,
        max_length=MAX_TAGS,
        description="Labels for grouping targets.",
    )
    enabled: bool = Field(
        default=True,
        description="Whether this target may be assessed. Disabled targets are out of scope.",
    )
    scope: ScopeRules = Field(
        default_factory=ScopeRules,
        description="Authorised scope for this target.",
    )
    auth: AuthProfile = Field(
        default_factory=AuthProfile,
        description="How requests to this target would be authenticated.",
    )
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="When the target was registered (UTC).",
    )
    updated_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="When the target was last modified (UTC).",
    )

    @field_validator("name")
    @classmethod
    def _validate_name(cls, value: str) -> str:
        return normalize_target_name(value)

    @field_validator("base_url")
    @classmethod
    def _validate_base_url(cls, value: str) -> str:
        """Canonicalise the base URL, rejecting query strings."""
        return normalize_url(value, label="base URL", allow_query=False).to_string()

    @field_validator("tags")
    @classmethod
    def _validate_tags(cls, tags: list[str]) -> list[str]:
        """Lowercase, trim, and de-duplicate tags."""
        cleaned: list[str] = []
        for raw in tags:
            tag = raw.strip().lower()
            if not tag:
                continue
            if len(tag) > 32 or any(char.isspace() for char in tag):
                raise ValueError(f"{raw!r} is not a valid tag; use up to 32 characters, no spaces")
            if tag not in cleaned:
                cleaned.append(tag)
        return cleaned

    @field_validator("created_at", "updated_at")
    @classmethod
    def _require_timezone(cls, value: datetime) -> datetime:
        """Keep timestamps unambiguous by requiring an offset."""
        if value.tzinfo is None:
            raise ValueError("timestamps must be timezone-aware")
        return value.astimezone(UTC)

    @classmethod
    def create(
        cls,
        *,
        name: str,
        base_url: str,
        description: str = "",
        tags: list[str] | None = None,
        enabled: bool = True,
        scope: ScopeRules | None = None,
        auth: AuthProfile | None = None,
    ) -> Target:
        """Build a new target, deriving scope defaults from the base URL.

        When no include patterns are given, the base URL's own path becomes the
        single include pattern. Registering ``https://api.example.com/v2``
        therefore puts ``/v2`` and everything below it in scope, and nothing
        else - narrower than the whole host, which is the safer default.
        """
        rules = scope or ScopeRules()
        if not rules.include_paths:
            base_path = normalize_url(base_url, label="base URL", allow_query=False).path
            rules = rules.model_copy(update={"include_paths": [base_path]})
        now = datetime.now(UTC)
        return cls(
            name=name,
            base_url=base_url,
            description=description,
            tags=tags or [],
            enabled=enabled,
            scope=rules,
            auth=auth or AuthProfile(),
            created_at=now,
            updated_at=now,
        )

    @property
    def url(self) -> NormalizedUrl:
        """The parsed base URL."""
        return normalize_url(self.base_url, label="base URL", allow_query=False)

    @property
    def host(self) -> str:
        """Canonical host of the base URL."""
        return self.url.host

    @property
    def scheme(self) -> str:
        """Scheme of the base URL. A target's scope is pinned to it."""
        return self.url.scheme

    @property
    def port(self) -> int:
        """Effective port of the base URL."""
        return self.url.port

    @property
    def base_path(self) -> str:
        """Path component of the base URL."""
        return self.url.path


class TargetCollection(BaseModel):
    """Every registered target, as persisted in the target store."""

    model_config = ConfigDict(extra="forbid")

    schema_version: int = Field(
        default=1,
        ge=1,
        description="Format version of the target store document.",
    )
    targets: dict[str, Target] = Field(
        default_factory=dict,
        description="Registered targets, keyed by target name.",
    )

    @model_validator(mode="after")
    def _check_keys_match_names(self) -> Self:
        """Reject a document whose keys disagree with the targets they hold."""
        for key, target in self.targets.items():
            if key != target.name:
                raise ValueError(f"target stored under key {key!r} is named {target.name!r}")
        return self

    def sorted_targets(self) -> list[Target]:
        """Targets ordered by name, for stable output."""
        return [self.targets[name] for name in sorted(self.targets)]


__all__ = [
    "MAX_DESCRIPTION_LENGTH",
    "MAX_SCOPE_RULES",
    "MAX_TAGS",
    "TARGET_NAME_PATTERN",
    "ApiKeyLocation",
    "AuthMethod",
    "AuthProfile",
    "ScopeRules",
    "Target",
    "TargetCollection",
    "normalize_target_name",
]
