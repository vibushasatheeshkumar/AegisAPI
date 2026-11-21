"""Operator-declared test identities, objects, and access expectations.

Authorization testing is impossible without ground truth. To know that reading
an object was *wrong*, AegisAPI has to be told who owns it and who should be
able to reach it. Guessing identifiers to see what comes back is exactly the
behaviour this project refuses: it would mean touching real users' data.

So every authorization check depends on a fixtures file the operator writes,
and without one those checks report ``SKIPPED`` rather than inventing a
baseline. Credentials are referenced the same way targets reference them - by
environment variable name, never by value.

Example fixtures file::

    {
      "identities": [
        {"name": "alice", "role": "user",
         "auth": {"method": "bearer", "token": {"variable": "ALICE_TOKEN"}}},
        {"name": "bob", "role": "user",
         "auth": {"method": "bearer", "token": {"variable": "BOB_TOKEN"}}}
      ],
      "objects": [
        {"owner": "alice", "parameter": "userId", "value": "1001"}
      ],
      "expectations": [
        {"identity": "bob", "path": "/v1/admin/**", "method": "GET", "allowed": false}
      ],
      "allow_write_methods": false
    }
"""

from __future__ import annotations

import json
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from aegisapi.core.exceptions import InvalidTargetError, format_validation_problems
from aegisapi.models.http import HttpMethod
from aegisapi.models.target import AuthProfile
from aegisapi.utils.urls import normalize_path_pattern

MAX_FIXTURE_BYTES = 256 * 1024
"""Largest fixtures file AegisAPI will read."""


class AssessmentIdentity(BaseModel):
    """A configured identity the assessment may act as."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=64, description="Identity name, for reporting.")
    role: str | None = Field(
        default=None, max_length=64, description="Role label, used by function-level checks."
    )
    auth: AuthProfile = Field(
        description="How to authenticate as this identity. Credentials by reference only."
    )
    description: str | None = Field(default=None, max_length=200)

    @field_validator("name", "role")
    @classmethod
    def _clean(cls, value: str | None) -> str | None:
        """Trim and reject control characters in a label."""
        if value is None:
            return None
        text = value.strip()
        if not text:
            raise ValueError("must not be empty when supplied")
        if any(ord(char) < 0x20 for char in text):
            raise ValueError("must not contain control characters")
        return text


class OwnedObject(BaseModel):
    """An object with known ownership, used as a controlled BOLA fixture."""

    model_config = ConfigDict(extra="forbid")

    owner: str = Field(min_length=1, description="Name of the identity that owns this object.")
    parameter: str = Field(
        min_length=1, description="Path parameter the identifier fills, such as 'userId'."
    )
    value: str = Field(min_length=1, max_length=200, description="The identifier itself.")
    description: str | None = Field(default=None, max_length=200)

    @field_validator("value")
    @classmethod
    def _safe_value(cls, value: str) -> str:
        """Keep an identifier usable in a path segment."""
        text = value.strip()
        if not text:
            raise ValueError("must not be empty")
        if any(char in text for char in "/?#%\\") or any(
            char.isspace() or ord(char) < 0x20 for char in text
        ):
            raise ValueError(
                "must be a single plain path segment without '/', '?', '#', '%', or whitespace"
            )
        return text


class AccessExpectation(BaseModel):
    """What an identity should and should not be able to reach.

    Function-level authorization needs this. Without a declared expectation,
    observing that a role reached an endpoint says nothing: it may be entitled
    to. An endpoint named ``/admin`` is not evidence either.
    """

    model_config = ConfigDict(extra="forbid")

    identity: str = Field(min_length=1, description="Identity the expectation applies to.")
    path: str = Field(description="Path pattern, as used in scope rules.")
    method: HttpMethod | None = Field(
        default=None, description="Method it applies to. Omit for every method."
    )
    allowed: bool = Field(description="Whether this identity should be permitted.")
    reason: str | None = Field(default=None, max_length=200)

    @field_validator("path")
    @classmethod
    def _normalise_path(cls, value: str) -> str:
        """Reuse the project's pattern normalisation rather than a second one."""
        return normalize_path_pattern(value, label="expectation path")


class AssessmentFixtures(BaseModel):
    """Everything the operator declared for an assessment."""

    model_config = ConfigDict(extra="forbid")

    identities: list[AssessmentIdentity] = Field(default_factory=list, max_length=20)
    objects: list[OwnedObject] = Field(default_factory=list, max_length=100)
    expectations: list[AccessExpectation] = Field(default_factory=list, max_length=200)
    allow_write_methods: bool = Field(
        default=False,
        description=(
            "Permit checks that send POST, PUT, PATCH, or DELETE. Off by default: a "
            "write during an assessment can change or destroy real data."
        ),
    )

    def identity(self, name: str) -> AssessmentIdentity | None:
        """Look up a declared identity."""
        for item in self.identities:
            if item.name == name:
                return item
        return None

    def objects_for(self, parameter: str) -> list[OwnedObject]:
        """Declared objects that fill one path parameter."""
        return [item for item in self.objects if item.parameter == parameter]

    def identities_by_role(self) -> dict[str, list[AssessmentIdentity]]:
        """Declared identities grouped by role."""
        grouped: dict[str, list[AssessmentIdentity]] = {}
        for item in self.identities:
            grouped.setdefault(item.role or "", []).append(item)
        return grouped

    @property
    def has_authorization_fixtures(self) -> bool:
        """``True`` when object-level checks have the ground truth they need."""
        return len(self.identities) >= 2 and bool(self.objects)

    def validate_references(self) -> list[str]:
        """Report fixtures that point at identities that do not exist.

        Returned rather than raised, so a partly usable fixtures file still runs
        the checks it can support while the gaps are reported.
        """
        names = {item.name for item in self.identities}
        problems: list[str] = []
        for item in self.objects:
            if item.owner not in names:
                problems.append(f"object {item.value!r} names unknown owner {item.owner!r}")
        for expectation in self.expectations:
            if expectation.identity not in names:
                problems.append(
                    f"expectation for {expectation.path!r} names unknown identity "
                    f"{expectation.identity!r}"
                )
        return problems


def load_fixtures(path: Path | str) -> AssessmentFixtures:
    """Read a fixtures file.

    Raises:
        InvalidTargetError: If the file is missing, too large, not JSON, or
            fails validation. Reported as target input because that is what it
            is: operator-supplied configuration for one engagement.
    """
    source = Path(path).expanduser()
    if not source.is_file():
        raise InvalidTargetError(
            f"Fixtures file not found: {source}",
            hint="Authorization checks need declared identities and owned objects.",
        )
    try:
        if source.stat().st_size > MAX_FIXTURE_BYTES:
            raise InvalidTargetError(
                f"The fixtures file is larger than {MAX_FIXTURE_BYTES} bytes: {source}"
            )
        raw = source.read_bytes()
    except OSError as exc:
        raise InvalidTargetError(
            f"The fixtures file could not be read: {source}", hint=exc.strerror
        ) from exc

    try:
        document = json.loads(raw.decode("utf-8-sig"))
    except UnicodeDecodeError as exc:
        raise InvalidTargetError(f"The fixtures file is not valid UTF-8: {source}") from exc
    except json.JSONDecodeError as exc:
        raise InvalidTargetError(
            f"The fixtures file is not valid JSON: {source}",
            hint=f"{exc.msg} (line {exc.lineno}, column {exc.colno})",
        ) from exc

    if not isinstance(document, dict):
        raise InvalidTargetError(
            f"The fixtures file must contain a JSON object: {source}",
            hint=f"Found {type(document).__name__}.",
        )

    try:
        return AssessmentFixtures.model_validate(document)
    except ValidationError as exc:
        raise InvalidTargetError(
            f"The fixtures file is not valid: {source}",
            hint=format_validation_problems(exc),
        ) from exc


__all__ = [
    "MAX_FIXTURE_BYTES",
    "AccessExpectation",
    "AssessmentFixtures",
    "AssessmentIdentity",
    "OwnedObject",
    "load_fixtures",
]
