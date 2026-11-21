"""Specification version detection.

A document declares its dialect, and AegisAPI believes that declaration rather
than sniffing structure: a file claiming ``openapi: 3.0.3`` but shaped like
Swagger 2.0 is malformed, and parsing it as whichever shape it happens to
resemble would produce an inventory the operator cannot trust.

An unrecognised major version is refused, not approximated. A dialect AegisAPI
does not understand may put security requirements somewhere it would not look,
and an inventory that quietly omits them is worse than no inventory.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from aegisapi.core.exceptions import (
    InvalidSpecificationError,
    UnsupportedSpecificationError,
)
from aegisapi.models.discovery import SpecificationVersion

SUPPORTED_VERSIONS: tuple[str, ...] = ("OpenAPI 3.1", "OpenAPI 3.0", "Swagger 2.0")
"""Dialects this build parses, for use in error messages."""


@dataclass(frozen=True)
class DetectedVersion:
    """The dialect a document declares."""

    version: SpecificationVersion
    raw: str

    @property
    def is_openapi_3(self) -> bool:
        """``True`` for either OpenAPI 3.x dialect."""
        return self.version in {
            SpecificationVersion.OPENAPI_30,
            SpecificationVersion.OPENAPI_31,
        }


def _as_version_string(value: Any, field: str) -> str:
    """Coerce a declared version to text, rejecting anything unusable."""
    if isinstance(value, str):
        declared = value.strip()
    elif isinstance(value, (int, float)) and not isinstance(value, bool):
        # YAML parses an unquoted 2.0 as a float, which is a common mistake.
        # bool is excluded deliberately: it is an int subclass, so `openapi:
        # true` would otherwise be reported as unsupported version "True"
        # rather than as the wrong type.
        declared = str(value)
    else:
        raise InvalidSpecificationError(
            f"The '{field}' field must be a version string.",
            hint=f"Found {type(value).__name__}.",
        )
    if not declared:
        raise InvalidSpecificationError(f"The '{field}' field must not be empty.")
    return declared


def looks_like_specification(document: dict[str, Any]) -> bool:
    """Whether a document declares a version field at all.

    A cheap pre-check for live probing, which fetches whatever a guessed path
    happens to serve. A single-page application answers 200 with valid JSON for
    almost any URL, so "it parsed" is no evidence that an inventory was found.
    Requiring a declared ``openapi`` or ``swagger`` key is what separates an
    actual specification from a JSON error body.

    Deliberately weaker than :func:`detect_version`: this answers "is it worth
    parsing", and that function answers "which dialect is it, and is it one we
    support", raising where it is not. A probe uses this to pass over a miss
    quietly, then lets the real detection reject a document that claims a
    dialect AegisAPI cannot read.
    """
    return isinstance(document.get("openapi"), (str, int, float)) or isinstance(
        document.get("swagger"), (str, int, float)
    )


def detect_version(document: dict[str, Any]) -> DetectedVersion:
    """Decide which dialect ``document`` declares.

    Raises:
        InvalidSpecificationError: If no version field is present, or one is
            present but unusable.
        UnsupportedSpecificationError: If the declared version is a dialect
            this build does not parse.
    """
    if "openapi" in document and "swagger" in document:
        raise InvalidSpecificationError(
            "The specification declares both 'openapi' and 'swagger'.",
            hint="A document must declare exactly one of them.",
        )

    if "openapi" in document:
        declared = _as_version_string(document["openapi"], "openapi")
        if declared.startswith("3.1"):
            return DetectedVersion(SpecificationVersion.OPENAPI_31, declared)
        if declared.startswith("3.0"):
            return DetectedVersion(SpecificationVersion.OPENAPI_30, declared)
        raise UnsupportedSpecificationError(
            f"OpenAPI version {declared!r} is not supported.",
            hint=f"AegisAPI parses {', '.join(SUPPORTED_VERSIONS)}.",
        )

    if "swagger" in document:
        declared = _as_version_string(document["swagger"], "swagger")
        if declared.startswith("2.0"):
            return DetectedVersion(SpecificationVersion.SWAGGER_20, declared)
        raise UnsupportedSpecificationError(
            f"Swagger version {declared!r} is not supported.",
            hint=f"AegisAPI parses {', '.join(SUPPORTED_VERSIONS)}.",
        )

    raise InvalidSpecificationError(
        "The document does not declare an 'openapi' or 'swagger' version.",
        hint=(
            "This does not look like an API specification. "
            f"AegisAPI parses {', '.join(SUPPORTED_VERSIONS)}."
        ),
    )


__all__ = [
    "SUPPORTED_VERSIONS",
    "DetectedVersion",
    "detect_version",
    "looks_like_specification",
]
