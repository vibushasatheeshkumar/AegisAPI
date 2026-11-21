"""The discovery result: what one specification said, and how it maps to a target.

This is the hand-off format for Phases 4 onward. Checks, risk analysis,
relationship analysis, and reporting all read a :class:`DiscoveryResult`
rather than a specification, so there is exactly one place where a dialect is
interpreted.

Three properties of this format are deliberate:

* **It carries provenance.** The source path, content digest, and declared
  version are recorded, so a later phase can say which document a finding came
  from and detect that the document has since changed.
* **It records classification, not permission.** Every endpoint keeps its
  scope classification, including out-of-scope ones, so a reviewer can see what
  the specification declared that the engagement does not cover. A path
  appearing in a specification is not authorisation to request it.
* **It holds no credentials.** Nothing here can contain a secret: security
  schemes are metadata, and the authentication profile that would resolve a
  credential lives on the target, which is referenced by name only.
"""

from __future__ import annotations

from collections import Counter
from datetime import UTC, datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

from aegisapi.models.endpoint import (
    Endpoint,
    SecurityAlternative,
    SecurityPosture,
    SecurityScheme,
)

DISCOVERY_SCHEMA_VERSION = 1
"""Format version of a persisted discovery result."""


class SpecificationFormat(StrEnum):
    """Serialisation the specification file used."""

    JSON = "json"
    YAML = "yaml"


class SpecificationVersion(StrEnum):
    """Specification dialects AegisAPI can parse, plus the absence of one."""

    OPENAPI_31 = "openapi_3.1"
    OPENAPI_30 = "openapi_3.0"
    SWAGGER_20 = "swagger_2.0"

    NONE = "none"
    """No specification was available; the inventory was observed.

    Exists so that a live scan which found no document can still produce a
    :class:`DiscoveryResult` without claiming to have parsed a dialect. A
    reviewer reading a report needs to be able to tell "parsed OpenAPI 3.1"
    from "guessed", and an enumeration with no way to say the second would
    force the first.
    """


class WarningCode(StrEnum):
    """Why a specification could be parsed but not fully understood.

    These are parsing observations, never security findings.
    """

    EXTERNAL_REFERENCE = "external_reference"
    """A ``$ref`` pointed outside the document. AegisAPI never fetches one."""

    MISSING_REFERENCE = "missing_reference"
    """A local ``$ref`` pointed at something the document does not contain."""

    CIRCULAR_REFERENCE = "circular_reference"
    """A schema refers back to itself; summarisation stopped at the cycle."""

    SCHEMA_TRUNCATED = "schema_truncated"
    """Summarisation stopped at the depth limit."""

    UNDEFINED_SECURITY_SCHEME = "undefined_security_scheme"
    """An operation required a scheme the document never defines."""

    UNKNOWN_SECURITY_SCHEME_TYPE = "unknown_security_scheme_type"
    """A declared scheme used a type this build does not recognise."""

    DUPLICATE_OPERATION = "duplicate_operation"
    """The same method and path appeared more than once; the first was kept."""

    MALFORMED_SECTION = "malformed_section"
    """A section had the wrong shape and was skipped rather than guessed at."""

    UNSUPPORTED_FEATURE = "unsupported_feature"
    """A construct AegisAPI recognises but does not yet normalise."""

    NO_OPERATIONS = "no_operations"
    """The document parsed cleanly but declared no operations."""

    TEMPLATED_SERVER = "templated_server"
    """A server URL contained a variable, so no concrete URL could be built."""


class ParseWarning(BaseModel):
    """One thing AegisAPI noticed while parsing but did not treat as fatal."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    code: WarningCode = Field(description="Machine-readable warning category.")
    message: str = Field(description="Human-readable explanation.")
    pointer: str | None = Field(
        default=None, description="JSON pointer to the part of the document involved."
    )


class ScopeClassification(StrEnum):
    """How a discovered endpoint relates to the target's configured scope."""

    IN_SCOPE = "in_scope"
    """A concrete URL could be built and the target's scope admits it."""

    OUT_OF_SCOPE = "out_of_scope"
    """A concrete URL could be built and the target's scope denies it."""

    UNRESOLVED = "unresolved"
    """No concrete URL could be built, so no scope decision was possible."""


class ClassifiedEndpoint(BaseModel):
    """A discovered endpoint together with its scope classification.

    Out-of-scope endpoints are kept, not dropped. What a specification declares
    beyond the engagement's boundary is exactly what a reviewer needs to see
    when deciding whether the scope, or the authorisation behind it, is right.
    """

    model_config = ConfigDict(extra="forbid")

    endpoint: Endpoint = Field(description="The normalised operation.")
    classification: ScopeClassification = Field(description="Scope decision for it.")
    reason: str = Field(description="Why the classification came out that way.")
    rule: str | None = Field(
        default=None, description="Configuration rule that decided it, where there was one."
    )
    resolved_url: str | None = Field(
        default=None,
        description="Concrete URL the classification was made against, if one could be built.",
    )
    server_url: str | None = Field(
        default=None, description="Server URL used to build the concrete URL."
    )

    @property
    def is_in_scope(self) -> bool:
        """``True`` only for an endpoint the target's scope admits."""
        return self.classification is ScopeClassification.IN_SCOPE


class RelationshipKind(StrEnum):
    """Categories of structural observation.

    Structural, not behavioural. Each one says something about how a document
    is shaped, and none of them is evidence of a vulnerability.
    """

    SHARED_PREFIX = "shared_prefix"
    """Operations that live under a common collection root."""

    PARENT_CHILD = "parent_child"
    """A resource path nested beneath an identified parent resource."""

    SHARED_IDENTIFIER = "shared_identifier"
    """The same path-parameter name appears on more than one operation."""

    CRUD_SET = "crud_set"
    """Create, read, update, and delete style methods over one resource."""

    SHARED_TAG = "shared_tag"
    """Operations the document groups under the same tag."""

    SHARED_SCHEMA = "shared_schema"
    """Operations that reference the same declared schema."""


class RelationshipObservation(BaseModel):
    """One structural observation about a group of endpoints.

    An observation is a hypothesis about structure for a later phase to build
    on. It asserts nothing about security, and Phase 8 is where these become
    inputs to risk intelligence rather than conclusions.
    """

    model_config = ConfigDict(extra="forbid")

    kind: RelationshipKind = Field(description="What kind of structure was observed.")
    subject: str = Field(
        description="What the observation is about: a path prefix, tag, or schema name."
    )
    description: str = Field(description="Human-readable explanation of the observation.")
    endpoint_keys: list[str] = Field(
        default_factory=list,
        description="Endpoints involved, as 'METHOD /path' keys.",
    )
    detail: dict[str, str] = Field(
        default_factory=dict, description="Extra structured facts about the observation."
    )


class SpecificationInfo(BaseModel):
    """Provenance and declared metadata of the parsed document."""

    model_config = ConfigDict(extra="forbid")

    version: SpecificationVersion = Field(description="Dialect AegisAPI parsed it as.")
    raw_version: str = Field(description="Version string exactly as declared.")
    format: SpecificationFormat = Field(description="JSON or YAML.")
    source_path: str = Field(
        description=(
            "Where the inventory came from: an absolute file path, the URL the "
            "target served the specification at, or the base URL when the "
            "inventory was observed rather than parsed."
        )
    )
    source_sha256: str = Field(
        description="SHA-256 of the file's bytes, so a later phase can detect a change."
    )
    byte_size: int = Field(ge=0, description="Size of the source file in bytes.")
    title: str | None = Field(default=None, description="Declared API title.")
    api_version: str | None = Field(default=None, description="Declared API version.")
    description: str | None = Field(default=None, description="Declared API description.")
    servers: list[str] = Field(
        default_factory=list, description="Server URLs declared at document level."
    )


class DiscoveryResult(BaseModel):
    """Everything one specification contributed, for one target."""

    model_config = ConfigDict(extra="forbid")

    schema_version: int = Field(
        default=DISCOVERY_SCHEMA_VERSION, ge=1, description="Format version of this document."
    )
    target_name: str = Field(description="Target this discovery run was associated with.")
    target_base_url: str = Field(
        description="Target base URL at the time of discovery, for provenance."
    )
    specification: SpecificationInfo = Field(description="Source document metadata.")
    endpoints: list[ClassifiedEndpoint] = Field(
        default_factory=list, description="Discovered operations with scope classifications."
    )
    security_schemes: list[SecurityScheme] = Field(
        default_factory=list, description="Security schemes the document declares."
    )
    global_security: list[SecurityAlternative] = Field(
        default_factory=list, description="Document-level security requirements."
    )
    relationships: list[RelationshipObservation] = Field(
        default_factory=list, description="Structural observations, not findings."
    )
    warnings: list[ParseWarning] = Field(
        default_factory=list, description="Parsing observations worth the operator's attention."
    )
    discovered_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC), description="When discovery ran (UTC)."
    )
    aegisapi_version: str = Field(description="AegisAPI version that produced this result.")

    @property
    def endpoint_count(self) -> int:
        """How many operations were discovered."""
        return len(self.endpoints)

    def classified(self, classification: ScopeClassification) -> list[ClassifiedEndpoint]:
        """Endpoints carrying one classification."""
        return [item for item in self.endpoints if item.classification is classification]

    def classification_counts(self) -> dict[ScopeClassification, int]:
        """How many endpoints fall into each classification."""
        counts = Counter(item.classification for item in self.endpoints)
        return {value: counts.get(value, 0) for value in ScopeClassification}

    def method_counts(self) -> dict[str, int]:
        """How many operations use each HTTP method, most frequent first."""
        counts = Counter(item.endpoint.method.value.upper() for item in self.endpoints)
        return dict(counts.most_common())

    def posture_counts(self) -> dict[SecurityPosture, int]:
        """How many operations fall into each declared-security posture."""
        counts = Counter(item.endpoint.declared_security.posture for item in self.endpoints)
        return {value: counts.get(value, 0) for value in SecurityPosture}

    def warning_counts(self) -> dict[WarningCode, int]:
        """How many warnings of each code were raised, most frequent first."""
        counts = Counter(warning.code for warning in self.warnings)
        return dict(counts.most_common())

    def endpoints_permitting_anonymous(self) -> list[ClassifiedEndpoint]:
        """Endpoints whose declaration admits an unauthenticated request.

        A declaration, not a test result. Whether these endpoints actually
        allow anonymous access is a question for a phase that can send
        requests.
        """
        return [
            item for item in self.endpoints if item.endpoint.declared_security.permits_anonymous
        ]

    def endpoints_without_security_metadata(self) -> list[ClassifiedEndpoint]:
        """Endpoints the document says nothing useful about, security-wise.

        This is a gap in the specification, not a vulnerability.
        """
        return [
            item
            for item in self.endpoints
            if not item.endpoint.declared_security.has_usable_metadata
        ]


__all__ = [
    "DISCOVERY_SCHEMA_VERSION",
    "ClassifiedEndpoint",
    "DiscoveryResult",
    "ParseWarning",
    "RelationshipKind",
    "RelationshipObservation",
    "ScopeClassification",
    "SpecificationFormat",
    "SpecificationInfo",
    "SpecificationVersion",
    "WarningCode",
]
