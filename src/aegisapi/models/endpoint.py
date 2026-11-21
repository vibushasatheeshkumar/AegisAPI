"""The normalised endpoint inventory.

A specification is a document in one of three dialects; an endpoint inventory
is AegisAPI's single internal representation of the operations that document
declares. Later phases work against this model only, so adding a fourth
dialect means writing another parser, not touching the checks.

Two rules shape every model here:

* **Absent is not false.** Where a specification says nothing, the field is
  ``None`` or an empty collection. A parser that defaulted a missing
  ``required`` to ``False``, or invented a ``200`` response, would hand later
  phases facts the API's author never stated.
* **Declared is not true.** ``declared_security`` records what the document
  claims. It is not evidence that an endpoint enforces anything, and nothing in
  this module decides whether an endpoint is secure.

Field naming note: schema-bearing fields are called ``value_schema`` rather
than ``schema``, because a Pydantic field named ``schema`` shadows an attribute
of ``BaseModel``.
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

MAX_SCHEMA_DEPTH = 6
"""How deep schema summarisation descends before marking a node truncated.

Specifications nest arbitrarily and may be self-referential. A bounded summary
is enough for the property, required-field, and identifier analysis later
phases need, and it cannot be made to consume unbounded memory.
"""


class HttpMethod(StrEnum):
    """HTTP methods an operation may be declared under."""

    GET = "get"
    PUT = "put"
    POST = "post"
    DELETE = "delete"
    OPTIONS = "options"
    HEAD = "head"
    PATCH = "patch"
    TRACE = "trace"


class ParameterLocation(StrEnum):
    """Where a parameter travels on a request."""

    PATH = "path"
    QUERY = "query"
    HEADER = "header"
    COOKIE = "cookie"
    FORM_DATA = "form_data"
    """Swagger 2.0 ``formData``; expressed as a request body in OpenAPI 3."""


class ParameterSource(StrEnum):
    """Which level of the specification declared a parameter.

    Recorded because parameter inheritance is a common source of confusion: an
    operation may override a path-level parameter of the same name and
    location, and an inventory that lost track of which one won would be
    misleading.
    """

    PATH_ITEM = "path_item"
    OPERATION = "operation"


class SchemaKind(StrEnum):
    """How much of a schema node AegisAPI was able to summarise."""

    RESOLVED = "resolved"
    CIRCULAR = "circular"
    """Summarisation stopped because the schema refers back to itself."""

    TRUNCATED = "truncated"
    """Summarisation stopped at :data:`MAX_SCHEMA_DEPTH`."""

    UNRESOLVED_EXTERNAL = "unresolved_external"
    """The node was an external ``$ref``, which AegisAPI never fetches."""

    UNRESOLVED_MISSING = "unresolved_missing"
    """A local ``$ref`` pointed at something the document does not contain."""

    EMPTY = "empty"
    """The specification declared a schema with no usable type information."""


class SchemaSummary(BaseModel):
    """A bounded summary of one schema node.

    Enough structure for later phases to reason about object properties,
    required fields, array element types, and identifier-shaped fields, without
    carrying a full JSON Schema evaluator.
    """

    model_config = ConfigDict(extra="forbid")

    kind: SchemaKind = Field(
        default=SchemaKind.RESOLVED, description="How completely this node was summarised."
    )
    ref: str | None = Field(default=None, description="The $ref this node came from, verbatim.")
    name: str | None = Field(
        default=None, description="Component name, when the node came from a named schema."
    )
    type: str | None = Field(default=None, description="Declared JSON type, if any.")
    format: str | None = Field(default=None, description="Declared format, such as 'uuid'.")
    nullable: bool | None = Field(
        default=None, description="Declared nullability, where the dialect expresses it."
    )
    required: list[str] = Field(default_factory=list, description="Names of required properties.")
    properties: dict[str, SchemaSummary] = Field(
        default_factory=dict, description="Summarised object properties."
    )
    items: SchemaSummary | None = Field(
        default=None, description="Summarised array element schema."
    )
    enum_values: list[str] = Field(
        default_factory=list, description="Declared enumeration values, rendered as text."
    )
    composed_of: list[SchemaSummary] = Field(
        default_factory=list,
        description="Branches of an allOf, anyOf, or oneOf composition.",
    )
    composition: str | None = Field(
        default=None, description="Which composition keyword produced 'composed_of'."
    )
    minimum: float | None = Field(
        default=None, description="Declared minimum numeric value (inclusive)."
    )
    maximum: float | None = Field(
        default=None, description="Declared maximum numeric value (inclusive)."
    )
    min_length: int | None = Field(
        default=None, description="Declared minimum string length."
    )
    max_length: int | None = Field(
        default=None, description="Declared maximum string length."
    )

    @property
    def is_resolved(self) -> bool:
        """``True`` when the node was summarised without hitting a limit."""
        return self.kind is SchemaKind.RESOLVED

    def property_names(self) -> tuple[str, ...]:
        """Property names declared directly on this node."""
        return tuple(self.properties)

    def referenced_names(self) -> set[str]:
        """Every component name reachable from this node.

        Used by relationship analysis to notice two operations that work on the
        same declared resource.
        """
        found: set[str] = set()
        if self.name:
            found.add(self.name)
        for child in self.properties.values():
            found |= child.referenced_names()
        if self.items is not None:
            found |= self.items.referenced_names()
        for branch in self.composed_of:
            found |= branch.referenced_names()
        return found


class Parameter(BaseModel):
    """One declared request parameter."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(description="Parameter name as the API expects it.")
    location: ParameterLocation = Field(description="Where the parameter travels.")
    required: bool | None = Field(
        default=None,
        description="Declared requirement. None means the specification did not say.",
    )
    description: str | None = Field(default=None, description="Declared description.")
    deprecated: bool | None = Field(default=None, description="Declared deprecation.")
    value_schema: SchemaSummary | None = Field(
        default=None, description="Summarised parameter schema."
    )
    source: ParameterSource = Field(
        default=ParameterSource.OPERATION,
        description="Whether the path item or the operation declared this parameter.",
    )

    @property
    def key(self) -> tuple[str, str]:
        """Identity used for inheritance and overrides: name plus location."""
        return (self.name, self.location.value)


class MediaTypeSchema(BaseModel):
    """A content type and the schema declared for it."""

    model_config = ConfigDict(extra="forbid")

    content_type: str = Field(description="Media type, such as 'application/json'.")
    value_schema: SchemaSummary | None = Field(
        default=None, description="Summarised schema for this media type."
    )


class RequestBodySpec(BaseModel):
    """A declared request body."""

    model_config = ConfigDict(extra="forbid")

    required: bool | None = Field(
        default=None, description="Whether the body is declared required."
    )
    description: str | None = Field(default=None, description="Declared description.")
    content: list[MediaTypeSchema] = Field(
        default_factory=list, description="Declared content types and their schemas."
    )

    @property
    def content_types(self) -> tuple[str, ...]:
        """Declared media types."""
        return tuple(item.content_type for item in self.content)


class ResponseSpec(BaseModel):
    """A declared response."""

    model_config = ConfigDict(extra="forbid")

    status_code: str = Field(description="Status code as declared: '200', '2XX', or 'default'.")
    description: str | None = Field(default=None, description="Declared description.")
    content: list[MediaTypeSchema] = Field(
        default_factory=list, description="Declared content types and their schemas."
    )
    header_names: list[str] = Field(
        default_factory=list,
        description="Declared response header names. Values are not recorded.",
    )

    @property
    def content_types(self) -> tuple[str, ...]:
        """Declared media types."""
        return tuple(item.content_type for item in self.content)


class SecuritySchemeType(StrEnum):
    """Kinds of security scheme the supported dialects can declare."""

    HTTP = "http"
    API_KEY = "api_key"
    OAUTH2 = "oauth2"
    OPEN_ID_CONNECT = "open_id_connect"
    BASIC = "basic"
    """Swagger 2.0 spells HTTP basic authentication as its own type."""

    UNKNOWN = "unknown"
    """The document declared a type this build does not recognise."""


class SecurityScheme(BaseModel):
    """A security scheme the specification declares.

    Recorded as metadata only. AegisAPI does not contact ``open_id_connect_url``
    or any OAuth2 endpoint while parsing, and a declared scheme is not evidence
    that it is enforced.
    """

    model_config = ConfigDict(extra="forbid")

    name: str = Field(description="Name the specification uses to refer to this scheme.")
    type: SecuritySchemeType = Field(description="Normalised scheme type.")
    raw_type: str | None = Field(
        default=None, description="Type exactly as the document spelled it."
    )
    scheme: str | None = Field(
        default=None, description="HTTP authentication scheme, such as 'bearer'."
    )
    bearer_format: str | None = Field(
        default=None, description="Declared bearer format, such as 'JWT'."
    )
    parameter_name: str | None = Field(
        default=None, description="Header, query, or cookie name carrying an API key."
    )
    parameter_location: str | None = Field(
        default=None, description="Where an API key travels: header, query, or cookie."
    )
    flows: list[str] = Field(default_factory=list, description="Declared OAuth2 flow names.")
    scopes: dict[str, str] = Field(
        default_factory=dict, description="Declared OAuth2 scope names and descriptions."
    )
    open_id_connect_url: str | None = Field(
        default=None,
        description="Declared discovery URL. Recorded verbatim and never fetched.",
    )
    description: str | None = Field(default=None, description="Declared description.")


class SecurityRequirement(BaseModel):
    """A reference to one security scheme, with the scopes it demands."""

    model_config = ConfigDict(extra="forbid")

    scheme_name: str = Field(description="Name of a declared security scheme.")
    scopes: list[str] = Field(default_factory=list, description="Scopes the requirement demands.")


class SecurityAlternative(BaseModel):
    """One acceptable way to satisfy a security requirement.

    A specification's ``security`` list is an OR of alternatives, and each
    alternative is an AND of schemes. An alternative with no schemes is the
    document's way of saying a request may be anonymous.
    """

    model_config = ConfigDict(extra="forbid")

    schemes: list[SecurityRequirement] = Field(
        default_factory=list, description="Schemes that must all be satisfied."
    )

    @property
    def permits_anonymous(self) -> bool:
        """``True`` when this alternative demands nothing."""
        return not self.schemes


class SecurityPosture(StrEnum):
    """Where an operation's declared security came from.

    This records the *document's* claim, nothing more. ``NOT_DECLARED`` means
    the specification is silent, which is a gap in metadata rather than a
    finding; whether the endpoint actually requires authentication is a
    question for a later phase that can send requests.
    """

    OPERATION_OVERRIDE = "operation_override"
    """The operation declared its own requirements, replacing any global ones."""

    INHERITED_GLOBAL = "inherited_global"
    """The operation inherited the document's global requirements."""

    EXPLICITLY_OPTIONAL = "explicitly_optional"
    """The operation states that authentication is not required."""

    NOT_DECLARED = "not_declared"
    """Neither the operation nor the document declared any requirement."""


class DeclaredSecurity(BaseModel):
    """What a specification says about authenticating one operation."""

    model_config = ConfigDict(extra="forbid")

    posture: SecurityPosture = Field(description="Where the declaration came from.")
    alternatives: list[SecurityAlternative] = Field(
        default_factory=list, description="Acceptable ways to satisfy the requirement."
    )
    undefined_schemes: list[str] = Field(
        default_factory=list,
        description="Referenced scheme names the document never defines.",
    )

    @property
    def permits_anonymous(self) -> bool:
        """``True`` when the declaration admits an unauthenticated request."""
        if self.posture is SecurityPosture.EXPLICITLY_OPTIONAL:
            return True
        return any(alternative.permits_anonymous for alternative in self.alternatives)

    @property
    def scheme_names(self) -> tuple[str, ...]:
        """Every scheme name referenced, in declaration order, de-duplicated."""
        names: list[str] = []
        for alternative in self.alternatives:
            for requirement in alternative.schemes:
                if requirement.scheme_name not in names:
                    names.append(requirement.scheme_name)
        return tuple(names)

    @property
    def has_usable_metadata(self) -> bool:
        """``False`` when the document says nothing AegisAPI can act on later."""
        if self.posture is SecurityPosture.NOT_DECLARED:
            return False
        return bool(self.scheme_names) or self.permits_anonymous


class DiscoverySource(StrEnum):
    """How AegisAPI came to know an operation exists.

    Carried on every endpoint because the three origins warrant very different
    confidence. An operation parsed from a specification has a declared method,
    parameters, and security requirement. One the operator named has a method
    and nothing else. One that answered a wordlist probe has only the fact that
    it answered - and that is worth recording precisely because it is the
    weakest basis for anything a check later concludes.
    """

    SPECIFICATION = "specification"
    """Declared by an OpenAPI or Swagger document."""

    SUPPLIED = "supplied"
    """Named explicitly by the operator on the command line."""

    PROBED = "probed"
    """Observed to respond during bounded path probing. Nothing is declared."""


class Endpoint(BaseModel):
    """One operation, normalised out of a specification."""

    model_config = ConfigDict(extra="forbid")

    method: HttpMethod = Field(description="HTTP method of the operation.")
    path: str = Field(description="Path template exactly as declared, such as '/users/{userId}'.")
    operation_id: str | None = Field(
        default=None, description="Declared operationId, if the document gave one."
    )
    summary: str | None = Field(default=None, description="Declared summary.")
    description: str | None = Field(default=None, description="Declared description.")
    tags: list[str] = Field(default_factory=list, description="Declared tags.")
    deprecated: bool | None = Field(default=None, description="Declared deprecation.")
    parameters: list[Parameter] = Field(
        default_factory=list,
        description="Effective parameters after path-level inheritance and overrides.",
    )
    request_body: RequestBodySpec | None = Field(
        default=None, description="Declared request body, if any."
    )
    responses: list[ResponseSpec] = Field(default_factory=list, description="Declared responses.")
    declared_security: DeclaredSecurity = Field(
        description="What the specification claims about authentication."
    )
    servers: list[str] = Field(
        default_factory=list,
        description="Server URLs declared at operation or path level, overriding the root.",
    )
    source_pointer: str = Field(
        description="JSON pointer to this operation inside the source document."
    )
    source: DiscoverySource = Field(
        default=DiscoverySource.SPECIFICATION,
        description="How this operation was discovered.",
    )
    source_detail: str | None = Field(
        default=None,
        description=(
            "Where it came from concretely: the specification URL or path, or "
            "the probe response that revealed it."
        ),
    )
    consumes: list[str] = Field(
        default_factory=list,
        description="Swagger 2.0 'consumes' values that applied to this operation.",
    )
    produces: list[str] = Field(
        default_factory=list,
        description="Swagger 2.0 'produces' values that applied to this operation.",
    )

    @property
    def key(self) -> str:
        """Stable identity for this operation, such as ``GET /users/{userId}``."""
        return f"{self.method.value.upper()} {self.path}"

    @property
    def path_segments(self) -> tuple[str, ...]:
        """Non-empty path segments of the template."""
        return tuple(segment for segment in self.path.split("/") if segment)

    @property
    def path_parameter_names(self) -> tuple[str, ...]:
        """Template variable names appearing in the path, in order."""
        names: list[str] = []
        for segment in self.path_segments:
            if segment.startswith("{") and segment.endswith("}"):
                name = segment[1:-1].strip()
                if name and name not in names:
                    names.append(name)
        return tuple(names)

    @property
    def is_templated(self) -> bool:
        """``True`` when the path contains at least one template variable."""
        return bool(self.path_parameter_names)

    def parameters_in(self, location: ParameterLocation) -> tuple[Parameter, ...]:
        """Declared parameters travelling in one location."""
        return tuple(item for item in self.parameters if item.location is location)

    def schema_names(self) -> set[str]:
        """Every declared component schema this operation touches."""
        names: set[str] = set()
        for parameter in self.parameters:
            if parameter.value_schema is not None:
                names |= parameter.value_schema.referenced_names()
        if self.request_body is not None:
            for media in self.request_body.content:
                if media.value_schema is not None:
                    names |= media.value_schema.referenced_names()
        for response in self.responses:
            for media in response.content:
                if media.value_schema is not None:
                    names |= media.value_schema.referenced_names()
        return names


__all__ = [
    "MAX_SCHEMA_DEPTH",
    "DeclaredSecurity",
    "DiscoverySource",
    "Endpoint",
    "HttpMethod",
    "MediaTypeSchema",
    "Parameter",
    "ParameterLocation",
    "ParameterSource",
    "RequestBodySpec",
    "ResponseSpec",
    "SchemaKind",
    "SchemaSummary",
    "SecurityAlternative",
    "SecurityPosture",
    "SecurityRequirement",
    "SecurityScheme",
    "SecuritySchemeType",
]
