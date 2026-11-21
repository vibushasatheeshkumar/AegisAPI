"""Swagger 2.0 normalisation.

Swagger 2.0 expresses the same ideas differently, and each difference is a
place where a careless parser loses information:

* The server is split across ``schemes``, ``host``, and ``basePath`` instead of
  a ``servers`` list. ``basePath`` is folded into the **server URL**, not into
  each path, which is exactly how OpenAPI 3 expresses the same thing
  (``servers: [https://host/v2]`` with paths relative to it). Doing it the other
  way - prefixing every path - would double the prefix once the server URL also
  carried it, and would silently classify paths against the wrong part of a
  target's scope.
* A request body is a parameter with ``in: body``, and form fields are
  parameters with ``in: formData``. Both become a request body here, so later
  phases see one shape.
* Content types come from ``consumes`` and ``produces``, which may be declared
  at document level and overridden per operation.
* Schemas live in ``definitions`` and security in ``securityDefinitions``.

Paths are therefore recorded exactly as the document declares them, and the
prefix lives on the server URL.
"""

from __future__ import annotations

from typing import Any

from aegisapi.discovery.normalisation import (
    HTTP_METHOD_KEYS,
    MAX_OPERATIONS,
    ParsedSpecification,
    bool_or_none,
    deduplicate_endpoints,
    deduplicate_parameters,
    merge_parameters,
    operation_pointer,
    parse_security_requirements,
    resolve_declared_security,
    string_list,
    text_or_none,
)
from aegisapi.discovery.references import ReferenceResolver, is_reference
from aegisapi.discovery.schemas import SchemaSummariser, WarningCollector
from aegisapi.models.discovery import WarningCode
from aegisapi.models.endpoint import (
    Endpoint,
    HttpMethod,
    MediaTypeSchema,
    Parameter,
    ParameterLocation,
    ParameterSource,
    RequestBodySpec,
    ResponseSpec,
    SchemaKind,
    SchemaSummary,
    SecurityScheme,
    SecuritySchemeType,
)

_DEFAULT_CONSUMES = "application/json"
_DEFAULT_PRODUCES = "application/json"

_SCHEME_TYPES = {
    "basic": SecuritySchemeType.BASIC,
    "apikey": SecuritySchemeType.API_KEY,
    "oauth2": SecuritySchemeType.OAUTH2,
}

_PARAMETER_LOCATIONS = {
    "path": ParameterLocation.PATH,
    "query": ParameterLocation.QUERY,
    "header": ParameterLocation.HEADER,
    "formdata": ParameterLocation.FORM_DATA,
}


class Swagger2Parser:
    """Normalises a Swagger 2.0 document into an endpoint inventory."""

    def __init__(self, document: dict[str, Any], warnings: WarningCollector) -> None:
        self._document = document
        self._warnings = warnings
        self._resolver = ReferenceResolver(document)
        self._schemas = SchemaSummariser(self._resolver, warnings)
        self._base_path = self._parse_base_path()

    def parse(self) -> ParsedSpecification:
        """Extract metadata, security declarations, and operations."""
        info = self._document.get("info")
        info = info if isinstance(info, dict) else {}

        schemes = self._parse_security_definitions()
        defined = {scheme.name for scheme in schemes}
        global_alternatives, global_undefined, global_anonymous = parse_security_requirements(
            self._document.get("security"),
            defined_schemes=defined,
            warnings=self._warnings,
            pointer="#/security",
        )

        result = ParsedSpecification(
            security_schemes=schemes,
            global_security=global_alternatives,
            servers=self._parse_servers(),
            title=text_or_none(info.get("title")),
            api_version=text_or_none(info.get("version")),
            description=text_or_none(info.get("description")),
        )
        result.endpoints = self._parse_paths(
            defined_schemes=defined,
            global_alternatives=global_alternatives,
            global_undefined=global_undefined,
            global_anonymous=global_anonymous,
        )
        return result

    def _parse_base_path(self) -> str:
        """Read ``basePath``, normalised to either empty or ``/prefix``."""
        base = text_or_none(self._document.get("basePath"))
        if base is None or base == "/":
            return ""
        if not base.startswith("/"):
            self._warnings.add(
                WarningCode.MALFORMED_SECTION,
                f"'basePath' should start with '/', found {base!r}",
                "#/basePath",
            )
            base = f"/{base}"
        return base.rstrip("/")

    def _parse_servers(self) -> list[str]:
        """Build server URLs from ``schemes``, ``host``, and ``basePath``.

        When ``host`` is absent the specification means "the host serving this
        document", which a local file cannot tell us. The base path alone is
        then recorded as a relative server, which classification resolves
        against the registered target's origin. With neither host nor basePath
        the document declares no server at all, and classification falls back
        to the target's base URL.
        """
        host = text_or_none(self._document.get("host"))
        schemes = [
            scheme.lower()
            for scheme in string_list(self._document.get("schemes"))
            if scheme.lower() in {"http", "https"}
        ]
        if host is None:
            return [self._base_path] if self._base_path else []
        if not schemes:
            # No scheme declared. Record the authority without inventing one;
            # classification resolves it against the target's scheme.
            return [f"//{host}{self._base_path}"]
        return [f"{scheme}://{host}{self._base_path}" for scheme in schemes]

    def _parse_security_definitions(self) -> list[SecurityScheme]:
        """Read ``securityDefinitions``.

        OAuth2 ``authorizationUrl`` and ``tokenUrl`` values are recorded as
        declared flows and scopes only. Nothing is requested.
        """
        raw = self._document.get("securityDefinitions")
        if raw is None:
            return []
        if not isinstance(raw, dict):
            self._warnings.add(
                WarningCode.MALFORMED_SECTION,
                f"'securityDefinitions' must be an object, found {type(raw).__name__}",
                "#/securityDefinitions",
            )
            return []

        schemes: list[SecurityScheme] = []
        for name, entry in raw.items():
            pointer = f"#/securityDefinitions/{name}"
            if not isinstance(entry, dict):
                self._warnings.add(
                    WarningCode.MALFORMED_SECTION,
                    f"security definition {name!r} must be an object",
                    pointer,
                )
                continue

            raw_type = text_or_none(entry.get("type"))
            scheme_type = _SCHEME_TYPES.get((raw_type or "").lower(), SecuritySchemeType.UNKNOWN)
            if scheme_type is SecuritySchemeType.UNKNOWN:
                self._warnings.add(
                    WarningCode.UNKNOWN_SECURITY_SCHEME_TYPE,
                    f"security definition {name!r} declares unrecognised type {raw_type!r}",
                    pointer,
                )

            flow = text_or_none(entry.get("flow"))
            declared_scopes = entry.get("scopes")
            schemes.append(
                SecurityScheme(
                    name=str(name),
                    type=scheme_type,
                    raw_type=raw_type,
                    scheme="basic" if scheme_type is SecuritySchemeType.BASIC else None,
                    parameter_name=text_or_none(entry.get("name")),
                    parameter_location=text_or_none(entry.get("in")),
                    flows=[flow] if flow else [],
                    scopes={
                        str(key): value if isinstance(value, str) else ""
                        for key, value in declared_scopes.items()
                    }
                    if isinstance(declared_scopes, dict)
                    else {},
                    description=text_or_none(entry.get("description")),
                )
            )
        return schemes

    def _parse_paths(
        self,
        *,
        defined_schemes: set[str],
        global_alternatives: list,
        global_undefined: list[str],
        global_anonymous: bool,
    ) -> list[Endpoint]:
        """Walk ``paths`` and normalise every operation."""
        raw_paths = self._document.get("paths")
        if raw_paths is None:
            self._warnings.add(
                WarningCode.NO_OPERATIONS, "the document declares no 'paths' section"
            )
            return []
        if not isinstance(raw_paths, dict):
            self._warnings.add(
                WarningCode.MALFORMED_SECTION,
                f"'paths' must be an object, found {type(raw_paths).__name__}",
                "#/paths",
            )
            return []

        document_consumes = string_list(self._document.get("consumes"))
        document_produces = string_list(self._document.get("produces"))

        endpoints: list[Endpoint] = []
        for path, raw_item in raw_paths.items():
            if len(endpoints) >= MAX_OPERATIONS:
                self._warnings.add(
                    WarningCode.UNSUPPORTED_FEATURE,
                    f"only the first {MAX_OPERATIONS} operations were normalised",
                    "#/paths",
                )
                break
            declared_path = str(path)
            pointer = f"#/paths/{declared_path}"
            item = raw_item
            if is_reference(item):
                resolution = self._resolver.resolve(item["$ref"])
                if not resolution.ok:
                    code = (
                        WarningCode.EXTERNAL_REFERENCE
                        if resolution.outcome.value == "external"
                        else WarningCode.MISSING_REFERENCE
                    )
                    self._warnings.add(
                        code,
                        f"path {declared_path!r} could not be resolved: {resolution.detail}",
                        pointer,
                    )
                    continue
                item = resolution.value
            if not isinstance(item, dict):
                self._warnings.add(
                    WarningCode.MALFORMED_SECTION,
                    f"path {declared_path!r} must map to an object",
                    pointer,
                )
                continue

            endpoints.extend(
                self._parse_path_item(
                    declared_path,
                    item,
                    document_consumes=document_consumes,
                    document_produces=document_produces,
                    defined_schemes=defined_schemes,
                    global_alternatives=global_alternatives,
                    global_undefined=global_undefined,
                    global_anonymous=global_anonymous,
                )
            )

        endpoints = deduplicate_endpoints(endpoints, warnings=self._warnings)
        if not endpoints:
            self._warnings.add(WarningCode.NO_OPERATIONS, "the document declares no operations")
        return endpoints

    def _parse_path_item(
        self,
        declared_path: str,
        item: dict[str, Any],
        *,
        document_consumes: list[str],
        document_produces: list[str],
        defined_schemes: set[str],
        global_alternatives: list,
        global_undefined: list[str],
        global_anonymous: bool,
    ) -> list[Endpoint]:
        """Normalise every operation under one path."""
        path_pointer = f"#/paths/{declared_path}"

        inherited_params, inherited_body = self._split_parameters(
            item.get("parameters"),
            f"{path_pointer}/parameters",
            ParameterSource.PATH_ITEM,
        )
        inherited_params = deduplicate_parameters(
            inherited_params,
            warnings=self._warnings,
            pointer=f"{path_pointer}/parameters",
            source=ParameterSource.PATH_ITEM,
        )

        endpoints: list[Endpoint] = []
        for method_key in HTTP_METHOD_KEYS:
            operation = item.get(method_key)
            if operation is None:
                continue
            pointer = operation_pointer(declared_path, method_key)
            if not isinstance(operation, dict):
                self._warnings.add(
                    WarningCode.MALFORMED_SECTION,
                    f"operation must be an object, found {type(operation).__name__}",
                    pointer,
                )
                continue

            own_params, own_body = self._split_parameters(
                operation.get("parameters"),
                f"{pointer}/parameters",
                ParameterSource.OPERATION,
            )
            own_params = deduplicate_parameters(
                own_params,
                warnings=self._warnings,
                pointer=f"{pointer}/parameters",
                source=ParameterSource.OPERATION,
            )

            consumes = string_list(operation.get("consumes")) or document_consumes
            produces = string_list(operation.get("produces")) or document_produces
            parameters = merge_parameters(inherited_params, own_params)
            body_source = own_body if own_body is not None else inherited_body

            endpoints.append(
                Endpoint(
                    method=HttpMethod(method_key),
                    path=declared_path,
                    operation_id=text_or_none(operation.get("operationId")),
                    summary=text_or_none(operation.get("summary")),
                    description=text_or_none(operation.get("description")),
                    tags=string_list(operation.get("tags")),
                    deprecated=bool_or_none(operation.get("deprecated")),
                    parameters=parameters,
                    request_body=self._build_request_body(body_source, parameters, consumes),
                    responses=self._parse_responses(
                        operation.get("responses"), f"{pointer}/responses", produces
                    ),
                    declared_security=resolve_declared_security(
                        operation_raw=operation.get("security"),
                        operation_present="security" in operation,
                        global_alternatives=global_alternatives,
                        global_permits_anonymous=global_anonymous,
                        global_undefined=global_undefined,
                        defined_schemes=defined_schemes,
                        warnings=self._warnings,
                        pointer=pointer,
                    ),
                    servers=[],
                    source_pointer=pointer,
                    consumes=consumes,
                    produces=produces,
                )
            )
        return endpoints

    def _split_parameters(
        self, raw: Any, pointer: str, source: ParameterSource
    ) -> tuple[list[Parameter], dict[str, Any] | None]:
        """Separate ordinary parameters from the single ``in: body`` parameter.

        Swagger 2.0 allows at most one body parameter. A second one is a
        document bug: the first is kept and the repeat reported.
        """
        if raw is None:
            return [], None
        if not isinstance(raw, list):
            self._warnings.add(
                WarningCode.MALFORMED_SECTION,
                f"'parameters' must be a list, found {type(raw).__name__}",
                pointer,
            )
            return [], None

        parameters: list[Parameter] = []
        body: dict[str, Any] | None = None

        for index, entry in enumerate(raw):
            entry_pointer = f"{pointer}/{index}"
            node = entry
            if is_reference(node):
                resolution = self._resolver.resolve(node["$ref"])
                if not resolution.ok:
                    code = (
                        WarningCode.EXTERNAL_REFERENCE
                        if resolution.outcome.value == "external"
                        else WarningCode.MISSING_REFERENCE
                    )
                    self._warnings.add(
                        code,
                        f"parameter could not be resolved: {resolution.detail}",
                        entry_pointer,
                    )
                    continue
                node = resolution.value
            if not isinstance(node, dict):
                self._warnings.add(
                    WarningCode.MALFORMED_SECTION,
                    f"a parameter must be an object, found {type(node).__name__}",
                    entry_pointer,
                )
                continue

            name = text_or_none(node.get("name"))
            location_raw = text_or_none(node.get("in"))
            if name is None or location_raw is None:
                self._warnings.add(
                    WarningCode.MALFORMED_SECTION,
                    "a parameter must declare both 'name' and 'in'",
                    entry_pointer,
                )
                continue

            if location_raw.lower() == "body":
                if body is not None:
                    self._warnings.add(
                        WarningCode.MALFORMED_SECTION,
                        "more than one 'body' parameter was declared; the first was kept",
                        entry_pointer,
                    )
                    continue
                body = {**node, "_pointer": entry_pointer}
                continue

            location = _PARAMETER_LOCATIONS.get(location_raw.replace("-", "").lower())
            if location is None:
                self._warnings.add(
                    WarningCode.MALFORMED_SECTION,
                    f"parameter {name!r} declares unknown location {location_raw!r}",
                    entry_pointer,
                )
                continue

            parameters.append(
                Parameter(
                    name=name,
                    location=location,
                    required=bool_or_none(node.get("required")),
                    description=text_or_none(node.get("description")),
                    value_schema=self._parameter_schema(node, entry_pointer),
                    source=source,
                )
            )
        return parameters, body

    def _parameter_schema(self, node: dict[str, Any], pointer: str) -> SchemaSummary | None:
        """Summarise a non-body parameter's type.

        Swagger 2.0 puts ``type``, ``format``, and ``items`` directly on the
        parameter rather than under a ``schema``, so the fields are lifted into
        the same summary shape the rest of AegisAPI uses.
        """
        if "schema" in node:
            return self._schemas.summarise(node["schema"], pointer=f"{pointer}/schema")
        if "type" not in node and "items" not in node:
            return None
        synthetic = {
            key: node[key]
            for key in ("type", "format", "items", "enum", "required")
            if key in node and key != "required"
        }
        return self._schemas.summarise(synthetic, pointer=pointer)

    def _build_request_body(
        self,
        body: dict[str, Any] | None,
        parameters: list[Parameter],
        consumes: list[str],
    ) -> RequestBodySpec | None:
        """Express a body or form parameters as an OpenAPI-style request body."""
        content_types = consumes or [_DEFAULT_CONSUMES]

        if body is not None:
            pointer = str(body.get("_pointer", "#"))
            summary = self._schemas.summarise(body.get("schema"), pointer=f"{pointer}/schema")
            return RequestBodySpec(
                required=bool_or_none(body.get("required")),
                description=text_or_none(body.get("description")),
                content=[
                    MediaTypeSchema(content_type=content_type, value_schema=summary)
                    for content_type in content_types
                ],
            )

        form_fields = [
            parameter
            for parameter in parameters
            if parameter.location is ParameterLocation.FORM_DATA
        ]
        if not form_fields:
            return None

        properties = {
            field.name: field.value_schema or SchemaSummary(kind=SchemaKind.EMPTY)
            for field in form_fields
        }
        required = [field.name for field in form_fields if field.required]
        return RequestBodySpec(
            required=bool(required) or None,
            description=None,
            content=[
                MediaTypeSchema(
                    content_type=content_type,
                    value_schema=SchemaSummary(
                        type="object", properties=properties, required=required
                    ),
                )
                for content_type in content_types
            ],
        )

    def _parse_responses(self, raw: Any, pointer: str, produces: list[str]) -> list[ResponseSpec]:
        """Read the ``responses`` map.

        Swagger 2.0 puts a single ``schema`` on a response and takes its media
        types from ``produces``, so one declared schema becomes one entry per
        produced content type.
        """
        if raw is None:
            return []
        if not isinstance(raw, dict):
            self._warnings.add(
                WarningCode.MALFORMED_SECTION,
                f"'responses' must be an object, found {type(raw).__name__}",
                pointer,
            )
            return []

        content_types = produces or [_DEFAULT_PRODUCES]
        responses: list[ResponseSpec] = []
        for status, entry in raw.items():
            status_text = str(status)
            entry_pointer = f"{pointer}/{status_text}"
            node = entry
            if is_reference(node):
                resolution = self._resolver.resolve(node["$ref"])
                if not resolution.ok:
                    code = (
                        WarningCode.EXTERNAL_REFERENCE
                        if resolution.outcome.value == "external"
                        else WarningCode.MISSING_REFERENCE
                    )
                    self._warnings.add(
                        code,
                        f"response {status_text!r} could not be resolved: {resolution.detail}",
                        entry_pointer,
                    )
                    responses.append(ResponseSpec(status_code=status_text))
                    continue
                node = resolution.value
            if not isinstance(node, dict):
                self._warnings.add(
                    WarningCode.MALFORMED_SECTION,
                    f"response {status_text!r} must be an object",
                    entry_pointer,
                )
                continue

            summary = self._schemas.summarise(node.get("schema"), pointer=f"{entry_pointer}/schema")
            headers = node.get("headers")
            responses.append(
                ResponseSpec(
                    status_code=status_text,
                    description=text_or_none(node.get("description")),
                    content=[
                        MediaTypeSchema(content_type=content_type, value_schema=summary)
                        for content_type in content_types
                    ]
                    if summary is not None
                    else [],
                    header_names=sorted(str(name) for name in headers)
                    if isinstance(headers, dict)
                    else [],
                )
            )
        return responses


__all__ = ["Swagger2Parser"]
