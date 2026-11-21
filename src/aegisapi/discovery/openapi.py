"""OpenAPI 3.0 and 3.1 normalisation.

The two revisions differ very little in the parts AegisAPI reads: 3.1 aligns
schemas with JSON Schema and allows a type list, which
:mod:`aegisapi.discovery.schemas` already handles, and it adds no path or
security construct that changes how an operation is identified. They are
therefore parsed by one implementation and distinguished only in the recorded
version.

A malformed section is skipped and reported, never guessed at. If ``paths`` is
not an object, AegisAPI says so and produces no endpoints rather than inventing
an empty inventory that looks like a clean parse.
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
    SecurityScheme,
    SecuritySchemeType,
)

_SCHEME_TYPES = {
    "http": SecuritySchemeType.HTTP,
    "apikey": SecuritySchemeType.API_KEY,
    "oauth2": SecuritySchemeType.OAUTH2,
    "openidconnect": SecuritySchemeType.OPEN_ID_CONNECT,
    "mutualtls": SecuritySchemeType.UNKNOWN,
}

_PARAMETER_LOCATIONS = {
    "path": ParameterLocation.PATH,
    "query": ParameterLocation.QUERY,
    "header": ParameterLocation.HEADER,
    "cookie": ParameterLocation.COOKIE,
}


class OpenApi3Parser:
    """Normalises an OpenAPI 3.x document into an endpoint inventory."""

    def __init__(self, document: dict[str, Any], warnings: WarningCollector) -> None:
        self._document = document
        self._warnings = warnings
        self._resolver = ReferenceResolver(document)
        self._schemas = SchemaSummariser(self._resolver, warnings)

    def parse(self) -> ParsedSpecification:
        """Extract metadata, security declarations, and operations."""
        info = self._document.get("info")
        info = info if isinstance(info, dict) else {}

        schemes = self._parse_security_schemes()
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
            servers=self._parse_servers(self._document.get("servers"), "#/servers"),
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

    def _parse_servers(self, raw: Any, pointer: str) -> list[str]:
        """Read server URLs, keeping template variables verbatim.

        A templated URL such as ``https://{region}.example.com`` is recorded as
        declared. Substituting a default here would invent a host, so
        classification treats it as unresolved instead.
        """
        if raw is None:
            return []
        if not isinstance(raw, list):
            self._warnings.add(
                WarningCode.MALFORMED_SECTION,
                f"'servers' must be a list, found {type(raw).__name__}",
                pointer,
            )
            return []
        urls: list[str] = []
        for index, entry in enumerate(raw):
            if not isinstance(entry, dict):
                self._warnings.add(
                    WarningCode.MALFORMED_SECTION,
                    f"a server entry must be an object, found {type(entry).__name__}",
                    f"{pointer}/{index}",
                )
                continue
            url = text_or_none(entry.get("url"))
            if url is None:
                self._warnings.add(
                    WarningCode.MALFORMED_SECTION,
                    "a server entry has no 'url'",
                    f"{pointer}/{index}",
                )
                continue
            if url not in urls:
                urls.append(url)
        return urls

    def _parse_security_schemes(self) -> list[SecurityScheme]:
        """Read ``components.securitySchemes``.

        Declared OAuth2 and OpenID Connect URLs are recorded verbatim and never
        requested. Discovering an issuer's configuration would mean contacting
        a third party while merely reading a file.
        """
        components = self._document.get("components")
        if not isinstance(components, dict):
            return []
        raw = components.get("securitySchemes")
        if raw is None:
            return []
        if not isinstance(raw, dict):
            self._warnings.add(
                WarningCode.MALFORMED_SECTION,
                f"'securitySchemes' must be an object, found {type(raw).__name__}",
                "#/components/securitySchemes",
            )
            return []

        schemes: list[SecurityScheme] = []
        for name, entry in raw.items():
            pointer = f"#/components/securitySchemes/{name}"
            node = entry
            if is_reference(node):
                resolution = self._resolver.resolve(node["$ref"])
                if not resolution.ok:
                    self._warnings.add(
                        WarningCode.MISSING_REFERENCE,
                        f"security scheme {name!r} could not be resolved: {resolution.detail}",
                        pointer,
                    )
                    continue
                node = resolution.value
            if not isinstance(node, dict):
                self._warnings.add(
                    WarningCode.MALFORMED_SECTION,
                    f"security scheme {name!r} must be an object",
                    pointer,
                )
                continue

            raw_type = text_or_none(node.get("type"))
            scheme_type = _SCHEME_TYPES.get(
                (raw_type or "").replace("-", "").replace("_", "").lower(),
                SecuritySchemeType.UNKNOWN,
            )
            if scheme_type is SecuritySchemeType.UNKNOWN:
                self._warnings.add(
                    WarningCode.UNKNOWN_SECURITY_SCHEME_TYPE,
                    f"security scheme {name!r} declares unrecognised type {raw_type!r}",
                    pointer,
                )

            flows_raw = node.get("flows")
            flows = sorted(flows_raw) if isinstance(flows_raw, dict) else []
            schemes.append(
                SecurityScheme(
                    name=str(name),
                    type=scheme_type,
                    raw_type=raw_type,
                    scheme=text_or_none(node.get("scheme")),
                    bearer_format=text_or_none(node.get("bearerFormat")),
                    parameter_name=text_or_none(node.get("name")),
                    parameter_location=text_or_none(node.get("in")),
                    flows=flows,
                    scopes=_oauth_scopes(flows_raw),
                    open_id_connect_url=text_or_none(node.get("openIdConnectUrl")),
                    description=text_or_none(node.get("description")),
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

        endpoints: list[Endpoint] = []
        for path, raw_item in raw_paths.items():
            if len(endpoints) >= MAX_OPERATIONS:
                self._warnings.add(
                    WarningCode.UNSUPPORTED_FEATURE,
                    f"only the first {MAX_OPERATIONS} operations were normalised",
                    "#/paths",
                )
                break
            path_text = str(path)
            pointer = f"#/paths/{path_text}"
            item = self._resolve_path_item(raw_item, pointer, path_text)
            if item is None:
                continue
            endpoints.extend(
                self._parse_path_item(
                    path_text,
                    item,
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

    def _resolve_path_item(self, raw_item: Any, pointer: str, path: str) -> dict[str, Any] | None:
        """Resolve a path item, which may itself be a ``$ref``."""
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
                    f"path {path!r} could not be resolved: {resolution.detail}",
                    pointer,
                )
                return None
            item = resolution.value
        if not isinstance(item, dict):
            self._warnings.add(
                WarningCode.MALFORMED_SECTION,
                f"path {path!r} must map to an object, found {type(item).__name__}",
                pointer,
            )
            return None
        return item

    def _parse_path_item(
        self,
        path: str,
        item: dict[str, Any],
        *,
        defined_schemes: set[str],
        global_alternatives: list,
        global_undefined: list[str],
        global_anonymous: bool,
    ) -> list[Endpoint]:
        """Normalise every operation under one path."""
        path_pointer = f"#/paths/{path}"
        inherited = deduplicate_parameters(
            self._parse_parameters(
                item.get("parameters"),
                f"{path_pointer}/parameters",
                ParameterSource.PATH_ITEM,
            ),
            warnings=self._warnings,
            pointer=f"{path_pointer}/parameters",
            source=ParameterSource.PATH_ITEM,
        )
        path_servers = self._parse_servers(item.get("servers"), f"{path_pointer}/servers")

        endpoints: list[Endpoint] = []
        for method_key in HTTP_METHOD_KEYS:
            operation = item.get(method_key)
            if operation is None:
                continue
            pointer = operation_pointer(path, method_key)
            if not isinstance(operation, dict):
                self._warnings.add(
                    WarningCode.MALFORMED_SECTION,
                    f"operation must be an object, found {type(operation).__name__}",
                    pointer,
                )
                continue

            own = deduplicate_parameters(
                self._parse_parameters(
                    operation.get("parameters"),
                    f"{pointer}/parameters",
                    ParameterSource.OPERATION,
                ),
                warnings=self._warnings,
                pointer=f"{pointer}/parameters",
                source=ParameterSource.OPERATION,
            )
            operation_servers = self._parse_servers(operation.get("servers"), f"{pointer}/servers")

            endpoints.append(
                Endpoint(
                    method=HttpMethod(method_key),
                    path=path,
                    operation_id=text_or_none(operation.get("operationId")),
                    summary=text_or_none(operation.get("summary")),
                    description=text_or_none(operation.get("description")),
                    tags=string_list(operation.get("tags")),
                    deprecated=bool_or_none(operation.get("deprecated")),
                    parameters=merge_parameters(inherited, own),
                    request_body=self._parse_request_body(
                        operation.get("requestBody"), f"{pointer}/requestBody"
                    ),
                    responses=self._parse_responses(
                        operation.get("responses"), f"{pointer}/responses"
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
                    servers=operation_servers or path_servers,
                    source_pointer=pointer,
                )
            )
        return endpoints

    def _parse_parameters(self, raw: Any, pointer: str, source: ParameterSource) -> list[Parameter]:
        """Read a parameter list, resolving any ``$ref`` entries."""
        if raw is None:
            return []
        if not isinstance(raw, list):
            self._warnings.add(
                WarningCode.MALFORMED_SECTION,
                f"'parameters' must be a list, found {type(raw).__name__}",
                pointer,
            )
            return []

        parameters: list[Parameter] = []
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
            location = _PARAMETER_LOCATIONS.get(location_raw.lower())
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
                    deprecated=bool_or_none(node.get("deprecated")),
                    value_schema=self._schemas.summarise(
                        node.get("schema"), pointer=f"{entry_pointer}/schema"
                    ),
                    source=source,
                )
            )
        return parameters

    def _parse_request_body(self, raw: Any, pointer: str) -> RequestBodySpec | None:
        """Read a request body, resolving a ``$ref`` if present."""
        if raw is None:
            return None
        node = raw
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
                    f"request body could not be resolved: {resolution.detail}",
                    pointer,
                )
                return None
            node = resolution.value
        if not isinstance(node, dict):
            self._warnings.add(
                WarningCode.MALFORMED_SECTION,
                f"'requestBody' must be an object, found {type(node).__name__}",
                pointer,
            )
            return None

        return RequestBodySpec(
            required=bool_or_none(node.get("required")),
            description=text_or_none(node.get("description")),
            content=self._parse_content(node.get("content"), f"{pointer}/content"),
        )

    def _parse_content(self, raw: Any, pointer: str) -> list[MediaTypeSchema]:
        """Read a ``content`` map of media types to schemas."""
        if raw is None:
            return []
        if not isinstance(raw, dict):
            self._warnings.add(
                WarningCode.MALFORMED_SECTION,
                f"'content' must be an object, found {type(raw).__name__}",
                pointer,
            )
            return []

        media: list[MediaTypeSchema] = []
        for content_type, entry in raw.items():
            entry_pointer = f"{pointer}/{content_type}"
            schema_node = entry.get("schema") if isinstance(entry, dict) else None
            if not isinstance(entry, dict):
                self._warnings.add(
                    WarningCode.MALFORMED_SECTION,
                    f"media type {content_type!r} must map to an object",
                    entry_pointer,
                )
                continue
            media.append(
                MediaTypeSchema(
                    content_type=str(content_type),
                    value_schema=self._schemas.summarise(
                        schema_node, pointer=f"{entry_pointer}/schema"
                    ),
                )
            )
        return media

    def _parse_responses(self, raw: Any, pointer: str) -> list[ResponseSpec]:
        """Read the ``responses`` map.

        A missing or empty ``responses`` section produces no entries rather
        than an assumed ``200``. Later phases must be able to tell that the
        document said nothing.
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

            headers = node.get("headers")
            responses.append(
                ResponseSpec(
                    status_code=status_text,
                    description=text_or_none(node.get("description")),
                    content=self._parse_content(node.get("content"), f"{entry_pointer}/content"),
                    header_names=sorted(str(name) for name in headers)
                    if isinstance(headers, dict)
                    else [],
                )
            )
        return responses


def _oauth_scopes(flows: Any) -> dict[str, str]:
    """Collect declared OAuth2 scopes across every flow."""
    if not isinstance(flows, dict):
        return {}
    scopes: dict[str, str] = {}
    for flow in flows.values():
        if not isinstance(flow, dict):
            continue
        declared = flow.get("scopes")
        if isinstance(declared, dict):
            for name, description in declared.items():
                scopes[str(name)] = description if isinstance(description, str) else ""
    return scopes


__all__ = ["OpenApi3Parser"]
