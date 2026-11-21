"""Automatic test fixture generation from OpenAPI schemas.

Generates plausible, valid values for path parameters so that the input
validation and configuration checks can run against templated endpoints like
``GET /users/{userId}`` without the operator having to declare anything.

Generation rules, in priority order for each parameter:

1. If the schema declares an enumeration, use the first value.
2. If the schema declares a UUID/GUID format, use a fixed test UUID.
3. If the schema declares an integer or number type, use the minimum if one is
   declared, otherwise ``"1"``.
4. If the schema declares a string type with a minimum length, pad to that
   length; otherwise use ``"1"`` for ID-like parameter names or ``"test"`` for
   everything else.
5. If no schema is available, fall back to the name heuristic.

Generated values are always safe, synthetic, and obviously non-production.
They never contain SQL, shell metacharacters, path traversal, or SSRF targets.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from aegisapi.models.endpoint import Endpoint, ParameterLocation, SchemaSummary

_ID_WORDS = frozenset({"id", "key", "num", "code", "ref", "no", "pk", "uid", "uuid"})

_TEST_UUID = "00000000-0000-0000-0000-000000000001"


@dataclass(frozen=True)
class EndpointFixtures:
    """Auto-generated fixtures for one endpoint.

    Holds path parameter values derived from the endpoint's OpenAPI schema.
    An empty ``path_values`` means either the endpoint is not templated or no
    value could be generated (which is recorded as a skip, not an error).
    """

    path_values: dict[str, str] = field(default_factory=dict)

    @property
    def has_path_values(self) -> bool:
        """``True`` when at least one path parameter value was generated."""
        return bool(self.path_values)


def fill_path_template(path: str, values: dict[str, str]) -> str | None:
    """Substitute all template variables in ``path`` using ``values``.

    Returns the filled path, or ``None`` when any variable was not supplied.
    A path that still contains ``{`` after substitution would be sent
    literally to the server and produce a meaningless result, so ``None``
    is the signal to skip rather than guess.
    """
    filled = path
    for name, value in values.items():
        filled = filled.replace(f"{{{name}}}", value)
    if "{" in filled or "}" in filled:
        return None
    return filled


def _schema_path_value(param_name: str, schema: SchemaSummary | None) -> str:
    """Derive one valid path parameter value from an OpenAPI schema.

    The returned value is always a string because path parameters travel as
    text; callers that need a typed value must parse it themselves.
    """
    if schema is None:
        return _id_fallback(param_name)

    if schema.enum_values:
        return schema.enum_values[0]

    fmt = (schema.format or "").lower()
    if fmt in ("uuid", "guid"):
        return _TEST_UUID

    if schema.type in ("integer", "number"):
        if schema.minimum is not None:
            val = schema.minimum
            return str(int(val)) if schema.type == "integer" else str(val)
        return "1"

    if schema.type == "string":
        if fmt in ("uuid", "guid"):
            return _TEST_UUID
        min_len = schema.min_length
        if min_len is not None and min_len > 4:
            return "a" * min_len
        return _id_fallback(param_name)

    return _id_fallback(param_name)


def _id_fallback(name: str) -> str:
    """Use ``"1"`` for identifier-like names, ``"test"`` for everything else."""
    lower = name.lower()
    if any(word in lower for word in _ID_WORDS):
        return "1"
    return "test"


def generate_endpoint_fixtures(endpoint: Endpoint) -> EndpointFixtures:
    """Generate auto fixtures for one endpoint.

    For non-templated endpoints returns an empty ``EndpointFixtures``.
    For templated endpoints generates one value per path parameter, drawing
    from the parameter's declared schema when one is available.
    """
    if not endpoint.is_templated:
        return EndpointFixtures()

    path_params = {p.name: p for p in endpoint.parameters_in(ParameterLocation.PATH)}
    path_values: dict[str, str] = {}
    for name in endpoint.path_parameter_names:
        param = path_params.get(name)
        schema = param.value_schema if param is not None else None
        path_values[name] = _schema_path_value(name, schema)

    return EndpointFixtures(path_values=path_values)


def generate_fixtures(endpoints: list[Endpoint]) -> dict[str, EndpointFixtures]:
    """Generate fixtures for all endpoints, keyed by ``endpoint.key``.

    Non-templated endpoints are included with empty fixtures so a lookup by
    key always succeeds.
    """
    return {ep.key: generate_endpoint_fixtures(ep) for ep in endpoints}


__all__ = [
    "EndpointFixtures",
    "fill_path_template",
    "generate_endpoint_fixtures",
    "generate_fixtures",
]
