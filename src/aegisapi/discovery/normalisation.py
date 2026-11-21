"""Helpers shared by the OpenAPI 3 and Swagger 2 parsers.

The two dialects differ in where they put things, not in what an operation
fundamentally is. Everything that is genuinely common - reading optional text,
merging inherited parameters, and interpreting a ``security`` list - lives here
so the two parsers cannot drift apart on the parts that matter.

The security helpers are the important ones. Getting the OR-of-ANDs semantics
wrong, or losing the difference between "no requirement declared" and
"declared as not required", would mislead every later phase that reads the
inventory.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from aegisapi.discovery.schemas import WarningCollector
from aegisapi.models.discovery import ParseWarning, WarningCode
from aegisapi.models.endpoint import (
    DeclaredSecurity,
    Endpoint,
    HttpMethod,
    Parameter,
    ParameterSource,
    SecurityAlternative,
    SecurityPosture,
    SecurityRequirement,
    SecurityScheme,
)

HTTP_METHOD_KEYS: tuple[str, ...] = tuple(method.value for method in HttpMethod)
"""Keys inside a path item that denote an operation."""

MAX_OPERATIONS = 5000
"""How many operations AegisAPI will normalise from one document.

A document with more than this is either generated at a scale AegisAPI is not
the right tool for, or constructed to exhaust memory. Either way, stopping and
saying so is better than grinding.
"""


@dataclass
class ParsedSpecification:
    """What a dialect parser extracted from one document."""

    endpoints: list[Endpoint] = field(default_factory=list)
    security_schemes: list[SecurityScheme] = field(default_factory=list)
    global_security: list[SecurityAlternative] = field(default_factory=list)
    servers: list[str] = field(default_factory=list)
    title: str | None = None
    api_version: str | None = None
    description: str | None = None
    warnings: list[ParseWarning] = field(default_factory=list)


def text_or_none(value: Any) -> str | None:
    """Return trimmed text, or ``None`` when the document gave none.

    Anything that is not a string is treated as absent rather than coerced: a
    summary of ``42`` is a malformed document, and inventing ``"42"`` would
    hide that.
    """
    return (value.strip() or None) if isinstance(value, str) else None


def bool_or_none(value: Any) -> bool | None:
    """Return a bool only when the document actually declared one.

    ``None`` means "the specification did not say", which is different from
    ``False`` and must stay different.
    """
    return value if isinstance(value, bool) else None


def string_list(value: Any) -> list[str]:
    """Return the non-empty strings in a list, in order, de-duplicated."""
    if not isinstance(value, list):
        return []
    result: list[str] = []
    for item in value:
        if isinstance(item, str) and item.strip() and item.strip() not in result:
            result.append(item.strip())
    return result


def escape_pointer_token(token: str) -> str:
    """Encode one JSON pointer token, per RFC 6901."""
    return token.replace("~", "~0").replace("/", "~1")


def operation_pointer(path: str, method: str) -> str:
    """JSON pointer to an operation inside a document."""
    return f"#/paths/{escape_pointer_token(path)}/{method}"


def merge_parameters(
    path_level: list[Parameter],
    operation_level: list[Parameter],
) -> list[Parameter]:
    """Combine inherited and operation parameters.

    A path-level parameter applies to every operation under that path, and an
    operation may override one by declaring the same name and location. The
    override replaces the inherited declaration rather than merging with it,
    which is what the specification requires and what an operator reading the
    inventory will expect.

    Order is path-level first, then operation-only additions, so the result is
    stable across runs.
    """
    merged: dict[tuple[str, str], Parameter] = {}
    for parameter in path_level:
        merged[parameter.key] = parameter
    for parameter in operation_level:
        merged[parameter.key] = parameter
    return list(merged.values())


def deduplicate_parameters(
    parameters: list[Parameter],
    *,
    warnings: WarningCollector,
    pointer: str,
    source: ParameterSource,
) -> list[Parameter]:
    """Drop repeats of the same name and location within one level.

    The specification requires uniqueness there. A repeat is a document bug, so
    the first declaration is kept and the duplicate reported rather than
    silently winning.
    """
    seen: dict[tuple[str, str], Parameter] = {}
    for parameter in parameters:
        if parameter.key in seen:
            warnings.add(
                WarningCode.MALFORMED_SECTION,
                (
                    f"parameter {parameter.name!r} in {parameter.location.value} is declared "
                    f"more than once at {source.value} level; the first was kept"
                ),
                pointer,
            )
            continue
        seen[parameter.key] = parameter
    return list(seen.values())


def parse_security_requirements(
    raw: Any,
    *,
    defined_schemes: set[str],
    warnings: WarningCollector,
    pointer: str,
) -> tuple[list[SecurityAlternative], list[str], bool]:
    """Interpret a ``security`` list.

    A ``security`` value is a list of requirement objects. The list is an OR:
    satisfying any one entry is enough. Each entry is an AND: every scheme in
    it must be satisfied. An **empty entry** (``{}``) means a request may be
    anonymous, which is the document explicitly permitting unauthenticated
    access.

    Returns:
        The alternatives, the names of referenced schemes the document never
        defines, and whether an empty alternative was present.

    The undefined-scheme list matters: an operation that requires
    ``"bearerAuth"`` when no such scheme is declared has insufficient security
    metadata, and a later phase must not act as though it understood it.
    """
    if raw is None:
        return [], [], False
    if not isinstance(raw, list):
        warnings.add(
            WarningCode.MALFORMED_SECTION,
            f"'security' must be a list, found {type(raw).__name__}",
            pointer,
        )
        return [], [], False

    alternatives: list[SecurityAlternative] = []
    undefined: list[str] = []
    permits_anonymous = False

    for index, entry in enumerate(raw):
        entry_pointer = f"{pointer}/{index}"
        if not isinstance(entry, dict):
            warnings.add(
                WarningCode.MALFORMED_SECTION,
                f"a security requirement must be an object, found {type(entry).__name__}",
                entry_pointer,
            )
            continue
        if not entry:
            permits_anonymous = True
            alternatives.append(SecurityAlternative(schemes=[]))
            continue

        requirements: list[SecurityRequirement] = []
        for name, scopes in entry.items():
            scheme_name = str(name).strip()
            if not scheme_name:
                warnings.add(
                    WarningCode.MALFORMED_SECTION,
                    "a security requirement names an empty scheme",
                    entry_pointer,
                )
                continue
            if scheme_name not in defined_schemes and scheme_name not in undefined:
                undefined.append(scheme_name)
                warnings.add(
                    WarningCode.UNDEFINED_SECURITY_SCHEME,
                    (
                        f"security scheme {scheme_name!r} is required but never defined "
                        "in the document"
                    ),
                    entry_pointer,
                )
            requirements.append(
                SecurityRequirement(scheme_name=scheme_name, scopes=string_list(scopes))
            )
        if requirements:
            alternatives.append(SecurityAlternative(schemes=requirements))

    return alternatives, undefined, permits_anonymous


def resolve_declared_security(
    *,
    operation_raw: Any,
    operation_present: bool,
    global_alternatives: list[SecurityAlternative],
    global_permits_anonymous: bool,
    global_undefined: list[str],
    defined_schemes: set[str],
    warnings: WarningCollector,
    pointer: str,
) -> DeclaredSecurity:
    """Decide what a specification claims about authenticating one operation.

    The four postures are kept distinct on purpose:

    * an operation that declares its own requirements **overrides** the global
      ones entirely, rather than adding to them;
    * ``security: []`` on an operation is an **explicit** statement that no
      authentication is required, which is different from saying nothing;
    * an operation that declares nothing **inherits** the document's global
      requirements;
    * when neither declares anything, the document is simply silent. That is a
      gap in metadata, not a finding.
    """
    if operation_present:
        alternatives, undefined, permits_anonymous = parse_security_requirements(
            operation_raw,
            defined_schemes=defined_schemes,
            warnings=warnings,
            pointer=f"{pointer}/security",
        )
        if isinstance(operation_raw, list) and not operation_raw:
            # security: [] - the operation states authentication is not needed.
            return DeclaredSecurity(
                posture=SecurityPosture.EXPLICITLY_OPTIONAL,
                alternatives=[SecurityAlternative(schemes=[])],
            )
        if permits_anonymous and len(alternatives) == 1:
            return DeclaredSecurity(
                posture=SecurityPosture.EXPLICITLY_OPTIONAL,
                alternatives=alternatives,
                undefined_schemes=undefined,
            )
        if alternatives:
            return DeclaredSecurity(
                posture=SecurityPosture.OPERATION_OVERRIDE,
                alternatives=alternatives,
                undefined_schemes=undefined,
            )
        # A malformed operation-level declaration leaves nothing usable. Say so
        # rather than falling back to the global requirements, which the
        # operation was trying to replace.
        return DeclaredSecurity(
            posture=SecurityPosture.NOT_DECLARED,
            undefined_schemes=undefined,
        )

    if global_alternatives:
        posture = (
            SecurityPosture.EXPLICITLY_OPTIONAL
            if global_permits_anonymous and len(global_alternatives) == 1
            else SecurityPosture.INHERITED_GLOBAL
        )
        return DeclaredSecurity(
            posture=posture,
            alternatives=global_alternatives,
            undefined_schemes=list(global_undefined),
        )

    return DeclaredSecurity(posture=SecurityPosture.NOT_DECLARED)


def deduplicate_endpoints(
    endpoints: list[Endpoint],
    *,
    warnings: WarningCollector,
) -> list[Endpoint]:
    """Keep one endpoint per method and path.

    A duplicate can arise from a document listing the same path twice, or from
    a path item ``$ref`` that resolves onto an already-parsed path. The first
    declaration wins and the repeat is reported, because picking the later one
    would make the inventory depend on dictionary ordering.
    """
    unique: dict[str, Endpoint] = {}
    for endpoint in endpoints:
        if endpoint.key in unique:
            warnings.add(
                WarningCode.DUPLICATE_OPERATION,
                f"{endpoint.key} is declared more than once; the first declaration was kept",
                endpoint.source_pointer,
            )
            continue
        unique[endpoint.key] = endpoint
    return list(unique.values())


__all__ = [
    "HTTP_METHOD_KEYS",
    "MAX_OPERATIONS",
    "ParsedSpecification",
    "bool_or_none",
    "deduplicate_endpoints",
    "deduplicate_parameters",
    "escape_pointer_token",
    "merge_parameters",
    "operation_pointer",
    "parse_security_requirements",
    "resolve_declared_security",
    "string_list",
    "text_or_none",
]
