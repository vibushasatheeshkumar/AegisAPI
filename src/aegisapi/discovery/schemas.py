"""Schema summarisation.

Later phases need to know what a request or response is *shaped* like: which
properties an object has, which are required, what an array holds, and which
fields look like identifiers. They do not need a JSON Schema evaluator, and
building one here would be a large, risky dependency on a specification far
broader than anything AegisAPI will assess.

So this module produces a bounded summary. It descends at most
:data:`~aegisapi.models.endpoint.MAX_SCHEMA_DEPTH` levels, stops at a cycle,
and records *why* it stopped on the node itself, so a later phase can tell
"this object has no properties" apart from "AegisAPI did not look further".
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from aegisapi.discovery.references import (
    ReferenceOutcome,
    ReferenceResolver,
    is_reference,
)
from aegisapi.models.discovery import ParseWarning, WarningCode
from aegisapi.models.endpoint import MAX_SCHEMA_DEPTH, SchemaKind, SchemaSummary

_COMPOSITION_KEYWORDS = ("allOf", "anyOf", "oneOf")
MAX_PROPERTIES_PER_SCHEMA = 200
"""How many properties of one object are summarised.

A document declaring more than this is either generated or hostile; either way,
the first two hundred are enough to reason about structure.
"""

MAX_ENUM_VALUES = 50
"""How many enumeration values are recorded per schema node."""


@dataclass
class WarningCollector:
    """Gathers parse warnings, de-duplicated and capped.

    Capped because one malformed section can otherwise produce a warning per
    operation, and a wall of identical messages hides the useful ones.
    """

    limit: int = 200
    _seen: set[tuple[str, str | None]] = field(default_factory=set)
    _warnings: list[ParseWarning] = field(default_factory=list)
    suppressed: int = 0

    def add(self, code: WarningCode, message: str, pointer: str | None = None) -> None:
        """Record a warning, ignoring an exact repeat."""
        key = (f"{code.value}:{message}", pointer)
        if key in self._seen:
            return
        if len(self._warnings) >= self.limit:
            self.suppressed += 1
            return
        self._seen.add(key)
        self._warnings.append(ParseWarning(code=code, message=message, pointer=pointer))

    @property
    def warnings(self) -> list[ParseWarning]:
        """Warnings collected so far, in order."""
        return list(self._warnings)


_OUTCOME_TO_KIND = {
    ReferenceOutcome.EXTERNAL: SchemaKind.UNRESOLVED_EXTERNAL,
    ReferenceOutcome.MISSING: SchemaKind.UNRESOLVED_MISSING,
    ReferenceOutcome.MALFORMED: SchemaKind.UNRESOLVED_MISSING,
    ReferenceOutcome.CIRCULAR: SchemaKind.CIRCULAR,
}

_OUTCOME_TO_WARNING = {
    ReferenceOutcome.EXTERNAL: WarningCode.EXTERNAL_REFERENCE,
    ReferenceOutcome.MISSING: WarningCode.MISSING_REFERENCE,
    ReferenceOutcome.MALFORMED: WarningCode.MISSING_REFERENCE,
    ReferenceOutcome.CIRCULAR: WarningCode.CIRCULAR_REFERENCE,
}


class SchemaSummariser:
    """Turns raw schema nodes into bounded :class:`SchemaSummary` values."""

    def __init__(
        self,
        resolver: ReferenceResolver,
        warnings: WarningCollector,
        *,
        max_depth: int = MAX_SCHEMA_DEPTH,
    ) -> None:
        self._resolver = resolver
        self._warnings = warnings
        self._max_depth = max_depth

    def summarise(
        self,
        node: Any,
        *,
        pointer: str,
        depth: int = 0,
        following: tuple[str, ...] = (),
    ) -> SchemaSummary | None:
        """Summarise one schema node.

        Args:
            node: The raw schema, a ``$ref`` object, or anything else the
                document put there.
            pointer: JSON pointer to the node, for warning messages.
            depth: Current recursion depth.
            following: ``$ref`` pointers already being followed, so a cycle is
                reported rather than recursed into.

        Returns:
            A summary, or ``None`` when the document declared nothing at all.
            ``None`` and "an empty schema" are different facts, and the
            distinction is preserved.
        """
        if node is None:
            return None
        if isinstance(node, bool):
            # JSON Schema allows `true`/`false` as a whole schema: everything
            # or nothing. There is no structure to summarise.
            return SchemaSummary(kind=SchemaKind.EMPTY)
        if not isinstance(node, dict):
            self._warnings.add(
                WarningCode.MALFORMED_SECTION,
                f"a schema must be an object, found {type(node).__name__}",
                pointer,
            )
            return SchemaSummary(kind=SchemaKind.EMPTY)

        if is_reference(node):
            return self._summarise_reference(node["$ref"], pointer, depth, following)

        if depth >= self._max_depth:
            self._warnings.add(
                WarningCode.SCHEMA_TRUNCATED,
                f"schema nesting deeper than {self._max_depth} levels was not summarised",
                pointer,
            )
            return SchemaSummary(kind=SchemaKind.TRUNCATED, type=_declared_type(node))

        return self._summarise_object(node, pointer, depth, following)

    def _summarise_reference(
        self,
        ref: str,
        pointer: str,
        depth: int,
        following: tuple[str, ...],
    ) -> SchemaSummary:
        """Resolve a ``$ref`` and summarise what it points at."""
        resolution = self._resolver.resolve(ref, following=following)
        name = self._resolver.component_name(ref) if ref.startswith("#") else None

        if not resolution.ok:
            kind = _OUTCOME_TO_KIND.get(resolution.outcome, SchemaKind.UNRESOLVED_MISSING)
            code = _OUTCOME_TO_WARNING.get(resolution.outcome, WarningCode.MISSING_REFERENCE)
            self._warnings.add(
                code,
                f"$ref {ref!r} was not resolved: {resolution.detail}",
                pointer,
            )
            return SchemaSummary(kind=kind, ref=ref, name=name)

        summary = self.summarise(
            resolution.value,
            pointer=resolution.pointer or pointer,
            depth=depth,
            following=(*following, ref),
        )
        if summary is None:
            return SchemaSummary(kind=SchemaKind.EMPTY, ref=ref, name=name)
        return summary.model_copy(update={"ref": ref, "name": name or summary.name})

    def _summarise_object(
        self,
        node: dict[str, Any],
        pointer: str,
        depth: int,
        following: tuple[str, ...],
    ) -> SchemaSummary:
        """Summarise a plain schema object."""
        properties: dict[str, SchemaSummary] = {}
        raw_properties = node.get("properties")
        if isinstance(raw_properties, dict):
            for index, (name, child) in enumerate(raw_properties.items()):
                if index >= MAX_PROPERTIES_PER_SCHEMA:
                    self._warnings.add(
                        WarningCode.SCHEMA_TRUNCATED,
                        f"only the first {MAX_PROPERTIES_PER_SCHEMA} properties were summarised",
                        pointer,
                    )
                    break
                child_summary = self.summarise(
                    child,
                    pointer=f"{pointer}/properties/{name}",
                    depth=depth + 1,
                    following=following,
                )
                if child_summary is not None:
                    properties[str(name)] = child_summary
        elif raw_properties is not None:
            self._warnings.add(
                WarningCode.MALFORMED_SECTION,
                f"'properties' must be an object, found {type(raw_properties).__name__}",
                pointer,
            )

        items = self.summarise(
            node.get("items"),
            pointer=f"{pointer}/items",
            depth=depth + 1,
            following=following,
        )

        composition, branches = self._summarise_composition(node, pointer, depth, following)
        declared_type = _declared_type(node)
        summary = SchemaSummary(
            kind=SchemaKind.RESOLVED,
            type=declared_type,
            format=_as_text(node.get("format")),
            nullable=_as_bool(node.get("nullable")),
            required=_string_list(node.get("required")),
            properties=properties,
            items=items,
            enum_values=_enum_values(node.get("enum")),
            composition=composition,
            composed_of=branches,
            minimum=_as_number(node.get("minimum")),
            maximum=_as_number(node.get("maximum")),
            min_length=_as_int(node.get("minLength")),
            max_length=_as_int(node.get("maxLength")),
        )

        if (
            declared_type is None
            and not properties
            and items is None
            and not branches
            and not summary.enum_values
        ):
            return summary.model_copy(update={"kind": SchemaKind.EMPTY})
        return summary

    def _summarise_composition(
        self,
        node: dict[str, Any],
        pointer: str,
        depth: int,
        following: tuple[str, ...],
    ) -> tuple[str | None, list[SchemaSummary]]:
        """Summarise ``allOf`` / ``anyOf`` / ``oneOf`` branches, if present."""
        for keyword in _COMPOSITION_KEYWORDS:
            raw = node.get(keyword)
            if raw is None:
                continue
            if not isinstance(raw, list):
                self._warnings.add(
                    WarningCode.MALFORMED_SECTION,
                    f"'{keyword}' must be a list, found {type(raw).__name__}",
                    pointer,
                )
                continue
            branches: list[SchemaSummary] = []
            for index, branch in enumerate(raw):
                summary = self.summarise(
                    branch,
                    pointer=f"{pointer}/{keyword}/{index}",
                    depth=depth + 1,
                    following=following,
                )
                if summary is not None:
                    branches.append(summary)
            if branches:
                return keyword, branches
        return None, []


def _declared_type(node: dict[str, Any]) -> str | None:
    """Read a declared type.

    OpenAPI 3.1 follows JSON Schema in allowing a list of types, which is
    rendered as ``"string|null"`` so the information is not lost.
    """
    raw = node.get("type")
    if isinstance(raw, str):
        return raw.strip() or None
    if isinstance(raw, list):
        values = [item.strip() for item in raw if isinstance(item, str) and item.strip()]
        return "|".join(values) if values else None
    return None


def _as_text(value: Any) -> str | None:
    """Return a trimmed string, or ``None`` for anything else."""
    return value.strip() or None if isinstance(value, str) else None


def _as_bool(value: Any) -> bool | None:
    """Return a bool only when the document actually gave one."""
    return value if isinstance(value, bool) else None


def _string_list(value: Any) -> list[str]:
    """Return the string members of a list, in order, de-duplicated."""
    if not isinstance(value, list):
        return []
    result: list[str] = []
    for item in value:
        if isinstance(item, str) and item.strip() and item.strip() not in result:
            result.append(item.strip())
    return result


def _as_number(value: Any) -> float | None:
    """Return a float for a numeric literal, None for anything else."""
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    return None


def _as_int(value: Any) -> int | None:
    """Return an int for an integer-valued literal, None for anything else."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float) and value.is_integer():
        return int(value)
    return None


def _enum_values(value: Any) -> list[str]:
    """Render enumeration values as text, capped."""
    if not isinstance(value, list):
        return []
    rendered: list[str] = []
    for item in value[:MAX_ENUM_VALUES]:
        rendered.append(item if isinstance(item, str) else repr(item))
    return rendered


__all__ = [
    "MAX_ENUM_VALUES",
    "MAX_PROPERTIES_PER_SCHEMA",
    "SchemaSummariser",
    "WarningCollector",
]
