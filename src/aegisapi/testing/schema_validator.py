"""Pure schema validation logic, independent of HTTP or check infrastructure.

Validates a parsed JSON value against a :class:`~aegisapi.models.endpoint.SchemaSummary`
and returns structured :class:`SchemaViolation` objects — never raw response values,
so this module cannot leak sensitive data into reports.

Design constraints:

* **No network access.** The validator takes already-parsed values, never URLs.
* **No value leakage.** Violations describe types and positions, not values.
  ``actual`` says ``"integer"`` rather than ``"42"`` so a response body cannot
  inject sensitive data into a finding.
* **Bounded output.** Validation stops after :data:`MAX_VIOLATIONS` per call so
  one malformed response cannot produce a report-sized finding.
* **Bounded recursion.** Depth is capped at :data:`MAX_DEPTH` to handle
  accidental or adversarial circular references without crashing.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from aegisapi.models.endpoint import SchemaSummary

MAX_VIOLATIONS = 20
"""Maximum violations returned per top-level validate_against_schema call."""

MAX_DEPTH = 6
"""Maximum recursion depth into nested objects and arrays."""

MAX_ITEMS_CHECKED = 10
"""Maximum array items validated when an items schema is declared."""


@dataclass(frozen=True)
class SchemaViolation:
    """One discrepancy between a value and its declared schema.

    Describes position and expected constraint — never the actual value —
    so a violation record cannot contain sensitive response data.
    """

    path: str
    """JSON path to the offending value, e.g. ``$.items[0].price``."""

    code: str
    """Machine-readable violation type: ``wrong_type``, ``missing_required``,
    ``invalid_enum``, ``below_minimum``, ``above_maximum``,
    ``below_min_length``, ``above_max_length``,
    ``anyof_no_match``, ``oneof_no_match``, ``oneof_multiple_match``."""

    expected: str
    """Human-readable description of what was expected (never a secret)."""

    actual: str
    """The JSON type name or structural description of what arrived."""

    message: str
    """One sentence suitable for a finding's explanation."""


# Python type for each JSON Schema primitive type.
_TYPE_MAP: dict[str, type | tuple[type, ...]] = {
    "string": str,
    "integer": int,
    "number": (int, float),
    "boolean": bool,
    "object": dict,
    "array": list,
    "null": type(None),
}


def _json_type_name(value: Any) -> str:
    """Return the JSON type name for any Python value."""
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, float):
        return "number"
    if isinstance(value, str):
        return "string"
    if isinstance(value, dict):
        return "object"
    if isinstance(value, list):
        return "array"
    if value is None:
        return "null"
    return type(value).__name__


def _check_type(value: Any, expected_type: str, path: str) -> SchemaViolation | None:
    """Return a wrong_type violation, or None when the type matches."""
    # Python's bool is a subclass of int, so isinstance(True, int) is True.
    # Treat boolean values as not matching integer/number to avoid false passes.
    if expected_type in ("integer", "number") and isinstance(value, bool):
        return SchemaViolation(
            path=path,
            code="wrong_type",
            expected=expected_type,
            actual="boolean",
            message=f"Expected {expected_type}, got boolean",
        )
    expected_py = _TYPE_MAP.get(expected_type)
    if expected_py is None:
        return None
    if not isinstance(value, expected_py):
        return SchemaViolation(
            path=path,
            code="wrong_type",
            expected=expected_type,
            actual=_json_type_name(value),
            message=f"Expected {expected_type}, got {_json_type_name(value)}",
        )
    return None


def _check_numeric_constraints(
    value: int | float, schema: SchemaSummary, path: str
) -> list[SchemaViolation]:
    out: list[SchemaViolation] = []
    if schema.minimum is not None and value < schema.minimum:
        out.append(SchemaViolation(
            path=path,
            code="below_minimum",
            expected=f">= {schema.minimum}",
            actual="below minimum",
            message=f"Value is below declared minimum of {schema.minimum}",
        ))
    if schema.maximum is not None and value > schema.maximum:
        out.append(SchemaViolation(
            path=path,
            code="above_maximum",
            expected=f"<= {schema.maximum}",
            actual="above maximum",
            message=f"Value is above declared maximum of {schema.maximum}",
        ))
    return out


def _check_string_constraints(value: str, schema: SchemaSummary, path: str) -> list[SchemaViolation]:
    out: list[SchemaViolation] = []
    length = len(value)
    if schema.min_length is not None and length < schema.min_length:
        out.append(SchemaViolation(
            path=path,
            code="below_min_length",
            expected=f"length >= {schema.min_length}",
            actual=f"length {length}",
            message=f"String length {length} is below declared minLength of {schema.min_length}",
        ))
    if schema.max_length is not None and length > schema.max_length:
        out.append(SchemaViolation(
            path=path,
            code="above_max_length",
            expected=f"length <= {schema.max_length}",
            actual=f"length {length}",
            message=f"String length {length} is above declared maxLength of {schema.max_length}",
        ))
    return out


def _validate_object(
    value: dict, schema: SchemaSummary, *, path: str, depth: int
) -> list[SchemaViolation]:
    out: list[SchemaViolation] = []
    for prop_name in schema.required:
        if prop_name not in value:
            out.append(SchemaViolation(
                path=f"{path}.{prop_name}",
                code="missing_required",
                expected="present",
                actual="absent",
                message=f"Required property '{prop_name}' is missing",
            ))
            if len(out) >= MAX_VIOLATIONS:
                return out
    for prop_name, prop_schema in schema.properties.items():
        if prop_name in value:
            sub = validate_against_schema(
                value[prop_name], prop_schema, path=f"{path}.{prop_name}", _depth=depth
            )
            out.extend(sub)
            if len(out) >= MAX_VIOLATIONS:
                return out[:MAX_VIOLATIONS]
    return out


def _validate_array(
    value: list, schema: SchemaSummary, *, path: str, depth: int
) -> list[SchemaViolation]:
    if schema.items is None:
        return []
    out: list[SchemaViolation] = []
    for i, item in enumerate(value[:MAX_ITEMS_CHECKED]):
        sub = validate_against_schema(
            item, schema.items, path=f"{path}[{i}]", _depth=depth
        )
        out.extend(sub)
        if len(out) >= MAX_VIOLATIONS:
            return out[:MAX_VIOLATIONS]
    return out


def _validate_composition(
    value: Any, schema: SchemaSummary, *, path: str, depth: int
) -> list[SchemaViolation]:
    if not schema.composed_of:
        return []
    comp = schema.composition
    branch_violations = [
        validate_against_schema(value, branch, path=path, _depth=depth)
        for branch in schema.composed_of
    ]
    if comp == "allOf":
        combined: list[SchemaViolation] = []
        for bv in branch_violations:
            combined.extend(bv)
        return combined[:MAX_VIOLATIONS]
    if comp == "anyOf":
        if any(len(bv) == 0 for bv in branch_violations):
            return []
        return [SchemaViolation(
            path=path,
            code="anyof_no_match",
            expected=f"to match one of {len(schema.composed_of)} anyOf schemas",
            actual=_json_type_name(value),
            message=(
                f"Value does not match any of the {len(schema.composed_of)} "
                "declared anyOf schemas"
            ),
        )]
    if comp == "oneOf":
        passing = [i for i, bv in enumerate(branch_violations) if len(bv) == 0]
        if len(passing) == 1:
            return []
        if len(passing) == 0:
            return [SchemaViolation(
                path=path,
                code="oneof_no_match",
                expected=f"to match exactly one of {len(schema.composed_of)} oneOf schemas",
                actual=_json_type_name(value),
                message=(
                    f"Value does not match any of the {len(schema.composed_of)} "
                    "declared oneOf schemas"
                ),
            )]
        return [SchemaViolation(
            path=path,
            code="oneof_multiple_match",
            expected=f"to match exactly one of {len(schema.composed_of)} oneOf schemas",
            actual=f"matches {len(passing)}",
            message=(
                f"Value matches {len(passing)} of the declared oneOf schemas; "
                "must match exactly one"
            ),
        )]
    return []


def validate_against_schema(
    value: Any,
    schema: SchemaSummary,
    *,
    path: str = "$",
    _depth: int = 0,
) -> list[SchemaViolation]:
    """Validate *value* against *schema* and return all violations found.

    Args:
        value: The parsed JSON value (Python ``dict``, ``list``, ``str``,
            ``int``, ``float``, ``bool``, or ``None``).
        schema: The declared schema to validate against.
        path: JSON path prefix for violation locations (default ``"$"``).
        _depth: Internal recursion depth counter. Callers leave this unset.

    Returns:
        A list of :class:`SchemaViolation` objects, empty when the value is
        valid. At most :data:`MAX_VIOLATIONS` entries are returned.
    """
    if _depth > MAX_DEPTH:
        return []

    # Null handling: short-circuit before type checks.
    if value is None:
        if schema.type == "null":
            return []
        if schema.nullable:
            return []
        if schema.type:
            return [SchemaViolation(
                path=path,
                code="wrong_type",
                expected=schema.type,
                actual="null",
                message=f"Expected {schema.type}, got null",
            )]
        return []

    # Composition schemas delegate entirely to their branches.
    if schema.composition and schema.composed_of:
        return _validate_composition(value, schema, path=path, depth=_depth + 1)

    out: list[SchemaViolation] = []

    # Type check — stop further checks if the type itself is wrong, since
    # property/constraint checks on the wrong type would produce noise.
    if schema.type:
        violation = _check_type(value, schema.type, path)
        if violation is not None:
            return [violation]

    # Enum check
    if schema.enum_values and value not in schema.enum_values:
        display = schema.enum_values[:5]
        out.append(SchemaViolation(
            path=path,
            code="invalid_enum",
            expected=f"one of: {display}",
            actual=_json_type_name(value),
            message="Value is not in the declared enumeration",
        ))

    # Numeric constraint checks
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        out.extend(_check_numeric_constraints(value, schema, path))

    # String constraint checks
    if isinstance(value, str):
        out.extend(_check_string_constraints(value, schema, path))

    # Object property validation
    if isinstance(value, dict) and schema.type in (None, "object"):
        out.extend(_validate_object(value, schema, path=path, depth=_depth + 1))

    # Array item validation
    if isinstance(value, list) and schema.type in (None, "array"):
        out.extend(_validate_array(value, schema, path=path, depth=_depth + 1))

    return out[:MAX_VIOLATIONS]


__all__ = ["MAX_DEPTH", "MAX_ITEMS_CHECKED", "MAX_VIOLATIONS", "SchemaViolation", "validate_against_schema"]
