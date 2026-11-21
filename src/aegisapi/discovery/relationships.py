"""Structural relationship observation.

This module answers one question: how is this API *shaped*? It groups
operations that share a collection root, spots resources nested beneath an
identified parent, notices an identifier used in several places, and recognises
create/read/update/delete sets.

**Every output is a structural observation, never a finding.** That ``/users/
{userId}`` and ``/users/{userId}/orders`` form a parent-child pair says nothing
about whether either enforces authorisation. Deciding that requires sending
requests and comparing responses, which belongs to a later phase; asserting it
from path shape alone would be inventing vulnerabilities.

Phase 8 is intended to extend this into context-aware risk intelligence and
attack-path hypotheses. The seam is deliberate: observations are produced here
with enough structured ``detail`` for a scoring layer to consume, and that
layer can be added without changing the parsers.
"""

from __future__ import annotations

import re
from collections import defaultdict
from collections.abc import Iterable, Sequence

from aegisapi.models.discovery import RelationshipKind, RelationshipObservation
from aegisapi.models.endpoint import Endpoint, HttpMethod, ParameterLocation

MAX_OBSERVATIONS_PER_KIND = 100
"""How many observations of one kind are recorded.

A large generated API would otherwise produce thousands of shared-tag
observations, which buries the informative ones.
"""

MIN_GROUP_SIZE = 2
"""An observation needs at least two operations to be about a relationship."""

_IDENTIFIER_HINTS = ("id", "uuid", "guid", "key", "slug", "ref", "number", "code")
"""Substrings that suggest a parameter names a resource identifier.

A heuristic, and labelled as one. It informs which observations are recorded,
not whether anything is wrong.
"""

_TEMPLATE_SEGMENT = re.compile(r"^\{.+\}$")

_WRITE_METHODS = {HttpMethod.POST, HttpMethod.PUT, HttpMethod.PATCH, HttpMethod.DELETE}


def _is_template(segment: str) -> bool:
    """``True`` when a path segment is a template variable."""
    return bool(_TEMPLATE_SEGMENT.match(segment))


def looks_like_identifier(name: str) -> bool:
    """``True`` when a parameter name suggests a resource identifier.

    Heuristic by nature: ``userId`` and ``order_uuid`` match, ``limit`` does
    not. Used to decide which structural observations are worth recording.
    """
    lowered = name.strip().lower()
    if not lowered:
        return False
    return any(hint in lowered for hint in _IDENTIFIER_HINTS)


def static_prefix(endpoint: Endpoint) -> str:
    """Leading path segments up to the first template variable.

    ``/users/{userId}/orders`` has the static prefix ``/users``, which is the
    collection the operation ultimately acts within.
    """
    collected: list[str] = []
    for segment in endpoint.path_segments:
        if _is_template(segment):
            break
        collected.append(segment)
    return "/" + "/".join(collected) if collected else "/"


def _resource_root(endpoint: Endpoint) -> str:
    """The first static segment, which names the top-level resource."""
    for segment in endpoint.path_segments:
        if not _is_template(segment):
            return f"/{segment}"
    return "/"


def _is_parent_of(parent: Endpoint, child: Endpoint) -> bool:
    """``True`` when ``child``'s path is nested under ``parent``'s.

    The parent must end with a template variable, because that is what makes it
    an *identified* resource rather than a collection, and the child must have
    strictly more segments.
    """
    parent_segments = parent.path_segments
    child_segments = child.path_segments
    if not parent_segments or len(child_segments) <= len(parent_segments):
        return False
    if not _is_template(parent_segments[-1]):
        return False
    # Both sides must be the same sequence type: a tuple slice never compares
    # equal to a list, which would silently disable this observation.
    return child_segments[: len(parent_segments)] == parent_segments


def _sorted_keys(endpoints: Iterable[Endpoint]) -> list[str]:
    """Endpoint keys, sorted, for stable output."""
    return sorted({endpoint.key for endpoint in endpoints})


def _observe_shared_prefixes(endpoints: Sequence[Endpoint]) -> list[RelationshipObservation]:
    """Group operations that act within the same collection root."""
    groups: dict[str, list[Endpoint]] = defaultdict(list)
    for endpoint in endpoints:
        root = _resource_root(endpoint)
        if root != "/":
            groups[root].append(endpoint)

    observations: list[RelationshipObservation] = []
    for root, members in sorted(groups.items()):
        if len(members) < MIN_GROUP_SIZE:
            continue
        paths = sorted({member.path for member in members})
        observations.append(
            RelationshipObservation(
                kind=RelationshipKind.SHARED_PREFIX,
                subject=root,
                description=(
                    f"{len(members)} operation(s) across {len(paths)} path(s) act under "
                    f"the '{root}' resource root."
                ),
                endpoint_keys=_sorted_keys(members),
                detail={"path_count": str(len(paths)), "operation_count": str(len(members))},
            )
        )
    return observations[:MAX_OBSERVATIONS_PER_KIND]


def _observe_parent_child(endpoints: Sequence[Endpoint]) -> list[RelationshipObservation]:
    """Record resource paths nested beneath an identified parent resource."""
    by_path: dict[str, list[Endpoint]] = defaultdict(list)
    for endpoint in endpoints:
        by_path[endpoint.path].append(endpoint)

    observations: list[RelationshipObservation] = []
    paths = sorted(by_path)
    for parent_path in paths:
        parent_sample = by_path[parent_path][0]
        children: list[Endpoint] = []
        child_paths: set[str] = set()
        for child_path in paths:
            if child_path == parent_path:
                continue
            child_sample = by_path[child_path][0]
            if _is_parent_of(parent_sample, child_sample):
                children.extend(by_path[child_path])
                child_paths.add(child_path)
        if not children:
            continue
        observations.append(
            RelationshipObservation(
                kind=RelationshipKind.PARENT_CHILD,
                subject=parent_path,
                description=(
                    f"'{parent_path}' identifies a resource that {len(child_paths)} "
                    "nested path(s) hang beneath. Structural only: nesting does not "
                    "imply shared or inherited authorisation."
                ),
                endpoint_keys=_sorted_keys([*by_path[parent_path], *children]),
                detail={
                    "parent_path": parent_path,
                    "child_paths": ", ".join(sorted(child_paths)),
                    "identifier": ", ".join(parent_sample.path_parameter_names) or "unknown",
                },
            )
        )
    return observations[:MAX_OBSERVATIONS_PER_KIND]


def _observe_shared_identifiers(
    endpoints: Sequence[Endpoint],
) -> list[RelationshipObservation]:
    """Record identifier names that appear on more than one operation.

    Both path templates and identifier-shaped query parameters count: an
    identifier accepted in two places is exactly the structure later phases
    want to reason about.
    """
    groups: dict[str, list[Endpoint]] = defaultdict(list)
    for endpoint in endpoints:
        names = set(endpoint.path_parameter_names)
        for parameter in endpoint.parameters:
            if parameter.location in (
                ParameterLocation.QUERY,
                ParameterLocation.PATH,
            ) and looks_like_identifier(parameter.name):
                names.add(parameter.name)
        for name in names:
            if looks_like_identifier(name):
                groups[name].append(endpoint)

    observations: list[RelationshipObservation] = []
    for name, members in sorted(groups.items()):
        unique = {member.key: member for member in members}
        if len(unique) < MIN_GROUP_SIZE:
            continue
        observations.append(
            RelationshipObservation(
                kind=RelationshipKind.SHARED_IDENTIFIER,
                subject=name,
                description=(
                    f"The identifier '{name}' appears on {len(unique)} operation(s). "
                    "Structural only: this is not evidence that one operation's "
                    "identifier is accepted by another."
                ),
                endpoint_keys=_sorted_keys(unique.values()),
                detail={"identifier": name, "operation_count": str(len(unique))},
            )
        )
    return observations[:MAX_OBSERVATIONS_PER_KIND]


def _observe_crud_sets(endpoints: Sequence[Endpoint]) -> list[RelationshipObservation]:
    """Record create/read/update/delete style method sets over one resource.

    Grouped by static prefix rather than exact path, so a collection and its
    identified member (``/users`` and ``/users/{userId}``) are recognised as one
    resource, which is how a reader thinks about them.
    """
    groups: dict[str, list[Endpoint]] = defaultdict(list)
    for endpoint in endpoints:
        groups[static_prefix(endpoint)].append(endpoint)

    observations: list[RelationshipObservation] = []
    for prefix, members in sorted(groups.items()):
        methods = {member.method for member in members}
        if len(members) < MIN_GROUP_SIZE or not methods & _WRITE_METHODS:
            continue
        operations: list[str] = []
        if HttpMethod.POST in methods:
            operations.append("create")
        if HttpMethod.GET in methods:
            operations.append("read")
        if methods & {HttpMethod.PUT, HttpMethod.PATCH}:
            operations.append("update")
        if HttpMethod.DELETE in methods:
            operations.append("delete")
        if len(operations) < MIN_GROUP_SIZE:
            continue
        observations.append(
            RelationshipObservation(
                kind=RelationshipKind.CRUD_SET,
                subject=prefix,
                description=(
                    f"The '{prefix}' resource exposes {', '.join(operations)} operations "
                    f"({', '.join(sorted(method.value.upper() for method in methods))})."
                ),
                endpoint_keys=_sorted_keys(members),
                detail={
                    "operations": ", ".join(operations),
                    "methods": ", ".join(sorted(method.value.upper() for method in methods)),
                },
            )
        )
    return observations[:MAX_OBSERVATIONS_PER_KIND]


def _observe_shared_tags(endpoints: Sequence[Endpoint]) -> list[RelationshipObservation]:
    """Record the document's own grouping of operations by tag."""
    groups: dict[str, list[Endpoint]] = defaultdict(list)
    for endpoint in endpoints:
        for tag in endpoint.tags:
            groups[tag].append(endpoint)

    observations: list[RelationshipObservation] = []
    for tag, members in sorted(groups.items()):
        if len(members) < MIN_GROUP_SIZE:
            continue
        observations.append(
            RelationshipObservation(
                kind=RelationshipKind.SHARED_TAG,
                subject=tag,
                description=(
                    f"{len(members)} operation(s) are tagged '{tag}' by the specification."
                ),
                endpoint_keys=_sorted_keys(members),
                detail={"tag": tag, "operation_count": str(len(members))},
            )
        )
    return observations[:MAX_OBSERVATIONS_PER_KIND]


def _observe_shared_schemas(endpoints: Sequence[Endpoint]) -> list[RelationshipObservation]:
    """Record declared schemas referenced by more than one operation.

    Two operations that read and write the same declared resource are the
    clearest structural signal that they act on one thing, which is why schema
    sharing is tracked alongside path shape.
    """
    groups: dict[str, list[Endpoint]] = defaultdict(list)
    for endpoint in endpoints:
        for name in endpoint.schema_names():
            groups[name].append(endpoint)

    observations: list[RelationshipObservation] = []
    for name, members in sorted(groups.items()):
        unique = {member.key: member for member in members}
        if len(unique) < MIN_GROUP_SIZE:
            continue
        observations.append(
            RelationshipObservation(
                kind=RelationshipKind.SHARED_SCHEMA,
                subject=name,
                description=(
                    f"{len(unique)} operation(s) reference the '{name}' schema, so they "
                    "likely act on the same declared resource."
                ),
                endpoint_keys=_sorted_keys(unique.values()),
                detail={"schema": name, "operation_count": str(len(unique))},
            )
        )
    return observations[:MAX_OBSERVATIONS_PER_KIND]


def observe_relationships(endpoints: Sequence[Endpoint]) -> list[RelationshipObservation]:
    """Produce every structural observation for an endpoint inventory.

    Observations are ordered by kind so output is stable between runs, which
    keeps a stored discovery result diffable.

    None of these are security findings. They describe how the specification is
    organised, and they exist so Phase 8 has structure to reason over.
    """
    if not endpoints:
        return []
    return [
        *_observe_shared_prefixes(endpoints),
        *_observe_parent_child(endpoints),
        *_observe_shared_identifiers(endpoints),
        *_observe_crud_sets(endpoints),
        *_observe_shared_tags(endpoints),
        *_observe_shared_schemas(endpoints),
    ]


__all__ = [
    "MAX_OBSERVATIONS_PER_KIND",
    "MIN_GROUP_SIZE",
    "looks_like_identifier",
    "observe_relationships",
    "static_prefix",
]
