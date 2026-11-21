"""``$ref`` resolution, strictly inside the document.

A ``$ref`` is a URI, which means a naive resolver is a fetcher: point one at
``http://169.254.169.254/`` or ``file:///etc/shadow`` and a parse becomes a
request or a file read. AegisAPI resolves **local pointers only**
(``#/components/schemas/User``) and reports everything else without touching
it.

Outcomes are values rather than exceptions, because an unresolvable reference
is usually a fact about the document worth reporting, not a reason to abandon
the whole inventory. The caller decides, and
:class:`~aegisapi.models.discovery.ParseWarning` is how it tells the operator.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any

MAX_REFERENCE_CHAIN = 32
"""How many ``$ref`` hops may be followed before the chain is called circular.

A pointer chain longer than this is either a cycle or a document pathological
enough that refusing to follow it is the right answer.
"""


class ReferenceOutcome(StrEnum):
    """Why a reference did or did not resolve."""

    RESOLVED = "resolved"
    EXTERNAL = "external"
    """The reference pointed outside the document. Never fetched."""

    MISSING = "missing"
    """A local pointer addressed something the document does not contain."""

    CIRCULAR = "circular"
    """Following the chain came back to a pointer already being followed."""

    MALFORMED = "malformed"
    """The reference was not a usable JSON pointer."""


@dataclass(frozen=True)
class Resolution:
    """The result of resolving one ``$ref``."""

    outcome: ReferenceOutcome
    value: Any = None
    pointer: str | None = None
    """Canonical local pointer that was resolved, when one was."""

    detail: str | None = None
    """Why resolution failed, for a warning message."""

    @property
    def ok(self) -> bool:
        """``True`` when a value was produced."""
        return self.outcome is ReferenceOutcome.RESOLVED


def is_reference(node: Any) -> bool:
    """``True`` when ``node`` is a ``$ref`` object."""
    return isinstance(node, dict) and isinstance(node.get("$ref"), str)


def unescape_pointer_token(token: str) -> str:
    """Decode one JSON pointer token.

    RFC 6901 escapes ``~`` as ``~0`` and ``/`` as ``~1``. The order matters:
    decoding ``~1`` first would turn ``~01`` into ``/`` instead of ``~1``.
    """
    return token.replace("~1", "/").replace("~0", "~")


def split_pointer(pointer: str) -> list[str]:
    """Split a local JSON pointer into decoded tokens."""
    body = pointer.lstrip("#")
    if not body or body == "/":
        return []
    return [unescape_pointer_token(token) for token in body.lstrip("/").split("/")]


class ReferenceResolver:
    """Resolves local ``$ref`` pointers against one document."""

    def __init__(self, document: dict[str, Any]) -> None:
        self._document = document
        self._cache: dict[str, Resolution] = {}

    def resolve(self, ref: str, *, following: tuple[str, ...] = ()) -> Resolution:
        """Resolve one reference.

        Args:
            ref: The ``$ref`` string, verbatim.
            following: Pointers already being followed on this chain, used to
                detect a cycle.

        Returns:
            A :class:`Resolution`. External and missing references return an
            outcome rather than raising, so the caller can record a warning and
            carry on with the rest of the document.
        """
        reference = ref.strip()
        if not reference:
            return Resolution(ReferenceOutcome.MALFORMED, detail="the reference is empty")

        if not reference.startswith("#"):
            return Resolution(
                ReferenceOutcome.EXTERNAL,
                pointer=reference,
                detail="references outside this document are not resolved or fetched",
            )
        if len(reference) > 1 and not reference.startswith("#/"):
            return Resolution(
                ReferenceOutcome.MALFORMED,
                pointer=reference,
                detail="a local reference must start with '#/'",
            )

        if reference in following:
            return Resolution(
                ReferenceOutcome.CIRCULAR,
                pointer=reference,
                detail="the reference chain returns to this pointer",
            )
        if len(following) >= MAX_REFERENCE_CHAIN:
            return Resolution(
                ReferenceOutcome.CIRCULAR,
                pointer=reference,
                detail=f"the reference chain exceeded {MAX_REFERENCE_CHAIN} hops",
            )

        cached = self._cache.get(reference)
        if cached is not None and cached.outcome is not ReferenceOutcome.CIRCULAR:
            return cached

        resolution = self._lookup(reference)
        if resolution.ok and is_reference(resolution.value):
            # A pointer to another pointer. Follow it, carrying the chain so a
            # cycle is caught rather than recursed into.
            resolution = self.resolve(resolution.value["$ref"], following=(*following, reference))

        if resolution.outcome is not ReferenceOutcome.CIRCULAR:
            self._cache[reference] = resolution
        return resolution

    def _lookup(self, reference: str) -> Resolution:
        """Walk the document along a validated local pointer."""
        node: Any = self._document
        for token in split_pointer(reference):
            if isinstance(node, dict):
                if token not in node:
                    return Resolution(
                        ReferenceOutcome.MISSING,
                        pointer=reference,
                        detail=f"the document has no {token!r} at that location",
                    )
                node = node[token]
                continue
            if isinstance(node, list):
                try:
                    index = int(token)
                except ValueError:
                    return Resolution(
                        ReferenceOutcome.MALFORMED,
                        pointer=reference,
                        detail=f"{token!r} is not a valid list index",
                    )
                if not 0 <= index < len(node):
                    return Resolution(
                        ReferenceOutcome.MISSING,
                        pointer=reference,
                        detail=f"index {index} is out of range",
                    )
                node = node[index]
                continue
            return Resolution(
                ReferenceOutcome.MISSING,
                pointer=reference,
                detail=f"cannot descend into a {type(node).__name__} at {token!r}",
            )
        return Resolution(ReferenceOutcome.RESOLVED, value=node, pointer=reference)

    def component_name(self, pointer: str) -> str | None:
        """Last token of a pointer, which is a component's name.

        ``#/components/schemas/User`` gives ``User``, which is what a reader and
        relationship analysis both want to see.
        """
        tokens = split_pointer(pointer)
        return tokens[-1] if tokens else None


__all__ = [
    "MAX_REFERENCE_CHAIN",
    "ReferenceOutcome",
    "ReferenceResolver",
    "Resolution",
    "is_reference",
    "split_pointer",
    "unescape_pointer_token",
]
