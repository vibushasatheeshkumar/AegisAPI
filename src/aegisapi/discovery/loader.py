"""Reading a specification file from the local filesystem.

A specification is untrusted input. It arrives from a client, a bug bounty
programme, or a repository, and AegisAPI's job is to read it without letting it
do anything.

Three defences live here:

* **YAML is parsed with ``yaml.safe_load`` only.** The unsafe loaders construct
  arbitrary Python objects from tags such as ``!!python/object/apply``, which
  turns reading a file into running code. ``safe_load`` cannot do that, and
  AegisAPI never calls anything else.
* **This module fetches nothing.** :func:`load_specification` accepts a local
  path and opens no socket. A specification served by the target under
  assessment is read by :func:`load_specification_bytes`, which is handed bytes
  that :mod:`aegisapi.discovery.probe` already retrieved through the scope-gated
  HTTP client. The split is the point: the only code that can reach a host is
  code holding a client bound to an authorised target, and a parser never
  resolves a URL of its own.
* **Size and alias budgets.** A file larger than :data:`MAX_SPECIFICATION_BYTES`
  is refused, and so is one using more YAML aliases than
  :data:`MAX_YAML_ALIASES`. See the note on that constant for what this does and
  does not protect against.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from aegisapi.core.exceptions import (
    InvalidSpecificationError,
    SpecificationNotFoundError,
)
from aegisapi.models.discovery import SpecificationFormat

MAX_SPECIFICATION_BYTES = 16 * 1024 * 1024
"""Largest specification file AegisAPI will read.

Generous enough for the largest public API documents, small enough that a
hostile file cannot exhaust memory through sheer length.
"""

MAX_YAML_ALIASES = 500
"""Most YAML aliases a specification may use.

A YAML file can nest anchors and aliases so that a small document expands into
an enormous structure - the "billion laughs" shape. The expansion happens
inside the parser, before AegisAPI can inspect anything, so the only cheap
defence is to count alias references in the raw text first and refuse an
implausible number.

This is a mitigation, not a guarantee: a smaller number of deeply nested
aliases can still expand sharply. The size cap bounds the input, and this cap
bounds the obvious attack. Treat a specification from a third party as
untrusted input regardless.
"""

_YAML_SUFFIXES = frozenset({".yaml", ".yml"})
_JSON_SUFFIXES = frozenset({".json"})

# A YAML alias reference: '*name' in a value position.
_YAML_ALIAS = re.compile(r"(?m)(?:^|[\s\[{,])\*[A-Za-z0-9_][^\s\[\]{},]*")


@dataclass(frozen=True)
class LoadedSpecification:
    """A specification document plus the provenance of where it came from.

    Exactly one of ``source_path`` and ``source_url`` is set, so a result always
    records whether the inventory came off this machine or off the target.
    """

    document: dict[str, Any]
    format: SpecificationFormat
    source_sha256: str
    byte_size: int
    source_path: Path | None = None
    """Resolved path, when the document was read from the filesystem."""

    source_url: str | None = None
    """URL it was retrieved from, when the target served it."""

    @property
    def source_label(self) -> str:
        """Provenance as one displayable string, whichever kind it is."""
        if self.source_url is not None:
            return self.source_url
        return str(self.source_path)

    @property
    def is_remote(self) -> bool:
        """``True`` when the document was retrieved over HTTP."""
        return self.source_url is not None


def _reject(message: str, *, hint: str | None = None) -> InvalidSpecificationError:
    """Build an :class:`InvalidSpecificationError` with an actionable hint."""
    return InvalidSpecificationError(message, hint=hint)


def detect_format(path: Path, text: str) -> SpecificationFormat:
    """Decide whether the file is JSON or YAML.

    The suffix decides when it is recognisable. Otherwise the first meaningful
    character does: a document opening with ``{`` is JSON. YAML is a superset
    of JSON, so either parser would accept a JSON file, but the format is
    recorded in the result and should be accurate.
    """
    suffix = path.suffix.lower()
    if suffix in _JSON_SUFFIXES:
        return SpecificationFormat.JSON
    if suffix in _YAML_SUFFIXES:
        return SpecificationFormat.YAML
    stripped = text.lstrip()
    return SpecificationFormat.JSON if stripped.startswith("{") else SpecificationFormat.YAML


def _read_bytes(path: Path) -> bytes:
    """Read the file, refusing anything that is not a plausible specification."""
    try:
        resolved = path.expanduser()
    except (OSError, RuntimeError) as exc:  # pragma: no cover - platform dependent
        raise _reject(f"The specification path is not usable: {path}") from exc

    if not resolved.exists():
        raise SpecificationNotFoundError(
            f"Specification file not found: {resolved}",
            hint="Pass a path to a local OpenAPI or Swagger document.",
        )
    if resolved.is_dir():
        raise SpecificationNotFoundError(
            f"Expected a specification file but found a directory: {resolved}"
        )

    try:
        size = resolved.stat().st_size
        if size > MAX_SPECIFICATION_BYTES:
            raise _reject(
                f"The specification file is larger than {MAX_SPECIFICATION_BYTES} bytes: "
                f"{resolved}",
                hint="AegisAPI refuses oversized documents rather than parsing them.",
            )
        return resolved.read_bytes()
    except OSError as exc:
        raise _reject(
            f"The specification file could not be read: {resolved}",
            hint=exc.strerror,
        ) from exc


def _decode(raw: bytes, source: object) -> str:
    """Decode the document as UTF-8, tolerating a byte-order mark."""
    try:
        return raw.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise _reject(
            f"The specification is not valid UTF-8 text: {source}",
            hint="Re-save the document as UTF-8.",
        ) from exc


def _parse_json(text: str, source: object) -> Any:
    """Parse JSON, reporting the position of a syntax error."""
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise _reject(
            f"The specification is not valid JSON: {source}",
            hint=f"{exc.msg} (line {exc.lineno}, column {exc.colno})",
        ) from exc


def _parse_yaml(text: str, source: object) -> Any:
    """Parse YAML safely, after checking the alias budget."""
    aliases = len(_YAML_ALIAS.findall(text))
    if aliases > MAX_YAML_ALIASES:
        raise _reject(
            f"The specification uses {aliases} YAML aliases, "
            f"more than the {MAX_YAML_ALIASES} AegisAPI will parse: {source}",
            hint="Heavy alias use can expand a small file into an enormous structure.",
        )

    try:
        # safe_load, always: the unsafe loaders can construct arbitrary Python
        # objects from a document, which would make parsing equivalent to
        # executing the file.
        return yaml.safe_load(text)
    except yaml.YAMLError as exc:
        detail = getattr(exc, "problem", None) or str(exc)
        mark = getattr(exc, "problem_mark", None)
        position = f" (line {mark.line + 1}, column {mark.column + 1})" if mark else ""
        raise _reject(
            f"The specification is not valid YAML: {source}",
            hint=f"{detail}{position}",
        ) from exc


def _deserialise(
    raw: bytes,
    *,
    specification_format: SpecificationFormat,
    source: object,
) -> dict[str, Any]:
    """Decode and parse raw bytes into a specification object.

    The single place a specification turns from bytes into a document,
    whichever side it arrived from. A remote document gets the same UTF-8
    strictness, the same ``safe_load``, and the same alias budget as a local
    file, because "the target served it" is not a reason to parse it more
    trustingly - it is a reason to parse it less so.
    """
    text = _decode(raw, source)
    if specification_format is SpecificationFormat.JSON:
        document = _parse_json(text, source)
    else:
        document = _parse_yaml(text, source)

    if document is None:
        raise _reject(
            f"The specification is empty: {source}",
            hint="An API specification must declare at least a version and paths.",
        )
    if not isinstance(document, dict):
        raise _reject(
            f"The specification must be an object at the top level: {source}",
            hint=f"Found {type(document).__name__}.",
        )
    return document


def load_specification(path: Path | str) -> LoadedSpecification:
    """Read and deserialise a local specification file.

    Args:
        path: Path to a JSON or YAML document on this machine.

    Returns:
        The document and its provenance. The content digest lets a later phase
        notice that the specification changed after a result was stored.

    Raises:
        SpecificationNotFoundError: If the path is missing or is a directory.
        InvalidSpecificationError: If the file is too large, not UTF-8, not
            valid JSON or YAML, or does not deserialise to an object.
    """
    source = Path(path)
    raw = _read_bytes(source)
    specification_format = detect_format(source, _decode(raw, source))
    document = _deserialise(raw, specification_format=specification_format, source=source)

    return LoadedSpecification(
        document=document,
        format=specification_format,
        source_path=source.expanduser().resolve(strict=False),
        source_sha256=hashlib.sha256(raw).hexdigest(),
        byte_size=len(raw),
    )


def format_from_content_type(content_type: str | None, text: str) -> SpecificationFormat:
    """Decide the format of a fetched document from its type, then its content.

    The declared type is taken when it is recognisable, and the first
    meaningful character decides otherwise - a server that serves
    ``openapi.json`` as ``text/plain`` is common enough that trusting the
    header alone would mislabel the document.
    """
    declared = (content_type or "").split(";", 1)[0].strip().lower()
    if declared.endswith("json") or declared in {"application/json", "text/json"}:
        return SpecificationFormat.JSON
    if "yaml" in declared or "yml" in declared:
        return SpecificationFormat.YAML
    return SpecificationFormat.JSON if text.lstrip().startswith("{") else SpecificationFormat.YAML


def load_specification_bytes(
    raw: bytes,
    *,
    source_url: str,
    content_type: str | None = None,
) -> LoadedSpecification:
    """Deserialise a specification that was retrieved over HTTP.

    This function performs no I/O. It is given bytes that
    :mod:`aegisapi.discovery.probe` already fetched through a scope-gated
    client, so the authorisation decision stays with the only component that
    can make it, and a parser never becomes a route to a host.

    Args:
        raw: The response body, exactly as received.
        source_url: The URL it came from, recorded as the result's provenance.
        content_type: The declared response content type, when there was one.

    Returns:
        The parsed document and its provenance, with ``source_url`` set.

    Raises:
        InvalidSpecificationError: If the body is too large, not UTF-8, not
            valid JSON or YAML, or does not deserialise to an object.
    """
    if len(raw) > MAX_SPECIFICATION_BYTES:
        raise _reject(
            f"The specification served by {source_url} is larger than "
            f"{MAX_SPECIFICATION_BYTES} bytes.",
            hint="AegisAPI refuses oversized documents rather than parsing them.",
        )

    specification_format = format_from_content_type(content_type, _decode(raw, source_url))
    document = _deserialise(raw, specification_format=specification_format, source=source_url)

    return LoadedSpecification(
        document=document,
        format=specification_format,
        source_url=source_url,
        source_sha256=hashlib.sha256(raw).hexdigest(),
        byte_size=len(raw),
    )


__all__ = [
    "MAX_SPECIFICATION_BYTES",
    "MAX_YAML_ALIASES",
    "LoadedSpecification",
    "detect_format",
    "format_from_content_type",
    "load_specification",
    "load_specification_bytes",
]
