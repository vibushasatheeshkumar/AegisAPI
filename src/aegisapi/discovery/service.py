"""The discovery pipeline.

One function runs the whole sequence: load, detect, parse, observe structure,
classify against scope. It exists so the CLI stays thin and so a later phase
can run discovery without going through Typer.

No step in this pipeline opens a network connection.
"""

from __future__ import annotations

from pathlib import Path

from aegisapi import __version__
from aegisapi.core.logging import get_logger
from aegisapi.discovery.classification import classify_endpoints
from aegisapi.discovery.loader import LoadedSpecification, load_specification
from aegisapi.discovery.normalisation import ParsedSpecification
from aegisapi.discovery.openapi import OpenApi3Parser
from aegisapi.discovery.relationships import observe_relationships
from aegisapi.discovery.schemas import WarningCollector
from aegisapi.discovery.swagger import Swagger2Parser
from aegisapi.discovery.versions import DetectedVersion, detect_version
from aegisapi.models.discovery import (
    DISCOVERY_SCHEMA_VERSION,
    DiscoveryResult,
    SpecificationInfo,
    SpecificationVersion,
)
from aegisapi.models.target import Target

_logger = get_logger(__name__)


def parse_specification(
    loaded: LoadedSpecification,
    detected: DetectedVersion,
    warnings: WarningCollector,
) -> ParsedSpecification:
    """Dispatch to the parser for the detected dialect."""
    if detected.version is SpecificationVersion.SWAGGER_20:
        return Swagger2Parser(loaded.document, warnings).parse()
    return OpenApi3Parser(loaded.document, warnings).parse()


def discover_from_specification(
    path: Path | str,
    *,
    target: Target,
) -> DiscoveryResult:
    """Run discovery for one specification file against one target.

    Args:
        path: Local path to a JSON or YAML OpenAPI/Swagger document.
        target: The registered target to classify endpoints against. It is read
            only; discovery never modifies a target or widens its scope.

    Returns:
        A :class:`~aegisapi.models.discovery.DiscoveryResult` holding the
        normalised inventory, declared security metadata, structural
        observations, scope classifications, and any parse warnings.

    Raises:
        SpecificationNotFoundError: If the file is missing.
        InvalidSpecificationError: If the file cannot be parsed.
        UnsupportedSpecificationError: If the dialect is not supported.
    """
    loaded = load_specification(path)
    detected = detect_version(loaded.document)
    warnings = WarningCollector()

    parsed = parse_specification(loaded, detected, warnings)
    endpoints = list(parsed.endpoints)

    classified = classify_endpoints(
        endpoints,
        target=target,
        specification_servers=parsed.servers,
        warnings=warnings,
    )
    relationships = observe_relationships(endpoints)

    _logger.debug(
        "Parsed %d operation(s) from %s as %s",
        len(endpoints),
        loaded.source_label,
        detected.version.value,
    )

    return DiscoveryResult(
        schema_version=DISCOVERY_SCHEMA_VERSION,
        target_name=target.name,
        target_base_url=target.base_url,
        specification=SpecificationInfo(
            version=detected.version,
            raw_version=detected.raw,
            format=loaded.format,
            source_path=loaded.source_label,
            source_sha256=loaded.source_sha256,
            byte_size=loaded.byte_size,
            title=parsed.title,
            api_version=parsed.api_version,
            description=parsed.description,
            servers=parsed.servers,
        ),
        endpoints=classified,
        security_schemes=parsed.security_schemes,
        global_security=parsed.global_security,
        relationships=relationships,
        warnings=warnings.warnings,
        aegisapi_version=__version__,
    )


__all__ = ["discover_from_specification", "parse_specification"]
