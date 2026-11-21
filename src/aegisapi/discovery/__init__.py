"""API specification parsing and endpoint discovery.

The subsystem is a pipeline, and each stage is a module that can be tested on
its own:

1. :mod:`aegisapi.discovery.loader` reads a local file into a plain document.
2. :mod:`aegisapi.discovery.versions` decides which dialect it is.
3. :mod:`aegisapi.discovery.references` resolves local ``$ref`` pointers.
4. :mod:`aegisapi.discovery.schemas` summarises schema structure.
5. :mod:`aegisapi.discovery.openapi` and :mod:`aegisapi.discovery.swagger`
   normalise operations into :class:`~aegisapi.models.endpoint.Endpoint`.
6. :mod:`aegisapi.discovery.relationships` records structural observations.
7. :mod:`aegisapi.discovery.classification` maps endpoints onto a target's scope.
8. :mod:`aegisapi.discovery.service` runs the pipeline, and
   :mod:`aegisapi.discovery.store` persists the result.

**Nothing in this package opens a network connection.** A specification is
data: it is parsed, never executed, and a ``$ref`` or server URL pointing
somewhere else is recorded and reported, never fetched.
"""

from aegisapi.discovery.service import discover_from_specification
from aegisapi.discovery.store import DiscoveryStore

__all__ = ["DiscoveryStore", "discover_from_specification"]
