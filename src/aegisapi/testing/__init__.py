"""Controlled, evidence-driven API security checks.

Every check in this package runs through
:class:`~aegisapi.http.ScopedHttpClient`, so every request is scope-validated
before transmission. A check is handed a client and nothing else; it cannot
build a transport, widen a target's scope, or reach the network any other way.

What the engine is careful about:

* **A failed check is not a confirmed vulnerability.** Outcome and finding
  class are separate, and a status code on its own almost never justifies
  ``CONFIRMED``.
* **Authorization needs ground truth.** Object-level and function-level checks
  require operator-declared identities, owned objects, and access
  expectations, and skip without them rather than guessing identifiers or
  reading strangers' data.
* **Nothing unbounded.** A shared request budget caps the whole run, input
  probes are single benign values drawn from the declared schema, and the rate
  probe stops on the first refusal.
* **Writes are opt-in.** Only read-shaped methods are sent unless the operator
  sets ``allow_write_methods`` in the fixtures.

This package performs no fuzzing, no exploitation, and no reporting.
"""

from aegisapi.testing.engine import AssessmentEngine, register_builtin_checks
from aegisapi.testing.fixtures import AssessmentFixtures, load_fixtures
from aegisapi.testing.registry import REGISTRY, CheckContext, CheckRegistry, RequestBudget
from aegisapi.testing.store import AssessmentStore, IntelligenceStore

__all__ = [
    "REGISTRY",
    "AssessmentEngine",
    "AssessmentFixtures",
    "AssessmentStore",
    "CheckContext",
    "CheckRegistry",
    "IntelligenceStore",
    "RequestBudget",
    "load_fixtures",
    "register_builtin_checks",
]
