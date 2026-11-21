"""Context-aware risk intelligence.

Turns a discovery result and an assessment result into an explained,
prioritised view: what relates to what, which findings reinforce each other,
what to look at first, and what remains unproven.

Three properties hold throughout:

* **Everything carries provenance.** Each edge, correlation, and path step
  records whether it was observed, declared by the operator, read from the
  specification, or inferred from structure.
* **Scoring is a published table, not a tuned formula.** Every contribution to
  a risk score is a named factor with its points and its reason, so a score can
  be read back as an argument.
* **It runs locally and deterministically.** No requests, no external service,
  and the same inputs produce the same report.

Nothing here claims an unverified path is exploitable, and counting weak
observations never produces a confirmed finding.
"""

from aegisapi.intelligence.attack_paths import find_attack_paths
from aegisapi.intelligence.correlation import correlate
from aegisapi.intelligence.engine import analyse
from aegisapi.intelligence.graph import build_graph
from aegisapi.intelligence.risk import band_for, build_risks, model_description

__all__ = [
    "analyse",
    "band_for",
    "build_graph",
    "build_risks",
    "correlate",
    "find_attack_paths",
    "model_description",
]
