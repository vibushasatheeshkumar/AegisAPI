"""The one-shot scan pipeline.

``aegisapi scan --url URL`` runs the whole assessment in one command:
validate the URL, derive the narrowest scope that admits it, confirm the target
answers, build an endpoint inventory, run the security checks, analyse what
they found, and compose the report.

The pipeline owns the *order* of those stages and nothing else. Each one
delegates to the component that already does that job, so a scan and the
equivalent sequence of ``discover``, ``check``, ``risk``, and ``report``
commands run the same code and produce the same results.
"""

from aegisapi.scan.authorisation import ScanAuthorisation, authorise_scan_url
from aegisapi.scan.events import EventDispatcher, EventHandler, ScanEvent, ScanEventType
from aegisapi.scan.pipeline import (
    DEFAULT_SCAN_BUDGET,
    ScanOptions,
    ScanResult,
    ScanStage,
    run_scan,
)

__all__ = [
    "DEFAULT_SCAN_BUDGET",
    "EventDispatcher",
    "EventHandler",
    "ScanAuthorisation",
    "ScanEvent",
    "ScanEventType",
    "ScanOptions",
    "ScanResult",
    "ScanStage",
    "authorise_scan_url",
    "run_scan",
]
