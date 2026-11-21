"""Models for security checks, their evidence, and their results.

The vocabulary here encodes the project's central discipline: **a failed check
is not a confirmed vulnerability**. Two independent axes keep that honest:

* :class:`CheckOutcome` - what happened when the check ran.
* :class:`FindingClass` - how much the evidence actually supports a security
  claim.

A check can FAIL and still only be ``SUSPECTED``, because a status code alone
rarely proves anything. Severity, confidence, and evidence strength are kept
separate on purpose; collapsing them is how tools end up reporting a critical
finding backed by one 500 response.

Nothing here can hold a credential. Evidence is built from an
:class:`~aegisapi.models.http.HttpResponse`, which is already redacted, and
every field below is either a reference, a redacted value, or a bounded
excerpt.
"""

from __future__ import annotations

import hashlib
from collections import Counter
from datetime import UTC, datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

from aegisapi.models.common import Confidence, Severity

ASSESSMENT_SCHEMA_VERSION = 1
"""Format version of a persisted assessment document."""

MAX_EVIDENCE_EXCERPT = 1024
"""Longest response excerpt kept on a piece of evidence.

Evidence exists to let a reviewer confirm a conclusion, not to archive the
API's responses. A kilobyte is enough to show a status line, an error shape, or
the first fields of an object.
"""

MAX_EVIDENCE_PER_RESULT = 6
"""How many evidence items one result keeps."""


class OwaspApiCategory(StrEnum):
    """OWASP API Security Top 10 (2023) categories.

    The value is the published identifier so a report is comparable with any
    other tool's output and with a programme's own taxonomy.
    """

    API1_BOLA = "API1:2023 Broken Object Level Authorization"
    API2_BROKEN_AUTHENTICATION = "API2:2023 Broken Authentication"
    API3_BOPLA = "API3:2023 Broken Object Property Level Authorization"
    API4_RESOURCE_CONSUMPTION = "API4:2023 Unrestricted Resource Consumption"
    API5_BFLA = "API5:2023 Broken Function Level Authorization"
    API6_SENSITIVE_BUSINESS_FLOWS = "API6:2023 Unrestricted Access to Sensitive Business Flows"
    API7_SSRF = "API7:2023 Server Side Request Forgery"
    API8_MISCONFIGURATION = "API8:2023 Security Misconfiguration"
    API9_INVENTORY = "API9:2023 Improper Inventory Management"
    API10_UNSAFE_CONSUMPTION = "API10:2023 Unsafe Consumption of APIs"

    @property
    def identifier(self) -> str:
        """Just the ``API8:2023`` part, for a compact table column."""
        return self.value.split(" ", 1)[0]

    @property
    def title(self) -> str:
        """Just the category name, without the identifier."""
        return self.value.split(" ", 1)[1]


class CheckCategory(StrEnum):
    """Security area a check belongs to."""

    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    INPUT_VALIDATION = "input_validation"
    CONFIGURATION = "configuration"
    RATE_LIMITS = "rate_limits"
    SCHEMA_VALIDATION = "schema_validation"


class CheckOutcome(StrEnum):
    """What happened when a check ran."""

    PASS = "pass"
    """The expected secure behaviour was observed."""

    FAIL = "fail"
    """The expected behaviour was not observed. Not the same as a vulnerability."""

    NEEDS_REVIEW = "needs_review"
    """Something worth a human look that the check cannot settle itself."""

    SKIPPED = "skipped"
    """Preconditions were not met, so nothing was sent."""

    ERROR = "error"
    """The check could not complete. Says nothing about the API."""


class FindingClass(StrEnum):
    """How strongly the evidence supports a security claim."""

    CONFIRMED = "confirmed"
    """Direct evidence supports the claim."""

    SUSPECTED = "suspected"
    """Evidence indicates a possible issue but does not prove it."""

    INFORMATIONAL = "informational"
    """Useful behaviour or configuration information. Not a weakness."""

    INCONCLUSIVE = "inconclusive"
    """No reliable conclusion could be reached."""

    NONE = "none"
    """Nothing to report; the check passed or was skipped."""

    @property
    def is_finding(self) -> bool:
        """``True`` for classes that represent a potential security issue."""
        return self in {FindingClass.CONFIRMED, FindingClass.SUSPECTED}


class Evidence(BaseModel):
    """One observation that supports a check's conclusion.

    Built from an already-redacted response, so it cannot contain an
    authorization header, a cookie, or a sensitive query value. Bodies are
    bounded; full responses are never retained.
    """

    model_config = ConfigDict(extra="forbid")

    evidence_id: str = Field(
        description="Stable identifier, so intelligence can reference evidence "
        "instead of copying it."
    )
    label: str = Field(description="Short description of what was observed.")
    method: str = Field(description="HTTP method sent.")
    url: str = Field(description="Destination URL, with sensitive query values redacted.")
    status_code: int | None = Field(
        default=None, description="Status received, or None when no response arrived."
    )
    request_headers: dict[str, str] = Field(
        default_factory=dict, description="Request headers, values redacted where sensitive."
    )
    response_headers: dict[str, str] = Field(
        default_factory=dict, description="Response headers, values redacted where sensitive."
    )
    content_type: str | None = Field(default=None, description="Declared response content type.")
    body_excerpt: str | None = Field(
        default=None, description="Bounded, sanitised excerpt of the response body."
    )
    body_bytes: int = Field(default=0, ge=0, description="Size of the response body received.")
    truncated: bool = Field(default=False, description="Whether the excerpt was cut short.")
    elapsed_ms: float = Field(default=0.0, ge=0, description="Round-trip time in milliseconds.")
    authenticated: bool = Field(
        default=False, description="Whether a credential was attached to this request."
    )
    identity: str | None = Field(
        default=None, description="Configured test identity used, by name only."
    )
    note: str | None = Field(default=None, description="Why this observation matters.")
    recorded_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC), description="When it was recorded (UTC)."
    )

    @staticmethod
    def make_id(check_id: str, label: str, url: str, status: int | None) -> str:
        """Build a stable evidence identifier.

        Derived from the check, label, URL, and status rather than a counter, so
        the same observation gets the same identifier on a repeat run and
        intelligence output stays diffable.
        """
        digest = hashlib.sha256(f"{check_id}|{label}|{url}|{status}".encode()).hexdigest()
        return f"ev-{digest[:16]}"


class CheckResult(BaseModel):
    """The outcome of running one check against one endpoint."""

    model_config = ConfigDict(extra="forbid")

    check_id: str = Field(description="Stable identifier of the check that ran.")
    check_name: str = Field(description="Human-readable check name.")
    category: CheckCategory = Field(description="Security area.")
    target_name: str = Field(description="Target the check ran against.")
    endpoint_key: str = Field(description="Operation tested, as 'METHOD /path'.")
    url: str | None = Field(
        default=None, description="Redacted URL tested, when a request was made."
    )
    outcome: CheckOutcome = Field(description="What happened when the check ran.")
    finding_class: FindingClass = Field(
        default=FindingClass.NONE, description="How strongly the evidence supports a claim."
    )
    severity: Severity | None = Field(
        default=None,
        description="Impact rating, set only when a finding is justified.",
    )
    confidence: Confidence = Field(
        default=Confidence.LOW, description="How certain the check is of its conclusion."
    )
    owasp: OwaspApiCategory | None = Field(
        default=None,
        description=(
            "OWASP API Security Top 10 category this check's subject belongs to. "
            "A classification of the weakness class, not a claim that an instance "
            "of it was confirmed; finding_class carries that."
        ),
    )
    remediation: str | None = Field(
        default=None,
        description=(
            "What to change in the API to address this weakness class. Recorded "
            "per check rather than per finding, and absent when none is recorded."
        ),
    )
    summary: str = Field(description="One line stating what was observed.")
    explanation: str = Field(
        default="", description="Why the observation leads to this conclusion."
    )
    limitations: list[str] = Field(
        default_factory=list,
        description="What this result does not establish. Always populated for a finding.",
    )
    next_step: str | None = Field(
        default=None, description="The verification a researcher should do next."
    )
    evidence: list[Evidence] = Field(
        default_factory=list, max_length=MAX_EVIDENCE_PER_RESULT, description="Observations."
    )
    requests_sent: int = Field(default=0, ge=0, description="Requests this check transmitted.")
    recorded_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC), description="When the check ran (UTC)."
    )

    @property
    def evidence_ids(self) -> tuple[str, ...]:
        """Identifiers of the evidence behind this result."""
        return tuple(item.evidence_id for item in self.evidence)

    @property
    def is_finding(self) -> bool:
        """``True`` when this result represents a potential security issue."""
        return self.finding_class.is_finding

    @property
    def result_id(self) -> str:
        """Stable identifier for this result, for cross-referencing."""
        digest = hashlib.sha256(
            f"{self.check_id}|{self.target_name}|{self.endpoint_key}".encode()
        ).hexdigest()
        return f"res-{digest[:16]}"


class AssessmentResult(BaseModel):
    """Every check result from one assessment run.

    This is the hand-off to the intelligence engine, and the reason it is
    persisted at all. It is **not** assessment history: one document per target,
    replaced on request. Comparing runs over time belongs to a later phase.
    """

    model_config = ConfigDict(extra="forbid")

    schema_version: int = Field(default=ASSESSMENT_SCHEMA_VERSION, ge=1)
    target_name: str = Field(description="Target assessed.")
    target_base_url: str = Field(description="Target base URL at the time of the run.")
    results: list[CheckResult] = Field(default_factory=list, description="Check results.")
    checks_run: list[str] = Field(
        default_factory=list, description="Check identifiers that were selected."
    )
    endpoints_considered: int = Field(
        default=0, ge=0, description="Operations the engine looked at."
    )
    endpoints_tested: int = Field(
        default=0, ge=0, description="Operations that met at least one check's preconditions."
    )
    requests_sent: int = Field(default=0, ge=0, description="Total requests transmitted.")
    request_budget: int = Field(default=0, ge=0, description="Budget the run was given.")
    budget_exhausted: bool = Field(
        default=False, description="Whether the run stopped because the budget ran out."
    )
    scan_timed_out: bool = Field(
        default=False, description="Whether the run stopped because scan_timeout_seconds was reached."
    )
    endpoints_at_limit: list[str] = Field(
        default_factory=list,
        description="Endpoint keys that hit the per-endpoint request limit.",
    )
    checks_timed_out: int = Field(
        default=0, ge=0, description="Number of checks that exceeded check_timeout_seconds."
    )
    specification_sha256: str | None = Field(
        default=None, description="Digest of the specification the endpoints came from."
    )
    started_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC), description="When the run started (UTC)."
    )
    aegisapi_version: str = Field(description="AegisAPI version that produced this document.")

    def findings(self) -> list[CheckResult]:
        """Results that represent a potential security issue."""
        return [item for item in self.results if item.is_finding]

    def by_outcome(self) -> dict[CheckOutcome, int]:
        """How many results fell into each outcome."""
        counts = Counter(item.outcome for item in self.results)
        return {value: counts.get(value, 0) for value in CheckOutcome}

    def by_finding_class(self) -> dict[FindingClass, int]:
        """How many results fell into each finding class."""
        counts = Counter(item.finding_class for item in self.results)
        return {value: counts.get(value, 0) for value in FindingClass}

    def by_category(self) -> dict[CheckCategory, int]:
        """How many results came from each category."""
        counts = Counter(item.category for item in self.results)
        return {value: counts.get(value, 0) for value in CheckCategory}

    def result_for(self, check_id: str, endpoint_key: str) -> CheckResult | None:
        """Look up one result, for correlation."""
        for item in self.results:
            if item.check_id == check_id and item.endpoint_key == endpoint_key:
                return item
        return None

    def evidence_index(self) -> dict[str, Evidence]:
        """Every piece of evidence, keyed by identifier."""
        index: dict[str, Evidence] = {}
        for result in self.results:
            for item in result.evidence:
                index[item.evidence_id] = item
        return index


__all__ = [
    "ASSESSMENT_SCHEMA_VERSION",
    "MAX_EVIDENCE_EXCERPT",
    "MAX_EVIDENCE_PER_RESULT",
    "AssessmentResult",
    "CheckCategory",
    "CheckOutcome",
    "CheckResult",
    "Evidence",
    "FindingClass",
    "OwaspApiCategory",
]
