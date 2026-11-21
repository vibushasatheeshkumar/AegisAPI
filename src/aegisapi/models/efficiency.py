"""Efficiency metrics model for one assessment scan."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class EfficiencySummary(BaseModel):
    """Efficiency gains and metrics for one assessment scan.

    Collects statistics about GET response caching across checks, redundant
    check execution elimination, and endpoint prioritization. All fields count
    things that did *not* happen — requests not sent, checks not re-run — so a
    larger number means more was saved rather than more was done.
    """

    model_config = ConfigDict(extra="forbid")

    requests_deduped: int = Field(
        default=0,
        ge=0,
        description=(
            "GET requests suppressed because an identical request (same method, URL, "
            "body, and auth context) was already sent by a *different* check in this "
            "assessment and its response was safely reused."
        ),
    )
    cache_hits: int = Field(
        default=0,
        ge=0,
        description=(
            "GET responses served from cache rather than re-fetched because a "
            "different check had already retrieved the same URL under the same "
            "authentication context.  Equal to requests_deduped in this implementation."
        ),
    )
    redundant_checks_skipped: int = Field(
        default=0,
        ge=0,
        description=(
            "Check executions skipped because the same (check_id, endpoint_key) "
            "pair had already completed earlier in this assessment."
        ),
    )
    endpoints_prioritized: int = Field(
        default=0,
        ge=0,
        description=(
            "In-scope endpoints that were reordered by the security-impact "
            "prioritiser before the assessment began."
        ),
    )
    total_requests_saved: int = Field(
        default=0,
        ge=0,
        description="Sum of requests_deduped and any other per-request savings.",
    )


__all__ = ["EfficiencySummary"]
