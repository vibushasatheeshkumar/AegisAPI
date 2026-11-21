"""Rendering a report as a SARIF 2.1.0 document.

SARIF (Static Analysis Results Interchange Format) is defined at
https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html and is the
standard for exchanging static analysis results with tooling such as GitHub
Code Scanning.

Only confirmed and suspected findings are emitted; passed, skipped,
inconclusive, and informational results are intentionally omitted so that the
file contains only actionable signal.

Security properties
-------------------
* No credentials or authorization headers appear in the output. Evidence
  already cannot hold a raw secret, but this renderer goes further and
  excludes all evidence headers and body excerpts, since SARIF files are
  routinely uploaded to public CI systems.
* Every string from the report reaches :func:`json.dumps` as a plain Python
  value. No string interpolation into a larger JSON blob occurs; there is no
  way for a report field to escape its JSON context.
* The URL fields in :class:`~aegisapi.models.assessment.CheckResult` are
  already redacted by the layers that built them and are reproduced verbatim.
* Remediation guidance, OWASP category, and severity appear only as
  properties so that downstream tools can filter them without rendering them
  into human-visible text that may carry misleading implications.
"""

from __future__ import annotations

import json

from aegisapi import APP_NAME
from aegisapi.models.assessment import CheckResult, FindingClass, OwaspApiCategory
from aegisapi.models.common import Severity
from aegisapi.models.report import Report

_SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
_SARIF_VERSION = "2.1.0"

# OWASP API Security Top 10 (2023) → primary CWE identifier.
# Used to populate rule tags so that tools which understand CWE can filter.
_OWASP_CWE: dict[OwaspApiCategory, str] = {
    OwaspApiCategory.API1_BOLA: "CWE-284",
    OwaspApiCategory.API2_BROKEN_AUTHENTICATION: "CWE-287",
    OwaspApiCategory.API3_BOPLA: "CWE-284",
    OwaspApiCategory.API4_RESOURCE_CONSUMPTION: "CWE-400",
    OwaspApiCategory.API5_BFLA: "CWE-285",
    OwaspApiCategory.API6_SENSITIVE_BUSINESS_FLOWS: "CWE-284",
    OwaspApiCategory.API7_SSRF: "CWE-918",
    OwaspApiCategory.API8_MISCONFIGURATION: "CWE-16",
    OwaspApiCategory.API9_INVENTORY: "CWE-284",
    OwaspApiCategory.API10_UNSAFE_CONSUMPTION: "CWE-350",
}

# GitHub Code Scanning reads ``security-severity`` from a rule's properties
# and uses it to determine the alert level shown in the UI.
# Scale: 9.0–10.0 = critical, 7.0–8.9 = high, 4.0–6.9 = medium, 0.1–3.9 = low.
_GITHUB_SECURITY_SEVERITY: dict[Severity, str] = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH: "8.0",
    Severity.MEDIUM: "5.5",
    Severity.LOW: "2.5",
    Severity.INFO: "0.0",
}

_SARIF_LEVEL: dict[Severity, str] = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}


def _result_level(result: CheckResult) -> str:
    """SARIF level for one result. Falls back to 'note' when severity is unset."""
    if result.severity is not None:
        return _SARIF_LEVEL.get(result.severity, "note")
    return "note"


def _make_rule(
    check_id: str,
    check_name: str,
    owasp: OwaspApiCategory | None,
    category: str,
    severity: Severity | None,
) -> dict:
    """Build a SARIF ``reportingDescriptor`` object for one check."""
    tags: list[str] = ["security", category]
    if owasp is not None:
        tags.append(f"owasp:{owasp.identifier}")
        cwe = _OWASP_CWE.get(owasp)
        if cwe:
            tags.append(cwe)

    properties: dict = {"tags": tags}
    if severity is not None and severity in _GITHUB_SECURITY_SEVERITY:
        properties["security-severity"] = _GITHUB_SECURITY_SEVERITY[severity]

    level = _SARIF_LEVEL.get(severity, "note") if severity is not None else "note"

    return {
        "id": check_id,
        "name": check_id,
        "shortDescription": {"text": check_name},
        "defaultConfiguration": {"level": level},
        "properties": properties,
    }


def _make_location(result: CheckResult) -> dict:
    """Build a SARIF ``location`` for one check result.

    Uses ``physicalLocation`` with the redacted endpoint URL when one is
    present, plus a ``logicalLocation`` carrying the operation key so that
    tooling that cannot render a URL still has a readable identifier.
    """
    loc: dict = {}
    if result.url:
        loc["physicalLocation"] = {
            "artifactLocation": {
                "uri": result.url,
                "uriBaseId": "%APIROOT%",
            }
        }
    loc["logicalLocations"] = [
        {
            "name": result.endpoint_key,
            "kind": "api-endpoint",
        }
    ]
    return loc


def _make_result(result: CheckResult) -> dict:
    """Build a SARIF ``result`` object for one finding.

    The message is composed from the check's own summary and explanation,
    neither of which is derived from attacker-controlled API responses.
    No request or response body, no header values, and no raw evidence
    excerpts are included.
    """
    parts = [result.summary]
    if result.explanation:
        parts.append(result.explanation)
    message_text = " ".join(parts)

    # Properties carry machine-readable metadata only. No secrets, no header
    # values, no response bodies.
    props: dict[str, str] = {
        "aegisapi.finding_class": result.finding_class.value,
        "aegisapi.confidence": result.confidence.value,
    }
    if result.severity is not None:
        props["aegisapi.severity"] = result.severity.value
    if result.owasp is not None:
        props["aegisapi.owasp"] = result.owasp.value
    if result.remediation:
        props["aegisapi.remediation"] = result.remediation

    return {
        "ruleId": result.check_id,
        "level": _result_level(result),
        "message": {"text": message_text},
        "locations": [_make_location(result)],
        "fingerprints": {"aegisapi/v1": result.result_id},
        "properties": props,
    }


def render_sarif_report(report: Report) -> str:
    """Render ``report`` as a SARIF 2.1.0 JSON document.

    Only results whose :attr:`~aegisapi.models.assessment.CheckResult.is_finding`
    property is ``True`` (confirmed and suspected) are included. Passed,
    skipped, inconclusive, informational, and errored results are intentionally
    excluded so that the file contains only actionable signal.

    No credential, authorization header, response body excerpt, or request
    header value is ever written to the output.

    Returns:
        SARIF 2.1.0 JSON text, ending in a newline.
    """
    findings = [r for r in report.results if r.is_finding]

    # Build a deduplicated rules list in first-appearance order.  Rules are
    # keyed by check_id so each check appears exactly once regardless of how
    # many endpoints it matched.
    seen: dict[str, tuple] = {}
    for r in findings:
        if r.check_id not in seen:
            seen[r.check_id] = (r.check_name, r.owasp, r.category.value, r.severity)

    rules = [
        _make_rule(cid, name, owasp, cat, sev)
        for cid, (name, owasp, cat, sev) in seen.items()
    ]

    sarif_results = [_make_result(r) for r in findings]

    document = {
        "$schema": _SARIF_SCHEMA,
        "version": _SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": APP_NAME,
                        "version": report.aegisapi_version,
                        "rules": rules,
                    }
                },
                "results": sarif_results,
                "automationDetails": {
                    "id": f"aegisapi/{report.target_name}",
                },
            }
        ],
    }

    return json.dumps(document, indent=2, ensure_ascii=False) + "\n"


__all__ = [
    "render_sarif_report",
    "_OWASP_CWE",
    "_SARIF_LEVEL",
    "_GITHUB_SECURITY_SEVERITY",
]
