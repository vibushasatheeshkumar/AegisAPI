"""Rendering a report as a self-contained HTML document.

Dependency-free, and deliberately plain: semantic elements, one embedded
stylesheet, and nothing else. The output opens from the filesystem, prints
cleanly, and works with a browser's Print-to-PDF, which is how this build
produces a PDF.

Security properties, and why each one is here
---------------------------------------------

A report embeds material AegisAPI did not write. Response excerpts and header
values come from the API under test; operation paths, schema names, and
security-scheme names come from a specification supplied by a client or a bug
bounty programme. All of it is attacker-influencable, so the renderer treats
every model-derived string as hostile.

* **One escaping helper.** :func:`_esc` wraps ``html.escape(value, quote=True)``
  and is the only way model data enters the document. ``quote=True`` escapes
  ``"`` and ``'`` as well, so a value is safe in an attribute as well as in a
  text node. Nothing in this module interpolates a model value without it.
* **No model URL is ever a link.** ``Evidence.url`` and ``CheckResult.url`` are
  rendered as escaped text, never inside ``href`` or ``src``. Escaping does not
  defuse a ``javascript:`` URL - the browser would still run it on click - so
  the only safe answer is not to make it a link at all. This document contains
  no outbound link of any kind.
* **No JavaScript, no external resources.** No ``<script>``, no event-handler
  attributes, no ``<img>``, no web fonts, no external stylesheet. Everything the
  document needs is in the file, so opening it fetches nothing and a reviewer
  can read it offline.
* **A restrictive Content Security Policy** is declared in a ``<meta>`` element:
  ``default-src 'none'`` blocks every fetch and inline script, and
  ``style-src 'unsafe-inline'`` permits only the embedded stylesheet. It makes
  the two properties above enforced by the browser rather than merely intended.
* **Excerpts stay inert.** A body excerpt is escaped and placed in a ``<pre>``
  that wraps, so newlines survive for a reader without the text being able to
  close an element. The HTTP layer has already stripped control characters, but
  this module escapes regardless rather than relying on that.

Nothing here can leak a credential: every model it renders is built from
already-redacted material.
"""

from __future__ import annotations

import html
from collections.abc import Iterable

from aegisapi import APP_NAME
from aegisapi.models.assessment import CheckResult, Evidence
from aegisapi.models.intelligence import AttackPath, Correlation, PrioritisedRisk
from aegisapi.models.report import Report

NEXT_STEP_HEADING = "Next Verification Step"
"""What ``next_step`` actually is.

It names the observation a researcher should make next to settle whether a
finding is real.
"""

REMEDIATION_HEADING = "Recommended Remediation"
"""Heading for the per-check remediation guidance section."""

OWASP_HEADING = "OWASP API Security"
"""Heading for the OWASP API Top-10 category label."""

PATHS_PREAMBLE = (
    "An attack path is a hypothesis about reachability assembled from declared "
    "relationships and recorded findings. It is not a demonstrated exploit, and "
    "nothing below has been executed. Each path names its weakest step, which is "
    "where verification should start."
)

RISKS_PREAMBLE = (
    "Risks are prioritised by a published, deterministic scoring model. Every "
    "contribution to a score is listed with the reason it applied, so a ranking "
    "can be read back as an argument rather than taken on trust."
)

EXECUTIVE_SUMMARY_HEADING = "Executive Summary"
"""Heading for the executive summary section."""

METHODOLOGY_HEADING = "Assessment Methodology & Scope"
"""Heading for the methodology and scope section."""

DASH = "&mdash;"
"""Rendered in place of a value the models left unset."""

_STYLESHEET = """\
:root {
  --ink: #1a1a1a;
  --muted: #595959;
  --rule: #d4d4d4;
  --panel: #f6f6f4;
  --accent: #1f4e79;
  --critical: #7d1128;
  --high: #a63a1e;
  --medium: #8a6100;
  --low: #3d5a2b;
  --info: #37527a;
}
* { box-sizing: border-box; }
body {
  margin: 0 auto;
  max-width: 54rem;
  padding: 2rem 1.25rem 4rem;
  background: #ffffff;
  color: var(--ink);
  font-family: system-ui, -apple-system, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
  font-size: 15px;
  line-height: 1.55;
}
h1 { font-size: 1.7rem; margin: 0 0 .35rem; letter-spacing: -.01em; }
h2 {
  font-size: 1.25rem;
  margin: 2.5rem 0 .75rem;
  padding-bottom: .3rem;
  border-bottom: 2px solid var(--accent);
}
h3 { font-size: 1.02rem; margin: 1.5rem 0 .4rem; }
h4 { font-size: .93rem; margin: 1rem 0 .3rem; color: var(--muted); }
p { margin: .5rem 0; }
code, pre { font-family: ui-monospace, "Cascadia Mono", Consolas, "DejaVu Sans Mono", monospace; }
.subtitle { color: var(--muted); font-size: 1.05rem; margin: 0 0 1rem; }
.target-url { font-size: .9rem; word-break: break-all; }
.caveat {
  background: var(--panel);
  border-left: 4px solid var(--accent);
  padding: .8rem 1rem;
  margin: 1.5rem 0;
  font-size: .92rem;
}
.preamble { color: var(--muted); font-size: .92rem; margin: .4rem 0 1rem; }
table { border-collapse: collapse; width: 100%; margin: .6rem 0 1rem; font-size: .9rem; }
th, td { text-align: left; padding: .4rem .6rem; border-bottom: 1px solid var(--rule); }
th { background: var(--panel); font-weight: 600; }
td.num, th.num { text-align: right; white-space: nowrap; }
dl.meta, dl.facts {
  display: grid;
  grid-template-columns: max-content 1fr;
  gap: .18rem .9rem;
  font-size: .88rem;
}
dl.facts { margin: .5rem 0; }
dl.meta dt, dl.facts dt { color: var(--muted); }
dl.meta dd, dl.facts dd { margin: 0; word-break: break-word; }
.item { border: 1px solid var(--rule); border-radius: 4px; padding: .9rem 1.1rem; margin: 1rem 0; }
.item > h3 { margin-top: 0; }
.tag {
  display: inline-block;
  padding: .05rem .45rem;
  border-radius: 3px;
  font-size: .76rem;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: .03em;
  border: 1px solid currentColor;
}
.sev-critical { color: var(--critical); }
.sev-high { color: var(--high); }
.sev-medium { color: var(--medium); }
.sev-low { color: var(--low); }
.sev-info { color: var(--info); }
.sev-none { color: var(--muted); }
ul.plain { margin: .35rem 0 .35rem 1.1rem; padding: 0; }
ul.plain li { margin: .18rem 0; }
ol.steps { margin: .4rem 0 .4rem 1.2rem; padding: 0; font-size: .9rem; }
ol.steps li { margin: .3rem 0; }
pre.excerpt {
  background: var(--panel);
  border: 1px solid var(--rule);
  border-radius: 3px;
  padding: .55rem .7rem;
  margin: .35rem 0;
  font-size: .82rem;
  white-space: pre-wrap;
  overflow-wrap: anywhere;
  max-height: 22rem;
  overflow-y: auto;
}
.url { font-size: .82rem; word-break: break-all; color: var(--muted); }
.empty { color: var(--muted); font-style: italic; }
footer {
  margin-top: 3rem;
  padding-top: .8rem;
  border-top: 1px solid var(--rule);
  color: var(--muted);
  font-size: .82rem;
}
@media print {
  body { max-width: none; padding: 0; font-size: 10.5pt; color: #000; }
  h2 { page-break-after: avoid; }
  h3, h4 { page-break-after: avoid; }
  .item, table, pre.excerpt { page-break-inside: avoid; }
  pre.excerpt { max-height: none; overflow: visible; }
  .caveat { border-left-width: 3px; }
  footer { page-break-before: avoid; }
}
"""


def _esc(value: object) -> str:
    """Escape a value for HTML, in a text node or an attribute.

    **The only route by which model data enters the document.** ``quote=True``
    escapes ``"`` and ``'`` as well as ``<``, ``>``, and ``&``, so one helper
    covers both contexts and there is no second rule to remember.
    """
    return html.escape(str(value), quote=True)


def _opt(value: object | None) -> str:
    """Escape a value, or render a dash when the models left it unset."""
    return DASH if value is None or value == "" else _esc(value)


def _severity_class(severity: object | None) -> str:
    """CSS class for a severity, chosen from a fixed set rather than the value."""
    known = {"critical", "high", "medium", "low", "info", "informational"}
    text = str(severity) if severity is not None else ""
    return f"sev-{text}" if text in known else "sev-none"


def _tag(text: object, *, severity: object | None = None) -> str:
    """A small inline label. Both the text and the class are safe."""
    return f'<span class="tag {_severity_class(severity)}">{_esc(text)}</span>'


def _facts(rows: Iterable[tuple[str, str]], *, css: str = "facts") -> str:
    """Build a definition list. Labels are literals; values are pre-escaped."""
    items = "".join(f"<dt>{_esc(label)}</dt><dd>{value}</dd>" for label, value in rows)
    return f'<dl class="{css}">{items}</dl>' if items else ""


def _count_table(heading: str, counts: dict[object, int], *, label: str) -> str:
    """Render a distribution as a two-column table, omitting empty mappings."""
    rows = [(key, value) for key, value in counts.items() if value]
    if not rows:
        return ""
    body = "".join(
        f'<tr><td>{_esc(key)}</td><td class="num">{_esc(value)}</td></tr>' for key, value in rows
    )
    return (
        f"<h4>{_esc(heading)}</h4>"
        f'<table><thead><tr><th>{_esc(label)}</th><th class="num">Count</th></tr></thead>'
        f"<tbody>{body}</tbody></table>"
    )


def _bullets(heading: str, values: Iterable[str]) -> str:
    """A labelled bullet list, or nothing when there is nothing to say."""
    items = "".join(f"<li>{_esc(item)}</li>" for item in values)
    if not items:
        return ""
    return f'<h4>{_esc(heading)}</h4><ul class="plain">{items}</ul>'


def _evidence_block(evidence: Evidence) -> str:
    """Render one observation.

    The URL is text, never a link. The excerpt is escaped inside a wrapping
    ``<pre>`` so its newlines survive while its content stays inert.
    """
    parts = [f"<h4>{_esc(evidence.label)}</h4>"]
    parts.append(
        _facts(
            [
                ("Request", _esc(f"{evidence.method} {evidence.url}")),
                ("Status", _opt(evidence.status_code)),
                ("Content type", _opt(evidence.content_type)),
                ("Body size", _esc(f"{evidence.body_bytes} bytes")),
                ("Round trip", _esc(f"{evidence.elapsed_ms} ms")),
                ("Authenticated", _esc("yes" if evidence.authenticated else "no")),
                ("Identity", _opt(evidence.identity)),
                ("Evidence id", _esc(evidence.evidence_id)),
            ]
        )
    )
    if evidence.note:
        parts.append(f"<p>{_esc(evidence.note)}</p>")

    if evidence.request_headers:
        rows = "".join(
            f"<tr><td>{_esc(name)}</td><td>{_esc(value)}</td></tr>"
            for name, value in sorted(evidence.request_headers.items())
        )
        parts.append(
            "<table><thead><tr><th>Request header</th><th>Value</th></tr></thead>"
            f"<tbody>{rows}</tbody></table>"
        )

    if evidence.response_headers:
        rows = "".join(
            f"<tr><td>{_esc(name)}</td><td>{_esc(value)}</td></tr>"
            for name, value in sorted(evidence.response_headers.items())
        )
        parts.append(
            "<table><thead><tr><th>Response header</th><th>Value</th></tr></thead>"
            f"<tbody>{rows}</tbody></table>"
        )

    if evidence.body_excerpt is not None:
        truncated = " (truncated)" if evidence.truncated else ""
        parts.append(f"<h4>Response excerpt{_esc(truncated)}</h4>")
        parts.append(f'<pre class="excerpt">{_esc(evidence.body_excerpt)}</pre>')

    return "".join(parts)


def _result_block(result: CheckResult) -> str:
    """Render one check result, including what it does not establish."""
    parts = [
        '<article class="item">',
        f"<h3>{_esc(result.check_id)} {DASH} {_esc(result.check_name)}</h3>",
        "<p>"
        + _tag(result.outcome, severity=result.severity)
        + " "
        + _tag(result.finding_class)
        + (f" {_tag(result.severity, severity=result.severity)}" if result.severity else "")
        + "</p>",
        _facts(
            [
                ("Operation", _esc(result.endpoint_key)),
                ("URL", f'<span class="url">{_opt(result.url)}</span>'),
                ("Category", _esc(result.category)),
                ("Confidence", _esc(result.confidence)),
                ("Requests sent", _esc(result.requests_sent)),
                ("Recorded", _esc(result.recorded_at)),
                (
                    OWASP_HEADING,
                    _esc(result.owasp.value) if result.owasp else DASH,
                ),
            ]
        ),
        f"<p><strong>{_esc(result.summary)}</strong></p>",
    ]
    if result.explanation:
        parts.append(f"<p>{_esc(result.explanation)}</p>")
    parts.append(_bullets("What this does not establish", result.limitations))
    if result.next_step:
        parts.append(f"<h4>{_esc(NEXT_STEP_HEADING)}</h4><p>{_esc(result.next_step)}</p>")
    if result.remediation:
        parts.append(
            f"<h4>{_esc(REMEDIATION_HEADING)}</h4><p>{_esc(result.remediation)}</p>"
        )
    for item in result.evidence:
        parts.append(_evidence_block(item))
    parts.append("</article>")
    return "".join(parts)


def _risk_block(risk: PrioritisedRisk) -> str:
    """Render one prioritised risk and the argument behind its score."""
    parts = [
        '<article class="item">',
        f"<h3>{_esc(risk.title)}</h3>",
        "<p>"
        + _tag(risk.band, severity=risk.band)
        + " "
        + _tag(f"score {risk.score}")
        + " "
        + _tag(risk.severity, severity=risk.severity)
        + " "
        + _tag(f"confidence {risk.confidence}")
        + "</p>",
        _facts(
            [
                ("Risk id", _esc(risk.risk_id)),
                ("Category", _esc(risk.category)),
                ("Operations", _esc(", ".join(risk.endpoints)) if risk.endpoints else DASH),
                ("Evidence strength", _esc(risk.evidence_strength)),
                (
                    "Claim established by direct evidence",
                    _esc("yes" if risk.confirmed else "no"),
                ),
            ]
        ),
        f"<h4>What was observed</h4><p>{_esc(risk.what_was_observed)}</p>",
        f"<h4>Why it matters</h4><p>{_esc(risk.why_it_matters)}</p>",
    ]
    if risk.factors:
        rows = "".join(
            f"<tr><td>{_esc(factor.name)}</td>"
            f'<td class="num">{_esc(factor.points)}</td>'
            f"<td>{_esc(factor.reason)}</td></tr>"
            for factor in risk.factors
        )
        parts.append(
            "<h4>Score contributions</h4>"
            '<table><thead><tr><th>Factor</th><th class="num">Points</th>'
            f"<th>Reason</th></tr></thead><tbody>{rows}</tbody></table>"
        )
    parts.append(_bullets("Not established", risk.unverified))
    parts.append(f"<h4>{_esc(NEXT_STEP_HEADING)}</h4><p>{_esc(risk.next_step)}</p>")
    parts.append("</article>")
    return "".join(parts)


def _path_block(path: AttackPath) -> str:
    """Render one potential attack path, weakest step named."""
    steps = "".join(
        f"<li>{_tag(step.kind)} {_esc(step.description)}"
        f'<br><span class="url">{_esc(step.from_node)} &rarr; {_esc(step.to_node)}'
        f" ({_esc(step.edge_kind)})</span></li>"
        for step in path.steps
    )
    parts = [
        '<article class="item">',
        f"<h3>{_esc(path.title)}</h3>",
        "<p>"
        + _tag(path.severity, severity=path.severity)
        + " "
        + _tag(f"confidence {path.confidence}")
        + " "
        + _tag(f"weakest step: {path.weakest_step}")
        + " "
        + _tag("fully evidenced" if path.fully_evidenced else "not fully evidenced")
        + "</p>",
        _facts(
            [
                ("Path id", _esc(path.path_id)),
                ("Steps", _esc(path.length)),
                ("Operations", _esc(", ".join(path.endpoints)) if path.endpoints else DASH),
            ]
        ),
        f"<p>{_esc(path.reasoning)}</p>",
    ]
    if steps:
        parts.append(f'<h4>Transitions</h4><ol class="steps">{steps}</ol>')
    parts.append(_bullets("Would have to be proven", path.unverified))
    parts.append("</article>")
    return "".join(parts)


def _correlation_block(correlation: Correlation) -> str:
    """Render one cross-endpoint correlation."""
    parts = [
        '<article class="item">',
        f"<h3>{_esc(correlation.title)}</h3>",
        "<p>"
        + _tag(correlation.provenance)
        + " "
        + _tag(f"confidence {correlation.confidence}")
        + " "
        + _tag("confirmed" if correlation.confirmed else "not confirmed")
        + "</p>",
        _facts(
            [
                ("Correlation id", _esc(correlation.correlation_id)),
                ("Kind", _esc(correlation.kind)),
                (
                    "Operations",
                    _esc(", ".join(correlation.endpoints)) if correlation.endpoints else DASH,
                ),
            ]
        ),
        f"<p>{_esc(correlation.reasoning)}</p>",
        _bullets("Not established", correlation.limitations),
        "</article>",
    ]
    return "".join(parts)


def _executive_summary_section(report: Report) -> str:
    """A concise, accurate overview derived entirely from recorded assessment data.

    Every statement is derived from structured fields — no prose is generated or
    inferred. When information is unavailable, the section says so rather than
    omitting or converting the gap into a positive claim.

    Accuracy constraints enforced here
    -----------------------------------
    * Potential findings are never described as confirmed.
    * Risk scores are labelled "not CVSS" to prevent misreading.
    * No overall security grade is invented.
    * When no findings are recorded, a neutral note says so without claiming
      the target is secure — the absence of a result does not establish the
      absence of a vulnerability.
    """
    summary = report.summary

    parts = [f"<section><h2>{_esc(EXECUTIVE_SUMMARY_HEADING)}</h2>"]

    # Assessment overview — provenance and coverage numbers.
    parts.append(
        _facts(
            [
                (
                    "Target",
                    f"{_esc(report.target_name)} "
                    f'<span class="url">{_esc(report.target_base_url)}</span>',
                ),
                ("Assessment started", _opt(report.assessment_started_at)),
                ("Checks selected", _esc(len(report.checks_run))),
                ("Operations tested", _esc(summary.endpoints_tested)),
                ("Results recorded", _esc(summary.results_total)),
            ]
        )
    )

    # Security posture — finding counts and highest severity.
    parts.append("<h3>Security posture</h3>")

    # Highest observed severity: pick the Severity key with the greatest rank
    # that has at least one result. Uses .rank via duck typing to avoid an
    # extra import; Severity is never None by the time it reaches by_severity.
    top_severity = max(
        (sev for sev, count in summary.by_severity.items() if count > 0),
        key=lambda s: getattr(s, "rank", 0),
        default=None,
    )

    parts.append(
        _facts(
            [
                ("Confirmed findings", _esc(summary.confirmed_findings)),
                ("Potential findings", _esc(summary.potential_findings)),
                ("Results needing review", _esc(summary.needs_review)),
                (
                    "Highest observed severity",
                    _tag(str(top_severity), severity=top_severity)
                    if top_severity is not None
                    else DASH,
                ),
            ]
        )
    )

    # Severity distribution table (omitted when no result carries a severity).
    if summary.by_severity:
        parts.append(_count_table("By severity", dict(summary.by_severity), label="Severity"))

    # Accurate zero-findings note — never equates absence of findings with security.
    if not report.has_findings and summary.needs_review == 0:
        parts.append(
            '<p class="preamble">No confirmed or potential findings and no results '
            "needing review were identified by the checks that ran. This does not "
            "establish the absence of vulnerabilities not covered by the selected "
            "checks or operations not tested.</p>"
        )

    # Risk highlights — only shown when an intelligence analysis was supplied.
    if report.has_intelligence:
        parts.append("<h3>Risk highlights</h3>")
        parts.append(
            _facts(
                [
                    ("Prioritised risks", _esc(summary.risks_total)),
                    ("Confirmed by direct evidence", _esc(summary.confirmed_risks)),
                    ("Potential attack paths", _esc(summary.attack_paths_total)),
                ]
            )
        )

        # Highest-priority confirmed risk (risks are highest-priority first).
        top_risk = next((r for r in report.risks if r.confirmed), None)
        if top_risk is not None:
            parts.append("<h4>Highest-priority confirmed risk</h4>")
            parts.append(
                "<p>"
                + _tag(top_risk.band, severity=top_risk.band)
                + " "
                + _tag(top_risk.severity, severity=top_risk.severity)
                + f" {_esc(top_risk.title)}</p>"
            )
            parts.append(
                _facts(
                    [
                        ("Risk id", _esc(top_risk.risk_id)),
                        ("Score (not CVSS)", _esc(top_risk.score)),
                        ("Category", _esc(top_risk.category)),
                        ("Confidence", _esc(top_risk.confidence)),
                    ]
                )
            )
            parts.append(f'<p class="preamble">{_esc(top_risk.what_was_observed)}</p>')

    # Assessment limitations — budget, missing analysis, untested operations.
    limitations: list[str] = []
    if summary.budget_exhausted:
        limitations.append(
            "The request budget was exhausted; some operations may not have been "
            "tested. The absence of a finding does not establish its absence."
        )
    if not report.has_intelligence:
        limitations.append(
            "No risk analysis was performed. This report shows check results only; "
            "no prioritised risks or attack paths were computed."
        )
    gap = max(0, summary.endpoints_considered - summary.endpoints_tested)
    if gap > 0:
        limitations.append(
            f"{gap} in-scope operation(s) were not tested because no check's "
            "preconditions were met for them."
        )

    if limitations:
        parts.append("<h3>Assessment limitations</h3>")
        items = "".join(f"<li>{_esc(item)}</li>" for item in limitations)
        parts.append(f'<ul class="plain">{items}</ul>')

    parts.append("</section>")
    return "".join(parts)


def _methodology_section(report: Report) -> str:
    """A structured account of the checks selected, what was covered, and how evidence was gathered.

    Only information that is recorded in the report is shown; nothing is
    inferred or invented. Scope rules (include/exclude paths, auth method) are
    held by the Target model and are not embedded in assessments, so they do
    not appear here.
    """
    summary = report.summary

    # Build a check-name lookup from whatever results the report displays.
    # Checks with no displayed result appear as bare IDs.
    check_name_map: dict[str, str] = {r.check_id: r.check_name for r in report.results}

    parts = [f"<section><h2>{_esc(METHODOLOGY_HEADING)}</h2>"]

    # Checks selected — readable list with names where derivable.
    if report.checks_run:
        check_labels = [
            f"{cid} — {check_name_map[cid]}" if cid in check_name_map else cid
            for cid in report.checks_run
        ]
        parts.append(
            _bullets(f"Checks selected ({len(report.checks_run)})", check_labels)
        )
    else:
        parts.append("<p>No checks were selected for this assessment.</p>")

    # Security areas covered — categories that produced at least one result.
    covered_categories = sorted(
        [cat for cat, count in summary.by_category.items() if count > 0],
        key=lambda c: c.value,
    )
    if covered_categories:
        parts.append(
            _bullets("Security areas covered", [cat.value for cat in covered_categories])
        )

    # OWASP API Security categories covered — only present when results carry an
    # OWASP mapping.
    if summary.by_owasp:
        parts.append(
            _bullets(
                "OWASP API Security Top 10 categories covered",
                sorted(cat.value for cat in summary.by_owasp),
            )
        )

    # Operations and request coverage.
    not_tested = max(0, summary.endpoints_considered - summary.endpoints_tested)
    parts.append("<h3>Coverage</h3>")
    parts.append(
        _facts(
            [
                ("Operations in scope", _esc(summary.endpoints_considered)),
                ("Operations tested", _esc(summary.endpoints_tested)),
                ("Operations not tested", _esc(not_tested)),
                (
                    "Requests sent",
                    _esc(f"{summary.requests_sent} of {summary.request_budget} budgeted"),
                ),
                (
                    "Request budget exhausted",
                    _esc("yes" if summary.budget_exhausted else "no"),
                ),
            ]
        )
    )

    if summary.budget_exhausted:
        parts.append(
            '<p class="preamble">The request budget was exhausted before all '
            "checks completed. Some operations may not have been tested. The absence "
            "of a finding for an operation does not establish its absence.</p>"
        )

    # Evidence collection approach.
    parts.append("<h3>Evidence collection</h3>")
    parts.append(
        '<p class="preamble">'
        "Each recorded observation captures the HTTP method, destination URL "
        "(with sensitive query values redacted), response status code, selected "
        "response headers, and a bounded body excerpt (1 KB maximum). Request "
        "headers are recorded with credential values replaced by [REDACTED]. "
        "No credential reaches a report.</p>"
    )

    parts.append("</section>")
    return "".join(parts)


def _summary_section(report: Report) -> str:
    """Counts describing the whole assessment, however much is displayed."""
    summary = report.summary
    rows = [
        ("Confirmed findings", _esc(summary.confirmed_findings)),
        ("Potential findings", _esc(summary.potential_findings)),
        ("Results needing review", _esc(summary.needs_review)),
        ("Prioritised risks", _esc(summary.risks_total) if report.has_intelligence else DASH),
        (
            "Risks established by direct evidence",
            _esc(summary.confirmed_risks) if report.has_intelligence else DASH,
        ),
        (
            "Potential attack paths",
            _esc(summary.attack_paths_total) if report.has_intelligence else DASH,
        ),
        ("Results recorded", _esc(summary.results_total)),
        ("Results displayed", _esc(summary.results_displayed)),
        ("Operations considered", _esc(summary.endpoints_considered)),
        ("Operations tested", _esc(summary.endpoints_tested)),
        (
            "Requests sent",
            _esc(f"{summary.requests_sent} of {summary.request_budget} budgeted"),
        ),
        ("Budget exhausted", _esc("yes" if summary.budget_exhausted else "no")),
    ]
    parts = ["<section><h2>Summary</h2>", _facts(rows, css="meta")]
    parts.append(
        '<p class="preamble">Findings and risks are counted separately and never '
        "added together: a risk is derived from check results, so the same "
        "observation appears in both.</p>"
    )
    parts.append(_count_table("By severity", dict(summary.by_severity), label="Severity"))
    parts.append(
        _count_table("By finding class", dict(summary.by_finding_class), label="Finding class")
    )
    parts.append(_count_table("By outcome", dict(summary.by_outcome), label="Outcome"))
    parts.append(_count_table("By category", dict(summary.by_category), label="Category"))
    parts.append(
        _count_table(
            "By OWASP API Security Top 10",
            dict(summary.by_owasp),
            label="Category",
        )
    )
    if report.has_intelligence:
        parts.append(_count_table("Risks by band", dict(summary.risk_bands), label="Band"))
    parts.append("</section>")
    return "".join(parts)


def render_html_report(report: Report) -> str:
    """Render ``report`` as one self-contained HTML document.

    The result references no external resource, contains no script, and holds
    no link. Every value taken from the report passes through :func:`_esc`.

    Returns:
        Complete HTML text, ending in a newline.
    """
    title = f"{APP_NAME} report {DASH} {_esc(report.target_name)}"

    head = (
        "<!DOCTYPE html>\n"
        '<html lang="en">\n<head>\n'
        '<meta charset="utf-8">\n'
        '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
        '<meta http-equiv="Content-Security-Policy" '
        "content=\"default-src 'none'; style-src 'unsafe-inline'\">\n"
        f"<title>{title}</title>\n"
        f"<style>\n{_STYLESHEET}</style>\n"
        "</head>\n<body>\n"
    )

    header = (
        "<header>"
        f"<h1>{_esc(APP_NAME)} security assessment report</h1>"
        f'<p class="subtitle">{_esc(report.target_name)}'
        f'<br><span class="target-url">{_esc(report.target_base_url)}</span></p>'
        + _facts(
            [
                ("Generated", _esc(report.generated_at)),
                ("Assessment started", _opt(report.assessment_started_at)),
                ("Risk analysis", _opt(report.analysed_at)),
                ("AegisAPI version", _esc(report.aegisapi_version)),
                ("Specification digest", _opt(report.specification_sha256)),
                (
                    "Checks selected",
                    _esc(", ".join(report.checks_run)) if report.checks_run else DASH,
                ),
                (
                    "Schema versions",
                    _esc(
                        f"report {report.schema_version}, "
                        f"assessment {report.source_assessment_schema}, "
                        + (
                            f"intelligence {report.source_intelligence_schema}"
                            if report.has_intelligence
                            else "intelligence none"
                        )
                    ),
                ),
            ],
            css="meta",
        )
        + "</header>"
    )

    caveat = (
        '<section class="caveat"><strong>Read this first.</strong> '
        + _esc(
            "A failed check is not a confirmed vulnerability and an attack path is "
            "not an exploit. Outcome, finding class, severity, confidence, and "
            "evidence strength are separate judgements, and each item below states "
            "what it does not establish."
        )
        + "</section>"
    )

    body: list[str] = [
        header,
        caveat,
        _executive_summary_section(report),
        _methodology_section(report),
        _summary_section(report),
    ]

    if report.has_intelligence:
        body.append("<section><h2>Prioritised risks</h2>")
        body.append(f'<p class="preamble">{_esc(RISKS_PREAMBLE)}</p>')
        if report.risks:
            body.extend(_risk_block(risk) for risk in report.risks)
        else:
            body.append('<p class="empty">No risks were raised by the analysis.</p>')
        body.append("</section>")

    body.append("<section><h2>Check results</h2>")
    if report.results:
        body.extend(_result_block(result) for result in report.results)
    elif report.summary.results_total:
        body.append(
            '<p class="empty">No findings and nothing needing review. '
            "Use --include-all to show the passed, skipped, and errored results "
            "the assessment recorded.</p>"
        )
    else:
        body.append('<p class="empty">The assessment recorded no results.</p>')
    body.append("</section>")

    if report.attack_paths:
        body.append("<section><h2>Potential attack paths</h2>")
        body.append(f'<p class="preamble">{_esc(PATHS_PREAMBLE)}</p>')
        body.extend(_path_block(path) for path in report.attack_paths)
        body.append("</section>")

    if report.correlations:
        body.append("<section><h2>Cross-endpoint correlations</h2>")
        body.extend(_correlation_block(item) for item in report.correlations)
        body.append("</section>")

    body.append("<section><h2>Limitations</h2>")
    if report.notes:
        notes = "".join(f"<li>{_esc(note)}</li>" for note in report.notes)
        body.append(f'<ul class="plain">{notes}</ul>')
    else:
        body.append('<p class="empty">No limitations were recorded.</p>')
    body.append("</section>")

    footer = (
        "<footer>"
        + _esc(
            f"Generated by {APP_NAME} {report.aegisapi_version}. "
            "Only assess APIs you own or have explicit written authorisation to test."
        )
        + "</footer>"
    )

    return head + "\n".join([*body, footer]) + "\n</body>\n</html>\n"


__all__ = [
    "EXECUTIVE_SUMMARY_HEADING",
    "METHODOLOGY_HEADING",
    "NEXT_STEP_HEADING",
    "PATHS_PREAMBLE",
    "REMEDIATION_HEADING",
    "RISKS_PREAMBLE",
    "render_html_report",
]
