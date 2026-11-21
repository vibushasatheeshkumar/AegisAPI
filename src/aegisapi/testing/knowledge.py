"""What each check means in OWASP terms, and what to do about it.

A check knows how to observe something. It should not also carry a paragraph of
remediation prose, because that prose is about the *class* of weakness and is
identical however many endpoints the check runs against. Keeping it here means:

* One place to read when the mapping is reviewed, instead of fourteen.
* Guidance attached by identifier, so a result carries it without every check
  having to remember to pass it.
* No guidance invented per finding. A check that is not in the table gets
  :data:`None` and the report says nothing rather than something generic.

The OWASP mapping is a *classification*, not a claim of exploitability. CONF-001
maps to API8:2023 because missing headers belong to that category; it does not
mean a missing header is a confirmed API8 vulnerability. The finding class and
confidence on the result carry that judgement, and nothing here overrides them.
"""

from __future__ import annotations

from dataclasses import dataclass

from aegisapi.models.assessment import OwaspApiCategory


@dataclass(frozen=True)
class CheckKnowledge:
    """The fixed, per-check context a finding is reported with."""

    owasp: OwaspApiCategory
    """The OWASP API Security Top 10 category this check's subject belongs to."""

    remediation: str
    """What to change in the API to address the weakness class.

    Written as a configuration or design instruction, not as "consider
    reviewing". A report whose remediation column says "review this" has not
    told the reader anything they did not know.
    """


KNOWLEDGE: dict[str, CheckKnowledge] = {
    "AUTH-001": CheckKnowledge(
        owasp=OwaspApiCategory.API2_BROKEN_AUTHENTICATION,
        remediation=(
            "Require an authenticated principal at the edge for every operation that "
            "is not deliberately public, and deny by default so a newly added route "
            "is protected before anyone remembers to protect it. Enforce this in the "
            "gateway or a global middleware rather than per handler."
        ),
    ),
    "AUTH-002": CheckKnowledge(
        owasp=OwaspApiCategory.API2_BROKEN_AUTHENTICATION,
        remediation=(
            "Reject a malformed, expired, or unverifiable credential with 401 before "
            "any handler runs. Verify the token signature and issuer against a "
            "pinned key set, and never fall back to treating an unverifiable token "
            "as anonymous access to a protected route."
        ),
    ),
    "AUTH-003": CheckKnowledge(
        owasp=OwaspApiCategory.API9_INVENTORY,
        remediation=(
            "Declare a security scheme for every operation in the specification and "
            "keep it synchronised with what the service enforces. A specification "
            "that understates protection sends reviewers and clients the wrong model "
            "of the API."
        ),
    ),
    "BOLA-001": CheckKnowledge(
        owasp=OwaspApiCategory.API1_BOLA,
        remediation=(
            "Authorise every object access against the identity making the request, "
            "in the data layer, by filtering on the owner rather than by checking an "
            "identifier the caller supplied. Treat unguessable identifiers as a "
            "convenience and never as the access-control mechanism."
        ),
    ),
    "BFLA-001": CheckKnowledge(
        owasp=OwaspApiCategory.API5_BFLA,
        remediation=(
            "Derive the permitted operations from the caller's role on the server "
            "side and deny by default. Administrative functions belong behind an "
            "explicit role check, not behind an undocumented path or a client that "
            "simply does not display the button."
        ),
    ),
    "INPUT-001": CheckKnowledge(
        owasp=OwaspApiCategory.API8_MISCONFIGURATION,
        remediation=(
            "Validate the request against the declared schema before the handler "
            "runs and reject a missing required parameter with 400. Accepting the "
            "request instead pushes an absent value into business logic that was "
            "written assuming it is present."
        ),
    ),
    "INPUT-002": CheckKnowledge(
        owasp=OwaspApiCategory.API8_MISCONFIGURATION,
        remediation=(
            "Enforce declared parameter types at the boundary and reject a value "
            "that does not convert, rather than coercing it. Silent coercion makes "
            "the effective contract different from the published one."
        ),
    ),
    "INPUT-003": CheckKnowledge(
        owasp=OwaspApiCategory.API8_MISCONFIGURATION,
        remediation=(
            "Reject a value outside a declared enumeration with 400. An accepted "
            "out-of-range value reaches code that switched on the documented set and "
            "has no branch for this one."
        ),
    ),
    "CONF-001": CheckKnowledge(
        owasp=OwaspApiCategory.API8_MISCONFIGURATION,
        remediation=(
            "Set the response headers that apply to this API at the gateway so every "
            "route inherits them. For an API reached by browsers, set "
            "X-Content-Type-Options, a restrictive Content-Security-Policy, and - "
            "over HTTPS - Strict-Transport-Security. For a machine-to-machine API, "
            "record the decision that they are unnecessary instead of leaving the "
            "absence unexplained."
        ),
    ),
    "CONF-002": CheckKnowledge(
        owasp=OwaspApiCategory.API8_MISCONFIGURATION,
        remediation=(
            "Validate the Origin header against an allow-list of exact origins and "
            "echo only a matching one. Never reflect an arbitrary origin, and never "
            "combine a reflected or wildcard origin with "
            "Access-Control-Allow-Credentials: true, which lets any site read "
            "authenticated responses."
        ),
    ),
    "CONF-003": CheckKnowledge(
        owasp=OwaspApiCategory.API8_MISCONFIGURATION,
        remediation=(
            "Serve only the methods an operation implements and return 405 for the "
            "rest. Disable TRACE and remove write methods advertised on read-only "
            "routes, whether they were enabled by a framework default or by a "
            "permissive gateway rule."
        ),
    ),
    "CONF-004": CheckKnowledge(
        owasp=OwaspApiCategory.API8_MISCONFIGURATION,
        remediation=(
            "Strip Server, X-Powered-By, and framework version headers at the "
            "gateway. Return a generic error body to clients and keep stack traces, "
            "internal paths, and SQL text in server-side logs only."
        ),
    ),
    "CONF-005": CheckKnowledge(
        owasp=OwaspApiCategory.API8_MISCONFIGURATION,
        remediation=(
            "Return the Content-Type the response body actually is, and make the "
            "error path use the same serialiser as the success path. A JSON API that "
            "answers with HTML under failure is usually a proxy or framework error "
            "page escaping to the client."
        ),
    ),
    "RATE-001": CheckKnowledge(
        owasp=OwaspApiCategory.API4_RESOURCE_CONSUMPTION,
        remediation=(
            "Apply rate limiting per client identity and per IP at the gateway, "
            "return 429 with Retry-After when it trips, and publish the limit in "
            "RateLimit headers. Pair it with a maximum page size and a request body "
            "size cap so one caller cannot consume the service."
        ),
    ),
    "DISC-001": CheckKnowledge(
        owasp=OwaspApiCategory.API9_INVENTORY,
        remediation=(
            "Decide whether the specification and documentation UI are meant to be "
            "public. If they are not, require authentication for them or serve them "
            "only on an internal network: a published specification hands an "
            "attacker the full route list, parameter names, and schema."
        ),
    ),
    "DISC-002": CheckKnowledge(
        owasp=OwaspApiCategory.API9_INVENTORY,
        remediation=(
            "Retire or protect API versions that are no longer supported. An older "
            "version that is still routable usually predates the current "
            "authorisation model and is not covered by its tests."
        ),
    ),
    "TLS-001": CheckKnowledge(
        owasp=OwaspApiCategory.API8_MISCONFIGURATION,
        remediation=(
            "Serve the API over HTTPS only, redirect HTTP to HTTPS, and send "
            "Strict-Transport-Security. Over plaintext, the credentials and "
            "responses in every request on this API are readable and modifiable by "
            "anything on the path."
        ),
    ),
    "SCHEMA-001": CheckKnowledge(
        owasp=OwaspApiCategory.API9_INVENTORY,
        remediation=(
            "Keep the response schema in the specification synchronised with what "
            "the API actually returns. Run contract tests in CI so schema drift is "
            "caught before it reaches production. A diverged schema misleads clients, "
            "auto-generated SDKs, and security reviewers about what the API does."
        ),
    ),
    "SCHEMA-002": CheckKnowledge(
        owasp=OwaspApiCategory.API9_INVENTORY,
        remediation=(
            "Declare every status code and content type the API can return in the "
            "response specifications. An undeclared status code or content type "
            "means the specification is incomplete; clients that follow the spec "
            "strictly may not handle the undeclared response correctly."
        ),
    ),
}
"""Per-check OWASP category and remediation, keyed by check identifier.

A check absent from this table reports no OWASP category and no remediation.
That is deliberate: inventing a plausible-looking category for an unmapped
check would make the classification untrustworthy for the ones that are mapped.
"""


def knowledge_for(check_id: str) -> CheckKnowledge | None:
    """The recorded OWASP category and remediation for a check, if any."""
    return KNOWLEDGE.get(check_id.strip().upper())


__all__ = ["KNOWLEDGE", "CheckKnowledge", "OwaspApiCategory", "knowledge_for"]
