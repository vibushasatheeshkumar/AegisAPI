# AegisAPI

A CLI-first API security assessment platform for bug bounty hunters and
penetration testers.

AegisAPI is a command-line tool. It is not a web application, and it ships no
dashboard or browser interface.

> **Phase 7 of 12.** This build manages targets, enforces configured scope,
> parses OpenAPI/Swagger specifications, sends scope-gated HTTP requests, runs
> **evidence-driven security checks**, produces **context-aware risk
> intelligence**, and generates **JSON and HTML reports**. It performs no
> fuzzing, no exploitation, and no probing for undocumented endpoints; it
> generates no PDF without a browser, and keeps no assessment history.
> Everything marked *planned* below is design intent. Run `aegisapi info` for an
> authoritative list of what this build actually does.
>
> **A failed check is not a confirmed vulnerability**, and an unverified attack
> path is not an exploit. AegisAPI reports outcome and finding class as separate
> things, keeps severity, confidence, and evidence strength apart, and states
> what each conclusion does *not* establish.

## Who it is for

- **Bug bounty hunters** who need repeatable, scoped assessments of API
  targets and defensible evidence for reports.
- **Penetration testers** who need API coverage inside a larger engagement,
  with findings that can be prioritised and exported.

Both audiences work under authorisation constraints, which is why scope
enforcement and credential handling are first-class concerns rather than
afterthoughts.

## Long-term objectives

AegisAPI is being built toward the following. Items marked **shipped** work in
this build; the rest are design intent.

- API target management - **shipped**
- OpenAPI and Swagger specification parsing - **shipped**, local files only
- API endpoint discovery - **shipped** for the operations a specification
  declares; probing for undocumented endpoints is still planned
- Automated API security checks - **shipped**, 14 checks
- Advanced authorization testing - **shipped**, and it needs operator-declared
  fixtures to reach a conclusion
- Intelligent risk assessment - **shipped**
- Correlation of security findings - **shipped**
- Context-aware API relationship analysis - **shipped**
- Evidence collection - **shipped** as bounded, redacted excerpts stored inside
  a saved result; there is no separate evidence store
- JSON, HTML, and PDF reporting - **shipped for JSON and HTML** via
  `aegisapi report generate`. Native PDF is still planned; the HTML report
  carries a print stylesheet so a browser's Print to PDF produces one today
- Assessment history and comparison - **planned**

## The core innovation

**Context-Aware API Risk Intelligence and Relationship Analysis.**

Most API scanners grade each endpoint in isolation, so a report becomes a flat
list in which a reflected header on a health check sits beside an
authorisation flaw on a payments route. AegisAPI's analysis layer instead
correlates endpoints, the resources they expose, their authentication
requirements, and the findings raised against them, in order to:

- group endpoints that operate on the same underlying resource;
- notice when one endpoint leaks an identifier that another endpoint accepts;
- distinguish an unauthenticated route that is meant to be public from one that
  is not;
- promote findings that sit on a path reachable from an unauthenticated entry
  point, and demote those that are not;
- explain *why* a finding ranks where it does, using the relationships rather
  than a static severity table.

**This is implemented**, and runs through `aegisapi risk`. See
[Risk intelligence](#risk-intelligence) for the relationship graph, the
published scoring table, and the attack-path rules, or
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the module boundaries.

Two limits belong up front. Relationships are drawn from what a specification
declares and what the checks actually observed, never from guessing at an API's
internals - every edge carries its provenance. And an attack path is a
hypothesis about reachability, not a demonstrated exploit: no output describes a
path as exploitable, and each one names its weakest step so you know where to
start verifying.

## Currently implemented

| Capability | Status |
| --- | --- |
| `aegisapi --help`, `--version` | Working |
| `aegisapi info` - product, environment, configuration, capability report | Working |
| `aegisapi init` - safe, repeatable workspace creation | Working |
| `aegisapi target add/list/show/update/remove` | Working |
| `aegisapi target scope` - local scope validation, no requests sent | Working |
| `aegisapi discover spec` - OpenAPI 3.0/3.1 and Swagger 2.0 parsing | Working |
| `aegisapi discover show` - redisplay a saved inventory | Working |
| `aegisapi request` - one scope-gated HTTP request | Working |
| Scope enforcement at the request boundary, before transmission | Working |
| Redirect policy: off by default, every hop re-validated | Working |
| Credential attachment, withheld across origins | Working |
| Timeouts, response-size cap, rate and concurrency limits, retries | Working |
| `aegisapi check list/run/show` - 14 evidence-driven security checks | Working |
| `aegisapi risk analyze/show/graph/paths/explain` - risk intelligence | Working |
| Relationship graph with provenance on every edge | Working |
| Cross-endpoint correlation and deterministic risk prioritisation | Working |
| TOML configuration with defaults, validation, and documented precedence | Working |
| Scope model: hosts, subdomains, ports, path patterns, exclusions | Working |
| Authentication profiles by environment-variable reference | Working |
| Endpoint inventory: parameters, bodies, responses, declared security | Working |
| Structural relationship observations over discovered operations | Working |
| Centralised logging with credential redaction | Working |
| Application exception hierarchy with distinct exit codes | Working |
| Raw JSON export of a saved inventory, result, or risk report (`--export`) | Working |
| `aegisapi report generate` - JSON reports, from a saved assessment | Working |
| `aegisapi report generate` - HTML reports: self-contained, no scripts, print stylesheet | Working |
| Native PDF generation, without a browser | **Not implemented** |
| Assessment history and comparison between runs | **Not implemented** |
| Live probing for undocumented endpoints | **Not implemented** |

## Installation

Requires Python 3.11 or newer. Developed and verified on Python 3.11.9,
Windows 11.

```powershell
cd C:\Users\<you>\AegisAPI
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
```

Then either activate the environment:

```powershell
.\.venv\Scripts\Activate.ps1
aegisapi --version
```

…or call the executable directly, without activating:

```powershell
.\.venv\Scripts\aegisapi.exe --version
```

If PowerShell refuses to run `Activate.ps1`, allow local scripts for your user:

```powershell
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
```

## Quick start

```powershell
# 1. Create the workspace and a commented sample configuration.
aegisapi init

# 2. Record the hosts you are authorised to assess (tool-wide gate).
#    Edit %APPDATA%\AegisAPI\config.toml:
#        [scope]
#        allowed_hosts = ["api.example.com"]

# 3. Register the API, with the scope you have permission to touch.
aegisapi target add example https://api.example.com/v1 `
    --description "Example engagement" `
    --exclude-path /v1/admin

# 4. Confirm what is and is not in scope, locally, before anything runs.
aegisapi target scope example `
    https://api.example.com/v1/orders `
    https://api.example.com/v1/admin/users

# 5. Review everything AegisAPI will consider authorised.
aegisapi target show example

# 6. Parse the API's specification into an endpoint inventory.
aegisapi discover spec example --file .\openapi.yaml --save

# 7. Run the security checks and save the results.
aegisapi check run example --budget 60 --save

# 8. Correlate and prioritise what the checks found.
aegisapi risk analyze example --save

# 9. Generate a report to read or share.
aegisapi report generate example --format html
```

## Targets

A target records three things that belong together: where an API lives, which
parts of it you are authorised to assess, and how a request to it would be
authenticated.

### Managing targets

```powershell
# Register. Without --include-path, the base URL's own path becomes the scope.
aegisapi target add acme https://api.acme.test/v1

# Full scope and authentication configuration.
aegisapi target add acme https://api.acme.test/v1 `
    --description "Acme public API" `
    --tag prod --tag eu `
    --include-path "/v1/**" `
    --exclude-path /v1/admin `
    --extra-host cdn.acme.test `
    --allowed-port 8443 `
    --allow-subdomains `
    --auth-method bearer `
    --token-env ACME_API_TOKEN

aegisapi target list                      # table; never shows credentials
aegisapi target list --enabled-only --tag prod
aegisapi target show acme                 # full detail; never shows credentials

# Update. Options you omit are left alone; a repeatable option replaces its
# whole list, and --clear empties one.
aegisapi target update acme --exclude-path /v1/internal
aegisapi target update acme --clear exclude-paths
aegisapi target update acme --disable     # keeps the record, removes it from scope
aegisapi target update acme --token-env ACME_NEW_TOKEN

aegisapi target remove acme               # prompts for confirmation
aegisapi target remove acme --yes         # for scripts
```

`--clear` accepts `description`, `tags`, `include-paths`, `exclude-paths`,
`extra-hosts`, `allowed-ports`, and `auth`.

### Target configuration format

Targets live in `<workspace>\targets.json`, written atomically and validated on
every load. The file is managed by the CLI; this is the shape it holds:

```json
{
  "schema_version": 1,
  "targets": {
    "acme": {
      "name": "acme",
      "base_url": "https://api.acme.test/v1",
      "description": "Acme public API",
      "tags": ["prod"],
      "enabled": true,
      "scope": {
        "include_paths": ["/v1/**"],
        "exclude_paths": ["/v1/admin"],
        "extra_hosts": ["cdn.acme.test"],
        "allowed_ports": [8443],
        "allow_subdomains": false
      },
      "auth": {
        "method": "bearer",
        "token": { "provider": "env", "variable": "ACME_API_TOKEN" },
        "api_key": null,
        "api_key_name": "X-API-Key",
        "api_key_location": "header",
        "username": null,
        "password": null
      },
      "created_at": "2026-10-23T17:38:34Z",
      "updated_at": "2026-10-23T17:38:34Z"
    }
  }
}
```

Notes on the format:

- Unknown fields are **rejected**, not ignored. A typo, or a field AegisAPI
  deliberately does not support such as `token_value`, fails loudly.
- Target names are lowercase slugs, so `Acme` and `acme` cannot become two
  targets for the same API.
- `base_url` is stored canonicalised: lowercase scheme and host, default port
  removed, path normalised, no trailing slash.
- A damaged file is reported and **never silently rewritten**. It may be the
  only record of what an engagement was authorised to touch.

## Scope rules and enforcement

**A scope check is a technical control, not permission.** Passing it means a URL
matches what you configured. It says nothing about whether the API's owner
authorised the assessment.

### The two gates

A URL must pass both before AegisAPI will contact it:

1. **The target's own scope** - `scope` in `targets.json`, per target.
2. **The tool-wide allow-list** - `scope.allowed_hosts` in `config.toml`, which
   caps everything AegisAPI may contact regardless of how many targets exist.

`aegisapi target scope <name> <url>...` reports both verdicts separately, so you
can see which gate denied a URL and why. It exits `0` when every URL is in
scope and `5` when any is not.

### How a URL is evaluated

| Check | Rule |
| --- | --- |
| Target state | A disabled target is out of scope entirely. |
| Scheme | Pinned to the base URL's scheme. An `https` target does not admit `http`. |
| Host | Exact match, or an entry in `extra_hosts`, or a subdomain when `allow_subdomains` is set. |
| Port | The base URL's port, or an entry in `allowed_ports`. |
| Path | Must match an `include_paths` pattern and no `exclude_paths` pattern. |

Path patterns use `*` for one segment and `**` for a subtree. A pattern without
wildcards covers itself and everything below it, stopping at a segment
boundary: `/admin` covers `/admin` and `/admin/users`, but not
`/administrator`. A trailing `/**` also matches its own prefix, so `/v1/**`
covers `/v1`.

### Default deny, and why it is strict

Every rule is an *allowance*. A URL is out of scope unless something admits it.

- An **empty** `include_paths` admits nothing. A target file that lost its
  include list denies everything rather than quietly widening to the whole host.
- `scope.allowed_hosts` in `config.toml` ships **empty**, so no host is
  globally authorised until you name one.
- **Exclusions win** over includes, and are matched case-insensitively, so
  `/Admin` cannot slip past an exclusion written as `/admin`.
- **An unparseable URL is denied**, never passed through. A gate that raised an
  error here would invite a caller to treat the error as "probably fine".
- Registering one URL never authorises an unrelated host.

AegisAPI **rejects** ambiguous URLs rather than interpreting them, because a
wrong guess in a scope decision means contacting a host nobody authorised:

| Rejected form | Why |
| --- | --- |
| `ftp://`, `file://`, `javascript:` | Not an API request. |
| `https://api.example.com@attacker.test/` | Userinfo: the real host is `attacker.test`. |
| `https://example.com./v1` | A trailing root label compares unequal to the same server. |
| `https://example.com/v1#frag` | A fragment is never transmitted. |
| `/v1\admin` | Several servers and proxies treat `\` as a separator. |
| `/v1/admin%2f..%2forders` | A percent-encoded separator means different things to different servers. |
| `/v1/%252e%252e/admin` | Double encoding: the result depends on how many times the server decodes. |
| `/../etc/passwd` | Traverses above the root. |

Normalisation happens *before* matching, so `/v1/orders/../admin` is evaluated
as `/v1/admin` and is caught by an exclusion on `/v1/admin`. Trailing slashes
are stripped for the same reason.

## Authentication profiles and credential safety

AegisAPI stores the **name of an environment variable**, never a credential.

```powershell
# Bearer token
aegisapi target add acme https://api.acme.test/v1 `
    --auth-method bearer --token-env ACME_API_TOKEN

# API key, in a header (default) or the query string
aegisapi target add acme https://api.acme.test/v1 `
    --auth-method api_key --api-key-env ACME_KEY `
    --api-key-name X-Acme-Key --api-key-in header

# Basic authentication: the user name is stored, the password is referenced
aegisapi target add acme https://api.acme.test/v1 `
    --auth-method basic --username scanner --password-env ACME_PASSWORD

# No authentication (the default)
aegisapi target add acme https://api.acme.test/v1 --auth-method none
```

Then set the variable in your own shell, per run:

```powershell
$env:ACME_API_TOKEN = "<token>"
aegisapi target show acme     # shows "env:ACME_API_TOKEN  set"
```

### What this guarantees

- **No model field can hold a credential.** Every secret is a reference, so
  serialising a target cannot leak one, and `target list` / `target show`
  display only the variable name plus whether it is set.
- **Resolved credentials are opaque.** They are wrapped in a `Secret` whose
  `repr`, `str`, and f-string formatting all render `[REDACTED]`, and which
  refuses to be pickled, copied, hashed, JSON-serialised, or stored on a
  Pydantic model.
- **A missing credential is an error**, never an empty string. An
  unauthenticated request that was meant to be authenticated produces
  assessment results that look like findings but are not.
- **Mistyped input is not echoed.** If you paste a token where a variable name
  belongs, the error says so without printing what you pasted.
- Logging is redacted centrally as well, so an authorization header cannot
  reach a log file even if a future module passes one to the logger.

### Limits of this approach, stated plainly

- An environment variable is readable by every process running as the same
  user, and often appears in shell history, in `ps` output on POSIX systems,
  and in crash dumps. **It is a reasonable default, not a vault.**
- AegisAPI never persists a credential, which also means it cannot help you
  rotate or audit one.
- The variable-name pattern (`[A-Za-z_][A-Za-z0-9_]*`) rejects most pasted
  tokens, but it is a guard, not a guarantee.
- `Secret` is not encryption. It protects your terminal, log files, and saved
  files, not AegisAPI's memory.
- A future phase can add a real secret provider without changing the target
  file format, because `provider` is already part of the reference.

## API discovery

`aegisapi discover spec` reads a local OpenAPI or Swagger document, normalises
every operation it declares, and classifies each one against a target's scope.

```powershell
aegisapi discover spec acme --file .\openapi.yaml

# Store the inventory so 'check run' and 'risk analyze' can read it.
aegisapi discover spec acme --file .\openapi.yaml --save

# Write the full inventory anywhere as JSON.
aegisapi discover spec acme --file .\openapi.json --export .\inventory.json

# Replace an existing saved result or export.
aegisapi discover spec acme --file .\openapi.yaml --save --force

aegisapi discover spec acme --file .\spec.yaml --limit 0        # list every operation
aegisapi discover spec acme --file .\spec.yaml --only-in-scope  # hide out-of-scope rows
aegisapi discover spec acme --file .\spec.yaml --no-relationships

aegisapi discover show acme    # redisplay the saved inventory
```

Supported dialects: **OpenAPI 3.1**, **OpenAPI 3.0**, and **Swagger 2.0**, in
JSON or YAML. A document declaring any other version is refused rather than
approximated, because a dialect AegisAPI does not understand may put security
requirements somewhere it would not look.

### What the inventory records

Per operation, where the document provides it: method, path template,
`operationId`, summary, description, tags, deprecation, the effective
parameters after path-level inheritance, request-body content types and
schemas, response codes with content types and header names, declared security,
and a JSON pointer back to the source.

Two rules govern it:

- **Absent is not false.** Where a specification says nothing, the field is
  absent. AegisAPI does not default a missing `required` to false or invent a
  `200` response.
- **Declared is not enforced.** The security columns report what the document
  *claims*. Verifying that an endpoint actually requires authentication needs a
  phase that can send requests.

Parameter inheritance follows the specification: a path-level parameter applies
to every operation beneath it, and an operation overrides one by redeclaring
the same name *and* location. The inventory records which level won.

### Declared security

Four postures are kept distinct, because they mean different things:

| Posture | Meaning |
| --- | --- |
| `inherited global` | The operation inherits the document's `security`. |
| `operation override` | The operation declares its own, replacing the global one. |
| `explicitly optional` | The document states authentication is not required (`security: []`, or an empty `{}` alternative). |
| `not declared` | Neither declares anything. A gap in metadata. |

A `security` list is an OR of alternatives, each an AND of schemes, and
AegisAPI preserves that structure. A requirement naming a scheme the document
never defines is recorded as insufficient metadata and reported as a warning.

**`not declared` is not a vulnerability report.** It means the specification is
silent. Nothing in discovery concludes that an endpoint is unprotected; only a
check that actually sent a request can say anything about enforcement.

### Structural observations

Discovery records how an API is *shaped*: operations sharing a collection root,
resources nested beneath an identified parent (`/users/{userId}` then
`/users/{userId}/orders`), an identifier appearing on several operations,
create/read/update/delete sets, shared tags, and shared schemas.

**These are structural observations, not security findings.** That two paths
form a parent-child pair says nothing about whether either enforces
authorisation. Discovery only records the structure; `aegisapi risk` is what
builds context-aware risk intelligence on top of these observations, reusing
them rather than recomputing them.

### Scope classification

Every discovered operation is classified using the **same** scope validator the
rest of AegisAPI uses:

| Classification | Meaning |
| --- | --- |
| `in scope` | A concrete URL was built and the target's scope admits it. |
| `out of scope` | A concrete URL was built and the target's scope denies it. |
| `unresolved` | No concrete URL could be built, so no decision was possible. |

Out-of-scope operations are **kept, not dropped**. What a specification declares
beyond the engagement boundary is exactly what a reviewer needs in order to
judge whether the scope is right.

Limits worth knowing:

- **A path in a specification is not authorisation.** Discovery never widens a
  target's scope, and never modifies a target at all.
- **The document's server may not be your target.** A vendor's document often
  declares a production host while the engagement covers staging. Those
  operations classify as out of scope against the registered target, which is
  correct; AegisAPI says so explicitly rather than leaving it looking broken.
- **A templated server cannot be resolved.** `https://{region}.example.com` has
  no concrete host, so those operations are `unresolved`.
- **Paths are templates.** `/users/{userId}` is classified as the literal
  template, so classification is **advisory**. A concrete request is re-checked
  by `assert_in_scope()` at request time, which is the authoritative gate.
- For Swagger 2.0, `basePath` is folded into the server URL rather than onto
  each path, mirroring how OpenAPI 3 expresses the same thing.

### Specification parsing safety

A specification is untrusted input, so parsing is defensive:

- **YAML is parsed with `yaml.safe_load` only.** The unsafe loaders construct
  arbitrary Python objects from tags such as `!!python/object/apply`, which
  turns reading a file into running code.
- **Nothing is fetched.** A `$ref` is resolved only inside the document. An
  external reference - `https://...`, `file://`, or another file - is recorded
  and reported, never followed. A declared OpenID Connect or OAuth2 URL is
  stored verbatim and never requested.
- **Circular references are detected**, not followed, and reported as warnings.
- **Bounded work.** Files over 16 MiB are refused, as are documents using more
  than 500 YAML aliases (the "billion laughs" shape). Schema nesting stops at 6
  levels, objects at 200 properties, documents at 5000 operations. The alias cap
  is a mitigation, not a guarantee: treat a third-party specification as
  untrusted regardless.
- **Malformed sections are skipped and reported**, never guessed at. An invalid
  specification is not quietly treated as a valid one.

### Discovery result format

`--save` writes `<workspace>\discovery\<target>.json`; `--export` writes the
same document anywhere. Both are versioned (`schema_version`), written
atomically, and refuse to replace an existing file without `--force`.

The document records the target name and base URL, the source path, a SHA-256
of the specification's bytes (recorded on an assessment too, so you can tell
the document changed after a run),
the declared version and format, every classified endpoint, the declared
security schemes, the structural observations, and the parse warnings.

**It cannot contain a credential.** The target is referenced by name, so no
authentication profile - and therefore no environment variable name, let alone
a secret - is serialised into it.

## Sending a request

`aegisapi request` sends one HTTP request to a registered target. It is a
transport smoke test: it does exactly what you ask, once, and interprets
nothing.

```powershell
# The host must be in scope.allowed_hosts before anything will be sent.
aegisapi request acme GET /orders
aegisapi request acme GET /orders -q limit=10 -H "Accept: application/json"
aegisapi request acme POST /orders -d '{"item":1}' --content-type application/json
aegisapi request acme POST /orders --data-file .\body.json

aegisapi request acme GET /orders --no-auth              # send without credentials
aegisapi request acme GET /orders --timeout 30           # read timeout, seconds
aegisapi request acme GET /orders --max-bytes 4096       # response size cap
aegisapi request acme GET /orders --retries 2            # read-shaped methods only
aegisapi request acme GET /start --follow-redirects      # every hop re-validated
aegisapi request acme GET /orders --no-body --no-headers
```

A `PATH` is resolved against the target's base URL and **cannot change the
origin**: a protocol-relative value such as `//attacker.test/x` is refused
rather than joined. A full URL is accepted, but it is not thereby trusted - it
still passes the full scope gate.

### Authorization required before anything is sent

Two independent gates must both admit a destination, and both are checked
immediately before transmission:

1. **The target's own scope** - scheme, host, port, and path rules in
   `targets.json`.
2. **The tool-wide allow-list** - `scope.allowed_hosts` in `config.toml`.

`scope.allowed_hosts` ships **empty**, so a fresh install sends nothing until
you name a host. That friction is deliberate.

A disabled target never sends. A denial raises before any socket is opened,
exits `5`, and says which gate refused and why.

### Scope enforcement at the request boundary

Everything above the transport goes through one function, and there is no
public method that sends without validating. The sequence per request:

| Step | What happens |
| --- | --- |
| 1 | Resolve the destination; a path can never change the origin |
| 2 | Normalise and validate the URL with the project's strict URL utilities |
| 3 | Check the target is enabled, then its scope rules |
| 4 | Check the tool-wide allow-list |
| 5 | Refuse before transmission if any check fails |
| 6 | Attach credentials, only for the target's own origin |
| 7 | Throttle, send, then **verify the transport went where it was told** |

Step 7 is not ceremony. The whole guarantee is that the bytes leaving the
machine match the URL that was checked, so the client compares the transmitted
origin and path against the validated destination and abandons the exchange on
any mismatch.

**The authoritative gate is one function: `aegisapi.core.scope.assert_in_scope()`.**
Every outbound request passes through it - the first request and each redirect
hop - and it is the only place in the project that turns a scope decision into
a refusal for a request being sent. It parses the URL once, applies the target
gate and then the allow-list, redacts and logs the refusal, and on success
returns a `ScopeAuthorisation` carrying both decisions, which is what the
response records as its scope reason. `ScopedHttpClient` keeps no copy of that
sequence; it delegates. A future probing module must call the same function
rather than assemble its own, because a second assembly would be a second
policy.

The non-raising half of the policy is deliberately separate:
`ScopeValidator.check()` and `check_global_allow_list()` return a
`ScopeDecision` without throwing, so code that reports a verdict without
sending anything can use it. That is `target scope`, which displays both gates'
verdicts, and discovery's scope classification, which labels an inventory.
Neither can transmit, and the request path does not use them directly.

Traversal, encoded dot segments, case variation, and trailing slashes are
normalised *before* the decision, so a single exclusion catches every spelling.
Encoded *separators* (`%2f`) and other ambiguous forms are refused outright.

### Redirect policy

Redirects are **disabled by default**. A 3xx comes back as an ordinary
response, with its `Location` header intact for you to read.

With `--follow-redirects`:

- every hop is validated independently through both gates before the next
  request is built - a redirect is not permission to go anywhere;
- a hop to another host, scheme, or port is refused and the chain stops;
- credentials are **never carried to a different origin**, including a caller's
  own `Authorization` header;
- hops are capped by `http.max_redirects`, and a loop is detected and refused;
- `301`, `302`, and `303` convert the method to `GET` and drop the body.

### Authentication

The target's configured profile is applied, resolving the environment variable
only once the request has passed scope enforcement and only when the
destination is the target's own origin.

- A **missing or empty** variable raises and sends nothing. AegisAPI never
  downgrades to an unauthenticated request, because the resulting 401 would
  look like a finding.
- A credential is passed straight to the transport and **never stored** on a
  model, logged, or serialised.
- `Host`, `Content-Length`, and `Transfer-Encoding` cannot be set by a caller:
  overriding `Host` would send a request to one address while claiming another
  name, which would make the scope decision describe a different destination.

Environment-variable credentials carry the limits described under *Limits of
this approach* above: readable by any process running as the same user, and
often present in shell history. Passing one with `-H` additionally leaves it in
your shell history, so prefer configuring `--token-env` on the target.

### Limits and TLS

| Setting | Default | Purpose |
| --- | --- | --- |
| `http.connect_timeout_seconds` | 5 | Connection establishment |
| `http.read_timeout_seconds` | 10 | Waiting for response data |
| `http.max_response_bytes` | 1 MiB | Response cap, enforced **while receiving** |
| `http.max_concurrency` | 4 | Requests in flight |
| `http.requests_per_second` | 2 | Rate ceiling, shared across all workers |
| `http.max_retries` | 0 | Retries. Opt-in |
| `http.follow_redirects` | false | Redirect following |
| `http.verify_tls` | true | HTTPS certificate verification |

The two top-level settings `request_timeout_seconds` and `max_concurrency` seed
their `[http]` counterparts, so an existing `config.toml` keeps working;
anything written under `[http]` wins.

The size cap is applied as data arrives, not after the body has been
downloaded, so an endless response is abandoned mid-transfer. A truncated body
is reported as truncated rather than discarded.

Retries are deliberately narrow: only `GET`, `HEAD`, and `OPTIONS`, and only
for a connection failure, a timeout, a 429, or a 503. A `POST` is never
retried. A 401, 403, 404, or 500 is an answer, not a transient fault. A TLS
failure is never retried. `Retry-After` is honoured, capped at 60 seconds so a
hostile server cannot stall an assessment. A retry goes back through the same
boundary, so it is scope-checked and rate-limited like any other request.

**TLS verification is on by default and cannot be disabled quietly.** Setting
`http.verify_tls = false` logs a warning on client construction and prints one
with every response, because a response that cannot be attributed to the
intended host is not evidence of anything.

### Error handling and redaction

Transport failures and HTTP statuses are different things, and the types keep
them apart: an `HttpResponse` means the API answered, whatever the status,
while a failure to get an answer raises and exits `10`.

- Authorization headers, cookies, tokens, API keys, and sensitive query
  parameters are redacted from every recorded URL, header set, log line, and
  error message.
- Response bodies are bounded, stripped of control characters, and rendered
  through Rich `Text` - never as markup. A response containing HTML or Rich
  tags is displayed, not interpreted.
- Full responses are never written to disk automatically.
- Exception messages carry the exception type and its own message only; request
  headers are never interpolated into one.

### Known limitations

- **No proxy support.** `trust_env=False`, so `HTTP_PROXY` and friends are
  ignored. An intercepting proxy would sit between the scope decision and the
  real destination.
- **No cookie jar.** Cookies are cleared after every request, so a session is
  never carried implicitly between requests.
- **No client certificates**, and no way to pin a certificate.
- **No HTTP/2**, and no streaming access to a body larger than the cap - only
  the first `max_response_bytes` are available.
- **`aegisapi request` records nothing to disk.** `check run` does: with
  `--save` or `--export`, bounded and redacted request and response excerpts
  are stored as evidence inside the result document. There is no separate
  evidence store, and the `evidence/` directory is unused.
- Rate limiting is per process. Two concurrent `aegisapi` invocations do not
  share a budget.
- `--follow-redirects` re-validates each hop but keeps no per-hop record beyond
  the redacted URL chain.

## Security checks

`aegisapi check` runs controlled checks against the operations discovery found.
Every request goes through the same scope-gated client as `aegisapi request`;
there is no second HTTP path.

```powershell
aegisapi check list                          # the catalogue
aegisapi check list --category authorization

# Requires a saved discovery result.
aegisapi check run acme --budget 60
aegisapi check run acme --category authentication --category configuration
aegisapi check run acme --check AUTH-001 --check CONF-002
aegisapi check run acme --fixtures .\fixtures.json --save
aegisapi check run acme --export .\assessment.json

aegisapi check show acme                     # the saved results
aegisapi check show acme --check BOLA-001    # one result in full
```

### Outcome is not the same as a finding

Two independent axes, and conflating them is how scanners produce noise:

| Outcome | Meaning |
| --- | --- |
| `pass` | The expected secure behaviour was observed |
| `fail` | The expected behaviour was not observed |
| `needs_review` | Worth a human look; the check cannot settle it |
| `skipped` | Preconditions not met, nothing sent |
| `error` | The check could not complete; says nothing about the API |

| Finding class | Meaning |
| --- | --- |
| `confirmed` | Direct evidence supports the security claim |
| `suspected` | Evidence indicates a possible issue but does not prove it |
| `informational` | Useful information, not a weakness |
| `inconclusive` | No reliable conclusion was reached |

A check can `fail` while the finding is only `suspected` - that is the normal
case. Every finding also carries **limitations** stating what it does not
establish.

### What the checks do

| ID | Category | What it does |
| --- | --- | --- |
| `AUTH-001` | authentication | Sends an operation that declares authentication without credentials, then with them. Confirms a weakness **only when both responses carry the same body** - a 200 alone proves nothing |
| `AUTH-002` | authentication | Sends a fixed, obviously synthetic invalid token and expects refusal |
| `AUTH-003` | authentication | Reports missing or incomplete security metadata. Sends nothing. A documentation gap, never a vulnerability |
| `BOLA-001` | authorization | Requests a **declared** object as its owner and as another **declared** identity, and compares |
| `BFLA-001` | authorization | Calls an operation as an identity the operator **declared** should not reach it |
| `INPUT-001/2/3` | input validation | Omits a required parameter, sends a wrong primitive type, sends an out-of-enumeration value |
| `CONF-001` | configuration | Security-relevant response headers, interpreted for an API rather than a browser page |
| `CONF-002` | configuration | CORS reflection. Only reflection **with credentials** is treated as serious |
| `CONF-003` | configuration | Compares the advertised `Allow` header with the specification. Sends only `OPTIONS` |
| `CONF-004` | configuration | Server software disclosure |
| `CONF-005` | configuration | Observed content type against the documented one |
| `RATE-001` | rate limits | A handful of identical reads, stopping on the first 429 |

### Authorization needs ground truth

`BOLA-001` and `BFLA-001` **skip** unless you supply a fixtures file. That is
deliberate: to know that reading an object was *wrong*, AegisAPI must be told
who owns it. The alternative - guessing identifiers to see what comes back -
means reading strangers' data, and this project will not do it. An endpoint
named `/admin` is not an authorization model either.

```json
{
  "identities": [
    {"name": "alice", "role": "user",
     "auth": {"method": "bearer", "token": {"variable": "ALICE_TOKEN"}}},
    {"name": "bob", "role": "user",
     "auth": {"method": "bearer", "token": {"variable": "BOB_TOKEN"}}}
  ],
  "objects": [{"owner": "alice", "parameter": "orderId", "value": "1001"}],
  "expectations": [
    {"identity": "bob", "path": "/v1/admin/**", "method": "GET", "allowed": false}
  ],
  "allow_write_methods": false
}
```

Credentials are referenced by environment variable name, exactly as targets
reference them. The file contains no secrets.

### Safety bounds

- **A shared request budget** caps the whole run (default 60). Every check
  charges it before sending, so no check can consume the run alone. Two
  caveats, stated precisely: the budget counts the requests checks *intend* to
  send, so automatic retries and followed redirect hops are not charged against
  it - inert at the defaults, since `http.max_retries` is `0` and
  `http.follow_redirects` is off - and it is a convention the checks observe,
  not a ceiling the HTTP client enforces.
- **Read-shaped methods only.** `POST`, `PUT`, `PATCH`, and `DELETE` are never
  sent unless the fixtures set `allow_write_methods`.
- **No fuzzing.** Input checks send one benign, fixed value drawn from the
  declared schema - `aegisapi-not-a-number`, not a payload. No SQL, no shell
  metacharacters, no traversal, no SSRF targets.
- **A 500 is not an exploit.** An unhandled error is reported as a low-severity
  error-handling observation that explicitly says it is not evidence of
  injection.
- **Out-of-scope and disabled targets are recorded as skipped**, with no
  request sent.
- **Evidence is bounded**: a 1 KiB excerpt, an allow-list of response headers,
  and no credential anywhere - evidence is built from already-redacted
  responses.

## Risk intelligence

`aegisapi risk` turns discovery and assessment results into an explained,
prioritised view. It runs **locally and deterministically**: no requests, no
external service, and the same inputs produce the same report.

```powershell
aegisapi risk analyze acme --save
aegisapi risk show acme
aegisapi risk graph acme          # relationships, with provenance
aegisapi risk paths acme          # potential multi-step relationships
aegisapi risk explain acme        # the scoring model
aegisapi risk explain acme risk-abc123   # one risk in full
```

### Everything carries provenance

| Provenance | Meaning |
| --- | --- |
| `observed` | AegisAPI sent a request and saw this |
| `fixture` | The operator declared it |
| `specification` | The API's own document states it |
| `inferred` | Derived from structure, such as a shared path prefix |
| `hypothetical` | Possible if an assumption held. Never evidence |

Edges are created only from specification metadata, discovery's structural
observations, recorded evidence, or operator fixtures. **Similar names create
no edge**: `/orders` and `/orderings` are not related because they look alike.

### Correlation

Cross-endpoint conclusions no single result makes: a resource reachable through
one operation but restricted through another, inconsistent declared
authentication across one resource, a confirmed weakness on a resource several
operations share, and clusters of weak observations.

**Counting weak observations never produces a confirmed finding.** Several
informational results on one resource produce a prompt to look, explicitly
marked unconfirmed and explicitly not escalated in severity.

### Scoring is a published table

| Factor | Weight |
| --- | --- |
| impact | critical 50, high 40, medium 25, low 12, info 4; multiplied by finding class (confirmed 1.0, suspected 0.6, informational 0.25, inconclusive 0.1) |
| check confidence | confirmed 12, high 8, medium 4, low 0 |
| evidence strength | 3 per direct observation, capped at 9 |
| unauthenticated reach | 8 when the operation is documented as needing no credential |
| breadth | 1.5 per additional related operation, **capped at 6** |
| correlation | 6 confirmed, 2 supporting |
| bands | critical 70+, high 50+, medium 30+, low 12+, informational 0+ |

Three rules the model does not break:

1. **Severity, confidence, and evidence strength stay separate.** A
   high-severity, low-confidence item scores below a confirmed medium one, but
   its severity is still reported as high.
2. **Breadth never raises severity.** Affecting six operations adds a small,
   capped priority contribution - "look here first", not "this is worse".
3. **Unverified stays unverified.** A suspected finding cannot be reported as
   confirmed, whatever else supports it.

Every risk lists its contributing factors with the reason each applied, so a
score can be read back as an argument and disagreed with. `aegisapi risk
explain` prints exactly that.

### Attack paths

A path is a **hypothesis about reachability**, built from documented
relationships ending at a recorded finding - for example, a collection
operation that exposes an identifier, a detail operation that accepts it, and a
confirmed authorization weakness there.

Each step is labelled `observed`, `documented`, `inferred`, or `hypothetical`,
and each path names its **weakest step** - where to start verifying. A path
containing a hypothetical step is never marked fully evidenced, and nothing in
the output describes a path as exploitable. Traversal is capped at depth 4 and
25 paths.

### Storage

`--save` writes `<workspace>\assessments\<target>.json` and
`<target>.intelligence.json`, atomically, refusing to replace an existing file
without `--force`. This is plumbing so the intelligence engine can read the
assessment - **not** assessment history; one document per target, and
comparing runs over time is a later phase.

## Reports

`aegisapi report` turns documents that are already on disk into something a
person reads.

```powershell
# Format comes from configuration when you do not say.
aegisapi report generate acme

aegisapi report generate acme --format html
aegisapi report generate acme --format json

# Write somewhere else.
aegisapi report generate acme --format html --output .\acme-report.html

# Replace an existing report, and show every result rather than findings only.
aegisapi report generate acme --format html --force --include-all
```

```
aegisapi report generate NAME [--format json|html|pdf] [--output PATH] [--force] [--include-all]
```

### It renders, it does not assess

A report is built from the **saved** assessment, and from the saved risk
analysis when one exists. Generating one **runs no security checks and sends no
network requests** - it opens no socket at all, which the test suite enforces
by making any socket use fail during report generation. A disabled target can
still be reported on, because nothing is contacted.

That also means a report is only as current as the documents behind it. Re-run
`aegisapi check run --save` and `aegisapi risk analyze --save` first if you want
it to reflect the API as it is now.

If no analysis is saved, the report is generated from check results alone, says
so on screen, and records the omission in its own limitations section rather
than leaving you to notice the risks are missing.

### Formats

| Format | State |
| --- | --- |
| `json` | **Working.** The report envelope, with sorted keys so two reports diff cleanly |
| `html` | **Working.** One self-contained file: semantic markup, embedded stylesheet, print stylesheet |
| `pdf` | **Not implemented.** Refused, never substituted |

`--format pdf` exits `11` with a message pointing at the alternative. If
`default_report_format` is set to `pdf` in `config.toml`, generation fails the
same way but with a different message, naming the setting and the file, because
that mistake lives in a file rather than on the command line. **No format is
ever silently swapped for another**; a report in the wrong format is a different
artefact, not a smaller version of the right one.

To get a PDF today, generate the HTML report and use your browser's Print to
PDF. The print stylesheet avoids breaking findings and tables across pages.

Format precedence is the project's usual order, highest first: `--format`, then
`AEGISAPI_REPORT_FORMAT`, then `default_report_format` in `config.toml`, then
the built-in default of `json`.

### Raw export is not a report

These are different things, and both are supported:

| | Writes | Schema |
| --- | --- | --- |
| `check run --export`, `risk analyze --export` | The stored document verbatim | The assessment's or analysis's own schema |
| `report generate` | A report envelope | `models/report.py`, with its own `schema_version` |

The `--export` options are unchanged by this phase. They are a serialisation of
what AegisAPI stored; a report composes those documents, adds summary counts,
orders findings by severity, and carries the three schema versions it was built
from - its own, the assessment's, and the analysis's.

### Output paths and overwriting

| Format | Default destination |
| --- | --- |
| `json` | `<workspace>\reports\<target>.json` |
| `html` | `<workspace>\reports\<target>.html` |

`--output PATH` writes anywhere instead, creating parent directories as needed.

An existing file is **refused** unless you pass `--force`; the refusal names
`--force` and exits `11`. Writes are atomic - a temporary file, flushed and
fsynced, then renamed - so a reader sees either the previous report or the new
one, never a half-written document, and a failure part-way through leaves no
partial file and no stale temporary behind. A rejected format is caught before
any document is read, so nothing is written at all.

### What a report contains

By default the body shows **findings** - confirmed or suspected - plus anything
whose outcome is `NEEDS_REVIEW`, because that outcome exists to mark what a
human should look at. `--include-all` adds the passed, skipped, and errored
results as well.

**Filtering changes what is shown, never what is counted.** The summary always
describes the whole assessment, so a filtered report still tells you how much
was examined to produce what you are reading.

Findings are ordered most severe first, then by how strongly the evidence
supports the claim, then by check and operation so the order is stable across
rebuilds.

### Findings and risks are not two tallies of the same thing

A report counts them separately and **never adds them together**, because a
risk is *derived from* check results. The same observation legitimately appears
in both: as a finding, which is what was seen, and inside a risk, which is that
finding placed in context and prioritised. Summing them would report one issue
twice.

| Count | Means |
| --- | --- |
| `confirmed_findings` | Results whose finding class is `confirmed` |
| `potential_findings` | Results whose finding class is `suspected` |
| `needs_review` | Results with the `NEEDS_REVIEW` **outcome**, whatever their finding class |
| `risks_total`, `confirmed_risks` | Prioritised risks derived from those results |
| `attack_paths_total`, `fully_evidenced_paths` | Inference about reachability, counted apart from both |

There is no combined total anywhere in the report, by design.

`next_step` is rendered under **"Next Verification Step"**, never as
remediation. AegisAPI records no remediation guidance for any check, so a
report does not imply any: the field names the observation that would settle
whether a finding is real.

### HTML safety

A report embeds material AegisAPI did not write - response excerpts and header
values from the API under test, and operation paths and schema names from a
specification supplied by a client. The renderer treats all of it as hostile.

- **Every model value is escaped** through one helper wrapping
  `html.escape(value, quote=True)`, which covers `<`, `>`, `&`, `"`, and `'`.
- **No links.** `href` and `src` do not appear in the output at all. A URL from
  a model is rendered as escaped text, because escaping does not defuse a
  `javascript:` URL inside an `href` - the browser would still run it.
- **No JavaScript and no external resources**: no `<script>`, no inline event
  handlers, no `<img>`, no web fonts, no external stylesheet, no `<iframe>`,
  `<object>`, `<embed>`, or `<form>`.
- **A Content Security Policy** is declared in a `<meta>` element -
  `default-src 'none'; style-src 'unsafe-inline'` - so a browser enforces the
  two properties above rather than taking them on trust. The policy permits
  only the embedded stylesheet.
- **Response excerpts stay inert**: escaped and placed in a wrapping `<pre>`,
  so newlines survive for a reader while the text cannot close its element.

What this does *not* claim: the HTML is not sanitised against a browser bug, and
a report still contains whatever the API returned, bounded to a 1 KiB excerpt.
Treat a report from a third-party API as untrusted content you are reading, not
as a document you have validated.

Credentials cannot reach a report. Every model it embeds is built from
already-redacted material, and the suite asserts the test token never appears in
either format.

## Configuration

### Location

| Platform | Workspace |
| --- | --- |
| Windows | `%APPDATA%\AegisAPI` |
| Linux, macOS | `$XDG_CONFIG_HOME/aegisapi`, else `~/.config/aegisapi` |

`AEGISAPI_HOME` relocates the workspace. `--workspace PATH` overrides it for a
single command. The workspace holds:

| Path | Contents |
| --- | --- |
| `config.toml` | Tool-wide settings, written by `aegisapi init`. |
| `targets.json` | Registered targets, created by the first `target add`. |
| `discovery/<target>.json` | Saved endpoint inventory, written by `discover spec --save`. |
| `logs/` | Log files written with `--log-file`. |
| `assessments/<target>.json` | Saved check results, written by `check run --save`. |
| `assessments/<target>.intelligence.json` | Saved risk report, written by `risk analyze --save`. |
| `reports/<target>.json`, `reports/<target>.html` | Generated reports, written by `report generate`. |
| `evidence/` | Created by `init`, but still reserved: nothing writes to it. Evidence lives inside a saved assessment and is rendered from there. |

### Format

TOML, parsed with the standard library. `aegisapi init` writes this:

```toml
log_level = "INFO"                 # DEBUG, INFO, WARNING, ERROR, CRITICAL
request_timeout_seconds = 10.0     # per-request timeout for future HTTP modules
max_concurrency = 4                # concurrent-request ceiling for future HTTP modules
default_report_format = "json"     # json or html; pdf validates but is not produced

[scope]
enforce = true                     # apply the tool-wide allow-list
allowed_hosts = []                 # bare hostnames: no scheme, port, or path
```

Unknown keys are rejected rather than ignored, so a typo such as `log_levl`
fails loudly instead of silently leaving a security-relevant setting at its
default. A UTF-8 byte-order mark, which Windows editors add readily, is
tolerated.

### Precedence

Lowest to highest:

1. Built-in defaults
2. `config.toml` (workspace, or `--config` / `AEGISAPI_CONFIG`)
3. `AEGISAPI_*` environment variables
4. Command-line options

Nested tables merge rather than replace, so `AEGISAPI_ENFORCE_SCOPE=false` does
not discard the `allowed_hosts` list from the file.

Recognised variables are documented in [.env.example](.env.example). AegisAPI
reads them from the real process environment; it does not load `.env` files.

### Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Success |
| 1 | Generic, expected failure (including a declined confirmation) |
| 2 | Command-line usage error (from the CLI parser) |
| 3 | Configuration missing, malformed, or invalid |
| 4 | Workspace could not be created or read |
| 5 | URL rejected by scope enforcement |
| 6 | Target problem: not found, duplicate, invalid definition, corrupt store |
| 7 | A configured credential reference could not be resolved |
| 8 | A specification could not be read, parsed, or is an unsupported version |
| 9 | A discovery result could not be stored, exported, or loaded |
| 10 | An authorised request failed before a complete response arrived |
| 11 | A report could not be built or written, or an unsupported format was requested |
| 70 | Unexpected internal error |
| 130 | Interrupted with Ctrl+C |

## Authorized testing requirement

**Use AegisAPI only against APIs you own or have explicit written authorisation
to test.** Unauthorised scanning is unlawful in most jurisdictions and will
breach the terms of most bug bounty programmes.

Registering a target and passing a scope check are not authorisation. They are
technical controls that stop a mistake from reaching an unintended host;
AegisAPI cannot know whether the configuration itself was permitted.

- Keep the authorised hosts in `scope.allowed_hosts` and leave
  `scope.enforce = true`.
- Configure each target's scope to match the written permission you hold, and
  use `aegisapi target scope` to confirm it before any assessment phase runs.
- Respect each programme's scope, rate limits, and out-of-bounds rules; they
  override anything this tool makes technically possible.
- Treat `targets.json`, `assessments/`, `reports/`, and `logs/` as sensitive
  engagement data. They live in the workspace rather than the repository, and
  `.gitignore` additionally excludes `logs/`, `reports/`, `evidence/`,
  `assessments/`, and `*.log` so a copy inside a checkout cannot be committed
  by accident. Saved assessments and generated reports both contain response
  excerpts from the API you assessed, so a report is engagement data, not a
  shareable summary until you have decided it is.
- Never commit credentials. Target files hold settings and variable names only.

## Security notes

- Credentials are redacted centrally: authorization headers, cookies, API keys,
  tokens, and passwords are scrubbed from every log record, console message,
  and log file before being written.
- Scope enforcement is one function, `aegisapi.core.scope.assert_in_scope`.
  Every outbound request and every redirect hop passes through it, and the HTTP
  client holds no second copy of the policy. Routing all outbound traffic
  through a single gate is what makes the guarantee auditable; a check module
  that opened its own socket would bypass the control entirely, so none does -
  a check is handed a scope-gated client and is given no other route to the
  network.
- Ordinary CLI users see short error messages, never internal tracebacks.
  `--debug` reveals full diagnostics when you need them.
- `targets.json` is written through a temporary file and an atomic rename, so a
  reader sees either the old document or the new one. A half-written scope
  cannot be loaded.
- `aegisapi init` never overwrites an existing `config.toml` without `--force`,
  and neither command touches files it did not create.
- On POSIX systems the workspace is created mode `0700`, and `config.toml` and
  `targets.json` mode `0600`. On Windows, access follows the user profile's
  inherited ACLs.
- No dynamic imports, `eval`, or shell execution; configuration and target
  files are parsed as data and never executed.
- A specification is parsed as data, never executed: YAML goes through
  `yaml.safe_load`, and a `$ref` or declared discovery URL pointing outside the
  document is reported rather than fetched.
- Only the `http/` package opens a network connection, and only through
  `ScopedHttpClient`. Importing AegisAPI opens none. `init`, `target`,
  `discover`, and every `risk` command transmit nothing: discovery parses local
  files, and risk analysis is local and deterministic. `request` and
  `check run` are the only commands that send traffic.

## Running the tests

```powershell
.\.venv\Scripts\python.exe -m pytest
.\.venv\Scripts\python.exe -m pytest -v
.\.venv\Scripts\python.exe -m pytest tests\test_scope.py
```

Lint and format:

```powershell
.\.venv\Scripts\python.exe -m ruff check .
.\.venv\Scripts\python.exe -m ruff format --check .
```

The suite uses temporary directories and never reads or writes your real
workspace. It requires no internet access: the transport tests run against a
local HTTP server bound to 127.0.0.1 on an ephemeral port, and one test breaks
the socket module to prove discovery cannot reach the network at all. Denial
tests use a transport that fails the test if it is asked to send anything, so
"no request was transmitted" is proven rather than inferred. Four tests covering
POSIX mode bits and POSIX path layout skip on Windows.

## Project structure

```
AegisAPI/
├── pyproject.toml           Metadata, dependencies, ruff and pytest config
├── README.md
├── LICENSE                  MIT
├── .gitignore
├── .env.example             Documented environment variables (no secrets)
│
├── src/aegisapi/
│   ├── __init__.py          Authoritative version, name, description
│   ├── main.py              Console-script entry point
│   ├── cli.py               Typer commands, options, error boundary
│   │
│   ├── core/
│   │   ├── config.py        TOML loading, validation, precedence, sample
│   │   ├── exceptions.py    Exception hierarchy and exit codes
│   │   ├── logging.py       Logger setup, redaction filter
│   │   ├── paths.py         Platform-aware workspace locations
│   │   ├── scope.py         Scope decisions, and assert_in_scope: the outbound gate
│   │   ├── targets.py       Atomic target persistence
│   │   └── workspace.py     Safe, idempotent workspace creation
│   │
│   ├── http/
│   │   ├── client.py        The request boundary: validate, then send
│   │   ├── transport.py     Pluggable transport; httpx behind an interface
│   │   ├── auth.py          Credential attachment, withheld across origins
│   │   ├── throttle.py      Rate and concurrency limits
│   │   └── retry.py         What may be retried, and after how long
│   │
│   ├── testing/
│   │   ├── registry.py      Check contract, selection, request budget
│   │   ├── engine.py        Endpoint selection, budget, error containment
│   │   ├── evidence.py      Bounded, redacted observations
│   │   ├── fixtures.py      Declared identities, objects, expectations
│   │   ├── authentication.py / authorization.py / input_validation.py
│   │   ├── configuration.py / rate_limits.py
│   │   └── store.py         Atomic assessment and risk-report persistence
│   │
│   ├── intelligence/
│   │   ├── graph.py         Relationship graph with provenance
│   │   ├── correlation.py   Cross-endpoint conclusions
│   │   ├── risk.py          Published, deterministic scoring model
│   │   ├── attack_paths.py  Bounded traversal, evidence vs inference
│   │   └── engine.py        Orchestrates the analysis
│   │
│   ├── reporting/
│   │   ├── build.py         Pure composition into a Report. No I/O
│   │   ├── formats.py       Supported formats, precedence, PDF refusal
│   │   ├── json_report.py   Sorted-key JSON rendering
│   │   ├── html_report.py   Semantic HTML, one escaping helper, no scripts
│   │   └── writer.py        Atomic write of rendered text
│   │
│   ├── discovery/
│   │   ├── loader.py         Safe local file reading (safe_load only)
│   │   ├── versions.py       Dialect detection
│   │   ├── references.py     Local-only $ref resolution
│   │   ├── schemas.py        Bounded schema summarisation
│   │   ├── normalisation.py  Shared parsing helpers, security semantics
│   │   ├── openapi.py        OpenAPI 3.0/3.1 normalisation
│   │   ├── swagger.py        Swagger 2.0 normalisation
│   │   ├── relationships.py  Structural observations, reused by intelligence/
│   │   ├── classification.py Scope classification via core/scope.py
│   │   ├── service.py        The discovery pipeline
│   │   └── store.py          Atomic discovery-result persistence
│   │
│   ├── models/
│   │   ├── common.py        Severity, Confidence, AssessmentStatus, metadata
│   │   ├── discovery.py     DiscoveryResult, classifications, warnings
│   │   ├── endpoint.py      Endpoint, parameters, schemas, declared security
│   │   ├── http.py          HttpLimits, RequestRecord, HttpResponse
│   │   ├── assessment.py    CheckResult, Evidence, outcomes, finding classes
│   │   ├── intelligence.py  Graph, correlations, risks, attack paths
│   │   ├── report.py        Report envelope and summary counts
│   │   ├── secrets.py       Credential references, never credentials
│   │   └── target.py        Target, ScopeRules, AuthProfile
│   │
│   ├── commands/            Presentation (info, init, target, discover,
│   │                        request, assess - checks and risk)
│   └── utils/
│       ├── redaction.py     Credential scrubbing
│       ├── secrets.py       Opaque Secret wrapper
│       └── urls.py          Strict URL and path normalisation
│
├── tests/                   Pytest suite
├── docs/
│   ├── ARCHITECTURE.md      Module responsibilities, planned layers
│   └── DEVELOPMENT.md       Environment setup and contribution guide
└── examples/                Example configuration files
```

## Current limitations

- No fuzzing, no exploitation, no enumeration of undocumented endpoints. The
  checks send a bounded number of benign requests to operations the
  specification declares.
- **No native PDF generation.** JSON and HTML reports are produced;
  `--format pdf` is refused rather than substituted. Print to PDF from the HTML
  report is the supported route, which means a PDF needs a browser.
- **A report is a snapshot of saved documents**, not a fresh assessment. It
  reflects whatever `check run --save` and `risk analyze --save` last wrote, and
  generating one does not re-check anything.
- **No assessment history and no comparison between runs.** Storage is one
  document per target, so a second `check run --save` replaces the first, and
  one report per target per format, replaced only with `--force`.
- Authorization checks need operator-declared fixtures and skip without them.
- The rate-limit probe cannot detect a limit above AegisAPI's own configured
  request rate, and says so in every result.
- Discovery reads **local files only**. There is no support for fetching a
  specification by URL, and no live probing for undocumented endpoints.
- See *Known limitations* under *Sending a request* for the transport's own
  constraints: no proxy, no cookie jar, no client certificates, no HTTP/2.
- **The request budget counts check requests, not transmissions.** Each check
  charges `--budget` before it sends, but automatic retries and redirect hops
  are not charged, so a run can exceed its budget in wire requests. The
  defaults make this inert - `http.max_retries` is `0` and
  `http.follow_redirects` is off - but raising either breaks the equivalence.
  The budget is also a convention the checks observe rather than a ceiling the
  HTTP client enforces: a new check that forgot to charge it would send
  unmetered traffic.
- **File permissions are POSIX-only.** The workspace is created mode `0700` and
  its files mode `0600` on Linux and macOS. On Windows those mode bits are not
  applied at all, and protection relies entirely on the inherited ACLs of the
  user profile directory. Saved assessments hold response excerpts from a
  client's API, so on Windows they are only as protected as `%APPDATA%`.
- Credentials rely on environment variables; see *Limits of this approach*.
- `targets.json` and each document under `discovery/` and `assessments/` is a
  single file. Each is written atomically, so a reader never sees a partial
  document, but AegisAPI keeps no backup of a previous version and retains only
  the latest inventory, result, and risk report per target. `--save` refuses to
  replace an existing document without `--force`.
- Schema summaries are bounded: nesting deeper than 6 levels, more than 200
  properties on one object, and circular references are recorded as such rather
  than expanded.

## Planned next phases

Roughly in order:

1. **Assessment history and comparison** - keeping several runs per target and
   diffing them, which needs a storage-layout decision the current
   one-document-per-target scheme does not make. A diff will be able to say
   *what changed between two runs*, and deliberately not that a change means a
   fix: a finding absent from a later run may have been remediated, but it may
   equally have been skipped, missed because the request budget ran out, or
   excluded by a narrowed scope. Only a verification establishes a fix.
2. **Native PDF generation** - rendering a PDF without a browser, so a report
   can be produced on a machine that has none. Needs a dependency AegisAPI does
   not currently have, which is why Print to PDF from the HTML report is the
   route today.
3. **Live probing for undocumented endpoints** - last, because it is the only
   one that synthesises URLs no specification declared and sends traffic to
   them. It must pass every candidate through `assert_in_scope()`, and mark
   probed operations distinctly from declared ones.
4. **Packaging.**

Each lands behind the module boundaries described in
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## License

MIT. See [LICENSE](LICENSE).
