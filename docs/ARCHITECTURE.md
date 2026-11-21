# Architecture

AegisAPI is a layered command-line application. This document describes what
exists today and where future functionality is intended to go.

Status labels are used throughout:

- **Implemented** - present and tested in this repository.
- **Planned** - designed for, not written. No code exists for it.

## Design principles

1. **The CLI is a shell, not the application.** `cli.py` parses options and
   renders results. Behaviour lives in `core/`, `discovery/`, `http/`,
   `testing/`, and `intelligence/`. A future API, scheduler, or test harness
   can drive the same logic without Typer.
2. **One authoritative source per fact.** The version lives in
   `src/aegisapi/__init__.py`; `pyproject.toml` reads it dynamically.
   Credential redaction lives in `utils/redaction.py`, URL parsing in
   `utils/urls.py`, and scope decisions in `core/scope.py` - each in exactly
   one place.
3. **Fail loudly, report quietly.** Unknown configuration keys are rejected;
   unexpected exceptions are logged in full and shown to the operator as a
   single line. Nothing is swallowed silently.
4. **Fail closed.** Every scope rule is an allowance, defaults deny, and a URL
   that cannot be parsed unambiguously is refused rather than interpreted.
5. **Credentials are referenced, never held.** No persisted model has a field
   that can contain a secret.
6. **Nothing happens until asked.** Importing AegisAPI configures no logging on
   the root logger, touches no files, and makes no network calls. Disk writes
   are explicit: `init`, the `target` write commands, `--log-file`, the
   `--save`/`--export` options on `discover spec`, `check run`, and `risk
   analyze`, and `report generate`. Network traffic is narrower still - only
   `request` and `check run` transmit, and only through `http/`. `report
   generate` writes a file but opens no socket.

## Layer map

```
                      +------------------------------+
                      |  cli.py / main.py            |  Implemented
                      |  option parsing, exit codes, |
                      |  error boundary              |
                      +---------------+--------------+
                                      |
                      +---------------v--------------+
                      |  commands/                   |  Implemented
                      |  per-command presentation    |  (info, init, target,
                      |                              |   discover, request,
                      |                              |   assess, report)
                      +---------------+--------------+
                                      |
        +-----------------------------v-----------------------------+
        |  core/                                                    |
        |  config  paths  workspace  logging  exceptions            |  Implemented
        |  targets (persistence)  scope (assert_in_scope: the gate) |
        +--+-------------+-------------+-------------+--------------+
           |             |             |             |
    +------v-----+ +-----v------+ +----v-------+ +---v-------------+
    | discovery/ | | http/      | | testing/   | | intelligence/   |
    | spec parse | | client,    | | the 14     | | graph, risk,    |
    | inventory  | | transport, | | security   | | correlation,    |
    | relations  | | auth       | | checks     | | attack paths    |
    +------+-----+ +-----+------+ +----+-------+ +---+-------------+
      Implemented   Implemented    Implemented    Implemented
           |             |             |             |
        +--v-------------v-------------v-------------v--+
        |  models/  target, secrets, endpoint, discovery,|  Implemented
        |           http, assessment, intelligence,      |
        |           report, common vocabulary            |
        +--+---------------------------------------+-----+
           |                                       |
    +------v-----------+              +------------v---+
    | reporting/       | Implemented  | persistence/   |  Planned
    | build  formats   | (json, html; | history, store |
    | json  html       |  no pdf)     |                |
    | writer           |              |                |
    +------------------+              +----------------+

        utils/  redaction  secrets  urls                  Implemented
                (no dependencies on anything above)
```

## Implemented modules

### `src/aegisapi/__init__.py`

The single source of `__version__`, `APP_NAME`, `APP_SLUG`, and
`APP_DESCRIPTION`. Imports no submodules, so anything may import it without
creating a cycle. `pyproject.toml` reads the version from here via setuptools'
dynamic metadata.

### `main.py`

The `aegisapi` console script. Runs the Typer application and provides a
last-resort guard for errors raised outside a command, so a user never sees a
bare traceback. Also maps `Ctrl+C` to exit code 130.

### `cli.py`

Owns the Typer applications - the root app and the `target` sub-app - global
options, and two pieces of shared machinery:

- `CliContext` - the options every command needs, resolved once in the root
  callback, plus accessors for the configuration and the target store.
  Configuration loading is **lazy**, so a command that repairs a broken
  workspace (`init`) is not blocked by a malformed `config.toml`, and
  `target scope` loads it only when it actually needs the global allow-list.
- `error_boundary()` - converts `AegisAPIError` into a short message plus the
  error's exit code, and anything unexpected into an internal-error report at
  exit code 70. Typer's own control-flow exceptions pass through untouched.

Commands contain no business logic. They translate options into models, call
`core/`, and hand the result to a `commands/` renderer. The option-to-model
translation lives here deliberately: it is CLI adaptation, and the rules it
feeds are validated in the models where they are tested directly.

### `core/exceptions.py`

`AegisAPIError` carries a user-facing `message`, an optional actionable `hint`,
and an `exit_code`. The hierarchy:

| Class | Exit code | Raised when |
| --- | --- | --- |
| `ConfigError` (`ConfigNotFoundError`, `InvalidConfigError`) | 3 | `config.toml` is missing, malformed, or invalid |
| `WorkspaceError` | 4 | The workspace cannot be created or read |
| `ScopeViolationError` | 5 | A URL fails a scope gate |
| `TargetError` (`TargetNotFoundError`, `DuplicateTargetError`, `InvalidTargetError`, `InvalidUrlError`, `TargetStoreError`) | 6 | Target management or target/URL input problems |
| `CredentialError` (`MissingCredentialError`) | 7 | A credential reference does not resolve |
| `SpecificationError` (`SpecificationNotFoundError`, `InvalidSpecificationError`, `UnsupportedSpecificationError`) | 8 | A specification cannot be read, parsed, or is an unsupported dialect |
| `DiscoveryError` | 9 | A discovery result cannot be stored, exported, or loaded |
| `TransportError` (`ConnectionFailedError`, `RequestTimeoutError`, `TlsError`, `ResponseTooLargeError`, `DestinationMismatchError`) | 10 | An authorised request produced no complete response |
| `ReportError` | 11 | A report cannot be built or written, or an unsupported format was requested |

`format_validation_problems()` turns a Pydantic error into a short list of
locations and messages. It exists partly for readability and partly for safety:
Pydantic's own representation includes input values, which could echo
credential-shaped input back to a terminal.

### `core/paths.py`

Platform-aware locations, kept separate from `config.py` because persistence,
reporting, and evidence collection will all need the same answers, and because
the rules differ enough per platform to deserve focused tests.

`WorkspacePaths` is a frozen dataclass deriving every path from one root,
including `targets_file`. `validate_path_input()` rejects empty and
NUL-containing values and makes paths absolute, so no later code depends on the
process working directory.

Resolution order: `AEGISAPI_HOME`, then `%APPDATA%\AegisAPI` on Windows, then
`$XDG_CONFIG_HOME/aegisapi` or `~/.config/aegisapi`.

### `core/config.py`

TOML via the standard library's `tomllib`; validation via Pydantic.
`AegisConfig` forbids extra keys, so typos surface immediately. Precedence is
implemented as an explicit merge chain - defaults, file, `AEGISAPI_*`
environment, caller overrides - with nested tables deep-merged rather than
replaced.

`ScopeSettings` here is the **tool-wide** gate (`enforce`, `allowed_hosts`), a
separate concern from a target's own scope rules. `render_sample_config()`
generates the commented `config.toml` that `init` writes, derived from the model
defaults so documentation and behaviour cannot drift apart.

### `core/workspace.py`

Creates the workspace: the root plus `logs/`, `assessments/`, `reports/`,
`evidence/`, and a sample `config.toml`. `targets.json` is deliberately *not*
created here, so a fresh workspace can distinguish "no targets yet" from "an
empty target list was deliberately saved".

Idempotent and non-destructive by construction. The returned `InitResult`
reports exactly what was created, overwritten, and preserved, which is what
makes the behaviour testable and the output honest. `restrict_permissions()`
and the `DIR_MODE`/`FILE_MODE` constants are shared with `core/targets.py` and
`testing/store.py`, so every file AegisAPI writes inside the workspace is
created the same way.

**That hardening is POSIX-only.** `restrict_permissions()` applies `0700` to
directories and `0600` to files on Linux and macOS, and returns immediately on
Windows: the mode bits are not honoured meaningfully there, and the per-user
profile directory is already restricted, so AegisAPI does not attempt ACL
surgery. The consequence is worth naming, because saved assessments contain
response excerpts from a client's API: on Windows those documents are only as
protected as `%APPDATA%`. The tests that assert the mode bits skip on Windows,
which is three of the suite's four skips.

### `core/logging.py`

Configures the `aegisapi` logger only, never the root logger, so importing
AegisAPI cannot hijack a host application's logging. Handlers installed here
are marked, so repeated configuration replaces its own handlers and leaves
foreign ones (a test framework's, a host application's) alone.

`SensitiveDataFilter` interpolates each record's arguments, scrubs the result,
and clears the arguments. Scrubbing the raw format string instead would be both
unsafe and incorrect: a credential passed as an argument to
`"Authorization: %s"` would never be examined, and editing text around a `%s`
breaks interpolation.

### `core/targets.py`

Persistence for registered targets: a single JSON document, loaded with full
validation and written through a temporary file plus an atomic rename.

Two decisions worth keeping:

- **Atomic writes matter more than they sound.** A half-written target file
  would silently narrow or widen a scope, and a scope the operator cannot trust
  is worse than no scope at all.
- **A damaged file is never repaired automatically.** AegisAPI reports the
  problem and stops. That file may be the only record of what an engagement was
  authorised to touch, so discarding it to make a command succeed would be the
  wrong trade.

A document declaring a higher `schema_version` is refused rather than guessed
at: a newer build may have added a scope field whose absence would silently
widen what this build considers authorised.

### `core/scope.py`

The gate. `ScopeValidator` evaluates a URL against one target's rules and
returns a `ScopeDecision` - allowed or denied, with the reason and the rule that
decided it, which is what makes the CLI output explain itself.

- `check()` never raises for a bad URL; it **denies** it. A gate that errored on
  strange input would invite a caller to treat the error as "probably fine".
- Exclusions are evaluated before includes and matched case-insensitively,
  while includes are matched case-sensitively. Both directions err toward
  denial.
- `check_global_allow_list()` is the second, independent gate, over
  `config.toml`.
- **`assert_in_scope()` is the authoritative gate, and the only entry point a
  network module may use.** It parses the URL once, applies the target gate and
  then the allow-list, redacts and logs a refusal, and returns a
  `ScopeAuthorisation` holding the parsed URL and both decisions. Returning the
  decisions is what lets a caller record *why* a destination was permitted
  without re-running the checks, which is how `HttpResponse.scope_reason` is
  populated.
- `ScopedHttpClient._authorise()` **delegates** to it, for the first request and
  for every redirect hop. The client holds no copy of the sequence. Routing all
  outbound traffic through one function is what makes the guarantee auditable;
  a check module that opened its own socket would bypass the control entirely,
  which is why a check is handed a scope-gated client and nothing else.
- The split between raising and non-raising is deliberate. `check()` and
  `check_global_allow_list()` serve code that reports a verdict without sending
  - `target scope`, which displays both verdicts, and `discovery/`'s
  classification, which labels an inventory. `assert_in_scope()` serves code
  that is about to transmit. A malformed URL is therefore *denied* by `check()`
  but *raises* `InvalidUrlError` from `assert_in_scope()`: a sender has to be
  stopped by something, and checking one spelling of a URL while sending
  another would be worse than refusing both.
- `ScopeValidator.assert_allowed()` applies the target gate alone and raises. It
  is a convenience for local reasoning, not the outbound gate, and it shares
  the same private refusal helper so a denial reads identically either way.

The module docstring states explicitly that a scope check is not authorisation,
and `AUTHORISATION_REMINDER` is printed by the commands that report scope.

### `utils/urls.py`

Strict URL and path normalisation, with no dependency on anything above it.
Its guiding rule is **reject rather than interpret**. The module docstring
lists every refused form with the reason; the short version is that userinfo,
trailing-dot hosts, fragments, backslashes, percent-encoded separators, and
double encoding all mean different things to different servers, and a scope
decision cannot afford that ambiguity.

Normalisation that *is* applied: lowercased scheme and host, IDNA encoding,
explicit default ports, collapsed slashes, resolved dot segments, and a
stripped trailing slash. The last one is load-bearing: without it, `/admin/`
would slip past an exclusion written as `/admin`.

`is_subdomain_of()` holds the dot-boundary check that defeats hostname
confusion - `example.com.attacker.test` does not end with `.example.com`.

### `utils/secrets.py`

`Secret`, an opaque container for credential material. The value is reachable
only through `reveal()`; `repr`, `str`, and formatting render `[REDACTED]`, and
pickling, copying, hashing, JSON serialisation, and use as a Pydantic field all
raise.

The threat it addresses is not a deliberate `print`. It is a debug log line, an
exception message that interpolates a request object, or a JSON dump of a
configuration structure.

### `models/secrets.py`

`SecretRef` - a provider plus the name of an environment variable. The variable
name pattern doubles as a guard against pasting a credential where a name
belongs, since real tokens almost always contain characters it rejects.

`resolve()` raises `MissingCredentialError` for an unset *or empty* variable.
AegisAPI never substitutes an empty value: a request that silently goes out
unauthenticated produces results that look like findings but are not.

`SecretProvider` exists so a later phase can add a real secret manager without
changing the target file format.

### `models/target.py`

`Target`, `ScopeRules`, and `AuthProfile`. Every model forbids unknown fields,
so a hand-edited file with `token_value` fails loudly rather than being ignored.

- `Target.create()` derives `include_paths` from the base URL's path when the
  caller gives none, which is narrower than the whole host.
- `AuthProfile` requires exactly the references its method needs. An
  over-specified profile is as much a bug as an under-specified one, because it
  hides which credential would actually be used.
- `ScopeRules` defaults to an **empty** include list, meaning nothing is in
  scope. Fail-closed is the point.

### `discovery/` - specification parsing and endpoint discovery

A pipeline, one module per stage, each testable alone:

| Module | Responsibility |
| --- | --- |
| `loader.py` | Read a local file into a plain document. `yaml.safe_load` only. |
| `versions.py` | Decide the dialect from what the document declares. |
| `references.py` | Resolve `$ref` **inside the document only**. |
| `schemas.py` | Summarise schema structure within fixed bounds. |
| `normalisation.py` | Helpers both parsers share, including security semantics. |
| `openapi.py` | OpenAPI 3.0/3.1 normalisation. |
| `swagger.py` | Swagger 2.0 normalisation. |
| `relationships.py` | Structural observations, reused by `intelligence/`. |
| `classification.py` | Map endpoints onto a target's scope via `core/scope.py`. |
| `service.py` | Run the pipeline. |
| `store.py` | Atomic persistence of results. |

Decisions worth keeping:

- **A `$ref` is a URI, which makes a naive resolver a fetcher.** Point one at
  `http://169.254.169.254/` or `file:///etc/shadow` and parsing becomes a
  request or a file read. `references.py` resolves local pointers only and
  returns an *outcome value* for everything else, so the caller records a
  warning instead of the parser making a network decision.
- **`yaml.safe_load`, always.** The unsafe loaders construct arbitrary Python
  objects from document tags. Using one would make reading a specification
  equivalent to executing it.
- **Unresolvable means reported, not fatal.** An external reference or a
  missing pointer is usually a fact about the document worth telling the
  operator, so parsing continues and a `ParseWarning` carries the detail. An
  invalid *document*, by contrast, is refused outright.
- **Bounded by construction.** Schema depth, property count, operation count,
  file size, and YAML alias count all have caps. A hostile specification should
  not be able to exhaust memory or time, and the caps are documented as
  mitigations rather than guarantees.
- **The two dialect parsers share semantics, not shape.** Everything genuinely
  common - optional-field reading, parameter inheritance, the OR-of-ANDs
  security interpretation - lives in `normalisation.py` so the parsers cannot
  drift apart on the parts that matter. Swagger's `basePath` is folded into the
  server URL rather than onto each path, which makes both dialects produce the
  same shape and avoids doubling the prefix.
- **Classification reuses the shared validator.** `classification.py` calls
  `ScopeValidator.check()`; it does not reimplement scope rules. Being the
  non-raising half of the policy is the point: classification labels an
  operation, it never sends, and the real URL is gated again by
  `assert_in_scope()` at request time. It also never writes to a target, so
  discovery cannot widen a scope.

### `models/endpoint.py` and `models/discovery.py`

The inventory vocabulary. Two invariants are enforced by the model rather than
by convention:

- **Absent stays absent.** Optional fields are `None` or empty, never defaulted.
  A parser that turned a missing `required` into `False`, or invented a `200`
  response, would hand later phases facts the API's author never stated.
- **Declared is not enforced.** `DeclaredSecurity` records the document's claim
  and its four postures (`inherited global`, `operation override`,
  `explicitly optional`, `not declared`). Nothing in it says an endpoint is
  secure, and `not declared` is a metadata gap rather than a finding.

`DiscoveryResult` is the hand-off to `testing/` and `intelligence/`: provenance
(source path, SHA-256,
declared version), classified endpoints including out-of-scope ones, declared
security schemes, structural observations, and warnings. It references the
target by name, so it structurally cannot contain a credential.

### `models/common.py`

The shared vocabulary every later layer must agree on: `Severity` and
`Confidence` (deliberately separate - "how bad" and "how sure" are different
questions, and risk prioritisation needs both), `AssessmentStatus`,
`ReportFormat`, `LogLevel`, and `AppMetadata`.

Findings, endpoints, the relationship graph, and the report envelope have since
been built on top of this vocabulary: see `models/endpoint.py`,
`models/assessment.py`, `models/intelligence.py`, and `models/report.py`.

`ReportFormat` lists `json`, `html`, and `pdf`. The first two are rendered; the
third is defined, validated by configuration, and refused at generation time.
The member stays because removing it would invalidate an existing `config.toml`
that names it, and because the enum documents the intended range rather than
the currently buildable subset - `reporting/formats.py` owns that distinction.

### `commands/`

Presentation only, one module per command group. `info.py` renders an explicit
available-versus-planned capability table - no invented scan counts or finding
totals. `init.py` renders an `InitResult`. `target.py` renders target tables,
detail panels, and scope reports. `discover.py` renders an inventory and its
warnings. `request.py` renders one exchange, with the body always passed
through Rich `Text` so a response cannot inject markup. `assess.py` renders the
check catalogue, assessment results, risk tables, the graph, attack paths, and
the scoring model, and is shared by the `check` and `risk` groups. `report.py`
renders what a generated report contains and where it was written, using the
same counts the report itself carries so the terminal and the file cannot
disagree.

No function in this package can print a credential, because no model it renders
holds one.

### `http/` - HTTP communication

**The only package that opens a network connection.** Everything above it goes
through `ScopedHttpClient`, which validates the destination before any bytes
leave the machine.

| Module | Responsibility |
| --- | --- |
| `client.py` | The request boundary: resolve, validate, authenticate, throttle, send, verify |
| `transport.py` | Pluggable transport; `httpx` behind an interface |
| `auth.py` | Credential attachment, withheld across origins |
| `throttle.py` | Rate and concurrency limits, shared across threads |
| `retry.py` | Which failures may be retried, and after how long |

Decisions worth keeping:

- **One boundary, no bypass.** There is no public method that sends without
  validating, and the transport is private to the client. Callers cannot forget
  a check because they are not offered the option.
- **The destination is verified after sending, not assumed.** The guarantee is
  that the transmitted URL matches the validated one, so the client compares
  origin and path against the scope decision and abandons the exchange on a
  mismatch. It costs one comparison and catches a transport that rewrote a URL
  or followed a redirect on its own.
- **Redirects are handled by the client, not the library.** `httpx` is
  configured with `follow_redirects=False` permanently; following a `Location`
  header would move the request to a destination nothing checked. When
  following is enabled, each hop goes back through both gates.
- **Credentials resolve at the point of use, for one origin only.** The
  resolved secret is handed to the transport and never stored on a model,
  which is why `RequestRecord` structurally cannot hold one.
- **Bodies are streamed.** The size cap is applied while receiving, so an
  oversized or endless response is abandoned rather than measured afterwards.
- **An injectable transport, not a mocked library.** `httpx` types stay behind
  `transport.py`, so the request path is testable with no network and no
  sleeping on real sockets.
- **No global client state.** A transport owns its own pool and is closed
  explicitly; there is no module-level client for a stray import to
  reconfigure. `trust_env=False` keeps proxy environment variables out of the
  path between the scope decision and the destination, and the cookie jar is
  cleared after every request.

### `models/http.py`

`HttpLimits`, `RequestRecord`, and `HttpResponse`. One invariant is encoded in
the types: an `HttpResponse` means the API answered, whatever the status, while
a failure to get an answer is a `TransportError`. A check cannot confuse
"the endpoint returned 500" with "the host was unreachable".

### `testing/` - the security checks

Checks are small objects with a declared contract; the engine owns everything
else.

| Module | Responsibility |
| --- | --- |
| `registry.py` | The check contract, selection, the shared request budget |
| `engine.py` | Endpoint selection, budget, error containment, client lifetime |
| `evidence.py` | Bounded, redacted observations with stable identifiers |
| `fixtures.py` | Operator-declared identities, owned objects, expectations |
| `authentication.py` etc. | One module per category |
| `store.py` | Atomic persistence of assessments and risk reports, one document per target |

Decisions worth keeping:

- **A check cannot reach the network except through the client it is given.**
  `CheckContext` hands over a `ScopedHttpClient` and nothing else. There is no
  transport to build and no way to widen scope, so the request boundary's
  guarantee holds by construction rather than by review.
- **Outcome and finding class are separate fields.** A check can FAIL with only
  a `SUSPECTED` finding, which is the normal case. Collapsing them is how a
  tool ends up reporting a critical finding backed by one 500 response.
- **Confirmation requires comparison, not a status code.** `AUTH-001` and
  `BOLA-001` confirm only when two responses carry the *same body*. A 200
  without credentials might be a public endpoint or an error page.
- **Authorization depends on declared ground truth and skips without it.**
  Guessing identifiers to see what returns would mean reading real users'
  data.
- **The engine contains failures.** A check that raises becomes an `ERROR`
  result; one broken check never ends a run, and an exception is never
  mistaken for a finding.
- **Identity clients share one transport and one throttle**, so acting as
  several identities cannot multiply the request rate.
- **The budget counts intended requests, not transmissions.** `RequestBudget`
  lives on `CheckContext` and each check calls `consume()` before it sends, but
  `ScopedHttpClient` does not consult it: retries and redirect hops are
  therefore uncharged, and a new check that forgot to charge it would send
  unmetered traffic. The defaults keep the two numbers equal -
  `http.max_retries` is `0` and `http.follow_redirects` is off - so this is a
  bound on check behaviour rather than a hard ceiling on wire requests. Moving
  the accounting into the client is the fix if that distinction ever matters.

### `intelligence/` - context-aware risk

| Module | Responsibility |
| --- | --- |
| `graph.py` | Nodes and edges, each edge carrying its provenance |
| `correlation.py` | Conclusions spanning more than one operation |
| `risk.py` | The published scoring table and the explanations |
| `attack_paths.py` | Bounded traversal from a reachable operation to a finding |
| `engine.py` | Orchestration into an `IntelligenceReport` |

Decisions worth keeping:

- **Provenance on everything.** A reader can always tell "the specification
  says these share a schema" from "these paths start with the same word".
  Phase 3's structural observations are reused rather than recomputed, and
  arrive as `INFERRED` because that is what they are.
- **Scoring is a table, not a formula.** Each contribution is a named factor
  with its points and its reason, so a score is an argument rather than a
  number. `risk explain` prints the table.
- **Breadth is the smallest term and capped.** Affecting more operations
  changes where to look first, never how bad something is.
- **Weak observations never accumulate into a confirmed finding.** That
  correlation exists, and its output is "a human should look", explicitly
  unconfirmed.
- **Paths end at findings and name their weakest step.** A walk that reaches
  nothing of concern is a sitemap, not an attack path, and a path containing a
  hypothetical step is never called fully evidenced.
- **Deterministic and local.** Sorted inputs throughout, no clock beyond the
  timestamp, no service. Running twice over the same inputs produces the same
  report.

### `reporting/` - output generation

| Module | Responsibility |
| --- | --- |
| `build.py` | Pure composition of saved documents into a `Report`. No I/O |
| `formats.py` | Which formats exist, how one is chosen, and the refusal |
| `json_report.py` | Sorted-key JSON rendering |
| `html_report.py` | Semantic HTML, one escaping helper, no scripts or links |
| `writer.py` | Atomic write of already-rendered text |

**Read-only with respect to the assessment.** The package loads nothing itself:
`cli.py` hands it an `AssessmentResult` and, when one is saved, an
`IntelligenceReport`, and it produces text. It sends no requests and runs no
checks, which is what keeps reporting from becoming a second assessment path -
a test makes any socket use fail during generation to hold that line.

Decisions worth keeping:

- **Composition, not duplication.** `models/report.py` embeds `CheckResult`,
  `PrioritisedRisk`, `Correlation`, and `AttackPath` rather than redeclaring
  their fields, so there is one definition of a finding and a report cannot
  drift from the documents it was built from.
- **Three schema versions, kept apart.** `REPORT_SCHEMA_VERSION` describes the
  envelope; `source_assessment_schema` and `source_intelligence_schema` record
  what it was built from. The report layout can change without the stored
  documents changing, and a consumer needs to know which input formats produced
  a given file.
- **Rendering is separate from writing.** Both renderers are pure functions
  returning a string, so every escaping guarantee is testable without touching
  the filesystem.
- **Filtering changes what is shown, never what is counted.** The default body
  is findings plus `NEEDS_REVIEW` results; `ReportSummary` always describes the
  whole assessment. `--include-all` widens the body alone.
- **Findings and risks are never summed.** A risk is derived *from* check
  results, so adding the two would count one observation twice. They are
  separate fields and the summary carries no combined total.
- **No silent format substitution.** `ReportFormat` has included `pdf` since
  the configuration vocabulary was defined, and this build cannot produce it, so
  `resolve_format()` raises `ReportError` instead of falling back. The refusal
  distinguishes a format asked for on the command line from one inherited from
  `default_report_format`, because the second mistake lives in a file.
- **The HTML renderer treats every model string as hostile.** One helper wraps
  `html.escape(value, quote=True)`, and it is the only route by which model
  data enters the document. Model URLs are rendered as text and never as an
  `href`, because escaping does not defuse a `javascript:` URL that a browser
  would still follow on click. The document declares
  `default-src 'none'; style-src 'unsafe-inline'` in a `<meta>` element, so the
  absence of scripts and external resources is browser-enforced rather than
  merely intended.
- **A third atomic writer, deliberately.** `write_report_text()` exists because
  `testing/store.write_document` and `discovery/store.write_result_file` both
  take a *model* and serialise it internally, so neither can accept HTML. It
  reuses `restrict_permissions` and `FILE_MODE` from `core/workspace.py` rather
  than reimplementing permissions. Consolidating all three behind one primitive
  is a reasonable later cleanup.

## Planned modules

None of the following exists. The boundaries are recorded so that adding them
does not disturb the layers above.

### Native PDF rendering - extending `reporting/`

`ReportFormat.PDF` is defined and refused. Producing a PDF without a browser
needs a rendering dependency AegisAPI does not have, which is the only reason
it is not implemented; the module boundary is already in place, since
`formats.py` dispatches on the format and would gain one branch.

Until then the supported route is Print to PDF from the HTML report, whose
print stylesheet avoids breaking findings and tables across pages. Whatever
lands here must keep the refusal behaviour for anything it still cannot
produce: a report in the wrong format is a different artefact, not a smaller
version of the right one.

### Live probing - extending `discovery/`

Probing for undocumented endpoints is the one part of discovery that needs the
network. It belongs beside the existing parsers, must pass every candidate URL
through `assert_in_scope()` before probing it, and should mark probed endpoints
distinctly from declared ones in the inventory. It is the most dangerous of the
planned layers, because it is the only one that synthesises URLs no
specification declared, so it should land last.

### `persistence/` - assessment history

Store assessments, findings, and evidence under the workspace; support listing,
reloading, and comparing runs. Uses `core/paths.py` for locations and should
follow the atomic-write pattern in `core/targets.py`.

What exists today is storage, not history. `AssessmentStore` and
`IntelligenceStore` keep **one document per target** under `assessments/`, so a
second `check run --save` replaces the first; `reporting/` writes one report per
target per format the same way. Evidence is stored inside the result rather than
in `evidence/`, which stays empty. Keeping several runs and diffing them is the
gap, and it needs a storage-layout decision the current scheme does not make -
timestamped documents or an index.

One rule this layer must encode rather than leave to a reader: **a diff reports
what changed between two runs, never that something was fixed.** A finding
present in one run and absent from the next may have been remediated, but it may
equally have been skipped for want of a fixture, missed because the request
budget ran out, excluded by a narrowed scope, or recorded as an error. The
existing vocabulary already keeps those apart - `CheckOutcome.SKIPPED` and
`ERROR` are distinct from `PASS`, and `budget_exhausted` is on the assessment -
so a comparison has the information it needs to describe a disappearance
honestly. Presenting absence as proof of a fix would be the same mistake as
treating a failed check as a confirmed vulnerability.

## Data flow

Everything above the dashed line works today. Below it is planned.

```
target (registered, scoped)
        |
        v
  discovery/  --(local specification, no network)-->  endpoint inventory
        |                                             + scope classification
        |                                             + structural observations
        v
  testing/  --(via http/, scope-gated)-->  check results + evidence
        |
        v
  intelligence/  ->  relationship graph + correlations
        |             + prioritised risk + attack paths
        |
        +--> testing/store.py  (raw JSON: --save, --export)
        |
        +--> reporting/  (reads the saved documents, sends nothing)
        |       +--> JSON report   reports/<target>.json
        |       +--> HTML report   reports/<target>.html
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
        +--> reporting/   (native PDF, without a browser)
        +--> persistence/ (history, comparison)
```

Every arrow that leaves the machine passes through `http/`, and every request
`http/` makes is validated against both scope gates immediately before
transmission. That is enforced by the module boundary, not by convention: the
transport is private to `ScopedHttpClient`.

## Testing strategy

Tests mirror the module layout:

| File | Covers |
| --- | --- |
| `test_cli.py` | Root CLI: help, version, info, init, error handling |
| `test_cli_discover.py` | The `discover` command group, success and failure paths |
| `test_cli_assess.py` | The `check` and `risk` groups against a local server |
| `test_cli_request.py` | The `request` command against a local HTTP server |
| `test_assessment_engine.py` | Selection, budgets, containment, scope safety |
| `test_checks.py` | Each check's conclusions and its refusals |
| `test_intelligence.py` | Graph, provenance, correlation, scoring, paths |
| `test_http_auth.py` | Credential attachment and cross-origin refusal |
| `test_http_client.py` | The request boundary and every scope-denial path |
| `test_http_models.py` | Limits, response models, configuration wiring |
| `test_http_retry.py` | The retry policy and `Retry-After` handling |
| `test_http_throttle.py` | Rate and concurrency limits, under real threads |
| `test_http_transport.py` | The real transport against 127.0.0.1 |
| `test_cli_target.py` | The `target` command group, success and failure paths |
| `test_discovery_classification.py` | Candidate URL resolution and scope classification |
| `test_discovery_store.py` | Discovery result persistence, export, corruption |
| `test_relationships.py` | Structural observations, and that none claims a finding |
| `test_spec_adversarial.py` | Hostile specifications, bounds, and the no-network guard |
| `test_spec_loader.py` | File loading, format sniffing, dialect detection |
| `test_spec_parsing.py` | Operation normalisation for all three dialects |
| `test_config.py` | Defaults, precedence, validation, malformed files |
| `test_logging.py` | Logger setup, redaction, exception behaviour |
| `test_models.py` | Shared enumerations and application metadata |
| `test_scope.py` | Scope decisions, hostname confusion, path boundaries, and the `assert_in_scope()` gate |
| `test_scope_enforcement.py` | That the request path delegates to that gate, and that direct and client enforcement agree |
| `test_secrets.py` | `Secret` opacity and `SecretRef` resolution |
| `test_target_model.py` | Target, scope, and auth validation and serialisation |
| `test_target_store.py` | Persistence, reload, corruption, atomic writes |
| `test_urls.py` | URL and path normalisation, and every rejected form |
| `test_workspace.py` | Path resolution and safe initialisation |
| `test_report_model.py` | The report envelope, summary counting, and result filtering |
| `test_report_json.py` | JSON determinism, sorted keys, recorded schema versions |
| `test_report_html.py` | The HTML escaping contract, and that no script or link is emitted |
| `test_report_writer.py` | Atomic writes, overwrite refusal, and every failure path |
| `test_report_formats.py` | Format precedence, and the refusal to substitute a format |
| `test_cli_report.py` | The `report` group, including that generation opens no socket |

Filesystem tests use `tmp_path`; environment isolation is enforced by an
autouse fixture that removes every `AEGISAPI_*` variable. No test touches the
network or the developer's real workspace.

The scope and URL tests are written as a behavioural contract rather than
coverage: each denial case corresponds to a way a request could otherwise reach
a host or path nobody authorised. Treat them as load-bearing when refactoring.

`test_spec_adversarial.py` does the same job for parsing. One test replaces
`socket.socket`, `socket.create_connection`, and `socket.getaddrinfo` with
functions that raise, then runs discovery over a document stuffed with external
references and a declared OpenID Connect URL. If any future change makes the
parser fetch something, that test fails. Keep it.

Specification fixtures live in `tests/specs.py` as Python literals, with
`spec_copy()` for tests that mutate one, so no test can affect another.

`tests/httpstub.py` holds the HTTP doubles. `FakeTransport` records what the
client decided to send; `RefusingTransport` fails the test if it is asked to
send anything, which is how every denial test proves zero transmissions rather
than inferring it from a counter. `local_server()` runs a real server on
127.0.0.1 with an ephemeral port for the transport tests, and always shuts it
down. Treat the denial and redirect tests as load-bearing: each corresponds to
a way bytes could reach a destination nobody authorised.

`test_report_html.py` is written the same way as the scope tests, and for the
same reason. A report embeds response excerpts and specification paths that
AegisAPI did not write, so each test there corresponds to a way that content
could otherwise execute, fetch something, or escape its element. A payload
carrying `< > & ' "` is injected into every string-bearing field of every model
the renderer touches, and the suite asserts the raw form never survives, that
`href` and `src` appear nowhere, and that the Content Security Policy is
declared. Treat them as load-bearing.

`test_scope_enforcement.py` guards the consolidation rather than the policy. It
spies on the gate to prove the client calls it once per request and once per
redirect hop, and it runs a matrix of URLs through both the gate directly and
the client, asserting the verdict *and* its reason match. A reintroduced second
copy of the two-gate sequence would make it fail, including the subtle case of
a copy that forgets the tool-wide allow-list.

Future layers should follow the same split: pure logic, as `intelligence/` does
today, tested against fixtures; anything that sends tested against a local stub
rather than any real API.
