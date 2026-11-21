# Development

How to set up an AegisAPI development environment and contribute changes.
Commands are given for Windows PowerShell, which is the primary development
platform; POSIX equivalents follow where they differ.

## Requirements

- Python 3.11 or newer. Developed and verified on **Python 3.11.9** (Windows 11).
- Git.
- No other system dependencies. AegisAPI has three runtime dependencies
  (`typer`, `rich`, `pydantic`) and two development dependencies (`pytest`,
  `ruff`).

Check what you have:

```powershell
python --version
py -0p          # lists every installed interpreter on Windows
```

If `python` is not 3.11+, pick an interpreter explicitly when creating the
environment, for example `py -V:3.12 -m venv .venv`.

## First-time setup

```powershell
cd C:\Users\<you>\AegisAPI
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
```

`-e` installs in editable mode: source edits take effect immediately, with no
reinstall. The `[dev]` extra adds pytest and ruff.

Activating is optional. Without activation, call the interpreter directly
(`.\.venv\Scripts\python.exe -m pytest`); the examples below use that form so
they work in a fresh shell.

```powershell
.\.venv\Scripts\Activate.ps1        # optional
```

If PowerShell blocks the activation script:

```powershell
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
```

On Linux or macOS:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install -e ".[dev]"
```

### Verify the installation

```powershell
.\.venv\Scripts\aegisapi.exe --version
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe -m ruff check .
```

## Everyday commands

```powershell
# Tests
.\.venv\Scripts\python.exe -m pytest                        # whole suite
.\.venv\Scripts\python.exe -m pytest -v                     # verbose
.\.venv\Scripts\python.exe -m pytest tests\test_config.py   # one file
.\.venv\Scripts\python.exe -m pytest -k redaction           # by name
.\.venv\Scripts\python.exe -m pytest -x                     # stop on first failure

# Lint and format
.\.venv\Scripts\python.exe -m ruff check .                  # lint
.\.venv\Scripts\python.exe -m ruff check . --fix            # autofix
.\.venv\Scripts\python.exe -m ruff format .                 # format
.\.venv\Scripts\python.exe -m ruff format --check .         # verify formatting

# Run the CLI from source
.\.venv\Scripts\python.exe -m aegisapi.main info            # module form
.\.venv\Scripts\aegisapi.exe info                           # console script
```

Everything is configured in `pyproject.toml`: pytest under
`[tool.pytest.ini_options]`, ruff under `[tool.ruff]`. There are no separate
`setup.cfg`, `pytest.ini`, or `.ruff.toml` files.

### Working against a throwaway workspace

Never develop against your real workspace. Point `AEGISAPI_HOME` elsewhere, or
pass `--workspace`:

```powershell
$env:AEGISAPI_HOME = "$env:TEMP\aegis-dev"
.\.venv\Scripts\aegisapi.exe init
.\.venv\Scripts\aegisapi.exe info

# or, per command
.\.venv\Scripts\aegisapi.exe --workspace $env:TEMP\aegis-dev init
```

Remove it when finished:

```powershell
Remove-Item -Recurse -Force "$env:TEMP\aegis-dev"
Remove-Item Env:\AEGISAPI_HOME
```

## Project conventions

### Where code goes

| Putting in... | Belongs in |
| --- | --- |
| A new command | `commands/<name>.py` for rendering, logic in `core/` |
| Behaviour, rules, filesystem or data handling | `core/` |
| A shared enum or model | `models/common.py`, only once a consumer exists |
| A persisted document shape | `models/<thing>.py`, with `extra="forbid"` |
| A specification dialect or parsing stage | `discovery/<stage>.py` |
| Anything that sends a request | `http/`, behind `ScopedHttpClient` |
| A new security check | `testing/<category>.py`, registered in `testing/engine.py` |
| Analysis over findings | `intelligence/`, which performs no I/O |
| A helper used by more than one subsystem | `utils/` |
| Option parsing, exit codes | `cli.py` |

`cli.py` must stay free of business logic. If a command function grows past
resolving inputs, calling `core/`, and rendering the result, move the middle
part out.

`utils/` must not import from `core/` or `models/` beyond `core.exceptions`.
Keeping that direction one-way is what lets `utils/urls.py` be tested as pure
input validation.

### Scope and credentials

Two rules override convenience anywhere in this codebase.

**Every outbound request goes through `ScopedHttpClient`.** `http/` is the only
package that opens a socket, and the client validates both scope gates
immediately before transmission. A check module that makes its own connection
defeats the control the whole tool rests on. If you find yourself wanting to
skip the gate "just for a health probe", the answer is no.

Concretely, when adding a module that needs the network:

- take a `ScopedHttpClient`, do not build a transport or an `httpx` client;
- never pass a caller-controlled `Host` header or a URL you have not resolved
  through `resolve_request_url`;
- treat an `HttpResponse` as "the API answered", and a `TransportError` as "we
  got no answer" - never convert one into the other;
- if you need a new limit, add it to `HttpLimits` with a conservative default
  and a test that proves the default holds.

**No persisted model may hold a credential.** Secrets are referenced by
`SecretRef` (an environment variable name) and resolved at the point of use
into a `Secret`, which is never stored or returned up the stack. When adding a
field, ask whether a `model_dump()` of it could contain something a user would
not want in a file, a log, or a report. If so, it belongs behind a reference.

**A specification is data, never code.** Parse YAML with `yaml.safe_load` and
nothing else, resolve a `$ref` only inside the document, and never fetch a URL
a document mentions - not a `$ref`, not a server, not an OpenID Connect
discovery endpoint. If a construct cannot be interpreted unambiguously, record
a `ParseWarning` and move on; if the document itself is invalid, refuse it.
Anything unbounded needs a cap, and the cap needs a comment saying what it does
and does not protect against.

**Absent is not false.** When adding an inventory field, ask what it should hold
when the document says nothing. The answer is almost always `None` or empty,
not a default. Later phases cannot distinguish "the author said no" from
"AegisAPI assumed no" once that information is gone.

**Declared is not enforced.** Discovery reports what a specification claims.
Nothing in `discovery/` or `models/endpoint.py` may conclude that an endpoint is
secure, insecure, or vulnerable, and relationship output is a structural
observation. There is a test that greps observation text for words like
"vulnerability" and "exploit"; if you need those words, you are in the wrong
phase.

**A failed check is not a confirmed vulnerability.** When adding a check, set
`finding_class` from what the evidence establishes, not from how alarming the
status code looks. `CONFIRMED` needs direct evidence of the claim itself -
usually two responses compared, not one observed. Always populate
`limitations`; a finding without them is overstated.

**Authorization checks need declared ground truth.** Never guess an identifier
to see what comes back. If the fixtures do not supply an owner or an
expectation, skip.

**Nothing unbounded.** A new check declares `requests_per_endpoint`, consumes
the shared budget before sending, and sends read-shaped methods unless the
operator opted into writes. No generated payloads.

**Intelligence performs no I/O and must stay deterministic.** Sort before
grouping, never iterate a set, and add a test that the same inputs produce the
same output. New edges need a `Provenance` and a `reason`; if nothing supports
an edge, do not create it.

When adding a new scope rule:

- Make it an *allowance*, so the default denies.
- Give the decision a `rule` string, so the CLI can explain itself.
- Add both an allow case and the corresponding bypass attempt to
  `tests/test_scope.py`.

### Code style

- Type hints on every function signature, including `-> None`.
- `from __future__ import annotations` at the top of each module.
- Docstrings on public functions, classes, and modules. Say *why*, not just
  what; a reader can see what the code does.
- `pathlib`, not `os.path`. Ruff's `PTH` rules enforce this.
- Explicit error handling. No bare `except:`, and no `except Exception: pass`.
- Line length 100. Ruff formats; do not hand-align.
- Keep modules focused. Prefer a new module over a large one, and avoid
  abstraction with only one implementation.

### Errors

Raise an `AegisAPIError` subclass for anything an operator could cause or fix,
with a `message` they can act on and a `hint` where one helps:

```python
raise InvalidConfigError(
    f"Configuration file is not valid TOML: {path}",
    hint=str(exc),
)
```

Add a new subclass when a failure deserves its own exit code. Never let an
internal detail - a stack frame, a library type name - reach the `message`.

### Logging and credentials

- Get loggers with `get_logger(__name__)`.
- Never log an authorization header, cookie, token, API key, or password.
  `SensitiveDataFilter` will scrub it, but it is a safety net, not a licence:
  the filter is heuristic over free-form text, and the surest redaction is the
  value you never pass.
- Keep operator-facing output and diagnostics apart. Command output goes to
  stdout via `cli.console`; diagnostics and errors go to stderr.
- If you add a new credential-bearing key name, add it to
  `SENSITIVE_KEY_HINTS` in `utils/redaction.py` with a test.

### Security expectations for contributions

- No dynamic imports, `eval`, `exec`, or shell execution.
- Configuration and specification files are **data**. Parse them; never execute
  them.
- No network access during import, configuration loading, or `init`.
- Never write a file the user did not ask for, and never overwrite one without
  an explicit flag.
- No hardcoded credentials, hostnames, or tokens, including in tests.
- When the HTTP layer lands, every outbound request must pass through it, so
  scope enforcement cannot be bypassed.

## Writing tests

- Use `tmp_path` for anything touching the filesystem.
- Use the `workspace_root` fixture to redirect the default workspace; it sets
  `AEGISAPI_HOME` to a temporary directory.
- Use `conftest.make_target()` to build a target, so tests exercise the same
  scope derivation that `target add` uses rather than a parallel shortcut.
- Use the fixtures in `tests/specs.py` for specification tests, and
  `spec_copy()` whenever you mutate one.
- Use `httpstub.FakeTransport` to assert what would be sent, and
  `httpstub.RefusingTransport` whenever the point is that nothing is sent.
- Use `httpstub.local_server()` for anything that needs a real socket. Bind
  only to 127.0.0.1, and never contact an external host from a test.
- Use the builders in `tests/assessfix.py` for discovery and assessment
  fixtures rather than constructing models inline.
- When a test involves a credential, assert that its *value* is absent from
  whatever the code produced - the file, the output, the log. Several existing
  tests are written that way on purpose; copy the pattern.
- Pass `env={...}` explicitly to `load_config` and friends in unit tests rather
  than relying on the process environment.
- Use the `runner` fixture plus `cli_text(result)` for CLI tests.
- Assert on behaviour, not on execution. `assert result.exit_code == 0` alone
  is not a test; check the output, the exit code, and the files on disk.
- No network access, ever. If a future test needs HTTP, stand up a local stub.
- Mark platform-specific tests with
  `@pytest.mark.skipif(sys.platform == "win32", ...)` and keep a Windows
  counterpart where the behaviour differs.

Tests live in files mirroring the module under test. An autouse fixture clears
every `AEGISAPI_*` variable, pins console width for stable Rich output, and
resets logging between tests.

## Before you commit

```powershell
.\.venv\Scripts\python.exe -m ruff format .
.\.venv\Scripts\python.exe -m ruff check .
.\.venv\Scripts\python.exe -m pytest
```

All three must pass. Then check:

- New behaviour has tests that would fail without the change.
- Documentation matches reality. If a feature is not implemented, it is labelled
  **planned** in `README.md`, `docs/ARCHITECTURE.md`, and the `info` capability
  table. Never describe unwritten functionality as working.
- `aegisapi info` still reports accurately: new capabilities move from
  `PLANNED_CAPABILITIES` to `AVAILABLE_CAPABILITIES` in `commands/info.py` only
  when they genuinely work.
- The version in `src/aegisapi/__init__.py` is the only place you changed it.
- No engagement data, logs, reports, or evidence is staged.

## Adding a dependency

Dependencies are deliberately minimal. Before adding one, ask whether the
standard library covers it - configuration uses `tomllib` for exactly this
reason. If it is justified:

1. Add it to `[project].dependencies` (or `[project.optional-dependencies].dev`)
   in `pyproject.toml` with a lower bound and a major-version ceiling.
2. Reinstall: `.\.venv\Scripts\python.exe -m pip install -e ".[dev]"`.
3. Note in the pull request why it is needed and what it replaces.

## Adding a command

1. Implement the behaviour in `core/`, with its own tests.
2. Add a renderer in `commands/<name>.py` that takes a result object and a
   `Console`.
3. Add a thin `@app.command()` in `cli.py` that resolves inputs inside
   `error_boundary(...)`, calls `core/`, and renders.
4. Add CLI tests covering success, failure, and the help text.
5. Document it in `README.md` and, if it introduces a layer, in
   `docs/ARCHITECTURE.md`.

## Troubleshooting

| Symptom | Cause and fix |
| --- | --- |
| `aegisapi` not found | The environment is not activated. Use `.\.venv\Scripts\aegisapi.exe`, or activate first. |
| `Activate.ps1 cannot be loaded` | Execution policy. Run `Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned`. |
| `ModuleNotFoundError: aegisapi` | The editable install did not run, or you are using a different interpreter. Re-run `pip install -e ".[dev]"`. |
| Configuration changes have no effect | Precedence. An `AEGISAPI_*` variable or `--config` overrides the workspace file; `aegisapi info` shows which file was loaded. |
| Every URL is out of scope | `scope.allowed_hosts` in `config.toml` ships empty, so the tool-wide gate denies everything. `aegisapi target scope <name> <url>` shows which of the two gates denied it. |
| `target scope` exits 5 on a URL you expect to pass | That is the contract: exit 5 means at least one URL was out of scope. Read the two verdict columns. |
| A credential shows as `not set` | The variable is unset or empty in *this* shell. AegisAPI stores only its name, never its value. |
| Every discovered endpoint is out of scope | The specification's server probably is not the registered target. `discover spec` prints a note naming the mismatched server. |
| `discover spec --save` refuses to run | A result is already saved for that target. Pass `--force` to replace it. |
| A `$ref` resolved to nothing | It points outside the document. AegisAPI never fetches an external reference; the warning names it. |
| `aegisapi request` refuses every URL | `scope.allowed_hosts` is empty by default, so the tool-wide gate denies everything until you name a host. |
| A request is denied but the path looks right | Scope is checked against the *normalised* URL. `aegisapi target scope <name> <url>` shows which gate refused and why. |
| A redirect was not followed | Redirects are off by default. With `--follow-redirects`, a hop to another origin is still refused. |
| A 401 appeared with credentials configured | Check the variable is set in *this* shell; a missing one raises rather than sending unauthenticated. Credentials are also withheld from any origin other than the target's. |
| `Configuration file is not valid TOML` | A real syntax error. A UTF-8 byte-order mark is tolerated, so it is not that. Compare against `aegisapi init --force` output. |
| Rich output wrapping oddly in a test | Set `COLUMNS`; the autouse fixture already pins it to 200. |
