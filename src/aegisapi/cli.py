"""Typer command-line interface.

This module is deliberately thin. It parses options, builds a
:class:`CliContext`, delegates to :mod:`aegisapi.core` for behaviour and to
:mod:`aegisapi.commands` for presentation, and converts application errors into
clean messages and exit codes. No assessment logic belongs here.
"""

from __future__ import annotations

from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Annotated, Any

import typer
from pydantic import ValidationError
from rich.text import Text

from aegisapi import APP_DESCRIPTION, APP_NAME, __version__
from aegisapi.commands import assess as assess_command
from aegisapi.commands import discover as discover_command
from aegisapi.commands import info as info_command
from aegisapi.commands import init as init_command
from aegisapi.commands import report as report_command
from aegisapi.commands import request as request_command
from aegisapi.commands import scan as scan_command
from aegisapi.commands import target as target_command
from aegisapi.commands import theme
from aegisapi.core.config import AegisConfig, ScopeSettings, load_config, resolve_config_path
from aegisapi.core.exceptions import (
    EXIT_FINDINGS_FOUND,
    EXIT_INTERNAL_ERROR,
    EXIT_SCOPE_ERROR,
    AegisAPIError,
    InvalidTargetError,
    format_validation_problems,
)
from aegisapi.core.logging import configure_logging, get_logger, set_log_level
from aegisapi.core.paths import WorkspacePaths
from aegisapi.core.scope import ScopeValidator, check_global_allow_list
from aegisapi.core.targets import TargetStore
from aegisapi.core.workspace import initialize_workspace
from aegisapi.discovery import DiscoveryStore, discover_from_specification
from aegisapi.discovery.store import write_result_file as write_discovery_file
from aegisapi.http import ScopedHttpClient, resolve_request_url
from aegisapi.intelligence import analyse
from aegisapi.models.assessment import CheckCategory
from aegisapi.models.common import LogLevel, ReportFormat, Severity
from aegisapi.models.http import HttpLimits, HttpMethod
from aegisapi.models.secrets import SecretRef
from aegisapi.models.target import (
    ApiKeyLocation,
    AuthMethod,
    AuthProfile,
    ScopeRules,
    Target,
)
from aegisapi.reporting import (
    build_report,
    render,
    resolve_format,
    suffix_for,
    write_report_text,
)
from aegisapi.scan.events import EventDispatcher
from aegisapi.scan.pipeline import (
    DEFAULT_SCAN_BUDGET,
    ScanOptions,
    ScanResult,
    run_scan,
)
from aegisapi.testing import AssessmentEngine, AssessmentStore, IntelligenceStore, load_fixtures
from aegisapi.testing.engine import DEFAULT_REQUEST_BUDGET
from aegisapi.testing.registry import REGISTRY
from aegisapi.testing.store import write_document
from aegisapi.utils.urls import HostExposure, classify_host_exposure, normalize_url

console = theme.make_console()
"""Command output. Everything a user asked for goes here (stdout)."""

error_console = theme.make_console(stderr=True)
"""Diagnostics and error messages (stderr)."""

logger = get_logger(__name__)

_CONTROL_FLOW_EXCEPTIONS: tuple[type[Exception], ...] = (
    typer.Exit,
    typer.Abort,
    typer.TyperException,
)
"""Exceptions Typer uses for control flow; they must reach Typer untouched."""

_USAGE_EXIT_CODE = 2
"""Exit code for an invocation that named no command.

Matches what Typer's own ``no_args_is_help`` produced before the overview was
taken over by the root callback, so a script that checks the status of a bare
``aegisapi`` sees no change.
"""

_EPILOG = "Use AegisAPI only against APIs you own or have explicit written authorisation to test."

app = typer.Typer(
    name="aegisapi",
    help=(
        f"{APP_DESCRIPTION}\n\n"
        "Available today: workspace and configuration management, target "
        "registration, local scope validation, local OpenAPI/Swagger parsing, "
        "scope-gated HTTP requests, evidence-driven security checks, "
        "context-aware risk intelligence, and JSON and HTML reports. "
        "Native PDF reporting, assessment history, and probing for "
        "undocumented endpoints are planned and not yet implemented; run "
        "'aegisapi info' for the current status."
    ),
    epilog=_EPILOG,
    # Handled in the root callback instead, so the no-argument overview can
    # carry the banner while '--help' stays plain. The exit code is preserved.
    no_args_is_help=False,
    invoke_without_command=True,
    add_completion=False,
    rich_markup_mode="rich",
    context_settings={"help_option_names": ["-h", "--help"]},
)

discover_app = typer.Typer(
    name="discover",
    help=(
        "Discover API operations from a specification.\n\n"
        "Parses a local OpenAPI or Swagger document and classifies the operations "
        "it declares against a registered target's scope. No requests are sent, "
        "and nothing the specification references is fetched."
    ),
    epilog=_EPILOG,
    no_args_is_help=True,
    rich_markup_mode="rich",
)

target_app = typer.Typer(
    name="target",
    help=(
        "Register and manage API assessment targets.\n\n"
        "A target records a base URL, the scope you are authorised to assess, "
        "and how a request would be authenticated. These commands never send a "
        "request; scope checks are local configuration checks."
    ),
    epilog=_EPILOG,
    no_args_is_help=True,
    rich_markup_mode="rich",
)
check_app = typer.Typer(
    name="check",
    help=(
        "Run controlled security checks against a registered target.\n\n"
        "Checks send requests through the same scope-gated client as every other "
        "command. A failed check is not a confirmed vulnerability: read the finding "
        "class and the limitations."
    ),
    epilog=_EPILOG,
    no_args_is_help=True,
    rich_markup_mode="rich",
)

risk_app = typer.Typer(
    name="risk",
    help=(
        "Contextual risk intelligence over discovery and assessment results.\n\n"
        "Builds an endpoint relationship graph, correlates findings across "
        "operations, prioritises them with a published scoring model, and reports "
        "potential attack paths. Runs locally and sends no requests."
    ),
    epilog=_EPILOG,
    no_args_is_help=True,
    rich_markup_mode="rich",
)

report_app = typer.Typer(
    name="report",
    help=(
        "Generate a report from a target's saved results.\n\n"
        "Renders documents that already exist: it sends no requests and runs no "
        "checks. JSON and HTML are produced; native PDF is not implemented, and "
        "the HTML report carries a print stylesheet for Print to PDF instead."
    ),
    epilog=_EPILOG,
    no_args_is_help=True,
    rich_markup_mode="rich",
)

app.add_typer(target_app, name="target")
app.add_typer(discover_app, name="discover")
app.add_typer(check_app, name="check")
app.add_typer(risk_app, name="risk")
app.add_typer(report_app, name="report")


@dataclass
class CliContext:
    """Options shared by every command, resolved once in the root callback."""

    debug: bool
    config_option: Path | None
    workspace: WorkspacePaths

    def target_store(self) -> TargetStore:
        """Build the target store for the active workspace."""
        return TargetStore.for_workspace(self.workspace)

    def discovery_store(self) -> DiscoveryStore:
        """Build the discovery result store for the active workspace."""
        return DiscoveryStore.for_workspace(self.workspace)

    def assessment_store(self) -> AssessmentStore:
        """Build the assessment store for the active workspace."""
        return AssessmentStore.for_workspace(self.workspace)

    def intelligence_store(self) -> IntelligenceStore:
        """Build the intelligence report store for the active workspace."""
        return IntelligenceStore.for_workspace(self.workspace)

    def load_config(self) -> tuple[AegisConfig, Path | None]:
        """Load configuration and apply its log level.

        Loading is lazy so that commands which repair a broken workspace, such
        as ``init``, are not blocked by a malformed configuration file.

        Returns:
            The validated configuration and the file it came from, if any.
        """
        path = resolve_config_path(self.config_option, workspace=self.workspace)
        config = load_config(path)
        if not self.debug:
            set_log_level(config.log_level)
        return config, path


def render_error(exc: AegisAPIError) -> None:
    """Print a user-facing error message without a traceback."""
    error_console.print(Text("Error:", style="status.error"), Text(exc.message))
    if exc.hint:
        error_console.print(Text(f"Hint:  {exc.hint}", style="status.warn"))


@contextmanager
def error_boundary(debug: bool) -> Iterator[None]:
    """Convert application errors into clean CLI output and exit codes.

    Expected failures (:class:`AegisAPIError`) are reported as short messages.
    Unexpected exceptions are reported as internal errors and logged; they are
    never silently swallowed, and the traceback is shown only in debug mode.
    """
    try:
        yield
    except _CONTROL_FLOW_EXCEPTIONS:
        raise
    except AegisAPIError as exc:
        logger.debug("Handled %s", type(exc).__name__, exc_info=debug)
        render_error(exc)
        raise typer.Exit(exc.exit_code) from exc
    except Exception as exc:
        logger.error("Unexpected %s: %s", type(exc).__name__, exc, exc_info=True)
        error_console.print(
            Text("Internal error:", style="status.error"),
            Text(f"{type(exc).__name__}: {exc}"),
        )
        if not debug:
            error_console.print(
                Text("Hint:  re-run with --debug for the full traceback.", style="status.warn")
            )
        raise typer.Exit(EXIT_INTERNAL_ERROR) from exc


def _version_callback(value: bool) -> None:
    """Print the version and exit, before any other option is processed."""
    if value:
        console.print(f"{APP_NAME} {__version__}")
        raise typer.Exit()


def _cli_context(ctx: typer.Context) -> CliContext:
    """Fetch the shared context, tolerating direct command invocation."""
    if isinstance(ctx.obj, CliContext):
        return ctx.obj
    return CliContext(debug=False, config_option=None, workspace=WorkspacePaths.resolve())


@app.callback()
def root(
    ctx: typer.Context,
    version: Annotated[
        bool,
        typer.Option(
            "--version",
            "-V",
            callback=_version_callback,
            is_eager=True,
            help="Show the AegisAPI version and exit.",
        ),
    ] = False,
    config: Annotated[
        Path | None,
        typer.Option(
            "--config",
            "-c",
            metavar="PATH",
            help="Configuration file to use instead of the workspace config.toml.",
        ),
    ] = None,
    workspace: Annotated[
        Path | None,
        typer.Option(
            "--workspace",
            "-w",
            metavar="PATH",
            help="Workspace directory to use instead of the platform default.",
        ),
    ] = None,
    debug: Annotated[
        bool,
        typer.Option("--debug", help="Enable debug logging and full tracebacks."),
    ] = False,
    log_file: Annotated[
        Path | None,
        typer.Option("--log-file", metavar="PATH", help="Mirror log records into a file."),
    ] = None,
) -> None:
    """Set up logging and the context shared by all commands."""
    del version  # handled eagerly by _version_callback
    with error_boundary(debug):
        configure_logging(
            LogLevel.DEBUG if debug else LogLevel.INFO,
            debug=debug,
            console=error_console,
            log_file=log_file,
        )
        ctx.obj = CliContext(
            debug=debug,
            config_option=config,
            workspace=WorkspacePaths.resolve(workspace),
        )

    if ctx.invoked_subcommand is None:
        # A bare 'aegisapi'. The banner belongs here and in 'info' only; '--help'
        # is handled eagerly by Typer and never reaches this point, so it stays
        # plain for anyone reading it in a pager or a script.
        # No description in the banner here: the help printed immediately below
        # already opens with it, and repeating it only widens the panel.
        console.print(theme.banner())
        console.print()
        typer.echo(ctx.get_help())
        raise typer.Exit(_USAGE_EXIT_CODE)


@app.command()
def info(ctx: typer.Context) -> None:
    """Show product, environment, configuration, and capability information."""
    cli_ctx = _cli_context(ctx)
    with error_boundary(cli_ctx.debug):
        config, config_path = cli_ctx.load_config()
        info_command.render_info(
            console,
            config=config,
            workspace=cli_ctx.workspace,
            config_path=config_path,
        )


@app.command()
def init(
    ctx: typer.Context,
    force: Annotated[
        bool,
        typer.Option(
            "--force",
            help="Replace an existing config.toml with a fresh sample.",
        ),
    ] = False,
) -> None:
    """Create the local AegisAPI workspace and a sample configuration file."""
    cli_ctx = _cli_context(ctx)
    with error_boundary(cli_ctx.debug):
        result = initialize_workspace(cli_ctx.workspace.root, force=force)
        init_command.render_init_result(console, result)


class ClearableField(StrEnum):
    """Fields that ``target update --clear`` can reset to their default.

    Repeatable options replace a list wholesale, which leaves no way to express
    "remove every entry". This enum provides that, explicitly and discoverably.
    """

    DESCRIPTION = "description"
    TAGS = "tags"
    INCLUDE_PATHS = "include-paths"
    EXCLUDE_PATHS = "exclude-paths"
    EXTRA_HOSTS = "extra-hosts"
    ALLOWED_PORTS = "allowed-ports"
    AUTH = "auth"


class ScanFormat(StrEnum):
    """Report formats ``scan`` can write.

    Separate from :class:`~aegisapi.models.common.ReportFormat` because a scan
    writes a *set* of files rather than one: "both" is the default, since an
    operator usually wants the HTML to read and the JSON to process, and
    "none" exists for a terminal-only run.
    """

    JSON = "json"
    HTML = "html"
    BOTH = "both"
    SARIF = "sarif"
    NONE = "none"


class FailOn(StrEnum):
    """Lowest severity that makes ``scan`` exit non-zero."""

    NEVER = "never"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


NameArgument = Annotated[str, typer.Argument(help="Target name.", metavar="NAME")]
DescriptionOption = Annotated[
    str | None, typer.Option("--description", "-d", help="Free-text note about the target.")
]
TagOption = Annotated[
    list[str] | None,
    typer.Option("--tag", help="Label for grouping. Repeatable; replaces existing tags."),
]
IncludePathOption = Annotated[
    list[str] | None,
    typer.Option(
        "--include-path",
        help=(
            "Path in scope. Repeatable; replaces the existing list. "
            "Supports '*' (one segment) and '**' (subtree)."
        ),
    ),
]
ExcludePathOption = Annotated[
    list[str] | None,
    typer.Option(
        "--exclude-path",
        help="Path never in scope, even if included. Repeatable; replaces the existing list.",
    ),
]
ExtraHostOption = Annotated[
    list[str] | None,
    typer.Option(
        "--extra-host",
        help="Additional authorised host, matched exactly. Repeatable; replaces the list.",
    ),
]
AllowedPortOption = Annotated[
    list[int] | None,
    typer.Option(
        "--allowed-port",
        help="Additional authorised port. Repeatable; replaces the existing list.",
    ),
]
SubdomainOption = Annotated[
    bool | None,
    typer.Option(
        "--allow-subdomains/--no-allow-subdomains",
        help="Whether subdomains of the base URL host are in scope. Denied by default.",
    ),
]
AuthMethodOption = Annotated[
    AuthMethod | None,
    typer.Option("--auth-method", help="How a request to this target would authenticate."),
]
TokenEnvOption = Annotated[
    str | None,
    typer.Option(
        "--token-env",
        metavar="VAR",
        help="NAME of the environment variable holding the bearer token.",
    ),
]
ApiKeyEnvOption = Annotated[
    str | None,
    typer.Option(
        "--api-key-env", metavar="VAR", help="NAME of the environment variable holding the API key."
    ),
]
ApiKeyNameOption = Annotated[
    str | None,
    typer.Option("--api-key-name", help="Header or query parameter that carries the API key."),
]
ApiKeyLocationOption = Annotated[
    ApiKeyLocation | None,
    typer.Option("--api-key-in", help="Whether the API key goes in a header or the query string."),
]
UsernameOption = Annotated[
    str | None, typer.Option("--username", help="Basic authentication user name.")
]
PasswordEnvOption = Annotated[
    str | None,
    typer.Option(
        "--password-env",
        metavar="VAR",
        help="NAME of the environment variable holding the basic-auth password.",
    ),
]


def _secret_ref(variable: str | None, *, option: str) -> SecretRef | None:
    """Turn an environment variable name into a reference.

    The error deliberately omits the offending value. If an operator pastes a
    token where a variable name belongs, echoing it back would print the
    credential to the terminal and into their shell scrollback.
    """
    if variable is None:
        return None
    try:
        return SecretRef(variable=variable)
    except ValidationError as exc:
        raise InvalidTargetError(
            f"The value given to {option} is not a valid environment variable name.",
            hint=(
                f"Pass the NAME of a variable, not the credential itself, "
                f"for example: {option} ACME_API_TOKEN"
            ),
        ) from exc


def _validate_target(data: dict[str, Any]) -> Target:
    """Validate a target document, converting Pydantic errors to AegisAPI errors."""
    try:
        return Target.model_validate(data)
    except ValidationError as exc:
        raise InvalidTargetError(
            "The target definition is not valid.",
            hint=format_validation_problems(exc),
        ) from exc


def _auth_data(
    *,
    method: AuthMethod,
    token_env: str | None,
    api_key_env: str | None,
    api_key_name: str | None,
    api_key_location: ApiKeyLocation | None,
    username: str | None,
    password_env: str | None,
) -> dict[str, Any]:
    """Assemble an authentication profile payload from CLI options."""
    data: dict[str, Any] = {"method": method}
    token = _secret_ref(token_env, option="--token-env")
    api_key = _secret_ref(api_key_env, option="--api-key-env")
    password = _secret_ref(password_env, option="--password-env")

    if token is not None:
        data["token"] = token
    if api_key is not None:
        data["api_key"] = api_key
    if api_key_name is not None:
        data["api_key_name"] = api_key_name
    if api_key_location is not None:
        data["api_key_location"] = api_key_location
    if username is not None:
        data["username"] = username
    if password is not None:
        data["password"] = password
    return data


def _scope_data(
    *,
    include_paths: Sequence[str] | None,
    exclude_paths: Sequence[str] | None,
    extra_hosts: Sequence[str] | None,
    allowed_ports: Sequence[int] | None,
    allow_subdomains: bool | None,
) -> dict[str, Any]:
    """Assemble a scope payload from the options that were actually supplied."""
    data: dict[str, Any] = {}
    if include_paths is not None:
        data["include_paths"] = list(include_paths)
    if exclude_paths is not None:
        data["exclude_paths"] = list(exclude_paths)
    if extra_hosts is not None:
        data["extra_hosts"] = list(extra_hosts)
    if allowed_ports is not None:
        data["allowed_ports"] = list(allowed_ports)
    if allow_subdomains is not None:
        data["allow_subdomains"] = allow_subdomains
    return data


@target_app.command("add")
def target_add(
    ctx: typer.Context,
    name: NameArgument,
    base_url: Annotated[
        str, typer.Argument(help="Base URL of the API, including scheme.", metavar="BASE_URL")
    ],
    description: DescriptionOption = None,
    tag: TagOption = None,
    include_path: IncludePathOption = None,
    exclude_path: ExcludePathOption = None,
    extra_host: ExtraHostOption = None,
    allowed_port: AllowedPortOption = None,
    allow_subdomains: SubdomainOption = None,
    auth_method: AuthMethodOption = None,
    token_env: TokenEnvOption = None,
    api_key_env: ApiKeyEnvOption = None,
    api_key_name: ApiKeyNameOption = None,
    api_key_in: ApiKeyLocationOption = None,
    username: UsernameOption = None,
    password_env: PasswordEnvOption = None,
    disabled: Annotated[
        bool, typer.Option("--disabled", help="Register the target but leave it out of scope.")
    ] = False,
) -> None:
    """Register a new API target.

    When no --include-path is given, the base URL's own path becomes the only
    path in scope, which is narrower than the whole host.
    """
    cli_ctx = _cli_context(ctx)
    with error_boundary(cli_ctx.debug):
        scope = _scope_data(
            include_paths=include_path,
            exclude_paths=exclude_path,
            extra_hosts=extra_host,
            allowed_ports=allowed_port,
            allow_subdomains=allow_subdomains,
        )
        auth = _auth_data(
            method=auth_method or AuthMethod.NONE,
            token_env=token_env,
            api_key_env=api_key_env,
            api_key_name=api_key_name,
            api_key_location=api_key_in,
            username=username,
            password_env=password_env,
        )
        try:
            target = Target.create(
                name=name,
                base_url=base_url,
                description=description or "",
                tags=list(tag or []),
                enabled=not disabled,
                scope=ScopeRules.model_validate(scope),
                auth=AuthProfile.model_validate(auth),
            )
        except ValidationError as exc:
            raise InvalidTargetError(
                "The target definition is not valid.",
                hint=format_validation_problems(exc),
            ) from exc
        stored = cli_ctx.target_store().add(target)
        target_command.render_target_saved(console, stored, action="registered")


@target_app.command("list")
def target_list(
    ctx: typer.Context,
    enabled_only: Annotated[
        bool, typer.Option("--enabled-only", help="Hide targets that are disabled.")
    ] = False,
    tag: Annotated[
        list[str] | None,
        typer.Option("--tag", help="Only show targets carrying this tag. Repeatable."),
    ] = None,
) -> None:
    """List registered targets. Credential values are never shown."""
    cli_ctx = _cli_context(ctx)
    with error_boundary(cli_ctx.debug):
        targets = cli_ctx.target_store().list_targets()
        if enabled_only:
            targets = [item for item in targets if item.enabled]
        if tag:
            wanted = {label.strip().lower() for label in tag}
            targets = [item for item in targets if wanted & set(item.tags)]
        target_command.render_target_table(console, targets)


@target_app.command("show")
def target_show(ctx: typer.Context, name: NameArgument) -> None:
    """Show one target's full configuration, without credential values."""
    cli_ctx = _cli_context(ctx)
    with error_boundary(cli_ctx.debug):
        target = cli_ctx.target_store().get(name)
        target_command.render_target_detail(console, target)


@target_app.command("update")
def target_update(
    ctx: typer.Context,
    name: NameArgument,
    base_url: Annotated[
        str | None, typer.Option("--base-url", help="Replace the base URL.")
    ] = None,
    description: DescriptionOption = None,
    tag: TagOption = None,
    include_path: IncludePathOption = None,
    exclude_path: ExcludePathOption = None,
    extra_host: ExtraHostOption = None,
    allowed_port: AllowedPortOption = None,
    allow_subdomains: SubdomainOption = None,
    auth_method: AuthMethodOption = None,
    token_env: TokenEnvOption = None,
    api_key_env: ApiKeyEnvOption = None,
    api_key_name: ApiKeyNameOption = None,
    api_key_in: ApiKeyLocationOption = None,
    username: UsernameOption = None,
    password_env: PasswordEnvOption = None,
    enabled: Annotated[
        bool | None,
        typer.Option("--enable/--disable", help="Allow or forbid assessment of this target."),
    ] = None,
    clear: Annotated[
        list[ClearableField] | None,
        typer.Option("--clear", help="Reset a field to its default. Repeatable."),
    ] = None,
) -> None:
    """Change a registered target.

    Options you do not pass are left alone. A repeatable option replaces the
    whole list it belongs to; use --clear to empty one.
    """
    cli_ctx = _cli_context(ctx)
    with error_boundary(cli_ctx.debug):
        store = cli_ctx.target_store()
        existing = store.get(name)
        cleared = {field.value for field in clear or []}
        notes: list[str] = []

        data = existing.model_dump(mode="python")
        if base_url is not None:
            data["base_url"] = base_url
        if description is not None:
            data["description"] = description
        if tag is not None:
            data["tags"] = list(tag)
        if enabled is not None:
            data["enabled"] = enabled

        scope = dict(data["scope"])
        scope.update(
            _scope_data(
                include_paths=include_path,
                exclude_paths=exclude_path,
                extra_hosts=extra_host,
                allowed_ports=allowed_port,
                allow_subdomains=allow_subdomains,
            )
        )

        auth_options = (
            auth_method,
            token_env,
            api_key_env,
            api_key_name,
            api_key_in,
            username,
            password_env,
        )
        auth_changed = any(value is not None for value in auth_options)
        if auth_changed:
            auth = _auth_data(
                method=auth_method or existing.auth.method,
                token_env=token_env,
                api_key_env=api_key_env,
                api_key_name=api_key_name,
                api_key_location=api_key_in,
                username=username,
                password_env=password_env,
            )
            if auth_method is None:
                # Keep references the operator did not mention.
                previous = existing.auth.model_dump(mode="python")
                for field in ("token", "api_key", "password", "username"):
                    if field not in auth and previous.get(field) is not None:
                        auth[field] = previous[field]
            data["auth"] = auth

        if "description" in cleared:
            data["description"] = ""
        if "tags" in cleared:
            data["tags"] = []
        if "include-paths" in cleared:
            scope["include_paths"] = []
            notes.append("Include paths were cleared, so nothing is in scope for this target.")
        if "exclude-paths" in cleared:
            scope["exclude_paths"] = []
        if "extra-hosts" in cleared:
            scope["extra_hosts"] = []
        if "allowed-ports" in cleared:
            scope["allowed_ports"] = []
        if "auth" in cleared:
            data["auth"] = {"method": AuthMethod.NONE}

        data["scope"] = scope
        updated = _validate_target(data)

        if base_url is not None and include_path is None and updated.base_url != existing.base_url:
            notes.append(
                "The base URL changed but the include paths did not; "
                "check 'aegisapi target show' to confirm the scope is still right."
            )

        stored = store.replace(updated)
        target_command.render_target_saved(console, stored, action="updated", notes=notes)


@target_app.command("remove")
def target_remove(
    ctx: typer.Context,
    name: NameArgument,
    yes: Annotated[bool, typer.Option("--yes", "-y", help="Skip the confirmation prompt.")] = False,
) -> None:
    """Remove a registered target.

    Asks for confirmation first. In a script, pass --yes; without a terminal
    the command aborts rather than assuming consent.
    """
    cli_ctx = _cli_context(ctx)
    with error_boundary(cli_ctx.debug):
        store = cli_ctx.target_store()
        target = store.get(name)
        if not yes:
            typer.confirm(
                f"Remove target '{target.name}' ({target.base_url})?",
                abort=True,
            )
        removed = store.remove(target.name)
        target_command.render_target_removed(console, removed)


@target_app.command("scope")
def target_scope(
    ctx: typer.Context,
    name: NameArgument,
    urls: Annotated[
        list[str] | None,
        typer.Argument(help="URLs to check against the target's scope.", metavar="[URL]..."),
    ] = None,
) -> None:
    """Show a target's scope rules, or check URLs against them.

    Checking is entirely local: no request is sent. Each URL is evaluated
    against the target's own scope and the tool-wide allow-list in config.toml,
    and both verdicts are shown. Exits with code 5 if any URL is out of scope.
    """
    cli_ctx = _cli_context(ctx)
    with error_boundary(cli_ctx.debug):
        target = cli_ctx.target_store().get(name)
        if not urls:
            target_command.render_scope_rules(console, target)
            return

        config, _ = cli_ctx.load_config()
        validator = ScopeValidator(target)
        checks = []
        for url in urls:
            global_decision = check_global_allow_list(
                _host_for_check(url, fallback=target.host), config.scope
            )
            checks.append((url, validator.check(url), global_decision))

        target_command.render_scope_checks(console, checks)
        if any(not td.allowed or not gd.allowed for _, td, gd in checks):
            raise typer.Exit(EXIT_SCOPE_ERROR)


@discover_app.command("spec")
def discover_spec(
    ctx: typer.Context,
    name: NameArgument,
    file: Annotated[
        Path,
        typer.Option(
            "--file",
            "-f",
            metavar="PATH",
            help="Local OpenAPI 3.0/3.1 or Swagger 2.0 document, in JSON or YAML.",
        ),
    ],
    save: Annotated[
        bool,
        typer.Option(
            "--save",
            help="Store the inventory in the workspace for 'check run' and 'risk analyze'.",
        ),
    ] = False,
    export: Annotated[
        Path | None,
        typer.Option("--export", metavar="PATH", help="Write the full inventory as JSON."),
    ] = None,
    force: Annotated[
        bool,
        typer.Option("--force", help="Allow --save or --export to replace an existing file."),
    ] = False,
    limit: Annotated[
        int,
        typer.Option(
            "--limit",
            min=0,
            help="How many operations to list. 0 shows all.",
        ),
    ] = discover_command.DEFAULT_ENDPOINT_LIMIT,
    only_in_scope: Annotated[
        bool,
        typer.Option(
            "--only-in-scope",
            help="Hide operations the target's scope does not cover. They are still counted.",
        ),
    ] = False,
    relationships: Annotated[
        bool,
        typer.Option(
            "--relationships/--no-relationships",
            help="Show structural observations about how the API is organised.",
        ),
    ] = True,
) -> None:
    """Discover operations from a local specification file.

    Parses the document, normalises every operation, records structural
    observations, and classifies each operation against the target's configured
    scope. Nothing is requested: not the target, and not any URL the
    specification mentions.
    """
    cli_ctx = _cli_context(ctx)
    with error_boundary(cli_ctx.debug):
        target = cli_ctx.target_store().get(name)
        result = discover_from_specification(file, target=target)

        discover_command.render_discovery_result(
            console,
            result,
            target,
            limit=limit,
            only_in_scope=only_in_scope,
            show_relationships=relationships,
        )

        written: list[str] = []
        if save:
            written.append(str(cli_ctx.discovery_store().save(result, overwrite=force)))
        if export is not None:
            written.append(str(write_discovery_file(export, result, overwrite=force)))
        if written:
            console.print()
            discover_command.render_saved(console, written)


@discover_app.command("show")
def discover_show(
    ctx: typer.Context,
    name: NameArgument,
    limit: Annotated[
        int,
        typer.Option("--limit", min=0, help="How many operations to list. 0 shows all."),
    ] = discover_command.DEFAULT_ENDPOINT_LIMIT,
    only_in_scope: Annotated[
        bool,
        typer.Option("--only-in-scope", help="Hide operations outside the target's scope."),
    ] = False,
    relationships: Annotated[
        bool,
        typer.Option("--relationships/--no-relationships", help="Show structural observations."),
    ] = True,
) -> None:
    """Show the inventory previously saved for a target."""
    cli_ctx = _cli_context(ctx)
    with error_boundary(cli_ctx.debug):
        target = cli_ctx.target_store().get(name)
        result = cli_ctx.discovery_store().load(target.name)
        discover_command.render_discovery_result(
            console,
            result,
            target,
            limit=limit,
            only_in_scope=only_in_scope,
            show_relationships=relationships,
        )


@app.command("request")
def send_request(
    ctx: typer.Context,
    name: NameArgument,
    method: Annotated[
        HttpMethod,
        typer.Argument(help="HTTP method to send.", metavar="METHOD"),
    ],
    path: Annotated[
        str,
        typer.Argument(
            help="Path relative to the target's base URL, or a full URL.",
            metavar="PATH",
        ),
    ],
    header: Annotated[
        list[str] | None,
        typer.Option(
            "--header",
            "-H",
            metavar="'Name: value'",
            help="Extra request header. Repeatable. Host cannot be set.",
        ),
    ] = None,
    query: Annotated[
        list[str] | None,
        typer.Option("--query", "-q", metavar="key=value", help="Query parameter. Repeatable."),
    ] = None,
    data: Annotated[str | None, typer.Option("--data", "-d", help="Request body, as text.")] = None,
    data_file: Annotated[
        Path | None,
        typer.Option("--data-file", metavar="PATH", help="Read the request body from a file."),
    ] = None,
    content_type: Annotated[
        str | None,
        typer.Option("--content-type", help="Content type for the request body."),
    ] = None,
    connect_timeout: Annotated[
        float | None,
        typer.Option("--connect-timeout", min=0.1, max=300, help="Override connect timeout."),
    ] = None,
    read_timeout: Annotated[
        float | None,
        typer.Option("--timeout", min=0.1, max=600, help="Override read timeout."),
    ] = None,
    max_bytes: Annotated[
        int | None,
        typer.Option("--max-bytes", min=1, help="Override the response size limit."),
    ] = None,
    retries: Annotated[
        int | None,
        typer.Option("--retries", min=0, max=5, help="Retries for read-shaped methods."),
    ] = None,
    follow_redirects: Annotated[
        bool | None,
        typer.Option(
            "--follow-redirects/--no-follow-redirects",
            help="Follow redirects, re-checking scope on every hop. Off by default.",
        ),
    ] = None,
    max_redirects: Annotated[
        int | None,
        typer.Option("--max-redirects", min=0, max=20, help="Redirect hops to follow."),
    ] = None,
    authenticate: Annotated[
        bool,
        typer.Option(
            "--auth/--no-auth",
            help="Attach the target's configured credentials. On by default.",
        ),
    ] = True,
    show_body: Annotated[
        bool, typer.Option("--body/--no-body", help="Show a bounded body preview.")
    ] = True,
    show_headers: Annotated[
        bool, typer.Option("--headers/--no-headers", help="Show response headers.")
    ] = True,
    local_lab: Annotated[
        bool,
        typer.Option(
            "--local-lab",
            help=(
                "Confirm that the target is your own local test environment. "
                "Required when the target host is a loopback or private address."
            ),
        ),
    ] = False,
) -> None:
    """Send one authorised HTTP request to a registered target.

    A transport smoke test, not a scanner: it sends exactly the request you
    describe, once. The destination is validated against the target's scope and
    the tool-wide allow-list before anything is transmitted, and a denied
    request produces no network traffic at all.

    A response tells you what the API did. It does not tell you the API is
    secure.
    """
    cli_ctx = _cli_context(ctx)
    with error_boundary(cli_ctx.debug):
        config, _ = cli_ctx.load_config()
        target = cli_ctx.target_store().get(name)
        ephemeral_scope = _require_local_lab_or_raise(target, local_lab, config)
        if ephemeral_scope is not None:
            config = config.model_copy(update={"scope": ephemeral_scope})
        if not target.enabled:
            raise InvalidTargetError(
                f"Target '{target.name}' is disabled, so no request was sent.",
                hint=f"Enable it with 'aegisapi target update {target.name} --enable'.",
            )

        limits = _limit_overrides(
            config.http,
            connect_timeout=connect_timeout,
            read_timeout=read_timeout,
            max_bytes=max_bytes,
            retries=retries,
            follow_redirects=follow_redirects,
            max_redirects=max_redirects,
        )
        body = _request_body(data, data_file)

        destination = resolve_request_url(target, path)
        request_command.render_request_plan(
            console, method=method.value, url=destination, limits=limits
        )
        console.print()

        with ScopedHttpClient(target=target, settings=config.scope, limits=limits) as client:
            response = client.request(
                method,
                path,
                params=_parse_query(query),
                headers=_parse_headers(header),
                body=body,
                content_type=content_type,
                authenticate=authenticate,
            )

        request_command.render_response(
            console,
            response,
            limits=limits,
            show_body=show_body,
            show_headers=show_headers,
        )


def _limit_overrides(
    base: HttpLimits,
    *,
    connect_timeout: float | None,
    read_timeout: float | None,
    max_bytes: int | None,
    retries: int | None,
    follow_redirects: bool | None,
    max_redirects: int | None,
) -> HttpLimits:
    """Apply command-line overrides on top of the configured limits."""
    updates: dict[str, object] = {}
    if connect_timeout is not None:
        updates["connect_timeout_seconds"] = connect_timeout
    if read_timeout is not None:
        updates["read_timeout_seconds"] = read_timeout
    if max_bytes is not None:
        updates["max_response_bytes"] = max_bytes
    if retries is not None:
        updates["max_retries"] = retries
    if follow_redirects is not None:
        updates["follow_redirects"] = follow_redirects
    if max_redirects is not None:
        updates["max_redirects"] = max_redirects
    if not updates:
        return base
    try:
        return HttpLimits.model_validate(base.model_dump() | updates)
    except ValidationError as exc:
        raise InvalidTargetError(
            "The request limits are not valid.",
            hint=format_validation_problems(exc),
        ) from exc


def _parse_headers(values: list[str] | None) -> dict[str, str]:
    """Parse repeated ``Name: value`` options.

    A credential passed this way is redacted everywhere AegisAPI records it,
    but it still lands in shell history, so the help text points at
    ``--token-env`` on the target instead.
    """
    headers: dict[str, str] = {}
    for item in values or []:
        name, separator, value = item.partition(":")
        if not separator or not name.strip():
            raise InvalidTargetError(
                f"Header {item!r} is not in 'Name: value' form.",
                hint="For example: -H 'Accept: application/json'",
            )
        headers[name.strip()] = value.strip()
    return headers


def _parse_query(values: list[str] | None) -> dict[str, str]:
    """Parse repeated ``key=value`` options."""
    params: dict[str, str] = {}
    for item in values or []:
        key, separator, value = item.partition("=")
        if not separator or not key.strip():
            raise InvalidTargetError(
                f"Query parameter {item!r} is not in 'key=value' form.",
                hint="For example: -q limit=10",
            )
        params[key.strip()] = value
    return params


def _request_body(data: str | None, data_file: Path | None) -> bytes | None:
    """Read the request body from an option or a file."""
    if data is not None and data_file is not None:
        raise InvalidTargetError(
            "Pass either --data or --data-file, not both.",
        )
    if data is not None:
        return data.encode("utf-8")
    if data_file is None:
        return None
    try:
        return data_file.expanduser().read_bytes()
    except OSError as exc:
        raise InvalidTargetError(
            f"The request body file could not be read: {data_file}",
            hint=exc.strerror,
        ) from exc


@check_app.command("list")
def check_list(
    ctx: typer.Context,
    category: Annotated[
        list[CheckCategory] | None,
        typer.Option("--category", "-c", help="Only show checks in this category."),
    ] = None,
) -> None:
    """List the available security checks."""
    cli_ctx = _cli_context(ctx)
    with error_boundary(cli_ctx.debug):
        checks = REGISTRY.select(categories=category)
        assess_command.render_check_catalogue(console, checks)


@check_app.command("run")
def check_run(
    ctx: typer.Context,
    name: NameArgument,
    category: Annotated[
        list[CheckCategory] | None,
        typer.Option("--category", "-c", help="Restrict to these categories. Repeatable."),
    ] = None,
    check: Annotated[
        list[str] | None,
        typer.Option("--check", help="Run exactly these check ids. Repeatable."),
    ] = None,
    fixtures: Annotated[
        Path | None,
        typer.Option(
            "--fixtures",
            metavar="PATH",
            help="Declared identities, owned objects, and access expectations.",
        ),
    ] = None,
    budget: Annotated[
        int,
        typer.Option("--budget", min=0, max=5000, help="Total requests the run may send."),
    ] = DEFAULT_REQUEST_BUDGET,
    max_endpoints: Annotated[
        int | None,
        typer.Option("--max-endpoints", min=1, help="Only consider the first N operations."),
    ] = None,
    save: Annotated[
        bool, typer.Option("--save", help="Store the results for 'risk analyze'.")
    ] = False,
    export: Annotated[
        Path | None,
        typer.Option("--export", metavar="PATH", help="Write the full results as JSON."),
    ] = None,
    force: Annotated[
        bool, typer.Option("--force", help="Allow --save or --export to replace a file.")
    ] = False,
    show_skipped: Annotated[
        bool, typer.Option("--show-skipped", help="Include skipped results in the table.")
    ] = False,
    limit: Annotated[
        int, typer.Option("--limit", min=0, help="Rows to display. 0 shows all.")
    ] = 40,
    local_lab: Annotated[
        bool,
        typer.Option(
            "--local-lab",
            help=(
                "Confirm that the target is your own local test environment. "
                "Required when the target host is a loopback or private address."
            ),
        ),
    ] = False,
) -> None:
    """Run security checks against a target's discovered endpoints.

    Requires a saved discovery result: AegisAPI tests the operations a
    specification declares, not paths it guessed. Every request passes the
    same scope gates as any other command, and a disabled or out-of-scope
    endpoint is recorded as skipped without being contacted.
    """
    cli_ctx = _cli_context(ctx)
    with error_boundary(cli_ctx.debug):
        config, _ = cli_ctx.load_config()
        target = cli_ctx.target_store().get(name)
        discovery = cli_ctx.discovery_store().load(target.name)

        ephemeral_scope = _require_local_lab_or_raise(target, local_lab, config)
        if ephemeral_scope is not None:
            config = config.model_copy(update={"scope": ephemeral_scope})

        declared = load_fixtures(fixtures) if fixtures is not None else None
        if declared is not None:
            for problem in declared.validate_references():
                console.print(Text(f"Fixture warning: {problem}", style="status.warn"))

        engine = AssessmentEngine(target=target, config=config)
        result = engine.run(
            discovery=discovery,
            fixtures=declared,
            categories=category,
            check_ids=check,
            budget=budget,
            max_endpoints=max_endpoints,
        )

        assess_command.render_assessment(console, result, show_skipped=show_skipped, limit=limit)

        written: list[str] = []
        if save:
            written.append(str(cli_ctx.assessment_store().save(result, overwrite=force)))
        if export is not None:
            written.append(str(write_document(export, result, overwrite=force)))
        if written:
            console.print()
            for path in written:
                console.print(Text("Written", style="status.ok"), Text(path))


@check_app.command("show")
def check_show(
    ctx: typer.Context,
    name: NameArgument,
    result_check: Annotated[
        str | None,
        typer.Option("--check", help="Show one check's result in full."),
    ] = None,
    endpoint: Annotated[
        str | None,
        typer.Option("--endpoint", help="Operation key, such as 'GET /orders'."),
    ] = None,
    show_skipped: Annotated[
        bool, typer.Option("--show-skipped", help="Include skipped results.")
    ] = False,
    limit: Annotated[
        int, typer.Option("--limit", min=0, help="Rows to display. 0 shows all.")
    ] = 40,
) -> None:
    """Show the assessment results saved for a target."""
    cli_ctx = _cli_context(ctx)
    with error_boundary(cli_ctx.debug):
        target = cli_ctx.target_store().get(name)
        assessment = cli_ctx.assessment_store().load(target.name)

        if result_check is not None:
            matches = [
                item
                for item in assessment.results
                if item.check_id.upper() == result_check.upper()
                and (endpoint is None or item.endpoint_key == endpoint)
            ]
            if not matches:
                raise InvalidTargetError(
                    f"No saved result for check {result_check!r}"
                    + (f" on {endpoint!r}" if endpoint else "")
                    + ".",
                    hint="Run 'aegisapi check show <target>' to see what was recorded.",
                )
            for item in matches:
                assess_command.render_result_detail(console, item)
                console.print()
            return

        assess_command.render_assessment(
            console, assessment, show_skipped=show_skipped, limit=limit
        )


@risk_app.command("analyze")
def risk_analyze(
    ctx: typer.Context,
    name: NameArgument,
    fixtures: Annotated[
        Path | None,
        typer.Option("--fixtures", metavar="PATH", help="Fixtures used for the assessment."),
    ] = None,
    save: Annotated[bool, typer.Option("--save", help="Store the report.")] = False,
    export: Annotated[
        Path | None,
        typer.Option("--export", metavar="PATH", help="Write the report as JSON."),
    ] = None,
    force: Annotated[
        bool, typer.Option("--force", help="Allow --save or --export to replace a file.")
    ] = False,
    limit: Annotated[
        int, typer.Option("--limit", min=0, help="Risks to display. 0 shows all.")
    ] = 20,
) -> None:
    """Correlate findings and prioritise risks for a target.

    Reads the saved discovery result and, if present, the saved assessment.
    Sends no requests: the analysis is local and deterministic.
    """
    cli_ctx = _cli_context(ctx)
    with error_boundary(cli_ctx.debug):
        target = cli_ctx.target_store().get(name)
        discovery = cli_ctx.discovery_store().load(target.name)

        store = cli_ctx.assessment_store()
        assessment = store.load(target.name) if store.exists(target.name) else None
        if assessment is None:
            console.print(
                Text(
                    "No saved assessment; the report will contain relationships only.",
                    style="status.warn",
                )
            )

        declared = load_fixtures(fixtures) if fixtures is not None else None
        report = analyse(discovery, assessment, declared)

        assess_command.render_intelligence_summary(console, report)
        assess_command.render_risks(console, report.risks, limit=limit)
        console.print()
        assess_command.render_correlations(console, report)
        assess_command.render_notes(console, report.notes)

        written: list[str] = []
        if save:
            written.append(str(cli_ctx.intelligence_store().save(report, overwrite=force)))
        if export is not None:
            written.append(str(write_document(export, report, overwrite=force)))
        if written:
            console.print()
            for path in written:
                console.print(Text("Written", style="status.ok"), Text(path))


@risk_app.command("show")
def risk_show(
    ctx: typer.Context,
    name: NameArgument,
    limit: Annotated[
        int, typer.Option("--limit", min=0, help="Risks to display. 0 shows all.")
    ] = 20,
) -> None:
    """Show the saved intelligence report for a target."""
    cli_ctx = _cli_context(ctx)
    with error_boundary(cli_ctx.debug):
        target = cli_ctx.target_store().get(name)
        report = cli_ctx.intelligence_store().load(target.name)
        assess_command.render_intelligence_summary(console, report)
        assess_command.render_risks(console, report.risks, limit=limit)
        assess_command.render_notes(console, report.notes)


@risk_app.command("graph")
def risk_graph(
    ctx: typer.Context,
    name: NameArgument,
    limit: Annotated[
        int, typer.Option("--limit", min=0, help="Edges to display. 0 shows all.")
    ] = 40,
) -> None:
    """Show the endpoint relationship graph, with each edge's provenance."""
    cli_ctx = _cli_context(ctx)
    with error_boundary(cli_ctx.debug):
        target = cli_ctx.target_store().get(name)
        report = cli_ctx.intelligence_store().load(target.name)
        assess_command.render_graph(console, report, limit=limit)


@risk_app.command("paths")
def risk_paths(
    ctx: typer.Context,
    name: NameArgument,
    limit: Annotated[
        int, typer.Option("--limit", min=0, help="Paths to display. 0 shows all.")
    ] = 10,
) -> None:
    """Show potential multi-step relationships between operations."""
    cli_ctx = _cli_context(ctx)
    with error_boundary(cli_ctx.debug):
        target = cli_ctx.target_store().get(name)
        report = cli_ctx.intelligence_store().load(target.name)
        assess_command.render_attack_paths(console, report.attack_paths, limit=limit)


@risk_app.command("explain")
def risk_explain(
    ctx: typer.Context,
    name: Annotated[
        str | None,
        typer.Argument(help="Target name. Required when RISK is given.", metavar="[NAME]"),
    ] = None,
    risk_id: Annotated[
        str | None,
        typer.Argument(help="Risk identifier. Omit to show the scoring model.", metavar="[RISK]"),
    ] = None,
) -> None:
    """Explain one risk, or print the scoring model when no risk is named."""
    cli_ctx = _cli_context(ctx)
    with error_boundary(cli_ctx.debug):
        if risk_id is None:
            assess_command.render_scoring_model(console)
            return
        if name is None:
            raise typer.BadParameter("NAME is required when RISK is given.", param_hint="NAME")
        target = cli_ctx.target_store().get(name)
        report = cli_ctx.intelligence_store().load(target.name)
        risk = report.risk(risk_id)
        if risk is None:
            raise InvalidTargetError(
                f"No risk with id {risk_id!r} in the saved report.",
                hint=f"Run 'aegisapi risk show {target.name}' to list them.",
            )
        assess_command.render_risk_explanation(console, risk)


@report_app.command("generate")
def report_generate(
    ctx: typer.Context,
    name: NameArgument,
    report_format: Annotated[
        ReportFormat | None,
        typer.Option(
            "--format",
            help="Output format. Defaults to default_report_format from configuration.",
        ),
    ] = None,
    output: Annotated[
        Path | None,
        typer.Option(
            "--output",
            "-o",
            metavar="PATH",
            help="Write here instead of the workspace reports directory.",
        ),
    ] = None,
    force: Annotated[
        bool, typer.Option("--force", help="Allow the report to replace an existing file.")
    ] = False,
    include_all: Annotated[
        bool,
        typer.Option(
            "--include-all",
            help="Show every result, not only findings and results needing review.",
        ),
    ] = False,
) -> None:
    """Generate a report from a target's saved assessment.

    Reads the stored assessment and, when one exists, the stored risk analysis.
    Sends no requests and runs no checks: it renders documents that are already
    on disk. Without a saved analysis the report covers check results only and
    records that in its limitations rather than leaving it to be inferred.

    A failed generation writes nothing: the format is validated before anything
    is read, and the file is written atomically at the end.
    """
    cli_ctx = _cli_context(ctx)
    with error_boundary(cli_ctx.debug):
        config, _ = cli_ctx.load_config()
        # Resolved first, so an unsupported format fails before any document is
        # read and never leaves a partial file behind.
        chosen = resolve_format(report_format, config.default_report_format)

        target = cli_ctx.target_store().get(name)
        assessment = cli_ctx.assessment_store().load(target.name)

        intelligence_store = cli_ctx.intelligence_store()
        intelligence = (
            intelligence_store.load(target.name) if intelligence_store.exists(target.name) else None
        )
        if intelligence is None:
            console.print(Text(report_command.NO_INTELLIGENCE_WARNING, style="status.warn"))

        document = build_report(assessment, intelligence, include_all=include_all)
        text = render(document, chosen)

        destination = output or cli_ctx.workspace.report_file(target.name, suffix_for(chosen))
        written = write_report_text(destination, text, overwrite=force)

        report_command.render_report_written(console, document, path=written, report_format=chosen)



@app.command("scan")
def scan(
    ctx: typer.Context,
    target_name: Annotated[
        str | None,
        typer.Argument(
            metavar="TARGET",
            help=(
                "Registered target name. Run 'aegisapi target add' to register one. "
                "Mutually exclusive with --url."
            ),
        ),
    ] = None,
    url: Annotated[
        str | None,
        typer.Option(
            "--url",
            "-u",
            metavar="URL",
            help=(
                "Base URL of the API to assess, including the scheme. "
                "Alternative to TARGET for one-off scans."
            ),
        ),
    ] = None,
    output: Annotated[
        Path | None,
        typer.Option(
            "--output",
            "-o",
            metavar="PATH",
            help=(
                "Where to write the report. With --format both, the suffix is "
                "replaced to write one file per format."
            ),
        ),
    ] = None,
    report_format: Annotated[
        ScanFormat,
        typer.Option("--format", "-f", help="Report format to write."),
    ] = ScanFormat.BOTH,
    local_lab: Annotated[
        bool,
        typer.Option(
            "--local-lab",
            help=(
                "Confirm that a loopback or private target is your own test "
                "environment. Required for such a host."
            ),
        ),
    ] = False,
    active: Annotated[
        bool,
        typer.Option(
            "--active",
            help=(
                "Allow checks that send more than read-shaped requests. The "
                "shipped checks are read-shaped either way; this records intent "
                "and gates any check that needs more."
            ),
        ),
    ] = False,
    timeout: Annotated[
        float | None,
        typer.Option("--timeout", min=0.1, max=600, help="Per-request read timeout in seconds."),
    ] = None,
    threads: Annotated[
        int | None,
        typer.Option("--threads", min=1, max=64, help="Maximum requests in flight at once."),
    ] = None,
    rate: Annotated[
        float | None,
        typer.Option("--rate", min=0.1, max=100, help="Ceiling on requests per second."),
    ] = None,
    budget: Annotated[
        int,
        typer.Option(
            "--budget",
            min=1,
            max=5000,
            help="Total requests the scan may send, discovery included.",
        ),
    ] = DEFAULT_SCAN_BUDGET,
    scan_timeout: Annotated[
        float | None,
        typer.Option(
            "--scan-timeout",
            min=1.0,
            max=86400.0,
            help="Stop the scan after this many seconds, even if not all endpoints are tested.",
        ),
    ] = None,
    max_endpoint_requests: Annotated[
        int | None,
        typer.Option(
            "--max-endpoint-requests",
            min=1,
            max=1000,
            help="Maximum requests per endpoint across all checks.",
        ),
    ] = None,
    max_check_requests: Annotated[
        int | None,
        typer.Option(
            "--max-check-requests",
            min=1,
            max=1000,
            help="Maximum requests a single check id may send across all endpoints.",
        ),
    ] = None,
    check_timeout: Annotated[
        float | None,
        typer.Option(
            "--check-timeout",
            min=0.5,
            max=300.0,
            help="Abandon a check that runs longer than this many seconds.",
        ),
    ] = None,
    workers: Annotated[
        int,
        typer.Option(
            "--workers",
            min=1,
            max=32,
            help="Parallel worker threads for security checks (default 4; 1 = sequential).",
        ),
    ] = 4,
    endpoint: Annotated[
        list[str] | None,
        typer.Option(
            "--endpoint",
            metavar="PATH",
            help="Probe this path as well as anything discovered. Repeatable.",
        ),
    ] = None,
    wordlist: Annotated[
        Path | None,
        typer.Option(
            "--wordlist",
            metavar="PATH",
            help="File of paths to probe, one per line. Bounded; nothing is generated.",
        ),
    ] = None,
    no_spec_probe: Annotated[
        bool,
        typer.Option(
            "--no-spec-probe",
            help="Do not try the conventional specification locations.",
        ),
    ] = False,
    no_docs_probe: Annotated[
        bool,
        typer.Option(
            "--no-docs-probe",
            help="Do not try the conventional documentation locations.",
        ),
    ] = False,
    category: Annotated[
        list[CheckCategory] | None,
        typer.Option("--category", help="Restrict to these check categories. Repeatable."),
    ] = None,
    check: Annotated[
        list[str] | None,
        typer.Option("--check", help="Run exactly these check ids. Repeatable."),
    ] = None,
    max_endpoints: Annotated[
        int | None,
        typer.Option("--max-endpoints", min=1, help="Only assess the first N in-scope operations."),
    ] = None,
    extra_host: ExtraHostOption = None,
    auth_method: AuthMethodOption = None,
    token_env: TokenEnvOption = None,
    api_key_env: ApiKeyEnvOption = None,
    api_key_name: ApiKeyNameOption = None,
    api_key_in: ApiKeyLocationOption = None,
    username: UsernameOption = None,
    password_env: PasswordEnvOption = None,
    fixtures: Annotated[
        Path | None,
        typer.Option(
            "--fixtures",
            metavar="PATH",
            help="Declared identities and owned objects, for the authorisation checks.",
        ),
    ] = None,
    limit: Annotated[
        int, typer.Option("--limit", min=0, help="Finding rows to display. 0 shows all.")
    ] = 40,
    detail: Annotated[
        bool,
        typer.Option("--detail", help="Print each finding in full, with evidence and remediation."),
    ] = False,
    verbose: Annotated[
        bool, typer.Option("--verbose", "-v", help="Print every progress message.")
    ] = False,
    no_progress: Annotated[
        bool,
        typer.Option(
            "--no-progress",
            help=(
                "Suppress live findings and progress output (CI mode). "
                "The final report is still written."
            ),
        ),
    ] = False,
    force: Annotated[
        bool, typer.Option("--force", help="Allow a report to replace an existing file.")
    ] = False,
    fail_on: Annotated[
        FailOn,
        typer.Option(
            "--fail-on",
            help=(
                "Exit non-zero when a finding at least this serious was recorded. "
                "'never' always exits 0 when the scan completed."
            ),
        ),
    ] = FailOn.NEVER,
) -> None:
    """Assess an API end to end: discover, check, analyse, and report.

    Accepts a registered TARGET name (from 'aegisapi target add') or a one-off
    --url. Exactly one must be given; they are mutually exclusive.

    For TARGET: the target's configured scope, authentication, and base URL are
    used. Reports are written to the workspace reports directory by default.

    For --url: an ephemeral target is derived from the URL with the narrowest
    possible scope. Only assess an API you own or have explicit written
    authorisation to test. A loopback or private address needs --local-lab.
    """
    cli_ctx = _cli_context(ctx)
    with error_boundary(cli_ctx.debug):
        # Mutual exclusion: exactly one of TARGET or --url is required.
        if target_name is not None and url is not None:
            raise typer.BadParameter(
                "Pass either TARGET (a registered target name) or --url, not both.",
                param_hint="TARGET / --url",
            )
        if target_name is None and url is None:
            raise typer.BadParameter(
                "Either TARGET (a registered target name) or --url is required.",
                param_hint="TARGET / --url",
            )

        config, _ = cli_ctx.load_config()
        config = _scan_config(config, timeout=timeout, threads=threads, rate=rate)

        declared = load_fixtures(fixtures) if fixtures is not None else None
        if declared is not None:
            for problem in declared.validate_references():
                console.print(Text(f"Fixture warning: {problem}", style="status.warn"))

        if target_name is not None:
            # ── Registered-target path ──────────────────────────────────────
            store = cli_ctx.target_store()
            registered = store.get(target_name)
            if not registered.enabled:
                from aegisapi.core.exceptions import InvalidTargetError as _ITE
                raise _ITE(
                    f"Target '{registered.name}' is disabled.",
                    hint=(
                        f"Enable it with 'aegisapi target update {registered.name} "
                        "--enable'."
                    ),
                )

            # CLI auth options override the target's configured auth when given.
            if auth_method is not None:
                cli_auth = AuthProfile.model_validate(
                    _auth_data(
                        method=auth_method,
                        token_env=token_env,
                        api_key_env=api_key_env,
                        api_key_name=api_key_name,
                        api_key_location=api_key_in,
                        username=username,
                        password_env=password_env,
                    )
                )
                scan_target = registered.model_copy(
                    update={
                        "auth": (
                            cli_auth if cli_auth.method is not AuthMethod.NONE else None
                        )
                    }
                )
            else:
                scan_target = registered

            options = ScanOptions(
                url=scan_target.base_url,
                target=scan_target,
                local_lab=local_lab,
                active=active,
                budget=budget,
                categories=tuple(category or ()),
                check_ids=tuple(check or ()),
                supplied_paths=tuple(endpoint or ()),
                wordlist_paths=tuple(_read_wordlist_file(wordlist)) if wordlist else (),
                probe_specification=not no_spec_probe,
                probe_documentation=not no_docs_probe,
                max_endpoints=max_endpoints,
                extra_hosts=tuple(extra_host or ()),
                scan_timeout_seconds=scan_timeout,
                max_endpoint_requests=max_endpoint_requests,
                max_check_requests=max_check_requests,
                check_timeout_seconds=check_timeout,
                max_workers=workers,
            )

            # Default report output to workspace reports directory.
            effective_output: Path | None = output
            if effective_output is None:
                effective_output = cli_ctx.workspace.reports_dir / scan_target.name

        else:
            # ── URL path (one-off, existing behaviour) ─────────────────────
            assert url is not None  # guaranteed by the check above
            auth = AuthProfile.model_validate(
                _auth_data(
                    method=auth_method or AuthMethod.NONE,
                    token_env=token_env,
                    api_key_env=api_key_env,
                    api_key_name=api_key_name,
                    api_key_location=api_key_in,
                    username=username,
                    password_env=password_env,
                )
            )

            options = ScanOptions(
                url=url,
                local_lab=local_lab,
                active=active,
                budget=budget,
                categories=tuple(category or ()),
                check_ids=tuple(check or ()),
                supplied_paths=tuple(endpoint or ()),
                wordlist_paths=tuple(_read_wordlist_file(wordlist)) if wordlist else (),
                probe_specification=not no_spec_probe,
                probe_documentation=not no_docs_probe,
                max_endpoints=max_endpoints,
                extra_hosts=tuple(extra_host or ()),
                auth=auth if auth.method is not AuthMethod.NONE else None,
                scan_timeout_seconds=scan_timeout,
                max_endpoint_requests=max_endpoint_requests,
                max_check_requests=max_check_requests,
                check_timeout_seconds=check_timeout,
                max_workers=workers,
            )

            effective_output = output

        _dispatcher = EventDispatcher()
        _dispatcher.subscribe(
            scan_command.make_event_handler(error_console, no_progress=no_progress)
        )
        result = run_scan(
            options,
            config=config,
            progress=scan_command.make_progress_printer(error_console, verbose=verbose),
            fixtures=declared,
            event_dispatcher=_dispatcher,
        )

        console.print()
        scan_command.render_scan(console, result, limit=limit, detail=detail)

        written = _write_scan_reports(
            result,
            output=effective_output,
            report_format=report_format,
            overwrite=force,
        )
        scan_command.render_written(console, written)

        exit_code = _scan_exit_code(result, fail_on)
        if exit_code:
            raise typer.Exit(exit_code)


def _local_lab_scope(target: Target) -> ScopeSettings:
    """Build an ephemeral scope settings that authorises only the target's host.

    Used by commands that accept ``--local-lab`` to allow requests to loopback
    and private hosts without requiring ``scope.allowed_hosts`` in config.toml.
    The scope is ephemeral: it is never written to disk.
    """
    return ScopeSettings(enforce=True, allowed_hosts=[target.host])


def _require_local_lab_or_raise(
    target: Target,
    local_lab: bool,
    config: "AegisConfig | None" = None,
) -> ScopeSettings | None:
    """Return an ephemeral scope, or raise for unconfirmed loopback/private targets.

    When *local_lab* is True the target's host is added to an ephemeral allow-list
    that is used for this command only.  When it is False and the target is a
    loopback or private address, a :class:`~aegisapi.core.exceptions.ScopeViolationError`
    is raised before any network activity begins.  Public targets return ``None``
    so the caller keeps the loaded configuration unchanged.

    If *config* is supplied and the target host is already in its allow-list (e.g.
    via ``AEGISAPI_ALLOWED_HOSTS``), the existing config is sufficient and ``None``
    is returned without requiring ``--local-lab``.
    """
    from aegisapi.core.exceptions import ScopeViolationError

    exposure = classify_host_exposure(target.host)
    if exposure is HostExposure.PUBLIC:
        return None
    if config is not None and target.host in config.scope.allowed_hosts:
        return None
    if local_lab:
        return _local_lab_scope(target)
    name = "loopback" if exposure is HostExposure.LOOPBACK else "private or internal"
    raise ScopeViolationError(
        f"{target.host} is a {name} address, and was not explicitly authorised.",
        hint=(
            "Pass --local-lab to confirm you are assessing your own local test API. "
            "AegisAPI will not send requests to a loopback or private host without it."
        ),
    )


def _scan_config(
    config: AegisConfig,
    *,
    timeout: float | None,
    threads: int | None,
    rate: float | None,
) -> AegisConfig:
    """Apply the scan's transport overrides to the loaded configuration.

    Only the three limits the options name are changed. TLS verification is not
    among them: there is no scan option that turns it off, because a scanner
    that silently accepted any certificate could not attribute a response to
    the host it meant to assess. Turning it off stays a deliberate edit to
    config.toml, where it is visible and reviewable.
    """
    overrides: dict[str, object] = {}
    if timeout is not None:
        overrides["read_timeout_seconds"] = timeout
    if threads is not None:
        overrides["max_concurrency"] = threads
    if rate is not None:
        overrides["requests_per_second"] = rate
    if not overrides:
        return config
    try:
        return config.model_copy(update={"http": config.http.model_copy(update=overrides)})
    except ValidationError as exc:
        raise InvalidTargetError(
            "The transport options are not valid.",
            hint=format_validation_problems(exc),
        ) from exc


def _read_wordlist_file(path: Path) -> list[str]:
    """Read a wordlist of paths, one per line.

    Blank lines and ``#`` comments are dropped by the probe's own
    normalisation, which also enforces the cap, so this only has to get the
    bytes off disk and report a readable error when it cannot.
    """
    try:
        text = path.expanduser().read_text(encoding="utf-8")
    except OSError as exc:
        raise InvalidTargetError(
            f"The wordlist could not be read: {path}",
            hint=exc.strerror,
        ) from exc
    return [line for line in text.splitlines() if line.strip()]


def _scan_report_paths(
    output: Path | None,
    report_format: ScanFormat,
) -> list[tuple[Path, ReportFormat]]:
    """Work out which files a scan writes, and in which format."""
    formats: list[ReportFormat] = {
        ScanFormat.JSON: [ReportFormat.JSON],
        ScanFormat.HTML: [ReportFormat.HTML],
        ScanFormat.BOTH: [ReportFormat.JSON, ReportFormat.HTML],
        ScanFormat.SARIF: [ReportFormat.SARIF],
        ScanFormat.NONE: [],
    }[report_format]

    if not formats:
        return []

    base = output or Path("aegisapi-scan")
    if len(formats) == 1 and output is not None and output.suffix:
        # An explicit single format with an explicit suffix honours the name
        # exactly as given, so '--output findings.txt --format json' writes
        # findings.txt. A path without an extension (a basename, a workspace-
        # derived path) always gets the format's own extension appended.
        return [(base, formats[0])]
    return [(base.with_suffix(f".{suffix_for(item)}"), item) for item in formats]


def _write_scan_reports(
    result: ScanResult,
    *,
    output: Path | None,
    report_format: ScanFormat,
    overwrite: bool,
) -> list[str]:
    """Render and write the scan's reports."""
    written: list[str] = []
    for path, item in _scan_report_paths(output, report_format):
        text = render(result.report, item)
        written.append(str(write_report_text(path, text, overwrite=overwrite)))
    return written


def _scan_exit_code(result: ScanResult, fail_on: FailOn) -> int:
    """Decide the exit status from the findings and the --fail-on threshold.

    Zero unless the operator asked for a threshold. A scan that completed did
    its job whether or not it found anything, and a tool that exits non-zero on
    every informational observation cannot be used in a pipeline. The threshold
    makes the failure condition the operator's choice and nothing else's.
    """
    if fail_on is FailOn.NEVER:
        return 0

    wanted = {
        FailOn.LOW: {Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL},
        FailOn.MEDIUM: {Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL},
        FailOn.HIGH: {Severity.HIGH, Severity.CRITICAL},
        FailOn.CRITICAL: {Severity.CRITICAL},
    }[fail_on]

    counts = result.report.summary.by_severity
    if any(counts.get(severity, 0) for severity in wanted):
        return EXIT_FINDINGS_FOUND
    return 0


def _host_for_check(url: str, *, fallback: str) -> str:
    """Extract the host from a URL for the global allow-list check.

    A URL the parser rejects has no trustworthy host, so the target's own host
    is used instead: the target gate has already denied the URL, and this keeps
    the global column meaningful rather than blank.
    """
    try:
        return normalize_url(url).host
    except AegisAPIError:
        return fallback


__all__ = [
    "ClearableField",
    "CliContext",
    "app",
    "check_app",
    "discover_app",
    "error_boundary",
    "render_error",
    "report_app",
    "risk_app",
    "target_app",
]
