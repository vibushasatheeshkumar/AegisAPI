"""Console-script entry point.

``aegisapi`` resolves to :func:`main`. The Typer application already converts
expected failures into clean messages inside its own error boundary; the guard
here is a last resort for anything raised outside a command, so a user never
sees a bare traceback.
"""

from __future__ import annotations

from aegisapi.cli import app, error_console, render_error
from aegisapi.core.exceptions import AegisAPIError

_INTERRUPTED_EXIT_CODE = 130


def main() -> None:
    """Run the AegisAPI command-line interface."""
    try:
        app()
    except AegisAPIError as exc:
        render_error(exc)
        raise SystemExit(exc.exit_code) from exc
    except KeyboardInterrupt:
        error_console.print("Interrupted.")
        raise SystemExit(_INTERRUPTED_EXIT_CODE) from None


if __name__ == "__main__":  # pragma: no cover - module executed as a script
    main()
