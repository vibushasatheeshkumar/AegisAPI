"""Command implementations.

Each module here owns the presentation of a single CLI command. The modules
depend on :mod:`aegisapi.core` for behaviour so that the Typer layer in
:mod:`aegisapi.cli` stays thin and free of business logic.
"""
