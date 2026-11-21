"""References to credentials, rather than credentials themselves.

AegisAPI stores the *name* of an environment variable, never a token. A target
file can therefore be read, copied, diffed, and committed to a private repo
without leaking anything, and no AegisAPI code path can print a credential it
never held.

Security assumptions and limits of this approach, stated plainly:

* An environment variable is readable by every process running as the same
  user, and often appears in shell history and in crash dumps. It is a
  reasonable default, not a vault.
* Setting the variable is the operator's responsibility, which means a
  credential is never persisted by AegisAPI at all.
* :class:`SecretProvider` exists so a future phase can add a real secret
  manager without changing the target file format.

A missing credential is always an error. AegisAPI never falls back to an empty
value: a request that silently goes out unauthenticated produces assessment
results that look like findings but are not.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, field_validator

from aegisapi.core.exceptions import MissingCredentialError
from aegisapi.utils.secrets import Secret

ENV_VARIABLE_PATTERN = r"^[A-Za-z_][A-Za-z0-9_]{0,127}$"
"""Shape of an environment variable name.

This doubles as a guard against pasting a credential where a name belongs:
real tokens almost always contain characters this pattern rejects, such as
``-``, ``.``, ``/``, ``=``, or ``:``.
"""


class SecretProvider(StrEnum):
    """Where a credential is read from at the moment it is needed."""

    ENV = "env"


class SecretRef(BaseModel):
    """A pointer to a credential held outside AegisAPI."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    provider: SecretProvider = Field(
        default=SecretProvider.ENV,
        description="Credential source. Only environment variables are supported.",
    )
    variable: str = Field(
        description="Name of the environment variable holding the credential.",
        pattern=ENV_VARIABLE_PATTERN,
    )

    @field_validator("variable", mode="before")
    @classmethod
    def _strip(cls, value: object) -> object:
        """Trim surrounding whitespace before the pattern is applied."""
        return value.strip() if isinstance(value, str) else value

    def describe(self) -> str:
        """Render the reference for display, for example ``env:ACME_TOKEN``.

        Safe to print: a variable name is not a credential.
        """
        return f"{self.provider.value}:{self.variable}"

    def is_available(self, env: Mapping[str, str] | None = None) -> bool:
        """``True`` when the referenced variable is set to a non-empty value."""
        environ = os.environ if env is None else env
        return bool(environ.get(self.variable, "").strip())

    def resolve(self, env: Mapping[str, str] | None = None) -> Secret:
        """Read the credential.

        Returns:
            The value wrapped in a :class:`~aegisapi.utils.secrets.Secret`, so
            it cannot be logged or serialised by accident. Surrounding
            whitespace is trimmed, which makes a variable populated from a file
            usable without hidden newline trouble.

        Raises:
            MissingCredentialError: If the variable is unset or empty. The
                message names the variable, never a value.
        """
        environ = os.environ if env is None else env
        raw = environ.get(self.variable)
        if raw is None:
            raise MissingCredentialError(
                f"Environment variable {self.variable} is not set.",
                hint=f"Set {self.variable} in this shell before running the command.",
            )
        value = raw.strip()
        if not value:
            raise MissingCredentialError(
                f"Environment variable {self.variable} is set but empty.",
                hint="AegisAPI will not send an empty credential in place of a real one.",
            )
        return Secret(value)


__all__ = ["ENV_VARIABLE_PATTERN", "SecretProvider", "SecretRef"]
