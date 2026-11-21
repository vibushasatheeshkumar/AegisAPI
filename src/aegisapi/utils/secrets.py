"""A container that makes credential material hard to leak by accident.

The usual way a secret escapes is not a deliberate ``print``; it is a debug
log line, an exception message that interpolates a request object, or a JSON
dump of a configuration structure. :class:`Secret` closes those paths: the
value is reachable only through :meth:`Secret.reveal`, and every implicit
conversion renders as a redaction marker instead.

What this does *not* do: it is not encryption, and it does not protect against
a process that can read AegisAPI's memory. It protects against the operator's
own terminal, log files, and saved reports.
"""

from __future__ import annotations

import hmac
from typing import Any, NoReturn, final

from aegisapi.utils.redaction import REDACTED


@final
class Secret:
    """An opaque wrapper around a credential string.

    ``repr``, ``str``, and f-string formatting all render ``[REDACTED]``.
    Pickling and copying raise, so a secret cannot be smuggled into a cache or
    a serialised structure, and the class is unhashable to keep it out of
    dictionary keys. ``json.dumps`` fails on it, which is the intended outcome:
    a secret should never reach a report or a stored assessment record.

    Use :meth:`reveal` at the point of use, and never store the result.
    """

    __slots__ = ("_value",)

    def __init__(self, value: str) -> None:
        if not isinstance(value, str):
            raise TypeError(f"Secret expects a string, got {type(value).__name__}.")
        self._value = value

    def reveal(self) -> str:
        """Return the underlying credential.

        Call this as late as possible, pass the result straight to the consumer,
        and never assign it to anything that is logged, stored, or serialised.
        """
        return self._value

    @property
    def length(self) -> int:
        """Length of the credential, for diagnostics that must not reveal it."""
        return len(self._value)

    def __repr__(self) -> str:
        return f"Secret({REDACTED})"

    def __str__(self) -> str:
        return REDACTED

    def __format__(self, format_spec: str) -> str:
        del format_spec  # a width or precision must not shape the real value
        return REDACTED

    def __bool__(self) -> bool:
        return bool(self._value)

    def __eq__(self, other: object) -> bool:
        """Compare two secrets without leaking timing information."""
        if not isinstance(other, Secret):
            return NotImplemented
        return hmac.compare_digest(self._value, other._value)

    __hash__ = None  # type: ignore[assignment]

    def __reduce__(self) -> NoReturn:
        raise TypeError("Secret objects must not be pickled, copied, or serialised.")

    def __getstate__(self) -> NoReturn:
        raise TypeError("Secret objects must not be pickled, copied, or serialised.")

    def __get_pydantic_core_schema__(self, *args: Any, **kwargs: Any) -> NoReturn:
        """Refuse to participate in Pydantic models, which are serialisable."""
        del args, kwargs
        raise TypeError("Secret must not be stored on a Pydantic model; store a SecretRef instead.")


__all__ = ["Secret"]
