r"""URL and path normalisation for scope decisions.

Scope enforcement is only as trustworthy as the URL parsing underneath it, so
this module is deliberately strict. Its guiding rule is **reject rather than
interpret**: where a URL could plausibly mean two different things, AegisAPI
refuses it instead of guessing, because a wrong guess in a scope decision means
contacting a host nobody authorised.

What is rejected, and why:

* Schemes other than ``http`` and ``https`` - nothing else is an API request.
* Userinfo (``https://example.com@attacker.test/``) - a classic host-confusion
  trick, and a place credentials must never be written.
* A trailing dot on a host (``example.com.``) - the root-label form compares
  unequal to ``example.com`` while addressing the same server.
* Fragments - they are never transmitted, so a URL carrying one does not mean
  what it appears to mean.
* Backslashes in a path - several servers and proxies treat them as separators.
* Percent-encoded separators (``%2f``) and double encoding (``%252e``) - the
  decoded form depends on how many times the server decodes.
* Control characters, NUL bytes, and whitespace anywhere in the URL.

Normalisation that *is* applied: the scheme and host are lowercased, a default
port is made explicit, duplicate slashes are collapsed, ``.`` and ``..``
segments are resolved, and a trailing slash is stripped from every path except
the root. Stripping the trailing slash matters: without it, ``/admin/`` would
slip past an exclusion written as ``/admin``.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from enum import StrEnum
from urllib.parse import unquote, urlsplit

from aegisapi.core.exceptions import InvalidUrlError

SUPPORTED_SCHEMES: frozenset[str] = frozenset({"http", "https"})
"""The only schemes AegisAPI will ever contact."""

DEFAULT_PORTS: dict[str, int] = {"http": 80, "https": 443}
"""Port assumed when a URL does not state one."""

MAX_URL_LENGTH = 2048
"""Refuse absurdly long URLs rather than spending time normalising them."""

MAX_HOST_LENGTH = 253
"""Maximum length of a DNS name, per RFC 1035."""

_LABEL = r"[a-z0-9_]([a-z0-9_\-]*[a-z0-9_])?"
_HOSTNAME_PATTERN = re.compile(rf"^{_LABEL}(\.{_LABEL})*$")

# A percent sign followed by two hex digits: still-encoded text after one
# decoding pass, which means the input was encoded more than once.
_PERCENT_ESCAPE = re.compile(r"%[0-9a-fA-F]{2}")

_FORBIDDEN_IN_PATH = ("\\", "\x00")


def _reject(message: str, *, hint: str | None = None) -> InvalidUrlError:
    """Build an :class:`InvalidUrlError`; never includes credential material."""
    return InvalidUrlError(message, hint=hint)


def _has_control_or_space(text: str) -> bool:
    """``True`` if ``text`` holds a control character or any whitespace."""
    return any(char.isspace() or ord(char) < 0x20 or ord(char) == 0x7F for char in text)


def normalize_host(raw: str, *, label: str = "host") -> str:
    """Return ``raw`` as a canonical, comparable host string.

    Lowercases the name, encodes internationalised names with IDNA, and accepts
    IPv4 and bracketed IPv6 literals. The result is safe to compare with ``==``.

    Raises:
        InvalidUrlError: If the host is empty, malformed, carries a trailing
            dot, or cannot be encoded.
    """
    host = raw.strip().lower()
    if not host:
        raise _reject(f"The {label} must not be empty.")
    if _has_control_or_space(host):
        raise _reject(f"The {label} contains whitespace or control characters.")
    if len(host) > MAX_HOST_LENGTH:
        raise _reject(f"The {label} is longer than {MAX_HOST_LENGTH} characters.")

    if host.startswith("[") or host.endswith("]"):
        if not (host.startswith("[") and host.endswith("]")):
            raise _reject(f"The {label} has mismatched brackets: {host!r}")
        try:
            address = ipaddress.IPv6Address(host[1:-1])
        except ValueError as exc:
            raise _reject(f"The {label} is not a valid IPv6 literal: {host!r}") from exc
        return f"[{address.compressed}]"

    if ":" in host:
        raise _reject(
            f"The {label} contains a colon: {host!r}",
            hint="Write an IPv6 address in brackets, and give a port separately.",
        )
    if host.endswith("."):
        raise _reject(
            f"The {label} ends with a dot: {host!r}",
            hint="Use the plain name, for example 'api.example.com'.",
        )

    if not host.isascii():
        try:
            host = host.encode("idna").decode("ascii")
        except UnicodeError as exc:
            raise _reject(f"The {label} is not a valid internationalised name: {host!r}") from exc

    try:
        return str(ipaddress.IPv4Address(host))
    except ValueError:
        pass

    if ".." in host or host.startswith(".") or not _HOSTNAME_PATTERN.match(host):
        raise _reject(f"The {label} is not a valid hostname: {host!r}")
    return host


def normalize_path(raw: str, *, label: str = "path") -> str:
    """Return ``raw`` as a canonical absolute path.

    Collapses duplicate slashes, resolves ``.`` and ``..`` segments, and strips
    a trailing slash from everything but the root.

    Raises:
        InvalidUrlError: If the path is relative, contains a forbidden or
            ambiguously encoded character, or traverses above the root.
    """
    path = raw.strip() or "/"
    if _has_control_or_space(path):
        raise _reject(f"The {label} contains whitespace or control characters.")
    if not path.startswith("/"):
        raise _reject(
            f"The {label} must start with '/': {path!r}",
            hint="Scope paths are absolute, for example '/v1/orders'.",
        )
    for forbidden in _FORBIDDEN_IN_PATH:
        if forbidden in path:
            raise _reject(f"The {label} contains a forbidden character: {forbidden!r}")

    try:
        decoded = unquote(path, errors="strict") if "%" in path else path
    except UnicodeDecodeError as exc:
        raise _reject(
            f"The {label} contains percent-encoding that is not valid UTF-8: {path!r}"
        ) from exc
    if _PERCENT_ESCAPE.search(decoded):
        raise _reject(
            f"The {label} is percent-encoded more than once: {path!r}",
            hint="Supply the path in its decoded form; double encoding is ambiguous.",
        )
    if decoded.count("/") != path.count("/"):
        raise _reject(
            f"The {label} encodes a '/' separator: {path!r}",
            hint="A percent-encoded slash means different things to different servers.",
        )
    if _has_control_or_space(decoded):
        raise _reject(f"The {label} decodes to whitespace or control characters: {path!r}")
    for forbidden in (*_FORBIDDEN_IN_PATH, "?", "#"):
        if forbidden in decoded:
            raise _reject(
                f"The {label} encodes a reserved character: {forbidden!r}",
                hint="Encoded separators are ambiguous and are not accepted.",
            )

    resolved = _remove_dot_segments(decoded, label=label)
    return resolved


def _remove_dot_segments(path: str, *, label: str) -> str:
    """Apply RFC 3986 dot-segment removal, refusing to escape above the root."""
    output: list[str] = []
    for segment in path.split("/"):
        if segment in ("", "."):
            continue
        if segment == "..":
            if not output:
                raise _reject(
                    f"The {label} traverses above the root: {path!r}",
                    hint="Remove the leading '..' segments.",
                )
            output.pop()
            continue
        output.append(segment)
    return "/" + "/".join(output)


def normalize_path_pattern(raw: str, *, label: str = "path pattern") -> str:
    """Return a canonical scope path pattern.

    Patterns use the same shape as paths and may contain wildcards: ``*``
    matches within one segment, and ``**`` matches across segments. Percent
    encoding is not accepted in a pattern, because a pattern is compared
    against already-decoded paths.

    Raises:
        InvalidUrlError: If the pattern is relative, encoded, or malformed.
    """
    pattern = raw.strip()
    if "%" in pattern:
        raise _reject(
            f"The {label} must not be percent-encoded: {pattern!r}",
            hint="Patterns are matched against decoded paths; write '/a b' not '/a%20b'.",
        )
    normalized = normalize_path(pattern, label=label)
    if "***" in normalized:
        raise _reject(
            f"The {label} uses an unsupported wildcard: {pattern!r}",
            hint="Use '*' for one segment or '**' for a subtree.",
        )
    return normalized


@dataclass(frozen=True)
class NormalizedUrl:
    """A URL reduced to the parts a scope decision needs."""

    scheme: str
    host: str
    port: int
    path: str
    query: str = ""
    explicit_port: bool = False

    @property
    def is_default_port(self) -> bool:
        """``True`` when the port is the scheme's default."""
        return DEFAULT_PORTS.get(self.scheme) == self.port

    @property
    def host_port(self) -> str:
        """Host with the port appended when it is not the scheme default."""
        return self.host if self.is_default_port else f"{self.host}:{self.port}"

    @property
    def origin(self) -> str:
        """Scheme and authority, without a path."""
        return f"{self.scheme}://{self.host_port}"

    @property
    def segments(self) -> tuple[str, ...]:
        """Path split into non-empty segments."""
        return tuple(segment for segment in self.path.split("/") if segment)

    def to_string(self, *, include_query: bool = True) -> str:
        """Render the canonical URL."""
        rendered = f"{self.origin}{self.path}"
        if include_query and self.query:
            rendered = f"{rendered}?{self.query}"
        return rendered

    def __str__(self) -> str:
        return self.to_string()


def normalize_url(raw: str, *, label: str = "URL", allow_query: bool = True) -> NormalizedUrl:
    """Parse and canonicalise an ``http``/``https`` URL.

    Args:
        raw: The URL as supplied by a user or a configuration file.
        label: Noun used in error messages, such as ``"base URL"``.
        allow_query: When ``False``, a query string is rejected. Base URLs use
            this, because a stored base URL with a query is ambiguous.

    Raises:
        InvalidUrlError: For anything this module refuses to interpret. See the
            module docstring for the full list.
    """
    text = raw.strip()
    if not text:
        raise _reject(f"The {label} must not be empty.")
    if len(text) > MAX_URL_LENGTH:
        raise _reject(f"The {label} is longer than {MAX_URL_LENGTH} characters.")
    if _has_control_or_space(text):
        raise _reject(f"The {label} contains whitespace or control characters.")
    if "://" not in text:
        raise _reject(
            f"The {label} must include a scheme: {text!r}",
            hint="Write the full URL, for example 'https://api.example.com'.",
        )

    try:
        parts = urlsplit(text)
    except ValueError as exc:
        raise _reject(f"The {label} could not be parsed: {text!r}", hint=str(exc)) from exc

    scheme = parts.scheme.lower()
    if scheme not in SUPPORTED_SCHEMES:
        raise _reject(
            f"The {label} uses an unsupported scheme: {scheme!r}",
            hint="Only http and https are supported.",
        )
    if parts.fragment or "#" in text:
        raise _reject(
            f"The {label} must not contain a fragment: {text!r}",
            hint="A fragment is never sent to a server, so it cannot be assessed.",
        )
    if "@" in parts.netloc:
        raise _reject(
            f"The {label} must not contain userinfo: {text!r}",
            hint="Credentials belong in an environment variable, not in a URL.",
        )
    if not allow_query and parts.query:
        raise _reject(
            f"The {label} must not contain a query string: {text!r}",
            hint="Register the base URL without a query.",
        )

    hostname = parts.hostname
    if not hostname:
        raise _reject(f"The {label} does not contain a host: {text!r}")
    bracketed = f"[{hostname}]" if ":" in hostname else hostname
    host = normalize_host(bracketed, label=f"{label} host")

    try:
        port = parts.port
    except ValueError as exc:
        raise _reject(
            f"The {label} has an invalid port: {text!r}",
            hint="A port must be a number between 1 and 65535.",
        ) from exc
    if port is not None and not 1 <= port <= 65535:
        raise _reject(f"The {label} has a port outside 1-65535: {text!r}")

    return NormalizedUrl(
        scheme=scheme,
        host=host,
        port=port if port is not None else DEFAULT_PORTS[scheme],
        path=normalize_path(parts.path or "/", label=f"{label} path"),
        query=parts.query,
        explicit_port=port is not None,
    )


def _parse_legacy_ipv4(candidate: str) -> ipaddress.IPv4Address | None:
    """Parse the legacy IPv4 spellings ``ipaddress`` deliberately refuses.

    ``inet_aton`` has always accepted fewer than four parts and non-decimal
    parts, so ``127.1``, ``0x7f.0.0.1``, ``0177.1``, and the bare integer
    ``2130706433`` all reach the loopback interface. The :mod:`ipaddress`
    module accepts only the strict dotted-quad form, which is correct for it
    and wrong for a security guard: every one of those spellings is a way to
    write ``127.0.0.1`` that a strict parser reports as "not an address", and
    therefore as a public host.

    Returns the address, or ``None`` when the text is not a numeric address in
    any of these forms - a hostname, for instance.
    """
    parts = candidate.split(".")
    if not 1 <= len(parts) <= 4:
        return None

    values: list[int] = []
    for part in parts:
        if not part:
            return None
        try:
            if part.lower().startswith("0x"):
                value = int(part, 16)
            elif part.startswith("0") and len(part) > 1:
                value = int(part, 8)
            else:
                value = int(part, 10)
        except ValueError:
            return None
        if value < 0:
            return None
        values.append(value)

    # The final part absorbs the remaining octets: 'a.b.c' is a.b.(c as 16 bits).
    trailing_octets = 4 - len(values)
    if any(value > 0xFF for value in values[:-1]):
        return None
    if values[-1] > (1 << (8 * (trailing_octets + 1))) - 1:
        return None

    packed = 0
    for value in values[:-1]:
        packed = (packed << 8) | value
    packed = (packed << (8 * (trailing_octets + 1))) | values[-1]

    try:
        return ipaddress.IPv4Address(packed)
    except ipaddress.AddressValueError:  # pragma: no cover - range already checked
        return None


class HostExposure(StrEnum):
    """Where a host sits relative to the operator's own infrastructure.

    Used by the one-shot ``scan`` command, which derives its scope from the URL
    it was given rather than from a reviewed target record. Deriving scope
    automatically is convenient, and it is exactly how a tool ends up probing
    the machine it is running on or the network it is running inside, so the
    classification exists to make the local and private cases ask first.
    """

    PUBLIC = "public"
    """A routable name or address. The ordinary assessment case."""

    LOOPBACK = "loopback"
    """The machine AegisAPI is running on."""

    PRIVATE = "private"
    """An address inside a private, link-local, or otherwise internal range."""


_LOOPBACK_NAMES = frozenset({"localhost", "ip6-localhost", "ip6-loopback"})
_INTERNAL_SUFFIXES = (".localhost", ".local", ".internal", ".home.arpa")


def classify_host_exposure(host: str) -> HostExposure:
    """Classify a hostname or address as public, loopback, or private.

    An address is judged by the ``ipaddress`` module, which knows the full set
    of reserved ranges and is not fooled by the spellings a blocklist of
    prefixes misses - ``127.1``, ``0x7f.1``, ``[::1]``, or an IPv4-mapped
    ``::ffff:127.0.0.1`` all resolve to loopback here. Legacy numeric
    spellings are expanded first, because a strict parser reports those as "not
    an address" and a guard that trusted it would call loopback public.

    A *name* can only be judged by what it is: this function does not resolve
    DNS, so a public name pointing at ``10.0.0.5`` is reported as
    :attr:`HostExposure.PUBLIC`. The destination guard in
    :mod:`aegisapi.http.client` is what notices where a name actually went;
    this is a pre-flight classification of what the operator typed.
    """
    candidate = host.strip().lower()
    if not candidate:
        return HostExposure.PUBLIC

    bracketed = candidate
    if bracketed.startswith("[") and bracketed.endswith("]"):
        bracketed = bracketed[1:-1]
    address: ipaddress.IPv4Address | ipaddress.IPv6Address | None
    try:
        address = ipaddress.ip_address(bracketed)
    except ValueError:
        address = _parse_legacy_ipv4(bracketed)

    if address is None:
        if candidate in _LOOPBACK_NAMES or candidate.endswith(".localhost"):
            return HostExposure.LOOPBACK
        if any(candidate.endswith(suffix) for suffix in _INTERNAL_SUFFIXES):
            return HostExposure.PRIVATE
        return HostExposure.PUBLIC

    mapped = getattr(address, "ipv4_mapped", None)
    if mapped is not None:
        address = mapped

    if address.is_loopback:
        return HostExposure.LOOPBACK
    if address.is_private or address.is_link_local or address.is_reserved or address.is_unspecified:
        return HostExposure.PRIVATE
    return HostExposure.PUBLIC


def is_subdomain_of(host: str, parent: str) -> bool:
    """``True`` when ``host`` sits strictly below ``parent`` in the DNS tree.

    The dot boundary is what defeats hostname confusion:
    ``example.com.attacker.test`` does not end with ``.example.com``, so it is
    not a subdomain of ``example.com`` no matter how similar it looks.
    """
    if not host or not parent or host == parent:
        return False
    return host.endswith(f".{parent}")


__all__ = [
    "DEFAULT_PORTS",
    "MAX_HOST_LENGTH",
    "MAX_URL_LENGTH",
    "SUPPORTED_SCHEMES",
    "HostExposure",
    "NormalizedUrl",
    "classify_host_exposure",
    "is_subdomain_of",
    "normalize_host",
    "normalize_path",
    "normalize_path_pattern",
    "normalize_url",
]
