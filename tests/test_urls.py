"""URL and path normalisation, including the forms AegisAPI refuses."""

from __future__ import annotations

import pytest

from aegisapi.core.exceptions import InvalidUrlError
from aegisapi.utils.urls import (
    MAX_URL_LENGTH,
    HostExposure,
    classify_host_exposure,
    is_subdomain_of,
    normalize_host,
    normalize_path,
    normalize_path_pattern,
    normalize_url,
)


class TestNormalizeUrl:
    def test_canonicalises_scheme_host_and_port(self) -> None:
        url = normalize_url("HTTPS://API.Example.COM/v1")

        assert url.scheme == "https"
        assert url.host == "api.example.com"
        assert url.port == 443
        assert url.is_default_port is True
        assert url.origin == "https://api.example.com"
        assert url.to_string() == "https://api.example.com/v1"

    def test_default_port_is_made_explicit_but_not_rendered(self) -> None:
        assert normalize_url("http://example.com").port == 80
        assert normalize_url("http://example.com:80/x").to_string() == "http://example.com/x"

    def test_non_default_port_is_kept(self) -> None:
        url = normalize_url("https://example.com:8443/v1")

        assert url.port == 8443
        assert url.host_port == "example.com:8443"
        assert url.to_string() == "https://example.com:8443/v1"

    def test_missing_path_becomes_root(self) -> None:
        assert normalize_url("https://example.com").path == "/"

    def test_query_is_preserved_but_separate_from_the_path(self) -> None:
        url = normalize_url("https://example.com/search?q=1&page=2")

        assert url.path == "/search"
        assert url.query == "q=1&page=2"
        assert url.to_string(include_query=False) == "https://example.com/search"

    def test_segments_exposes_the_path_parts(self) -> None:
        assert normalize_url("https://example.com/v1/orders/42").segments == ("v1", "orders", "42")

    def test_ipv4_and_ipv6_literals_are_supported(self) -> None:
        assert normalize_url("http://127.0.0.1:8080/x").host == "127.0.0.1"
        assert normalize_url("http://[::1]:8080/x").host == "[::1]"

    def test_internationalised_host_is_idna_encoded(self) -> None:
        assert normalize_url("https://bücher.example/v1").host == "xn--bcher-kva.example"

    @pytest.mark.parametrize("raw", ["", "   "])
    def test_empty_url_is_rejected(self, raw: str) -> None:
        with pytest.raises(InvalidUrlError, match="must not be empty"):
            normalize_url(raw)

    @pytest.mark.parametrize("raw", ["example.com/v1", "//example.com/v1", "/v1/orders"])
    def test_url_without_a_scheme_is_rejected(self, raw: str) -> None:
        with pytest.raises(InvalidUrlError, match="must include a scheme"):
            normalize_url(raw)

    @pytest.mark.parametrize(
        "raw",
        [
            "ftp://example.com",
            "file:///etc/passwd",
            "javascript://example.com/%0aalert(1)",
            "gopher://example.com",
        ],
    )
    def test_unsupported_schemes_are_rejected(self, raw: str) -> None:
        with pytest.raises(InvalidUrlError):
            normalize_url(raw)

    def test_userinfo_is_rejected(self) -> None:
        # The classic host-confusion trick: the real host is attacker.test.
        with pytest.raises(InvalidUrlError, match="userinfo"):
            normalize_url("https://api.example.com@attacker.test/v1")

    def test_fragment_is_rejected(self) -> None:
        with pytest.raises(InvalidUrlError, match="fragment"):
            normalize_url("https://example.com/v1#section")

    def test_trailing_dot_host_is_rejected(self) -> None:
        with pytest.raises(InvalidUrlError, match="ends with a dot"):
            normalize_url("https://example.com./v1")

    @pytest.mark.parametrize("raw", ["https://example.com:0/x", "https://example.com:99999/x"])
    def test_out_of_range_port_is_rejected(self, raw: str) -> None:
        with pytest.raises(InvalidUrlError):
            normalize_url(raw)

    def test_non_numeric_port_is_rejected(self) -> None:
        with pytest.raises(InvalidUrlError):
            normalize_url("https://example.com:http/x")

    def test_missing_host_is_rejected(self) -> None:
        with pytest.raises(InvalidUrlError):
            normalize_url("https:///v1/orders")

    @pytest.mark.parametrize("raw", ["https://example.com/a b", "https://exa mple.com/a"])
    def test_whitespace_is_rejected(self, raw: str) -> None:
        with pytest.raises(InvalidUrlError, match="whitespace or control"):
            normalize_url(raw)

    def test_control_characters_are_rejected(self) -> None:
        with pytest.raises(InvalidUrlError, match="whitespace or control"):
            normalize_url("https://example.com/a\x01b")

    def test_overlong_url_is_rejected(self) -> None:
        raw = "https://example.com/" + "a" * MAX_URL_LENGTH

        with pytest.raises(InvalidUrlError, match="longer than"):
            normalize_url(raw)

    def test_base_url_may_forbid_a_query(self) -> None:
        with pytest.raises(InvalidUrlError, match="query string"):
            normalize_url("https://example.com/v1?debug=1", allow_query=False)

    def test_label_appears_in_the_error_message(self) -> None:
        with pytest.raises(InvalidUrlError, match="base URL"):
            normalize_url("nonsense", label="base URL")


class TestNormalizePath:
    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("/", "/"),
            ("", "/"),
            ("/v1/orders", "/v1/orders"),
            ("/v1//orders///42", "/v1/orders/42"),
            ("/v1/./orders", "/v1/orders"),
            ("/v1/orders/", "/v1/orders"),
            ("/v1/orders/../admin", "/v1/admin"),
            ("/v1/a/b/../../c", "/v1/c"),
            ("/v1/%61%62", "/v1/ab"),
        ],
    )
    def test_canonical_forms(self, raw: str, expected: str) -> None:
        assert normalize_path(raw) == expected

    def test_trailing_slash_is_stripped_so_exclusions_cannot_be_dodged(self) -> None:
        assert normalize_path("/admin/") == normalize_path("/admin") == "/admin"

    def test_relative_path_is_rejected(self) -> None:
        with pytest.raises(InvalidUrlError, match="must start with"):
            normalize_path("v1/orders")

    def test_traversal_above_the_root_is_rejected(self) -> None:
        with pytest.raises(InvalidUrlError, match="above the root"):
            normalize_path("/../etc/passwd")

    def test_backslash_is_rejected(self) -> None:
        with pytest.raises(InvalidUrlError, match="forbidden character"):
            normalize_path("/v1\\admin")

    @pytest.mark.parametrize("raw", ["/v1/admin%2f..%2forders", "/v1%2Fadmin"])
    def test_encoded_separator_is_rejected(self, raw: str) -> None:
        with pytest.raises(InvalidUrlError, match="encodes a '/'"):
            normalize_path(raw)

    @pytest.mark.parametrize("raw", ["/v1/%252e%252e/admin", "/v1/%2561"])
    def test_double_encoding_is_rejected(self, raw: str) -> None:
        with pytest.raises(InvalidUrlError, match="encoded more than once"):
            normalize_path(raw)

    @pytest.mark.parametrize(
        ("raw", "pattern"),
        [
            ("/v1/%00", "control characters"),
            ("/v1/%5cadmin", "reserved character"),
            ("/v1/%3fadmin", "reserved character"),
            ("/v1/%23admin", "reserved character"),
        ],
    )
    def test_encoded_dangerous_characters_are_rejected(self, raw: str, pattern: str) -> None:
        with pytest.raises(InvalidUrlError, match=pattern):
            normalize_path(raw)

    def test_invalid_utf8_encoding_is_rejected(self) -> None:
        with pytest.raises(InvalidUrlError, match="not valid UTF-8"):
            normalize_path("/v1/%ff%fe")

    def test_literal_percent_is_allowed(self) -> None:
        assert normalize_path("/reports/100%") == "/reports/100%"


class TestNormalizePathPattern:
    @pytest.mark.parametrize(
        ("raw", "expected"),
        [("/v1", "/v1"), ("/v1/**", "/v1/**"), ("/v1/*/orders", "/v1/*/orders"), ("/", "/")],
    )
    def test_patterns_are_canonicalised(self, raw: str, expected: str) -> None:
        assert normalize_path_pattern(raw) == expected

    def test_percent_encoding_is_rejected_in_a_pattern(self) -> None:
        with pytest.raises(InvalidUrlError, match="must not be percent-encoded"):
            normalize_path_pattern("/v1/%2e%2e")

    def test_triple_wildcard_is_rejected(self) -> None:
        with pytest.raises(InvalidUrlError, match="unsupported wildcard"):
            normalize_path_pattern("/v1/***")

    def test_relative_pattern_is_rejected(self) -> None:
        with pytest.raises(InvalidUrlError, match="must start with"):
            normalize_path_pattern("v1/*")


class TestNormalizeHost:
    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("API.Example.com", "api.example.com"),
            ("  example.com  ", "example.com"),
            ("localhost", "localhost"),
            ("10.0.0.1", "10.0.0.1"),
            ("[2001:DB8::1]", "[2001:db8::1]"),
        ],
    )
    def test_canonical_forms(self, raw: str, expected: str) -> None:
        assert normalize_host(raw) == expected

    @pytest.mark.parametrize(
        "raw",
        [
            "",
            "example.com.",
            "exa mple.com",
            "example..com",
            ".example.com",
            "-example.com",
            "example.com:443",
            "[::1",
            "[not-an-address]",
            "a" * 300,
        ],
    )
    def test_malformed_hosts_are_rejected(self, raw: str) -> None:
        with pytest.raises(InvalidUrlError):
            normalize_host(raw)


class TestIsSubdomainOf:
    @pytest.mark.parametrize(
        ("host", "parent"),
        [
            ("api.example.com", "example.com"),
            ("a.b.example.com", "example.com"),
            ("staging.api.example.com", "api.example.com"),
        ],
    )
    def test_true_for_real_subdomains(self, host: str, parent: str) -> None:
        assert is_subdomain_of(host, parent) is True

    @pytest.mark.parametrize(
        ("host", "parent"),
        [
            # The hostname-confusion case this function exists to defeat.
            ("example.com.attacker.test", "example.com"),
            ("notexample.com", "example.com"),
            ("example.com", "example.com"),
            ("example.com", "api.example.com"),
            ("", "example.com"),
            ("example.com", ""),
        ],
    )
    def test_false_for_lookalikes_and_equal_hosts(self, host: str, parent: str) -> None:
        assert is_subdomain_of(host, parent) is False


class TestClassifyHostExposure:
    """Unit tests for :func:`classify_host_exposure`.

    The main concern is correct handling of loopback addresses, including the
    legacy IPv4 short forms that :mod:`ipaddress` rejects but real operating
    systems accept.  Private-network classification follows, then public.
    """

    @pytest.mark.parametrize(
        "host",
        [
            # Standard loopback
            "127.0.0.1",
            "::1",
            "[::1]",
            # Named loopback
            "localhost",
            "ip6-localhost",
            "ip6-loopback",
            # Suffixed loopback
            "anything.localhost",
            # Legacy IPv4 short forms — ipaddress.ip_address would reject these
            "127.1",        # 127.0.0.1 in 2-part form
            "0x7f.1",       # hex first octet
            "2130706433",   # 127.0.0.1 as a 32-bit decimal integer
            "0177.0.0.1",   # octal first octet
            "0x7f000001",   # full 32-bit hex
        ],
    )
    def test_loopback(self, host: str) -> None:
        assert classify_host_exposure(host) is HostExposure.LOOPBACK, (
            f"Expected {host!r} to be classified as LOOPBACK"
        )

    @pytest.mark.parametrize(
        "host",
        [
            # RFC 1918 private ranges
            "10.0.0.1",
            "10.1",         # 2-part 10.0.0.1 form
            "172.16.0.1",
            "172.31.255.255",
            "192.168.1.100",
            "192.168.0.1",
            # Link-local
            "169.254.1.1",
            "169.254.0.0",
            # IPv6 ULA
            "fc00::1",
            "fd00::1",
            # DNS suffixes that imply private/internal
            "myserver.local",
            "app.internal",
            "db.home.arpa",
        ],
    )
    def test_private(self, host: str) -> None:
        assert classify_host_exposure(host) is HostExposure.PRIVATE, (
            f"Expected {host!r} to be classified as PRIVATE"
        )

    @pytest.mark.parametrize(
        "host",
        [
            "example.com",
            "api.example.com",
            "8.8.8.8",   # Google Public DNS
            "1.1.1.1",   # Cloudflare DNS
        ],
    )
    def test_public(self, host: str) -> None:
        assert classify_host_exposure(host) is HostExposure.PUBLIC, (
            f"Expected {host!r} to be classified as PUBLIC"
        )
