"""Scope enforcement: what is admitted, what is denied, and why.

These tests are the behavioural contract for the gate every future network
module must pass through. Each denial case below is a way a request could
otherwise reach a host or path nobody authorised.
"""

from __future__ import annotations

import logging

import pytest

from aegisapi.core.config import ScopeSettings
from aegisapi.core.exceptions import InvalidUrlError, ScopeViolationError
from aegisapi.core.logging import LOGGER_NAME
from aegisapi.core.scope import (
    ScopeAuthorisation,
    ScopeDecision,
    ScopeValidator,
    assert_in_scope,
    check_global_allow_list,
    combine_decisions,
    path_matches,
)
from aegisapi.models.target import ScopeRules, Target
from aegisapi.utils.urls import normalize_url
from conftest import make_target

TOKEN = "eyJhbGciOiJIUzI1NiJ9.super-secret-token-value"
ALLOWED = ScopeSettings(allowed_hosts=["api.acme.test"])


def validator_for(**overrides: object) -> ScopeValidator:
    """Build a validator over a target assembled from ``overrides``."""
    return ScopeValidator(make_target(**overrides))


class TestDefaultDeny:
    def test_a_target_with_no_include_paths_denies_everything(self) -> None:
        target = Target(name="acme", base_url="https://api.acme.test")
        decision = ScopeValidator(target).check("https://api.acme.test/")

        assert decision.allowed is False
        assert "no include patterns" in decision.reason
        assert decision.rule == "scope.include_paths"

    def test_a_disabled_target_denies_its_own_base_url(self) -> None:
        decision = validator_for(enabled=False).check("https://api.acme.test/v1/orders")

        assert decision.allowed is False
        assert "disabled" in decision.reason

    @pytest.mark.parametrize(
        "url",
        [
            "not a url",
            "example.com/v1",
            "ftp://api.acme.test/v1",
            "https://api.acme.test@attacker.test/v1",
            "https://api.acme.test/v1#frag",
            "https://api.acme.test/v1/%2e%2e%2fadmin",
            "",
        ],
    )
    def test_an_unparseable_url_is_denied_rather_than_raising(self, url: str) -> None:
        # A gate that raised here would invite a caller to treat the error as
        # "probably fine"; a denial cannot be misread.
        decision = validator_for().check(url)

        assert decision.allowed is False
        assert decision.rule in {"url.parse", "base_url.scheme"}


class TestHostMatching:
    def test_the_target_host_is_allowed(self) -> None:
        decision = validator_for().check("https://api.acme.test/v1/orders")

        assert decision.allowed is True

    def test_host_matching_is_case_insensitive(self) -> None:
        assert validator_for().check("https://API.Acme.Test/v1/orders").allowed is True

    @pytest.mark.parametrize(
        "url",
        [
            # Hostname confusion: the authorised name appears as a prefix of a
            # host the attacker controls.
            "https://api.acme.test.attacker.test/v1/orders",
            "https://api.acme.test.evil.example/v1/orders",
            "https://notapi.acme.test/v1/orders",
            "https://api.acme.test.co/v1/orders",
            "https://attacker.test/v1/orders",
        ],
    )
    def test_lookalike_hosts_are_denied(self, url: str) -> None:
        decision = validator_for().check(url)

        assert decision.allowed is False
        assert decision.rule == "base_url.host"

    def test_a_subdomain_is_denied_by_default(self) -> None:
        decision = validator_for().check("https://staging.api.acme.test/v1/orders")

        assert decision.allowed is False

    def test_a_subdomain_is_allowed_only_when_configured(self) -> None:
        url = "https://staging.api.acme.test/v1/orders"
        denied = validator_for(scope=ScopeRules(include_paths=["/"]))
        allowed = validator_for(scope=ScopeRules(include_paths=["/"], allow_subdomains=True))

        assert denied.check(url).allowed is False
        assert allowed.check(url).allowed is True

    def test_allowing_subdomains_still_denies_a_lookalike(self) -> None:
        target_validator = validator_for(
            scope=ScopeRules(include_paths=["/"], allow_subdomains=True)
        )

        decision = target_validator.check("https://api.acme.test.attacker.test/v1")

        assert decision.allowed is False

    def test_an_extra_host_is_allowed_exactly(self) -> None:
        target_validator = validator_for(
            scope=ScopeRules(include_paths=["/"], extra_hosts=["cdn.acme.test"])
        )

        assert target_validator.check("https://cdn.acme.test/v1/assets").allowed is True
        assert target_validator.check("https://sub.cdn.acme.test/v1").allowed is False

    def test_registering_one_host_does_not_authorise_another(self) -> None:
        # A registered URL is never blanket authorisation for unrelated hosts.
        assert validator_for().check("https://unrelated.test/v1/orders").allowed is False


class TestSchemeAndPort:
    def test_scheme_is_pinned_to_the_base_url(self) -> None:
        decision = validator_for().check("http://api.acme.test/v1/orders")

        assert decision.allowed is False
        assert decision.rule == "base_url.scheme"

    def test_matching_scheme_is_allowed(self) -> None:
        http_validator = validator_for(base_url="http://api.acme.test/v1")

        assert http_validator.check("http://api.acme.test/v1/orders").allowed is True
        assert http_validator.check("https://api.acme.test/v1/orders").allowed is False

    def test_default_port_matches_an_implicit_one(self) -> None:
        assert validator_for().check("https://api.acme.test:443/v1/orders").allowed is True

    def test_a_different_port_is_denied(self) -> None:
        decision = validator_for().check("https://api.acme.test:8443/v1/orders")

        assert decision.allowed is False
        assert decision.rule == "base_url.port"

    def test_an_allowed_port_is_admitted(self) -> None:
        url = "https://api.acme.test:8443/v1/orders"
        denied = validator_for(scope=ScopeRules(include_paths=["/"]))
        allowed = validator_for(scope=ScopeRules(include_paths=["/"], allowed_ports=[8443]))

        assert denied.check(url).allowed is False
        assert allowed.check(url).allowed is True

    def test_a_non_default_base_port_becomes_the_expected_port(self) -> None:
        target_validator = validator_for(base_url="https://api.acme.test:8443/v1")

        assert target_validator.check("https://api.acme.test:8443/v1/x").allowed is True
        assert target_validator.check("https://api.acme.test/v1/x").allowed is False


class TestPathMatching:
    def test_the_include_path_itself_is_in_scope(self) -> None:
        assert validator_for().check("https://api.acme.test/v1").allowed is True

    def test_paths_below_an_include_are_in_scope(self) -> None:
        assert validator_for().check("https://api.acme.test/v1/orders/42").allowed is True

    def test_a_trailing_slash_does_not_change_the_decision(self) -> None:
        assert validator_for().check("https://api.acme.test/v1/").allowed is True

    def test_an_include_respects_segment_boundaries(self) -> None:
        # '/v1' must not admit '/v1beta' or '/v1keys'.
        target_validator = validator_for(base_url="https://api.acme.test/v1")

        assert target_validator.check("https://api.acme.test/v1beta/orders").allowed is False
        assert target_validator.check("https://api.acme.test/v1keys").allowed is False

    def test_a_sibling_path_is_denied(self) -> None:
        decision = validator_for().check("https://api.acme.test/v2/orders")

        assert decision.allowed is False
        assert "does not match any include pattern" in decision.reason

    def test_root_include_admits_every_path(self) -> None:
        target_validator = validator_for(base_url="https://api.acme.test")

        assert target_validator.check("https://api.acme.test/anything/deep").allowed is True

    def test_traversal_is_resolved_before_matching(self) -> None:
        # '/v1/orders/../../v2' resolves to '/v2', outside the include.
        decision = validator_for().check("https://api.acme.test/v1/orders/../../v2")

        assert decision.allowed is False

    def test_single_segment_wildcard(self) -> None:
        target_validator = validator_for(scope=ScopeRules(include_paths=["/v1/*/orders"]))

        assert target_validator.check("https://api.acme.test/v1/eu/orders").allowed is True
        assert target_validator.check("https://api.acme.test/v1/eu/west/orders").allowed is False

    def test_subtree_wildcard_covers_the_prefix_and_below(self) -> None:
        target_validator = validator_for(scope=ScopeRules(include_paths=["/v1/**"]))

        assert target_validator.check("https://api.acme.test/v1").allowed is True
        assert target_validator.check("https://api.acme.test/v1/a/b/c").allowed is True
        assert target_validator.check("https://api.acme.test/v2").allowed is False


class TestExclusions:
    def excluding_validator(self) -> ScopeValidator:
        return validator_for(
            scope=ScopeRules(include_paths=["/v1/**"], exclude_paths=["/v1/admin"])
        )

    def test_an_excluded_path_is_denied(self) -> None:
        decision = self.excluding_validator().check("https://api.acme.test/v1/admin")

        assert decision.allowed is False
        assert decision.rule == "scope.exclude_paths"

    def test_everything_below_an_exclusion_is_denied(self) -> None:
        decision = self.excluding_validator().check("https://api.acme.test/v1/admin/users/1")

        assert decision.allowed is False

    def test_exclusion_beats_a_matching_include(self) -> None:
        target_validator = validator_for(
            scope=ScopeRules(include_paths=["/v1/admin/**"], exclude_paths=["/v1/admin"])
        )

        assert target_validator.check("https://api.acme.test/v1/admin/users").allowed is False

    @pytest.mark.parametrize(
        "url",
        [
            # Each of these is an attempt to slip past 'exclude /v1/admin'.
            "https://api.acme.test/v1/admin/",
            "https://api.acme.test/v1//admin",
            "https://api.acme.test/v1/./admin",
            "https://api.acme.test/v1/orders/../admin",
            "https://api.acme.test/v1/Admin",
            "https://api.acme.test/v1/ADMIN/users",
            "https://api.acme.test/v1/%61dmin",
        ],
    )
    def test_ordinary_prefix_tricks_do_not_bypass_an_exclusion(self, url: str) -> None:
        assert self.excluding_validator().check(url).allowed is False

    def test_a_similarly_named_sibling_is_not_excluded(self) -> None:
        # Exclusions respect segment boundaries too: '/v1/administrator' is a
        # different resource and stays in scope.
        decision = self.excluding_validator().check("https://api.acme.test/v1/administrator")

        assert decision.allowed is True

    def test_excluding_the_root_denies_everything(self) -> None:
        target_validator = validator_for(scope=ScopeRules(include_paths=["/"], exclude_paths=["/"]))

        assert target_validator.check("https://api.acme.test/v1").allowed is False

    def test_wildcard_exclusion(self) -> None:
        target_validator = validator_for(
            scope=ScopeRules(include_paths=["/v1/**"], exclude_paths=["/v1/*/internal"])
        )

        assert target_validator.check("https://api.acme.test/v1/eu/internal").allowed is False
        assert target_validator.check("https://api.acme.test/v1/eu/public").allowed is True


class TestPathMatchesHelper:
    @pytest.mark.parametrize(
        ("path", "pattern", "expected"),
        [
            ("/v1", "/v1", True),
            ("/v1/orders", "/v1", True),
            ("/v1keys", "/v1", False),
            ("/anything", "/", True),
            ("/v1/eu/orders", "/v1/*/orders", True),
            ("/v1/eu/west/orders", "/v1/*/orders", False),
            ("/v1", "/v1/**", True),
            ("/v1/a/b", "/v1/**", True),
            ("/v2", "/v1/**", False),
            ("/v1/a.json", "/v1/*.json", True),
        ],
    )
    def test_matching(self, path: str, pattern: str, expected: bool) -> None:
        assert path_matches(path, pattern) is expected

    def test_case_sensitivity_is_selectable(self) -> None:
        assert path_matches("/Admin", "/admin") is False
        assert path_matches("/Admin", "/admin", case_sensitive=False) is True


class TestAssertAllowed:
    def test_returns_the_parsed_url_when_in_scope(self) -> None:
        url = validator_for().assert_allowed("https://api.acme.test/v1/orders")

        assert url.host == "api.acme.test"
        assert url.path == "/v1/orders"

    def test_raises_with_the_reason_when_out_of_scope(self) -> None:
        with pytest.raises(ScopeViolationError) as excinfo:
            validator_for().assert_allowed("https://attacker.test/v1")

        assert "out of scope" in excinfo.value.message
        assert "attacker.test" in excinfo.value.message
        assert excinfo.value.exit_code == 5
        assert "authorisation" in str(excinfo.value.hint)


class TestGlobalAllowList:
    def test_empty_allow_list_denies_everything(self) -> None:
        decision = check_global_allow_list("api.acme.test", ScopeSettings())

        assert decision.allowed is False
        assert "empty" in decision.reason

    def test_listed_host_is_allowed(self) -> None:
        settings = ScopeSettings(allowed_hosts=["api.acme.test"])

        assert check_global_allow_list("api.acme.test", settings).allowed is True

    def test_unlisted_host_is_denied(self) -> None:
        settings = ScopeSettings(allowed_hosts=["api.acme.test"])

        assert check_global_allow_list("other.test", settings).allowed is False

    def test_subdomains_are_not_implied(self) -> None:
        settings = ScopeSettings(allowed_hosts=["acme.test"])

        assert check_global_allow_list("api.acme.test", settings).allowed is False

    def test_disabling_enforcement_allows_any_host(self) -> None:
        decision = check_global_allow_list("anything.test", ScopeSettings(enforce=False))

        assert decision.allowed is True
        assert "disabled" in decision.reason


class TestCombineDecisions:
    def test_first_denial_wins(self) -> None:
        combined = combine_decisions(
            ScopeDecision.allow("fine"),
            ScopeDecision.deny("host denied"),
            ScopeDecision.deny("path denied"),
        )

        assert combined.allowed is False
        assert combined.reason == "host denied"

    def test_all_allowed_returns_the_last(self) -> None:
        combined = combine_decisions(ScopeDecision.allow("a"), ScopeDecision.allow("b"))

        assert combined.allowed is True
        assert combined.reason == "b"

    def test_no_decisions_is_an_error(self) -> None:
        # An empty conjunction would have to default to "allowed".
        with pytest.raises(ValueError, match="at least one decision"):
            combine_decisions()

    def test_decision_is_truthy_when_allowed(self) -> None:
        assert bool(ScopeDecision.allow("ok")) is True
        assert bool(ScopeDecision.deny("no")) is False
        assert ScopeDecision.allow("ok").verdict == "in scope"
        assert ScopeDecision.deny("no").verdict == "out of scope"


class TestAssertInScope:
    """The authoritative outbound gate.

    Everything that sends a request goes through this function, so these tests
    are the contract the HTTP client and any future probing module inherit.
    """

    def test_both_gates_must_admit_the_url(self) -> None:
        target = make_target()

        authorisation = assert_in_scope(
            "https://api.acme.test/v1/orders", target=target, settings=ALLOWED
        )

        assert isinstance(authorisation, ScopeAuthorisation)
        assert authorisation.url.path == "/v1/orders"
        assert authorisation.target_decision.allowed is True
        assert authorisation.global_decision is not None
        assert authorisation.global_decision.allowed is True

    def test_the_reason_names_both_gates(self) -> None:
        authorisation = assert_in_scope(
            "https://api.acme.test/v1/orders", target=make_target(), settings=ALLOWED
        )

        assert "target scope: " in authorisation.reason
        assert "global: " in authorisation.reason

    def test_target_scope_alone_can_deny(self) -> None:
        target = make_target()

        with pytest.raises(ScopeViolationError, match="out of scope"):
            assert_in_scope("https://api.acme.test/v2", target=target, settings=ALLOWED)

    def test_global_allow_list_alone_can_deny(self) -> None:
        target = make_target()

        with pytest.raises(ScopeViolationError, match="not globally authorised"):
            assert_in_scope(
                "https://api.acme.test/v1/orders", target=target, settings=ScopeSettings()
            )

    def test_omitting_settings_checks_the_target_scope_only(self) -> None:
        target = make_target()

        authorisation = assert_in_scope("https://api.acme.test/v1/orders", target=target)

        assert authorisation.url.host == "api.acme.test"
        assert authorisation.global_decision is None
        assert "global:" not in authorisation.reason

    def test_an_already_parsed_url_is_judged_and_returned_unchanged(self) -> None:
        # The URL that was checked must be the URL that gets contacted, so a
        # caller that already parsed one gets that exact object back.
        parsed = normalize_url("https://api.acme.test/v1/orders")

        authorisation = assert_in_scope(parsed, target=make_target(), settings=ALLOWED)

        assert authorisation.url is parsed

    @pytest.mark.parametrize(
        "url",
        [
            "ftp://api.acme.test/v1",
            "https://api.acme.test/v1/orders%2f..%2fadmin",
            "not a url",
            "",
        ],
    )
    def test_a_malformed_url_is_reported_as_bad_input(self, url: str) -> None:
        # Raised rather than denied: a malformed destination is bad input, and
        # treating it as a scope decision would mean checking one spelling of a
        # URL while sending another. Either way nothing is sent.
        with pytest.raises(InvalidUrlError) as excinfo:
            assert_in_scope(url, target=make_target(), settings=ALLOWED)

        assert not isinstance(excinfo.value, ScopeViolationError)

    @pytest.mark.parametrize(
        ("url", "settings", "expected"),
        [
            (f"https://api.acme.test/v2?api_key={TOKEN}", ALLOWED, "out of scope"),
            (
                f"https://api.acme.test/v1/orders?api_key={TOKEN}",
                ScopeSettings(),
                "not globally authorised",
            ),
        ],
    )
    def test_a_refusal_never_echoes_a_credential(
        self, url: str, settings: ScopeSettings, expected: str
    ) -> None:
        # A refusal is printed to the terminal and written to the log, so a key
        # in the query string must not survive into the message.
        with pytest.raises(ScopeViolationError) as excinfo:
            assert_in_scope(url, target=make_target(), settings=settings)

        assert expected in excinfo.value.message
        assert TOKEN not in excinfo.value.message
        assert "[REDACTED]" in excinfo.value.message

    def test_a_refusal_is_logged_without_the_credential(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        with (
            caplog.at_level(logging.WARNING, logger=LOGGER_NAME),
            pytest.raises(ScopeViolationError),
        ):
            assert_in_scope(
                f"https://api.acme.test/v2?api_key={TOKEN}",
                target=make_target(),
                settings=ALLOWED,
            )

        messages = [record.getMessage() for record in caplog.records]
        assert any("refused" in message for message in messages)
        assert all(TOKEN not in message for message in messages)

    def test_a_disabled_target_admits_nothing(self) -> None:
        with pytest.raises(ScopeViolationError, match="disabled"):
            assert_in_scope(
                "https://api.acme.test/v1/orders",
                target=make_target(enabled=False),
                settings=ALLOWED,
            )

    def test_the_refusal_hint_says_nothing_was_sent(self) -> None:
        with pytest.raises(ScopeViolationError) as excinfo:
            assert_in_scope("https://attacker.test/v1", target=make_target(), settings=ALLOWED)

        assert "No request was sent" in str(excinfo.value.hint)
        assert "authorisation" in str(excinfo.value.hint)
