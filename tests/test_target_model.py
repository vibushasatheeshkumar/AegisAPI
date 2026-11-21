"""The target data model: validation, defaults, and serialisation safety."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from aegisapi.core.exceptions import InvalidUrlError, MissingCredentialError
from aegisapi.models.secrets import SecretRef
from aegisapi.models.target import (
    ApiKeyLocation,
    AuthMethod,
    AuthProfile,
    ScopeRules,
    Target,
    TargetCollection,
    normalize_target_name,
)
from aegisapi.utils.secrets import Secret

TOKEN_VALUE = "eyJhbGciOiJIUzI1NiJ9.super-secret-token-value"


class TestTargetName:
    @pytest.mark.parametrize(
        ("raw", "expected"),
        [("acme", "acme"), ("ACME", "acme"), ("  Acme-API_2  ", "acme-api_2"), ("a", "a")],
    )
    def test_names_are_normalised_to_lowercase_slugs(self, raw: str, expected: str) -> None:
        assert normalize_target_name(raw) == expected

    @pytest.mark.parametrize(
        "raw",
        [
            "",
            "   ",
            "-leading",
            "_leading",
            "has space",
            "has/slash",
            "has.dot",
            "a" * 49,
            "ümlaut",
        ],
    )
    def test_invalid_names_are_rejected(self, raw: str) -> None:
        with pytest.raises(ValueError, match="target name"):
            normalize_target_name(raw)

    def test_case_differences_cannot_create_two_targets(self) -> None:
        assert Target.create(name="ACME", base_url="https://a.test").name == "acme"


class TestTargetCreation:
    def test_include_paths_default_to_the_base_url_path(self) -> None:
        target = Target.create(name="acme", base_url="https://api.acme.test/v2")

        # Narrower than the whole host, which is the safer default.
        assert target.scope.include_paths == ["/v2"]

    def test_root_base_url_includes_the_whole_host(self) -> None:
        target = Target.create(name="acme", base_url="https://api.acme.test")

        assert target.scope.include_paths == ["/"]

    def test_explicit_include_paths_are_not_overwritten(self) -> None:
        target = Target.create(
            name="acme",
            base_url="https://api.acme.test/v2",
            scope=ScopeRules(include_paths=["/v2/orders"]),
        )

        assert target.scope.include_paths == ["/v2/orders"]

    def test_base_url_is_canonicalised(self) -> None:
        target = Target.create(name="acme", base_url="HTTPS://API.Acme.Test:443/v1/")

        assert target.base_url == "https://api.acme.test/v1"
        assert target.host == "api.acme.test"
        assert target.scheme == "https"
        assert target.port == 443
        assert target.base_path == "/v1"

    def test_timestamps_are_timezone_aware_utc(self) -> None:
        before = datetime.now(UTC) - timedelta(seconds=1)
        target = Target.create(name="acme", base_url="https://a.test")

        assert target.created_at.tzinfo is not None
        assert target.created_at >= before
        assert target.updated_at >= target.created_at

    def test_naive_timestamps_are_rejected(self) -> None:
        with pytest.raises(ValidationError, match="timezone-aware"):
            Target(
                name="acme",
                base_url="https://a.test",
                created_at=datetime(2026, 1, 1),
                updated_at=datetime.now(UTC),
            )

    def test_defaults_are_enabled_with_no_authentication(self) -> None:
        target = Target.create(name="acme", base_url="https://a.test")

        assert target.enabled is True
        assert target.auth.method is AuthMethod.NONE
        assert target.auth.requires_credentials is False

    @pytest.mark.parametrize(
        "base_url",
        [
            "ftp://api.acme.test",
            "api.acme.test",
            "https://api.acme.test@attacker.test",
            "https://api.acme.test/v1?debug=1",
            "https://api.acme.test/v1#frag",
        ],
    )
    def test_invalid_base_urls_are_rejected(self, base_url: str) -> None:
        with pytest.raises(InvalidUrlError):
            Target.create(name="acme", base_url=base_url)

    def test_tags_are_normalised_and_deduplicated(self) -> None:
        target = Target.create(
            name="acme", base_url="https://a.test", tags=["Prod", "prod", " EU ", ""]
        )

        assert target.scope.include_paths == ["/"]
        assert target.tags == ["prod", "eu"]

    def test_invalid_tag_is_rejected(self) -> None:
        with pytest.raises(ValidationError, match="valid tag"):
            Target.create(name="acme", base_url="https://a.test", tags=["two words"])

    def test_unknown_fields_are_rejected(self) -> None:
        # Notably a field that would hold a credential in plaintext.
        with pytest.raises(ValidationError):
            Target(name="acme", base_url="https://a.test", token="secret")

    def test_description_length_is_bounded(self) -> None:
        with pytest.raises(ValidationError):
            Target.create(name="acme", base_url="https://a.test", description="x" * 501)


class TestScopeRules:
    def test_default_rules_include_nothing(self) -> None:
        rules = ScopeRules()

        # Default deny: an empty include list admits no path at all.
        assert rules.include_paths == []
        assert rules.exclude_paths == []
        assert rules.extra_hosts == []
        assert rules.allowed_ports == []
        assert rules.allow_subdomains is False

    def test_patterns_are_canonicalised_and_deduplicated(self) -> None:
        rules = ScopeRules(
            include_paths=["/v1/", "/v1", "/v1//orders"],
            exclude_paths=["/v1/admin/"],
        )

        assert rules.include_paths == ["/v1", "/v1/orders"]
        assert rules.exclude_paths == ["/v1/admin"]

    def test_hosts_are_canonicalised_and_deduplicated(self) -> None:
        rules = ScopeRules(extra_hosts=["API.Other.Test", "api.other.test"])

        assert rules.extra_hosts == ["api.other.test"]

    def test_malformed_host_is_rejected(self) -> None:
        with pytest.raises(InvalidUrlError):
            ScopeRules(extra_hosts=["https://api.other.test/v1"])

    def test_encoded_pattern_is_rejected(self) -> None:
        with pytest.raises(InvalidUrlError):
            ScopeRules(include_paths=["/v1/%2e%2e"])

    @pytest.mark.parametrize("port", [0, -1, 70000])
    def test_invalid_ports_are_rejected(self, port: int) -> None:
        with pytest.raises(ValidationError, match="valid port"):
            ScopeRules(allowed_ports=[port])

    def test_ports_are_deduplicated(self) -> None:
        assert ScopeRules(allowed_ports=[8443, 8443, 8080]).allowed_ports == [8443, 8080]

    def test_unknown_rule_is_rejected(self) -> None:
        with pytest.raises(ValidationError):
            ScopeRules(allow_everything=True)

    def test_summary_is_human_readable(self) -> None:
        rules = ScopeRules(
            include_paths=["/v1"],
            exclude_paths=["/v1/admin"],
            extra_hosts=["other.test"],
            allowed_ports=[8443],
            allow_subdomains=True,
        )

        summary = rules.summary()
        assert "1 include" in summary
        assert "1 exclude" in summary
        assert "subdomains" in summary


class TestAuthProfile:
    def test_default_is_no_authentication(self) -> None:
        profile = AuthProfile()

        assert profile.method is AuthMethod.NONE
        assert profile.references == ()
        assert profile.describe() == ("no authentication configured",)

    def test_bearer_requires_a_token_reference(self) -> None:
        with pytest.raises(ValidationError, match="requires token"):
            AuthProfile(method=AuthMethod.BEARER)

    def test_api_key_requires_a_key_reference(self) -> None:
        with pytest.raises(ValidationError, match="requires api_key"):
            AuthProfile(method=AuthMethod.API_KEY)

    def test_basic_requires_a_password_reference(self) -> None:
        with pytest.raises(ValidationError, match="requires password"):
            AuthProfile(method=AuthMethod.BASIC, username="scanner")

    def test_basic_requires_both_username_and_password(self) -> None:
        with pytest.raises(ValidationError, match="requires password, username"):
            AuthProfile(method=AuthMethod.BASIC)

    def test_none_must_not_carry_credentials(self) -> None:
        # An over-specified profile hides which credential would be used.
        with pytest.raises(ValidationError, match="must not define token"):
            AuthProfile(method=AuthMethod.NONE, token=SecretRef(variable="ACME_TOKEN"))

    def test_bearer_must_not_carry_an_api_key(self) -> None:
        with pytest.raises(ValidationError, match="must not define api_key"):
            AuthProfile(
                method=AuthMethod.BEARER,
                token=SecretRef(variable="ACME_TOKEN"),
                api_key=SecretRef(variable="ACME_KEY"),
            )

    def test_bearer_profile_exposes_its_reference(self) -> None:
        profile = AuthProfile(method=AuthMethod.BEARER, token=SecretRef(variable="ACME_TOKEN"))

        assert profile.requires_credentials is True
        assert [field for field, _ in profile.references] == ["token"]

    def test_api_key_defaults_to_a_header(self) -> None:
        profile = AuthProfile(method=AuthMethod.API_KEY, api_key=SecretRef(variable="ACME_KEY"))

        assert profile.api_key_location is ApiKeyLocation.HEADER
        assert profile.api_key_name == "X-API-Key"

    @pytest.mark.parametrize(
        "name", ["", "   ", "has space", "has:colon", "has=equals", 'has"quote']
    )
    def test_invalid_api_key_name_is_rejected(self, name: str) -> None:
        with pytest.raises(ValidationError):
            AuthProfile(
                method=AuthMethod.API_KEY,
                api_key=SecretRef(variable="ACME_KEY"),
                api_key_name=name,
            )

    def test_credential_status_reports_availability_only(self) -> None:
        profile = AuthProfile(method=AuthMethod.BEARER, token=SecretRef(variable="ACME_TOKEN"))

        assert profile.credential_status({"ACME_TOKEN": TOKEN_VALUE}) == {"token": True}
        assert profile.credential_status({}) == {"token": False}

    def test_resolve_credentials_returns_opaque_secrets(self) -> None:
        profile = AuthProfile(
            method=AuthMethod.BASIC,
            username="scanner",
            password=SecretRef(variable="ACME_PASSWORD"),
        )

        resolved = profile.resolve_credentials({"ACME_PASSWORD": TOKEN_VALUE})

        assert isinstance(resolved["password"], Secret)
        assert resolved["password"].reveal() == TOKEN_VALUE

    def test_resolve_credentials_raises_rather_than_returning_empty(self) -> None:
        profile = AuthProfile(method=AuthMethod.BEARER, token=SecretRef(variable="ACME_TOKEN"))

        with pytest.raises(MissingCredentialError):
            profile.resolve_credentials({})

    def test_describe_contains_no_credential_value(self) -> None:
        profile = AuthProfile(
            method=AuthMethod.API_KEY,
            api_key=SecretRef(variable="ACME_KEY"),
            api_key_name="X-Key",
        )

        lines = profile.describe()
        assert "api_key from env:ACME_KEY" in lines
        assert all(TOKEN_VALUE not in line for line in lines)

    def test_plaintext_credential_fields_do_not_exist(self) -> None:
        for forbidden in ("token_value", "password_value", "api_key_value", "secret"):
            assert forbidden not in AuthProfile.model_fields


class TestSerialisation:
    def test_round_trip_preserves_everything(self) -> None:
        target = Target.create(
            name="acme",
            base_url="https://api.acme.test/v1",
            description="Acme API",
            tags=["prod"],
            scope=ScopeRules(
                include_paths=["/v1/**"],
                exclude_paths=["/v1/admin"],
                extra_hosts=["other.test"],
                allowed_ports=[8443],
                allow_subdomains=True,
            ),
            auth=AuthProfile(method=AuthMethod.BEARER, token=SecretRef(variable="ACME_TOKEN")),
        )

        restored = Target.model_validate(json.loads(target.model_dump_json()))

        assert restored == target

    def test_serialised_target_holds_no_credential_value(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("ACME_TOKEN", TOKEN_VALUE)
        target = Target.create(
            name="acme",
            base_url="https://api.acme.test",
            auth=AuthProfile(method=AuthMethod.BEARER, token=SecretRef(variable="ACME_TOKEN")),
        )

        serialised = target.model_dump_json()

        # Only the variable name is persisted, even though the value is set.
        assert "ACME_TOKEN" in serialised
        assert TOKEN_VALUE not in serialised

    def test_repr_of_a_target_holds_no_credential_value(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("ACME_TOKEN", TOKEN_VALUE)
        target = Target.create(
            name="acme",
            base_url="https://api.acme.test",
            auth=AuthProfile(method=AuthMethod.BEARER, token=SecretRef(variable="ACME_TOKEN")),
        )

        assert TOKEN_VALUE not in repr(target)


class TestTargetCollection:
    def test_empty_collection_is_valid(self) -> None:
        collection = TargetCollection()

        assert collection.schema_version == 1
        assert collection.sorted_targets() == []

    def test_targets_are_sorted_by_name(self) -> None:
        collection = TargetCollection(
            targets={
                "zeta": Target.create(name="zeta", base_url="https://z.test"),
                "alpha": Target.create(name="alpha", base_url="https://a.test"),
            }
        )

        assert [target.name for target in collection.sorted_targets()] == ["alpha", "zeta"]

    def test_key_must_match_the_target_name(self) -> None:
        with pytest.raises(ValidationError, match="is named"):
            TargetCollection(
                targets={"wrong": Target.create(name="acme", base_url="https://a.test")}
            )

    def test_unknown_field_is_rejected(self) -> None:
        with pytest.raises(ValidationError):
            TargetCollection(targets={}, extra_section={})

    def test_schema_version_must_be_positive(self) -> None:
        with pytest.raises(ValidationError):
            TargetCollection(schema_version=0)
