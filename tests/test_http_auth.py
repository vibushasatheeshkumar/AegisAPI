"""Attaching credentials to requests, and refusing to when it is unsafe."""

from __future__ import annotations

import base64

import pytest

from aegisapi.core.exceptions import MissingCredentialError
from aegisapi.http.auth import (
    credential_header_names,
    prepare_authentication,
    same_origin,
    strip_credential_headers,
)
from aegisapi.models.secrets import SecretRef
from aegisapi.models.target import ApiKeyLocation, AuthMethod, AuthProfile
from aegisapi.utils.urls import normalize_url

TOKEN = "eyJhbGciOiJIUzI1NiJ9.super-secret-token-value"
TARGET_ORIGIN = normalize_url("https://api.acme.test/v1")


def bearer() -> AuthProfile:
    """A bearer profile referencing ACME_TOKEN."""
    return AuthProfile(method=AuthMethod.BEARER, token=SecretRef(variable="ACME_TOKEN"))


class TestSameOrigin:
    def test_identical_origins_match(self) -> None:
        assert same_origin(normalize_url("https://a.test/x"), normalize_url("https://a.test/y"))

    @pytest.mark.parametrize(
        "other",
        [
            "http://api.acme.test/v1",
            "https://api.acme.test:8443/v1",
            "https://other.acme.test/v1",
            "https://api.acme.test.attacker.test/v1",
        ],
    )
    def test_scheme_host_and_port_all_matter(self, other: str) -> None:
        # A credential scoped to https://api.acme.test must not travel over
        # plain http, to another port, or to a lookalike host.
        assert same_origin(normalize_url(other), TARGET_ORIGIN) is False


class TestPreparation:
    def test_no_authentication_attaches_nothing(self) -> None:
        prepared = prepare_authentication(
            AuthProfile(), destination=TARGET_ORIGIN, target_origin=TARGET_ORIGIN
        )

        assert prepared.applied is False
        assert prepared.headers == {}
        assert prepared.method is AuthMethod.NONE

    def test_bearer_token_becomes_an_authorization_header(self) -> None:
        prepared = prepare_authentication(
            bearer(),
            destination=TARGET_ORIGIN,
            target_origin=TARGET_ORIGIN,
            env={"ACME_TOKEN": TOKEN},
        )

        assert prepared.applied is True
        assert prepared.headers == {"Authorization": f"Bearer {TOKEN}"}
        assert TOKEN not in prepared.reason

    def test_api_key_header(self) -> None:
        profile = AuthProfile(
            method=AuthMethod.API_KEY,
            api_key=SecretRef(variable="ACME_KEY"),
            api_key_name="X-Acme-Key",
        )

        prepared = prepare_authentication(
            profile,
            destination=TARGET_ORIGIN,
            target_origin=TARGET_ORIGIN,
            env={"ACME_KEY": TOKEN},
        )

        assert prepared.headers == {"X-Acme-Key": TOKEN}
        assert prepared.params == {}

    def test_api_key_query_parameter(self) -> None:
        profile = AuthProfile(
            method=AuthMethod.API_KEY,
            api_key=SecretRef(variable="ACME_KEY"),
            api_key_name="api_key",
            api_key_location=ApiKeyLocation.QUERY,
        )

        prepared = prepare_authentication(
            profile,
            destination=TARGET_ORIGIN,
            target_origin=TARGET_ORIGIN,
            env={"ACME_KEY": TOKEN},
        )

        assert prepared.params == {"api_key": TOKEN}
        assert prepared.headers == {}

    def test_basic_credentials_are_encoded(self) -> None:
        profile = AuthProfile(
            method=AuthMethod.BASIC,
            username="scanner",
            password=SecretRef(variable="ACME_PASSWORD"),
        )

        prepared = prepare_authentication(
            profile,
            destination=TARGET_ORIGIN,
            target_origin=TARGET_ORIGIN,
            env={"ACME_PASSWORD": TOKEN},
        )

        expected = base64.b64encode(f"scanner:{TOKEN}".encode()).decode("ascii")
        assert prepared.headers == {"Authorization": f"Basic {expected}"}


class TestRefusals:
    def test_credentials_are_withheld_from_another_origin(self) -> None:
        prepared = prepare_authentication(
            bearer(),
            destination=normalize_url("https://attacker.test/v1"),
            target_origin=TARGET_ORIGIN,
            env={"ACME_TOKEN": TOKEN},
        )

        assert prepared.applied is False
        assert prepared.headers == {}
        assert "withheld" in prepared.reason
        assert TOKEN not in prepared.reason

    def test_credentials_are_withheld_on_a_scheme_downgrade(self) -> None:
        prepared = prepare_authentication(
            bearer(),
            destination=normalize_url("http://api.acme.test/v1"),
            target_origin=TARGET_ORIGIN,
            env={"ACME_TOKEN": TOKEN},
        )

        assert prepared.applied is False

    def test_disabling_authentication_is_recorded(self) -> None:
        prepared = prepare_authentication(
            bearer(),
            destination=TARGET_ORIGIN,
            target_origin=TARGET_ORIGIN,
            env={"ACME_TOKEN": TOKEN},
            enabled=False,
        )

        assert prepared.applied is False
        assert "disabled" in prepared.reason

    def test_missing_variable_raises_rather_than_downgrading(self) -> None:
        with pytest.raises(MissingCredentialError, match="is not set"):
            prepare_authentication(
                bearer(), destination=TARGET_ORIGIN, target_origin=TARGET_ORIGIN, env={}
            )

    @pytest.mark.parametrize("value", ["", "   "])
    def test_empty_variable_raises(self, value: str) -> None:
        with pytest.raises(MissingCredentialError, match="set but empty"):
            prepare_authentication(
                bearer(),
                destination=TARGET_ORIGIN,
                target_origin=TARGET_ORIGIN,
                env={"ACME_TOKEN": value},
            )

    def test_resolution_error_does_not_contain_a_value(self) -> None:
        with pytest.raises(MissingCredentialError) as excinfo:
            prepare_authentication(
                bearer(),
                destination=TARGET_ORIGIN,
                target_origin=TARGET_ORIGIN,
                env={"ACME_TOKEN": ""},
            )

        assert TOKEN not in str(excinfo.value)
        assert "ACME_TOKEN" in excinfo.value.message


class TestHeaderStripping:
    @pytest.mark.parametrize(
        "name", ["Authorization", "authorization", "Cookie", "X-API-Key", "Proxy-Authorization"]
    )
    def test_credential_headers_are_removed(self, name: str) -> None:
        stripped = strip_credential_headers({name: TOKEN, "Accept": "application/json"})

        assert name not in stripped
        assert stripped == {"Accept": "application/json"}

    def test_a_configured_api_key_header_is_also_removed(self) -> None:
        profile = AuthProfile(
            method=AuthMethod.API_KEY,
            api_key=SecretRef(variable="ACME_KEY"),
            api_key_name="X-Custom-Secret",
        )

        stripped = strip_credential_headers(
            {"X-Custom-Secret": TOKEN, "Accept": "*/*"},
            extra_names=credential_header_names(profile),
        )

        assert "X-Custom-Secret" not in stripped

    def test_credential_header_names_per_method(self) -> None:
        assert credential_header_names(bearer()) == frozenset({"Authorization"})
        assert credential_header_names(AuthProfile()) == frozenset()
