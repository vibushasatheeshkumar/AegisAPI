"""Credential references and the opaque Secret wrapper.

These tests are the guarantee behind the claim that AegisAPI cannot leak a
credential through configuration, logging, or serialisation.
"""

from __future__ import annotations

import copy
import json
import logging
import pickle

import pytest
from pydantic import BaseModel, ValidationError

from aegisapi.core.exceptions import MissingCredentialError
from aegisapi.core.logging import configure_logging, get_logger
from aegisapi.models.secrets import SecretProvider, SecretRef
from aegisapi.utils.redaction import REDACTED
from aegisapi.utils.secrets import Secret
from test_logging import capture_console

VALUE = "eyJhbGciOiJIUzI1NiJ9.super-secret-token-value"


class TestSecret:
    def test_reveal_returns_the_value(self) -> None:
        assert Secret(VALUE).reveal() == VALUE

    def test_repr_does_not_contain_the_value(self) -> None:
        rendered = repr(Secret(VALUE))

        assert VALUE not in rendered
        assert REDACTED in rendered

    def test_str_does_not_contain_the_value(self) -> None:
        assert str(Secret(VALUE)) == REDACTED

    def test_f_string_interpolation_does_not_leak(self) -> None:
        secret = Secret(VALUE)

        assert VALUE not in f"token={secret}"
        assert VALUE not in f"token={secret!s}"
        assert VALUE not in f"token={secret!r}"
        assert VALUE not in f"{secret:>60}"

    def test_percent_formatting_does_not_leak(self) -> None:
        # Percent formatting is exactly what this test exercises.
        assert VALUE not in "token=%s" % (Secret(VALUE),)  # noqa: UP031

    def test_json_serialisation_is_refused(self) -> None:
        with pytest.raises(TypeError):
            json.dumps({"token": Secret(VALUE)})

    def test_pickling_is_refused(self) -> None:
        with pytest.raises(TypeError, match="must not be pickled"):
            pickle.dumps(Secret(VALUE))

    def test_copying_is_refused(self) -> None:
        with pytest.raises(TypeError, match="must not be pickled"):
            copy.deepcopy(Secret(VALUE))

    def test_is_unhashable_so_it_cannot_become_a_dict_key(self) -> None:
        with pytest.raises(TypeError):
            hash(Secret(VALUE))

    def test_equality_compares_values_only_against_other_secrets(self) -> None:
        assert Secret(VALUE) == Secret(VALUE)
        assert Secret(VALUE) != Secret("other")
        assert Secret(VALUE) != VALUE

    def test_length_is_available_without_revealing(self) -> None:
        assert Secret(VALUE).length == len(VALUE)

    def test_truthiness_reflects_emptiness(self) -> None:
        assert bool(Secret(VALUE)) is True
        assert bool(Secret("")) is False

    def test_non_string_is_rejected(self) -> None:
        with pytest.raises(TypeError, match="expects a string"):
            Secret(12345)  # type: ignore[arg-type]

    def test_cannot_be_used_as_a_pydantic_field(self) -> None:
        # A Secret on a model would be serialisable, which is the one thing
        # this type exists to prevent.
        with pytest.raises(TypeError, match="SecretRef"):

            class Leaky(BaseModel):
                token: Secret

    def test_logging_a_secret_does_not_leak_it(self) -> None:
        console, buffer = capture_console()
        configure_logging("INFO", console=console)

        get_logger("test").info("using token %s", Secret(VALUE))

        output = buffer.getvalue()
        assert VALUE not in output
        assert REDACTED in output

    def test_logging_a_revealed_secret_is_still_redacted_by_the_filter(self) -> None:
        console, buffer = capture_console()
        configure_logging("INFO", console=console)

        get_logger("test").info("Authorization: Bearer %s", Secret(VALUE).reveal())

        assert VALUE not in buffer.getvalue()

    def test_exception_messages_do_not_leak_a_secret(self) -> None:
        secret = Secret(VALUE)

        error = RuntimeError(f"request failed with {secret}")

        assert VALUE not in str(error)

    def test_logging_level_name_sanity(self) -> None:
        # Guards the helper import above from silently changing behaviour.
        assert logging.getLevelName(logging.INFO) == "INFO"


class TestSecretRef:
    @pytest.mark.parametrize("variable", ["ACME_TOKEN", "_private", "A", "TOKEN_2", "a_b_c_123"])
    def test_valid_variable_names(self, variable: str) -> None:
        assert SecretRef(variable=variable).variable == variable

    def test_surrounding_whitespace_is_trimmed(self) -> None:
        assert SecretRef(variable="  ACME_TOKEN  ").variable == "ACME_TOKEN"

    @pytest.mark.parametrize(
        "variable",
        [
            "",
            "   ",
            "9LEADING_DIGIT",
            "WITH-DASH",
            "WITH.DOT",
            "WITH SPACE",
            "WITH/SLASH",
            "WITH=EQUALS",
            "eyJhbGciOiJIUzI1NiJ9.abc",
            "A" * 200,
        ],
    )
    def test_invalid_variable_names_are_rejected(self, variable: str) -> None:
        # The pattern doubles as a guard against pasting a credential here:
        # real tokens contain characters it refuses.
        with pytest.raises(ValidationError):
            SecretRef(variable=variable)

    def test_default_provider_is_the_environment(self) -> None:
        assert SecretRef(variable="ACME_TOKEN").provider is SecretProvider.ENV

    def test_unknown_provider_is_rejected(self) -> None:
        with pytest.raises(ValidationError):
            SecretRef(variable="ACME_TOKEN", provider="vault")

    def test_extra_fields_are_rejected(self) -> None:
        # In particular, a field that would hold the credential itself.
        with pytest.raises(ValidationError):
            SecretRef(variable="ACME_TOKEN", value=VALUE)

    def test_reference_is_frozen(self) -> None:
        ref = SecretRef(variable="ACME_TOKEN")

        with pytest.raises(ValidationError):
            ref.variable = "OTHER"

    def test_describe_shows_the_name_not_a_value(self) -> None:
        assert SecretRef(variable="ACME_TOKEN").describe() == "env:ACME_TOKEN"

    def test_serialised_reference_contains_only_the_name(self) -> None:
        dumped = SecretRef(variable="ACME_TOKEN").model_dump(mode="json")

        assert dumped == {"provider": "env", "variable": "ACME_TOKEN"}
        assert VALUE not in json.dumps(dumped)

    def test_is_available_reflects_the_environment(self) -> None:
        ref = SecretRef(variable="ACME_TOKEN")

        assert ref.is_available({"ACME_TOKEN": VALUE}) is True
        assert ref.is_available({}) is False
        assert ref.is_available({"ACME_TOKEN": ""}) is False
        assert ref.is_available({"ACME_TOKEN": "   "}) is False

    def test_resolve_returns_an_opaque_secret(self) -> None:
        secret = SecretRef(variable="ACME_TOKEN").resolve({"ACME_TOKEN": VALUE})

        assert isinstance(secret, Secret)
        assert secret.reveal() == VALUE

    def test_resolve_trims_surrounding_whitespace(self) -> None:
        secret = SecretRef(variable="ACME_TOKEN").resolve({"ACME_TOKEN": f"  {VALUE}\n"})

        assert secret.reveal() == VALUE

    def test_resolve_raises_when_unset(self) -> None:
        with pytest.raises(MissingCredentialError, match="is not set"):
            SecretRef(variable="ACME_TOKEN").resolve({})

    @pytest.mark.parametrize("value", ["", "   ", "\n"])
    def test_resolve_raises_when_empty(self, value: str) -> None:
        # An empty credential must never be substituted for a real one.
        with pytest.raises(MissingCredentialError, match="set but empty"):
            SecretRef(variable="ACME_TOKEN").resolve({"ACME_TOKEN": value})

    def test_resolution_error_names_the_variable_not_a_value(self) -> None:
        with pytest.raises(MissingCredentialError) as excinfo:
            SecretRef(variable="ACME_TOKEN").resolve({})

        assert "ACME_TOKEN" in excinfo.value.message
        assert VALUE not in str(excinfo.value)
        assert excinfo.value.exit_code == 7

    def test_resolve_reads_the_process_environment_by_default(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("ACME_TOKEN", VALUE)

        assert SecretRef(variable="ACME_TOKEN").resolve().reveal() == VALUE
