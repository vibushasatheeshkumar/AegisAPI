"""HTTP limit, request, and response models, and their configuration wiring."""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from aegisapi.core.config import AegisConfig, load_config, render_sample_config
from aegisapi.core.exceptions import InvalidConfigError
from aegisapi.models.http import (
    DEFAULT_MAX_RETRIES,
    HttpLimits,
    HttpMethod,
    HttpResponse,
    RequestRecord,
)


def response(status: int = 200, **overrides: object) -> HttpResponse:
    """Build a response model for property tests."""
    payload: dict[str, object] = {
        "status_code": status,
        "request": RequestRecord(method=HttpMethod.GET, url="https://api.acme.test/v1"),
        "final_url": "https://api.acme.test/v1",
        "elapsed_seconds": 0.01,
        "scope_reason": "allowed",
    }
    payload.update(overrides)
    return HttpResponse.model_validate(payload)


class TestHttpMethod:
    @pytest.mark.parametrize("method", [HttpMethod.GET, HttpMethod.HEAD, HttpMethod.OPTIONS])
    def test_read_shaped_methods_are_retryable(self, method: HttpMethod) -> None:
        assert method.is_idempotent is True

    @pytest.mark.parametrize(
        "method",
        [HttpMethod.POST, HttpMethod.PUT, HttpMethod.PATCH, HttpMethod.DELETE],
    )
    def test_writing_methods_are_never_retried(self, method: HttpMethod) -> None:
        # PUT and DELETE are idempotent on paper, but a duplicate during an
        # engagement is the kind of surprise AegisAPI will not cause.
        assert method.is_idempotent is False

    def test_method_set_is_closed(self) -> None:
        with pytest.raises(ValueError, match="TRACE"):
            HttpMethod("TRACE")


class TestHttpLimits:
    def test_defaults_are_conservative(self) -> None:
        limits = HttpLimits()

        assert limits.connect_timeout_seconds == 5.0
        assert limits.read_timeout_seconds == 10.0
        assert limits.max_response_bytes == 1024 * 1024
        assert limits.max_concurrency == 4
        assert limits.requests_per_second == 2.0
        assert limits.max_retries == DEFAULT_MAX_RETRIES == 0
        assert limits.follow_redirects is False
        assert limits.verify_tls is True

    @pytest.mark.parametrize(
        ("field", "value"),
        [
            ("connect_timeout_seconds", 0),
            ("connect_timeout_seconds", -1),
            ("read_timeout_seconds", 0),
            ("max_response_bytes", 0),
            ("max_concurrency", 0),
            ("max_concurrency", 999),
            ("requests_per_second", 0),
            ("max_retries", -1),
            ("max_retries", 99),
            ("max_redirects", -1),
        ],
    )
    def test_out_of_range_values_are_rejected(self, field: str, value: object) -> None:
        with pytest.raises(ValidationError):
            HttpLimits.model_validate({field: value})

    def test_unknown_field_is_rejected(self) -> None:
        with pytest.raises(ValidationError):
            HttpLimits.model_validate({"verify": False})

    @pytest.mark.parametrize("agent", ["", "   ", "bad\ragent", "bad\nagent"])
    def test_user_agent_cannot_split_a_header(self, agent: str) -> None:
        with pytest.raises(ValidationError):
            HttpLimits(user_agent=agent)

    def test_body_preview_never_exceeds_the_response_limit(self) -> None:
        limits = HttpLimits(max_response_bytes=100, body_preview_bytes=4096)

        assert limits.body_preview_limit == 100


class TestHttpResponse:
    def test_status_families(self) -> None:
        assert response(204).is_success is True
        assert response(302).is_redirect is True
        assert response(404).is_success is False
        assert response(503).status_class == "5xx"

    def test_a_response_model_cannot_hold_a_credential_field(self) -> None:
        for forbidden in ("token", "secret", "credential", "password"):
            assert forbidden not in HttpResponse.model_fields
            assert forbidden not in RequestRecord.model_fields

    def test_request_record_defaults_to_unauthenticated(self) -> None:
        record = RequestRecord(method=HttpMethod.GET, url="https://api.acme.test/v1")

        assert record.authenticated is False
        assert record.auth_method is None

    def test_timestamp_is_timezone_aware(self) -> None:
        assert response().sent_at.tzinfo is not None


class TestConfigurationIntegration:
    def test_config_exposes_http_limits(self) -> None:
        assert AegisConfig().http == HttpLimits()

    def test_legacy_fields_seed_their_http_counterparts(self) -> None:
        config = AegisConfig.model_validate({"request_timeout_seconds": 42.0, "max_concurrency": 9})

        assert config.http.read_timeout_seconds == 42.0
        assert config.http.max_concurrency == 9

    def test_explicit_http_values_win_over_the_legacy_fields(self) -> None:
        config = AegisConfig.model_validate(
            {"request_timeout_seconds": 42.0, "http": {"read_timeout_seconds": 7.0}}
        )

        assert config.http.read_timeout_seconds == 7.0

    def test_http_section_loads_from_a_file(self, tmp_path: Path) -> None:
        path = tmp_path / "config.toml"
        path.write_text(
            "[http]\n"
            "connect_timeout_seconds = 2.5\n"
            "max_response_bytes = 2048\n"
            "requests_per_second = 1.0\n"
            "max_retries = 2\n"
            "verify_tls = false\n",
            encoding="utf-8",
        )

        config = load_config(path, env={})

        assert config.http.connect_timeout_seconds == 2.5
        assert config.http.max_response_bytes == 2048
        assert config.http.max_retries == 2
        assert config.http.verify_tls is False

    def test_unknown_http_key_is_rejected(self, tmp_path: Path) -> None:
        path = tmp_path / "config.toml"
        path.write_text("[http]\nverify = false\n", encoding="utf-8")

        with pytest.raises(InvalidConfigError) as excinfo:
            load_config(path, env={})

        assert "verify" in str(excinfo.value.hint)

    def test_malformed_http_section_is_rejected(self, tmp_path: Path) -> None:
        path = tmp_path / "config.toml"
        path.write_text('http = "nope"\n', encoding="utf-8")

        with pytest.raises(InvalidConfigError):
            load_config(path, env={})

    @pytest.mark.parametrize(
        ("variable", "value", "field", "expected"),
        [
            ("AEGISAPI_CONNECT_TIMEOUT", "3", "connect_timeout_seconds", 3.0),
            ("AEGISAPI_READ_TIMEOUT", "15", "read_timeout_seconds", 15.0),
            ("AEGISAPI_MAX_RESPONSE_BYTES", "4096", "max_response_bytes", 4096),
            ("AEGISAPI_REQUESTS_PER_SECOND", "0.5", "requests_per_second", 0.5),
            ("AEGISAPI_MAX_RETRIES", "2", "max_retries", 2),
            ("AEGISAPI_VERIFY_TLS", "false", "verify_tls", False),
        ],
    )
    def test_environment_overrides(
        self, variable: str, value: str, field: str, expected: object
    ) -> None:
        config = load_config(None, env={variable: value})

        assert getattr(config.http, field) == expected

    def test_invalid_environment_value_is_reported(self) -> None:
        with pytest.raises(InvalidConfigError, match="AEGISAPI_MAX_RETRIES"):
            load_config(None, env={"AEGISAPI_MAX_RETRIES": "lots"})

    def test_sample_config_documents_http_and_round_trips(self, tmp_path: Path) -> None:
        sample = render_sample_config()
        path = tmp_path / "config.toml"
        path.write_text(sample, encoding="utf-8")

        assert "[http]" in sample
        assert "verify_tls" in sample
        assert "follow_redirects" in sample
        assert load_config(path, env={}) == AegisConfig()

    def test_sample_config_declares_safe_defaults(self) -> None:
        sample = render_sample_config()

        assert "verify_tls = true" in sample
        assert "follow_redirects = false" in sample
        assert "max_retries = 0" in sample
