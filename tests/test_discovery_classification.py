"""Classifying discovered endpoints against a target's configured scope.

Classification must reuse the Phase 2 scope validator, must never widen a
target's scope, and must keep out-of-scope endpoints rather than dropping them.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from aegisapi.discovery.classification import (
    classify_endpoints,
    resolve_candidate_url,
    server_matches_target,
)
from aegisapi.discovery.schemas import WarningCollector
from aegisapi.discovery.service import discover_from_specification
from aegisapi.models.discovery import ScopeClassification, WarningCode
from aegisapi.models.endpoint import (
    DeclaredSecurity,
    Endpoint,
    HttpMethod,
    SecurityPosture,
)
from aegisapi.models.target import ScopeRules, Target
from conftest import make_target
from specs import FULL_OPENAPI_30, SWAGGER_20, spec_copy, write_json, write_yaml


def endpoint(path: str, *, method: str = "get", servers: list[str] | None = None) -> Endpoint:
    """Build an endpoint for classification tests."""
    return Endpoint(
        method=HttpMethod(method.lower()),
        path=path,
        servers=servers or [],
        declared_security=DeclaredSecurity(posture=SecurityPosture.NOT_DECLARED),
        source_pointer=f"#/paths/{path}/{method.lower()}",
    )


class TestCandidateUrlResolution:
    def test_specification_server_is_used(self) -> None:
        target = make_target(base_url="https://api.acme.test/v1")

        url, server, unresolved = resolve_candidate_url(
            endpoint("/users"),
            target=target,
            specification_servers=["https://api.acme.test/v1"],
        )

        assert url == "https://api.acme.test/v1/users"
        assert server == "https://api.acme.test/v1"
        assert unresolved is None

    def test_operation_server_overrides_the_document(self) -> None:
        target = make_target()

        url, server, _ = resolve_candidate_url(
            endpoint("/users", servers=["https://other.acme.test/v2"]),
            target=target,
            specification_servers=["https://api.acme.test/v1"],
        )

        assert url == "https://other.acme.test/v2/users"
        assert server == "https://other.acme.test/v2"

    def test_no_declared_server_falls_back_to_the_target_base_url(self) -> None:
        target = make_target(base_url="https://api.acme.test/v1")

        url, server, _ = resolve_candidate_url(
            endpoint("/users"), target=target, specification_servers=[]
        )

        assert url == "https://api.acme.test/v1/users"
        assert server is None

    def test_relative_server_resolves_against_the_target_origin(self) -> None:
        target = make_target(base_url="https://api.acme.test/v1")

        url, server, _ = resolve_candidate_url(
            endpoint("/invoices"), target=target, specification_servers=["/v2"]
        )

        # Resolved against the origin, not the target's own base path, so the
        # prefix is not doubled.
        assert url == "https://api.acme.test/v2/invoices"
        assert server == "/v2"

    def test_scheme_less_server_borrows_the_target_scheme(self) -> None:
        target = make_target(base_url="https://api.acme.test/v1")

        url, _, _ = resolve_candidate_url(
            endpoint("/invoices"),
            target=target,
            specification_servers=["//api.acme.test/v1"],
        )

        assert url == "https://api.acme.test/v1/invoices"

    def test_templated_server_is_unresolved(self) -> None:
        target = make_target()

        url, server, unresolved = resolve_candidate_url(
            endpoint("/users"),
            target=target,
            specification_servers=["https://{region}.acme.test/v1"],
        )

        assert url is None
        assert server == "https://{region}.acme.test/v1"
        assert unresolved is not None
        assert "variable" in unresolved

    def test_nonsense_server_is_unresolved(self) -> None:
        target = make_target()

        url, _, unresolved = resolve_candidate_url(
            endpoint("/users"), target=target, specification_servers=["not a url"]
        )

        assert url is None
        assert unresolved is not None

    def test_root_path_joins_cleanly(self) -> None:
        target = make_target(base_url="https://api.acme.test")

        url, _, _ = resolve_candidate_url(
            endpoint("/"), target=target, specification_servers=["https://api.acme.test"]
        )

        assert url == "https://api.acme.test"


class TestClassification:
    def test_in_scope_endpoint(self) -> None:
        target = make_target(base_url="https://api.acme.test/v1")

        results = classify_endpoints(
            [endpoint("/users")],
            target=target,
            specification_servers=["https://api.acme.test/v1"],
        )

        assert results[0].classification is ScopeClassification.IN_SCOPE
        assert results[0].is_in_scope is True
        assert results[0].resolved_url == "https://api.acme.test/v1/users"

    def test_excluded_path_is_out_of_scope(self) -> None:
        target = make_target(
            base_url="https://api.acme.test/v1",
            scope=ScopeRules(include_paths=["/v1"], exclude_paths=["/v1/admin"]),
        )

        results = classify_endpoints(
            [endpoint("/admin/audit")],
            target=target,
            specification_servers=["https://api.acme.test/v1"],
        )

        assert results[0].classification is ScopeClassification.OUT_OF_SCOPE
        assert "excluded" in results[0].reason
        assert results[0].rule == "scope.exclude_paths"

    def test_different_host_is_out_of_scope(self) -> None:
        target = make_target(base_url="https://api.acme.test/v1")

        results = classify_endpoints(
            [endpoint("/users")],
            target=target,
            specification_servers=["https://production.acme.test/v1"],
        )

        assert results[0].classification is ScopeClassification.OUT_OF_SCOPE
        assert results[0].server_url == "https://production.acme.test/v1"

    def test_a_specification_path_is_not_authorisation(self) -> None:
        # The document declares an endpoint on a host the operator never
        # registered. Declaring it does not put it in scope.
        target = make_target(base_url="https://api.acme.test/v1")

        results = classify_endpoints(
            [endpoint("/users", servers=["https://attacker.test"])],
            target=target,
            specification_servers=[],
        )

        assert results[0].classification is ScopeClassification.OUT_OF_SCOPE

    def test_out_of_scope_endpoints_are_retained(self) -> None:
        target = make_target(base_url="https://api.acme.test/v1")

        results = classify_endpoints(
            [endpoint("/users"), endpoint("/users", servers=["https://other.test"])],
            target=target,
            specification_servers=["https://api.acme.test/v1"],
        )

        # Nothing is discarded: the reviewer sees what the document declares
        # beyond the engagement boundary.
        assert len(results) == 2
        assert {item.classification for item in results} == {
            ScopeClassification.IN_SCOPE,
            ScopeClassification.OUT_OF_SCOPE,
        }

    def test_templated_server_is_unresolved_and_warns(self) -> None:
        target = make_target()
        warnings = WarningCollector()

        results = classify_endpoints(
            [endpoint("/users")],
            target=target,
            specification_servers=["https://{region}.acme.test/v1"],
            warnings=warnings,
        )

        assert results[0].classification is ScopeClassification.UNRESOLVED
        assert results[0].resolved_url is None
        assert WarningCode.TEMPLATED_SERVER in {warning.code for warning in warnings.warnings}

    def test_disabled_target_puts_everything_out_of_scope(self) -> None:
        target = make_target(base_url="https://api.acme.test/v1", enabled=False)

        results = classify_endpoints(
            [endpoint("/users")],
            target=target,
            specification_servers=["https://api.acme.test/v1"],
        )

        assert results[0].classification is ScopeClassification.OUT_OF_SCOPE
        assert "disabled" in results[0].reason

    def test_empty_include_list_denies_everything(self) -> None:
        target = Target(name="acme", base_url="https://api.acme.test/v1")

        results = classify_endpoints(
            [endpoint("/users")],
            target=target,
            specification_servers=["https://api.acme.test/v1"],
        )

        assert results[0].classification is ScopeClassification.OUT_OF_SCOPE
        assert "no include patterns" in results[0].reason

    def test_templated_path_classification_is_flagged_as_advisory(self) -> None:
        target = make_target(base_url="https://api.acme.test/v1")

        results = classify_endpoints(
            [endpoint("/users/{userId}")],
            target=target,
            specification_servers=["https://api.acme.test/v1"],
        )

        # A concrete request is re-checked at request time, and the reason says so.
        assert "template" in results[0].reason

    def test_unparseable_candidate_url_is_unresolved_not_allowed(self) -> None:
        target = make_target(base_url="https://api.acme.test/v1")

        results = classify_endpoints(
            [endpoint("/users\x01bad")],
            target=target,
            specification_servers=["https://api.acme.test/v1"],
        )

        assert results[0].classification is ScopeClassification.UNRESOLVED

    def test_classification_does_not_modify_the_target(self) -> None:
        target = make_target(base_url="https://api.acme.test/v1")
        before = target.model_dump_json()

        classify_endpoints(
            [endpoint("/admin/secret", servers=["https://elsewhere.test"])],
            target=target,
            specification_servers=[],
        )

        assert target.model_dump_json() == before


class TestServerMatching:
    def test_matching_host(self) -> None:
        target = make_target(base_url="https://api.acme.test/v1")

        assert server_matches_target("https://api.acme.test/v1", target) is True

    def test_different_host(self) -> None:
        target = make_target(base_url="https://api.acme.test/v1")

        assert server_matches_target("https://production.acme.test", target) is False

    @pytest.mark.parametrize("server", ["/v2", "https://{region}.acme.test"])
    def test_relative_and_templated_servers_are_not_mismatches(self, server: str) -> None:
        target = make_target()

        assert server_matches_target(server, target) is True

    def test_malformed_server_is_a_mismatch(self) -> None:
        assert server_matches_target("::::", make_target()) is False


class TestEndToEndClassification:
    def test_openapi_document_against_a_scoped_target(self, tmp_path: Path) -> None:
        path = write_yaml(tmp_path / "spec.yaml", FULL_OPENAPI_30)
        target = make_target(
            base_url="https://api.acme.test/v1",
            scope=ScopeRules(include_paths=["/v1"], exclude_paths=["/v1/admin"]),
        )

        result = discover_from_specification(path, target=target)
        by_key = {item.endpoint.key: item for item in result.endpoints}

        assert by_key["GET /users"].classification is ScopeClassification.IN_SCOPE
        assert by_key["GET /admin/audit"].classification is (ScopeClassification.OUT_OF_SCOPE)
        counts = result.classification_counts()
        assert counts[ScopeClassification.IN_SCOPE] == 6
        assert counts[ScopeClassification.OUT_OF_SCOPE] == 1
        assert counts[ScopeClassification.UNRESOLVED] == 0

    def test_swagger_base_path_is_not_doubled(self, tmp_path: Path) -> None:
        path = write_json(tmp_path / "spec.json", SWAGGER_20)
        target = make_target(base_url="https://api.acme.test/v1")

        result = discover_from_specification(path, target=target)
        urls = {item.resolved_url for item in result.endpoints}

        assert "https://api.acme.test/v1/invoices" in urls
        assert not any(url and "/v1/v1/" in url for url in urls)

    def test_result_records_target_provenance(self, tmp_path: Path) -> None:
        path = write_yaml(tmp_path / "spec.yaml", FULL_OPENAPI_30)
        target = make_target(base_url="https://api.acme.test/v1")

        result = discover_from_specification(path, target=target)

        assert result.target_name == target.name
        assert result.target_base_url == target.base_url
        assert result.specification.source_path == str(path.resolve())
        assert len(result.specification.source_sha256) == 64

    def test_mismatched_server_puts_everything_out_of_scope(self, tmp_path: Path) -> None:
        document = spec_copy(FULL_OPENAPI_30)
        document["servers"] = [{"url": "https://production.acme.test/v1"}]
        path = write_yaml(tmp_path / "spec.yaml", document)
        target = make_target(base_url="https://staging.acme.test/v1")

        result = discover_from_specification(path, target=target)

        assert all(
            item.classification is ScopeClassification.OUT_OF_SCOPE for item in result.endpoints
        )
