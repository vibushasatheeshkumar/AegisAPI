"""Structural relationship observation.

Every assertion here is about *structure*. None of these observations is a
security finding, and the tests check that the output says so rather than
implying otherwise.
"""

from __future__ import annotations

import pytest

from aegisapi.discovery.relationships import (
    looks_like_identifier,
    observe_relationships,
    static_prefix,
)
from aegisapi.models.discovery import RelationshipKind, RelationshipObservation
from aegisapi.models.endpoint import (
    DeclaredSecurity,
    Endpoint,
    HttpMethod,
    MediaTypeSchema,
    Parameter,
    ParameterLocation,
    ResponseSpec,
    SchemaSummary,
    SecurityPosture,
)


def endpoint(
    method: str,
    path: str,
    *,
    tags: list[str] | None = None,
    schema_name: str | None = None,
    query_params: list[str] | None = None,
) -> Endpoint:
    """Build an endpoint for relationship tests."""
    responses = []
    if schema_name is not None:
        responses = [
            ResponseSpec(
                status_code="200",
                content=[
                    MediaTypeSchema(
                        content_type="application/json",
                        value_schema=SchemaSummary(name=schema_name, type="object"),
                    )
                ],
            )
        ]
    parameters = [
        Parameter(name=name, location=ParameterLocation.QUERY) for name in (query_params or [])
    ]
    return Endpoint(
        method=HttpMethod(method.lower()),
        path=path,
        tags=tags or [],
        parameters=parameters,
        responses=responses,
        declared_security=DeclaredSecurity(posture=SecurityPosture.NOT_DECLARED),
        source_pointer=f"#/paths/{path}/{method.lower()}",
    )


def of_kind(
    observations: list[RelationshipObservation], kind: RelationshipKind
) -> list[RelationshipObservation]:
    """Filter observations by kind."""
    return [item for item in observations if item.kind is kind]


class TestHelpers:
    @pytest.mark.parametrize(
        "name",
        ["id", "userId", "user_id", "orderUUID", "apiKey", "slug", "accountNumber", "ref"],
    )
    def test_identifier_shapes_are_recognised(self, name: str) -> None:
        assert looks_like_identifier(name) is True

    @pytest.mark.parametrize("name", ["limit", "page", "sort", "q", "", "   "])
    def test_non_identifiers_are_not(self, name: str) -> None:
        assert looks_like_identifier(name) is False

    @pytest.mark.parametrize(
        ("path", "expected"),
        [
            ("/users", "/users"),
            ("/users/{userId}", "/users"),
            ("/users/{userId}/orders", "/users"),
            ("/", "/"),
            ("/{tenant}/users", "/"),
        ],
    )
    def test_static_prefix(self, path: str, expected: str) -> None:
        assert static_prefix(endpoint("get", path)) == expected


class TestSharedPrefix:
    def test_operations_under_one_root_are_grouped(self) -> None:
        endpoints = [
            endpoint("get", "/users"),
            endpoint("post", "/users"),
            endpoint("get", "/users/{userId}"),
            endpoint("get", "/invoices"),
        ]

        observations = of_kind(observe_relationships(endpoints), RelationshipKind.SHARED_PREFIX)

        assert [item.subject for item in observations] == ["/users"]
        assert len(observations[0].endpoint_keys) == 3

    def test_a_single_operation_is_not_a_relationship(self) -> None:
        observations = observe_relationships([endpoint("get", "/users")])

        assert of_kind(observations, RelationshipKind.SHARED_PREFIX) == []


class TestParentChild:
    def test_nested_resource_under_an_identified_parent(self) -> None:
        endpoints = [
            endpoint("get", "/users/{userId}"),
            endpoint("get", "/users/{userId}/orders"),
        ]

        observations = of_kind(observe_relationships(endpoints), RelationshipKind.PARENT_CHILD)

        assert len(observations) == 1
        observation = observations[0]
        assert observation.subject == "/users/{userId}"
        assert observation.detail["child_paths"] == "/users/{userId}/orders"
        assert observation.detail["identifier"] == "userId"

    def test_deeper_nesting_is_recorded(self) -> None:
        endpoints = [
            endpoint("get", "/users/{userId}"),
            endpoint("get", "/users/{userId}/orders"),
            endpoint("get", "/users/{userId}/orders/{orderId}"),
        ]

        observations = of_kind(observe_relationships(endpoints), RelationshipKind.PARENT_CHILD)
        subjects = {item.subject for item in observations}

        assert "/users/{userId}" in subjects
        assert "/users/{userId}/orders/{orderId}" not in subjects

    def test_a_collection_is_not_a_parent(self) -> None:
        # '/users' does not end in an identifier, so '/users/{userId}' is not a
        # child relationship - that is just the collection's member.
        endpoints = [endpoint("get", "/users"), endpoint("get", "/users/{userId}")]

        assert of_kind(observe_relationships(endpoints), RelationshipKind.PARENT_CHILD) == []

    def test_unrelated_paths_are_not_parent_child(self) -> None:
        endpoints = [
            endpoint("get", "/users/{userId}"),
            endpoint("get", "/invoices/{invoiceId}"),
        ]

        assert of_kind(observe_relationships(endpoints), RelationshipKind.PARENT_CHILD) == []

    def test_sibling_prefix_is_not_a_child(self) -> None:
        endpoints = [
            endpoint("get", "/users/{userId}"),
            endpoint("get", "/usersextra/{userId}/orders"),
        ]

        assert of_kind(observe_relationships(endpoints), RelationshipKind.PARENT_CHILD) == []

    def test_description_disclaims_authorisation_inheritance(self) -> None:
        endpoints = [
            endpoint("get", "/users/{userId}"),
            endpoint("get", "/users/{userId}/orders"),
        ]

        observation = of_kind(observe_relationships(endpoints), RelationshipKind.PARENT_CHILD)[0]

        assert "Structural only" in observation.description
        assert "does not imply" in observation.description


class TestSharedIdentifier:
    def test_identifier_across_operations(self) -> None:
        endpoints = [
            endpoint("get", "/users/{userId}"),
            endpoint("get", "/users/{userId}/orders"),
            endpoint("get", "/invoices"),
        ]

        observations = of_kind(observe_relationships(endpoints), RelationshipKind.SHARED_IDENTIFIER)

        assert [item.subject for item in observations] == ["userId"]
        assert len(observations[0].endpoint_keys) == 2

    def test_identifier_shaped_query_parameters_count(self) -> None:
        endpoints = [
            endpoint("get", "/orders", query_params=["customerId"]),
            endpoint("get", "/invoices", query_params=["customerId"]),
        ]

        observations = of_kind(observe_relationships(endpoints), RelationshipKind.SHARED_IDENTIFIER)

        assert [item.subject for item in observations] == ["customerId"]

    def test_non_identifier_parameters_are_ignored(self) -> None:
        endpoints = [
            endpoint("get", "/orders", query_params=["limit"]),
            endpoint("get", "/invoices", query_params=["limit"]),
        ]

        assert of_kind(observe_relationships(endpoints), RelationshipKind.SHARED_IDENTIFIER) == []

    def test_an_identifier_on_one_operation_is_not_shared(self) -> None:
        endpoints = [endpoint("get", "/users/{userId}"), endpoint("get", "/invoices")]

        assert of_kind(observe_relationships(endpoints), RelationshipKind.SHARED_IDENTIFIER) == []

    def test_description_disclaims_cross_acceptance(self) -> None:
        endpoints = [
            endpoint("get", "/users/{userId}"),
            endpoint("get", "/users/{userId}/orders"),
        ]

        observation = of_kind(observe_relationships(endpoints), RelationshipKind.SHARED_IDENTIFIER)[
            0
        ]

        assert "not evidence" in observation.description


class TestCrudSets:
    def test_full_crud_set_is_recognised(self) -> None:
        endpoints = [
            endpoint("post", "/users"),
            endpoint("get", "/users"),
            endpoint("get", "/users/{userId}"),
            endpoint("put", "/users/{userId}"),
            endpoint("delete", "/users/{userId}"),
        ]

        observations = of_kind(observe_relationships(endpoints), RelationshipKind.CRUD_SET)

        assert len(observations) == 1
        operations = observations[0].detail["operations"]
        assert "create" in operations
        assert "read" in operations
        assert "update" in operations
        assert "delete" in operations

    def test_patch_counts_as_update(self) -> None:
        endpoints = [endpoint("get", "/users/{id}"), endpoint("patch", "/users/{id}")]

        observations = of_kind(observe_relationships(endpoints), RelationshipKind.CRUD_SET)

        assert "update" in observations[0].detail["operations"]

    def test_read_only_resource_is_not_a_crud_set(self) -> None:
        endpoints = [endpoint("get", "/users"), endpoint("get", "/users/{userId}")]

        assert of_kind(observe_relationships(endpoints), RelationshipKind.CRUD_SET) == []

    def test_a_lone_write_is_not_a_crud_set(self) -> None:
        endpoints = [endpoint("post", "/users"), endpoint("post", "/invoices")]

        assert of_kind(observe_relationships(endpoints), RelationshipKind.CRUD_SET) == []


class TestSharedTagsAndSchemas:
    def test_tags_group_operations(self) -> None:
        endpoints = [
            endpoint("get", "/a", tags=["billing"]),
            endpoint("get", "/b", tags=["billing"]),
            endpoint("get", "/c", tags=["other"]),
        ]

        observations = of_kind(observe_relationships(endpoints), RelationshipKind.SHARED_TAG)

        assert [item.subject for item in observations] == ["billing"]

    def test_schemas_group_operations(self) -> None:
        endpoints = [
            endpoint("get", "/users", schema_name="User"),
            endpoint("post", "/users", schema_name="User"),
            endpoint("get", "/invoices", schema_name="Invoice"),
        ]

        observations = of_kind(observe_relationships(endpoints), RelationshipKind.SHARED_SCHEMA)

        assert [item.subject for item in observations] == ["User"]
        assert len(observations[0].endpoint_keys) == 2


class TestOutputProperties:
    def test_no_endpoints_produces_no_observations(self) -> None:
        assert observe_relationships([]) == []

    def test_observations_are_stable_across_runs(self) -> None:
        endpoints = [
            endpoint("get", "/users/{userId}", tags=["users"], schema_name="User"),
            endpoint("post", "/users", tags=["users"], schema_name="User"),
            endpoint("delete", "/users/{userId}", tags=["users"]),
            endpoint("get", "/users/{userId}/orders", tags=["orders"], schema_name="Order"),
        ]

        first = observe_relationships(endpoints)
        second = observe_relationships(list(reversed(endpoints)))

        assert [(item.kind, item.subject) for item in first] == [
            (item.kind, item.subject) for item in second
        ]

    def test_endpoint_keys_are_sorted(self) -> None:
        endpoints = [endpoint("post", "/users"), endpoint("get", "/users")]

        observation = of_kind(observe_relationships(endpoints), RelationshipKind.SHARED_PREFIX)[0]

        assert observation.endpoint_keys == sorted(observation.endpoint_keys)

    def test_no_observation_claims_a_vulnerability(self) -> None:
        endpoints = [
            endpoint("get", "/users/{userId}"),
            endpoint("get", "/users/{userId}/orders"),
            endpoint("delete", "/users/{userId}"),
            endpoint("post", "/users", schema_name="User"),
            endpoint("get", "/users", schema_name="User", tags=["users"]),
            endpoint("get", "/users/{userId}/audit", tags=["users"]),
        ]

        forbidden = ("vulnerab", "exploit", "insecure", "attack", "bola", "idor", "finding")
        for observation in observe_relationships(endpoints):
            lowered = observation.description.lower()
            for word in forbidden:
                assert word not in lowered, observation.description
