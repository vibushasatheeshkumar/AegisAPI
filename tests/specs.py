"""Specification fixtures used by the discovery tests.

Kept as Python literals rather than files so each test can write exactly the
document it needs into ``tmp_path``, and so a test that mutates one cannot
affect another.
"""

from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path
from typing import Any

import yaml

MINIMAL_OPENAPI_30: dict[str, Any] = {
    "openapi": "3.0.3",
    "info": {"title": "Minimal", "version": "1.0"},
    "servers": [{"url": "https://api.acme.test/v1"}],
    "paths": {
        "/ping": {
            "get": {
                "operationId": "ping",
                "responses": {"200": {"description": "OK"}},
            }
        }
    },
}

FULL_OPENAPI_30: dict[str, Any] = {
    "openapi": "3.0.3",
    "info": {
        "title": "Acme Orders API",
        "version": "2.1",
        "description": "Order management.",
    },
    "servers": [{"url": "https://api.acme.test/v1"}],
    "security": [{"bearerAuth": []}],
    "paths": {
        "/users": {
            "parameters": [
                {
                    "name": "X-Request-Id",
                    "in": "header",
                    "required": False,
                    "schema": {"type": "string"},
                }
            ],
            "get": {
                "operationId": "listUsers",
                "summary": "List users",
                "description": "Returns a page of users.",
                "tags": ["users"],
                "deprecated": False,
                "parameters": [
                    {
                        "name": "limit",
                        "in": "query",
                        "schema": {"type": "integer", "format": "int32"},
                    }
                ],
                "responses": {
                    "200": {
                        "description": "A page of users",
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "array",
                                    "items": {"$ref": "#/components/schemas/User"},
                                }
                            }
                        },
                        "headers": {"X-Total-Count": {"schema": {"type": "integer"}}},
                    },
                    "default": {"description": "Error"},
                },
            },
            "post": {
                "operationId": "createUser",
                "tags": ["users"],
                "requestBody": {
                    "required": True,
                    "description": "The user to create",
                    "content": {
                        "application/json": {"schema": {"$ref": "#/components/schemas/User"}}
                    },
                },
                "responses": {"201": {"description": "Created"}},
            },
        },
        "/users/{userId}": {
            "parameters": [
                {
                    "name": "userId",
                    "in": "path",
                    "required": True,
                    "schema": {"type": "string", "format": "uuid"},
                },
                {
                    "name": "X-Request-Id",
                    "in": "header",
                    "required": False,
                    "schema": {"type": "string"},
                },
            ],
            "get": {
                "operationId": "getUser",
                "tags": ["users"],
                "parameters": [
                    {
                        "name": "X-Request-Id",
                        "in": "header",
                        "required": True,
                        "description": "Overridden to required",
                        "schema": {"type": "string"},
                    }
                ],
                "responses": {
                    "200": {
                        "description": "One user",
                        "content": {
                            "application/json": {"schema": {"$ref": "#/components/schemas/User"}}
                        },
                    }
                },
            },
            "delete": {
                "operationId": "deleteUser",
                "tags": ["users"],
                "security": [{"bearerAuth": [], "adminKey": []}],
                "responses": {"204": {"description": "Deleted"}},
            },
        },
        "/users/{userId}/orders": {
            "get": {
                "operationId": "listUserOrders",
                "tags": ["orders"],
                "parameters": [
                    {
                        "name": "userId",
                        "in": "path",
                        "required": True,
                        "schema": {"type": "string", "format": "uuid"},
                    }
                ],
                "responses": {
                    "200": {
                        "description": "Orders",
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "array",
                                    "items": {"$ref": "#/components/schemas/Order"},
                                }
                            }
                        },
                    }
                },
            }
        },
        "/health": {
            "get": {
                "operationId": "health",
                "security": [],
                "responses": {"200": {"description": "OK"}},
            }
        },
        "/admin/audit": {
            "get": {
                "operationId": "readAudit",
                "responses": {"200": {"description": "Audit log"}},
            }
        },
    },
    "components": {
        "securitySchemes": {
            "bearerAuth": {"type": "http", "scheme": "bearer", "bearerFormat": "JWT"},
            "adminKey": {"type": "apiKey", "in": "header", "name": "X-Admin-Key"},
            "oauth": {
                "type": "oauth2",
                "flows": {
                    "authorizationCode": {
                        "authorizationUrl": "https://auth.acme.test/authorize",
                        "tokenUrl": "https://auth.acme.test/token",
                        "scopes": {"read": "Read access", "write": "Write access"},
                    }
                },
            },
        },
        "schemas": {
            "User": {
                "type": "object",
                "required": ["id", "email"],
                "properties": {
                    "id": {"type": "string", "format": "uuid"},
                    "email": {"type": "string"},
                    "manager": {"$ref": "#/components/schemas/User"},
                },
            },
            "Order": {
                "type": "object",
                "required": ["orderId"],
                "properties": {
                    "orderId": {"type": "string"},
                    "owner": {"$ref": "#/components/schemas/User"},
                    "total": {"type": "number"},
                },
            },
        },
    },
}

OPENAPI_31: dict[str, Any] = {
    "openapi": "3.1.0",
    "info": {"title": "Acme 3.1", "version": "1.0"},
    "servers": [{"url": "https://api.acme.test/v1"}],
    "paths": {
        "/items": {
            "get": {
                "operationId": "listItems",
                "parameters": [
                    {
                        "name": "cursor",
                        "in": "query",
                        "schema": {"type": ["string", "null"]},
                    }
                ],
                "responses": {
                    "200": {
                        "description": "Items",
                        "content": {
                            "application/json": {"schema": {"$ref": "#/components/schemas/Item"}}
                        },
                    }
                },
            }
        }
    },
    "components": {
        "schemas": {
            "Item": {
                "type": "object",
                "required": ["itemId"],
                "properties": {
                    "itemId": {"type": "string"},
                    "variants": {"type": "array", "items": {"type": "string"}},
                },
            }
        }
    },
}

SWAGGER_20: dict[str, Any] = {
    "swagger": "2.0",
    "info": {"title": "Legacy Acme API", "version": "1.0"},
    "host": "api.acme.test",
    "basePath": "/v1",
    "schemes": ["https"],
    "consumes": ["application/json"],
    "produces": ["application/json"],
    "securityDefinitions": {
        "apiKeyHeader": {"type": "apiKey", "in": "header", "name": "X-Api-Key"},
        "basicAuth": {"type": "basic"},
        "oauthLegacy": {
            "type": "oauth2",
            "flow": "implicit",
            "authorizationUrl": "https://auth.acme.test/authorize",
            "scopes": {"read": "Read"},
        },
    },
    "security": [{"apiKeyHeader": []}],
    "paths": {
        "/invoices": {
            "parameters": [
                {"name": "X-Tenant", "in": "header", "required": True, "type": "string"}
            ],
            "get": {
                "operationId": "listInvoices",
                "tags": ["invoices"],
                "parameters": [
                    {"name": "page", "in": "query", "type": "integer", "format": "int32"}
                ],
                "responses": {
                    "200": {
                        "description": "Invoices",
                        "schema": {
                            "type": "array",
                            "items": {"$ref": "#/definitions/Invoice"},
                        },
                        "headers": {"X-Total-Count": {"type": "integer"}},
                    }
                },
            },
            "post": {
                "operationId": "createInvoice",
                "tags": ["invoices"],
                "parameters": [
                    {
                        "name": "body",
                        "in": "body",
                        "required": True,
                        "schema": {"$ref": "#/definitions/Invoice"},
                    }
                ],
                "responses": {"201": {"description": "Created"}},
            },
        },
        "/invoices/{invoiceId}": {
            "get": {
                "operationId": "getInvoice",
                "parameters": [
                    {"name": "invoiceId", "in": "path", "required": True, "type": "string"}
                ],
                "security": [],
                "responses": {
                    "200": {
                        "description": "One invoice",
                        "schema": {"$ref": "#/definitions/Invoice"},
                    }
                },
            }
        },
        "/uploads": {
            "post": {
                "operationId": "upload",
                "consumes": ["multipart/form-data"],
                "parameters": [
                    {"name": "file", "in": "formData", "required": True, "type": "string"},
                    {"name": "note", "in": "formData", "type": "string"},
                ],
                "responses": {"200": {"description": "Uploaded"}},
            }
        },
    },
    "definitions": {
        "Invoice": {
            "type": "object",
            "required": ["invoiceId"],
            "properties": {
                "invoiceId": {"type": "string"},
                "amount": {"type": "number"},
            },
        }
    },
}


def spec_copy(document: dict[str, Any]) -> dict[str, Any]:
    """Deep copy a fixture so a test can mutate it safely."""
    return deepcopy(document)


def write_json(path: Path, document: Any) -> Path:
    """Write ``document`` as JSON and return the path."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(document, indent=2), encoding="utf-8")
    return path


def write_yaml(path: Path, document: Any) -> Path:
    """Write ``document`` as YAML and return the path."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")
    return path


def write_text(path: Path, text: str) -> Path:
    """Write raw text and return the path, for malformed-input tests."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path
