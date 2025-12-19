from datetime import datetime

import httpx
import pytest
from pytest_httpx import HTTPXMock

from treetop_client.client import TreeTopClient
from treetop_client.models import (
    Action,
    Decision,
    QualifiedId,
    Request,
    Resource,
    ResourceAttribute,
    User,
)


@pytest.fixture(autouse=True)
def client_cleanup():
    # ensure singleton reset between tests
    TreeTopClient().close()
    yield
    TreeTopClient().close()


def make_req():
    return Request(
        principal=User(id=QualifiedId(id="alice"), groups=[]),
        action=Action(id=QualifiedId(id="view")),
        resource=Resource(
            kind="Photo",
            id="42",
            attrs={
                "id": ResourceAttribute.new("42"),
            },
        ),
    )


def test_sync_check(httpx_mock: HTTPXMock):
    httpx_mock.add_response(
        method="POST",
        url="http://localhost:9999/api/v1/check",
        json={"decision": "Allow"},
        status_code=200,
    )
    client = TreeTopClient()
    resp = client.check(make_req())
    assert resp.is_allowed()
    assert resp.decision == Decision.ALLOW


def test_sync_check_detailed(httpx_mock: HTTPXMock):
    httpx_mock.add_response(
        method="POST",
        url="http://localhost:9999/api/v1/check_detailed",
        json={
            "decision": {
                "Allow": {
                    "policy": {
                        "literal": 'permit (\n    principal == User::"alice",\n    action in [Action::"view", Action::"edit", Action::"delete"],\n    resource == Photo::"VacationPhoto94.jpg"\n);',
                        "json": {
                            "action": {
                                "entities": [
                                    {"id": "view", "type": "Action"},
                                    {"id": "edit", "type": "Action"},
                                    {"id": "delete", "type": "Action"},
                                ],
                                "op": "in",
                            },
                            "conditions": [],
                            "effect": "permit",
                            "principal": {
                                "entity": {"id": "alice", "type": "User"},
                                "op": "==",
                            },
                            "resource": {
                                "entity": {
                                    "id": "VacationPhoto94.jpg",
                                    "type": "Photo",
                                },
                                "op": "==",
                            },
                        },
                    },
                    "version": {
                        "hash": "c82d116854d77bf689c3d15e167764876dffe869c970bc08ab7c5dacd7726219",
                        "loaded_at": "2025-12-16T15:25:55.384783000Z",
                    },
                },
            },
        },
        status_code=200,
    )
    client = TreeTopClient()
    resp = client.check_detailed(make_req())
    assert resp.is_allowed()
    assert resp.decision == Decision.ALLOW
    assert resp.policy is not None
    assert (
        resp.policy.literal
        == 'permit (\n    principal == User::"alice",\n    action in [Action::"view", Action::"edit", Action::"delete"],\n    resource == Photo::"VacationPhoto94.jpg"\n);'
    )
    assert resp.policy.json["principal"]["entity"]["id"] == "alice"
    assert (
        resp.version_hash()
        == "c82d116854d77bf689c3d15e167764876dffe869c970bc08ab7c5dacd7726219"
    )
    loaded_at = resp.version_loaded_at()
    assert loaded_at is not None
    assert isinstance(loaded_at, datetime)
    assert loaded_at.isoformat() == "2025-12-16T15:25:55.384783+00:00"


def test_sync_check_deny(httpx_mock: HTTPXMock):
    httpx_mock.add_response(
        method="POST",
        url="http://localhost:9999/api/v1/check",
        json={"decision": "Deny"},
        status_code=200,
    )
    client = TreeTopClient()
    resp = client.check(make_req())
    assert resp.is_denied()
    assert resp.decision == Decision.DENY


def test_sync_check_error(httpx_mock: HTTPXMock):
    httpx_mock.add_response(
        method="POST",
        url="http://localhost:9999/api/v1/check",
        json={"error": "Invalid request"},
        status_code=400,
    )
    client = TreeTopClient()
    with pytest.raises(httpx.HTTPStatusError):
        client.check(make_req())


def test_async_check(httpx_mock: HTTPXMock):
    httpx_mock.add_response(
        method="POST",
        url="http://localhost:9999/api/v1/check",
        json={"decision": "Deny"},
        status_code=200,
    )
    client = TreeTopClient()
    import asyncio

    # Create an event loop if not already running
    asyncio.set_event_loop(asyncio.new_event_loop())
    resp = asyncio.get_event_loop().run_until_complete(client.acheck(make_req()))
    assert resp.is_denied()
    assert resp.decision == Decision.DENY


def test_sync_check_detailed_legacy_format(httpx_mock: HTTPXMock):
    """Test backward compatibility with older API format without version field."""
    httpx_mock.add_response(
        method="POST",
        url="http://localhost:9999/api/v1/check_detailed",
        json={
            "decision": {
                "Allow": {
                    "policy": {
                        "literal": 'permit (\n    principal == User::"alice",\n    action in [Action::"view"],\n    resource == Photo::"test.jpg"\n);',
                        "json": {
                            "effect": "permit",
                            "principal": {
                                "entity": {"id": "alice", "type": "User"},
                                "op": "==",
                            },
                            "action": {
                                "entities": [{"id": "view", "type": "Action"}],
                                "op": "in",
                            },
                            "resource": {
                                "entity": {"id": "test.jpg", "type": "Photo"},
                                "op": "==",
                            },
                            "conditions": [],
                        },
                    },
                    # No version field in legacy format
                },
            },
        },
        status_code=200,
    )
    client = TreeTopClient()
    resp = client.check_detailed(make_req())
    assert resp.is_allowed()
    assert resp.decision == Decision.ALLOW
    assert resp.policy is not None
    assert resp.version_hash() is None  # Should be None for legacy format
    assert resp.version_loaded_at() is None


def test_sync_check_deny_legacy_format(httpx_mock: HTTPXMock):
    """Test backward compatibility with simple Deny format."""
    httpx_mock.add_response(
        method="POST",
        url="http://localhost:9999/api/v1/check_detailed",
        json={"decision": "Deny"},
        status_code=200,
    )
    client = TreeTopClient()
    resp = client.check_detailed(make_req())
    assert resp.is_denied()
    assert resp.decision == Decision.DENY
    assert resp.policy is None
    assert resp.version_hash() is None  # Should be None for legacy format
    assert resp.version_loaded_at() is None


def test_sync_check_deny_new_format(httpx_mock: HTTPXMock):
    """Test new Deny format with version field."""
    httpx_mock.add_response(
        method="POST",
        url="http://localhost:9999/api/v1/check_detailed",
        json={
            "decision": {
                "Deny": {
                    "version": {
                        "hash": "abc123",
                        "loaded_at": "2025-12-19T10:00:00.000000000Z",
                    }
                }
            }
        },
        status_code=200,
    )
    client = TreeTopClient()
    resp = client.check_detailed(make_req())
    assert resp.is_denied()
    assert resp.decision == Decision.DENY
    assert resp.policy is None
    assert resp.version_hash() == "abc123"
    loaded_at = resp.version_loaded_at()
    assert loaded_at is not None
    assert isinstance(loaded_at, datetime)
    assert loaded_at.isoformat() == "2025-12-19T10:00:00+00:00"
    assert loaded_at.isoformat() == "2025-12-19T10:00:00+00:00"
