import httpx
import pytest
from pytest_httpx import HTTPXMock

from treetop_client.client import TreeTopClient
from treetop_client.models import Action, QualifiedId, Request, Resource, User


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
        resource=Resource(kind="Photo", attrs={"id": "42"}),
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
    assert resp.decision == "Allow"
    assert resp.is_allowed()


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
                },
            },
        },
        status_code=200,
    )
    client = TreeTopClient()
    resp = client.check_detailed(make_req())
    assert resp.decision == "Allow"
    assert resp.policy is not None
    assert (
        resp.policy.literal
        == 'permit (\n    principal == User::"alice",\n    action in [Action::"view", Action::"edit", Action::"delete"],\n    resource == Photo::"VacationPhoto94.jpg"\n);'
    )
    assert resp.policy.json["principal"]["entity"]["id"] == "alice"
    assert resp.is_allowed()


def test_sync_check_deny(httpx_mock: HTTPXMock):
    httpx_mock.add_response(
        method="POST",
        url="http://localhost:9999/api/v1/check",
        json={"decision": "Deny"},
        status_code=200,
    )
    client = TreeTopClient()
    resp = client.check(make_req())
    assert resp.decision == "Deny"
    assert resp.is_denied()


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
    assert resp.decision == "Deny"
