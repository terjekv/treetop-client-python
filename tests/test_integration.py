import subprocess
import time

import httpx
import pytest

from treetop_client.client import TreeTopClient
from treetop_client.models import Action, Request, Resource, User

pytestmark = pytest.mark.integration

PORT = 10101
NAMESPACE = ["DNS"]


@pytest.fixture(scope="session")
def docker_compose_up_down(tmp_path_factory: pytest.TempPathFactory):
    """
    Spin up the server via docker-compose.integration.yml before tests,
    tear it down afterwards.
    """
    # bring up
    subprocess.check_call(
        ["docker-compose", "-f", "docker-compose.integration.yml", "up", "-d"]
    )
    # wait for the server to be ready
    for _ in range(10):
        try:
            resp = httpx.get(f"http://localhost:{PORT}/api/v1/status", timeout=1.0)
            if resp.status_code == 200:
                size = resp.json().get("policies").get("size")
                print(f"policy size: {size}")
                if size != 0:
                    break
                else:
                    time.sleep(1)
        except Exception:
            time.sleep(1)
    else:
        pytest.skip("policy-server did not start in time")
    yield
    # tear down
    subprocess.call(
        ["docker", "compose", "-f", "docker-compose.integration.yml", "down"]
    )


@pytest.mark.parametrize(
    "principal, groups, action, expected",
    [
        (
            "alice",
            ["admins", "users"],
            "create_host",
            True,
        ),
        (
            "bob",
            ["users"],
            "create_host",
            False,
        ),
        (
            "alice",
            ["admins", "users"],
            "view_host",
            True,
        ),
        (
            "bob",
            ["users"],
            "view_host",
            True,
        ),
        (
            "alice",
            ["admins", "users"],
            "delete_host",
            True,
        ),
        (
            "bob",
            ["users"],
            "delete_host",
            False,
        ),
    ],
)
def test_live_check_allows_user(
    principal: str,
    groups: list[str],
    action: str,
    expected: bool,
    docker_compose_up_down: None,
):
    client = TreeTopClient(base_url=f"http://localhost:{PORT}")

    req = Request(
        principal=User.new(principal, NAMESPACE, groups),
        action=Action.new(action, NAMESPACE),
        resource=Resource.new(
            kind="Host", attrs={"name": "host.example.com", "ip": "10.0.0.1"}
        ),
    )
    resp = client.check(req)
    assert resp.decision == ("Allow" if expected else "Deny")


@pytest.mark.parametrize(
    "resource_kind, attrs",
    [
        ("Generic", {"kind": "Any", "id": "12345"}),
        ("Host", {"name": "host.example.com", "ip": "10.0.0.1"}),
    ],
)
def test_live_check_allows_super_bare(
    resource_kind: str, attrs: dict[str, str], docker_compose_up_down: None
):
    client = TreeTopClient(base_url=f"http://localhost:{PORT}")

    req = Request(
        principal=User.new("super"),
        action=Action.new("any"),
        resource=Resource.new(resource_kind, attrs),
    )
    resp = client.check(req)
    assert resp.decision == "Allow"


def test_live_check_allow_detailed(
    docker_compose_up_down: None,
):
    client = TreeTopClient(base_url=f"http://localhost:{PORT}")

    req = Request(
        principal=User.new("alice", NAMESPACE, ["admins"]),
        action=Action.new("view_host", NAMESPACE),
        resource=Resource.new(
            kind="Host", attrs={"name": "host.example.com", "ip": "10.0.0.1"}
        ),
    )
    resp = client.check_detailed(req)
    assert resp.decision == "Allow"
    assert resp.policy is not None
    assert (
        resp.policy_literal()
        == """@id("DNS.admins_policy")
permit (
    principal in DNS::Group::"admins",
    action in
        [DNS::Action::"create_host",
         DNS::Action::"delete_host",
         DNS::Action::"view_host",
         DNS::Action::"edit_host"],
    resource is Host
);"""
    )
