import subprocess
import time

import httpx
import pytest

from treetop_client.client import TreeTopClient
from treetop_client.models import (Action, Decision, Request, Resource,
                                   ResourceAttribute, ResourceAttributeType,
                                   User)

pytestmark = pytest.mark.integration

PORT = 10101
NAMESPACE = ["DNS"]


def make_host_resource(
    host_id: str, ip: str = "10.0.0.1"
) -> Resource:
    """Create a Host resource with name and IP attributes."""
    return Resource.new(
        kind="Host",
        id=host_id,
        attrs={
            "name": ResourceAttribute.new(host_id),
            "ip": ResourceAttribute.new(ip, type=ResourceAttributeType.IP),
        },
    )


def make_request(
    principal: str,
    action: str,
    host_id: str,
    groups: list[str] | None = None,
    request_id: str | None = None,
    ip: str = "10.0.0.1",
) -> Request:
    """Create an authorization request for a Host resource."""
    return Request(
        principal=User.new(principal, NAMESPACE, groups),
        action=Action.new(action, NAMESPACE),
        resource=make_host_resource(host_id, ip),
        id=request_id,
    )


@pytest.fixture
def client(docker_compose_up_down) -> TreeTopClient: # type: ignore[reportMissingParameterType]
    """Create a TreeTopClient connected to the test server."""
    return TreeTopClient(base_url=f"http://localhost:{PORT}")


@pytest.fixture(scope="session")
def docker_compose_up_down(tmp_path_factory: pytest.TempPathFactory):
    """
    Spin up the server via docker-compose.integration.yml before tests,
    tear it down afterwards.
    """
    # bring up
    subprocess.check_call(
        ["docker", "compose", "-f", "docker-compose.integration.yml", "up", "-d"]
    )
    # wait for the server to be ready
    for _ in range(10):
        try:
            resp = httpx.get(f"http://localhost:{PORT}/api/v1/policies", timeout=1.0)
            if resp.status_code == 200:
                entries = resp.json().get("policies", {}).get("entries", 0)
                if entries:
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
    client: TreeTopClient,
):
    req = make_request(principal, action, "host.example.com", groups)
    resp = client.check(req)
    if expected:
        assert resp.is_allowed()
        assert resp.decision == Decision.ALLOW
    else:
        assert resp.is_denied()
        assert resp.decision == Decision.DENY


@pytest.mark.parametrize(
    "resource_kind, id, attrs",
    [
        ("Generic", "12345", {"kind": ResourceAttribute.new("Any")}),
        (
            "Host",
            "host.example.com",
            {
                "name": ResourceAttribute.new("host.example.com"),
                "ip": ResourceAttribute.new("10.0.0.1", type=ResourceAttributeType.IP),
            },
        ),
    ],
)
def test_live_check_allows_super_bare(
    resource_kind: str,
    id: str,
    attrs: dict[str, ResourceAttribute],
    client: TreeTopClient,
):
    req = Request(
        principal=User.new("super"),
        action=Action.new("any"),
        resource=Resource.new(resource_kind, id, attrs),
    )
    resp = client.check(req)
    assert resp.is_allowed()
    assert resp.decision == Decision.ALLOW


def test_live_check_allow_detailed(
    client: TreeTopClient,
):
    req = make_request("alice", "view_host", "host.example.com", ["admins"])
    resp = client.check_detailed(req)
    assert resp.is_allowed()
    assert resp.decision == Decision.ALLOW
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
    # Verify version information is present
    assert resp.version_hash() is not None
    assert resp.version_loaded_at() is not None


# Batch authorization tests
def test_live_batch_authorize_multiple_requests(
    client: TreeTopClient,
):
    """Test batch authorize with multiple requests."""
    requests = [
        make_request("alice", "create_host", "host1.example.com", ["admins"], "req-alice-create", "10.0.0.1"),
        make_request("bob", "create_host", "host2.example.com", ["users"], "req-bob-create", "10.0.0.2"),
        make_request("bob", "view_host", "host3.example.com", ["users"], "req-bob-view", "10.0.0.3"),
    ]

    response = client.authorize(requests)

    # Verify counts
    assert response.successful == 3
    assert response.failed == 0
    assert len(response) == 3

    # Verify results by index
    assert response[0].is_success()
    assert response[0].is_allowed()  # alice can create_host (admin)

    assert response[1].is_success()
    assert response[1].is_denied()  # bob cannot create_host (not admin)

    assert response[2].is_success()
    assert response[2].is_allowed()  # bob can view_host (user)


def test_live_batch_authorize_lookup_by_id(
    client: TreeTopClient,
):
    """Test batch authorize with lookup by request ID."""
    requests = [
        make_request("alice", "delete_host", "dangerous.example.com", ["admins"], "admin-delete", "10.0.0.99"),
        make_request("bob", "delete_host", "restricted.example.com", ["users"], "user-delete", "10.0.0.88"),
    ]

    response = client.authorize(requests)

    # Lookup by ID
    admin_result = response.get_by_id("admin-delete")
    assert admin_result is not None
    assert admin_result.is_allowed()  # alice can delete_host (admin)

    user_result = response.get_by_id("user-delete")
    assert user_result is not None
    assert user_result.is_denied()  # bob cannot delete_host (user)

    # Verify non-existent ID returns None
    nonexistent = response.get_by_id("nonexistent-id")
    assert nonexistent is None


def test_live_batch_authorize_detailed_multiple_requests(
    client: TreeTopClient,
):
    """Test batch authorize_detailed with multiple requests."""
    requests = [
        make_request("alice", "create_host", "host-a.example.com", ["admins"], "alice-create-detailed", "10.0.0.1"),
        make_request("bob", "view_host", "host-b.example.com", ["users"], "bob-view-detailed", "10.0.0.2"),
    ]

    response = client.authorize_detailed(requests)

    # Verify batch metadata
    assert response.successful == 2
    assert response.failed == 0

    # Verify detailed results by index
    alice_result = response[0]
    assert alice_result.is_allowed()
    alice_policy = alice_result.policy_literal()
    assert alice_policy is not None
    assert "admins_policy" in alice_policy
    assert alice_result.version_hash() is not None

    bob_result = response[1]
    assert bob_result.is_allowed()
    bob_policy = bob_result.policy_literal()
    assert bob_policy is not None
    assert "users_policy" in bob_policy
    assert bob_result.version_hash() is not None


def test_live_batch_authorize_detailed_lookup_by_id(
    client: TreeTopClient,
):
    """Test batch authorize_detailed with lookup by ID."""
    requests = [
        Request(
            principal=User.new("super"),
            action=Action.new("any"),
            resource=make_host_resource("super-host.example.com", "10.0.0.100"),
            id="super-admin-any",
        ),
        make_request("bob", "create_host", "bob-host.example.com", ["users"], "bob-create-detailed", "10.0.0.50"),
    ]

    response = client.authorize_detailed(requests)

    # Lookup by ID
    super_result = response.get_by_id("super-admin-any")
    assert super_result is not None
    assert super_result.is_allowed()  # super can do anything
    assert super_result.policy_literal() is not None
    assert super_result.version_hash() is not None
    assert super_result.version_loaded_at() is not None

    bob_result = response.get_by_id("bob-create-detailed")
    assert bob_result is not None
    assert bob_result.is_denied()  # bob cannot create_host (user)
    assert bob_result.policy_literal() is None  # Deny has no policy


def test_live_batch_authorize_iteration(
    client: TreeTopClient,
):
    """Test iterating over batch results and filtering."""
    requests = [
        make_request("alice", "create_host", "host-iter-1.example.com", ["admins"], "iter-1", "10.1.0.1"),
        make_request("bob", "create_host", "host-iter-2.example.com", ["users"], "iter-2", "10.1.0.2"),
        make_request("alice", "view_host", "host-iter-3.example.com", ["admins"], "iter-3", "10.1.0.3"),
    ]

    response = client.authorize(requests)

    # Test iteration
    decisions = [result.get_decision() for result in response]
    assert len(decisions) == 3
    assert decisions[0] == Decision.ALLOW  # alice create_host
    assert decisions[1] == Decision.DENY   # bob create_host
    assert decisions[2] == Decision.ALLOW  # alice view_host

    # Test filtering authorized requests
    allowed_count = sum(1 for result in response if result.is_allowed())
    assert allowed_count == 2

    # Test filtering denied requests
    denied_count = sum(1 for result in response if result.is_denied())
    assert denied_count == 1


def test_live_batch_large_query_ordering_and_performance(
    client: TreeTopClient,
) -> None:
    """Test batch authorize with 50+ requests - verify ordering and performance.
    
    Performance Notes:
    - Tests the server's ability to handle large batches efficiently
    - Verifies that results maintain the same order as requests (critical!)
    - Measures end-to-end response time for bulk operations
    - Useful for benchmarking and understanding scalability limits
    """
    import time as time_module

    # Create 60 requests with various combinations
    # Alternating between admins/users, and different actions
    num_requests = 60
    requests: list[tuple[Request, bool]] = []
    
    for i in range(num_requests):
        # Alternate: admins get all operations, users get view/edit only
        if i % 3 == 0:
            principal = "alice"
            groups = ["admins"]
            action = "create_host"
            expected_allowed = True
        elif i % 3 == 1:
            principal = "bob"
            groups = ["users"]
            action = "create_host"
            expected_allowed = False  # users can't create
        else:
            principal = "bob"
            groups = ["users"]
            action = "view_host"
            expected_allowed = True  # users can view
        
        req = make_request(
            principal=principal,
            action=action,
            host_id=f"host-stress-{i}.example.com",
            groups=groups,
            request_id=f"stress-{i}",
            ip=f"10.2.{i // 256}.{i % 256}",  # Generate diverse IPs
        )
        requests.append((req, expected_allowed))
    
    # Time the batch operation
    start_time = time_module.time()
    response = client.authorize([req for req, _ in requests])
    elapsed_time = time_module.time() - start_time
    
    # Verify response counts
    assert len(response) == num_requests
    assert response.successful == num_requests
    assert response.failed == 0
    
    # Verify all results came back in the correct order
    for i, (_, expected_allowed) in enumerate(requests):
        result = response[i]
        assert result.index == i, f"Result {i} has wrong index: {result.index}"
        assert result.id == f"stress-{i}", f"Result {i} has wrong ID: {result.id}"
        assert result.is_success(), f"Result {i} should be successful"
        
        if expected_allowed:
            assert result.is_allowed(), f"Result {i} should be allowed (alice or bob viewing)"
        else:
            assert result.is_denied(), f"Result {i} should be denied (bob creating)"
    
    # Verify lookup by ID works for random samples
    stress_0_result = response.get_by_id("stress-0")
    assert stress_0_result is not None
    assert stress_0_result.is_allowed() is True
    
    stress_1_result = response.get_by_id("stress-1")
    assert stress_1_result is not None
    assert stress_1_result.is_denied() is True
    
    stress_59_result = response.get_by_id("stress-59")
    assert stress_59_result is not None
    assert stress_59_result.is_allowed() is True
    
    # Performance reporting
    requests_per_second = num_requests / elapsed_time
    print(f"\n==== Batch Authorization Performance ====")
    print(f"Total requests  : {num_requests}")
    print(f"Total time      : {elapsed_time:.3f} seconds")
    print(f"Throughput      : {requests_per_second:.1f} requests/second")
    print(f"Per-request time: {(elapsed_time / num_requests) * 1000:.1f} ms")
    print(f"=========================================\n")
    
    # Performance expectations (may vary by system)
    # Should handle 60 requests in < 0.5 seconds realistically
    assert elapsed_time < 0.5, f"Batch took too long: {elapsed_time:.2f}s for {num_requests} requests"
