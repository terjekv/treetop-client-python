# TreeTop Client

Dataclass-based HTTPX client for the [Treetop REST API](https://github.com/terjekv/treetop-rest).
Python ≥ 3.12, zero runtime deps beyond HTTPX.

## Example

```python
from treetop_client.client import TreeTopClient
from treetop_client.models import (
    Action,
    Decision,
    Request,
    Resource,
    User,
    ResourceAttribute,
    ResourceAttributeType,
)

client = TreeTopClient(base_url=f"http://localhost:{PORT}")

attrs = {}
attrs["ip"] = ResourceAttribute.new("10.0.0.1", ResourceAttributeType.IP)
attrs["name"] = ResourceAttribute.new("myhost.example.com", ResourceAttributeType.STRING)

req = Request(
    principal=User.new("myuser", "mynamespace", ["mygroup"]),
    action=Action.new("myaction", ["mynamespace"]),
    resource=Resource.new("Host", id="myhost", attrs=attrs)
)
resp = client.check(req)

# Use is_allowed() / is_denied() methods
assert resp.is_allowed()
# Or compare with the Decision enum
assert resp.decision == Decision.ALLOW
```

You can also use the `check_detailed` method to get more information about the decision:

```python
from treetop_client.client import TreeTopClient
from treetop_client.models import (
    Action,
    Decision,
    Request,
    Resource,
    User,
    ResourceAttribute,
    ResourceAttributeType,
)

client = TreeTopClient(base_url=f"http://localhost:{PORT}")

attrs = {}
attrs["ip"] = ResourceAttribute.new("10.0.0.1", ResourceAttributeType.IP)
attrs["name"] = ResourceAttribute.new("myhost.example.com", ResourceAttributeType.STRING)

req = Request(
    principal=User.new("myuser", "mynamespace", ["mygroup"]),
    action=Action.new("myaction", ["mynamespace"]),
    resource=Resource.new("Host", id="myhost", attrs=attrs)
)

resp = client.check_detailed(req)
assert resp.is_allowed()
assert resp.decision == Decision.ALLOW

# Access policy information (if allowed)
assert resp.policy_literal() is not None  # Cedar format
assert resp.policy_json() is not None     # JSON format

# Access version information (if server supports it)
hash = resp.version_hash()           # SHA-256 hash or None
loaded_at = resp.version_loaded_at() # datetime or None
```

Note that for `User` the namespace and groups are optional, and for `Action` the namespace is optional. If you don't provide a namespace, it will default to the root namespace.

## Correlation ID

You can pass a correlation ID to the `check` and `check_detailed` methods. This ID will be included in the request headers and can be used on the server side
to trace requests across queries or services. The value is a string of the client's choosing.

```python
from treetop_client.client import TreeTopClient
from treetop_client.models import (
    Action,
    Request,
    Resource,
    User,
    ResourceAttribute,
    ResourceAttributeType,
)

client = TreeTopClient(base_url=f"http://localhost:{PORT}")

attrs = {}
attrs["ip"] = ResourceAttribute.new("10.0.0.1", ResourceAttributeType.IP)
attrs["name"] = ResourceAttribute.new("myhost.example.com", ResourceAttributeType.STRING)

req = Request(
    principal=User.new("myuser", "mynamespace", ["mygroup"]),
    action=Action.new("myaction", ["mynamespace"]),
    resource=Resource.new("Host", id="myhost", attrs=attrs)
)

resp = client.check(req, correlation_id="my-correlation-id")
```

## Integration tests

Make sure you have Docker & Docker Compose installed.  

```bash
# Run only unit tests:
pytest

# Run integration tests (will spin up Docker Compose):
pytest -m integration
```
