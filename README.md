# TreeTop Client

Dataclass-based HTTPX client for the [Treetop REST API](https://github.com/terjekv/treetop-rest).
Python ≥ 3.11, zero runtime deps beyond HTTPX.

## Example

```python
from treetop_client.client import TreeTopClient
from treetop_client.models import Action, Request, Resource, User


client = TreeTopClient(base_url=f"http://localhost:{PORT}")

req = Request(
    principal=User.new("myuser", "mynamespace", ["mygroup"]),
    action=Action.new("myaction", ["mynamespace"]),
    resource=Resource.new("Host", {"name": "myhost.example.com", "ip": "10.0.0.1"}),
)
resp = client.check(req)
assert resp.is_allowed() 
assert resp.decision == "Allow"

# The other possible value for decision is "Deny" which makes `is_denied()` True
# (and `is_allowed()` False).
```

You can also use the `check_detailed` method to get more information about the decision:

```python
from treetop_client.client import TreeTopClient
from treetop_client.models import Action, Request, Resource, User

client = TreeTopClient(base_url=f"http://localhost:{PORT}")

req = Request(
    principal=User.new("myuser", "mynamespace", ["mygroup"]),
    action=Action.new("myaction", ["mynamespace"]),
    resource=Resource.new("Host", {"name": "myhost.example.com", "ip": "10.0.0.1"}),
)

resp = client.check_detailed(req)
assert resp.is_allowed()
assert resp.decision == "Allow"
 # This will contain the policy that was matched, in cedar format
assert resp.policy_literal() is not None
 # This will contain the policy that was matched, in JSON format
assert resp.policy_json() is not None
```

Note that for `User` the namespace and groups are optional, and for `Action` the namespace is optional. If you don't provide a namespace, it will default to the root namespace.

## Integration tests

Make sure you have Docker & Docker Compose installed.  

```bash
# Run only unit tests:
pytest

# Run integration tests (will spin up Docker Compose):
pytest -m integration
```
