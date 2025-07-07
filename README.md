# treetop-dataclient

Dataclass-based HTTPX client for the Treetop REST API  
Python ≥ 3.11, zero runtime deps beyond HTTPX.

## Integration tests

Make sure you have Docker & Docker Compose installed.  

```bash
# Run only unit tests:
pytest

# Run integration tests (will spin up Docker Compose):
pytest -m integration
```
