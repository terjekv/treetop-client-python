from __future__ import annotations

import enum
import re
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Generic, TypeVar, cast

_COLON = re.compile(r":")
_POLICY_ID = re.compile(r'@id\("([^"]+)"\)')


def _no_colon(value: str, *, field_name: str) -> str:
    if _COLON.search(value):
        raise ValueError(f"{field_name} may not contain ':' - got {value!r}")
    return value


def _policy_id_from_literal(literal: str) -> str | None:
    match = _POLICY_ID.search(literal)
    return match.group(1) if match else None


class Endpoint(enum.Enum):
    AUTHORIZE = "/api/v1/authorize"


class Decision(str, enum.Enum):
    ALLOW = "Allow"
    DENY = "Deny"


@dataclass(slots=True, frozen=True)
class QualifiedId:
    id: str
    namespace: list[str] = field(default_factory=list)

    def __post_init__(self):
        _no_colon(self.id, field_name="QualifiedId.id")
        for ns in self.namespace:
            _no_colon(ns, field_name="QualifiedId.namespace element")

    def to_api(self) -> dict[str, Any]:
        return {"id": self.id, "namespace": self.namespace}

    def __str__(self) -> str:
        if self.namespace:
            return f"{'::'.join(self.namespace)}::{self.id}"
        return self.id


@dataclass(slots=True, frozen=True)
class Group:
    id: QualifiedId

    def to_api(self) -> dict[str, Any]:
        return self.id.to_api()

    @classmethod
    def new(
        cls,
        id: str,
        namespace: list[str] | None = None,
    ) -> Group:
        """Create a new Group with a QualifiedId."""
        return Group(id=QualifiedId(id=id, namespace=namespace or []))

    def __str__(self) -> str:
        return str(self.id)


@dataclass(slots=True, frozen=True)
class Action:
    id: QualifiedId

    def to_api(self) -> dict[str, Any]:
        return self.id.to_api()

    @classmethod
    def new(
        cls,
        id: str,
        namespace: list[str] | None = None,
    ) -> Action:
        """Create a new Action."""
        return Action(id=QualifiedId(id=id, namespace=namespace or []))

    def __str__(self) -> str:
        return str(self.id)


@dataclass(slots=True, frozen=True)
class User:
    id: QualifiedId
    groups: list[Group] = field(default_factory=list)

    def to_api(self) -> dict[str, Any]:
        return {
            **self.id.to_api(),
            "groups": [g.to_api() for g in self.groups],
        }

    @classmethod
    def new(
        cls,
        id: str,
        namespace: list[str] | None = None,
        groups: list[str] | None = None,
    ) -> User:
        """Create a new User.

        Note that this interface assumes that groups share the same namespace as the user.
        If groups are in a different namespace, you should create the object manually.

        Args:
            id: The user ID.
            namespace: Optional namespace for the user ID.
            groups: Optional list of group IDs. If provided, they will be converted to Group objects
                     with the same namespace as the user.
        Returns:
            A User object with the given ID, namespace, and groups.
        """
        return User(
            id=QualifiedId(id=id, namespace=namespace or []),
            groups=[Group.new(id=g, namespace=namespace or []) for g in groups or []],
        )

    def __str__(self) -> str:
        return str(self.id)


Principal = User | Group


class ResourceAttributeType(str, enum.Enum):
    STRING = "String"
    NUMBER = "Long"
    BOOLEAN = "Boolean"
    IP = "Ip"


@dataclass(slots=True, frozen=True)
class ResourceAttribute:
    type: ResourceAttributeType
    value: str

    def to_api(self) -> dict[str, Any]:
        if self.type == ResourceAttributeType.BOOLEAN:
            # Convert "true"/"false" strings to actual booleans for the API
            val = self.value.lower() == "true"
            return {"type": self.type.value, "value": val}
        elif self.type == ResourceAttributeType.NUMBER:
            # Convert numeric strings to actual floats for the API
            val = float(self.value)
            return {"type": self.type.value, "value": val}

        return {"type": self.type.value, "value": self.value}

    @classmethod
    def new(
        cls, value: str, type: ResourceAttributeType | None = None
    ) -> ResourceAttribute:
        """Create a new ResourceAttribute."""
        if type is None:
            type = ResourceAttributeType.STRING

        return cls(type=type, value=value)


@dataclass(slots=True, frozen=True)
class Resource:
    kind: str
    id: str
    attrs: dict[str, ResourceAttribute]

    def __post_init__(self):
        _no_colon(self.kind, field_name="Resource.kind")
        if not self.attrs:
            raise ValueError("Resource.attrs cannot be empty")

    def to_api(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "id": self.id,
            "attrs": {k: v.to_api() for k, v in self.attrs.items()},
        }

    @classmethod
    def new(cls, kind: str, id: str, attrs: dict[str, ResourceAttribute]) -> Resource:
        """Create a new Resource with kind and attributes."""
        return cls(kind=kind, id=id, attrs=attrs)


@dataclass(slots=True, frozen=True)
class Request:
    principal: Principal
    action: Action
    resource: Resource
    id: str | None = None

    def to_api(self) -> dict[str, Any]:
        # Principal: User already returns {"User": {...}}.
        # Group should be wrapped as {"Group": {...}} here.
        if isinstance(self.principal, User):
            principal_payload: dict[str, Any] = {"User": self.principal.to_api()}
        elif isinstance(self.principal, Group):  # type: ignore[unreachable]
            principal_payload = {"Group": self.principal.to_api()}
        else:
            raise TypeError(
                f"Unsupported principal type: {type(self.principal).__name__}"
            )

        result: dict[str, Any] = {
            "principal": principal_payload,
            "action": self.action.to_api(),
            "resource": self.resource.to_api(),
        }
        if self.id is not None:
            result["id"] = self.id
        return result


def as_api(obj: Request | dict[str, Any]) -> dict[str, Any]:
    return obj.to_api() if isinstance(obj, Request) else obj


@dataclass(slots=True, frozen=True)
class PermitPolicyBrief:
    id: str


@dataclass(slots=True, frozen=True)
class PermitPolicyDetailed:
    id: str | None
    literal: str
    json: dict[str, Any]

    @classmethod
    def list_from_api(
        cls, data: dict[str, Any] | list[dict[str, Any]]
    ) -> list[PermitPolicyDetailed]:
        if isinstance(data, list):
            if not data:
                raise ValueError("policy list is empty")
            policies: list[PermitPolicyDetailed] = []
            for item in data:
                literal = item["literal"]
                policy_id = (
                    item.get("annotation_id")
                    or item.get("cedar_id")
                    or item.get("id")
                    or _policy_id_from_literal(literal)
                )
                policies.append(
                    cls(
                        id=policy_id,
                        literal=literal,
                        json=item["json"],
                    )
                )
            return policies
        if not isinstance(data, dict):
            raise TypeError(f"policy must be dict or list, got {type(data)!r}")
        literal = data["literal"]
        policy_id = (
            data.get("annotation_id")
            or data.get("cedar_id")
            or data.get("id")
            or _policy_id_from_literal(literal)
        )
        return [cls(id=policy_id, literal=literal, json=data["json"])]


@dataclass(slots=True, frozen=True)
class PolicyVersion:
    hash: str
    loaded_at: datetime

    @classmethod
    def from_api(cls, data: dict[str, Any]) -> PolicyVersion:
        return cls(
            hash=data["hash"],
            loaded_at=datetime.fromisoformat(data["loaded_at"].replace("Z", "+00:00")),
        )


PolicyT = TypeVar(
    "PolicyT",
    bound="PermitPolicyBrief | PermitPolicyDetailed",
    covariant=True,
)


@dataclass(slots=True, frozen=True)
class AuthorizedResponse(Generic[PolicyT]):
    decision: Decision
    policies: Sequence[PolicyT] = field(default_factory=list)
    version: PolicyVersion | None = None

    @staticmethod
    def from_api_brief(
        data: dict[str, Any]
    ) -> AuthorizedResponse[PermitPolicyBrief]:
        dec = data.get("decision", data.get("desicion"))
        if dec is None:
            raise KeyError("decision")
        if isinstance(dec, dict):
            if Decision.ALLOW.value in dec:
                dec = Decision.ALLOW.value
            elif Decision.DENY.value in dec:
                dec = Decision.DENY.value
            else:
                raise ValueError(f"Unrecognized decision shape: {dec!r}")
        decision = Decision(dec)

        raw_policy_ids = data.get("policy_id")
        if isinstance(raw_policy_ids, str):
            policy_ids = [p.strip() for p in raw_policy_ids.split(";") if p.strip()]
        elif raw_policy_ids is None:
            policy_ids = []
        elif isinstance(raw_policy_ids, list):
            # Check that all items in the list are strings
            if not all(isinstance(p, str) for p in raw_policy_ids):
                raise TypeError(
                    f"All items in policy_id list must be strings, got {raw_policy_ids!r}"
                )
            policy_ids = [str(p) for p in raw_policy_ids]
        else:
            raise TypeError(
                f"policy_id must be string if present, got {type(raw_policy_ids)!r}"
            )
        policies = [PermitPolicyBrief(id=policy_id) for policy_id in policy_ids]
        version_blob = data.get("version")
        version = PolicyVersion.from_api(version_blob) if version_blob else None
        return AuthorizedResponse(
            decision=decision, policies=policies, version=version
        )

    @staticmethod
    def from_api_detailed(
        data: dict[str, Any]
    ) -> AuthorizedResponse[PermitPolicyDetailed]:
        dec = data.get("decision", data.get("desicion"))  # Temporary typo support
        if dec is None:
            raise KeyError("decision")

        # 1) Is it a simple Deny (old format)?
        if dec == Decision.DENY.value:
            version_blob = data.get("version")
            version = PolicyVersion.from_api(version_blob) if version_blob else None
            return AuthorizedResponse(
                decision=Decision.DENY, policies=[], version=version
            )

        # 1b) Is it a simple Allow with top-level policy/version?
        if dec == Decision.ALLOW.value:
            if "policy" not in data:
                raise ValueError(f"Allow decision missing policy: {data!r}")
            policy_blob = data["policy"]
            version_blob = data.get("version")
            version = PolicyVersion.from_api(version_blob) if version_blob else None
            return AuthorizedResponse(
                decision=Decision.ALLOW,
                policies=PermitPolicyDetailed.list_from_api(policy_blob),
                version=version,
            )

        # 2) Is it a Deny with version (new format)?
        if isinstance(dec, dict) and Decision.DENY.value in dec:
            deny_dict = cast(dict[str, Any], dec[Decision.DENY.value])
            version_blob = deny_dict.get("version")
            version = PolicyVersion.from_api(version_blob) if version_blob else None
            return AuthorizedResponse(
                decision=Decision.DENY,
                policies=[],
                version=version,
            )

        # 3) If it's a dict with an "Allow" key, pull the policy and optional version
        if isinstance(dec, dict) and Decision.ALLOW.value in dec:
            if not isinstance(dec[Decision.ALLOW.value], dict):
                raise ValueError(f"Malformed Allow decision: {dec!r}")

            allow_dict = cast(dict[str, Any], dec[Decision.ALLOW.value])

            if "policy" not in allow_dict:
                raise ValueError(f"Allow decision missing policy: {dec!r}")

            policy_blob = allow_dict["policy"]
            version_blob = allow_dict.get("version")
            version = PolicyVersion.from_api(version_blob) if version_blob else None
            return AuthorizedResponse(
                decision=Decision.ALLOW,
                policies=PermitPolicyDetailed.list_from_api(policy_blob),
                version=version,
            )

        # 4) Otherwise it's malformed
        raise ValueError(f"Unrecognized decision shape: {dec!r}")

    def is_allowed(self) -> bool:
        return self.decision == Decision.ALLOW

    def is_denied(self) -> bool:
        return self.decision == Decision.DENY

    def policy_ids(self) -> list[str]:
        return [policy.id for policy in self.policies if policy.id]

    def version_hash(self) -> str | None:
        """Return the policy version hash if available, otherwise None."""
        return self.version.hash if self.version else None

    def version_loaded_at(self) -> datetime | None:
        """Return the policy version loaded_at timestamp if available, otherwise None."""
        return self.version.loaded_at if self.version else None


# Generic type variables for authorization results and responses
DecisionT = TypeVar("DecisionT", bound=AuthorizedResponse[Any], covariant=True)


@dataclass(slots=True, frozen=True)
class AuthorizeResult(Generic[DecisionT]):
    """A single result from the authorize endpoint."""

    index: int
    id: str | None
    status: str
    result: DecisionT | None = None
    error: str | None = None

    def is_success(self) -> bool:
        """Check if this result is successful."""
        return self.status == "success"

    def is_failed(self) -> bool:
        """Check if this result failed."""
        return self.status == "failed"

    def get_decision(self) -> Decision | None:
        """Get the decision if successful, otherwise None."""
        return self.result.decision if self.result else None

    def is_allowed(self) -> bool:
        """Check if the decision is Allow."""
        return self.result.is_allowed() if self.result else False

    def is_denied(self) -> bool:
        """Check if the decision is Deny."""
        return self.result.is_denied() if self.result else False


    @staticmethod
    def from_api_brief(
        data: dict[str, Any]
    ) -> AuthorizeResult[AuthorizedResponse[PermitPolicyBrief]]:
        index = data["index"]
        result_id = data.get("id")
        status = data["status"]
        error = data.get("error")

        result = None
        if status == "success" and "result" in data:
            result = AuthorizedResponse.from_api_brief(data["result"])

        return AuthorizeResult(
            index=index, id=result_id, status=status, result=result, error=error
        )

    @staticmethod
    def from_api_detailed(
        data: dict[str, Any]
    ) -> AuthorizeResult[AuthorizedResponse[PermitPolicyDetailed]]:
        index = data["index"]
        result_id = data.get("id")
        status = data["status"]
        error = data.get("error")

        result = None
        if status == "success" and "result" in data:
            result = AuthorizedResponse.from_api_detailed(data["result"])

        return AuthorizeResult(
            index=index, id=result_id, status=status, result=result, error=error
        )


AuthorizeResultT = TypeVar(
    "AuthorizeResultT",
    bound=AuthorizeResult[AuthorizedResponse[Any]],
    covariant=True,
)


@dataclass(slots=True, frozen=True)
class AuthorizeResponse(Generic[AuthorizeResultT]):
    """Batch response from the authorize endpoint."""

    results: Sequence[AuthorizeResultT]
    version: PolicyVersion
    successful: int
    failed: int

    def __iter__(self):
        """Iterate over results."""
        return iter(self.results)

    def __len__(self):
        """Return the number of results."""
        return len(self.results)

    def __getitem__(self, index: int) -> AuthorizeResultT:
        """Get result by index."""
        return self.results[index]

    def get_by_id(self, request_id: str) -> AuthorizeResultT | None:
        """Get result by client-provided request ID."""
        for result in self.results:
            if result.id == request_id:
                return result
        return None

    def denied_count(self) -> int:
        """Return the number of denied results."""
        return sum(1 for r in self.results if r.is_success() and r.is_denied())

    def allowed_count(self) -> int:
        """Return the number of allowed results."""
        return sum(1 for r in self.results if r.is_success() and r.is_allowed())

    def all_allowed(self) -> bool:
        """Check if all successful results are allowed."""
        return all(r.is_allowed() for r in self.results if r.is_success())

    @staticmethod
    def from_api_brief(
        data: dict[str, Any]
    ) -> AuthorizeResponse[AuthorizeResult[AuthorizedResponse[PermitPolicyBrief]]]:
        results = [AuthorizeResult.from_api_brief(r) for r in data.get("results", [])]
        version = PolicyVersion.from_api(data["version"])
        successful = data.get("successful", 0)
        failed = data.get("failed", 0)

        return AuthorizeResponse(
            results=results, version=version, successful=successful, failed=failed
        )
    @staticmethod
    def from_api_detailed(
        data: dict[str, Any]
    ) -> AuthorizeResponse[AuthorizeResult[AuthorizedResponse[PermitPolicyDetailed]]]:
        results = [
            AuthorizeResult.from_api_detailed(r) for r in data.get("results", [])
        ]
        version = PolicyVersion.from_api(data["version"])
        successful = data.get("successful", 0)
        failed = data.get("failed", 0)

        return AuthorizeResponse(
            results=results, version=version, successful=successful, failed=failed
        )


BriefDecision = AuthorizedResponse[PermitPolicyBrief]
DetailedDecision = AuthorizedResponse[PermitPolicyDetailed]
BriefAuthorizeResult = AuthorizeResult[BriefDecision]
DetailedAuthorizeResult = AuthorizeResult[DetailedDecision]
BriefAuthorizeResponse = AuthorizeResponse[BriefAuthorizeResult]
DetailedAuthorizeResponse = AuthorizeResponse[DetailedAuthorizeResult]
