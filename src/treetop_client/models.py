from __future__ import annotations

import enum
import re
from dataclasses import dataclass, field
from typing import Any, ClassVar

_COLON = re.compile(r":")


def _no_colon(value: str, *, field_name: str) -> str:
    if _COLON.search(value):
        raise ValueError(f"{field_name} may not contain ':' – got {value!r}")
    return value


class Endpoint(enum.Enum):
    CHECK = "/api/v1/check"
    CHECK_DETAILED = "/api/v1/check_detailed"


@dataclass(slots=True, frozen=True)
class QualifiedId:
    id: str
    namespace: list[str] = field(default_factory=list[str])

    def __post_init__(self):
        _no_colon(self.id, field_name="QualifiedId.id")
        for ns in self.namespace:
            _no_colon(ns, field_name="QualifiedId.namespace element")

    def to_api(self) -> dict[str, Any]:
        return {"id": self.id, "namespace": self.namespace}


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


@dataclass(slots=True, frozen=True)
class Action:
    id: QualifiedId

    def to_api(self) -> dict[str, Any]:
        return {"id": self.id.to_api()}

    @classmethod
    def new(
        cls,
        id: str,
        namespace: list[str] | None = None,
    ) -> Action:
        """Create a new Action."""
        return Action(id=QualifiedId(id=id, namespace=namespace or []))


@dataclass(slots=True, frozen=True)
class User:
    id: QualifiedId
    groups: list[Group] = field(default_factory=list[Group])

    def to_api(self) -> dict[str, Any]:
        return {
            "User": {
                "id": self.id.to_api(),
                "groups": [g.to_api() for g in self.groups],
            }
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


Principal = User | Group


@dataclass(slots=True, frozen=True)
class Resource:
    kind: str
    attrs: dict[str, Any]

    def __post_init__(self):
        _no_colon(self.kind, field_name="Resource.kind")
        if not self.attrs:
            raise ValueError("Resource.attrs cannot be empty")

    def to_api(self) -> dict[str, Any]:
        return {self.kind: self.attrs}

    @classmethod
    def new(cls, kind: str, attrs: dict[str, Any]) -> Resource:
        """Create a new Resource with kind and attributes."""
        return cls(kind=kind, attrs=attrs)


@dataclass(slots=True, frozen=True)
class Request:
    principal: Principal
    action: Action
    resource: Resource

    def to_api(self) -> dict[str, Any]:
        return {
            "principal": self.principal.to_api(),
            "action": self.action.to_api(),
            "resource": self.resource.to_api(),
        }


def as_api(obj: Request | dict[str, Any]) -> dict[str, Any]:
    return obj.to_api() if isinstance(obj, Request) else obj


@dataclass(slots=True, frozen=True)
class CheckResponseBrief:
    decision: str  # "Allow" or "Deny"

    _KEYS: ClassVar[tuple[str, ...]] = ("decision",)

    @classmethod
    def from_api(cls, data: dict[str, Any]) -> CheckResponseBrief:
        # will KeyError if missing, or propagate other types
        return cls(decision=data["decision"])

    def is_allowed(self) -> bool:
        return self.decision == "Allow"

    def is_denied(self) -> bool:
        return self.decision == "Deny"


@dataclass(slots=True, frozen=True)
class PermitPolicy:
    literal: str
    json: dict[str, Any]

    @classmethod
    def from_api(cls, data: dict[str, Any]) -> PermitPolicy:
        return cls(literal=data["literal"], json=data["json"])


@dataclass(slots=True, frozen=True)
class CheckResponse:
    # Either decision == "Deny" or {"Allow": PermitPolicy}
    decision: str
    policy: PermitPolicy | None

    @classmethod
    def from_api(cls, data: dict[str, Any]) -> CheckResponse:
        dec = data["decision"]

        # 1) Is it a simple Deny?
        if dec == "Deny":
            return cls(decision="Deny", policy=None)

        # 2) If it's a dict with an "Allow" key, pull the policy out of there
        if isinstance(dec, dict) and "Allow" in dec:
            policy_blob = dec["Allow"]["policy"]  # type: ignore[assignment]
            return cls(
                decision="Allow",
                policy=PermitPolicy.from_api(policy_blob),  # type: ignore[call-arg]
            )

        # 3) Otherwise it's malformed
        raise ValueError(f"Unrecognized decision shape: {dec!r}")

    def is_allowed(self) -> bool:
        return self.decision == "Allow"

    def is_denied(self) -> bool:
        return self.decision == "Deny"

    def policy_literal(self) -> str | None:
        """Return the policy literal if available, otherwise None."""
        return self.policy.literal if self.policy else None

    def policy_json(self) -> dict[str, Any] | None:
        """Return the policy JSON if available, otherwise None."""
        return self.policy.json if self.policy else None
