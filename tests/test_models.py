import pytest

from treetop_client.models import (
    Action,
    AuthorizedResponse,
    Decision,
    Group,
    PermitPolicyDetailed,
    QualifiedId,
    Request,
    Resource,
    ResourceAttribute,
    User,
)


def test_qualified_id_and_group():
    q = QualifiedId(id="alice", namespace=["App"])
    g = Group(id=q)
    u = User(id=q, groups=[g])
    req = Request(
        principal=u,
        action=Action(id=QualifiedId(id="x")),
        resource=Resource(
            kind="Photo",
            id="1",
            attrs={"id": ResourceAttribute.new("1")},
        ),
    )
    api = req.to_api()
    assert api["principal"]["User"]["id"] == "alice"
    assert api["principal"]["User"]["namespace"] == ["App"]
    assert api["principal"]["User"] == {
        "id": "alice",
        "namespace": ["App"],
        "groups": [{"id": "alice", "namespace": ["App"]}],
    }


def test_resource_empty_attrs():
    with pytest.raises(ValueError):
        Resource(kind="Photo", id="1", attrs={})


def test_user_no_colon():
    with pytest.raises(ValueError):
        User(id=QualifiedId(id="bad:user"))


def test_group_no_colon():
    with pytest.raises(ValueError):
        Group(id=QualifiedId(id="bad:group", namespace=["App"]))


def test_action_no_colon():
    with pytest.raises(ValueError):
        Action(id=QualifiedId(id="bad:action"))


def test_user_with_namespace():
    q = QualifiedId(id="alice", namespace=["App"])
    u = User(id=q, groups=[])
    assert u.to_api() == {
        "id": "alice",
        "namespace": ["App"],
        "groups": [],
    }


def test_group_with_namespace():
    g = Group(id=QualifiedId(id="group1", namespace=["App"]))
    assert g.to_api() == {"id": "group1", "namespace": ["App"]}


def test_action_with_namespace():
    q = QualifiedId(id="edit", namespace=["App"])
    a = Action(id=q)
    assert a.to_api() == {"id": "edit", "namespace": ["App"]}


def test_user_new():
    u = User.new(id="alice", namespace=["App"], groups=["group1", "group2"])
    assert u.to_api() == {
        "id": "alice",
        "namespace": ["App"],
        "groups": [
            {"id": "group1", "namespace": ["App"]},
            {"id": "group2", "namespace": ["App"]},
        ],
    }


def test_group_new():
    g = Group.new(id="group1", namespace=["App"])
    assert g.to_api() == {"id": "group1", "namespace": ["App"]}


def test_action_new():
    a = Action.new(id="edit", namespace=["App"])
    assert a.to_api() == {"id": "edit", "namespace": ["App"]}


def test_authorized_response_detailed_multiple_policies():
    data = {
        "decision": {
            "Allow": {
                "policy": [
                    {
                        "literal": '@id("policy.alice")\npermit (principal == User::"alice", action, resource);',
                        "json": {"effect": "permit"},
                    },
                    {
                        "literal": '@id("policy.bob")\npermit (principal == User::"bob", action, resource);',
                        "json": {"effect": "permit"},
                    },
                ]
            }
        }
    }
    resp = AuthorizedResponse.from_api_detailed(data)
    assert resp.is_allowed()
    assert resp.policies
    assert [policy.literal for policy in resp.policies] == [
        '@id("policy.alice")\npermit (principal == User::"alice", action, resource);',
        '@id("policy.bob")\npermit (principal == User::"bob", action, resource);',
    ]
    assert [policy.json for policy in resp.policies] == [
        {"effect": "permit"},
        {"effect": "permit"},
    ]
    assert [policy.id for policy in resp.policies] == ["policy.alice", "policy.bob"]


def test_permit_policy_empty_list_rejected():
    with pytest.raises(ValueError):
        PermitPolicyDetailed.list_from_api([])


def test_permit_policy_id_from_literal():
    data = {
        "literal": '@id("policy.literal_only")\npermit (principal, action, resource);',
        "json": {"effect": "permit"},
    }
    policies = PermitPolicyDetailed.list_from_api(data)
    assert len(policies) == 1
    assert policies[0].id == "policy.literal_only"


def test_authorized_response_detailed_deny_has_no_policy():
    data = {"decision": Decision.DENY.value}
    resp = AuthorizedResponse.from_api_detailed(data)
    assert resp.is_denied()
    assert resp.policies == []


def test_authorized_response_brief_policy_ids_parsing():
    data = {"decision": Decision.ALLOW.value, "policy_id": "a;b ; c;;"}
    resp = AuthorizedResponse.from_api_brief(data)
    assert resp.is_allowed()
    assert resp.policy_ids() == ["a", "b", "c"]


def test_authorized_response_brief_policy_ids_missing():
    data = {"decision": Decision.DENY.value}
    resp = AuthorizedResponse.from_api_brief(data)
    assert resp.is_denied()
    assert resp.policy_ids() == []
