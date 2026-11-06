"""Shared builders for the evaluator and rules tests (E-policy).

Fixtures hand out a :class:`PolicyKit`: principal models from raw IAM statements, resource/trust/key policies,
organisation models and an :class:`~aws_enumerator.engine.policy.evaluator.Evaluator` over them, so every test
states its policies literally. Account ids are the documentation placeholders only.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Union

import pytest

from aws_enumerator.engine.iam.principals import build_action_index
from aws_enumerator.engine.model import PrincipalModel, Statement
from aws_enumerator.engine.policy.evaluator import Evaluator
from aws_enumerator.engine.policy.org import OrgModel
from aws_enumerator.engine.policy.parse import parse_policy, request_principal
from aws_enumerator.engine.policy.resource_policy import ResourcePolicyIndex

ACCT = "111122223333"
OTHER = "999999999999"
REF_TIME = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)


def doc(*statements: Mapping[str, Any]) -> Dict[str, Any]:
    return {"Version": "2012-10-17", "Statement": list(statements)}


def allow(action: Any = "*", resource: Any = "*", condition: Optional[Mapping[str, Any]] = None,
          **extra: Any) -> Dict[str, Any]:
    stmt: Dict[str, Any] = {"Effect": "Allow", "Action": action, "Resource": resource}
    if condition:
        stmt["Condition"] = dict(condition)
    stmt.update(extra)
    return stmt


def deny(action: Any = "*", resource: Any = "*", condition: Optional[Mapping[str, Any]] = None,
         **extra: Any) -> Dict[str, Any]:
    stmt = allow(action, resource, condition, **extra)
    stmt["Effect"] = "Deny"
    return stmt


def stmts(statements: Sequence[Mapping[str, Any]], *, layer: str = "identity", name: str = "p",
          partition: str = "aws") -> tuple:
    source_type = {"identity": "inline", "boundary": "boundary", "scp": "scp", "rcp": "rcp"}.get(layer, "resource")
    return parse_policy(doc(*statements), layer=layer, source_type=source_type, policy_name=name,
                        partition=partition).statements


class PolicyKit:
    """Builds principal models, a resource index and an evaluator for one test."""

    def __init__(self, account: str = ACCT, partition: str = "aws"):
        self.account = account
        self.partition = partition
        self.models: Dict[str, PrincipalModel] = {}
        self.resources = ResourcePolicyIndex(default_owner=account, partition=partition)
        self.org: Optional[OrgModel] = None

    def arn(self, kind: str, name: str, account: Optional[str] = None) -> str:
        return f"arn:{self.partition}:iam::{account or self.account}:{kind}/{name}"

    def principal(self, arn: str, identity: Sequence[Mapping[str, Any]] = (), *,
                  boundary: Union[None, str, Sequence[Mapping[str, Any]]] = None,
                  tags: Optional[Mapping[str, str]] = None,
                  groups: Iterable[str] = (), service_linked: bool = False, gaps: Iterable[str] = (),
                  scp_chain: Optional[Sequence[Sequence[Mapping[str, Any]]]] = None) -> PrincipalModel:
        ident: tuple = stmts(identity, partition=self.partition)
        bnd: Any = boundary if boundary is None or boundary == "missing" else stmts(boundary, layer="boundary",
                                                                                    partition=self.partition)
        chain = None if scp_chain is None else tuple(stmts(level, layer="scp", partition=self.partition)
                                                     for level in scp_chain)
        p = request_principal(arn, partition=self.partition)
        if ":group/" in arn:
            from aws_enumerator.engine.model import Principal
            p = Principal("aws_user", arn, arn, self.account, self.partition, None)
        model = PrincipalModel(id=arn, principal=p, identity=ident, boundary=bnd, groups=tuple(groups),
                               tags=dict(tags or {}), scp_chain=chain, is_service_linked=service_linked,
                               action_index=build_action_index(ident), gaps=frozenset(gaps))
        self.models[arn] = model
        return model

    def user(self, name: str, identity: Sequence[Mapping[str, Any]] = (), **kw: Any) -> PrincipalModel:
        return self.principal(self.arn("user", name), identity, **kw)

    def role(self, name: str, identity: Sequence[Mapping[str, Any]] = (), *,
             trust: Optional[Sequence[Mapping[str, Any]]] = None, **kw: Any) -> PrincipalModel:
        model = self.principal(self.arn("role", name), identity, **kw)
        if trust is not None:
            self.resources.add(model.id, doc(*trust), layer="trust", owner=self.account)
        return model

    def resource_policy(self, arn: str, statements: Sequence[Mapping[str, Any]], *, layer: str = "resource",
                        owner: Optional[str] = None) -> None:
        self.resources.add(arn, doc(*statements), layer=layer, owner=owner)

    def org_model(self, *, levels: Sequence[Sequence[Mapping[str, Any]]] = (),
                  rcp_levels: Optional[Sequence[Sequence[Mapping[str, Any]]]] = None, management: Optional[str] = None,
                  org_id: str = "o-exampleorgid", in_org: Optional[bool] = True) -> OrgModel:
        """Root → OU → account; ``levels[i]`` is attached at level ``i``, the remaining levels get the AWS
        default full-access policy (AWS keeps one attached to every level while a policy type is enabled)."""
        path = ["r-ex12", "ou-ex12-11111111", self.account]
        full = [allow("*")]
        policies: List[Dict[str, Any]] = []
        for ptype, chain in (("SERVICE_CONTROL_POLICY", levels), ("RESOURCE_CONTROL_POLICY", rcp_levels)):
            if chain is None:
                continue
            for i, target in enumerate(path):
                content = list(chain[i]) if i < len(chain) else full
                policies.append({"PolicyId": f"p-{ptype[:3].lower()}{i}", "Name": f"{ptype[:3].lower()}{i}",
                                 "Type": ptype, "Targets": [target], "Content": doc(*content)})
        types = [{"Type": "SERVICE_CONTROL_POLICY", "Status": "ENABLED"}]
        if rcp_levels is not None:
            types.append({"Type": "RESOURCE_CONTROL_POLICY", "Status": "ENABLED"})
        org = {"InOrganization": in_org, "Id": org_id, "ManagementAccountId": management or "000000000000",
               "AvailablePolicyTypes": types}
        self.org = OrgModel.from_documents(org, list(path), policies, account_id=self.account,
                                           partition=self.partition)
        return self.org

    def evaluator(self, *, reference_time: Optional[datetime] = REF_TIME) -> Evaluator:
        return Evaluator(None, self.models, self.resources, self.org, account_id=self.account,
                         partition=self.partition, reference_time=reference_time)


@pytest.fixture
def kit() -> PolicyKit:
    return PolicyKit()


@pytest.fixture
def kit_factory():
    return PolicyKit


@pytest.fixture
def policy_helpers():
    """``allow``/``deny``/``doc``/``stmts`` for tests that build statements inline."""
    class H:
        pass
    h = H()
    h.allow, h.deny, h.doc, h.stmts = allow, deny, doc, stmts
    h.ACCT, h.OTHER, h.REF_TIME = ACCT, OTHER, REF_TIME
    return h


__all__ = ["ACCT", "OTHER", "PolicyKit", "REF_TIME", "allow", "deny", "doc", "stmts", "Statement"]
