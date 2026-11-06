"""Elastic Load Balancing: ALB/NLB/GWLB (elbv2) and classic load balancers, their exposure
(scheme, security groups, subnets, listeners) and backend targets.

Output (``<region>/elb/``):

* ``resources.json`` (list), sorted by ``Arn``::

    {Type: "elb", Arn, Name, LBType, Scheme, DNSName, VpcId, SecurityGroups, Subnets,
     Listeners: [{Port, Protocol, DefaultActionTypes, AuthenticateActions: [{Type, UserPoolArn, Issuer}]}]|null,
     TargetGroups: [{Arn, Name, TargetType, Protocol, Port}]|null,
     Targets: [{kind, id, TargetGroupArn}]|null, CollectionErrors?}

  Classic load balancers get their real, partition-aware ARN
  (``arn:<p>:elasticloadbalancing:<region>:<account>:loadbalancer/<name>``) instead of the bare name
  (F-051). Each load balancer is isolated: a failing listener or target-group call only marks that
  load balancer (``CollectionErrors``; ``Targets`` keeps the target groups that could be read).
  ``Listeners`` show ``authenticate-oidc`` / ``authenticate-cognito`` default actions.
"""

from __future__ import annotations

from typing import Any, Dict, List

from aws_enumerator.collectors._common import add_error
from aws_enumerator.registry import CollectorSpec

SPEC = CollectorSpec(
    name="elb", scope="regional", output_dir="elb", services=("elbv2", "elb"),
    tier=1, cost="low", noise="low", default=True, groups=("@network", "@edge"),
    actions=("elasticloadbalancing:DescribeLoadBalancers", "elasticloadbalancing:DescribeTargetGroups",
             "elasticloadbalancing:DescribeTargetHealth", "elasticloadbalancing:DescribeListeners"),
    probe=("elbv2", "DescribeLoadBalancers", (("PageSize", 1),)),
    outputs=(("resources.json", "list"),),
    description="Application, network and classic load balancers: exposure, listeners and targets",
)

_PAGE = 400


def _listeners(ctx: Any, v2: Any, item: Dict[str, Any]) -> None:
    result = ctx.paginate(v2, "describe_listeners", "Listeners", page_size=_PAGE, item=item["Arn"],
                          LoadBalancerArn=item["Arn"])
    if not result.ok:
        add_error(item, result)
        return
    listeners = []
    for lst in result.value:
        actions = sorted(lst.get("DefaultActions") or [], key=lambda a: a.get("Order") or 0)
        auth = []
        for a in actions:
            if a.get("Type") == "authenticate-cognito":
                auth.append({"Type": a["Type"], "UserPoolArn": (a.get("AuthenticateCognitoConfig") or {})
                             .get("UserPoolArn"), "Issuer": None})
            elif a.get("Type") == "authenticate-oidc":
                auth.append({"Type": a["Type"], "UserPoolArn": None,
                             "Issuer": (a.get("AuthenticateOidcConfig") or {}).get("Issuer")})
        listeners.append({"Port": lst.get("Port"), "Protocol": lst.get("Protocol"),
                          "DefaultActionTypes": [a.get("Type") for a in actions], "AuthenticateActions": auth})
    item["Listeners"] = sorted(listeners, key=lambda x: (x["Port"] or 0, str(x["Protocol"])))


def _targets(ctx: Any, v2: Any, item: Dict[str, Any]) -> None:
    groups = ctx.paginate(v2, "describe_target_groups", "TargetGroups", page_size=_PAGE, item=item["Arn"],
                          LoadBalancerArn=item["Arn"])
    if not groups.ok:
        add_error(item, groups)
        return
    item["TargetGroups"] = sorted(({"Arn": tg.get("TargetGroupArn"), "Name": tg.get("TargetGroupName"),
                                    "TargetType": tg.get("TargetType"), "Protocol": tg.get("Protocol"),
                                    "Port": tg.get("Port")} for tg in groups.value), key=lambda t: str(t["Arn"]))
    targets = []
    for tg in groups.value:
        health = ctx.call(v2, "describe_target_health", item=tg.get("TargetGroupArn"),
                          TargetGroupArn=tg.get("TargetGroupArn"))
        if not health.ok:
            add_error(item, health)
            continue
        for h in health.get("TargetHealthDescriptions") or []:
            tid = (h.get("Target") or {}).get("Id")
            if tid:
                targets.append({"kind": tg.get("TargetType"), "id": tid, "TargetGroupArn": tg.get("TargetGroupArn")})
    item["Targets"] = sorted(targets, key=lambda t: (str(t["id"]), str(t["TargetGroupArn"])))


def _v2(ctx: Any, out: List[Dict[str, Any]]) -> None:
    v2 = ctx.client("elbv2")
    listed = ctx.paginate(v2, "describe_load_balancers", "LoadBalancers", page_size=_PAGE)
    for lb in listed.value:
        item: Dict[str, Any] = {
            "Type": "elb", "Arn": lb.get("LoadBalancerArn"), "Name": lb.get("LoadBalancerName"),
            "LBType": lb.get("Type"), "Scheme": lb.get("Scheme"), "DNSName": lb.get("DNSName"),
            "VpcId": lb.get("VpcId"), "SecurityGroups": sorted(lb.get("SecurityGroups") or []),
            "Subnets": sorted(z.get("SubnetId") for z in lb.get("AvailabilityZones") or [] if z.get("SubnetId")),
            "Listeners": None, "TargetGroups": None, "Targets": None,
        }
        _listeners(ctx, v2, item)
        _targets(ctx, v2, item)
        out.append(item)


def _classic(ctx: Any, out: List[Dict[str, Any]]) -> None:
    v1 = ctx.client("elb")
    listed = ctx.paginate(v1, "describe_load_balancers", "LoadBalancerDescriptions", page_size=_PAGE)
    for lb in listed.value:
        name = lb.get("LoadBalancerName")
        listeners = [d.get("Listener") or {} for d in lb.get("ListenerDescriptions") or []]
        out.append({
            "Type": "elb", "Arn": ctx.arn("elasticloadbalancing", f"loadbalancer/{name}"), "Name": name,
            "LBType": "classic", "Scheme": lb.get("Scheme"), "DNSName": lb.get("DNSName"),
            "VpcId": lb.get("VPCId"), "SecurityGroups": sorted(lb.get("SecurityGroups") or []),
            "Subnets": sorted(lb.get("Subnets") or []),
            "Listeners": sorted(({"Port": x.get("LoadBalancerPort"), "Protocol": x.get("Protocol"),
                                  "InstancePort": x.get("InstancePort"), "InstanceProtocol": x.get("InstanceProtocol"),
                                  "DefaultActionTypes": [], "AuthenticateActions": []} for x in listeners),
                                key=lambda x: (x["Port"] or 0, str(x["Protocol"]))),
            "TargetGroups": [],
            "Targets": sorted(({"kind": "instance", "id": i["InstanceId"], "TargetGroupArn": None}
                               for i in lb.get("Instances") or [] if i.get("InstanceId")), key=lambda t: t["id"]),
        })


def collect(ctx: Any) -> None:
    resources: List[Dict[str, Any]] = []
    with ctx.section("v2"):
        _v2(ctx, resources)
    with ctx.section("classic"):
        _classic(ctx, resources)
    resources.sort(key=lambda r: str(r["Arn"]))
    ctx.out.write("resources.json", resources)
    public = sum(1 for r in resources if r.get("Scheme") == "internet-facing")
    ctx.log.info("%d load balancers, %d internet-facing", len(resources), public)
