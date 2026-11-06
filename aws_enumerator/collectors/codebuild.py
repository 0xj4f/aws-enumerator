"""CodeBuild: projects (service role, source, webhook, environment variable names) and source
credentials metadata.

A build runs arbitrary commands as its service role (PRIVESC-019); a webhook-triggered project from
a source anyone can push to is a poisoned-pipeline entry point (F-113). Secret-bearing fields are
never stored: environment variable **values**, the inline buildspec, webhook ``secret`` and
``payloadUrl``, credentials embedded in a source URL (``https://user:token@host/...``), and
``source.auth.resource``.

Output (``<region>/codebuild/``):

* ``resources.json`` (list), sorted by ``Arn``::

    {Type: "codebuild", Arn, Name, Roles: [serviceRole]|null, ProjectVisibility,
     Source: {Type, Location, AuthType, ReportBuildStatus}|null, SecondarySources: [...]|null,
     Webhook: {Url, BuildType, FilterGroups, ManualCreation, LastModifiedSecret}|null,
     EnvironmentVariables: [{Name, Type}]|null, Environment: {Type, Image, ComputeType, PrivilegedMode}|null,
     CollectionErrors?}

  ``BatchGetProjects`` takes 100 names; when a batch fails it is bisected until single names remain,
  and a name that still fails is kept with ``CollectionErrors`` and ``null`` fields (F-102), instead of
  losing the whole batch.
* ``source_credentials.json`` (list): ``{Arn, ServerType, AuthType}`` (metadata only, never tokens).
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from urllib.parse import urlsplit, urlunsplit

from aws_enumerator.coverage import CallResult
from aws_enumerator.registry import CollectorSpec

SPEC = CollectorSpec(
    name="codebuild", scope="regional", output_dir="codebuild", services=("codebuild",),
    tier=2, cost="low", noise="low", default=True, groups=("@compute",),
    actions=("codebuild:ListProjects", "codebuild:BatchGetProjects", "codebuild:ListSourceCredentials"),
    probe=("codebuild", "ListProjects", ()),
    outputs=(("resources.json", "list"), ("source_credentials.json", "list")),
    description="CodeBuild projects (role, source, webhook, env var names) and source credential metadata",
)

BATCH_SIZE = 100


def strip_userinfo(location: Optional[str]) -> Optional[str]:
    """``https://user:token@host/path`` -> ``https://host/path`` (other locations unchanged)."""
    if not location or "@" not in location or "://" not in location:
        return location
    parts = urlsplit(location)
    if "@" not in parts.netloc:
        return location
    return urlunsplit((parts.scheme, parts.netloc.rpartition("@")[2], parts.path, parts.query, parts.fragment))


def _source(src: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    if not src:
        return None
    return {"Type": src.get("type"), "Location": strip_userinfo(src.get("location")),
            "AuthType": (src.get("auth") or {}).get("type"), "ReportBuildStatus": src.get("reportBuildStatus"),
            "SourceIdentifier": src.get("sourceIdentifier")}


def _webhook(hook: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    if not hook:
        return None
    return {"Url": hook.get("url"), "BuildType": hook.get("buildType"), "FilterGroups": hook.get("filterGroups"),
            "ManualCreation": hook.get("manualCreation"), "LastModifiedSecret": hook.get("lastModifiedSecret")}


def project_item(p: Dict[str, Any]) -> Dict[str, Any]:
    """The stored projection of one CodeBuild project (no secret-bearing fields)."""
    env = p.get("environment") or {}
    role = p.get("serviceRole")
    return {
        "Type": "codebuild", "Arn": p.get("arn"), "Name": p.get("name"), "Roles": [role] if role else [],
        "ProjectVisibility": p.get("projectVisibility"), "Source": _source(p.get("source")),
        "SecondarySources": [_source(s) for s in p.get("secondarySources") or []],
        "Webhook": _webhook(p.get("webhook")),
        "EnvironmentVariables": [{"Name": v.get("name"), "Type": v.get("type")}
                                 for v in env.get("environmentVariables") or []],
        "Environment": {"Type": env.get("type"), "Image": env.get("image"), "ComputeType": env.get("computeType"),
                        "PrivilegedMode": env.get("privilegedMode")} if env else None,
    }


def _unreadable(ctx: Any, name: str, result: CallResult) -> Dict[str, Any]:
    item: Dict[str, Any] = {"Type": "codebuild", "Arn": ctx.arn("codebuild", f"project/{name}"), "Name": name,
                            "Roles": None, "ProjectVisibility": None, "Source": None, "SecondarySources": None,
                            "Webhook": None, "EnvironmentVariables": None, "Environment": None}
    err = result.collection_error()
    if err is not None:
        item["CollectionErrors"] = [err]
    return item


def _batch(ctx: Any, cb: Any, names: List[str], *, top: bool, out: List[Dict[str, Any]]) -> None:
    """Describe ``names``; on failure bisect until single names, which are kept with ``CollectionErrors``."""
    single = len(names) == 1
    kwargs: Dict[str, Any] = {}
    if single:
        kwargs["item"] = ctx.arn("codebuild", f"project/{names[0]}")
    elif not top:
        kwargs["optional"] = True   # a bisection probe: the single names below carry the real outcome
    result = ctx.call(cb, "batch_get_projects", names=names, **kwargs)
    if result.ok:
        out.extend(project_item(p) for p in result.get("projects") or [])
        missing = result.get("projectsNotFound") or []
        if missing:
            ctx.log.debug("%d projects vanished between list and describe", len(missing))
        return
    if single:
        out.append(_unreadable(ctx, names[0], result))
        return
    middle = len(names) // 2
    _batch(ctx, cb, names[:middle], top=False, out=out)
    _batch(ctx, cb, names[middle:], top=False, out=out)


def _projects(ctx: Any, cb: Any, out: List[Dict[str, Any]]) -> None:
    listed = ctx.paginate(cb, "list_projects", "projects", primary=True)
    names = sorted(set(listed.value))
    for start in range(0, len(names), BATCH_SIZE):
        _batch(ctx, cb, names[start:start + BATCH_SIZE], top=True, out=out)


def _source_credentials(ctx: Any, cb: Any) -> List[Dict[str, Any]]:
    result = ctx.call(cb, "list_source_credentials")
    infos = (result.get("sourceCredentialsInfos") or []) if result.ok else []
    return sorted(({"Arn": c.get("arn"), "ServerType": c.get("serverType"), "AuthType": c.get("authType")}
                   for c in infos), key=lambda c: str(c["Arn"]))


def collect(ctx: Any) -> None:
    cb = ctx.client("codebuild")
    projects: List[Dict[str, Any]] = []
    credentials: List[Dict[str, Any]] = []
    with ctx.section("projects"):
        _projects(ctx, cb, projects)
    projects.sort(key=lambda p: str(p["Arn"]))
    ctx.out.write("resources.json", projects)
    with ctx.section("source_credentials"):
        credentials = _source_credentials(ctx, cb)
    ctx.out.write("source_credentials.json", credentials)
    ctx.log.info("%d projects, %d source credentials", len(projects), len(credentials))
