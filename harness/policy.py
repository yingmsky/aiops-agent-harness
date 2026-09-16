# -*- coding: utf-8 -*-
"""多租户隔离 + 权限交集 + 风险分级。

权限是四元交集，不是二元的「有没有权限」：
    effective = 用户上界 ∩ 组织(租户)策略 ∩ 工作负载角色 ∩ 本次任务委托

推论：**Agent 只能收窄用户权限，不能放大。**
子 Agent 拿的是父的**子集**，永不超集。

多租户隔离的四道闸：
    工具白名单 > 凭证 scoping > 模型 entitlement > 计算隔离
这里实现前三道（计算隔离要靠 K8s / 沙箱层，代码里以 quota 表达）。
"""

from dataclasses import dataclass, field

POLICY_VERSION = "pv-2026.09.1"


@dataclass(frozen=True)
class Tenant:
    id: str
    allowed_tools: frozenset          # 工具白名单：第一道闸
    max_scopes: frozenset             # 组织策略上界：第二道闸
    quota_per_run: int = 8            # 计算隔离的资源表达
    model_entitlement: str = "qwen2.5-7b"   # 第三道闸：能用哪个模型


TENANTS = {
    "acme": Tenant(
        id="acme",
        allowed_tools=frozenset({"kb_query", "k8s_describe", "k8s_restart"}),
        max_scopes=frozenset({"kb:read", "k8s:read", "k8s:write"}),
        quota_per_run=8,
        model_entitlement="qwen2.5-7b",
    ),
    # 只读租户：用来演示「跨租户越权尝试」被拦在第一道闸
    "globex": Tenant(
        id="globex",
        allowed_tools=frozenset({"kb_query"}),
        max_scopes=frozenset({"kb:read"}),
        quota_per_run=2,
        model_entitlement="qwen2.5-1.5b",
    ),
}

# 工作负载身份（Agent 自己的角色，跟用户身份是两回事）
WORKLOAD_ROLE_SCOPES = {
    "sre-runner": frozenset({"kb:read", "k8s:read", "k8s:write"}),
    "readonly-bot": frozenset({"kb:read", "k8s:read"}),
}

# 工具风险分级：决定是否需要人工审批
TOOL_RISK = {
    "kb_query": "low",
    "k8s_describe": "low",
    "k8s_restart": "high",     # 有副作用 -> 必须过审批门
    "secret_rotate": "high",
}


def get_tenant(tenant_id: str) -> Tenant:
    if tenant_id not in TENANTS:
        raise KeyError(f"unknown tenant: {tenant_id}")
    return TENANTS[tenant_id]


def effective_scopes(user_scopes, tenant: Tenant,
                     workload_role: str = "sre-runner",
                     task_delegation=frozenset()) -> frozenset:
    """四元交集。user / tenant / workload / task_delegation 缺一不可。"""
    role = WORKLOAD_ROLE_SCOPES.get(workload_role, frozenset())
    return (frozenset(user_scopes) & tenant.max_scopes & role
            & frozenset(task_delegation))


def check_tool_allowed(tenant: Tenant, tool: str):
    """第一道闸：工具白名单。返回 (allowed, reason)。"""
    if tool not in tenant.allowed_tools:
        return False, (f"tool {tool!r} not in tenant {tenant.id!r} allowlist "
                       f"(allowed={sorted(tenant.allowed_tools)})")
    return True, ""


def check_scopes(effective: frozenset, required: frozenset):
    """第二道闸：凭证 scoping。"""
    missing = frozenset(required) - effective
    if missing:
        return False, f"missing scopes: {sorted(missing)}"
    return True, ""


def risk_level(tool: str, args: dict) -> str:
    base = TOOL_RISK.get(tool, "low")
    # 风险可被参数抬高：删生产 / 批量操作直接升 high
    target = str(args.get("target", ""))
    if "prod" in target:
        return "high"
    if int(args.get("replicas", 1) or 1) > 1:
        return "medium"
    return base
