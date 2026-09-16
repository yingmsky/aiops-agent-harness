# -*- coding: utf-8 -*-
"""自有工具协议：BaseAdapter.invoke(args, ctx) -> ToolResult（D4：不用 MCP）。

为什么不用 MCP：工具全部内部、同进程、同语言，ACL 已把模糊性隔离在边界，
工具签名稳定。MCP 的价值在「把工具开放给外部 Agent / 第三方」时才成立。
"""

import hashlib
import json
from dataclasses import dataclass, field


@dataclass
class ToolResult:
    ok: bool
    data: dict = field(default_factory=dict)
    error: str = ""

    def to_dict(self):
        return {"ok": self.ok, "data": self.data, "error": self.error}


@dataclass
class RunContext:
    """一次运行的执行上下文。凭证只通过 broker 的 ref 传递，从不带明文。"""

    tenant_id: str
    user_scopes: frozenset
    run_id: str
    broker: object          # CredentialBroker
    idem: object            # GuardStore（幂等，对应 redis-guard 不可丢实例）
    checkpointer: object    # Checkpointer
    control: object         # RunControl（超时 / 取消 / 暂停）
    trace: list = field(default_factory=list)
    policy_version: str = "pv-2026.09.1"

    def emit(self, event: str, data: dict):
        """落 trace。注意：数据必须是已经过 redact 的。"""
        self.trace.append({"event": event, "data": data})


class BaseAdapter:
    name = ""
    required_scopes: frozenset = frozenset()
    risk = "low"            # low / medium / high
    needs_credential = False
    retryable = True

    async def invoke(self, args: dict, ctx: RunContext, credential: str = "") -> ToolResult:
        raise NotImplementedError


def canonical_json(obj) -> str:
    """稳定序列化：用于参数摘要与幂等键。键序必须确定，否则同义异构会绕过去重。"""
    return json.dumps(obj, sort_keys=True, ensure_ascii=False,
                      separators=(",", ":"), default=str)


def digest(obj) -> str:
    return hashlib.sha256(canonical_json(obj).encode("utf-8")).hexdigest()
