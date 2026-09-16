# -*- coding: utf-8 -*-
"""人工介入（human-in-the-loop）审批门。

关键不是「弹个确认框」，而是：

> **`userConfirmed: true` 不是授权。**

审批必须密码学绑定到「具体动作 + 参数 + 目标 + 策略版本 + 过期时间」。
否则模型在审批通过之后、执行之前改一下参数，审批就形同虚设 —— 这是 TOCTOU。

所以本实现做两件事：
  1. 审批对象是 **ActionBinding**（含 args_digest），不是一句「可以吗」；
  2. 执行前**重新校验 args_digest**，不一致即作废（与 credential.resolve 双重校验）。

三条出口：
  - granted  -> 正常执行
  - denied   -> 跳过该工具，继续降级（不整体失败）
  - timeout  -> 走 L3 空包收口（复用降级哲学：失败之后系统处在什么状态，比失败本身重要）
"""

import asyncio
import hashlib
import json
import time
from dataclasses import dataclass, asdict

POLICY_VERSION = "pv-2026.09.1"


@dataclass(frozen=True)
class ActionBinding:
    """审批绑定体：审批的**是这个**，不是一句话。"""
    tool: str
    args_digest: str
    target: str
    policy_version: str
    expires_at: float
    risk: str

    def fingerprint(self) -> str:
        payload = json.dumps(asdict(self), sort_keys=True, ensure_ascii=False)
        return hashlib.sha256(payload.encode()).hexdigest()[:16]

    def to_dict(self):
        d = asdict(self)
        d["fingerprint"] = self.fingerprint()
        return d


class ApprovalOutcome:
    GRANTED = "granted"
    DENIED = "denied"
    TIMEOUT = "timeout"


class ApprovalGate:
    """审批门。mode: auto（自动批准）/ deny（自动拒绝）/ timeout（模拟无人响应）。

    真实系统里审批来自 IM / 工单 / Webhook；这里用 mode 把三条分支都跑出来：
    granted / denied / timeout，三者把系统留在不同的状态。
    """

    def __init__(self, mode: str = "auto", timeout: float = 3.0):
        if mode not in ("auto", "deny", "timeout"):
            raise ValueError(f"bad approval mode: {mode}")
        self.mode = mode
        self.timeout = timeout
        self.history = []

    async def require(self, binding: ActionBinding, tenant: str):
        """返回 (outcome, extra_dict)。"""
        if self.mode == "deny":
            out = (ApprovalOutcome.DENIED, {"reason": "operator_denied"})
        elif self.mode == "timeout":
            try:
                await asyncio.wait_for(asyncio.sleep(60), timeout=self.timeout)
                out = (ApprovalOutcome.GRANTED, {})
            except (asyncio.TimeoutError, TimeoutError):
                out = (ApprovalOutcome.TIMEOUT,
                       {"reason": f"no_response_in_{self.timeout}s"})
        else:
            await asyncio.sleep(0)
            out = (ApprovalOutcome.GRANTED, {"approved_by": "operator:auto"})

        self.history.append({
            "tenant": tenant,
            "binding": binding.to_dict(),
            "outcome": out[0],
            "at": round(time.time(), 3),
        })
        return out

    def verify(self, binding: ActionBinding, args_digest_now: str) -> bool:
        """执行前复核：参数是否还是当初被批准的那一份。"""
        return binding.args_digest == args_digest_now
