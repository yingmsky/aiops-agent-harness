# -*- coding: utf-8 -*-
"""运行时控制：幂等 / 检查点 / 暂停恢复 / 超时 / 取消 / 重试。

JD 原文要求：「完善同步、异步、流式及长时间任务的超时、取消、重试、幂等、
检查点、暂停恢复和人工介入机制」——这一节逐条对应。

Redis 双实例的第二次兑现（D6）：
  - GuardStore  = redis-guard（noeviction + AOF，不可丢）—— 放幂等键与检查点。
    幂等键被驱逐 = 去重失效 = 重复扣款 / 重复重启，属于**不可丢**状态。
  - TieredCache = redis-state（allkeys-lru，可丢）—— 放答案缓存，丢了只是重算。
"""

import asyncio
import json
import os
import time
from typing import Optional

from .protocol import canonical_json

WORKDIR = ".runs"


class GuardStore:
    """幂等 + 检查点存储（不可丢实例）。mock 模式下落内存 / 落盘。"""

    def __init__(self, workdir: str = WORKDIR, persist: bool = False):
        self._mem = {}
        self.workdir = workdir
        self.persist = persist
        if persist:
            os.makedirs(workdir, exist_ok=True)

    def _path(self, key: str) -> str:
        return os.path.join(self.workdir, key.replace("/", "_") + ".json")

    def put_if_absent(self, key: str, value: dict, ttl: int = 3600) -> bool:
        """原子占位。True = 首次（可以执行）；False = 已存在（幂等重放）。"""
        if self.persist:
            p = self._path(key)
            if os.path.exists(p):
                return False
            with open(p, "w", encoding="utf-8") as f:
                json.dump({"value": value, "exp": time.time() + ttl}, f,
                          ensure_ascii=False)
            return True
        if key in self._mem:
            return False
        self._mem[key] = {"value": value, "exp": time.time() + ttl}
        return True

    def get(self, key: str) -> Optional[dict]:
        if self.persist:
            p = self._path(key)
            if not os.path.exists(p):
                return None
            with open(p, encoding="utf-8") as f:
                rec = json.load(f)
            return rec["value"]
        rec = self._mem.get(key)
        return rec["value"] if rec else None

    def put(self, key: str, value: dict, ttl: int = 3600):
        if self.persist:
            with open(self._path(key), "w", encoding="utf-8") as f:
                json.dump({"value": value, "exp": time.time() + ttl}, f,
                          ensure_ascii=False)
        else:
            self._mem[key] = {"value": value, "exp": time.time() + ttl}

    def release(self, key: str):
        """释放幂等占位。

        用于「暂停 / 中断」场景：该步骤其实没有真正落地，占位必须回滚，
        否则恢复后会误判为「已执行过」而直接跳过 —— 幂等键一旦写错时机，
        就从「防重」变成了「吞掉重试」。
        """
        self._mem.pop(key, None)
        if self.persist and os.path.exists(self._path(key)):
            os.remove(self._path(key))


def idem_key(tenant: str, tool: str, args: dict) -> str:
    """幂等键 = 租户 + 工具 + 参数规范摘要。

    参数必须 canonical（键序稳定），否则 {"a":1,"b":2} 与 {"b":2,"a":1}
    会被当成两次不同的调用 —— 这是自写幂等最常见的坑。
    """
    import hashlib
    raw = f"{tenant}|{tool}|{canonical_json(args)}"
    return "idem_" + hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


class Checkpointer:
    """节点级检查点：支持 --resume <run_id> 从中断处继续。"""

    def __init__(self, workdir: str = WORKDIR, persist: bool = False):
        self._mem = {}
        self.workdir = workdir
        self.persist = persist
        if persist:
            os.makedirs(workdir, exist_ok=True)

    def _path(self, run_id: str) -> str:
        return os.path.join(self.workdir, f"{run_id}.ckpt.json")

    def save(self, run_id: str, node: str, payload: dict):
        rec = {"run_id": run_id, "node": node, "payload": payload,
               "at": round(time.time(), 3)}
        if self.persist:
            with open(self._path(run_id), "w", encoding="utf-8") as f:
                json.dump(rec, f, ensure_ascii=False)
        self._mem[run_id] = rec
        return rec

    def load(self, run_id: str):
        if self.persist and os.path.exists(self._path(run_id)):
            with open(self._path(run_id), encoding="utf-8") as f:
                return json.load(f)
        return self._mem.get(run_id)

    def clear(self, run_id: str):
        self._mem.pop(run_id, None)
        if self.persist and os.path.exists(self._path(run_id)):
            os.remove(self._path(run_id))


class Paused(Exception):
    """暂停信号：不是错误，是一种可恢复的中间态。"""


class RunControl:
    """超时 / 取消 / 暂停。"""

    def __init__(self, timeout: float = 30.0, pause_after: str = ""):
        self.timeout = timeout
        self.pause_after = pause_after      # 在哪个节点后暂停
        self.cancelled = False
        self.paused_at = None

    def cancel(self):
        self.cancelled = True

    def should_pause(self, node: str) -> bool:
        return bool(self.pause_after) and node == self.pause_after

    async def run_step(self, coro, step: str):
        """带超时的单步执行。超时按「取消」处理，不抛 5xx。"""
        if self.cancelled:
            raise asyncio.CancelledError(f"run cancelled before {step}")
        try:
            return await asyncio.wait_for(coro, timeout=self.timeout)
        except (asyncio.TimeoutError, TimeoutError):
            raise TimeoutError(f"step {step} exceeded {self.timeout}s")


async def with_retry(fn, *, attempts: int = 3, base_delay: float = 0.05,
                     retry_on=(Exception,), on_retry=None):
    """指数退避重试。只对可重试错误重试；业务错误（如权限拒绝）不重试。"""
    last = None
    for i in range(attempts):
        try:
            return await fn()
        except retry_on as e:
            last = e
            if i == attempts - 1:
                break
            delay = base_delay * (2 ** i)
            if on_retry:
                on_retry(i + 1, delay, e)
            await asyncio.sleep(delay)
    raise last
