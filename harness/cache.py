# -*- coding: utf-8 -*-
"""三级降级缓存（D1 完备性 + D7 降级产物不进缓存）。

L1 进程内 LRU(60s) -> L2 Redis(300s) -> L3 空包
任意一级可用即返回；全不可用也不抛 5xx。

D7 的教训：**降级产物永远不能进缓存。**
缓存的是「成功的结果」，不是「失败的记录」。
否则一次 3 秒的后端抖动，会被 L2 的 300s TTL 拉成 5 分钟的故障窗口，
而且监控面板还全绿（200 + 空内容比 500 更难发现）。

多租户：key 强制带 tenant 前缀 —— 没有前缀的缓存是跨租户数据泄露的经典入口。
"""

import json
import time
from collections import OrderedDict

try:
    import redis as _redis
except Exception:  # pragma: no cover
    _redis = None


class TieredCache:
    def __init__(self, redis_url: str = "", l1_ttl: int = 60, l2_ttl: int = 300):
        self.l1_ttl = l1_ttl
        self.l2_ttl = l2_ttl
        self._l1 = OrderedDict()
        self._redis = None
        if redis_url and _redis is not None:
            try:
                self._redis = _redis.Redis.from_url(redis_url)
                self._redis.ping()
            except Exception:
                self._redis = None

    # ---------------- key 构造 ----------------
    @staticmethod
    def key(tenant: str, intent: str, clean: str) -> str:
        return f"t:{tenant}|q:{intent}:{clean}"

    # ---------------- L1 ----------------
    def _l1_get(self, key):
        if key not in self._l1:
            return None
        payload, exp = self._l1[key]
        if time.time() > exp:
            self._l1.pop(key, None)
            return None
        self._l1.move_to_end(key)
        return payload

    def _l1_put(self, key, payload):
        self._l1[key] = (payload, time.time() + self.l1_ttl)
        self._l1.move_to_end(key)
        while len(self._l1) > 1024:
            self._l1.popitem(last=False)

    # ---------------- L2 ----------------
    def _l2_get(self, key):
        if not self._redis:
            return None
        try:
            raw = self._redis.get(key)
            return json.loads(raw) if raw else None
        except Exception:
            return None

    def _l2_put(self, key, payload):
        if not self._redis:
            return
        try:
            self._redis.setex(key, self.l2_ttl, json.dumps(payload, ensure_ascii=False))
        except Exception:
            pass

    # ---------------- 对外 ----------------
    def get(self, key: str):
        """返回 (tier, payload)。tier=3 表示空包收口。"""
        p = self._l1_get(key)
        if p is not None:
            return 1, p
        p = self._l2_get(key)
        if p is not None:
            self._l1_put(key, p)
            return 2, p
        return 3, None

    def put(self, key, payload):
        self._l1_put(key, payload)
        self._l2_put(key, payload)
