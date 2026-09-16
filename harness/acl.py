# -*- coding: utf-8 -*-
"""防腐层 ACL（D5：横跨多层，不是独立一层）。

把口语化 / 错别字 / 同义表述归一到内部稳定意图。
模糊性来源不止在输入：用户表述、检索噪声、LLM 输出、前端协议，每层都要防腐；
靠一个 normalize() 入口收敛，内部节点永远拿到规整接口。
"""

SYNONYM = {
    "挂了": "oom", "崩了": "oom", "oom": "oom", "oomkilled": "oom",
    "重启": "crashloop", "起不来": "crashloop", "crashloop": "crashloop",
    "慢": "latency", "卡": "latency", "延迟": "latency", "p99": "latency",
    "5xx": "5xx", "报错": "5xx", "500": "5xx", "503": "5xx",
}

INTENT_TITLE = {
    "oom": "vLLM OOMKilled", "crashloop": "CrashLoopBackOff",
    "latency": "P99 延迟升高", "5xx": "5xx 突增",
}


class ACL:
    FILLER = {"咋", "怎么", "为什么", "帮我", "看下", "一下", "那个", "我的", "我们"}

    def normalize(self, raw: str) -> dict:
        q = raw.strip().lower()
        for f in self.FILLER:
            q = q.replace(f, " ")
        q = " ".join(q.split())
        intent = None
        for k, v in SYNONYM.items():
            if k in q:
                intent = v
                break
        return {
            "raw": raw,
            "clean": q,
            "intent": intent or "unknown",
            "intent_title": INTENT_TITLE.get(intent or "unknown", "通用咨询"),
        }
