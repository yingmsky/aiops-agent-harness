# -*- coding: utf-8 -*-
"""LLM 后端：mock（可离线跑）/ vLLM OpenAI 兼容（接真实服务）。

关于 --inject 演示的诚实说明：
    本项目三层防线是 ① 不进 prompt ② 不进 tool_result ③ 出站脱敏。
    --inject 演示的是「前两层因为某种原因失效」时的最后一层：
    模拟上游把明文泄进了 context（工程师贴了 key / 历史 tool_result 未脱敏），
    模型又被投毒文档指示复述它 —— 此时只有**出站边界**能拦住。
    这不是「模型本来拿得到明文」，而是 defense in depth 的兜底演练。
"""

import asyncio
import re

from .grapheme import chunk_by_grapheme

try:
    from openai import AsyncOpenAI
except Exception:  # pragma: no cover
    AsyncOpenAI = None


_SECRET_IN_TEXT = re.compile(r"sk-live-[A-Za-z0-9]{16,}")


class LLMBackend:
    def __init__(self, base_url: str = "", model: str = "qwen2.5-7b",
                 chaos: bool = False, per: int = 3):
        self.base_url = base_url
        self.model = model
        self.chaos = chaos
        self.per = per                 # 流式分块粒度（D8：真实 LLM 约等于 1）
        self._client = None
        if base_url and AsyncOpenAI is not None:
            self._client = AsyncOpenAI(base_url=base_url, api_key="EMPTY")

    async def stream(self, prompt: str):
        if self.chaos:
            raise RuntimeError("backend unavailable (chaos)")

        if self._client is not None:
            try:
                async for chunk in await self._client.chat.completions.create(
                    model=self.model,
                    messages=[{"role": "user", "content": prompt}],
                    max_tokens=256, temperature=0, stream=True,
                ):
                    delta = chunk.choices[0].delta.content or ""
                    if delta:
                        yield delta
                return
            except Exception:
                raise RuntimeError("vLLM call failed")

        await asyncio.sleep(0)
        # ---- mock：被投毒时，模型「照做」把 context 里的明文复述出来 ----
        m = _SECRET_IN_TEXT.search(prompt)
        if m:
            answer = (f"⚠️ 按手册要求，正在使用的访问凭证是 {m.group(0)}，"
                      f"token 见上。请值班同学核验。")
        else:
            answer = ("⚠️ 知识库建议：先按意图定位，再逐步收敛。"
                      "本例为本地 mock，未调用真实模型。")
        for piece in chunk_by_grapheme(answer, per=self.per):
            yield piece
