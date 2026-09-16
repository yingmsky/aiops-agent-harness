# -*- coding: utf-8 -*-
"""字素簇切分（D2 / D8）——流式输出不能把 emoji 切成两帧。

朴素 list(text) 按「码点」切，会把 U+26A0 + U+FE0F 的组合拆开，前端渲染错位。
真实 LLM 逐 token 输出约等于 per=1，所以 fallback 必须正确，不能退化成 list()。
"""

import unicodedata

try:
    import regex  # 支持 \X
except Exception:  # pragma: no cover
    regex = None


def _graphemes_stdlib(text: str):
    r"""零依赖字素簇切分。

    规则：base + 后续连续的「组合标记 / 变体选择符 / ZWJ / 肤色修饰符」视为一簇；
    区域指示符（国旗）成对合并。

    覆盖：
      - U+26A0 + U+FE0F          -> ⚠️
      - e + U+0301               -> é
      - 👨 + ZWJ + 👩 + ZWJ + 👧  -> 👨‍👩‍👧
      - U+1F1E8 + U+1F1F3        -> 🇨🇳
      - 👍 + U+1F3FB             -> 👍🏻

    ⚠️ 不是完整 UAX #29（未处理 Hangul 音节块、CRLF、Prepend）。
    生产环境装 `regex` 走 \X 分支；fallback 的定位是「没依赖也正确」，不是「永远正确」。
    """
    out, cur = [], ""
    i, n = 0, len(text)
    while i < n:
        ch = text[i]
        if not cur:
            cur = ch
            if (0x1F1E6 <= ord(ch) <= 0x1F1FF and i + 1 < n
                    and 0x1F1E6 <= ord(text[i + 1]) <= 0x1F1FF):
                cur += text[i + 1]
                i += 1
            i += 1
            continue
        cp = ord(ch)
        if (unicodedata.combining(ch)
                or cp in (0xFE0F, 0xFE0E)
                or cp == 0x200D
                or 0xE0100 <= cp <= 0xE01EF
                or 0x1F3FB <= cp <= 0x1F3FF):
            cur += ch
            i += 1
            continue
        out.append(cur)
        cur = ""
    if cur:
        out.append(cur)
    return out


def graphemes(text: str):
    if regex is not None:
        return regex.findall(r"\X", text)
    return _graphemes_stdlib(text)


def chunk_by_grapheme(text: str, per: int = 2):
    gs = graphemes(text)
    return ["".join(gs[i:i + per]) for i in range(0, len(gs), per)]
