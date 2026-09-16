# -*- coding: utf-8 -*-
"""凭证代管（Credential Broker）——本项目最关键的一块。

Agent 拿着凭证去调用工具，风险集中在三处：凭证被写进 prompt、被复述进日志、
被长期持有。对应三条设计要求（每一条都在代码层强制，不依赖 prompt 约束）：
  1. **不进 prompt**：模型与 Agent 循环里只出现 cred_ref，绝不出现明文。
  2. **不进 trace / 日志**：所有出站文本（SSE 事件、trace 落盘、工具参数）先过脱敏。
  3. **用完即弃（Zero Standing Privilege）**：JIT 签发，TTL 短，任务结束 / 换参数即失效。

两个传统安全没有、Agent 特有的失败模式，这里都在代码层强制（enforce in code,
not in prompt）：
  - **凭证被模型复述出去**  -> StreamingRedactor 在出站边界 fail-closed 截断。
  - **TOCTOU（批准后改参数）** -> lease 绑定 args_digest，执行时校验，改一个字就作废。

实现要点：
  - 明文 secret **从不落库**：resolve() 用 HMAC(root_secret, ref) 现算，用完即弃。
    Broker 内存里只有 lease 元数据，没有明文。
  - token 自带 HMAC 签名与过期时间，校验不依赖存储（可被下游无状态验签）。
"""

import hashlib
import hmac
import json
import os
import re
import secrets
import time
from dataclasses import dataclass, field

DEFAULT_TTL = 15 * 60          # 15 分钟（演示里可用 --ttl 调成秒级）
POLICY_VERSION = "pv-2026.09.1"


# --------------------------------------------------------------------------
# 明文形态：故意做成「一眼就是密钥」的样子，便于演示脱敏是否真的生效
# --------------------------------------------------------------------------
SECRET_PREFIX = "sk-live-"


def _derive_secret(root: bytes, ref: str) -> str:
    """由 ref 派生明文。Broker 不存储明文，只存 root secret。"""
    mac = hmac.new(root, f"secret:{ref}".encode(), hashlib.sha256).hexdigest()
    return SECRET_PREFIX + mac[:24]


# --------------------------------------------------------------------------
# 泄露检测：这是「不进 prompt / 不进 trace」的强制执行点
# --------------------------------------------------------------------------
LEAK_PATTERNS = [
    (r"sk-live-[A-Za-z0-9]{16,}", "live_secret"),
    (r"sk-[A-Za-z0-9]{20,}", "openai_style_key"),
    (r"AKIA[0-9A-Z]{16}", "aws_access_key"),
    (r"v1\.[A-Za-z0-9_-]{1,32}\.[A-Za-z0-9_-]{1,32}\.[a-f0-9]{8}\.\d+\.[A-Za-z0-9]{6,}\.[a-f0-9]{8,}",
     "broker_token"),
    (r"-----BEGIN [A-Z ]*PRIVATE KEY-----", "private_key"),
]
_LEAK_RE = [(re.compile(p), name) for p, name in LEAK_PATTERNS]


def detect_leak(text: str):
    """返回 [(pattern_name, matched_snippet_head)]，空列表表示安全。"""
    if not text:
        return []
    hits = []
    for rx, name in _LEAK_RE:
        m = rx.search(text)
        if m:
            # 只回显前 6 个字符 + 掩码，避免检测日志本身成为泄露源
            s = m.group(0)
            hits.append((name, s[:6] + "*" * max(0, len(s) - 6)))
    return hits


def redact(text: str, ref_hint: str = ""):
    """一次性脱敏（用于非流式文本，如工具参数、日志行）。"""
    if not text:
        return text, []
    hits = detect_leak(text)
    if not hits:
        return text, []
    out = text
    for rx, _ in _LEAK_RE:
        out = rx.sub(f"[REDACTED{':' + ref_hint if ref_hint else ''}]", out)
    return out, hits


class StreamingRedactor:
    """流式脱敏（用于 SSE 逐段输出）。

    流式下最难的点是 secret 可能**跨 chunk 边界**：chunk1 结尾 "sk-li"、
    chunk2 开头 "ve-xxxx"。所以不能无脑来一段吐一段。

    朴素做法是固定保留一段 tail，但那会牺牲流式体验（tail 太长则几乎不吐字）。
    这里的做法是**按锚点判定**：只有 buf 尾部真的出现了某个密钥形态的起始片段
    （"sk-" / "AKIA" / "v1." / "-----BEGIN"）时才保留它，否则整段放行。
    —— 用「按需缓冲」替代「固定缓冲」，流式观感和安全性都要。

    一旦确认泄露，立即 fail-closed：截断到泄露起点，丢弃后续全部内容。
    """

    ANCHORS = ("sk", "AKIA", "v1.", "-----BEGIN")
    TAIL = 12           # 固定兜底：覆盖「锚点被切在 chunk 边界」的情况
    MAX_HOLD = 96       # 锚点后跟了这么长还不成 secret，说明不是，放行

    def __init__(self):
        self._buf = ""
        self._blocked = False

    @property
    def blocked(self):
        return self._blocked

    def feed(self, chunk: str):
        """返回 (safe_text, blocked_now)。"""
        if self._blocked:
            return "", False                      # 已拦截，后续全部丢弃
        self._buf += chunk

        if detect_leak(self._buf):
            starts = [m.start() for rx, _ in _LEAK_RE
                      for m in [rx.search(self._buf)] if m]
            safe = self._buf[:min(starts)]
            self._buf = ""
            self._blocked = True
            return safe, True

        # 默认只留固定 TAIL；若尾部出现密钥形态的起始片段，则连它一起留着等完整。
        # ANCHORS 用 "sk" 而不是 "sk-live-"：分块会把长锚点切碎在 chunk 边界上，
        # 锚点必须足够短才能跨块命中 —— 这是第一版漏拦截的根因。
        cut_anchor = len(self._buf)
        for a in self.ANCHORS:
            i = self._buf.rfind(a)
            if i != -1:
                cut_anchor = min(cut_anchor, i)
        cut_tail = max(0, len(self._buf) - self.TAIL)
        cut = min(cut_anchor, cut_tail)
        if len(self._buf) - cut > self.MAX_HOLD:
            cut = cut_tail          # 锚点后拖太长还不成 secret -> 不是 secret
        out, self._buf = self._buf[:cut], self._buf[cut:]
        return out, False

    def flush(self):
        if self._blocked:
            self._buf = ""
            return ""
        out, self._buf = self._buf, ""
        return out


# --------------------------------------------------------------------------
# Lease：凭证租约
# --------------------------------------------------------------------------
@dataclass
class Lease:
    ref: str                 # 可进 prompt / trace 的引用（本身不含任何秘密）
    tenant: str
    tool: str
    scopes: frozenset
    args_digest: str         # ★ 绑定参数：防 TOCTOU
    issued_at: float
    expires_at: float
    revoked: bool = False
    use_count: int = 0

    def to_dict(self):
        """可安全进 trace 的视图——注意：没有 token，没有明文。"""
        return {
            "cred_ref": self.ref,
            "tenant": self.tenant,
            "tool": self.tool,
            "scopes": sorted(self.scopes),
            "args_digest": self.args_digest[:12],
            "ttl_left_s": round(max(0.0, self.expires_at - time.time()), 1),
            "revoked": self.revoked,
            "use_count": self.use_count,
        }


class CredentialError(Exception):
    pass


class CredentialBroker:
    """凭证代管：签发、解出、撤销、扫过期。

    token 形态：v1.<tenant>.<tool>.<args8>.<exp>.<nonce>.<sig16>
    sig = HMAC-SHA256(root_secret, 前面各段)，下游可无状态验签。
    """

    def __init__(self, root_secret: bytes = None, default_ttl: int = DEFAULT_TTL):
        self._root = root_secret or secrets.token_bytes(32)
        self.default_ttl = default_ttl
        self._leases: dict = {}
        self._counter = 0

    # ---------------- 签发 ----------------
    def issue(self, tenant: str, tool: str, scopes, args_digest: str,
              ttl: int = None) -> Lease:
        """JIT 签发。调用方拿到的是 Lease，**不是明文**。"""
        self._counter += 1
        exp = int(time.time() + (ttl if ttl is not None else self.default_ttl))
        nonce = secrets.token_hex(4)
        payload = f"v1.{tenant}.{tool}.{args_digest[:8]}.{exp}.{nonce}"
        sig = hmac.new(self._root, payload.encode(), hashlib.sha256).hexdigest()[:16]
        token = f"{payload}.{sig}"
        ref = "cred_" + hashlib.sha256(token.encode()).hexdigest()[:12]
        lease = Lease(
            ref=ref, tenant=tenant, tool=tool,
            scopes=frozenset(scopes), args_digest=args_digest,
            issued_at=time.time(), expires_at=exp,
        )
        self._leases[ref] = lease
        return lease

    # ---------------- 验签（下游可独立调用） ----------------
    def verify_token(self, token: str) -> bool:
        try:
            payload, sig = token.rsplit(".", 1)
        except ValueError:
            return False
        expect = hmac.new(self._root, payload.encode(), hashlib.sha256).hexdigest()[:16]
        if not hmac.compare_digest(sig, expect):
            return False
        parts = payload.split(".")
        return len(parts) == 6 and int(parts[4]) > time.time()

    # ---------------- 解出明文（最后一跳） ----------------
    def resolve(self, ref: str, tenant: str, tool: str, args_digest: str) -> str:
        """在真正调用工具的最后一跳才解出明文。

        四要素全校验：存在 / 未撤销 / 未过期 / tenant+tool+args_digest 一致。
        任何一项不符都抛 CredentialError —— 这是防 TOCTOU 的关键：
        审批通过后模型若改了参数，args_digest 变了，凭证自动作废。
        """
        lease = self._leases.get(ref)
        if lease is None:
            raise CredentialError("unknown_cred_ref")
        if lease.revoked:
            raise CredentialError("credential_revoked")
        if time.time() > lease.expires_at:
            raise CredentialError("credential_expired")
        if lease.tenant != tenant:
            raise CredentialError("tenant_mismatch")
        if lease.tool != tool:
            raise CredentialError("tool_mismatch")
        if lease.args_digest != args_digest:
            # ★ 参数被改 -> 凭证作废（TOCTOU 防线）
            raise CredentialError("args_digest_mismatch")
        lease.use_count += 1
        return _derive_secret(self._root, ref)

    # ---------------- 生命周期 ----------------
    def revoke(self, ref: str):
        lease = self._leases.get(ref)
        if lease:
            lease.revoked = True

    def revoke_all(self, tenant: str = None):
        """任务结束 / Kill Switch 触发时整体撤销。"""
        for lease in self._leases.values():
            if tenant is None or lease.tenant == tenant:
                lease.revoked = True

    def sweep(self) -> int:
        now = time.time()
        dead = [r for r, l in self._leases.items() if now > l.expires_at]
        for r in dead:
            self._leases.pop(r, None)
        return len(dead)

    def leases(self, tenant: str = None):
        return [l for l in self._leases.values() if tenant is None or l.tenant == tenant]

    def audit_view(self, tenant: str = None) -> str:
        """审计视图：只有 ref 与元数据，永远看不到明文。"""
        return json.dumps([l.to_dict() for l in self.leases(tenant)],
                          ensure_ascii=False, indent=2)
