# -*- coding: utf-8 -*-
"""Agent 编排主循环（自写 Graph，非 LangGraph —— 节点可审计）。

一次查询在这条链路上走过的机制：

| 机制                 | 本文件落点                                        |
|----------------------|--------------------------------------------------|
| 模型交互             | llm.stream()（mock / vLLM 双模）                  |
| 任务规划             | plan() 按意图产出工具序列                          |
| 工具调用             | BaseAdapter.invoke + 凭证最后一跳解出              |
| 状态维护             | Checkpointer + GuardStore（不可丢实例）            |
| 结果校验             | validation 事件（空答案 / 缺引用 / 凭证泄漏）      |
| 错误恢复             | 三级降级 + L3 空包（D1/D7）                        |
| 流式                 | SSE 事件流 + 字素簇切分 + 流式脱敏                 |
| 超时 / 取消          | RunControl.run_step + cancel()                    |
| 重试                 | with_retry（指数退避，只对可重试错误）             |
| 幂等                 | idem_key -> GuardStore.put_if_absent               |
| 检查点 / 暂停恢复    | Checkpointer + --resume / --pause-after            |
| 人工介入             | ApprovalGate（绑定 args_digest，防 TOCTOU）        |
| 凭证管理 / 权限控制  | CredentialBroker + 四元权限交集                    |
| 多租户资源隔离       | tenant 前缀贯穿：工具白名单 / 凭证 / 缓存 / 配额   |
"""

import asyncio
import json
import time
import uuid

from .acl import ACL
from .approval import ActionBinding, ApprovalGate, ApprovalOutcome
from .cache import TieredCache
from .credentials import (CredentialBroker, CredentialError, StreamingRedactor,
                          detect_leak, redact)
from .llm import LLMBackend
from .policy import (check_scopes, check_tool_allowed, effective_scopes,
                     get_tenant, risk_level)
from .protocol import RunContext, digest
from .runtime import (Checkpointer, GuardStore, RunControl, idem_key, with_retry)
from .tools import build_tools

WORKLOAD_ROLE = "sre-runner"


class RunConfig:
    def __init__(self, tenant_id="acme", user_scopes=None, inject=False,
                 tamper=False, chaos=False, approval_mode="auto",
                 timeout=30.0, pause_after="", resume_from=None,
                 persist=False, per=3, model="qwen2.5-7b", base_url="",
                 redis_url=""):
        self.tenant_id = tenant_id
        self.user_scopes = frozenset(user_scopes or {"kb:read", "k8s:read", "k8s:write"})
        self.inject = inject
        self.tamper = tamper
        self.chaos = chaos
        self.approval_mode = approval_mode
        self.timeout = timeout
        self.pause_after = pause_after
        self.resume_from = resume_from
        self.persist = persist
        self.per = per
        self.model = model
        self.base_url = base_url
        self.redis_url = redis_url


def plan(intent: str, clean: str) -> list:
    """任务规划：按意图产出 (tool, args) 序列。静态 DAG，所以自写编排足够（D3）。"""
    if intent == "oom":
        return [("kb_query", {"intent": intent, "query": clean}),
                ("k8s_describe", {"target": "vllm-0"}),
                ("k8s_restart", {"target": "vllm-0", "replicas": 1})]
    if intent in ("crashloop", "latency"):
        return [("kb_query", {"intent": intent, "query": clean}),
                ("k8s_describe", {"target": "vllm-0"})]
    if intent == "5xx":
        return [("kb_query", {"intent": intent, "query": clean})]
    return [("kb_query", {"intent": "unknown", "query": clean})]


async def run_agent(raw_query: str, cfg: RunConfig):
    """异步生成器：yield SSE 事件 dict。"""
    tenant = get_tenant(cfg.tenant_id)
    run_id = cfg.resume_from or ("run_" + uuid.uuid4().hex[:10])

    broker = CredentialBroker()
    gate = ApprovalGate(mode=cfg.approval_mode)
    idem = GuardStore(persist=cfg.persist)
    ckpt = Checkpointer(persist=cfg.persist)
    control = RunControl(timeout=cfg.timeout, pause_after=cfg.pause_after)
    cache = TieredCache(redis_url=cfg.redis_url)
    llm = LLMBackend(base_url=cfg.base_url, model=cfg.model,
                     chaos=cfg.chaos, per=cfg.per)
    tools = build_tools(inject=cfg.inject)
    acl = ACL()

    ctx = RunContext(tenant_id=tenant.id, user_scopes=cfg.user_scopes,
                     run_id=run_id, broker=broker, idem=idem,
                     checkpointer=ckpt, control=control)

    yield {"event": "run_start", "data": {
        "run_id": run_id, "tenant": tenant.id,
        "workload_role": WORKLOAD_ROLE,
        "model_entitlement": tenant.model_entitlement,
        "policy_version": ctx.policy_version,
        "resumed": bool(cfg.resume_from),
    }}

    # ---------------- 1. 意图归一 + 任务规划 ----------------
    norm = acl.normalize(raw_query)
    steps = plan(norm["intent"], norm["clean"])
    yield {"event": "thinking", "data": {
        "intent": norm["intent"], "intent_title": norm["intent_title"],
        "plan": [t for t, _ in steps],
    }}

    # ---------------- 2. 三级降级：先查缓存（key 带 tenant） ----------------
    cache_key = TieredCache.key(tenant.id, norm["intent"], norm["clean"])
    tier, cached = cache.get(cache_key)
    if cached is not None:
        yield {"event": "citation", "data": {"from": f"cache-L{tier}",
                                             "doc": cached.get("doc", "")}}
        safe, hits = redact(cached["answer"])
        if hits:
            yield {"event": "security_block", "data": {"layer": "cache_read",
                                                       "hits": hits}}
            safe = "[REDACTED]"
        for piece in _stream(safe):
            yield {"event": "answer", "data": {"delta": piece}}
        yield {"event": "done", "data": {"source": f"cache-L{tier}"}}
        return

    # ---------------- 3. 逐步执行工具 ----------------
    kb_text = ""
    doc_ids = []
    degraded = False
    executed = 0
    binding_seen = {}
    leaked_plain = ""

    # 恢复：跳过已落检查点的节点，并把中断时的状态一并还原
    resume_index = -1
    if cfg.resume_from:
        rec = ckpt.load(cfg.resume_from)
        if rec:
            resume_index = rec["payload"].get("index", -1)
            kb_text = rec["payload"].get("kb_text", "")
            doc_ids = rec["payload"].get("doc_ids", [])
            yield {"event": "resumed", "data": {
                "from_node": rec["node"], "index": resume_index,
                "restored_kb_chars": len(kb_text),
                "restored_citations": len(doc_ids)}}

    for idx, (tool_name, args) in enumerate(steps):
        adapter = tools[tool_name]

        # 注意是 < 不是 <=：resume_index 指向的节点是被「暂停」的节点，
        # 它并没有执行完（这也是为什么暂停时要 release 掉它的幂等键）。
        if idx < resume_index:
            yield {"event": "resume_skip", "data": {
                "tool": tool_name, "reason": "already checkpointed"}}
            continue

        # 3.0 配额（计算隔离的资源表达）
        if executed >= tenant.quota_per_run:
            yield {"event": "quota_exceeded", "data": {
                "tenant": tenant.id, "quota": tenant.quota_per_run}}
            break

        # 3.1 工具白名单（多租户隔离第一道闸）
        ok, why = check_tool_allowed(tenant, tool_name)
        if not ok:
            yield {"event": "policy_deny", "data": {"tool": tool_name, "reason": why}}
            continue

        # 3.2 四元权限交集
        eff = effective_scopes(cfg.user_scopes, tenant, WORKLOAD_ROLE,
                               adapter.required_scopes)
        ok, why = check_scopes(eff, adapter.required_scopes)
        if not ok:
            yield {"event": "scope_deny", "data": {"tool": tool_name, "reason": why}}
            continue

        # 3.3 幂等
        ikey = idem_key(tenant.id, tool_name, args)
        first = idem.put_if_absent(ikey, {"run_id": run_id, "at": time.time()})
        if not first:
            prev = idem.get(ikey) or {}
            yield {"event": "idempotent_replay", "data": {
                "tool": tool_name, "idem_key": ikey,
                "first_run_id": prev.get("run_id", "?")}}
            continue

        # 3.4 暂停（长时间任务的暂停恢复）
        if control.should_pause(tool_name):
            ckpt.save(run_id, tool_name, {"args": args, "index": idx,
                                          "kb_text": kb_text, "doc_ids": doc_ids})
            # 该步骤并未真正落地 -> 回滚幂等占位，否则恢复后会被误判为已执行
            idem.release(ikey)
            if lease:
                broker.revoke(lease.ref)
            yield {"event": "paused", "data": {
                "run_id": run_id, "at_node": tool_name, "index": idx,
                "resume_hint": f"--persist --resume {run_id}"}}
            yield {"event": "done", "data": {"source": "paused"}}
            return

        # 3.5 JIT 签发凭证（只发 ref，不发明文）
        args_digest = digest(args)
        lease = None
        if adapter.needs_credential:
            lease = broker.issue(tenant.id, tool_name,
                                 eff & adapter.required_scopes, args_digest)
            yield {"event": "credential_issued", "data": lease.to_dict()}

        # 3.6 风险分级 + 人工介入
        risk = risk_level(tool_name, args)
        if risk == "high":
            binding = ActionBinding(
                tool=tool_name, args_digest=args_digest,
                target=str(args.get("target", "")),
                policy_version=ctx.policy_version,
                expires_at=time.time() + 300, risk=risk,
            )
            binding_seen[tool_name] = binding
            yield {"event": "approval_required", "data": binding.to_dict()}
            outcome, extra = await gate.require(binding, tenant.id)
            if outcome == ApprovalOutcome.DENIED:
                yield {"event": "approval_denied", "data": {"tool": tool_name, **extra}}
                if lease:
                    broker.revoke(lease.ref)
                continue
            if outcome == ApprovalOutcome.TIMEOUT:
                yield {"event": "approval_timeout", "data": {"tool": tool_name, **extra}}
                degraded = True
                break
            yield {"event": "approval_granted", "data": {"tool": tool_name, **extra}}

        # 3.7 ★ TOCTOU 演示：批准后模型改参数
        if cfg.tamper and tool_name == "k8s_restart":
            args = dict(args, target="prod-db-0")     # 改成生产库
            if not gate.verify(binding_seen[tool_name], digest(args)):
                yield {"event": "security_block", "data": {
                    "layer": "approval_binding",
                    "reason": "args_digest_mismatch",
                    "detail": "批准后参数被修改（vllm-0 -> prod-db-0），审批绑定失效"}}
                if lease:
                    broker.revoke(lease.ref)
                continue

        # 3.8 最后一跳解出明文
        credential = ""
        if adapter.needs_credential:
            try:
                credential = broker.resolve(lease.ref, tenant.id, tool_name,
                                            digest(args))
                ctx._last_cred_ref = lease.ref
                if cfg.inject and not leaked_plain:
                    # 模拟「上游把明文泄进了 context」—— 用于演示出站脱敏
                    leaked_plain = credential
                    yield {"event": "context_poisoned", "data": {
                        "reason": "upstream leaked plaintext into context",
                        "cred_ref": lease.ref}}
            except CredentialError as e:
                yield {"event": "security_block", "data": {
                    "layer": "credential_resolve", "reason": str(e),
                    "tool": tool_name}}
                continue

        # 3.9 执行（超时 + 重试）
        yield {"event": "tool_call", "data": {
            "tool": tool_name, "args": redact_deep(args),
            "risk": risk, "cred_ref": lease.ref if lease else ""}}

        try:
            async def _call():
                return await adapter.invoke(args, ctx, credential)
            res = await control.run_step(
                with_retry(_call, attempts=2, base_delay=0.02,
                           retry_on=(RuntimeError, TimeoutError)),
                step=tool_name)
        except (TimeoutError, asyncio.CancelledError) as e:
            yield {"event": "tool_error", "data": {"tool": tool_name,
                                                   "error": str(e),
                                                   "recoverable": True}}
            degraded = True
            break
        except Exception as e:                       # noqa: BLE001
            yield {"event": "tool_error", "data": {"tool": tool_name,
                                                   "error": type(e).__name__}}
            continue
        finally:
            credential = ""                          # 用完即弃

        # 3.10 结果脱敏：工具结果要回灌进 LLM context，必须先过闸
        payload_text = json.dumps(res.data, ensure_ascii=False, default=str)
        safe_text, hits = redact(payload_text)
        if hits:
            yield {"event": "security_block", "data": {
                "layer": "tool_result", "tool": tool_name, "hits": hits}}
            res = type(res)(ok=False, error="result_contained_secret")

        yield {"event": "tool_result", "data": {
            "tool": tool_name, "ok": res.ok,
            "data": json.loads(safe_text) if res.ok else {},
            "error": res.error}}

        if res.ok:
            executed += 1
            if tool_name == "kb_query":
                kb_text = "；".join(h.get("body", "") for h in res.data.get("hits", []))
                doc_ids = [h.get("id") for h in res.data.get("hits", [])]
            ckpt.save(run_id, tool_name, {"ok": True, "index": idx,
                                          "kb_text": kb_text, "doc_ids": doc_ids})

    # ---------------- 4. 模型交互（流式 + 出站脱敏） ----------------
    degraded_by_approval = degraded
    prompt = (f"用户问题：{norm['raw']}\n知识库片段：{kb_text}\n给出 SRE 处理建议：")
    if cfg.inject and leaked_plain:
        prompt += f"\n（来自上游未脱敏的历史上下文）access_key={leaked_plain}"

    sr = StreamingRedactor()
    collected = []
    try:
        async for delta in llm.stream(prompt):
            safe, blocked = sr.feed(delta)
            if safe:
                collected.append(safe)
                yield {"event": "answer", "data": {"delta": safe}}
            if blocked:
                yield {"event": "security_block", "data": {
                    "layer": "outbound_stream",
                    "reason": "credential_leak",
                    "detail": "检测到明文凭证正在流出，已 fail-closed 截断"}}
                degraded = True
                break
        tail = sr.flush()
        if tail and not sr.blocked:
            collected.append(tail)
            yield {"event": "answer", "data": {"delta": tail}}
    except Exception as e:                           # noqa: BLE001
        degraded = True
        msg = "（暂无可用的模型结果，已按 L3 空包兜底返回，不影响服务可用性）"
        collected.append(msg)
        yield {"event": "answer", "data": {"delta": msg}}
        yield {"event": "degraded", "data": {"layer": "llm", "error": type(e).__name__}}

    answer_text = "".join(collected)

    # ---------------- 5. 引用 ----------------
    if doc_ids:
        yield {"event": "citation", "data": {"from": "KBAdapter", "doc": doc_ids[0]}}

    # ---------------- 6. 结果校验 ----------------
    checks = {
        "answer_non_empty": bool(answer_text.strip()),
        "has_citation": bool(doc_ids),
        "no_plaintext_credential": not bool(detect_leak(answer_text)),
        "tools_executed": executed,
    }
    yield {"event": "validation", "data": checks}

    # ---------------- 7. 写缓存（D7：降级产物不进缓存） ----------------
    if not degraded and answer_text.strip():
        cache.put(cache_key, {"answer": answer_text,
                              "doc": doc_ids[0] if doc_ids else ""})
    elif degraded:
        yield {"event": "cache_skipped", "data": {
            "reason": "degraded result must not be cached (D7)"}}

    # ---------------- 8. 收尾：撤销本次全部凭证 ----------------
    broker.revoke_all(tenant.id)

    source = ("L3-empty" if degraded and not degraded_by_approval
              else "approval-incomplete" if degraded_by_approval else "llm")
    yield {"event": "done", "data": {
        "source": source, "run_id": run_id,
        "leases_issued": len(broker.leases(tenant.id)),
        "leases_revoked": all(l.revoked for l in broker.leases(tenant.id)),
    }}


def _stream(text: str, per: int = 3):
    from .grapheme import chunk_by_grapheme
    return chunk_by_grapheme(text, per=per)


def redact_deep(obj):
    """递归脱敏：工具参数里也可能混进凭证。"""
    if isinstance(obj, dict):
        return {k: redact_deep(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [redact_deep(v) for v in obj]
    if isinstance(obj, str):
        return redact(obj)[0]
    return obj
