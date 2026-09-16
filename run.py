#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ai-ops-harness 入口。

一条命令跑通（无 GPU / 无网络 / 无 Redis 也能跑）：

    python run.py                          # 默认：mock 全流程演示
    python run.py --chaos                  # 后端故障 -> L3 空包收口（5xx 逃逸率 0%）
    python run.py --inject                 # 投毒 + 凭证外泄 -> 出站脱敏 fail-closed
    python run.py --tamper                 # 批准后改参数 -> TOCTOU 拦截
    python run.py --tenant globex          # 只读租户越权 -> 工具白名单拦截
    python run.py --approve deny           # 人工拒绝 -> 跳过高风险动作
    python run.py --approve timeout        # 无人审批 -> 超时 -> L3 收口
    python run.py --pause-after k8s_restart --resume <run_id>
    python run.py --eval                   # 任务级 eval，输出可回归数字
    python run.py --serve --port 8000      # 起 SSE 服务
"""

import argparse
import asyncio
import json
import os
import sys

# 允许从任意 cwd 运行
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from harness.graph import RunConfig, run_agent          # noqa: E402
from harness.eval_harness import eval_main              # noqa: E402
from harness.credentials import CredentialBroker        # noqa: E402

DEFAULT_Q = "vllm 挂了怎么办"


async def selftest(args):
    cfg = RunConfig(
        tenant_id=args.tenant,
        inject=args.inject,
        tamper=args.tamper,
        chaos=args.chaos,
        approval_mode=args.approve,
        timeout=args.timeout,
        pause_after=args.pause_after,
        resume_from=args.resume,
        persist=args.persist,
        per=args.per,
        model=args.model,
        base_url=args.base_url,
        redis_url=args.redis,
    )
    title = " / ".join([x for x in [
        f"tenant={args.tenant}",
        "chaos" if args.chaos else "",
        "inject" if args.inject else "",
        "tamper" if args.tamper else "",
        f"approve={args.approve}",
        f"pause@{args.pause_after}" if args.pause_after else "",
        f"resume={args.resume}" if args.resume else "",
    ] if x])
    print("\n" + "=" * 72)
    print(f"  ai-ops-harness 事件流    [{title}]")
    print(f"  query: {args.q!r}")
    print("=" * 72)

    async for ev in run_agent(args.q, cfg):
        data = json.dumps(ev["data"], ensure_ascii=False)
        if len(data) > 150:
            data = data[:147] + "..."
        print(f"  [{ev['event']:>18}] {data}")

    print("=" * 72)
    print("  说明：credential_issued 里只有 cred_ref，没有明文；")
    print("        done.leases_revoked=True 表示本次凭证已全部撤销。")
    print("=" * 72 + "\n")


async def demo_credentials():
    """单独演示凭证三原则，输出审计视图（只有 ref，永远没有明文）。"""
    b = CredentialBroker(default_ttl=900)
    lease = b.issue("acme", "k8s_describe", {"k8s:read"}, "digest-abc")
    print("\n" + "=" * 72)
    print("  凭证代管演示")
    print("=" * 72)
    print("  审计视图（可安全进 trace / 日志，永远没有明文）：")
    for line in b.audit_view("acme").splitlines():
        print("  " + line)
    ok = b.resolve(lease.ref, "acme", "k8s_describe", "digest-abc")
    print(f"  最后一跳解出明文（只在工具调用处短暂存在）：{ok[:12]}...（已截断显示）")
    try:
        b.resolve(lease.ref, "acme", "k8s_describe", "digest-CHANGED")
    except Exception as e:
        print(f"  参数被改后解出 -> 拒绝：{type(e).__name__}: {e}")
    b.revoke(lease.ref)
    try:
        b.resolve(lease.ref, "acme", "k8s_describe", "digest-abc")
    except Exception as e:
        print(f"  撤销后解出     -> 拒绝：{type(e).__name__}: {e}")
    print("=" * 72 + "\n")


def serve(args):
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    import urllib.parse

    def make_cfg(q, params):
        return RunConfig(
            tenant_id=params.get("tenant", ["acme"])[0],
            inject="inject" in params,
            tamper="tamper" in params,
            chaos="chaos" in params,
            approval_mode=params.get("approve", ["auto"])[0],
            timeout=args.timeout,
            redis_url=args.redis,
            model=args.model,
            base_url=args.base_url,
        )

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            # HTTP 请求行按 latin-1 解码；客户端若直接发 UTF-8 原始字节会变乱码，
            # 这里还原一次，保证中文 query 不被误判为 unknown intent。
            try:
                path = self.path.encode("latin-1", "ignore").decode("utf-8", "ignore")
            except Exception:
                path = self.path
            u = urllib.parse.urlparse(path)
            params = urllib.parse.parse_qs(u.query)
            if u.path.startswith("/ask"):
                raw = params.get("q", [""])[0]
                cfg = make_cfg(raw, params)
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.send_header("Cache-Control", "no-cache")
                self.send_header("Connection", "keep-alive")
                self.send_header("X-Accel-Buffering", "no")
                self.end_headers()

                async def pump():
                    async for ev in run_agent(raw, cfg):
                        body = (f"event: {ev['event']}\n"
                                f"data: {json.dumps(ev['data'], ensure_ascii=False)}\n\n")
                        self.wfile.write(body.encode("utf-8"))
                        self.wfile.flush()
                asyncio.run(pump())
            elif u.path.startswith("/healthz"):
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"ok\n")
            else:
                self.send_response(200)
                self.end_headers()
                self.wfile.write(
                    b'GET /ask?q=...&tenant=acme&inject=1&tamper=1&chaos=1\n')

    print(f"SSE 服务已启动： http://localhost:{args.port}/ask?q=vllm%20挂了怎么办")
    ThreadingHTTPServer(("0.0.0.0", args.port), H).serve_forever()


def main():
    ap = argparse.ArgumentParser(description="ai-ops-harness")
    ap.add_argument("--q", default=DEFAULT_Q)
    ap.add_argument("--tenant", default="acme", choices=["acme", "globex"])
    ap.add_argument("--chaos", action="store_true", help="强制后端故障（演示 L3 收口）")
    ap.add_argument("--inject", action="store_true", help="投毒 + 凭证外泄（演示出站脱敏）")
    ap.add_argument("--tamper", action="store_true", help="批准后改参数（演示 TOCTOU 拦截）")
    ap.add_argument("--approve", default="auto", choices=["auto", "deny", "timeout"])
    ap.add_argument("--timeout", type=float, default=30.0)
    ap.add_argument("--pause-after", default="", help="在某个节点后暂停")
    ap.add_argument("--resume", default="", help="从 run_id 恢复")
    ap.add_argument("--persist", action="store_true", help="检查点落盘到 .runs/")
    ap.add_argument("--per", type=int, default=3, help="流式分块粒度（真实 LLM≈1）")
    ap.add_argument("--model", default="qwen2.5-7b")
    ap.add_argument("--base-url", default="", help="vLLM OpenAI 兼容地址")
    ap.add_argument("--redis", default="", help="可选：Redis URL 启用 L2 降级")
    ap.add_argument("--eval", action="store_true", help="跑任务级 eval")
    ap.add_argument("--demo-cred", action="store_true", help="单独演示凭证代管")
    ap.add_argument("--serve", action="store_true")
    ap.add_argument("--port", type=int, default=8000)
    args = ap.parse_args()

    if args.eval:
        asyncio.run(eval_main())
    elif args.demo_cred:
        asyncio.run(demo_credentials())
    elif args.serve:
        serve(args)
    else:
        asyncio.run(selftest(args))


if __name__ == "__main__":
    main()
