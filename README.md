# ai-ops-harness

一个 Agent Harness / Runtime 的参考实现，关注点只有一个：**当 Agent 拿着凭证去干活的时候，怎么保证凭证不出事。**

它脱胎于一个线上 AIOps 知识库助手。那套系统当年是按"工具编排 + 状态维护 + 流式 + 降级"搭的，
这版重写补上了当时没有的部分：凭证代管、权限判定、租户隔离，以及一套能回归的 eval。

Python 3.9+，零必需依赖，不需要 GPU / 网络 / Redis。

---

## 快速开始

```bash
git clone https://github.com/yingmsky/aiops-agent-harness.git
cd aiops-agent-harness

python3 run.py        # 跑一遍完整流程：规划 → 凭证签发 → 审批 → 流式输出 → 收口
bash smoke.sh         # 冒烟测试，15 项验证，末尾给 PASS/FAIL 汇总
```

`smoke.sh` 的退出码等于失败项数，可以直接接 CI。当前结果 PASS=15 / FAIL=0。

可选依赖：`regex`（字素簇切分更准）、`redis`（L2 缓存）、`openai`（接 vLLM 之类的 OpenAI 兼容后端）。
不装这三个也能完整跑通，默认走 mock 后端。

---

## 它解决了什么问题

传统服务里，凭证是静态的：部署时把密钥配给进程，进程按预先写好的代码路径调用接口。
权限可以在部署前分配好，审计只需要回答"哪个服务在谁的授权下做了什么"。

Agent 打破了这个前提——执行者不再是一个行为确定的进程，而是一个**会自己决定下一步做什么的规划器**。
于是几件事变了：

- 权限没法预先写死，只能按每次工具调用动态判定；
- Agent 长期持有凭证等于埋雷，因为模型随时可能被诱导着用掉它；
- 凭证一旦进了 prompt 或 context，就可能被复述出去、写进日志和 trace；
- 审批发生在参数确定之前，模型可以在你批准之后改掉参数再执行。

这个项目的绝大部分代码，都是围绕这四件事写的。

---

## 凭证是怎么管的

三原则，每一条在代码里都有强制点，不依赖 prompt 约束：

| 原则 | 实现 |
|---|---|
| 凭证不进 prompt | Agent 循环里只有 `cred_ref`；明文在工具调用的最后一跳才解出，且**不落库**——由 `HMAC(root_secret, ref)` 现算 |
| 凭证不进日志和 trace | 所有出站文本（SSE、trace、工具参数、工具结果）先过脱敏；流式输出命中即 fail-closed 截断 |
| 用完即弃 | JIT 签发，TTL 15 分钟；任务结束 `revoke_all(tenant)` |

两个 Agent 特有的失败模式，堵在代码层：

**出站泄漏。** 模型可能把凭证复述出来。流式场景下这很难处理——secret 可能跨 chunk 边界被切碎，
所以脱敏器要保留一段尾巴等确认，而保留多少又直接影响流式的观感。这里的实现是检测到锚点才缓冲，
命中即截断后续全部内容。`--inject` 可以复现。

**TOCTOU。** 审批发生在参数确定之前，模型可以在批准后改参数。这里把 lease 绑定 `args_digest`：
工具、租户、参数摘要四要素任一不符，凭证立即作废。`--tamper` 可以复现。

权限用四元交集，Agent 只能收窄、不能放大：

```
effective = 用户上界 ∩ 租户策略 ∩ 工作负载角色 ∩ 本次任务委托
```

多租户隔离有四道闸：工具白名单、凭证 scope、模型 entitlement、配额。
缓存 key 强制带租户前缀——跨租户数据泄漏最常见的入口就是缓存 key 忘了带 namespace。

---

## 其他已实现的机制

三级降级（L1 进程内 60s → L2 300s → L3 空包兜底，不抛 5xx）、幂等键、检查点、
暂停与恢复、人工审批门（granted / denied / timeout 三条出口）、超时与取消、
指数退避重试（只对可重试错误）、字素簇流式切分（emoji 不被拆帧）、任务级 eval。

关于降级有一条教训值得单独说：降级产物不能进缓存。
早期版本把 L3 空包无条件写回缓存，结果后端抖 3 秒，用户后面 5 分钟拿到的全是空答案，
而监控面板上"5xx 逃逸率 0%"这条红线一直是绿的——它不报错，所以没人发现。

---

## 演示命令

| 命令 | 演示什么 |
|---|---|
| `python3 run.py` | 完整流程 |
| `python3 run.py --inject` | 凭证外泄 → 出站脱敏 fail-closed 截断 |
| `python3 run.py --tamper` | 批准后改参数 → 凭证作废 |
| `python3 run.py --tenant globex` | 只读租户越权 → 被白名单拦住 |
| `python3 run.py --chaos` | 后端全挂 → L3 收口，且降级产物不进缓存 |
| `python3 run.py --approve deny` | 人工拒绝 → 跳过有副作用的动作 |
| `python3 run.py --approve timeout` | 无人审批 → 超时收口 |
| `python3 run.py --eval` | 任务级 eval，9 个指标 |

暂停恢复需要落盘：

```bash
python3 run.py --pause-after k8s_restart --persist    # 输出 run_id
python3 run.py --persist --resume <run_id>            # 跳过已完成节点，重跑被暂停的那个
```

起 SSE 服务：

```bash
python3 run.py --serve --port 8000
curl -N --data-urlencode "q=vllm 挂了怎么办" --get http://localhost:8000/ask
```

---

## 目录结构

```
ai-ops-harness/
├── run.py                  入口
├── smoke.sh                一键冒烟
├── harness/
│   ├── credentials.py      凭证代管：JIT 签发 / 用完即弃 / args 绑定 / 流式脱敏
│   ├── policy.py           租户策略（工具白名单 / scope 上界 / 配额）+ 风险分级
│   ├── approval.py         审批门，绑定参数摘要
│   ├── runtime.py          幂等 / 检查点 / 暂停恢复 / 超时 / 取消 / 重试
│   ├── cache.py            三级降级
│   ├── graph.py            主编排（异步生成器，yield 事件）
│   ├── tools.py            工具适配器
│   ├── acl.py              口语 → 稳定意图
│   ├── llm.py              mock / OpenAI 兼容双模后端
│   ├── grapheme.py         字素簇切分
│   └── eval_harness.py     任务级 eval
└── eval/tasks.json         回归用例
```

---

## 已知边界

- 这是参考实现，不是生产代码。真实系统跑了 8 个里程碑、78 项测试，这里是工程脊柱的公开重建版。
- **没有真正的沙箱隔离。** 真隔离要靠 gVisor / Kata / Firecracker，这里只有策略层的隔离（白名单 / scope / 配额）。
- **没接 HSM。** 生产环境根密钥应该在 HSM 内、永不出硬件边界；这里 root secret 只是进程内的一串字节。
- `_graphemes_stdlib()` 不是完整的 UAX #29 实现（未处理 Hangul / CRLF / Prepend），生产请装 `regex`。
- eval 是任务级的，没有做在线 A/B，也没接 CI 门禁。
- 凭证续租与并存期轮转没做。

代码里几处非直觉的写法（比如为什么不用现成的 agent 框架、为什么工具协议不照搬 MCP）
都是权衡的结果，不是随手写的，注释里有写理由和适用边界。
