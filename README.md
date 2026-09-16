# ai-ops-harness

一个**面向多租户的 Agent Harness / Runtime 参考实现**——按小红书「Agent 工程平台」的 JD 要求重写，
重点是把「凭证管理、权限控制、多租户资源隔离」从一句 JD 话术，变成**跑得起来、拦得住、可回归**的代码。

> 前身是 AIOps 知识库助手（8 里程碑 / 78 测试 / 5xx 逃逸率 0%）。
> 重写的原因是：当年那套设计**本来就是个 Agent Harness，只是当时没这个词**，
> 而且缺了 JD 里点名的四样东西：凭证管理、权限控制、多租户隔离、eval。

---

## 30 秒讲清这个项目

> 一个给 SRE 用的 AIOps 助手，我用它把 Agent Harness 该有的东西都实现了一遍：
> 工具编排、状态维护、流式、降级收口，以及**凭证怎么在 Agent 手里才不会出事**。
> 跑 `python run.py --eval` 能看到 9 个可回归的数字，其中「凭证泄漏拦截率」和
> 「降级收口率」是别人拿不出来的——因为别人没有 L3 空包和出站脱敏这两层设计。

---

## 快速开始

**要求：Python 3.9+，零必需依赖。** 不需要 GPU / 网络 / Redis。
（实测通过：`python3.9` / `python3.13` 均可；`regex` / `redis` / `openai` 都是可选增强，不装也能跑。）

```bash
cd ai-ops-harness
python3 run.py                      # 默认：完整流程 + 流式输出
bash smoke.sh                       # 一键冒烟：15 项验证，末尾给 PASS/FAIL 汇总
```

> **`bash smoke.sh` 是给别人看的第一条命令** —— 它会把下面八条命令全跑一遍并逐项打勾，
> 别人 clone 下来不用读文档就能确认"这项目是真的能跑"。当前结果：**PASS=15 FAIL=0**。

### 八条演示命令，每条对应一个 JD 要求

| 命令 | 演示什么 | 你应该看到 |
|---|---|---|
| `python run.py` | 完整编排 + 流式 | 三层工具、凭证签发、审批门、字素簇流式输出 |
| `python run.py --inject` | **凭证外泄 → 出站脱敏 fail-closed** | 输出到「凭证是 」被截断，`security_block` |
| `python run.py --tamper` | **TOCTOU：批准后改参数** | `args_digest_mismatch`，危险动作没执行 |
| `python run.py --tenant globex` | **多租户隔离** | `policy_deny` ×2，工具白名单拦住越权 |
| `python run.py --chaos` | **降级收口（5xx 逃逸率 0%）** | `L3-empty` + `cache_skipped`（D7） |
| `python run.py --approve deny` | 人工拒绝 | `approval_denied`，跳过副作用动作 |
| `python run.py --approve timeout` | 无人审批 | `approval_timeout` → `L3-empty` 收口 |
| `python run.py --eval` | 任务级 eval | 9 个指标，当前全绿 |

暂停恢复（需要落盘）：

```bash
python run.py --pause-after k8s_restart --persist     # 输出 run_id
python run.py --persist --resume <run_id>             # 跳过已完成节点，重跑被暂停的那个
```

单独看凭证代管：`python run.py --demo-cred`
起 SSE 服务：`python run.py --serve --port 8000`，然后
`curl -N --data-urlencode "q=vllm 挂了怎么办" --get http://localhost:8000/ask`

---

## 凭证这块是怎么设计的

三原则，代码里每一条都有强制点：

| 原则 | 强制点 | 代码位置 |
|---|---|---|
| **不进 prompt** | 模型与 Agent 循环里只有 `cred_ref`；明文只在工具调用最后一跳解出 | `credentials.py` `resolve()` |
| **不进 trace / 日志** | 所有出站文本（SSE、trace、工具参数、工具结果）先过脱敏 | `StreamingRedactor` / `redact_deep()` |
| **用完即弃** | JIT 签发（TTL 15min），任务结束整体 revoke；**明文不落库**，由 `HMAC(root, ref)` 现算 | `CredentialBroker` |

两个 Agent 特有的失败模式，在代码层（不是 prompt 层）被堵死：

1. **模型把凭证复述出去** → 出站流式脱敏，命中即 fail-closed 截断（`--inject` 可复现）。
2. **TOCTOU（批准后改参数）** → lease 绑定 `args_digest`，改一个字凭证自动作废（`--tamper` 可复现）。

权限用四元交集，Agent 只能收窄、不能放大：

```
effective = 用户上界 ∩ 租户策略 ∩ 工作负载角色 ∩ 本次任务委托
```

---

## 目录结构

```
ai-ops-harness/
├── run.py                  入口（selftest / eval / serve / demo-cred）
├── smoke.sh                一键冒烟：15 项验证 + PASS/FAIL 汇总
├── harness/
│   ├── credentials.py  ★  凭证代管：JIT 签发 / 用完即弃 / args 绑定 / 流式脱敏
│   ├── policy.py           多租户（工具白名单 / scope 上界 / 配额）+ 风险分级
│   ├── approval.py         人工介入审批门（绑定参数摘要，防 TOCTOU）
│   ├── runtime.py          幂等 / 检查点 / 暂停恢复 / 超时 / 取消 / 重试
│   ├── cache.py            三级降级 L1→L2→L3 空包
│   ├── graph.py            主编排（异步生成器，yield SSE 事件）
│   ├── tools.py            工具适配器（自有 BaseAdapter 协议，非 MCP）
│   ├── acl.py              防腐层：口语 → 稳定意图
│   ├── llm.py              mock / vLLM 双模后端
│   ├── grapheme.py         字素簇切分（emoji 不被拆帧）
│   └── eval_harness.py     任务级 eval
└── eval/tasks.json         回归用例
```

---

## JD 对照表

| 小红书 Agent 工程平台 JD | 本实现落点 |
|---|---|
| 模型交互 | `llm.py`（mock / vLLM OpenAI 兼容） |
| 任务规划 | `plan()` 按意图产出工具序列（静态 DAG） |
| 工具调用 | `BaseAdapter.invoke` + 凭证最后一跳解出 |
| 状态维护 | `Checkpointer` + `GuardStore`（不可丢实例） |
| 结果校验 | `validation` 事件：空答案 / 缺引用 / 含明文凭证 |
| 错误恢复 | 三级降级 + L3 空包（D1 / D7） |
| 流式 | SSE 事件流 + 字素簇 + 流式脱敏 |
| 超时 / 取消 | `RunControl.run_step` + `cancel()` |
| 重试 | `with_retry` 指数退避，只对可重试错误 |
| 幂等 | `idem_key` → `GuardStore.put_if_absent` |
| 检查点 / 暂停恢复 | `Checkpointer` + `--pause-after` / `--resume` |
| 人工介入 | `ApprovalGate`（三条出口：granted / denied / timeout） |
| **凭证管理 / 权限控制** | `CredentialBroker` + 四元权限交集 |
| **多租户资源隔离** | tenant 前缀贯穿：白名单 / 凭证 / 缓存 key / 配额 |

---

## 诚实边界（面试要主动讲）

- **这是参考实现，不是生产代码。** 真实项目在 IBM（8 里程碑 / 78 测试），此处是工程脊柱的公开重建版。
- **沙箱没做。** 真隔离要靠 gVisor / Kata / Firecracker，本项目没实现，只有策略层的隔离（白名单 / scope / 配额）。
- **HSM 没接。** 真实环境根密钥应在 HSM 内、永不出硬件边界；这里 root secret 只是进程内的一串字节。
- **`_graphemes_stdlib()` 不是完整 UAX #29**（未处理 Hangul / CRLF / Prepend），生产请装 `regex`。
- **eval 是任务级的**，没有做在线 A/B 与回归门禁接入 CI。

---

## 配套文档

- `DECISIONS.md` —— D1–D13 决策与踩坑记录（含本次重跑挖出的新 bug）

## 面试三句话

1. 「这是一个把 Agent Harness 该有的机制都实现了一遍的项目：编排、状态、流式、降级，以及凭证怎么在 Agent 手里才安全。」
2. 「凭证那块我做了三件事：不进 prompt、不进 trace、用完即弃。其中出站脱敏是流式的——第一版被分块切碎绕过去了，我把锚点缩短才真正拦住。」
3. 「别人做 harness 是做编排，我做 harness 是做边界。」
