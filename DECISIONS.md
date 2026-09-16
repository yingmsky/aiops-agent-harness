# 决策 / 踩坑记录 · ai-ops-harness

> 面试价值：能讲清「为什么这么做、踩过什么坑、边界在哪」比「做完了」值钱得多。
> D1–D8 继承自前身 AIOps 项目（`../ai-infra-practice/aiops-observability/DECISIONS.md`），
> D9–D13 是本次按 Agent 工程平台 JD 重写时新增 / 重跑发现的。

---

## 继承的八条（摘要，细节见原文件）

| # | 决策 | 一句话 |
|---|---|---|
| D1 | L3 空包收口 | 降级链必须画到尽头，任何上游不可用什么都回 `200 + done`，端到端永不 5xx |
| D2 | 字素簇切分 | 流式按 grapheme 切，否则 `⚠️`(U+26A0+U+FE0F) 被拆成两帧 |
| D3 | 自写 Graph，不用 LangGraph | 链路短且固定；边界是「变成动态 DAG 时要重评」 |
| D4 | 自有协议，不用 MCP | 工具内部同进程；边界是「开放给外部 Agent 时 MCP 才有价值」 |
| D5 | ACL 横跨多层 | 模糊性不止来自输入，每层都要防腐 |
| D6 | Redis 双实例 | state(allkeys-lru，可丢) 与 guard(noeviction+AOF，不可丢) 分开，否则关键状态被自己驱逐 |
| D7 | **降级产物不进缓存** | 无条件 `cache.put` 会把 3 秒抖动拉成 5 分钟故障窗口，且监控全绿 |
| D8 | 字素簇 fallback 不能退化 | 无 `regex` 时退化成 `list()`，M7.4 修复只在装了依赖的环境生效 |

---

## D9 — 明文凭证不落库，由 HMAC 现算

**决策**：`CredentialBroker` 只存 lease 元数据（ref / tenant / tool / scopes / args_digest / 过期），
**不存明文**。明文在 `resolve()` 时用 `HMAC-SHA256(root_secret, ref)` 现算，用完即弃。

**理由**：
- 存储里没有明文 = 数据库被拖走也拿不到凭证；
- 派生是确定性的，同一 ref 每次 resolve 得到同一个 secret，便于对账；
- 与 HSM 的思维方式一致：**根密钥永不出现，出现的都是派生的、可撤销的会话密钥**。

**边界**：root secret 仍是进程内字节。生产里它应该在 HSM 里，且派生操作在 HSM 内完成
（PKCS#11 的 `CKA_SENSITIVE` / `CKA_EXTRACTABLE` 就是控制这件事的）。

---

## D10 — 流式脱敏：锚点必须足够短（本次实测踩到）

**现象**：第一版 `StreamingRedactor` 用固定 `TAIL=48` 缓冲，结果是**整句都不吐字**，
流式体验没了；改成「按锚点按需缓冲」后，第一版锚点用 `"sk-live-"`，
`--inject` 演示时**明文被完整吐了出来**（`sk-live-7bce...` 逐块流出，一次没拦住）。

**根因（两个叠加）**：
1. 分块粒度 `per=3` 会把 `sk-live-` 切碎在 chunk 边界上（`"sk"` / `"-li"` / `"ve-"` / `"349"`…），
   长锚点 `rfind("sk-live-")` 永远命中不到；
2. 更致命的一处：当锚点落在 buffer 下标 0 时，`cut == 0`，
   我写的分支条件 `if cut > 0 and ...` 不成立，于是走了 else 分支把内容**吐了出去**。
   保护逻辑在最关键的那一刻反而变成了放行逻辑。

**修复**：
- 锚点缩短到 `"sk" / "AKIA" / "v1." / "-----BEGIN"`（短到不可能被切碎在边界外）；
- 保留量用 `min(锚点位置, len-TAIL)` 计算，`cut == 0` 表示「全部保留等更多数据」——**这是正确行为，不是异常**；
- 加 `MAX_HOLD=96` 上限：锚点后拖了 96 字符还没形成完整 secret，说明不是 secret，放行。

**可讲的点**：**边界保护代码本身也要走一遍「最坏输入」。**
我第一版写的是「看起来更安全」的固定缓冲，反而在两个地方失守。
流式脱敏的难点从来不是检测，是**检测窗口与流式体验的取舍**。

---

## D11 — 审批必须绑定参数摘要，否则形同虚设

**决策**：`userConfirmed: true` **不是授权**。审批对象是 `ActionBinding`
（tool + args_digest + target + policy_version + expires_at + risk），
执行前用 `gate.verify()` 复核参数，并与 `credential.resolve()` 的 args_digest 校验形成双保险。

**理由**：模型在审批通过之后、执行之前改一下参数，审批就白批了 —— 这是 TOCTOU。
`--tamper` 演示：批准后把 `vllm-0` 改成 `prod-db-0`，凭证立即作废，危险动作没执行。

**可讲的点**：**凭证和审批绑的是同一份「参数指纹」，不是同一句「可以吗」。**
这也解释了为什么 DPoP（RFC 9449）不够用——它证明「谁持有密钥」，**不绑定 tool arguments**。

**边界**：真实系统里审批来自 IM / 工单 / Webhook，本项目用 `--approve auto|deny|timeout`
把三条出口跑出来，因为「三种出口分别把系统留在什么状态」比「做了审批」更能说明设计。

---

## D12 — 暂停时必须回滚幂等键

**现象**：`--pause-after` 时，被暂停的那一步已经 `put_if_absent` 写下了幂等占位。
恢复后该步骤会被判成「已执行过」而直接跳过 —— **幂等键从「防重」变成了「吞掉重试」**。

**修复**：暂停分支里 `idem.release(ikey)` 回滚占位，并 `revoke` 该步的凭证。
恢复时用 `idx < resume_index`（不是 `<=`）跳过已完成节点，**被暂停的那个节点要重跑**。

**可讲的点**：幂等键的写入时机必须和「这一步真的落地了」对齐。
只在开始执行前占位、执行失败却不释放，是幂等实现最常见的坑。

---

## D13 — 缓存 key 必须带 tenant 前缀

**决策**：`TieredCache.key(tenant, intent, clean)` 强制带租户前缀；
凭证按 tenant 隔离签发与撤销（`revoke_all(tenant)`）。

**理由**：没有 tenant 前缀的缓存是**跨租户数据泄露**的经典入口——
两个租户问同一个问题，A 会拿到 B 的答案（而答案里可能含 B 的内部信息）。
多租户隔离的四道闸是：**工具白名单 > 凭证 scoping > 模型 entitlement > 计算隔离**，
缓存隔离属于第一道闸的延伸。

**演示**：`--tenant globex`（只读租户）尝试 `k8s_describe` / `k8s_restart`
→ 两次 `policy_deny`，`leases_issued=0`。

---

## 诚实的「没做」（边界清单）

| 项 | 状态 / 理由 |
|---|---|
| 真实沙箱隔离 | 没做。真隔离要 gVisor / Kata / Firecracker，本项目只有策略层隔离 |
| HSM / PKCS#11 接入 | 没接。root secret 是进程内字节；生产应在 HSM 内派生 |
| 凭证 refresh / 轮转 | 只做了签发与撤销，没做续租与并存期轮转 |
| eval 接 CI 门禁 | 只能本地跑，没有 regression gating |
| 在线 A/B 与任务回放 | trace 落盘在 `.runs/`，没有回放 UI |
| 分布式 trace | 单进程 trace，没有跨服务 propagation |
