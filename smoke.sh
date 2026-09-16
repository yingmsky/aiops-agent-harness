#!/usr/bin/env bash
# ai-ops-harness 一键冒烟：跑完全部验证，末尾给 PASS/FAIL 汇总。
# 用法：bash smoke.sh          （在项目根目录执行）
# 零依赖，Python 3.9+ 即可。不需要 GPU / 网络 / Redis。

set -u
cd "$(dirname "$0")" || exit 1

PY="${PYTHON:-python3}"
PASS=0
FAIL=0

ok()   { echo "  ✅ $1"; PASS=$((PASS+1)); }
bad()  { echo "  ❌ $1"; FAIL=$((FAIL+1)); }
head_() { echo; echo "──────────────────────────────────────────────"; echo "$1"; }

echo "================================================================"
echo "  ai-ops-harness 冒烟测试"
echo "  python: $($PY -V 2>&1)"
echo "================================================================"

# ---------------------------------------------------------------- 1
head_ "1/8  能否 import（语法与依赖）"
if $PY -c "import sys; sys.path.insert(0,'.'); import harness" 2>/tmp/ah.err; then
  ok "import 成功，无缺失依赖"
else
  bad "import 失败：$(tail -3 /tmp/ah.err)"
fi

# ---------------------------------------------------------------- 2
head_ "2/8  默认流程（编排 + 流式 + 凭证签发 + 审批）"
OUT=$($PY run.py 2>&1)
echo "$OUT" | grep -q "credential_issued"  && ok "凭证已签发（credential_issued）"  || bad "缺 credential_issued"
echo "$OUT" | grep -q "approval_required"  && ok "高风险动作触发审批门"            || bad "缺 approval_required"
echo "$OUT" | grep -qE "\[ +answer\]"  && ok "流式输出正常"                    || bad "缺 answer 流式事件"
echo "$OUT" | grep -q "leases_revoked\": true" && ok "任务结束凭证已全部撤销"      || bad "凭证未撤销"

# ---------------------------------------------------------------- 3
head_ "3/8  凭证外泄拦截（--inject）"
OUT=$($PY run.py --inject 2>&1)
echo "$OUT" | grep -q "security_block"     && ok "出站脱敏触发 fail-closed"        || bad "未触发 security_block"
N=$(echo "$OUT" | grep -c "sk-live-")
[ "$N" -eq 0 ] && ok "输出中明文凭证出现 0 次（期望 0）" || bad "明文泄漏！出现 $N 次"

# ---------------------------------------------------------------- 4
head_ "4/8  TOCTOU：批准后改参数（--tamper）"
OUT=$($PY run.py --tamper 2>&1)
echo "$OUT" | grep -q "args_digest_mismatch" && ok "参数被篡改 → 凭证作废"         || bad "未拦住参数篡改"

# ---------------------------------------------------------------- 5
head_ "5/8  多租户隔离（--tenant globex，只读租户）"
OUT=$($PY run.py --tenant globex 2>&1)
N=$(echo "$OUT" | grep -c "policy_deny")
[ "$N" -ge 2 ] && ok "越权工具被拦 $N 次（期望 ≥2）" || bad "越权未拦住，policy_deny 只有 $N 次"

# ---------------------------------------------------------------- 6
head_ "6/8  降级收口 + D7（--chaos，后端全挂）"
OUT=$($PY run.py --chaos 2>&1)
echo "$OUT" | grep -q "L3-empty"      && ok "降级到 L3 空包，不抛 5xx"  || bad "未走 L3 收口"
echo "$OUT" | grep -q "cache_skipped" && ok "降级产物未写进缓存（D7）"  || bad "降级结果污染了缓存"
echo "$OUT" | grep -qE "\[ +done\]"        && ok "仍以 200 + done 正常收口"  || bad "未正常收口"

# ---------------------------------------------------------------- 7
head_ "7/8  审批两条出口"
$PY run.py --approve deny 2>&1    | grep -q "approval_denied"  && ok "人工拒绝 → 跳过副作用动作" || bad "deny 分支异常"
$PY run.py --approve timeout 2>&1 | grep -q "approval_timeout" && ok "无人审批 → 超时收口"        || bad "timeout 分支异常"

# ---------------------------------------------------------------- 8
head_ "8/8  任务级 eval（9 个指标）"
$PY run.py --eval 2>&1 | tail -13
if $PY run.py --eval 2>&1 | grep -qE "0/5|PASS 失败|❌"; then
  bad "eval 存在未通过项"
else
  ok "eval 指标全绿"
fi

# ---------------------------------------------------------------- 汇总
echo
echo "================================================================"
echo "  结果：PASS=$PASS  FAIL=$FAIL"
echo "================================================================"
head_ "可选：暂停恢复（需要落盘）"
echo "  $PY run.py --pause-after k8s_restart --persist     # 记下 run_id"
echo "  $PY run.py --persist --resume <run_id>"
head_ "可选：SSE 服务"
echo "  $PY run.py --serve --port 8000"
echo "  curl -N --data-urlencode \"q=vllm 挂了怎么办\" --get http://localhost:8000/ask"
echo
[ "$FAIL" -eq 0 ] && echo "全部通过 🎉" || echo "有 $FAIL 项失败，按上面的 ❌ 行排查"
exit "$FAIL"
