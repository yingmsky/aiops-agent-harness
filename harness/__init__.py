# -*- coding: utf-8 -*-
"""ai-ops-harness —— 面向多租户的 Agent Harness / Runtime 参考实现。

对外暴露的主要构件：
  CredentialBroker  凭证代管（JIT 签发 / 用完即弃 / args 绑定 / 出站脱敏）
  ApprovalGate      人工介入审批门（绑定参数摘要，防 TOCTOU）
  GuardStore        幂等与检查点（不可丢实例）
  Checkpointer      节点级检查点（暂停恢复）
  RunControl        超时 / 取消 / 暂停
  TieredCache       三级降级（L1 -> L2 -> L3 空包）
  run_agent         主编排（异步生成器，yield SSE 事件）
"""

__version__ = "0.2.0"

from .acl import ACL
from .approval import ActionBinding, ApprovalGate
from .cache import TieredCache
from .credentials import CredentialBroker, CredentialError, StreamingRedactor, detect_leak, redact
from .graph import RunConfig, run_agent
from .llm import LLMBackend
from .policy import TENANTS, Tenant, effective_scopes, get_tenant, risk_level
from .protocol import BaseAdapter, RunContext, ToolResult, digest
from .runtime import Checkpointer, GuardStore, RunControl, idem_key, with_retry
from .tools import build_tools

__all__ = [
    "ACL", "ActionBinding", "ApprovalGate", "TieredCache",
    "CredentialBroker", "CredentialError", "StreamingRedactor",
    "detect_leak", "redact", "RunConfig", "run_agent", "LLMBackend",
    "TENANTS", "Tenant", "effective_scopes", "get_tenant", "risk_level",
    "BaseAdapter", "RunContext", "ToolResult", "digest",
    "Checkpointer", "GuardStore", "RunControl", "idem_key", "with_retry",
    "build_tools",
]
