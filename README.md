# AI Security Protocol Framework

一个与 Agent 开发框架协同工作的安全控制与审计层。当前 MVP 提供框架无关的工具调用前置策略检查与 JSONL 事后审计。运行时控制只对经过 `SecurityRuntime.execute_tool(...)` 或正确集成的适配器调用生效；它不控制模型内部推理。

## 安装

```bash
python -m pip install .
```

开发模式：

```bash
python -m pip install -e .
```

需要 Python 3.10 或更高版本。基础包只依赖 Python 标准库。

## 工具调用安全运行时

策略默认拒绝所有未列出的工具操作。必须显式授权 `role/tool/action/resource` 组合，并由宿主框架提供可信身份上下文。

```python
from ai_security_protocol import (
    PolicyEngine,
    SecurityContext,
    SecurityPolicy,
    SecurityRuntime,
    ToolCall,
    ToolPermission,
)

policy = SecurityPolicy(
    policy_id="support-agent",
    version="1",
    permissions=frozenset({
        ToolPermission("support", "read_ticket", "read", "ticket:T-123"),
    }),
)
runtime = SecurityRuntime(PolicyEngine(policy))
context = SecurityContext(
    principal_id="agent-7",
    role="support",
    trusted=True,  # 只能由可信宿主认证层设置，不能取自模型输出
    request_id="request-123",
)
call = ToolCall(
    tool_name="read_ticket",
    action="read",
    resource="ticket:T-123",
    arguments={"ticket_id": "T-123"},
)

result = runtime.execute_tool(
    call,
    context,
    lambda ticket_id: {"ticket_id": ticket_id, "status": "open"},
)
```

不允许的调用会抛出 `SecurityDenied`，工具函数不会被执行。高风险动作可配置 `approval_required_actions`；审批必须由可信宿主提供 `ApprovalGrant`，并绑定主体、工具、动作、资源及参数摘要。不得把模型生成的 `approved=True` 当作审批证据。

`event_sink` 可接收 `SecurityEvent`，记录策略决定、工具开始、完成或失败。日志后端的访问控制、防篡改与保留策略由集成应用负责配置。

## 离线 JSONL 审计

保留现有离线审计 CLI：

```bash
ai-security-audit examples/agent_audit/sample_events.jsonl
# 或
python -m ai_security_protocol examples/agent_audit/sample_events.jsonl
```

CLI 输出 JSON；退出码 `0` 表示无发现，`1` 表示有发现，`2` 表示输入错误。此功能分析已记录事件，不会拦截调用，也不能证明日志真实或不可篡改。

## Agent 框架适配

`adapters` 中定义了框架无关的适配器接口，但当前尚未交付 LangChain、LangGraph、CrewAI 等具体框架适配器。集成时必须将 guard 放在真实工具执行边界，证明拒绝决策发生在副作用之前。不要只在工具执行后写日志。

## 当前能力边界

此 MVP 可在本包运行时入口内对工具调用做确定性 allow/deny/approval 检查，并生成��件。它不提供身份认证、审批系统、模型输入/输出语义安全、数据加密、完整日志存储或框架 hook 的自动覆盖。`trusted=True` 是集成方的信任边界，生产环境必须只由可信认证中间件创建上下文。

## 测试

```bash
python -m unittest discover -s tests -v
```
