# 可运行的 AI Agent 行为审计示例

这个示例把 agent 的**工具调用事件**与明确策略逐条比对，报告越权操作、未审批的敏感操作、对外导出和短时间内反复被拒绝的行为。纯 Python 标准库，无需安装依赖。

> 审计器检查的是可信执行层记录的事件；它本身不拦截工具调用，也不能证明日志未被执行层伪造。生产环境应在工具网关/执行中间件内记录调用，并在执行前做策略拦截、将日志写入受保护的集中存储。

## 运行

```bash
python3 examples/agent_audit/audit.py examples/agent_audit/sample_events.jsonl
```

示例中的 `support-bot-7` 有一次合法读取，以及尝试导出客户记录、删除工单、发送付款的行为。预期结果是报告 `UNAUTHORIZED_ACTION`、`APPROVAL_REQUIRED`、`EXTERNAL_DATA_EXPORT` 和 `DENIED_ACTION_BURST`。发现问题时退出码为 `1`；无发现为 `0`；输入格式错误为 `2`。

## 事件格式

每行一个 JSON 对象，至少包含 `timestamp`（ISO 8601 且带时区）、`agent_id`、`role`、`action`、`resource`。可选字段：`destination`、`approved`、`outcome`。`outcome` 为 `denied` 的事件用于检测一分钟内重复拒绝；生产接入时应记录**所有尝试**，不能只记录成功调用。

```json
{"timestamp":"2026-11-07T10:00:00Z","agent_id":"support-bot-7","role":"support","action":"read","resource":"ticket","outcome":"allowed"}
```

## 策略与测试

在 `audit.py` 的 `ALLOWED`、`SENSITIVE_ACTIONS` 和 `EXTERNAL_DESTINATIONS` 中修改示例策略。运行单元测试：

```bash
python3 -m unittest discover -s examples/agent_audit -v
```

检测规则是可解释的确定性检查，不等同于对任意 agent 的语义理解、完整安全保证或合规认证。审计事件还应由执行层可靠地产生，并保护其完整性、访问权限和保留期限。
