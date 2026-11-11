# 安装与使用

此目录可作为独立 Python 命令行工具安装。项目仅使用 Python 标准库，不需要额外运行时依赖。

## 从源码安装

```bash
cd examples/agent_audit
python3 -m pip install .
```

安装后可在任意目录调用 `agent-audit`：

```bash
agent-audit /path/to/events.jsonl
agent-audit /path/to/events.jsonl --burst-limit 5
```

也可以在仓库根目录直接使用示例事件验证安装：

```bash
agent-audit examples/agent_audit/sample_events.jsonl
```

发现策略问题时命令返回状态码 `1`，输入文件或事件格式错误时返回 `2`，没有发现问题时返回 `0`。报告以 JSON 输出到标准输出。示例事件预期会产生发现项，因此最后一条命令返回 `1` 是正常行为。

## 隔离安装（可选）

推荐使用虚拟环境避免修改系统 Python：

```bash
python3 -m venv .venv
. .venv/bin/activate  # Windows: .venv\\Scripts\\activate
python -m pip install ./examples/agent_audit
agent-audit examples/agent_audit/sample_events.jsonl
```

卸载：

```bash
python -m pip uninstall agent-audit-example
```

策略配置和事件格式请参阅本目录的 [README](README.md)。该审计器只检查记录下来的事件，不会拦截工具调用，也不能替代可信执行层的日志保护。
