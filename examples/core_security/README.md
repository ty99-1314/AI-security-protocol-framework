# 核心安全控制实例

本目录提供两个可直接运行的 Python 标准库示例；行为审计实例见 [`../agent_audit`](../agent_audit/README.md)。这些示例用于理解控制逻辑，不是生产级身份系统或安全认证。

## 1. 基于角色的授权（RBAC）

`security_basics.py` 以 `(角色, 动作, 资源)` 白名单进行检查，未配置角色或未命中规则时一律拒绝（default deny）。示例策略允许 `support` 读取/回复工单，允许 `finance` 读取/导出发票。

## 2. 消息完整性与认证

示例使用 HMAC-SHA256 对规范化 JSON 计算签名，可检测消息内容被篡改；验证时使用常量时间比较。发送方和接收方必须安全共享密钥。**HMAC 不加密内容**，不能隐藏消息；传输保密应使用正确配置的 TLS，密钥应通过密钥管理系统保存和轮换，而不是硬编码。

## 3. 行为审计

`agent_audit` 示例读取 JSONL 工具调用事件，报告越权、敏感操作缺少审批、外部导出和短时间内多次被拒绝等发现。审计只检查日志，不会阻止调用。

## 运行和测试

在仓库根目录执行：

```bash
python3 examples/core_security/security_basics.py
python3 -m unittest discover -s examples/core_security -v
python3 -m unittest discover -s examples/agent_audit -v
```

可自行修改 `security_basics.py` 中的 `POLICY` 并补充测试。生产系统还需要可信身份认证、服务端强制授权、密钥安全存储/轮换、TLS、日志保护和威胁建模；不能仅依赖调用方提交的角色字段或本地示例代码。
