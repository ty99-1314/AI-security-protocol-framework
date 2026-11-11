from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Mapping

from ..core import (
    Decision,
    DecisionAction,
    PolicyEngine,
    SecurityContext,
    ToolCall,
)
from ..events import SecurityEvent


class SecurityDenied(PermissionError):
    def __init__(self, decision: Decision) -> None:
        self.decision = decision
        super().__init__(f"{decision.reason_code}: {decision.message}")


@dataclass
class SecurityRuntime:
    """Framework-independent guard for tool calls.

    The guard only protects calls routed through ``execute_tool``. A host
    adapter must make this the actual execution boundary and construct context
    from trusted authentication/approval systems.
    """

    engine: PolicyEngine
    event_sink: Callable[[SecurityEvent], None] | None = None

    def _emit(self, event: SecurityEvent) -> None:
        if self.event_sink is not None:
            self.event_sink(event)

    def before_tool_call(self, call: ToolCall, context: SecurityContext) -> Decision:
        decision = self.engine.evaluate_tool_call(call, context)
        self._emit(
            SecurityEvent(
                event_type="tool.call.decided",
                agent_id=context.principal_id,
                request_id=decision.request_id,
                policy_version=decision.policy_version,
                operation=call.action,
                resource=call.resource,
                tool_name=call.tool_name,
                decision=decision.action.value,
                reason_code=decision.reason_code,
                execution_status="not_started",
            )
        )
        return decision

    def execute_tool(
        self,
        call: ToolCall,
        context: SecurityContext,
        tool: Callable[..., Any],
    ) -> Any:
        """Authorize before calling ``tool``; rejected calls never execute it."""
        decision = self.before_tool_call(call, context)
        if decision.action is not DecisionAction.ALLOW:
            raise SecurityDenied(decision)

        self._emit(
            SecurityEvent(
                event_type="tool.execution.started",
                agent_id=context.principal_id,
                request_id=decision.request_id,
                policy_version=decision.policy_version,
                operation=call.action,
                resource=call.resource,
                tool_name=call.tool_name,
                decision=decision.action.value,
                reason_code=decision.reason_code,
                execution_status="started",
            )
        )
        try:
            result = tool(**dict(call.arguments))
        except Exception as error:
            self._emit(
                SecurityEvent(
                    event_type="tool.execution.failed",
                    agent_id=context.principal_id,
                    request_id=decision.request_id,
                    policy_version=decision.policy_version,
                    operation=call.action,
                    resource=call.resource,
                    tool_name=call.tool_name,
                    decision=decision.action.value,
                    reason_code="TOOL_EXECUTION_FAILED",
                    execution_status="failed",
                )
            )
            raise

        self._emit(
            SecurityEvent(
                event_type="tool.execution.completed",
                agent_id=context.principal_id,
                request_id=decision.request_id,
                policy_version=decision.policy_version,
                operation=call.action,
                resource=call.resource,
                tool_name=call.tool_name,
                decision=decision.action.value,
                reason_code=decision.reason_code,
                execution_status="completed",
            )
        )
        return result
