from typing import Protocol

from ..core import SecurityContext, ToolCall
from ..runtime import SecurityRuntime


class AgentFrameworkAdapter(Protocol):
    """Contract for framework integrations; adapters remain optional extras."""

    def guard_tool_call(
        self,
        runtime: SecurityRuntime,
        call: ToolCall,
        context: SecurityContext,
    ) -> None:
        """Must enforce the returned decision before invoking the real tool."""
        ...
