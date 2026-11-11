from __future__ import annotations

from dataclasses import dataclass, field
from typing import FrozenSet


@dataclass(frozen=True)
class ToolPermission:
    role: str
    tool_name: str
    action: str
    resource: str
    rule_id: str = "tool-permission"


@dataclass(frozen=True)
class SecurityPolicy:
    """Fail-closed policy for tool execution.

    An empty permissions set denies all tools. Approval is required for every
    action listed in ``approval_required_actions``.
    """

    policy_id: str = "default"
    version: str = "1"
    permissions: FrozenSet[ToolPermission] = field(default_factory=frozenset)
    approval_required_actions: FrozenSet[str] = field(default_factory=frozenset)

    def __post_init__(self) -> None:
        if not self.policy_id.strip() or not self.version.strip():
            raise ValueError("policy_id and version must not be empty")
