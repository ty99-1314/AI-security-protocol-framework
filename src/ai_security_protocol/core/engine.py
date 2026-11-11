from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Mapping

from .context import SecurityContext
from .decisions import Decision, DecisionAction
from .policy import SecurityPolicy, ToolPermission


@dataclass(frozen=True)
class ToolCall:
    tool_name: str
    action: str
    resource: str
    arguments: Mapping[str, Any] = field(default_factory=dict)
    request_id: str | None = None

    def __post_init__(self) -> None:
        for name in ("tool_name", "action", "resource"):
            if not getattr(self, name).strip():
                raise ValueError(f"{name} must not be empty")


def arguments_fingerprint(arguments: Mapping[str, Any]) -> str:
    """Return a stable digest for JSON-compatible tool arguments."""
    try:
        canonical = json.dumps(arguments, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    except (TypeError, ValueError) as error:
        raise ValueError("tool arguments must be JSON serializable") from error
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class PolicyEngine:
    def __init__(self, policy: SecurityPolicy) -> None:
        self.policy = policy

    def evaluate_tool_call(self, call: ToolCall, context: SecurityContext) -> Decision:
        common = {
            "policy_version": self.policy.version,
            "request_id": call.request_id or context.request_id,
        }
        if not context.trusted:
            return Decision(
                DecisionAction.DENY,
                "IDENTITY_UNTRUSTED",
                "A trusted security context is required.",
                **common,
            )

        permission = next(
            (
                item
                for item in self.policy.permissions
                if item.role == context.role
                and item.tool_name == call.tool_name
                and item.action == call.action
                and item.resource == call.resource
            ),
            None,
        )
        if permission is None:
            return Decision(
                DecisionAction.DENY,
                "TOOL_NOT_ALLOWED",
                "The policy does not allow this role to perform this tool action on this resource.",
                **common,
            )

        if call.action in self.policy.approval_required_actions:
            digest = arguments_fingerprint(call.arguments)
            grant = next(
                (
                    item
                    for item in context.approvals
                    if item.principal_id == context.principal_id
                    and item.tool_name == call.tool_name
                    and item.action == call.action
                    and item.resource == call.resource
                    and item.arguments_sha256 == digest
                ),
                None,
            )
            if grant is None:
                return Decision(
                    DecisionAction.REQUIRE_APPROVAL,
                    "APPROVAL_REQUIRED",
                    "A valid approval bound to this principal and exact operation is required.",
                    rule_id=permission.rule_id,
                    approval_ref=None,
                    **common,
                )
            return Decision(
                DecisionAction.ALLOW,
                "APPROVAL_VERIFIED",
                "The operation is allowed and has matching trusted approval evidence.",
                rule_id=permission.rule_id,
                approval_ref=grant.approval_ref,
                **common,
            )

        return Decision(
            DecisionAction.ALLOW,
            "POLICY_ALLOWED",
            "The operation is allowed by policy.",
            rule_id=permission.rule_id,
            **common,
        )
