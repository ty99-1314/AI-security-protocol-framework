from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any


class DecisionAction(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"
    TRANSFORM = "TRANSFORM"
    ESCALATE = "ESCALATE"


@dataclass(frozen=True)
class Decision:
    action: DecisionAction
    reason_code: str
    message: str
    rule_id: str | None = None
    policy_version: str | None = None
    request_id: str | None = None
    approval_ref: str | None = None
    details: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "action": self.action.value,
            "reason_code": self.reason_code,
            "message": self.message,
            "rule_id": self.rule_id,
            "policy_version": self.policy_version,
            "request_id": self.request_id,
            "approval_ref": self.approval_ref,
            "details": self.details,
        }
