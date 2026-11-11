from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any


@dataclass(frozen=True)
class SecurityEvent:
    event_type: str
    agent_id: str
    request_id: str | None = None
    session_id: str | None = None
    timestamp: str = ""
    policy_version: str | None = None
    operation: str | None = None
    resource: str | None = None
    tool_name: str | None = None
    decision: str | None = None
    reason_code: str | None = None
    execution_status: str | None = None

    def __post_init__(self) -> None:
        if not self.timestamp:
            object.__setattr__(self, "timestamp", datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
