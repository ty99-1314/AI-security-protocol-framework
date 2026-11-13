"""Canonical event schema used as the audit input boundary."""

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from agent_security_audit.constants import EventType


class RawEvent(BaseModel):
    model_config = ConfigDict(extra="allow")

    event_id: str | None = None
    timestamp: datetime
    event_type: EventType = EventType.TOOL_CALL
    agent_id: str | None = None
    role: str | None = None
    action: str | None = None
    resource: str | None = None
    outcome: str | None = None
    approved: bool | None = None
    destination: str | None = None
    request_id: str | None = None
    session_id: str | None = None
    actor_id: str | None = None
    encrypted: bool | None = None
    integrity_valid: bool | None = None
    authenticated: bool | None = None
    logged: bool | None = None
    trace_id: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("timestamp")
    @classmethod
    def timestamp_must_be_timezone_aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("timestamp must include a timezone")
        return value
