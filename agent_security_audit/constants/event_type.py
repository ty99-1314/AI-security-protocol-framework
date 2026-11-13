"""Normalized event categories accepted by the audit framework."""

from enum import Enum


class EventType(str, Enum):
    AUTH = "auth"
    AUTHZ = "authz"
    TOOL_CALL = "tool_call"
    APPROVAL = "approval"
    POLICY_CHANGE = "policy_change"
    LOG_EVENT = "log_event"
    NETWORK = "network"
    DATA_ACCESS = "data_access"
    SYSTEM_EVENT = "system_event"
