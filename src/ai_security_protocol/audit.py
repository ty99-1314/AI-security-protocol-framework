from __future__ import annotations

import json
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping

REQUIRED_EVENT_FIELDS = {"timestamp", "agent_id", "role", "action", "resource"}
DEFAULT_ALLOWED_ACTIONS = {
    ("support", "read", "ticket"),
    ("support", "reply", "ticket"),
    ("finance", "read", "invoice"),
    ("finance", "export", "invoice"),
}
DEFAULT_SENSITIVE_ACTIONS = {"delete", "export", "send_payment"}
DEFAULT_EXTERNAL_DESTINATIONS = {"external", "public", "unknown"}


@dataclass(frozen=True)
class AuditPolicy:
    """Rule set used to evaluate agent tool-call events."""

    allowed_actions: set[tuple[str, str, str]] = field(
        default_factory=lambda: set(DEFAULT_ALLOWED_ACTIONS)
    )
    sensitive_actions: set[str] = field(
        default_factory=lambda: set(DEFAULT_SENSITIVE_ACTIONS)
    )
    external_destinations: set[str] = field(
        default_factory=lambda: set(DEFAULT_EXTERNAL_DESTINATIONS)
    )
    burst_limit: int = 3
    burst_window_seconds: int = 60

    def __post_init__(self) -> None:
        if self.burst_limit < 1:
            raise ValueError("burst_limit must be at least 1")
        if self.burst_window_seconds < 1:
            raise ValueError("burst_window_seconds must be at least 1")


@dataclass(frozen=True)
class AuditFinding:
    """A single security finding raised from an agent event."""

    line: int | None
    agent_id: str
    severity: str
    code: str
    message: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "line": self.line,
            "agent_id": self.agent_id,
            "severity": self.severity,
            "code": self.code,
            "message": self.message,
        }


def parse_timestamp(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("timestamp must include a timezone")
    return parsed.astimezone(timezone.utc)


def read_events(path: str | Path) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    with Path(path).open(encoding="utf-8") as source:
        for line_number, line in enumerate(source, start=1):
            if not line.strip():
                continue
            try:
                event = json.loads(line)
                if not isinstance(event, dict):
                    raise ValueError("event must be a JSON object")
                missing = REQUIRED_EVENT_FIELDS - set(event.keys())
                if missing:
                    raise ValueError(f"missing fields: {', '.join(sorted(missing))}")
                event["_line"] = line_number
                event["_time"] = parse_timestamp(str(event["timestamp"]))
                events.append(event)
            except (json.JSONDecodeError, ValueError, TypeError) as error:
                raise ValueError(f"line {line_number}: {error}") from error
    return events


def audit_events(
    events: Iterable[Mapping[str, Any]],
    *,
    policy: AuditPolicy | None = None,
) -> list[dict[str, Any]]:
    """Evaluate agent action events against a policy and return structured findings."""

    selected_policy = policy or AuditPolicy()
    findings: list[AuditFinding] = []
    attempts: dict[str, deque[datetime]] = defaultdict(deque)

    def flag(event: Mapping[str, Any], severity: str, code: str, message: str) -> None:
        findings.append(
            AuditFinding(
                line=event.get("_line"),
                agent_id=str(event["agent_id"]),
                severity=severity,
                code=code,
                message=message,
            )
        )

    for event in events:
        if not isinstance(event, Mapping):
            raise TypeError("each event must be a mapping/dictionary")
        event_data = dict(event)
        if "timestamp" not in event_data:
            raise ValueError("event is missing required field: timestamp")
        required_missing = REQUIRED_EVENT_FIELDS - set(event_data.keys())
        if required_missing:
            missing = ", ".join(sorted(required_missing))
            raise ValueError(f"missing fields: {missing}")
        event_data["_time"] = parse_timestamp(str(event_data["timestamp"]))

        role = str(event_data["role"])
        action = str(event_data["action"])
        resource = str(event_data["resource"])
        destination = event_data.get("destination")
        approved = event_data.get("approved") is True

        if (role, action, resource) not in selected_policy.allowed_actions:
            flag(event_data, "HIGH", "UNAUTHORIZED_ACTION", f"{role} is not allowed to {action} {resource}")

        if action in selected_policy.sensitive_actions and not approved:
            flag(event_data, "HIGH", "APPROVAL_REQUIRED", f"{action} requires explicit human approval")

        if action == "export" and destination in selected_policy.external_destinations:
            flag(event_data, "CRITICAL", "EXTERNAL_DATA_EXPORT", f"export destination is {destination!r}")

        if event_data.get("outcome") == "denied":
            agent = str(event_data["agent_id"])
            now = event_data["_time"]
            recent = attempts[agent]
            window_seconds = selected_policy.burst_window_seconds
            while recent and (now - recent[0]).total_seconds() > window_seconds:
                recent.popleft()
            recent.append(now)
            if len(recent) == selected_policy.burst_limit:
                flag(event_data, "MEDIUM", "DENIED_ACTION_BURST", f"{len(recent)} denied attempts by this agent within {window_seconds} seconds")

    return [finding.to_dict() for finding in findings]


def audit(
    events: Iterable[Mapping[str, Any]],
    *,
    burst_limit: int = 3,
    burst_window_seconds: int = 60,
    policy: AuditPolicy | None = None,
) -> list[dict[str, Any]]:
    """Backward-compatible wrapper matching the existing example function signature."""

    if policy is None:
        policy = AuditPolicy(
            burst_limit=burst_limit,
            burst_window_seconds=burst_window_seconds,
        )
    return audit_events(events, policy=policy)


__all__ = [
    "AuditFinding",
    "AuditPolicy",
    "audit",
    "audit_events",
    "parse_timestamp",
    "read_events",
    "REQUIRED_EVENT_FIELDS",
    "DEFAULT_ALLOWED_ACTIONS",
    "DEFAULT_SENSITIVE_ACTIONS",
    "DEFAULT_EXTERNAL_DESTINATIONS",
]
