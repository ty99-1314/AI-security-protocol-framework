"""Deterministic auditing for AI-agent action events.

This module reviews recorded events; it does not authenticate agents, enforce
permissions, or block tool calls. Collect events at a trusted execution boundary.
The implementation uses only the Python standard library.
"""

from __future__ import annotations

import json
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping

Event = Mapping[str, Any]
Finding = dict[str, Any]


@dataclass(frozen=True)
class Policy:
    """Explicit allow-list and audit rules for agent actions."""

    allowed: frozenset[tuple[str, str, str]] = field(default_factory=lambda: frozenset({
        ("support", "read", "ticket"),
        ("support", "reply", "ticket"),
        ("finance", "read", "invoice"),
        ("finance", "export", "invoice"),
    }))
    sensitive_actions: frozenset[str] = frozenset({"delete", "export", "send_payment"})
    external_destinations: frozenset[str] = frozenset({"external", "public", "unknown"})


DEFAULT_POLICY = Policy()
_REQUIRED_FIELDS = frozenset({"timestamp", "agent_id", "role", "action", "resource"})


def parse_timestamp(value: Any) -> datetime:
    """Parse an ISO-8601 timestamp and normalize it to UTC.

    Naive timestamps are rejected so audit-window checks are unambiguous.
    """
    if not isinstance(value, str) or not value.strip():
        raise ValueError("timestamp must be a non-empty ISO-8601 string")
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError("timestamp must be a valid ISO-8601 timestamp") from error
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("timestamp must include a timezone")
    return parsed.astimezone(timezone.utc)


def read_jsonl(path: str | Path) -> list[dict[str, Any]]:
    """Read and validate a JSONL event file, retaining source line numbers."""
    events: list[dict[str, Any]] = []
    with Path(path).open(encoding="utf-8") as source:
        for line_number, line in enumerate(source, start=1):
            if not line.strip():
                continue
            try:
                event = json.loads(line)
                if not isinstance(event, dict):
                    raise ValueError("event must be a JSON object")
                _validate_event(event)
                event["_line"] = line_number
                events.append(event)
            except (json.JSONDecodeError, ValueError, TypeError) as error:
                raise ValueError(f"line {line_number}: {error}") from error
    return events


def audit_events(
    events: Iterable[Event],
    *,
    policy: Policy = DEFAULT_POLICY,
    burst_limit: int = 3,
    window_seconds: int = 60,
) -> list[Finding]:
    """Return explainable findings for events, without modifying the input.

    A denied-action burst is counted per agent over a rolling time window.
    Events may be supplied in any order. ``burst_limit`` and ``window_seconds``
    must be positive integers.
    """
    if isinstance(burst_limit, bool) or not isinstance(burst_limit, int) or burst_limit < 1:
        raise ValueError("burst_limit must be a positive integer")
    if isinstance(window_seconds, bool) or not isinstance(window_seconds, int) or window_seconds < 1:
        raise ValueError("window_seconds must be a positive integer")

    normalized: list[tuple[int, dict[str, Any], datetime]] = []
    for index, original in enumerate(events, start=1):
        if not isinstance(original, Mapping):
            raise ValueError(f"event {index}: event must be a mapping")
        event = dict(original)
        try:
            timestamp = _validate_event(event)
        except (ValueError, TypeError) as error:
            raise ValueError(f"event {index}: {error}") from error
        line = event.get("_line", index)
        if isinstance(line, bool) or not isinstance(line, int) or line < 1:
            line = index
        normalized.append((index, event, timestamp))

    findings_with_order: list[tuple[int, int, Finding]] = []
    sequence = 0

    def flag(index: int, event: dict[str, Any], severity: str, code: str, message: str) -> None:
        nonlocal sequence
        sequence += 1
        findings_with_order.append((index, sequence, {
            "line": event.get("_line", index),
            "agent_id": event["agent_id"],
            "severity": severity,
            "code": code,
            "message": message,
        }))

    for index, event, _timestamp in normalized:
        role, action, resource = (event[name] for name in ("role", "action", "resource"))
        if (role, action, resource) not in policy.allowed:
            flag(index, event, "HIGH", "UNAUTHORIZED_ACTION",
                 f"{role} is not allowed to {action} {resource}")
        if action in policy.sensitive_actions and event.get("approved") is not True:
            flag(index, event, "HIGH", "APPROVAL_REQUIRED",
                 f"{action} requires explicit human approval")
        destination = event.get("destination")
        if action == "export" and destination in policy.external_destinations:
            flag(index, event, "CRITICAL", "EXTERNAL_DATA_EXPORT",
                 f"export destination is {destination!r}")

    denied_by_agent: dict[str, list[tuple[datetime, int, dict[str, Any]]]] = defaultdict(list)
    for index, event, timestamp in normalized:
        if event.get("outcome") == "denied":
            denied_by_agent[str(event["agent_id"])].append((timestamp, index, event))

    window = timedelta(seconds=window_seconds)
    for attempts in denied_by_agent.values():
        attempts.sort(key=lambda item: (item[0], item[1]))
        recent: deque[tuple[datetime, int, dict[str, Any]]] = deque()
        for timestamp, index, event in attempts:
            while recent and timestamp - recent[0][0] > window:
                recent.popleft()
            recent.append((timestamp, index, event))
            if len(recent) == burst_limit:
                flag(index, event, "MEDIUM", "DENIED_ACTION_BURST",
                     f"{len(recent)} denied attempts by this agent within {window_seconds} seconds")

    findings_with_order.sort(key=lambda item: (item[0], item[1]))
    return [finding for _, _, finding in findings_with_order]


def _validate_event(event: Mapping[str, Any]) -> datetime:
    missing = _REQUIRED_FIELDS.difference(event)
    if missing:
        raise ValueError(f"missing fields: {', '.join(sorted(missing))}")
    for name in ("agent_id", "role", "action", "resource"):
        value = event[name]
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"{name} must be a non-empty string")
    return parse_timestamp(event["timestamp"])


__all__ = ["DEFAULT_POLICY", "Finding", "Policy", "audit_events", "parse_timestamp", "read_jsonl"]
