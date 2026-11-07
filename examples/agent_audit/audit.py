#!/usr/bin/env python3
"""Audit AI-agent action events against a small, explicit policy.

Input is JSON Lines: one event per line. This audits recorded attempts/actions;
it does not intercept or block tools. Connect it to trusted tool-execution
middleware and emit an event before/after every tool call for production use.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict, deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# Minimal demo policy. Adapt role/action/resource names to your environment.
ALLOWED = {
    ("support", "read", "ticket"),
    ("support", "reply", "ticket"),
    ("finance", "read", "invoice"),
    ("finance", "export", "invoice"),
}
SENSITIVE_ACTIONS = {"delete", "export", "send_payment"}
EXTERNAL_DESTINATIONS = {"external", "public", "unknown"}
REQUIRED_FIELDS = {"timestamp", "agent_id", "role", "action", "resource"}


def parse_timestamp(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("timestamp must include a timezone")
    return parsed.astimezone(timezone.utc)


def read_events(path: Path) -> list[dict[str, Any]]:
    events = []
    with path.open(encoding="utf-8") as source:
        for line_number, line in enumerate(source, start=1):
            if not line.strip():
                continue
            try:
                event = json.loads(line)
                if not isinstance(event, dict):
                    raise ValueError("event must be a JSON object")
                missing = REQUIRED_FIELDS - event.keys()
                if missing:
                    raise ValueError(f"missing fields: {', '.join(sorted(missing))}")
                event["_line"] = line_number
                event["_time"] = parse_timestamp(str(event["timestamp"]))
                events.append(event)
            except (json.JSONDecodeError, ValueError, TypeError) as error:
                raise ValueError(f"line {line_number}: {error}") from error
    return events


def audit(events: list[dict[str, Any]], burst_limit: int = 3) -> list[dict[str, Any]]:
    """Return policy findings. A denied attempt is still recorded and reviewed."""
    findings: list[dict[str, Any]] = []
    attempts: dict[str, deque[datetime]] = defaultdict(deque)

    def flag(event: dict[str, Any], severity: str, code: str, message: str) -> None:
        findings.append({
            "line": event["_line"],
            "agent_id": event["agent_id"],
            "severity": severity,
            "code": code,
            "message": message,
        })

    for event in events:
        role, action, resource = event["role"], event["action"], event["resource"]
        destination = event.get("destination")
        approved = event.get("approved") is True

        if (role, action, resource) not in ALLOWED:
            flag(event, "HIGH", "UNAUTHORIZED_ACTION",
                 f"{role} is not allowed to {action} {resource}")

        if action in SENSITIVE_ACTIONS and not approved:
            flag(event, "HIGH", "APPROVAL_REQUIRED",
                 f"{action} requires explicit human approval")

        if action == "export" and destination in EXTERNAL_DESTINATIONS:
            flag(event, "CRITICAL", "EXTERNAL_DATA_EXPORT",
                 f"export destination is {destination!r}")

        if event.get("outcome") == "denied":
            agent = str(event["agent_id"])
            now = event["_time"]
            recent = attempts[agent]
            while recent and (now - recent[0]).total_seconds() > 60:
                recent.popleft()
            recent.append(now)
            if len(recent) == burst_limit:
                flag(event, "MEDIUM", "DENIED_ACTION_BURST",
                     f"{len(recent)} denied attempts by this agent within 60 seconds")

    return findings


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("events", type=Path, help="JSONL action-event file")
    parser.add_argument("--burst-limit", type=int, default=3,
                        help="denied attempts in 60 seconds that trigger an alert (default: 3)")
    args = parser.parse_args()
    if args.burst_limit < 1:
        parser.error("--burst-limit must be at least 1")
    try:
        events = read_events(args.events)
    except (OSError, ValueError) as error:
        print(f"audit input error: {error}", file=sys.stderr)
        return 2

    findings = audit(events, args.burst_limit)
    print(json.dumps({
        "events_reviewed": len(events),
        "findings_count": len(findings),
        "findings": findings,
    }, ensure_ascii=False, indent=2))
    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
