"""Behavior policy, approval, and denied-attempt burst checks."""

from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import Any, Iterable, Mapping

from agent_security_audit.constants import AuditDomain, FindingCode, RiskLevel
from agent_security_audit.models import Finding, PolicyConfig
from .base_checker import BaseChecker


class BehaviorConstraintChecker(BaseChecker):
    domain = AuditDomain.BEHAVIOR_CONSTRAINTS

    def run(self, events: Iterable[Mapping[str, Any]]) -> list[Finding]:
        events = list(events)
        findings = []
        for event in events:
            action = event.get("action")
            if action in self.policy.require_approval_for and event.get("approved") is not True:
                findings.append(self.make_finding(code=FindingCode.POLICY_VIOLATION.value,
                    title="Sensitive action lacks approval", severity=RiskLevel.HIGH,
                    description=f"Action {action!r} requires explicit approval.", event=event,
                    recommendation="Require a verifiable human approval before executing the action."))
        denied = defaultdict(list)
        for event in events:
            if event.get("outcome") == "denied":
                try:
                    timestamp = _parse_time(event.get("timestamp"))
                except (TypeError, ValueError):
                    continue
                denied[str(event.get("agent_id") or "<unknown>")].append((timestamp, event))
        window = timedelta(seconds=self.policy.denied_burst_window_seconds)
        for attempts in denied.values():
            attempts.sort(key=lambda pair: pair[0])
            recent = deque()
            for timestamp, event in attempts:
                while recent and timestamp - recent[0][0] > window:
                    recent.popleft()
                recent.append((timestamp, event))
                if len(recent) == self.policy.denied_burst_limit:
                    findings.append(self.make_finding(code=FindingCode.DENIED_ACTION_BURST.value,
                        title="Repeated denied actions", severity=RiskLevel.MEDIUM,
                        description=f"Agent reached {len(recent)} denied attempts within {window.total_seconds():g} seconds.",
                        event=event, recommendation="Investigate the activity and review agent permissions or automation loops."))
        return findings


def _parse_time(value: Any) -> datetime:
    if isinstance(value, datetime):
        result = value
    elif isinstance(value, str):
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    else:
        raise ValueError("missing timestamp")
    if result.tzinfo is None or result.utcoffset() is None:
        raise ValueError("timestamp must be timezone aware")
    return result
