"""Common checker interface and finding construction helpers."""

from abc import ABC, abstractmethod
from typing import Any, Iterable, Mapping
from uuid import uuid4

from agent_security_audit.constants import AuditDomain, RiskLevel
from agent_security_audit.models import Finding, PolicyConfig


class BaseChecker(ABC):
    domain: AuditDomain

    def __init__(self, policy: PolicyConfig):
        self.policy = policy

    def get_domain(self) -> AuditDomain:
        return self.domain

    @abstractmethod
    def run(self, events: Iterable[Mapping[str, Any]]) -> list[Finding]:
        """Evaluate events in this checker's domain."""

    def make_finding(self, *, code: str, title: str, severity: RiskLevel,
                     description: str, event: Mapping[str, Any], recommendation: str) -> Finding:
        event_id = str(event.get("event_id") or "")
        return Finding(
            finding_id=str(uuid4()), code=code, title=title, severity=severity,
            domain=self.domain, description=description,
            evidence=[{"event_id": event_id or None, "timestamp": str(event.get("timestamp", "")),
                       "event_type": str(event.get("event_type", ""))}],
            recommendation=recommendation,
            affected_agent=event.get("agent_id"),
            affected_resource=event.get("resource"),
            source_event_ids=[event_id] if event_id else [],
        )


def as_mapping(event: Any) -> Mapping[str, Any]:
    if isinstance(event, Mapping):
        return event
    if hasattr(event, "model_dump"):
        return event.model_dump(mode="json")
    raise TypeError("events must be mappings or Pydantic models")
