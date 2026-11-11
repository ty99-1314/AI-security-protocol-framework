from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, Mapping

from .core import AuditPolicy, AuditFinding, audit, audit_events, parse_timestamp, read_events


@dataclass(frozen=True)
class AuditReport:
    events_reviewed: int
    findings: list[dict[str, Any]]

    @property
    def findings_count(self) -> int:
        return len(self.findings)

    def to_dict(self) -> dict[str, Any]:
        return {
            "events_reviewed": self.events_reviewed,
            "findings_count": self.findings_count,
            "findings": self.findings,
        }


def audit_records(
    events: Iterable[Mapping[str, Any]], *, policy: AuditPolicy | None = None
) -> AuditReport:
    records = list(events)
    return AuditReport(len(records), audit_events(records, policy=policy))


__all__ = [
    "AuditFinding", "AuditPolicy", "AuditReport", "audit", "audit_events",
    "audit_records", "parse_timestamp", "read_events",
]
